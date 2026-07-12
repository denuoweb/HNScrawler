from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .infra import BULK_DEFAULT_RESOURCE_IPS, KNOWN_HNS_RESOLVER_IPS, NON_ACTIONABLE_PROVIDER_TYPES
from .live_db import (
    authority_health_for_keys,
    begin_sweep_run,
    finish_sweep_run,
    get_live_meta,
    record_authority_health,
    set_live_meta,
    store_probe_result,
    store_sweep_coverage,
    sweep_coverage_for_roots,
    upsert_candidate,
    upsert_discovered_hosts,
    upsert_root,
)
from .live_delegations import delegation_group_rows
from .live_models import ONLINE_CATEGORIES, LiveCandidate, TopologyRoot
from .live_probe import ProbeConfig, probe_host
from .timeutil import utc_now

SWEEP_TIERS = (
    "shared_delegation",
    "ds_bootstrap",
    "bootstrap",
    "ds_delegated",
    "delegated",
)
PRIORITY_SWEEP_TIERS = ("shared_delegation",)
UNKNOWN_AUTHORITY_SAMPLES = 3
EXCLUDED_BOOTSTRAP_IPS = frozenset([*BULK_DEFAULT_RESOURCE_IPS, *KNOWN_HNS_RESOLVER_IPS])

_TIER_PREDICATES = {
    "ds_bootstrap": """
        COALESCE(rs.has_ds, 0) = 1
        AND (COALESCE(rs.has_synth, 0) = 1 OR COALESCE(rs.has_glue, 0) = 1)
    """,
    "bootstrap": """
        COALESCE(rs.has_ds, 0) = 0
        AND (COALESCE(rs.has_synth, 0) = 1 OR COALESCE(rs.has_glue, 0) = 1)
    """,
    "ds_delegated": """
        COALESCE(rs.has_ds, 0) = 1
        AND COALESCE(rs.has_ns, 0) = 1
        AND COALESCE(rs.has_synth, 0) = 0
        AND COALESCE(rs.has_glue, 0) = 0
    """,
    "delegated": """
        COALESCE(rs.has_ds, 0) = 0
        AND COALESCE(rs.has_ns, 0) = 1
        AND COALESCE(rs.has_synth, 0) = 0
        AND COALESCE(rs.has_glue, 0) = 0
    """,
}


@dataclass(frozen=True)
class SweepBatchConfig:
    limit: int | None = 500
    page_size: int = 1000
    concurrency: int = 50
    min_delay_ms: int = 100
    authority_delay_ms: int = 500
    timeout: float = 2.0
    max_nameservers: int = 2
    max_addresses: int = 2
    fallback_resolver: str | None = None
    tiers: tuple[str, ...] = SWEEP_TIERS


def parse_sweep_tiers(value: str) -> tuple[str, ...]:
    tiers = tuple(part.strip() for part in str(value).split(",") if part.strip())
    if not tiers:
        raise ValueError("at least one sweep tier is required")
    unknown = sorted(set(tiers).difference(SWEEP_TIERS))
    if unknown:
        raise ValueError(f"unknown sweep tiers: {', '.join(unknown)}")
    return tiers


class AdaptiveAuthorityLimiter:
    def __init__(
        self,
        *,
        min_delay_ms: int,
        authority_delay_ms: int,
        max_authority_delay_ms: int = 10_000,
    ):
        self._global_delay = max(0, min_delay_ms) / 1000
        self._authority_delay = max(0, authority_delay_ms) / 1000
        self._max_authority_delay = max(self._authority_delay, max_authority_delay_ms / 1000)
        self._lock = threading.Lock()
        self._global_next = 0.0
        self._authority_next: dict[str, float] = {}
        self._authority_delay_by_key: dict[str, float] = {}

    def wait(self, authority_keys: list[str]) -> None:
        keys = sorted(set(authority_keys)) or ["unknown"]
        with self._lock:
            now = time.monotonic()
            start_at = max(
                now,
                self._global_next,
                *(self._authority_next.get(key, 0.0) for key in keys),
            )
            self._global_next = start_at + self._global_delay
            for key in keys:
                delay = self._authority_delay_by_key.get(key, self._authority_delay)
                self._authority_next[key] = start_at + delay
        if start_at > now:
            time.sleep(start_at - now)

    def record(self, authority_keys: list[str], result) -> None:
        keys = sorted(set(authority_keys)) or ["unknown"]
        overloaded = (
            result.http_status_code in {429, 503}
            or result.https_status_code in {429, 503}
        )
        with self._lock:
            for key in keys:
                current = self._authority_delay_by_key.get(key, self._authority_delay)
                if overloaded:
                    self._authority_delay_by_key[key] = min(
                        self._max_authority_delay,
                        max(self._authority_delay, current * 2),
                    )
                elif current > self._authority_delay:
                    self._authority_delay_by_key[key] = max(
                        self._authority_delay,
                        current * 0.75,
                    )

    def summary(self) -> dict[str, int]:
        with self._lock:
            backed_off = sum(
                1
                for delay in self._authority_delay_by_key.values()
                if delay > self._authority_delay
            )
        return {"authority_backoffs": backed_off}


def run_sweep_batch(
    conn: sqlite3.Connection,
    *,
    topology_db: str | Path,
    config: SweepBatchConfig,
) -> dict[str, Any]:
    selection = select_sweep_candidates(
        conn,
        topology_db=topology_db,
        limit=config.limit,
        page_size=config.page_size,
        tiers=config.tiers,
    )
    candidates = selection["candidates"]
    if not candidates:
        with conn:
            _store_selection_progress(conn, selection)
        return {
            "candidates": 0,
            "checked": 0,
            "online": 0,
            "errors": 0,
            "discovered": 0,
            "tiers": selection["tiers"],
            "authority_backoffs": 0,
        }

    probe_config = ProbeConfig(
        timeout=config.timeout,
        max_nameservers=config.max_nameservers,
        max_addresses=config.max_addresses,
        fallback_resolver=config.fallback_resolver,
    )
    limiter = AdaptiveAuthorityLimiter(
        min_delay_ms=config.min_delay_ms,
        authority_delay_ms=config.authority_delay_ms,
    )
    with conn:
        run_id = begin_sweep_run(
            conn,
            candidate_count=len(candidates),
            concurrency=max(1, config.concurrency),
            min_delay_ms=max(0, config.min_delay_ms),
            authority_delay_ms=max(0, config.authority_delay_ms),
        )

    checked = 0
    online = 0
    errors = 0
    discovered = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, config.concurrency)) as executor:
            futures = {
                executor.submit(_probe_sweep_candidate, candidate, probe_config, limiter): candidate
                for candidate in candidates
            }
            for future in concurrent.futures.as_completed(futures):
                candidate = futures[future]
                result = future.result()
                with conn:
                    record_authority_health(
                        conn,
                        authority_keys=candidate["authority_health_keys"],
                        result=result,
                    )
                    store_sweep_coverage(
                        conn,
                        root_name=result.root_name,
                        resource_hash=result.topology_resource_hash,
                        signal_tier=str(candidate["signal_tier"]),
                        result=result,
                    )
                    if result.category in ONLINE_CATEGORIES:
                        _promote_endpoint(conn, candidate, result)
                        discovered += upsert_discovered_hosts(
                            conn,
                            root_name=result.root_name,
                            hosts=result.discovered_hosts,
                            topology_resource_hash=result.topology_resource_hash,
                            source_detail=f"authoritative response while sweeping {result.host}",
                        )
                checked += 1
                online += int(result.category in ONLINE_CATEGORIES)
                errors += int(result.failure_reason.startswith("probe_error:"))
        with conn:
            _store_selection_progress(conn, selection)
            finish_sweep_run(
                conn,
                run_id,
                checked_count=checked,
                online_count=online,
                error_count=errors,
            )
    except Exception:
        with conn:
            finish_sweep_run(
                conn,
                run_id,
                checked_count=checked,
                online_count=online,
                error_count=errors + 1,
                status="failed",
            )
        raise

    return {
        "run_id": run_id,
        "candidates": len(candidates),
        "checked": checked,
        "online": online,
        "errors": errors,
        "discovered": discovered,
        "tiers": selection["tiers"],
        **limiter.summary(),
    }


def select_sweep_candidates(
    conn: sqlite3.Connection,
    *,
    topology_db: str | Path,
    limit: int | None,
    page_size: int,
    tiers: tuple[str, ...] = SWEEP_TIERS,
) -> dict[str, Any]:
    source = Path(topology_db)
    if not source.is_file():
        raise FileNotFoundError(f"topology database does not exist: {source}")
    selected: list[dict[str, Any]] = []
    unknown_authority_samples: dict[str, int] = {}
    progress: dict[str, str] = {}
    completed: list[str] = []
    now = utc_now()
    maximum = None if limit is None else max(0, limit)
    uri = f"file:{source.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as topology:
        topology.row_factory = sqlite3.Row
        if "shared_delegation" in tiers and get_live_meta(conn, _not_before_key("shared_delegation")) <= now:
            selected.extend(
                _select_shared_delegation_candidates(
                    conn,
                    topology=topology,
                    limit=maximum,
                    now=now,
                )
            )
        for tier in tiers:
            if tier == "shared_delegation":
                continue
            if tier not in _TIER_PREDICATES:
                raise ValueError(f"unknown sweep tier: {tier}")
            if maximum is not None and len(selected) >= maximum:
                break
            if get_live_meta(conn, _not_before_key(tier)) > now:
                continue
            cursor = get_live_meta(conn, _cursor_key(tier))
            while maximum is None or len(selected) < maximum:
                rows = list(
                    _topology_page(
                        topology,
                        tier=tier,
                        after_name=cursor,
                        limit=max(1, page_size),
                    )
                )
                if not rows:
                    progress[tier] = ""
                    completed.append(tier)
                    break
                page = [_candidate_from_row(row, tier=tier) for row in rows]
                _mark_shared_authority_keys(page)
                coverage = sweep_coverage_for_roots(
                    conn,
                    [str(candidate["root_name"]) for candidate in page if not candidate["skip_sweep"]],
                )
                authority_health = authority_health_for_keys(
                    conn,
                    [
                        key
                        for candidate in page
                        if not candidate["skip_sweep"]
                        for key in candidate["authority_health_keys"]
                    ],
                )
                reached_limit = False
                waiting_for_authority_health = False
                for candidate in page:
                    root_name = str(candidate["root_name"])
                    if candidate["skip_sweep"]:
                        if not waiting_for_authority_health:
                            cursor = root_name
                            progress[tier] = cursor
                        continue
                    resource_hash = str(candidate["topology_resource_hash"])
                    previous = coverage.get(root_name)
                    if not _coverage_is_due(previous, resource_hash=resource_hash, now=now):
                        if not waiting_for_authority_health:
                            cursor = root_name
                            progress[tier] = cursor
                        continue
                    authority_state = _authority_selection_state(
                        candidate["authority_health_keys"],
                        authority_health,
                        now=now,
                    )
                    if authority_state == "suppressed":
                        if not waiting_for_authority_health:
                            cursor = root_name
                            progress[tier] = cursor
                        continue
                    authority_key = ""
                    if authority_state == "unknown":
                        authority_key = _unknown_authority_key(
                            candidate["authority_health_keys"],
                            authority_health,
                            now=now,
                        )
                        if unknown_authority_samples.get(authority_key, 0) >= UNKNOWN_AUTHORITY_SAMPLES:
                            waiting_for_authority_health = True
                            continue
                    if maximum is not None and len(selected) >= maximum:
                        reached_limit = True
                        break
                    selected.append(candidate)
                    if authority_state == "unknown":
                        unknown_authority_samples[authority_key] = (
                            unknown_authority_samples.get(authority_key, 0) + 1
                        )
                        # Do not move the persistent cursor past speculative samples.
                        # The next cycle expands healthy groups and skips unhealthy ones.
                        waiting_for_authority_health = True
                    elif not waiting_for_authority_health:
                        cursor = root_name
                        progress[tier] = cursor
                if waiting_for_authority_health or reached_limit or len(rows) < max(1, page_size):
                    if len(rows) < max(1, page_size) and not (waiting_for_authority_health or reached_limit):
                        progress[tier] = ""
                        completed.append(tier)
                    break
    return {
        "candidates": selected,
        "cursor_updates": progress,
        "completed_tiers": completed,
        "tiers": [str(candidate["signal_tier"]) for candidate in selected],
        "selected_at": now,
    }


def _probe_sweep_candidate(
    candidate: dict[str, Any],
    config: ProbeConfig,
    limiter: AdaptiveAuthorityLimiter,
):
    authority_keys = candidate["authority_keys"]
    limiter.wait(authority_keys)
    result = probe_host(
        candidate,
        config=config,
        include_dns_details=False,
    )
    limiter.record(authority_keys, result)
    return result


def _promote_endpoint(conn: sqlite3.Connection, candidate: dict[str, Any], result) -> None:
    root = candidate["topology_root"]
    upsert_root(conn, root, synced_at=result.checked_at)
    upsert_candidate(
        conn,
        LiveCandidate(
            root_name=root.name,
            host=root.name,
            source="broad_sweep",
            source_detail=_sweep_source_detail(candidate),
            priority=70 if root.has_ds else 60,
            topology_resource_hash=root.resource_hash,
        ),
        seen_at=result.checked_at,
    )
    store_probe_result(conn, result)


def _sweep_source_detail(candidate: dict[str, Any]) -> str:
    delegation_host = str(candidate.get("delegation_host") or "")
    if delegation_host:
        return f"shared delegation {delegation_host} endpoint sweep"
    return f"{candidate['signal_tier']} endpoint sweep"


def _store_selection_progress(conn: sqlite3.Connection, selection: dict[str, Any]) -> None:
    for tier, cursor in selection["cursor_updates"].items():
        set_live_meta(conn, _cursor_key(tier), cursor)
        if cursor:
            set_live_meta(conn, _not_before_key(tier), "")
    for tier in selection["completed_tiers"]:
        set_live_meta(conn, _not_before_key(tier), _after(str(selection["selected_at"]), days=7))


def _topology_page(
    conn: sqlite3.Connection,
    *,
    tier: str,
    after_name: str,
    limit: int,
):
    excluded = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    return conn.execute(
        f"""
        SELECT
          n.name, n.provider_guess, n.last_seen_height, n.updated_at,
          COALESCE(rs.resource_hash, n.resource_hash, '') AS resource_hash,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records,
          rs.has_ds, rs.has_ns, rs.has_glue, rs.has_synth,
          COALESCE(ps.provider_type, 'unknown') AS provider_type
        FROM names n
        CROSS JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE COALESCE(n.expired, 0) = 0
          AND n.name > ?
          AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded})
          AND ({_TIER_PREDICATES[tier]})
        ORDER BY n.name
        LIMIT ?
        """,
        (after_name, *NON_ACTIONABLE_PROVIDER_TYPES, limit),
    )


def _select_shared_delegation_candidates(
    conn: sqlite3.Connection,
    *,
    topology: sqlite3.Connection,
    limit: int | None,
    now: str,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    groups = delegation_group_rows(conn)
    handoffs = _delegation_handoffs(topology, groups)
    groups.sort(
        key=lambda group: (
            str(group["nameserver"]) not in handoffs,
            -(int(group["member_count"]) if int(group["member_count"]) <= 100 else 0),
            -int(group["member_count"]),
            str(group["nameserver"]),
        )
    )
    for group in groups:
        if limit is not None and len(selected) >= limit:
            break
        roots = [str(root) for root in group["member_roots"]]
        rows = _topology_rows_for_names(topology, roots)
        coverage = sweep_coverage_for_roots(conn, [str(row["name"]) for row in rows])
        row_by_name = {str(row["name"]): row for row in rows}
        for root_name in roots:
            if limit is not None and len(selected) >= limit:
                break
            row = row_by_name.get(root_name)
            if row is None:
                continue
            candidate = _candidate_from_row(row, tier="shared_delegation")
            candidate["delegation_host"] = str(group["nameserver"])
            candidate["ns_names"] = [str(group["nameserver"])]
            candidate["authority_keys"] = [f"ns:{group['nameserver']}"]
            candidate["authority_health_keys"] = []
            handoff = handoffs.get(str(group["nameserver"]))
            if handoff:
                candidate["ns_handoffs"] = [handoff]
                candidate["signal_tier"] = "ds_handoff" if candidate["has_ds"] else "delegation_handoff"
            if _coverage_is_due(
                coverage.get(root_name),
                resource_hash=str(candidate["topology_resource_hash"]),
                now=now,
            ):
                selected.append(candidate)
    return selected


def _delegation_handoffs(
    topology: sqlite3.Connection,
    groups: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    root_by_nameserver = {
        str(group["nameserver"]): _nameserver_hns_root(str(group["nameserver"]))
        for group in groups
    }
    rows = _topology_rows_for_names(topology, list(root_by_nameserver.values()))
    bootstrap_by_root: dict[str, list[str]] = {}
    for row in rows:
        candidate = _candidate_from_row(row, tier="shared_delegation")
        addresses = list(candidate["bootstrap_addresses"])
        if addresses:
            bootstrap_by_root[str(row["name"])] = addresses
    return {
        nameserver: {
            "nameserver": nameserver,
            "root_name": root_name,
            "bootstrap_addresses": bootstrap_by_root[root_name],
        }
        for nameserver, root_name in root_by_nameserver.items()
        if root_name in bootstrap_by_root
    }


def _nameserver_hns_root(nameserver: str) -> str:
    labels = [label for label in str(nameserver).strip().lower().rstrip(".").split(".") if label]
    return labels[-1] if labels else ""


def _topology_rows_for_names(conn: sqlite3.Connection, names: list[str]) -> list[sqlite3.Row]:
    normalized = sorted({str(name) for name in names if str(name)})
    rows: list[sqlite3.Row] = []
    excluded = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    for start in range(0, len(normalized), 500):
        batch = normalized[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows.extend(
            conn.execute(
                f"""
                SELECT
                  n.name, n.provider_guess, n.last_seen_height, n.updated_at,
                  COALESCE(rs.resource_hash, n.resource_hash, '') AS resource_hash,
                  rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records,
                  rs.has_ds, rs.has_ns, rs.has_glue, rs.has_synth,
                  COALESCE(ps.provider_type, 'unknown') AS provider_type
                FROM names n
                CROSS JOIN resource_summary rs ON rs.name = n.name
                LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
                WHERE n.name IN ({placeholders})
                  AND COALESCE(n.expired, 0) = 0
                  AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded})
                """,
                (*batch, *NON_ACTIONABLE_PROVIDER_TYPES),
            )
        )
    return rows


def _candidate_from_row(row: sqlite3.Row, *, tier: str) -> dict[str, Any]:
    root_name = str(row["name"])
    bootstrap_addresses = sorted(
        {
            address
            for column in ("synth4", "synth6", "glue4", "glue6")
            for address in _json_strings(row[column])
            if _actionable_bootstrap_ip(address)
        }
    )
    root = TopologyRoot(
        name=root_name,
        provider_guess=str(row["provider_guess"] or "unknown/custom"),
        provider_type=str(row["provider_type"] or "unknown"),
        resource_hash=str(row["resource_hash"] or ""),
        last_seen_height=int(row["last_seen_height"])
        if row["last_seen_height"] is not None
        else None,
        ns_names=_json_strings(row["ns_names"]),
        bootstrap_addresses=bootstrap_addresses,
        ds_records=[item for item in _json_values(row["ds_records"]) if isinstance(item, dict)],
        has_ds=bool(row["has_ds"]),
        strict_ready=bool(bootstrap_addresses),
    )
    candidate = {
        "root_name": root.name,
        "host": root.name,
        "topology_resource_hash": root.resource_hash,
        "provider_guess": root.provider_guess,
        "provider_type": root.provider_type,
        "ns_names": root.ns_names,
        "bootstrap_addresses": root.bootstrap_addresses,
        "ds_records": root.ds_records,
        "has_ds": root.has_ds,
        "strict_ready": root.strict_ready,
        "signal_tier": tier,
        "topology_root": root,
        "skip_sweep": tier in {"ds_bootstrap", "bootstrap"} and not root.bootstrap_addresses,
    }
    candidate["authority_keys"] = _authority_keys(candidate)
    candidate["authority_health_keys"] = []
    return candidate


def _coverage_is_due(
    coverage: dict[str, Any] | None,
    *,
    resource_hash: str,
    now: str,
) -> bool:
    return (
        coverage is None
        or str(coverage.get("resource_hash") or "") != resource_hash
        or str(coverage.get("next_check_at") or "") <= now
    )


def _authority_keys(candidate: dict[str, Any]) -> list[str]:
    addresses = [
        f"ip:{address}"
        for address in candidate.get("bootstrap_addresses", [])
        if _actionable_bootstrap_ip(str(address))
    ]
    if addresses:
        return addresses
    names = [f"ns:{str(name).strip().lower().rstrip('.')}" for name in candidate.get("ns_names", [])]
    return [name for name in names if name != "ns:"] or [
        f"provider:{str(candidate.get('provider_guess') or 'unknown')}"
    ]


def _authority_selection_state(
    authority_keys: list[str],
    health: dict[str, dict[str, Any]],
    *,
    now: str,
) -> str:
    if not authority_keys:
        return "ready"
    records = [health.get(key) for key in authority_keys]
    if any(record is not None and record.get("state") == "healthy" for record in records):
        return "healthy"
    if any(record is None or str(record.get("next_probe_at") or "") <= now for record in records):
        return "unknown"
    return "suppressed"


def _unknown_authority_key(
    authority_keys: list[str],
    health: dict[str, dict[str, Any]],
    *,
    now: str,
) -> str:
    for key in authority_keys:
        record = health.get(key)
        if record is None or str(record.get("next_probe_at") or "") <= now:
            return key
    return authority_keys[0] if authority_keys else "unknown"


def _mark_shared_authority_keys(candidates: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = {}
    for candidate in candidates:
        if candidate["skip_sweep"]:
            continue
        for key in candidate["authority_keys"]:
            counts[key] = counts.get(key, 0) + 1
    for candidate in candidates:
        candidate["authority_health_keys"] = [
            key for key in candidate["authority_keys"] if counts.get(key, 0) > 1
        ]


def _cursor_key(tier: str) -> str:
    return f"sweep.cursor.{tier}"


def _not_before_key(tier: str) -> str:
    return f"sweep.not_before.{tier}"


def _after(timestamp: str, *, days: int) -> str:
    instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return (
        (instant + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _json_values(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _json_strings(value: str | None) -> list[str]:
    return [str(item).strip().lower().rstrip(".") for item in _json_values(value) if str(item).strip()]


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _actionable_bootstrap_ip(value: str) -> bool:
    if not _public_ip(value):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(address) not in EXCLUDED_BOOTSTRAP_IPS
