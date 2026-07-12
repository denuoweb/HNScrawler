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

from .infra import NON_ACTIONABLE_PROVIDER_TYPES
from .live_db import (
    begin_sweep_run,
    finish_sweep_run,
    get_live_meta,
    set_live_meta,
    store_probe_result,
    store_sweep_coverage,
    sweep_coverage_for_roots,
    upsert_candidate,
    upsert_discovered_hosts,
    upsert_root,
)
from .live_models import ONLINE_CATEGORIES, LiveCandidate, TopologyRoot
from .live_probe import ProbeConfig, probe_host
from .timeutil import utc_now

SWEEP_TIERS = (
    "ds_bootstrap",
    "bootstrap",
    "ds_delegated",
    "delegated",
)

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
    limit: int | None = 3000
    page_size: int = 1000
    concurrency: int = 50
    min_delay_ms: int = 100
    authority_delay_ms: int = 500
    timeout: float = 2.0
    max_nameservers: int = 2
    max_addresses: int = 2
    fallback_resolver: str | None = None
    tiers: tuple[str, ...] = SWEEP_TIERS


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
            or result.dns_status == "unreachable"
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
    progress: dict[str, str] = {}
    completed: list[str] = []
    now = utc_now()
    maximum = None if limit is None else max(0, limit)
    uri = f"file:{source.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as topology:
        topology.row_factory = sqlite3.Row
        for tier in tiers:
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
                coverage = sweep_coverage_for_roots(conn, [str(row["name"]) for row in rows])
                reached_limit = False
                for row in rows:
                    root_name = str(row["name"])
                    resource_hash = str(row["resource_hash"] or "")
                    previous = coverage.get(root_name)
                    if _coverage_is_due(previous, resource_hash=resource_hash, now=now):
                        if maximum is not None and len(selected) >= maximum:
                            reached_limit = True
                            break
                        selected.append(_candidate_from_row(row, tier=tier))
                    cursor = root_name
                    progress[tier] = cursor
                if reached_limit or len(rows) < max(1, page_size):
                    if len(rows) < max(1, page_size) and not reached_limit:
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
    authority_keys = _authority_keys(candidate)
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
            source_detail=f"{candidate['signal_tier']} endpoint sweep",
            priority=70 if root.has_ds else 60,
            topology_resource_hash=root.resource_hash,
        ),
        seen_at=result.checked_at,
    )
    store_probe_result(conn, result)


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
        JOIN resource_summary rs ON rs.name = n.name
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


def _candidate_from_row(row: sqlite3.Row, *, tier: str) -> dict[str, Any]:
    root_name = str(row["name"])
    bootstrap_addresses = sorted(
        {
            address
            for column in ("synth4", "synth6", "glue4", "glue6")
            for address in _json_strings(row[column])
            if _public_ip(address)
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
    return {
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
    }


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
        if _public_ip(str(address))
    ]
    if addresses:
        return addresses
    names = [f"ns:{str(name).strip().lower().rstrip('.')}" for name in candidate.get("ns_names", [])]
    return [name for name in names if name != "ns:"] or [
        f"provider:{str(candidate.get('provider_guess') or 'unknown')}"
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
