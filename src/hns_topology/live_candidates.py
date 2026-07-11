from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .infra import (
    BULK_DEFAULT_RESOURCE_IPS,
    KNOWN_HNS_RESOLVER_IPS,
    NON_ACTIONABLE_PROVIDER_TYPES,
)
from .live_db import (
    begin_topology_sync,
    finish_topology_sync,
    set_live_meta,
    upsert_candidate,
    upsert_root,
)
from .live_models import LiveCandidate, TopologyRoot
from .timeutil import utc_now

HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
DISCOVERABLE_TYPES = {"A", "AAAA", "CNAME", "HTTPS", "SVCB", "TLSA"}
PUBLIC_BOOTSTRAP_SQL = """
(
  EXISTS (
    SELECT 1 FROM json_each(COALESCE(rs.synth4, '[]')) ip
    WHERE hns_live_actionable_ip(ip.value) = 1
  )
  OR EXISTS (
    SELECT 1 FROM json_each(COALESCE(rs.synth6, '[]')) ip
    WHERE hns_live_actionable_ip(ip.value) = 1
  )
  OR EXISTS (
    SELECT 1 FROM json_each(COALESCE(rs.glue4, '[]')) ip
    WHERE hns_live_actionable_ip(ip.value) = 1
  )
  OR EXISTS (
    SELECT 1 FROM json_each(COALESCE(rs.glue6, '[]')) ip
    WHERE hns_live_actionable_ip(ip.value) = 1
  )
)
"""
ROOT_CLASSES_SQL = "'DIRECT_SYNTH', 'DELEGATED_WITH_GLUE', 'DELEGATED_NO_GLUE', 'DNSSEC_CANDIDATE'"
ROOT_SELECTION_SQL = f"""
(
  (
    (COALESCE(rs.has_synth, 0) = 1 OR COALESCE(rs.has_glue, 0) = 1)
    AND {PUBLIC_BOOTSTRAP_SQL}
  )
  OR (
    COALESCE(rs.has_ns, 0) = 1
    AND (
      COALESCE(rs.has_ds, 0) = 1
      OR COALESCE(tes.has_tlsa, 0) = 1
      OR COALESCE(ps.provider_type, 'unknown') = 'external_dns'
    )
  )
)
"""
EXCLUDED_BOOTSTRAP_IPS = frozenset([*BULK_DEFAULT_RESOURCE_IPS, *KNOWN_HNS_RESOLVER_IPS])


def sync_topology(live_conn: sqlite3.Connection, topology_db: str | Path) -> dict[str, int]:
    source = Path(topology_db)
    if not source.is_file():
        raise FileNotFoundError(f"topology database does not exist: {source}")
    synced_at = utc_now()
    root_count = 0
    changed_roots = 0
    uri = f"file:{source.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as topology:
        topology.row_factory = sqlite3.Row
        topology.create_function(
            "hns_live_actionable_ip",
            1,
            _is_actionable_bootstrap_ip,
            deterministic=True,
        )
        topology.execute("PRAGMA temp_store = FILE")
        _require_topology_tables(topology)
        _prepare_candidate_names(topology)
        meta = {
            row["key"]: row["value"]
            for row in topology.execute("SELECT key, value FROM snapshot_meta")
        }
        with live_conn:
            begin_topology_sync(live_conn)
            for row in _topology_root_rows(topology):
                root = _root_from_row(row)
                root_count += 1
                changed_roots += int(upsert_root(live_conn, root, synced_at=synced_at))
                upsert_candidate(
                    live_conn,
                    _apex_candidate(root, has_tlsa=bool(row["has_tlsa"])),
                    seen_at=synced_at,
                )
                for owner in _json_list(row["tlsa_owners"]):
                    host = host_from_dns_owner(root.name, str(owner), "TLSA")
                    if host and host != root.name:
                        upsert_candidate(
                            live_conn,
                            LiveCandidate(
                                root_name=root.name,
                                host=host,
                                source="tlsa_owner",
                                source_detail=str(owner),
                                priority=90,
                                topology_resource_hash=root.resource_hash,
                            ),
                            seen_at=synced_at,
                        )
            for candidate in _dns_evidence_candidates(topology):
                upsert_candidate(live_conn, candidate, seen_at=synced_at)
            finish_topology_sync(live_conn, synced_at=synced_at)
            set_live_meta(live_conn, "topology_synced_at", synced_at)
            set_live_meta(live_conn, "topology_source", str(source))
            set_live_meta(live_conn, "topology_height", str(meta.get("last_indexed_height") or ""))
            set_live_meta(
                live_conn, "topology_tip_hash", str(meta.get("last_indexed_tip_hash") or "")
            )
            set_live_meta(live_conn, "topology_generated_at", str(meta.get("generated_at") or ""))
            set_live_meta(live_conn, "topology_fingerprint", _topology_fingerprint(meta, source))
    candidate_count = int(
        live_conn.execute(
            "SELECT COUNT(*) FROM candidates WHERE active = 1 AND suppressed = 0"
        ).fetchone()[0]
    )
    return {
        "roots": root_count,
        "candidates": candidate_count,
        "changed_roots": changed_roots,
    }


def sync_topology_if_changed(
    live_conn: sqlite3.Connection,
    topology_db: str | Path,
) -> dict[str, int | bool]:
    source = Path(topology_db)
    meta = _read_topology_meta(source)
    fingerprint = _topology_fingerprint(meta, source)
    current = live_conn.execute(
        "SELECT value FROM live_meta WHERE key = 'topology_fingerprint'"
    ).fetchone()
    if current is not None and str(current["value"]) == fingerprint:
        return {"roots": 0, "candidates": 0, "changed_roots": 0, "skipped": True}
    return {**sync_topology(live_conn, source), "skipped": False}


def host_from_dns_owner(root_name: str, owner: str, rrtype: str) -> str:
    root = _normalize_host(root_name)
    text = str(owner or "").strip().lower().rstrip(".")
    record_type = str(rrtype or "").upper()
    if record_type not in DISCOVERABLE_TYPES:
        return ""
    if record_type == "TLSA":
        prefix = "_443._tcp."
        if not text.startswith(prefix):
            return ""
        text = text.removeprefix(prefix)
    if text.startswith("_"):
        return ""
    host = _normalize_host(text)
    if not root or not host:
        return ""
    if host != root and not host.endswith(f".{root}"):
        return ""
    return host


def dns_hosts_from_evidence(root_name: str, item: dict[str, Any]) -> list[str]:
    hosts: set[str] = set()
    for line in item.get("answer", []) or []:
        owner, line_type = _rr_line_owner_type(str(line))
        host = host_from_dns_owner(root_name, owner, line_type)
        if host:
            hosts.add(host)
    return sorted(hosts)


def _prepare_candidate_names(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS temp.live_candidate_names")
    conn.execute(
        """
        CREATE TEMP TABLE live_candidate_names (
          name TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    excluded_ips = sorted(EXCLUDED_BOOTSTRAP_IPS)
    placeholders = ",".join("?" for _ in excluded_ips)
    conn.execute(
        f"""
        INSERT OR IGNORE INTO live_candidate_names(name)
        SELECT name
        FROM resource_ip
        WHERE ip NOT IN ({placeholders})
        GROUP BY name
        """,
        excluded_ips,
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO live_candidate_names(name)
        SELECT name
        FROM names INDEXED BY idx_names_class
        WHERE onchain_class = 'DNSSEC_CANDIDATE'
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO live_candidate_names(name)
        SELECT name
        FROM tlsa_evidence_summary
        WHERE has_tlsa = 1
        """
    )
    provider_keys = [
        str(row["provider_key"])
        for row in conn.execute(
            "SELECT provider_key FROM provider_summary WHERE provider_type = 'external_dns'"
        )
    ]
    for provider_key in provider_keys:
        conn.execute(
            f"""
            INSERT OR IGNORE INTO live_candidate_names(name)
            SELECT name
            FROM names INDEXED BY idx_names_provider
            WHERE provider_guess = ?
              AND onchain_class IN ({ROOT_CLASSES_SQL})
            """,
            (provider_key,),
        )


def _topology_root_rows(conn: sqlite3.Connection):
    excluded = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    return conn.execute(
        f"""
        SELECT
          n.name, n.provider_guess, n.last_seen_height, rs.resource_hash,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records,
          rs.has_ds, rs.has_ns, rs.has_glue, rs.has_synth,
          COALESCE(ps.provider_type, 'unknown') AS provider_type,
          COALESCE(tes.has_tlsa, 0) AS has_tlsa,
          COALESCE(tes.tlsa_owners, '[]') AS tlsa_owners
        FROM live_candidate_names candidate
        CROSS JOIN names n ON n.name = candidate.name
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
        WHERE COALESCE(n.expired, 0) = 0
          AND n.onchain_class IN ({ROOT_CLASSES_SQL})
          AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded})
          AND {ROOT_SELECTION_SQL}
        """,
        NON_ACTIONABLE_PROVIDER_TYPES,
    )


def _root_from_row(row: sqlite3.Row) -> TopologyRoot:
    bootstrap = [
        value
        for column in ("synth4", "synth6", "glue4", "glue6")
        for value in _json_strings(row[column])
        if _is_actionable_bootstrap_ip(value)
    ]
    return TopologyRoot(
        name=_normalize_host(row["name"]),
        provider_guess=str(row["provider_guess"] or "unknown/custom"),
        provider_type=str(row["provider_type"] or "unknown"),
        resource_hash=str(row["resource_hash"] or ""),
        last_seen_height=int(row["last_seen_height"])
        if row["last_seen_height"] is not None
        else None,
        ns_names=_json_strings(row["ns_names"]),
        bootstrap_addresses=sorted(set(bootstrap)),
        ds_records=[item for item in _json_list(row["ds_records"]) if isinstance(item, dict)],
        has_ds=bool(row["has_ds"]),
        strict_ready=bool(bootstrap),
    )


def _apex_candidate(root: TopologyRoot, *, has_tlsa: bool) -> LiveCandidate:
    if has_tlsa:
        priority = 90
    elif root.strict_ready and root.has_ds:
        priority = 70
    elif root.strict_ready:
        priority = 60
    elif root.has_ds:
        priority = 50
    elif root.provider_type == "external_dns":
        priority = 40
    else:
        priority = 30
    return LiveCandidate(
        root_name=root.name,
        host=root.name,
        source="apex",
        source_detail="root apex",
        priority=priority,
        topology_resource_hash=root.resource_hash,
    )


def _dns_evidence_candidates(
    conn: sqlite3.Connection,
) -> Iterator[LiveCandidate]:
    excluded = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    for row in conn.execute(
        f"""
        SELECT de.name, de.qname, de.rrtype, de.answer_json, de.captured_at,
               rs.resource_hash
        FROM live_candidate_names candidate
        CROSS JOIN names n ON n.name = candidate.name
        JOIN dns_evidence de ON de.name = n.name
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
        WHERE COALESCE(n.expired, 0) = 0
          AND LOWER(de.status) = 'ok'
          AND (
            de.rcode IS NULL OR TRIM(de.rcode) = '' OR UPPER(de.rcode) = 'NOERROR'
          )
          AND n.onchain_class IN ({ROOT_CLASSES_SQL})
          AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded})
          AND {ROOT_SELECTION_SQL}
        """,
        NON_ACTIONABLE_PROVIDER_TYPES,
    ):
        root_name = _normalize_host(row["name"])
        if not root_name:
            continue
        item = {
            "qname": row["qname"],
            "rrtype": row["rrtype"],
            "answer": _json_list(row["answer_json"]),
        }
        for host in dns_hosts_from_evidence(root_name, item):
            if host == root_name:
                continue
            yield LiveCandidate(
                root_name=root_name,
                host=host,
                source="dns_evidence",
                source_detail=f"{row['rrtype']} {row['qname']}",
                priority=80,
                topology_resource_hash=str(row["resource_hash"] or ""),
            )


def _rr_line_owner_type(line: str) -> tuple[str, str]:
    tokens = line.strip().split()
    if len(tokens) < 3:
        return "", ""
    owner = tokens[0]
    upper = [token.upper() for token in tokens]
    try:
        class_index = upper.index("IN")
    except ValueError:
        return "", ""
    if class_index + 1 >= len(tokens):
        return "", ""
    return owner, upper[class_index + 1]


def _require_topology_tables(conn: sqlite3.Connection) -> None:
    required = {
        "snapshot_meta",
        "names",
        "resource_summary",
        "provider_summary",
        "resource_ip",
        "dns_evidence",
        "tlsa_evidence_summary",
    }
    available = {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    missing = sorted(required - available)
    if missing:
        raise RuntimeError(f"topology database is missing tables: {', '.join(missing)}")


def _read_topology_meta(source: Path) -> dict[str, str]:
    if not source.is_file():
        raise FileNotFoundError(f"topology database does not exist: {source}")
    uri = f"file:{source.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        available = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if "snapshot_meta" not in available:
            raise RuntimeError("topology database is missing table: snapshot_meta")
        return {
            str(row["key"]): str(row["value"])
            for row in conn.execute("SELECT key, value FROM snapshot_meta")
        }


def _topology_fingerprint(meta: dict[str, Any], source: Path) -> str:
    values = (
        str(source.resolve()),
        str(meta.get("last_indexed_tip_hash") or ""),
        str(meta.get("last_indexed_height") or ""),
        str(meta.get("provider_rules_hash") or ""),
        str(meta.get("generated_at") or ""),
    )
    return "|".join(values)


def _normalize_host(value: Any) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host or len(host) > 253 or not HOST_RE.fullmatch(host):
        return ""
    return host


def _json_strings(value: str | None) -> list[str]:
    return [
        str(item).strip().lower().rstrip(".") for item in _json_list(value) if str(item).strip()
    ]


def _json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _is_actionable_bootstrap_ip(value: str) -> bool:
    if not _is_public_ip(value):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(address) not in EXCLUDED_BOOTSTRAP_IPS
