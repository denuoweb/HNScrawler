from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json
from .live_models import (
    ONLINE_CATEGORIES,
    HostProbeResult,
    LiveCandidate,
    TopologyRoot,
)
from .timeutil import utc_now

LIVE_SCHEMA_VERSION = "1"

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS live_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roots (
  name TEXT PRIMARY KEY,
  provider_guess TEXT NOT NULL,
  provider_type TEXT NOT NULL,
  resource_hash TEXT NOT NULL,
  last_seen_height INTEGER,
  ns_names_json TEXT NOT NULL DEFAULT '[]',
  bootstrap_addresses_json TEXT NOT NULL DEFAULT '[]',
  ds_records_json TEXT NOT NULL DEFAULT '[]',
  has_ds INTEGER NOT NULL DEFAULT 0,
  strict_ready INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  topology_updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  root_name TEXT NOT NULL,
  host TEXT NOT NULL,
  sources_json TEXT NOT NULL DEFAULT '[]',
  source_details_json TEXT NOT NULL DEFAULT '[]',
  priority INTEGER NOT NULL DEFAULT 0,
  topology_resource_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  suppressed INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY(root_name, host),
  FOREIGN KEY(root_name) REFERENCES roots(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_status (
  root_name TEXT NOT NULL,
  host TEXT NOT NULL,
  topology_resource_hash TEXT NOT NULL,
  category TEXT NOT NULL,
  listing_state TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  dns_status TEXT NOT NULL,
  addresses_json TEXT NOT NULL DEFAULT '[]',
  dnssec_status TEXT NOT NULL,
  tlsa_status TEXT NOT NULL,
  tlsa_records_json TEXT NOT NULL DEFAULT '[]',
  dane_status TEXT NOT NULL,
  http_status TEXT NOT NULL,
  http_status_code INTEGER,
  http_location TEXT,
  https_status TEXT NOT NULL,
  https_status_code INTEGER,
  https_location TEXT,
  webpki_status TEXT NOT NULL,
  certificate_sha256 TEXT,
  spki_sha256 TEXT,
  certificate_not_valid_after TEXT,
  failure_reason TEXT,
  checked_at TEXT NOT NULL,
  next_check_at TEXT NOT NULL,
  first_online_at TEXT,
  last_online_at TEXT,
  last_good_category TEXT,
  last_good_url TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(root_name, host),
  FOREIGN KEY(root_name, host) REFERENCES candidates(root_name, host) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS probe_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  candidate_count INTEGER NOT NULL DEFAULT 0,
  checked_count INTEGER NOT NULL DEFAULT 0,
  online_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  concurrency INTEGER NOT NULL,
  min_delay_ms INTEGER NOT NULL,
  timeout_seconds REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_roots_active ON roots(active, strict_ready, name);
CREATE INDEX IF NOT EXISTS idx_candidates_active_priority
  ON candidates(active, suppressed, priority DESC, host);
CREATE INDEX IF NOT EXISTS idx_host_status_due ON host_status(next_check_at, listing_state);
CREATE INDEX IF NOT EXISTS idx_host_status_category ON host_status(category, listing_state, host);
"""


def connect_live(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_live_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.execute("UPDATE host_status SET listing_state = 'unlisted' WHERE listing_state = 'repair'")
    set_live_meta(conn, "schema_version", LIVE_SCHEMA_VERSION)
    conn.commit()


def set_live_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    text = value if isinstance(value, str) else dumps_json(value)
    conn.execute(
        "INSERT INTO live_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, text),
    )


def get_live_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM live_meta WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def begin_topology_sync(conn: sqlite3.Connection) -> None:
    conn.execute("UPDATE roots SET active = 0")
    conn.execute("UPDATE candidates SET active = 0")


def upsert_root(conn: sqlite3.Connection, root: TopologyRoot, *, synced_at: str) -> bool:
    previous = conn.execute(
        "SELECT resource_hash FROM roots WHERE name = ?",
        (root.name,),
    ).fetchone()
    changed = previous is not None and previous["resource_hash"] != root.resource_hash
    conn.execute(
        """
        INSERT INTO roots(
          name, provider_guess, provider_type, resource_hash, last_seen_height,
          ns_names_json, bootstrap_addresses_json, ds_records_json, has_ds,
          strict_ready, active, topology_updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(name) DO UPDATE SET
          provider_guess=excluded.provider_guess,
          provider_type=excluded.provider_type,
          resource_hash=excluded.resource_hash,
          last_seen_height=excluded.last_seen_height,
          ns_names_json=excluded.ns_names_json,
          bootstrap_addresses_json=excluded.bootstrap_addresses_json,
          ds_records_json=excluded.ds_records_json,
          has_ds=excluded.has_ds,
          strict_ready=excluded.strict_ready,
          active=1,
          topology_updated_at=excluded.topology_updated_at
        """,
        (
            root.name,
            root.provider_guess,
            root.provider_type,
            root.resource_hash,
            root.last_seen_height,
            dumps_json(root.ns_names),
            dumps_json(root.bootstrap_addresses),
            dumps_json(root.ds_records),
            int(root.has_ds),
            int(root.strict_ready),
            synced_at,
        ),
    )
    return changed


def finish_topology_sync(
    conn: sqlite3.Connection,
    *,
    synced_at: str,
    discovered_retention_days: int = 90,
) -> None:
    retained_after = _before(synced_at, days=max(0, discovered_retention_days))
    conn.execute(
        """
        UPDATE candidates AS c
        SET
          active = 1,
          topology_resource_hash = (
            SELECT r.resource_hash FROM roots r WHERE r.name = c.root_name
          )
        WHERE c.active = 0
          AND c.last_seen_at >= ?
          AND EXISTS (
            SELECT 1 FROM json_each(c.sources_json) source
            WHERE source.value = 'probe_dns'
          )
          AND EXISTS (
            SELECT 1 FROM roots r WHERE r.name = c.root_name AND r.active = 1
          )
        """,
        (retained_after,),
    )


def upsert_candidate(
    conn: sqlite3.Connection,
    candidate: LiveCandidate,
    *,
    seen_at: str | None = None,
) -> None:
    now = seen_at or utc_now()
    row = conn.execute(
        """
        SELECT sources_json, source_details_json, priority, topology_resource_hash
        FROM candidates
        WHERE root_name = ? AND host = ?
        """,
        (candidate.root_name, candidate.host),
    ).fetchone()
    sources = _json_strings(row["sources_json"] if row else None)
    details = _json_strings(row["source_details_json"] if row else None)
    if candidate.source not in sources:
        sources.append(candidate.source)
    if candidate.source_detail and candidate.source_detail not in details:
        details.append(candidate.source_detail)
    priority = max(int(row["priority"] or 0) if row else 0, candidate.priority)
    conn.execute(
        """
        INSERT INTO candidates(
          root_name, host, sources_json, source_details_json, priority,
          topology_resource_hash, active, first_seen_at, last_seen_at
        ) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(root_name, host) DO UPDATE SET
          sources_json=excluded.sources_json,
          source_details_json=excluded.source_details_json,
          priority=excluded.priority,
          topology_resource_hash=excluded.topology_resource_hash,
          active=1,
          last_seen_at=excluded.last_seen_at
        """,
        (
            candidate.root_name,
            candidate.host,
            dumps_json(sorted(sources)),
            dumps_json(sorted(details)),
            priority,
            candidate.topology_resource_hash,
            now,
            now,
        ),
    )


def select_due_candidates(
    conn: sqlite3.Connection,
    *,
    limit: int | None,
    now: str | None = None,
) -> list[dict[str, Any]]:
    checked_at = now or utc_now()
    sql = """
      WITH sync_meta AS (
        SELECT COALESCE(
          (SELECT value FROM live_meta WHERE key = 'topology_synced_at'),
          ''
        ) AS topology_synced_at
      ), due AS (
        SELECT
          c.root_name, c.host, c.sources_json, c.source_details_json, c.priority,
          c.topology_resource_hash, c.first_seen_at,
          r.provider_guess, r.provider_type, r.resource_hash, r.last_seen_height,
          r.ns_names_json, r.bootstrap_addresses_json, r.ds_records_json,
          r.has_ds, r.strict_ready,
          hs.category AS previous_category,
          hs.listing_state AS previous_listing_state,
          hs.next_check_at AS previous_next_check_at,
          hs.last_good_category,
          hs.consecutive_failures,
          CASE
            WHEN hs.host IS NOT NULL AND hs.topology_resource_hash != c.topology_resource_hash THEN 0
            WHEN hs.host IS NULL AND c.first_seen_at >= sync_meta.topology_synced_at THEN 0
            WHEN hs.last_good_category IN ('https', 'http_only') THEN 1
            WHEN hs.host IS NULL THEN 2
            ELSE 3
          END AS queue_tier,
          COALESCE(hs.next_check_at, c.first_seen_at) AS due_at
        FROM candidates c
        JOIN roots r ON r.name = c.root_name
        LEFT JOIN host_status hs ON hs.root_name = c.root_name AND hs.host = c.host
        CROSS JOIN sync_meta
        WHERE c.active = 1
          AND r.active = 1
          AND c.suppressed = 0
          AND (
            hs.host IS NULL
            OR hs.topology_resource_hash != c.topology_resource_hash
            OR hs.next_check_at <= ?
          )
      ), ranked AS (
        SELECT
          due.*,
          row_number() OVER (
            PARTITION BY provider_guess, queue_tier
            ORDER BY due_at, priority DESC, host
          ) AS provider_rank
        FROM due
      )
      SELECT *
      FROM ranked
      ORDER BY queue_tier, provider_rank, priority DESC, due_at, host
    """
    params: list[Any] = [checked_at]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(max(0, limit))
    return [_candidate_row(row) for row in conn.execute(sql, params)]


def candidate_plan(conn: sqlite3.Connection, *, now: str | None = None) -> dict[str, int]:
    checked_at = now or utc_now()
    row = conn.execute(
        """
        WITH sync_meta AS (
          SELECT COALESCE(
            (SELECT value FROM live_meta WHERE key = 'topology_synced_at'),
            ''
          ) AS topology_synced_at
        )
        SELECT
          COUNT(*) AS active,
          SUM(CASE WHEN hs.host IS NULL
                        OR hs.topology_resource_hash != c.topology_resource_hash
                        OR hs.next_check_at <= ?
                   THEN 1 ELSE 0 END) AS due_total,
          SUM(CASE WHEN hs.host IS NULL THEN 1 ELSE 0 END) AS never_checked,
          SUM(CASE WHEN hs.host IS NULL
                        AND c.first_seen_at >= sync_meta.topology_synced_at
                   THEN 1 ELSE 0 END) AS topology_new,
          SUM(CASE WHEN hs.host IS NOT NULL AND hs.topology_resource_hash != c.topology_resource_hash
                   THEN 1 ELSE 0 END) AS topology_changed,
          SUM(CASE WHEN hs.topology_resource_hash = c.topology_resource_hash
                        AND hs.next_check_at <= ?
                        AND hs.last_good_category IN ('https', 'http_only')
                   THEN 1 ELSE 0 END) AS online_due,
          SUM(CASE WHEN hs.topology_resource_hash = c.topology_resource_hash
                        AND hs.next_check_at <= ?
                        AND hs.last_good_category IS NULL
                   THEN 1 ELSE 0 END) AS retry_due
        FROM candidates c
        JOIN roots r ON r.name = c.root_name
        LEFT JOIN host_status hs ON hs.root_name = c.root_name AND hs.host = c.host
        CROSS JOIN sync_meta
        WHERE c.active = 1 AND r.active = 1 AND c.suppressed = 0
        """,
        (checked_at, checked_at, checked_at),
    ).fetchone()
    return {key: int(value or 0) for key, value in dict(row).items()}


def begin_probe_run(
    conn: sqlite3.Connection,
    *,
    candidate_count: int,
    concurrency: int,
    min_delay_ms: int,
    timeout_seconds: float,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO probe_runs(
          started_at, candidate_count, concurrency, min_delay_ms, timeout_seconds
        ) VALUES(?, ?, ?, ?, ?)
        """,
        (utc_now(), candidate_count, concurrency, min_delay_ms, timeout_seconds),
    )
    return int(cursor.lastrowid)


def finish_probe_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    checked_count: int,
    online_count: int,
    error_count: int,
    status: str = "complete",
) -> None:
    conn.execute(
        """
        UPDATE probe_runs
        SET finished_at = ?, checked_count = ?, online_count = ?, error_count = ?, status = ?
        WHERE id = ?
        """,
        (utc_now(), checked_count, online_count, error_count, status, run_id),
    )


def store_probe_result(conn: sqlite3.Connection, result: HostProbeResult) -> None:
    previous = conn.execute(
        "SELECT * FROM host_status WHERE root_name = ? AND host = ?",
        (result.root_name, result.host),
    ).fetchone()
    previous_dict = dict(previous) if previous is not None else {}
    state = _listing_state(result, previous_dict)
    conn.execute(
        """
        INSERT INTO host_status(
          root_name, host, topology_resource_hash, category, listing_state, canonical_url,
          dns_status, addresses_json, dnssec_status, tlsa_status, tlsa_records_json,
          dane_status, http_status, http_status_code, http_location, https_status,
          https_status_code, https_location, webpki_status, certificate_sha256,
          spki_sha256, certificate_not_valid_after, failure_reason, checked_at,
          next_check_at, first_online_at, last_online_at, last_good_category,
          last_good_url, consecutive_failures, duration_ms
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(root_name, host) DO UPDATE SET
          topology_resource_hash=excluded.topology_resource_hash,
          category=excluded.category,
          listing_state=excluded.listing_state,
          canonical_url=excluded.canonical_url,
          dns_status=excluded.dns_status,
          addresses_json=excluded.addresses_json,
          dnssec_status=excluded.dnssec_status,
          tlsa_status=excluded.tlsa_status,
          tlsa_records_json=excluded.tlsa_records_json,
          dane_status=excluded.dane_status,
          http_status=excluded.http_status,
          http_status_code=excluded.http_status_code,
          http_location=excluded.http_location,
          https_status=excluded.https_status,
          https_status_code=excluded.https_status_code,
          https_location=excluded.https_location,
          webpki_status=excluded.webpki_status,
          certificate_sha256=excluded.certificate_sha256,
          spki_sha256=excluded.spki_sha256,
          certificate_not_valid_after=excluded.certificate_not_valid_after,
          failure_reason=excluded.failure_reason,
          checked_at=excluded.checked_at,
          next_check_at=excluded.next_check_at,
          first_online_at=excluded.first_online_at,
          last_online_at=excluded.last_online_at,
          last_good_category=excluded.last_good_category,
          last_good_url=excluded.last_good_url,
          consecutive_failures=excluded.consecutive_failures,
          duration_ms=excluded.duration_ms
        """,
        (
            result.root_name,
            result.host,
            result.topology_resource_hash,
            result.category,
            state["listing_state"],
            result.canonical_url,
            result.dns_status,
            dumps_json(result.addresses),
            result.dnssec_status,
            result.tlsa_status,
            dumps_json(result.tlsa_records),
            result.dane_status,
            result.http_status,
            result.http_status_code,
            result.http_location,
            result.https_status,
            result.https_status_code,
            result.https_location,
            result.webpki_status,
            result.certificate_sha256,
            result.spki_sha256,
            result.certificate_not_valid_after,
            result.failure_reason,
            result.checked_at,
            state["next_check_at"],
            state["first_online_at"],
            state["last_online_at"],
            state["last_good_category"],
            state["last_good_url"],
            state["consecutive_failures"],
            result.duration_ms,
        ),
    )


def live_summary_counts(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute(
        """
        SELECT
          COUNT(*) AS checked,
          SUM(CASE WHEN hs.listing_state IN ('listed', 'degraded') AND hs.last_good_category = 'https'
                   THEN 1 ELSE 0 END) AS https,
          SUM(CASE WHEN hs.listing_state IN ('listed', 'degraded') AND hs.last_good_category = 'http_only'
                   THEN 1 ELSE 0 END) AS http_only,
          SUM(CASE WHEN hs.listing_state = 'degraded' THEN 1 ELSE 0 END) AS degraded,
          SUM(CASE WHEN hs.listing_state = 'unlisted' THEN 1 ELSE 0 END) AS offline
        FROM host_status hs
        JOIN candidates c ON c.root_name = hs.root_name AND c.host = hs.host
        JOIN roots r ON r.name = hs.root_name
        WHERE c.active = 1 AND r.active = 1
          AND hs.topology_resource_hash = c.topology_resource_hash
        """
    ).fetchone()
    return {key: int(value or 0) for key, value in dict(row).items()}


def live_dane_evidence_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM roots WHERE active = 1) AS active_roots,
          COUNT(DISTINCT hs.root_name) AS checked_roots,
          COUNT(DISTINCT CASE
            WHEN r.has_ds = 1
             AND hs.dnssec_status = 'valid'
             AND hs.tlsa_status = 'present_secure'
            THEN hs.root_name
          END) AS observed_roots,
          MAX(hs.checked_at) AS last_checked_at
        FROM host_status hs
        JOIN candidates c ON c.root_name = hs.root_name AND c.host = hs.host
        JOIN roots r ON r.name = hs.root_name
        WHERE c.active = 1 AND r.active = 1
          AND hs.topology_resource_hash = c.topology_resource_hash
        """
    ).fetchone()
    values = dict(row)
    return {
        "active_roots": int(values["active_roots"] or 0),
        "checked_roots": int(values["checked_roots"] or 0),
        "observed_roots": int(values["observed_roots"] or 0),
        "last_checked_at": str(values["last_checked_at"] or ""),
    }


def directory_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
          hs.*, c.sources_json, c.source_details_json, c.priority,
          r.provider_guess, r.provider_type, r.last_seen_height
        FROM host_status hs
        JOIN candidates c ON c.root_name = hs.root_name AND c.host = hs.host
        JOIN roots r ON r.name = hs.root_name
        WHERE c.active = 1 AND r.active = 1
          AND hs.topology_resource_hash = c.topology_resource_hash
          AND hs.listing_state IN ('listed', 'degraded', 'unlisted')
        ORDER BY
          CASE
            WHEN hs.listing_state IN ('listed', 'degraded') AND hs.last_good_category = 'https' THEN 0
            WHEN hs.listing_state IN ('listed', 'degraded') AND hs.last_good_category = 'http_only' THEN 1
            ELSE 2
          END,
          hs.host
        """
    )
    return [_directory_row(row) for row in rows]


def latest_probe_run(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM probe_runs ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else {}


def _candidate_row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    for key in (
        "sources_json",
        "source_details_json",
        "ns_names_json",
        "bootstrap_addresses_json",
        "ds_records_json",
    ):
        result[key.removesuffix("_json")] = _json_value(result.pop(key), [])
    result["has_ds"] = bool(result["has_ds"])
    result["strict_ready"] = bool(result["strict_ready"])
    return result


def _listing_state(result: HostProbeResult, previous: dict[str, Any]) -> dict[str, Any]:
    first_online_at = previous.get("first_online_at")
    last_online_at = previous.get("last_online_at")
    last_good_category = previous.get("last_good_category")
    last_good_url = previous.get("last_good_url")
    failures = int(previous.get("consecutive_failures") or 0)

    if result.category in ONLINE_CATEGORIES:
        return {
            "listing_state": "listed",
            "next_check_at": _after(result.checked_at, days=7),
            "first_online_at": first_online_at or result.checked_at,
            "last_online_at": result.checked_at,
            "last_good_category": result.category,
            "last_good_url": result.canonical_url,
            "consecutive_failures": 0,
        }
    failures += 1
    degraded = bool(last_good_category) and failures < 2
    backoff_days = 1 if degraded else min(90, 7 * (2 ** max(0, failures - 2)))
    return {
        "listing_state": "degraded" if degraded else "unlisted",
        "next_check_at": _after(result.checked_at, days=backoff_days),
        "first_online_at": first_online_at,
        "last_online_at": last_online_at,
        "last_good_category": last_good_category,
        "last_good_url": last_good_url,
        "consecutive_failures": failures,
    }


def _directory_row(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    listed = value["listing_state"] in {"listed", "degraded"}
    category = value["last_good_category"] if listed else "offline"
    canonical_url = value["last_good_url"] if listed else value["canonical_url"]
    return {
        "root_name": value["root_name"],
        "host": value["host"],
        "category": category,
        "listing_state": value["listing_state"],
        "url": canonical_url,
        "provider_guess": value["provider_guess"],
        "provider_type": value["provider_type"],
        "sources": _json_strings(value["sources_json"]),
        "priority": int(value["priority"] or 0),
        "dns_status": value["dns_status"],
        "addresses": _json_value(value["addresses_json"], []),
        "dnssec_status": value["dnssec_status"],
        "tlsa_status": value["tlsa_status"],
        "dane_status": value["dane_status"],
        "http_status": value["http_status"],
        "http_status_code": value["http_status_code"],
        "http_location": value["http_location"] or "",
        "https_status": value["https_status"],
        "https_status_code": value["https_status_code"],
        "https_location": value["https_location"] or "",
        "webpki_status": value["webpki_status"],
        "certificate_not_valid_after": value["certificate_not_valid_after"] or "",
        "failure_reason": value["failure_reason"] or "",
        "checked_at": value["checked_at"],
        "last_online_at": value["last_online_at"] or "",
        "consecutive_failures": int(value["consecutive_failures"] or 0),
        "last_seen_height": value["last_seen_height"],
    }


def _after(timestamp: str, *, days: int) -> str:
    instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return (
        (instant + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _before(timestamp: str, *, days: int) -> str:
    instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return (
        (instant - timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _json_strings(value: str | None) -> list[str]:
    parsed = _json_value(value, [])
    return [str(item) for item in parsed if item]


def _json_value(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def upsert_discovered_hosts(
    conn: sqlite3.Connection,
    *,
    root_name: str,
    hosts: Iterable[str],
    topology_resource_hash: str,
    source_detail: str,
) -> int:
    count = 0
    for host in sorted(set(hosts)):
        if host == root_name:
            continue
        upsert_candidate(
            conn,
            LiveCandidate(
                root_name=root_name,
                host=host,
                source="probe_dns",
                source_detail=source_detail,
                priority=75,
                topology_resource_hash=topology_resource_hash,
            ),
        )
        count += 1
    return count
