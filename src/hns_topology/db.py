from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json, loads_json_list
from .models import DnsEvidence, LiveStatus, NameRecord, ResourceSummary

RESOURCE_IP_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS resource_ip (
  name TEXT NOT NULL,
  ip TEXT NOT NULL,
  field TEXT NOT NULL,
  PRIMARY KEY(name, ip, field),
  FOREIGN KEY(name) REFERENCES resource_summary(name) ON DELETE CASCADE
) WITHOUT ROWID;
"""

RESOURCE_IP_LOOKUP_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_resource_ip_ip_name ON resource_ip(ip, name);
"""

SCHEMA_SQL = f"""
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS snapshot_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS names (
  name TEXT PRIMARY KEY,
  name_hash TEXT NOT NULL,
  state TEXT,
  renewal_height INTEGER,
  expired INTEGER DEFAULT 0,
  resource_hash TEXT,
  record_types TEXT,
  onchain_class TEXT,
  provider_guess TEXT,
  last_seen_height INTEGER,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS resource_summary (
  name TEXT PRIMARY KEY,
  ns_names TEXT,
  glue4 TEXT,
  glue6 TEXT,
  synth4 TEXT,
  synth6 TEXT,
  ds_records TEXT,
  has_ds INTEGER DEFAULT 0,
  has_ns INTEGER DEFAULT 0,
  has_glue INTEGER DEFAULT 0,
  has_synth INTEGER DEFAULT 0,
  has_txt INTEGER DEFAULT 0,
  raw_size INTEGER,
  resource_version INTEGER,
  resource_hash TEXT,
  FOREIGN KEY(name) REFERENCES names(name) ON DELETE CASCADE
);

{RESOURCE_IP_TABLE_SQL}

CREATE TABLE IF NOT EXISTS live_status (
  name TEXT PRIMARY KEY,
  dns_reachable TEXT,
  dnssec_status TEXT,
  tlsa_status TEXT,
  dane_status TEXT,
  https_status TEXT,
  strict_hns_status TEXT,
  doh_fallback_status TEXT,
  failure_reason TEXT,
  checked_at TEXT,
  next_check_at TEXT,
  FOREIGN KEY(name) REFERENCES names(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS provider_summary (
  provider_key TEXT PRIMARY KEY,
  provider_type TEXT,
  ns_pattern TEXT,
  ip_pattern TEXT,
  names_count INTEGER,
  likely_website_count INTEGER,
  working_count INTEGER,
  dane_count INTEGER,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS dns_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  qname TEXT NOT NULL,
  rrtype TEXT NOT NULL,
  server TEXT,
  source TEXT NOT NULL DEFAULT 'scanner',
  source_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  rcode TEXT,
  flags TEXT,
  answer_json TEXT NOT NULL DEFAULT '[]',
  authority_json TEXT NOT NULL DEFAULT '[]',
  additional_json TEXT NOT NULL DEFAULT '[]',
  elapsed_ms INTEGER,
  error TEXT,
  captured_at TEXT NOT NULL,
  FOREIGN KEY(name) REFERENCES names(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS block_history (
  height INTEGER PRIMARY KEY,
  block_hash TEXT NOT NULL,
  changed_names TEXT NOT NULL,
  indexed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS changed_name_rollbacks (
  height INTEGER NOT NULL,
  name TEXT NOT NULL,
  previous_resource_hash TEXT,
  previous_classification TEXT,
  previous_live_status TEXT,
  previous_name_row TEXT,
  previous_resource_summary TEXT,
  block_hash_at_height TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  PRIMARY KEY(height, name)
);
"""

CORE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_names_class ON names(onchain_class);
CREATE INDEX IF NOT EXISTS idx_names_provider ON names(provider_guess);
CREATE INDEX IF NOT EXISTS idx_names_expired ON names(expired);
CREATE INDEX IF NOT EXISTS idx_live_failure ON live_status(failure_reason);
CREATE INDEX IF NOT EXISTS idx_live_next_check ON live_status(next_check_at);
CREATE INDEX IF NOT EXISTS idx_dns_evidence_name_captured ON dns_evidence(name, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_evidence_query_captured ON dns_evidence(name, qname, rrtype, captured_at DESC);
"""

NAMES_COLUMNS = (
    "name",
    "name_hash",
    "state",
    "renewal_height",
    "expired",
    "resource_hash",
    "record_types",
    "onchain_class",
    "provider_guess",
    "last_seen_height",
    "updated_at",
)

RESOURCE_COLUMNS = (
    "name",
    "ns_names",
    "glue4",
    "glue6",
    "synth4",
    "synth6",
    "ds_records",
    "has_ds",
    "has_ns",
    "has_glue",
    "has_synth",
    "has_txt",
    "raw_size",
    "resource_version",
    "resource_hash",
)

RESOURCE_COLUMN_INDEX = {column: index for index, column in enumerate(RESOURCE_COLUMNS)}
RESOURCE_IP_FIELDS = (
    ("GLUE4", "glue4"),
    ("GLUE6", "glue6"),
    ("SYNTH4", "synth4"),
    ("SYNTH6", "synth6"),
)
RESOURCE_IP_INDEX_META_KEY = "resource_ip_index_version"
RESOURCE_IP_INDEX_VERSION = "2"

LIVE_COLUMNS = (
    "name",
    "dns_reachable",
    "dnssec_status",
    "tlsa_status",
    "dane_status",
    "https_status",
    "strict_hns_status",
    "doh_fallback_status",
    "failure_reason",
    "checked_at",
    "next_check_at",
)

DNS_EVIDENCE_COLUMNS = (
    "name",
    "qname",
    "rrtype",
    "server",
    "source",
    "source_id",
    "status",
    "rcode",
    "flags",
    "answer_json",
    "authority_json",
    "additional_json",
    "elapsed_ms",
    "error",
    "captured_at",
)


def _insert_sql(table: str, columns: tuple[str, ...]) -> str:
    column_sql = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    return f"INSERT INTO {table}({column_sql}) VALUES({placeholders})"


def _upsert_sql(table: str, columns: tuple[str, ...], *, conflict_column: str = "name") -> str:
    column_sql = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    assignments = ", ".join(
        f"{column}=excluded.{column}" for column in columns if column != conflict_column
    )
    return (
        f"INSERT INTO {table}({column_sql}) VALUES({placeholders}) "
        f"ON CONFLICT({conflict_column}) DO UPDATE SET {assignments}"
    )


SCHEMA_COLUMN_MIGRATIONS = {
    "names": {
        "name_hash": "TEXT NOT NULL DEFAULT ''",
        "state": "TEXT",
        "renewal_height": "INTEGER",
        "expired": "INTEGER DEFAULT 0",
        "resource_hash": "TEXT",
        "record_types": "TEXT",
        "onchain_class": "TEXT",
        "provider_guess": "TEXT",
        "last_seen_height": "INTEGER",
        "updated_at": "TEXT",
    },
    "resource_summary": {
        "ns_names": "TEXT",
        "glue4": "TEXT",
        "glue6": "TEXT",
        "synth4": "TEXT",
        "synth6": "TEXT",
        "ds_records": "TEXT",
        "has_ds": "INTEGER DEFAULT 0",
        "has_ns": "INTEGER DEFAULT 0",
        "has_glue": "INTEGER DEFAULT 0",
        "has_synth": "INTEGER DEFAULT 0",
        "has_txt": "INTEGER DEFAULT 0",
        "raw_size": "INTEGER",
        "resource_version": "INTEGER",
        "resource_hash": "TEXT",
    },
    "live_status": {
        "dns_reachable": "TEXT",
        "dnssec_status": "TEXT",
        "tlsa_status": "TEXT",
        "dane_status": "TEXT",
        "https_status": "TEXT",
        "strict_hns_status": "TEXT",
        "doh_fallback_status": "TEXT",
        "failure_reason": "TEXT",
        "checked_at": "TEXT",
        "next_check_at": "TEXT",
    },
    "provider_summary": {
        "provider_type": "TEXT",
        "ns_pattern": "TEXT",
        "ip_pattern": "TEXT",
        "names_count": "INTEGER",
        "likely_website_count": "INTEGER",
        "working_count": "INTEGER",
        "dane_count": "INTEGER",
        "updated_at": "TEXT",
    },
    "dns_evidence": {
        "qname": "TEXT",
        "rrtype": "TEXT",
        "server": "TEXT",
        "source": "TEXT NOT NULL DEFAULT 'scanner'",
        "source_id": "TEXT NOT NULL DEFAULT ''",
        "status": "TEXT NOT NULL DEFAULT 'unknown'",
        "rcode": "TEXT",
        "flags": "TEXT",
        "answer_json": "TEXT NOT NULL DEFAULT '[]'",
        "authority_json": "TEXT NOT NULL DEFAULT '[]'",
        "additional_json": "TEXT NOT NULL DEFAULT '[]'",
        "elapsed_ms": "INTEGER",
        "error": "TEXT",
        "captured_at": "TEXT",
    },
    "changed_name_rollbacks": {
        "previous_resource_hash": "TEXT",
        "previous_classification": "TEXT",
        "previous_live_status": "TEXT",
        "previous_name_row": "TEXT",
        "previous_resource_summary": "TEXT",
        "block_hash_at_height": "TEXT NOT NULL DEFAULT ''",
        "captured_at": "TEXT",
    },
}

JSON_ARRAY_DEFAULT_COLUMNS = {
    "names": ("record_types",),
    "resource_summary": ("ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"),
    "dns_evidence": ("answer_json", "authority_json", "additional_json"),
}

UPSERT_NAME_SQL = _upsert_sql("names", NAMES_COLUMNS)
UPSERT_RESOURCE_SQL = _upsert_sql("resource_summary", RESOURCE_COLUMNS)
UPSERT_LIVE_SQL = _upsert_sql("live_status", LIVE_COLUMNS)
INSERT_DNS_EVIDENCE_SQL = _insert_sql("dns_evidence", DNS_EVIDENCE_COLUMNS)


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    _migrate_schema(conn)
    conn.executescript(CORE_INDEX_SQL)
    conn.commit()


def set_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    if not isinstance(value, str):
        value = dumps_json(value)
    conn.execute(
        "INSERT INTO snapshot_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM snapshot_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def upsert_name(conn: sqlite3.Connection, record: NameRecord) -> None:
    conn.execute(UPSERT_NAME_SQL, _name_params(record))


def upsert_names(conn: sqlite3.Connection, records: Iterable[NameRecord]) -> None:
    conn.executemany(UPSERT_NAME_SQL, (_name_params(record) for record in records))


def upsert_name_rows(conn: sqlite3.Connection, rows: Iterable[tuple[Any, ...]]) -> None:
    conn.executemany(UPSERT_NAME_SQL, rows)


def upsert_resource(conn: sqlite3.Connection, summary: ResourceSummary) -> None:
    params = _resource_params(summary)
    conn.execute(UPSERT_RESOURCE_SQL, params)
    _replace_resource_ip_rows(conn, params)


def upsert_resources(conn: sqlite3.Connection, summaries: Iterable[ResourceSummary]) -> None:
    rows = [_resource_params(summary) for summary in summaries]
    if not rows:
        return
    conn.executemany(UPSERT_RESOURCE_SQL, rows)
    _replace_resource_ip_rows_batch(conn, rows)


def upsert_resource_rows(conn: sqlite3.Connection, rows: Iterable[tuple[Any, ...]]) -> None:
    row_list = list(rows)
    if not row_list:
        return
    conn.executemany(UPSERT_RESOURCE_SQL, row_list)
    _replace_resource_ip_rows_batch(conn, row_list)


def upsert_live_status(conn: sqlite3.Connection, status: LiveStatus) -> None:
    conn.execute(UPSERT_LIVE_SQL, _live_status_params(status))


def insert_dns_evidence(conn: sqlite3.Connection, evidence: DnsEvidence) -> None:
    conn.execute(INSERT_DNS_EVIDENCE_SQL, _dns_evidence_params(evidence))


def insert_dns_evidence_batch(conn: sqlite3.Connection, evidence: Iterable[DnsEvidence]) -> None:
    conn.executemany(INSERT_DNS_EVIDENCE_SQL, (_dns_evidence_params(item) for item in evidence))


def capture_rollback(
    conn: sqlite3.Connection,
    *,
    height: int,
    name: str,
    block_hash: str,
    captured_at: str,
) -> None:
    name_row = _row_dict(conn.execute("SELECT * FROM names WHERE name = ?", (name,)).fetchone())
    resource_row = _row_dict(
        conn.execute("SELECT * FROM resource_summary WHERE name = ?", (name,)).fetchone()
    )
    live_row = _row_dict(conn.execute("SELECT * FROM live_status WHERE name = ?", (name,)).fetchone())
    if name_row is None:
        previous_live = None
        previous_resource_hash = None
        previous_classification = None
    else:
        previous_resource_hash = name_row["resource_hash"]
        previous_classification = name_row["onchain_class"]
        previous_live = live_row
    conn.execute(
        """
        INSERT OR REPLACE INTO changed_name_rollbacks(
          height, name, previous_resource_hash, previous_classification,
          previous_live_status, previous_name_row, previous_resource_summary,
          block_hash_at_height, captured_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            height,
            name,
            previous_resource_hash,
            previous_classification,
            dumps_json(previous_live) if previous_live is not None else None,
            dumps_json(name_row) if name_row is not None else None,
            dumps_json(resource_row) if resource_row is not None else None,
            block_hash,
            captured_at,
        ),
    )


def record_block_history(
    conn: sqlite3.Connection,
    *,
    height: int,
    block_hash: str,
    changed_names: Iterable[str],
    indexed_at: str,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO block_history(height, block_hash, changed_names, indexed_at)
        VALUES(?, ?, ?, ?)
        """,
        (height, block_hash, dumps_json(sorted(set(changed_names))), indexed_at),
    )


def prune_reorg_metadata(conn: sqlite3.Connection, keep_blocks: int, latest_height: int) -> None:
    min_height = max(0, latest_height - keep_blocks)
    conn.execute("DELETE FROM block_history WHERE height < ?", (min_height,))
    conn.execute("DELETE FROM changed_name_rollbacks WHERE height < ?", (min_height,))


def rollback_to_height(
    conn: sqlite3.Connection,
    *,
    rollback_height: int,
    rolled_back_at: str,
) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT *
        FROM changed_name_rollbacks
        WHERE height >= ?
        ORDER BY height DESC, name ASC
        """,
        (rollback_height,),
    ).fetchall()
    heights = sorted({int(row["height"]) for row in rows})

    for row in rows:
        name = row["name"]
        previous_name = _loads_optional_dict(row["previous_name_row"])
        previous_resource = _loads_optional_dict(row["previous_resource_summary"])
        previous_live = _loads_optional_dict(row["previous_live_status"])

        if previous_name is None:
            conn.execute("DELETE FROM names WHERE name = ?", (name,))
            continue

        _upsert_raw_row(conn, "names", NAMES_COLUMNS, previous_name)
        if previous_resource is None:
            conn.execute("DELETE FROM resource_summary WHERE name = ?", (name,))
        else:
            _upsert_raw_row(conn, "resource_summary", RESOURCE_COLUMNS, previous_resource)
            _replace_resource_ip_rows_from_mapping(conn, previous_resource)

        if previous_live is None:
            conn.execute("DELETE FROM live_status WHERE name = ?", (name,))
        else:
            previous_live.setdefault("name", name)
            _upsert_raw_row(conn, "live_status", LIVE_COLUMNS, previous_live)

    conn.execute("DELETE FROM block_history WHERE height >= ?", (rollback_height,))
    conn.execute("DELETE FROM changed_name_rollbacks WHERE height >= ?", (rollback_height,))

    remaining = conn.execute(
        "SELECT height, block_hash FROM block_history ORDER BY height DESC LIMIT 1"
    ).fetchone()
    if remaining is None:
        set_meta(conn, "last_indexed_height", str(max(0, rollback_height - 1)))
        set_meta(conn, "last_indexed_tip_hash", "")
    else:
        set_meta(conn, "last_indexed_height", str(remaining["height"]))
        set_meta(conn, "last_indexed_tip_hash", remaining["block_hash"])
    set_meta(conn, "last_reorg_rollback_at", rolled_back_at)
    set_meta(conn, "last_reorg_rollback_height", str(rollback_height))
    return {
        "rollback_height": rollback_height,
        "rolled_back_heights": heights,
        "names_restored": len(rows),
        "rolled_back_at": rolled_back_at,
    }


def recompute_provider_summary(
    conn: sqlite3.Connection,
    provider_types: dict[str, str],
    updated_at: str,
    provider_patterns: dict[str, dict[str, str]] | None = None,
) -> None:
    provider_patterns = provider_patterns or {}
    conn.execute("DELETE FROM provider_summary")
    rows = conn.execute(
        """
        SELECT
          n.provider_guess AS provider_key,
          COUNT(*) AS names_count,
          SUM(CASE
            WHEN n.expired = 0 AND (
              rs.has_synth = 1 OR
              rs.has_glue = 1 OR
              rs.has_ds = 1
            ) THEN 1 ELSE 0 END
          ) AS likely_website_count,
          SUM(CASE WHEN ls.strict_hns_status = 'working' THEN 1 ELSE 0 END) AS working_count,
          SUM(CASE WHEN ls.dane_status = 'valid' THEN 1 ELSE 0 END) AS dane_count
        FROM names n
        LEFT JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        GROUP BY n.provider_guess
        ORDER BY names_count DESC
        """
    ).fetchall()
    for row in rows:
        provider_key = row["provider_key"] or "unknown/custom"
        patterns = provider_patterns.get(provider_key, {})
        conn.execute(
            """
            INSERT INTO provider_summary(
              provider_key, provider_type, ns_pattern, ip_pattern, names_count,
              likely_website_count, working_count, dane_count, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provider_key,
                provider_types.get(provider_key, "unknown"),
                patterns.get("ns_pattern", ""),
                patterns.get("ip_pattern", ""),
                int(row["names_count"] or 0),
                int(row["likely_website_count"] or 0),
                int(row["working_count"] or 0),
                int(row["dane_count"] or 0),
                updated_at,
            ),
        )


def backfill_resource_flags(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        """
        UPDATE resource_summary AS rs
        SET
          has_ds = CASE WHEN COALESCE(json_array_length(ds_records), 0) > 0 THEN 1 ELSE 0 END,
          has_ns = CASE WHEN COALESCE(json_array_length(ns_names), 0) > 0 THEN 1 ELSE 0 END,
          has_glue = CASE
            WHEN COALESCE(json_array_length(glue4), 0) > 0
              OR COALESCE(json_array_length(glue6), 0) > 0
            THEN 1 ELSE 0 END,
          has_synth = CASE
            WHEN COALESCE(json_array_length(synth4), 0) > 0
              OR COALESCE(json_array_length(synth6), 0) > 0
            THEN 1 ELSE 0 END,
          has_txt = CASE
            WHEN EXISTS (
              SELECT 1
              FROM names n, json_each(n.record_types) rt
              WHERE n.name = rs.name AND rt.value = 'TXT'
            )
            THEN 1 ELSE 0 END
        WHERE
          COALESCE(has_ds, -1) != CASE WHEN COALESCE(json_array_length(ds_records), 0) > 0 THEN 1 ELSE 0 END
          OR COALESCE(has_ns, -1) != CASE WHEN COALESCE(json_array_length(ns_names), 0) > 0 THEN 1 ELSE 0 END
          OR COALESCE(has_glue, -1) != CASE
              WHEN COALESCE(json_array_length(glue4), 0) > 0
                OR COALESCE(json_array_length(glue6), 0) > 0
              THEN 1 ELSE 0 END
          OR COALESCE(has_synth, -1) != CASE
              WHEN COALESCE(json_array_length(synth4), 0) > 0
                OR COALESCE(json_array_length(synth6), 0) > 0
              THEN 1 ELSE 0 END
          OR COALESCE(has_txt, -1) != CASE
              WHEN EXISTS (
                SELECT 1
                FROM names n, json_each(n.record_types) rt
                WHERE n.name = rs.name AND rt.value = 'TXT'
              )
              THEN 1 ELSE 0 END
        """
    )
    return int(cursor.rowcount if cursor.rowcount is not None else 0)


def resource_ip_index_is_current(conn: sqlite3.Connection) -> bool:
    return (
        get_meta(conn, RESOURCE_IP_INDEX_META_KEY) == RESOURCE_IP_INDEX_VERSION
        and resource_ip_lookup_index_exists(conn)
    )


def mark_resource_ip_index_current(conn: sqlite3.Connection) -> None:
    set_meta(conn, RESOURCE_IP_INDEX_META_KEY, RESOURCE_IP_INDEX_VERSION)


def ensure_resource_ip_lookup_index(conn: sqlite3.Connection) -> None:
    conn.execute(RESOURCE_IP_LOOKUP_INDEX_SQL)


def resource_ip_lookup_index_exists(conn: sqlite3.Connection) -> bool:
    return any(
        row["name"] == "idx_resource_ip_ip_name"
        for row in conn.execute("PRAGMA index_list(resource_ip)")
    )


def require_resource_ip_index(conn: sqlite3.Connection) -> None:
    if resource_ip_index_is_current(conn):
        return
    raise RuntimeError(
        "resource_ip derived index is missing or stale; run "
        "`hns-topology rebuild-resource-ip --db <path>` before exporting the site"
    )


def rebuild_resource_ip_index(
    conn: sqlite3.Connection,
    *,
    batch_size: int = 100_000,
    progress_interval: int = 500_000,
    progress: Callable[[int, int], None] | None = None,
) -> int:
    batch_size = max(1, batch_size)
    progress_interval = max(0, progress_interval)
    conn.execute("DROP INDEX IF EXISTS idx_resource_ip_ip_name")
    conn.execute("DROP TABLE IF EXISTS resource_ip")
    conn.execute(RESOURCE_IP_TABLE_SQL)

    scanned = 0
    inserted = 0
    batch: list[tuple[str, str, str]] = []

    def flush() -> None:
        nonlocal inserted
        if not batch:
            return
        conn.executemany(
            """
            INSERT INTO resource_ip(name, ip, field)
            VALUES(?, ?, ?)
            """,
            batch,
        )
        inserted += len(batch)
        batch.clear()

    rows = conn.execute(
        """
        SELECT name, glue4, glue6, synth4, synth6
        FROM resource_summary
        ORDER BY name
        """
    )
    for row in rows:
        scanned += 1
        batch.extend(_resource_ip_rows_from_mapping(row))
        if len(batch) >= batch_size:
            flush()
        if progress is not None and progress_interval and scanned % progress_interval == 0:
            progress(scanned, inserted + len(batch))

    flush()
    ensure_resource_ip_lookup_index(conn)
    mark_resource_ip_index_current(conn)
    if progress is not None:
        progress(scanned, inserted)
    return inserted


def table_count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0] if row else 0)


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def parse_json_columns(row: dict[str, Any], columns: Iterable[str]) -> dict[str, Any]:
    result = dict(row)
    for column in columns:
        value = result.get(column)
        if isinstance(value, str):
            try:
                result[column] = json.loads(value)
            except json.JSONDecodeError:
                result[column] = []
    return result


def _migrate_schema(conn: sqlite3.Connection) -> None:
    for table, columns in SCHEMA_COLUMN_MIGRATIONS.items():
        _ensure_columns(conn, table, columns)
    for table, columns in JSON_ARRAY_DEFAULT_COLUMNS.items():
        for column in columns:
            conn.execute(f"UPDATE {table} SET {column} = '[]' WHERE {column} IS NULL")
    backfill_resource_flags(conn)


def _dns_evidence_params(evidence: DnsEvidence) -> tuple[Any, ...]:
    return (
        evidence.name,
        evidence.qname,
        evidence.rrtype,
        evidence.server,
        evidence.source,
        evidence.source_id,
        evidence.status,
        evidence.rcode,
        evidence.flags,
        dumps_json(evidence.answer),
        dumps_json(evidence.authority),
        dumps_json(evidence.additional),
        evidence.elapsed_ms,
        evidence.error,
        evidence.captured_at,
    )


def _live_status_params(status: LiveStatus) -> tuple[Any, ...]:
    return (
        status.name,
        status.dns_reachable,
        status.dnssec_status,
        status.tlsa_status,
        status.dane_status,
        status.https_status,
        status.strict_hns_status,
        status.doh_fallback_status,
        status.failure_reason,
        status.checked_at,
        status.next_check_at,
    )


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for column, column_type in columns.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def _name_params(record: NameRecord) -> tuple[Any, ...]:
    return (
        record.name,
        record.name_hash,
        record.state,
        record.renewal_height,
        int(record.expired),
        record.resource_hash,
        dumps_json(record.record_types),
        record.onchain_class,
        record.provider_guess,
        record.last_seen_height,
        record.updated_at,
    )


def _resource_params(summary: ResourceSummary) -> tuple[Any, ...]:
    return (
        summary.name,
        dumps_json(summary.ns_names),
        dumps_json(summary.glue4),
        dumps_json(summary.glue6),
        dumps_json(summary.synth4),
        dumps_json(summary.synth6),
        dumps_json(summary.ds_records),
        int(summary.has_ds),
        int(summary.has_ns),
        int(summary.has_glue),
        int(summary.has_synth),
        int(summary.has_txt),
        summary.raw_size,
        summary.resource_version,
        summary.resource_hash,
    )


def _replace_resource_ip_rows_batch(conn: sqlite3.Connection, rows: Iterable[tuple[Any, ...]]) -> None:
    row_list = list(rows)
    if not row_list:
        return
    conn.executemany(
        "DELETE FROM resource_ip WHERE name = ?",
        ((row[RESOURCE_COLUMN_INDEX["name"]],) for row in row_list),
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO resource_ip(name, ip, field)
        VALUES(?, ?, ?)
        """,
        _iter_resource_ip_rows(row_list),
    )


def _replace_resource_ip_rows(conn: sqlite3.Connection, row: tuple[Any, ...]) -> None:
    _replace_resource_ip_rows_batch(conn, [row])


def _replace_resource_ip_rows_from_mapping(conn: sqlite3.Connection, row: Mapping[str, Any]) -> None:
    values = tuple(row.get(column) for column in RESOURCE_COLUMNS)
    _replace_resource_ip_rows(conn, values)


def _resource_ip_rows_from_mapping(row: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    name = str(row["name"] or "")
    if not name:
        return []
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for field, column in RESOURCE_IP_FIELDS:
        for value in _json_string_values(row[column]):
            ip = str(value).strip().lower()
            if not ip:
                continue
            item = (name, ip, field)
            if item in seen:
                continue
            seen.add(item)
            rows.append(item)
    return rows


def _iter_resource_ip_rows(rows: Iterable[tuple[Any, ...]]) -> Iterable[tuple[str, str, str]]:
    for row in rows:
        name = str(row[RESOURCE_COLUMN_INDEX["name"]] or "")
        if not name:
            continue
        for field, column in RESOURCE_IP_FIELDS:
            for value in _json_string_values(row[RESOURCE_COLUMN_INDEX[column]]):
                ip = str(value).strip().lower()
                if ip:
                    yield name, ip, field


def _json_string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        parsed = loads_json_list(value)
    elif isinstance(value, list):
        parsed = value
    else:
        parsed = []
    return [str(item) for item in parsed if item is not None]


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _loads_optional_dict(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else None


def _upsert_raw_row(
    conn: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
    values: dict[str, Any],
) -> None:
    conn.execute(_upsert_sql(table, columns), tuple(values.get(column) for column in columns))
