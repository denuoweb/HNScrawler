from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json, loads_json_list
from .models import (
    DnsEvidence,
    NameRecord,
    ResourceSummary,
)

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

TLSA_EVIDENCE_SUMMARY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS tlsa_evidence_summary (
  name TEXT PRIMARY KEY,
  has_tlsa INTEGER NOT NULL DEFAULT 0,
  tlsa_records TEXT NOT NULL DEFAULT '[]',
  tlsa_owners TEXT NOT NULL DEFAULT '[]',
  observed_at TEXT,
  checked_at TEXT,
  FOREIGN KEY(name) REFERENCES names(name) ON DELETE CASCADE
) WITHOUT ROWID;
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
  tlsa_records TEXT,
  tlsa_cert_not_valid_after TEXT,
  tlsa_cert_expired INTEGER DEFAULT 0,
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

CREATE TABLE IF NOT EXISTS provider_summary (
  provider_key TEXT PRIMARY KEY,
  provider_type TEXT,
  ns_pattern TEXT,
  ip_pattern TEXT,
  names_count INTEGER,
  likely_website_count INTEGER,
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

{TLSA_EVIDENCE_SUMMARY_TABLE_SQL}

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
CREATE INDEX IF NOT EXISTS idx_dns_evidence_name_captured ON dns_evidence(name, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_evidence_query_captured ON dns_evidence(name, qname, rrtype, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_tlsa_evidence_summary_present ON tlsa_evidence_summary(has_tlsa, name);
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
    "tlsa_records",
    "tlsa_cert_not_valid_after",
    "tlsa_cert_expired",
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
TLSA_EVIDENCE_SUMMARY_META_KEY = "tlsa_evidence_summary_version"
TLSA_EVIDENCE_SUMMARY_VERSION = "1"

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


def _upsert_sql(
    table: str,
    columns: tuple[str, ...],
    *,
    conflict_column: str | tuple[str, ...] = "name",
) -> str:
    conflict_columns = (conflict_column,) if isinstance(conflict_column, str) else conflict_column
    column_sql = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    assignments = ", ".join(
        f"{column}=excluded.{column}" for column in columns if column not in conflict_columns
    )
    conflict_sql = ", ".join(conflict_columns)
    return (
        f"INSERT INTO {table}({column_sql}) VALUES({placeholders}) "
        f"ON CONFLICT({conflict_sql}) DO UPDATE SET {assignments}"
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
        "tlsa_records": "TEXT",
        "tlsa_cert_not_valid_after": "TEXT",
        "tlsa_cert_expired": "INTEGER DEFAULT 0",
        "has_ds": "INTEGER DEFAULT 0",
        "has_ns": "INTEGER DEFAULT 0",
        "has_glue": "INTEGER DEFAULT 0",
        "has_synth": "INTEGER DEFAULT 0",
        "has_txt": "INTEGER DEFAULT 0",
        "raw_size": "INTEGER",
        "resource_version": "INTEGER",
        "resource_hash": "TEXT",
    },
    "provider_summary": {
        "provider_type": "TEXT",
        "ns_pattern": "TEXT",
        "ip_pattern": "TEXT",
        "names_count": "INTEGER",
        "likely_website_count": "INTEGER",
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
        "previous_name_row": "TEXT",
        "previous_resource_summary": "TEXT",
        "block_hash_at_height": "TEXT NOT NULL DEFAULT ''",
        "captured_at": "TEXT",
    },
}

JSON_ARRAY_DEFAULT_COLUMNS = {
    "names": ("record_types",),
    "resource_summary": (
        "ns_names",
        "glue4",
        "glue6",
        "synth4",
        "synth6",
        "ds_records",
        "tlsa_records",
    ),
    "dns_evidence": ("answer_json", "authority_json", "additional_json"),
}

OBSOLETE_TABLES = (
    "live_status",
    "host_candidates",
    "host_live_status",
    "browser_evidence",
)

OBSOLETE_COLUMNS = {
    "changed_name_rollbacks": ("previous_live_status",),
}

UPSERT_NAME_SQL = _upsert_sql("names", NAMES_COLUMNS)
UPSERT_RESOURCE_SQL = _upsert_sql("resource_summary", RESOURCE_COLUMNS)
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
    _drop_obsolete_schema(conn)
    conn.executescript(CORE_INDEX_SQL)
    _ensure_tlsa_evidence_summary_current(conn)
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


def insert_dns_evidence(conn: sqlite3.Connection, evidence: DnsEvidence) -> None:
    conn.execute(INSERT_DNS_EVIDENCE_SQL, _dns_evidence_params(evidence))
    if evidence.rrtype.upper() == "TLSA":
        refresh_tlsa_evidence_summary(conn, names=[evidence.name])


def insert_dns_evidence_batch(conn: sqlite3.Connection, evidence: Iterable[DnsEvidence]) -> None:
    items = list(evidence)
    if not items:
        return
    conn.executemany(INSERT_DNS_EVIDENCE_SQL, (_dns_evidence_params(item) for item in items))
    tlsa_names = {item.name for item in items if item.rrtype.upper() == "TLSA"}
    if tlsa_names:
        refresh_tlsa_evidence_summary(conn, names=tlsa_names)


def refresh_tlsa_evidence_summary(
    conn: sqlite3.Connection,
    *,
    names: Iterable[str] | None = None,
) -> int:
    from .tlsa_evidence import summarize_tlsa_evidence

    normalized_names = None
    if names is not None:
        normalized_names = sorted({str(name).strip().lower().rstrip(".") for name in names if name})
        if not normalized_names:
            return 0
        conn.executemany(
            "DELETE FROM tlsa_evidence_summary WHERE name = ?",
            ((name,) for name in normalized_names),
        )
        rows: list[sqlite3.Row] = []
        for offset in range(0, len(normalized_names), 500):
            name_batch = normalized_names[offset : offset + 500]
            placeholders = ",".join("?" for _ in name_batch)
            rows.extend(
                conn.execute(
                    f"""
                    SELECT de.*
                    FROM dns_evidence de
                    JOIN names n ON n.name = de.name
                    WHERE de.name IN ({placeholders}) AND upper(de.rrtype) = 'TLSA'
                    ORDER BY de.name, de.captured_at DESC, de.id DESC
                    """,
                    name_batch,
                )
            )
    else:
        conn.execute("DELETE FROM tlsa_evidence_summary")
        rows = conn.execute(
            """
            SELECT de.*
            FROM dns_evidence de
            JOIN names n ON n.name = de.name
            WHERE upper(de.rrtype) = 'TLSA'
            ORDER BY de.name, de.captured_at DESC, de.id DESC
            """
        )

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["name"]), []).append(dict(row))

    summaries = [summarize_tlsa_evidence(name, evidence_rows) for name, evidence_rows in grouped.items()]
    conn.executemany(
        """
        INSERT INTO tlsa_evidence_summary(
          name, has_tlsa, tlsa_records, tlsa_owners, observed_at, checked_at
        ) VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            (
                summary.name,
                int(summary.has_tlsa),
                dumps_json(summary.records),
                dumps_json(summary.owners),
                summary.observed_at,
                summary.checked_at,
            )
            for summary in summaries
        ),
    )
    if normalized_names is None:
        set_meta(conn, TLSA_EVIDENCE_SUMMARY_META_KEY, TLSA_EVIDENCE_SUMMARY_VERSION)
    return len(summaries)


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
    if name_row is None:
        previous_resource_hash = None
        previous_classification = None
    else:
        previous_resource_hash = name_row["resource_hash"]
        previous_classification = name_row["onchain_class"]
    conn.execute(
        """
        INSERT OR REPLACE INTO changed_name_rollbacks(
          height, name, previous_resource_hash, previous_classification,
          previous_name_row, previous_resource_summary,
          block_hash_at_height, captured_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            height,
            name,
            previous_resource_hash,
            previous_classification,
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

        if previous_name is None:
            conn.execute("DELETE FROM names WHERE name = ?", (name,))
            continue

        _upsert_raw_row(conn, "names", NAMES_COLUMNS, previous_name)
        if previous_resource is None:
            conn.execute("DELETE FROM resource_summary WHERE name = ?", (name,))
        else:
            _upsert_raw_row(conn, "resource_summary", RESOURCE_COLUMNS, previous_resource)
            _replace_resource_ip_rows_from_mapping(conn, previous_resource)

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
          ) AS likely_website_count
        FROM names n
        LEFT JOIN resource_summary rs ON rs.name = n.name
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
              likely_website_count, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provider_key,
                provider_types.get(provider_key, "unknown"),
                patterns.get("ns_pattern", ""),
                patterns.get("ip_pattern", ""),
                int(row["names_count"] or 0),
                int(row["likely_website_count"] or 0),
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


def _ensure_tlsa_evidence_summary_current(conn: sqlite3.Connection) -> None:
    if get_meta(conn, TLSA_EVIDENCE_SUMMARY_META_KEY) == TLSA_EVIDENCE_SUMMARY_VERSION:
        return
    refresh_tlsa_evidence_summary(conn)


def _drop_obsolete_schema(conn: sqlite3.Connection) -> None:
    for table in OBSOLETE_TABLES:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    for table, columns in OBSOLETE_COLUMNS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column in columns:
            if column in existing:
                conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


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
        dumps_json(summary.tlsa_records),
        summary.tlsa_cert_not_valid_after,
        int(summary.tlsa_cert_expired),
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
