from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .jsonutil import dumps_json
from .models import LiveStatus, NameRecord, ResourceSummary

SCHEMA_SQL = """
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
  has_ds INTEGER DEFAULT 0,
  has_txt INTEGER DEFAULT 0,
  raw_size INTEGER,
  resource_hash TEXT,
  FOREIGN KEY(name) REFERENCES names(name) ON DELETE CASCADE
);

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
  block_hash_at_height TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  PRIMARY KEY(height, name)
);

CREATE INDEX IF NOT EXISTS idx_names_class ON names(onchain_class);
CREATE INDEX IF NOT EXISTS idx_names_provider ON names(provider_guess);
CREATE INDEX IF NOT EXISTS idx_names_expired ON names(expired);
CREATE INDEX IF NOT EXISTS idx_live_failure ON live_status(failure_reason);
CREATE INDEX IF NOT EXISTS idx_live_next_check ON live_status(next_check_at);
"""


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
    conn.execute(
        """
        INSERT INTO names(
          name, name_hash, state, renewal_height, expired, resource_hash, record_types,
          onchain_class, provider_guess, last_seen_height, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          name_hash=excluded.name_hash,
          state=excluded.state,
          renewal_height=excluded.renewal_height,
          expired=excluded.expired,
          resource_hash=excluded.resource_hash,
          record_types=excluded.record_types,
          onchain_class=excluded.onchain_class,
          provider_guess=excluded.provider_guess,
          last_seen_height=excluded.last_seen_height,
          updated_at=excluded.updated_at
        """,
        (
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
        ),
    )


def upsert_resource(conn: sqlite3.Connection, summary: ResourceSummary) -> None:
    conn.execute(
        """
        INSERT INTO resource_summary(
          name, ns_names, glue4, glue6, synth4, synth6, has_ds, has_txt,
          raw_size, resource_hash
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          ns_names=excluded.ns_names,
          glue4=excluded.glue4,
          glue6=excluded.glue6,
          synth4=excluded.synth4,
          synth6=excluded.synth6,
          has_ds=excluded.has_ds,
          has_txt=excluded.has_txt,
          raw_size=excluded.raw_size,
          resource_hash=excluded.resource_hash
        """,
        (
            summary.name,
            dumps_json(summary.ns_names),
            dumps_json(summary.glue4),
            dumps_json(summary.glue6),
            dumps_json(summary.synth4),
            dumps_json(summary.synth6),
            int(summary.has_ds),
            int(summary.has_txt),
            summary.raw_size,
            summary.resource_hash,
        ),
    )


def upsert_live_status(conn: sqlite3.Connection, status: LiveStatus) -> None:
    conn.execute(
        """
        INSERT INTO live_status(
          name, dns_reachable, dnssec_status, tlsa_status, dane_status, https_status,
          strict_hns_status, doh_fallback_status, failure_reason, checked_at, next_check_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          dns_reachable=excluded.dns_reachable,
          dnssec_status=excluded.dnssec_status,
          tlsa_status=excluded.tlsa_status,
          dane_status=excluded.dane_status,
          https_status=excluded.https_status,
          strict_hns_status=excluded.strict_hns_status,
          doh_fallback_status=excluded.doh_fallback_status,
          failure_reason=excluded.failure_reason,
          checked_at=excluded.checked_at,
          next_check_at=excluded.next_check_at
        """,
        (
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
        ),
    )


def capture_rollback(
    conn: sqlite3.Connection,
    *,
    height: int,
    name: str,
    block_hash: str,
    captured_at: str,
) -> None:
    row = conn.execute(
        """
        SELECT n.resource_hash, n.onchain_class, ls.*
        FROM names n
        LEFT JOIN live_status ls ON ls.name = n.name
        WHERE n.name = ?
        """,
        (name,),
    ).fetchone()
    if row is None:
        previous_live = None
        previous_resource_hash = None
        previous_classification = None
    else:
        previous_resource_hash = row["resource_hash"]
        previous_classification = row["onchain_class"]
        live_keys = (
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
        previous_live = {key: row[key] for key in live_keys if row[key] is not None}
    conn.execute(
        """
        INSERT OR REPLACE INTO changed_name_rollbacks(
          height, name, previous_resource_hash, previous_classification,
          previous_live_status, block_hash_at_height, captured_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            height,
            name,
            previous_resource_hash,
            previous_classification,
            dumps_json(previous_live) if previous_live is not None else None,
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


def recompute_provider_summary(
    conn: sqlite3.Connection, provider_types: dict[str, str], updated_at: str
) -> None:
    conn.execute("DELETE FROM provider_summary")
    rows = conn.execute(
        """
        SELECT
          n.provider_guess AS provider_key,
          COUNT(*) AS names_count,
          SUM(CASE
            WHEN n.expired = 0 AND (
              json_array_length(rs.synth4) > 0 OR
              json_array_length(rs.synth6) > 0 OR
              json_array_length(rs.glue4) > 0 OR
              json_array_length(rs.glue6) > 0 OR
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
                "",
                "",
                int(row["names_count"] or 0),
                int(row["likely_website_count"] or 0),
                int(row["working_count"] or 0),
                int(row["dane_count"] or 0),
                updated_at,
            ),
        )


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

