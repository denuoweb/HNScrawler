from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from typing import Any

NS_HANDOFF_TABLE = "export_ns_handoff"
NS_HANDOFF_COLUMNS = (
    "ns_handoff_ns",
    "ns_handoff_root",
    "ns_handoff_glue4",
    "ns_handoff_glue6",
    "ns_handoff_synth4",
    "ns_handoff_synth6",
    "ns_handoff_bootstrap_ip",
    "ns_handoff_bootstrap_field",
)


def normalize_nameserver(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def nameserver_hns_root(value: Any) -> str:
    normalized = normalize_nameserver(value)
    labels = [label for label in normalized.split(".") if label]
    return labels[-1] if labels else ""


def register_ns_handoff_sql_functions(conn: sqlite3.Connection) -> None:
    conn.create_function("hns_normalize_ns", 1, normalize_nameserver)
    conn.create_function("hns_root_from_ns", 1, nameserver_hns_root)


def prepare_temp_ns_handoff_table(
    conn: sqlite3.Connection,
    source_names_sql: str,
    params: Sequence[Any] = (),
) -> None:
    """Materialize first indirect HNS nameserver bootstrap evidence per source name.

    source_names_sql must select one column named or aliased as name. The derived
    address is the bootstrap for the HNS root that hosts the NS name, not the final
    A/AAAA address of the nameserver hostname.
    """
    register_ns_handoff_sql_functions(conn)
    drop_temp_ns_handoff_table(conn)
    conn.execute(
        f"""
        CREATE TEMP TABLE {NS_HANDOFF_TABLE}(
          name TEXT PRIMARY KEY,
          ns_handoff_ns TEXT,
          ns_handoff_root TEXT,
          ns_handoff_glue4 TEXT,
          ns_handoff_glue6 TEXT,
          ns_handoff_synth4 TEXT,
          ns_handoff_synth6 TEXT,
          ns_handoff_bootstrap_ip TEXT,
          ns_handoff_bootstrap_field TEXT
        ) WITHOUT ROWID
        """
    )
    conn.execute(
        f"""
        WITH source_names(name) AS (
          {source_names_sql}
        ),
        expanded AS (
          SELECT
            sn.name,
            CAST(ns.key AS INTEGER) AS ns_index,
            hns_normalize_ns(ns.value) AS ns_handoff_ns,
            hns_root_from_ns(ns.value) AS ns_handoff_root
          FROM source_names sn
          JOIN resource_summary rs ON rs.name = sn.name
          JOIN json_each(rs.ns_names) ns
          WHERE COALESCE(rs.has_ns, 0) = 1
            AND COALESCE(rs.has_glue, 0) = 0
            AND COALESCE(rs.has_synth, 0) = 0
        ),
        candidates AS (
          SELECT
            e.name,
            e.ns_index,
            e.ns_handoff_ns,
            e.ns_handoff_root,
            NULLIF(json_extract(root_rs.glue4, '$[0]'), '') AS ns_handoff_glue4,
            NULLIF(json_extract(root_rs.glue6, '$[0]'), '') AS ns_handoff_glue6,
            NULLIF(json_extract(root_rs.synth4, '$[0]'), '') AS ns_handoff_synth4,
            NULLIF(json_extract(root_rs.synth6, '$[0]'), '') AS ns_handoff_synth6
          FROM expanded e
          JOIN names root_name
            ON root_name.name = e.ns_handoff_root
           AND COALESCE(root_name.expired, 0) = 0
          JOIN resource_summary root_rs ON root_rs.name = root_name.name
          WHERE e.ns_handoff_ns != ''
            AND e.ns_handoff_root != ''
            AND (
              COALESCE(root_rs.has_glue, 0) = 1
              OR COALESCE(root_rs.has_synth, 0) = 1
            )
        ),
        ranked AS (
          SELECT
            candidates.*,
            row_number() OVER (
              PARTITION BY name
              ORDER BY ns_index, ns_handoff_ns
            ) AS handoff_rank
          FROM candidates
        )
        INSERT INTO {NS_HANDOFF_TABLE}(
          name, ns_handoff_ns, ns_handoff_root,
          ns_handoff_glue4, ns_handoff_glue6, ns_handoff_synth4, ns_handoff_synth6,
          ns_handoff_bootstrap_ip, ns_handoff_bootstrap_field
        )
        SELECT
          name,
          ns_handoff_ns,
          ns_handoff_root,
          ns_handoff_glue4,
          ns_handoff_glue6,
          ns_handoff_synth4,
          ns_handoff_synth6,
          COALESCE(
            ns_handoff_synth4,
            ns_handoff_glue4,
            ns_handoff_synth6,
            ns_handoff_glue6
          ) AS ns_handoff_bootstrap_ip,
          CASE
            WHEN ns_handoff_synth4 IS NOT NULL THEN 'SYNTH4'
            WHEN ns_handoff_glue4 IS NOT NULL THEN 'GLUE4'
            WHEN ns_handoff_synth6 IS NOT NULL THEN 'SYNTH6'
            WHEN ns_handoff_glue6 IS NOT NULL THEN 'GLUE6'
            ELSE NULL
          END AS ns_handoff_bootstrap_field
        FROM ranked
        WHERE handoff_rank = 1
        """,
        tuple(params),
    )


def drop_temp_ns_handoff_table(conn: sqlite3.Connection) -> None:
    conn.execute(f"DROP TABLE IF EXISTS temp.{NS_HANDOFF_TABLE}")
