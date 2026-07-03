from __future__ import annotations

import csv
import gzip
import math
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .db import get_meta, parse_json_columns, rows_to_dicts, table_count
from .fileutil import file_sha256
from .jsonutil import dumps_json, dumps_pretty
from .models import FAILURE_REASONS, ONCHAIN_CLASSES
from .timeutil import utc_now

DATA_ARTIFACTS = (
    "summary.json",
    "faq_answers.json",
    "classes.json",
    "providers.json",
    "broken.json",
    "names-pages.json",
)

PAGE_SIZE = 1000
DETAILED_NAME_COLLECTION_ROW_LIMIT = 100_000
FAILURE_REASON_FILTER_PREFIX = "failure_reason:"
PROVIDER_TYPE_FILTER_PREFIX = "provider_type:"

NAME_FILTERS = {
    "direct_ip_records": "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0",
    "delegated_names": "json_array_length(rs.ns_names) > 0",
    "default_provider_names": "ps.provider_type = 'default_parking'",
    "ds_records": "rs.has_ds = 1",
    "dnssec_candidates": "rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0",
    "dane_rows": "rs.has_ds = 1 OR ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL",
    "likely_websites": (
        "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0 OR "
        "json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0 OR "
        "(rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0)"
    ),
    "strict_hns_working": "ls.strict_hns_status = 'working'",
    "doh_fallback_required": "ls.doh_fallback_status IN ('required', 'doh_fallback_only')",
    "dane_working": "ls.dane_status = 'valid'",
    "missing_glue": "ls.failure_reason = 'missing_glue'",
    "missing_glue_only": (
        "json_array_length(rs.ns_names) > 0 AND json_array_length(rs.glue4) = 0 "
        "AND json_array_length(rs.glue6) = 0 "
        "AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'"
    ),
    "stale_tlsa": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
    "stale_tlsa_only": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
}

DANE_BASE_WHERE = "rs.has_ds = 1 OR ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL"
DANE_FILTERS = {
    "ds_records": "rs.has_ds = 1",
    "dnssec_candidates": "rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0",
    "dane_working": "ls.dane_status = 'valid'",
    "stale_tlsa": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
    "stale_tlsa_only": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
}

DANE_CANDIDATE_CLASSES = ("DNSSEC_CANDIDATE", "DANE_CANDIDATE")
NAME_CLASS_FILTERS = {
    "direct_ip_records": "n.onchain_class = 'DIRECT_SYNTH'",
    "delegated_names": "n.onchain_class IN ('DELEGATED_WITH_GLUE', 'DELEGATED_NO_GLUE', 'DNSSEC_CANDIDATE', 'DANE_CANDIDATE', 'PARKED_OR_DEFAULT')",
    "ds_records": "n.onchain_class IN ('DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
    "dnssec_candidates": "n.onchain_class IN ('DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
    "likely_websites": "n.onchain_class IN ('DIRECT_SYNTH', 'DELEGATED_WITH_GLUE', 'DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
    "missing_glue_only": "n.onchain_class = 'DELEGATED_NO_GLUE'",
}
NAME_LIVE_FILTERS = {
    "strict_hns_working": "ls.strict_hns_status = 'working'",
    "doh_fallback_required": "ls.doh_fallback_status IN ('required', 'doh_fallback_only')",
    "dane_working": "ls.dane_status = 'valid'",
    "missing_glue": "ls.failure_reason = 'missing_glue'",
    "stale_tlsa": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
    "stale_tlsa_only": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
}

FAQ_KEYS = (
    "direct_ip_records",
    "delegated_names",
    "default_provider_names",
    "ds_records",
    "dnssec_candidates",
    "likely_websites",
    "strict_hns_working",
    "doh_fallback_required",
    "dane_working",
    "missing_glue_only",
    "stale_tlsa_only",
)


def export_all(
    conn: sqlite3.Connection,
    *,
    db_path: str | Path,
    out_dir: str | Path,
    names_limit: int = 0,
    include_downloads: bool = False,
) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = build_summary(conn)
    effective_names_limit = _effective_names_limit(summary, names_limit)
    _log_export(f"export start out={out} names_limit={names_limit} effective_names_limit={effective_names_limit}")
    write_json(out / "summary.json", summary)
    _log_export("wrote summary.json")
    write_json(out / "faq_answers.json", build_faq_answers(conn, summary))
    _log_export("wrote faq_answers.json")
    write_json(out / "classes.json", build_classes(conn))
    _log_export("wrote classes.json")
    write_json(out / "providers.json", build_providers(conn))
    _log_export("wrote providers.json")
    write_json(out / "broken.json", build_broken(conn))
    _log_export("wrote broken.json")
    _remove_obsolete_data(out)
    write_json(out / "names-pages.json", write_names_pages(conn, out, limit=effective_names_limit, page_size=PAGE_SIZE))
    _log_export("wrote names-pages.json")
    if include_downloads:
        write_json(out / "names.json", build_names(conn, limit=effective_names_limit))
        _log_export("wrote names.json")
        write_names_csv(conn, out / "names.csv", limit=effective_names_limit)
        _log_export("wrote names.csv")
        gzip_sqlite(db_path, out / "topology.sqlite.gz")
        _log_export("wrote topology.sqlite.gz")
    else:
        for relative in ("names.json", "names.csv", "topology.sqlite.gz"):
            (out / relative).unlink(missing_ok=True)
    write_json(
        out / "manifest.json",
        build_manifest(out, summary=summary, names_limit=names_limit, include_downloads=include_downloads),
    )
    _log_export("wrote manifest.json")


def build_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    resource_counts = conn.execute(
        """
        SELECT
          COUNT(*) AS total_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0 THEN 1 ELSE 0 END) AS active_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 1 THEN 1 ELSE 0 END) AS expired_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_synth, 0) = 1
                   THEN 1 ELSE 0 END) AS direct_ip_records,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ns, 0) = 1
                   THEN 1 ELSE 0 END) AS delegated_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ns, 0) = 1
                    AND COALESCE(rs.has_glue, 0) = 1
                   THEN 1 ELSE 0 END) AS delegated_with_glue,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ns, 0) = 1
                    AND COALESCE(rs.has_glue, 0) = 0
                   THEN 1 ELSE 0 END) AS delegated_no_glue,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ds, 0) = 1
                   THEN 1 ELSE 0 END) AS ds_records,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ds, 0) = 1
                    AND COALESCE(rs.has_ns, 0) = 1
                   THEN 1 ELSE 0 END) AS dnssec_candidates,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND (
                      COALESCE(rs.has_synth, 0) = 1
                      OR COALESCE(rs.has_glue, 0) = 1
                      OR (COALESCE(rs.has_ds, 0) = 1 AND COALESCE(rs.has_ns, 0) = 1)
                    )
                   THEN 1 ELSE 0 END) AS likely_websites,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0 AND ps.provider_type = 'default_parking'
                   THEN 1 ELSE 0 END) AS default_provider_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND COALESCE(rs.has_ns, 0) = 1
                    AND COALESCE(rs.has_glue, 0) = 0
                    AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'
                   THEN 1 ELSE 0 END) AS missing_glue_only
        FROM names n
        LEFT JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        """
    ).fetchone()
    live_counts = conn.execute(
        """
        SELECT
          SUM(CASE WHEN dnssec_status = 'valid' THEN 1 ELSE 0 END) AS dnssec_valid,
          SUM(CASE WHEN strict_hns_status = 'working' THEN 1 ELSE 0 END) AS strict_hns_working,
          SUM(CASE WHEN doh_fallback_status IN ('required', 'doh_fallback_only') THEN 1 ELSE 0 END) AS doh_fallback_required,
          SUM(CASE WHEN dane_status = 'valid' THEN 1 ELSE 0 END) AS dane_working,
          SUM(CASE WHEN failure_reason = 'stale_tlsa_spki_mismatch' THEN 1 ELSE 0 END) AS stale_tlsa_only
        FROM live_status
        """
    ).fetchone()
    return {
        "generated_at": get_meta(conn, "generated_at", utc_now()),
        "last_indexed_height": _meta_int(conn, "last_indexed_height"),
        "last_indexed_tip_hash": get_meta(conn, "last_indexed_tip_hash", ""),
        "hsd_chain": get_meta(conn, "hsd_chain", ""),
        "hsd_version": get_meta(conn, "hsd_version", ""),
        "crawler_version": get_meta(conn, "crawler_version", ""),
        "source_type": get_meta(conn, "source_type", ""),
        "source_file": get_meta(conn, "source_file", ""),
        "source_file_hash": get_meta(conn, "source_file_hash", ""),
        "source_rpc_url": get_meta(conn, "source_rpc_url", ""),
        "provider_rules_version": _meta_int(conn, "provider_rules_version"),
        "provider_rules_hash": get_meta(conn, "provider_rules_hash", ""),
        "provider_rules_path": get_meta(conn, "provider_rules_path", ""),
        "total_names": _row_int(resource_counts, "total_names"),
        "active_names": _row_int(resource_counts, "active_names"),
        "expired_names": _row_int(resource_counts, "expired_names"),
        "direct_ip_records": _row_int(resource_counts, "direct_ip_records"),
        "delegated_names": _row_int(resource_counts, "delegated_names"),
        "delegated_with_glue": _row_int(resource_counts, "delegated_with_glue"),
        "delegated_no_glue": _row_int(resource_counts, "delegated_no_glue"),
        "default_provider_names": _row_int(resource_counts, "default_provider_names"),
        "ds_records": _row_int(resource_counts, "ds_records"),
        "dnssec_candidates": _row_int(resource_counts, "dnssec_candidates"),
        "dnssec_valid": _row_int(live_counts, "dnssec_valid"),
        "likely_websites": _row_int(resource_counts, "likely_websites"),
        "strict_hns_working": _row_int(live_counts, "strict_hns_working"),
        "doh_fallback_required": _row_int(live_counts, "doh_fallback_required"),
        "dane_working": _row_int(live_counts, "dane_working"),
        "missing_glue_only": _row_int(resource_counts, "missing_glue_only"),
        "stale_tlsa_only": _row_int(live_counts, "stale_tlsa_only"),
        "live_check_started_at": get_meta(conn, "live_check_started_at", ""),
        "live_check_finished_at": get_meta(conn, "live_check_finished_at", ""),
        "live_check_limit": get_meta(conn, "live_check_limit", ""),
        "live_check_candidate_count": _meta_int(conn, "live_check_candidate_count"),
        "live_check_checked_count": _meta_int(conn, "live_check_checked_count"),
        "live_check_concurrency": _meta_int(conn, "live_check_concurrency"),
        "live_check_min_delay_ms": _meta_int(conn, "live_check_min_delay_ms"),
        "live_check_timeout_seconds": _meta_float(conn, "live_check_timeout_seconds"),
        "live_check_recheck_seconds": _meta_int(conn, "live_check_recheck_seconds"),
        "live_check_resolver": get_meta(conn, "live_check_resolver", ""),
    }


def build_faq_answers(conn: sqlite3.Connection, summary: dict[str, Any]) -> list[dict[str, Any]]:
    active = max(1, int(summary["active_names"]))
    examples = build_faq_examples(conn)

    def answer(key: str, question: str, count_key: str, definition: str, filter_link: str) -> dict[str, Any]:
        count = int(summary[count_key])
        return {
            "key": key,
            "question": question,
            "count": count,
            "percentage_of_active": round((count / active) * 100, 4),
            "definition": definition,
            "examples": examples.get(key, []),
            "last_checked_height": summary["last_indexed_height"],
            "last_checked_time": summary["generated_at"],
            "filter_link": filter_link,
        }

    return [
        answer(
            "direct_ip_records",
            "How many HNS names have usable direct IP records?",
            "direct_ip_records",
            "Current HNS resource data contains SYNTH4 or SYNTH6.",
            "names.html?filter=direct_ip_records",
        ),
        answer(
            "delegated_names",
            "How many delegate to real nameservers?",
            "delegated_names",
            "Current HNS resource data contains NS, GLUE4, or GLUE6 nameserver data.",
            "names.html?filter=delegated_names",
        ),
        answer(
            "default_provider_names",
            "How many use Namebase-style/default nameservers?",
            "default_provider_names",
            "Provider rules classify the resource as default parking or default hosted infrastructure.",
            "names.html?filter=default_provider_names",
        ),
        answer(
            "ds_records",
            "How many have DS records?",
            "ds_records",
            "Current HNS resource data contains at least one DS record.",
            "names.html?filter=ds_records",
        ),
        answer(
            "dnssec_candidates",
            "How many are DNSSEC candidates?",
            "dnssec_candidates",
            "Current HNS resource data contains DS plus delegated nameserver data.",
            "names.html?filter=dnssec_candidates",
        ),
        answer(
            "likely_websites",
            "How many are likely websites?",
            "likely_websites",
            "Active names with direct IP, GLUE-backed delegation, or DS-backed delegation.",
            "names.html?filter=likely_websites",
        ),
        answer(
            "strict_hns_working",
            "How many actually load in strict HNS mode?",
            "strict_hns_working",
            "Latest live check marked strict_hns_status as working.",
            "names.html?filter=strict_hns_working",
        ),
        answer(
            "doh_fallback_required",
            "How many require DoH fallback?",
            "doh_fallback_required",
            "Latest live check could only find a website address through the configured fallback resolver, not through strict HNS bootstrap.",
            "names.html?filter=doh_fallback_required",
        ),
        answer(
            "dane_working",
            "How many have working DANE?",
            "dane_working",
            "Latest live check found a TLSA record matching the HTTPS certificate/SPKI.",
            "names.html?filter=dane_working",
        ),
        answer(
            "missing_glue_only",
            "Which names are broken only because of missing GLUE?",
            "missing_glue_only",
            "Delegated names with no GLUE4/GLUE6 and no stronger live-check failure.",
            "names.html?filter=missing_glue_only",
        ),
        answer(
            "stale_tlsa_only",
            "Which names are broken only because of stale TLSA?",
            "stale_tlsa_only",
            "Latest live check found TLSA data that does not match the current HTTPS certificate/SPKI.",
            "names.html?filter=stale_tlsa_only",
        ),
    ]


def build_classes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    counts = {
        row["onchain_class"]: int(row["count"])
        for row in conn.execute("SELECT onchain_class, COUNT(*) AS count FROM names GROUP BY onchain_class")
    }
    return [{"class": klass, "count": counts.get(klass, 0)} for klass in ONCHAIN_CLASSES]


def build_faq_examples(conn: sqlite3.Connection) -> dict[str, list[str]]:
    examples = {key: [] for key in FAQ_KEYS}
    class_filters = {
        "direct_ip_records": "n.onchain_class = 'DIRECT_SYNTH'",
        "delegated_names": "n.onchain_class IN ('DELEGATED_WITH_GLUE', 'DELEGATED_NO_GLUE', 'DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
        "default_provider_names": "n.onchain_class = 'PARKED_OR_DEFAULT'",
        "ds_records": "n.onchain_class IN ('DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
        "dnssec_candidates": "n.onchain_class IN ('DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
        "likely_websites": "n.onchain_class IN ('DIRECT_SYNTH', 'DELEGATED_WITH_GLUE', 'DNSSEC_CANDIDATE', 'DANE_CANDIDATE')",
        "missing_glue_only": "n.onchain_class = 'DELEGATED_NO_GLUE'",
    }
    for key, where in class_filters.items():
        rows = conn.execute(
            f"""
            SELECT n.name
            FROM names n
            WHERE COALESCE(n.expired, 0) = 0 AND {where}
            LIMIT 5
            """
        ).fetchall()
        examples[key] = [row["name"] for row in rows]

    live_filters = {
        "strict_hns_working": "ls.strict_hns_status = 'working'",
        "doh_fallback_required": "ls.doh_fallback_status IN ('required', 'doh_fallback_only')",
        "dane_working": "ls.dane_status = 'valid'",
        "stale_tlsa_only": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
    }
    for key, where in live_filters.items():
        rows = conn.execute(
            f"""
            SELECT n.name
            FROM live_status ls
            JOIN names n ON n.name = ls.name
            WHERE COALESCE(n.expired, 0) = 0 AND {where}
            ORDER BY n.name
            LIMIT 5
            """
        ).fetchall()
        examples[key] = [row["name"] for row in rows]
    return examples


def build_providers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return rows_to_dicts(
        conn.execute(
            """
            SELECT
              provider_key, provider_type, ns_pattern, ip_pattern,
              names_count, likely_website_count, working_count, dane_count, updated_at
            FROM provider_summary
            ORDER BY names_count DESC, provider_key
            """
        )
    )


def build_broken(conn: sqlite3.Connection) -> dict[str, Any]:
    reasons = [
        {
            "failure_reason": reason,
            "count": table_count(conn, "SELECT COUNT(*) FROM live_status WHERE failure_reason = ?", (reason,)),
        }
        for reason in FAILURE_REASONS
    ]
    example_rows = conn.execute(
        """
        SELECT
          n.name, n.onchain_class, n.provider_guess,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.has_ds,
          ls.dns_reachable, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
          ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
        FROM live_status ls
        JOIN names n ON n.name = ls.name
        JOIN resource_summary rs ON rs.name = n.name
        WHERE ls.failure_reason IS NOT NULL
        ORDER BY ls.checked_at DESC, n.name
        LIMIT 200
        """
    ).fetchall()
    examples = [
        parse_json_columns(
            dict(row),
            ["ns_names", "glue4", "glue6", "synth4", "synth6"],
        )
        for row in example_rows
    ]
    return {"reasons": reasons, "examples": examples}


def build_dane(conn: sqlite3.Connection, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    ds_count = int(summary["ds_records"]) if summary else table_count(
        conn,
        """
        SELECT COUNT(*) FROM names
        WHERE COALESCE(expired, 0) = 0 AND instr(COALESCE(record_types, ''), '"DS"') > 0
        """,
    )
    return {
        "ds_count": ds_count,
        "valid_dane_count": table_count(conn, "SELECT COUNT(*) FROM live_status WHERE dane_status = 'valid'"),
        "rows": build_dane_rows(conn, limit=500),
    }


def build_names(
    conn: sqlite3.Connection,
    *,
    limit: int,
    offset: int = 0,
    where: str = "1=1",
) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT
          n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
          COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds,
          ls.dns_reachable, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
          ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE {where}
        ORDER BY n.updated_at DESC, n.name
        LIMIT ?
        OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    return [
        parse_json_columns(
            dict(row),
            ["record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"],
        )
        for row in rows
    ]


def build_dane_rows(
    conn: sqlite3.Connection,
    *,
    limit: int,
    offset: int = 0,
    where: str = DANE_BASE_WHERE,
) -> list[dict[str, Any]]:
    if where == DANE_BASE_WHERE:
        rows = _collect_dane_rows(conn, limit=max(0, limit + offset))
        return rows[offset : offset + limit]
    rows = conn.execute(
        f"""
        SELECT n.name, rs.has_ds, rs.ns_names, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.failure_reason, ls.checked_at
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        WHERE {where}
        ORDER BY COALESCE(ls.checked_at, n.updated_at) DESC, n.name
        LIMIT ?
        OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    return [parse_json_columns(dict(row), ["ns_names"]) for row in rows]


def _collect_dane_rows(conn: sqlite3.Connection, *, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(query: str, params: tuple[Any, ...]) -> None:
        for row in conn.execute(query, params):
            name = row["name"]
            if name in seen:
                continue
            seen.add(name)
            rows.append(parse_json_columns(dict(row), ["ns_names"]))
            if len(rows) >= limit:
                break

    add(
        """
        SELECT
          n.name, rs.has_ds, rs.ns_names, ls.dnssec_status, ls.tlsa_status,
          ls.dane_status, ls.failure_reason, ls.checked_at
        FROM live_status ls
        CROSS JOIN names n ON n.name = ls.name
        CROSS JOIN resource_summary rs ON rs.name = n.name
        WHERE COALESCE(n.expired, 0) = 0
          AND (ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL)
        ORDER BY ls.checked_at DESC, n.name
        LIMIT ?
        """,
        (limit,),
    )
    if len(rows) >= limit:
        return rows

    class_placeholders = ",".join("?" for _ in DANE_CANDIDATE_CLASSES)
    add(
        f"""
        SELECT
          n.name, rs.has_ds, rs.ns_names, ls.dnssec_status, ls.tlsa_status,
          ls.dane_status, ls.failure_reason, ls.checked_at
        FROM names n INDEXED BY idx_names_class
        CROSS JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        WHERE COALESCE(n.expired, 0) = 0
          AND n.onchain_class IN ({class_placeholders})
        LIMIT ?
        """,
        (*DANE_CANDIDATE_CLASSES, limit),
    )
    return rows


def write_names_pages(
    conn: sqlite3.Connection,
    out: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    return _write_names_pages_streamed(conn, out / "names-pages", limit=limit, page_size=page_size)


def write_dane_pages(
    conn: sqlite3.Connection,
    out: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    return _write_dane_pages_streamed(conn, out / "dane-pages", limit=limit, page_size=page_size)


def _write_names_pages_streamed(
    conn: sqlite3.Connection,
    base_dir: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    collections: dict[str, Any] = {}
    keys = _name_collection_keys(conn)
    _log_export(f"writing names-pages collections={len(keys)} page_size={page_size} limit={limit}")
    for key in keys:
        collections[key] = _write_name_collection(conn, base_dir, key, limit=limit, page_size=page_size)
    _log_export("finished names-pages collections")
    return {
        "page_size": page_size,
        "limit": limit,
        "collections": collections,
    }


def _build_name_page_rows(conn: sqlite3.Connection, key: str, *, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    from_sql = _name_rows_from_sql()
    where, params = _name_collection_where(key)
    rows = conn.execute(
        f"""
        SELECT {_name_row_columns()}
        {from_sql}
        WHERE {where}
        ORDER BY n.name
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    return [
        parse_json_columns(
            dict(row),
            ["record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"],
        )
        for row in rows
    ]


def _write_name_collection(
    conn: sqlite3.Connection,
    base_dir: Path,
    key: str,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    collection_dir = base_dir / key
    collection_dir.mkdir(parents=True, exist_ok=True)
    from_sql = _name_rows_from_sql()
    where, params = _name_collection_where(key)
    total_count = int(
        conn.execute(
            f"""
            SELECT COUNT(*)
            {from_sql}
            WHERE {where}
            """,
            params,
        ).fetchone()[0]
        or 0
    )
    count = min(total_count, max(0, limit))
    page_count = max(1, math.ceil(count / page_size)) if count else 0
    row_detail = "full" if total_count <= DETAILED_NAME_COLLECTION_ROW_LIMIT else "compact"
    _log_export(
        f"writing names-pages/{key} rows={count} total={total_count} pages={page_count} "
        f"truncated={total_count > count} row_detail={row_detail}"
    )
    row_columns = _name_row_columns(row_detail=row_detail)
    json_columns = _name_json_columns(row_detail=row_detail)
    if count == 0:
        write_json(collection_dir / "page-1.json", {"page": 1, "rows": []})
    else:
        cursor = conn.execute(
            f"""
            SELECT {row_columns}
            {from_sql}
            WHERE {where}
            ORDER BY n.name
            LIMIT ?
            """,
            (*params, count),
        )
        page = 1
        while True:
            page_rows = cursor.fetchmany(page_size)
            if not page_rows:
                break
            rows = [
                parse_json_columns(
                    dict(row),
                    json_columns,
                )
                for row in page_rows
            ]
            write_json(collection_dir / f"page-{page}.json", {"page": page, "rows": rows})
            page += 1
    _log_export(f"finished names-pages/{key}")
    return {
        "row_count": count,
        "total_count": total_count,
        "page_size": page_size,
        "page_count": page_count,
        "path_template": f"{base_dir.name}/{key}/page-{{page}}.json",
        "truncated": total_count > count,
        "row_detail": row_detail,
    }


def _name_collection_keys(conn: sqlite3.Connection) -> list[str]:
    provider_types = [
        row["provider_type"]
        for row in conn.execute(
            """
            SELECT DISTINCT COALESCE(provider_type, 'unknown') AS provider_type
            FROM provider_summary
            ORDER BY provider_type
            """
        )
        if row["provider_type"]
    ]
    return [
        "all",
        *NAME_FILTERS,
        *(f"{FAILURE_REASON_FILTER_PREFIX}{reason}" for reason in FAILURE_REASONS),
        *(f"{PROVIDER_TYPE_FILTER_PREFIX}{provider_type}" for provider_type in provider_types),
    ]


def _name_row_columns(*, row_detail: str = "full") -> str:
    if row_detail == "compact":
        return """
      n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
      COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types, rs.has_ds,
      ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
      ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
    """
    return """
      n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
      COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
      rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds,
      ls.dns_reachable, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
      ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
    """


def _name_json_columns(*, row_detail: str = "full") -> list[str]:
    if row_detail == "compact":
        return ["record_types"]
    return ["record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"]


def _name_rows_from_sql() -> str:
    return """
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN live_status ls ON ls.name = n.name
      LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
    """


def _name_collection_where(key: str) -> tuple[str, tuple[Any, ...]]:
    if key == "all":
        return "1=1", ()
    if key.startswith(FAILURE_REASON_FILTER_PREFIX):
        return "COALESCE(n.expired, 0) = 0 AND ls.failure_reason = ?", (
            key.removeprefix(FAILURE_REASON_FILTER_PREFIX),
        )
    if key.startswith(PROVIDER_TYPE_FILTER_PREFIX):
        return "COALESCE(ps.provider_type, 'unknown') = ?", (
            key.removeprefix(PROVIDER_TYPE_FILTER_PREFIX),
        )
    return f"COALESCE(n.expired, 0) = 0 AND ({NAME_FILTERS.get(key, '1=1')})", ()


def _write_dane_pages_streamed(
    conn: sqlite3.Connection,
    base_dir: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    keys = ["all", *DANE_FILTERS]
    rows_by_key: dict[str, list[dict[str, Any]]] = {key: [] for key in keys}
    if limit > 0:
        remaining = set(keys)
        for item in _collect_dane_rows(conn, limit=limit):
            for key in list(remaining):
                if key == "all" or _dane_row_matches_filter(item, key):
                    rows_by_key[key].append(item)
                    if len(rows_by_key[key]) >= limit:
                        remaining.remove(key)
            if not remaining:
                break
    return _write_paginated_row_sets(base_dir, rows_by_key, limit=limit, page_size=page_size)


def _write_paginated_row_sets(
    base_dir: Path,
    rows_by_key: dict[str, list[dict[str, Any]]],
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    collections: dict[str, Any] = {}
    for key, rows in rows_by_key.items():
        collection_dir = base_dir / key
        collection_dir.mkdir(parents=True, exist_ok=True)
        count = min(len(rows), limit)
        page_count = max(1, math.ceil(count / page_size)) if count else 0
        collections[key] = {
            "row_count": count,
            "page_size": page_size,
            "page_count": page_count,
            "path_template": f"{base_dir.name}/{key}/page-{{page}}.json",
        }
        for page in range(1, page_count + 1):
            offset = (page - 1) * page_size
            page_rows = rows[offset : offset + page_size]
            write_json(collection_dir / f"page-{page}.json", {"page": page, "rows": page_rows})
        if page_count == 0:
            write_json(collection_dir / "page-1.json", {"page": 1, "rows": []})
    return {
        "page_size": page_size,
        "limit": limit,
        "collections": collections,
    }


def _name_row_matches_filter(row: dict[str, Any], key: str) -> bool:
    has_ns = bool(row.get("ns_names"))
    has_glue = bool(row.get("glue4") or row.get("glue6"))
    has_synth = bool(row.get("synth4") or row.get("synth6"))
    has_ds = bool(row.get("has_ds"))
    if key.startswith(FAILURE_REASON_FILTER_PREFIX):
        return row.get("failure_reason") == key.removeprefix(FAILURE_REASON_FILTER_PREFIX)
    if key.startswith(PROVIDER_TYPE_FILTER_PREFIX):
        return row.get("provider_type") == key.removeprefix(PROVIDER_TYPE_FILTER_PREFIX)
    if key == "direct_ip_records":
        return has_synth
    if key == "delegated_names":
        return has_ns
    if key == "default_provider_names":
        return row.get("provider_type") == "default_parking"
    if key == "ds_records":
        return has_ds
    if key == "dnssec_candidates":
        return has_ds and has_ns
    if key == "dane_rows":
        return has_ds or bool(row.get("tlsa_status")) or bool(row.get("dane_status"))
    if key == "likely_websites":
        return has_synth or has_glue or (has_ds and has_ns)
    if key == "strict_hns_working":
        return row.get("strict_hns_status") == "working"
    if key == "doh_fallback_required":
        return row.get("doh_fallback_status") in {"required", "doh_fallback_only"}
    if key == "dane_working":
        return row.get("dane_status") == "valid"
    if key == "missing_glue":
        return row.get("failure_reason") == "missing_glue"
    if key == "missing_glue_only":
        return has_ns and not has_glue and (row.get("failure_reason") or "missing_glue") == "missing_glue"
    if key == "stale_tlsa":
        return row.get("failure_reason") == "stale_tlsa_spki_mismatch"
    if key == "stale_tlsa_only":
        return row.get("failure_reason") == "stale_tlsa_spki_mismatch"
    return True


def _dane_row_matches_filter(row: dict[str, Any], key: str) -> bool:
    has_ds = bool(row.get("has_ds"))
    has_ns = bool(row.get("ns_names"))
    if key == "ds_records":
        return has_ds
    if key == "dnssec_candidates":
        return has_ds and has_ns
    if key == "dane_working":
        return row.get("dane_status") == "valid"
    if key == "stale_tlsa":
        return row.get("failure_reason") == "stale_tlsa_spki_mismatch"
    if key == "stale_tlsa_only":
        return row.get("failure_reason") == "stale_tlsa_spki_mismatch"
    return True


def _write_paginated_collections(
    conn: sqlite3.Connection,
    base_dir: Path,
    *,
    page_size: int,
    limit: int,
    filters: dict[str, str],
    collection_rows,
    base_where: str = "1=1",
) -> dict[str, Any]:
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    collections: dict[str, Any] = {}
    for key, where in {"all": base_where, **filters}.items():
        collection_dir = base_dir / key
        collection_dir.mkdir(parents=True, exist_ok=True)
        rows = collection_rows(where)
        count = min(len(rows), limit)
        page_count = max(1, math.ceil(count / page_size)) if count else 0
        collections[key] = {
            "row_count": count,
            "page_size": page_size,
            "page_count": page_count,
            "path_template": f"{base_dir.name}/{key}/page-{{page}}.json",
        }
        for page in range(1, page_count + 1):
            offset = (page - 1) * page_size
            page_rows = rows[offset : offset + page_size]
            write_json(collection_dir / f"page-{page}.json", {"page": page, "rows": page_rows})
        if page_count == 0:
            write_json(collection_dir / "page-1.json", {"page": 1, "rows": []})

    return {
        "page_size": page_size,
        "limit": limit,
        "collections": collections,
    }


def examples_for_filter(conn: sqlite3.Connection, key: str) -> list[str]:
    filters = {"default_provider_names": "ps.provider_type = 'default_parking'", **NAME_FILTERS}
    where = filters.get(key, "1=1")
    rows = conn.execute(
        f"""
        SELECT n.name
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE n.expired = 0 AND ({where})
        ORDER BY n.name
        LIMIT 5
        """
    ).fetchall()
    return [row["name"] for row in rows]


def write_names_csv(conn: sqlite3.Connection, path: Path, *, limit: int) -> None:
    rows = build_names(conn, limit=limit)
    fieldnames = [
        "name",
        "state",
        "expired",
        "onchain_class",
        "provider_guess",
        "provider_type",
        "record_types",
        "ns_names",
        "glue4",
        "glue6",
        "synth4",
        "synth6",
        "ds_records",
        "has_ds",
        "dns_reachable",
        "dnssec_status",
        "tlsa_status",
        "dane_status",
        "https_status",
        "strict_hns_status",
        "doh_fallback_status",
        "failure_reason",
        "checked_at",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})


def gzip_sqlite(db_path: str | Path, out_path: Path) -> None:
    source = Path(db_path)
    if not source.exists():
        return
    with tempfile.TemporaryDirectory() as tmpdir:
        snapshot = Path(tmpdir) / "topology.sqlite"
        with sqlite3.connect(source) as src_conn, sqlite3.connect(snapshot) as dst_conn:
            src_conn.backup(dst_conn)
        with snapshot.open("rb") as src, gzip.open(out_path, "wb", compresslevel=9) as dst:
            shutil.copyfileobj(src, dst)


def write_json(path: Path, value: Any) -> None:
    path.write_text(dumps_pretty(value), encoding="utf-8")


def build_manifest(
    out_dir: str | Path,
    *,
    summary: dict[str, Any],
    names_limit: int,
    include_downloads: bool = False,
) -> dict[str, Any]:
    out = Path(out_dir)
    names_total = int(summary["total_names"])
    names_exported = _effective_names_limit(summary, names_limit)
    return {
        "manifest_version": 1,
        "exported_at": utc_now(),
        "crawler_version": __version__,
        "export": {
            "format": "hns-topology-static-report",
            "names_limit": names_limit,
            "names_total_count": summary["total_names"],
            "names_exported_count": names_exported,
            "names_truncated": names_exported < names_total,
            "download_artifacts_included": include_downloads,
        },
        "snapshot": {
            "height": summary["last_indexed_height"],
            "tip_hash": summary["last_indexed_tip_hash"],
            "generated_at": summary["generated_at"],
            "hsd_chain": summary["hsd_chain"],
            "hsd_version": summary["hsd_version"],
            "source_type": summary["source_type"],
            "source_file": summary["source_file"],
            "source_file_hash": summary["source_file_hash"],
            "source_rpc_url": summary["source_rpc_url"],
            "provider_rules_version": summary["provider_rules_version"],
            "provider_rules_hash": summary["provider_rules_hash"],
            "provider_rules_path": summary["provider_rules_path"],
        },
        "summary": summary,
        "artifacts": [
            _artifact_entry(out / relative, relative)
            for relative in _manifest_artifact_paths(out, include_downloads=include_downloads)
        ],
    }


def _manifest_artifact_paths(out: Path, *, include_downloads: bool) -> list[str]:
    paths = list(DATA_ARTIFACTS)
    if include_downloads:
        paths.extend(("names.json", "names.csv", "topology.sqlite.gz"))
    for directory in ("names-pages",):
        paths.extend(
            path.relative_to(out).as_posix()
            for path in sorted((out / directory).glob("*/*.json"))
        )
    return paths


def _effective_names_limit(summary: dict[str, Any], names_limit: int) -> int:
    total = int(summary["total_names"])
    if names_limit <= 0:
        return total
    return min(total, names_limit)


def _remove_obsolete_data(out: Path) -> None:
    for relative in ("dane.json", "dane-pages.json"):
        (out / relative).unlink(missing_ok=True)
    shutil.rmtree(out / "dane-pages", ignore_errors=True)


def _log_export(message: str) -> None:
    print(f"[export] {utc_now()} {message}", file=sys.stderr, flush=True)


def _artifact_entry(path: Path, relative: str) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
    }


def _row_int(row: sqlite3.Row | None, key: str) -> int:
    if row is None:
        return 0
    value = row[key]
    return int(value) if value is not None else 0


def _csv_value(value: Any) -> Any:
    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return ",".join(value)
        return dumps_json(value)
    return value


def _meta_int(conn: sqlite3.Connection, key: str) -> int | None:
    value = get_meta(conn, key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _meta_float(conn: sqlite3.Connection, key: str) -> float | None:
    value = get_meta(conn, key)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
