from __future__ import annotations

import csv
import gzip
import json
import math
import shutil
import sqlite3
import sys
import tempfile
import time
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
    "names-pages.json",
)

PAGE_SIZE = 1000
DETAILED_NAME_COLLECTION_ROW_LIMIT = 100_000
FAILURE_REASON_FILTER_PREFIX = "failure_reason:"
PROVIDER_FILTER_PREFIX = "provider:"
PROVIDER_TYPE_FILTER_PREFIX = "provider_type:"

NAME_FILTERS = {
    "direct_ip_records": "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0",
    "delegated_names": "json_array_length(rs.ns_names) > 0",
    "default_provider_names": "ps.provider_type = 'default_parking'",
    "ds_records": "rs.has_ds = 1",
    "dnssec_candidates": "rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0",
    "dane_rows": "rs.has_ds = 1 OR ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL",
    "strict_hns_ready": (
        "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0 OR "
        "(json_array_length(rs.ns_names) > 0 AND "
        "(json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0))"
    ),
    "likely_websites": (
        "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0 OR "
        "json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0 OR "
        "(rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0)"
    ),
    "strict_hns_working": "ls.strict_hns_status = 'working'",
    "doh_fallback_required": "ls.doh_fallback_status IN ('required', 'doh_fallback_only')",
    "needs_dane": (
        "(rs.has_ds = 1 OR ls.dnssec_status = 'valid') "
        "AND COALESCE(ls.dane_status, '') != 'valid' "
        "AND COALESCE(ls.tlsa_status, 'missing') IN ('missing', 'unknown', '')"
    ),
    "dane_working": "ls.dane_status = 'valid'",
    "needs_fix": (
        "ls.failure_reason IS NOT NULL OR "
        "(json_array_length(rs.ns_names) > 0 AND json_array_length(rs.glue4) = 0 "
        "AND json_array_length(rs.glue6) = 0 "
        "AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue')"
    ),
    "missing_glue": "ls.failure_reason = 'missing_glue'",
    "missing_glue_only": (
        "json_array_length(rs.ns_names) > 0 AND json_array_length(rs.glue4) = 0 "
        "AND json_array_length(rs.glue6) = 0 "
        "AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'"
    ),
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
    "strict_hns_ready",
    "strict_hns_working",
    "doh_fallback_required",
    "needs_dane",
    "dane_working",
    "needs_fix",
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
    _remove_obsolete_data(out)
    write_json(out / "names-pages.json", write_names_pages(conn, out, limit=effective_names_limit, page_size=PAGE_SIZE))
    _log_export("wrote names-pages.json")
    evidence_count = write_dns_evidence(conn, out)
    _log_export(f"wrote dns evidence files={evidence_count}")
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
                      OR (COALESCE(rs.has_ns, 0) = 1 AND COALESCE(rs.has_glue, 0) = 1)
                    )
                   THEN 1 ELSE 0 END) AS strict_hns_ready,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND (
                      COALESCE(rs.has_synth, 0) = 1
                      OR COALESCE(rs.has_glue, 0) = 1
                      OR (COALESCE(rs.has_ds, 0) = 1 AND COALESCE(rs.has_ns, 0) = 1)
                    )
                   THEN 1 ELSE 0 END) AS likely_websites,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND (COALESCE(rs.has_ds, 0) = 1 OR ls.dnssec_status = 'valid')
                    AND COALESCE(ls.dane_status, '') != 'valid'
                    AND COALESCE(ls.tlsa_status, 'missing') IN ('missing', 'unknown', '')
                   THEN 1 ELSE 0 END) AS needs_dane,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0 AND ps.provider_type = 'default_parking'
                   THEN 1 ELSE 0 END) AS default_provider_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND (
                      ls.failure_reason IS NOT NULL
                      OR (
                        COALESCE(rs.has_ns, 0) = 1
                        AND COALESCE(rs.has_glue, 0) = 0
                        AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'
                      )
                    )
                   THEN 1 ELSE 0 END) AS needs_fix,
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
    summary = {
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
        "synth_nameserver_records": _row_int(resource_counts, "direct_ip_records"),
        "delegated_names": _row_int(resource_counts, "delegated_names"),
        "delegated_with_glue": _row_int(resource_counts, "delegated_with_glue"),
        "delegated_no_glue": _row_int(resource_counts, "delegated_no_glue"),
        "default_provider_names": _row_int(resource_counts, "default_provider_names"),
        "ds_records": _row_int(resource_counts, "ds_records"),
        "dnssec_candidates": _row_int(resource_counts, "dnssec_candidates"),
        "dnssec_valid": _row_int(live_counts, "dnssec_valid"),
        "likely_websites": _row_int(resource_counts, "likely_websites"),
        "strict_hns_ready": _row_int(resource_counts, "strict_hns_ready"),
        "strict_hns_working": _row_int(live_counts, "strict_hns_working"),
        "doh_fallback_required": _row_int(live_counts, "doh_fallback_required"),
        "resolver_fallback_required": _row_int(live_counts, "doh_fallback_required"),
        "needs_dane": _row_int(resource_counts, "needs_dane"),
        "dane_working": _row_int(live_counts, "dane_working"),
        "needs_fix": _row_int(resource_counts, "needs_fix"),
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
    summary["classes"] = build_classes(conn)
    summary["providers"] = build_providers(conn)
    summary["broken"] = build_broken(conn)
    summary["next_actions"] = build_next_actions(summary)
    return summary


def build_next_actions(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "key": "generate_tlsa",
            "label": "Generate TLSA",
            "count": int(summary["needs_dane"]),
            "filter": "needs_dane",
            "filter_link": "names.html?filter=needs_dane",
            "generator_intent": "generate_tlsa",
            "definition": "DS or live-valid DNSSEC exists, but valid TLSA/DANE is not proven.",
        },
        {
            "key": "fix_ns_glue",
            "label": "Generate NS/GLUE setup",
            "count": int(summary["missing_glue_only"]),
            "filter": "missing_glue_only",
            "filter_link": "names.html?filter=missing_glue_only",
            "generator_intent": "missing_glue",
            "definition": "Delegated names need parent-side nameserver bootstrap before strict HNS can work.",
        },
        {
            "key": "replace_tlsa",
            "label": "Generate current TLSA",
            "count": int(summary["stale_tlsa_only"]),
            "filter": "stale_tlsa_only",
            "filter_link": "names.html?filter=stale_tlsa_only",
            "generator_intent": "stale_tlsa",
            "definition": "TLSA data did not match the current HTTPS certificate public key.",
        },
        {
            "key": "plan_dnssec_dane",
            "label": "Plan DNSSEC/DANE",
            "count": int(summary["strict_hns_ready"]),
            "filter": "strict_hns_ready",
            "filter_link": "names.html?filter=strict_hns_ready",
            "generator_intent": "dnssec_dane",
            "definition": "Strict-HNS bootstrap material exists; sign the zone, publish DS, and add TLSA.",
        },
        {
            "key": "verified_dane",
            "label": "Verified DANE",
            "count": int(summary["dane_working"]),
            "filter": "dane_working",
            "filter_link": "names.html?filter=dane_working",
            "generator_intent": "",
            "definition": "Latest live check matched DNSSEC, TLSA, and HTTPS certificate/SPKI.",
        },
    ]


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
            "How many HNS names use SYNTH nameserver bootstrap?",
            "direct_ip_records",
            "Current HNS resource data contains SYNTH4 or SYNTH6 nameserver bootstrap addresses. The authoritative DNS server still publishes website A, AAAA, and TLSA records.",
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
            "Active names with SYNTH nameserver bootstrap, GLUE-backed delegation, or DS-backed delegation.",
            "names.html?filter=likely_websites",
        ),
        answer(
            "strict_hns_ready",
            "How many are strict-HNS ready from on-chain data?",
            "strict_hns_ready",
            "Active names with SYNTH nameserver bootstrap or delegated nameserver data plus GLUE. This is readiness from HNS resource data, not proof the website currently loads.",
            "names.html?filter=strict_hns_ready",
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
            "How many require resolver fallback?",
            "doh_fallback_required",
            "Latest live check could only find a website address through the configured fallback resolver, not through strict HNS bootstrap. This does not prove a specific DoH transport by itself.",
            "names.html?filter=doh_fallback_required",
        ),
        answer(
            "needs_dane",
            "Which names need a TLSA/DANE step next?",
            "needs_dane",
            "Names with DS or live-valid DNSSEC where the latest data does not show valid DANE and TLSA is missing or still unknown.",
            "names.html?filter=needs_dane",
        ),
        answer(
            "dane_working",
            "How many have working DANE?",
            "dane_working",
            "Latest live check found a TLSA record matching the HTTPS certificate/SPKI.",
            "names.html?filter=dane_working",
        ),
        answer(
            "needs_fix",
            "Which names need a DNS or DANE fix?",
            "needs_fix",
            "Names with a live-check failure reason, plus delegated names that are missing GLUE before live checks can prove anything stronger.",
            "names.html?filter=needs_fix",
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
    for key in FAQ_KEYS:
        where = NAME_FILTERS.get(key)
        if not where:
            continue
        rows = conn.execute(
            f"""
            SELECT n.name
            {_name_rows_from_sql()}
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
    return {"reasons": reasons}


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
          rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
          { _dns_evidence_path_sql() },
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


def write_names_pages(
    conn: sqlite3.Connection,
    out: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    return _write_names_pages_streamed(conn, out / "names-pages", limit=limit, page_size=page_size)


def write_dns_evidence(conn: sqlite3.Connection, out: Path) -> int:
    base_dir = out / "dns-evidence"
    _remove_tree(base_dir, missing_ok=True)
    names = [
        row["name"]
        for row in conn.execute(
            """
            SELECT DISTINCT name
            FROM dns_evidence
            ORDER BY name
            """
        )
    ]
    if not names:
        return 0
    base_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        write_json(base_dir / f"{name}.json", build_dns_evidence(conn, name))
    return len(names)


def build_dns_evidence(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT *
        FROM dns_evidence
        WHERE name = ?
        ORDER BY captured_at DESC, id DESC
        """,
        (name,),
    ).fetchall()
    seen: set[tuple[str, str, str, str, str]] = set()
    observations: list[dict[str, Any]] = []
    for row in rows:
        key = (
            row["qname"],
            row["rrtype"],
            row["server"] or "",
            row["source"] or "",
            row["source_id"] or "",
        )
        if key in seen:
            continue
        seen.add(key)
        observations.append(_dns_evidence_row(row))
    observations.sort(
        key=lambda item: (
            str(item.get("qname") or ""),
            str(item.get("rrtype") or ""),
            str(item.get("server") or ""),
            str(item.get("source") or ""),
            str(item.get("source_id") or ""),
        )
    )
    return {
        "name": name,
        "observation_count": len(observations),
        "observations": observations,
    }


def _write_names_pages_streamed(
    conn: sqlite3.Connection,
    base_dir: Path,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    if base_dir.exists():
        _remove_tree(base_dir)
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


def _write_name_collection(
    conn: sqlite3.Connection,
    base_dir: Path,
    key: str,
    *,
    limit: int,
    page_size: int,
) -> dict[str, Any]:
    collection_dir = base_dir / _collection_dir_name(key)
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
    output_keys = _name_output_keys(row_detail=row_detail)
    if count == 0:
        page_payload: dict[str, Any] = {"page": 1, "rows": []}
        if row_detail == "compact":
            page_payload["columns"] = output_keys
        write_json(collection_dir / "page-1.json", page_payload)
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
            page_payload = {"page": page, "rows": rows}
            if row_detail == "compact":
                page_payload["columns"] = output_keys
                page_payload["rows"] = [[row.get(key) for key in output_keys] for row in rows]
            write_json(collection_dir / f"page-{page}.json", page_payload)
            page += 1
    _log_export(f"finished names-pages/{key}")
    return {
        "row_count": count,
        "total_count": total_count,
        "page_size": page_size,
        "page_count": page_count,
        "path_template": f"{base_dir.name}/{_collection_dir_name(key)}/page-{{page}}.json",
        "truncated": total_count > count,
        "row_detail": row_detail,
        "columns": output_keys if row_detail == "compact" else None,
    }


def _collection_dir_name(key: str) -> str:
    return key.replace("/", "__slash__")


def _name_collection_keys(conn: sqlite3.Connection) -> list[str]:
    provider_keys = [
        row["provider_key"]
        for row in conn.execute(
            """
            SELECT provider_key
            FROM provider_summary
            ORDER BY names_count DESC, provider_key
            """
        )
        if row["provider_key"]
    ]
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
        *(f"{PROVIDER_FILTER_PREFIX}{provider_key}" for provider_key in provider_keys),
        *(f"{PROVIDER_TYPE_FILTER_PREFIX}{provider_type}" for provider_type in provider_types),
    ]


def _name_row_columns(*, row_detail: str = "full") -> str:
    if row_detail == "compact":
        return f"""
      n.name, n.onchain_class, n.provider_guess,
      COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types, rs.has_ds,
      json_extract(rs.ns_names, '$[0]') AS first_ns,
      json_extract(rs.glue4, '$[0]') AS first_glue4,
      json_extract(rs.glue6, '$[0]') AS first_glue6,
      json_extract(rs.synth4, '$[0]') AS first_synth4,
      json_extract(rs.synth6, '$[0]') AS first_synth6,
      rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
      {_dns_evidence_path_sql()},
      ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.failure_reason, ls.checked_at
    """
    return f"""
      n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
      COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
      rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds,
      rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
      {_dns_evidence_path_sql()},
      ls.dns_reachable, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.https_status,
      ls.strict_hns_status, ls.doh_fallback_status, ls.failure_reason, ls.checked_at
    """


def _name_json_columns(*, row_detail: str = "full") -> list[str]:
    if row_detail == "compact":
        return ["record_types"]
    return ["record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"]


def _name_output_keys(*, row_detail: str = "full") -> list[str]:
    if row_detail == "compact":
        return [
            "name",
            "onchain_class",
            "provider_guess",
            "provider_type",
            "record_types",
            "has_ds",
            "first_ns",
            "first_glue4",
            "first_glue6",
            "first_synth4",
            "first_synth6",
            "raw_size",
            "resource_version",
            "resource_hash",
            "last_seen_height",
            "updated_at",
            "dns_evidence_path",
            "dnssec_status",
            "tlsa_status",
            "dane_status",
            "failure_reason",
            "checked_at",
        ]
    return []


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
    if key.startswith(PROVIDER_FILTER_PREFIX):
        return "COALESCE(n.expired, 0) = 0 AND n.provider_guess = ?", (
            key.removeprefix(PROVIDER_FILTER_PREFIX),
        )
    if key.startswith(PROVIDER_TYPE_FILTER_PREFIX):
        return "COALESCE(ps.provider_type, 'unknown') = ?", (
            key.removeprefix(PROVIDER_TYPE_FILTER_PREFIX),
        )
    return f"COALESCE(n.expired, 0) = 0 AND ({NAME_FILTERS.get(key, '1=1')})", ()


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
        "raw_size",
        "resource_version",
        "resource_hash",
        "last_seen_height",
        "updated_at",
        "dns_evidence_path",
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
    for directory in ("names-pages", "dns-evidence"):
        paths.extend(
            path.relative_to(out).as_posix()
            for path in sorted((out / directory).glob("*/*.json"))
        )
        paths.extend(
            path.relative_to(out).as_posix()
            for path in sorted((out / directory).glob("*.json"))
        )
    return paths


def _effective_names_limit(summary: dict[str, Any], names_limit: int) -> int:
    total = int(summary["total_names"])
    if names_limit <= 0:
        return total
    return min(total, names_limit)


def _remove_obsolete_data(out: Path) -> None:
    for relative in ("classes.json", "providers.json", "broken.json", "dane.json", "dane-pages.json"):
        (out / relative).unlink(missing_ok=True)
    _remove_tree(out / "dane-pages", missing_ok=True)
    _remove_tree(out / "dns-evidence", missing_ok=True)


def _remove_tree(path: Path, *, missing_ok: bool = False) -> None:
    if not path.exists():
        if missing_ok:
            return
        raise FileNotFoundError(path)
    last_error: OSError | None = None
    for attempt in range(5):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        except OSError as exc:
            last_error = exc
            time.sleep(0.25 * (attempt + 1))
    if last_error is not None:
        raise last_error


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


def _dns_evidence_path_sql() -> str:
    return """
      CASE WHEN EXISTS(
        SELECT 1
        FROM dns_evidence de
        WHERE de.name = n.name
      ) THEN 'dns-evidence/' || n.name || '.json' ELSE NULL END AS dns_evidence_path
    """


def _dns_evidence_row(row: sqlite3.Row) -> dict[str, Any]:
    result = {
        "qname": row["qname"],
        "rrtype": row["rrtype"],
        "server": row["server"],
        "source": row["source"],
        "source_id": row["source_id"],
        "status": row["status"],
        "rcode": row["rcode"],
        "flags": row["flags"],
        "elapsed_ms": row["elapsed_ms"],
        "error": row["error"],
        "captured_at": row["captured_at"],
        "answer": _loads_json_list(row["answer_json"]),
        "authority": _loads_json_list(row["authority_json"]),
        "additional": _loads_json_list(row["additional_json"]),
    }
    return {key: value for key, value in result.items() if value not in (None, "", [])}


def _loads_json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


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
