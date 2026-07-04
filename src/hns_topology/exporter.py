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
from urllib.parse import quote

from . import __version__
from .db import get_meta, parse_json_columns, require_resource_ip_index, rows_to_dicts, table_count
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
IP_FIELD_BITS = {
    "GLUE4": 1,
    "GLUE6": 2,
    "SYNTH4": 4,
    "SYNTH6": 8,
}

NAME_FILTERS = {
    "direct_ip_records": "rs.has_synth = 1",
    "delegated_names": "rs.has_ns = 1",
    "default_provider_names": "ps.provider_type = 'default_parking'",
    "ds_records": "rs.has_ds = 1",
    "dnssec_candidates": "rs.has_ds = 1 AND rs.has_ns = 1",
    "dane_rows": "rs.has_ds = 1 OR ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL",
    "strict_hns_ready": (
        "rs.has_synth = 1 OR (rs.has_ns = 1 AND rs.has_glue = 1)"
    ),
    "likely_websites": (
        "rs.has_synth = 1 OR rs.has_glue = 1 OR (rs.has_ds = 1 AND rs.has_ns = 1)"
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
        "(rs.has_ns = 1 AND rs.has_glue = 0 AND "
        "COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue')"
    ),
    "missing_glue": "ls.failure_reason = 'missing_glue'",
    "missing_glue_only": (
        "rs.has_ns = 1 AND rs.has_glue = 0 AND "
        "COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'"
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
    require_resource_ip_index(conn)
    summary = build_summary(conn)
    effective_names_limit = _effective_names_limit(summary, names_limit)
    _log_export(f"export start out={out} names_limit={names_limit} effective_names_limit={effective_names_limit}")
    write_json(out / "summary.json", summary)
    _log_export("wrote summary.json")
    write_json(out / "faq_answers.json", build_faq_answers(conn, summary))
    _log_export("wrote faq_answers.json")
    write_json(out / "names-pages.json", write_names_pages(conn, out, limit=effective_names_limit, page_size=PAGE_SIZE))
    _log_export("wrote names-pages.json")
    ip_address_count = write_ip_address_names(conn, out, limit=effective_names_limit)
    _log_export(f"wrote ip address files={ip_address_count}")
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


def write_ip_address_names(conn: sqlite3.Connection, out: Path, *, limit: int) -> int:
    base_dir = out / "ip-addresses"
    _remove_tree(base_dir, missing_ok=True)
    if limit <= 0:
        return 0
    base_dir.mkdir(parents=True, exist_ok=True)
    row_detail = "ip_matches"
    output_keys = ["name", "field_mask"]
    file_count = 0
    total_names = table_count(conn, "SELECT COUNT(*) FROM names")
    for item in _ip_address_counts(conn, limit=limit, total_names=total_names):
        ip = item["ip"]
        row_count = int(item["row_count"] or 0)
        field_counts = _ip_address_field_counts(conn, ip, limit=limit, total_names=total_names)
        default_field_mask = _default_ip_field_mask(field_counts, row_count)
        current_rows: list[dict[str, Any]] = []
        current_page = 1
        for row in _ip_address_rows(conn, ip, limit=limit, total_names=total_names):
            current_rows.append(
                {
                    "name": row["name"],
                    "field_mask": _ip_field_mask(str(row["fields"] or "")),
                }
            )
            if len(current_rows) >= PAGE_SIZE:
                _write_ip_address_page(
                    base_dir,
                    ip,
                    current_page,
                    current_rows,
                    output_keys=output_keys,
                    default_field_mask=default_field_mask,
                )
                current_rows = []
                current_page += 1
        _finish_ip_address_pages(
            base_dir,
            ip,
            rows=current_rows,
            row_count=row_count,
            page=current_page,
            row_detail=row_detail,
            output_keys=output_keys,
            field_counts=field_counts,
            default_field_mask=default_field_mask,
        )
        file_count += 1
    return file_count


def _ip_address_counts(
    conn: sqlite3.Connection,
    *,
    limit: int,
    total_names: int,
) -> sqlite3.Cursor:
    if limit >= total_names:
        return conn.execute(
            """
            SELECT ip, COUNT(DISTINCT name) AS row_count
            FROM resource_ip
            GROUP BY ip
            ORDER BY ip
            """
        )
    return conn.execute(
        """
        WITH exported_names AS (
          SELECT name
          FROM names
          ORDER BY name
          LIMIT ?
        )
        SELECT ri.ip, COUNT(DISTINCT ri.name) AS row_count
        FROM resource_ip ri
        JOIN exported_names en ON en.name = ri.name
        GROUP BY ri.ip
        ORDER BY ri.ip
        """,
        (limit,),
    )


def _ip_address_field_counts(
    conn: sqlite3.Connection,
    ip: str,
    *,
    limit: int,
    total_names: int,
) -> dict[str, int]:
    if limit >= total_names:
        rows = conn.execute(
            """
            SELECT field, COUNT(DISTINCT name) AS row_count
            FROM resource_ip
            WHERE ip = ?
            GROUP BY field
            ORDER BY field
            """,
            (ip,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            WITH exported_names AS (
              SELECT name
              FROM names
              ORDER BY name
              LIMIT ?
            )
            SELECT ri.field, COUNT(DISTINCT ri.name) AS row_count
            FROM resource_ip ri
            JOIN exported_names en ON en.name = ri.name
            WHERE ri.ip = ?
            GROUP BY ri.field
            ORDER BY ri.field
            """,
            (limit, ip),
        ).fetchall()
    return {row["field"]: int(row["row_count"] or 0) for row in rows}


def _ip_address_rows(
    conn: sqlite3.Connection,
    ip: str,
    *,
    limit: int,
    total_names: int,
) -> sqlite3.Cursor:
    if limit >= total_names:
        return conn.execute(
            """
            SELECT name, group_concat(field) AS fields
            FROM resource_ip
            WHERE ip = ?
            GROUP BY name
            ORDER BY name
            """,
            (ip,),
        )
    return conn.execute(
        """
        WITH exported_names AS (
          SELECT name
          FROM names
          ORDER BY name
          LIMIT ?
        )
        SELECT ri.name, group_concat(ri.field) AS fields
        FROM resource_ip ri
        JOIN exported_names en ON en.name = ri.name
        WHERE ri.ip = ?
        GROUP BY ri.name
        ORDER BY ri.name
        """,
        (limit, ip),
    )


def _finish_ip_address_pages(
    base_dir: Path,
    ip: str,
    *,
    rows: list[dict[str, Any]],
    row_count: int,
    page: int,
    row_detail: str,
    output_keys: list[str],
    field_counts: dict[str, int],
    default_field_mask: int | None,
) -> None:
    if rows:
        _write_ip_address_page(
            base_dir,
            ip,
            page,
            rows,
            output_keys=output_keys,
            default_field_mask=default_field_mask,
        )
    _write_ip_address_index(
        base_dir,
        ip,
        row_count=row_count,
        row_detail=row_detail,
        output_keys=output_keys,
        field_counts=field_counts,
        default_field_mask=default_field_mask,
    )


def _write_ip_address_index(
    base_dir: Path,
    ip: str,
    *,
    row_count: int,
    row_detail: str,
    output_keys: list[str],
    field_counts: dict[str, int],
    default_field_mask: int | None,
) -> None:
    page_count = math.ceil(row_count / PAGE_SIZE) if row_count else 0
    payload = {
        "ip": ip,
        "row_count": row_count,
        "page_size": PAGE_SIZE,
        "page_count": page_count,
        "path_template": f"ip-addresses/{_ip_address_basename(ip)}/page-{{page}}.json",
        "row_detail": row_detail,
        "columns": output_keys,
        "field_map": {str(bit): field for field, bit in IP_FIELD_BITS.items()},
        "field_counts": dict(sorted(field_counts.items())),
        "default_field_mask": default_field_mask,
    }
    write_json(base_dir / _ip_address_filename(ip), payload)


def _write_ip_address_page(
    base_dir: Path,
    ip: str,
    page: int,
    rows: list[dict[str, Any]],
    *,
    output_keys: list[str],
    default_field_mask: int | None,
) -> None:
    page_dir = base_dir / _ip_address_basename(ip)
    page_dir.mkdir(parents=True, exist_ok=True)
    if default_field_mask is not None and all(row.get("field_mask") == default_field_mask for row in rows):
        payload = {
            "page": page,
            "row_encoding": "name",
            "field_mask": default_field_mask,
            "rows": [row["name"] for row in rows],
        }
    else:
        payload = {
            "page": page,
            "row_encoding": "name_field_mask",
            "columns": output_keys,
            "rows": [[row.get(key) for key in output_keys] for row in rows],
        }
    write_compact_json(page_dir / f"page-{page}.json", payload)


def _ip_field_mask(fields: str) -> int:
    mask = 0
    for field in fields.split(","):
        mask |= IP_FIELD_BITS.get(field, 0)
    return mask


def _default_ip_field_mask(field_counts: dict[str, int], row_count: int) -> int | None:
    if row_count <= 0 or len(field_counts) != 1:
        return None
    [(field, count)] = field_counts.items()
    if count != row_count:
        return None
    return IP_FIELD_BITS.get(field)


def _ip_address_basename(ip: str) -> str:
    return quote(ip, safe="")


def _ip_address_filename(ip: str) -> str:
    return f"{_ip_address_basename(ip)}.json"


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

    total_names = table_count(conn, "SELECT COUNT(*) FROM names")
    exported_names = min(total_names, max(0, limit))
    row_detail = "full" if total_names <= DETAILED_NAME_COLLECTION_ROW_LIMIT else "compact"
    output_keys = _name_output_keys(row_detail=row_detail)
    _prepare_export_name_ordinals(conn, exported_names)
    try:
        collections: dict[str, Any] = {}
        keys = _name_collection_keys(conn)
        _log_export(
            f"writing names-pages row_store rows={exported_names} total={total_names} "
            f"row_detail={row_detail}"
        )
        collections["all"] = _write_name_row_store(
            conn,
            base_dir,
            row_count=exported_names,
            total_count=total_names,
            row_detail=row_detail,
            page_size=page_size,
        )
        _log_export(f"writing names-pages postings collections={len(keys) - 1}")
        for key in keys:
            if key == "all":
                continue
            collections[key] = _write_name_postings_collection(
                conn,
                base_dir,
                key,
                row_detail=row_detail,
                page_size=page_size,
            )
        _log_export("finished names-pages collections")
        return {
            "page_size": page_size,
            "limit": limit,
            "row_store": {
                "path_template": collections["all"]["path_template"],
                "row_detail": row_detail,
                "columns": output_keys if row_detail == "compact" else None,
                "page_size": page_size,
                "row_count": exported_names,
                "page_count": collections["all"]["page_count"],
            },
            "collections": collections,
        }
    finally:
        conn.execute("DROP TABLE IF EXISTS temp.export_name_ordinals")


def _prepare_export_name_ordinals(conn: sqlite3.Connection, limit: int) -> None:
    conn.execute("DROP TABLE IF EXISTS temp.export_name_ordinals")
    conn.execute(
        """
        CREATE TEMP TABLE export_name_ordinals(
          name TEXT PRIMARY KEY,
          ordinal INTEGER NOT NULL
        ) WITHOUT ROWID
        """
    )
    if limit <= 0:
        return
    conn.execute(
        """
        INSERT INTO export_name_ordinals(name, ordinal)
        SELECT name, ordinal
        FROM (
          SELECT
            name,
            row_number() OVER (ORDER BY name) - 1 AS ordinal
          FROM names
          ORDER BY name
          LIMIT ?
        )
        """,
        (limit,),
    )


def _write_name_row_store(
    conn: sqlite3.Connection,
    base_dir: Path,
    *,
    row_count: int,
    total_count: int,
    row_detail: str,
    page_size: int,
) -> dict[str, Any]:
    key = "all"
    collection_dir = base_dir / _collection_dir_name(key)
    collection_dir.mkdir(parents=True, exist_ok=True)
    from_sql = _name_rows_from_sql()
    page_count = max(1, math.ceil(row_count / page_size)) if row_count else 0
    _log_export(
        f"writing names-pages/{key} rows={row_count} total={total_count} pages={page_count} "
        f"truncated={total_count > row_count} row_detail={row_detail}"
    )
    row_columns = _name_row_columns(row_detail=row_detail)
    json_columns = _name_json_columns(row_detail=row_detail)
    output_keys = _name_output_keys(row_detail=row_detail)
    if row_count == 0:
        page_payload: dict[str, Any] = {"page": 1, "rows": []}
        if row_detail == "compact":
            page_payload["columns"] = output_keys
        write_compact_json(collection_dir / "page-1.json", page_payload)
    else:
        cursor = conn.execute(
            f"""
            SELECT {row_columns}
            {from_sql}
            JOIN export_name_ordinals eno ON eno.name = n.name
            ORDER BY n.name
            """
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
            write_compact_json(collection_dir / f"page-{page}.json", page_payload)
            page += 1
    _log_export(f"finished names-pages/{key}")
    return {
        "row_count": row_count,
        "total_count": total_count,
        "page_size": page_size,
        "page_count": page_count,
        "path_template": f"{base_dir.name}/{_collection_dir_name(key)}/page-{{page}}.json",
        "truncated": total_count > row_count,
        "row_source": "rows",
        "row_detail": row_detail,
        "columns": output_keys if row_detail == "compact" else None,
    }


def _write_name_postings_collection(
    conn: sqlite3.Connection,
    base_dir: Path,
    key: str,
    *,
    row_detail: str,
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
    row_count = int(
        conn.execute(
            f"""
            SELECT COUNT(*)
            {from_sql}
            JOIN export_name_ordinals eno ON eno.name = n.name
            WHERE {where}
            """,
            params,
        ).fetchone()[0]
        or 0
    )
    page_count = max(1, math.ceil(row_count / page_size)) if row_count else 0
    _log_export(
        f"writing names-pages/{key} postings rows={row_count} total={total_count} "
        f"pages={page_count} truncated={total_count > row_count}"
    )
    if row_count == 0:
        write_compact_json(
            collection_dir / "page-1.json",
            {"page": 1, "row_encoding": "ordinal", "rows": []},
        )
    else:
        cursor = conn.execute(
            f"""
            SELECT eno.ordinal
            {from_sql}
            JOIN export_name_ordinals eno ON eno.name = n.name
            WHERE {where}
            ORDER BY n.name
            """,
            params,
        )
        page = 1
        while True:
            page_rows = cursor.fetchmany(page_size)
            if not page_rows:
                break
            write_compact_json(
                collection_dir / f"page-{page}.json",
                {
                    "page": page,
                    "row_encoding": "ordinal",
                    "rows": [int(row["ordinal"]) for row in page_rows],
                },
            )
            page += 1
    _log_export(f"finished names-pages/{key}")
    output_keys = _name_output_keys(row_detail=row_detail)
    return {
        "row_count": row_count,
        "total_count": total_count,
        "page_size": page_size,
        "page_count": page_count,
        "path_template": f"{base_dir.name}/{_collection_dir_name(key)}/page-{{page}}.json",
        "truncated": total_count > row_count,
        "row_source": "postings",
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


def write_compact_json(path: Path, value: Any) -> None:
    path.write_text(dumps_json(value), encoding="utf-8")


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
    for directory in ("names-pages", "ip-addresses", "dns-evidence"):
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
