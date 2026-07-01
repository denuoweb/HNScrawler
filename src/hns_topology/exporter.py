from __future__ import annotations

import csv
import gzip
import shutil
import sqlite3
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
    "dane.json",
    "names.json",
    "names.csv",
    "topology.sqlite.gz",
)


def export_all(conn: sqlite3.Connection, *, db_path: str | Path, out_dir: str | Path, names_limit: int = 5000) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = build_summary(conn)
    write_json(out / "summary.json", summary)
    write_json(out / "faq_answers.json", build_faq_answers(conn, summary))
    write_json(out / "classes.json", build_classes(conn))
    write_json(out / "providers.json", build_providers(conn))
    write_json(out / "broken.json", build_broken(conn))
    write_json(out / "dane.json", build_dane(conn))
    write_json(out / "names.json", build_names(conn, limit=names_limit))
    write_names_csv(conn, out / "names.csv", limit=names_limit)
    gzip_sqlite(db_path, out / "topology.sqlite.gz")
    write_json(out / "manifest.json", build_manifest(out, summary=summary, names_limit=names_limit))


def build_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    active = table_count(conn, "SELECT COUNT(*) FROM names WHERE expired = 0")
    total = table_count(conn, "SELECT COUNT(*) FROM names")
    expired = table_count(conn, "SELECT COUNT(*) FROM names WHERE expired = 1")
    direct_ip = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND (json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0)
        """,
    )
    delegated = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND json_array_length(rs.ns_names) > 0
        """,
    )
    delegated_with_glue = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND json_array_length(rs.ns_names) > 0
          AND (json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0)
        """,
    )
    delegated_no_glue = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND json_array_length(rs.ns_names) > 0
          AND json_array_length(rs.glue4) = 0 AND json_array_length(rs.glue6) = 0
        """,
    )
    ds_records = table_count(
        conn,
        "SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name WHERE n.expired = 0 AND rs.has_ds = 1",
    )
    dnssec_candidates = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0
        """,
    )
    dnssec_valid = table_count(
        conn,
        "SELECT COUNT(*) FROM live_status WHERE dnssec_status = 'valid'",
    )
    likely_websites = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN resource_summary rs ON rs.name = n.name
        WHERE n.expired = 0 AND (
          json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0 OR
          json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0 OR
          (rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0)
        )
        """,
    )
    strict_hns_working = table_count(
        conn,
        "SELECT COUNT(*) FROM live_status WHERE strict_hns_status = 'working'",
    )
    doh_fallback_required = table_count(
        conn,
        "SELECT COUNT(*) FROM live_status WHERE doh_fallback_status IN ('required', 'doh_fallback_only')",
    )
    dane_working = table_count(conn, "SELECT COUNT(*) FROM live_status WHERE dane_status = 'valid'")
    default_provider = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE n.expired = 0 AND ps.provider_type = 'default_parking'
        """,
    )
    missing_glue = table_count(
        conn,
        """
        SELECT COUNT(*) FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        WHERE n.expired = 0
          AND json_array_length(rs.ns_names) > 0
          AND json_array_length(rs.glue4) = 0
          AND json_array_length(rs.glue6) = 0
          AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'
        """,
    )
    stale_tlsa = table_count(
        conn,
        "SELECT COUNT(*) FROM live_status WHERE failure_reason = 'stale_tlsa_spki_mismatch'",
    )
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
        "total_names": total,
        "active_names": active,
        "expired_names": expired,
        "direct_ip_records": direct_ip,
        "delegated_names": delegated,
        "delegated_with_glue": delegated_with_glue,
        "delegated_no_glue": delegated_no_glue,
        "default_provider_names": default_provider,
        "ds_records": ds_records,
        "dnssec_candidates": dnssec_candidates,
        "dnssec_valid": dnssec_valid,
        "likely_websites": likely_websites,
        "strict_hns_working": strict_hns_working,
        "doh_fallback_required": doh_fallback_required,
        "dane_working": dane_working,
        "missing_glue_only": missing_glue,
        "stale_tlsa_only": stale_tlsa,
        "live_check_started_at": get_meta(conn, "live_check_started_at", ""),
        "live_check_finished_at": get_meta(conn, "live_check_finished_at", ""),
    }


def build_faq_answers(conn: sqlite3.Connection, summary: dict[str, Any]) -> list[dict[str, Any]]:
    active = max(1, int(summary["active_names"]))

    def answer(key: str, question: str, count_key: str, definition: str, filter_link: str) -> dict[str, Any]:
        count = int(summary[count_key])
        return {
            "key": key,
            "question": question,
            "count": count,
            "percentage_of_active": round((count / active) * 100, 4),
            "definition": definition,
            "examples": examples_for_filter(conn, key),
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
            "providers.html?filter=default_provider_names",
        ),
        answer(
            "ds_records",
            "How many have DS records?",
            "ds_records",
            "Current HNS resource data contains at least one DS record.",
            "dane.html?filter=ds_records",
        ),
        answer(
            "dnssec_candidates",
            "How many are DNSSEC candidates?",
            "dnssec_candidates",
            "Current HNS resource data contains DS plus delegated nameserver data.",
            "dane.html?filter=dnssec_candidates",
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
            "broken.html?filter=doh_fallback_required",
        ),
        answer(
            "dane_working",
            "How many have working DANE?",
            "dane_working",
            "Latest live check found a TLSA record matching the HTTPS certificate/SPKI.",
            "dane.html?filter=dane_working",
        ),
        answer(
            "missing_glue_only",
            "Which names are broken only because of missing GLUE?",
            "missing_glue_only",
            "Delegated names with no GLUE4/GLUE6 and no stronger live-check failure.",
            "broken.html?filter=missing_glue_only",
        ),
        answer(
            "stale_tlsa_only",
            "Which names are broken only because of stale TLSA?",
            "stale_tlsa_only",
            "Latest live check found TLSA data that does not match the current HTTPS certificate/SPKI.",
            "broken.html?filter=stale_tlsa_only",
        ),
    ]


def build_classes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = []
    for klass in ONCHAIN_CLASSES:
        count = table_count(conn, "SELECT COUNT(*) FROM names WHERE onchain_class = ?", (klass,))
        rows.append({"class": klass, "count": count})
    return rows


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


def build_dane(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = [
        parse_json_columns(
            dict(row),
            ["ns_names"],
        )
        for row in conn.execute(
            """
            SELECT n.name, rs.has_ds, rs.ns_names, ls.dnssec_status, ls.tlsa_status, ls.dane_status, ls.failure_reason, ls.checked_at
            FROM names n
            JOIN resource_summary rs ON rs.name = n.name
            LEFT JOIN live_status ls ON ls.name = n.name
            WHERE rs.has_ds = 1 OR ls.tlsa_status IS NOT NULL OR ls.dane_status IS NOT NULL
            ORDER BY COALESCE(ls.checked_at, n.updated_at) DESC, n.name
            LIMIT 500
            """
        )
    ]
    return {
        "ds_count": table_count(conn, "SELECT COUNT(*) FROM resource_summary WHERE has_ds = 1"),
        "valid_dane_count": table_count(conn, "SELECT COUNT(*) FROM live_status WHERE dane_status = 'valid'"),
        "rows": rows,
    }


def build_names(conn: sqlite3.Connection, *, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
          n.name, n.state, n.expired, n.onchain_class, n.provider_guess, n.record_types,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds,
          ls.dns_reachable, ls.dnssec_status, ls.dane_status, ls.https_status, ls.strict_hns_status,
          ls.doh_fallback_status, ls.failure_reason, ls.checked_at
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN live_status ls ON ls.name = n.name
        ORDER BY n.updated_at DESC, n.name
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [
        parse_json_columns(
            dict(row),
            ["record_types", "ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"],
        )
        for row in rows
    ]


def examples_for_filter(conn: sqlite3.Connection, key: str) -> list[str]:
    filters = {
        "direct_ip_records": "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0",
        "delegated_names": "json_array_length(rs.ns_names) > 0",
        "default_provider_names": "ps.provider_type = 'default_parking'",
        "ds_records": "rs.has_ds = 1",
        "dnssec_candidates": "rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0",
        "likely_websites": "json_array_length(rs.synth4) > 0 OR json_array_length(rs.synth6) > 0 OR json_array_length(rs.glue4) > 0 OR json_array_length(rs.glue6) > 0 OR (rs.has_ds = 1 AND json_array_length(rs.ns_names) > 0)",
        "strict_hns_working": "ls.strict_hns_status = 'working'",
        "doh_fallback_required": "ls.doh_fallback_status IN ('required', 'doh_fallback_only')",
        "dane_working": "ls.dane_status = 'valid'",
        "missing_glue_only": "json_array_length(rs.ns_names) > 0 AND json_array_length(rs.glue4) = 0 AND json_array_length(rs.glue6) = 0 AND COALESCE(ls.failure_reason, 'missing_glue') = 'missing_glue'",
        "stale_tlsa_only": "ls.failure_reason = 'stale_tlsa_spki_mismatch'",
    }
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


def build_manifest(out_dir: str | Path, *, summary: dict[str, Any], names_limit: int) -> dict[str, Any]:
    out = Path(out_dir)
    return {
        "manifest_version": 1,
        "exported_at": utc_now(),
        "crawler_version": __version__,
        "export": {
            "format": "hns-topology-static-report",
            "names_limit": names_limit,
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
        "artifacts": [_artifact_entry(out / relative, relative) for relative in DATA_ARTIFACTS],
    }


def _artifact_entry(path: Path, relative: str) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": file_sha256(path),
        "bytes": path.stat().st_size,
    }


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
