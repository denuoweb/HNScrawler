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
from collections import OrderedDict
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import quote

from . import __version__
from .compliance import (
    COMPLIANCE_STAGE_DEFINITIONS,
    COMPLIANCE_STAGE_LABELS,
    COMPLIANCE_STAGES,
    compliance_stage_case,
)
from .db import get_meta, parse_json_columns, require_resource_ip_index, rows_to_dicts, table_count
from .fileutil import file_sha256
from .infra import KNOWN_HNS_RESOLVERS, NON_ACTIONABLE_PROVIDER_TYPES, resource_ip_role
from .jsonutil import dumps_json, dumps_pretty
from .models import ONCHAIN_CLASSES
from .ns_handoff import (
    HANDOFF_COHORT_MAX_MEMBERS,
    HANDOFF_COHORT_MIN_MEMBERS,
    NS_HANDOFF_COLUMNS,
    NS_HANDOFF_TABLE,
    drop_temp_ns_handoff_table,
    prepare_temp_ns_handoff_table,
)
from .timeutil import utc_now
from .verification import build_verification_plan

DATA_ARTIFACTS = (
    "summary.json",
    "overview-pages.json",
    "names-pages.json",
    "hns-handoff-groups.json",
)

PAGE_SIZE = 1000
NAMESERVER_SHARD_COUNT = 1024
OVERVIEW_PAGE_SIZE = 25
DETAILED_NAME_COLLECTION_ROW_LIMIT = 100_000
EXPORTED_NAMES_ORDER_SQL = "n.name"
PROVIDER_FILTER_PREFIX = "provider:"
COMPLIANCE_STAGE_FILTER_PREFIX = "stage:"
IP_FIELD_BITS = {
    "GLUE4": 1,
    "GLUE6": 2,
    "SYNTH4": 4,
    "SYNTH6": 8,
}
NON_ACTIONABLE_PROVIDER_TYPES_SQL = ", ".join(f"'{item}'" for item in NON_ACTIONABLE_PROVIDER_TYPES)
ACTIONABLE_PROVIDER_SQL = (
    f"COALESCE(ps.provider_type, 'unknown') NOT IN ({NON_ACTIONABLE_PROVIDER_TYPES_SQL})"
)
ACTIONABLE_EXPORT_SQL = f"provider_type NOT IN ({NON_ACTIONABLE_PROVIDER_TYPES_SQL})"
HANDOFF_COHORT_CLASSES = (
    "DIRECT_SYNTH",
    "DELEGATED_WITH_GLUE",
    "DELEGATED_NO_GLUE",
    "DNSSEC_CANDIDATE",
)
HANDOFF_COHORT_CLASSES_SQL = ", ".join(f"'{item}'" for item in HANDOFF_COHORT_CLASSES)
HANDOFF_UNBOUNDED_CANARY_MEMBERS = 3


class NextActionSpec(NamedTuple):
    key: str
    label: str
    stage: str
    generator_intent: str
    definition: str


class OverviewExplainerSpec(NamedTuple):
    key: str
    label: str
    count_key: str
    definition: str

NAME_FILTERS = {
    "direct_ip_records": "rs.has_synth = 1",
    "delegated_names": "rs.has_ns = 1",
    "default_provider_names": "ps.provider_type = 'default_parking'",
    "ds_records": "rs.has_ds = 1",
    "dnssec_candidates": "rs.has_ds = 1 AND rs.has_ns = 1",
    "tlsa_present_names": "COALESCE(tes.has_tlsa, 0) = 1",
    "strict_hns_ready": (
        f"{ACTIONABLE_PROVIDER_SQL} AND "
        "(rs.has_synth = 1 OR (rs.has_ns = 1 AND rs.has_glue = 1))"
    ),
    "likely_websites": (
        f"{ACTIONABLE_PROVIDER_SQL} AND "
        "(rs.has_synth = 1 OR rs.has_glue = 1 OR (rs.has_ds = 1 AND rs.has_ns = 1))"
    ),
    "needs_dane": (
        f"{ACTIONABLE_PROVIDER_SQL} AND "
        "rs.has_ds = 1 AND COALESCE(tes.has_tlsa, 0) = 0"
    ),
    "indirect_ns_handoffs": "enh.ns_handoff_bootstrap_ip IS NOT NULL",
    "needs_fix": "rs.has_ns = 1 AND rs.has_glue = 0 AND enh.ns_handoff_bootstrap_ip IS NULL",
    "missing_glue_only": "rs.has_ns = 1 AND rs.has_glue = 0 AND enh.ns_handoff_bootstrap_ip IS NULL",
}

NEXT_ACTION_SPECS = (
    NextActionSpec(
        key="generate_tlsa",
        label="Verify or generate TLSA",
        stage="tlsa_gap",
        generator_intent="generate_tlsa",
        definition="Parent DS is present, but no authoritative or authenticated TLSA answer is stored.",
    ),
    NextActionSpec(
        key="verify_ns_handoff",
        label="Verify NS handoff",
        stage="indirect_ns_handoff",
        generator_intent="missing_glue",
        definition="A delegated nameserver can be bootstrapped through another HNS root. Verify that handoff authority before treating the zone as reachable.",
    ),
    NextActionSpec(
        key="fix_ns_glue",
        label="Create NS/GLUE handoff",
        stage="missing_glue",
        generator_intent="missing_glue",
        definition="Delegated names need parent-side nameserver bootstrap before HNS resolution can reach the signed TLSA zone.",
    ),
    NextActionSpec(
        key="plan_dnssec_dane",
        label="Plan DNSSEC + DANE",
        stage="bootstrap_ready",
        generator_intent="dnssec_dane",
        definition="HNS bootstrap material exists; sign the authoritative zone, publish DS at the parent, and add TLSA.",
    ),
)

OVERVIEW_EXPLAINER_SPECS = (
    OverviewExplainerSpec(
        key="direct_ip_records",
        label="SYNTH nameserver bootstrap",
        count_key="direct_ip_records",
        definition="Current HNS resource data contains SYNTH4 or SYNTH6 nameserver bootstrap addresses. The authoritative DNS server can publish host A, AAAA, and TLSA records.",
    ),
    OverviewExplainerSpec(
        key="delegated_names",
        label="Delegated nameservers",
        count_key="delegated_names",
        definition="Current HNS resource data contains NS, GLUE4, or GLUE6 nameserver data.",
    ),
    OverviewExplainerSpec(
        key="default_provider_names",
        label="Default provider infrastructure",
        count_key="default_provider_names",
        definition="Provider rules classify the resource as default parking or default hosted infrastructure.",
    ),
    OverviewExplainerSpec(
        key="ds_records",
        label="DS records",
        count_key="ds_records",
        definition="Current HNS resource data contains at least one DS record.",
    ),
    OverviewExplainerSpec(
        key="dnssec_candidates",
        label="DNSSEC candidates",
        count_key="dnssec_candidates",
        definition="Current HNS resource data contains DS plus delegated nameserver data.",
    ),
    OverviewExplainerSpec(
        key="tlsa_present_names",
        label="TLSA observed",
        count_key="tlsa_present_names",
        definition="Stored delegated-DNS evidence contains an authoritative or authenticated HTTPS TLSA answer. This is presence evidence, not certificate-match proof.",
    ),
    OverviewExplainerSpec(
        key="likely_websites",
        label="Likely host roots",
        count_key="likely_websites",
        definition="Active roots with bootstrap or DNSSEC indicators that may be worth operator review.",
    ),
    OverviewExplainerSpec(
        key="strict_hns_ready",
        label="Strict HNS ready",
        count_key="strict_hns_ready",
        definition="Active roots with SYNTH nameserver bootstrap or delegated nameserver data plus GLUE. This is readiness from HNS resource data, not proof any host currently loads.",
    ),
    OverviewExplainerSpec(
        key="needs_dane",
        label="TLSA unobserved",
        count_key="needs_dane",
        definition="Actionable active names with parent DS but no stored authoritative or authenticated TLSA answer. Verify before generating a replacement.",
    ),
    OverviewExplainerSpec(
        key="indirect_ns_handoffs",
        label="Indirect NS handoffs",
        count_key="indirect_ns_handoffs",
        definition="Delegated names whose nameserver host can be bootstrapped through another active HNS root. They do not need duplicate direct GLUE, but the handoff authority still needs verification.",
    ),
    OverviewExplainerSpec(
        key="needs_fix",
        label="Needs fix",
        count_key="needs_fix",
        definition="Delegated names with neither direct GLUE nor an indexed HNS nameserver handoff.",
    ),
    OverviewExplainerSpec(
        key="missing_glue_only",
        label="Missing GLUE only",
        count_key="missing_glue_only",
        definition="Delegated names with no direct GLUE and no indexed HNS nameserver handoff.",
    ),
)

EXPORTED_NAME_FILTERS = (
    "direct_ip_records",
    "delegated_names",
    "default_provider_names",
    "likely_websites",
    "strict_hns_ready",
    "indirect_ns_handoffs",
    "needs_fix",
    "ds_records",
    "dnssec_candidates",
    "tlsa_present_names",
    "needs_dane",
    "missing_glue_only",
)

POSTING_NAME_FILTERS = {
    "direct_ip_records": "has_synth = 1",
    "delegated_names": "has_ns = 1",
    "default_provider_names": "provider_type = 'default_parking'",
    "ds_records": "has_ds = 1",
    "dnssec_candidates": "has_ds = 1 AND has_ns = 1",
    "tlsa_present_names": "has_tlsa = 1",
    "strict_hns_ready": (
        f"{ACTIONABLE_EXPORT_SQL} AND "
        "(has_synth = 1 OR (has_ns = 1 AND has_glue = 1))"
    ),
    "likely_websites": (
        f"{ACTIONABLE_EXPORT_SQL} AND "
        "(has_synth = 1 OR has_glue = 1 OR (has_ds = 1 AND has_ns = 1))"
    ),
    "needs_dane": f"{ACTIONABLE_EXPORT_SQL} AND has_ds = 1 AND has_tlsa = 0",
    "indirect_ns_handoffs": "compliance_stage = 'indirect_ns_handoff'",
    "needs_fix": "compliance_stage = 'missing_glue'",
    "missing_glue_only": "compliance_stage = 'missing_glue'",
}


def _name_compliance_stage_sql() -> str:
    return compliance_stage_case(
        expired="n.expired",
        provider_type="ps.provider_type",
        has_ds="rs.has_ds",
        has_ns="rs.has_ns",
        has_glue="rs.has_glue",
        has_synth="rs.has_synth",
        has_ns_handoff="enh.ns_handoff_bootstrap_ip IS NOT NULL",
        has_tlsa="COALESCE(tes.has_tlsa, 0)",
    )


def _export_compliance_stage_sql() -> str:
    return compliance_stage_case(
        expired="expired",
        provider_type="provider_type",
        has_ds="has_ds",
        has_ns="has_ns",
        has_glue="has_glue",
        has_synth="has_synth",
        has_ns_handoff="has_ns_handoff",
        has_tlsa="has_tlsa",
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
    write_json(out / "overview-pages.json", write_overview_pages(conn, out, page_size=OVERVIEW_PAGE_SIZE))
    _log_export("wrote overview-pages.json")
    write_json(out / "names-pages.json", write_names_pages(conn, out, limit=effective_names_limit, page_size=PAGE_SIZE))
    _log_export("wrote names-pages.json")
    handoff_group_count = write_hns_handoff_groups(conn, out)
    _log_export(f"wrote hns handoff groups={handoff_group_count}")
    ip_address_count = write_ip_address_names(conn, out, limit=effective_names_limit)
    _log_export(f"wrote ip address files={ip_address_count}")
    nameserver_count = write_nameserver_names(conn, out, limit=effective_names_limit)
    _log_export(f"wrote nameserver files={nameserver_count}")
    evidence_count = write_dns_evidence(conn, out)
    _log_export(f"wrote dns evidence files={evidence_count}")
    if include_downloads:
        write_json(out / "names.json", build_names(conn, limit=effective_names_limit))
        _log_export("wrote names.json")
        write_names_csv(conn, out / "names.csv", limit=effective_names_limit)
        _log_export("wrote names.csv")
        write_verification_csv(conn, out / "verification.csv", limit=effective_names_limit)
        _log_export("wrote verification.csv")
        gzip_sqlite(db_path, out / "topology.sqlite.gz")
        _log_export("wrote topology.sqlite.gz")
    else:
        for relative in (
            "names.json",
            "names.csv",
            "verification.csv",
            "topology.sqlite.gz",
        ):
            (out / relative).unlink(missing_ok=True)
    write_json(
        out / "manifest.json",
        build_manifest(out, summary=summary, names_limit=names_limit, include_downloads=include_downloads),
    )
    _log_export("wrote manifest.json")


def build_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    resource_counts = conn.execute(
        f"""
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
                    AND COALESCE(tes.has_tlsa, 0) = 1
                   THEN 1 ELSE 0 END) AS tlsa_present_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND tes.name IS NOT NULL
                   THEN 1 ELSE 0 END) AS tlsa_evidence_names,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND {ACTIONABLE_PROVIDER_SQL}
                    AND (
                      COALESCE(rs.has_synth, 0) = 1
                      OR (COALESCE(rs.has_ns, 0) = 1 AND COALESCE(rs.has_glue, 0) = 1)
                    )
                   THEN 1 ELSE 0 END) AS strict_hns_ready,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND {ACTIONABLE_PROVIDER_SQL}
                    AND (
                      COALESCE(rs.has_synth, 0) = 1
                      OR COALESCE(rs.has_glue, 0) = 1
                      OR (COALESCE(rs.has_ds, 0) = 1 AND COALESCE(rs.has_ns, 0) = 1)
                    )
                   THEN 1 ELSE 0 END) AS likely_websites,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0
                    AND {ACTIONABLE_PROVIDER_SQL}
                    AND COALESCE(rs.has_ds, 0) = 1
                    AND COALESCE(tes.has_tlsa, 0) = 0
                   THEN 1 ELSE 0 END) AS needs_dane,
          SUM(CASE WHEN COALESCE(n.expired, 0) = 0 AND ps.provider_type = 'default_parking'
                   THEN 1 ELSE 0 END) AS default_provider_names
        FROM names n
        LEFT JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
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
        "tlsa_present_names": _row_int(resource_counts, "tlsa_present_names"),
        "tlsa_evidence_names": _row_int(resource_counts, "tlsa_evidence_names"),
        "likely_websites": _row_int(resource_counts, "likely_websites"),
        "strict_hns_ready": _row_int(resource_counts, "strict_hns_ready"),
        "needs_dane": _row_int(resource_counts, "needs_dane"),
        "needs_fix": 0,
        "missing_glue_only": 0,
        "indirect_ns_handoffs": 0,
    }
    summary["classes"] = build_classes(conn)
    summary["providers"] = build_providers(conn)
    summary["top_resource_ips"] = build_top_resource_ips(conn)
    summary["top_nameservers"] = build_top_nameservers(conn)
    summary["known_hns_resolvers"] = build_known_hns_resolvers(conn)
    summary["compliance_stages"] = build_compliance_stages(conn)
    summary["compliance_stage_counts"] = {
        item["stage"]: int(item["count"]) for item in summary["compliance_stages"]
    }
    summary["indirect_ns_handoffs"] = summary["compliance_stage_counts"].get(
        "indirect_ns_handoff", 0
    )
    summary["needs_fix"] = summary["compliance_stage_counts"].get("missing_glue", 0)
    summary["missing_glue_only"] = summary["needs_fix"]
    summary["next_actions"] = build_next_actions(summary)
    summary["overview_explainers"] = build_overview_explainers(summary)
    return summary


def build_next_actions(summary: dict[str, Any]) -> list[dict[str, Any]]:
    stage_counts = summary.get("compliance_stage_counts", {})
    return [
        _next_action_from_spec(spec, stage_counts)
        for spec in NEXT_ACTION_SPECS
        if int(stage_counts.get(spec.stage, 0)) > 0
    ]


def build_compliance_stages(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    stage_sql = _name_compliance_stage_sql()
    prepare_temp_ns_handoff_table(
        conn,
        "SELECT name FROM names WHERE COALESCE(expired, 0) = 0",
    )
    try:
        counts = {
            row["compliance_stage"]: int(row["count"] or 0)
            for row in conn.execute(
                f"""
                SELECT compliance_stage, COUNT(*) AS count
                FROM (
                  SELECT {stage_sql} AS compliance_stage
                  FROM names n
                  JOIN resource_summary rs ON rs.name = n.name
                  LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
                  LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
                  LEFT JOIN {NS_HANDOFF_TABLE} enh ON enh.name = n.name
                  WHERE COALESCE(n.expired, 0) = 0
                )
                GROUP BY compliance_stage
                """
            )
        }
    finally:
        drop_temp_ns_handoff_table(conn)
    return [
        {
            "stage": stage,
            "label": COMPLIANCE_STAGE_LABELS[stage],
            "count": counts.get(stage, 0),
            "definition": COMPLIANCE_STAGE_DEFINITIONS[stage],
            "filter": _stage_filter(stage),
            "filter_link": _stage_filter_link(stage),
        }
        for stage in COMPLIANCE_STAGES
    ]


def build_overview_explainers(summary: dict[str, Any]) -> list[dict[str, Any]]:
    active = max(1, int(summary["active_names"]))
    return [
        _overview_explainer_from_spec(spec, summary, active)
        for spec in OVERVIEW_EXPLAINER_SPECS
    ]


def _next_action_from_spec(spec: NextActionSpec, stage_counts: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": spec.key,
        "label": spec.label,
        "count": int(stage_counts.get(spec.stage, 0)),
        "stage": spec.stage,
        "filter": _stage_filter(spec.stage),
        "filter_link": _stage_filter_link(spec.stage),
        "generator_intent": spec.generator_intent,
        "definition": spec.definition,
    }


def _overview_explainer_from_spec(
    spec: OverviewExplainerSpec,
    summary: dict[str, Any],
    active: int,
) -> dict[str, Any]:
    count = int(summary[spec.count_key])
    return {
        "key": spec.key,
        "label": spec.label,
        "count": count,
        "percentage_of_active": round((count / active) * 100, 4),
        "definition": spec.definition,
        "filter_link": _filter_link(spec.key),
    }


def _filter_link(filter_key: str) -> str:
    return f"names.html?filter={filter_key}"


def _stage_filter(stage: str) -> str:
    return f"{COMPLIANCE_STAGE_FILTER_PREFIX}{stage}"


def _stage_filter_link(stage: str) -> str:
    return _filter_link(_stage_filter(stage))


def build_classes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    counts = {
        row["onchain_class"]: int(row["count"])
        for row in conn.execute("SELECT onchain_class, COUNT(*) AS count FROM names GROUP BY onchain_class")
    }
    return [{"class": klass, "count": counts.get(klass, 0)} for klass in ONCHAIN_CLASSES]


def build_providers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return rows_to_dicts(
        conn.execute(
            """
            SELECT
              provider_key, provider_type, ns_pattern, ip_pattern,
              names_count, likely_website_count, updated_at
            FROM provider_summary
            ORDER BY names_count DESC, provider_key
            """
        )
    )


def build_top_resource_ips(conn: sqlite3.Connection, *, limit: int = 10) -> list[dict[str, Any]]:
    return build_resource_ips(conn, limit=limit)


def build_resource_ips(conn: sqlite3.Connection, *, limit: int | None = None) -> list[dict[str, Any]]:
    limit_sql = "LIMIT ?" if limit is not None else ""
    params: tuple[Any, ...] = (limit,) if limit is not None else ()
    rows = conn.execute(
        f"""
        SELECT ri.ip, COUNT(DISTINCT ri.name) AS names_count
        FROM resource_ip ri
        JOIN names n ON n.name = ri.name
        WHERE COALESCE(n.expired, 0) = 0
        GROUP BY ri.ip
        ORDER BY names_count DESC, ri.ip
        {limit_sql}
        """,
        params,
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        ip = str(row["ip"])
        role = resource_ip_role(ip)
        result.append(
            {
                "ip": ip,
                "names_count": int(row["names_count"] or 0),
                "field_counts": _top_ip_field_counts(conn, ip),
                "role": role["role"],
                "label": role["label"],
                "source": role["source"],
                "filter_link": f"names.html?q={quote(ip, safe='')}",
            }
        )
    return result


def build_top_nameservers(conn: sqlite3.Connection, *, limit: int = 10) -> list[dict[str, Any]]:
    return build_nameservers(conn, limit=limit)


def build_nameservers(conn: sqlite3.Connection, *, limit: int | None = None) -> list[dict[str, Any]]:
    limit_sql = "LIMIT ?" if limit is not None else ""
    params: tuple[Any, ...] = (limit,) if limit is not None else ()
    return [
        {
            "nameserver": str(row["nameserver"]),
            "names_count": int(row["names_count"] or 0),
            "filter_link": f"names.html?search=nameserver&q={quote(str(row['nameserver']), safe='')}",
        }
        for row in conn.execute(
            f"""
            SELECT LOWER(TRIM(ns.value, '.')) AS nameserver, COUNT(DISTINCT rs.name) AS names_count
            FROM resource_summary rs
            JOIN names n ON n.name = rs.name
            JOIN json_each(rs.ns_names) ns
            WHERE COALESCE(n.expired, 0) = 0
              AND ns.value IS NOT NULL
              AND LOWER(TRIM(ns.value, '.')) != ''
            GROUP BY LOWER(TRIM(ns.value, '.'))
            ORDER BY names_count DESC, nameserver
            {limit_sql}
            """,
            params,
        )
    ]


def build_known_hns_resolvers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {
            **dict(item),
            "names_count": _active_resource_ip_count(conn, str(item["ip"])),
            "filter_link": f"names.html?q={quote(str(item['ip']), safe='')}",
        }
        for item in KNOWN_HNS_RESOLVERS
    ]


def _active_resource_ip_count(conn: sqlite3.Connection, ip: str) -> int:
    return int(
        conn.execute(
            """
            SELECT COUNT(DISTINCT ri.name)
            FROM resource_ip ri
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
              AND ri.ip = ?
            """,
            (ip,),
        ).fetchone()[0]
        or 0
    )


def _top_ip_field_counts(conn: sqlite3.Connection, ip: str) -> dict[str, int]:
    return {
        row["field"]: int(row["names_count"] or 0)
        for row in conn.execute(
            """
            SELECT ri.field, COUNT(DISTINCT ri.name) AS names_count
            FROM resource_ip ri
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
              AND ri.ip = ?
            GROUP BY ri.field
            ORDER BY ri.field
            """,
            (ip,),
        )
    }


def build_names(
    conn: sqlite3.Connection,
    *,
    limit: int,
    offset: int = 0,
    where: str = "1=1",
) -> list[dict[str, Any]]:
    compliance_stage_sql = _name_compliance_stage_sql()
    params = (limit, offset)
    prepare_temp_ns_handoff_table(
        conn,
        f"""
        SELECT n.name
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
        WHERE {where}
        ORDER BY n.name
        LIMIT ?
        OFFSET ?
        """,
        params,
    )
    try:
        rows = conn.execute(
            f"""
            SELECT
              n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
              COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
              rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6,
              rs.ds_records, COALESCE(tes.tlsa_records, '[]') AS tlsa_records,
              COALESCE(tes.tlsa_owners, '[]') AS tlsa_owners,
              COALESCE(tes.has_tlsa, 0) AS has_tlsa,
              tes.observed_at AS tlsa_observed_at, tes.checked_at AS tlsa_checked_at,
              rs.has_ds,
              { _ns_handoff_select_columns() },
              rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
              { _dns_evidence_path_sql() },
              {compliance_stage_sql} AS compliance_stage
            {_name_rows_from_sql()}
            WHERE {where}
            ORDER BY n.name
            LIMIT ?
            OFFSET ?
            """,
            params,
        ).fetchall()
    finally:
        drop_temp_ns_handoff_table(conn)
    return [
        _name_row(
            row,
            [
                "record_types",
                "ns_names",
                "glue4",
                "glue6",
                "synth4",
                "synth6",
                "ds_records",
                "tlsa_records",
                "tlsa_owners",
            ],
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


def write_overview_pages(conn: sqlite3.Connection, out: Path, *, page_size: int) -> dict[str, Any]:
    base_dir = out / "overview-pages"
    _remove_tree(base_dir, missing_ok=True)
    base_dir.mkdir(parents=True, exist_ok=True)
    collections = {
        "resource_ips": _write_overview_collection(
            base_dir,
            "resource_ips",
            build_resource_ips(conn),
            page_size=page_size,
        ),
        "nameservers": _write_overview_collection(
            base_dir,
            "nameservers",
            build_nameservers(conn),
            page_size=page_size,
        ),
        "resolvers": _write_overview_collection(
            base_dir,
            "resolvers",
            build_known_hns_resolvers(conn),
            page_size=page_size,
        ),
    }
    return {
        "page_size": page_size,
        "collections": collections,
    }


def _write_overview_collection(
    base_dir: Path,
    key: str,
    rows: list[dict[str, Any]],
    *,
    page_size: int,
) -> dict[str, Any]:
    collection_dir = base_dir / key
    collection_dir.mkdir(parents=True, exist_ok=True)
    row_count = len(rows)
    page_count = math.ceil(row_count / page_size) if row_count else 0
    for index in range(page_count):
        page = index + 1
        start = index * page_size
        write_compact_json(
            collection_dir / f"page-{page}.json",
            {
                "page": page,
                "rows": rows[start:start + page_size],
            },
        )
    return {
        "row_count": row_count,
        "page_size": page_size,
        "page_count": page_count,
        "path_template": f"{base_dir.name}/{key}/page-{{page}}.json",
        "row_source": "rows",
    }


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


def write_hns_handoff_groups(conn: sqlite3.Connection, out: Path) -> int:
    """Write bounded cohorts and DS priority routes sharing an HNS NS handoff."""

    output_path = out / "hns-handoff-groups.json"
    prepare_temp_ns_handoff_table(
        conn,
        f"""
        SELECT n.name
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE COALESCE(n.expired, 0) = 0
          AND n.onchain_class IN ({HANDOFF_COHORT_CLASSES_SQL})
          AND COALESCE(ps.provider_type, 'unknown') NOT IN ({NON_ACTIONABLE_PROVIDER_TYPES_SQL})
          AND COALESCE(rs.has_ns, 0) = 1
          AND COALESCE(rs.has_glue, 0) = 0
          AND COALESCE(rs.has_synth, 0) = 0
        """,
    )
    groups: list[dict[str, Any]] = []
    ds_priority_groups: list[dict[str, Any]] = []
    unbounded_canary_groups: list[dict[str, Any]] = []
    ds_preflight_groups: list[dict[str, Any]] = []
    current_key: tuple[str, str, str, str] | None = None
    current_members: list[dict[str, Any]] = []

    def finish_group() -> None:
        if current_key is None:
            return
        nameserver, root_name, bootstrap_ip, bootstrap_field = current_key
        group = {
            "nameserver": nameserver,
            "root_name": root_name,
            "bootstrap_addresses": [bootstrap_ip],
            "bootstrap_field": bootstrap_field,
        }
        # The resolver-first preflight is intentionally independent from the
        # bounded website-cohort policy.  A valid AD response is a much
        # stronger, per-name signal than a shared nameserver route, so retain
        # every DS-backed indirect handoff here, including bounded cohorts.
        ds_members = [member for member in current_members if member["has_ds"]]
        if ds_members:
            ds_preflight_groups.append(
                {**group, "member_count": len(ds_members), "members": ds_members}
            )
        if HANDOFF_COHORT_MIN_MEMBERS <= len(current_members) <= HANDOFF_COHORT_MAX_MEMBERS:
            groups.append({**group, "member_count": len(current_members), "members": current_members})
            return
        if len(current_members) == 1 and ds_members:
            ds_priority_groups.append(
                {**group, "member_count": len(ds_members), "members": ds_members}
            )
        elif len(current_members) > HANDOFF_COHORT_MAX_MEMBERS and ds_members:
            canaries = _handoff_canaries(ds_members)
            if canaries:
                unbounded_canary_groups.append(
                    {**group, "member_count": len(canaries), "members": canaries}
                )

    try:
        rows = conn.execute(
            f"""
            SELECT
              enh.ns_handoff_ns,
              enh.ns_handoff_root,
              enh.ns_handoff_bootstrap_ip,
              enh.ns_handoff_bootstrap_field,
              n.name,
              n.provider_guess,
              n.last_seen_height,
              COALESCE(rs.resource_hash, n.resource_hash, '') AS resource_hash,
              rs.ns_names,
              rs.ds_records,
              rs.has_ds,
              COALESCE(ps.provider_type, 'unknown') AS provider_type
            FROM {NS_HANDOFF_TABLE} enh
            JOIN names n ON n.name = enh.name
            JOIN resource_summary rs ON rs.name = n.name
            LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
            WHERE enh.ns_handoff_bootstrap_ip IS NOT NULL
              AND n.onchain_class IN ({HANDOFF_COHORT_CLASSES_SQL})
              AND COALESCE(n.expired, 0) = 0
              AND COALESCE(ps.provider_type, 'unknown') NOT IN ({NON_ACTIONABLE_PROVIDER_TYPES_SQL})
            ORDER BY
              enh.ns_handoff_ns,
              enh.ns_handoff_root,
              enh.ns_handoff_bootstrap_ip,
              enh.ns_handoff_bootstrap_field,
              n.name
            """
        )
        for row in rows:
            key = (
                str(row["ns_handoff_ns"] or ""),
                str(row["ns_handoff_root"] or ""),
                str(row["ns_handoff_bootstrap_ip"] or ""),
                str(row["ns_handoff_bootstrap_field"] or ""),
            )
            if key != current_key:
                finish_group()
                current_key = key
                current_members = []
            current_members.append(
                {
                    "name": str(row["name"]),
                    "provider_guess": str(row["provider_guess"] or "unknown/custom"),
                    "provider_type": str(row["provider_type"] or "unknown"),
                    "resource_hash": str(row["resource_hash"] or ""),
                    "last_seen_height": _cohort_int(row["last_seen_height"]),
                    "ns_names": _cohort_json_list(row["ns_names"]),
                    "ds_records": _cohort_json_list(row["ds_records"]),
                    "has_ds": bool(row["has_ds"]),
                }
            )
        finish_group()
    finally:
        drop_temp_ns_handoff_table(conn)

    write_json(
        output_path,
        {
            "format": "hns-handoff-cohorts-v1",
            "generated_at": utc_now(),
            "min_members": HANDOFF_COHORT_MIN_MEMBERS,
            "max_members": HANDOFF_COHORT_MAX_MEMBERS,
            "group_count": len(groups),
            "member_count": sum(int(group["member_count"]) for group in groups),
            "groups": groups,
            "ds_priority_group_count": len(ds_priority_groups),
            "ds_priority_member_count": sum(
                int(group["member_count"]) for group in ds_priority_groups
            ),
            "ds_priority_groups": ds_priority_groups,
            "unbounded_canary_group_count": len(unbounded_canary_groups),
            "unbounded_canary_member_count": sum(
                int(group["member_count"]) for group in unbounded_canary_groups
            ),
            "unbounded_canary_groups": unbounded_canary_groups,
            "ds_preflight_group_count": len(ds_preflight_groups),
            "ds_preflight_member_count": sum(
                int(group["member_count"]) for group in ds_preflight_groups
            ),
            "ds_preflight_groups": ds_preflight_groups,
        },
    )
    return len(groups) + len(ds_priority_groups) + len(unbounded_canary_groups)


def _handoff_canaries(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Choose stable, spread-out DS roots from an unbounded route."""

    if len(members) <= HANDOFF_UNBOUNDED_CANARY_MEMBERS:
        return list(members)
    last = len(members) - 1
    indices = {
        round(index * last / (HANDOFF_UNBOUNDED_CANARY_MEMBERS - 1))
        for index in range(HANDOFF_UNBOUNDED_CANARY_MEMBERS)
    }
    return [members[index] for index in sorted(indices)]


def _cohort_json_list(value: Any) -> list[Any]:
    try:
        parsed = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _cohort_int(value: Any) -> int | None:
    return int(value) if value is not None else None


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


def write_nameserver_names(conn: sqlite3.Connection, out: Path, *, limit: int) -> int:
    base_dir = out / "nameservers"
    _remove_tree(base_dir, missing_ok=True)
    if limit <= 0:
        return 0
    base_dir.mkdir(parents=True, exist_ok=True)
    shards_dir = base_dir / "shards"
    shards_dir.mkdir(parents=True, exist_ok=True)
    row_detail = "nameserver_matches"
    output_keys = ["name", "nameserver"]
    exported_count = 0
    total_names = table_count(conn, "SELECT COUNT(*) FROM names")
    shard_writers = _NameserverShardWriters(shards_dir, NAMESERVER_SHARD_COUNT)
    try:
        _prepare_export_nameserver_rows(conn, limit=limit, total_names=total_names)
        nameserver_count = table_count(
            conn,
            "SELECT COUNT(DISTINCT nameserver) FROM export_nameserver_rows",
        )
        _write_nameserver_lookup_index(
            base_dir,
            shard_count=NAMESERVER_SHARD_COUNT,
            row_detail=row_detail,
            output_keys=output_keys,
        )
        _log_export(
            f"writing nameserver lookup shards nameservers={nameserver_count} shards={NAMESERVER_SHARD_COUNT}"
        )
        for item in _nameserver_counts(conn):
            nameserver = str(item["nameserver"])
            row_count = int(item["row_count"] or 0)
            current_names: list[str] = []
            current_page = 1
            for row in _nameserver_rows(conn, nameserver):
                current_names.append(str(row["name"]))
                if row_count > PAGE_SIZE and len(current_names) >= PAGE_SIZE:
                    _write_nameserver_page(
                        base_dir,
                        nameserver,
                        current_page,
                        [{"name": name, "nameserver": nameserver} for name in current_names],
                        output_keys=output_keys,
                    )
                    current_names = []
                    current_page += 1
            if row_count > PAGE_SIZE:
                if current_names:
                    _write_nameserver_page(
                        base_dir,
                        nameserver,
                        current_page,
                        [{"name": name, "nameserver": nameserver} for name in current_names],
                        output_keys=output_keys,
                    )
                shard_writers.write(
                    nameserver,
                    {
                        "n": nameserver,
                        "c": row_count,
                        "t": f"nameservers/{_nameserver_page_dirname(nameserver)}/page-{{page}}.json",
                    },
                )
            else:
                shard_writers.write(
                    nameserver,
                    {
                        "n": nameserver,
                        "c": row_count,
                        "r": current_names,
                    },
                )
            exported_count += 1
            if exported_count % 1000 == 0:
                _log_export(f"wrote nameserver lookup progress={exported_count}/{nameserver_count}")
        return exported_count
    finally:
        shard_writers.close()
        conn.execute("DROP TABLE IF EXISTS temp.export_nameserver_rows")


def _ip_address_counts(
    conn: sqlite3.Connection,
    *,
    limit: int,
    total_names: int,
) -> sqlite3.Cursor:
    if limit >= total_names:
        return conn.execute(
            """
            SELECT ri.ip, COUNT(DISTINCT ri.name) AS row_count
            FROM resource_ip ri
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
            GROUP BY ri.ip
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
        JOIN names n ON n.name = ri.name
        WHERE COALESCE(n.expired, 0) = 0
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
            SELECT ri.field, COUNT(DISTINCT ri.name) AS row_count
            FROM resource_ip ri
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
              AND ri.ip = ?
            GROUP BY ri.field
            ORDER BY ri.field
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
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
              AND ri.ip = ?
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
            SELECT ri.name, group_concat(ri.field) AS fields
            FROM resource_ip ri
            JOIN names n ON n.name = ri.name
            WHERE COALESCE(n.expired, 0) = 0
              AND ri.ip = ?
            GROUP BY ri.name
            ORDER BY ri.name
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
        JOIN names n ON n.name = ri.name
        WHERE COALESCE(n.expired, 0) = 0
          AND ri.ip = ?
        GROUP BY ri.name
        ORDER BY ri.name
        """,
        (limit, ip),
    )


def _prepare_export_nameserver_rows(
    conn: sqlite3.Connection,
    *,
    limit: int,
    total_names: int,
) -> None:
    conn.execute("DROP TABLE IF EXISTS temp.export_nameserver_rows")
    conn.execute(
        """
        CREATE TEMP TABLE export_nameserver_rows(
          nameserver TEXT NOT NULL,
          name TEXT NOT NULL,
          PRIMARY KEY(nameserver, name)
        ) WITHOUT ROWID
        """
    )
    if limit >= total_names:
        conn.execute(
            """
            INSERT OR IGNORE INTO export_nameserver_rows(nameserver, name)
            SELECT LOWER(TRIM(ns.value, '.')) AS nameserver, rs.name
            FROM resource_summary rs
            JOIN names n ON n.name = rs.name
            JOIN json_each(rs.ns_names) ns
            WHERE COALESCE(n.expired, 0) = 0
              AND ns.value IS NOT NULL
              AND LOWER(TRIM(ns.value, '.')) != ''
            ORDER BY nameserver
            """
        )
    else:
        conn.execute(
            """
            INSERT OR IGNORE INTO export_nameserver_rows(nameserver, name)
            WITH exported_names AS (
              SELECT name
              FROM names
              ORDER BY name
              LIMIT ?
            )
            SELECT LOWER(TRIM(ns.value, '.')) AS nameserver, rs.name
            FROM resource_summary rs
            JOIN exported_names en ON en.name = rs.name
            JOIN names n ON n.name = rs.name
            JOIN json_each(rs.ns_names) ns
            WHERE COALESCE(n.expired, 0) = 0
              AND ns.value IS NOT NULL
              AND LOWER(TRIM(ns.value, '.')) != ''
            ORDER BY nameserver
            """,
            (limit,),
        )


def _nameserver_counts(conn: sqlite3.Connection) -> sqlite3.Cursor:
    return conn.execute(
        """
        SELECT nameserver, COUNT(*) AS row_count
        FROM export_nameserver_rows
        GROUP BY nameserver
        ORDER BY nameserver
        """
    )


def _nameserver_rows(conn: sqlite3.Connection, nameserver: str) -> sqlite3.Cursor:
    return conn.execute(
        """
        SELECT name
        FROM export_nameserver_rows
        WHERE nameserver = ?
        ORDER BY name
        """,
        (nameserver,),
    )


class _NameserverShardWriters:
    def __init__(self, base_dir: Path, shard_count: int, *, max_open: int = 64) -> None:
        self.base_dir = base_dir
        self.shard_count = shard_count
        self.max_open = max_open
        self._handles: OrderedDict[str, Any] = OrderedDict()

    def write(self, nameserver: str, payload: dict[str, Any]) -> None:
        shard = _nameserver_shard_id(nameserver, self.shard_count)
        handle = self._handle(shard)
        handle.write(dumps_json(payload))
        handle.write("\n")

    def close(self) -> None:
        while self._handles:
            _, handle = self._handles.popitem()
            handle.close()

    def _handle(self, shard: str) -> Any:
        handle = self._handles.get(shard)
        if handle is not None:
            self._handles.move_to_end(shard)
            return handle
        if len(self._handles) >= self.max_open:
            _, old_handle = self._handles.popitem(last=False)
            old_handle.close()
        path = self.base_dir / f"{shard}.jsonl"
        handle = path.open("a", encoding="utf-8")
        self._handles[shard] = handle
        return handle


def _write_nameserver_lookup_index(
    base_dir: Path,
    *,
    shard_count: int,
    row_detail: str,
    output_keys: list[str],
) -> None:
    write_json(
        base_dir / "index.json",
        {
            "version": 2,
            "lookup": "sharded-jsonl",
            "hash": "fnv1a32",
            "shard_count": shard_count,
            "shard_width": len(f"{shard_count - 1:x}"),
            "path_template": "nameservers/shards/{shard}.jsonl",
            "page_size": PAGE_SIZE,
            "row_detail": row_detail,
            "columns": output_keys,
        },
    )


def _nameserver_shard_id(nameserver: str, shard_count: int) -> str:
    shard = _fnv1a32(_normalize_nameserver(nameserver)) % shard_count
    width = len(f"{shard_count - 1:x}")
    return f"{shard:0{width}x}"


def _fnv1a32(value: str) -> int:
    result = 0x811C9DC5
    for byte in value.encode("utf-8"):
        result ^= byte
        result = (result * 0x01000193) & 0xFFFFFFFF
    return result


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


def _finish_nameserver_pages(
    base_dir: Path,
    nameserver: str,
    *,
    rows: list[dict[str, Any]],
    row_count: int,
    page: int,
    row_detail: str,
    output_keys: list[str],
) -> None:
    if rows:
        _write_nameserver_page(
            base_dir,
            nameserver,
            page,
            rows,
            output_keys=output_keys,
        )
    _write_nameserver_index(
        base_dir,
        nameserver,
        row_count=row_count,
        row_detail=row_detail,
        output_keys=output_keys,
    )


def _write_nameserver_index(
    base_dir: Path,
    nameserver: str,
    *,
    row_count: int,
    row_detail: str,
    output_keys: list[str],
) -> None:
    page_count = math.ceil(row_count / PAGE_SIZE) if row_count else 0
    payload = {
        "nameserver": nameserver,
        "row_count": row_count,
        "page_size": PAGE_SIZE,
        "page_count": page_count,
        "path_template": f"nameservers/{_nameserver_page_dirname(nameserver)}/page-{{page}}.json",
        "row_detail": row_detail,
        "columns": output_keys,
    }
    write_json(base_dir / _nameserver_filename(nameserver), payload)


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


def _write_nameserver_page(
    base_dir: Path,
    nameserver: str,
    page: int,
    rows: list[dict[str, Any]],
    *,
    output_keys: list[str],
) -> None:
    page_dir = base_dir / _nameserver_page_dirname(nameserver)
    page_dir.mkdir(parents=True, exist_ok=True)
    write_compact_json(
        page_dir / f"page-{page}.json",
        {
            "page": page,
            "columns": output_keys,
            "rows": [[row.get(key) for key in output_keys] for row in rows],
        },
    )


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


def _nameserver_basename(nameserver: str) -> str:
    return quote(_normalize_nameserver(nameserver), safe="")


def _nameserver_page_dirname(nameserver: str) -> str:
    return f"{_nameserver_basename(nameserver)}.pages"


def _nameserver_filename(nameserver: str) -> str:
    return f"{_nameserver_basename(nameserver)}.json"


def _normalize_nameserver(nameserver: str) -> str:
    return str(nameserver).strip().lower().rstrip(".")


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
    try:
        prepare_temp_ns_handoff_table(
            conn,
            "SELECT name FROM names ORDER BY name LIMIT ?",
            (exported_names,),
        )
        _prepare_export_name_ordinals(conn, exported_names)
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
                full_export=exported_names == total_names,
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
        drop_temp_ns_handoff_table(conn)


def _prepare_export_name_ordinals(conn: sqlite3.Connection, limit: int) -> None:
    conn.execute("DROP TABLE IF EXISTS temp.export_name_ordinals")
    conn.execute(
        """
        CREATE TEMP TABLE export_name_ordinals(
          name TEXT PRIMARY KEY,
          ordinal INTEGER NOT NULL,
          expired INTEGER NOT NULL,
          provider_guess TEXT,
          provider_type TEXT NOT NULL,
          has_ds INTEGER NOT NULL,
          has_ns INTEGER NOT NULL,
          has_glue INTEGER NOT NULL,
          has_synth INTEGER NOT NULL,
          has_ns_handoff INTEGER NOT NULL,
          has_tlsa INTEGER NOT NULL,
          compliance_stage TEXT NOT NULL
        ) WITHOUT ROWID
        """
    )
    if limit <= 0:
        return
    conn.execute(
        f"""
        INSERT INTO export_name_ordinals(
          name, ordinal, expired, provider_guess, provider_type, has_ds, has_ns,
          has_glue, has_synth, has_ns_handoff, has_tlsa, compliance_stage
        )
        SELECT
          name, ordinal, expired, provider_guess, provider_type, has_ds, has_ns,
          has_glue, has_synth, has_ns_handoff, has_tlsa, {_export_compliance_stage_sql()} AS compliance_stage
        FROM (
          SELECT
            n.name,
            row_number() OVER (ORDER BY n.name) - 1 AS ordinal,
            COALESCE(n.expired, 0) AS expired,
            n.provider_guess,
            COALESCE(ps.provider_type, 'unknown') AS provider_type,
            COALESCE(rs.has_ds, 0) AS has_ds,
            COALESCE(rs.has_ns, 0) AS has_ns,
            COALESCE(rs.has_glue, 0) AS has_glue,
            COALESCE(rs.has_synth, 0) AS has_synth,
            CASE WHEN enh.ns_handoff_bootstrap_ip IS NOT NULL THEN 1 ELSE 0 END AS has_ns_handoff,
            COALESCE(tes.has_tlsa, 0) AS has_tlsa
          FROM names n
          JOIN resource_summary rs ON rs.name = n.name
          LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
          LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
          LEFT JOIN {NS_HANDOFF_TABLE} enh ON enh.name = n.name
          ORDER BY n.name
          LIMIT ?
        )
        """,
        (limit,),
    )
    conn.execute("CREATE INDEX temp.idx_export_ordinals_ordinal ON export_name_ordinals(ordinal)")
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_provider ON export_name_ordinals(provider_guess, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_provider_type ON export_name_ordinals(provider_type, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_ns ON export_name_ordinals(has_ns, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_synth ON export_name_ordinals(has_synth, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_ds ON export_name_ordinals(has_ds, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_tlsa ON export_name_ordinals(has_tlsa, ordinal)"
    )
    conn.execute(
        "CREATE INDEX temp.idx_export_ordinals_compliance ON export_name_ordinals(compliance_stage, ordinal)"
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
                _name_row(row, json_columns)
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
    full_export: bool,
) -> dict[str, Any]:
    collection_dir = base_dir / _collection_dir_name(key)
    collection_dir.mkdir(parents=True, exist_ok=True)
    where, params = _posting_collection_where(key)
    row_count = int(
        conn.execute(
            f"""
            SELECT COUNT(*)
            FROM export_name_ordinals
            WHERE {where}
            """,
            params,
        ).fetchone()[0]
        or 0
    )
    total_count = row_count if full_export else _base_collection_count(conn, key)
    page_count = max(1, math.ceil(row_count / page_size)) if row_count else 0
    _log_export(
        f"writing names-pages/{key} postings rows={row_count} total={total_count} "
        f"pages={page_count} truncated={total_count > row_count}"
    )
    if row_count > 0:
        cursor = conn.execute(
            f"""
            SELECT ordinal
            FROM export_name_ordinals
            WHERE {where}
            ORDER BY ordinal
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


def _base_collection_count(conn: sqlite3.Connection, key: str) -> int:
    from_sql = _name_rows_from_sql()
    where, params = _name_collection_where(key)
    return int(
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


def _posting_collection_where(key: str) -> tuple[str, tuple[Any, ...]]:
    if key.startswith(COMPLIANCE_STAGE_FILTER_PREFIX):
        return "expired = 0 AND compliance_stage = ?", (
            key.removeprefix(COMPLIANCE_STAGE_FILTER_PREFIX),
        )
    if key.startswith(PROVIDER_FILTER_PREFIX):
        return "expired = 0 AND provider_guess = ?", (
            key.removeprefix(PROVIDER_FILTER_PREFIX),
        )
    if key in POSTING_NAME_FILTERS:
        return f"expired = 0 AND ({POSTING_NAME_FILTERS[key]})", ()
    raise KeyError(f"unknown names posting collection: {key}")


def _collection_dir_name(key: str) -> str:
    return key.replace("/", "__slash__")


def _name_collection_keys(conn: sqlite3.Connection) -> list[str]:
    filter_keys = [
        key for key in EXPORTED_NAME_FILTERS if _collection_has_exported_rows(conn, key)
    ]
    compliance_stages = [
        row["compliance_stage"]
        for row in conn.execute(
            """
            SELECT compliance_stage
            FROM export_name_ordinals
            WHERE expired = 0
            GROUP BY compliance_stage
            ORDER BY compliance_stage
            """
        )
        if row["compliance_stage"]
    ]
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
    return [
        "all",
        *filter_keys,
        *(f"{COMPLIANCE_STAGE_FILTER_PREFIX}{stage}" for stage in compliance_stages),
        *(f"{PROVIDER_FILTER_PREFIX}{provider_key}" for provider_key in provider_keys),
    ]


def _collection_has_exported_rows(conn: sqlite3.Connection, key: str) -> bool:
    where, params = _posting_collection_where(key)
    return (
        conn.execute(
            f"""
            SELECT 1
            FROM export_name_ordinals
            WHERE {where}
            LIMIT 1
            """,
            params,
        ).fetchone()
        is not None
    )


def _name_row_columns(*, row_detail: str = "full") -> str:
    if row_detail == "compact":
        return f"""
          n.name, n.expired, n.onchain_class, n.provider_guess,
          COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types, rs.has_ds,
          COALESCE(tes.has_tlsa, 0) AS has_tlsa,
          json_extract(rs.ns_names, '$[0]') AS first_ns,
          json_extract(rs.glue4, '$[0]') AS first_glue4,
          json_extract(rs.glue6, '$[0]') AS first_glue6,
          json_extract(rs.synth4, '$[0]') AS first_synth4,
          json_extract(rs.synth6, '$[0]') AS first_synth6,
          {_ns_handoff_select_columns()},
          rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
          {_dns_evidence_path_sql()},
          eno.compliance_stage AS compliance_stage
        """
    return f"""
          n.name, n.state, n.expired, n.onchain_class, n.provider_guess,
          COALESCE(ps.provider_type, 'unknown') AS provider_type, n.record_types,
          rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6,
          rs.ds_records, COALESCE(tes.tlsa_records, '[]') AS tlsa_records,
          COALESCE(tes.tlsa_owners, '[]') AS tlsa_owners,
          COALESCE(tes.has_tlsa, 0) AS has_tlsa,
          tes.observed_at AS tlsa_observed_at, tes.checked_at AS tlsa_checked_at,
          rs.has_ds,
          {_ns_handoff_select_columns()},
          rs.raw_size, rs.resource_version, rs.resource_hash, n.last_seen_height, n.updated_at,
          {_dns_evidence_path_sql()},
          eno.compliance_stage AS compliance_stage
        """


def _name_json_columns(*, row_detail: str = "full") -> list[str]:
    if row_detail == "compact":
        return ["record_types"]
    return [
        "record_types",
        "ns_names",
        "glue4",
        "glue6",
        "synth4",
        "synth6",
        "ds_records",
        "tlsa_records",
        "tlsa_owners",
    ]


def _name_output_keys(*, row_detail: str = "full") -> list[str]:
    if row_detail == "compact":
        return [
            "name",
            "expired",
            "onchain_class",
            "provider_guess",
            "provider_type",
            "record_types",
            "has_ds",
            "has_tlsa",
            "first_ns",
            "first_glue4",
            "first_glue6",
            "first_synth4",
            "first_synth6",
            *NS_HANDOFF_COLUMNS,
            "raw_size",
            "resource_version",
            "resource_hash",
            "last_seen_height",
            "updated_at",
            "dns_evidence_path",
            "compliance_stage",
        ]
    return []


def _name_rows_from_sql() -> str:
    return f"""
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
      LEFT JOIN tlsa_evidence_summary tes ON tes.name = n.name
      LEFT JOIN {NS_HANDOFF_TABLE} enh ON enh.name = n.name
    """


def _ns_handoff_select_columns() -> str:
    return ",\n          ".join(f"enh.{column}" for column in NS_HANDOFF_COLUMNS)


def _name_collection_where(key: str) -> tuple[str, tuple[Any, ...]]:
    if key == "all":
        return "1=1", ()
    if key.startswith(COMPLIANCE_STAGE_FILTER_PREFIX):
        return f"COALESCE(n.expired, 0) = 0 AND {_name_compliance_stage_sql()} = ?", (
            key.removeprefix(COMPLIANCE_STAGE_FILTER_PREFIX),
        )
    if key.startswith(PROVIDER_FILTER_PREFIX):
        return "COALESCE(n.expired, 0) = 0 AND n.provider_guess = ?", (
            key.removeprefix(PROVIDER_FILTER_PREFIX),
        )
    if key in {"indirect_ns_handoffs", "needs_fix", "missing_glue_only"}:
        stage = {
            "indirect_ns_handoffs": "indirect_ns_handoff",
            "needs_fix": "missing_glue",
            "missing_glue_only": "missing_glue",
        }[key]
        return f"COALESCE(n.expired, 0) = 0 AND {_name_compliance_stage_sql()} = ?", (stage,)
    if key in NAME_FILTERS:
        return f"COALESCE(n.expired, 0) = 0 AND ({NAME_FILTERS[key]})", ()
    raise KeyError(f"unknown names collection: {key}")


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
        "tlsa_records",
        "tlsa_owners",
        "has_tlsa",
        "tlsa_observed_at",
        "tlsa_checked_at",
        "has_ds",
        *NS_HANDOFF_COLUMNS,
        "raw_size",
        "resource_version",
        "resource_hash",
        "last_seen_height",
        "updated_at",
        "dns_evidence_path",
        "compliance_stage",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(value) for key, value in row.items()})


def write_verification_csv(conn: sqlite3.Connection, path: Path, *, limit: int) -> None:
    fieldnames = [
        "name",
        "mode",
        "sequence",
        "purpose",
        "label",
        "qname",
        "rrtype",
        "transport",
        "command",
        "server",
        "server_field",
        "nameserver",
        "requires",
        "note",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        prepare_temp_ns_handoff_table(
            conn,
            """
            SELECT n.name
            FROM names n
            ORDER BY n.name
            LIMIT ?
            """,
            (limit,),
        )
        try:
            cursor = conn.execute(
                f"""
                WITH exported_names AS (
                  SELECT n.name
                  FROM names n
                  ORDER BY n.name
                  LIMIT ?
                )
                SELECT
                  n.name,
                  n.expired,
                  json_extract(rs.ns_names, '$[0]') AS first_ns,
                  json_extract(rs.glue4, '$[0]') AS first_glue4,
                  json_extract(rs.glue6, '$[0]') AS first_glue6,
                  json_extract(rs.synth4, '$[0]') AS first_synth4,
                  json_extract(rs.synth6, '$[0]') AS first_synth6,
                  {_ns_handoff_select_columns()}
                FROM exported_names en
                JOIN names n ON n.name = en.name
                JOIN resource_summary rs ON rs.name = n.name
                LEFT JOIN {NS_HANDOFF_TABLE} enh ON enh.name = n.name
                WHERE COALESCE(n.expired, 0) = 0
                  AND (
                    NULLIF(json_extract(rs.synth4, '$[0]'), '') IS NOT NULL
                    OR NULLIF(json_extract(rs.glue4, '$[0]'), '') IS NOT NULL
                    OR NULLIF(json_extract(rs.synth6, '$[0]'), '') IS NOT NULL
                    OR NULLIF(json_extract(rs.glue6, '$[0]'), '') IS NOT NULL
                    OR (
                      enh.ns_handoff_bootstrap_ip IS NOT NULL
                      AND enh.ns_handoff_ns IS NOT NULL
                    )
                  )
                ORDER BY n.name
                """,
                (limit,),
            )
            for row in cursor:
                plan = build_verification_plan(dict(row))
                if plan is None:
                    continue
                for index, command in enumerate(plan["commands"], start=1):
                    writer.writerow(
                        {
                            "name": plan["name"],
                            "mode": plan["mode"],
                            "sequence": index,
                            "purpose": command["purpose"],
                            "label": command["label"],
                            "qname": command["qname"],
                            "rrtype": command["rrtype"],
                            "transport": command["transport"],
                            "command": command["command"],
                            "server": command.get("server") or "",
                            "server_field": plan.get("server_field") or "",
                            "nameserver": plan.get("nameserver") or "",
                            "requires": command.get("requires") or "",
                            "note": command.get("note") or plan.get("note") or "",
                        }
                    )
        finally:
            drop_temp_ns_handoff_table(conn)


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
        paths.extend(
            (
                "names.json",
                "names.csv",
                "verification.csv",
                "topology.sqlite.gz",
            )
        )
    for directory in ("overview-pages", "names-pages", "ip-addresses", "nameservers", "dns-evidence"):
        paths.extend(
            path.relative_to(out).as_posix()
            for path in sorted((out / directory).glob("*/*.json"))
        )
        paths.extend(
            path.relative_to(out).as_posix()
            for path in sorted((out / directory).glob("*/*.jsonl"))
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


def _name_row(row: sqlite3.Row, json_columns: list[str]) -> dict[str, Any]:
    parsed = parse_json_columns(dict(row), json_columns)
    if "has_tlsa" in parsed:
        parsed["has_tlsa"] = bool(parsed["has_tlsa"])
    return parsed


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
