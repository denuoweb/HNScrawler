from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

SITE_DIRECTORY_FIELDS = [
    "root_name",
    "host",
    "url",
    "directory_status",
    "evidence_source",
    "evidence_confidence",
    "transport_note",
    "compliance_stage",
    "provider_guess",
    "provider_type",
    "strict_hns_status",
    "https_status",
    "dnssec_status",
    "tlsa_status",
    "dane_status",
    "fallback_status",
    "failure_reason",
    "checked_at",
    "certificate_not_valid_after",
    "certificate_sha256",
    "spki_sha256",
    "browser_result",
    "browser_evidence_effect",
    "browser_action",
    "browser_fallback_reason",
    "browser_captured_at",
    "diagnostic_path",
]

_SOURCE_PRIORITY = {
    "host_live_dane": 0,
    "host_live_https": 1,
    "browser_dane": 2,
    "browser_loaded": 3,
}


def site_directory_rows(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        directory_row = site_directory_row(row)
        if directory_row is not None:
            output.append(directory_row)
    return sorted(
        output,
        key=lambda item: (_SOURCE_PRIORITY.get(item["evidence_source"], 99), item["host"]),
    )


def site_directory_row(row: Mapping[str, Any]) -> dict[str, Any] | None:
    if _truthy(row.get("expired")):
        return None
    evidence = _site_evidence(row)
    if evidence is None:
        return None
    return _site_directory_row(row, evidence)


def _site_directory_row(row: Mapping[str, Any], evidence: tuple[str, str]) -> dict[str, Any]:
    source, confidence = evidence
    root_name = _root_name(row)
    host = _host(row) or root_name
    return {
        "root_name": root_name,
        "host": host,
        "url": _text(row.get("url")) or f"https://{host}/",
        "directory_status": _directory_status(source, confidence),
        "evidence_source": source,
        "evidence_confidence": confidence,
        "transport_note": _transport_note(row),
        "compliance_stage": _text(row.get("compliance_stage")),
        "provider_guess": _text(row.get("provider_guess")),
        "provider_type": _text(row.get("provider_type")),
        "strict_hns_status": _text(row.get("strict_hns_status")),
        "https_status": _text(row.get("https_status")),
        "dnssec_status": _text(row.get("dnssec_status")),
        "tlsa_status": _text(row.get("tlsa_status")),
        "dane_status": _text(row.get("dane_status")),
        "fallback_status": _fallback_status(row),
        "failure_reason": _text(row.get("failure_reason")),
        "checked_at": _text(row.get("checked_at")),
        "certificate_not_valid_after": _text(
            row.get("certificate_not_valid_after") or row.get("https_cert_not_valid_after")
        ),
        "certificate_sha256": _text(row.get("certificate_sha256") or row.get("https_cert_sha256")),
        "spki_sha256": _text(row.get("spki_sha256") or row.get("https_spki_sha256")),
        "browser_result": _text(row.get("browser_result")),
        "browser_evidence_effect": _text(row.get("browser_evidence_effect")),
        "browser_action": _text(row.get("browser_action")),
        "browser_fallback_reason": _text(row.get("browser_fallback_reason")),
        "browser_captured_at": _text(row.get("browser_captured_at")),
        "diagnostic_path": f"names.html?q={quote(root_name)}&host={quote(host)}",
    }


def _site_evidence(row: Mapping[str, Any]) -> tuple[str, str] | None:
    if row.get("dane_status") == "valid":
        return "host_live_dane", "dane_verified"
    if row.get("https_status") in {"working", "tls_unverified"}:
        return "host_live_https", (
            "strict_hns_https_reachable"
            if row.get("strict_hns_status") == "working"
            else "https_reachable"
        )
    if row.get("browser_result") == "dane_verified" or row.get("browser_dane_status") == "verified":
        return "browser_dane", "browser_dane_verified"
    if row.get("browser_result") == "loaded":
        return "browser_loaded", "browser_loaded"
    return None


def _directory_status(source: str, confidence: str) -> str:
    if source == "host_live_dane":
        return "dane_verified"
    if source == "browser_dane":
        return "browser_dane_verified"
    if source == "browser_loaded":
        return "browser_loaded"
    if source == "host_live_https":
        return "https_reachable"
    return confidence


def _transport_note(row: Mapping[str, Any]) -> str:
    fallback = _fallback_status(row)
    if fallback in {"required", "doh_fallback_only"}:
        return "resolver_fallback_required"
    if row.get("browser_evidence_effect") == "context_network_blocks_53":
        return "browser_network_blocks_53"
    if _text(row.get("browser_fallback_reason")).lower() == "network_blocks_53":
        return "browser_network_blocks_53"
    if row.get("strict_hns_status") == "working":
        return "strict_hns"
    return ""


def _root_name(row: Mapping[str, Any]) -> str:
    return _text(row.get("root_name") or row.get("name")).strip(".").lower()


def _host(row: Mapping[str, Any]) -> str:
    return _text(row.get("host") or row.get("name")).strip(".").lower()


def _fallback_status(row: Mapping[str, Any]) -> str:
    return _text(row.get("fallback_status") or row.get("doh_fallback_status"))


def _text(value: Any) -> str:
    return str(value or "").strip()


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)
