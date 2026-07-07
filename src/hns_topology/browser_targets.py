from __future__ import annotations

import shlex
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from .infra import NON_ACTIONABLE_PROVIDER_TYPES

HNS_BROWSER_PACKAGE = "com.denuoweb.hnsdane"
HNS_BROWSER_ACTIVITY = f"{HNS_BROWSER_PACKAGE}/.ui.MainActivity"
HNS_BROWSER_LOAD_URL_EXTRA = "com.denuoweb.hnsdane.LOAD_URL"

BROWSER_TARGET_FIELDS = [
    "name",
    "url",
    "priority",
    "category",
    "reason",
    "adb_command",
    "compliance_stage",
    "provider_guess",
    "provider_type",
    "record_types",
    "has_ds",
    "has_ns",
    "has_glue",
    "has_synth",
    "first_ns",
    "first_glue4",
    "first_glue6",
    "first_synth4",
    "first_synth6",
    "ns_handoff_ns",
    "ns_handoff_root",
    "ns_handoff_bootstrap_ip",
    "ns_handoff_bootstrap_field",
    "dnssec_status",
    "tlsa_status",
    "dane_status",
    "https_status",
    "strict_hns_status",
    "doh_fallback_status",
    "failure_reason",
    "browser_result",
    "browser_evidence_effect",
    "browser_action",
    "browser_fallback_reason",
    "browser_captured_at",
    "diagnostic_path",
]


def browser_target_row(row: Mapping[str, Any]) -> dict[str, Any] | None:
    name = _name(row)
    if not name or _truthy(row.get("expired")):
        return None
    category = _target_category(row)
    if category is None:
        return None
    priority, label, reason = category
    url = f"https://{name}/"
    return {
        "name": name,
        "url": url,
        "priority": priority,
        "category": label,
        "reason": reason,
        "adb_command": _adb_command(url),
        "compliance_stage": _text(row.get("compliance_stage")),
        "provider_guess": _text(row.get("provider_guess")),
        "provider_type": _text(row.get("provider_type")),
        "record_types": _record_types(row.get("record_types")),
        "has_ds": _int_flag(_has_ds(row)),
        "has_ns": _int_flag(_has_ns(row)),
        "has_glue": _int_flag(_has_glue(row)),
        "has_synth": _int_flag(_has_synth(row)),
        "first_ns": _text(row.get("first_ns")),
        "first_glue4": _text(row.get("first_glue4")),
        "first_glue6": _text(row.get("first_glue6")),
        "first_synth4": _text(row.get("first_synth4")),
        "first_synth6": _text(row.get("first_synth6")),
        "ns_handoff_ns": _text(row.get("ns_handoff_ns")),
        "ns_handoff_root": _text(row.get("ns_handoff_root")),
        "ns_handoff_bootstrap_ip": _text(row.get("ns_handoff_bootstrap_ip")),
        "ns_handoff_bootstrap_field": _text(row.get("ns_handoff_bootstrap_field")),
        "dnssec_status": _text(row.get("dnssec_status")),
        "tlsa_status": _text(row.get("tlsa_status")),
        "dane_status": _text(row.get("dane_status")),
        "https_status": _text(row.get("https_status")),
        "strict_hns_status": _text(row.get("strict_hns_status")),
        "doh_fallback_status": _text(row.get("doh_fallback_status")),
        "failure_reason": _text(row.get("failure_reason")),
        "browser_result": _text(row.get("browser_result")),
        "browser_evidence_effect": _text(row.get("browser_evidence_effect")),
        "browser_action": _text(row.get("browser_action")),
        "browser_fallback_reason": _text(row.get("browser_fallback_reason")),
        "browser_captured_at": _text(row.get("browser_captured_at")),
        "diagnostic_path": f"names.html?q={quote(name)}",
    }


def _target_category(row: Mapping[str, Any]) -> tuple[int, str, str] | None:
    browser_result = _text(row.get("browser_result"))
    browser_dane = _text(row.get("browser_dane_status"))
    if browser_result == "dane_verified" or browser_dane == "verified":
        return (
            0,
            "browser_dane_verified",
            "Browser evidence already verified DANE; use as a known-good comparison target.",
        )
    if browser_result == "loaded":
        return (1, "browser_loaded", "Browser evidence loaded the site; recheck to refresh live directory proof.")
    if browser_result == "certificate_expired":
        return (
            2,
            "browser_certificate_expired",
            "Browser reached the origin but saw an expired certificate; recheck after renewal or TLSA repair.",
        )
    if row.get("dane_status") == "valid":
        return (3, "live_dane_verified", "Crawler verified DNSSEC, TLSA, and HTTPS certificate/SPKI.")
    if row.get("https_status") in {"working", "tls_unverified"}:
        return (4, "live_https_reachable", "Crawler reached HTTPS; browser check can confirm user-visible behavior.")
    if row.get("strict_hns_status") == "working":
        return (5, "strict_hns_working", "Strict HNS bootstrap worked; browser check can confirm page load.")
    if browser_result == "resolver_fallback" or _text(row.get("browser_fallback_reason")) == "network_blocks_53":
        return (
            6,
            "browser_resolver_fallback",
            "Browser trace shows client-network resolver fallback context; retry on another network or compare DoH.",
        )
    if _actionable(row) and (_has_synth(row) or (_has_ns(row) and _has_glue(row))):
        return (7, "strict_hns_ready", "HNS resource has direct bootstrap material and is a strong browser-check candidate.")
    if _actionable(row) and _has_ds(row) and _has_ns(row):
        return (8, "dnssec_delegated_candidate", "DS plus delegation suggests a DANE candidate worth browser testing.")
    if row.get("ns_handoff_bootstrap_ip") and row.get("ns_handoff_ns"):
        return (
            9,
            "indirect_ns_handoff",
            "Delegation lacks parent GLUE, but the nameserver host has an HNS bootstrap path to inspect.",
        )
    return None


def _adb_command(url: str) -> str:
    return (
        f"adb shell am force-stop {HNS_BROWSER_PACKAGE} && "
        f"adb shell am start -W -n {HNS_BROWSER_ACTIVITY} "
        f"--es {HNS_BROWSER_LOAD_URL_EXTRA} {shlex.quote(url)}"
    )


def _actionable(row: Mapping[str, Any]) -> bool:
    provider_type = _text(row.get("provider_type")) or "unknown"
    return provider_type not in NON_ACTIONABLE_PROVIDER_TYPES


def _has_ds(row: Mapping[str, Any]) -> bool:
    return _truthy(row.get("has_ds")) or _has_record_type(row, "DS")


def _has_ns(row: Mapping[str, Any]) -> bool:
    return _truthy(row.get("has_ns")) or bool(_text(row.get("first_ns"))) or _has_record_type(row, "NS")


def _has_glue(row: Mapping[str, Any]) -> bool:
    return (
        _truthy(row.get("has_glue"))
        or bool(_text(row.get("first_glue4")) or _text(row.get("first_glue6")))
        or _has_record_type(row, "GLUE4")
        or _has_record_type(row, "GLUE6")
    )


def _has_synth(row: Mapping[str, Any]) -> bool:
    return (
        _truthy(row.get("has_synth"))
        or bool(_text(row.get("first_synth4")) or _text(row.get("first_synth6")))
        or _has_record_type(row, "SYNTH4")
        or _has_record_type(row, "SYNTH6")
    )


def _has_record_type(row: Mapping[str, Any], rrtype: str) -> bool:
    value = row.get("record_types")
    if isinstance(value, list):
        return rrtype in {str(item).upper() for item in value}
    text = _text(value).upper()
    return rrtype in {part.strip().strip('"') for part in text.replace("[", "").replace("]", "").split(",")}


def _record_types(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(item) for item in value if item)
    return _text(value)


def _name(row: Mapping[str, Any]) -> str:
    return str(row.get("name") or "").strip().lower().rstrip(".")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int_flag(value: Any) -> int:
    return 1 if _truthy(value) else 0


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)
