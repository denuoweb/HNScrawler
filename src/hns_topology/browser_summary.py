from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

BROWSER_SUMMARY_COLUMNS = (
    "browser_result",
    "browser_hns_proof",
    "browser_resolution_source",
    "browser_authoritative_udp",
    "browser_authoritative_tcp",
    "browser_authoritative_doh",
    "browser_fallback_used",
    "browser_fallback_reason",
    "browser_dnssec_status",
    "browser_tlsa_status",
    "browser_dane_status",
    "browser_certificate_expired",
    "browser_certificate_not_valid_after",
    "browser_captured_at",
)

BROWSER_EFFECT_COLUMNS = (
    "browser_evidence_effect",
    "browser_evidence_severity",
    "browser_action",
    "browser_action_label",
    "browser_action_detail",
)

BROWSER_SUMMARY_BOOL_COLUMNS = (
    "browser_fallback_used",
    "browser_certificate_expired",
)


def browser_summary_select_columns(alias: str = "lbe") -> str:
    return f"""
          {alias}.browser_result AS browser_result,
          {alias}.hns_proof AS browser_hns_proof,
          {alias}.resolution_source AS browser_resolution_source,
          {alias}.authoritative_udp AS browser_authoritative_udp,
          {alias}.authoritative_tcp AS browser_authoritative_tcp,
          {alias}.authoritative_doh AS browser_authoritative_doh,
          {alias}.fallback_used AS browser_fallback_used,
          {alias}.fallback_reason AS browser_fallback_reason,
          {alias}.dnssec_status AS browser_dnssec_status,
          {alias}.tlsa_status AS browser_tlsa_status,
          {alias}.dane_status AS browser_dane_status,
          {alias}.certificate_expired AS browser_certificate_expired,
          {alias}.certificate_not_valid_after AS browser_certificate_not_valid_after,
          {alias}.captured_at AS browser_captured_at
    """.strip()


def latest_browser_evidence_join(alias: str = "lbe") -> str:
    return f"""
      LEFT JOIN browser_evidence {alias} ON {alias}.id = (
        SELECT be_latest.id
        FROM browser_evidence be_latest
        WHERE be_latest.name = n.name
        ORDER BY be_latest.captured_at DESC, be_latest.id DESC
        LIMIT 1
      )
    """.rstrip()


def normalize_browser_summary_bools(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for column in BROWSER_SUMMARY_BOOL_COLUMNS:
        value = result.get(column)
        if value is not None:
            result[column] = bool(value)
    return result


def apply_browser_evidence_policy(row: dict[str, Any]) -> dict[str, Any]:
    result = normalize_browser_summary_bools(row)
    if not _has_browser_evidence(result):
        return _with_effect(result, None, None, None, None, None)

    if result.get("browser_certificate_expired") is True:
        if _live_dane_supersedes_browser(result):
            return _with_effect(
                result,
                "live_supersedes_browser",
                "pass",
                None,
                None,
                "Live crawler DANE verification is newer than the browser certificate-expiry observation.",
            )
        return _with_effect(
            result,
            "promoted_certificate_expired",
            "action",
            "renew_certificate",
            "Renew HTTPS certificate",
            "Latest browser evidence saw an expired HTTPS certificate; renew it before treating TLSA/DANE gaps as current.",
        )

    if result.get("browser_result") == "dane_verified" or result.get("browser_dane_status") == "verified":
        if result.get("dane_status") == "valid":
            return _with_effect(
                result,
                "browser_confirms_live_dane",
                "pass",
                None,
                None,
                "Browser evidence agrees with live crawler DANE verification.",
            )
        return _with_effect(
            result,
            "positive_browser_dane",
            "review",
            "compare_browser_dane",
            "Review browser DANE proof",
            "Latest browser evidence verified DANE, but crawler live status is not DANE-valid yet; compare resolver paths and timestamps.",
        )

    if _browser_port53_blocked(result):
        return _with_effect(
            result,
            "context_network_blocks_53",
            "context",
            "network_blocks_53_context",
            "Review client network",
            "Latest browser evidence used fallback because the client network blocked or timed out port 53. This is context, not a domain-side compliance failure.",
        )

    return _with_effect(
        result,
        "context_observed",
        "context",
        None,
        None,
        "Latest browser evidence is available as contextual device evidence.",
    )


def _has_browser_evidence(row: dict[str, Any]) -> bool:
    return any(row.get(key) not in (None, "") for key in BROWSER_SUMMARY_COLUMNS)


def _live_dane_supersedes_browser(row: dict[str, Any]) -> bool:
    if row.get("dane_status") != "valid":
        return False
    live_checked = _parse_utc(row.get("checked_at"))
    browser_captured = _parse_utc(row.get("browser_captured_at"))
    if live_checked is None or browser_captured is None:
        return bool(live_checked)
    return live_checked >= browser_captured


def _browser_port53_blocked(row: dict[str, Any]) -> bool:
    reason = str(row.get("browser_fallback_reason") or "").lower()
    if reason == "network_blocks_53":
        return True
    udp = str(row.get("browser_authoritative_udp") or "").lower()
    tcp = str(row.get("browser_authoritative_tcp") or "").lower()
    doh = str(row.get("browser_authoritative_doh") or "").lower()
    return (
        udp in {"blocked", "timeout", "transport_error"}
        and tcp in {"blocked", "timeout", "transport_error", "not_attempted"}
        and doh == "ok"
    )


def _with_effect(
    row: dict[str, Any],
    effect: str | None,
    severity: str | None,
    action: str | None,
    label: str | None,
    detail: str | None,
) -> dict[str, Any]:
    row.update(
        {
            "browser_evidence_effect": effect,
            "browser_evidence_severity": severity,
            "browser_action": action,
            "browser_action_label": label,
            "browser_action_detail": detail,
        }
    )
    return row


def _parse_utc(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
