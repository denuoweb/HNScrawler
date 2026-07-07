from __future__ import annotations

import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

from .models import BrowserEvidence
from .timeutil import utc_now


def parse_browser_evidence_text(
    text: str,
    *,
    source: str,
    source_id: str,
    captured_at: str | None = None,
) -> list[BrowserEvidence]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return parse_gateway_event_lines(
            stripped,
            source=source,
            source_id=source_id,
            captured_at=captured_at,
        )
    return browser_evidence_from_payload(
        payload,
        source=source,
        source_id=source_id,
        captured_at=captured_at,
    )


def browser_evidence_from_payload(
    payload: Any,
    *,
    source: str,
    source_id: str,
    captured_at: str | None = None,
) -> list[BrowserEvidence]:
    documents = _payload_documents(payload)
    evidence: list[BrowserEvidence] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if _looks_like_gateway_event(document):
            item = _gateway_event_from_dict(
                document,
                source=source,
                source_id=source_id,
                captured_at=captured_at,
            )
        else:
            item = _trace_from_dict(
                document,
                source=source,
                source_id=source_id,
                captured_at=captured_at,
            )
        if item is not None:
            evidence.append(item)
    return evidence


def parse_gateway_event_lines(
    text: str,
    *,
    source: str,
    source_id: str,
    captured_at: str | None = None,
) -> list[BrowserEvidence]:
    evidence: list[BrowserEvidence] = []
    for line in text.splitlines():
        item = _gateway_event_from_line(
            line,
            source=source,
            source_id=source_id,
            captured_at=captured_at,
        )
        if item is not None:
            evidence.append(item)
    return evidence


def _payload_documents(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("observations", "browser_evidence", "traces", "events"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    for key in ("trace", "resolver_trace", "tlsa_trace"):
        value = payload.get(key)
        if isinstance(value, dict):
            return [value]
    return [payload]


def _trace_from_dict(
    trace: dict[str, Any],
    *,
    source: str,
    source_id: str,
    captured_at: str | None,
) -> BrowserEvidence | None:
    host = _normalize_host(_text(trace.get("host")) or _text(trace.get("url")))
    name = _hns_name_from_trace(trace, host)
    if not name:
        return None
    tls = _dict_value(trace.get("tls"))
    certificate = _dict_value(tls.get("certificate")) if tls else {}
    dane = _dict_value(tls.get("dane")) if tls else {}
    fallback = _dict_value(trace.get("fallback"))
    authoritative_dns = _dict_value(trace.get("authoritativeDns"))
    tlsa_blocked_by = _text(tls.get("tlsaBlockedBy")) if tls else ""
    final_error = _optional_text(trace.get("finalError"))
    fallback_used = _optional_bool(fallback.get("used")) if fallback else None
    fallback_reason = _optional_text(fallback.get("reason")) if fallback else None
    dane_status = _optional_text(dane.get("decision")) if dane else None
    reason = _mapped_reason(tlsa_blocked_by, final_error)
    captured_at_value = _captured_at(trace, captured_at)
    certificate_not_valid_after = (
        _certificate_timestamp(
            certificate,
            "notValidAfter",
            "not_valid_after",
            "notAfter",
            "not_after",
            "validTo",
            "valid_to",
            "expiresAt",
            "expires_at",
        )
        if certificate
        else None
    )
    certificate_expired = _certificate_expired_at(
        certificate_not_valid_after,
        captured_at_value,
    )
    if certificate_expired is True:
        reason = "certificate_expired"
    return BrowserEvidence(
        name=name,
        host=host,
        url=_text(trace.get("url")),
        source=source or "browser",
        source_id=source_id or "",
        evidence_type="resolver_trace",
        browser_result=_browser_result(
            dane_status=dane_status,
            fallback_used=fallback_used,
            reason=reason,
            final_error=final_error,
            origin_address=_optional_text(trace.get("originAddress")),
        ),
        status_code=None,
        stage=None,
        reason=reason,
        mode=_optional_text(trace.get("mode")),
        hns_proof=_optional_text(trace.get("hnsProof")),
        resolution_source=_optional_text(trace.get("resolutionSource")),
        authoritative_udp=_optional_text(authoritative_dns.get("udp53")) if authoritative_dns else None,
        authoritative_tcp=_optional_text(authoritative_dns.get("tcp53")) if authoritative_dns else None,
        authoritative_doh=_optional_text(authoritative_dns.get("doh")) if authoritative_dns else None,
        fallback_used=fallback_used,
        fallback_reason=fallback_reason,
        dnssec_status=_optional_text(trace.get("dnssec")),
        tlsa_owner=_optional_text(tls.get("tlsaOwner")) if tls else None,
        tlsa_status=_optional_text(tls.get("tlsaStatus")) if tls else None,
        tlsa_source=_optional_text(tls.get("tlsaSource")) if tls else None,
        dane_status=dane_status,
        certificate_sha256=_optional_text(certificate.get("endEntitySha256")) if certificate else None,
        spki_sha256=_optional_text(certificate.get("spkiSha256")) if certificate else None,
        final_error=final_error,
        raw_json=trace,
        captured_at=captured_at_value,
        certificate_not_valid_after=certificate_not_valid_after,
        certificate_expired=certificate_expired,
    )


def _gateway_event_from_line(
    line: str,
    *,
    source: str,
    source_id: str,
    captured_at: str | None,
) -> BrowserEvidence | None:
    text = line.strip()
    if not text:
        return None
    parts = text.split("\t", 4) if "\t" in text else text.split(maxsplit=4)
    if len(parts) != 5:
        return None
    timestamp, stage, host, status, reason = parts
    if _optional_int(timestamp) is None or _optional_int(status) is None:
        return None
    return _gateway_event_from_dict(
        {
            "timestampMillis": timestamp,
            "stage": stage,
            "host": host,
            "status": status,
            "reason": reason,
        },
        source=source,
        source_id=source_id,
        captured_at=captured_at,
    )


def _gateway_event_from_dict(
    event: dict[str, Any],
    *,
    source: str,
    source_id: str,
    captured_at: str | None,
) -> BrowserEvidence | None:
    host = _normalize_host(_text(event.get("host")))
    name = _hns_name_from_host(host)
    if not name:
        return None
    status_code = _optional_int(event.get("status") or event.get("status_code"))
    reason = _optional_text(event.get("reason"))
    return BrowserEvidence(
        name=name,
        host=host,
        url=_text(event.get("url")),
        source=source or "browser",
        source_id=source_id or "",
        evidence_type="gateway_event",
        browser_result=_gateway_result(status_code, reason),
        status_code=status_code,
        stage=_optional_text(event.get("stage")),
        reason=reason,
        mode=None,
        hns_proof=None,
        resolution_source=None,
        authoritative_udp=None,
        authoritative_tcp=None,
        authoritative_doh=None,
        fallback_used=None,
        fallback_reason=None,
        dnssec_status=None,
        tlsa_owner=None,
        tlsa_status=None,
        tlsa_source=None,
        dane_status=None,
        certificate_sha256=None,
        spki_sha256=None,
        final_error=None,
        raw_json=event,
        captured_at=_captured_at(event, captured_at),
    )


def _looks_like_gateway_event(document: dict[str, Any]) -> bool:
    return (
        ("status" in document or "status_code" in document)
        and "stage" in document
        and "reason" in document
        and "tls" not in document
    )


def _browser_result(
    *,
    dane_status: str | None,
    fallback_used: bool | None,
    reason: str | None,
    final_error: str | None,
    origin_address: str | None,
) -> str:
    if reason == "certificate_expired":
        return "certificate_expired"
    if dane_status == "verified":
        return "dane_verified"
    if fallback_used is True:
        return "resolver_fallback"
    if reason:
        return reason
    if final_error:
        return "failed"
    if origin_address:
        return "loaded"
    return "observed"


def _gateway_result(status_code: int | None, reason: str | None) -> str:
    mapped = _mapped_reason(reason or "", None)
    if mapped and mapped not in {"ok", "loaded", "success"}:
        return mapped
    if status_code is not None and 200 <= status_code < 400:
        return "loaded"
    if status_code is not None and status_code >= 400:
        return "failed"
    return mapped or "observed"


def _mapped_reason(reason: str, final_error: str | None) -> str | None:
    reason_text = reason.strip().lower()
    final_text = (final_error or "").strip().lower()
    if (
        "certificate_expired" in reason_text
        or "origin_certificate_expired" in reason_text
        or "certificate expired" in final_text
        or "certificate has expired" in final_text
        or "cert has expired" in final_text
        or "not valid after" in final_text
    ):
        return "certificate_expired"
    if reason_text in {
        "no_verified_nameserver_address",
        "authoritative_nameserver_transport_failed",
        "authoritative_nameserver_invalid_response",
    }:
        return reason_text
    if reason_text == "delegated_dnssec_validation_failed":
        return "dnssec_bogus"
    return reason_text or None


def _hns_name_from_trace(trace: dict[str, Any], host: str) -> str:
    root = _normalize_hns_name(_text(trace.get("root")))
    return root or _hns_name_from_host(host)


def _hns_name_from_host(host: str) -> str:
    labels = [label for label in host.strip(".").lower().split(".") if label]
    return _normalize_hns_name(labels[-1]) if labels else ""


def _normalize_hns_name(value: str) -> str:
    text = value.strip().lower().strip(".")
    if not text or text == "unknown":
        return ""
    first = text.split(".", 1)[0]
    return first if _valid_hns_label(first) else ""


def _valid_hns_label(value: str) -> bool:
    return 1 <= len(value) <= 63 and all(char.isalnum() or char == "-" for char in value)


def _normalize_host(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = parsed.hostname or text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return host.strip().strip(".").lower()


def _captured_at(document: dict[str, Any], fallback: str | None) -> str:
    for key in ("captured_at", "capturedAt", "timestamp"):
        value = _optional_text(document.get(key))
        if value:
            return value
    millis = _optional_int(document.get("timestampMillis"))
    if millis is not None:
        return datetime.fromtimestamp(millis / 1000, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return fallback or utc_now()


def _certificate_timestamp(certificate: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        timestamp = _optional_timestamp(certificate.get(key))
        if timestamp:
            return timestamp
    return None


def _certificate_expired_at(not_valid_after: str | None, captured_at: str) -> bool | None:
    expiry = _parse_timestamp(not_valid_after)
    captured = _parse_timestamp(captured_at)
    if expiry is None:
        return None
    if captured is None:
        captured = datetime.now(UTC)
    return expiry <= captured


def _optional_timestamp(value: Any) -> str | None:
    parsed = _parse_timestamp(value)
    if parsed is not None:
        return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return _optional_text(value)


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        try:
            parsed = datetime.fromtimestamp(seconds, UTC)
        except (OSError, OverflowError, ValueError):
            return None
    else:
        text = str(value).strip()
        if not text or text.lower() == "null":
            return None
        if text.isdigit():
            return _parse_timestamp(int(text))
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(text)
            except (TypeError, ValueError):
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _optional_text(value: Any) -> str | None:
    text = _text(value)
    return None if not text or text == "null" else text


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
