from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from .jsonutil import dumps_json
from .models import ResourceSummary

RECORD_TYPE_ALIASES = {
    0: "DS",
    1: "NS",
    2: "GLUE4",
    3: "GLUE6",
    4: "SYNTH4",
    5: "SYNTH6",
    6: "TXT",
}


def normalize_name(name: str) -> str:
    return name.strip().strip(".").lower()


def normalize_ns(ns: str) -> str:
    return ns.strip().lower().rstrip(".")


def resource_hash(resource: Any) -> str:
    return hashlib.sha256(dumps_json(resource).encode("utf-8")).hexdigest()


def _record_type(value: Any) -> str:
    if isinstance(value, int):
        return RECORD_TYPE_ALIASES.get(value, str(value)).upper()
    return str(value or "").upper()


def _records_from_resource(resource: Any) -> tuple[list[dict[str, Any]], bool]:
    if resource is None:
        return [], False
    if isinstance(resource, list):
        records = resource
    elif isinstance(resource, dict):
        records = resource.get("records", [])
    else:
        return [], True
    if records is None:
        return [], False
    if not isinstance(records, list):
        return [], True
    malformed = any(not isinstance(record, dict) for record in records)
    return [record for record in records if isinstance(record, dict)], malformed


def summarize_resource(name: str, resource: Any) -> ResourceSummary:
    records, malformed = _records_from_resource(resource)
    resource_version = _resource_version(resource)
    canonical_resource = {"records": records} if isinstance(resource, (dict, list)) else resource
    if isinstance(canonical_resource, dict) and resource_version is not None:
        canonical_resource = {"version": resource_version, **canonical_resource}
    raw = dumps_json(canonical_resource).encode("utf-8")

    ns_names: set[str] = set()
    glue4: set[str] = set()
    glue6: set[str] = set()
    synth4: set[str] = set()
    synth6: set[str] = set()
    ds_records: list[dict[str, Any]] = []
    authoritative_doh: list[dict[str, Any]] = []
    record_types: set[str] = set()
    has_ds = False
    has_txt = False

    for record in records:
        record_type = _record_type(record.get("type"))
        if not record_type:
            malformed = True
            continue
        record_types.add(record_type)
        ns = record.get("ns")
        address = record.get("address")

        if record_type == "NS" and ns:
            ns_names.add(normalize_ns(str(ns)))
        elif record_type == "GLUE4":
            if ns:
                ns_names.add(normalize_ns(str(ns)))
            if address:
                glue4.add(str(address).strip())
        elif record_type == "GLUE6":
            if ns:
                ns_names.add(normalize_ns(str(ns)))
            if address:
                glue6.add(str(address).strip())
        elif record_type == "SYNTH4":
            if address:
                synth4.add(str(address).strip())
        elif record_type == "SYNTH6":
            if address:
                synth6.add(str(address).strip())
        elif record_type == "DS":
            has_ds = True
            ds_records.append(_normalize_ds_record(record))
        elif record_type == "TXT":
            has_txt = True
            authoritative_doh.extend(_authoritative_doh_declarations(name, record))

    return ResourceSummary(
        name=normalize_name(name),
        ns_names=sorted(ns_names),
        glue4=sorted(glue4),
        glue6=sorted(glue6),
        synth4=sorted(synth4),
        synth6=sorted(synth6),
        ds_records=sorted(ds_records, key=lambda item: dumps_json(item)),
        authoritative_doh=sorted(authoritative_doh, key=lambda item: dumps_json(item)),
        has_ds=has_ds,
        has_txt=has_txt,
        raw_size=len(raw),
        resource_version=resource_version,
        resource_hash=resource_hash(canonical_resource),
        record_types=sorted(record_types),
        malformed=malformed,
    )


def classify_onchain(summary: ResourceSummary, *, expired: bool, provider_guess: str) -> str:
    return classify_onchain_fields(
        record_types=summary.record_types,
        expired=expired,
        provider_guess=provider_guess,
        has_ds=summary.has_ds,
        has_ns=summary.has_ns,
        has_glue=summary.has_glue,
        has_synth=summary.has_synth,
        malformed=summary.malformed,
    )


def classify_onchain_fields(
    *,
    record_types: list[str],
    expired: bool,
    provider_guess: str,
    has_ds: bool,
    has_ns: bool,
    has_glue: bool,
    has_synth: bool,
    malformed: bool = False,
) -> str:
    if expired:
        return "EXPIRED"
    if malformed:
        return "MALFORMED_RESOURCE"
    if not record_types:
        return "EMPTY"
    if set(record_types) == {"TXT"}:
        return "TXT_ONLY"
    if provider_guess.endswith("/default") or provider_guess in {
        "namebase/default",
        "impervious/default",
    }:
        return "PARKED_OR_DEFAULT"
    if has_ds and (has_ns or has_glue):
        return "DNSSEC_CANDIDATE"
    if has_synth:
        return "DIRECT_SYNTH"
    if has_ns and has_glue:
        return "DELEGATED_WITH_GLUE"
    if has_ns:
        return "DELEGATED_NO_GLUE"
    return "UNKNOWN_OTHER"


def record_types_json(summary: ResourceSummary) -> str:
    return json.dumps(summary.record_types, separators=(",", ":"), sort_keys=True)


def _normalize_ds_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "keyTag": _safe_int(record.get("keyTag")),
        "algorithm": _safe_int(record.get("algorithm")),
        "digestType": _safe_int(record.get("digestType")),
        "digest": str(record.get("digest") or "").replace(" ", "").lower(),
    }


def _authoritative_doh_declarations(name: str, record: dict[str, Any]) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for text in _txt_strings(record):
        parsed = _parse_hnsdns_txt(name, text)
        if parsed is not None:
            declarations.append(parsed)
    return declarations


def _txt_strings(record: dict[str, Any]) -> list[str]:
    raw = record.get("txt", record.get("text", []))
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        values = [str(item).strip() for item in raw if str(item).strip()]
        if len(values) > 1 and any(";" in item or item.startswith("hnsdns=") for item in values):
            return values
        return ["".join(values)] if values else []
    return []


def _parse_hnsdns_txt(name: str, text: str) -> dict[str, Any] | None:
    fields: dict[str, str] = {}
    for part in text.split(";"):
        key, separator, value = part.strip().partition("=")
        if not separator:
            continue
        fields[key.strip().lower()] = value.strip()
    if fields.get("hnsdns") != "1":
        return None
    ns = _normalize_hnsdns_ns(name, fields.get("ns"))
    if not ns:
        return None
    doh = fields.get("doh")
    if doh:
        parsed = _parse_doh_url(doh)
        if parsed is None:
            return None
        parsed["ns"] = ns
        return parsed
    if fields.get("transport", "").lower() != "doh":
        return None
    port = _safe_int(fields.get("port")) or 443
    if port <= 0 or port > 65535:
        return None
    path = fields.get("path") or "/dns-query"
    if not path.startswith("/"):
        path = f"/{path}"
    host = fields.get("host") or ns
    return {
        "ns": ns,
        "url": f"https://{host}{'' if port == 443 else f':{port}'}{path}",
        "host": host.rstrip(".").lower(),
        "path": path,
        "port": port,
    }


def _normalize_hnsdns_ns(name: str, value: str | None) -> str | None:
    if not value:
        return None
    ns = value.strip().lower().rstrip(".")
    if not ns:
        return None
    root = normalize_name(name)
    if "." not in ns and root:
        ns = f"{ns}.{root}"
    return ns


def _parse_doh_url(value: str) -> dict[str, Any] | None:
    normalized = value.strip()
    if normalized.endswith("{?dns}"):
        normalized = normalized[: -len("{?dns}")]
    parsed = urlparse(normalized)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None
    try:
        port = parsed.port or 443
    except ValueError:
        return None
    if port <= 0 or port > 65535:
        return None
    path = parsed.path or "/dns-query"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return {
        "url": normalized,
        "host": parsed.hostname.rstrip(".").lower(),
        "path": path,
        "port": port,
    }


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _resource_version(resource: Any) -> int | None:
    if not isinstance(resource, dict):
        return None
    return _safe_int(resource.get("version"))
