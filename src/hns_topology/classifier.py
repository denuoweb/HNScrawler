from __future__ import annotations

import hashlib
import json
from typing import Any

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
    canonical_resource = {"records": records} if isinstance(resource, (dict, list)) else resource
    raw = dumps_json(canonical_resource).encode("utf-8")

    ns_names: set[str] = set()
    glue4: set[str] = set()
    glue6: set[str] = set()
    synth4: set[str] = set()
    synth6: set[str] = set()
    ds_records: list[dict[str, Any]] = []
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

    return ResourceSummary(
        name=normalize_name(name),
        ns_names=sorted(ns_names),
        glue4=sorted(glue4),
        glue6=sorted(glue6),
        synth4=sorted(synth4),
        synth6=sorted(synth6),
        ds_records=sorted(ds_records, key=lambda item: dumps_json(item)),
        has_ds=has_ds,
        has_txt=has_txt,
        raw_size=len(raw),
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


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
