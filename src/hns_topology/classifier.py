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
        elif record_type == "TXT":
            has_txt = True

    return ResourceSummary(
        name=normalize_name(name),
        ns_names=sorted(ns_names),
        glue4=sorted(glue4),
        glue6=sorted(glue6),
        synth4=sorted(synth4),
        synth6=sorted(synth6),
        has_ds=has_ds,
        has_txt=has_txt,
        raw_size=len(raw),
        resource_hash=resource_hash(canonical_resource),
        record_types=sorted(record_types),
        malformed=malformed,
    )


def classify_onchain(summary: ResourceSummary, *, expired: bool, provider_guess: str) -> str:
    if expired:
        return "EXPIRED"
    if summary.malformed:
        return "MALFORMED_RESOURCE"
    if not summary.record_types:
        return "EMPTY"
    if set(summary.record_types) == {"TXT"}:
        return "TXT_ONLY"
    if provider_guess.endswith("/default") or provider_guess in {
        "namebase/default",
        "impervious/default",
    }:
        return "PARKED_OR_DEFAULT"
    if summary.has_ds and (summary.has_ns or summary.has_glue):
        return "DNSSEC_CANDIDATE"
    if summary.has_synth:
        return "DIRECT_SYNTH"
    if summary.has_ns and summary.has_glue:
        return "DELEGATED_WITH_GLUE"
    if summary.has_ns:
        return "DELEGATED_NO_GLUE"
    return "UNKNOWN_OTHER"


def record_types_json(summary: ResourceSummary) -> str:
    return json.dumps(summary.record_types, separators=(",", ":"), sort_keys=True)

