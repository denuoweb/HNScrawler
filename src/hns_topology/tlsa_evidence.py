from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype


@dataclass(frozen=True)
class TlsaEvidenceSummary:
    name: str
    has_tlsa: bool
    records: list[dict[str, Any]]
    owners: list[str]
    observed_at: str | None
    checked_at: str | None


def summarize_tlsa_evidence(
    name: str,
    rows: Iterable[Mapping[str, Any]],
) -> TlsaEvidenceSummary:
    """Summarize the latest TLSA observation from each evidence vantage point.

    An evidence identity is the query owner/type, server, source, and source ID.
    Older answers from the same identity must not keep a removed TLSA RRset alive.
    """

    normalized_name = _normalized_dns_name(name)
    latest: dict[tuple[str, str, str, str, str], Mapping[str, Any]] = {}
    for row in rows:
        if str(row.get("rrtype") or "").upper() != "TLSA":
            continue
        key = (
            _normalized_dns_name(row.get("qname")),
            "TLSA",
            str(row.get("server") or ""),
            str(row.get("source") or ""),
            str(row.get("source_id") or ""),
        )
        current = latest.get(key)
        if current is None or _observation_order(row) > _observation_order(current):
            latest[key] = row

    records_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    positive_times: list[str] = []
    checked_times: list[str] = []
    for row in latest.values():
        captured_at = str(row.get("captured_at") or "")
        if captured_at:
            checked_times.append(captured_at)
        if not _successful_answer(row):
            continue
        qname = _normalized_dns_name(row.get("qname"))
        for record in parse_tlsa_answer_lines(_json_string_list(row.get("answer_json"))):
            owner = str(record["owner"])
            if owner != qname or not _is_https_owner_for_name(owner, normalized_name):
                continue
            key = (
                owner,
                record["usage"],
                record["selector"],
                record["matchingType"],
                record["association"],
            )
            records_by_key[key] = record
            if captured_at:
                positive_times.append(captured_at)

    records = sorted(
        records_by_key.values(),
        key=lambda item: (
            str(item["owner"]),
            int(item["usage"]),
            int(item["selector"]),
            int(item["matchingType"]),
            str(item["association"]),
        ),
    )
    return TlsaEvidenceSummary(
        name=normalized_name.rstrip("."),
        has_tlsa=bool(records),
        records=records,
        owners=sorted({str(record["owner"]) for record in records}),
        observed_at=max(positive_times, default=None),
        checked_at=max(checked_times, default=None),
    )


def parse_tlsa_answer_lines(lines: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in lines:
        parts = str(line).split()
        type_index = _tlsa_type_index(parts)
        if type_index is None:
            continue
        try:
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.TLSA,
                " ".join(parts[type_index + 1 :]),
            )
        except (ValueError, TypeError, dns.exception.DNSException):
            continue
        prefix = parts[1:type_index]
        ttl = next((int(item) for item in prefix if item.isdigit()), None)
        record: dict[str, Any] = {
            "owner": _normalized_dns_name(parts[0]),
            "usage": int(rdata.usage),
            "selector": int(rdata.selector),
            "matchingType": int(rdata.mtype),
            "association": bytes(rdata.cert).hex(),
        }
        if ttl is not None:
            record["ttl"] = ttl
        records.append(record)
    return records


def _tlsa_type_index(parts: list[str]) -> int | None:
    if len(parts) < 5:
        return None
    for index in range(1, min(4, len(parts))):
        if parts[index].upper() != "TLSA":
            continue
        prefix = parts[1:index]
        if all(item.upper() == "IN" or item.isdigit() for item in prefix):
            return index
    return None


def _successful_answer(row: Mapping[str, Any]) -> bool:
    if str(row.get("status") or "").lower() != "ok":
        return False
    rcode = str(row.get("rcode") or "").upper()
    if rcode not in {"", "NOERROR"}:
        return False
    flags = {item.upper() for item in str(row.get("flags") or "").split()}
    return bool(flags & {"AA", "AD"})


def _is_https_owner_for_name(owner: str, name: str) -> bool:
    prefix = "_443._tcp."
    if not owner.startswith(prefix):
        return False
    host = owner.removeprefix(prefix).rstrip(".")
    root = name.rstrip(".")
    return bool(root) and (host == root or host.endswith(f".{root}"))


def _normalized_dns_name(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    return f"{text}." if text else ""


def _observation_order(row: Mapping[str, Any]) -> tuple[str, int]:
    try:
        row_id = int(row.get("id") or 0)
    except (TypeError, ValueError):
        row_id = 0
    return str(row.get("captured_at") or ""), row_id


def _json_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
    else:
        parsed = value
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if item is not None]
