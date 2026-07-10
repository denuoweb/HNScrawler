from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ONCHAIN_CLASSES = (
    "EXPIRED",
    "EMPTY",
    "TXT_ONLY",
    "DIRECT_SYNTH",
    "DELEGATED_WITH_GLUE",
    "DELEGATED_NO_GLUE",
    "DNSSEC_CANDIDATE",
    "DANE_CANDIDATE",
    "PARKED_OR_DEFAULT",
    "MALFORMED_RESOURCE",
    "UNKNOWN_OTHER",
)


@dataclass(frozen=True)
class ResourceSummary:
    name: str
    ns_names: list[str]
    glue4: list[str]
    glue6: list[str]
    synth4: list[str]
    synth6: list[str]
    ds_records: list[dict[str, Any]]
    tlsa_records: list[dict[str, Any]]
    tlsa_cert_not_valid_after: str | None
    tlsa_cert_expired: bool
    has_ds: bool
    has_txt: bool
    raw_size: int
    resource_version: int | None
    resource_hash: str
    record_types: list[str]
    malformed: bool = False

    @property
    def has_ns(self) -> bool:
        return bool(self.ns_names)

    @property
    def has_glue(self) -> bool:
        return bool(self.glue4 or self.glue6)

    @property
    def has_synth(self) -> bool:
        return bool(self.synth4 or self.synth6)


@dataclass(frozen=True)
class NameRecord:
    name: str
    name_hash: str
    state: str | None
    renewal_height: int | None
    expired: bool
    resource_hash: str
    record_types: list[str]
    onchain_class: str
    provider_guess: str
    last_seen_height: int | None
    updated_at: str


@dataclass(frozen=True)
class DnsEvidence:
    name: str
    qname: str
    rrtype: str
    server: str
    source: str
    source_id: str
    status: str
    rcode: str | None
    flags: str | None
    answer: list[str]
    authority: list[str]
    additional: list[str]
    elapsed_ms: int | None
    error: str | None
    captured_at: str


JsonDict = dict[str, Any]
