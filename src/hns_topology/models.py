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

FAILURE_REASONS = (
    "missing_glue",
    "nameserver_unreachable_udp",
    "nameserver_unreachable_tcp",
    "no_a_or_aaaa",
    "dnssec_missing",
    "dnssec_bogus",
    "ds_dnskey_mismatch",
    "rrsig_expired",
    "tlsa_missing",
    "tlsa_wrong_owner",
    "stale_tlsa_spki_mismatch",
    "https_connect_failed",
    "certificate_mismatch",
    "doh_fallback_only",
    "malformed_resource",
    "unknown_error",
)

PROMISING_CLASSES = {
    "DIRECT_SYNTH",
    "DELEGATED_WITH_GLUE",
    "DNSSEC_CANDIDATE",
    "DANE_CANDIDATE",
}


@dataclass(frozen=True)
class ResourceSummary:
    name: str
    ns_names: list[str]
    glue4: list[str]
    glue6: list[str]
    synth4: list[str]
    synth6: list[str]
    ds_records: list[dict[str, Any]]
    has_ds: bool
    has_txt: bool
    raw_size: int
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
class LiveStatus:
    name: str
    dns_reachable: str
    dnssec_status: str
    tlsa_status: str
    dane_status: str
    https_status: str
    strict_hns_status: str
    doh_fallback_status: str
    failure_reason: str | None
    checked_at: str
    next_check_at: str


JsonDict = dict[str, Any]
