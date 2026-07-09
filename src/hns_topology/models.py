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
    "certificate_expired",
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
    authoritative_doh: list[dict[str, Any]]
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
    https_cert_sha256: str | None = None
    https_spki_sha256: str | None = None
    https_cert_not_valid_after: str | None = None


@dataclass(frozen=True)
class HostCandidate:
    root_name: str
    host: str
    source: str
    source_detail: str
    confidence: int
    first_seen_at: str
    last_seen_at: str
    next_check_at: str | None = None
    suppressed: bool = False


@dataclass(frozen=True)
class HostLiveStatus:
    root_name: str
    host: str
    url: str
    address_status: str
    dns_reachable: str
    dnssec_status: str
    tlsa_status: str
    dane_status: str
    https_status: str
    strict_hns_status: str
    authoritative_udp_status: str
    authoritative_tcp_status: str
    authoritative_doh_status: str
    fallback_status: str
    failure_reason: str | None
    checked_at: str
    next_check_at: str
    certificate_sha256: str | None = None
    spki_sha256: str | None = None
    certificate_not_valid_after: str | None = None


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


@dataclass(frozen=True)
class BrowserEvidence:
    name: str
    host: str
    url: str
    source: str
    source_id: str
    evidence_type: str
    browser_result: str
    status_code: int | None
    stage: str | None
    reason: str | None
    mode: str | None
    hns_proof: str | None
    resolution_source: str | None
    authoritative_udp: str | None
    authoritative_tcp: str | None
    authoritative_doh: str | None
    fallback_used: bool | None
    fallback_reason: str | None
    dnssec_status: str | None
    tlsa_owner: str | None
    tlsa_status: str | None
    tlsa_source: str | None
    dane_status: str | None
    certificate_sha256: str | None
    spki_sha256: str | None
    final_error: str | None
    raw_json: dict[str, Any]
    captured_at: str
    certificate_not_valid_after: str | None = None
    certificate_expired: bool | None = None


JsonDict = dict[str, Any]
