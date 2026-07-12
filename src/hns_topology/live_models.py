from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CATEGORY_HTTPS = "https"
CATEGORY_HTTP_ONLY = "http_only"
CATEGORY_OFFLINE = "offline"

ONLINE_CATEGORIES = (CATEGORY_HTTPS, CATEGORY_HTTP_ONLY)


@dataclass(frozen=True)
class TopologyRoot:
    name: str
    provider_guess: str
    provider_type: str
    resource_hash: str
    last_seen_height: int | None
    ns_names: list[str]
    bootstrap_addresses: list[str]
    ds_records: list[dict[str, Any]]
    has_ds: bool
    strict_ready: bool
    ns_handoffs: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class LiveCandidate:
    root_name: str
    host: str
    source: str
    source_detail: str
    priority: int
    topology_resource_hash: str


@dataclass(frozen=True)
class DnsProbeResult:
    status: str
    addresses: list[str] = field(default_factory=list)
    dnssec_status: str = "unknown"
    tlsa_status: str = "unknown"
    tlsa_records: list[dict[str, Any]] = field(default_factory=list)
    tlsa_secure: bool = False
    discovered_hosts: list[str] = field(default_factory=list)
    server: str = ""
    failure_reason: str = ""


@dataclass(frozen=True)
class WebProbeResult:
    scheme: str
    status: str
    status_code: int | None = None
    location: str = ""
    address: str = ""
    webpki_status: str = "not_applicable"
    certificate_der: bytes | None = None
    certificate_sha256: str = ""
    spki_sha256: str = ""
    certificate_not_valid_after: str = ""
    failure_reason: str = ""


@dataclass(frozen=True)
class HostProbeResult:
    root_name: str
    host: str
    topology_resource_hash: str
    category: str
    canonical_url: str
    dns_status: str
    addresses: list[str]
    dnssec_status: str
    tlsa_status: str
    tlsa_records: list[dict[str, Any]]
    dane_status: str
    http_status: str
    http_status_code: int | None
    http_location: str
    https_status: str
    https_status_code: int | None
    https_location: str
    webpki_status: str
    certificate_sha256: str
    spki_sha256: str
    certificate_not_valid_after: str
    failure_reason: str
    discovered_hosts: list[str]
    checked_at: str
    duration_ms: int
