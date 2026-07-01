import hashlib

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from hns_topology.livecheck import (
    DnssecResult,
    HttpsResult,
    LiveCheckConfig,
    _ds_matches_dnskey,
    _match_association,
    check_name,
)


def test_tlsa_association_matching_supports_full_and_hashes():
    selected = b"certificate-or-spki"

    assert _match_association(selected, 0, selected)
    assert _match_association(selected, 1, hashlib.sha256(selected).digest())
    assert _match_association(selected, 2, hashlib.sha512(selected).digest())
    assert not _match_association(selected, 1, b"wrong")


def test_ds_record_matches_dnskey():
    owner = dns.name.from_text("example.")
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        "257 3 8 AwEAAQIDBAUGBwgJ",
    )
    ds = dns.dnssec.make_ds(owner, dnskey, 2)
    rrset = dns.rrset.from_rdata(owner, 3600, dnskey)

    assert _ds_matches_dnskey(
        owner,
        [
            {
                "keyTag": dns.dnssec.key_id(dnskey),
                "algorithm": dnskey.algorithm,
                "digestType": ds.digest_type,
                "digest": ds.digest.hex(),
            }
        ],
        rrset,
    )


class DummyLimiter:
    def __init__(self):
        self.waits = 0

    def wait(self):
        self.waits += 1


def test_direct_synth_uses_onchain_address_without_resolver_fallback(monkeypatch):
    def fail_resolve_addresses(resolver, name):
        raise AssertionError("direct SYNTH checks must not use resolver fallback for addresses")

    def fail_resolve_tlsa(resolver, name):
        raise AssertionError("direct SYNTH without strict delegation must not use fallback TLSA")

    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", fail_resolve_addresses)
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", fail_resolve_tlsa)
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("working", b"cert", None)
        if address == "198.51.100.20"
        else HttpsResult("failed", None, "https_connect_failed"),
    )

    status = check_name(
        {
            "name": "direct",
            "ns_names": [],
            "synth4": ["198.51.100.20"],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "ds_records": [],
            "has_ds": 0,
        },
        LiveCheckConfig(timeout=0.1, resolver="192.0.2.53"),
        DummyLimiter(),
    )

    assert status.dns_reachable == "reachable"
    assert status.strict_hns_status == "working"
    assert status.doh_fallback_status == "not_required"
    assert status.failure_reason is None


def test_glue_is_used_as_nameserver_not_website_address(monkeypatch):
    def resolve_addresses(resolver, name):
        assert resolver.nameservers == ["203.0.113.53"]
        return ["198.51.100.30"]

    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", resolve_addresses)
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [])
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("working", b"cert", None)
        if address == "198.51.100.30"
        else HttpsResult("failed", None, "https_connect_failed"),
    )

    status = check_name(
        {
            "name": "delegated",
            "ns_names": ["ns1.delegated"],
            "synth4": [],
            "synth6": [],
            "glue4": ["203.0.113.53"],
            "glue6": [],
            "ds_records": [],
            "has_ds": 0,
        },
        LiveCheckConfig(timeout=0.1, resolver="192.0.2.53"),
        DummyLimiter(),
    )

    assert status.dns_reachable == "reachable"
    assert status.strict_hns_status == "working"
    assert status.doh_fallback_status == "not_required"
    assert status.failure_reason is None


def test_missing_glue_with_fallback_success_is_fallback_only(monkeypatch):
    def resolve_addresses(resolver, name):
        assert resolver.nameservers == ["192.0.2.53"]
        return ["198.51.100.40"]

    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", resolve_addresses)
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("working", b"cert", None),
    )

    status = check_name(
        {
            "name": "noglue",
            "ns_names": ["ns1.noglue"],
            "synth4": [],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "ds_records": [],
            "has_ds": 0,
        },
        LiveCheckConfig(timeout=0.1, resolver="192.0.2.53"),
        DummyLimiter(),
    )

    assert status.dns_reachable == "fallback_reachable"
    assert status.strict_hns_status == "fallback_only"
    assert status.doh_fallback_status == "required"
    assert status.failure_reason == "missing_glue"


def test_missing_glue_with_fallback_https_failure_keeps_https_failure(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: ["198.51.100.40"])
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("failed", None, "https_connect_failed"),
    )

    status = check_name(
        {
            "name": "noglue",
            "ns_names": ["ns1.noglue"],
            "synth4": [],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "ds_records": [],
            "has_ds": 0,
        },
        LiveCheckConfig(timeout=0.1, resolver="192.0.2.53"),
        DummyLimiter(),
    )

    assert status.doh_fallback_status == "required"
    assert status.strict_hns_status == "fallback_only"
    assert status.failure_reason == "https_connect_failed"


def test_missing_glue_without_fallback_address_preserves_missing_glue(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])

    status = check_name(
        {
            "name": "noglue",
            "ns_names": ["ns1.noglue"],
            "synth4": [],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "ds_records": [],
            "has_ds": 0,
        },
        LiveCheckConfig(timeout=0.1, resolver="192.0.2.53"),
        DummyLimiter(),
    )

    assert status.dns_reachable == "missing_glue"
    assert status.failure_reason == "missing_glue"


def test_dane_match_can_work_without_webpki_validation(monkeypatch):
    limiter = DummyLimiter()
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [(3, 1, 1, b"x")])
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("valid"),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: True)

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": ["127.0.0.53"],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        LiveCheckConfig(timeout=0.1),
        limiter,
    )

    assert limiter.waits == 1
    assert status.https_status == "tls_unverified"
    assert status.tlsa_status == "present"
    assert status.dane_status == "valid"
    assert status.strict_hns_status == "working"
    assert status.failure_reason is None


def test_stale_tlsa_takes_precedence_over_certificate_mismatch(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [(3, 1, 1, b"x")])
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("valid"),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: False)

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": ["127.0.0.53"],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.dane_status == "invalid"
    assert status.failure_reason == "stale_tlsa_spki_mismatch"


def test_unverified_https_without_tlsa_keeps_certificate_failure(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [])
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("not_delegated"),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "has_ds": 0,
            "ds_records": [],
        },
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.tlsa_status == "missing"
    assert status.dane_status == "unknown"
    assert status.failure_reason == "certificate_mismatch"


def test_dnssec_failure_prevents_working_dane(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [(3, 1, 1, b"x")])
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("ds_dnskey_mismatch", "ds_dnskey_mismatch"),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("working", b"cert", None),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: True)

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": ["127.0.0.53"],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.dnssec_status == "ds_dnskey_mismatch"
    assert status.dane_status == "invalid"
    assert status.failure_reason == "ds_dnskey_mismatch"
