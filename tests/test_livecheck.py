import hashlib
import ssl
from pathlib import Path

import dns.dnssec
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from hns_topology.db import connect
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.livecheck import (
    AddressResolution,
    DnssecResult,
    HttpsResult,
    LiveCheckConfig,
    StrictAnswer,
    TlsaResolution,
    _certificate_failure_reason,
    _ds_matches_dnskey,
    _find_rrsig,
    _match_association,
    _resolve_strict_address_resolution,
    _resolve_strict_addresses,
    _resolve_tlsa_secure,
    _strict_doh_endpoints,
    _validate_dnssec_delegation,
    check_host,
    check_name,
    collect_dns_evidence,
    select_live_check_candidates,
)
from hns_topology.provider_rules import ProviderRules

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


def test_tlsa_association_matching_supports_full_and_hashes():
    selected = b"certificate-or-spki"

    assert _match_association(selected, 0, selected)
    assert _match_association(selected, 1, hashlib.sha256(selected).digest())
    assert _match_association(selected, 2, hashlib.sha512(selected).digest())
    assert not _match_association(selected, 1, b"wrong")


def test_certificate_verification_expiry_has_specific_failure_reason():
    exc = ssl.SSLCertVerificationError("certificate has expired")

    assert _certificate_failure_reason(exc) == "certificate_expired"


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


def test_find_rrsig_accepts_dnspython_covers_property():
    owner = dns.name.from_text("example.")

    class RrsigLike:
        name = owner
        rdtype = dns.rdatatype.RRSIG
        covers = dns.rdatatype.DNSKEY

    class ResponseLike:
        answer = [RrsigLike()]

    assert _find_rrsig(ResponseLike(), owner, dns.rdatatype.DNSKEY) is ResponseLike.answer[0]


def test_priority_live_check_names_are_selected_before_limit(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        rows = select_live_check_candidates(conn, limit=1, priority_names=["secure"])

    assert [row["name"] for row in rows] == ["secure"]


def test_collect_dns_evidence_queries_bootstrap_server(monkeypatch):
    seen = []

    def fake_udp(query, server, timeout, raise_on_truncation=False):
        seen.append((query.question[0].name.to_text(), dns.rdatatype.to_text(query.question[0].rdtype), server))
        response = dns.message.make_response(query)
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(
                dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10")
            )
        return response

    monkeypatch.setattr("dns.query.udp", fake_udp)

    evidence = collect_dns_evidence(
        {
            "name": "secure",
            "ns_names": ["ns1.secure"],
            "glue4": ["203.0.113.53"],
            "glue6": [],
            "synth4": [],
            "synth6": [],
        },
        LiveCheckConfig(timeout=0.1),
    )

    assert [item.rrtype for item in evidence] == ["A", "AAAA", "TLSA", "TLSA", "DNSKEY"]
    assert evidence[0].server == "203.0.113.53"
    assert evidence[0].answer == ["secure. 300 IN A 198.51.100.10"]
    assert seen[0] == ("secure.", "A", "203.0.113.53")


def test_strict_address_lookup_requires_authoritative_nonrecursive_answer(monkeypatch):
    seen_flags = []

    def fake_udp(query, server, timeout, raise_on_truncation=False):
        seen_flags.append(query.flags)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.flags |= dns.flags.RA
        response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    def fake_tcp(query, server, timeout):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.flags |= dns.flags.RA
        response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    assert _resolve_strict_addresses(resolver, "secure") == []
    assert seen_flags
    assert not seen_flags[0] & dns.flags.RD


def test_strict_address_lookup_accepts_authoritative_answer(monkeypatch):
    def fake_udp(query, server, timeout, raise_on_truncation=False):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    def fake_tcp(query, server, timeout):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    assert _resolve_strict_addresses(resolver, "secure") == ["198.51.100.10"]


def test_strict_address_lookup_falls_back_to_tcp_on_non_authoritative_udp(monkeypatch):
    calls = []

    def fake_udp(query, server, timeout, raise_on_truncation):
        calls.append("udp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    def fake_tcp(query, server, timeout):
        calls.append("tcp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    assert _resolve_strict_addresses(resolver, "secure") == ["198.51.100.10"]
    assert calls == ["udp", "tcp", "udp", "tcp"]


def test_strict_address_lookup_falls_back_to_tcp_on_udp_failure(monkeypatch):
    calls = []

    def fake_udp(query, server, timeout, raise_on_truncation):
        calls.append("udp")
        raise dns.exception.Timeout

    def fake_tcp(query, server, timeout):
        calls.append("tcp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    assert _resolve_strict_addresses(resolver, "secure") == ["198.51.100.10"]
    assert calls == ["udp", "tcp", "udp", "tcp"]


def test_strict_address_lookup_falls_back_to_tcp_on_truncated_udp(monkeypatch):
    calls = []

    def fake_udp(query, server, timeout, raise_on_truncation):
        calls.append("udp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.TC
        return response

    def fake_tcp(query, server, timeout):
        calls.append("tcp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)

    assert _resolve_strict_addresses(resolver, "secure") == ["198.51.100.10"]
    assert calls == ["udp", "tcp", "udp", "tcp"]


def test_strict_address_lookup_uses_authoritative_doh_after_port53_failure(monkeypatch):
    calls = []

    def fake_udp(query, server, timeout, raise_on_truncation):
        calls.append(("udp", server))
        raise dns.exception.Timeout

    def fake_tcp(query, server, timeout):
        calls.append(("tcp", server))
        raise OSError("blocked")

    def fake_https(query, where, timeout, port, path, post, bootstrap_address, verify, **kwargs):
        calls.append(("doh", where, port, path, bootstrap_address, post, verify))
        assert query.id == 0
        assert not query.flags & dns.flags.RD
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(query.question[0].name, 300, "IN", "A", "198.51.100.10"))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)
    monkeypatch.setattr("dns.query.https", fake_https)

    endpoints = [
        {
            "host": "ns1.secure",
            "path": "/dns-query",
            "port": 443,
            "bootstrap_address": "203.0.113.53",
        }
    ]

    result = _resolve_strict_address_resolution(resolver, "secure", DnssecResult("not_delegated"), endpoints)

    assert result.addresses == ["198.51.100.10"]
    assert ("doh", "ns1.secure", 443, "/dns-query", "203.0.113.53", True, False) in calls


def test_strict_doh_endpoints_are_discovered_from_rfc9461_svcb(monkeypatch):
    def fake_strict_resolve(resolver, owner, rrtype):
        assert owner == "_dns.ns1.secure"
        assert rrtype == "SVCB"
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.SVCB,
            "1 ns1.secure. alpn=h2 dohpath=/dns-query{?dns}",
        )
        return StrictAnswer(
            rrset=dns.rrset.from_rdata("_dns.ns1.secure.", 300, rdata),
            response=dns.message.make_response(dns.message.make_query("_dns.ns1.secure.", dns.rdatatype.SVCB)),
        )

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    monkeypatch.setattr("hns_topology.livecheck._strict_resolve_rrset", fake_strict_resolve)

    endpoints = _strict_doh_endpoints(
        {
            "ns_names": ["ns1.secure"],
            "glue4": ["203.0.113.53"],
            "glue6": [],
            "synth4": [],
            "synth6": [],
            "authoritative_doh": [],
        },
        resolver,
    )

    assert endpoints == [
        {
            "host": "ns1.secure",
            "path": "/dns-query",
            "port": 443,
            "bootstrap_address": "203.0.113.53",
            "url": "https://ns1.secure/dns-query",
        }
    ]


def test_tlsa_lookup_uses_exact_requested_service_owner(monkeypatch):
    seen = []

    def fake_strict_resolve(resolver, owner, rrtype):
        seen.append((owner, rrtype))
        if owner == "_443._tcp.www.example":
            return StrictAnswer(
                rrset=dns.rrset.from_text("_443._tcp.www.example.", 300, "IN", "TLSA", "3 1 1 aa"),
                response=dns.message.make_response(
                    dns.message.make_query("_443._tcp.www.example.", dns.rdatatype.TLSA)
                ),
            )
        return None

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    monkeypatch.setattr("hns_topology.livecheck._strict_resolve_rrset", fake_strict_resolve)

    result = _resolve_tlsa_secure(resolver, "example", DnssecResult("not_delegated"))

    assert seen == [("_443._tcp.example", "TLSA")]
    assert result.records == []


def test_strict_address_resolution_uses_host_owner_and_root_key_owner(monkeypatch):
    seen = {}

    def fake_strict_resolve(resolver, owner, rrtype, doh_endpoints=None):
        seen.setdefault("queries", []).append((owner, rrtype))
        if rrtype == "A":
            return StrictAnswer(
                rrset=dns.rrset.from_text("www.denuoweb.", 300, "IN", "A", "198.51.100.10"),
                response=dns.message.make_response(
                    dns.message.make_query("www.denuoweb.", dns.rdatatype.A)
                ),
            )
        return None

    def fake_rrset_signature_valid(rrset, response, key_owner, dnskey_rrset):
        seen["key_owner"] = key_owner.to_text()
        return True

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    monkeypatch.setattr("hns_topology.livecheck._strict_resolve_rrset", fake_strict_resolve)
    monkeypatch.setattr("hns_topology.livecheck._rrset_signature_valid", fake_rrset_signature_valid)

    result = _resolve_strict_address_resolution(
        resolver,
        "www.denuoweb",
        DnssecResult("valid", dnskey_rrset=object()),
        key_owner="denuoweb",
    )

    assert result.addresses == ["198.51.100.10"]
    assert seen["queries"] == [("www.denuoweb", "A"), ("www.denuoweb", "AAAA")]
    assert seen["key_owner"] == "denuoweb."


def test_tlsa_lookup_uses_host_owner_and_root_key_owner(monkeypatch):
    seen = {}

    def fake_strict_resolve(resolver, owner, rrtype, doh_endpoints=None):
        seen["owner"] = owner
        return StrictAnswer(
            rrset=dns.rrset.from_text("_443._tcp.jaron.crewball.", 300, "IN", "TLSA", "3 1 1 aa"),
            response=dns.message.make_response(
                dns.message.make_query("_443._tcp.jaron.crewball.", dns.rdatatype.TLSA)
            ),
        )

    def fake_rrset_signature_valid(rrset, response, key_owner, dnskey_rrset):
        seen["key_owner"] = key_owner.to_text()
        return True

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    monkeypatch.setattr("hns_topology.livecheck._strict_resolve_rrset", fake_strict_resolve)
    monkeypatch.setattr("hns_topology.livecheck._rrset_signature_valid", fake_rrset_signature_valid)

    result = _resolve_tlsa_secure(
        resolver,
        "jaron.crewball",
        DnssecResult("valid", dnskey_rrset=object()),
        key_owner="crewball",
    )

    assert result.records == [(3, 1, 1, bytes.fromhex("aa"))]
    assert seen["owner"] == "_443._tcp.jaron.crewball"
    assert seen["key_owner"] == "crewball."


def test_dnssec_validation_requires_dnskey_rrsig(monkeypatch):
    owner = dns.name.from_text("example.")
    dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        "257 3 8 AwEAAQIDBAUGBwgJ",
    )
    ds = dns.dnssec.make_ds(owner, dnskey, 2)

    def fake_udp(query, server, timeout, raise_on_truncation=False):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.answer.append(dns.rrset.from_rdata(owner, 3600, dnskey))
        return response

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["203.0.113.53"]
    resolver.timeout = 0.1
    monkeypatch.setattr("dns.query.udp", fake_udp)

    status = _validate_dnssec_delegation(
        resolver,
        "example",
        [
            {
                "keyTag": dns.dnssec.key_id(dnskey),
                "algorithm": dnskey.algorithm,
                "digestType": ds.digest_type,
                "digest": ds.digest.hex(),
            }
        ],
    )

    assert status.status == "missing_rrsig"
    assert status.failure_reason == "dnssec_missing"


class DummyLimiter:
    def __init__(self):
        self.waits = 0

    def wait(self):
        self.waits += 1


def test_check_host_uses_host_for_resolution_tlsa_and_sni(monkeypatch):
    seen = {}

    def validate_dnssec(resolver, name, ds_records):
        seen["zone_name"] = name
        return DnssecResult("valid", dnskey_rrset=object())

    def resolve_addresses(resolver, name, dnssec_result, doh_endpoints=None, *, key_owner=None):
        seen["address_owner"] = name
        seen["address_key_owner"] = key_owner
        return AddressResolution(["198.51.100.99"], secure=True)

    def resolve_tlsa(resolver, name, dnssec_result, doh_endpoints=None, *, key_owner=None):
        seen["tlsa_host"] = name
        seen["tlsa_key_owner"] = key_owner
        return TlsaResolution([])

    def https_connect(hostname, address, timeout):
        seen["sni_hostname"] = hostname
        seen["https_address"] = address
        return HttpsResult("working", b"cert", None)

    monkeypatch.setattr("hns_topology.livecheck._validate_dnssec_delegation", validate_dnssec)
    monkeypatch.setattr("hns_topology.livecheck._resolve_strict_address_resolution", resolve_addresses)
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa_secure", resolve_tlsa)
    monkeypatch.setattr("hns_topology.livecheck._https_connect", https_connect)

    status = check_host(
        {
            "name": "denuoweb",
            "ns_names": ["ns1.denuoweb"],
            "synth4": [],
            "synth6": [],
            "glue4": ["203.0.113.53"],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        "www.denuoweb",
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.root_name == "denuoweb"
    assert status.host == "www.denuoweb"
    assert status.url == "https://www.denuoweb/"
    assert seen == {
        "zone_name": "denuoweb",
        "address_owner": "www.denuoweb",
        "address_key_owner": "denuoweb",
        "sni_hostname": "www.denuoweb",
        "https_address": "198.51.100.99",
        "tlsa_host": "www.denuoweb",
        "tlsa_key_owner": "denuoweb",
    }


def test_synth_is_used_as_nameserver_bootstrap_not_website_address(monkeypatch):
    def resolve_addresses(resolver, name, dnssec_result):
        assert resolver.nameservers == ["198.51.100.20"]
        return AddressResolution(["198.51.100.99"])

    def resolve_tlsa(resolver, name, dnssec_result):
        assert resolver.nameservers == ["198.51.100.20"]
        return TlsaResolution([])

    monkeypatch.setattr("hns_topology.livecheck._resolve_strict_address_resolution", resolve_addresses)
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa_secure", resolve_tlsa)
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("working", b"cert", None)
        if address == "198.51.100.99"
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
    def resolve_addresses(resolver, name, dnssec_result):
        assert resolver.nameservers == ["203.0.113.53"]
        return AddressResolution(["198.51.100.30"])

    monkeypatch.setattr("hns_topology.livecheck._resolve_strict_address_resolution", resolve_addresses)
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa_secure", lambda resolver, name, dnssec_result: TlsaResolution([]))
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
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"], secure=True),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([(3, 1, 1, b"x")], secure=True),
    )
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


def test_dane_requires_secure_address_rrset(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"], secure=False),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([(3, 1, 1, b"x")], secure=True),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("valid", dnskey_rrset=object()),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("tls_unverified", b"cert", "certificate_mismatch"),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: True)

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.tlsa_status == "present"
    assert status.dane_status == "invalid"
    assert status.failure_reason == "dnssec_missing"


def test_dane_requires_secure_tlsa_rrset(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"], secure=True),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([(3, 1, 1, b"x")], secure=False),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("valid", dnskey_rrset=object()),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult("tls_unverified", b"cert", "certificate_mismatch"),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: True)

    status = check_name(
        {
            "name": "example",
            "synth4": ["127.0.0.1"],
            "synth6": [],
            "glue4": [],
            "glue6": [],
            "has_ds": 1,
            "ds_records": [{"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "00"}],
        },
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.tlsa_status == "present"
    assert status.dane_status == "invalid"
    assert status.failure_reason == "dnssec_missing"


def test_stale_tlsa_takes_precedence_over_certificate_mismatch(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"], secure=True),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([(3, 1, 1, b"x")], secure=True),
    )
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
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"]),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([]),
    )
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


def test_expired_certificate_without_tlsa_reports_time_failure(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"]),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([]),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._validate_dnssec_delegation",
        lambda resolver, name, ds_records: DnssecResult("not_delegated"),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_expired",
            cert_sha256="ab" * 32,
            spki_sha256="cd" * 32,
            cert_not_valid_after="2026-07-01T00:00:00Z",
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
    assert status.failure_reason == "certificate_expired"
    assert status.https_cert_sha256 == "ab" * 32
    assert status.https_spki_sha256 == "cd" * 32
    assert status.https_cert_not_valid_after == "2026-07-01T00:00:00Z"


def test_dnssec_failure_prevents_working_dane(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_strict_address_resolution",
        lambda resolver, name, dnssec_result: AddressResolution(["127.0.0.2"], secure=True),
    )
    monkeypatch.setattr(
        "hns_topology.livecheck._resolve_tlsa_secure",
        lambda resolver, name, dnssec_result: TlsaResolution([(3, 1, 1, b"x")], secure=True),
    )
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
