from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hns_topology.live_models import DnsProbeResult, WebProbeResult
from hns_topology.live_probe import (
    ProbeConfig,
    _public_ip,
    probe_dns,
    probe_hns_doh_preflight,
    probe_host,
)


def test_probe_classifies_dane_authenticated_https(monkeypatch):
    cert = _certificate()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    dns_result = DnsProbeResult(
        status="resolved",
        addresses=["93.184.216.34"],
        dnssec_status="valid",
        tlsa_status="present_secure",
        tlsa_records=[
            {
                "owner": "_443._tcp.example.",
                "usage": 3,
                "selector": 1,
                "matching_type": 1,
                "association": hashlib.sha256(spki).hexdigest(),
            }
        ],
        tlsa_secure=True,
    )
    monkeypatch.setattr("hns_topology.live_probe.probe_dns", lambda *args, **kwargs: dns_result)

    def web(_host, _addresses, *, scheme, config):
        if scheme == "http":
            return WebProbeResult(scheme="http", status="failed", failure_reason="refused")
        return WebProbeResult(
            scheme="https",
            status="response",
            status_code=200,
            webpki_status="invalid",
            certificate_der=cert_der,
            failure_reason="certificate_untrusted",
        )

    monkeypatch.setattr("hns_topology.live_probe._probe_web", web)

    result = probe_host(_candidate(), config=ProbeConfig())

    assert result.category == "https"
    assert result.https_status == "online_dane"
    assert result.dane_status == "valid"
    assert result.canonical_url == "https://example/"


def test_resolved_address_filter_requires_global_unicast():
    assert _public_ip("93.184.216.34") is True
    assert _public_ip("224.0.0.1") is False
    assert _public_ip("ff02::1") is False
    assert _public_ip("10.0.0.1") is False


def test_dns_probe_resolves_delegation_hosts_when_glue_is_missing(monkeypatch):
    responses = {
        ("example", "A"): _response_with_a("example", "93.184.216.34"),
        ("example", "AAAA"): _empty_response("example", "AAAA"),
        ("_443._tcp.example", "TLSA"): _empty_response("_443._tcp.example", "TLSA"),
    }
    resolver_calls = []
    authoritative_servers = []

    def resolve_nameserver(host, *, timeout, resolver_address):
        resolver_calls.append((host, timeout, resolver_address))
        return ["93.184.216.53"]

    def query(servers, qname, rrtype, *, timeout):
        authoritative_servers.append(tuple(servers))
        return responses[(qname, rrtype)], servers[0]

    monkeypatch.setattr("hns_topology.live_probe._fallback_addresses", resolve_nameserver)
    monkeypatch.setattr("hns_topology.live_probe._authoritative_query", query)
    candidate = {
        **_candidate(),
        "bootstrap_addresses": [],
        "ns_names": ["ns1.provider.net"],
    }

    result = probe_dns(
        candidate,
        config=ProbeConfig(fallback_resolver="1.1.1.1"),
    )

    assert resolver_calls == [("ns1.provider.net", 5.0, "1.1.1.1")]
    assert authoritative_servers == [("93.184.216.53",)] * 3
    assert result.status == "resolved"
    assert result.addresses == ["93.184.216.34"]


def test_dns_probe_uses_hns_doh_when_direct_bootstrap_is_unavailable(monkeypatch):
    tlsa = dns.rrset.from_text(
        "_443._tcp.example.",
        300,
        "IN",
        "TLSA",
        "3 1 1 " + "ab" * 32,
    )
    responses = {
        ("example", "A"): _authenticated_response(_response_with_a("example", "93.184.216.34")),
        ("example", "AAAA"): _authenticated_response(_empty_response("example", "AAAA")),
        ("_443._tcp.example", "TLSA"): _authenticated_response(
            _response_with_rrset(tlsa)
        ),
    }
    doh_calls = []

    def doh(qname, rrtype, *, resolver_url, timeout):
        doh_calls.append((qname, rrtype, resolver_url, timeout))
        return responses[(qname, rrtype)]

    monkeypatch.setattr("hns_topology.live_probe._hns_doh_query", doh)
    candidate = {
        **_candidate(),
        "bootstrap_addresses": [],
        "ns_names": [],
        "ns_handoffs": [],
    }

    result = probe_dns(
        candidate,
        config=ProbeConfig(hns_doh_url="https://resolver.example/dns-query"),
    )

    assert doh_calls == [
        ("example", "A", "https://resolver.example/dns-query", 5.0),
        ("example", "AAAA", "https://resolver.example/dns-query", 5.0),
        ("_443._tcp.example", "TLSA", "https://resolver.example/dns-query", 5.0),
    ]
    assert result.status == "resolved"
    assert result.addresses == ["93.184.216.34"]
    assert result.dnssec_status == "resolver_validated"
    assert result.tlsa_status == "present_secure"
    assert result.tlsa_secure is True


def test_hns_doh_preflight_resolves_only_addresses_and_preserves_ad_signal(monkeypatch):
    calls = []

    def doh(qname, rrtype, *, resolver_url, timeout):
        calls.append((qname, rrtype, resolver_url, timeout))
        if rrtype == "A":
            return _authenticated_response(_response_with_a(qname, "93.184.216.34"))
        return _authenticated_response(_empty_response(qname, rrtype))

    monkeypatch.setattr("hns_topology.live_probe._hns_doh_query", doh)

    result = probe_hns_doh_preflight(
        _candidate(),
        config=ProbeConfig(hns_doh_url="https://resolver.example/dns-query"),
    )

    assert calls == [
        ("example", "A", "https://resolver.example/dns-query", 5.0),
        ("example", "AAAA", "https://resolver.example/dns-query", 5.0),
    ]
    assert result.status == "resolved"
    assert result.addresses == ["93.184.216.34"]
    assert result.dnssec_status == "resolver_validated"
    assert result.tlsa_status == "not_checked"


def test_dns_probe_falls_back_to_hns_doh_after_direct_authority_has_no_address(monkeypatch):
    direct_queries = []

    def authority(_servers, qname, rrtype, *, timeout):
        direct_queries.append((qname, rrtype, timeout))
        return _empty_response(qname, rrtype), "93.184.216.53"

    def doh(qname, rrtype, *, resolver_url, timeout):
        if rrtype == "A":
            return _authenticated_response(_response_with_a(qname, "93.184.216.34"))
        return _authenticated_response(_empty_response(qname, rrtype))

    monkeypatch.setattr("hns_topology.live_probe._authoritative_query", authority)
    monkeypatch.setattr("hns_topology.live_probe._hns_doh_query", doh)

    result = probe_dns(
        _candidate(),
        config=ProbeConfig(hns_doh_url="https://resolver.example/dns-query"),
    )

    assert direct_queries == [
        ("example", "A", 5.0),
        ("example", "AAAA", 5.0),
        ("_443._tcp.example", "TLSA", 5.0),
    ]
    assert result.status == "resolved"
    assert result.addresses == ["93.184.216.34"]
    assert result.dnssec_status == "resolver_validated"


def test_probe_classifies_http_response_when_https_fails(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.live_probe.probe_dns",
        lambda *args, **kwargs: DnsProbeResult(
            status="resolved",
            addresses=["93.184.216.34"],
            dnssec_status="unsigned",
            tlsa_status="missing",
        ),
    )

    def web(_host, _addresses, *, scheme, config):
        if scheme == "http":
            return WebProbeResult(scheme="http", status="response", status_code=200)
        return WebProbeResult(scheme="https", status="failed", failure_reason="connection_refused")

    monkeypatch.setattr("hns_topology.live_probe._probe_web", web)

    result = probe_host(_candidate(), config=ProbeConfig())

    assert result.category == "http_only"
    assert result.canonical_url == "http://example/"
    assert result.failure_reason == "connection_refused"


def test_probe_rejects_web_response_when_parent_ds_cannot_validate_dnssec(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.live_probe.probe_dns",
        lambda *args, **kwargs: DnsProbeResult(
            status="resolved",
            addresses=["93.184.216.34"],
            dnssec_status="dnskey_missing",
            tlsa_status="missing",
        ),
    )

    def web(_host, _addresses, *, scheme, config):
        if scheme == "http":
            return WebProbeResult(scheme="http", status="response", status_code=302)
        return WebProbeResult(scheme="https", status="failed", failure_reason="certificate_untrusted")

    monkeypatch.setattr("hns_topology.live_probe._probe_web", web)

    result = probe_host(
        {**_candidate(), "ds_records": [{"keyTag": 1}]},
        config=ProbeConfig(),
    )

    assert result.category == "offline"
    assert result.canonical_url == ""
    assert result.https_status == "blocked_dnssec"
    assert result.failure_reason == "dnssec_validation_failed"


def test_probe_does_not_treat_unavailable_dns_as_a_dnssec_validation_failure(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.live_probe.probe_dns",
        lambda *args, **kwargs: DnsProbeResult(
            status="no_bootstrap",
            dnssec_status="unknown",
            failure_reason="no_public_authoritative_address",
        ),
    )
    monkeypatch.setattr(
        "hns_topology.live_probe._probe_web",
        lambda *args, **kwargs: WebProbeResult(scheme="http", status="not_checked"),
    )

    result = probe_host(
        {**_candidate(), "ds_records": [{"keyTag": 1}]},
        config=ProbeConfig(),
    )

    assert result.category == "offline"
    assert result.https_status == "failed"
    assert result.failure_reason == "no_public_authoritative_address"


def test_probe_classifies_untrusted_https_without_http_as_offline(monkeypatch):
    monkeypatch.setattr(
        "hns_topology.live_probe.probe_dns",
        lambda *args, **kwargs: DnsProbeResult(
            status="resolved",
            addresses=["93.184.216.34"],
            dnssec_status="unsigned",
            tlsa_status="missing",
        ),
    )

    def web(_host, _addresses, *, scheme, config):
        if scheme == "http":
            return WebProbeResult(scheme="http", status="failed", failure_reason="connection_refused")
        return WebProbeResult(
            scheme="https",
            status="response",
            status_code=200,
            webpki_status="invalid",
            failure_reason="certificate_untrusted",
        )

    monkeypatch.setattr("hns_topology.live_probe._probe_web", web)

    result = probe_host(_candidate(), config=ProbeConfig())

    assert result.category == "offline"
    assert result.canonical_url == ""
    assert result.failure_reason == "certificate_untrusted"


def test_probe_tries_all_addresses_until_https_authenticates(monkeypatch):
    dns_result = DnsProbeResult(
        status="resolved",
        addresses=["93.184.216.34", "93.184.216.35"],
        dnssec_status="unsigned",
        tlsa_status="missing",
    )
    monkeypatch.setattr(
        "hns_topology.live_probe.probe_dns",
        lambda *args, **kwargs: dns_result,
    )
    https_addresses = []

    def web(_host, addresses, *, scheme, config):
        if scheme == "http":
            return WebProbeResult(scheme="http", status="failed", failure_reason="refused")
        https_addresses.append(addresses[0])
        return WebProbeResult(
            scheme="https",
            status="response",
            status_code=200,
            address=addresses[0],
            webpki_status="valid" if addresses[0].endswith("35") else "invalid",
            failure_reason="" if addresses[0].endswith("35") else "certificate_untrusted",
        )

    monkeypatch.setattr("hns_topology.live_probe._probe_web", web)

    result = probe_host(_candidate(), config=ProbeConfig())

    assert https_addresses == ["93.184.216.34", "93.184.216.35"]
    assert result.category == "https"
    assert result.webpki_status == "valid"


def test_dns_probe_validates_ds_dnskey_and_tlsa_signatures(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    owner = dns.name.from_text("example.")
    dnskey = dns.dnssec.make_dnskey(private_key.public_key(), 8)
    dnskey_rrset = dns.rrset.from_rdata(owner, 300, dnskey)
    ds = dns.dnssec.make_ds(owner, dnskey, 2)
    a_rrset = dns.rrset.from_text("example.", 300, "IN", "A", "93.184.216.34")
    tlsa_rrset = dns.rrset.from_text(
        "_443._tcp.example.",
        300,
        "IN",
        "TLSA",
        "3 1 1 " + "ab" * 32,
    )
    responses = {
        ("example", "DNSKEY"): _signed_response(dnskey_rrset, private_key, owner, dnskey),
        ("example", "A"): _signed_response(a_rrset, private_key, owner, dnskey),
        ("example", "AAAA"): _empty_response("example", "AAAA"),
        ("_443._tcp.example", "TLSA"): _signed_response(tlsa_rrset, private_key, owner, dnskey),
    }

    def query(_servers, qname, rrtype, *, timeout):
        return responses[(qname, rrtype)], "93.184.216.53"

    monkeypatch.setattr("hns_topology.live_probe._authoritative_query", query)
    candidate = {
        **_candidate(),
        "ds_records": [
            {
                "keyTag": int(ds.key_tag),
                "algorithm": int(ds.algorithm),
                "digestType": int(ds.digest_type),
                "digest": ds.digest.hex(),
            }
        ],
    }

    result = probe_dns(candidate, config=ProbeConfig())

    assert result.status == "resolved"
    assert result.addresses == ["93.184.216.34"]
    assert result.dnssec_status == "valid"
    assert result.tlsa_status == "present_secure"
    assert result.tlsa_secure is True


def _candidate():
    return {
        "root_name": "example",
        "host": "example",
        "topology_resource_hash": "hash-1",
        "bootstrap_addresses": ["93.184.216.34"],
        "ds_records": [],
    }


def _certificate() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def _signed_response(rrset, private_key, signer, dnskey):
    now = datetime.now(UTC)
    signature = dns.dnssec.sign(
        rrset,
        private_key,
        signer,
        dnskey,
        inception=now - timedelta(minutes=1),
        expiration=now + timedelta(days=1),
    )
    query = dns.message.make_query(rrset.name, rrset.rdtype)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    response.answer.extend([rrset, dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)])
    return response


def _empty_response(qname, rrtype):
    response = dns.message.make_response(dns.message.make_query(qname, rrtype))
    response.flags |= dns.flags.AA
    return response


def _response_with_a(qname: str, address: str):
    rrset = dns.rrset.from_text(f"{qname}.", 300, "IN", "A", address)
    return _response_with_rrset(rrset)


def _response_with_rrset(rrset):
    response = dns.message.make_response(dns.message.make_query(rrset.name, rrset.rdtype))
    response.flags |= dns.flags.AA
    response.answer.append(rrset)
    return response


def _authenticated_response(response):
    response.flags |= dns.flags.AD
    return response
