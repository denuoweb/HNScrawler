from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hns_topology.classifier import classify_onchain, summarize_resource
from hns_topology.infra import resource_ip_role
from hns_topology.provider_rules import ProviderRules


def test_summarizes_direct_synth_records():
    summary = summarize_resource(
        "Direct.",
        {"records": [{"type": "SYNTH4", "address": "203.0.113.10"}]},
    )

    assert summary.name == "direct"
    assert summary.synth4 == ["203.0.113.10"]
    assert summary.record_types == ["SYNTH4"]
    assert classify_onchain(summary, expired=False, provider_guess="unknown/custom") == "DIRECT_SYNTH"


def test_summarizes_resource_version():
    summary = summarize_resource(
        "versioned",
        {"version": 0, "records": [{"type": "NS", "ns": "ns1.versioned."}]},
    )

    assert summary.resource_version == 0
    assert summary.raw_size > 0


def test_classifies_delegated_without_glue():
    summary = summarize_resource(
        "noglue",
        {"records": [{"type": "NS", "ns": "ns1.example."}]},
    )

    assert summary.ns_names == ["ns1.example"]
    assert classify_onchain(summary, expired=False, provider_guess="unknown/custom") == "DELEGATED_NO_GLUE"


def test_classifies_dnssec_candidate_before_plain_delegation():
    summary = summarize_resource(
        "secure",
        {
            "records": [
                {"type": "NS", "ns": "ns1.secure."},
                {"type": "GLUE4", "ns": "ns1.secure.", "address": "198.51.100.3"},
                {"type": "DS", "keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "aa"},
            ]
        },
    )

    assert summary.has_ds is True
    assert classify_onchain(summary, expired=False, provider_guess="self-hosted") == "DNSSEC_CANDIDATE"


def test_hnsdns_txt_is_plain_txt_not_authoritative_doh_discovery():
    summary = summarize_resource(
        "dane",
        {
            "records": [
                {"type": "NS", "ns": "ns1.dane."},
                {"type": "GLUE4", "ns": "ns1.dane.", "address": "198.51.100.53"},
                {"type": "TXT", "txt": ["hnsdns=1;ns=ns1.dane.;doh=https://ns1.dane/dns-query{?dns}"]},
            ]
        },
    )

    assert summary.has_txt is True
    assert summary.record_types == ["GLUE4", "NS", "TXT"]


def test_summarizes_static_embedded_tlsa_certificate_expiration():
    cert = make_certificate(days_valid=-1)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    summary = summarize_resource(
        "expiredcert",
        {
            "records": [
                {
                    "type": "TLSA",
                    "usage": 3,
                    "selector": 0,
                    "matchingType": 0,
                    "certificate": cert_der.hex(),
                }
            ]
        },
    )

    assert summary.record_types == ["TLSA"]
    assert summary.tlsa_cert_expired is True
    assert summary.tlsa_cert_not_valid_after.endswith("Z")
    assert summary.tlsa_records[0]["certificateExpired"] is True
    assert summary.tlsa_records[0]["certificateNotValidAfter"] == summary.tlsa_cert_not_valid_after


def test_spki_hash_tlsa_does_not_infer_certificate_expiration():
    summary = summarize_resource(
        "spki",
        {
            "records": [
                {
                    "type": "TLSA",
                    "usage": 3,
                    "selector": 1,
                    "matchingType": 1,
                    "certificate": "aa" * 32,
                }
            ]
        },
    )

    assert summary.record_types == ["TLSA"]
    assert summary.tlsa_records[0]["selector"] == 1
    assert "certificateNotValidAfter" not in summary.tlsa_records[0]
    assert summary.tlsa_cert_not_valid_after is None
    assert summary.tlsa_cert_expired is False


def test_classifies_malformed_resource():
    summary = summarize_resource("bad", {"records": "wrong"})

    assert summary.malformed is True
    assert classify_onchain(summary, expired=False, provider_guess="unknown/custom") == "MALFORMED_RESOURCE"


def test_provider_rules_detect_self_hosted_and_default():
    rules = ProviderRules.from_file("configs/provider_rules.json")

    self_hosted = summarize_resource(
        "example",
        {"records": [{"type": "NS", "ns": "ns1.example."}]},
    )
    parked = summarize_resource(
        "parked",
        {"records": [{"type": "NS", "ns": "ns1.namebase.io."}]},
    )

    assert rules.match("example", self_hosted) == "self-hosted"
    assert rules.match("parked", parked) == "namebase/default"
    assert rules.provider_patterns["self-hosted"]["ns_pattern"] == "self_hosted"
    assert (
        rules.provider_patterns["namebase/default"]["ns_pattern"]
        == "suffix:namebase.io,suffix:parking.namebase.io"
    )


def test_provider_rules_mark_shared_default_glue_before_self_hosted():
    rules = ProviderRules.from_file("configs/provider_rules.json")
    summary = summarize_resource(
        "bulk",
        {
            "records": [
                {"type": "NS", "ns": "ns1.bulk."},
                {"type": "GLUE4", "ns": "ns1.bulk.", "address": "44.231.6.183"},
            ]
        },
    )

    provider = rules.match("bulk", summary)

    assert provider == "bulk/default"
    assert classify_onchain(summary, expired=False, provider_guess=provider) == "PARKED_OR_DEFAULT"


def test_resource_ip_role_uses_source_backed_glue_labels():
    assert resource_ip_role("44.231.6.183")["label"] == "Namebase glue cluster"
    assert (
        resource_ip_role("34.123.215.203")["label"]
        == "BNS collision study identified glue cluster"
    )
    assert resource_ip_role("203.0.113.10")["role"] == "unknown"


def test_provider_rules_mark_known_public_resolver_ips():
    rules = ProviderRules.from_file("configs/provider_rules.json")
    summary = summarize_resource(
        "resolverglue",
        {
            "records": [
                {"type": "NS", "ns": "ns1.resolverglue."},
                {"type": "GLUE4", "ns": "ns1.resolverglue.", "address": "194.50.5.27"},
            ]
        },
    )

    assert rules.match("resolverglue", summary) == "hns-resolver/plain-dns"


def test_provider_rules_match_common_dns_providers():
    rules = ProviderRules.from_file("configs/provider_rules.json")
    cases = [
        ("cloudflare", "alice", "mona.ns.cloudflare.com", "cloudflare"),
        ("route53", "alice", "ns-123.awsdns-45.com", "aws/route53"),
        ("digitalocean", "alice", "ns1.digitalocean.com", "digitalocean"),
        ("namecheap", "alice", "dns1.registrar-servers.com", "namecheap"),
        ("godaddy", "alice", "ns01.domaincontrol.com", "godaddy"),
        ("porkbun", "alice", "curitiba.ns.porkbun.com", "porkbun"),
        ("dynadot", "alice", "ns1.dynadot.com", "dynadot"),
        ("dnsimple", "alice", "ns1.dnsimple.com", "dnsimple"),
        ("gandi", "alice", "ns-1-a.gandi.net", "gandi"),
        ("ovh", "alice", "dns10.ovh.net", "ovh"),
        ("he", "alice", "ns1.he.net", "hurricane-electric"),
        ("linode", "alice", "ns1.linode.com", "akamai/linode"),
        ("akamai", "alice", "a1-1.akam.net", "akamai/linode"),
        ("ns1", "alice", "dns1.p01.nsone.net", "ns1"),
        ("vercel", "alice", "ns1.vercel-dns.com", "vercel"),
        ("cloudns", "alice", "pns1.cloudns.net", "cloudns"),
        ("desec", "alice", "ns1.desec.io", "desec"),
        ("google", "alice", "ns-cloud-a1.googledomains.com", "google/cloud-dns"),
        ("azure", "alice", "ns1-01.azure-dns.com", "azure-dns"),
        ("dns-made-easy", "alice", "ns10.dnsmadeeasy.com", "dns-made-easy"),
        ("hetzner", "alice", "hydrogen.ns.hetzner.com", "hetzner"),
        ("bunny", "alice", "kiki.bunny.net", "bunny"),
        ("easydns", "alice", "dns1.easydns.com", "easydns"),
        ("spaceship", "alice", "launch1.spaceship.net", "spaceship"),
    ]

    for label, name, ns, expected in cases:
        summary = summarize_resource(label, {"records": [{"type": "NS", "ns": f"{ns}."}]})
        assert rules.match(name, summary) == expected


def test_provider_rules_keep_self_hosted_priority_over_suffix_rules():
    rules = ProviderRules.from_file("configs/provider_rules.json")
    summary = summarize_resource("cloudflare", {"records": [{"type": "NS", "ns": "ns1.cloudflare."}]})

    assert rules.match("cloudflare", summary) == "self-hosted"


def test_provider_rules_match_private_direct_ip_clusters():
    rules = ProviderRules.from_file("configs/provider_rules.json")
    summary = summarize_resource("private", {"records": [{"type": "SYNTH4", "address": "10.8.0.1"}]})

    assert rules.match("private", summary) == "direct-ip/private"


def make_certificate(*, days_valid: int) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expiredcert")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
