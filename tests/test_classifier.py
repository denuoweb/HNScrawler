from hns_topology.classifier import classify_onchain, summarize_resource
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
