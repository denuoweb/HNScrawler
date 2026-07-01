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

