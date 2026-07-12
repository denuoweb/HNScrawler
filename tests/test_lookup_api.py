import json
from pathlib import Path

from hns_topology.db import connect
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.lookup_api import lookup_name, normalize_name
from hns_topology.provider_rules import ProviderRules

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


def test_normalize_name_accepts_common_hns_inputs():
    assert normalize_name("denuoweb/") == "denuoweb"
    assert normalize_name("hns://DenuoWeb/") == "denuoweb"
    assert normalize_name("https://denuoweb/path") == "denuoweb"


def test_lookup_name_returns_full_snapshot_row(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    result = lookup_name(db_path, "direct/")

    assert result["found"] is True
    assert result["normalized"] == "direct"
    assert result["row"]["name"] == "direct"
    assert result["row"]["onchain_class"] == "DIRECT_SYNTH"
    assert result["row"]["compliance_stage"] == "bootstrap_ready"
    assert "provider_type" in result["row"]
    assert result["row"]["synth4"] == ["203.0.113.10"]
    assert result["row"]["resource_version"] == 0
    assert result["row"]["raw_size"] > 0
    assert result["row"]["resource_hash"]
    assert "browser_evidence_path" not in result["row"]
    assert "https_cert_sha256" not in result["row"]
    assert result["snapshot"]["last_indexed_height"] == "123456"


def test_lookup_name_includes_indirect_nameserver_handoff(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    fixture_path = tmp_path / "handoff.json"
    fixture_path.write_text(
        json.dumps(
            {
                "chain": "fixture",
                "height": 337132,
                "tip_hash": "handoff-tip",
                "hsd_version": "fixture",
                "names": [
                    {
                        "name": "mercenary",
                        "nameHash": "hash-mercenary",
                        "state": "CLOSED",
                        "renewal": 337000,
                        "resource": {"records": [{"type": "NS", "ns": "ns1.skyinclude."}]},
                    },
                    {
                        "name": "skyinclude",
                        "nameHash": "hash-skyinclude",
                        "state": "CLOSED",
                        "renewal": 337000,
                        "resource": {
                            "records": [
                                {"type": "GLUE4", "ns": "ns1.hshub.", "address": "192.155.93.228"},
                                {"type": "NS", "ns": "ns1.hshub."},
                            ]
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=fixture_path, rules=rules)

    result = lookup_name(db_path, "mercenary/")

    assert result["found"] is True
    assert result["row"]["compliance_stage"] == "indirect_ns_handoff"
    assert result["row"]["ns_handoff_ns"] == "ns1.skyinclude"
    assert result["row"]["ns_handoff_root"] == "skyinclude"
    assert result["row"]["ns_handoff_bootstrap_ip"] == "192.155.93.228"
    assert result["row"]["ns_handoff_bootstrap_field"] == "GLUE4"


def test_lookup_name_rejects_invalid_names(tmp_path):
    result = lookup_name(tmp_path / "missing.sqlite", "../bad")

    assert result["found"] is False
    assert result["error"] == "invalid_name"
