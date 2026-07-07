import json
from pathlib import Path

from hns_topology.db import connect, insert_browser_evidence_batch, upsert_live_status
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.lookup_api import lookup_name, normalize_name
from hns_topology.models import BrowserEvidence, LiveStatus
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
        upsert_live_status(
            conn,
            LiveStatus(
                name="direct",
                dns_reachable="working",
                dnssec_status="unknown",
                tlsa_status="unknown",
                dane_status="unknown",
                https_status="tls_unverified",
                strict_hns_status="working",
                doh_fallback_status="not_required",
                failure_reason=None,
                checked_at="2026-07-06T00:00:00Z",
                next_check_at="2026-07-13T00:00:00Z",
                https_cert_sha256="aa" * 32,
                https_spki_sha256="bb" * 32,
                https_cert_not_valid_after="2026-08-01T00:00:00Z",
            ),
        )
        insert_browser_evidence_batch(
            conn,
            [
                BrowserEvidence(
                    name="direct",
                    host="direct",
                    url="https://direct/",
                    source="hns-browser",
                    source_id="pixel9",
                    evidence_type="resolver_trace",
                    browser_result="loaded",
                    status_code=None,
                    stage=None,
                    reason=None,
                    mode="hns_compatibility",
                    hns_proof="verified",
                    resolution_source="hns_resource",
                    authoritative_udp="ok",
                    authoritative_tcp=None,
                    authoritative_doh=None,
                    fallback_used=False,
                    fallback_reason=None,
                    dnssec_status="unknown",
                    tlsa_owner=None,
                    tlsa_status=None,
                    tlsa_source=None,
                    dane_status=None,
                    certificate_sha256="aa" * 32,
                    spki_sha256="bb" * 32,
                    certificate_not_valid_after="2026-08-01T00:00:00Z",
                    certificate_expired=False,
                    final_error=None,
                    raw_json={"host": "direct"},
                    captured_at="2026-07-06T00:00:00Z",
                )
            ],
        )

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
    assert result["row"]["browser_evidence_path"] == "browser-evidence/direct.json"
    assert result["row"]["https_cert_sha256"] == "aa" * 32
    assert result["row"]["https_spki_sha256"] == "bb" * 32
    assert result["row"]["https_cert_not_valid_after"] == "2026-08-01T00:00:00Z"
    assert result["row"]["browser_result"] == "loaded"
    assert result["row"]["browser_fallback_used"] is False
    assert result["row"]["browser_certificate_not_valid_after"] == "2026-08-01T00:00:00Z"
    assert result["row"]["browser_certificate_expired"] is False
    assert result["row"]["browser_evidence_effect"] == "context_observed"
    assert result["row"]["browser_evidence_severity"] == "context"
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
    assert result["row"]["compliance_stage"] == "missing_glue"
    assert result["row"]["ns_handoff_ns"] == "ns1.skyinclude"
    assert result["row"]["ns_handoff_root"] == "skyinclude"
    assert result["row"]["ns_handoff_bootstrap_ip"] == "192.155.93.228"
    assert result["row"]["ns_handoff_bootstrap_field"] == "GLUE4"


def test_lookup_name_rejects_invalid_names(tmp_path):
    result = lookup_name(tmp_path / "missing.sqlite", "../bad")

    assert result["found"] is False
    assert result["error"] == "invalid_name"
