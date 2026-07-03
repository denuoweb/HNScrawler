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
    assert result["row"]["synth4"] == ["203.0.113.10"]
    assert result["snapshot"]["last_indexed_height"] == "123456"


def test_lookup_name_rejects_invalid_names(tmp_path):
    result = lookup_name(tmp_path / "missing.sqlite", "../bad")

    assert result["found"] is False
    assert result["error"] == "invalid_name"
