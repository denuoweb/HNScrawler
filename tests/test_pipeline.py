from pathlib import Path

from hns_topology.db import connect
from hns_topology.exporter import build_faq_answers, build_summary
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


def test_fixture_bootstrap_builds_expected_counts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        count = bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        summary = build_summary(conn)
        answers = build_faq_answers(conn, summary)

    assert count == 9
    assert summary["total_names"] == 9
    assert summary["active_names"] == 8
    assert summary["direct_ip_records"] == 1
    assert summary["delegated_names"] == 4
    assert summary["delegated_with_glue"] == 2
    assert summary["delegated_no_glue"] == 2
    assert summary["default_provider_names"] == 1
    assert summary["ds_records"] == 1
    assert any(item["key"] == "direct_ip_records" for item in answers)


def test_generate_site_writes_requested_artifacts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    for relative in [
        "index.html",
        "faq.html",
        "providers.html",
        "classes.html",
        "names.html",
        "broken.html",
        "dane.html",
        "data/summary.json",
        "data/providers.json",
        "data/classes.json",
        "data/topology.sqlite.gz",
    ]:
        assert (out / relative).exists()

