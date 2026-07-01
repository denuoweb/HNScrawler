import json
from pathlib import Path

from hns_topology.db import connect
from hns_topology.exporter import build_faq_answers, build_summary
from hns_topology.indexer import (
    bootstrap_from_fixture,
    find_reorg_mismatch,
    index_changed_names,
    rollback_reorg,
)
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


class FakeHsdClient:
    def __init__(self, *, block_hashes: dict[int, str], resources: dict[str, dict]):
        self.block_hashes = block_hashes
        self.resources = resources

    def call(self, method: str, params: list):
        if method == "getnameinfo":
            name = params[0]
            return {
                "name": name,
                "nameHash": f"hash-{name}",
                "state": "CLOSED",
                "renewal": 123000,
            }
        raise AssertionError(f"unexpected method {method}")

    def get_name_resource(self, name: str):
        return self.resources[name]

    def get_block_hash(self, height: int) -> str:
        return self.block_hashes[height]


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
    assert summary["source_type"] == "fixture"
    assert summary["source_file_hash"]
    assert summary["provider_rules_version"] == 1
    assert summary["provider_rules_hash"]
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


def test_reorg_rollback_restores_previous_compact_rows(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    update_height = 123457
    client = FakeHsdClient(
        block_hashes={update_height: "old-hash"},
        resources={
            "direct": {
                "records": [
                    {"type": "NS", "ns": "ns1.external.example."},
                ]
            }
        },
    )
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        index_changed_names(
            conn,
            client=client,
            rules=rules,
            changed_names=["direct"],
            height=update_height,
            block_hash="old-hash",
        )
        changed = conn.execute("SELECT onchain_class FROM names WHERE name = 'direct'").fetchone()
        changed_resource = conn.execute(
            "SELECT ns_names, synth4 FROM resource_summary WHERE name = 'direct'"
        ).fetchone()

        assert changed["onchain_class"] == "DELEGATED_NO_GLUE"
        assert json.loads(changed_resource["ns_names"]) == ["ns1.external.example"]
        assert json.loads(changed_resource["synth4"]) == []

        reorg_client = FakeHsdClient(block_hashes={update_height: "new-hash"}, resources={})
        mismatch = find_reorg_mismatch(conn, client=reorg_client)
        assert mismatch == {
            "height": update_height,
            "stored_hash": "old-hash",
            "current_hash": "new-hash",
        }

        rollback = rollback_reorg(conn, rules=rules, rollback_height=update_height)
        restored = conn.execute("SELECT onchain_class FROM names WHERE name = 'direct'").fetchone()
        restored_resource = conn.execute(
            "SELECT ns_names, synth4 FROM resource_summary WHERE name = 'direct'"
        ).fetchone()
        remaining_history = conn.execute("SELECT COUNT(*) FROM block_history").fetchone()[0]

    assert rollback["names_restored"] == 1
    assert restored["onchain_class"] == "DIRECT_SYNTH"
    assert json.loads(restored_resource["ns_names"]) == []
    assert json.loads(restored_resource["synth4"]) == ["203.0.113.10"]
    assert remaining_history == 0
