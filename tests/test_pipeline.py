import json
from pathlib import Path

from hns_topology.db import connect
from hns_topology.exporter import build_faq_answers, build_summary
from hns_topology.indexer import (
    UnpaginatedGetNamesError,
    bootstrap_from_fixture,
    bootstrap_from_hsd,
    bootstrap_from_jsonl,
    extract_changed_name_refs_from_block,
    find_reorg_mismatch,
    index_changed_names,
    rollback_reorg,
)
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site
from hns_topology.validator import release_is_valid, validate_release

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")
JSONL_FIXTURE = Path("tests/fixtures/sample_hsd_names.jsonl")


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

    def get_name_by_hash(self, name_hash: str):
        return None

    def get_block_hash(self, height: int) -> str:
        return self.block_hashes[height]


class FakeBootstrapHsdClient:
    url = "http://127.0.0.1:12037"

    def __init__(self):
        self.get_names_calls = 0

    def get_blockchain_info(self):
        return {
            "blocks": 123456,
            "bestblockhash": "hash-tip",
            "chain": "main",
            "version": "fake-hsd",
        }

    def get_names(self):
        self.get_names_calls += 1
        return [
            {
                "name": "direct",
                "nameHash": "hash-direct",
                "state": "CLOSED",
                "renewal": 123000,
            }
        ]

    def get_name_resource(self, name: str):
        return {"records": [{"type": "SYNTH4", "address": "203.0.113.10"}]}


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

    checks = validate_release(db_path=db_path, public_dir=out)
    assert release_is_valid(checks), [check for check in checks if not check.ok]


def test_release_validator_catches_missing_artifacts(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    (out / "data/summary.json").unlink()
    checks = validate_release(db_path=db_path, public_dir=out)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "required_public_files" in failed


def test_release_validator_enforces_live_check_gate(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    out = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        generate_site(conn, db_path=db_path, out_dir=out)

    checks = validate_release(db_path=db_path, public_dir=out, require_live_checks=True)

    assert not release_is_valid(checks)
    failed = {check.name: check.detail for check in checks if not check.ok}
    assert "live_status_present" in failed
    assert "live_check_timestamps" in failed


def test_jsonl_bootstrap_streams_names_and_records_provenance(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        count = bootstrap_from_jsonl(conn, jsonl_path=JSONL_FIXTURE, rules=rules)
        summary = build_summary(conn)

    assert count == 2
    assert summary["active_names"] == 2
    assert summary["direct_ip_records"] == 1
    assert summary["delegated_no_glue"] == 1
    assert summary["source_type"] == "jsonl"
    assert summary["source_file_hash"]
    assert summary["hsd_version"] == "fixture-jsonl"


def test_hsd_bootstrap_requires_limit_or_explicit_unpaginated_opt_in(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    client = FakeBootstrapHsdClient()

    with connect(db_path) as conn:
        try:
            bootstrap_from_hsd(conn, client=client, rules=rules)
        except UnpaginatedGetNamesError:
            pass
        else:
            raise AssertionError("expected unpaginated getnames guard")

    assert client.get_names_calls == 0


def test_hsd_bootstrap_smoke_limit_records_provenance(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    client = FakeBootstrapHsdClient()

    with connect(db_path) as conn:
        count = bootstrap_from_hsd(conn, client=client, rules=rules, limit=1)
        summary = build_summary(conn)

    assert count == 1
    assert client.get_names_calls == 1
    assert summary["source_type"] == "hsd_rpc"
    assert summary["source_rpc_url"] == "http://127.0.0.1:12037"


def test_extract_changed_name_refs_decodes_raw_names_and_resolves_hashes():
    update_hash = "11" * 32
    open_hash = "22" * 32
    block = {
        "tx": [
            {
                "vout": [
                    {
                        "covenant": {
                            "action": "OPEN",
                            "items": [open_hash, "00000000", "646972656374"],
                        }
                    },
                    {
                        "covenant": {
                            "action": "UPDATE",
                            "items": [update_hash, "01000000", "00"],
                        }
                    },
                ]
            }
        ]
    }

    extraction = extract_changed_name_refs_from_block(
        block,
        name_by_hash=lambda name_hash: "resolved" if name_hash == update_hash else None,
    )

    assert extraction.names == ["direct", "resolved"]
    assert extraction.name_hashes == [update_hash, open_hash]
    assert extraction.unresolved_name_hashes == []
    assert extraction.name_covenant_count == 2
    assert extraction.non_dict_tx_count == 0


def test_extract_changed_name_refs_reports_unresolved_hashes():
    update_hash = "11" * 32
    block = {
        "tx": [
            {
                "vout": [
                    {
                        "covenant": {
                            "action": "UPDATE",
                            "items": [update_hash, "01000000", "00"],
                        }
                    }
                ]
            }
        ]
    }

    extraction = extract_changed_name_refs_from_block(block, name_by_hash=lambda _: None)

    assert extraction.names == []
    assert extraction.name_hashes == [update_hash]
    assert extraction.unresolved_name_hashes == [update_hash]
    assert extraction.name_covenant_count == 1
    assert extraction.non_dict_tx_count == 0


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
