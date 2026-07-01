import argparse

from hns_topology import cli
from hns_topology.db import connect


class FakeScanClient:
    url = "http://127.0.0.1:12037"

    def __init__(self, block):
        self.block = block

    def get_block_by_height(self, height: int):
        return self.block

    def get_block_hash(self, height: int):
        return "fallback-hash"

    def get_name_by_hash(self, name_hash: str):
        return None


def incremental_args(db_path, **overrides):
    values = {
        "db": str(db_path),
        "rules": "configs/provider_rules.json",
        "hsd_rpc_url": None,
        "hsd_api_key": None,
        "height": None,
        "block_hash": None,
        "changed_names_file": None,
        "scan_block_height": 123,
        "reorg_keep_blocks": 300,
        "rollback_on_reorg": False,
        "allow_empty_block_scan": False,
        "allow_unresolved_name_hashes": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_incremental_scan_refuses_empty_block_without_explicit_allow(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_EMPTY_BLOCK_SCAN", raising=False)
    monkeypatch.setattr(cli, "_client", lambda _: FakeScanClient({"hash": "empty-hash", "tx": []}))

    result = cli.cmd_incremental(incremental_args(tmp_path / "topology.sqlite"))

    assert result == 4


def test_incremental_scan_can_record_known_empty_block(tmp_path, monkeypatch):
    db_path = tmp_path / "topology.sqlite"
    monkeypatch.setattr(cli, "_client", lambda _: FakeScanClient({"hash": "empty-hash", "tx": []}))

    result = cli.cmd_incremental(incremental_args(db_path, allow_empty_block_scan=True))

    with connect(db_path) as conn:
        history = conn.execute("SELECT height, block_hash, changed_names FROM block_history").fetchone()

    assert result == 0
    assert dict(history) == {"height": 123, "block_hash": "empty-hash", "changed_names": "[]"}


def test_incremental_scan_refuses_unresolved_name_hashes(tmp_path, monkeypatch):
    unresolved_hash = "11" * 32
    block = {
        "hash": "name-hash-block",
        "tx": [
            {
                "vout": [
                    {
                        "covenant": {
                            "action": "UPDATE",
                            "items": [unresolved_hash, "01000000", "00"],
                        }
                    }
                ]
            }
        ],
    }
    monkeypatch.setattr(cli, "_client", lambda _: FakeScanClient(block))

    result = cli.cmd_incremental(incremental_args(tmp_path / "topology.sqlite"))

    assert result == 4
