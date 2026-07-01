import argparse
import json

from hns_topology import cli
from hns_topology.db import connect, init_db, set_meta


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
        "catch_up_max_blocks": None,
        "catch_up_to_height": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class FakeCatchUpClient:
    url = "http://127.0.0.1:12037"

    def __init__(self, blocks):
        self.blocks = blocks

    def get_blockchain_info(self):
        return {"blocks": max(self.blocks)}

    def get_block_by_height(self, height: int):
        return self.blocks[height]

    def get_block_hash(self, height: int):
        return self.blocks[height]["hash"]

    def get_name_by_hash(self, name_hash: str):
        return None

    def get_name_resource(self, name: str):
        return {"records": [{"type": "SYNTH4", "address": "203.0.113.10"}]}

    def call(self, method: str, params=None):
        if method == "getnameinfo":
            name = params[0]
            return {"name": name, "nameHash": f"hash-{name}", "state": "CLOSED"}
        raise AssertionError(f"unexpected method: {method}")


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


def test_incremental_scan_refuses_txid_only_block_response(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cli,
        "_client",
        lambda _: FakeScanClient({"hash": "txid-only", "tx": ["00" * 32]}),
    )

    result = cli.cmd_incremental(
        incremental_args(tmp_path / "topology.sqlite", allow_empty_block_scan=True)
    )

    assert result == 4


def test_incremental_catch_up_records_empty_and_changed_blocks(tmp_path, monkeypatch):
    db_path = tmp_path / "topology.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        set_meta(conn, "last_indexed_height", "123")
        conn.commit()

    blocks = {
        124: {
            "hash": "hash-124",
            "tx": [{"vout": [{"covenant": {"action": "NONE", "items": []}}]}],
        },
        125: {
            "hash": "hash-125",
            "tx": [
                {
                    "vout": [
                        {
                            "covenant": {
                                "action": "OPEN",
                                "items": ["22" * 32, "00000000", "646972656374"],
                            }
                        }
                    ]
                }
            ],
        },
    }
    monkeypatch.setattr(cli, "_client", lambda _: FakeCatchUpClient(blocks))

    result = cli.cmd_incremental(incremental_args(db_path, scan_block_height=None))

    with connect(db_path) as conn:
        history = conn.execute(
            "SELECT height, block_hash, changed_names FROM block_history ORDER BY height"
        ).fetchall()
        name = conn.execute("SELECT name, onchain_class FROM names WHERE name = 'direct'").fetchone()

    assert result == 0
    assert [(row["height"], row["block_hash"], json.loads(row["changed_names"])) for row in history] == [
        (124, "hash-124", []),
        (125, "hash-125", ["direct"]),
    ]
    assert dict(name) == {"name": "direct", "onchain_class": "DIRECT_SYNTH"}


def test_incremental_catch_up_refuses_large_ranges(tmp_path, monkeypatch):
    db_path = tmp_path / "topology.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        set_meta(conn, "last_indexed_height", "123")
        conn.commit()

    blocks = {
        124: {"hash": "hash-124", "tx": [{"vout": []}]},
        125: {"hash": "hash-125", "tx": [{"vout": []}]},
    }
    monkeypatch.setattr(cli, "_client", lambda _: FakeCatchUpClient(blocks))

    result = cli.cmd_incremental(
        incremental_args(db_path, scan_block_height=None, catch_up_max_blocks=1)
    )

    assert result == 5
