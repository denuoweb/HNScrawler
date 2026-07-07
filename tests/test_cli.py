import argparse
import json
from pathlib import Path

from hns_topology import cli
from hns_topology.db import (
    RESOURCE_IP_INDEX_META_KEY,
    RESOURCE_IP_INDEX_VERSION,
    connect,
    get_meta,
    init_db,
    set_meta,
)
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.models import LiveStatus
from hns_topology.provider_rules import ProviderRules
from hns_topology.site_generator import generate_site
from hns_topology.validator import release_is_valid, validate_release

FIXTURE = Path("tests/fixtures/sample_hsd_names.json")


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


def live_check_args(db_path, **overrides):
    values = {
        "db": str(db_path),
        "rules": "configs/provider_rules.json",
        "limit": 2,
        "concurrency": 1,
        "min_delay_ms": 1,
        "timeout": 0.1,
        "resolver": "192.0.2.53",
        "priority_name": [],
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def import_dns_evidence_args(db_path, evidence_path, **overrides):
    values = {
        "db": str(db_path),
        "file": str(evidence_path),
        "source": "crowd",
        "source_id": "worker-1",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def import_browser_evidence_args(db_path, evidence_path, **overrides):
    values = {
        "db": str(db_path),
        "file": str(evidence_path),
        "source": "hns-browser",
        "source_id": "pixel9",
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


def test_live_check_records_rate_limit_metadata(tmp_path, monkeypatch):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    def fake_check_name(row, config, limiter):
        limiter.wait()
        return LiveStatus(
            name=row["name"],
            dns_reachable="reachable",
            dnssec_status="not_delegated",
            tlsa_status="missing",
            dane_status="unknown",
            https_status="working",
            strict_hns_status="working",
            doh_fallback_status="not_required",
            failure_reason=None,
            checked_at="2026-01-01T00:00:00Z",
            next_check_at="2026-01-08T00:00:00Z",
        )

    monkeypatch.setattr("hns_topology.livecheck.check_name", fake_check_name)
    monkeypatch.setattr("hns_topology.livecheck.collect_dns_evidence", lambda *args, **kwargs: [])

    result = cli.cmd_live_check(live_check_args(db_path))

    with connect(db_path) as conn:
        assert result == 0
        assert get_meta(conn, "live_check_limit") == "2"
        assert get_meta(conn, "live_check_concurrency") == "1"
        assert get_meta(conn, "live_check_min_delay_ms") == "1"
        assert get_meta(conn, "live_check_timeout_seconds") == "0.1"
        assert get_meta(conn, "live_check_recheck_seconds") == str(7 * 24 * 60 * 60)
        assert get_meta(conn, "live_check_resolver") == "192.0.2.53"
        assert int(get_meta(conn, "live_check_candidate_count")) >= 2
        assert get_meta(conn, "live_check_checked_count") == "2"
        generate_site(conn, db_path=db_path, out_dir=public_dir)

    checks = validate_release(db_path=db_path, public_dir=public_dir, require_live_checks=True)
    assert release_is_valid(checks), [check for check in checks if not check.ok]


def test_import_dns_evidence_exports_static_observations(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "name": "secure",
                "observations": [
                    {
                        "qname": "secure.",
                        "rrtype": "DNSKEY",
                        "server": "198.51.100.3",
                        "status": "ok",
                        "rcode": "NOERROR",
                        "flags": "QR AA",
                        "answer": ["secure. 300 IN DNSKEY 257 3 13 abc"],
                        "captured_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    result = cli.cmd_import_dns_evidence(import_dns_evidence_args(db_path, evidence_path))

    with connect(db_path) as conn:
        assert result == 0
        generate_site(conn, db_path=db_path, out_dir=public_dir)

    names_rows = json.loads(
        (public_dir / "data/names-pages/all/page-1.json").read_text(encoding="utf-8")
    )["rows"]
    secure = next(row for row in names_rows if row["name"] == "secure")
    evidence = json.loads(
        (public_dir / "data" / secure["dns_evidence_path"]).read_text(encoding="utf-8")
    )

    assert secure["dns_evidence_path"] == "dns-evidence/secure.json"
    assert evidence["observations"][0]["source"] == "crowd"
    assert evidence["observations"][0]["source_id"] == "worker-1"
    assert evidence["observations"][0]["answer"] == ["secure. 300 IN DNSKEY 257 3 13 abc"]


def test_import_browser_evidence_exports_static_observations(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    public_dir = tmp_path / "public"
    evidence_path = tmp_path / "browser-trace.json"
    evidence_path.write_text(
        json.dumps(
            {
                "host": "secure",
                "root": "secure",
                "mode": "hns_compatibility",
                "hnsProof": "verified",
                "resolutionSource": "authoritative_doh",
                "authoritativeDns": {"udp53": "blocked", "tcp53": "blocked", "doh": "ok"},
                "fallback": {"used": True, "reason": "network_blocks_53"},
                "dnssec": "secure",
                "originAddress": "198.51.100.3",
                "tls": {
                    "tlsaOwner": "_443._tcp.secure",
                    "tlsaStatus": "present",
                    "tlsaSource": "native_tlsa",
                    "certificate": {
                        "endEntitySha256": "aa" * 32,
                        "spkiSha256": "bb" * 32,
                        "notValidAfter": "2026-08-01T00:00:00Z",
                    },
                    "dane": {"decision": "verified"},
                },
                "captured_at": "2026-07-06T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    result = cli.cmd_import_browser_evidence(import_browser_evidence_args(db_path, evidence_path))

    with connect(db_path) as conn:
        assert result == 0
        generate_site(conn, db_path=db_path, out_dir=public_dir)

    names_rows = json.loads(
        (public_dir / "data/names-pages/all/page-1.json").read_text(encoding="utf-8")
    )["rows"]
    summary = json.loads((public_dir / "data/summary.json").read_text(encoding="utf-8"))
    secure = next(row for row in names_rows if row["name"] == "secure")
    evidence = json.loads(
        (public_dir / "data" / secure["browser_evidence_path"]).read_text(encoding="utf-8")
    )

    assert secure["browser_evidence_path"] == "browser-evidence/secure.json"
    observation = evidence["observations"][0]
    assert observation["browser_result"] == "dane_verified"
    assert observation["fallback_used"] is True
    assert observation["fallback_reason"] == "network_blocks_53"
    assert observation["authoritative_udp"] == "blocked"
    assert observation["authoritative_doh"] == "ok"
    assert observation["spki_sha256"] == "bb" * 32
    assert observation["certificate_not_valid_after"] == "2026-08-01T00:00:00Z"
    assert observation["certificate_expired"] is False
    assert secure["browser_result"] == "dane_verified"
    assert secure["browser_fallback_used"] is True
    assert secure["browser_fallback_reason"] == "network_blocks_53"
    assert secure["browser_authoritative_udp"] == "blocked"
    assert secure["browser_authoritative_doh"] == "ok"
    assert secure["browser_certificate_expired"] is False
    assert secure["browser_evidence_effect"] == "positive_browser_dane"
    assert secure["browser_evidence_severity"] == "review"
    assert secure["browser_action"] == "compare_browser_dane"
    assert secure["compliance_stage"] != "resolver_fallback"
    assert summary["browser_evidence_names"] == 1
    assert summary["browser_dane_verified_names"] == 1
    assert summary["browser_network_blocks_53_names"] == 1
    assert summary["browser_certificate_expired_names"] == 0
    names_pages = json.loads((public_dir / "data/names-pages.json").read_text(encoding="utf-8"))
    assert names_pages["collections"]["browser_evidence_names"]["row_count"] == 1
    assert names_pages["collections"]["browser_dane_verified_names"]["row_count"] == 1
    assert names_pages["collections"]["browser_network_blocks_53_names"]["row_count"] == 1
    assert "browser_certificate_expired_names" not in names_pages["collections"]


def test_import_browser_evidence_accepts_directory(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    evidence_dir = tmp_path / "browser-evidence"
    evidence_dir.mkdir()
    (evidence_dir / "resolver-trace.json").write_text(
        json.dumps(
            {
                "host": "secure",
                "root": "secure",
                "mode": "hns_compatibility",
                "hnsProof": "verified",
                "resolutionSource": "authoritative_doh",
                "authoritativeDns": {"udp53": "blocked", "tcp53": "blocked", "doh": "ok"},
                "fallback": {"used": True, "reason": "network_blocks_53"},
                "dnssec": "secure",
                "originAddress": "198.51.100.3",
                "tls": {
                    "tlsaOwner": "_443._tcp.secure",
                    "tlsaStatus": "present",
                    "tlsaSource": "native_tlsa",
                    "certificate": {"spkiSha256": "bb" * 32},
                    "dane": {"decision": "verified"},
                },
                "captured_at": "2026-07-06T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "gateway-events.log").write_text(
        "1783324451000\twebview_native_response\tdirect\t200\tOK\n",
        encoding="utf-8",
    )
    (evidence_dir / "diagnostic-bundle.md").write_text(
        """
# HNS DANE Browser Diagnostic Bundle

## Recent Gateway Events
```
1783324452000 webview_native_response secure 502 delegated_dnssec_validation_failed
1783324453000 webview_native_response denuoweb 502 delegated_dnssec_validation_failed
```
""",
        encoding="utf-8",
    )
    (evidence_dir / "ignored.bin").write_text("not browser evidence", encoding="utf-8")
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    result = cli.cmd_import_browser_evidence(import_browser_evidence_args(db_path, evidence_dir))

    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT name, evidence_type, browser_result
            FROM browser_evidence
            ORDER BY name, evidence_type, browser_result
            """
        ).fetchall()

    assert result == 0
    assert [(row["name"], row["evidence_type"], row["browser_result"]) for row in rows] == [
        ("direct", "gateway_event", "loaded"),
        ("secure", "gateway_event", "dnssec_bogus"),
        ("secure", "resolver_trace", "dane_verified"),
    ]


def test_rebuild_resource_ip_command_restores_derived_index(tmp_path):
    db_path = tmp_path / "topology.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(db_path) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        conn.execute("DELETE FROM resource_ip")
        conn.execute("DELETE FROM snapshot_meta WHERE key = ?", (RESOURCE_IP_INDEX_META_KEY,))
        conn.commit()

    result = cli.cmd_rebuild_resource_ip(argparse.Namespace(db=str(db_path)))

    with connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM resource_ip").fetchone()[0]
        version = get_meta(conn, RESOURCE_IP_INDEX_META_KEY)
        indexes = {row["name"] for row in conn.execute("PRAGMA index_list(resource_ip)")}

    assert result == 0
    assert count == 5
    assert version == RESOURCE_IP_INDEX_VERSION
    assert "idx_resource_ip_ip_name" in indexes
