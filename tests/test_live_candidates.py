import json

from hns_topology.db import connect, insert_dns_evidence
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.live_candidates import (
    _distinct_resource_ips,
    _is_actionable_bootstrap_ip,
    _is_public_ip,
    _topology_root_rows,
    dns_hosts_from_evidence,
    sync_topology,
    sync_topology_if_changed,
)
from hns_topology.live_db import connect_live, init_live_db, select_due_candidates
from hns_topology.models import DnsEvidence
from hns_topology.provider_rules import ProviderRules

FIXTURE = "tests/fixtures/sample_hsd_names.json"


def test_bootstrap_ip_filter_requires_global_unicast():
    assert _is_public_ip("93.184.216.34") is True
    assert _is_public_ip("224.0.0.1") is False
    assert _is_public_ip("ff02::1") is False
    assert _is_public_ip("127.0.0.1") is False
    assert _is_actionable_bootstrap_ip("93.184.216.34") is True
    assert _is_actionable_bootstrap_ip("44.231.6.183") is False


def test_distinct_resource_ips_uses_indexed_key_seeks():
    with connect(":memory:") as conn:
        conn.execute("CREATE TABLE resource_ip (name TEXT NOT NULL, ip TEXT NOT NULL)")
        conn.execute("CREATE INDEX idx_resource_ip_ip_name ON resource_ip(ip, name)")
        conn.executemany(
            "INSERT INTO resource_ip(name, ip) VALUES(?, ?)",
            [
                ("alpha", "192.0.2.1"),
                ("beta", "192.0.2.1"),
                ("gamma", "198.51.100.2"),
            ],
        )
        statements = []
        conn.set_trace_callback(statements.append)

        addresses = list(_distinct_resource_ips(conn))

    assert addresses == ["192.0.2.1", "198.51.100.2"]
    assert not any("SELECT DISTINCT" in statement for statement in statements)
    assert any("WHERE ip >" in statement for statement in statements)


def test_root_detail_query_starts_from_materialized_candidate_names():
    captured = []
    connection = type(
        "CaptureConnection",
        (),
        {"execute": lambda self, sql, params: captured.append((sql, params))},
    )()

    _topology_root_rows(connection)

    sql, _params = captured[0]
    assert "FROM live_candidate_names candidate" in sql
    assert "CROSS JOIN names n ON n.name = candidate.name" in sql
    assert "names n INDEXED BY idx_names_class" not in sql


def test_sync_adds_apex_and_evidence_subdomains_without_guessing_www(tmp_path, monkeypatch):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(topology_db) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        with conn:
            insert_dns_evidence(
                conn,
                DnsEvidence(
                    name="direct",
                    qname="_443._tcp.blog.direct.",
                    rrtype="TLSA",
                    server="203.0.113.10",
                    source="scanner",
                    source_id="candidate-test",
                    status="ok",
                    rcode="NOERROR",
                    flags="QR AA",
                    answer=["_443._tcp.blog.direct. 300 IN TLSA 3 1 1 " + "ab" * 32],
                    authority=[],
                    additional=[],
                    elapsed_ms=1,
                    error=None,
                    captured_at="2026-07-11T00:00:00Z",
                ),
            )

    monkeypatch.setattr("hns_topology.live_candidates._is_public_ip", lambda value: bool(value))
    with connect_live(live_db) as conn:
        init_live_db(conn)
        result = sync_topology(conn, topology_db)
        unchanged = sync_topology_if_changed(conn, topology_db)
        candidates = {
            (row["root_name"], row["host"]): row for row in conn.execute("SELECT * FROM candidates")
        }

    assert result["roots"] == 3
    assert unchanged["skipped"] is True
    assert ("direct", "direct") in candidates
    assert ("direct", "blog.direct") in candidates
    assert not any(host.startswith("www.") for _, host in candidates)
    assert "tlsa_owner" in candidates[("direct", "blog.direct")]["sources_json"]


def test_sync_excludes_ds_root_without_actionable_bootstrap_or_tlsa(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(topology_db) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        result = sync_topology(conn, topology_db)
        roots = [dict(row) for row in conn.execute("SELECT name, strict_ready FROM roots")]

    assert result["roots"] == 0
    assert result["candidates"] == 0
    assert roots == []


def test_sync_retains_known_external_dns_delegations_without_glue(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(topology_db) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)
        with conn:
            conn.execute("UPDATE names SET provider_guess = 'cloudflare' WHERE name = 'noglue'")
            conn.execute(
                """
                INSERT INTO provider_summary(provider_key, provider_type)
                VALUES('cloudflare', 'external_dns')
                ON CONFLICT(provider_key) DO UPDATE SET provider_type = excluded.provider_type
                """
            )

    with connect_live(live_db) as conn:
        init_live_db(conn)
        sync_topology(conn, topology_db)
        row = conn.execute(
            "SELECT provider_type, strict_ready FROM roots WHERE name = 'noglue'"
        ).fetchone()

    assert dict(row) == {"provider_type": "external_dns", "strict_ready": 0}


def test_sync_carries_hns_handoff_to_live_probe_candidates(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
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
                        "name": "agent",
                        "nameHash": "hash-agent",
                        "state": "CLOSED",
                        "renewal": 337000,
                        "resource": {
                            "records": [
                                {
                                    "type": "DS",
                                    "keyTag": 1,
                                    "algorithm": 13,
                                    "digestType": 2,
                                    "digest": "aa" * 32,
                                },
                                {"type": "NS", "ns": "ns1.handoff."},
                            ]
                        },
                    },
                    {
                        "name": "handoff",
                        "nameHash": "hash-handoff",
                        "state": "CLOSED",
                        "renewal": 337000,
                        "resource": {
                            "records": [
                                {"type": "GLUE4", "ns": "ns1.handoff.", "address": "8.8.8.8"}
                            ]
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(topology_db) as conn:
        bootstrap_from_fixture(conn, fixture_path=fixture_path, rules=rules)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        sync_topology(conn, topology_db)
        root = conn.execute(
            "SELECT strict_ready, ns_handoffs_json FROM roots WHERE name = 'agent'"
        ).fetchone()
        candidate = next(
            item for item in select_due_candidates(conn, limit=10) if item["root_name"] == "agent"
        )
        sources = conn.execute(
            "SELECT sources_json FROM candidates WHERE root_name = 'agent' AND host = 'agent'"
        ).fetchone()["sources_json"]

    assert root["strict_ready"] == 0
    assert json.loads(root["ns_handoffs_json"]) == [
        {
            "bootstrap_addresses": ["8.8.8.8"],
            "bootstrap_field": "GLUE4",
            "nameserver": "ns1.handoff",
            "root_name": "handoff",
        }
    ]
    assert candidate["ns_handoffs"] == json.loads(root["ns_handoffs_json"])
    assert "indirect_ns_handoff" in json.loads(sources)


def test_dns_evidence_parser_accepts_named_subdomains_and_rejects_other_roots():
    item = {
        "qname": "api.example.",
        "rrtype": "A",
        "answer": [
            "api.example. 300 IN A 192.0.2.8",
            "outside.other. 300 IN A 192.0.2.9",
            "_443._tcp.shop.example. 300 IN TLSA 3 1 1 " + "aa" * 32,
        ],
        "authority": [],
        "additional": [],
    }

    assert dns_hosts_from_evidence("example", item) == ["api.example", "shop.example"]
    assert (
        dns_hosts_from_evidence(
            "example",
            {"qname": "www.example.", "rrtype": "A", "answer": []},
        )
        == []
    )
