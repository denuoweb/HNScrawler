from hns_topology.db import connect, insert_dns_evidence
from hns_topology.indexer import bootstrap_from_fixture
from hns_topology.live_candidates import (
    _is_public_ip,
    dns_hosts_from_evidence,
    sync_topology,
    sync_topology_if_changed,
)
from hns_topology.live_db import connect_live, init_live_db
from hns_topology.models import DnsEvidence
from hns_topology.provider_rules import ProviderRules

FIXTURE = "tests/fixtures/sample_hsd_names.json"


def test_bootstrap_ip_filter_requires_global_unicast():
    assert _is_public_ip("93.184.216.34") is True
    assert _is_public_ip("224.0.0.1") is False
    assert _is_public_ip("ff02::1") is False
    assert _is_public_ip("127.0.0.1") is False


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


def test_sync_excludes_untrusted_bootstrap_but_retains_ds_delegation(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    rules = ProviderRules.from_file("configs/provider_rules.json")
    with connect(topology_db) as conn:
        bootstrap_from_fixture(conn, fixture_path=FIXTURE, rules=rules)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        result = sync_topology(conn, topology_db)
        roots = [dict(row) for row in conn.execute("SELECT name, strict_ready FROM roots")]

    assert result["roots"] == 1
    assert result["candidates"] == 1
    assert roots == [{"name": "secure", "strict_ready": 0}]


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
