import json
import sqlite3
from dataclasses import replace

from hns_topology.live_db import (
    connect_live,
    init_live_db,
    record_authority_health,
)
from hns_topology.live_delegations import refresh_delegation_groups
from hns_topology.live_models import HostProbeResult
from hns_topology.live_sweep import SweepBatchConfig, run_sweep_batch, select_sweep_candidates


def test_sweep_prioritizes_ds_bootstrap_before_other_root_signals(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_topology(topology_db)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=4,
            page_size=2,
        )

    assert [item["root_name"] for item in selection["candidates"]] == [
        "a-ds-bootstrap",
        "b-bootstrap",
        "c-ds-delegated",
        "d-delegated",
    ]
    assert [item["signal_tier"] for item in selection["candidates"]] == [
        "ds_bootstrap",
        "bootstrap",
        "ds_delegated",
        "delegated",
    ]


def test_sweep_pages_from_the_name_cursor(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    _seed_topology(topology_db)

    with sqlite3.connect(topology_db) as conn:
        plan = conn.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT n.name
            FROM names n
            CROSS JOIN resource_summary rs ON rs.name = n.name
            WHERE n.name > ?
            ORDER BY n.name
            LIMIT ?
            """,
            ("", 10),
        ).fetchall()

    assert any("SEARCH n USING COVERING INDEX" in detail for *_, detail in plan)


def test_sweep_promotes_http_endpoint_but_keeps_offline_root_compact(tmp_path, monkeypatch):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_topology(topology_db)

    def fake_probe(candidate, *, config, include_dns_details):
        assert include_dns_details is False
        host = candidate["host"]
        return _result(
            root_name=host,
            resource_hash=candidate["topology_resource_hash"],
            category="http_only" if host == "a-ds-bootstrap" else "offline",
        )

    monkeypatch.setattr("hns_topology.live_sweep.probe_host", fake_probe)
    with connect_live(live_db) as conn:
        init_live_db(conn)
        result = run_sweep_batch(
            conn,
            topology_db=topology_db,
            config=SweepBatchConfig(
                limit=2,
                page_size=2,
                concurrency=1,
                min_delay_ms=0,
                authority_delay_ms=0,
            ),
        )
        coverage = {
            row["root_name"]: dict(row)
            for row in conn.execute("SELECT * FROM sweep_coverage ORDER BY root_name")
        }
        endpoints = [
            dict(row)
            for row in conn.execute("SELECT root_name, host, category FROM host_status ORDER BY root_name")
        ]
        authority_health_rows = conn.execute("SELECT COUNT(*) FROM authority_health").fetchone()[0]

    assert result["checked"] == 2
    assert result["online"] == 1
    assert coverage["a-ds-bootstrap"]["outcome_code"] == "http_endpoint"
    assert coverage["b-bootstrap"]["outcome_code"] == "no_address"
    assert endpoints == [
        {"root_name": "a-ds-bootstrap", "host": "a-ds-bootstrap", "category": "http_only"}
    ]
    assert authority_health_rows == 0


def test_sweep_samples_unknown_authorities_then_skips_shared_unreachable_group(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_shared_authority_topology(topology_db)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        initial = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=500,
            page_size=100,
            tiers=("ds_bootstrap",),
        )
        assert [item["root_name"] for item in initial["candidates"]] == [
            "aa-shared",
            "ab-shared",
            "ac-shared",
        ]
        assert initial["cursor_updates"] == {}

        unreachable = replace(
            _result(root_name="aa-shared", resource_hash="hash-aa-shared", category="offline"),
            dns_status="unreachable",
            failure_reason="authoritative_dns_unreachable",
        )
        for _ in range(3):
            record_authority_health(
                conn,
                authority_keys=["ip:93.184.216.34"],
                result=unreachable,
            )

        skipped = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=500,
            page_size=100,
            tiers=("ds_bootstrap",),
        )

    assert skipped["candidates"] == []
    assert skipped["completed_tiers"] == ["ds_bootstrap"]


def test_sweep_expands_a_shared_healthy_authority(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_shared_authority_topology(topology_db)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        record_authority_health(
            conn,
            authority_keys=["ip:93.184.216.34"],
            result=_result(
                root_name="aa-shared",
                resource_hash="hash-aa-shared",
                category="offline",
            ),
        )
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=500,
            page_size=100,
            tiers=("ds_bootstrap",),
        )

    assert [item["root_name"] for item in selection["candidates"]] == [
        "aa-shared",
        "ab-shared",
        "ac-shared",
        "ad-shared",
    ]


def test_sweep_excludes_known_generic_bootstrap_addresses(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_shared_authority_topology(topology_db, address="44.231.6.183")

    with connect_live(live_db) as conn:
        init_live_db(conn)
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=500,
            page_size=100,
            tiers=("ds_bootstrap",),
        )

    assert selection["candidates"] == []
    assert selection["completed_tiers"] == ["ds_bootstrap"]


def test_delegation_index_keeps_only_bounded_shared_groups(tmp_path):
    live_db = tmp_path / "live.sqlite"
    topology_site = tmp_path / "site"
    shard = topology_site / "data" / "nameservers" / "shards" / "001.jsonl"
    shard.parent.mkdir(parents=True)
    shard.write_text(
        "\n".join(
            [
                json.dumps({"n": "ns1.trapify", "c": 5, "r": ["a", "b", "c", "d", "e"]}),
                json.dumps({"n": "ns1.small", "c": 4, "r": ["a", "b", "c", "d"]}),
                json.dumps({"n": "ns1.large", "c": 251, "r": ["a"] * 251}),
            ]
        )
        + "\n"
    )

    with connect_live(live_db) as conn:
        init_live_db(conn)
        first = refresh_delegation_groups(conn, topology_site=topology_site)
        second = refresh_delegation_groups(conn, topology_site=topology_site)
        groups = [dict(row) for row in conn.execute("SELECT * FROM delegation_groups")]

    assert first["indexed"] is True
    assert second["indexed"] is False
    assert [(row["nameserver"], row["member_count"]) for row in groups] == [
        ("ns1.trapify", 5)
    ]


def test_sweep_prioritizes_members_of_a_shared_delegation_group(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_shared_authority_topology(topology_db)

    with connect_live(live_db) as conn:
        init_live_db(conn)
        conn.execute(
            """
            INSERT INTO delegation_groups(
              nameserver, member_count, member_roots_json, source_signature, indexed_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (
                "ns1.trapify",
                4,
                json.dumps(["aa-shared", "ab-shared", "ac-shared", "ad-shared"]),
                "test",
                "2026-07-12T00:00:00Z",
            ),
        )
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=10,
            page_size=100,
            tiers=("shared_delegation",),
        )

    assert [item["root_name"] for item in selection["candidates"]] == [
        "aa-shared",
        "ab-shared",
        "ac-shared",
        "ad-shared",
    ]
    assert {tuple(item["authority_keys"]) for item in selection["candidates"]} == {
        ("ns:ns1.trapify",)
    }
    assert {tuple(item["ns_names"]) for item in selection["candidates"]} == {
        ("ns1.trapify",)
    }


def _seed_topology(path):
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE names (
              name TEXT PRIMARY KEY,
              expired INTEGER DEFAULT 0,
              provider_guess TEXT,
              last_seen_height INTEGER,
              updated_at TEXT,
              resource_hash TEXT
            );
            CREATE TABLE resource_summary (
              name TEXT PRIMARY KEY,
              ns_names TEXT,
              glue4 TEXT,
              glue6 TEXT,
              synth4 TEXT,
              synth6 TEXT,
              ds_records TEXT,
              has_ds INTEGER,
              has_ns INTEGER,
              has_glue INTEGER,
              has_synth INTEGER,
              resource_hash TEXT
            );
            CREATE TABLE provider_summary (provider_key TEXT PRIMARY KEY, provider_type TEXT);
            """
        )
        for name, has_ds, has_ns, has_synth in (
            ("a-ds-bootstrap", 1, 1, 1),
            ("b-bootstrap", 0, 1, 1),
            ("c-ds-delegated", 1, 1, 0),
            ("d-delegated", 0, 1, 0),
        ):
            conn.execute(
                "INSERT INTO names(name, provider_guess, last_seen_height, resource_hash) VALUES(?, ?, ?, ?)",
                (name, "self-hosted", 100, f"hash-{name}"),
            )
            conn.execute(
                """
                INSERT INTO resource_summary(
                  name, ns_names, glue4, glue6, synth4, synth6, ds_records,
                  has_ds, has_ns, has_glue, has_synth, resource_hash
                ) VALUES(?, ?, '[]', '[]', ?, '[]', ?, ?, ?, 0, ?, ?)
                """,
                (
                    name,
                    json.dumps([f"ns1.{name}"]),
                    json.dumps(["93.184.216.34"] if has_synth else []),
                    json.dumps([{"keyTag": 1}] if has_ds else []),
                    has_ds,
                    has_ns,
                    has_synth,
                    f"hash-{name}",
                ),
            )


def _seed_shared_authority_topology(path, *, address="93.184.216.34"):
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE names (
              name TEXT PRIMARY KEY,
              expired INTEGER DEFAULT 0,
              provider_guess TEXT,
              last_seen_height INTEGER,
              updated_at TEXT,
              resource_hash TEXT
            );
            CREATE TABLE resource_summary (
              name TEXT PRIMARY KEY,
              ns_names TEXT,
              glue4 TEXT,
              glue6 TEXT,
              synth4 TEXT,
              synth6 TEXT,
              ds_records TEXT,
              has_ds INTEGER,
              has_ns INTEGER,
              has_glue INTEGER,
              has_synth INTEGER,
              resource_hash TEXT
            );
            CREATE TABLE provider_summary (provider_key TEXT PRIMARY KEY, provider_type TEXT);
            """
        )
        for name in ("aa-shared", "ab-shared", "ac-shared", "ad-shared"):
            conn.execute(
                "INSERT INTO names(name, provider_guess, last_seen_height, resource_hash) VALUES(?, ?, ?, ?)",
                (name, "self-hosted", 100, f"hash-{name}"),
            )
            conn.execute(
                """
                INSERT INTO resource_summary(
                  name, ns_names, glue4, glue6, synth4, synth6, ds_records,
                  has_ds, has_ns, has_glue, has_synth, resource_hash
                ) VALUES(?, ?, '[]', '[]', ?, '[]', ?, 1, 1, 0, 1, ?)
                """,
                (
                    name,
                    json.dumps([f"ns1.{name}"]),
                    json.dumps([address]),
                    json.dumps([{"keyTag": 1}]),
                    f"hash-{name}",
                ),
            )


def _result(*, root_name, resource_hash, category):
    online = category == "http_only"
    return HostProbeResult(
        root_name=root_name,
        host=root_name,
        topology_resource_hash=resource_hash,
        category=category,
        canonical_url=f"http://{root_name}/" if online else "",
        dns_status="resolved" if online else "no_address",
        addresses=["93.184.216.34"] if online else [],
        dnssec_status="not_checked",
        tlsa_status="not_checked",
        tlsa_records=[],
        dane_status="missing",
        http_status="response" if online else "failed",
        http_status_code=200 if online else None,
        http_location="",
        https_status="failed",
        https_status_code=None,
        https_location="",
        webpki_status="not_checked",
        certificate_sha256="",
        spki_sha256="",
        certificate_not_valid_after="",
        failure_reason="" if online else "no_public_a_or_aaaa",
        discovered_hosts=[],
        checked_at="2026-07-11T00:00:00Z",
        duration_ms=10,
    )
