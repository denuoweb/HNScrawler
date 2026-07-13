import json
import sqlite3
from dataclasses import replace

from hns_topology.exporter import _handoff_canaries
from hns_topology.live_cli import parser
from hns_topology.live_db import (
    HNS_HANDOFF_NOT_BEFORE_META_KEY,
    connect_live,
    get_live_meta,
    init_live_db,
    record_authority_health,
)
from hns_topology.live_delegations import refresh_delegation_groups
from hns_topology.live_handoffs import refresh_hns_handoff_groups
from hns_topology.live_models import DnsProbeResult, HostProbeResult
from hns_topology.live_probe import ProbeConfig, probe_dns
from hns_topology.live_sweep import (
    PRIORITY_SWEEP_TIERS,
    HnsHandoffPreflightConfig,
    SweepBatchConfig,
    parse_sweep_tiers,
    run_hns_handoff_preflight,
    run_sweep_batch,
    select_sweep_candidates,
)


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


def test_priority_sweep_tiers_exclude_unindexed_generic_backlog():
    assert PRIORITY_SWEEP_TIERS == ("hns_handoff", "shared_delegation")
    assert parse_sweep_tiers("hns_handoff,shared_delegation,ds_bootstrap") == (
        "hns_handoff",
        "shared_delegation",
        "ds_bootstrap",
    )


def test_unbounded_handoff_canaries_are_stable_and_spread_across_the_route():
    members = [{"name": f"root-{index}", "has_ds": True} for index in range(11)]

    selected = _handoff_canaries(members)

    assert [member["name"] for member in selected] == ["root-0", "root-5", "root-10"]


def test_cycle_defers_full_topology_sync_by_default():
    base = ["cycle", "--db", "live.sqlite", "--topology-db", "topology.sqlite", "--out", "public"]
    assert parser().parse_args(base).sync_topology is False
    assert parser().parse_args([*base, "--sync-topology"]).sync_topology is True


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
            for row in conn.execute(
                "SELECT root_name, host, category FROM host_status ORDER BY root_name"
            )
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
        first = refresh_delegation_groups(conn, topology_site=topology_site, min_members=5)
        second = refresh_delegation_groups(conn, topology_site=topology_site, min_members=5)
        groups = [dict(row) for row in conn.execute("SELECT * FROM delegation_groups")]

    assert first["indexed"] is True
    assert second["indexed"] is False
    assert [(row["nameserver"], row["member_count"]) for row in groups] == [("ns1.trapify", 5)]


def test_handoff_index_keeps_only_bounded_route_cohorts(tmp_path):
    live_db = tmp_path / "live.sqlite"
    topology_site = tmp_path / "site"
    artifact = topology_site / "data" / "hns-handoff-groups.json"
    artifact.parent.mkdir(parents=True)
    members = [
        {
            "name": name,
            "provider_guess": "self-hosted",
            "provider_type": "external_dns",
            "resource_hash": f"hash-{name}",
            "last_seen_height": 100,
            "ns_names": ["ns1.skyinclude"],
            "ds_records": [{"keyTag": 1}],
            "has_ds": True,
        }
        for name in ("alpha", "beta")
    ]
    artifact.write_text(
        json.dumps(
            {
                "format": "hns-handoff-cohorts-v1",
                "groups": [
                    {
                        "nameserver": "ns1.skyinclude",
                        "root_name": "skyinclude",
                        "bootstrap_addresses": ["8.8.8.8"],
                        "bootstrap_field": "glue4",
                        "member_count": 2,
                        "members": members,
                    },
                    {
                        "nameserver": "ns1.large",
                        "root_name": "large",
                        "bootstrap_addresses": ["8.8.4.4"],
                        "bootstrap_field": "glue4",
                        "member_count": 251,
                        "members": [members[0]] * 251,
                    },
                ],
                "ds_priority_groups": [
                    {
                        "nameserver": "a.namenode",
                        "root_name": "namenode",
                        "bootstrap_addresses": ["138.199.197.111"],
                        "bootstrap_field": "glue4",
                        "member_count": 1,
                        "members": [
                            {
                                **members[0],
                                "name": "shakeshift",
                                "resource_hash": "hash-shakeshift",
                            }
                        ],
                    },
                    {
                        "nameserver": "ns1.unbounded",
                        "root_name": "unbounded",
                        "bootstrap_addresses": ["8.8.4.4"],
                        "bootstrap_field": "glue4",
                        "member_count": 2,
                        "members": members,
                    },
                ],
                "unbounded_canary_groups": [
                    {
                        "nameserver": "a.shakestation",
                        "root_name": "shakestation",
                        "bootstrap_addresses": ["44.231.6.183"],
                        "bootstrap_field": "glue4",
                        "member_count": 3,
                        "members": [
                            {**members[0], "name": "canary-a"},
                            {**members[0], "name": "canary-b"},
                            {**members[0], "name": "canary-c"},
                        ],
                    }
                ],
                "ds_preflight_groups": [
                    {
                        "nameserver": "ns1.skyinclude",
                        "root_name": "skyinclude",
                        "bootstrap_addresses": ["8.8.8.8"],
                        "bootstrap_field": "glue4",
                        "member_count": 2,
                        "members": members,
                    },
                    {
                        "nameserver": "a.namenode",
                        "root_name": "namenode",
                        "bootstrap_addresses": ["138.199.197.111"],
                        "bootstrap_field": "glue4",
                        "member_count": 1,
                        "members": [{**members[0], "name": "shakeshift"}],
                    },
                ],
            }
        )
    )

    with connect_live(live_db) as conn:
        init_live_db(conn)
        first = refresh_hns_handoff_groups(conn, topology_site=topology_site)
        second = refresh_hns_handoff_groups(conn, topology_site=topology_site)
        conn.execute(
            "INSERT INTO live_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (HNS_HANDOFF_NOT_BEFORE_META_KEY, "2099-01-01T00:00:00Z"),
        )
        artifact.write_text(artifact.read_text(encoding="utf-8") + "\n")
        third = refresh_hns_handoff_groups(conn, topology_site=topology_site)
        groups = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM hns_handoff_groups ORDER BY priority DESC, nameserver"
            )
        ]
        not_before = get_live_meta(conn, HNS_HANDOFF_NOT_BEFORE_META_KEY)

    assert first["indexed"] is True
    assert second["indexed"] is False
    assert third["indexed"] is True
    assert not_before == ""
    assert first["ds_priority_groups"] == 1
    assert first["unbounded_canary_groups"] == 1
    assert first["preflight_roots"] == 3
    assert [
        (row["nameserver"], row["root_name"], row["member_count"], row["priority"])
        for row in groups
    ] == [
        ("a.namenode", "namenode", 1, 2),
        ("a.shakestation", "shakestation", 3, 1),
        ("ns1.skyinclude", "skyinclude", 2, 0),
    ]


def test_handoff_preflight_promotes_only_ad_validated_hns_doh_roots(tmp_path, monkeypatch):
    live_db = tmp_path / "live.sqlite"
    topology_site = tmp_path / "site"
    artifact = topology_site / "data" / "hns-handoff-groups.json"
    artifact.parent.mkdir(parents=True)
    members = [
        {
            "name": name,
            "provider_guess": "self-hosted",
            "provider_type": "external_dns",
            "resource_hash": f"hash-{name}",
            "last_seen_height": 100,
            "ns_names": ["ns1.handoff"],
            "ds_records": [{"keyTag": 1}],
            "has_ds": True,
        }
        for name in ("validated", "unverified")
    ]
    artifact.write_text(
        json.dumps(
            {
                "format": "hns-handoff-cohorts-v1",
                "groups": [],
                "ds_priority_groups": [],
                "unbounded_canary_groups": [],
                "ds_preflight_groups": [
                    {
                        "nameserver": "ns1.handoff",
                        "root_name": "handoff",
                        "bootstrap_addresses": ["8.8.8.8"],
                        "bootstrap_field": "glue4",
                        "member_count": 2,
                        "members": members,
                    }
                ],
            }
        )
    )
    seen = []

    def fake_preflight(candidate, *, config):
        seen.append((candidate["root_name"], candidate["host"], candidate["ns_handoffs"]))
        return DnsProbeResult(
            status="resolved",
            addresses=["93.184.216.34"],
            dnssec_status=(
                "resolver_validated"
                if candidate["root_name"] == "validated"
                else "resolver_unverified"
            ),
        )

    monkeypatch.setattr("hns_topology.live_sweep.probe_hns_doh_preflight", fake_preflight)
    with connect_live(live_db) as conn:
        init_live_db(conn)
        refresh_hns_handoff_groups(conn, topology_site=topology_site)
        result = run_hns_handoff_preflight(
            conn,
            config=HnsHandoffPreflightConfig(limit=10, concurrency=1, min_delay_ms=0),
        )
        preflight = {
            row["root_name"]: dict(row)
            for row in conn.execute("SELECT * FROM hns_handoff_preflight ORDER BY root_name")
        }
        candidates = [
            dict(row)
            for row in conn.execute("SELECT root_name, sources_json, priority FROM candidates")
        ]

    assert result == {
        "selected": 2,
        "checked": 2,
        "resolver_validated": 1,
        "promoted": 1,
        "errors": 0,
    }
    assert seen == [
        (
            "unverified",
            "unverified",
            [
                {
                    "nameserver": "ns1.handoff",
                    "root_name": "handoff",
                    "bootstrap_addresses": ["8.8.8.8"],
                }
            ],
        ),
        (
            "validated",
            "validated",
            [
                {
                    "nameserver": "ns1.handoff",
                    "root_name": "handoff",
                    "bootstrap_addresses": ["8.8.8.8"],
                }
            ],
        ),
    ]
    assert preflight["validated"]["dnssec_status"] == "resolver_validated"
    assert preflight["validated"]["next_check_at"]
    assert preflight["unverified"]["dnssec_status"] == "resolver_unverified"
    assert len(candidates) == 1
    assert candidates[0]["root_name"] == "validated"
    assert json.loads(candidates[0]["sources_json"]) == ["hns_doh_preflight"]
    assert candidates[0]["priority"] == 90


def test_ds_priority_handoff_singleton_precedes_bounded_cohorts(tmp_path):
    live_db = tmp_path / "live.sqlite"
    with connect_live(live_db) as conn:
        init_live_db(conn)
        conn.executemany(
            """
            INSERT INTO hns_handoff_groups(
              nameserver, root_name, bootstrap_ip, bootstrap_field, priority, member_count,
              members_json, source_signature, indexed_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "ns1.cohort",
                    "cohort",
                    "8.8.8.8",
                    "glue4",
                    0,
                    2,
                    json.dumps(
                        [
                            {
                                "name": "alpha",
                                "provider_guess": "self-hosted",
                                "provider_type": "external_dns",
                                "resource_hash": "hash-alpha",
                                "last_seen_height": 100,
                                "ns_names": ["ns1.cohort"],
                                "ds_records": [],
                                "has_ds": False,
                            },
                            {
                                "name": "beta",
                                "provider_guess": "self-hosted",
                                "provider_type": "external_dns",
                                "resource_hash": "hash-beta",
                                "last_seen_height": 100,
                                "ns_names": ["ns1.cohort"],
                                "ds_records": [],
                                "has_ds": False,
                            },
                        ]
                    ),
                    "test",
                    "2026-07-12T00:00:00Z",
                ),
                (
                    "a.namenode",
                    "namenode",
                    "138.199.197.111",
                    "glue4",
                    2,
                    1,
                    json.dumps(
                        [
                            {
                                "name": "shakeshift",
                                "provider_guess": "unknown/custom",
                                "provider_type": "unknown",
                                "resource_hash": "hash-shakeshift",
                                "last_seen_height": 100,
                                "ns_names": ["a.namenode"],
                                "ds_records": [{"keyTag": 48942}],
                                "has_ds": True,
                            }
                        ]
                    ),
                    "test",
                    "2026-07-12T00:00:00Z",
                ),
                (
                    "a.shakestation",
                    "shakestation",
                    "44.231.6.183",
                    "glue4",
                    1,
                    1,
                    json.dumps(
                        [
                            {
                                "name": "canary",
                                "provider_guess": "unknown/custom",
                                "provider_type": "unknown",
                                "resource_hash": "hash-canary",
                                "last_seen_height": 100,
                                "ns_names": ["a.shakestation"],
                                "ds_records": [{"keyTag": 1}],
                                "has_ds": True,
                            }
                        ]
                    ),
                    "test",
                    "2026-07-12T00:00:00Z",
                ),
            ],
        )
        selection = select_sweep_candidates(
            conn,
            topology_db=tmp_path / "not-needed.sqlite",
            limit=2,
            page_size=100,
            tiers=("hns_handoff",),
        )

    assert [candidate["root_name"] for candidate in selection["candidates"]] == [
        "shakeshift",
        "canary",
    ]
    singleton, canary = selection["candidates"]
    assert singleton["signal_tier"] == "ds_handoff"
    assert singleton["handoff_cohort"]["priority"] == 2
    assert "ds-singleton" in singleton["sweep_coverage_resource_hash"]
    assert canary["handoff_cohort"]["priority"] == 1
    assert "unbounded-canary" in canary["sweep_coverage_resource_hash"]


def test_handoff_cohort_sweep_uses_compact_index_without_topology_database(tmp_path):
    live_db = tmp_path / "live.sqlite"
    with connect_live(live_db) as conn:
        init_live_db(conn)
        conn.execute(
            """
            INSERT INTO hns_handoff_groups(
              nameserver, root_name, bootstrap_ip, bootstrap_field, member_count,
              members_json, source_signature, indexed_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "a.namenode",
                "namenode",
                "138.199.197.111",
                "glue4",
                2,
                json.dumps(
                    [
                        {
                            "name": "alpha",
                            "provider_guess": "self-hosted",
                            "provider_type": "external_dns",
                            "resource_hash": "hash-alpha",
                            "last_seen_height": 100,
                            "ns_names": ["a.namenode"],
                            "ds_records": [{"keyTag": 1}],
                            "has_ds": True,
                        },
                        {
                            "name": "beta",
                            "provider_guess": "self-hosted",
                            "provider_type": "external_dns",
                            "resource_hash": "hash-beta",
                            "last_seen_height": 100,
                            "ns_names": ["a.namenode"],
                            "ds_records": [],
                            "has_ds": False,
                        },
                    ]
                ),
                "test",
                "2026-07-12T00:00:00Z",
            ),
        )
        conn.execute(
            """
            INSERT INTO sweep_coverage(
              root_name, resource_hash, signal_tier, outcome_code, endpoint_category,
              checked_at, next_check_at, failure_reason
            ) VALUES(?, ?, ?, ?, '', ?, ?, '')
            """,
            (
                "alpha",
                "hash-alpha",
                "ds_handoff",
                "no_endpoint",
                "2026-07-12T00:00:00Z",
                "2099-01-01T00:00:00Z",
            ),
        )
        selection = select_sweep_candidates(
            conn,
            topology_db=tmp_path / "not-needed.sqlite",
            limit=10,
            page_size=100,
            tiers=("hns_handoff",),
        )

    assert [item["root_name"] for item in selection["candidates"]] == ["alpha", "beta"]
    assert [item["signal_tier"] for item in selection["candidates"]] == [
        "ds_handoff",
        "delegation_handoff",
    ]
    assert {tuple(item["authority_keys"]) for item in selection["candidates"]} == {
        ("hns-handoff:a.namenode|namenode|138.199.197.111",)
    }
    assert {tuple(item["authority_health_keys"]) for item in selection["candidates"]} == {()}
    assert {item["ns_handoffs"][0]["root_name"] for item in selection["candidates"]} == {"namenode"}
    assert all(
        "hns-handoff-v1" in item["sweep_coverage_resource_hash"] for item in selection["candidates"]
    )


def test_sweep_prioritizes_members_of_a_shared_delegation_group(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_shared_authority_topology(topology_db)
    _seed_handoff_root(topology_db, name="trapify")

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
    assert {tuple(item["ns_names"]) for item in selection["candidates"]} == {("ns1.trapify",)}
    assert {item["signal_tier"] for item in selection["candidates"]} == {"ds_handoff"}
    assert {item["ns_handoffs"][0]["root_name"] for item in selection["candidates"]} == {"trapify"}


def test_shared_delegation_selection_skips_covered_groups_without_topology_reads(
    tmp_path, monkeypatch
):
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
        conn.executemany(
            """
            INSERT INTO sweep_coverage(
              root_name, resource_hash, signal_tier, outcome_code, endpoint_category,
              checked_at, next_check_at, failure_reason
            ) VALUES(?, ?, ?, ?, '', ?, ?, '')
            """,
            [
                (
                    name,
                    f"hash-{name}",
                    "shared_delegation",
                    "no_endpoint",
                    "2026-07-12T00:00:00Z",
                    "2099-01-01T00:00:00Z",
                )
                for name in ("aa-shared", "ab-shared", "ac-shared", "ad-shared")
            ],
        )
        monkeypatch.setattr(
            "hns_topology.live_sweep._topology_rows_for_names",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("unexpected topology read")
            ),
        )
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=10,
            page_size=100,
            tiers=("shared_delegation",),
        )

    assert selection["candidates"] == []


def test_probe_resolves_a_hns_nameserver_handoff_before_the_delegated_zone(monkeypatch):
    calls = []

    def fake_resolve_addresses(servers, host, root_name, **kwargs):
        calls.append((servers, host, root_name))
        if host == "ns1.skyinclude":
            return ["9.9.9.9"], [], set(), "8.8.8.8"
        return ["93.184.216.34"], [], set(), "9.9.9.9"

    monkeypatch.setattr("hns_topology.live_probe._resolve_addresses", fake_resolve_addresses)
    result = probe_dns(
        {
            "root_name": "agent",
            "host": "agent",
            "bootstrap_addresses": [],
            "ns_names": ["ns1.skyinclude"],
            "ns_handoffs": [
                {
                    "nameserver": "ns1.skyinclude",
                    "root_name": "skyinclude",
                    "bootstrap_addresses": ["8.8.8.8"],
                }
            ],
            "ds_records": [],
        },
        config=ProbeConfig(timeout=1, max_nameservers=2, max_addresses=2),
        include_dns_details=False,
    )

    assert result.status == "resolved"
    assert calls == [
        (["8.8.8.8"], "ns1.skyinclude", "skyinclude"),
        (["9.9.9.9"], "agent", "agent"),
    ]


def test_general_delegated_sweep_marks_and_uses_hns_handoff(tmp_path):
    topology_db = tmp_path / "topology.sqlite"
    live_db = tmp_path / "live.sqlite"
    _seed_topology(topology_db)
    _seed_handoff_root(topology_db, name="handoff")
    with sqlite3.connect(topology_db) as conn:
        conn.execute(
            "UPDATE resource_summary SET ns_names = ? WHERE name = 'c-ds-delegated'",
            (json.dumps(["ns1.handoff"]),),
        )

    with connect_live(live_db) as conn:
        init_live_db(conn)
        selection = select_sweep_candidates(
            conn,
            topology_db=topology_db,
            limit=10,
            page_size=10,
            tiers=("ds_delegated",),
        )

    assert len(selection["candidates"]) == 1
    candidate = selection["candidates"][0]
    assert candidate["root_name"] == "c-ds-delegated"
    assert candidate["signal_tier"] == "ds_handoff"
    assert candidate["ns_handoffs"] == [
        {
            "nameserver": "ns1.handoff",
            "root_name": "handoff",
            "bootstrap_addresses": ["8.8.8.8"],
        }
    ]
    assert candidate["topology_root"].ns_handoffs == candidate["ns_handoffs"]


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


def _seed_handoff_root(path, *, name):
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO names(name, provider_guess, last_seen_height, resource_hash) VALUES(?, ?, ?, ?)",
            (name, "self-hosted", 100, f"hash-{name}"),
        )
        conn.execute(
            """
            INSERT INTO resource_summary(
              name, ns_names, glue4, glue6, synth4, synth6, ds_records,
              has_ds, has_ns, has_glue, has_synth, resource_hash
            ) VALUES(?, ?, '[]', '[]', ?, '[]', '[]', 0, 1, 0, 1, ?)
            """,
            (name, json.dumps([f"ns1.{name}"]), json.dumps(["8.8.8.8"]), f"hash-{name}"),
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
