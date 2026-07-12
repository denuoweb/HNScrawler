import sqlite3
from dataclasses import replace

from hns_topology.live_db import (
    begin_topology_sync,
    connect_live,
    directory_rows,
    finish_topology_sync,
    get_live_meta,
    init_live_db,
    select_due_candidates,
    set_live_meta,
    store_probe_result,
    upsert_candidate,
    upsert_root,
)
from hns_topology.live_models import HostProbeResult, LiveCandidate, TopologyRoot


def test_online_host_survives_one_failure_then_is_unlisted(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        _seed_candidate(conn)
        with conn:
            store_probe_result(conn, _result(category="https", checked_at="2026-07-01T00:00:00Z"))
        assert directory_rows(conn)[0]["category"] == "https"

        with conn:
            store_probe_result(conn, _result(category="offline", checked_at="2026-07-08T00:00:00Z"))
        degraded = directory_rows(conn)
        assert len(degraded) == 1
        assert degraded[0]["category"] == "https"
        assert degraded[0]["listing_state"] == "degraded"
        status = conn.execute("SELECT * FROM host_status").fetchone()
        assert status["next_check_at"] == "2026-07-09T00:00:00Z"
        assert status["consecutive_failures"] == 1

        with conn:
            store_probe_result(conn, _result(category="offline", checked_at="2026-07-09T00:00:00Z"))
        unlisted = directory_rows(conn)
        assert len(unlisted) == 1
        assert unlisted[0]["category"] == "offline"
        assert unlisted[0]["listing_state"] == "unlisted"
        status = conn.execute("SELECT * FROM host_status").fetchone()
        assert status["listing_state"] == "unlisted"
        assert status["consecutive_failures"] == 2


def test_dnssec_validation_failure_unlists_a_previously_online_host_immediately(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        _seed_candidate(conn)
        with conn:
            store_probe_result(conn, _result(category="https", checked_at="2026-07-01T00:00:00Z"))
            store_probe_result(
                conn,
                replace(
                    _result(category="offline", checked_at="2026-07-02T00:00:00Z"),
                    dnssec_status="dnskey_missing",
                    failure_reason="dnssec_validation_failed",
                ),
            )

        row = directory_rows(conn)[0]
        status = conn.execute("SELECT * FROM host_status").fetchone()

    assert row["category"] == "offline"
    assert row["listing_state"] == "unlisted"
    assert status["next_check_at"] == "2026-07-09T00:00:00Z"


def test_init_live_db_migrates_handoff_storage(tmp_path):
    db_path = tmp_path / "live.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE roots (
              name TEXT PRIMARY KEY,
              provider_guess TEXT NOT NULL,
              provider_type TEXT NOT NULL,
              resource_hash TEXT NOT NULL,
              last_seen_height INTEGER,
              ns_names_json TEXT NOT NULL DEFAULT '[]',
              bootstrap_addresses_json TEXT NOT NULL DEFAULT '[]',
              ds_records_json TEXT NOT NULL DEFAULT '[]',
              has_ds INTEGER NOT NULL DEFAULT 0,
              strict_ready INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 1,
              topology_updated_at TEXT NOT NULL
            )
            """
        )

    with connect_live(db_path) as conn:
        init_live_db(conn)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(roots)")}
        handoff_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(hns_handoff_groups)")
        }
        schema_version = get_live_meta(conn, "schema_version")

    assert "ns_handoffs_json" in columns
    assert "priority" in handoff_columns
    assert schema_version == "8"


def test_topology_hash_change_makes_candidate_immediately_due(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        _seed_candidate(conn)
        with conn:
            store_probe_result(conn, _result(category="https", checked_at="2026-07-01T00:00:00Z"))
            upsert_candidate(
                conn,
                LiveCandidate(
                    root_name="example",
                    host="example",
                    source="apex",
                    source_detail="root apex",
                    priority=70,
                    topology_resource_hash="hash-2",
                ),
                seen_at="2026-07-02T00:00:00Z",
            )

        due = select_due_candidates(conn, limit=10, now="2026-07-02T00:00:00Z")

    assert [item["host"] for item in due] == ["example"]
    assert due[0]["topology_resource_hash"] == "hash-2"


def test_new_candidate_batch_round_robins_provider_groups(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        with conn:
            for name, provider in (
                ("a-one", "provider-a"),
                ("a-two", "provider-a"),
                ("b-one", "provider-b"),
            ):
                upsert_root(
                    conn,
                    TopologyRoot(
                        name=name,
                        provider_guess=provider,
                        provider_type="external_dns",
                        resource_hash=f"hash-{name}",
                        last_seen_height=100,
                        ns_names=[f"ns1.{name}"],
                        bootstrap_addresses=["93.184.216.34"],
                        ds_records=[],
                        has_ds=False,
                        strict_ready=True,
                    ),
                    synced_at="2026-07-01T00:00:00Z",
                )
                upsert_candidate(
                    conn,
                    LiveCandidate(
                        root_name=name,
                        host=name,
                        source="apex",
                        source_detail="root apex",
                        priority=60,
                        topology_resource_hash=f"hash-{name}",
                    ),
                    seen_at="2026-07-01T00:00:00Z",
                )

        due = select_due_candidates(conn, limit=2, now="2026-07-01T00:00:00Z")

    assert {item["provider_guess"] for item in due} == {"provider-a", "provider-b"}


def test_new_topology_candidates_run_before_existing_weekly_rechecks(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        _seed_candidate(conn)
        with conn:
            store_probe_result(
                conn,
                _result(category="https", checked_at="2026-07-01T00:00:00Z"),
            )
            set_live_meta(conn, "topology_synced_at", "2026-07-10T00:00:00Z")
            _upsert_named_candidate(
                conn,
                name="new-root",
                provider="new-provider",
                seen_at="2026-07-10T00:00:00Z",
            )

        due = select_due_candidates(conn, limit=1, now="2026-07-10T00:00:00Z")

    assert due[0]["host"] == "new-root"
    assert due[0]["queue_tier"] == 0


def test_topology_sync_deactivates_stale_evidence_but_retains_recent_probe_discovery(tmp_path):
    with connect_live(tmp_path / "live.sqlite") as conn:
        init_live_db(conn)
        _seed_candidate(conn)
        with conn:
            for host, source in (
                ("old.example", "dns_evidence"),
                ("found.example", "probe_dns"),
            ):
                upsert_candidate(
                    conn,
                    LiveCandidate(
                        root_name="example",
                        host=host,
                        source=source,
                        source_detail="test evidence",
                        priority=80,
                        topology_resource_hash="hash-1",
                    ),
                    seen_at="2026-07-01T00:00:00Z",
                )
            begin_topology_sync(conn)
            upsert_root(
                conn,
                TopologyRoot(
                    name="example",
                    provider_guess="self-hosted",
                    provider_type="self_hosted",
                    resource_hash="hash-2",
                    last_seen_height=101,
                    ns_names=["ns1.example"],
                    bootstrap_addresses=["93.184.216.34"],
                    ds_records=[],
                    has_ds=False,
                    strict_ready=True,
                ),
                synced_at="2026-07-10T00:00:00Z",
            )
            upsert_candidate(
                conn,
                LiveCandidate(
                    root_name="example",
                    host="example",
                    source="apex",
                    source_detail="root apex",
                    priority=60,
                    topology_resource_hash="hash-2",
                ),
                seen_at="2026-07-10T00:00:00Z",
            )
            finish_topology_sync(conn, synced_at="2026-07-10T00:00:00Z")

        candidates = {
            row["host"]: dict(row)
            for row in conn.execute("SELECT host, active, topology_resource_hash FROM candidates")
        }

    assert candidates["example"]["active"] == 1
    assert candidates["old.example"]["active"] == 0
    assert candidates["found.example"]["active"] == 1
    assert candidates["found.example"]["topology_resource_hash"] == "hash-2"


def _seed_candidate(conn):
    with conn:
        upsert_root(
            conn,
            TopologyRoot(
                name="example",
                provider_guess="self-hosted",
                provider_type="self_hosted",
                resource_hash="hash-1",
                last_seen_height=100,
                ns_names=["ns1.example"],
                bootstrap_addresses=["93.184.216.34"],
                ds_records=[],
                has_ds=False,
                strict_ready=True,
            ),
            synced_at="2026-07-01T00:00:00Z",
        )
        upsert_candidate(
            conn,
            LiveCandidate(
                root_name="example",
                host="example",
                source="apex",
                source_detail="root apex",
                priority=60,
                topology_resource_hash="hash-1",
            ),
            seen_at="2026-07-01T00:00:00Z",
        )


def _upsert_named_candidate(conn, *, name: str, provider: str, seen_at: str) -> None:
    upsert_root(
        conn,
        TopologyRoot(
            name=name,
            provider_guess=provider,
            provider_type="external_dns",
            resource_hash=f"hash-{name}",
            last_seen_height=100,
            ns_names=[f"ns1.{name}"],
            bootstrap_addresses=["93.184.216.34"],
            ds_records=[],
            has_ds=False,
            strict_ready=True,
        ),
        synced_at=seen_at,
    )
    upsert_candidate(
        conn,
        LiveCandidate(
            root_name=name,
            host=name,
            source="apex",
            source_detail="root apex",
            priority=60,
            topology_resource_hash=f"hash-{name}",
        ),
        seen_at=seen_at,
    )


def _result(*, category: str, checked_at: str) -> HostProbeResult:
    online = category in {"https", "http_only"}
    return HostProbeResult(
        root_name="example",
        host="example",
        topology_resource_hash="hash-1",
        category=category,
        canonical_url=f"{category == 'https' and 'https' or 'http'}://example/" if online else "",
        dns_status="resolved" if online else "unreachable",
        addresses=["93.184.216.34"] if online else [],
        dnssec_status="unsigned",
        tlsa_status="missing",
        tlsa_records=[],
        dane_status="missing",
        http_status="response" if category == "http_only" else "failed",
        http_status_code=200 if category == "http_only" else None,
        http_location="",
        https_status="online" if category == "https" else "failed",
        https_status_code=200 if category == "https" else None,
        https_location="",
        webpki_status="valid" if category == "https" else "not_checked",
        certificate_sha256="",
        spki_sha256="",
        certificate_not_valid_after="",
        failure_reason="" if online else "connect_failed",
        discovered_hosts=[],
        checked_at=checked_at,
        duration_ms=10,
    )
