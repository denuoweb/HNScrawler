import json

from hns_topology.live_db import (
    connect_live,
    init_live_db,
    store_probe_result,
    upsert_candidate,
    upsert_root,
)
from hns_topology.live_exporter import export_live_site, validate_live_site
from hns_topology.live_models import HostProbeResult, LiveCandidate, TopologyRoot


def test_live_export_is_standalone_and_valid(tmp_path):
    db_path = tmp_path / "live.sqlite"
    public = tmp_path / "hns-live"
    with connect_live(db_path) as conn:
        init_live_db(conn)
        with conn:
            upsert_root(
                conn,
                TopologyRoot(
                    name="example",
                    provider_guess="self-hosted",
                    provider_type="self_hosted",
                    resource_hash="hash-1",
                    last_seen_height=123,
                    ns_names=["ns1.example"],
                    bootstrap_addresses=["93.184.216.34"],
                    ds_records=[{"keyTag": 1}],
                    has_ds=True,
                    strict_ready=True,
                ),
                synced_at="2026-07-11T00:00:00Z",
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
                seen_at="2026-07-11T00:00:00Z",
            )
            store_probe_result(conn, _https_result())
        summary = export_live_site(conn, public)

    sites = json.loads((public / "data/sites.json").read_text(encoding="utf-8"))
    html = (public / "index.html").read_text(encoding="utf-8")

    assert summary["https_count"] == 1
    assert summary["online_count"] == 1
    assert summary["offline_count"] == 0
    assert "repair_count" not in summary
    assert summary["live_dane_evidence"] == {
        "active_roots": 1,
        "checked_roots": 1,
        "observed_roots": 1,
        "last_checked_at": "2026-07-11T00:00:00Z",
    }
    assert sites["rows"][0]["host"] == "example"
    assert sites["rows"][0]["category"] == "https"
    assert "/hns-topology/index.html" in html
    assert validate_live_site(public) == []


def _https_result() -> HostProbeResult:
    return HostProbeResult(
        root_name="example",
        host="example",
        topology_resource_hash="hash-1",
        category="https",
        canonical_url="https://example/",
        dns_status="resolved",
        addresses=["93.184.216.34"],
        dnssec_status="valid",
        tlsa_status="present_secure",
        tlsa_records=[{"owner": "_443._tcp.example."}],
        dane_status="valid",
        http_status="response",
        http_status_code=301,
        http_location="https://example/",
        https_status="online",
        https_status_code=200,
        https_location="",
        webpki_status="valid",
        certificate_sha256="aa" * 32,
        spki_sha256="bb" * 32,
        certificate_not_valid_after="2026-08-01T00:00:00Z",
        failure_reason="",
        discovered_hosts=[],
        checked_at="2026-07-11T00:00:00Z",
        duration_ms=25,
    )
