from hns_topology.host_candidates import (
    candidates_from_browser_evidence,
    candidates_from_tlsa_owner,
    default_hosts_for_root,
    normalize_host,
    root_from_host,
)


def test_normalize_host_rejects_urls_paths_ports_and_whitespace():
    assert normalize_host("  WWW.DENUOWEB. ") == "www.denuoweb"
    assert normalize_host("https://www.denuoweb/") == ""
    assert normalize_host("www.denuoweb/path") == ""
    assert normalize_host("www.denuoweb:443") == ""
    assert normalize_host("www. denuoweb") == ""


def test_root_from_host_uses_longest_known_root_suffix():
    known_roots = {"crewball", "forever", "denuoweb"}

    assert root_from_host("jaron.crewball", known_roots) == "crewball"
    assert root_from_host("www.denuoweb", known_roots) == "denuoweb"
    assert root_from_host("impervious.forever", known_roots) == "forever"
    assert root_from_host("example.com", known_roots) is None


def test_default_hosts_for_root_generates_apex_and_www_candidates():
    candidates = default_hosts_for_root("Denuoweb.")

    assert [(item.root_name, item.host, item.source) for item in candidates] == [
        ("denuoweb", "denuoweb", "default_apex"),
        ("denuoweb", "www.denuoweb", "default_www"),
    ]


def test_candidates_from_browser_evidence_uses_host_and_known_roots():
    rows = [
        {
            "url": "https://jaron.crewball/",
            "host": "jaron.crewball",
            "browser_result": "loaded",
            "source": "hns-browser",
            "source_id": "pixel9",
            "captured_at": "2026-07-06T00:00:00Z",
        },
        {
            "url": "https://impervious.forever/",
            "host": "",
            "browser_result": "dane_verified",
            "dane_status": "verified",
            "captured_at": "2026-07-06T00:00:00Z",
        },
    ]

    candidates = candidates_from_browser_evidence(rows, {"crewball", "forever"})

    assert [(item.root_name, item.host, item.source, item.confidence) for item in candidates] == [
        ("crewball", "jaron.crewball", "browser_evidence", 90),
        ("forever", "impervious.forever", "browser_evidence", 100),
    ]


def test_candidates_from_tlsa_owner_extracts_host_under_root():
    candidate = candidates_from_tlsa_owner("crewball", "_443._tcp.jaron.crewball.")

    assert candidate is not None
    assert candidate.root_name == "crewball"
    assert candidate.host == "jaron.crewball"
    assert candidate.source == "resource_tlsa_owner"


def test_candidates_from_tlsa_owner_rejects_out_of_root_hosts():
    assert candidates_from_tlsa_owner("crewball", "_443._tcp.impervious.forever.") is None
