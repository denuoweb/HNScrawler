from hns_topology.site_directory import site_directory_rows


def test_site_directory_prefers_live_dane_and_exports_cert_context():
    rows = site_directory_rows(
        [
            {
                "root_name": "secure",
                "host": "www.secure",
                "dane_status": "valid",
                "https_status": "tls_unverified",
                "strict_hns_status": "working",
                "certificate_not_valid_after": "2026-08-01T00:00:00Z",
                "spki_sha256": "bb" * 32,
                "checked_at": "2026-07-06T00:00:00Z",
            }
        ]
    )

    assert rows == [
        {
            "root_name": "secure",
            "host": "www.secure",
            "url": "https://www.secure/",
            "directory_status": "dane_verified",
            "evidence_source": "host_live_dane",
            "evidence_confidence": "dane_verified",
            "transport_note": "strict_hns",
            "compliance_stage": "",
            "provider_guess": "",
            "provider_type": "",
            "strict_hns_status": "working",
            "https_status": "tls_unverified",
            "dnssec_status": "",
            "tlsa_status": "",
            "dane_status": "valid",
            "fallback_status": "",
            "failure_reason": "",
            "checked_at": "2026-07-06T00:00:00Z",
            "certificate_not_valid_after": "2026-08-01T00:00:00Z",
            "certificate_sha256": "",
            "spki_sha256": "bb" * 32,
            "browser_result": "",
            "browser_evidence_effect": "",
            "browser_action": "",
            "browser_fallback_reason": "",
            "browser_captured_at": "",
            "diagnostic_path": "names.html?q=secure&host=www.secure",
        }
    ]


def test_site_directory_includes_browser_dane_context_without_live_dane():
    rows = site_directory_rows(
        [
            {
                "root_name": "woodburn",
                "host": "nathan.woodburn",
                "browser_result": "dane_verified",
                "browser_evidence_effect": "positive_browser_dane",
                "browser_fallback_reason": "network_blocks_53",
                "browser_captured_at": "2026-07-06T00:00:00Z",
            }
        ]
    )

    assert len(rows) == 1
    assert rows[0]["directory_status"] == "browser_dane_verified"
    assert rows[0]["evidence_source"] == "browser_dane"
    assert rows[0]["evidence_confidence"] == "browser_dane_verified"
    assert rows[0]["transport_note"] == "browser_network_blocks_53"


def test_site_directory_skips_expired_and_unproven_names():
    rows = site_directory_rows(
        [
            {"name": "expired", "expired": 1, "dane_status": "valid"},
            {"name": "candidate", "strict_hns_status": "not_checked"},
        ]
    )

    assert rows == []


def test_site_directory_allows_live_subdomain_without_live_apex():
    rows = site_directory_rows(
        [
            {"root_name": "crewball", "host": "crewball", "https_status": "failed"},
            {
                "root_name": "crewball",
                "host": "jaron.crewball",
                "https_status": "working",
                "strict_hns_status": "working",
            },
        ]
    )

    assert len(rows) == 1
    assert rows[0]["root_name"] == "crewball"
    assert rows[0]["host"] == "jaron.crewball"
    assert rows[0]["url"] == "https://jaron.crewball/"
    assert rows[0]["directory_status"] == "https_reachable"
