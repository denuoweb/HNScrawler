from hns_topology.browser_summary import apply_browser_evidence_policy


def test_browser_policy_keeps_network_blocks_53_context_only():
    row = apply_browser_evidence_policy(
        {
            "browser_result": "resolver_fallback",
            "browser_fallback_reason": "network_blocks_53",
            "browser_authoritative_udp": "blocked",
            "browser_authoritative_tcp": "blocked",
            "browser_authoritative_doh": "ok",
            "browser_captured_at": "2026-07-06T00:00:00Z",
        }
    )

    assert row["browser_evidence_effect"] == "context_network_blocks_53"
    assert row["browser_evidence_severity"] == "context"
    assert row["browser_action"] == "network_blocks_53_context"


def test_browser_policy_promotes_certificate_expiry_without_newer_live_dane():
    row = apply_browser_evidence_policy(
        {
            "dane_status": None,
            "checked_at": None,
            "browser_result": "certificate_expired",
            "browser_certificate_expired": 1,
            "browser_certificate_not_valid_after": "2026-07-01T00:00:00Z",
            "browser_captured_at": "2026-07-06T00:00:00Z",
        }
    )

    assert row["browser_certificate_expired"] is True
    assert row["browser_evidence_effect"] == "promoted_certificate_expired"
    assert row["browser_evidence_severity"] == "action"
    assert row["browser_action"] == "renew_certificate"


def test_browser_policy_live_dane_can_supersede_older_browser_expiry():
    row = apply_browser_evidence_policy(
        {
            "dane_status": "valid",
            "checked_at": "2026-07-07T00:00:00Z",
            "browser_result": "certificate_expired",
            "browser_certificate_expired": 1,
            "browser_captured_at": "2026-07-06T00:00:00Z",
        }
    )

    assert row["browser_evidence_effect"] == "live_supersedes_browser"
    assert row["browser_evidence_severity"] == "pass"
    assert row["browser_action"] is None


def test_browser_policy_marks_browser_dane_as_positive_review_evidence():
    row = apply_browser_evidence_policy(
        {
            "dane_status": "unknown",
            "browser_result": "dane_verified",
            "browser_dane_status": "verified",
            "browser_captured_at": "2026-07-06T00:00:00Z",
        }
    )

    assert row["browser_evidence_effect"] == "positive_browser_dane"
    assert row["browser_evidence_severity"] == "review"
    assert row["browser_action"] == "compare_browser_dane"
