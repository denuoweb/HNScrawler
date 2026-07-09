from hns_topology.browser_targets import browser_target_row


def test_browser_target_prefers_browser_dane_and_includes_adb_command():
    row = browser_target_row(
        {
            "root_name": "woodburn",
            "host": "nathan.woodburn",
            "provider_type": "unknown",
            "browser_result": "dane_verified",
            "browser_dane_status": "verified",
            "browser_fallback_reason": "network_blocks_53",
            "record_types": ["DS", "NS"],
            "has_ds": 1,
            "has_ns": 1,
        }
    )

    assert row is not None
    assert row["priority"] == 0
    assert row["category"] == "browser_dane_verified"
    assert row["root_name"] == "woodburn"
    assert row["host"] == "nathan.woodburn"
    assert row["url"] == "https://nathan.woodburn/"
    assert row["record_types"] == "DS,NS"
    assert "adb shell am force-stop com.denuoweb.hnsdane" in row["adb_command"]
    assert "com.denuoweb.hnsdane/.ui.MainActivity" in row["adb_command"]
    assert "com.denuoweb.hnsdane.LOAD_URL https://nathan.woodburn/" in row["adb_command"]


def test_browser_target_includes_static_strict_ready_candidates():
    row = browser_target_row(
        {
            "root_name": "direct",
            "host": "www.direct",
            "provider_type": "unknown",
            "has_synth": 1,
            "first_synth4": "203.0.113.10",
            "compliance_stage": "bootstrap_ready",
        }
    )

    assert row is not None
    assert row["priority"] == 7
    assert row["category"] == "strict_hns_ready"
    assert row["first_synth4"] == "203.0.113.10"
    assert row["url"] == "https://www.direct/"


def test_browser_target_skips_expired_and_non_actionable_static_only_names():
    assert browser_target_row({"name": "expired", "expired": 1, "browser_result": "loaded"}) is None
    assert browser_target_row(
        {
            "name": "parked",
            "provider_type": "default_parking",
            "has_ns": 1,
            "has_glue": 1,
        }
    ) is None
