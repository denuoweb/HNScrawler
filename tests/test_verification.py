from hns_topology.verification import build_verification_plan, verification_csv_rows


def test_direct_bootstrap_verification_plan_uses_first_strict_server():
    plan = build_verification_plan(
        {
            "name": "secure",
            "ns_names": ["ns1.secure"],
            "glue4": ["198.51.100.3"],
            "synth4": [],
            "expired": 0,
        }
    )

    assert plan is not None
    assert plan["mode"] == "direct_bootstrap"
    assert plan["server"] == "198.51.100.3"
    assert plan["nameserver"] == "ns1.secure."
    assert [command["command"] for command in plan["commands"][:4]] == [
        "dig @198.51.100.3 _dns.ns1.secure. SVCB +norecurse +dnssec",
        "dig @198.51.100.3 _dns.ns1.secure. SVCB +tcp +norecurse +dnssec",
        "dig @198.51.100.3 secure. A +norecurse +dnssec",
        "dig @198.51.100.3 secure. A +tcp +norecurse +dnssec",
    ]
    assert [command["transport"] for command in plan["commands"][:4]] == ["udp53", "tcp53", "udp53", "tcp53"]
    assert {command["rrtype"] for command in plan["commands"]} == {"A", "AAAA", "TLSA", "DNSKEY", "SVCB"}
    assert "RFC 9461" in plan["commands"][0]["note"]


def test_direct_bootstrap_verification_plan_works_without_nameserver_svcb_hint():
    plan = build_verification_plan(
        {
            "name": "secure",
            "glue4": ["198.51.100.3"],
            "expired": 0,
        }
    )

    assert plan is not None
    assert [command["command"] for command in plan["commands"][:4]] == [
        "dig @198.51.100.3 secure. A +norecurse +dnssec",
        "dig @198.51.100.3 secure. A +tcp +norecurse +dnssec",
        "dig @198.51.100.3 secure. AAAA +norecurse +dnssec",
        "dig @198.51.100.3 secure. AAAA +tcp +norecurse +dnssec",
    ]


def test_indirect_handoff_verification_plan_requires_resolved_nameserver_ip():
    plan = build_verification_plan(
        {
            "name": "mercenary",
            "ns_handoff_ns": "ns1.skyinclude",
            "ns_handoff_root": "skyinclude",
            "ns_handoff_bootstrap_ip": "192.155.93.228",
            "ns_handoff_bootstrap_field": "GLUE4",
        }
    )

    assert plan is not None
    assert plan["mode"] == "indirect_ns_handoff"
    assert plan["nameserver"] == "ns1.skyinclude."
    commands = [command["command"] for command in plan["commands"]]
    assert commands[0] == "dig @192.155.93.228 ns1.skyinclude. A +norecurse +dnssec"
    assert commands[1] == "dig @192.155.93.228 ns1.skyinclude. A +tcp +norecurse +dnssec"
    assert commands[4] == "dig @192.155.93.228 _dns.ns1.skyinclude. SVCB +norecurse +dnssec"
    assert commands[6] == "dig @<resolved-ns-ip> mercenary. A +norecurse +dnssec"
    assert plan["commands"][6]["requires"] == "resolved nameserver A/AAAA address"
    assert len(plan["commands"]) == 14


def test_verification_csv_rows_skips_names_without_probe_path():
    rows = verification_csv_rows(
        [
            {"name": "direct", "first_synth4": "203.0.113.10"},
            {"name": "txtonly"},
            {"name": "expired", "first_synth4": "203.0.113.11", "expired": 1},
        ]
    )

    assert len(rows) == 8
    assert {row["name"] for row in rows} == {"direct"}
    assert rows[0]["command"] == "dig @203.0.113.10 direct. A +norecurse +dnssec"
    assert rows[0]["purpose"] == "target_zone_probe"
    assert rows[0]["qname"] == "direct."
    assert rows[0]["rrtype"] == "A"
    assert rows[0]["transport"] == "udp53"
    assert rows[1]["command"] == "dig @203.0.113.10 direct. A +tcp +norecurse +dnssec"
