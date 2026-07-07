import json

from hns_topology.browser_evidence import parse_browser_evidence_text


def test_parse_resolver_trace_preserves_dane_success_with_fallback_context():
    evidence = parse_browser_evidence_text(
        json.dumps(
            {
                "host": "nathan.woodburn",
                "root": "woodburn",
                "mode": "hns_compatibility",
                "hnsProof": "verified",
                "resolutionSource": "authoritative_doh",
                "authoritativeDns": {"udp53": "blocked", "tcp53": "timeout", "doh": "ok"},
                "fallback": {"used": True, "reason": "network_blocks_53"},
                "dnssec": "secure",
                "originAddress": "103.152.197.116",
                "tls": {
                    "tlsaOwner": "_443._tcp.nathan.woodburn",
                    "tlsaStatus": "present",
                    "tlsaSource": "native_tlsa",
                    "certificate": {
                        "endEntitySha256": "aa" * 32,
                        "spkiSha256": "bb" * 32,
                    },
                    "dane": {"decision": "verified"},
                },
                "captured_at": "2026-07-06T00:00:00Z",
            }
        ),
        source="hns-browser",
        source_id="pixel9",
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.name == "woodburn"
    assert item.host == "nathan.woodburn"
    assert item.browser_result == "dane_verified"
    assert item.fallback_used is True
    assert item.fallback_reason == "network_blocks_53"
    assert item.authoritative_udp == "blocked"
    assert item.authoritative_doh == "ok"
    assert item.spki_sha256 == "bb" * 32


def test_parse_gateway_event_log_lines():
    evidence = parse_browser_evidence_text(
        "1783324451000\twebview_native_response\tmercenary\t502\tHNS_Origin_Certificate_Expired\n",
        source="hns-browser",
        source_id="pixel9",
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.name == "mercenary"
    assert item.evidence_type == "gateway_event"
    assert item.status_code == 502
    assert item.stage == "webview_native_response"
    assert item.browser_result == "certificate_expired"
    assert item.captured_at == "2026-07-06T07:54:11Z"


def test_parse_gateway_event_success_status_as_loaded():
    evidence = parse_browser_evidence_text(
        "1783324451000\twebview_native_response\tdirect\t200\tOK\n",
        source="hns-browser",
        source_id="pixel9",
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.name == "direct"
    assert item.evidence_type == "gateway_event"
    assert item.status_code == 200
    assert item.browser_result == "loaded"


def test_parse_markdown_diagnostic_bundle_gateway_events():
    evidence = parse_browser_evidence_text(
        """
# HNS DANE Browser Diagnostic Bundle

Generated: 2026-07-06T22:29:00Z

## Recent Gateway Events
```
1783324451000 webview_native_response denuoweb 502 delegated_dnssec_validation_failed
1783324452000 webview_native_response crewball 502 HNS_Origin_Certificate_Expired
```
""",
        source="hns-browser",
        source_id="pixel9",
    )

    assert [(item.name, item.status_code, item.browser_result) for item in evidence] == [
        ("denuoweb", 502, "dnssec_bogus"),
        ("crewball", 502, "certificate_expired"),
    ]


def test_parse_resolver_trace_marks_expired_certificate_from_validity_timestamp():
    evidence = parse_browser_evidence_text(
        json.dumps(
            {
                "host": "mercenary",
                "root": "mercenary",
                "mode": "hns_compatibility",
                "hnsProof": "verified",
                "resolutionSource": "authoritative_doh",
                "authoritativeDns": {"udp53": "blocked", "tcp53": "blocked", "doh": "ok"},
                "fallback": {"used": True, "reason": "network_blocks_53"},
                "dnssec": "secure",
                "originAddress": "198.51.100.4",
                "tls": {
                    "tlsaOwner": "_443._tcp.mercenary",
                    "tlsaStatus": "present",
                    "tlsaSource": "native_tlsa",
                    "certificate": {
                        "endEntitySha256": "aa" * 32,
                        "spkiSha256": "bb" * 32,
                        "notValidAfter": "2026-07-01T00:00:00Z",
                    },
                    "dane": {"decision": "verified"},
                },
                "captured_at": "2026-07-06T00:00:00Z",
            }
        ),
        source="hns-browser",
        source_id="pixel9",
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert item.name == "mercenary"
    assert item.browser_result == "certificate_expired"
    assert item.reason == "certificate_expired"
    assert item.certificate_not_valid_after == "2026-07-01T00:00:00Z"
    assert item.certificate_expired is True
    assert item.fallback_reason == "network_blocks_53"
