import json

from hns_topology.tlsa_evidence import parse_tlsa_answer_lines, summarize_tlsa_evidence

TLSA_HEX = "ab" * 32


def evidence_row(
    *,
    captured_at: str,
    answers: list[str],
    row_id: int = 1,
    qname: str = "_443._tcp.example.",
    status: str = "ok",
    rcode: str = "NOERROR",
    flags: str = "QR AA",
):
    return {
        "id": row_id,
        "qname": qname,
        "rrtype": "TLSA",
        "server": "192.0.2.53",
        "source": "scanner",
        "source_id": "worker-1",
        "status": status,
        "rcode": rcode,
        "flags": flags,
        "answer_json": json.dumps(answers),
        "captured_at": captured_at,
    }


def test_parses_exact_tlsa_and_ignores_rrsig_or_malformed_lines():
    records = parse_tlsa_answer_lines(
        [
            f"_443._tcp.example. 300 IN TLSA 3 1 1 {TLSA_HEX}",
            "_443._tcp.example. 300 IN RRSIG TLSA 13 3 300 0 0 1 example. signature",
            "_443._tcp.example. 300 IN TLSA not-valid",
        ]
    )

    assert records == [
        {
            "owner": "_443._tcp.example.",
            "ttl": 300,
            "usage": 3,
            "selector": 1,
            "matchingType": 1,
            "association": TLSA_HEX,
        }
    ]


def test_newer_negative_supersedes_positive_from_same_vantage_point():
    positive = evidence_row(
        captured_at="2026-01-01T00:00:00Z",
        answers=[f"_443._tcp.example. 300 IN TLSA 3 1 1 {TLSA_HEX}"],
    )
    newer_negative = evidence_row(
        captured_at="2026-01-02T00:00:00Z",
        answers=[],
        row_id=2,
    )

    summary = summarize_tlsa_evidence("example", [positive, newer_negative])

    assert summary.has_tlsa is False
    assert summary.records == []
    assert summary.observed_at is None
    assert summary.checked_at == "2026-01-02T00:00:00Z"


def test_requires_authoritative_or_authenticated_exact_https_owner():
    recursive = evidence_row(
        captured_at="2026-01-01T00:00:00Z",
        answers=[f"_443._tcp.example. 300 IN TLSA 3 1 1 {TLSA_HEX}"],
        flags="QR RA",
    )
    wrong_owner = evidence_row(
        captured_at="2026-01-01T00:00:01Z",
        answers=[f"_443._tcp.other. 300 IN TLSA 3 1 1 {TLSA_HEX}"],
        row_id=2,
    )

    summary = summarize_tlsa_evidence("example", [recursive, wrong_owner])

    assert summary.has_tlsa is False


def test_www_and_apex_records_deduplicate_to_one_root_summary():
    apex = evidence_row(
        captured_at="2026-01-01T00:00:00Z",
        answers=[f"_443._tcp.example. 300 IN TLSA 3 1 1 {TLSA_HEX}"],
    )
    www = evidence_row(
        captured_at="2026-01-01T00:00:01Z",
        answers=[f"_443._tcp.www.example. 300 IN TLSA 3 1 1 {TLSA_HEX}"],
        row_id=2,
        qname="_443._tcp.www.example.",
    )

    summary = summarize_tlsa_evidence("example", [apex, www])

    assert summary.has_tlsa is True
    assert summary.owners == ["_443._tcp.example.", "_443._tcp.www.example."]
    assert len(summary.records) == 2
