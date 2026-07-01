import hashlib

from hns_topology.livecheck import HttpsResult, LiveCheckConfig, _match_association, check_name


def test_tlsa_association_matching_supports_full_and_hashes():
    selected = b"certificate-or-spki"

    assert _match_association(selected, 0, selected)
    assert _match_association(selected, 1, hashlib.sha256(selected).digest())
    assert _match_association(selected, 2, hashlib.sha512(selected).digest())
    assert not _match_association(selected, 1, b"wrong")


class DummyLimiter:
    def __init__(self):
        self.waits = 0

    def wait(self):
        self.waits += 1


def test_dane_match_can_work_without_webpki_validation(monkeypatch):
    limiter = DummyLimiter()
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [(3, 1, 1, b"x")])
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: True)

    status = check_name(
        {"name": "example", "synth4": ["127.0.0.1"], "synth6": [], "glue4": [], "glue6": [], "has_ds": 1},
        LiveCheckConfig(timeout=0.1),
        limiter,
    )

    assert limiter.waits == 1
    assert status.https_status == "tls_unverified"
    assert status.tlsa_status == "present"
    assert status.dane_status == "valid"
    assert status.strict_hns_status == "working"
    assert status.failure_reason is None


def test_stale_tlsa_takes_precedence_over_certificate_mismatch(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [(3, 1, 1, b"x")])
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )
    monkeypatch.setattr("hns_topology.livecheck._match_any_tlsa", lambda cert, records: False)

    status = check_name(
        {"name": "example", "synth4": ["127.0.0.1"], "synth6": [], "glue4": [], "glue6": [], "has_ds": 1},
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.dane_status == "invalid"
    assert status.failure_reason == "stale_tlsa_spki_mismatch"


def test_unverified_https_without_tlsa_keeps_certificate_failure(monkeypatch):
    monkeypatch.setattr("hns_topology.livecheck._resolve_addresses", lambda resolver, name: [])
    monkeypatch.setattr("hns_topology.livecheck._resolve_tlsa", lambda resolver, name: [])
    monkeypatch.setattr(
        "hns_topology.livecheck._https_connect",
        lambda hostname, address, timeout: HttpsResult(
            "tls_unverified",
            b"cert",
            "certificate_mismatch",
        ),
    )

    status = check_name(
        {"name": "example", "synth4": ["127.0.0.1"], "synth6": [], "glue4": [], "glue6": [], "has_ds": 0},
        LiveCheckConfig(timeout=0.1),
        DummyLimiter(),
    )

    assert status.tlsa_status == "missing"
    assert status.dane_status == "unknown"
    assert status.failure_reason == "certificate_mismatch"
