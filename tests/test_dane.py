from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hns_topology import cli
from hns_topology.dane import (
    TLSARecord,
    build_tlsa_records,
    certificate_metadata_from_der,
    certificate_metadata_from_tlsa,
    parse_tlsa_zone_line,
    tlsa_record_matches_certificate,
)


def test_builds_tlsa_3_1_1_records_from_certificate_spki():
    cert = make_certificate()
    records = build_tlsa_records(cert, site_name="DenuoWeb", ttl=300, include_www=True)
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected_association = hashlib.sha256(spki_der).hexdigest()

    assert [record.owner for record in records] == [
        "_443._tcp.denuoweb.",
        "_443._tcp.www.denuoweb.",
    ]
    assert {record.association for record in records} == {expected_association}
    assert {record.usage for record in records} == {3}
    assert {record.selector for record in records} == {1}
    assert {record.matching_type for record in records} == {1}

    parsed = parse_tlsa_zone_line(records[0].to_zone_line())
    assert parsed == records[0]
    parsed_without_ttl = parse_tlsa_zone_line(
        f"{records[0].owner} IN TLSA 3 1 1 {records[0].association}"
    )
    assert parsed_without_ttl.ttl == 0
    assert parsed_without_ttl.association == records[0].association
    assert tlsa_record_matches_certificate(cert, parsed)
    assert not tlsa_record_matches_certificate(
        cert,
        TLSARecord(
            owner=parsed.owner,
            ttl=parsed.ttl,
            usage=parsed.usage,
            selector=parsed.selector,
            matching_type=parsed.matching_type,
            association="00" * 32,
        ),
    )

    www_records = build_tlsa_records(cert, site_name="www.denuoweb", ttl=300, include_www=True)
    assert [record.owner for record in www_records] == ["_443._tcp.www.denuoweb."]


def test_tlsa_cli_prints_and_verifies_records(tmp_path, capsys):
    cert = make_certificate()
    cert_path = tmp_path / "site.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print_result = cli.main(
        [
            "tlsa-from-cert",
            "--cert",
            str(cert_path),
            "--site",
            "denuoweb",
            "--ttl",
            "300",
        ]
    )
    printed = capsys.readouterr().out.strip().splitlines()

    assert print_result == 0
    assert printed[0].startswith("_443._tcp.denuoweb. 300 IN TLSA 3 1 1 ")
    assert printed[1].startswith("_443._tcp.www.denuoweb. 300 IN TLSA 3 1 1 ")

    verify_result = cli.main(
        [
            "verify-tlsa",
            "--cert",
            str(cert_path),
            "--record",
            printed[0],
        ]
    )
    verified = capsys.readouterr().out

    assert verify_result == 0
    assert "[ok] _443._tcp.denuoweb.: TLSA 3 1 1" in verified


def test_certificate_metadata_is_available_only_from_embedded_certificate_tlsa():
    cert = make_certificate()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    metadata = certificate_metadata_from_der(cert_der)
    embedded = TLSARecord(
        owner="_443._tcp.denuoweb.",
        ttl=300,
        usage=3,
        selector=0,
        matching_type=0,
        association=cert_der.hex(),
    )
    spki_hash = TLSARecord(
        owner="_443._tcp.denuoweb.",
        ttl=300,
        usage=3,
        selector=1,
        matching_type=1,
        association=metadata.spki_sha256,
    )

    assert certificate_metadata_from_tlsa(embedded) == metadata
    assert certificate_metadata_from_tlsa(spki_hash) is None
    assert metadata.not_valid_after.endswith("Z")


def make_certificate() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "denuoweb")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
