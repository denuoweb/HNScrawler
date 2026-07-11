from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


@dataclass(frozen=True)
class TLSARecord:
    owner: str
    ttl: int
    usage: int
    selector: int
    matching_type: int
    association: str

    def to_zone_line(self) -> str:
        return (
            f"{self.owner} {self.ttl} IN TLSA "
            f"{self.usage} {self.selector} {self.matching_type} {self.association}"
        )


@dataclass(frozen=True)
class CertificateMetadata:
    sha256: str
    spki_sha256: str
    not_valid_after: str


def load_certificate(path: str | Path) -> x509.Certificate:
    data = Path(path).read_bytes()
    return load_certificate_bytes(data)


def load_certificate_bytes(data: bytes) -> x509.Certificate:
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def certificate_metadata_from_der(cert_der: bytes) -> CertificateMetadata:
    cert = x509.load_der_x509_certificate(cert_der)
    spki_der = selected_certificate_bytes(cert, selector=1)
    return CertificateMetadata(
        sha256=hashlib.sha256(cert_der).hexdigest(),
        spki_sha256=hashlib.sha256(spki_der).hexdigest(),
        not_valid_after=cert.not_valid_after_utc.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    )


def build_tlsa_records(
    cert: x509.Certificate,
    *,
    site_name: str,
    ttl: int = 300,
    include_www: bool = True,
    usage: int = 3,
    selector: int = 1,
    matching_type: int = 1,
) -> list[TLSARecord]:
    association = certificate_association(
        cert,
        selector=selector,
        matching_type=matching_type,
    )
    records = [
        TLSARecord(
            owner=tlsa_owner(site_name),
            ttl=ttl,
            usage=usage,
            selector=selector,
            matching_type=matching_type,
            association=association,
        )
    ]
    base_name = site_name.rstrip(".")
    if include_www and not base_name.lower().startswith("www."):
        records.append(
            TLSARecord(
                owner=tlsa_owner("www." + base_name),
                ttl=ttl,
                usage=usage,
                selector=selector,
                matching_type=matching_type,
                association=association,
            )
        )
    return records


def tlsa_owner(site_name: str) -> str:
    return f"_443._tcp.{normalize_fqdn(site_name)}"


def normalize_fqdn(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("site name must not be empty")
    return normalized + "."


def certificate_association(
    cert: x509.Certificate,
    *,
    selector: int,
    matching_type: int,
) -> str:
    selected = selected_certificate_bytes(cert, selector=selector)
    return match_association_bytes(selected, matching_type=matching_type).hex()


def selected_certificate_bytes(cert: x509.Certificate, *, selector: int) -> bytes:
    if selector == 0:
        return cert.public_bytes(serialization.Encoding.DER)
    if selector == 1:
        return cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    raise ValueError(f"unsupported TLSA selector: {selector}")


def match_association_bytes(selected: bytes, *, matching_type: int) -> bytes:
    if matching_type == 0:
        return selected
    if matching_type == 1:
        return hashlib.sha256(selected).digest()
    if matching_type == 2:
        return hashlib.sha512(selected).digest()
    raise ValueError(f"unsupported TLSA matching type: {matching_type}")


def parse_tlsa_zone_line(line: str) -> TLSARecord:
    without_comment = line.split(";", 1)[0].strip()
    if not without_comment:
        raise ValueError("TLSA record line is empty")
    tokens = without_comment.split()
    if len(tokens) < 6:
        raise ValueError("TLSA record line is too short")
    owner = normalize_fqdn(tokens[0])
    index = 1
    ttl = 0
    if tokens[index].isdigit():
        ttl = int(tokens[index])
        index += 1
    if index < len(tokens) and tokens[index].upper() == "IN":
        index += 1
    if index >= len(tokens) or tokens[index].upper() != "TLSA":
        raise ValueError("record type must be TLSA")
    index += 1
    if len(tokens) - index < 4:
        raise ValueError("TLSA record is missing usage, selector, matching type, or association")
    usage = int(tokens[index])
    selector = int(tokens[index + 1])
    matching_type = int(tokens[index + 2])
    association = "".join(tokens[index + 3 :]).lower()
    bytes.fromhex(association)
    return TLSARecord(
        owner=owner,
        ttl=ttl,
        usage=usage,
        selector=selector,
        matching_type=matching_type,
        association=association,
    )


def tlsa_record_matches_certificate(cert: x509.Certificate, record: TLSARecord) -> bool:
    try:
        expected = certificate_association(
            cert,
            selector=record.selector,
            matching_type=record.matching_type,
        )
    except ValueError:
        return False
    return record.association.lower() == expected
