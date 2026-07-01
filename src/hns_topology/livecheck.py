from __future__ import annotations

import concurrent.futures
import hashlib
import socket
import ssl
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass

import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .db import parse_json_columns, upsert_live_status
from .models import FAILURE_REASONS, PROMISING_CLASSES, LiveStatus
from .timeutil import utc_after, utc_now


@dataclass(frozen=True)
class LiveCheckConfig:
    timeout: float = 5.0
    concurrency: int = 4
    min_delay_ms: int = 250
    recheck_seconds: int = 7 * 24 * 60 * 60
    resolver: str | None = None


class RateLimiter:
    def __init__(self, min_delay_ms: int):
        self.min_delay = min_delay_ms / 1000
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = self.min_delay - (now - self.last)
            if delay > 0:
                time.sleep(delay)
            self.last = time.monotonic()


def run_live_checks(conn, *, limit: int | None, config: LiveCheckConfig) -> int:
    rows = select_live_check_candidates(conn, limit=limit)
    limiter = RateLimiter(config.min_delay_ms)
    checked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        futures = [executor.submit(check_name, row, config, limiter) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            status = future.result()
            with conn:
                upsert_live_status(conn, status)
            checked += 1
    return checked


def select_live_check_candidates(conn, *, limit: int | None) -> list[dict]:
    class_placeholders = ",".join("?" for _ in PROMISING_CLASSES)
    sql = f"""
      SELECT n.name, n.onchain_class, rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.has_ds
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN live_status ls ON ls.name = n.name
      WHERE n.expired = 0
        AND n.onchain_class IN ({class_placeholders})
        AND (ls.next_check_at IS NULL OR ls.next_check_at <= ?)
      ORDER BY n.updated_at DESC, n.name
    """
    params: list = [*sorted(PROMISING_CLASSES), utc_now()]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [
        parse_json_columns(dict(row), ["ns_names", "glue4", "glue6", "synth4", "synth6"])
        for row in rows
    ]


def check_name(row: dict, config: LiveCheckConfig, limiter: RateLimiter) -> LiveStatus:
    name = row["name"]
    checked_at = utc_now()
    next_check_at = utc_after(config.recheck_seconds)
    dns_reachable = "unknown"
    dnssec_status = "unknown"
    tlsa_status = "unknown"
    dane_status = "unknown"
    https_status = "unknown"
    strict_hns_status = "unknown"
    doh_fallback_status = "not_checked"
    failure_reason = None

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = config.timeout
    resolver.timeout = config.timeout
    if config.resolver:
        resolver.nameservers = [config.resolver]

    try:
        addresses = sorted(set(_configured_addresses(row) + _resolve_addresses(resolver, name)))
        if not addresses:
            failure_reason = "no_a_or_aaaa"
            dns_reachable = "no_address"
        else:
            dns_reachable = "reachable"
            strict_hns_status = "candidate"
            https_result = _https_connect(name, addresses[0], config.timeout)
            https_status = https_result.status
            if https_result.status != "working":
                failure_reason = "https_connect_failed"
            tlsa_records = _resolve_tlsa(resolver, name)
            if tlsa_records:
                tlsa_status = "present"
                if https_result.cert_der and _match_any_tlsa(https_result.cert_der, tlsa_records):
                    dane_status = "valid"
                    strict_hns_status = "working"
                else:
                    dane_status = "invalid"
                    failure_reason = "stale_tlsa_spki_mismatch"
            else:
                tlsa_status = "missing"
                if failure_reason is None:
                    failure_reason = "tlsa_missing"
            dnssec_status = "candidate" if row.get("has_ds") else "not_delegated"
    except dns.resolver.NXDOMAIN:
        dns_reachable = "nxdomain"
        failure_reason = "no_a_or_aaaa"
    except dns.exception.Timeout:
        dns_reachable = "timeout"
        failure_reason = "nameserver_unreachable_udp"
    except Exception:
        failure_reason = "unknown_error"

    if failure_reason not in FAILURE_REASONS and failure_reason is not None:
        failure_reason = "unknown_error"

    return LiveStatus(
        name=name,
        dns_reachable=dns_reachable,
        dnssec_status=dnssec_status,
        tlsa_status=tlsa_status,
        dane_status=dane_status,
        https_status=https_status,
        strict_hns_status=strict_hns_status,
        doh_fallback_status=doh_fallback_status,
        failure_reason=failure_reason,
        checked_at=checked_at,
        next_check_at=next_check_at,
    )


def _configured_addresses(row: dict) -> list[str]:
    return [*row.get("synth4", []), *row.get("synth6", []), *row.get("glue4", []), *row.get("glue6", [])]


def _resolve_addresses(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    addresses: list[str] = []
    for rrtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(name, rrtype)
            addresses.extend([item.to_text() for item in answer])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
    return addresses


def _resolve_tlsa(resolver: dns.resolver.Resolver, name: str) -> list[tuple[int, int, int, bytes]]:
    records: list[tuple[int, int, int, bytes]] = []
    for owner in (f"_443._tcp.{name}", f"_443._tcp.www.{name}"):
        try:
            answer = resolver.resolve(owner, "TLSA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
        for item in answer:
            records.append((int(item.usage), int(item.selector), int(item.mtype), bytes(item.cert)))
    return records


@dataclass(frozen=True)
class HttpsResult:
    status: str
    cert_der: bytes | None


def _https_connect(hostname: str, address: str, timeout: float) -> HttpsResult:
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((address, 443), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as tls,
        ):
            return HttpsResult("working", tls.getpeercert(binary_form=True))
    except Exception:
        return HttpsResult("failed", None)


def _match_any_tlsa(cert_der: bytes, records: Iterable[tuple[int, int, int, bytes]]) -> bool:
    cert = x509.load_der_x509_certificate(cert_der)
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chain_items = {0: cert_der, 1: spki_der}
    for usage, selector, matching_type, association in records:
        if usage not in {0, 1, 2, 3}:
            continue
        selected = chain_items.get(selector)
        if selected is None:
            continue
        if _match_association(selected, matching_type, association):
            return True
    return False


def _match_association(selected: bytes, matching_type: int, association: bytes) -> bool:
    if matching_type == 0:
        return selected == association
    if matching_type == 1:
        return hashlib.sha256(selected).digest() == association
    if matching_type == 2:
        return hashlib.sha512(selected).digest() == association
    return False
