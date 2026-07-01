from __future__ import annotations

import concurrent.futures
import socket
import ssl
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass

import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver
from cryptography import x509

from .dane import match_association_bytes, selected_certificate_bytes
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


def count_live_check_candidates(conn) -> int:
    class_placeholders = ",".join("?" for _ in PROMISING_CLASSES)
    sql = f"""
      SELECT COUNT(*)
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN live_status ls ON ls.name = n.name
      WHERE n.expired = 0
        AND n.onchain_class IN ({class_placeholders})
        AND (ls.next_check_at IS NULL OR ls.next_check_at <= ?)
    """
    params: list = [*sorted(PROMISING_CLASSES), utc_now()]
    row = conn.execute(sql, params).fetchone()
    return int(row[0] if row else 0)


def select_live_check_candidates(conn, *, limit: int | None) -> list[dict]:
    class_placeholders = ",".join("?" for _ in PROMISING_CLASSES)
    sql = f"""
      SELECT n.name, n.onchain_class, rs.ns_names, rs.glue4, rs.glue6, rs.synth4, rs.synth6, rs.ds_records, rs.has_ds
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
        parse_json_columns(dict(row), ["ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"])
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

    fallback_resolver = _make_resolver(config)
    strict_resolver = _make_strict_resolver(row, config)

    try:
        limiter.wait()
        dnssec_result = _validate_dnssec_for_row(strict_resolver, row, name)
        dnssec_status = dnssec_result.status
        strict_addresses = _strict_addresses(row, strict_resolver, name)
        fallback_addresses: list[str] = []
        addresses = strict_addresses
        if strict_addresses:
            doh_fallback_status = "not_required"
        else:
            if row.get("ns_names") and not _glue_addresses(row):
                dns_reachable = "missing_glue"
                failure_reason = "missing_glue"
            fallback_addresses = _resolve_addresses(fallback_resolver, name)
            if fallback_addresses:
                doh_fallback_status = "required"
                strict_hns_status = "fallback_only"
                addresses = fallback_addresses
        if not addresses:
            failure_reason = _choose_failure(failure_reason, "no_a_or_aaaa")
            dns_reachable = dns_reachable if dns_reachable != "unknown" else "no_address"
        else:
            dns_reachable = "reachable" if strict_addresses else "fallback_reachable"
            if strict_addresses:
                strict_hns_status = "candidate"
            https_result = _https_connect(name, addresses[0], config.timeout)
            https_status = https_result.status
            if fallback_addresses and https_result.failure_reason:
                failure_reason = https_result.failure_reason
            else:
                failure_reason = _choose_failure(failure_reason, https_result.failure_reason)
            tlsa_resolver = strict_resolver
            tlsa_records = _resolve_tlsa(tlsa_resolver, name) if tlsa_resolver else []
            if tlsa_records:
                tlsa_status = "present"
                if (
                    bool(strict_addresses)
                    and
                    dnssec_result.status == "valid"
                    and https_result.cert_der
                    and _match_any_tlsa(https_result.cert_der, tlsa_records)
                ):
                    dane_status = "valid"
                    strict_hns_status = "working"
                    failure_reason = None
                else:
                    dane_status = "invalid"
                    failure_reason = _choose_failure(
                        dnssec_result.failure_reason,
                        "stale_tlsa_spki_mismatch" if https_result.cert_der else "https_connect_failed",
                    )
            else:
                tlsa_status = "missing"
                if failure_reason is None and row.get("has_ds"):
                    failure_reason = "tlsa_missing"
            if strict_addresses and https_result.status == "working" and strict_hns_status != "working":
                strict_hns_status = "working"
            failure_reason = _choose_failure(failure_reason, dnssec_result.failure_reason)
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


def _synth_addresses(row: dict) -> list[str]:
    return [*row.get("synth4", []), *row.get("synth6", [])]


def _glue_addresses(row: dict) -> list[str]:
    return [*row.get("glue4", []), *row.get("glue6", [])]


def _strict_addresses(
    row: dict,
    strict_resolver: dns.resolver.Resolver | None,
    name: str,
) -> list[str]:
    synth = _synth_addresses(row)
    if synth:
        return sorted(set(synth))
    if strict_resolver is None:
        return []
    return _resolve_addresses(strict_resolver, name)


def _make_resolver(
    config: LiveCheckConfig,
    nameservers: list[str] | None = None,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=nameservers is None)
    resolver.lifetime = config.timeout
    resolver.timeout = config.timeout
    resolver.use_edns(edns=True, ednsflags=dns.flags.DO, payload=1232)
    if nameservers is not None:
        resolver.nameservers = nameservers
    elif config.resolver:
        resolver.nameservers = [config.resolver]
    return resolver


def _make_strict_resolver(row: dict, config: LiveCheckConfig) -> dns.resolver.Resolver | None:
    glue = _glue_addresses(row)
    if not glue:
        return None
    return _make_resolver(config, glue)


@dataclass(frozen=True)
class DnssecResult:
    status: str
    failure_reason: str | None = None


def _validate_dnssec_for_row(
    strict_resolver: dns.resolver.Resolver | None,
    row: dict,
    name: str,
) -> DnssecResult:
    ds_records = row.get("ds_records", [])
    if not ds_records:
        return DnssecResult("not_delegated")
    if strict_resolver is None:
        if row.get("ns_names") and not _glue_addresses(row):
            return DnssecResult("missing_glue", "missing_glue")
        return DnssecResult("dnssec_missing", "dnssec_missing")
    return _validate_dnssec_delegation(strict_resolver, name, ds_records)


def _validate_dnssec_delegation(
    resolver: dns.resolver.Resolver,
    name: str,
    ds_records: list[dict],
) -> DnssecResult:
    if not ds_records:
        return DnssecResult("not_delegated")
    owner = dns.name.from_text(name.rstrip(".") + ".")
    try:
        answer = resolver.resolve(owner, "DNSKEY", raise_on_no_answer=False)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return DnssecResult("missing_dnskey", "dnssec_missing")
    except dns.exception.Timeout:
        return DnssecResult("timeout", "nameserver_unreachable_udp")
    except Exception:
        return DnssecResult("unknown_error", "unknown_error")

    dnskey_rrset = answer.rrset
    if dnskey_rrset is None:
        return DnssecResult("missing_dnskey", "dnssec_missing")

    if not _ds_matches_dnskey(owner, ds_records, dnskey_rrset):
        return DnssecResult("ds_dnskey_mismatch", "ds_dnskey_mismatch")

    rrsig_rrset = _find_rrsig(answer.response, owner, dns.rdatatype.DNSKEY)
    if rrsig_rrset is None:
        return DnssecResult("valid")
    try:
        dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {owner: dnskey_rrset})
    except dns.dnssec.ValidationFailure as exc:
        if "expired" in str(exc).lower():
            return DnssecResult("rrsig_expired", "rrsig_expired")
        return DnssecResult("bogus", "dnssec_bogus")
    except Exception:
        return DnssecResult("bogus", "dnssec_bogus")
    return DnssecResult("valid")


def _ds_matches_dnskey(
    owner: dns.name.Name,
    ds_records: list[dict],
    dnskey_rrset,
) -> bool:
    for dnskey in dnskey_rrset:
        for ds_record in ds_records:
            digest_type = ds_record.get("digestType")
            expected_digest = str(ds_record.get("digest") or "").lower()
            if not digest_type or not expected_digest:
                continue
            if ds_record.get("algorithm") is not None and int(ds_record["algorithm"]) != int(dnskey.algorithm):
                continue
            if ds_record.get("keyTag") is not None and int(ds_record["keyTag"]) != dns.dnssec.key_id(dnskey):
                continue
            try:
                computed = dns.dnssec.make_ds(owner, dnskey, int(digest_type), validating=True)
            except Exception:
                continue
            if computed.digest.hex().lower() == expected_digest:
                return True
    return False


def _find_rrsig(response, owner: dns.name.Name, covered_type: dns.rdatatype.RdataType):
    for rrset in response.answer:
        if rrset.name == owner and rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers() == covered_type:
            return rrset
    return None


def _choose_failure(current: str | None, candidate: str | None) -> str | None:
    if current is None:
        return candidate
    if candidate is None:
        return current
    priorities = {
        "tlsa_missing": 10,
        "certificate_mismatch": 20,
        "missing_glue": 45,
        "dnssec_missing": 60,
        "dnssec_bogus": 60,
        "ds_dnskey_mismatch": 60,
        "rrsig_expired": 60,
        "https_connect_failed": 35,
        "no_a_or_aaaa": 40,
        "stale_tlsa_spki_mismatch": 50,
    }
    return candidate if priorities.get(candidate, 0) > priorities.get(current, 0) else current


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
    failure_reason: str | None = None


def _https_connect(hostname: str, address: str, timeout: float) -> HttpsResult:
    verified_context = ssl.create_default_context()
    try:
        return _tls_connect(
            hostname,
            address,
            timeout,
            verified_context,
            status="working",
            failure_reason=None,
        )
    except ssl.SSLCertVerificationError:
        unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE
        try:
            return _tls_connect(
                hostname,
                address,
                timeout,
                unverified_context,
                status="tls_unverified",
                failure_reason="certificate_mismatch",
            )
        except Exception:
            return HttpsResult("failed", None, "https_connect_failed")
    except Exception:
        return HttpsResult("failed", None, "https_connect_failed")


def _tls_connect(
    hostname: str,
    address: str,
    timeout: float,
    context: ssl.SSLContext,
    *,
    status: str,
    failure_reason: str | None,
) -> HttpsResult:
    with (
        socket.create_connection((address, 443), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as tls,
    ):
        return HttpsResult(status, tls.getpeercert(binary_form=True), failure_reason)


def _match_any_tlsa(cert_der: bytes, records: Iterable[tuple[int, int, int, bytes]]) -> bool:
    cert = x509.load_der_x509_certificate(cert_der)
    for usage, selector, matching_type, association in records:
        if usage not in {0, 1, 2, 3}:
            continue
        try:
            selected = selected_certificate_bytes(cert, selector=selector)
        except ValueError:
            continue
        if _match_association(selected, matching_type, association):
            return True
    return False


def _match_association(selected: bytes, matching_type: int, association: bytes) -> bool:
    try:
        return match_association_bytes(selected, matching_type=matching_type) == association
    except ValueError:
        return False
