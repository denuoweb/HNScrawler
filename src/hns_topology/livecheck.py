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
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from cryptography import x509

from .dane import match_association_bytes, selected_certificate_bytes
from .db import insert_dns_evidence_batch, parse_json_columns, upsert_live_status
from .infra import NON_ACTIONABLE_PROVIDER_TYPES
from .models import FAILURE_REASONS, PROMISING_CLASSES, DnsEvidence, LiveStatus
from .timeutil import utc_after, utc_now

DNS_EVIDENCE_SERVER_LIMIT = 3


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


def run_live_checks(
    conn,
    *,
    limit: int | None,
    config: LiveCheckConfig,
    priority_names: Iterable[str] = (),
) -> int:
    rows = select_live_check_candidates(conn, limit=limit, priority_names=priority_names)
    limiter = RateLimiter(config.min_delay_ms)
    checked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        futures = [executor.submit(_check_name_with_evidence, row, config, limiter) for row in rows]
        for future in concurrent.futures.as_completed(futures):
            status, evidence = future.result()
            with conn:
                upsert_live_status(conn, status)
                if evidence:
                    insert_dns_evidence_batch(conn, evidence)
            checked += 1
    return checked


def _check_name_with_evidence(
    row: dict,
    config: LiveCheckConfig,
    limiter: RateLimiter,
) -> tuple[LiveStatus, list[DnsEvidence]]:
    status = check_name(row, config, limiter)
    evidence = collect_dns_evidence(row, config, limiter=limiter)
    return status, evidence


def count_live_check_candidates(conn) -> int:
    class_placeholders = ",".join("?" for _ in PROMISING_CLASSES)
    excluded_provider_placeholders = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    sql = f"""
      SELECT COUNT(*)
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN live_status ls ON ls.name = n.name
      LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
      WHERE n.expired = 0
        AND n.onchain_class IN ({class_placeholders})
        AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded_provider_placeholders})
        AND (ls.next_check_at IS NULL OR ls.next_check_at <= ?)
    """
    params: list = [*sorted(PROMISING_CLASSES), *NON_ACTIONABLE_PROVIDER_TYPES, utc_now()]
    row = conn.execute(sql, params).fetchone()
    return int(row[0] if row else 0)


def select_live_check_candidates(
    conn,
    *,
    limit: int | None,
    priority_names: Iterable[str] = (),
    ) -> list[dict]:
    class_placeholders = ",".join("?" for _ in PROMISING_CLASSES)
    excluded_provider_placeholders = ",".join("?" for _ in NON_ACTIONABLE_PROVIDER_TYPES)
    select_columns = (
        "n.name, n.onchain_class, rs.ns_names, rs.glue4, rs.glue6, "
        "rs.synth4, rs.synth6, rs.ds_records, rs.has_ds"
    )
    rows = []
    seen: set[str] = set()
    normalized_priority_names = [
        name.strip().lower().rstrip(".")
        for name in priority_names
        if name and name.strip()
    ]
    if normalized_priority_names:
        name_placeholders = ",".join("?" for _ in normalized_priority_names)
        priority_rows = conn.execute(
            f"""
            SELECT {select_columns}
            FROM names n
            JOIN resource_summary rs ON rs.name = n.name
            LEFT JOIN live_status ls ON ls.name = n.name
            WHERE n.expired = 0
              AND n.onchain_class IN ({class_placeholders})
              AND (ls.next_check_at IS NULL OR ls.next_check_at <= ?)
              AND n.name IN ({name_placeholders})
            ORDER BY n.name
            """,
            [*sorted(PROMISING_CLASSES), utc_now(), *normalized_priority_names],
        ).fetchall()
        for row in priority_rows:
            rows.append(row)
            seen.add(row["name"])

    remaining_limit = None if limit is None else max(0, limit - len(rows))
    if remaining_limit == 0:
        return [
            parse_json_columns(dict(row), ["ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records"])
            for row in rows
        ]

    exclusion = f"AND n.name NOT IN ({','.join('?' for _ in seen)})" if seen else ""
    sql = f"""
      SELECT {select_columns}
      FROM names n
      JOIN resource_summary rs ON rs.name = n.name
      LEFT JOIN live_status ls ON ls.name = n.name
      LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
      WHERE n.expired = 0
        AND n.onchain_class IN ({class_placeholders})
        AND COALESCE(ps.provider_type, 'unknown') NOT IN ({excluded_provider_placeholders})
        AND (ls.next_check_at IS NULL OR ls.next_check_at <= ?)
        {exclusion}
      ORDER BY n.updated_at DESC, n.name
    """
    params: list = [*sorted(PROMISING_CLASSES), *NON_ACTIONABLE_PROVIDER_TYPES, utc_now(), *sorted(seen)]
    if remaining_limit is not None:
        sql += " LIMIT ?"
        params.append(remaining_limit)
    rows.extend(conn.execute(sql, params).fetchall())
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
            if row.get("ns_names") and not _strict_bootstrap_addresses(row):
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


def collect_dns_evidence(
    row: dict,
    config: LiveCheckConfig,
    *,
    limiter: RateLimiter | None = None,
    source: str = "scanner",
    source_id: str = "",
) -> list[DnsEvidence]:
    name = str(row["name"]).strip().lower().rstrip(".")
    servers = sorted(set(_strict_bootstrap_addresses(row)))[:DNS_EVIDENCE_SERVER_LIMIT]
    if not name or not servers:
        return []
    queries = _dns_evidence_queries(name)
    captured: list[DnsEvidence] = []
    captured_at = utc_now()
    for server in servers:
        for qname, rrtype in queries:
            if limiter is not None:
                limiter.wait()
            captured.append(
                query_dns_evidence(
                    name=name,
                    server=server,
                    qname=qname,
                    rrtype=rrtype,
                    timeout=config.timeout,
                    source=source,
                    source_id=source_id,
                    captured_at=captured_at,
                )
            )
    return captured


def query_dns_evidence(
    *,
    name: str,
    server: str,
    qname: str,
    rrtype: str,
    timeout: float,
    source: str = "scanner",
    source_id: str = "",
    captured_at: str | None = None,
) -> DnsEvidence:
    captured_at = captured_at or utc_now()
    started = time.monotonic()
    try:
        query = dns.message.make_query(
            dns.name.from_text(_fqdn(qname)),
            dns.rdatatype.from_text(rrtype),
            want_dnssec=True,
        )
        query.flags &= ~dns.flags.RD
        response = dns.query.udp(query, server, timeout=timeout)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        rcode = dns.rcode.to_text(response.rcode())
        return DnsEvidence(
            name=name,
            qname=_fqdn(qname),
            rrtype=rrtype.upper(),
            server=server,
            source=source,
            source_id=source_id,
            status="ok" if response.rcode() == dns.rcode.NOERROR else "rcode",
            rcode=rcode,
            flags=dns.flags.to_text(response.flags),
            answer=_rrsets_to_text(response.answer),
            authority=_rrsets_to_text(response.authority),
            additional=_rrsets_to_text(response.additional),
            elapsed_ms=elapsed_ms,
            error=None,
            captured_at=captured_at,
        )
    except dns.exception.Timeout as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return _failed_dns_evidence(
            name=name,
            server=server,
            qname=qname,
            rrtype=rrtype,
            timeout_ms=elapsed_ms,
            source=source,
            source_id=source_id,
            captured_at=captured_at,
            status="timeout",
            error=type(exc).__name__,
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return _failed_dns_evidence(
            name=name,
            server=server,
            qname=qname,
            rrtype=rrtype,
            timeout_ms=elapsed_ms,
            source=source,
            source_id=source_id,
            captured_at=captured_at,
            status="error",
            error=type(exc).__name__,
        )


def _failed_dns_evidence(
    *,
    name: str,
    server: str,
    qname: str,
    rrtype: str,
    timeout_ms: int,
    source: str,
    source_id: str,
    captured_at: str,
    status: str,
    error: str,
) -> DnsEvidence:
    return DnsEvidence(
        name=name,
        qname=_fqdn(qname),
        rrtype=rrtype.upper(),
        server=server,
        source=source,
        source_id=source_id,
        status=status,
        rcode=None,
        flags=None,
        answer=[],
        authority=[],
        additional=[],
        elapsed_ms=timeout_ms,
        error=error,
        captured_at=captured_at,
    )


def _dns_evidence_queries(name: str) -> list[tuple[str, str]]:
    root = _fqdn(name)
    return [
        (root, "A"),
        (root, "AAAA"),
        (f"_443._tcp.{root}", "TLSA"),
        (f"_443._tcp.www.{root}", "TLSA"),
        (root, "DNSKEY"),
    ]


def _fqdn(value: str) -> str:
    text = str(value).strip()
    return text if text.endswith(".") else f"{text}."


def _rrsets_to_text(rrsets) -> list[str]:
    lines: list[str] = []
    for rrset in rrsets:
        lines.extend(line for line in rrset.to_text().splitlines() if line.strip())
    return lines


def _synth_addresses(row: dict) -> list[str]:
    return [*row.get("synth4", []), *row.get("synth6", [])]


def _glue_addresses(row: dict) -> list[str]:
    return [*row.get("glue4", []), *row.get("glue6", [])]


def _strict_bootstrap_addresses(row: dict) -> list[str]:
    return [*_glue_addresses(row), *_synth_addresses(row)]


def _strict_addresses(
    row: dict,
    strict_resolver: dns.resolver.Resolver | None,
    name: str,
) -> list[str]:
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
    bootstrap_addresses = sorted(set(_strict_bootstrap_addresses(row)))
    if not bootstrap_addresses:
        return None
    return _make_resolver(config, bootstrap_addresses)


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
        if row.get("ns_names") and not _strict_bootstrap_addresses(row):
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
        covers = getattr(rrset, "covers", None)
        covered = covers() if callable(covers) else covers
        if rrset.name == owner and rrset.rdtype == dns.rdatatype.RRSIG and covered == covered_type:
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
