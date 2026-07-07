from __future__ import annotations

import concurrent.futures
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.resolver
from cryptography import x509

from .dane import certificate_metadata_from_der, match_association_bytes, selected_certificate_bytes
from .db import insert_dns_evidence_batch, parse_json_columns, upsert_live_status
from .infra import NON_ACTIONABLE_PROVIDER_TYPES
from .models import FAILURE_REASONS, PROMISING_CLASSES, DnsEvidence, LiveStatus
from .timeutil import utc_after, utc_now

DNS_EVIDENCE_SERVER_LIMIT = 3
SVCB_PARAM_MANDATORY = int(dns.rdtypes.svcbbase.ParamKey.MANDATORY)
SVCB_PARAM_ALPN = int(dns.rdtypes.svcbbase.ParamKey.ALPN)
SVCB_PARAM_PORT = int(dns.rdtypes.svcbbase.ParamKey.PORT)
SVCB_PARAM_IPV4HINT = int(dns.rdtypes.svcbbase.ParamKey.IPV4HINT)
SVCB_PARAM_IPV6HINT = int(dns.rdtypes.svcbbase.ParamKey.IPV6HINT)
SVCB_PARAM_DOHPATH = int(dns.rdtypes.svcbbase.ParamKey.DOHPATH)
SVCB_SUPPORTED_MANDATORY_KEYS = {
    SVCB_PARAM_ALPN,
    SVCB_PARAM_PORT,
    SVCB_PARAM_IPV4HINT,
    SVCB_PARAM_IPV6HINT,
    SVCB_PARAM_DOHPATH,
}


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
        "rs.synth4, rs.synth6, rs.ds_records, rs.authoritative_doh, rs.has_ds"
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
            parse_json_columns(
                dict(row),
                ["ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records", "authoritative_doh"],
            )
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
        parse_json_columns(
            dict(row),
            ["ns_names", "glue4", "glue6", "synth4", "synth6", "ds_records", "authoritative_doh"],
        )
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
    https_result: HttpsResult | None = None

    fallback_resolver = _make_resolver(config)
    strict_resolver = _make_strict_resolver(row, config)
    strict_doh_endpoints = _strict_doh_endpoints(row, strict_resolver)

    try:
        limiter.wait()
        dnssec_result = _validate_dnssec_for_row(strict_resolver, row, name, strict_doh_endpoints)
        dnssec_status = dnssec_result.status
        strict_address_result = _strict_address_resolution(strict_resolver, name, dnssec_result, strict_doh_endpoints)
        strict_addresses = strict_address_result.addresses
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
            if strict_resolver and strict_doh_endpoints:
                tlsa_result = _resolve_tlsa_secure(strict_resolver, name, dnssec_result, strict_doh_endpoints)
            elif strict_resolver:
                tlsa_result = _resolve_tlsa_secure(strict_resolver, name, dnssec_result)
            else:
                tlsa_result = TlsaResolution([])
            tlsa_records = tlsa_result.records
            if tlsa_records:
                tlsa_status = "present"
                if (
                    bool(strict_addresses)
                    and
                    dnssec_result.status == "valid"
                    and strict_address_result.secure
                    and tlsa_result.secure
                    and https_result.cert_der
                    and _match_any_tlsa(https_result.cert_der, tlsa_records)
                ):
                    dane_status = "valid"
                    strict_hns_status = "working"
                    failure_reason = None
                else:
                    dane_status = "invalid"
                    dnssec_failure = None
                    if dnssec_result.status != "valid":
                        dnssec_failure = dnssec_result.failure_reason
                    elif not strict_address_result.secure or not tlsa_result.secure:
                        dnssec_failure = "dnssec_missing"
                    failure_reason = _choose_failure(
                        dnssec_failure,
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
        https_cert_sha256=https_result.cert_sha256 if https_result is not None else None,
        https_spki_sha256=https_result.spki_sha256 if https_result is not None else None,
        https_cert_not_valid_after=https_result.cert_not_valid_after if https_result is not None else None,
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


def _strict_doh_endpoints(
    row: dict,
    strict_resolver: dns.resolver.Resolver | None = None,
) -> list[dict]:
    bootstrap_addresses = sorted(set(_strict_bootstrap_addresses(row)))
    ns_names = sorted({str(ns).strip().rstrip(".").lower() for ns in row.get("ns_names", []) if str(ns).strip()})
    if not bootstrap_addresses or not ns_names or strict_resolver is None:
        return []
    endpoints: list[dict] = []
    for ns in ns_names:
        answer = _strict_resolve_rrset(strict_resolver, f"_dns.{ns}", "SVCB")
        if answer is None:
            continue
        for item in answer.rrset:
            endpoints.extend(_doh_endpoints_from_svcb_rdata(ns, item, bootstrap_addresses))
    return endpoints


def _safe_port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _svcb_param(params, key: int):
    return params.get(dns.rdtypes.svcbbase.ParamKey(key)) or params.get(key)


def _doh_endpoints_from_svcb_rdata(ns: str, item, bootstrap_addresses: list[str]) -> list[dict]:
    priority = int(getattr(item, "priority", 0))
    if priority == 0 or not _svcb_mandatory_keys_supported(item):
        return []
    target = str(getattr(item, "target", "")).strip().rstrip(".").lower()
    if target in {"", "."}:
        target = ns
    if target != ns:
        return []
    params = getattr(item, "params", {})
    alpn = _svcb_param(params, SVCB_PARAM_ALPN)
    alpn_ids = tuple(getattr(alpn, "ids", ()))
    if b"h2" not in alpn_ids:
        return []
    dohpath = _svcb_param(params, SVCB_PARAM_DOHPATH)
    path = _normalize_dohpath(getattr(dohpath, "value", None))
    if path is None:
        return []
    port_param = _svcb_param(params, SVCB_PARAM_PORT)
    port = _safe_port(getattr(port_param, "port", None) if port_param is not None else None) or 443
    return [
        {
            "host": ns,
            "path": path,
            "port": port,
            "bootstrap_address": address,
            "url": f"https://{ns}{'' if port == 443 else f':{port}'}{path}",
        }
        for address in bootstrap_addresses
    ]


def _svcb_mandatory_keys_supported(item) -> bool:
    params = getattr(item, "params", {})
    mandatory = _svcb_param(params, SVCB_PARAM_MANDATORY)
    if mandatory is None:
        return True
    keys = getattr(mandatory, "keys", ())
    return all(int(key) in SVCB_SUPPORTED_MANDATORY_KEYS for key in keys)


def _normalize_dohpath(value) -> str | None:
    if not isinstance(value, bytes):
        return None
    try:
        template = value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if "dns" not in template:
        return None
    if template.endswith("{?dns}"):
        template = template[: -len("{?dns}")]
    if not template.startswith("/") or any(char.isspace() for char in template) or "#" in template:
        return None
    return template


def _strict_addresses(
    row: dict,
    strict_resolver: dns.resolver.Resolver | None,
    name: str,
) -> list[str]:
    if strict_resolver is None:
        return []
    return _resolve_strict_addresses(strict_resolver, name)


def _strict_address_resolution(
    strict_resolver: dns.resolver.Resolver | None,
    name: str,
    dnssec_result: DnssecResult,
    doh_endpoints: list[dict] | None = None,
) -> AddressResolution:
    if strict_resolver is None:
        return AddressResolution([])
    if doh_endpoints:
        return _resolve_strict_address_resolution(strict_resolver, name, dnssec_result, doh_endpoints)
    return _resolve_strict_address_resolution(strict_resolver, name, dnssec_result)


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
    dnskey_rrset: object | None = None


@dataclass(frozen=True)
class StrictAnswer:
    rrset: object
    response: object


@dataclass(frozen=True)
class AddressResolution:
    addresses: list[str]
    secure: bool = False


@dataclass(frozen=True)
class TlsaResolution:
    records: list[tuple[int, int, int, bytes]]
    secure: bool = False


def _validate_dnssec_for_row(
    strict_resolver: dns.resolver.Resolver | None,
    row: dict,
    name: str,
    doh_endpoints: list[dict] | None = None,
) -> DnssecResult:
    ds_records = row.get("ds_records", [])
    if not ds_records:
        return DnssecResult("not_delegated")
    if strict_resolver is None:
        if row.get("ns_names") and not _strict_bootstrap_addresses(row):
            return DnssecResult("missing_glue", "missing_glue")
        return DnssecResult("dnssec_missing", "dnssec_missing")
    if doh_endpoints:
        return _validate_dnssec_delegation(strict_resolver, name, ds_records, doh_endpoints)
    return _validate_dnssec_delegation(strict_resolver, name, ds_records)


def _validate_dnssec_delegation(
    resolver: dns.resolver.Resolver,
    name: str,
    ds_records: list[dict],
    doh_endpoints: list[dict] | None = None,
) -> DnssecResult:
    if not ds_records:
        return DnssecResult("not_delegated")
    owner = dns.name.from_text(name.rstrip(".") + ".")
    answer = (
        _strict_resolve_rrset(resolver, owner.to_text(), "DNSKEY", doh_endpoints)
        if doh_endpoints
        else _strict_resolve_rrset(resolver, owner.to_text(), "DNSKEY")
    )
    if answer is None:
        return DnssecResult("missing_dnskey", "dnssec_missing")

    dnskey_rrset = answer.rrset
    if not _ds_matches_dnskey(owner, ds_records, dnskey_rrset):
        return DnssecResult("ds_dnskey_mismatch", "ds_dnskey_mismatch")

    rrsig_rrset = _find_rrsig(answer.response, owner, dns.rdatatype.DNSKEY)
    if rrsig_rrset is None:
        return DnssecResult("missing_rrsig", "dnssec_missing")
    try:
        dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {owner: dnskey_rrset})
    except dns.dnssec.ValidationFailure as exc:
        if "expired" in str(exc).lower():
            return DnssecResult("rrsig_expired", "rrsig_expired")
        return DnssecResult("bogus", "dnssec_bogus")
    except (dns.exception.DNSException, TypeError, ValueError):
        return DnssecResult("bogus", "dnssec_bogus")
    return DnssecResult("valid", dnskey_rrset=dnskey_rrset)


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
            except (dns.exception.DNSException, TypeError, ValueError):
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


def _rrset_signature_valid(
    rrset,
    response,
    key_owner: dns.name.Name,
    dnskey_rrset,
) -> bool:
    rrsig_rrset = _find_rrsig(response, rrset.name, rrset.rdtype)
    if rrsig_rrset is None:
        return False
    try:
        dns.dnssec.validate(rrset, rrsig_rrset, {key_owner: dnskey_rrset})
    except (dns.exception.DNSException, TypeError, ValueError):
        return False
    return True


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
        "certificate_expired": 55,
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


def _resolve_strict_addresses(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    return _resolve_strict_address_resolution(resolver, name, DnssecResult("not_delegated")).addresses


def _resolve_strict_address_resolution(
    resolver: dns.resolver.Resolver,
    name: str,
    dnssec_result: DnssecResult,
    doh_endpoints: list[dict] | None = None,
) -> AddressResolution:
    addresses: list[str] = []
    secure_checks: list[bool] = []
    key_owner = dns.name.from_text(_fqdn(name))
    for rrtype in ("A", "AAAA"):
        answer = (
            _strict_resolve_rrset(resolver, name, rrtype, doh_endpoints)
            if doh_endpoints
            else _strict_resolve_rrset(resolver, name, rrtype)
        )
        if answer is not None:
            addresses.extend(item.to_text() for item in answer.rrset)
            if dnssec_result.status == "valid" and dnssec_result.dnskey_rrset is not None:
                secure_checks.append(
                    _rrset_signature_valid(answer.rrset, answer.response, key_owner, dnssec_result.dnskey_rrset)
                )
    secure = bool(addresses) and bool(secure_checks) and all(secure_checks)
    return AddressResolution(addresses=addresses, secure=secure)


def _strict_resolve_rrset(
    resolver: dns.resolver.Resolver,
    name: str,
    rrtype: str,
    doh_endpoints: list[dict] | None = None,
) -> StrictAnswer | None:
    qname = dns.name.from_text(_fqdn(name))
    rdtype = dns.rdatatype.from_text(rrtype)
    for server in resolver.nameservers:
        answer = _strict_answer_from_transport(
            lambda server=server: dns.query.udp(
                _strict_query(qname, rdtype),
                server,
                timeout=resolver.timeout,
                raise_on_truncation=True,
            ),
            qname,
            rdtype,
        )
        if answer is not None:
            return answer
        answer = _strict_answer_from_transport(
            lambda server=server: dns.query.tcp(
                _strict_query(qname, rdtype),
                server,
                timeout=resolver.timeout,
            ),
            qname,
            rdtype,
        )
        if answer is not None:
            return answer
    for endpoint in doh_endpoints or []:
        answer = _strict_answer_from_transport(
            lambda endpoint=endpoint: dns.query.https(
                _strict_query(qname, rdtype, zero_id=True),
                endpoint["host"],
                timeout=resolver.timeout,
                port=int(endpoint["port"]),
                path=endpoint["path"],
                post=True,
                bootstrap_address=endpoint["bootstrap_address"],
                # HNS nameserver DoH transport is authenticated by the DNSSEC data path below.
                # WebPKI validation would reject DANE/self-signed HNS nameserver certificates.
                verify=False,
            ),
            qname,
            rdtype,
        )
        if answer is not None:
            return answer
    return None


def _strict_query(qname: dns.name.Name, rdtype, *, zero_id: bool = False):
    query = dns.message.make_query(qname, rdtype, want_dnssec=True)
    if zero_id:
        query.id = 0
    query.flags &= ~dns.flags.RD
    return query


def _strict_answer_from_transport(
    response_factory: Callable[[], dns.message.Message],
    qname: dns.name.Name,
    rdtype,
) -> StrictAnswer | None:
    try:
        response = response_factory()
    except Exception as exc:
        if not _is_strict_transport_error(exc):
            raise
        return None
    return _strict_answer_from_response(response, qname, rdtype)


def _is_strict_transport_error(exc: Exception) -> bool:
    if isinstance(exc, (dns.exception.DNSException, OSError, TimeoutError, ValueError, KeyError)):
        return True
    return type(exc).__module__.partition(".")[0] in {"httpx", "httpcore", "requests", "urllib3"}


def _strict_answer_from_response(response, qname: dns.name.Name, rdtype) -> StrictAnswer | None:
    if response.rcode() != dns.rcode.NOERROR:
        return None
    if not response.flags & dns.flags.AA:
        return None
    if response.flags & dns.flags.RA:
        return None
    for rrset in response.answer:
        if rrset.name == qname and rrset.rdtype == rdtype:
            return StrictAnswer(rrset=rrset, response=response)
    return None


def _resolve_tlsa_secure(
    resolver: dns.resolver.Resolver,
    name: str,
    dnssec_result: DnssecResult,
    doh_endpoints: list[dict] | None = None,
) -> TlsaResolution:
    records: list[tuple[int, int, int, bytes]] = []
    secure_checks: list[bool] = []
    key_owner = dns.name.from_text(_fqdn(name))
    owner = f"_443._tcp.{name}"
    answer = (
        _strict_resolve_rrset(resolver, owner, "TLSA", doh_endpoints)
        if doh_endpoints
        else _strict_resolve_rrset(resolver, owner, "TLSA")
    )
    if answer is None:
        return TlsaResolution(records)
    for item in answer.rrset:
        records.append((int(item.usage), int(item.selector), int(item.mtype), bytes(item.cert)))
    if dnssec_result.status == "valid" and dnssec_result.dnskey_rrset is not None:
        secure_checks.append(
            _rrset_signature_valid(answer.rrset, answer.response, key_owner, dnssec_result.dnskey_rrset)
        )
    secure = bool(records) and bool(secure_checks) and all(secure_checks)
    return TlsaResolution(records=records, secure=secure)


def _resolve_tlsa(resolver: dns.resolver.Resolver, name: str) -> list[tuple[int, int, int, bytes]]:
    return _resolve_tlsa_secure(resolver, name, DnssecResult("not_delegated")).records


@dataclass(frozen=True)
class HttpsResult:
    status: str
    cert_der: bytes | None
    failure_reason: str | None = None
    cert_sha256: str | None = None
    spki_sha256: str | None = None
    cert_not_valid_after: str | None = None


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
    except ssl.SSLCertVerificationError as exc:
        certificate_failure = _certificate_failure_reason(exc)
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
                failure_reason=certificate_failure,
            )
        except (OSError, ssl.SSLError):
            return HttpsResult("failed", None, certificate_failure)
    except (OSError, ssl.SSLError):
        return HttpsResult("failed", None, "https_connect_failed")


def _certificate_failure_reason(exc: ssl.SSLCertVerificationError) -> str:
    verify_code = getattr(exc, "verify_code", None)
    verify_message = str(getattr(exc, "verify_message", "") or "")
    text = f"{verify_message} {exc}".lower()
    if verify_code == 10 or "expired" in text or "not valid after" in text:
        return "certificate_expired"
    return "certificate_mismatch"


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
        return _https_result(status, tls.getpeercert(binary_form=True), failure_reason)


def _https_result(status: str, cert_der: bytes | None, failure_reason: str | None) -> HttpsResult:
    if not cert_der:
        return HttpsResult(status, cert_der, failure_reason)
    try:
        metadata = certificate_metadata_from_der(cert_der)
    except ValueError:
        return HttpsResult(status, cert_der, failure_reason)
    return HttpsResult(
        status,
        cert_der,
        failure_reason,
        cert_sha256=metadata.sha256,
        spki_sha256=metadata.spki_sha256,
        cert_not_valid_after=metadata.not_valid_after,
    )


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
