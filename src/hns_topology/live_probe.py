from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .dane import TLSARecord, certificate_metadata_from_der, tlsa_record_matches_certificate
from .live_candidates import host_from_dns_owner
from .live_models import (
    CATEGORY_HTTP_ONLY,
    CATEGORY_HTTPS,
    CATEGORY_OFFLINE,
    DnsProbeResult,
    HostProbeResult,
    WebProbeResult,
)
from .timeutil import utc_now

USER_AGENT = "Denuo-HNS-Live-Directory/0.1"


@dataclass(frozen=True)
class ProbeConfig:
    timeout: float = 5.0
    max_nameservers: int = 3
    max_addresses: int = 4
    fallback_resolver: str | None = None
    user_agent: str = USER_AGENT


class RateLimiter:
    def __init__(self, min_delay_ms: int):
        self._delay = max(0, min_delay_ms) / 1000
        self._lock = threading.Lock()
        self._last_started = 0.0

    def wait(self) -> None:
        with self._lock:
            delay = self._delay - (time.monotonic() - self._last_started)
            if delay > 0:
                time.sleep(delay)
            self._last_started = time.monotonic()


def probe_host(
    candidate: dict[str, Any],
    *,
    config: ProbeConfig,
    limiter: RateLimiter | None = None,
) -> HostProbeResult:
    started = time.monotonic()
    checked_at = utc_now()
    root_name = str(candidate["root_name"])
    host = str(candidate["host"])
    resource_hash = str(candidate["topology_resource_hash"])
    try:
        if limiter is not None:
            limiter.wait()
        dns_result = probe_dns(candidate, config=config)
        http_result = _probe_web(host, dns_result.addresses, scheme="http", config=config)
        https_result, dane_status = _probe_authenticated_https(
            host,
            dns_result,
            config=config,
        )
        category, canonical_url, https_status = _classify_web(
            host,
            http_result=http_result,
            https_result=https_result,
            dane_status=dane_status,
        )
        failure_reason = _failure_reason(
            category,
            dns_result=dns_result,
            http_result=http_result,
            https_result=https_result,
        )
        return HostProbeResult(
            root_name=root_name,
            host=host,
            topology_resource_hash=resource_hash,
            category=category,
            canonical_url=canonical_url,
            dns_status=dns_result.status,
            addresses=dns_result.addresses,
            dnssec_status=dns_result.dnssec_status,
            tlsa_status=dns_result.tlsa_status,
            tlsa_records=dns_result.tlsa_records,
            dane_status=dane_status,
            http_status=http_result.status,
            http_status_code=http_result.status_code,
            http_location=http_result.location,
            https_status=https_status,
            https_status_code=https_result.status_code,
            https_location=https_result.location,
            webpki_status=https_result.webpki_status,
            certificate_sha256=https_result.certificate_sha256,
            spki_sha256=https_result.spki_sha256,
            certificate_not_valid_after=https_result.certificate_not_valid_after,
            failure_reason=failure_reason,
            discovered_hosts=dns_result.discovered_hosts,
            checked_at=checked_at,
            duration_ms=round((time.monotonic() - started) * 1000),
        )
    except Exception as exc:
        return HostProbeResult(
            root_name=root_name,
            host=host,
            topology_resource_hash=resource_hash,
            category=CATEGORY_OFFLINE,
            canonical_url="",
            dns_status="error",
            addresses=[],
            dnssec_status="unknown",
            tlsa_status="unknown",
            tlsa_records=[],
            dane_status="unknown",
            http_status="failed",
            http_status_code=None,
            http_location="",
            https_status="failed",
            https_status_code=None,
            https_location="",
            webpki_status="not_checked",
            certificate_sha256="",
            spki_sha256="",
            certificate_not_valid_after="",
            failure_reason=f"probe_error:{type(exc).__name__}",
            discovered_hosts=[],
            checked_at=checked_at,
            duration_ms=round((time.monotonic() - started) * 1000),
        )


def probe_dns(candidate: dict[str, Any], *, config: ProbeConfig) -> DnsProbeResult:
    root_name = str(candidate["root_name"])
    host = str(candidate["host"])
    servers = [
        address for address in candidate.get("bootstrap_addresses", []) if _public_ip(address)
    ][: config.max_nameservers]
    if not servers:
        servers = _resolve_nameserver_addresses(
            candidate.get("ns_names", []),
            timeout=config.timeout,
            resolver_address=config.fallback_resolver,
            limit=config.max_nameservers,
        )
    if not servers:
        return DnsProbeResult(
            status="no_bootstrap", failure_reason="no_public_authoritative_address"
        )

    ds_records = candidate.get("ds_records", [])
    if ds_records:
        dnskey_rrset, dnskey_response, dnskey_server = _dnskey_response(
            servers,
            root_name,
            timeout=config.timeout,
        )
    else:
        dnskey_rrset, dnskey_response, dnskey_server = None, None, ""
    dnssec_status = _dnssec_status(
        root_name,
        ds_records,
        dnskey_rrset,
        dnskey_response,
    )
    addresses, address_responses, discovered, server = _resolve_addresses(
        servers,
        host,
        root_name,
        timeout=config.timeout,
        fallback_resolver=config.fallback_resolver,
    )
    tlsa_records, tlsa_secure, tlsa_response, tlsa_server = _resolve_tlsa(
        servers,
        host,
        root_name,
        dnskey_rrset=dnskey_rrset,
        dnssec_status=dnssec_status,
        timeout=config.timeout,
    )
    for response in [*address_responses, tlsa_response]:
        if response is not None:
            discovered.update(_discovered_hosts(response, root_name))

    addresses = [address for address in _dedupe(addresses) if _public_ip(address)]
    if tlsa_records:
        tlsa_status = "present_secure" if tlsa_secure else "present_insecure"
    else:
        tlsa_status = "missing"
    if addresses:
        status = "resolved"
        failure_reason = ""
    elif address_responses:
        status = "no_address"
        failure_reason = "no_public_a_or_aaaa"
    else:
        status = "unreachable"
        failure_reason = "authoritative_dns_unreachable"
    return DnsProbeResult(
        status=status,
        addresses=addresses[: config.max_addresses],
        dnssec_status=dnssec_status,
        tlsa_status=tlsa_status,
        tlsa_records=tlsa_records,
        tlsa_secure=tlsa_secure,
        discovered_hosts=sorted(discovered),
        server=tlsa_server or server or dnskey_server,
        failure_reason=failure_reason,
    )


def _dnskey_response(
    servers: list[str],
    root_name: str,
    *,
    timeout: float,
) -> tuple[Any, dns.message.Message | None, str]:
    response, server = _authoritative_query(servers, root_name, "DNSKEY", timeout=timeout)
    if response is None:
        return None, None, server
    owner = dns.name.from_text(_fqdn(root_name))
    return _find_rrset(response, owner, dns.rdatatype.DNSKEY), response, server


def _dnssec_status(
    root_name: str,
    ds_records: list[dict[str, Any]],
    dnskey_rrset,
    response: dns.message.Message | None,
) -> str:
    if not ds_records:
        return "unsigned"
    if dnskey_rrset is None or response is None:
        return "dnskey_missing"
    owner = dns.name.from_text(_fqdn(root_name))
    signature = _find_rrsig(response, owner, dns.rdatatype.DNSKEY)
    if signature is None:
        return "rrsig_missing"
    try:
        dns.dnssec.validate(dnskey_rrset, signature, {owner: dnskey_rrset})
    except (dns.dnssec.ValidationFailure, dns.exception.DNSException, ValueError):
        return "invalid"
    if not _ds_matches(root_name, ds_records, dnskey_rrset):
        return "ds_mismatch"
    return "valid"


def _ds_matches(root_name: str, ds_records: list[dict[str, Any]], dnskey_rrset) -> bool:
    owner = dns.name.from_text(_fqdn(root_name))
    expected = {
        (
            _int_or_none(item.get("keyTag")),
            _int_or_none(item.get("algorithm")),
            _int_or_none(item.get("digestType")),
            str(item.get("digest") or "").replace(" ", "").lower(),
        )
        for item in ds_records
    }
    for key in dnskey_rrset:
        for digest_type in {item[2] for item in expected if item[2] is not None}:
            try:
                generated = dns.dnssec.make_ds(owner, key, digest_type)
            except (dns.exception.DNSException, ValueError, TypeError):
                continue
            candidate = (
                int(generated.key_tag),
                int(generated.algorithm),
                int(generated.digest_type),
                generated.digest.hex().lower(),
            )
            if candidate in expected:
                return True
    return False


def _resolve_addresses(
    servers: list[str],
    host: str,
    root_name: str,
    *,
    timeout: float,
    fallback_resolver: str | None,
) -> tuple[list[str], list[dns.message.Message], set[str], str]:
    current = host
    responses: list[dns.message.Message] = []
    discovered: set[str] = set()
    server_used = ""
    for _ in range(6):
        addresses: list[str] = []
        cname_target = ""
        for rrtype in ("A", "AAAA"):
            response, server = _authoritative_query(servers, current, rrtype, timeout=timeout)
            if response is None:
                continue
            server_used = server_used or server
            responses.append(response)
            discovered.update(_discovered_hosts(response, root_name))
            owner = dns.name.from_text(_fqdn(current))
            rdtype = dns.rdatatype.from_text(rrtype)
            rrset = _find_rrset(response, owner, rdtype)
            if rrset is not None:
                addresses.extend(item.to_text() for item in rrset)
            if not cname_target:
                cname_target = _cname_target(response, owner)
        if addresses:
            return addresses, responses, discovered, server_used
        if not cname_target:
            return [], responses, discovered, server_used
        discovered_host = host_from_dns_owner(root_name, cname_target, "A")
        if discovered_host:
            discovered.add(discovered_host)
            current = discovered_host
            continue
        return (
            _fallback_addresses(cname_target, timeout=timeout, resolver_address=fallback_resolver),
            responses,
            discovered,
            server_used,
        )
    return [], responses, discovered, server_used


def _resolve_tlsa(
    servers: list[str],
    host: str,
    root_name: str,
    *,
    dnskey_rrset,
    dnssec_status: str,
    timeout: float,
) -> tuple[list[dict[str, Any]], bool, dns.message.Message | None, str]:
    owner_text = f"_443._tcp.{host}"
    response, server = _authoritative_query(servers, owner_text, "TLSA", timeout=timeout)
    if response is None:
        return [], False, None, server
    owner = dns.name.from_text(_fqdn(owner_text))
    rrset = _find_rrset(response, owner, dns.rdatatype.TLSA)
    if rrset is None:
        return [], False, response, server
    records = [
        {
            "owner": owner.to_text(),
            "usage": int(item.usage),
            "selector": int(item.selector),
            "matching_type": int(item.mtype),
            "association": bytes(item.cert).hex(),
        }
        for item in rrset
    ]
    secure = (
        dnssec_status == "valid"
        and dnskey_rrset is not None
        and _rrset_signature_valid(rrset, response, root_name, dnskey_rrset)
    )
    return records, secure, response, server


def _authoritative_query(
    servers: list[str],
    qname: str,
    rrtype: str,
    *,
    timeout: float,
) -> tuple[dns.message.Message | None, str]:
    name = dns.name.from_text(_fqdn(qname))
    rdtype = dns.rdatatype.from_text(rrtype)
    for server in servers:
        query = dns.message.make_query(name, rdtype, want_dnssec=True)
        query.flags &= ~dns.flags.RD
        try:
            response = dns.query.udp(query, server, timeout=timeout, raise_on_truncation=True)
        except dns.message.Truncated:
            try:
                response = dns.query.tcp(query, server, timeout=timeout)
            except (dns.exception.DNSException, OSError, TimeoutError):
                continue
        except (dns.exception.DNSException, OSError, TimeoutError):
            try:
                response = dns.query.tcp(query, server, timeout=timeout)
            except (dns.exception.DNSException, OSError, TimeoutError):
                continue
        if response.rcode() not in {dns.rcode.NOERROR, dns.rcode.NXDOMAIN}:
            continue
        if not response.flags & dns.flags.AA:
            continue
        return response, server
    return None, ""


def _find_rrset(response: dns.message.Message, owner: dns.name.Name, rdtype):
    for rrset in response.answer:
        if rrset.name == owner and rrset.rdtype == rdtype:
            return rrset
    return None


def _find_rrsig(response: dns.message.Message, owner: dns.name.Name, covered_type):
    for rrset in response.answer:
        if rrset.name != owner or rrset.rdtype != dns.rdatatype.RRSIG:
            continue
        covered = [item for item in rrset if item.type_covered == covered_type]
        if covered:
            return dns.rrset.from_rdata_list(rrset.name, rrset.ttl, covered)
    return None


def _rrset_signature_valid(rrset, response, key_owner: str, dnskey_rrset) -> bool:
    signature = _find_rrsig(response, rrset.name, rrset.rdtype)
    if signature is None:
        return False
    owner = dns.name.from_text(_fqdn(key_owner))
    try:
        dns.dnssec.validate(rrset, signature, {owner: dnskey_rrset})
    except (dns.dnssec.ValidationFailure, dns.exception.DNSException, ValueError):
        return False
    return True


def _cname_target(response: dns.message.Message, owner: dns.name.Name) -> str:
    rrset = _find_rrset(response, owner, dns.rdatatype.CNAME)
    if rrset is None:
        return ""
    for item in rrset:
        return item.target.to_text().rstrip(".").lower()
    return ""


def _fallback_addresses(
    host: str,
    *,
    timeout: float,
    resolver_address: str | None,
) -> list[str]:
    resolver = dns.resolver.Resolver(configure=resolver_address is None)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if resolver_address:
        resolver.nameservers = [resolver_address]
    addresses: list[str] = []
    for rrtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, rrtype, raise_on_no_answer=False)
        except dns.exception.DNSException:
            continue
        if answer.rrset is not None:
            addresses.extend(item.to_text() for item in answer.rrset)
    return addresses


def _resolve_nameserver_addresses(
    nameservers: list[str],
    *,
    timeout: float,
    resolver_address: str | None,
    limit: int,
) -> list[str]:
    addresses: list[str] = []
    for nameserver in nameservers[: max(1, limit)]:
        host = str(nameserver or "").strip().lower().rstrip(".")
        if not host:
            continue
        addresses.extend(
            _fallback_addresses(
                host,
                timeout=timeout,
                resolver_address=resolver_address,
            )
        )
        public = [address for address in _dedupe(addresses) if _public_ip(address)]
        if len(public) >= limit:
            return public[:limit]
    return [address for address in _dedupe(addresses) if _public_ip(address)][:limit]


def _discovered_hosts(response: dns.message.Message, root_name: str) -> set[str]:
    hosts: set[str] = set()
    for rrset in response.answer:
        try:
            rrtype = dns.rdatatype.to_text(rrset.rdtype)
        except ValueError:
            continue
        host = host_from_dns_owner(root_name, rrset.name.to_text(), rrtype)
        if host:
            hosts.add(host)
    return hosts


def _probe_web(
    host: str,
    addresses: list[str],
    *,
    scheme: str,
    config: ProbeConfig,
) -> WebProbeResult:
    if not addresses:
        return WebProbeResult(scheme=scheme, status="not_checked", failure_reason="no_address")
    failures: list[str] = []
    for address in addresses[: config.max_addresses]:
        if scheme == "http":
            try:
                return _http_request(host, address, scheme=scheme, config=config)
            except (OSError, TimeoutError, http.client.HTTPException) as exc:
                failures.append(type(exc).__name__)
                continue
        try:
            return _http_request(
                host,
                address,
                scheme=scheme,
                config=config,
                context=ssl.create_default_context(),
                webpki_status="valid",
            )
        except ssl.SSLCertVerificationError as exc:
            cert_failure = _certificate_failure(exc)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                return _http_request(
                    host,
                    address,
                    scheme=scheme,
                    config=config,
                    context=context,
                    webpki_status="invalid",
                    failure_reason=cert_failure,
                )
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as retry_exc:
                failures.append(f"{cert_failure}:{type(retry_exc).__name__}")
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            failures.append(type(exc).__name__)
    return WebProbeResult(
        scheme=scheme,
        status="failed",
        webpki_status="not_checked" if scheme == "https" else "not_applicable",
        failure_reason=(";".join(failures[:3]) or f"{scheme}_connect_failed"),
    )


def _probe_authenticated_https(
    host: str,
    dns_result: DnsProbeResult,
    *,
    config: ProbeConfig,
) -> tuple[WebProbeResult, str]:
    addresses = dns_result.addresses[: config.max_addresses]
    if not addresses:
        result = _probe_web(host, [], scheme="https", config=config)
        return result, _dane_status(dns_result, result)

    first_response: tuple[WebProbeResult, str] | None = None
    last_failure: tuple[WebProbeResult, str] | None = None
    for address in addresses:
        result = _probe_web(host, [address], scheme="https", config=config)
        dane_status = _dane_status(dns_result, result)
        if result.status == "response":
            if result.webpki_status == "valid" or dane_status == "valid":
                return result, dane_status
            if first_response is None:
                first_response = (result, dane_status)
        else:
            last_failure = (result, dane_status)
    if first_response is not None:
        return first_response
    if last_failure is not None:
        return last_failure
    result = WebProbeResult(scheme="https", status="failed", failure_reason="https_connect_failed")
    return result, _dane_status(dns_result, result)


def _http_request(
    host: str,
    address: str,
    *,
    scheme: str,
    config: ProbeConfig,
    context: ssl.SSLContext | None = None,
    webpki_status: str = "not_applicable",
    failure_reason: str = "",
) -> WebProbeResult:
    port = 443 if scheme == "https" else 80
    raw = socket.create_connection((address, port), timeout=config.timeout)
    stream: socket.socket | ssl.SSLSocket = raw
    try:
        raw.settimeout(config.timeout)
        if scheme == "https":
            if context is None:
                raise ValueError("TLS context is required for HTTPS")
            stream = context.wrap_socket(raw, server_hostname=host)
        certificate_der = (
            stream.getpeercert(binary_form=True) if isinstance(stream, ssl.SSLSocket) else None
        )
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {config.user_agent}\r\n"
            "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.1\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.sendall(request)
        response = http.client.HTTPResponse(stream)
        response.begin()
        location = response.getheader("Location", "")
        metadata = None
        if certificate_der:
            try:
                metadata = certificate_metadata_from_der(certificate_der)
            except ValueError:
                metadata = None
        return WebProbeResult(
            scheme=scheme,
            status="response",
            status_code=int(response.status),
            location=str(location or "")[:2048],
            address=address,
            webpki_status=webpki_status,
            certificate_der=certificate_der,
            certificate_sha256=metadata.sha256 if metadata else "",
            spki_sha256=metadata.spki_sha256 if metadata else "",
            certificate_not_valid_after=metadata.not_valid_after if metadata else "",
            failure_reason=failure_reason,
        )
    finally:
        stream.close()
        if stream is not raw:
            raw.close()


def _dane_status(dns_result: DnsProbeResult, https_result: WebProbeResult) -> str:
    if not dns_result.tlsa_records:
        return "missing"
    if not dns_result.tlsa_secure:
        return "insecure"
    if not https_result.certificate_der:
        return "certificate_unavailable"
    supported = False
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(https_result.certificate_der)
    except ValueError:
        return "certificate_unavailable"
    for item in dns_result.tlsa_records:
        usage = int(item.get("usage", -1))
        if usage == 3 or (usage == 1 and https_result.webpki_status == "valid"):
            supported = True
        else:
            continue
        record = TLSARecord(
            owner=str(item.get("owner") or ""),
            ttl=0,
            usage=usage,
            selector=int(item.get("selector", -1)),
            matching_type=int(item.get("matching_type", -1)),
            association=str(item.get("association") or ""),
        )
        if tlsa_record_matches_certificate(certificate, record):
            return "valid"
    return "mismatch" if supported else "unsupported_usage"


def _classify_web(
    host: str,
    *,
    http_result: WebProbeResult,
    https_result: WebProbeResult,
    dane_status: str,
) -> tuple[str, str, str]:
    https_responded = https_result.status == "response"
    https_authenticated = https_responded and (
        https_result.webpki_status == "valid" or dane_status == "valid"
    )
    http_responded = http_result.status == "response"
    if https_authenticated:
        https_status = "online" if https_result.webpki_status == "valid" else "online_dane"
        return CATEGORY_HTTPS, f"https://{host}/", https_status
    if http_responded:
        return CATEGORY_HTTP_ONLY, f"http://{host}/", ("untrusted" if https_responded else "failed")
    if https_responded:
        return CATEGORY_OFFLINE, "", "untrusted"
    return CATEGORY_OFFLINE, "", "failed"


def _failure_reason(
    category: str,
    *,
    dns_result: DnsProbeResult,
    http_result: WebProbeResult,
    https_result: WebProbeResult,
) -> str:
    if category == CATEGORY_HTTPS:
        return ""
    if category == CATEGORY_HTTP_ONLY:
        return https_result.failure_reason or "https_unavailable"
    return (
        dns_result.failure_reason
        or https_result.failure_reason
        or http_result.failure_reason
        or "no_web_response"
    )


def _certificate_failure(exc: ssl.SSLCertVerificationError) -> str:
    text = f"{getattr(exc, 'verify_message', '')} {exc}".lower()
    if getattr(exc, "verify_code", None) == 10 or "expired" in text:
        return "certificate_expired"
    return "certificate_untrusted"


def _fqdn(value: str) -> str:
    return f"{value.strip().lower().rstrip('.')}."


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
