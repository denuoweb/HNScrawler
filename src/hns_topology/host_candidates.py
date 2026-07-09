from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlparse

from .infra import NON_ACTIONABLE_PROVIDER_TYPES
from .models import PROMISING_CLASSES, HostCandidate
from .timeutil import utc_now

SOURCE_DEFAULT_APEX = "default_apex"
SOURCE_DEFAULT_WWW = "default_www"
SOURCE_BROWSER_EVIDENCE = "browser_evidence"
SOURCE_RESOURCE_TLSA_OWNER = "resource_tlsa_owner"
SOURCE_DNS_EVIDENCE_TLSA_OWNER = "dns_evidence_tlsa_owner"
SOURCE_PREVIOUS_LIVE_HOST = "previous_live_host"
SOURCE_OPERATOR_IMPORT = "operator_import"
SOURCE_LINK_EVIDENCE = "link_evidence"


def normalize_host(host: str) -> str:
    text = str(host or "").strip().lower().rstrip(".")
    if not text:
        return ""
    if "://" in text:
        return ""
    if any(char.isspace() for char in text):
        return ""
    if any(char in text for char in "/?#@"):
        return ""
    if ":" in text:
        return ""
    labels = text.split(".")
    if any(not _valid_label(label) for label in labels):
        return ""
    return text


def default_hosts_for_root(root_name: str) -> list[HostCandidate]:
    root = normalize_host(root_name)
    if not root:
        return []
    now = utc_now()
    return [
        HostCandidate(
            root_name=root,
            host=root,
            source=SOURCE_DEFAULT_APEX,
            source_detail="root apex default candidate",
            confidence=50,
            first_seen_at=now,
            last_seen_at=now,
        ),
        HostCandidate(
            root_name=root,
            host=f"www.{root}",
            source=SOURCE_DEFAULT_WWW,
            source_detail="www default candidate",
            confidence=45,
            first_seen_at=now,
            last_seen_at=now,
        ),
    ]


def root_from_host(host: str, known_roots: set[str]) -> str | None:
    normalized = normalize_host(host)
    if not normalized:
        return None
    roots = sorted(
        (normalize_host(root) for root in known_roots if normalize_host(root)),
        key=lambda item: item.count("."),
        reverse=True,
    )
    for root in roots:
        if normalized == root or normalized.endswith(f".{root}"):
            return root
    return None


def candidates_from_browser_evidence(
    rows: Iterable[Mapping[str, Any] | object],
    known_roots: set[str],
) -> list[HostCandidate]:
    candidates: list[HostCandidate] = []
    for row in rows:
        host = normalize_host(str(_value(row, "host") or ""))
        if not host:
            host = _host_from_url(str(_value(row, "url") or ""))
        root_name = root_from_host(host, known_roots)
        if not root_name:
            continue
        captured_at = str(_value(row, "captured_at") or "") or utc_now()
        source_detail = _source_detail(row)
        candidates.append(
            HostCandidate(
                root_name=root_name,
                host=host,
                source=SOURCE_BROWSER_EVIDENCE,
                source_detail=source_detail,
                confidence=_browser_confidence(row),
                first_seen_at=captured_at,
                last_seen_at=captured_at,
            )
        )
    return _dedupe_candidates(candidates)


def candidates_from_tlsa_owner(root_name: str, owner: str) -> HostCandidate | None:
    root = normalize_host(root_name)
    text = str(owner or "").strip().lower().rstrip(".")
    prefix = "_443._tcp."
    if not root or not text.startswith(prefix):
        return None
    host = normalize_host(text.removeprefix(prefix))
    if not host or not (host == root or host.endswith(f".{root}")):
        return None
    now = utc_now()
    return HostCandidate(
        root_name=root,
        host=host,
        source=SOURCE_RESOURCE_TLSA_OWNER,
        source_detail=text,
        confidence=75,
        first_seen_at=now,
        last_seen_at=now,
    )


def root_is_actionable(row: Mapping[str, Any]) -> bool:
    if _truthy(row.get("expired")):
        return False
    provider_type = str(row.get("provider_type") or "unknown").strip() or "unknown"
    if provider_type in NON_ACTIONABLE_PROVIDER_TYPES:
        return False
    if not (_truthy(row.get("has_synth")) or _truthy(row.get("has_glue"))):
        return False
    if str(row.get("onchain_class") or "") in PROMISING_CLASSES:
        return True
    return _truthy(row.get("has_ds"))


def candidate_source_counts(candidates: Iterable[HostCandidate]) -> dict[str, int]:
    return dict(Counter(candidate.source for candidate in candidates))


def discover_host_candidates(conn) -> dict[str, int]:
    from .db import select_known_roots, select_latest_browser_hosts, upsert_host_candidates
    from .jsonutil import loads_json_list

    known_roots = select_known_roots(conn)
    candidates: list[HostCandidate] = []
    root_rows = conn.execute(
        """
        SELECT
          n.name AS root_name,
          n.expired,
          n.onchain_class,
          COALESCE(ps.provider_type, 'unknown') AS provider_type,
          COALESCE(rs.has_ds, 0) AS has_ds,
          COALESCE(rs.has_ns, 0) AS has_ns,
          COALESCE(rs.has_glue, 0) AS has_glue,
          COALESCE(rs.has_synth, 0) AS has_synth,
          rs.tlsa_records
        FROM names n
        JOIN resource_summary rs ON rs.name = n.name
        LEFT JOIN provider_summary ps ON ps.provider_key = n.provider_guess
        WHERE COALESCE(n.expired, 0) = 0
        """
    ).fetchall()
    for row in root_rows:
        row_dict = dict(row)
        root_name = str(row_dict["root_name"])
        if root_is_actionable(row_dict):
            candidates.extend(default_hosts_for_root(root_name))
        for record in loads_json_list(row_dict.get("tlsa_records")):
            if not isinstance(record, dict):
                continue
            owner = str(record.get("owner") or "")
            candidate = candidates_from_tlsa_owner(root_name, owner)
            if candidate is not None:
                candidates.append(candidate)

    candidates.extend(candidates_from_browser_evidence(select_latest_browser_hosts(conn), known_roots))
    candidates.extend(_previous_live_host_candidates(conn, known_roots))
    candidates.extend(_dns_evidence_tlsa_candidates(conn, known_roots))
    candidates = _dedupe_candidates(candidates)
    upsert_host_candidates(conn, candidates)
    return candidate_source_counts(candidates)


def _dedupe_candidates(candidates: Iterable[HostCandidate]) -> list[HostCandidate]:
    best: dict[tuple[str, str, str], HostCandidate] = {}
    for candidate in candidates:
        key = (candidate.root_name, candidate.host, candidate.source)
        current = best.get(key)
        if current is None or candidate.confidence > current.confidence:
            best[key] = candidate
    return sorted(best.values(), key=lambda item: (item.root_name, item.host, item.source))


def _previous_live_host_candidates(conn, known_roots: set[str]) -> list[HostCandidate]:
    rows = conn.execute(
        """
        SELECT root_name, host, checked_at, dane_status, https_status
        FROM host_live_status
        WHERE dane_status = 'valid' OR https_status IN ('working', 'tls_unverified')
        """
    ).fetchall()
    candidates = []
    for row in rows:
        root_name = root_from_host(str(row["host"]), known_roots) or normalize_host(str(row["root_name"]))
        host = normalize_host(str(row["host"]))
        if not root_name or not host:
            continue
        checked_at = str(row["checked_at"] or "") or utc_now()
        confidence = 95 if row["dane_status"] == "valid" else 85
        candidates.append(
            HostCandidate(
                root_name=root_name,
                host=host,
                source=SOURCE_PREVIOUS_LIVE_HOST,
                source_detail="previous host live status",
                confidence=confidence,
                first_seen_at=checked_at,
                last_seen_at=checked_at,
            )
        )
    return candidates


def _dns_evidence_tlsa_candidates(conn, known_roots: set[str]) -> list[HostCandidate]:
    rows = conn.execute(
        """
        SELECT name, qname, captured_at
        FROM dns_evidence
        WHERE rrtype = 'TLSA'
          AND qname LIKE '_443._tcp.%'
        ORDER BY captured_at DESC
        """
    ).fetchall()
    candidates = []
    for row in rows:
        root_name = normalize_host(str(row["name"]))
        host = normalize_host(str(row["qname"]).rstrip(".").removeprefix("_443._tcp."))
        mapped_root = root_from_host(host, known_roots)
        if not host or mapped_root != root_name:
            continue
        captured_at = str(row["captured_at"] or "") or utc_now()
        candidates.append(
            HostCandidate(
                root_name=root_name,
                host=host,
                source=SOURCE_DNS_EVIDENCE_TLSA_OWNER,
                source_detail=str(row["qname"] or "").strip(),
                confidence=70,
                first_seen_at=captured_at,
                last_seen_at=captured_at,
            )
        )
    return candidates


def _browser_confidence(row: Mapping[str, Any] | object) -> int:
    result = str(_value(row, "browser_result") or "").strip().lower()
    dane = str(_value(row, "dane_status") or "").strip().lower()
    if result == "dane_verified" or dane == "verified":
        return 100
    if result == "loaded":
        return 90
    if result in {"certificate_expired", "resolver_fallback"}:
        return 65
    if result and result not in {"observed", "failed"}:
        return 55
    return 40


def _source_detail(row: Mapping[str, Any] | object) -> str:
    parts = [
        str(_value(row, "source") or "").strip(),
        str(_value(row, "source_id") or "").strip(),
        str(_value(row, "browser_result") or "").strip(),
    ]
    return " ".join(part for part in parts if part)


def _host_from_url(url: str) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"//{text}")
    return normalize_host(parsed.hostname or "")


def _value(row: Mapping[str, Any] | object, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def _valid_label(label: str) -> bool:
    if not 1 <= len(label) <= 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return all(char.isalnum() or char == "-" for char in label)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)
