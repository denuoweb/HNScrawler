from __future__ import annotations

from .infra import NON_ACTIONABLE_PROVIDER_TYPES

COMPLIANCE_STAGES = (
    "dane_verified",
    "tlsa_gap",
    "stale_tlsa",
    "dnssec_broken",
    "missing_glue",
    "bootstrap_ready",
    "resolver_fallback",
    "service_blocked",
    "non_actionable",
)

COMPLIANCE_STAGE_LABELS = {
    "dane_verified": "DANE verified",
    "tlsa_gap": "TLSA gap",
    "stale_tlsa": "Stale TLSA",
    "dnssec_broken": "DNSSEC broken",
    "missing_glue": "Missing GLUE",
    "bootstrap_ready": "Bootstrap ready",
    "resolver_fallback": "Resolver fallback",
    "service_blocked": "Service blocked",
    "non_actionable": "Non-actionable",
}

COMPLIANCE_STAGE_DEFINITIONS = {
    "dane_verified": "DNSSEC, TLSA, and the live HTTPS certificate/SPKI matched.",
    "tlsa_gap": "DNSSEC is present or live-valid, but matching TLSA is missing or still unproven.",
    "stale_tlsa": "TLSA exists but does not match the current HTTPS certificate public key.",
    "dnssec_broken": "Parent DS, delegated DNSKEY, or DNSSEC signatures need repair before DANE can validate.",
    "missing_glue": "Delegation is missing parent-side nameserver bootstrap address records.",
    "bootstrap_ready": "HNS bootstrap exists; the next compliance step is DNSSEC signing, DS, and TLSA.",
    "resolver_fallback": "The latest check needed the fallback resolver path instead of strict HNS bootstrap.",
    "service_blocked": "A live-check failure outside glue, DNSSEC, or stale TLSA blocked DANE proof.",
    "non_actionable": "Expired, parked/default, resolver infrastructure, empty, or unsupported resources.",
}

DNSSEC_BROKEN_FAILURE_REASONS = (
    "dnssec_missing",
    "dnssec_bogus",
    "ds_dnskey_mismatch",
    "rrsig_expired",
)
STALE_TLSA_FAILURE_REASONS = ("stale_tlsa_spki_mismatch", "tlsa_wrong_owner")


def compliance_stage_case(
    *,
    expired: str,
    provider_type: str,
    has_ds: str,
    has_ns: str,
    has_glue: str,
    has_synth: str,
    dnssec_status: str,
    tlsa_status: str,
    dane_status: str,
    doh_fallback_status: str,
    failure_reason: str,
) -> str:
    actionable_provider = (
        f"COALESCE({provider_type}, 'unknown') NOT IN ({_sql_strings(NON_ACTIONABLE_PROVIDER_TYPES)})"
    )
    return f"""
      CASE
        WHEN COALESCE({expired}, 0) != 0 THEN 'non_actionable'
        WHEN {dane_status} = 'valid' THEN 'dane_verified'
        WHEN NOT ({actionable_provider}) THEN 'non_actionable'
        WHEN {failure_reason} IN ({_sql_strings(STALE_TLSA_FAILURE_REASONS)})
          OR ({tlsa_status} = 'present' AND COALESCE({dane_status}, '') = 'invalid')
          THEN 'stale_tlsa'
        WHEN {failure_reason} IN ({_sql_strings(DNSSEC_BROKEN_FAILURE_REASONS)})
          OR {dnssec_status} IN ('bogus', 'ds_dnskey_mismatch', 'rrsig_expired')
          THEN 'dnssec_broken'
        WHEN COALESCE({has_ns}, 0) = 1
          AND COALESCE({has_glue}, 0) = 0
          AND COALESCE({failure_reason}, 'missing_glue') = 'missing_glue'
          THEN 'missing_glue'
        WHEN ({actionable_provider})
          AND (COALESCE({has_ds}, 0) = 1 OR {dnssec_status} = 'valid')
          AND COALESCE({dane_status}, '') != 'valid'
          AND COALESCE({tlsa_status}, 'missing') IN ('missing', 'unknown', '')
          THEN 'tlsa_gap'
        WHEN {failure_reason} IS NOT NULL AND {failure_reason} != 'doh_fallback_only'
          THEN 'service_blocked'
        WHEN {doh_fallback_status} IN ('required', 'doh_fallback_only')
          OR {failure_reason} = 'doh_fallback_only'
          THEN 'resolver_fallback'
        WHEN ({actionable_provider})
          AND (
            COALESCE({has_synth}, 0) = 1
            OR (COALESCE({has_ns}, 0) = 1 AND COALESCE({has_glue}, 0) = 1)
          )
          THEN 'bootstrap_ready'
        ELSE 'non_actionable'
      END
    """


def _sql_strings(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)
