from __future__ import annotations

from .infra import NON_ACTIONABLE_PROVIDER_TYPES

COMPLIANCE_STAGES = (
    "tlsa_present",
    "tlsa_gap",
    "missing_glue",
    "bootstrap_ready",
    "non_actionable",
)

COMPLIANCE_STAGE_LABELS = {
    "tlsa_present": "TLSA present",
    "tlsa_gap": "TLSA gap",
    "missing_glue": "Missing GLUE",
    "bootstrap_ready": "Bootstrap ready",
    "non_actionable": "Non-actionable",
}

COMPLIANCE_STAGE_DEFINITIONS = {
    "tlsa_present": "Current HNS resource data has DS and TLSA material; verify externally before treating it as working DANE.",
    "tlsa_gap": "Current HNS resource data has DS but no static TLSA material.",
    "missing_glue": "Delegation is missing parent-side nameserver bootstrap address records.",
    "bootstrap_ready": "HNS bootstrap exists; the next compliance step is DNSSEC signing, DS, and TLSA.",
    "non_actionable": "Expired, parked/default, resolver infrastructure, empty, or unsupported resources.",
}


def compliance_stage_case(
    *,
    expired: str,
    provider_type: str,
    has_ds: str,
    has_ns: str,
    has_glue: str,
    has_synth: str,
    has_tlsa: str,
) -> str:
    actionable_provider = (
        f"COALESCE({provider_type}, 'unknown') NOT IN ({_sql_strings(NON_ACTIONABLE_PROVIDER_TYPES)})"
    )
    return f"""
      CASE
        WHEN COALESCE({expired}, 0) != 0 THEN 'non_actionable'
        WHEN NOT ({actionable_provider}) THEN 'non_actionable'
        WHEN COALESCE({has_ns}, 0) = 1
          AND COALESCE({has_glue}, 0) = 0
          THEN 'missing_glue'
        WHEN COALESCE({has_ds}, 0) = 1
          AND COALESCE({has_tlsa}, 0) = 1
          THEN 'tlsa_present'
        WHEN COALESCE({has_ds}, 0) = 1
          THEN 'tlsa_gap'
        WHEN (
            COALESCE({has_synth}, 0) = 1
            OR (COALESCE({has_ns}, 0) = 1 AND COALESCE({has_glue}, 0) = 1)
          )
          THEN 'bootstrap_ready'
        ELSE 'non_actionable'
      END
    """


def _sql_strings(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)
