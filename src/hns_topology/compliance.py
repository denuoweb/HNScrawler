from __future__ import annotations

from .infra import NON_ACTIONABLE_PROVIDER_TYPES

COMPLIANCE_STAGES = (
    "tlsa_present",
    "tlsa_gap",
    "indirect_ns_handoff",
    "missing_glue",
    "bootstrap_ready",
    "non_actionable",
)

COMPLIANCE_STAGE_LABELS = {
    "tlsa_present": "DS + TLSA observed",
    "tlsa_gap": "TLSA unobserved",
    "indirect_ns_handoff": "Indirect NS handoff",
    "missing_glue": "Missing GLUE",
    "bootstrap_ready": "Bootstrap ready",
    "non_actionable": "Non-actionable",
}

COMPLIANCE_STAGE_DEFINITIONS = {
    "tlsa_present": "Parent DS is present and stored delegated-DNS evidence contains an authoritative or authenticated HTTPS TLSA answer; certificate matching is not implied.",
    "tlsa_gap": "Parent DS is present, but stored delegated-DNS evidence does not currently prove an HTTPS TLSA answer.",
    "indirect_ns_handoff": "Direct parent-side GLUE is absent, but an active HNS root supplies bootstrap material for a delegated nameserver host. Verify the handoff authority before treating the zone as reachable.",
    "missing_glue": "Delegation has neither direct parent-side GLUE nor an indexed HNS nameserver handoff.",
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
    has_ns_handoff: str,
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
          AND COALESCE({has_ns_handoff}, 0) = 1
          THEN 'indirect_ns_handoff'
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
