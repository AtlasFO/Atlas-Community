"""Broad evidence-contract gates for record_finding.

This module collapses the public gate stack into a few predictable contracts
while reusing the focused checkers internally. The narrow modules remain useful
as implementation details and for direct unit coverage, but record_finding now
reports broad failure classes:

  - evidence_strength
  - completeness
  - attribution
  - transfer
"""
from __future__ import annotations

from typing import Optional

from . import (
    confirmed_requires_linked_call_id,
    linked_call_id_must_exist,
    mitre_technique_validation,
    confirmed_requires_supported_evaluate,
    confidence_and_citation,
    hypothesize_required,
    negative_from_truncated,
    negative_completeness,
    temporal_negative_grounding,
    principal_attribution_grounding,
    named_actor_attribution_grounding,
    interactive_injection_grounding,
    exfil_channel_grounding,
    attribution_required,
    external_knowledge_grounding,
    indicator_absence,
)


def _as_contract(failure: dict | None, gate: str) -> Optional[dict]:
    if failure is None:
        return None
    original = failure.get("gate")
    out = {**failure, "gate": gate}
    if original and original != gate:
        out["detail_gate"] = original
    return out


# The focused checker modules behind each contract, in the order they run;
# each exposes ``check(ctx)``. A contract's first failure is its refusal;
# ``failures`` lists every one, so a finding can be told all of its
# objections at once.
CHECKS: dict[str, tuple] = {
    "evidence_strength": (
        confirmed_requires_linked_call_id,
        linked_call_id_must_exist,
        mitre_technique_validation,
        confirmed_requires_supported_evaluate,
        confidence_and_citation,
        hypothesize_required,
    ),
    "completeness": (
        negative_from_truncated,
        negative_completeness,
        temporal_negative_grounding,
        indicator_absence,
    ),
    "attribution": (
        principal_attribution_grounding,
        named_actor_attribution_grounding,
        interactive_injection_grounding,
        attribution_required,
        external_knowledge_grounding,
    ),
    "transfer": (
        exfil_channel_grounding,
    ),
}


def failures(gate: str, ctx) -> list[dict]:
    """Every objection the contract ``gate`` has to ``ctx``, in check order.

    Each checker is called once. The first entry is what the contract
    function returns on its own.
    """
    out: list[dict] = []
    for module in CHECKS[gate]:
        failure = module.check(ctx)
        if failure is not None:
            out.append(_as_contract(failure, gate))
    return out


def _first(gate: str, ctx) -> Optional[dict]:
    for module in CHECKS[gate]:
        failure = module.check(ctx)
        if failure is not None:
            return _as_contract(failure, gate)
    return None


def evidence_strength(ctx) -> Optional[dict]:
    """Confidence tier, linked evidence, ATT&CK IDs, review, and citations."""
    return _first("evidence_strength", ctx)


def completeness(ctx) -> Optional[dict]:
    """Absence/unknown claims require complete enough searched scope."""
    return _first("completeness", ctx)


def attribution(ctx) -> Optional[dict]:
    """Human/account/device/threat-actor attribution requires control evidence."""
    return _first("attribution", ctx)


def transfer(ctx) -> Optional[dict]:
    """Named exfiltration channels require a transfer artifact."""
    return _first("transfer", ctx)
