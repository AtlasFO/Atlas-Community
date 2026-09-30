"""Server-enforced gates on record_finding.

Each gate is a callable that takes a GateContext and returns either None
(pass) or a refusal dict carrying a stable `gate:` field. The public
`record_finding` in tools/misc.py runs every gate (``run_all_gates``) and
answers with the first failure as the refusal, the rest listed on it, so one
corrected call can clear every objection instead of meeting them one turn
at a time. ``run_gates`` keeps the first-failure form for callers that only
need a verdict.

To add a new gate:
  1. Create tools/_gates/<your_gate>.py exposing `check(ctx) -> Optional[dict]`.
  2. Import and append to GATES below (mind ordering — earlier gates run first).
  3. Add a row to tools/misc.py:record_finding's docstring table.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional, Any

from . import (
    mcp_routing, dair_required, lineage_required, lineage_relevance, contracts,
    access_limitation_dedupe, universal_from_truncated, quoted_text_grounding,
    instruction_text_grounding, tool_output_inventory, supersedes_target,
)


@dataclass
class GateContext:
    """All inputs a gate may need. Built once per record_finding call so each
    gate has the same view of the trace and the same precomputed window/index."""
    description: str
    confidence: str          # raw input (case as supplied)
    tier: str                # uppercased confidence ("CONFIRMED", "LIKELY", ...)
    source: str
    linked_call_id: int
    tested_hypothesis_id: str
    log: Any                 # core.execution_log.ExecutionLog
    idx: Any                 # core.execution_log.LogIndex
    window: list[dict]       # last 30 entries (strict-recency gates)

    # Widened look-back for content-matched reason_call lookups: last 30
    # entries PLUS recent reason_calls the 30-slice missed. Only lookups that
    # require the reason_call to reference this finding's text use it
    # (confidence_and_citation, and the description-matched evaluate), so
    # widening cannot admit a stale or unrelated verdict. Strict-recency
    # lookups (most-recent evaluate fallback/attribution/hypothesize/dair)
    # keep `window`. Falls back to `window` when unset.
    reason_window: list[dict] = None  # type: ignore[assignment]

    # Agent-declared upstream lineage — list of _atlas_call_id values for the
    # entries that informed this record_*. The lineage_required gate enforces
    # this is non-empty (after genesis grace) and that every cid actually
    # exists in the trace.
    input_call_ids: list[int] = None  # type: ignore[assignment]

    # The call ids the analyst cited, before any repair or auto-fill touched
    # input_call_ids. The ids Atlas infers (a value's source added by the
    # citation auto-fill, the calls about the named artifacts that replace
    # irrelevant ones) are lineage for every other gate and for the report;
    # universal_from_truncated reads only what the analyst rested the finding
    # on, and falls back to the inferred ids when the analyst cited nothing.
    # The trade-off: a truncated call that reaches the lineage only through
    # Atlas's inference is not judged even where it is one clause's real
    # basis (pinned in test_universal_from_truncated_scope as a known gap);
    # judging it made the analyst unable to record a true finding at all.
    analyst_call_ids: list[int] = None  # type: ignore[assignment]

    # Agent-declared MITRE technique IDs for this finding (e.g. ["T1190",
    # "T1059.005"]). A structured channel so techniques the analyst mapped via
    # correlate.mitre_map don't have to be smuggled into the prose description
    # to be counted. The mitre_technique_validation gate validates these
    # alongside any T-IDs found in the description.
    mitre_techniques: list[str] = None  # type: ignore[assignment]

    # Out-band data populated by gates so the success path can carry it. The
    # mitre_technique_validation gate appends to validated_techniques when a
    # T-ID resolves successfully; record_finding propagates this to the result.
    validated_techniques: list[dict] = None  # type: ignore[assignment]

    # Explicit gate-match foreign keys. Set by the gates that find their
    # matching reason_call entry. record_finding stamps these onto the
    # finding entry so downstream consumers (Process view, accuracy report,
    # synthesize) have direct call_id references rather than substring guesses.
    gated_by_evaluate_call_id: int = 0
    gated_by_confidence_call_id: int = 0
    gated_by_cite_check_call_id: int = 0
    gated_by_hypothesize_call_id: int = 0

    # True when record_finding filled input_call_ids itself because the agent
    # omitted (or fabricated) them. Citations Atlas chose are not the agent's
    # claim about relevance, so lineage_relevance leaves them alone and the
    # inference in tools.misc is made relevance-aware instead.
    lineage_inferred: bool = False

    # Inline supporting evidence. When non-empty, confidence_and_citation runs a
    # DETERMINISTIC citation check on it (tools/_gates/_citation.py) instead of
    # requiring separate reason.confidence_score + reason.cite_check model
    # round-trips. Empty ⇒ legacy path. Set by record_finding.
    supporting_evidence: str = ""
    # Stamped "deterministic" by confidence_and_citation when the fast path is
    # taken, so record_finding can mark the finding's citation provenance.
    citation_mode: str = ""
    # Observations a gate makes without refusing (the call ids whose output
    # carried instruction-like text, for one). record_finding stamps them on
    # the finding and repeats them in its result.
    notes: dict = None  # type: ignore[assignment]

    # The host the analyst gave, and the finding this record replaces
    # (supersedes=, a claim id or a call id). supersedes_target resolves the
    # name to the standing finding's trace entry and leaves it here, so
    # record_finding supersedes that finding's claim with the new one.
    host: str = ""
    supersedes: str = ""
    supersedes_entry: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.notes is None:
            self.notes = {}
        if self.validated_techniques is None:
            self.validated_techniques = []
        if self.input_call_ids is None:
            self.input_call_ids = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.reason_window is None:
            self.reason_window = self.window


GateFn = Callable[[GateContext], Optional[dict]]

# Ordering is load-bearing. Infrastructure refusals run first; broad evidence
# contracts then run from cheapest/most universal to most claim-specific.
GATES: list[tuple[str, GateFn]] = [
    ("mcp_routing", mcp_routing.check),
    ("dair_required", dair_required.check),
    ("supersedes_target", supersedes_target.check),
    # The shape of the statement comes before any question about its
    # citations: an inventory of a tool's output is not a finding whoever
    # it cites, and the refusal sends the inventory to a note.
    ("tool_output_inventory", tool_output_inventory.check),
    ("lineage_required", lineage_required.check),
    ("lineage_relevance", lineage_relevance.check),
    ("universal_from_truncated", universal_from_truncated.check),
    ("quoted_text_grounding", quoted_text_grounding.check),
    ("instruction_text_grounding", instruction_text_grounding.check),
    ("access_limitation_dedupe", access_limitation_dedupe.check),
    ("evidence_strength", contracts.evidence_strength),
    ("completeness", contracts.completeness),
    ("attribution", contracts.attribution),
    ("transfer", contracts.transfer),
]


def run_gates(ctx: GateContext) -> Optional[dict]:
    """Run each gate in order. Return the first refusal dict, or None on pass."""
    for _, gate_fn in GATES:
        failure = gate_fn(ctx)
        if failure is not None:
            return failure
    return None


def run_all_gates(ctx: GateContext) -> list[dict]:
    """Run every gate and return every refusal, in gate order; the broad
    contracts contribute each of their focused checkers' refusals. Empty on
    pass. The first entry is what ``run_gates`` would have returned.

    Gates that only observe (stamping ``gated_by_*`` ids, leaving notes on
    the context) do the same work either way; the one side effect a refusal
    carries, the self-correction a CHALLENGED evaluation records, is written
    once per finding here as it was under first-failure evaluation.
    """
    out: list[dict] = []
    for name, gate_fn in GATES:
        if name in contracts.CHECKS:
            out.extend(contracts.failures(name, ctx))
            continue
        failure = gate_fn(ctx)
        if failure is not None:
            out.append(failure)
    return out
