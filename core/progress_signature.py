"""core/progress_signature.py — the single, shared definition of "did the
investigation's KNOWLEDGE STATE actually move forward", independent of
whether the underlying tool calls technically succeeded or failed.

Background: DAIR previously equated "tool succeeded" with "made progress".
An agent could stay in Collect indefinitely re-reading tables, re-confirming
the same findings, or varying its tool arguments slightly — all while every
individual call "succeeded" and DAIR kept recommending "stay". This module
gives every consumer that needs to answer "are we actually still learning
something?" one shared, testable answer instead of five separate heuristics.

Actual consumers:
  - DAIR's productive-stall valve in tools/dair.py — **belief** only
  - agent ``core.run_budget`` — belief + coverage ledger + exploration
  - investigation exit Layer 3 (blocker extension) — belief progress
  - telemetry / trace debugging (why did DAIR force a phase?)

Force-report / synthesize-escape is gated by ``coverage_ledger``, not by
belief stall alone.

Two pure building blocks:

  snapshot(tier) -> ProgressSnapshot
      Reads core.execution_log and describes the current KNOWLEDGE state
      only. Deliberately excludes turn counters, token usage, prompt state,
      tool timings, and any other runtime/volatile metadata — two snapshots
      taken minutes apart with nothing new learned must compare equal.

  diff(prev, curr) -> ProgressDelta
      Pure comparison, no I/O. Trivial to unit test with hand-built
      snapshots, independent of a running case or execution log.

Decision-criticality rules (do not weaken these without re-reading the
design discussion — they exist specifically to keep this signal honest):

  * `changed` is the ONLY field a state machine may use to make control-flow
    decisions (force a phase transition, deny a blocker extension, trip a
    refuse-latch, ...). It is derived from hard knowledge dimensions only:
    findings, evidence references, confirmed hypotheses, report readiness,
    and timeline rows.
  * `score` is a telemetry/logging convenience number. Never gate control
    flow on it directly.
  * `new_ioc_hints` is a regex-based heuristic over already-recorded finding
    text (IP/hash-shaped substrings). It is NOT a validated indicator list
    and must never, by itself, be able to set `changed=True` — a re-read of
    the same evidence producing "new-looking" IP substrings is exactly the
    false-progress signal this module exists to prevent. It contributes a
    capped amount to `score` and appears in `reasons` for visibility only.
  * `repeated_query` is informational only (surfaced in `reasons`), and has
    no effect on `score` or `changed`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

PROGRESS_SIGNATURE_VERSION = 1

Tier = Literal["cheap", "expensive"]

_CONFIRMED_TIERS = frozenset({"CONFIRMED", "LIKELY"})

# The authoritative "is the report actually ready" signal is
# reason.pre_report_check's own verdict (tools/reasoning.py), which runs its
# own checklist (plan/synthesize called, blockers resolved, ...) — NOT DAIR's
# verification_satisfied (that flag is about Triage challenge-answering, a
# different and unrelated concept that happens to share the word
# "verification"). agent/loop.py::_pre_report_blocking parses the same
# marker; kept in sync deliberately — if that regex changes, update both.
_READY_TO_REPORT_RE = re.compile(r"READY_TO_REPORT:\s*(true|false)", re.IGNORECASE)


def _ready_to_report_from_trace(entries: list[dict]) -> bool:
    """Verdict of the most recent reason.pre_report_check call, or False if
    none has run yet."""
    for e in reversed(entries):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
            m = _READY_TO_REPORT_RE.search(e.get("conclusion") or "")
            return bool(m and m.group(1).lower() == "true")
    return False


_BLOCKING_COUNT_RE = re.compile(r"BLOCKING_ISSUES\s*\((\d+)\)", re.IGNORECASE)


def report_gate_blockers(entries: list[dict], since_call_id: int = 0) -> int | None:
    """How many blocking issues the most recent reason.pre_report_check
    verdict named, or None if none has run yet. With ``since_call_id`` only
    a verdict recorded after that call counts: a resumed log holds the
    verdicts of the run before."""
    for e in reversed(entries):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
            if int(e.get("call_id") or 0) <= since_call_id:
                return None
            m = _BLOCKING_COUNT_RE.search(e.get("conclusion") or "")
            return int(m.group(1)) if m else None
    return None

# ── IOC hint patterns ─────────────────────────────────────────────────────────
# Heuristic only (see module docstring). Deliberately narrow: IPv4 + hex-hash
# shapes are unambiguous and case-agnostic. Scanned over already-authored
# finding descriptions (not raw tool stdout) — raw table dumps re-read on
# every cycle would otherwise manufacture "new" hits from pure noise.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")


def _ioc_hints_in_text(text: str) -> frozenset[str]:
    """IOC-shaped substrings in finding text. Hint only — see module
    docstring. Never treat the returned set as validated indicators."""
    if not text:
        return frozenset()
    hits: set[str] = set()
    hits.update(_IPV4_RE.findall(text))
    hits.update(m.lower() for m in _HASH_RE.findall(text))
    return frozenset(hits)


@dataclass(frozen=True)
class ProgressSnapshot:
    """The investigation's KNOWLEDGE state at one point in time.

    Every field describes something an analyst would call "what we know",
    never something about how the run is executing. Two snapshots compare
    equal iff nothing was learned between them — that property is what makes
    diff() a reliable stall detector.

    as_of_call_id is compare/hash-excluded: it is a monotonically increasing
    trace pointer (audit/debugging only) that changes every cycle regardless
    of whether anything was learned. If it were compare-significant, two
    genuinely-equal knowledge states would compare unequal via `==` — diff()
    never uses it, but nothing should ever rely on `snap_a == snap_b` for a
    progress decision; only diff() is the sanctioned comparison path.
    """
    finding_ids: frozenset[int]
    evidenced_finding_ids: frozenset[int]
    evidence_ref_ids: frozenset[int]
    confirmed_hypothesis_ids: frozenset[str]
    ready_to_report: bool
    timeline_row_count: "int | None"   # None on cheap tier — not computed
    ioc_hints: frozenset[str]
    tier: Tier
    as_of_call_id: int = field(compare=False)

    def to_dict(self) -> dict:
        return {
            "as_of_call_id": self.as_of_call_id,
            "finding_ids": sorted(self.finding_ids),
            "evidenced_finding_ids": sorted(self.evidenced_finding_ids),
            "evidence_ref_ids": sorted(self.evidence_ref_ids),
            "confirmed_hypothesis_ids": sorted(self.confirmed_hypothesis_ids),
            "ready_to_report": self.ready_to_report,
            "timeline_row_count": self.timeline_row_count,
            "ioc_hints": sorted(self.ioc_hints),
            "tier": self.tier,
            "version": PROGRESS_SIGNATURE_VERSION,
        }

    @staticmethod
    def from_dict(d: dict) -> "ProgressSnapshot":
        return ProgressSnapshot(
            as_of_call_id=int(d.get("as_of_call_id") or 0),
            finding_ids=frozenset(d.get("finding_ids") or []),
            evidenced_finding_ids=frozenset(d.get("evidenced_finding_ids") or []),
            evidence_ref_ids=frozenset(d.get("evidence_ref_ids") or []),
            confirmed_hypothesis_ids=frozenset(
                d.get("confirmed_hypothesis_ids") or []),
            ready_to_report=bool(d.get("ready_to_report")),
            timeline_row_count=d.get("timeline_row_count"),
            ioc_hints=frozenset(d.get("ioc_hints") or []),
            tier=d.get("tier") or "cheap",
        )


def empty_snapshot(tier: Tier = "cheap") -> ProgressSnapshot:
    """Baseline snapshot for the first cycle (no prior dair_call to diff
    against yet)."""
    return ProgressSnapshot(
        as_of_call_id=0,
        finding_ids=frozenset(),
        evidenced_finding_ids=frozenset(),
        evidence_ref_ids=frozenset(),
        confirmed_hypothesis_ids=frozenset(),
        ready_to_report=False,
        timeline_row_count=None,
        ioc_hints=frozenset(),
        tier=tier,
    )


def snapshot(tier: Tier = "cheap") -> ProgressSnapshot:
    """Compute the current knowledge-state snapshot from the execution trace.

    cheap tier: pure trace scan (findings, evidence refs, confirmed
    hypotheses, readiness proxy) — same cost class as the existing DAIR valve
    helpers. Safe to call on every dair_assess cycle.

    expensive tier: additionally resolves the curated Attack Timeline via
    core.report_assemble.attack_timeline_readiness. This does claim-graph
    binding and evidence resolution — call it only near wrap-up/report-gate
    decisions, never on every Collect cycle.
    """
    from core.execution_log import log as _elog

    finding_ids: set[int] = set()
    evidenced_finding_ids: set[int] = set()
    evidence_ref_ids: set[int] = set()
    confirmed_hypothesis_ids: set[str] = set()
    ioc_hints: set[str] = set()
    last_call_id = 0

    try:
        entries = list(_elog._entries)
    except Exception:
        entries = []

    for e in entries:
        cid = e.get("call_id") or 0
        if cid:
            last_call_id = max(last_call_id, cid)
        if e.get("type") != "finding":
            continue
        finding_ids.add(cid)
        linked = int(e.get("linked_call_id") or 0)
        inputs = [int(c) for c in (e.get("input_call_ids") or []) if c]
        if linked:
            evidence_ref_ids.add(linked)
        evidence_ref_ids.update(inputs)
        if linked or inputs:
            evidenced_finding_ids.add(cid)
        tested = e.get("tested_hypothesis_id") or ""
        conf = str(e.get("confidence") or "").upper()
        if tested and conf in _CONFIRMED_TIERS:
            confirmed_hypothesis_ids.add(str(tested))
        ioc_hints.update(_ioc_hints_in_text(str(e.get("description") or "")))

    ready_to_report = _ready_to_report_from_trace(entries)

    timeline_row_count: "int | None" = None
    if tier == "expensive":
        try:
            cd = _elog.case_dir()
            if cd:
                from core.report_assemble import attack_timeline_readiness
                ready = attack_timeline_readiness(cd)
                timeline_row_count = int(ready.get("timeline_row_count") or 0)
        except Exception:
            timeline_row_count = None

    return ProgressSnapshot(
        as_of_call_id=last_call_id,
        finding_ids=frozenset(finding_ids),
        evidenced_finding_ids=frozenset(evidenced_finding_ids),
        evidence_ref_ids=frozenset(evidence_ref_ids),
        confirmed_hypothesis_ids=frozenset(confirmed_hypothesis_ids),
        ready_to_report=ready_to_report,
        timeline_row_count=timeline_row_count,
        ioc_hints=frozenset(ioc_hints),
        tier=tier,
    )


def load_prev_snapshot(tier: Tier = "cheap") -> ProgressSnapshot:
    """The most recently stored snapshot of the given tier from the dair_call
    trace, or an empty baseline if this is the first cycle (or the trace only
    has snapshots of the other tier — cheap and expensive are never mixed in
    a single diff)."""
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if e.get("type") != "dair_call":
                continue
            snap = e.get("progress_snapshot")
            if isinstance(snap, dict) and snap.get("tier") == tier:
                return ProgressSnapshot.from_dict(snap)
    except Exception:
        pass
    return empty_snapshot(tier)


@dataclass(frozen=True)
class ProgressDelta:
    """The explainable verdict: did knowledge change between two snapshots,
    and why (or why not)."""
    changed: bool
    changed_dimensions: frozenset[str]
    score: float
    signature: tuple
    new_findings: int
    new_evidence_refs: int
    new_ioc_hints: int
    hypothesis_delta: int
    readiness_delta: bool
    timeline_delta: "int | None"
    repeated_query: bool
    reasons: tuple[str, ...]
    version: int = PROGRESS_SIGNATURE_VERSION

    def to_dict(self) -> dict:
        return {
            "changed": self.changed,
            "changed_dimensions": sorted(self.changed_dimensions),
            "score": self.score,
            "new_findings": self.new_findings,
            "new_evidence_refs": self.new_evidence_refs,
            "new_ioc_hints": self.new_ioc_hints,
            "hypothesis_delta": self.hypothesis_delta,
            "readiness_delta": self.readiness_delta,
            "timeline_delta": self.timeline_delta,
            "repeated_query": self.repeated_query,
            "reasons": list(self.reasons),
            "version": self.version,
        }


def diff(prev: ProgressSnapshot, curr: ProgressSnapshot) -> ProgressDelta:
    """Pure comparison between two knowledge-state snapshots. No I/O — safe
    and cheap to call with hand-built snapshots in tests."""
    new_finding_ids = curr.finding_ids - prev.finding_ids
    new_evidence_ids = curr.evidence_ref_ids - prev.evidence_ref_ids
    new_hyp_ids = curr.confirmed_hypothesis_ids - prev.confirmed_hypothesis_ids
    new_ioc = curr.ioc_hints - prev.ioc_hints

    new_findings = len(new_finding_ids)
    new_evidence_refs = len(new_evidence_ids)
    hypothesis_delta = len(new_hyp_ids)
    new_ioc_hints = len(new_ioc)
    readiness_delta = bool(curr.ready_to_report) and not bool(prev.ready_to_report)

    timeline_delta: "int | None" = None
    if curr.timeline_row_count is not None and prev.timeline_row_count is not None:
        timeline_delta = curr.timeline_row_count - prev.timeline_row_count

    # Informational only (see module docstring) — no effect on score/changed.
    repeated_query = False

    changed_dimensions: set[str] = set()
    if new_findings:
        changed_dimensions.add("findings")
    if new_evidence_refs:
        changed_dimensions.add("evidence")
    if hypothesis_delta:
        changed_dimensions.add("hypotheses")
    if readiness_delta:
        changed_dimensions.add("readiness")
    if timeline_delta:
        changed_dimensions.add("timeline")

    # Decision-critical. Hard dimensions ONLY — new_ioc_hints and
    # repeated_query must never appear in this expression.
    changed = bool(changed_dimensions)

    timeline_gain = timeline_delta if (timeline_delta and timeline_delta > 0) else 0
    score = (3 * new_findings + 2 * new_evidence_refs + 2 * hypothesis_delta
             + 3 * int(readiness_delta) + 2 * timeline_gain
             + min(1, new_ioc_hints))  # capped — cannot dominate the score

    signature = (
        len(curr.finding_ids), len(curr.evidence_ref_ids),
        len(curr.confirmed_hypothesis_ids), curr.ready_to_report,
        curr.timeline_row_count,
    )

    reasons: list[str] = []
    if changed:
        if new_findings:
            reasons.append(f"+{new_findings} new finding(s)")
        if new_evidence_refs:
            reasons.append(f"+{new_evidence_refs} new evidence reference(s)")
        if hypothesis_delta:
            reasons.append(f"+{hypothesis_delta} hypothesis confirmation(s)")
        if readiness_delta:
            reasons.append("report readiness: not ready -> ready")
        if timeline_delta:
            sign = "+" if timeline_delta > 0 else ""
            reasons.append(f"timeline {sign}{timeline_delta} row(s)")
    else:
        reasons.append(f"findings unchanged ({len(curr.finding_ids)})")
        reasons.append(f"evidence references unchanged ({len(curr.evidence_ref_ids)})")
        reasons.append(
            f"hypotheses unchanged ({len(curr.confirmed_hypothesis_ids)} confirmed)")
        reasons.append(
            "readiness unchanged (%s)"
            % ("ready" if curr.ready_to_report else "not ready"))
        if curr.timeline_row_count is not None:
            reasons.append(f"timeline unchanged ({curr.timeline_row_count} rows)")
    if new_ioc_hints:
        reasons.append(
            f"note: +{new_ioc_hints} IOC-shaped hint(s) in finding text — "
            "heuristic only, not counted toward progress")

    return ProgressDelta(
        changed=changed,
        changed_dimensions=frozenset(changed_dimensions),
        score=float(score),
        signature=signature,
        new_findings=new_findings,
        new_evidence_refs=new_evidence_refs,
        new_ioc_hints=new_ioc_hints,
        hypothesis_delta=hypothesis_delta,
        readiness_delta=readiness_delta,
        timeline_delta=timeline_delta,
        repeated_query=repeated_query,
        reasons=tuple(reasons),
    )
