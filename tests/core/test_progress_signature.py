"""Tests for core.progress_signature — the shared "did we actually learn
something" definition used by DAIR's productive-stall valve (and, later, the
wrap-up/blocker-extension and refuse-latch layers).

diff() is pure (no I/O), so most cases here are hand-built snapshots with no
execution-log dependency at all. snapshot() itself is covered separately
against a stubbed execution log.
"""
import pytest

from core import progress_signature as ps


# ── diff(): pure comparison ───────────────────────────────────────────────────

class TestDiffNoChange:
    def test_identical_snapshots_no_progress(self):
        snap = ps.ProgressSnapshot(
            as_of_call_id=5, finding_ids=frozenset({1, 2}),
            evidenced_finding_ids=frozenset({1, 2}),
            evidence_ref_ids=frozenset({10, 11}),
            confirmed_hypothesis_ids=frozenset({"H0001"}),
            ready_to_report=False, timeline_row_count=None,
            ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(snap, snap)
        assert delta.changed is False
        assert delta.changed_dimensions == frozenset()
        assert delta.new_findings == 0
        assert delta.new_evidence_refs == 0

    def test_empty_baseline_vs_empty_current_no_progress(self):
        base = ps.empty_snapshot("cheap")
        delta = ps.diff(base, base)
        assert delta.changed is False
        assert "unchanged" in delta.reasons[0] or delta.reasons


class TestDiffHardDimensions:
    def test_new_finding_is_progress(self):
        prev = ps.empty_snapshot("cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset({1}),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is True
        assert "findings" in delta.changed_dimensions
        assert delta.new_findings == 1
        assert delta.score > 0

    def test_new_evidence_ref_is_progress(self):
        prev = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset({1}),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset({100}),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=2, finding_ids=frozenset({1}),
            evidenced_finding_ids=frozenset({1}),
            evidence_ref_ids=frozenset({100, 101}),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is True
        assert delta.changed_dimensions == frozenset({"evidence"})
        assert delta.new_evidence_refs == 1

    def test_hypothesis_confirmation_is_progress(self):
        prev = ps.empty_snapshot("cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset({"H0001"}), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is True
        assert "hypotheses" in delta.changed_dimensions

    def test_readiness_flip_is_progress(self):
        prev = ps.empty_snapshot("cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=True,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is True
        assert "readiness" in delta.changed_dimensions

    def test_readiness_flip_back_to_false_is_not_progress(self):
        # readiness_delta only fires on not-ready -> ready, never the reverse
        # (losing readiness is not "new knowledge").
        prev = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=True,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=2, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset(), tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is False

    def test_timeline_growth_is_progress_expensive_tier(self):
        prev = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=5, ioc_hints=frozenset(), tier="expensive")
        curr = ps.ProgressSnapshot(
            as_of_call_id=2, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=9, ioc_hints=frozenset(), tier="expensive")
        delta = ps.diff(prev, curr)
        assert delta.changed is True
        assert delta.timeline_delta == 4


class TestIocHintsAreNeverDecisive:
    """The user's explicit requirement: IOC hints are a soft telemetry signal
    only and must never, by themselves, flip `changed` to True."""

    def test_new_ioc_hints_alone_do_not_set_changed(self):
        prev = ps.empty_snapshot("cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None,
            ioc_hints=frozenset({"1.2.3.4", "5.6.7.8", "9.9.9.9"}),
            tier="cheap")
        delta = ps.diff(prev, curr)
        assert delta.changed is False
        assert "findings" not in delta.changed_dimensions
        assert "ioc" not in " ".join(sorted(delta.changed_dimensions))

    def test_ioc_hint_contribution_to_score_is_capped(self):
        prev = ps.empty_snapshot("cheap")
        many_hints = frozenset(f"1.2.3.{i}" for i in range(50))
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=many_hints, tier="cheap")
        delta = ps.diff(prev, curr)
        # 50 new "hints" must not out-weigh a single real finding elsewhere.
        assert delta.score <= 1

    def test_ioc_hints_surface_in_reasons_for_telemetry(self):
        prev = ps.empty_snapshot("cheap")
        curr = ps.ProgressSnapshot(
            as_of_call_id=1, finding_ids=frozenset(),
            evidenced_finding_ids=frozenset(), evidence_ref_ids=frozenset(),
            confirmed_hypothesis_ids=frozenset(), ready_to_report=False,
            timeline_row_count=None, ioc_hints=frozenset({"1.2.3.4"}),
            tier="cheap")
        delta = ps.diff(prev, curr)
        assert any("IOC" in r for r in delta.reasons)
        assert any("heuristic only" in r for r in delta.reasons)


class TestRepeatedQueryIsInformationalOnly:
    def test_repeated_query_field_does_not_affect_score_or_changed(self):
        # repeated_query is currently always False from diff() (reserved for
        # future output_hash wiring); this pins that it never leaks into the
        # decision-critical fields regardless.
        prev = ps.empty_snapshot("cheap")
        curr = ps.empty_snapshot("cheap")
        delta = ps.diff(prev, curr)
        assert delta.repeated_query is False
        assert delta.changed is False


class TestIocHintExtraction:
    def test_ipv4_and_hash_detected(self):
        text = "Beacon to 10.0.0.5 dropped payload sha256 " + "a" * 64
        hints = ps._ioc_hints_in_text(text)
        assert "10.0.0.5" in hints
        assert "a" * 64 in hints

    def test_empty_text_yields_no_hints(self):
        assert ps._ioc_hints_in_text("") == frozenset()


class TestSnapshotSerialization:
    def test_roundtrip(self):
        snap = ps.ProgressSnapshot(
            as_of_call_id=3, finding_ids=frozenset({1, 2}),
            evidenced_finding_ids=frozenset({1}),
            evidence_ref_ids=frozenset({10}),
            confirmed_hypothesis_ids=frozenset({"H0001"}),
            ready_to_report=True, timeline_row_count=7,
            ioc_hints=frozenset({"1.2.3.4"}), tier="expensive")
        restored = ps.ProgressSnapshot.from_dict(snap.to_dict())
        assert restored == snap


# ── snapshot(): reads core.execution_log ──────────────────────────────────────

@pytest.fixture
def clean_trace():
    from core.execution_log import log
    saved = list(log._entries)
    log._entries.clear()
    yield log
    log._entries.clear()
    log._entries.extend(saved)


class TestSnapshotFromTrace:
    def test_counts_findings_and_evidence_refs(self, clean_trace):
        clean_trace._entries.extend([
            {"type": "finding", "call_id": 1, "confidence": "LIKELY",
             "description": "f1", "linked_call_id": 100},
            {"type": "finding", "call_id": 2, "confidence": "SUSPECTED",
             "description": "f2"},
        ])
        snap = ps.snapshot("cheap")
        assert snap.finding_ids == frozenset({1, 2})
        assert snap.evidenced_finding_ids == frozenset({1})
        assert snap.evidence_ref_ids == frozenset({100})

    def test_confirmed_hypothesis_tracked(self, clean_trace):
        clean_trace._entries.append({
            "type": "finding", "call_id": 1, "confidence": "CONFIRMED",
            "description": "f1", "tested_hypothesis_id": "H0001",
        })
        snap = ps.snapshot("cheap")
        assert snap.confirmed_hypothesis_ids == frozenset({"H0001"})

    def test_unconfirmed_hypothesis_not_tracked(self, clean_trace):
        clean_trace._entries.append({
            "type": "finding", "call_id": 1, "confidence": "UNCONFIRMED",
            "description": "f1", "tested_hypothesis_id": "H0001",
        })
        snap = ps.snapshot("cheap")
        assert snap.confirmed_hypothesis_ids == frozenset()

    def test_readiness_from_most_recent_pre_report_check(self, clean_trace):
        # NOT dair_call.verification_satisfied — that flag is Triage
        # challenge-answering, unrelated to report readiness (audit finding).
        clean_trace._entries.extend([
            {"type": "reason_call", "call_id": 1,
             "tool": "reason_pre_report_check",
             "conclusion": "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): x"},
            {"type": "reason_call", "call_id": 2,
             "tool": "reason_pre_report_check",
             "conclusion": "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none"},
        ])
        snap = ps.snapshot("cheap")
        assert snap.ready_to_report is True

    def test_dair_verification_satisfied_does_not_affect_readiness(self, clean_trace):
        # Regression guard for the audit finding: DAIR's own flag must never
        # leak into report readiness.
        clean_trace._entries.append(
            {"type": "dair_call", "call_id": 1, "verification_satisfied": True})
        snap = ps.snapshot("cheap")
        assert snap.ready_to_report is False

    def test_readiness_uses_most_recent_check_not_first(self, clean_trace):
        clean_trace._entries.extend([
            {"type": "reason_call", "call_id": 1,
             "tool": "reason_pre_report_check",
             "conclusion": "READY_TO_REPORT: true"},
            {"type": "reason_call", "call_id": 2,
             "tool": "reason_pre_report_check",
             "conclusion": "READY_TO_REPORT: false"},
        ])
        snap = ps.snapshot("cheap")
        assert snap.ready_to_report is False

    def test_cheap_tier_skips_timeline(self, clean_trace):
        snap = ps.snapshot("cheap")
        assert snap.timeline_row_count is None
