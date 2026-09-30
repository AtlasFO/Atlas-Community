"""Tests for core.investigation_exit — Layers 2/3/4 exit policy."""
from __future__ import annotations

from core import investigation_exit as ie


def test_wrong_phase_reason_stable():
    r = ie.wrong_phase_reason("reason_synthesize", "Report", "Collect")
    assert r.startswith(ie.WRONG_PHASE_PREFIX)
    assert "reason_synthesize" in r
    assert "Report" in r
    assert "Collect" in r


def test_refuse_latch_counts_and_trips(tmp_path):
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    log.configure("LATCH", str(tmp_path / "t.json"), save_session=False)
    assert ie.consecutive_wrong_phase_refuses() == 0
    assert not ie.refuse_latch_tripped(threshold=3)

    # Patch the module to use our log
    import core.execution_log as el
    saved = el.log
    el.log = log
    try:
        for _ in range(3):
            ie.record_wrong_phase_refuse("reason_synthesize", "Report", "Collect")
        assert ie.consecutive_wrong_phase_refuses() == 3
        assert ie.refuse_latch_tripped(threshold=3)
        # Entering Report resets the latch
        log.record_dair_call(
            "Report", "", False, "", "", "stay", "focus")
        assert ie.consecutive_wrong_phase_refuses() == 0
        assert not ie.refuse_latch_tripped(threshold=3)
    finally:
        el.log = saved


def test_blocker_extension_policy(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    import core.execution_log as el

    allow, reason = ie.should_grant_blocker_extension(
        last_fingerprint="", last_extension_call_id=0,
        current_fingerprint="abc")
    assert allow and reason == "first_extension"

    allow, reason = ie.should_grant_blocker_extension(
        last_fingerprint="abc", last_extension_call_id=10,
        current_fingerprint="def")
    assert allow and reason == "blocker_changed"

    # Same fingerprint + empty configured log → no progress → deny
    log = ExecutionLog()
    log.configure("BLK", str(tmp_path / "t.json"), save_session=False)
    saved = el.log
    el.log = log
    try:
        allow, reason = ie.should_grant_blocker_extension(
            last_fingerprint="abc", last_extension_call_id=10,
            current_fingerprint="abc")
        assert not allow
        assert reason == "identical_blocker_no_progress"
    finally:
        el.log = saved


def test_degraded_report_with_findings():
    d = ie.degraded_report_decision({
        "ok": False, "finding_count": 5,
        "error": "Attack Timeline is empty: ...",
    })
    assert d["action"] == "degraded_write"
    assert d["limitations"]
    assert "Timeline unavailable" in d["timeline_section"]


def test_degraded_report_without_findings_still_partial():
    d = ie.degraded_report_decision({
        "ok": False, "finding_count": 0,
        "error": "No current findings...",
    })
    assert d["action"] == "degraded_write"
    assert d.get("minimal_body")


def test_inject_degraded_sections():
    md = ie.inject_degraded_sections(
        "# Report\n\nHello.\n",
        ie.degraded_report_decision({
            "ok": False, "finding_count": 2, "error": "Attack Timeline is empty",
        }),
    )
    assert "Timeline unavailable" in md
    assert "## Limitations" in md


def test_refuse_latch_valve_forces_report(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    import core.execution_log as el
    from tools import dair

    log = ExecutionLog()
    log.configure("LATCH2", str(tmp_path / "t.json"), save_session=False)
    saved = el.log
    el.log = log
    try:
        # Synthesize is callable from Analyze onward: the latch
        # records/forces Analyze, not Report, so the
        # forced jump no longer skips the analysis phase.
        for _ in range(3):
            ie.record_wrong_phase_refuse("reason_synthesize", "Analyze", "Collect")
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False, "next_phase": ""}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.x"]}, "s", "c")
        assert note == "refuse_latch"
        assert a["next_phase"] == "Analyze"
        assert a["stack_action"] == "push"
    finally:
        el.log = saved


class TestUnchangedBlockerVerdicts:
    """A blocker the agent neither resolves nor acknowledges leaves the report
    gate returning the same verdict forever: with no wall clock and no turn
    cap the budget backstop cannot arm while the run still looks busy. The
    count is taken over the gate's own output, not the agent's prose, so a
    run that reformats its blockers between passes cannot make a standing one
    look new."""

    class _Log:
        def __init__(self, entries):
            self._entries = entries

    @staticmethod
    def _gate(conclusion):
        return {"type": "reason_call", "tool": "reason_pre_report_check",
                "conclusion": conclusion}

    def _count(self, entries):
        from unittest.mock import patch
        from core.investigation_exit import unchanged_blocker_verdicts
        with patch("core.execution_log.log", self._Log(entries)):
            return unchanged_blocker_verdicts()

    def test_nothing_asked_yet_counts_nothing(self):
        assert self._count([]) == 0

    def test_a_repeated_verdict_accumulates(self):
        e = [self._gate("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed")
             for _ in range(3)]
        assert self._count(e) == 3

    def test_a_changed_verdict_resets_the_count(self):
        e = [self._gate("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed"),
             self._gate("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed"),
             self._gate("READY_TO_REPORT: false\nBLOCKERS: pagefile missing")]
        assert self._count(e) == 1

    def test_reformatting_the_same_blocker_does_not_look_like_progress(self):
        """Whitespace and case are normalised, so the same verdict rendered
        differently still counts as unchanged."""
        e = [self._gate("READY_TO_REPORT: false\nBLOCKERS:   pcap  unparsed"),
             self._gate("READY_TO_REPORT: FALSE\nblockers: pcap unparsed")]
        assert self._count(e) == 2

    def test_the_volatile_ready_line_is_not_part_of_the_identity(self):
        e = [self._gate("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed"),
             self._gate("READY_TO_REPORT: true\nBLOCKERS: pcap unparsed")]
        assert self._count(e) == 2

    def test_other_reason_calls_are_ignored(self):
        e = [{"type": "reason_call", "tool": "reason_synthesize",
              "conclusion": "BLOCKERS: pcap unparsed"},
             self._gate("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed")]
        assert self._count(e) == 1


class TestBlockerFingerprintIsTheBlockerSet:
    """The fingerprint identifies the blocking issues alone. The warnings
    beside them change as findings are recorded, and hashing them too meant
    the same standing blocker never fingerprinted the same twice."""

    def _verdict(self, issues, warnings):
        return (f"READY_TO_REPORT: false\n"
                f"BLOCKING_ISSUES ({len(issues)}): {'; '.join(issues)}\n"
                f"WARNINGS ({len(warnings)}): {'; '.join(warnings)}")

    def test_changing_warnings_do_not_change_the_fingerprint(self):
        from core.investigation_exit import blocker_fingerprint
        a = self._verdict(["Finding cites calls without its identifiers"],
                          ["2 finding(s) excluded", "5 of 11 unmapped"])
        b = self._verdict(["Finding cites calls without its identifiers"],
                          ["7 finding(s) excluded", "4 of 11 unmapped", "a new warning"])
        assert blocker_fingerprint(a) == blocker_fingerprint(b)

    def test_a_changed_blocker_changes_it(self):
        from core.investigation_exit import blocker_fingerprint
        a = self._verdict(["citation issue"], ["w"])
        b = self._verdict(["citation issue", "case question unanswered"], ["w"])
        assert blocker_fingerprint(a) != blocker_fingerprint(b)

    def test_documented_limitations_are_not_part_of_it(self):
        from core.investigation_exit import blocker_fingerprint
        a = self._verdict(["x"], ["w"])
        b = a + "\nDOCUMENTED_LIMITATIONS (1): something accepted"
        assert blocker_fingerprint(a) == blocker_fingerprint(b)

    def test_a_verdict_without_the_section_is_hashed_whole(self):
        from core.investigation_exit import blocker_fingerprint
        assert blocker_fingerprint("READY_TO_REPORT: false\nBLOCKERS: pcap unparsed") \
            == blocker_fingerprint("READY_TO_REPORT: true\nBLOCKERS:  pcap unparsed")
        assert blocker_fingerprint("BLOCKERS: pcap unparsed") \
            != blocker_fingerprint("BLOCKERS: pagefile missing")
