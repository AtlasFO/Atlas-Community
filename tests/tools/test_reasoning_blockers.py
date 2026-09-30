"""pre_report_check's synthesize-blocker hatch in prose form, and the
open-question blocker that names its way out."""
import json

from tools.reasoning import (
    _blocker_sentences, _split_persisted_blockers, _task_disposition_for_report,
)


def _synth(text):
    return {"type": "reason_call", "tool": "reason_synthesize",
            "success": True, "conclusion": text}


def _tool():
    return {"type": "tool_call", "success": True, "cmd": "strings"}


PROSE = ("The timeline is complete. The memory image could not be parsed, "
         "which remains a blocker for process attribution. No other gaps.")


def test_prose_blocker_sentences_are_extracted():
    assert _blocker_sentences(PROSE).splitlines() == [
        "The memory image could not be parsed, which remains a blocker "
        "for process attribution."]
    assert _blocker_sentences("No blockers remain. Free of blockers.") == ""


def test_prose_blocker_unchanged_after_work_is_persisted():
    entries = [_synth(PROSE), _tool(), _tool(), _synth(PROSE)]
    persisted, fresh = _split_persisted_blockers(entries, _blocker_sentences(PROSE))
    assert persisted and not fresh


def test_prose_blocker_without_work_between_stays_fresh():
    entries = [_synth(PROSE), _synth(PROSE)]
    persisted, fresh = _split_persisted_blockers(entries, _blocker_sentences(PROSE))
    assert not persisted and fresh


def test_new_prose_blocker_is_fresh():
    other = "The registry hive is missing, a blocker for persistence analysis."
    entries = [_synth(PROSE), _tool(), _synth(other)]
    persisted, fresh = _split_persisted_blockers(entries, _blocker_sentences(other))
    assert not persisted and fresh


def _tasks(case, rows):
    (case / ".atlas").mkdir(parents=True, exist_ok=True)
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "tasks": [{"id": f"T-{i:03d}", "text": text, "status": status,
                   "related_claim_ids": [], "superseded_by": "",
                   "created_at": "2000-01-01T00:00:00Z",
                   "updated_at": "2000-01-01T00:00:00Z"}
                  for i, (text, status) in enumerate(rows, 1)]}))


def test_open_questions_block_with_their_ids(tmp_path):
    _tasks(tmp_path, [("Which account logged on?", "open"),
                      ("What was exfiltrated?", "answered")])
    issue, warning = _task_disposition_for_report(tmp_path)
    assert issue and "T-001" in issue and "T-002" not in issue
    assert "misc.update_investigation_task" in issue
    assert warning is None


def test_blocked_questions_are_a_warning_not_a_blocker(tmp_path):
    _tasks(tmp_path, [("Which account logged on?", "blocked_missing_evidence"),
                      ("What was exfiltrated?", "answered")])
    issue, warning = _task_disposition_for_report(tmp_path)
    assert issue is None
    assert warning and "T-001" in warning and "Limitations" in warning


class TestMiscitedFindingsAreLoweredNotHeld:
    """A finding whose cited call carries none of the identifiers it rests on
    blocks the report, correctly — the report must not rest on evidence that
    does not say what the finding claims. But the gate's own message offers
    "or lower the finding", and a run that cannot re-cite it otherwise holds
    the report forever. After the gate has repeated itself, that remedy is
    applied: the claim drops to the floor tier, so the report claims only what
    the evidence shows."""

    def _finding(self, statement="Account gnome authenticated from 10.0.0.9"):
        return {"type": "finding", "description": statement, "call_id": 11,
                "linked_call_id": 7, "input_call_ids": [7], "host": "PC1"}

    def test_the_claim_is_written_at_the_floor_tier(self, tmp_path):
        from tools.reasoning import _lower_miscited_findings
        from core.claim_graph import load_graph
        f = self._finding()
        moved = _lower_miscited_findings([f], str(tmp_path))
        assert moved == [f["description"][:80]]
        nodes = (load_graph(str(tmp_path)).get("nodes") or {}).values()
        tiers = [n.get("confidence") for n in nodes
                 if n.get("kind") == "claim" or "statement" in n]
        assert tiers and all(t == "UNCONFIRMED" for t in tiers)

    def test_lowering_twice_moves_nothing_further(self, tmp_path):
        from tools.reasoning import _lower_miscited_findings
        f = self._finding()
        _lower_miscited_findings([f], str(tmp_path))
        again = _lower_miscited_findings([f], str(tmp_path))
        assert again == [f["description"][:80]]   # idempotent, still at floor

    def test_a_finding_with_no_statement_is_skipped(self, tmp_path):
        from tools.reasoning import _lower_miscited_findings
        assert _lower_miscited_findings([{"description": "  "}], str(tmp_path)) == []

    def test_no_case_directory_is_not_an_error(self):
        from tools.reasoning import _lower_miscited_findings
        assert _lower_miscited_findings([self._finding()], None) == []

    def test_the_descriptions_helper_still_answers_in_strings(self):
        """The blocking message is built from descriptions; exposing the
        entries for the downgrade must not change what the gate prints."""
        from tools.reasoning import _findings_with_unsupported_citations
        out = _findings_with_unsupported_citations([], [])
        assert out == []


class TestTheGateWritesOnlyForTheAnalyst:
    """The gate is consulted by things other than the analyst — a readiness
    panel, a status probe, a review of a finished case — and one remedy of
    its writes: a mis-cited finding is lowered once the gate has repeated
    itself. A panel that re-rendered the verdict would move a claim on every
    refresh, so the write is opt-in and only the analyst's own tool opts in."""

    def test_importing_the_check_gets_a_read_only_default(self):
        import inspect
        from tools.reasoning import _pre_report_check
        p = inspect.signature(_pre_report_check).parameters["apply_remedies"]
        assert p.default is False

    def test_the_analysts_tool_opts_in(self):
        from unittest.mock import patch
        import tools.reasoning as R
        with patch.object(R, "_pre_report_check", return_value={}) as impl:
            fn = getattr(R.reason_pre_report_check, "__wrapped__",
                         R.reason_pre_report_check)
            fn()
        impl.assert_called_once_with(apply_remedies=True)

    def test_the_model_facing_signature_is_unchanged(self):
        """The remedy switch is internal: adding it to the tool's own schema
        would let the analyst turn the gate's remedies off."""
        import inspect
        import tools.reasoning as R
        fn = getattr(R.reason_pre_report_check, "__wrapped__",
                     R.reason_pre_report_check)
        assert list(inspect.signature(fn).parameters) == []
