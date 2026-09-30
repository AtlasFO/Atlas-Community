"""The pre-report check's case-question gate: which questions it word-gates,
how many key words a finding must name, and where the question comes from."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from core.run_state import OBJECTIVE_FILE, read_objective, record_objective


@pytest.fixture
def case(tmp_path):
    """A case folder with its trace under analysis/ and a met coverage floor."""
    (tmp_path / "analysis").mkdir()
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    trace = tmp_path / "analysis" / "CASE-X_trace.json"
    log = ExecutionLog()
    log.configure("CASE-X", str(trace), save_session=False)
    return SimpleNamespace(dir=tmp_path, log=log, trace=str(trace))


def _ready(log):
    log.record_tool_call("vol.psscan", True, False, 0, 0)
    log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
    log.record_reason_call("reason_plan", True, "plan", {})
    log.record_reason_call("reason_hypothesize", True, "hyp", {})
    log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
    log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})


def _check(log):
    from tools.reasoning import reason_pre_report_check
    with patch("core.execution_log.log", log), \
            patch("tools.reasoning.reason_audit_findings",
                  return_value={"summary": {"candidate_count": 0}, "candidates": []}):
        return reason_pre_report_check()


def _cq_issues(result):
    return [i for i in result["blocking_issues"] if "Case question" in i]


def _warnings(result):
    return result.get("warnings") or []


def test_the_case_resolves_to_its_folder(case):
    assert os.path.realpath(case.log.case_dir()) == os.path.realpath(str(case.dir))
    assert case.log.trace_path() == os.path.abspath(case.trace)


# ── the word test ──────────────────────────────────────────────────────────

def test_a_one_word_question_can_be_answered(case):
    record_objective(case.dir, text="What did the attacker do?", source="question",
                     trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("The attacker copied the payroll export to removable media",
                            "LIKELY", "ez.mftecmd")
    assert _cq_issues(_check(case.log)) == []


def test_a_one_word_question_still_blocks_when_nothing_names_it(case):
    record_objective(case.dir, text="What did the attacker do?", source="question",
                     trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    issues = _cq_issues(_check(case.log))
    assert len(issues) == 1 and "attacker" in issues[0]


def test_a_question_without_key_words_warns_and_does_not_block(case):
    record_objective(case.dir, text="Why?", source="question", trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    result = _check(case.log)
    assert _cq_issues(result) == []
    assert any("no key word" in w for w in _warnings(result))


def test_the_blocker_names_the_missing_words(case):
    record_objective(case.dir, text="Which accounts logged on to the file server remotely?",
                     source="question", trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    issues = _cq_issues(_check(case.log))
    assert issues and "accounts" in issues[0] and "remotely" in issues[0]


def test_the_recorded_question_gates_without_any_marker_in_the_trace(case):
    record_objective(case.dir, text="Which accounts logged on to the file server remotely?",
                     source="question", trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("Accounts svc-backup and user7 logged on remotely to the file server",
                            "LIKELY", "ez.evtxecmd")
    assert _cq_issues(_check(case.log)) == []


# ── where the question comes from ─────────────────────────────────────────

def test_prose_about_the_case_question_does_not_anchor_the_gate(case):
    _ready(case.log)
    case.log.record_agent_message(
        "Working on the case question: which files were deleted from the finance share?")
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert _cq_issues(_check(case.log)) == []


def test_the_literal_marker_still_anchors_a_trace_without_a_record(case):
    _ready(case.log)
    case.log.record_agent_message(
        "CASE_QUESTION: Which files were deleted from the finance share?")
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert len(_cq_issues(_check(case.log))) == 1


def test_a_record_written_for_another_trace_is_ignored(case):
    record_objective(case.dir, text="Which accounts logged on to the file server remotely?",
                     source="question", trace_path=str(case.dir / "analysis" / "other_trace.json"))
    _ready(case.log)
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert _cq_issues(_check(case.log)) == []


def test_tracked_requests_are_left_to_the_task_gate(case):
    record_objective(case.dir, text="Which files were deleted from the finance share?",
                     source="tasks", trace_path=case.trace)
    _ready(case.log)
    case.log.record_agent_message(
        "CASE_QUESTION: Which files were deleted from the finance share?")
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert _cq_issues(_check(case.log)) == []


def test_a_legacy_marker_matching_a_tracked_request_by_wording_is_skipped(case):
    (case.dir / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "tasks": [{"id": "task-0001", "status": "answered",
                   "text": "Which files were deleted from the finance share? Include what can be recovered."}],
        "next_id": 2}), encoding="utf-8")
    _ready(case.log)
    case.log.record_agent_message(
        "CASE_QUESTION: Which files were deleted from the finance share?")
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert _cq_issues(_check(case.log)) == []


def test_the_standard_objective_never_blocks(case):
    from core.investigation_tasks import DEFAULT_OBJECTIVE
    record_objective(case.dir, text=DEFAULT_OBJECTIVE, source="default", trace_path=case.trace)
    _ready(case.log)
    result = _check(case.log)
    assert _cq_issues(result) == []
    assert any("Nothing recorded at CONFIRMED or LIKELY" in w for w in _warnings(result))
    case.log.record_finding("A scheduled task started an unsigned binary from a temp folder",
                            "LIKELY", "ez.evtxecmd")
    result = _check(case.log)
    assert _cq_issues(result) == []
    assert not any("Nothing recorded at CONFIRMED or LIKELY" in w for w in _warnings(result))


def test_a_free_umbrella_question_is_not_word_gated(case):
    record_objective(case.dir, text="What happened on the systems?", source="question",
                     trace_path=case.trace)
    _ready(case.log)
    case.log.record_finding("The disk image hash was verified", "CONFIRMED", "ewf.info")
    assert _cq_issues(_check(case.log)) == []


# ── the record ─────────────────────────────────────────────────────────────

def test_record_round_trip_and_trace_binding(tmp_path):
    (tmp_path / ".atlas").mkdir()
    trace = str(tmp_path / "analysis" / "t_trace.json")
    record_objective(tmp_path, text="Which host was accessed first?", source="question",
                     trace_path=trace)
    rec = read_objective(tmp_path)
    assert rec["text"] == "Which host was accessed first?" and rec["source"] == "question"
    assert read_objective(tmp_path, trace_path=trace)["source"] == "question"
    assert read_objective(tmp_path, trace_path=str(tmp_path / "other.json")) is None


def test_record_refuses_an_unknown_source_and_needs_a_case_store(tmp_path):
    with pytest.raises(ValueError):
        record_objective(tmp_path, text="x", source="elsewhere")
    assert record_objective(tmp_path, text="x", source="question") is None  # no .atlas/
    assert read_objective(tmp_path) is None


def test_a_fresh_run_clears_the_record(tmp_path, monkeypatch):
    from tools.misc import clear_case_run
    home = tmp_path / "home"
    home.mkdir()
    real_expanduser = os.path.expanduser
    monkeypatch.setattr(os.path, "expanduser",
                        lambda p: str(home) + p[1:] if p == "~" or p.startswith("~/")
                        else real_expanduser(p))
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / ".atlas").mkdir()
    record_objective(case, text="Which host was accessed first?", source="question")
    assert (case / ".atlas" / OBJECTIVE_FILE).is_file()
    clear_case_run(str(case), clear_memory=False)
    assert not (case / ".atlas" / OBJECTIVE_FILE).exists()


def test_the_cli_names_the_objective_source(tmp_path):
    from agent.cli import _objective_source
    (tmp_path / ".atlas").mkdir()
    assert _objective_source(SimpleNamespace(question="Who logged on?"), tmp_path) == "question"
    assert _objective_source(SimpleNamespace(question=""), tmp_path) == "default"
    (tmp_path / "CASE.md").write_text(
        "# Case\n\n## Investigation Requests\n\n1. Which accounts were created?\n",
        encoding="utf-8")
    assert _objective_source(SimpleNamespace(question=None), tmp_path) == "tasks"
