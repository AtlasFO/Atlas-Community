"""A tool that only commissioned reviews still gets its own trace record;
a reason tool's review is its own record."""
from __future__ import annotations

from core import middleware
from core.execution_log import ExecutionLog


def _log(tmp_path, monkeypatch):
    log = ExecutionLog()
    log.configure("BASE", str(tmp_path / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return log


def test_a_refused_finding_that_ran_a_review_keeps_its_baseline(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    log.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
    middleware._trace_success_baseline(
        "misc_record_finding", 0.1, before,
        result={"success": False, "gate": "evidence_strength", "error": "refused"},
        args={"description": "x"})
    kinds = [e["type"] for e in log._entries[before:]]
    assert kinds == ["reason_call", "tool_call"]
    assert log._entries[-1]["cmd"] == "<py>:misc_record_finding"
    assert log._entries[-1]["success"] is False


def test_a_reason_tools_own_review_is_its_record(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    log.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
    middleware._trace_success_baseline(
        "reason_evaluate_finding", 0.1, before,
        result={"success": True, "conclusion": "VERDICT: SUPPORTED"}, args={})
    assert [e["type"] for e in log._entries[before:]] == ["reason_call"]


def test_a_tool_that_logged_a_call_of_its_own_is_left_alone(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    log.record_tool_call("evtexport -m all SecEvent.Evt", True, False, 0, 0)
    middleware._trace_success_baseline("evt_evt_export", 0.1, before,
                                       result={"success": True}, args={})
    assert [e["type"] for e in log._entries[before:]] == ["tool_call"]
    assert log._entries[-1]["cmd"].startswith("evtexport")


def test_a_recorded_finding_is_its_own_record(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    log.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
    log.record_finding("claim", "CONFIRMED", "src", 0, "")
    middleware._trace_success_baseline("misc_record_finding", 0.1, before,
                                       result={"success": True}, args={})
    assert [e["type"] for e in log._entries[before:]] == ["reason_call", "finding"]
