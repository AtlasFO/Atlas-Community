"""A stopped run composes its answers before its report
and the report says it was stopped. Invented fixtures only (CASE-A,
CORP-WS01, dates in 2031)."""
from __future__ import annotations

import json

from core.investigation_exit import open_limit_lines, record_stop
from tests.core.test_incident_map import _case, _trace


def _tasks(case):
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "text": "When did the attacker reach CORP-WS01?", "status": "open"},
        {"id": "task-0002", "text": "Which account was used?", "status": "open"}]}), encoding="utf-8")


def test_a_stop_composes_every_question_and_the_report_says_so(tmp_path, monkeypatch):
    from core import report_assemble as R
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _tasks(case)
    asked = []
    monkeypatch.setattr("core.answer_synthesis.compose_on", lambda: True)
    monkeypatch.setattr("core.answer_synthesis.compose_answer", lambda root, task, *a, **k: asked.append(
        (task["id"], k.get("allow_calls"))) or {"outcome": "composed" if task["id"] == "task-0001" else "none"})
    monkeypatch.setattr("core.answer_synthesis.trace_composed", lambda *a, **k: None)
    log.add_work_item("host_pass", [], "", {"host": "CORP-WS01"}, "pass CORP-WS01", extra_key="hp")
    res = R.compose_at_stop(case)
    assert sorted(asked) == [("task-0001", True), ("task-0002", True)] and res["reached"]
    record_stop(case, "keyboard_interrupt", res)
    lines = open_limit_lines(case)
    assert lines[0] == "The run was stopped (keyboard_interrupt) with 1 item(s) still due: host_pass 1"
    assert not any("projections" in x for x in lines)


def test_an_unreachable_composer_leaves_projections_and_says_so(tmp_path, monkeypatch):
    from agent import cli
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _tasks(case)
    monkeypatch.setattr("core.report_assemble.compose_at_stop", lambda c: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr(cli, "_persist_run_status", lambda *a, **k: None)
    cli._compose_at_stop(case, {"stopped_reason": "keyboard_interrupt"})
    assert "Its answers are projections from the findings: the composer could not be reached at the stop" \
        in open_limit_lines(case)


def test_a_stop_writes_the_report_before_composing_and_rewrites_it(tmp_path, monkeypatch):
    from agent import cli
    from core.report_exit import exit_report_path
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _tasks(case)
    monkeypatch.setattr(cli, "_persist_run_status", lambda *a, **k: None)
    seen = []

    def compose(c):
        # A kill here must find a report on disk that says the answers are
        # projections not yet composed.
        seen.append(exit_report_path(case).read_text(encoding="utf-8"))
        return {"questions": 2, "outcomes": {"composed": 2}, "reached": True, "hurried": False}

    monkeypatch.setattr("core.report_assemble.compose_at_stop", compose)

    class Stopped:
        stats = {"stopped_reason": "keyboard_interrupt"}

        def _report_written(self):
            return False

    cli._reports_at_exit(case, Stopped(), Stopped.stats, True)
    assert len(seen) == 1 and "the composer had not answered" in seen[0]
    final = exit_report_path(case).read_text(encoding="utf-8")
    assert "the composer had not answered" not in final and "projections" not in final


def test_a_second_stop_request_ends_the_composition(tmp_path, monkeypatch):
    from core import report_assemble as R
    from core.report_projection import HURRY
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": f"task-000{i}", "text": f"Question {i}?", "status": "open"} for i in (1, 2, 3)]}), encoding="utf-8")
    calls = []

    def compose_answer(root, task, *a, breaker=None, **k):
        if breaker.tripped():
            return {"outcome": "fallback", "reason": f"breaker: {breaker.reason}"}
        calls.append(task["id"])
        HURRY.set()  # the second TERM lands during the first call
        return {"outcome": "composed"}

    monkeypatch.setattr("core.answer_synthesis.compose_on", lambda: True)
    monkeypatch.setattr("core.answer_synthesis.COMPOSE_WORKERS", 1)
    monkeypatch.setattr("core.answer_synthesis.compose_answer", compose_answer)
    monkeypatch.setattr("core.answer_synthesis.trace_composed", lambda *a, **k: None)
    try:
        res = R.compose_at_stop(case)
    finally:
        HURRY.clear()
    assert calls == ["task-0001"] and res["outcomes"] == {"composed": 1, "fallback": 2}
    assert res["hurried"] and not res["reached"]
    record_stop(case, "keyboard_interrupt", res)
    assert "2 answer(s) are projections from the findings: a second stop request ended the composition" \
        in open_limit_lines(case)


def test_questions_without_a_belief_are_not_projections(tmp_path, monkeypatch):
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    record_stop(case, "keyboard_interrupt", {"outcomes": {"none": 2}, "reached": True})
    assert not any("projections" in x for x in open_limit_lines(case))
    record_stop(case, "keyboard_interrupt", {"outcomes": {"composed": 1, "fallback": 1}, "reached": False})
    assert "1 answer(s) are projections from the findings: the composer did not answer them at the stop" \
        in open_limit_lines(case)
