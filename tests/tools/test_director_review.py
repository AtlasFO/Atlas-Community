"""The director's review job (ATLAS_DIRECTOR_REVIEW): it reads the
questions, the order, what each question's claims rest on and the findings
since its last review, and answers with work items and rulings on the
order's items. Invented fixtures only (CORP-WS04, jane.doe, dates in 2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

CSV = "evidence/corp-ws04_timeline.csv"


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    (root / CSV).write_text("date,time,desc\n", encoding="utf-8")
    (root / "evidence" / "corp-ws04.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS04", "path": "evidence/corp-ws04.raw"}]}), encoding="utf-8")
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "status": "open", "text": "Which account ran upd.exe?", "related_claim_ids": []},
        {"id": "task-0002", "status": "partial", "text": "When did it start?", "related_claim_ids": []}]}),
        encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    return root, log


def test_the_prompt_is_the_job_not_the_batch_plan(monkeypatch):
    from tools.dair import _dair_sys
    text = _dair_sys()
    assert "Your job is the work order." in text and '"work_items": []' in text
    assert "executes ONLY what you list" not in text and "ALSO run anti-forensics detectors" not in text
    assert "BEFORE reason.synthesize, call BOTH" not in text and "PHASE STACK:" in text
    monkeypatch.setenv("ATLAS_DIRECTOR_REVIEW", "0")
    assert "executes ONLY what you list" in _dair_sys()
    monkeypatch.setenv("ATLAS_DIRECTOR_REVIEW", "1")
    monkeypatch.setenv("ATLAS_WORK_ORDER", "0")
    assert "executes ONLY what you list" in _dair_sys()


def test_the_review_block_holds_questions_order_claims_and_new_findings(case):
    root, log = case
    from core import claim_graph as G
    from tools.dair import _review_block
    due = log.add_work_item("plan", ["task-0001"], "table_table_grep", {"path": CSV, "pattern": "upd.exe"}, "x")
    log.add_work_item("index", [], "", {"host": "CORP-WS04", "source_hint": "C/Users/jane.doe/NTUSER.DAT"},
                      "the case index lists NTUSER.DAT", status="proposed")
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt="row")
    claim = G.upsert_claim_from_finding(root, statement="jane.doe ran upd.exe on CORP-WS04",
                                        confidence="LIKELY", finding_call_id=cid + 1000, input_call_ids=[cid],
                                        analyst_call_ids=[cid], fresh=True)["claim_id"]
    tasks = json.loads((root / ".atlas" / "investigation_tasks.json").read_text())
    tasks["tasks"][0]["related_claim_ids"] = [claim]
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps(tasks))
    log.record_finding("jane.doe ran upd.exe on CORP-WS04", "LIKELY", source="test")
    block = _review_block()
    assert "QUESTIONS (all; status | items due/done/failed | claims linked | question):" in block
    assert "- task-0001 open     | 1/0/0 | 1 | Which account ran upd.exe?" in block
    assert f"- task-0001: {claim} rests on call {cid}" in block
    assert f"#{due['call_id']}" in block and "PROPOSED (adopt with a target, or keep with a note):" in block
    assert "NEW FINDINGS SINCE THE LAST REVIEW:" in block and "jane.doe ran upd.exe" in block


def _assess(raw: dict):
    from tools.dair import dair_assess
    with patch("tools.dair._ask", return_value={"success": True, "raw": "DAIR_ASSESSMENT " + json.dumps(raw),
                                                "input_tokens": 1, "output_tokens": 1}):
        return dair_assess("review", phase_stack=None)


def test_work_items_and_rulings_from_the_reply(case):
    root, log = case
    prop = log.add_work_item("index", [], "", {"host": "CORP-WS04", "source_hint": "NTUSER.DAT"},
                             "the case index lists NTUSER.DAT", status="proposed")
    stale = log.add_work_item("plan", ["task-0002"], "table_table_grep", {"path": CSV, "pattern": "4624"}, "y")
    raw = {"current_phase": "Analyze", "stack_action": "stay", "directives": {"priority_tools": []},
           "work_items": [
               {"task_ids": ["task-0001"], "tool": "table.table_grep", "host": "CORP-WS04",
                "source": "corp-ws04_timeline.csv", "pattern": "upd.exe", "why": "who ran it"},
               {"task_ids": ["task-0001"], "tool": "nope.tool", "host": "CORP-WS04", "source": "x", "why": "bad"}],
           "deferred_intent_dispositions": [
               {"call_id": prop["call_id"], "action": "promote", "inner_path": "C/Users/jane.doe/NTUSER.DAT"},
               {"call_id": stale["call_id"], "action": "dismiss", "basis_call_id": 999}]}
    with patch("core.question_plan.reading_tools", return_value=[("table.table_grep", "search tables")]):
        r = _assess(raw)
    added = [i for i in log.work_items() if i["origin"] == "director"]
    assert len(added) == 1 and added[0]["target"]["pattern"] == "upd.exe" and added[0]["status"] == "due"
    assert r["work_items_refused"] and "table.table_grep" in r["directives"]["priority_tools"]
    assert prop["status"] == "due" and prop["target"]["inner_path"] == "C/Users/jane.doe/NTUSER.DAT"
    rulings = {x["id"]: x for x in r["work_item_rulings"]}
    assert rulings[stale["call_id"]]["ok"] is False and "neither read nor failed" in rulings[stale["call_id"]]["error"]
    assert stale["status"] == "due"


def test_the_loop_review_carries_the_analysts_latest_notes(case, monkeypatch):
    root, log = case
    from agent.loop import Agent
    from tests.agent.test_loop_reliability import _ScriptedClient, _StubToolbox
    agent = Agent(_ScriptedClient([]), _StubToolbox(), case_dir=root, quiet=True)
    agent.case_dir = str(root)
    agent._log = lambda rec: None
    agent.messages = [{"role": "assistant", "content": "Next I will read the Prefetch folder of CORP-WS04."}]
    seen = {}
    monkeypatch.setattr("tools.dair.dair_assess", lambda summary, phase_stack=None: seen.setdefault("s", summary) and {})
    agent._director_event(3, "due_set_empty")
    assert "ANALYST'S LATEST NOTES" in seen["s"] and "Prefetch folder of CORP-WS04" in seen["s"]


def test_a_host_less_proposal_is_adopted_with_a_host_and_a_digit_string_id_counts(case):
    root, log = case
    prop = log.add_work_item("reason", [], "ez.recmd_hive", {"source_hint": "NTUSER.DAT"}, "who ran it",
                             status="proposed")
    item = log.add_work_item("plan", ["task-0002"], "table_table_grep", {"path": CSV, "pattern": "upd.exe"}, "y")
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt="0 rows")
    log.annotate_tool_call(cid, args=json.dumps({"path": CSV, "pattern": "upd.exe"}), mcp_tool="table_table_grep")
    raw = {"current_phase": "Analyze", "stack_action": "stay", "directives": {"priority_tools": []},
           "work_items": [{"task_ids": ["task-0001"], "tool": "table.table_grep", "host": "CORP-WS99",
                           "source": "x.csv", "pattern": "a", "why": "w"}],
           "deferred_intent_dispositions": [
               {"call_id": str(prop["call_id"]), "action": "promote", "host": "corp-ws04",
                "inner_path": "Users/jane.doe/NTUSER.DAT"},
               {"call_id": item["call_id"], "action": "dismiss", "basis_call_id": str(cid)}]}
    with patch("core.question_plan.reading_tools", return_value=[("table.table_grep", "search tables")]):
        r = _assess(raw)
    assert prop["status"] == "due" and prop["target"]["host"] == "CORP-WS04"
    assert prop["target"]["path"] == "evidence/corp-ws04.raw"
    assert item["status"] == "dismissed" and item["basis_call_id"] == cid
    assert "host CORP-WS99 is not a host of this case" in r["work_items_refused"][0]
    from tools.dair import _review_block
    assert "REFUSED AT THE LAST REVIEW" in _review_block() and "CORP-WS99" in _review_block()


def test_the_review_block_names_the_readers_by_format(case):
    root, log = case
    log.add_work_item("plan", ["task-0001"], "table_table_grep", {"path": CSV, "pattern": "upd.exe"}, "x")
    from tools.dair import _review_block
    assert "READERS BY INPUT FORMAT" in _review_block()


def test_a_failed_item_is_shown_as_closed_without_a_ruling(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "table_table_grep", {"path": CSV, "pattern": "upd.exe"}, "x")
    item["status"] = "failed"
    item["outcome"] = "file unreadable"
    from tools.dair import _DIRECTOR_JOB, _review_block
    block = _review_block()
    assert "FAILED (closed, no ruling" in block and f"#{item['call_id']}" in block
    assert "rulings are for due and proposed items" in _DIRECTOR_JOB


def test_no_ruling_rewrites_a_closed_item(case):
    root, log = case
    from core import work_order as W
    item = log.add_work_item("plan", ["task-0001"], "table_table_grep", {"path": CSV, "pattern": "upd.exe"}, "x")
    item.update(status="failed", outcome="unreadable")
    for action in ("dismiss", "promote", "keep"):
        r = W.dispose_work_item(log, item["call_id"], action, basis_call_id=1, target={"inner_path": "x"}, note="n")
        assert r["ok"] is False and "closed items take no ruling" in r["error"]
    assert item["status"] == "failed" and item["outcome"] == "unreadable" and "keep_note" not in item


def test_a_refused_promote_is_shown_to_the_next_review_with_keep_as_the_ruling(case):
    root, log = case
    series = log.add_work_item("series", [], "", None, "3 of 40 logs read", status="proposed")
    raw = {"current_phase": "Analyze", "stack_action": "stay", "directives": {"priority_tools": []},
           "work_items": [],
           "deferred_intent_dispositions": [{"call_id": series["call_id"], "action": "promote", "note": "read them"}]}
    r = _assess(raw)
    assert series["status"] == "proposed"
    ruling = r["work_item_rulings"][0]
    assert ruling["ok"] is False and "no target a call can reach" in ruling["error"] and ruling["error"].endswith("or keep")
    assert r["work_items_refused"] == [f"ruling promote #{series['call_id']}: {ruling['error']}"[:300]]
    from tools.dair import _last_refused_reads
    assert _last_refused_reads() == r["work_items_refused"]
    from tools.dair import _review_block
    assert "REFUSED AT THE LAST REVIEW" in _review_block() and "or keep" in _review_block()
