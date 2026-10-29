"""The work order in the loop: the closing hook, the
per-turn block, neglect by streak, and the report ladder keyed on items.
Invented fixtures only (CORP-WS01, jane.doe, dates in 2031)."""
from __future__ import annotations

import json

import pytest

from agent import loop as loop_mod
from agent.loop import Agent
from core.execution_log import ExecutionLog
from tests.agent.test_loop_reliability import _ScriptedClient, _StubToolbox

CSV = "evidence/corp-ws01_timeline.csv"


@pytest.fixture
def run(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    (root / CSV).write_text("date,time,desc\n", encoding="utf-8")
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
        {"tasks": [{"id": "task-0001", "status": "open", "text": "Which account logged on?"},
                   {"id": "task-0002", "status": "open", "text": "When?"}]}), encoding="utf-8")
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    agent = Agent(_ScriptedClient([]), _StubToolbox(), case_dir=root, quiet=True)
    agent.case_dir = str(root)
    events = []
    agent._log = events.append
    return root, log, agent, events


def _read(log, path=CSV):
    cid = log.record_tool_call("<py>:strings_strings_read_text", True, False, 0, 0, stdout_excerpt="x")
    log.annotate_tool_call(cid, args=json.dumps({"file": path}), mcp_tool="strings_strings_read_text")
    return cid


def test_the_hook_closes_the_item_a_call_reached(run):
    root, log, agent, _events = run
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    mark = agent._trace_length()
    _read(log)
    agent._close_work_items("strings_strings_read_text", {"file": CSV}, mark)
    assert item["status"] == "resolved" and agent._wo_moved == {item["call_id"]}
    assert ("item", item["call_id"]) in agent._report_done()


def test_a_replayed_call_closes_by_the_original_entry(run):
    root, log, agent, _events = run
    cid = _read(log)
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": "evidence/x.txt"}, "x")
    (root / "evidence" / "x.txt").write_text("x")
    cid2 = _read(log, "evidence/x.txt")
    item["status"] = "due"
    agent._close_work_items("strings_strings_read_text", {"file": "evidence/x.txt"}, 0, replay_of=cid2)
    assert item["status"] == "resolved" and item["basis_call_id"] == cid2 and cid


def test_the_block_is_shown_last_and_neglect_fires_after_the_streak(run, monkeypatch):
    root, log, agent, events = run
    monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 3)
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    for turn in range(1, 5):
        agent._work_order_turn(turn, False)
    assert agent.messages and "[work order]" in agent.messages[-1]["content"]
    assert [e for e in events if e.get("event") == "work_order_neglected"]
    assert agent.work_order_settled() is True


def test_one_movement_ends_the_streak(run, monkeypatch):
    root, log, agent, events = run
    monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 3)
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    other = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": "evidence/y.txt"}, "y")
    (root / "evidence" / "y.txt").write_text("y")
    agent._work_order_turn(1, False)
    agent._work_order_turn(2, False)
    mark = agent._trace_length()
    _read(log, "evidence/y.txt")
    agent._close_work_items("strings_strings_read_text", {"file": "evidence/y.txt"}, mark)
    agent._work_order_turn(3, False)
    agent._work_order_turn(4, False)
    assert other["status"] == "resolved"
    assert not [e for e in events if e.get("event") == "work_order_neglected"]
    assert agent.work_order_settled() is False


def test_the_finish_names_the_open_work_once_and_ends_when_called_again_right_away(run):
    root, log, agent, _events = run
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    msg = agent._finish_coverage_check(wall_expired=False)
    assert "atlas_finish deferred: work is still open" in msg and "strings_read_text" in msg
    assert "task-0001: read evidence for Which account logged on?" in msg and "task-0002: read evidence for When?" in msg
    assert "or limit one the evidence cannot answer with its basis" in msg and "link the finding" not in msg  # no binding invited
    assert agent._finish_coverage_check(wall_expired=False) == ""          # no model call since: ends


def test_after_model_work_the_finish_is_deferred_again_only_for_open_work_not_named_yet(run):
    root, log, agent, _events = run
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    assert agent._finish_coverage_check(wall_expired=False) != ""
    agent._model_calls = getattr(agent, "_model_calls", 0) + 1            # the model worked, nothing new
    assert agent._finish_coverage_check(wall_expired=False) == ""
    (root / "evidence" / "y.txt").write_text("y", encoding="utf-8")
    log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": "evidence/y.txt"}, "y")
    agent._model_calls += 1                                                # more work, a new item
    msg = agent._finish_coverage_check(wall_expired=False)
    assert "evidence/y.txt" in msg
    assert agent._finish_coverage_check(wall_expired=False) == ""


def test_a_new_open_item_without_a_model_call_since_the_deferral_does_not_defer_again(run):
    root, log, agent, _events = run
    assert agent._finish_coverage_check(wall_expired=False) != ""
    (root / "evidence" / "y.txt").write_text("y", encoding="utf-8")
    log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": "evidence/y.txt"}, "y")
    assert agent._finish_coverage_check(wall_expired=False) == ""          # new, but no model call since


def test_the_finish_passes_on_an_empty_list_and_on_the_wall_clock(run):
    root, log, agent, _events = run
    assert agent._finish_coverage_check(wall_expired=True) == ""
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": []}), encoding="utf-8")
    assert agent._finish_coverage_check(wall_expired=False) == ""


def test_moot_items_do_not_hold_the_run(run):
    root, log, agent, _events = run
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
        {"tasks": [{"id": "task-0001", "status": "answered", "text": "q"}]}), encoding="utf-8")
    assert agent._finish_coverage_check(wall_expired=False) == ""
    assert agent.work_order_settled() is True


def test_switch_off_keeps_todays_path(run, monkeypatch):
    root, log, agent, _events = run
    monkeypatch.setenv("ATLAS_WORK_ORDER", "0")
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    agent._work_order_turn(1, False)
    mark = agent._trace_length()
    _read(log)
    agent._close_work_items("strings_strings_read_text", {"file": CSV}, mark)
    assert item["status"] == "due" and not agent.messages and agent.work_order_settled() is True
    assert "UNRESOLVABLE" in agent._report_stall_msg()


def test_the_stall_ladder_waits_for_the_order():
    from core.run_budget import StallState, messages_for_turn, STALL_HARD_TURNS, STALL_FORCE_REPORT_GRACE
    st = StallState()
    st.hard_injected = True
    st.no_progress_streak = STALL_HARD_TURNS + STALL_FORCE_REPORT_GRACE
    out = messages_for_turn(st, turn=9, report_written=False, work_order=(False, ['tsk_icat(image="x")']))
    assert "[stall work-order redirect]" in out[-1]["content"] and 'tsk_icat(image="x")' in out[-1]["content"]
    st2 = StallState()
    st2.hard_injected = True
    st2.no_progress_streak = STALL_HARD_TURNS + STALL_FORCE_REPORT_GRACE
    out2 = messages_for_turn(st2, turn=9, report_written=False, work_order=(True, []))
    assert "[stall force-report]" in out2[-1]["content"]


def test_a_loop_review_moves_the_phase_parses_its_reads_and_leaves_one_line(run, monkeypatch):
    root, log, agent, events = run
    (root / "evidence" / "corp-ws01.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-WS01", "path": "evidence/corp-ws01.raw"}]}), encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    calls = []

    def fake(summary, phase_stack=None, **_kw):
        calls.append(summary)
        return {"current_phase": "Analyze", "_atlas_call_id": 5,
                "directives": {"priority_tools": ["ez.pecmd | CORP-WS01 C/Windows/Prefetch"]}}
    monkeypatch.setattr("tools.dair.dair_assess", fake)
    agent._dair_phase = "Collect"
    agent._director_event(3, "neglected")
    assert calls and calls[0].startswith("[loop review: neglected]")
    assert agent._dair_phase == "Analyze"
    assert [i["origin"] for i in log.work_items()] == ["director"]
    assert agent._wo_director_line.startswith("[director] phase Analyze (was Collect); added 1 items")


def test_a_failed_review_is_logged_and_skipped(run, monkeypatch):
    root, log, agent, events = run

    def boom(*_a, **_k):
        raise RuntimeError("provider down")
    monkeypatch.setattr("tools.dair.dair_assess", boom)
    agent._director_event(3, "due_set_empty")
    assert [e for e in events if e.get("event") == "work_order_director_review_failed"]


def test_the_plan_runs_once_the_inventory_gate_holds(run, monkeypatch):
    root, log, agent, events = run
    seen = []
    monkeypatch.setattr("core.evidence_inventory_gate.inventory_satisfied", lambda _c: True)
    monkeypatch.setattr("core.question_plan.reading_tools", lambda: [("ez.pecmd", "Prefetch")])

    def plan(_log, _case, task, tools=None, extra="", **_kw):
        seen.append(task["id"])
        return {"items": [], "invalid": 0, "empty": True, "reads": 0, "reason": "the plan reply held no read"}
    monkeypatch.setattr("core.question_plan.plan_question", plan)
    agent._derive_work_items(1)
    agent._derive_work_items(2)
    assert sorted(seen) == ["task-0001", "task-0002"]
    empty = [e for e in events if e.get("event") == "work_order_plan_empty"]
    assert empty and all(e["reason"] == "the plan reply held no read" for e in empty)



def test_the_progress_line_comes_every_twenty_actions_without_a_director_call(run):
    root, log, agent, _events = run
    for i in range(19):
        log.record_tool_call(f"<py>:strings_strings_read_text_{i}", True, False, 0, 0)
    assert agent._progress_line(1) == ""
    log.record_tool_call("<py>:strings_strings_read_text_x", True, False, 0, 0)
    line = agent._progress_line(2)
    assert line.startswith("[progress] last 20 actions:") and "Questions:" in line
    assert agent._progress_line(3) == ""


def test_the_progress_line_counts_neither_a_running_job_nor_a_call_of_no_analyst_tool(run):
    """A background job's start reads nothing while the job runs, and an
    entry the pre-run pass wrote is no analyst's read (the read rule)."""
    root, log, agent, _events = run
    for i in range(18):
        log.record_tool_call(f"<py>:strings_strings_read_text_{i}", True, False, 0, 0)
    cid = log.record_tool_call("[background job 20310301T081200_plaso_targeted_7_0] log2timeline.py "
                               "evidence/CORP-WS01.raw", True, False, 0, 0)
    log.annotate_tool_call(cid, mcp_tool="plaso_plaso_create_targeted")
    log.record_tool_call("mmls evidence/CORP-WS01.raw", True, False, 0, 0)
    assert "18 reads of new sources (0 failed)" in agent._progress_line(1)


def test_the_intake_count_opens_the_next_block(run, monkeypatch):
    root, log, agent, events = run
    monkeypatch.setenv("ATLAS_ESTATE_COUNT_ASYNC", "0")
    (root / CSV).write_text("date,time,desc\n03/01/2031,08:12:00,connect 203.0.113.9\n", encoding="utf-8")
    from core.ioc_pivots import record_counts
    record_counts(root, {"ip:203.0.113.9": {}})
    monkeypatch.setattr("core.evidence_inventory_gate.inventory_satisfied", lambda _c: True)
    monkeypatch.setattr(agent, "_estate_tables", lambda: [CSV])
    agent._estate_count_turn(1)
    assert any(line.startswith("- ip 203.0.113.9: 1 rows") for line in agent._wo_count_lines)
    entry = [e for e in log._entries if e.get("kind") == "count"][-1]
    assert entry["cmd"] == "<py>:coverage_count_indicators"
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    agent._work_order_turn(2, False)
    assert "[estate counts]" in agent.messages[-1]["content"]


def test_a_replan_of_reads_already_done_exhausts_the_question(run, monkeypatch):
    root, log, agent, events = run
    agent._wo_plan_done = True
    done = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    mark = agent._trace_length()
    _read(log)
    agent._close_work_items("strings_strings_read_text", {"file": CSV}, mark)
    assert done["status"] == "resolved"
    calls = []

    def replan(_log, case, task, tools=None, extra=""):
        calls.append(task["id"])
        again = _log.add_work_item("plan", [task["id"]], "ez_evtxecmd", {"path": CSV}, "same file, other parser")
        return {"items": [again], "invalid": 0, "empty": False, "reads": 1}
    monkeypatch.setattr("core.question_plan.plan_question", replan)
    monkeypatch.setattr(agent, "_director_event", lambda *_a: None)
    agent._plan_questions(5, str(root), [{"id": "task-0001", "status": "open"}])
    agent._plan_questions(6, str(root), [{"id": "task-0001", "status": "open"}])
    assert calls == ["task-0001"]
    assert [e for e in events if e.get("event") == "work_order_plan_exhausted"]


def test_a_question_closing_is_movement(run, monkeypatch):
    root, log, agent, events = run
    monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 2)
    monkeypatch.setattr(agent, "_director_event", lambda *_a: None)
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": "evidence/y.txt"}, "y")
    agent._work_order_turn(1, False)
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
        {"tasks": [{"id": "task-0001", "status": "answered", "text": "q"},
                   {"id": "task-0002", "status": "open", "text": "q"}]}), encoding="utf-8")
    agent._work_order_turn(2, False)
    assert agent._wo_streak == 0


def test_the_count_reads_beside_the_analyst_and_its_lines_follow(run, monkeypatch):
    import threading
    root, log, agent, events = run
    (root / CSV).write_text("date,time,desc\n03/01/2031,08:12:00,connect 203.0.113.9\n", encoding="utf-8")
    from core.ioc_pivots import record_counts
    record_counts(root, {"ip:203.0.113.9": {}})
    monkeypatch.setattr("core.evidence_inventory_gate.inventory_satisfied", lambda _c: True)
    monkeypatch.setattr(agent, "_estate_tables", lambda: [CSV])
    gate = threading.Event()
    import tools.tabular as tab
    real = tab.count_indicators
    monkeypatch.setattr(tab, "count_indicators", lambda *a, **k: (gate.wait(5), real(*a, **k))[1])
    agent._estate_count_turn(1)                          # returns while the pass waits
    assert not getattr(agent, "_wo_count_lines", None)
    assert agent._work_order_headers(1)[-1].startswith("[estate counts] counting 1 tables for 1 indicators")
    gate.set()
    agent._estate_jobs[0]["thread"].join(5)
    agent._estate_count_turn(2)
    assert any(line.startswith("- ip 203.0.113.9: 1 rows") for line in agent._wo_count_lines)
    assert [e for e in log._entries if e.get("kind") == "count"] and not agent._estate_pending()


def test_a_pass_still_reading_is_applied_before_the_report(run, monkeypatch):
    import threading
    root, log, agent, events = run
    (root / CSV).write_text("date,time,desc\n03/01/2031,08:12:00,connect 203.0.113.9\n", encoding="utf-8")
    gate = threading.Event()
    import tools.tabular as tab
    real = tab.count_indicators
    monkeypatch.setattr(tab, "count_indicators", lambda *a, **k: (gate.wait(5), real(*a, **k))[1])
    agent._estate_count(1, ["ip:203.0.113.9"], [CSV], why="intake")
    threading.Timer(0.2, gate.set).start()
    agent._estate_join(2)                                 # the report's entry waits for the pass
    from core.ioc_pivots import load_pivots
    assert load_pivots(root)["pivots"]["ip:203.0.113.9"]["counts"][CSV]["full"] == 1
    assert not agent._estate_jobs


def test_a_failed_pass_is_recorded_and_releases_its_indicators(run, monkeypatch):
    root, log, agent, events = run
    import tools.tabular as tab
    monkeypatch.setattr(tab, "count_indicators", lambda *a, **k: (_ for _ in ()).throw(OSError("unreadable")))
    agent._estate_count(1, ["ip:203.0.113.9"], [CSV], why="intake")
    agent._estate_join(2)
    failed = [e for e in log._entries if e.get("cmd") == "<py>:coverage_count_indicators" and not e.get("success")]
    assert failed and "unreadable" in failed[-1]["stderr"] and "ip:203.0.113.9" not in agent._estate_counted


def test_the_tables_that_appeared_in_one_turn_are_counted_in_one_pass(run, monkeypatch):
    """A parser that writes one table per log leaves dozens at once; the
    turn's new tables go into one pass (one thread, one trace entry, one
    block naming each indicator's tables), not one pass per table, which
    filled the recent-action window with counts."""
    import threading
    root, log, agent, events = run
    other = "evidence/corp-dc01_timeline.csv"
    (root / CSV).write_text("date,time,desc\n03/01/2031,08:12:00,connect 203.0.113.9\n", encoding="utf-8")
    (root / other).write_text("date,time,desc\n03/02/2031,09:00:00,connect 203.0.113.9\n"
                              "03/02/2031,09:01:00,connect 203.0.113.9\n", encoding="utf-8")
    from core.ioc_pivots import record_counts
    record_counts(root, {"ip:203.0.113.9": {}})
    agent._estate_intake_done = True
    agent._estate_tables_seen = set()
    monkeypatch.setattr(agent, "_estate_tables", lambda: [CSV, other])
    gate = threading.Event()
    import tools.tabular as tab
    real = tab.count_indicators
    monkeypatch.setattr(tab, "count_indicators", lambda *a, **k: (gate.wait(5), real(*a, **k))[1])
    agent._estate_count_turn(1)
    assert len(agent._estate_jobs) == 1 and agent._estate_tables_seen == {CSV, other}
    assert agent._estate_pending().startswith("[estate counts] counting 2 tables for 1 indicators")
    assert [e for e in events if e.get("event") == "estate_count_started"] == [
        {"event": "estate_count_started", "turn": 1, "why": "new tables", "indicators": 1, "tables": 2}]
    gate.set()
    agent._estate_jobs[0]["thread"].join(5)
    agent._estate_count_turn(2)
    counted = [e for e in log._entries if e.get("kind") == "count"]
    assert len(counted) == 1 and json.loads(counted[0]["stdout_excerpt"])["tables"] == 2
    assert any(line.startswith(f"- new tables: 203.0.113.9 2 rows {other}") and f"1 rows {CSV}" in line
               for line in agent._wo_count_lines)
    agent._estate_count_turn(3)                           # nothing new: no pass
    assert len(agent._estate_jobs) == 0 and len([e for e in log._entries if e.get("kind") == "count"]) == 1


def _carve(root, log):
    """One extracted output, exports/carve (jpg/a.jpg, gif/d.gif), its
    producer given every file by the attribution ledger."""
    from core.coverage_ledger import register_derived_outputs
    from core.provenance import reset_cache
    reset_cache()
    names = ("jpg/a.jpg", "gif/d.gif")
    for n in names:
        (root / "exports" / "carve" / n).parent.mkdir(parents=True, exist_ok=True)
        (root / "exports" / "carve" / n).write_bytes(b"x")
    made = log.record_tool_call(f"foremost -o {root}/exports/carve evidence/corp-ws01.raw", True, False, 0, 0)
    log.annotate_tool_call(made, mcp_tool="carve_foremost_carve")
    (root / ".atlas" / "output_provenance.json").write_text(json.dumps({"files": {
        f"exports/carve/{n}": {"call": made, "class": "derived"} for n in names}}), encoding="utf-8")
    assert register_derived_outputs(root, tool_name="carve_foremost_carve",
                                    arguments={"image_path": "evidence/corp-ws01.raw", "output_dir": "exports/carve"},
                                    result_text='{"success": true}') == ["exports/carve"]


def _blocks(agent):
    return [m["content"] for m in agent.messages if m.get("role") == "user"
            and str(m.get("content") or "").startswith("Extracted file classes no call has read")]


def test_the_unread_classes_come_back_each_turn_after_the_due_items_only_from_the_finish_deferral_on(run):
    from core.coverage_ledger import EXTRACTED_OPEN_HEAD
    root, log, agent, _events = run
    _carve(root, log)
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    agent._work_order_turn(1, False)
    assert not _blocks(agent)                                        # no deferral yet: the order alone
    assert agent._finish_coverage_check(wall_expired=False) != ""    # the first deferral names the classes
    agent._work_order_turn(2, False)
    agent._work_order_turn(3, False)
    (block,) = _blocks(agent)                                        # the standing copy replaced, never stacked
    assert block.startswith(EXTRACTED_OPEN_HEAD) and "read \"exports/carve/jpg/a.jpg\" (jpg, 0 of 1 read)" in block
    assert agent.messages[-1]["content"] == block                    # last, after the due items
    assert "[work order]" in agent.messages[-2]["content"]
    _read(log, "exports/carve/jpg/a.jpg")
    agent._work_order_turn(4, False)
    (block,) = _blocks(agent)
    assert "jpg" not in block and "read \"exports/carve/gif/d.gif\" (gif, 0 of 1 read)" in block
    _read(log, "exports/carve/gif/d.gif")
    agent._work_order_turn(5, False)
    assert not _blocks(agent)                                        # every class read: the block is gone


def test_a_class_whose_only_file_failed_two_reads_leaves_the_turn_block_one_failure_does_not(run):
    root, log, agent, _events = run
    _carve(root, log)
    assert agent._finish_coverage_check(wall_expired=False) != ""
    _read(log, "exports/carve/jpg/a.jpg")

    def fail():
        cid = log.record_tool_call("<py>:strings_strings_read_text", False, False, 0, 0, stdout_excerpt="unreadable")
        log.annotate_tool_call(cid, args=json.dumps({"file": "exports/carve/gif/d.gif"}),
                               mcp_tool="strings_strings_read_text")
    fail()
    agent._work_order_turn(1, False)
    assert 'read "exports/carve/gif/d.gif"' in _blocks(agent)[0]       # one failure: still offered
    fail()
    agent._work_order_turn(2, False)
    assert not _blocks(agent)            # two failures: nothing left to offer; the report still counts gif


# -- the readers the class block names load with the due items' tools, in one load --

class _LoadingToolbox(_StubToolbox):
    """A toolbox with one free slot: a load evicts a loaded namespace not
    kept (as the budgeted loader does), so a second load in the same turn
    with its own keep set would evict what the first brought in."""

    def __init__(self):
        from types import SimpleNamespace as NS
        self.tools = {"table_table_grep": NS(namespace="table", listed="table_grep"),
                      "steg_steg_extract": NS(namespace="steg", listed="steg_extract"),
                      "strings_strings_exiftool_metadata": NS(namespace="strings",
                                                               listed="strings_exiftool_metadata")}
        self.loaded = {"misc"}
        self.control_names = frozenset()
        self.loads = []

    def resolve(self, name):
        listed = str(name).replace(".", "_")                 # the dotted alias a work item carries
        return next((k for k, i in self.tools.items() if listed in (k, i.listed)), None)

    def load_with_budget(self, namespaces, *, keep=(), evict=True):
        self.loads.append({"wanted": list(namespaces), "keep": list(keep), "evict": evict})
        evicted = []
        for ns in namespaces:
            if ns in self.loaded:
                continue
            victim = next((v for v in sorted(self.loaded) if v not in keep), None)
            if victim is not None and evict:
                self.loaded.discard(victim)
                evicted.append(victim)
            self.loaded.add(ns)
        return {"newly_loaded": list(namespaces), "refused": [], "evicted": evicted}


READERS = [
    ("steg_steg_extract", {"properties": {"image_path": {"type": "string"}, "output_dir": {"type": "string"}},
                           "required": ["image_path", "output_dir"]}, "Extract hidden data.",
     {"reads": ["image/jpeg", "image/gif"]}),
    ("strings_strings_exiftool_metadata", {"properties": {"file_path": {"type": "string"}},
                                           "required": ["file_path"]}, "Extract metadata.",
     {"reads": ["image/*"], "depth": "metadata"}),
]


def test_the_class_blocks_readers_load_with_the_due_items_tools_in_one_load(run, monkeypatch):
    root, log, agent, _events = run
    monkeypatch.setenv("ATLAS_TOOL_ARRAY_STABLE", "0")
    monkeypatch.setattr("tools.tool_capabilities.registered_tool_schemas", lambda: READERS)
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    agent.toolbox = _LoadingToolbox()
    agent._tools_ok_at = 0
    _carve(root, log)
    log.add_work_item("plan", ["task-0001"], "table_grep", {"path": CSV, "pattern": "jane.doe"}, "x")
    assert agent._finish_coverage_check(wall_expired=False) != ""
    agent._work_order_turn(2, False)
    (block,) = _blocks(agent)
    assert "read \"exports/carve/jpg/a.jpg\" with steg_extract or strings_exiftool_metadata (metadata only)" in block
    assert len(agent.toolbox.loads) == 1                              # one load for the turn
    load = agent.toolbox.loads[0]
    assert load["wanted"] == ["table", "steg", "strings"] and load["keep"] == ["table", "steg", "strings"]
    assert {"table", "steg", "strings"} <= agent.toolbox.loaded      # the due item's namespace survived


def test_a_refused_finding_defers_the_finish_alone_then_the_list_then_the_run_ends(run):
    """Each open refused finding defers the finish once on its own line; the
    next finish shows the open-work list; the one after ends the run. The
    state is on the refusal's trace entry."""
    from core import middleware
    root, log, agent, _events = run
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    before = len(log._entries)
    desc = "README_RESTORE.txt on CORP-WS01 names 203.0.113.7. No other note exists."
    middleware._trace_success_baseline(
        "misc_record_finding", 0.1, before,
        result={"success": False, "gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
                "error": "refused", "description": desc, "objected_sentences": ["No other note exists."]},
        args={"description": desc, "confidence": "LIKELY"})
    rid = log._entries[-1]["call_id"]
    first = agent._finish_coverage_check(wall_expired=False)
    assert first.startswith("atlas_finish deferred for one refused finding") and f"call {rid}" in first
    assert "\n" not in first and "strings_read_text" not in first
    assert log.index().by_call_id[rid]["finish_deferred"] is True
    second = agent._finish_coverage_check(wall_expired=False)
    assert second.startswith("atlas_finish deferred: work is still open") and "strings_read_text" in second
    assert agent._finish_coverage_check(wall_expired=False) == ""


def test_the_same_refused_text_again_does_not_re_arm_its_own_deferral(run):
    """The own deferral belongs to the finding's text: the same text refused
    again goes to the open-work list at the next finish; a reworded finding
    is a new one and gets its own deferral once."""
    from core import middleware
    root, log, agent, _events = run
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")

    def refuse(desc):
        before = len(log._entries)
        middleware._trace_success_baseline(
            "misc_record_finding", 0.1, before,
            result={"success": False, "gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
                    "error": "refused", "description": desc, "objected_sentences": ["No other note exists."]},
            args={"description": desc, "confidence": "LIKELY"})
    desc = "README_RESTORE.txt on CORP-WS01 names 203.0.113.7. No other note exists."
    refuse(desc)
    assert agent._finish_coverage_check(wall_expired=False).startswith("atlas_finish deferred for one refused")
    refuse(desc)
    agent._model_calls = getattr(agent, "_model_calls", 0) + 1
    assert agent._finish_coverage_check(wall_expired=False).startswith("atlas_finish deferred: work is still open")
    refuse("README_RESTORE.txt on CORP-WS01 names 203.0.113.7 and 0042-7781. No other note exists.")
    agent._model_calls += 1
    assert agent._finish_coverage_check(wall_expired=False).startswith("atlas_finish deferred for one refused")


def test_parsed_outputs_defer_the_finish_once_per_set_after_the_refused_findings(run, monkeypatch):
    """Refused findings first, then one deferral naming every parsed output
    no row of which was looked at (each with its query step), then the
    open-work list, then the run ends. The same outputs again do not defer
    again; a new output defers once more, naming them all. A class no
    output holds a row of has no query step and stays on the list."""
    from core import middleware
    from core import work_order as W
    root, log, agent, _events = run
    outs = [{"output": "analysis/evtx_csv/CORP-WS01.csv", "no_rows": False, "overwritten": False,
             "classes": ["CORP-WS01: Windows event logs"], "filters": ["event ids 4624"]},
            {"output": "", "no_rows": True, "overwritten": False, "classes": ["CORP-WS01: Windows event logs"],
             "filters": ["event ids 4720"]}]
    monkeypatch.setattr(W, "parsed_outputs", lambda _case: list(outs))
    log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    before = len(log._entries)
    desc = "README_RESTORE.txt on CORP-WS01 names 203.0.113.7. No other note exists."
    middleware._trace_success_baseline(
        "misc_record_finding", 0.1, before,
        result={"success": False, "gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
                "error": "refused", "description": desc, "objected_sentences": ["No other note exists."]},
        args={"description": desc, "confidence": "LIKELY"})
    assert agent._finish_coverage_check(wall_expired=False).startswith("atlas_finish deferred for one refused")
    parsed = agent._finish_coverage_check(wall_expired=False)
    assert parsed.startswith("atlas_finish deferred for the parsed outputs no row of which was looked at")
    assert '- query "analysis/evtx_csv/CORP-WS01.csv": 1 class(es) (parsed with event ids 4624 only)' in parsed
    assert "strings_read_text" not in parsed and "4720" not in parsed
    listed = agent._finish_coverage_check(wall_expired=False)
    assert listed.startswith("atlas_finish deferred: work is still open") and "0 rows matched event ids 4720" in listed
    assert agent._finish_coverage_check(wall_expired=False) == ""
    _read(log)
    agent._model_calls = getattr(agent, "_model_calls", 0) + 1
    assert agent._finish_coverage_check(wall_expired=False) == ""          # the same outputs: no new deferral
    outs.append({"output": "analysis/evtx_csv/CORP-WS02.csv", "no_rows": False, "overwritten": False,
                 "classes": ["CORP-WS02: Windows event logs"], "filters": []})
    agent._model_calls += 1
    again = agent._finish_coverage_check(wall_expired=False)
    assert again.startswith("atlas_finish deferred for the parsed outputs")
    assert '"analysis/evtx_csv/CORP-WS01.csv"' in again and '"analysis/evtx_csv/CORP-WS02.csv"' in again
    assert not agent._finish_coverage_check(wall_expired=False).startswith("atlas_finish deferred for the parsed")
