"""The frontier loop over an Agent: a fresh start seeds its
items from the kept map, each item runs to its submit and closes, a
synthesis runs once per semantic change, and the run stops when nothing is
due. Resume in the other mode is refused. Invented fixtures only
(CORP-WS01, svc_kit.exe, dates in 2031)."""
from __future__ import annotations

import json

from agent.llm import ChatResponse, ToolCall
from agent.loop import Agent
from core import frontier_queue as Q
from tests.agent.test_item_executor import _Box, _Client
from tests.core.test_incident_map import _KIT, _case, _claim, _trace, _wide


def _submit(i, name, args):
    return ChatResponse(content="", tool_calls=[ToolCall(id=f"s{i}", name=name, arguments=args)])


def test_a_fresh_frontier_run_passes_the_host_synthesises_once_and_stops(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    client = _Client([
        _submit(1, "submit_host_pass", {"arrival": {"examined": {
            "call_ids": [], "why": "the item's reads show no inbound session"}}}),
        _submit(2, "submit_synthesis", {"contradictions": []})])
    a = Agent(client, _Box(), case_dir=case, quiet=True)
    for name in ("_triage_evidence", "_plan_questions"):
        monkeypatch.setattr(a, name, lambda *x, **k: None)
    monkeypatch.setattr(a, "_run_pre_report_check", lambda: None)
    monkeypatch.setattr(a, "_pre_report_ready", lambda: False)
    ended = {}
    monkeypatch.setattr(a, "_run_end", lambda turn, stopped, summary: ended.update(
        turn=turn, stopped=stopped, summary=summary) or summary)
    events = []
    monkeypatch.setattr(a, "_log", events.append)
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    out = a.run("sys", "user")
    assert ended["stopped"] == "finished" and "2 item(s) run (host_pass 1, synthesis 1)" in out
    items = {i["origin"]: i for i in log.work_items()}
    assert items["host_pass"]["status"] == "resolved" and items["synthesis"]["status"] == "dismissed"
    assert Q.load_state(case)["mode"] == "frontier"
    kinds = [e["event"] for e in events]
    assert kinds.count("frontier_item_end") == 2 and kinds[-1] == "frontier_stop"
    assert next(e for e in events if e["event"] == "frontier_seed")["items"]
    assert client.asks[0]["tools"][-3:] == ["item_use_readers", "item_note", "submit_host_pass"]
    assert client.asks[1]["tools"] == ["submit_synthesis"]


def test_a_resume_in_the_other_mode_is_refused(tmp_path, monkeypatch):
    from core.run_state import TRANSCRIPT_PREFIX
    case = _case(tmp_path)
    (case / "analysis" / f"{TRANSCRIPT_PREFIX}20310101T000000Z.jsonl").write_text(
        json.dumps({"event": "run_start", "loop_mode": "conversation"}) + "\n", encoding="utf-8")
    a = Agent(_Client([]), _Box(), case_dir=case, quiet=True)
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    out = a.run("sys", "user")
    assert "run in conversation mode; a resume in frontier mode is refused" in out
    assert a.stats["stopped_reason"] == "loop_mode_refused"
    monkeypatch.setenv("ATLAS_LOOP", "conversation")
    assert a._loop_mode_refusal("conversation") == ""


def test_the_frontier_has_no_director(tmp_path, monkeypatch):
    a = Agent(_Client([]), _Box(), case_dir=None, quiet=True)
    a._loop_mode = "frontier"
    monkeypatch.setattr("tools.dair.dair_assess", lambda *x, **k: (_ for _ in ()).throw(AssertionError("called")))
    a._director_event(1, "plan_exhausted")


def test_a_model_that_resubmits_a_refused_finding_cannot_chain_followups(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    finding = {"statement": "svc_kit.exe ran twice on CORP-WS01.",
               "basis": [{"call_id": 999, "quote": "svc_kit.exe"}]}      # a call of no item: no basis left
    arrival = {"examined": {"call_ids": [], "why": "the item's reads show no inbound session"}}
    client = _Client([_submit(1, "submit_host_pass", {"arrival": arrival, "findings": [finding]}),
                      _submit(2, "submit_host_pass", {"findings": [finding]}),
                      _submit(3, "submit_followup", {"findings": [finding]}),
                      _submit(4, "submit_followup", {"findings": [finding]}),
                      _submit(5, "submit_synthesis", {})])
    a = Agent(client, _Box(), case_dir=case, quiet=True)
    for name in ("_triage_evidence", "_plan_questions"):
        monkeypatch.setattr(a, name, lambda *x, **k: None)
    monkeypatch.setattr(a, "_run_pre_report_check", lambda: None)
    monkeypatch.setattr(a, "_pre_report_ready", lambda: False)
    monkeypatch.setattr(a, "_run_end", lambda turn, stopped, summary: summary)
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    a.run("sys", "user")
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    assert len(follow) == 1 and follow[0]["status"] == "dismissed"       # its own repeat added nothing
    assert [i["status"] for i in log.work_items() if i["origin"] == "host_pass"] == ["resolved"]
    assert not client.script                                            # and the run ended


def test_a_state_already_synthesised_is_not_synthesised_again(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    states = iter(["A", "B", "A", "B", "C"])
    fr.m = type("M", (), {"fingerprint": lambda self: next(states)})()
    state: dict = {"mode": "frontier"}
    made = [fr._synthesis(state) is not None for _ in range(5)]
    assert made == [True, True, False, False, True] and Q.load_state(case)["synthesised"] == ["A", "B", "C"]
    assert len([i for i in log.work_items() if i["origin"] == "synthesis"]) == 3


def test_a_not_ready_gate_turns_its_issues_into_one_item_and_stops_on_a_repeat(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    client = _Client([_submit(1, "submit_followup", {})])
    a = Agent(client, _Box(), case_dir=case, quiet=True)
    for name in ("_triage_evidence", "_plan_questions"):
        monkeypatch.setattr(a, name, lambda *x, **k: None)
    # the counts in an issue change between checks; the issue does not
    counts = iter([3, 4, 5])
    monkeypatch.setattr(a, "_run_pre_report_check", lambda: {
        "ready_to_report": False,
        "blocking_issues": [f"question task-0001 has no answer ({next(counts)} findings checked)"]})
    monkeypatch.setattr(a, "_close_out_spine", lambda turn, checked, need_dair=True: checked)
    ended = {}
    monkeypatch.setattr(a, "_run_end", lambda turn, stopped, summary: ended.update(stopped=stopped) or summary)
    events = []
    monkeypatch.setattr(a, "_log", events.append)
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    a.run("sys", "user")
    gate = [i for i in log.work_items() if (i.get("source_ref") or {}).get("kind") == "report_gate"]
    assert len(gate) == 1 and "task-0001 has no answer" in gate[0]["why"] and ended["stopped"] == "finished"
    stop = next(e for e in events if e["event"] == "frontier_stop")
    assert stop["left"]["due"] == 0 and "pending_units" in stop["left"] and stop["stopped"] == "finished"
    assert [e["event"] for e in events if e["event"].startswith("frontier_gate")] == [
        "frontier_gate_items", "frontier_gate_repeat"]
    # the issues the run ended with are disclosed, beside the label and in
    # the exit report's limitations
    from core.investigation_exit import completion_disclosure
    from core.report_exit import _with_gate_issues
    assert completion_disclosure(case)["report_gate_open"] == ["question task-0001 has no answer (4 findings checked)"]
    md = _with_gate_issues("# Report\n\n## Limitations\n\n- an earlier one\n", case)
    assert "## Limitations\n\n- The report gate was not ready at the run's end: question task-0001" in md
    assert "- an earlier one" in md
    assert "## Limitations\n\n- The report gate" in _with_gate_issues("# Report\n", case)


def test_other_origins_run_as_reads_and_lookups_are_adopted(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    look = log.add_work_item("reason", [], "table.table_grep", {"host": "CORP-WS01", "source_hint": "y.csv"},
                             "verify the name", status="proposed")
    log.add_work_item("blocker", [], "", None, "no read shows how the account was created", status="proposed")
    client = _Client([_submit(1, "submit_plan", {}), _submit(2, "submit_synthesis", {})])
    a = Agent(client, _Box(), case_dir=case, quiet=True)
    for name in ("_triage_evidence", "_plan_questions", "_claim_source_items"):
        monkeypatch.setattr(a, name, lambda *x, **k: None)
    monkeypatch.setattr(a, "_run_pre_report_check", lambda: None)
    monkeypatch.setattr(a, "_pre_report_ready", lambda: False)
    monkeypatch.setattr(a, "_run_end", lambda turn, stopped, summary: summary)
    seen = []
    import core.frontier_prompts as P
    real = P.item_text
    monkeypatch.setattr(P, "item_text", lambda c, item, m, readers="": seen.append(real(c, item, m, readers))
                        or seen[-1])
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    a.run("sys", "user")
    assert look["status"] in ("dismissed", "resolved") and client.asks[0]["tools"][-1] == "submit_plan"
    assert "no read shows how the account was created" in seen[-1]


def test_the_batch_sweep_reads_in_the_background_and_applies_on_the_run_thread(tmp_path, monkeypatch):
    import threading
    from agent.frontier import FrontierRun
    import core.frontier_sweep as S
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    monkeypatch.setenv("ATLAS_ESTATE_COUNT_ASYNC", "1")
    gate, applied = threading.Event(), []
    monkeypatch.setattr(S, "count", lambda job: (gate.wait(5), job.update(counted=threading.current_thread().name))
                        and job)
    monkeypatch.setattr(S, "apply", lambda log, job: applied.append((job["counted"], threading.current_thread().name))
                        or {"sightings": 0})
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    assert fr._sweeper([{"entity_id": 1, "value": "svc_kit.exe", "kind": "file"}]) == {"started": 1}
    fr._collect()
    assert applied == [] and len(fr.sweeps) == 1                       # still reading: the run goes on
    gate.set()
    fr._collect(wait=True)
    assert applied == [("atlas-frontier-sweep", threading.current_thread().name)] and fr.sweeps == []


def test_the_brief_item_labels_what_the_brief_states_and_a_finding_against_it_conflicts(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from core import incident_map as IM
    case = _wide(_case(tmp_path))
    _trace(case, monkeypatch)
    (case / "CASE.md").write_text(
        "# CASE-A\n\n## Context and false positives\n"
        "The responders deployed fieldagent.exe on every host on 2031-03-11.\n"
        "The attacker connected from 203.0.113.7 to CORP-WS01.\n", encoding="utf-8")
    client = _Client([_submit(1, "submit_brief", {"entities": [
        {"kind": "file", "value": "fieldagent.exe", "side": "benign",
         "sentence": "The responders deployed fieldagent.exe on every host on 2031-03-11."},
        {"kind": "endpoint", "value": "203.0.113.7", "side": "attacker",
         "sentence": "The attacker connected from 203.0.113.7 to CORP-WS01."},
        {"kind": "account", "value": "john.roe", "side": "attacker", "sentence": "john.roe is the attacker."}]})])
    fr = FrontierRun(Agent(client, _Box(), case_dir=case, quiet=True))
    fr.m = IM.open(case)
    state: dict = {"mode": "frontier"}
    fr._brief_item(state)
    assert {e["value"] for e in fr.m.attacker_entities()} == {"203.0.113.7"}      # john.roe: not in the brief
    cursor = fr.m.head()
    _claim(case, "fieldagent.exe ran as the attacker's tool on CORP-WS01 at 2031-03-12 10:00:00.",
           [{"type": "file", "value": "fieldagent.exe", "side": "attacker"}])
    assert "label_conflict" in [c["kind"] for c in fr.m.changes_since(cursor)[0]]
    fr._brief_item(state)                                   # the same brief: no second call
    assert len(client.asks) == 1 and Q.load_state(case)["brief_hash"]



def test_a_brief_conflict_never_asks_to_supersede_evidence_and_a_changed_brief_drops_its_old_labels(
        tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from core import incident_map as IM
    case = _wide(_case(tmp_path))
    _trace(case, monkeypatch)
    (case / "CASE.md").write_text(
        "# CASE-A\n\n## Context\njane.doe is the administrators' account.\n"
        "The responders deployed fieldagent.exe on every host.\n", encoding="utf-8")
    client = _Client([_submit(1, "submit_brief", {"entities": [
        {"kind": "account", "value": "jane.doe", "side": "benign", "sentence": "jane.doe is the administrators' account."},
        {"kind": "file", "value": "fieldagent.exe", "side": "benign",
         "sentence": "The responders deployed fieldagent.exe on every host."}]}),
        _submit(2, "submit_brief", {"entities": [
            {"kind": "account", "value": "jane.doe", "side": "benign",
             "sentence": "jane.doe is the administrators' account."}]})])
    fr = FrontierRun(Agent(client, _Box(), case_dir=case, quiet=True))
    fr.m = IM.open(case)
    state: dict = {"mode": "frontier"}
    fr._brief_item(state)
    cursor = fr.m.head()
    _claim(case, "jane.doe logged on to CORP-WS01 from the attacker's address at 2031-03-12 10:00:00.",
           [{"type": "account", "value": "jane.doe", "side": "attacker"}])
    _claim(case, "C:\\Temp\\fieldagent.exe ran as the attacker's tool on CORP-WS01 at 2031-03-12 10:05:00.",
           [{"type": "path", "value": "C:\\Temp\\fieldagent.exe", "side": "attacker"}])
    conflicts = [c for c in fr.m.changes_since(cursor)[0] if c["kind"] == "label_conflict"]
    assert len(conflicts) == 2                               # the account, and the file by its name alone
    for c in conflicts:
        note = fr.m.note_text(c)
        assert "the user's own statement" in note and "never supersede a label the evidence holds" in note
    # One rule in the note and the item text: an account the attacker used is labelled attacker from its first
    # attacker action, and its earlier activity stays the organisation's.
    notes = {c["fields"]["ref"]: fr.m.note_text(c) for c in conflicts}
    with fr.m._read() as con:
        kinds = {r: con.execute("SELECT kind FROM entities WHERE eid = ?", (int(r[2:]),)).fetchone()["kind"]
                 for r in notes}
    (account,) = [n for r, n in notes.items() if kinds[r] == "account"]
    (file_,) = [n for r, n in notes.items() if kinds[r] == "file"]
    assert "attacker_from at the attacker's first action" in account
    assert "earlier activity stays the organisation's" in account
    # a file gets file advice: the evidence's label where the attacker used it, no attacker_from
    assert "keeps the evidence's label where the attacker used it" in file_ and "attacker_from" not in file_
    (case / "CASE.md").write_text(
        "# CASE-A\n\n## Context\njane.doe is the administrators' account.\n", encoding="utf-8")
    fr._brief_item(state)                                    # a changed brief no longer states the file
    assert set(fr.m.brief_labels().values()) == {"benign"} and len(fr.m.brief_labels()) == 1


def test_the_triage_runs_beside_the_items_and_the_queue_waits_for_it_only_when_empty(tmp_path, monkeypatch):
    import threading
    from agent.frontier import FrontierRun
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    a = Agent(_Client([]), _Box(), case_dir=case, quiet=True)
    gate, done = threading.Event(), []
    monkeypatch.setattr(a, "_triage_evidence", lambda turn, c: (gate.wait(5), done.append(turn)))
    monkeypatch.setattr(a, "_plan_questions", lambda *x, **k: None)
    fr = FrontierRun(a)
    fr._pass({"mode": "frontier"})                       # returns while the triage still runs
    assert fr._busy_beside() and done == []
    gate.set()
    for t in fr.besides.values():
        t.join()
    assert done == [0] and not fr._busy_beside()


def test_an_item_the_guard_ends_after_progress_hands_its_note_to_one_continuation(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from agent.item_executor import ItemRun
    from core import incident_map as IM
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    item = log.add_work_item("join_hit", [], "", {"host": "CORP-WS01"}, "w",
                             source_ref={"host": "CORP-WS01", "closed_by": "executor"}, extra_key="j")
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    fr.m = IM.open(case)

    def fake_run_item(agent, spec, **kw):
        # the item's own observation (its applier writes it), not another thread's
        kw["on_submit"]._count_obs(fr.m.add_observation("svc_kit.exe sits in the public folder of CORP-WS01.",
                                                        "CORP-WS01", None, []))
        return ItemRun(submit=None, end="stuck", progressed=True, calls=[5],
                       notes=[{"fact": "svc_kit.exe in the public folder", "call_id": 5, "row_ref": "5#R1"}],
                       digest="EARLIER CALLS OF THIS ITEM (a digest ...)")
    monkeypatch.setattr("agent.item_executor.run_item", fake_run_item)
    fr._run_one(item)
    cont = [i for i in log.work_items() if (i.get("source_ref") or {}).get("kind") == "continuation"]
    assert len(cont) == 1 and cont[0]["source_ref"]["note"][0]["fact"] == "svc_kit.exe in the public folder"
    text = __import__("core.frontier_prompts", fromlist=["item_text"]).item_text(case, cont[0], fr.m)
    assert "THE EARLIER ITEM'S NOTE (verified):" in text and "EARLIER CALLS OF THIS ITEM" in text



def test_state_another_thread_writes_during_an_item_is_not_its_yield(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from agent.item_executor import ItemRun
    from core import incident_map as IM
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    item = log.add_work_item("join_hit", [], "", {"host": "CORP-WS01"}, "w",
                             source_ref={"host": "CORP-WS01", "closed_by": "executor"}, extra_key="j2")
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    fr.m = IM.open(case)
    tokens = []

    def fake_run_item(agent, spec, **kw):
        tokens.append(kw["progress"](ItemRun(submit=None, end="")))
        fr.m.add_observation("A beside thread wrote this.", "CORP-WS01", None, [])        # not the item's
        log.add_work_item("triage", [], "", {"host": "CORP-WS01"}, "w", status="due", source_ref={}, extra_key="t9")
        tokens.append(kw["progress"](ItemRun(submit=None, end="")))
        return ItemRun(submit=None, end="stuck", progressed=False, calls=[])
    monkeypatch.setattr("agent.item_executor.run_item", fake_run_item)
    fr._run_one(item)
    assert tokens[0] == tokens[1]
    closed = next(i for i in log.work_items() if i["call_id"] == item["call_id"])
    assert closed["status"] == "dismissed"
    assert not [i for i in log.work_items() if (i.get("source_ref") or {}).get("kind") == "continuation"]


def test_the_runs_end_never_waits_for_the_coverage_path(tmp_path, monkeypatch):
    import threading
    from agent.frontier import FrontierRun
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    gate = threading.Event()
    fr._beside("coverage", lambda turn: gate.wait(5))
    assert fr.besides["coverage"].is_alive() and not fr._busy_beside()
    fr._beside("plan", lambda turn: gate.wait(5))
    assert fr._busy_beside()
    gate.set()
    from core.coverage_path import coverage_on
    assert coverage_on() is False                         # off until its own paced lane


def test_a_continuation_that_only_replays_earlier_calls_is_dismissed_and_opens_none(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from agent.item_executor import ItemRun
    from core import incident_map as IM
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    item = log.add_work_item("followup", [], "", {"host": "CORP-WS01"}, "w",
                             source_ref={"kind": "continuation", "closed_by": "executor", "item": 1},
                             extra_key="continuation:1")
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    fr.m = IM.open(case)
    monkeypatch.setattr("core.contents_index.copied_entries", lambda c, ids: list(ids))   # any call id reads
    monkeypatch.setattr("agent.item_executor.run_item", lambda agent, spec, **kw: ItemRun(
        submit=None, end="context_fit", progressed=True, calls=[5, 6], ran_calls=[]))
    fr._run_one(item)
    assert next(i for i in log.work_items() if i["call_id"] == item["call_id"])["status"] == "dismissed"
    assert not [i for i in log.work_items() if i["call_id"] != item["call_id"]
                and (i.get("source_ref") or {}).get("kind") == "continuation"]


# -- progress counts records new to the run, not sources touched ----------------------------

def _fr(case=None):
    from agent.frontier import FrontierRun
    return FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))


def _run(shown: dict):
    from agent.item_executor import ItemRun
    return ItemRun(submit=None, end="", ran_calls=list(shown), shown_rows={c: list(k) for c, k in shown.items()})


def _sec_keys(rows, columns=None):
    from core.shown_rows import row_keys
    rs = [{"_sheet": "-", "_row": r, "UserName": "jane.doe", "RemoteHost": "203.0.113.7" if r == 99 else "10.0.0.5",
           "EventId": 4624} for r in rows]
    if columns:
        rs = [{k: v for k, v in r.items() if k in ("_sheet", "_row", *columns)} for r in rs]
    return row_keys("table_table_query", {"path": "evidence/CORP-WS02/sec.csv"},
                    {"path": "evidence/CORP-WS02/sec.csv", "rows": rs})


def test_new_rows_of_one_source_are_progress_and_rows_shown_before_are_not():
    fr = _fr()
    run = _run({101: _sec_keys(range(1, 11))})
    assert fr._own_reads(run, 1) == 10
    run.ran_calls.append(102)
    run.shown_rows[102] = _sec_keys(range(11, 21))                    # the next page of the same source
    assert fr._own_reads(run, 1) == 20
    run.ran_calls.append(103)
    run.shown_rows[103] = _sec_keys([99])                             # the attacker row, by a grep
    assert fr._own_reads(run, 1) == 21
    run.ran_calls.append(104)
    run.shown_rows[104] = _sec_keys(range(1, 21), columns=["UserName"])   # the same records, another projection
    assert fr._own_reads(run, 1) == 21
    later = _run({201: _sec_keys(range(5, 15))})                      # another item, records already shown
    assert fr._own_reads(later, 2) == 0


def test_a_call_that_showed_no_rows_and_a_replay_credit_nothing():
    fr = _fr()
    run = _run({})
    run.ran_calls = [7]                                               # ran, but refused or deferred: no rows
    assert fr._own_reads(run, 1) == 0


def test_a_continuation_that_re_shows_its_predecessors_rows_is_dismissed_and_opens_none(tmp_path, monkeypatch):
    from agent.item_executor import ItemRun
    from core import incident_map as IM
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    fr = _fr(case)
    fr.m = IM.open(case)
    assert fr._own_reads(_run({5: _sec_keys(range(1, 41))}), 7777) == 40   # the predecessor's pages
    item = log.add_work_item("followup", [], "", {"host": "CORP-WS02"}, "w",
                             source_ref={"kind": "continuation", "closed_by": "executor", "item": 1},
                             extra_key="continuation:1")
    monkeypatch.setattr("agent.item_executor.run_item", lambda agent, spec, **kw: ItemRun(
        submit=None, end="forced", progressed=True, calls=[8, 9], ran_calls=[8, 9],
        shown_rows={8: _sec_keys(range(1, 21), columns=["EventId"]), 9: _sec_keys(range(21, 41))}))
    fr._run_one(item)
    assert next(i for i in log.work_items() if i["call_id"] == item["call_id"])["status"] == "dismissed"
    assert not [i for i in log.work_items() if i["call_id"] != item["call_id"]
                and (i.get("source_ref") or {}).get("kind") == "continuation"]


def test_what_ends_an_item_that_pages_a_large_source(monkeypatch):
    """Each page shows records new to the run, so each round progresses;
    the request never reaches the budget (the digest holds its share and the
    last round is one page), so context_fit does not end it. The item ends
    when the pages show nothing new: three empty rounds force the submit."""
    import agent.item_executor as X
    from agent.item_executor import ItemSpec, run_item
    from tests.agent.test_item_executor import SUBMIT, _call
    monkeypatch.delenv("ATLAS_ITEM_PATIENCE", raising=False)
    pages, size = 40, 8000
    sizes: list[int] = []

    class _Sized(_Client):
        def chat(self, messages, tools=None, role=None, tool_choice=None, **kw):
            sizes.append(X._chars(messages))
            return super().chat(messages, tools=tools, role=role, tool_choice=tool_choice, **kw)

    script = [ChatResponse(content="", tool_calls=[_call(i, "table.table_query",
                                                         {"path": "evidence/estate.csv", "offset": i * 50})])
              for i in range(pages + 3)] + [ChatResponse(content="", tool_calls=[_call(999, "submit_x", {})])]
    agent = Agent(_Sized(script), _Box(), case_dir=None, quiet=True)
    agent._run_setup("sys", "user")
    calls = iter(range(1000, 2000))

    def once(name, args, **kw):
        cid = next(calls)
        page = min(int(args.get("offset") or 0) // 50, pages - 1)   # past the end: the last page again
        keys = _sec_keys(range(page * 50, page * 50 + 50))
        return {"kind": "ran", "ran_clean": True, "shown_rows": keys,
                "result": json.dumps({"rows": ["x" * (size // 50)] * 50, "_atlas_call_id": cid})}
    monkeypatch.setattr(agent, "_call_once", once)
    fr = _fr()
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_query"], submit=SUBMIT)
    run = run_item(agent, spec, progress=lambda r: fr._own_reads(r, 1))
    assert run.end == "forced" and run.rounds == pages + 4 and fr.read_count[1] == pages * 50
    assert max(sizes) < X._budget()



def test_every_reading_item_reads_that_the_brief_is_not_evidence_in_the_conflict_notes_terms():
    from core.frontier_prompts import KINDS, system_text
    for kind in [k for k in KINDS if k != "synthesis"]:
        text = system_text(kind)
        assert "The brief tells what the user knows; it is not evidence." in text
        assert "attacker_from at the attacker's first action with it" in text
        assert "its earlier activity stays the organisation's" in text


# -- the line after an empty round -------------------------------------------------------------

def test_the_request_after_an_empty_round_says_so_and_names_records_not_yet_shown(tmp_path, monkeypatch):
    """A behaviour signal, never a cap: the round after one that showed nothing
    new carries one line; it names, per table this item read, how many of its
    records no item has been shown (invented rows)."""
    import csv
    import agent.item_executor as X
    from agent.item_executor import ItemSpec, run_item
    from core.contents_index import build
    from tests.agent.test_item_executor import SUBMIT, _call
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    p = case / "evidence" / "CORP-WS02" / "sec.csv"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["TimeCreated", "Computer", "Channel", "EventId", "SourceFile"])
        for i in range(30):
            w.writerow([f"2031-03-10T10:{i:02d}:00Z", "CORP-WS02", "Security", 4624,
                        "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"])
    build(case)
    seen: list[list[str]] = []

    class _Seeing(_Client):
        def chat(self, messages, tools=None, role=None, tool_choice=None, **kw):
            seen.append([str(m.get("content") or "") for m in messages])
            return super().chat(messages, tools=tools, role=role, tool_choice=tool_choice, **kw)
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "4,4")
    script = [ChatResponse(content="", tool_calls=[_call(i, "table.table_query", {"path": str(p), "limit": 10})])
              for i in range(3)] + [ChatResponse(content="", tool_calls=[_call(9, "submit_x", {})])]
    agent = Agent(_Seeing(script), _Box(), case_dir=case, quiet=True)
    agent._run_setup("sys", "user")
    keys = _sec_keys(range(1, 11))
    monkeypatch.setattr(agent, "_call_once", lambda name, args, **kw: {
        "kind": "ran", "ran_clean": True, "shown_rows": keys, "shown_source": str(p),
        "result": json.dumps({"rows": [], "_atlas_call_id": 100 + len(seen)})})
    fr = _fr(case)
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_query"], submit=SUBMIT)
    run_item(agent, spec, progress=lambda r: fr._own_reads(r, 1), on_empty=fr._empty_note)
    lines = [m for req in seen for m in req if m.startswith("The last round showed no record new to this run")]
    assert not any("The last round showed" in m for m in seen[1])           # round 1 progressed: no line
    assert lines and "evidence/CORP-WS02/sec.csv: 20 of 30 records not yet shown" in lines[0]
    assert "item_note" in lines[0] and X.NOTE_SCHEMA["function"]["description"].endswith(
        "counts as this item's progress, as a record shown for the first time does.")


def test_a_host_pass_whose_note_entries_are_plain_strings_ends_by_its_submit_not_in_error(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    client = _Client([
        _submit(1, "item_note", {"add": ["jane.doe ran svc_kit.exe on CORP-WS01"]}),
        _submit(2, "submit_host_pass", {"arrival": {"examined": {
            "call_ids": [], "why": "the item's reads show no inbound session"}}}),
        _submit(3, "submit_synthesis", {"contradictions": []})])
    a = Agent(client, _Box(), case_dir=case, quiet=True)
    for name in ("_triage_evidence", "_plan_questions"):
        monkeypatch.setattr(a, name, lambda *x, **k: None)
    monkeypatch.setattr(a, "_run_pre_report_check", lambda: None)
    monkeypatch.setattr(a, "_pre_report_ready", lambda: False)
    monkeypatch.setattr(a, "_run_end", lambda turn, stopped, summary: summary)
    events = []
    monkeypatch.setattr(a, "_log", events.append)
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    a.run("sys", "user")
    ends = [e for e in events if e["event"] == "frontier_item_end" and e["kind"] == "host_pass"]
    assert ends and all(e["end"] != "error" for e in ends) and ends[0]["end"] == "submitted"
