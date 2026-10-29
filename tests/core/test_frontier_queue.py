"""The frontier queue from the incident map's change feed, and
the batched sweep. Invented fixtures only (CORP-WS01, CORP-WS02, jane.doe,
svc_kit.exe, dates in 2031)."""
from __future__ import annotations

from core import frontier_queue as Q
from core import incident_map as IM
from tests.core.test_incident_map import _KIT, _case, _claim, _trace, _wide


def test_an_attacker_event_gives_a_host_pass_and_a_join_on_another_host_too(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    out = Q.generate(log, case)
    items = log.work_items()
    assert [(i["origin"], i["target"]["host"]) for i in items] == [("host_pass", "CORP-WS01")]
    IM.open(case).upsert_entity("file", "D:\\Kit\\svc_kit.exe", host="CORP-WS02")
    Q.generate(log, case)
    hosts = sorted(i["target"]["host"] for i in log.work_items() if i["origin"] == "host_pass")
    assert hosts == ["CORP-WS01", "CORP-WS02"] and Q.load_state(case)["cursor"] > out["cursor"] - 1
    Q.generate(log, case)                                    # the same feed creates nothing twice
    assert len([i for i in log.work_items() if i["origin"] == "host_pass"]) == 2


def test_a_passed_host_gets_one_folded_join_item(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    _claim(case, "Beacon from CORP-WS02 at 2031-03-11 08:00:00.",
           [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS02")
    Q.generate(log, case)
    for i in log.work_items():
        i["status"] = "resolved"                             # both hosts passed
    m = IM.open(case)
    m.upsert_entity("file", "D:\\Kit\\svc_kit.exe", host="CORP-WS02")
    Q.generate(log, case)
    joins = [i for i in log.work_items() if i["origin"] == "join_hit" and i["status"] == "due"]
    assert len(joins) == 1 and joins[0]["target"]["host"] == "CORP-WS02"


def test_the_order_is_by_purpose_and_host_passes_by_entities(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    a = log.add_work_item("host_pass", [], "", {"host": "CORP-WS01"}, "a", source_ref={"host": "CORP-WS01",
                                                                                     "entities": [1]},
                          extra_key="host_pass:CORP-WS01:0")
    b = log.add_work_item("host_pass", [], "", {"host": "CORP-WS02"}, "b", source_ref={"host": "CORP-WS02",
                                                                                     "entities": [1, 2, 3]},
                          extra_key="host_pass:CORP-WS02:0")
    t = log.add_work_item("triage", [], "", {"host": "CORP-WS01"}, "t", source_ref={"kind": "evidence"},
                          extra_key="triage:x")
    f = log.add_work_item("followup", [], "", {"host": ""}, "f", source_ref={"kind": "followup"},
                          extra_key="followup:1")
    q = log.add_work_item("plan", ["task-0001"], "table.table_grep", {"host": "CORP-WS01", "source_hint": "x.csv",
                                                                    "pattern": "jane.doe"}, "q")
    syn = log.add_work_item("synthesis", [], "", None, "s", source_ref={"kind": "synthesis"}, extra_key="syn")
    # host passes by sightings, then what serves a question, then follow-ups,
    # the synthesis, and last the coverage read no question names
    assert [i["call_id"] for i in Q.due_items(log)] == [b["call_id"], a["call_id"], q["call_id"], f["call_id"],
                                                        syn["call_id"], t["call_id"]]


def test_the_sweep_writes_sightings_from_the_tables(tmp_path, monkeypatch):
    from core import frontier_sweep as S
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    (case / "analysis" / "corp-ws02-pslist.csv").write_text("Name,Time\nsvc_kit.exe,2031-03-12 09:00:00\n")
    monkeypatch.setattr(S, "_tables", lambda c: ["analysis/corp-ws02-pslist.csv"])
    m = IM.open(case)
    ent = next(e for e in m.attacker_entities() if e["value"] == "svc_kit.exe")
    out = S.sweep(case, log, [ent])
    assert out["sightings"] == 1 and out["call_id"]
    assert "CORP-WS02" in next(e for e in m.attacker_entities() if e["value"] == "svc_kit.exe")["hosts"]


def test_a_fresh_start_seeds_from_the_current_state_and_follows_the_head(tmp_path, monkeypatch):
    from core.claim_graph import supersede
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    old = _claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-09 10:00:00.", _KIT[:1], host="CORP-WS02")
    supersede(case, old, reason="the evidence no longer supports this belief")
    _claim(case, "Beacon from CORP-WS01 at 2031-03-11 08:00:00.",
           [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS01")
    state: dict = {"mode": "frontier"}
    out = Q.seed(log, case, state)
    assert out["cursor"] == IM.open(case).head() == Q.load_state(case)["cursor"]
    # the superseded belief's host is not passed; the current one's is
    assert [i["target"]["host"] for i in log.work_items() if i["origin"] == "host_pass"] == ["CORP-WS01"]
    assert Q.generate(log, case, Q.load_state(case))["items"] == []      # nothing replayed


def test_a_read_of_the_hosts_image_never_closes_its_host_pass(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    log.record_tool_call("icat evidence/corp-ws01.raw 4242", True, False, 0, 0, stdout_excerpt="bytes")
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    Q.generate(log, case)
    item = next(i for i in log.work_items() if i["origin"] == "host_pass")
    assert item["status"] == "due" and item["target"]["host"] == "CORP-WS01" and not item["target"]["path"]


def test_executor_items_are_never_closed_by_a_read_of_their_target(tmp_path, monkeypatch):
    """Even an executor item whose target names the image a call read stays
    due: only its run ends it (work_order.close_item)."""
    from core.work_order import EXECUTOR, close_item
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    log.record_tool_call("icat evidence/corp-ws01.raw 4242", True, False, 0, 0, stdout_excerpt="bytes")
    log._entries[-1]["mcp_tool"] = "tsk_tsk_icat"
    target = {"host": "CORP-WS01", "path": "evidence/corp-ws01.raw"}
    born = log.add_work_item("join_hit", [], "", target, "w", source_ref={"kind": "join_hit", "closed_by": EXECUTOR},
                             extra_key="join_hit:CORP-WS01:0")
    assert born["status"] == "due"
    log.record_tool_call("icat evidence/corp-ws01.raw 4243", True, False, 0, 0, stdout_excerpt="bytes")
    log._entries[-1]["mcp_tool"] = "tsk_tsk_icat"
    from core.work_order import close_items_for_call
    close_items_for_call(log, "tsk.tsk_icat", {"image": "evidence/corp-ws01.raw"}, [log._entries[-1]])
    assert born["status"] == "due"
    plain = log.add_work_item("plan", [], "tsk.tsk_icat", target, "read")
    assert plain["status"] == "resolved"                      # a read item keeps the matcher
    close_item(log, born["call_id"], "resolved", "ran")
    assert born["status"] == "resolved"


def test_every_due_origin_has_a_place_in_the_order(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    src = log.add_work_item("source", ["task-0001"], "table.table_grep", {"host": "CORP-WS01", "source_hint": "x.csv",
                                                                         "pattern": "jane.doe"}, "s")
    fol = log.add_work_item("followup", [], "", {"host": ""}, "f", source_ref={"kind": "followup"},
                            extra_key="followup:x")
    hp = log.add_work_item("host_pass", [], "", {"host": "CORP-WS01"}, "h", source_ref={"host": "CORP-WS01"},
                           extra_key="host_pass:CORP-WS01:0")
    assert [i["call_id"] for i in Q.due_items(log)] == [hp["call_id"], src["call_id"], fol["call_id"]]


def test_a_repeated_note_folds_into_its_open_followup(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m = IM.open(case)
    changes = [{"seq": s, "kind": "account_before_start", "ts": "", "fields": {"account": "CORP\\jane.doe",
                                                                                "event_id": s, "host": "CORP-WS01"}}
               for s in (1, 2)]
    monkeypatch.setattr(IM.IncidentMap, "changes_since", lambda self, cur=0: ([c for c in changes if c["seq"] > cur],
                                                                             max([cur] + [c["seq"] for c in changes])))
    Q.generate(log, case, {})
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    assert len(follow) == 1
    follow[0]["status"] = "resolved"
    changes.append({**changes[0], "seq": 3})
    Q.generate(log, case, {"cursor": 2})
    assert len([i for i in log.work_items() if i["origin"] == "followup"]) == 2


def test_a_failed_pass_leaves_its_host_unpassed(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    Q.generate(log, case)
    first = next(i for i in log.work_items() if i["origin"] == "host_pass")
    first["status"] = "failed"
    assert "CORP-WS01" not in Q.passed_hosts(log)
    # an earlier attacker event on the host moves its first attacker time
    _claim(case, "Beacon from CORP-WS01 at 2031-03-09 08:00:00.",
           [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS01")
    Q.generate(log, case)
    passes = [i for i in log.work_items() if i["origin"] == "host_pass"]
    assert [p["status"] for p in passes] == ["failed", "due"]


def test_a_clear_restarts_the_feed_cursor(tmp_path, monkeypatch):
    from tools.misc import clear_case_run
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    assert Q.generate(log, case)["cursor"] > 0
    clear_case_run(str(case), clear_memory=False)
    assert Q.load_state(case) == {} and int(Q.load_state(case).get("cursor") or 0) == 0


def test_two_early_events_on_one_host_are_one_followup_listing_both(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    changes = [{"seq": s, "kind": "seen_before_start", "ts": "", "fields": {"event_id": s, "host": "CORP-WS01",
                                                                             "time": "2031-03-09 10:00:00"}}
               for s in (1, 2)]
    monkeypatch.setattr(IM.IncidentMap, "changes_since", lambda self, cur=0: ([c for c in changes if c["seq"] > cur],
                                                                             max([cur] + [c["seq"] for c in changes])))
    Q.generate(log, case, {})
    items = [i for i in log.work_items() if i["origin"] == "followup"]
    # one followup per kind and host, its early sightings listed (was: one per event)
    assert [i["source_ref"]["subject"] for i in items] == ["seen_before_start:CORP-WS01"]
    assert [e["subject"] for e in items[0]["source_ref"]["early"]] == ["seen_before_start:v1:CORP-WS01",
                                                                       "seen_before_start:v2:CORP-WS01"]


def test_view_rows_fold_into_one_item_per_part_and_a_replaced_view_drops_its_rows(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m = IM.open(case)
    views = [{"view_id": 1, "task_id": "task-0001", "part_id": "p1", "declared_by": "plan", "spec": {},
              "rows": [{"row_key": h, "status": "open"} for h in ("CORP-WS01", "CORP-WS02")]}]
    monkeypatch.setattr(m, "views", lambda open_only=False: views)
    Q.view_parts(log, m)
    (item,) = [i for i in log.work_items() if i["origin"] == "view_row_opened"]
    assert item["source_ref"]["rows"] == ["CORP-WS01", "CORP-WS02"] and item["task_ids"] == ["task-0001"]
    views[0] = {**views[0], "view_id": 2, "rows": [{"row_key": "CORP-SRV01", "status": "open"}]}  # re-declared
    Q.view_parts(log, m)
    assert item["source_ref"]["rows"] == ["CORP-SRV01"] and len(
        [i for i in log.work_items() if i["origin"] == "view_row_opened"]) == 1
    item["status"] = "resolved"                                       # the item ran
    Q.view_parts(log, m)
    assert len([i for i in log.work_items() if i["origin"] == "view_row_opened"]) == 1   # no new rows: none
    views[0]["rows"].append({"row_key": "CORP-WS03", "status": "open"})
    Q.view_parts(log, m)
    assert len([i for i in log.work_items() if i["origin"] == "view_row_opened"]) == 2


def test_a_45_row_part_is_shown_whole_in_items_of_40_and_reopened_rows_get_an_item(tmp_path, monkeypatch):
    from core.frontier_prompts import item_text
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m = IM.open(case)
    keys = [f"acct{n:02d}" for n in range(45)]
    views = [{"view_id": 1, "task_id": "task-0001", "part_id": "p1", "declared_by": "plan", "spec": {},
              "rows": [{"row_key": k, "status": "open"} for k in keys]}]
    monkeypatch.setattr(m, "views", lambda open_only=False: views)
    Q.view_parts(log, m)
    items = [i for i in log.work_items() if i["origin"] == "view_row_opened"]
    assert [len(i["source_ref"]["rows"]) for i in items] == [40, 5]
    shown = set()
    for i in items:
        text = item_text(case, i, m)
        shown |= {k for k in keys if k in text}
        assert all(k in text for k in i["source_ref"]["rows"])
    assert shown == set(keys)
    for i in items:
        i["status"] = "resolved"                                      # both ran
    views[0]["rows"][0]["status"] = "filled"
    Q.view_parts(log, m)                                              # the fill is seen
    views[0]["rows"][0]["status"] = "open"                            # and the row reopens
    Q.view_parts(log, m)
    again = [i for i in log.work_items() if i["origin"] == "view_row_opened" and i["status"] == "due"]
    assert len(again) == 1 and again[0]["source_ref"]["rows"] == ["acct00"]


def test_an_older_traces_per_row_items_fold_into_the_part_items(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m = IM.open(case)
    old = log.add_work_item("view_row_opened", ["task-0001"], "", None, "row", status="due",
                            source_ref={"kind": "view_row", "view_id": 1, "row_key": "CORP-WS01"})
    monkeypatch.setattr(m, "views", lambda open_only=False: [])
    Q.view_parts(log, m)
    assert next(i for i in log.work_items() if i["call_id"] == old["call_id"])["status"] == "moot"


def test_rows_of_a_view_the_parts_own_item_re_declares_raise_no_follow_on_item(tmp_path, monkeypatch):
    from agent.frontier import SubmitApplier
    from tests.core.test_incident_map import _SPEC, _tasks, _three_hosts
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _tasks(case)
    _three_hosts(case)
    m = IM.open(case)
    m.declare_view("task-0001", "p1", {"over": "host", "where": {"label": "attacker", "host": "CORP-WS01"},
                                       "columns": ["inbound.src"]})
    Q.view_parts(log, m)
    (item,) = [i for i in log.work_items() if i["origin"] == "view_row_opened"]
    ap = SubmitApplier(None, case, m, item, "view_row_opened")
    ap._view(_SPEC, None)                                         # the item re-declares its part's view
    item["status"] = "resolved"
    Q.view_parts(log, m)
    assert len([i for i in log.work_items() if i["origin"] == "view_row_opened"]) == 1


def test_quick_reads_serving_an_open_part_lead_only_until_the_first_attacker_entity(tmp_path, monkeypatch):
    import json as _json
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    (case / ".atlas" / "investigation_tasks.json").write_text(_json.dumps({"tasks": [
        {"id": "task-0001", "text": "Who logged on?", "status": "open",
         "parts": [{"id": "p1", "text": "the accounts", "status": "open"}]}]}), encoding="utf-8")
    monkeypatch.setattr("core.contents_index.export_paths", lambda c: {"evidence/timelines/corp-ws01.csv"})
    m = IM.open(case)
    slow = log.add_work_item("triage", ["task-0001"], "", {"host": "CORP-WS01", "path": "evidence/disk/corp-ws01.raw"},
                             "slow", source_ref={"kind": "evidence"}, extra_key="triage:slow")
    plan = log.add_work_item("plan", ["task-0001"], "table.table_grep", {"host": "CORP-WS01",
                                                                       "path": "evidence/disk/corp-ws01.raw"}, "p")
    quick = log.add_work_item("triage", ["task-0001"], "", {"host": "", "path": "evidence/timelines"}, "quick",
                              source_ref={"kind": "evidence"}, extra_key="triage:quick")
    spans = log.add_work_item("triage", [], "", {"host": "", "path": "evidence/timelines"}, "spans",
                              source_ref={"kind": "evidence"}, extra_key="triage:spans")
    order = [i["call_id"] for i in Q.due_items(log, Q.rank_context(m, case))]
    # the planned read keeps its place beside the quick read; the quick read
    # that serves no part stays a coverage read
    assert order == [plan["call_id"], quick["call_id"], slow["call_id"], spans["call_id"]]
    m.label(f"e:{m.upsert_entity('endpoint', '203.0.113.7')}", "attacker", [], claim_id="",
            note="t", _by="brief")
    ctx = Q.rank_context(m, case)
    assert not ctx["bootstrap"]
    assert [i["call_id"] for i in Q.due_items(log, ctx)] == [slow["call_id"], plan["call_id"], quick["call_id"],
                                                             spans["call_id"]]


def test_examined_after_a_re_declaration_never_limits_rows_the_item_was_not_shown(tmp_path, monkeypatch):
    from agent.frontier import SubmitApplier
    from core.investigation_tasks import load_tasks
    from tests.core.test_incident_map import _SPEC, _tasks, _three_hosts
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _tasks(case)
    _three_hosts(case)
    m = IM.open(case)
    m.declare_view("task-0001", "p1", {"over": "host", "where": {"label": "attacker", "host": "CORP-WS01"},
                                       "columns": ["inbound.src"]})
    Q.view_parts(log, m)
    (item,) = [i for i in log.work_items() if i["origin"] == "view_row_opened"]
    ap = SubmitApplier(None, case, m, item, "view_row_opened")
    ap._view(_SPEC, {"call_ids": [11], "why": "the logon rows of the host show no inbound session"})
    part = load_tasks(case)["tasks"][0]["parts"][0]
    assert not (part.get("limitation") or {}) and ap.out["observations"] == 1



def test_an_all_planned_run_reads_its_quick_plan_reads_first(tmp_path, monkeypatch):
    import json as _json
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    (case / ".atlas" / "investigation_tasks.json").write_text(_json.dumps({"tasks": [
        {"id": "task-0001", "text": "Who logged on?", "status": "open",
         "parts": [{"id": "p1", "text": "the accounts", "status": "open"}]},
        {"id": "task-0002", "text": "What ran?", "status": "open",
         "parts": [{"id": "p1", "text": "the programs", "status": "open"}]}]}), encoding="utf-8")
    monkeypatch.setattr("core.contents_index.export_paths", lambda c: {"evidence/timelines/corp-ws01.csv"})
    m = IM.open(case)
    raw = log.add_work_item("plan", ["task-0001"], "table.table_grep", {"host": "CORP-WS01",
                                                                      "path": "evidence/disk/corp-ws01.raw"}, "r")
    raw2 = log.add_work_item("plan", ["task-0002"], "table.table_grep", {"host": "CORP-WS01",
                                                                       "path": "evidence/disk/corp-ws01.raw",
                                                                       "pattern": "x"}, "r2")
    quick = log.add_work_item("plan", ["task-0002"], "table.table_grep", {"host": "CORP-WS01",
                                                                        "source_hint": "corp-ws01.csv"}, "q")
    assert [i["call_id"] for i in Q.due_items(log, Q.rank_context(m, case))] == [
        quick["call_id"], raw["call_id"], raw2["call_id"]]
