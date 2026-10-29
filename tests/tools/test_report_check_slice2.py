"""With the work order, the scenario-shaped report checks off
with the open hypotheses and the case question disclosed
(ATLAS_REPORT_CHECK_NO_SCENARIO), the reviewer's blockers as proposed work
items with the UNRESOLVABLE hatch off (ATLAS_BLOCKER_ITEMS), open questions
a warning. Invented fixtures only (CORP-WS01, jane.doe, dates in 2031)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture
def log(tmp_path):
    l = ExecutionLog()
    (tmp_path / "analysis").mkdir()
    l.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"))
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_hypothesize", True, "hyp", {})
    return l


def _check(log):
    from tools.reasoning import reason_pre_report_check
    with patch("core.execution_log.log", log), \
         patch("tools.reasoning.reason_audit_findings",
               return_value={"summary": {"candidate_count": 0}, "candidates": []}):
        return reason_pre_report_check()


SYNTH = ("SUMMARY: draft\nBLOCKERS:\n- the sync client log on CORP-WS01 was located and never parsed\n"
         "- the admin account's first logon is not dated\nWARNINGS: none")


def test_the_synthesis_hook_makes_each_blocker_a_proposed_item_once(log):
    from tools.reasoning import reason_synthesize
    log.record_dair_call("Report", "", False, "", "", "stay", "")
    fake = {"success": True, "conclusion": SYNTH, "_atlas_call_id": 77}
    with patch("core.execution_log.log", log), patch("tools.reasoning._ask", return_value=dict(fake)):
        r = reason_synthesize("finding one")
        again = reason_synthesize("finding one")
    assert [w["status"] for w in r["work_items"]] == ["proposed", "proposed"]
    assert [w["id"] for w in again["work_items"]] == [w["id"] for w in r["work_items"]]
    assert len([i for i in log.work_items() if i["origin"] == "blocker"]) == 2
    with patch("core.execution_log.log", log), patch("tools.reasoning._ask",
                                                     return_value={**fake, "conclusion": "BLOCKERS: none"}):
        assert "work_items" not in reason_synthesize("finding one")


def test_blockers_are_a_warning_with_their_items_backfilled(log):
    log.record_reason_call("reason_synthesize", True, SYNTH, {})
    r = _check(log)
    assert not any("reason.synthesize" in i for i in r["blocking_issues"])
    w = [w for w in r["warnings"] if w.startswith("Reviewer blockers from reason.synthesize call")]
    assert w and w[0].count("proposed (the director decides)") == 2
    assert len([i for i in log.work_items() if i["origin"] == "blocker"]) == 2
    _check(log)
    assert len([i for i in log.work_items() if i["origin"] == "blocker"]) == 2


def test_an_unresolvable_statement_no_longer_waives_a_blocker(log):
    log.record_reason_call("reason_synthesize", True,
                           SYNTH + "\nUNRESOLVABLE: the sync log - the parser cannot read it", {})
    r = _check(log)
    assert not any("UNRESOLVABLE" in i for i in r["blocking_issues"] + r["warnings"])
    assert not any("documented limitation" in d.lower() for d in r.get("documented_limitations") or [])


def test_the_scenario_checks_are_off_and_the_open_hypotheses_disclosed(log):
    log.record_reason_call("reason_synthesize", True, "ok", {})
    log.record_finding("Covert local admin account 'svc_x' was created (RID 1500)", "CONFIRMED", "ez.recmd")
    r = _check(log)
    assert not any("controls it" in i.lower() for i in r["blocking_issues"])
    hyps = [w for w in r["warnings"] if "hypotheses raised and not resolved by any finding" in w]
    assert all("Resolve one only with a read that settles it" in w for w in hyps)


def test_switch_off_brings_the_scenario_check_back(log, monkeypatch):
    monkeypatch.setenv("ATLAS_REPORT_CHECK_NO_SCENARIO", "0")
    log.record_reason_call("reason_synthesize", True, "ok", {})
    log.record_finding("Covert local admin account 'svc_x' was created (RID 1500)", "CONFIRMED", "ez.recmd")
    assert any("controls it" in i.lower() for i in _check(log)["blocking_issues"])


def test_the_director_prompt_and_the_stall_text_lose_unresolvable(monkeypatch):
    import tools.dair as D
    from agent.loop import Agent
    assert "UNRESOLVABLE" not in D._dair_sys() and "key entities" not in D._dair_sys()
    assert "let it fail (the failed call closes the item)" in Agent._report_stall_msg()
    monkeypatch.setenv("ATLAS_BLOCKER_ITEMS", "0")
    monkeypatch.setenv("ATLAS_REPORT_CHECK_NO_SCENARIO", "0")
    assert "UNRESOLVABLE" in D._dair_sys() and "key entities" in D._dair_sys()


def test_the_playbook_drops_the_structural_and_hypothesize_rows():
    from agent.playbook import assemble_playbook
    text = assemble_playbook()
    assert "structural blocking issue" not in text and "| `hypothesize_required` |" not in text


def test_the_hypothesize_observer_is_gone():
    from types import SimpleNamespace
    from tools._gates import hypothesize_required
    ctx = SimpleNamespace(window=[{"type": "reason_call", "tool": "reason_hypothesize", "call_id": 5,
                                   "success": True, "conclusion": "x"}], log=None,
                          description="svchost.exe beacons", confidence="LIKELY", tier="LIKELY",
                          tested_hypothesis_id="", gated_by_hypothesize_call_id=0)
    assert hypothesize_required.check(ctx) is None and ctx.gated_by_hypothesize_call_id == 0


def test_open_questions_are_a_warning(tmp_path, monkeypatch):
    import json
    from tools.reasoning import _task_disposition_for_report
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
        {"tasks": [{"id": "task-0003", "status": "open", "text": "Who logged on?"}]}), encoding="utf-8")
    issue, warning = _task_disposition_for_report(str(tmp_path))
    assert issue is None and warning is None
    # The report gate's one Open work line names it beside the due reads.
    from core import work_order as W
    line = W.open_work_summary(W.open_work(None, str(tmp_path), derived=False))
    assert line.startswith("Open work, which the report states as open: 1 question part(s) in 1 question(s)")
    assert "task-0003 the question" in line and "planned read" not in line


def test_the_lookup_refusal_leaves_a_proposed_item(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from tools._gates import GateContext
    from tools._gates import external_knowledge_grounding as ekg
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    read = {"type": "tool_call", "cmd": "<py>:tsk_tsk_icat", "success": True,
            "args": json.dumps({"file_path": "/case/export/svc_update.exe"}), "stdout_excerpt": "ok"}
    ctx = GateContext(description="svc_update.exe is a RedCurtain loader.", confidence="LIKELY", tier="LIKELY",
                      source="test", linked_call_id=0, tested_hypothesis_id="", log=SimpleNamespace(_entries=[]),
                      idx=SimpleNamespace(by_call_id={7: read}), window=[], input_call_ids=[7],
                      supporting_evidence="")
    out = ekg.check(ctx)
    item = [i for i in log.work_items() if i["call_id"] == out["work_item"]][0]
    assert item["origin"] == "reason" and item["status"] == "proposed" and "RedCurtain" in item["why"]


def test_an_unaddressed_case_question_is_a_warning(log):
    log.record_reason_call("reason_synthesize", True, "ok", {})
    with patch("tools.reasoning._case_questions_for_pre_report",
               return_value=[("Which account copied the files?", "free")]), \
         patch("tools.reasoning._question_coverage", return_value=("unaddressed", ["account", "copied"], 1)):
        r = _check(log)
    assert not any("Case question" in i for i in r["blocking_issues"])
    assert any(w.startswith('Case question "Which account copied the files?" is not addressed') for w in r["warnings"])


def test_unread_high_value_artefacts_are_a_warning_naming_the_index_items(log):
    log.record_reason_call("reason_synthesize", True, "ok", {})
    item = log.add_work_item("index", [], "", {"source_hint": "C/Users/jane.doe/NTUSER.DAT"}, "unread hive",
                             status="proposed")
    state = {"items": [{"state": "open", "name": "NTUSER.DAT", "host": "CORP-WS01"}], "read": 0,
             "short_waivers": [], "unmatched_waivers": []}
    with patch("core.artifact_value.high_value_state", return_value=state):
        r = _check(log)
    assert not any("NTUSER.DAT" in i for i in r["blocking_issues"])
    assert any(f"#{item['call_id']} proposed" in w for w in r["warnings"])


def test_without_the_composer_the_case_question_still_blocks(log, monkeypatch):
    monkeypatch.setenv("ATLAS_ANSWER_COMPOSE", "0")
    log.record_reason_call("reason_synthesize", True, "ok", {})
    with patch("tools.reasoning._case_questions_for_pre_report",
               return_value=[("Which account copied the files?", "free")]), \
         patch("tools.reasoning._question_coverage", return_value=("unaddressed", ["account", "copied"], 1)):
        r = _check(log)
    assert any("Case question" in i for i in r["blocking_issues"])


def test_without_the_likely_evaluation_the_scenario_checks_stay(log, monkeypatch):
    from core.deferred_intents import report_check_no_scenario_on
    assert report_check_no_scenario_on() is True
    monkeypatch.setenv("ATLAS_EXTERNAL_LOOKUP_FIRST", "0")
    assert report_check_no_scenario_on() is False
    log.record_reason_call("reason_synthesize", True, "ok", {})
    log.record_finding("Covert local admin account 'svc_x' was created (RID 1500)", "CONFIRMED", "ez.recmd")
    assert any("controls it" in i.lower() for i in _check(log)["blocking_issues"])


def test_a_synthesis_asked_again_without_a_new_finding_points_at_the_last(log, monkeypatch):
    from tools.reasoning import reason_synthesize
    import tools.reasoning as R
    log.record_dair_call("Report", "", False, "", "", "stay", "")
    cid = log.record_reason_call("reason_synthesize", True, SYNTH, {})
    log.update_reason_call(cid, findings_fingerprint=R._findings_fingerprint(log))
    r0 = _check(log)
    w = next(w for w in r0["warnings"] if w.startswith("Reviewer blockers"))
    assert f"The synthesis of call {cid} stands" in w and "second reason.synthesize is not needed" in w
    asked = []
    fake = lambda *a, **k: asked.append(1) or {"success": True, "conclusion": SYNTH, "_atlas_call_id": 99}
    with patch("core.execution_log.log", log), patch("tools.reasoning._ask", side_effect=fake):
        r = reason_synthesize("finding one")
        assert r["synthesis_stands"] == cid and not asked and "not needed" in r["note"]
        assert "#" in r["note"] and "read each one or let the read fail" in r["note"]
        log.record_finding("jane.doe ran tool.exe on CORP-WS01", "LIKELY", source="test")
        reason_synthesize("finding one\nfinding two")
        assert asked == [1]
    monkeypatch.setenv("ATLAS_SYNTHESIS_STANDS", "0")
    log.record_reason_call("reason_synthesize", True, SYNTH, {})
    with patch("core.execution_log.log", log), patch("tools.reasoning._ask", side_effect=fake):
        reason_synthesize("finding one")
    assert asked == [1, 1]


def test_a_withdrawn_or_changed_finding_makes_a_new_synthesis_due(log, tmp_path):
    import json
    import tools.reasoning as R
    from tools.reasoning import reason_synthesize
    (tmp_path / ".atlas").mkdir(exist_ok=True)
    graph = {"nodes": {"C0001": {"id": "C0001", "kind": "claim", "status": "active", "confidence": "LIKELY",
                                 "statement": "jane.doe ran tool.exe on CORP-WS01"}}}
    gpath = tmp_path / ".atlas" / "claim_graph.json"
    gpath.write_text(json.dumps(graph), encoding="utf-8")
    log.record_dair_call("Report", "", False, "", "", "stay", "")
    cid = log.record_reason_call("reason_synthesize", True, SYNTH, {})
    log.update_reason_call(cid, findings_fingerprint=R._findings_fingerprint(log))
    asked = []
    fake = lambda *a, **k: asked.append(1) or {"success": True, "conclusion": SYNTH, "_atlas_call_id": 0}
    with patch("core.execution_log.log", log), patch("tools.reasoning._ask", side_effect=fake):
        assert reason_synthesize("f")["synthesis_stands"] == cid
        # Withdrawn (supersede with no replacement): the synthesis no longer stands.
        graph["nodes"]["C0001"].update(status="withdrawn", superseded_by="C0001")
        gpath.write_text(json.dumps(graph), encoding="utf-8")
        assert "synthesis_stands" not in reason_synthesize("f") and asked == [1]
        # A confidence changed in place, after a synthesis that saw the withdrawal.
        log.update_reason_call(cid, findings_fingerprint=R._findings_fingerprint(log))
        graph["nodes"]["C0001"].update(status="active", confidence="CONFIRMED", superseded_by=None)
        gpath.write_text(json.dumps(graph), encoding="utf-8")
        assert "synthesis_stands" not in reason_synthesize("f") and asked == [1, 1]
