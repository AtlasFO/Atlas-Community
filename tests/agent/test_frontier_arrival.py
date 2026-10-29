"""A host pass's arrival is recorded as a finding with a
host row carrying the arrival time, so the incident window anchors the host
and an earlier attacker event there draws a seen_before_start note.
Invented fixtures only (CORP-WS02, jane.doe, svc_kit.exe, 203.0.113.x,
dates in 2031)."""
from __future__ import annotations

import json
from types import SimpleNamespace

from agent.frontier import SubmitApplier
from core import incident_map as IM
from core.claim_graph import add_claim, set_claim_indicators
from tests.core.test_incident_map import _case, _claim, _trace, _wide


class _Recorder:
    """The record path reduced to what the map reads: a claim with its rows."""

    def __init__(self, case):
        self.case, self.records = case, []

    def _call_once(self, name, args, **kw):
        self.records.append(args)
        cid = add_claim(self.case, args["description"], confidence=args["confidence"], host=args["host"],
                        enforce_validation=False)["node_id"]
        set_claim_indicators(self.case, cid, args.get("indicators") or [])
        return {"result": json.dumps({"success": True, "claim_id": cid}), "kind": "ran"}


def test_a_host_pass_arrival_anchors_the_window_and_raises_the_early_event_note(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    # an attacker event on the host a day before the arrival the pass finds
    _claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-09 09:00:00.",
           [{"type": "file", "value": "svc_kit.exe", "side": "attacker"}], host="CORP-WS02")
    call = log.record_tool_call("table.table_grep logons", True, False, 0, 0,
                                stdout_excerpt="time,event\n2031-03-10 13:58:00,logon from 203.0.113.7 user jane.doe\n")
    m = IM.open(case)
    cursor = m.head()
    before = m.window()
    assert "CORP-WS02" not in before["hosts"]                   # an attacker event alone anchors nothing here
    item = log.add_work_item("host_pass", [], "", {"host": "CORP-WS02"}, "pass",
                             source_ref={"host": "CORP-WS02", "entities": [], "closed_by": "executor"},
                             extra_key="host_pass:CORP-WS02:0")
    agent = _Recorder(case)
    ap = SubmitApplier(agent, case, m, item, "host_pass")
    anchor = {"statement": "jane.doe logged on to CORP-WS02 from 203.0.113.7 at 2031-03-10 13:58:00.",
              "confidence": "likely",
              "event": {"time": "2031-03-10 13:58:00", "kind": "logon",
                        "src": {"kind": "endpoint", "value": "203.0.113.7"},
                        "actor": {"kind": "account", "value": "jane.doe"}},
              "basis": [{"call_id": call, "quote": "logon from 203.0.113.7"}]}
    labels = [{"ref": {"kind": "endpoint", "value": "203.0.113.7"}, "label": "attacker",
               "basis": [{"call_id": call, "quote": "203.0.113.7"}]}]
    assert ap({"arrival": {"anchor": anchor}, "labels": labels}, SimpleNamespace(calls=[call]), False) is None
    rows = agent.records[0]["indicators"]
    assert {"type": "host", "value": "CORP-WS02", "side": "victim", "attacker_from": "2031-03-10 13:58:00"} in rows
    assert {"type": "ip", "value": "203.0.113.7", "side": "attacker"} in rows
    w = m.window()
    assert "CORP-WS02" in w["hosts"] and "CORP-WS02" not in w["unanchored"] 
    # anchored by the arrival: its claim-backed event, or else its host row
    assert w["via"]["CORP-WS02"] in ("event", "row") and w["hosts"]["CORP-WS02"][0][0] == "2031-03-10 13:58:00"
    kinds = [c["kind"] for c in m.changes_since(cursor)[0]]
    assert "seen_before_start" in kinds
    # the arrival event carries the arrival's claim: a belief, not a proposal
    with m._read() as con:
        lab = con.execute("SELECT l.claim_id, l.proposal FROM labels l JOIN events e ON l.target = 'v:' || e.vid "
                          "WHERE e.verb = 'arrival' AND l.current = 1").fetchone()
    assert lab is not None and lab["claim_id"] and lab["proposal"] == 0


def test_hosts_without_an_arrival_are_disclosed(tmp_path, monkeypatch):
    from core.investigation_exit import completion_disclosure
    from core.report_exit import _with_gate_issues
    case = _wide(_case(tmp_path))
    (case / "CASE.md").write_text("# Case: A\n\n**Case ID:** A\n**System owner:** victim\n", encoding="utf-8")
    _trace(case, monkeypatch)
    _claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-09 09:00:00.",
           [{"type": "file", "value": "svc_kit.exe", "side": "attacker"}], host="CORP-WS02")
    assert "CORP-WS02" in completion_disclosure(case)["hosts_without_arrival"]
    md = _with_gate_issues("# Report\n", case)
    assert "## Limitations" in md and "CORP-WS02" in md.split("## Limitations")[1]
    # the client report states it under its gaps, whatever a model wrote
    from core.report_assemble import assemble_client_report
    report = assemble_client_report(case, compose=False)
    line = next(x for x in report.splitlines() if "CORP-WS02" in x and ("No start stated" in x
                                                                        or "no anchor stated" in x))
    assert line.startswith("- ") and line[2:] not in _with_gate_issues(report, case).replace(report, "")


def test_outside_the_incident_frame_a_label_without_a_start_states_no_missing_arrival(tmp_path, monkeypatch):
    """No brief names a victim (the neutral frame): an attacker label with
    no stated time states no window, so no host is said to lack its
    arrival, in the exit state or in the report's Limitations."""
    from core.investigation_exit import completion_disclosure, open_limit_lines
    case = _wide(_case(tmp_path))
    _trace(case, monkeypatch)
    _claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-09 09:00:00.",
           [{"type": "file", "value": "svc_kit.exe", "side": "attacker"}], host="CORP-WS02")
    assert "hosts_without_arrival" not in completion_disclosure(case)
    assert not any("CORP-WS02" in line for line in open_limit_lines(case))


def _pass_env(tmp_path, monkeypatch, host="CORP-WS02"):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    call = log.record_tool_call("table.table_grep logons", True, False, 0, 0,
                                stdout_excerpt="time,event\n2031-03-10 13:58:00,logon from CORP-WS01 user jane.doe\n")
    item = log.add_work_item("host_pass", [], "", {"host": host}, "pass",
                             source_ref={"host": host, "entities": [], "closed_by": "executor"},
                             extra_key=f"host_pass:{host}:0")
    return case, log, IM.open(case), item, call


def test_an_arrival_without_its_confidence_is_asked_for_and_never_assumed(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    anchor = {"statement": "jane.doe logged on at 2031-03-10 13:58:00.", "event": {"time": "2031-03-10 13:58:00"},
              "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}
    agent = _Recorder(case)
    ap = SubmitApplier(agent, case, m, item, "host_pass")
    assert "needs its confidence" in ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call]), False)
    assert agent.records == []
    ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call]), False)      # asked once, still none
    assert agent.records == [] and "CORP-WS02" not in m.window()["hosts"]
    ap2 = SubmitApplier(agent, case, m, item, "host_pass")
    ap2({"arrival": {"anchor": {**anchor, "confidence": "possible"}}}, SimpleNamespace(calls=[call]), False)
    assert agent.records[0]["confidence"] == "SUSPECTED"


def test_an_arrival_from_a_host_before_that_hosts_own_start_raises_a_note(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    # CORP-WS01's own start is stated a day after the arrival it is said to come from
    c = add_claim(case, "The attacker reached CORP-WS01 at 2031-03-11 09:00:00.", confidence="LIKELY",
                  host="CORP-WS01", enforce_validation=False)["node_id"]
    set_claim_indicators(case, c, [{"type": "host", "value": "CORP-WS01", "side": "victim",
                                    "attacker_from": "2031-03-11 09:00:00"}])
    anchor = {"statement": "jane.doe reached CORP-WS02 from CORP-WS01 at 2031-03-10 13:58:00.",
              "confidence": "likely", "event": {"time": "2031-03-10 13:58:00", "kind": "logon",
                                                "src": {"kind": "host", "value": "CORP-WS01"}},
              "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}
    ap = SubmitApplier(_Recorder(case), case, m, item, "host_pass")
    ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call]), False)
    chain = [i for i in log.work_items() if (i.get("source_ref") or {}).get("kind") == "chain"]
    assert len(chain) == 1 and "precedes CORP-WS01's own start 2031-03-11 09:00:00" in chain[0]["why"]


def test_an_address_in_attacker_from_is_sent_back_with_the_fields_meaning(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    anchor = {"statement": "jane.doe reached CORP-WS02 at 2031-03-10 13:58:00.", "confidence": "likely",
              "attacker_from": "203.0.113.7", "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}
    agent = _Recorder(case)
    ap = SubmitApplier(agent, case, m, item, "host_pass")
    reply = ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call]), False)
    assert "'203.0.113.7', which is no time" in reply and "src" in reply and agent.records == []
    ap({"arrival": {"anchor": {**anchor, "attacker_from": "2031-03-10 13:58:00"}}}, SimpleNamespace(calls=[call]),
       False)
    assert {"type": "host", "value": "CORP-WS02", "side": "victim",
            "attacker_from": "2031-03-10 13:58:00"} in agent.records[0]["indicators"]


def test_a_repair_that_drops_the_arrival_ends_with_the_arrival_marked_missing(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    agent = _Recorder(case)
    ap = SubmitApplier(agent, case, m, item, "host_pass")
    assert "arrival is required" in ap({"findings": []}, SimpleNamespace(calls=[call]), False)
    assert ap({"findings": []}, SimpleNamespace(calls=[call]), False) is None      # asked once: the item ends
    assert ap.out.get("arrival_missing") and agent.records == []
    assert "CORP-WS02" not in m.window()["hosts"]


def test_an_arrival_quoting_the_rendered_table_line_is_recorded(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    shown = "#1 2031-03-10 13:58:00 | logon from CORP-WS01 user jane.doe\n[trace call id %d]" % call
    anchor = {"statement": "jane.doe logged on to CORP-WS02 at 2031-03-10 13:58:00.", "confidence": "confirmed",
              "event": {"time": "2031-03-10 13:58:00", "kind": "logon"},
              "basis": [{"call_id": call, "quote": "#1 2031-03-10 13:58:00 | logon from CORP-WS01 user jane.doe"}]}
    agent = _Recorder(case)
    ap = SubmitApplier(agent, case, m, item, "host_pass")
    assert ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call], seen={call: shown}), False) is None
    assert agent.records and agent.records[0]["confidence"] == "CONFIRMED"
    assert m.window()["hosts"]["CORP-WS02"][0][0] == "2031-03-10 13:58:00"


def test_the_code_stated_window_line_names_every_host(tmp_path, monkeypatch):
    from core.investigation_exit import open_limit_lines
    case = _case(tmp_path)
    hosts = [f"CORP-X{i:02d}" for i in range(14)]
    monkeypatch.setattr("core.incident_window.incident_window", lambda g, case_dir=None: {
        "unanchored": hosts, "estate": ("2031-03-01 08:00:00", "C0001")})
    (line,) = open_limit_lines(case)
    assert all(h in line for h in hosts) and "the estate start 2031-03-01 08:00:00" in line


def test_an_arrival_refused_twice_leaves_the_pass_without_its_arrival(tmp_path, monkeypatch):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)

    class _Refuser:
        def _call_once(self, name, args, **kw):
            return {"result": json.dumps({"success": False, "gate": "evidence_strength", "error": "e"}),
                    "kind": "ran"}
    anchor = {"statement": "jane.doe logged on at 2031-03-10 13:58:00.", "confidence": "likely",
              "event": {"time": "2031-03-10 13:58:00"}, "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}
    ap = SubmitApplier(_Refuser(), case, m, item, "host_pass")
    assert ap({"arrival": {"anchor": anchor}}, SimpleNamespace(calls=[call]), False)
    ap({"findings": [{"statement": anchor["statement"], "basis": anchor["basis"]}]}, SimpleNamespace(calls=[call]),
       False)
    assert ap.out.get("arrival_missing") is True


# -- a bad anchor field holds only the arrival -----------------------------------------------

class _RefusingOnce(_Recorder):
    """Refuses the first record of each statement once, then records it."""

    def __init__(self, case):
        super().__init__(case)
        self.seen = set()

    def _call_once(self, name, args, **kw):
        if args["description"] not in self.seen and "routine" in args["description"]:
            self.seen.add(args["description"])
            return {"result": json.dumps({"success": False, "gate": "evidence_strength", "error": "cite the row"}),
                    "kind": "ran"}
        return super()._call_once(name, args, **kw)


def _pg2(tmp_path, monkeypatch, agent_cls=_Recorder):
    case, log, m, item, call = _pass_env(tmp_path, monkeypatch)
    bad = {"statement": "jane.doe reached CORP-WS02 at 2031-03-10 13:58:00.", "confidence": "likely",
           "attacker_from": "203.0.113.7", "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}
    finding = {"statement": "jane.doe logged on to CORP-WS02 from CORP-WS01 at 2031-03-10 13:58:00.",
               "confidence": "likely", "host": "CORP-WS02",
               "basis": [{"call_id": call, "quote": "logon from CORP-WS01 user jane.doe"}],
               "entities": [{"kind": "host", "value": "CORP-WS01"}]}
    labels = [{"ref": {"kind": "host", "value": "CORP-WS01"}, "label": "attacker",
               "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}]
    agent = agent_cls(case)
    return case, log, m, item, call, bad, finding, labels, agent, SubmitApplier(agent, case, m, item, "host_pass")


def test_a_bad_anchor_field_holds_only_the_arrival_and_says_which_field(tmp_path, monkeypatch):
    case, log, m, item, call, bad, finding, labels, agent, ap = _pg2(tmp_path, monkeypatch)
    reply = ap({"arrival": {"anchor": bad}, "findings": [finding], "labels": labels}, SimpleNamespace(calls=[call]),
               False)
    assert len(agent.records) == 1 and ap.out["findings"] == 1                   # the finding was taken
    assert "the arrival was not taken: its anchor has attacker_from '203.0.113.7', which is no time" in reply
    assert "the event's src" in reply and 'Resubmit the arrival alone ({"arrival": {...}})' in reply
    assert not ap.arrival_done
    # the arrival alone, as the reply asks (the schema requires only arrival)
    fixed = {**bad, "attacker_from": "2031-03-10 13:58:00"}
    assert ap({"arrival": {"anchor": fixed}}, SimpleNamespace(calls=[call]), False) is None
    assert ap.arrival_done and len(agent.records) == 2 and agent.records[1]["description"] == fixed["statement"]


def test_a_repairs_only_resubmit_after_a_held_anchor_is_taken_and_still_asks_for_the_arrival(tmp_path, monkeypatch):
    case, log, m, item, call, bad, finding, labels, agent, ap = _pg2(tmp_path, monkeypatch, _RefusingOnce)
    routine = {**finding, "statement": "jane.doe's routine logon at 2031-03-10 13:58:00."}
    reply = ap({"arrival": {"anchor": bad}, "findings": [routine], "labels": labels}, SimpleNamespace(calls=[call]),
               False)
    assert "refused (evidence_strength)" in reply and "the arrival was not taken" in reply
    reply = ap({"findings": [routine]}, SimpleNamespace(calls=[call]), False)     # repairs only, no arrival
    assert "arrival is required" not in reply and "the arrival is still owed" in reply
    assert len(agent.records) == 1


def test_the_arrival_resubmitted_beside_repairs_is_taken_first_and_the_repairs_keep_their_places(tmp_path,
                                                                                                 monkeypatch):
    case, log, m, item, call, bad, finding, labels, agent, ap = _pg2(tmp_path, monkeypatch, _RefusingOnce)
    routine = {**finding, "statement": "jane.doe's routine logon at 2031-03-10 13:58:00."}
    ap({"arrival": {"anchor": bad}, "findings": [routine, finding], "labels": labels}, SimpleNamespace(calls=[call]),
       False)
    fixed = {**bad, "attacker_from": "2031-03-10 13:58:00"}
    assert ap({"arrival": {"anchor": fixed}, "findings": [routine]}, SimpleNamespace(calls=[call]), False) is None
    statements = [r["description"] for r in agent.records]
    assert statements == [finding["statement"], fixed["statement"], routine["statement"]]
    assert ap.arrival_done and not ap.pending


def test_a_whole_submit_sent_again_counts_nothing_twice(tmp_path, monkeypatch):
    case, log, m, item, call, bad, finding, labels, agent, ap = _pg2(tmp_path, monkeypatch)
    obs = [{"text": "jane.doe logs on every morning.", "basis": [{"call_id": call, "quote": "logon from CORP-WS01"}]}]
    leads = [{"tool": "table.table_grep", "host": "CORP-WS01", "source": "evidence/x.csv", "pattern": "jane.doe",
              "why": "the source host"}]
    sub = {"arrival": {"anchor": bad}, "findings": [finding], "labels": labels, "observations": obs, "leads": leads}
    ap(sub, SimpleNamespace(calls=[call]), False)
    first = {k: ap.out[k] for k in ("findings", "labels", "observations", "items")}
    ap({**sub, "arrival": {"anchor": {**bad, "attacker_from": "2031-03-10 13:58:00"}}}, SimpleNamespace(calls=[call]),
       False)
    after = {k: ap.out[k] for k in ("labels", "observations", "items")}
    assert after == {k: first[k] for k in ("labels", "observations", "items")}
