"""An arrival the gates refused is repaired by the `arrival`
field of the next submit (it was ignored once the arrival counted as done),
and a second refusal of it is refused twice. Invented rows."""
from __future__ import annotations

import json
from types import SimpleNamespace

from agent.frontier import SubmitApplier
from core import incident_map as IM
from core.claim_graph import add_claim, set_claim_indicators
from tests.core.test_incident_map import _case, _trace, _wide


class _Rec:
    """Refuses the first ``refusals`` arrival records by a gate, records everything else."""

    def __init__(self, case, refusals=1):
        self.case, self.n_arrival, self.refusals = case, 0, refusals

    def _call_once(self, name, args, **kw):
        if "logged on" in args["description"]:
            self.n_arrival += 1
            if self.n_arrival <= self.refusals:
                return {"result": json.dumps({"success": False, "gate": "evidence_strength", "error": "weak"}),
                        "kind": "refused"}
        cid = add_claim(self.case, args["description"], confidence=args["confidence"], host=args["host"],
                        enforce_validation=False)["node_id"]
        set_claim_indicators(self.case, cid, args.get("indicators") or [])
        return {"result": json.dumps({"success": True, "claim_id": cid}), "kind": "ran"}


def _env(tmp_path, monkeypatch, refusals):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    call = log.record_tool_call("table.table_grep logons", True, False, 0, 0,
                                stdout_excerpt="time,event\n2031-03-10 13:58:00,logon from 203.0.113.7 user jane.doe\n")
    m = IM.open(case)
    item = log.add_work_item("host_pass", [], "", {"host": "CORP-WS02"}, "pass",
                             source_ref={"host": "CORP-WS02", "entities": [], "closed_by": "executor"},
                             extra_key="host_pass:CORP-WS02:0")
    agent = _Rec(case, refusals)
    anchor = {"statement": "jane.doe logged on to CORP-WS02 from 203.0.113.7 at 2031-03-10 13:58:00.",
              "confidence": "likely",
              "event": {"time": "2031-03-10 13:58:00", "kind": "logon",
                        "src": {"kind": "endpoint", "value": "203.0.113.7"}},
              "basis": [{"call_id": call, "quote": "logon from 203.0.113.7"}]}
    return log, agent, SubmitApplier(agent, case, m, item, "host_pass"), anchor, SimpleNamespace(calls=[call])


def test_a_refused_arrival_is_repaired_by_the_next_submits_arrival_field(tmp_path, monkeypatch):
    log, agent, ap, anchor, run = _env(tmp_path, monkeypatch, refusals=1)
    assert "refused (evidence_strength)" in ap({"arrival": {"anchor": anchor}}, run, False)
    assert ap({"arrival": {"anchor": anchor}, "findings": []}, run, False) is None
    ap.finish()
    assert agent.n_arrival == 2 and ap.out["findings"] == 1 and not ap.out.get("arrival_missing")
    assert not [i for i in log.work_items() if i["origin"] == "followup"]


def test_a_repaired_arrival_refused_again_is_refused_twice(tmp_path, monkeypatch):
    log, agent, ap, anchor, run = _env(tmp_path, monkeypatch, refusals=2)
    ap({"arrival": {"anchor": anchor}}, run, False)
    assert ap({"arrival": {"anchor": anchor}, "findings": []}, run, False) is None
    ap.finish()
    assert agent.n_arrival == 2 and ap.out.get("arrival_missing")
    assert [i["source_ref"]["gate"] for i in log.work_items() if i["origin"] == "followup"] == ["evidence_strength"]
