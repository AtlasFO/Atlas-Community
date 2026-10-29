"""The director's entries in the loop: an entry with no target a call can
reach makes no item and is shown to the next review as refused.
Invented fixtures only (CORP-WS01, dates in 2031)."""
from __future__ import annotations

import json

from tests.agent.test_work_order_loop import run  # noqa: F401 - the loop fixture
def test_a_reviews_bare_tool_names_make_no_item_and_are_shown_as_refused_next_time(run, monkeypatch):
    root, log, agent, events = run
    (root / "evidence" / "corp-ws01.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-WS01", "path": "evidence/corp-ws01.raw"}]}), encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    from core import work_order as W

    def fake(summary, phase_stack=None, **_kw):
        cid = log.record_dair_call("Analyze", "", False, "", "", "stay", "",
                                   directives={"priority_tools": ["ez.mftecmd", "tsk.mactime",
                                                                  "ez.pecmd | CORP-WS01 C/Windows/Prefetch"]})
        return {"current_phase": "Analyze", "_atlas_call_id": cid,
                "directives": {"priority_tools": ["ez.mftecmd", "tsk.mactime", "ez.pecmd | CORP-WS01 C/Windows/Prefetch"]}}
    monkeypatch.setattr("tools.dair.dair_assess", fake)
    agent._dair_phase = "Collect"
    agent._director_event(3, "neglected")
    items = log.work_items()
    assert [(i["origin"], i["status"], i["target"]["path"]) for i in items] == [("director", "due", "evidence/corp-ws01.raw")]
    assert log.work_items(statuses=("proposed",)) == []
    assert "added 1 items" in agent._wo_director_line and "2 not tracked (no target)" in agent._wo_director_line
    ev = next(e for e in events if e.get("event") == "director_entries_not_tracked")
    assert ev["count"] == 2 and ev["entries"] == [f"ez.mftecmd: {W.NOT_TRACKED}", f"tsk.mactime: {W.NOT_TRACKED}"]
    from tools import dair
    assert dair._last_refused_reads() == [f"ez.mftecmd, tsk.mactime: {W.NOT_TRACKED}"]
