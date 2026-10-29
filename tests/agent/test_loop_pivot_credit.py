"""The loop hands the pivot ledger a tool call's rendered result, so a table
search stopped at its hit cap credits only the indicators its rows show."""
from __future__ import annotations

import json

from agent import loop as loop_mod
from agent.llm import ChatResponse, ToolCall
from agent.loop import Agent
from core import ioc_pivots as ip

SOURCE = "evidence/fw/firewall.log"


import pytest

pytestmark = pytest.mark.usefixtures("todays_pivots")


class _StubToolbox:
    def openai_tools(self):
        return []

    def namespace_summary(self):
        return ""


class _ScriptedClient:
    model = "fake-model"
    base_url = "http://fake"
    total_input_tokens = 0
    total_output_tokens = 0

    def __init__(self, script):
        self.script = list(script)

    def chat(self, messages, tools=None, role=None):
        return self.script.pop(0) if self.script else ChatResponse(content="nothing more")


def _case(tmp_path):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    # The incident frame the pivots are pinned in is the brief's statement.
    (case / "CASE.md").write_text("**Case ID:** CASE-A\n**System owner:** victim\n", encoding="utf-8")
    (case / SOURCE).parent.mkdir(parents=True)
    (case / SOURCE).write_text("x", encoding="utf-8")
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
        "schema_version": "1.0", "edges": [],
        "nodes": {"C0001": {"id": "C0001", "kind": "claim", "status": "new",
                            "statement": "Beacons to 203.0.113.44 and update.example.com seen."}}}),
        encoding="utf-8")
    return case


def test_a_capped_table_search_credits_only_what_its_rows_show(tmp_path, monkeypatch):
    case = _case(tmp_path)
    ip.refresh_pivots(case)
    owed = {p["ioc"] for p in ip.open_pivots(case)}
    assert {"ip:203.0.113.44", "domain:update.example.com"} <= owed
    args = {"path": SOURCE, "pattern": "203.0.113.44|update.example.com"}
    rendered = json.dumps({"success": True, "path": SOURCE, "pattern": args["pattern"],
                           "hits": [{"_row": n, "line": "allow 10.0.0.7 -> 203.0.113.44"}
                                    for n in range(50)],
                           "hit_count": 50, "max_hits": 50, "hit_cap_reached": True,
                           "scan_capped": False}, indent=2, ensure_ascii=False)

    class _Grep(Agent):
        def _run_tool(self, tc):
            return rendered if tc.name == "table_table_grep" else '{"success": true}'

        def _dair_reengage_pending(self):
            return False

        def _report_written(self):
            return False

    for name, value in (("MAX_WALL_SECONDS", 0.0), ("MAX_TURNS", 0),
                        ("BLOCKER_EXTENSION_TURNS", 0), ("BLOCKER_EXTENSION_MAX", 0)):
        monkeypatch.setattr(loop_mod, name, value)
    grep = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="table_table_grep",
                                                         arguments=args)])
    finish = ChatResponse(content="", tool_calls=[
        ToolCall(id="2", name="atlas_finish", arguments={"summary": "done"})])
    _Grep(_ScriptedClient([grep, finish]), _StubToolbox(), case_dir=case, quiet=True).run(
        "sys", "user")
    ledger = ip.load_pivots(case)["pivots"]
    assert ledger["ip:203.0.113.44"]["targets"][SOURCE] == "searched"
    assert ledger["domain:update.example.com"]["targets"][SOURCE] == "pending"


def test_a_protocol_blocked_search_credits_nothing(tmp_path, monkeypatch):
    """A search the DAIR window or the deferred backlog blocked ran nothing:
    the pivot it named stays owed (and no coverage unit is probed by it)."""
    case = _case(tmp_path)
    ip.refresh_pivots(case)
    args = {"path": SOURCE, "pattern": "203.0.113.44|update.example.com"}
    blocked = ("TOOL INFO:\n[ATLAS_PROTOCOL] Tool table_table_grep blocked: DAIR engaged earlier "
               "but no dair_call in recent window. deferred_intent=#7 (open=1) [recorded] "
               "Call dair_assess next.")

    class _Blocked(Agent):
        def _run_tool(self, tc):
            return blocked if tc.name == "table_table_grep" else '{"success": true}'

        def _dair_reengage_pending(self):
            return False

        def _report_written(self):
            return False

    for name, value in (("MAX_WALL_SECONDS", 0.0), ("MAX_TURNS", 0),
                        ("BLOCKER_EXTENSION_TURNS", 0), ("BLOCKER_EXTENSION_MAX", 0)):
        monkeypatch.setattr(loop_mod, name, value)
    grep = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="table_table_grep",
                                                         arguments=args)])
    finish = ChatResponse(content="", tool_calls=[
        ToolCall(id="2", name="atlas_finish", arguments={"summary": "done"})])
    _Blocked(_ScriptedClient([grep, finish]), _StubToolbox(), case_dir=case, quiet=True).run(
        "sys", "user")
    ledger = ip.load_pivots(case)["pivots"]
    assert ledger["ip:203.0.113.44"]["targets"][SOURCE] == "pending"
    assert ledger["domain:update.example.com"]["targets"][SOURCE] == "pending"
