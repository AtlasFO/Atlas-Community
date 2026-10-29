"""One per-call path (Agent._call_once) shared by the
conversation loop and the frontier's items; run() split into the shared
setup and the loop the mode names (ATLAS_LOOP); Toolbox.schemas_for and
budget_free."""
from __future__ import annotations

import json

from agent import loop as loop_mod
from agent.loop import Agent
from tests.agent.test_loop_reliability import _ScriptedClient, _StubToolbox


class _CountingBox(_StubToolbox):
    def __init__(self, replies=None):
        self.calls = []
        self.replies = list(replies or [])

    def call(self, name, arguments, budget_free=False):
        self.calls.append((name, dict(arguments), budget_free))
        if self.replies:
            return self.replies.pop(0), False
        return json.dumps({"success": True, "rows": [1, 2]}), False

    def resolve(self, name):
        return name


def _agent(box):
    a = Agent(_ScriptedClient([]), box, case_dir=None, quiet=True)
    a._run_setup("sys", "user")
    return a


def test_a_repeat_is_pointed_at_or_replayed_and_never_run_twice():
    box = _CountingBox()
    a = _agent(box)
    first = a._call_once("table_table_grep", {"path": "x.csv", "pattern": "y"}, turn=1, tool_call_id="c1")
    assert first["kind"] == "ran" and first["ran_clean"]
    pointed = a._call_once("table_table_grep", {"path": "x.csv", "pattern": "y"}, turn=2,
                           in_context=lambda _id: True)
    assert pointed["kind"] == "pointer" and '"gate": "identical_call"' in pointed["result"]
    replay = a._call_once("table_table_grep", {"path": "x.csv", "pattern": "y"}, turn=3,
                          in_context=lambda _id: False)
    assert replay["kind"] == "replayed" and replay["result"].startswith("[replayed from turn 1")
    assert len(box.calls) == 1


def test_a_callers_gate_refuses_before_the_run_and_a_repeated_refusal_is_marked():
    refusal = json.dumps({"success": False, "gate": "some_gate", "error": "no"})
    box = _CountingBox([refusal, refusal])
    a = _agent(box)
    gated = a._call_once("misc_x", {"a": 1}, turn=1, before_run=lambda n, args: "refused by the caller")
    assert gated == {"result": "refused by the caller", "kind": "refused", "issue": None, "ran_clean": False}
    assert box.calls == []
    a._call_once("misc_x", {"a": 1}, turn=2)
    again = a._call_once("misc_x", {"a": 1}, turn=3)
    assert "REPEATED REFUSAL" in again["result"] and len(box.calls) == 2


def test_budget_free_reaches_the_toolbox():
    box = _CountingBox()
    a = _agent(box)
    a._call_once("table_table_grep", {"path": "z.csv", "pattern": "q"}, turn=1, budget_free=True)
    assert box.calls[0][2] is True


def test_the_loop_mode_dispatches_after_the_shared_setup(monkeypatch):
    a = Agent(_ScriptedClient([]), _CountingBox(), case_dir=None, quiet=True)
    events = []
    monkeypatch.setattr(a, "_log", events.append)
    monkeypatch.setattr(a, "_run_turns", lambda: "turns")
    monkeypatch.delenv("ATLAS_LOOP", raising=False)
    assert a.run("sys", "user") == "turns"
    assert next(e for e in events if e["event"] == "run_start")["loop_mode"] == "conversation"
    monkeypatch.setenv("ATLAS_LOOP", "frontier")
    monkeypatch.setenv("ATLAS_INCIDENT_MAP", "0")
    events.clear()
    out = a.run("sys", "user")
    assert "incident map" in out and a.stats["stopped_reason"] == "loop_mode_refused"
    assert not [e for e in events if e["event"] == "run_start"]          # refused before the setup
    assert loop_mod.loop_mode() == "frontier"
    monkeypatch.setenv("ATLAS_INCIDENT_MAP", "1")
    monkeypatch.setattr("agent.frontier.FrontierRun.run", lambda self: "frontier ran")
    events.clear()
    assert a.run("sys", "user") == "frontier ran"
    assert next(e for e in events if e["event"] == "run_start")["loop_mode"] == "frontier"


def test_schemas_for_lists_exactly_the_named_tools_in_order_and_budget_free_loads_nothing(monkeypatch):
    from agent.toolbox import Toolbox
    tb = Toolbox()
    names = ["strings.strings_grep", "table.table_grep", "no.such_tool"]
    out = [s["function"]["name"] for s in tb.schemas_for(names)]
    assert out == [tb.tools[tb.resolve(n)].listed or tb.resolve(n) for n in names[:2]]
    loaded = set(tb.loaded)
    monkeypatch.setattr(tb, "load_with_budget", lambda *a, **k: (_ for _ in ()).throw(AssertionError("loaded")))
    ns_tool = next(n for n, i in tb.tools.items() if i.namespace not in tb.loaded
                   and i.listed not in tb.control_names)
    text, auto = tb.call(ns_tool, {"_malformed_arguments": "x"}, budget_free=True)
    assert "not valid JSON" in text and auto is False and set(tb.loaded) == loaded


class _ShowingBox(_CountingBox):
    """A toolbox that, like agent.toolbox, notes the rows the call showed."""

    def call(self, name, arguments, budget_free=False):
        from agent import toolbox as T
        T._SHOWN.keys = ["k1", "k2"]
        return super().call(name, arguments, budget_free)


def test_a_clean_call_returns_the_rows_it_showed_and_a_refused_one_none():
    a = _agent(_ShowingBox([json.dumps({"success": True, "rows": [1]}),
                            json.dumps({"success": False, "error": "no such column"})]))
    ok = a._call_once("table_table_grep", {"path": "x.csv", "pattern": "y"}, turn=1)
    bad = a._call_once("table_table_grep", {"path": "x.csv", "pattern": "z"}, turn=1)
    assert ok["shown_rows"] == ["k1", "k2"] and bad["shown_rows"] == []
    from agent.toolbox import take_shown_rows
    assert take_shown_rows() is None                               # taken once, by the call path
