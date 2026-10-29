"""The stable tool list. A provider renders the tool schemas ahead of the
system prompt and the conversation, so any change to the list re-sends the
whole cached prompt. When the provider's declared budget, bounded by the
window, holds every namespace, an analysis run lists them all from the first
turn and the list never changes; any other session swaps namespaces.
Fixture servers and invented paths only."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastmcp import FastMCP

import agent.toolbox as toolbox_mod
from agent.toolbox import Toolbox
from core import llm_check


def _mount(monkeypatch, **sizes):
    """A server with one namespace per keyword, holding that many tools."""
    root = FastMCP("fixture")
    for ns, count in sizes.items():
        sub = FastMCP(ns)
        for i in range(count):
            def _tool(x: str, _i=i) -> dict:
                """Fixture tool."""
                return {"i": _i}
            sub.tool(name=f"t{i}")(_tool)
        root.mount(sub, namespace=ns)

    class FakeServer:
        mcp = root

    monkeypatch.setitem(__import__("sys").modules, "server", FakeServer)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("ATLAS_AGENT_MAX_OPENAI_TOOLS", raising=False)
    monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
    monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", None)
    monkeypatch.setattr(toolbox_mod, "_DECLARED_CAP", None)
    monkeypatch.setattr(llm_check, "_limits", None)


def _window(monkeypatch, tokens: int | None):
    monkeypatch.setattr(llm_check, "_limits",
                        llm_check.limits_for_window(tokens) if tokens else None)


def _stable_box(monkeypatch, command="run"):
    """Three namespaces, a declared budget and a 1M window: everything fits."""
    _mount(monkeypatch, a=6, b=4, c=3)
    _window(monkeypatch, 1_000_000)
    toolbox_mod.set_declared_tool_cap(1000)
    tb = Toolbox(loaded=("a",))
    tb.allow_stable(command)
    return tb


# ── the cap ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("window, cap", [(16_000, 24), (64_000, 64), (128_000, 128),
                                         (200_000, 128), (1_000_000, 500)])
def test_a_declared_budget_is_bounded_by_the_window(monkeypatch, window, cap):
    """One schema per 2,000 tokens of window above the window's own tier: a
    200K model keeps 128, a 1M model gets 500, a small window keeps its tier."""
    toolbox_mod.set_declared_tool_cap(1000)
    _window(monkeypatch, window)
    assert toolbox_mod.hard_tool_cap() == cap


@pytest.mark.parametrize("window, cap", [(16_000, 24), (64_000, 64), (1_000_000, 128)])
def test_without_a_declaration_the_cap_is_todays(monkeypatch, window, cap):
    _window(monkeypatch, window)
    assert toolbox_mod.hard_tool_cap() == cap


def test_no_window_no_declared_budget(monkeypatch):
    """With no measured window the declaration does not apply."""
    _mount(monkeypatch, a=100, b=100)
    toolbox_mod.set_declared_tool_cap(1000)
    _window(monkeypatch, None)
    assert toolbox_mod.hard_tool_cap() == 128
    tb = Toolbox(loaded=("a",))
    tb.allow_stable("run")
    assert not tb.fits_all() and not tb.stable() and tb.loaded == {"a"}
    assert tb.list_mode() == "namespace mode: no window, cap 128"


def test_the_operators_maximum_wins_over_a_declaration(monkeypatch):
    toolbox_mod.set_declared_tool_cap(1000)
    monkeypatch.setenv("ATLAS_AGENT_MAX_OPENAI_TOOLS", "200")
    monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 200)
    _window(monkeypatch, 1_000_000)
    assert toolbox_mod.hard_tool_cap() == 200


# ── which sessions ───────────────────────────────────────────────────────

@pytest.mark.parametrize("command, stable", [("run", True), ("train", True), ("rerun", True),
                                             ("chat", False), ("interactive", False), ("", False)])
def test_only_an_analysis_run_lists_every_tool(monkeypatch, command, stable):
    tb = _stable_box(monkeypatch, command)
    assert tb.stable() is stable
    assert (tb.loaded == {"a", "b", "c"}) is stable


def test_the_cli_declares_the_budget_for_analysis_runs_only():
    from agent.cli import _tool_budget_for
    claude = SimpleNamespace(profile="anthropic")
    assert _tool_budget_for("run", claude, "claude-sonnet-5-5") == 1000
    assert _tool_budget_for("rerun", claude, "claude-haiku-5-5") == 1000
    assert _tool_budget_for("chat", claude, "claude-sonnet-5-5") is None
    assert _tool_budget_for("run", SimpleNamespace(profile="openrouter"), "z-ai/glm-5.2") is None
    assert _tool_budget_for("run", SimpleNamespace(profile=""), "m") is None
    assert _tool_budget_for("run", SimpleNamespace(profile="no-such-profile"), "m") is None


# ── a stable list never changes ──────────────────────────────────────────

def test_loads_unloads_and_preloads_leave_the_array_as_it_was(monkeypatch):
    tb = _stable_box(monkeypatch)
    first = json.dumps(tb.openai_tools())
    tb.load_with_budget(["b"])                                  # the model's load
    assert json.dumps(tb.openai_tools()) == first
    assert tb.unload(["b", "c"]) == []                          # the model's unload
    assert json.dumps(tb.openai_tools()) == first
    tb.load_with_budget(["c"], keep=["a"], evict=False)         # a director preload
    out, auto = tb.call("c_t0", {"x": "1"})                     # a call: no auto-load
    assert not auto
    assert json.dumps(tb.openai_tools()) == first
    names = [t["function"]["name"] for t in tb.openai_tools()]
    assert {"a_t0", "b_t0", "c_t0"} <= set(names)


def test_unload_is_refused_only_in_the_stable_state(monkeypatch):
    tb = _stable_box(monkeypatch, "chat")
    tb.load_with_budget(["b"])
    assert tb.unload(["b"]) == ["b"]


def test_a_list_that_becomes_stable_mid_run_is_completed_in_one_step(monkeypatch):
    """A raised ceiling makes the budget hold everything: the next request
    lists all of it at once, and only then is unload refused."""
    _mount(monkeypatch, a=6, b=4, c=3)
    _window(monkeypatch, 1_000_000)
    toolbox_mod.set_declared_tool_cap(1000)
    toolbox_mod.set_learned_tool_ceiling(12)
    tb = Toolbox(loaded=("a",))
    tb.allow_stable("run")
    assert not tb.fits_all() and tb.loaded == {"a"}
    assert tb.unload(["a"]) == ["a"]                             # not stable: unload works
    toolbox_mod.set_learned_tool_ceiling(None)
    assert tb.fits_all() and not tb.stable()
    tb.openai_tools()
    assert tb.loaded == {"a", "b", "c"} and tb.stable()
    assert tb.unload(["b"]) == []


def test_a_cut_list_leaves_the_stable_state(monkeypatch):
    tb = _stable_box(monkeypatch)
    evicted = tb.shrink_to(tb.schema_count() - 4)
    toolbox_mod.set_learned_tool_ceiling(tb.schema_count())
    assert evicted and not tb.stable()
    assert tb.list_mode().startswith("namespace mode: learned ceiling")
    left = sorted(tb.loaded)[0]
    assert tb.unload([left]) == [left]


# ── what the model reads ─────────────────────────────────────────────────

def test_the_load_tool_and_the_summary_say_what_is_true(monkeypatch):
    tb = _stable_box(monkeypatch)
    load = next(t for t in tb.openai_tools() if t["function"]["name"] == "atlas_load_namespaces")
    assert "loads and unloads nothing" in load["function"]["description"]
    assert load["function"]["parameters"] == toolbox_mod.META_TOOLS[1]["function"]["parameters"]
    assert tb.namespace_summary().startswith("All 17 tool schemas are in your tool list")
    chat = _stable_box(monkeypatch, "chat")
    assert toolbox_mod.META_TOOLS[1] in chat.openai_tools()
    assert chat.namespace_summary().startswith("Tool-schema budget:")


def test_the_system_prompt_and_the_loop_notes_follow_the_same_check(monkeypatch):
    from agent import prompts
    from agent.loop import (Agent, _DROPPED_CALL_STABLE_MSG, _META_ONLY_STABLE_MSG,
                            _list_stable, _tool_list_mode)
    assert prompts._NAMESPACE_NOTE in prompts.ADAPTER_HEADER
    plain = prompts.build_system_prompt(None)
    stable = prompts.build_system_prompt(None, stable_tools=True)
    assert prompts.ADAPTER_HEADER in plain and prompts._NAMESPACE_NOTE in plain
    assert prompts._STABLE_NAMESPACE_NOTE in stable and prompts._NAMESPACE_NOTE not in stable
    assert stable.replace(prompts._STABLE_NAMESPACE_NOTE, prompts._NAMESPACE_NOTE) == plain
    tb = _stable_box(monkeypatch)
    assert _list_stable(tb) and Agent._dropped_call_message(SimpleNamespace(toolbox=tb)) \
        == _DROPPED_CALL_STABLE_MSG
    chat = _stable_box(monkeypatch, "chat")
    assert "Loaded now:" in Agent._dropped_call_message(SimpleNamespace(toolbox=chat))
    assert "loading changes nothing" in _META_ONLY_STABLE_MSG.format(streak=3, loaded="x", tools="y")
    assert _tool_list_mode(tb) == "stable, 17 schemas (cap 500)"
    assert _tool_list_mode(object()) == "" and not _list_stable(object())


def test_the_mode_names_why_the_list_is_not_stable(monkeypatch):
    _mount(monkeypatch, a=100, b=100)
    _window(monkeypatch, 1_000_000)
    tb = Toolbox(loaded=("a",))
    tb.allow_stable("chat")
    assert tb.list_mode() == "namespace mode: not an analysis run (chat)"
    tb.allow_stable("run")
    assert tb.list_mode() == "namespace mode: no declared tool budget, cap 128"
    toolbox_mod.set_declared_tool_cap(1000)
    _window(monkeypatch, 200_000)
    assert tb.list_mode() == "namespace mode: window share, cap 128 for 200000 tokens < 204 schemas"


def test_a_failed_probe_that_completed_the_list_still_takes_its_namespace_out(monkeypatch):
    """A ceiling probe can load the last missing namespace and so make the
    list stable for a moment. When its reply brings no call, the ceiling
    goes back first, so the unload of the probed namespace is not refused
    and no list goes out over the ceiling."""
    from agent.loop import Agent
    _mount(monkeypatch, a=6, b=4, c=3)
    _window(monkeypatch, 1_000_000)
    toolbox_mod.set_declared_tool_cap(1000)
    toolbox_mod.set_learned_tool_ceiling(14)
    tb = Toolbox(loaded=("a", "b"))
    tb.allow_stable("run")
    assert tb.schema_count() == 14 and not tb.stable()
    tb.tool_probe_limit = toolbox_mod.hard_tool_cap()
    probe = tb.load_with_budget(["c"])
    assert probe["probed"] == {"namespace": "c", "count": 17, "floor": 14} and tb.stable()
    fake = SimpleNamespace(toolbox=tb, _tool_probe_ns="c", _tool_probe_floor=14, _tool_probe_at=17,
                           _tool_probe_failed_at=0, _log=lambda record: None,
                           ui=SimpleNamespace(warn=lambda text: None))
    Agent._fail_tool_probe(fake, 5)
    assert tb.loaded == {"a", "b"} and not tb.stable()
    assert len(tb.openai_tools()) == 14 and tb.pop_schema_overflow_warning() is None


def test_the_mode_names_a_declared_budget_below_the_list(monkeypatch):
    _mount(monkeypatch, a=100, b=100)
    _window(monkeypatch, 1_000_000)
    toolbox_mod.set_declared_tool_cap(128)
    tb = Toolbox(loaded=("a",))
    tb.allow_stable("run")
    assert tb.list_mode() == "namespace mode: declared budget 128 < 204 schemas"


def test_a_non_numeric_operator_maximum_does_not_drop_the_declaration(monkeypatch):
    """The operator's maximum counts only as limits_for_window reads it."""
    monkeypatch.setenv("ATLAS_AGENT_MAX_OPENAI_TOOLS", "lots")
    toolbox_mod.set_declared_tool_cap(1000)
    _window(monkeypatch, 1_000_000)
    assert toolbox_mod.hard_tool_cap() == 500


@pytest.fixture()
def _run_case(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "default")
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text("## Investigation Requests\n\n- Investigate host\n", encoding="utf-8")
    return case


def test_a_run_with_a_stable_list_gets_the_stable_namespace_note(_run_case):
    """_run_investigation asks the system prompt for the stable wording when
    the agent's toolbox lists every tool."""
    from unittest.mock import MagicMock, patch
    from agent import cli as cli_mod
    from agent.prompts import _NAMESPACE_NOTE, _STABLE_NAMESPACE_NOTE
    agent = SimpleNamespace(ui=MagicMock(), stats=None, interactive=False,
                            toolbox=SimpleNamespace(namespace_summary=lambda: "ns", stable=lambda: True),
                            run=MagicMock(side_effect=KeyboardInterrupt))
    args = SimpleNamespace(json=False, quiet=False, remote=None, output_dir=None, question=None, case_id="")
    with patch.object(cli_mod, "plane_a_scan", create=True), \
         patch("core.incremental.plane_a_scan", return_value={"success": True, "case_id": "case"}), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         patch.object(cli_mod, "_configure_remote", return_value=None), \
         patch.object(cli_mod, "_make_agent", return_value=agent), \
         patch.object(cli_mod, "_teardown_local_mounts"), \
         patch.object(cli_mod, "_resolve_case_question", return_value="Investigate host"), \
         patch("agent.prompts.initial_user_message", return_value="user"), \
         patch("core.paths.register_answer_keys"), \
         patch("core.brain.answer_key.has_ground_truth", return_value=False):
        with pytest.raises(KeyboardInterrupt):
            cli_mod._run_investigation(args, _run_case, command="run")
    sent = " ".join(str(a) for a in list(agent.run.call_args.args) + list(agent.run.call_args.kwargs.values()))
    assert _STABLE_NAMESPACE_NOTE in sent and _NAMESPACE_NOTE not in sent
