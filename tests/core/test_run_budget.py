"""Tests for stall-based run budget (no default hard turn abort)."""
from __future__ import annotations

from core.run_budget import (
    StallState,
    hard_turn_cap_enabled,
    initial_turn_limit,
    messages_for_turn,
    should_allow_synthesize_escape,
    should_treat_as_wrapup,
)
from core import run_budget as rb


def test_default_no_hard_cap():
    assert rb.MAX_TURNS == 0 or not hard_turn_cap_enabled(0)
    assert hard_turn_cap_enabled(0) is False
    assert hard_turn_cap_enabled(150) is True
    assert initial_turn_limit(0) >= 10**6
    assert initial_turn_limit(150) == 150


def test_default_thresholds_not_too_tight():
    """Soft/hard stall thresholds must not be so tight that a run still
    making slow progress is exited as stalled."""
    assert rb.STALL_SOFT_TURNS >= 20
    assert rb.STALL_HARD_TURNS >= 40


def test_stall_soft_then_hard(monkeypatch):
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 3)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 5)
    monkeypatch.setattr(rb, "STALL_FORCE_REPORT_GRACE", 2)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)
    state = StallState(no_progress_streak=3)
    msgs = messages_for_turn(state, turn=10, report_written=False)
    assert any("stall soft" in m["content"] for m in msgs)
    assert state.soft_injected
    state.no_progress_streak = 5
    msgs2 = messages_for_turn(state, turn=12, report_written=False)
    assert any("stall hard" in m["content"] for m in msgs2)
    assert should_treat_as_wrapup(state)
    # Without open ledger gaps (no case_dir → fail-open), force-report ok
    state.no_progress_streak = 8
    msgs3 = messages_for_turn(state, turn=15, report_written=False)
    assert any("[stall force-report]" in m["content"] for m in msgs3)
    assert should_allow_synthesize_escape(state)


def test_hard_stall_message_does_not_demand_partial_report(monkeypatch):
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 2)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 3)
    monkeypatch.setattr(rb, "STALL_FORCE_REPORT_GRACE", 99)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)
    state = StallState(no_progress_streak=3)
    msgs = messages_for_turn(state, turn=10, report_written=False)
    hard = next(m["content"] for m in msgs if "stall hard" in m["content"])
    assert "Do NOT force a partial report" in hard
    assert not should_allow_synthesize_escape(state)


def test_unlimited_loop_does_not_stop_at_150(monkeypatch):
    """Regression: default must not abort at 150 turns."""
    from agent import loop as loop_mod
    from agent.llm import ChatResponse
    from agent.loop import Agent
    from tests.agent.test_loop_reliability import _StubToolbox, _ScriptedClient

    monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
    # Quiet after a few turns — must finish, not turn_cap
    client = _ScriptedClient([
        ChatResponse(content="working"),
        ChatResponse(content="working"),
        ChatResponse(content="nothing more to add"),
        ChatResponse(content="nothing more to add"),
        ChatResponse(content="nothing more to add"),
    ])
    agent = Agent(client, _StubToolbox(), case_dir=None, quiet=True)
    agent.run("sys", "user")
    assert agent.stats["stopped_reason"] != "turn_cap"
    assert agent.stats.get("turns", 0) >= 3 or agent.stats["stopped_reason"] in (
        "finished", "quiet")
