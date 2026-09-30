"""Unified LLM check: window-scaled budgets and pre-send fit."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _reset_llm_check(monkeypatch):
    from core.llm_check import reset_session

    monkeypatch.delenv("ATLAS_AGENT_MAX_OPENAI_TOOLS", raising=False)
    monkeypatch.delenv("ATLAS_AGENT_TOOL_OUTPUT_LIMIT", raising=False)
    monkeypatch.delenv("ATLAS_CONTEXT_CHARS_LOCK", raising=False)
    monkeypatch.setenv("ATLAS_CONTEXT_AUTO_CHARS", "1")
    monkeypatch.delenv("ATLAS_AGENT_CONTEXT_CHARS", raising=False)
    reset_session()
    yield
    reset_session()


def test_recommended_window_is_glm_1m():
    from core.llm_check import DEFAULT_WINDOW, RECOMMENDED_WINDOW, limits_for_window

    assert RECOMMENDED_WINDOW == 1_000_000
    assert DEFAULT_WINDOW == 1_000_000
    lim = limits_for_window(1_000_000)
    assert lim.detail_policy == "rich"
    assert lim.disk_first is False
    assert lim.below_minimum is False
    assert lim.context_chars == 3_000_000
    assert lim.max_openai_tools == 128
    assert lim.tool_output_chars == 12_000
    assert lim.send_budget_tokens == 750_000


def test_below_minimum_is_compact_disk_first():
    from core.llm_check import MIN_SENSIBLE_WINDOW, limits_for_window

    assert MIN_SENSIBLE_WINDOW == 32_000
    lim = limits_for_window(16_000)
    assert lim.below_minimum is True
    assert lim.disk_first is True
    assert lim.detail_policy == "compact"
    assert lim.context_chars == 48_000
    assert lim.max_openai_tools == 24
    assert lim.tool_output_chars == 2_500
    assert lim.notes


def test_apply_session_shrinks_and_grows(monkeypatch):
    from core.llm_check import apply_session_window

    monkeypatch.setenv("ATLAS_AGENT_CONTEXT_CHARS", "400000")
    small = apply_session_window(16_000)
    assert small.context_chars == 48_000
    assert os.environ["ATLAS_AGENT_CONTEXT_CHARS"] == "48000"

    big = apply_session_window(1_000_000)
    assert big.context_chars == 3_000_000
    assert os.environ["ATLAS_AGENT_CONTEXT_CHARS"] == "3000000"


def test_fit_messages_never_mutates_system():
    from core.llm_check import fit_messages

    system = "PLAYBOOK GATES " + ("keep-me " * 200)
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": "old question " + ("x" * 8000)},
        {"role": "assistant", "content": "old answer " + ("y" * 8000)},
        {"role": "tool", "content": "huge tool dump " + ("z" * 20000)},
        {"role": "user", "content": "latest question"},
        {"role": "assistant", "content": "latest answer"},
    ]
    fit_messages(messages, window_tokens=4096, tail=2)
    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == system
    assert "omitted" in (messages[1].get("content") or "")
    assert messages[-1]["content"] == "latest answer"


def test_fit_messages_stubs_old_tools_before_tail():
    from core.llm_check import _TOOL_STUB, fit_messages

    messages = [
        {"role": "system", "content": "sys"},
        {"role": "tool", "content": "BODY_TOOL " + ("t" * 50000)},
        {"role": "user", "content": "tail user"},
        {"role": "assistant", "content": "tail assistant"},
        {"role": "tool", "content": "TAIL_TOOL " + ("u" * 50000)},
        {"role": "user", "content": "now"},
    ]
    fit_messages(messages, window_tokens=8192, tail=4)
    assert messages[1]["content"] == _TOOL_STUB
    assert messages[0]["content"] == "sys"


def test_estimate_includes_tool_schemas():
    from core.llm_check import estimate_request_tokens

    messages = [{"role": "user", "content": "hi"}]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "misc_write_final_report",
                "description": "d" * 4000,
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]
    with_tools = estimate_request_tokens(messages, tools=tools)
    without = estimate_request_tokens(messages, tools=None)
    assert with_tools > without


def test_fit_messages_never_orphans_a_tool_message():
    """A compressed assistant tool_calls entry must keep its id — otherwise
    the paired role=tool message downstream points at a call that no longer
    exists, which is an invalid Chat Completions conversation shape."""
    from core.llm_check import fit_messages

    big_args = "x" * 20000
    messages = [
        {"role": "system", "content": "PLAYBOOK " + ("p" * 500)},
        {"role": "user", "content": "scan " + ("a" * 3000)},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": "big_tool", "arguments": big_args}},
        ]},
        {"role": "tool", "tool_call_id": "call_1", "content": "short result"},
        {"role": "user", "content": "now"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "sure"},
    ]
    fit_messages(messages, window_tokens=2900, tail=2)

    live_call_ids = {
        tc.get("id")
        for m in messages if m.get("role") == "assistant"
        for tc in (m.get("tool_calls") or [])
    }
    tool_call_ids = {
        m.get("tool_call_id") for m in messages if m.get("role") == "tool"
    }
    assert tool_call_ids <= live_call_ids
