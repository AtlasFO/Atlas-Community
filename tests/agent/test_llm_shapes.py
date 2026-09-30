"""Every provider response shape normalises to the same ChatResponse.

The fixtures under tests/fixtures/llm/ are written by hand from documented
response shapes: one directory per serving stack (sglang, vLLM, LiteLLM,
OpenAI, OpenRouter), each file named for the quirk it pins and reduced to
what the parser reads, plus synthetic/ for edge cases across stacks (think
tags left in content, content parts, encrypted-only reasoning, empty
replies). A fixture is never saved from a live call: a real reply carries
the provider's ids, signatures and serving internals. Each carries the
expectation a human wrote for it. A shape is supported when its fixture is
here and this test passes; adding a provider means adding fixtures, not
code branches.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.llm import (accepted_values_from_error, normalize_error_body,
                       parse_response)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "llm"
CASES = sorted(FIXTURES.glob("*/*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.mark.parametrize("path", CASES, ids=[f"{p.parent.name}/{p.stem}" for p in CASES])
def test_fixture_normalises_as_expected(path):
    case = _load(path)
    expect = case["expect"]
    if case["status"] != 200:
        text = normalize_error_body(json.dumps(case["response"]))
        assert expect["error_contains"] in text
        assert accepted_values_from_error(text) == expect["accepted_values"]
        return

    resp = parse_response(case["response"])

    if "content" in expect:
        assert resp.content == expect["content"]
    if "content_prefix" in expect:
        assert resp.content.startswith(expect["content_prefix"])
    if expect.get("reasoning_empty"):
        assert resp.reasoning == ""
    if "reasoning_prefix" in expect:
        assert resp.reasoning.startswith(expect["reasoning_prefix"]), resp.reasoning[:80]
    assert resp.reasoning_tokens == expect["reasoning_tokens"]
    assert len(resp.tool_calls) == expect["tool_calls"]
    if expect.get("tool_name"):
        assert resp.tool_calls[0].name == expect["tool_name"]
        assert resp.tool_calls[0].id
    if "tool_arguments" in expect:
        assert resp.tool_calls[0].arguments == expect["tool_arguments"]
    assert resp.finish_reason == expect["finish_reason"]
    assert resp.starved is expect["starved"]
    assert resp.thinking_observed is expect["thinking_observed"]
    for key in expect.get("raw_keys", []):
        assert key in resp.raw_message, f"{key} must survive on raw_message"


def test_corpus_covers_every_serving_stack():
    stacks = {p.parent.name for p in CASES}
    assert {"sglang", "vllm", "litellm", "openai", "openrouter", "synthetic"} <= stacks


def test_fixtures_are_written_by_hand():
    """No fixture is a saved reply: none is labelled as a recording, and every
    timestamp is an invented one in 2031 or later."""
    invented = 1924992000  # 2031-01-01
    for path in CASES:
        case = _load(path)
        assert "recorded" not in case["source"].lower(), path
        assert case["response"].get("created", invented) >= invented, path
