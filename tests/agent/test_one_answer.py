"""One answer per call: every single-reply role call (composer, planner,
director, reason tools, reviewers, report sections) asks under one output
allowance; a reply cut there is asked again once one thinking level lower,
and a second cut is a failed call for its caller's fallback. Invented
replies only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent.llm import ONE_ANSWER_MAX_TOKENS, cut_at_allowance, one_answer_chat


def _r(finish="stop", content="answer"):
    return SimpleNamespace(content=content, finish_reason=finish, cut_reason="", input_tokens=1,
                           output_tokens=ONE_ANSWER_MAX_TOKENS if finish == "length" else 10,
                           reasoning_tokens=0, length_cuts=0)


class _Client:
    def __init__(self, *replies, lower="low"):
        self.replies, self.calls, self.lower = list(replies), [], lower

    def chat(self, messages, **kw):
        self.calls.append(kw)
        return self.replies.pop(0)

    def next_lower_level(self, role, level=None):
        return self.lower


def test_the_allowance_is_sent_and_a_clean_reply_is_one_call():
    c = _Client(_r())
    resp = one_answer_chat(c, [], role="report_answer", temperature=0.1)
    assert len(c.calls) == 1 and c.calls[0]["max_tokens"] == 64_000 and c.calls[0]["role"] == "report_answer"
    assert resp.length_cuts == 0 and not cut_at_allowance(resp)


def test_a_cut_reply_is_asked_again_one_level_lower():
    c = _Client(_r("length", "a a a a"), _r())
    resp = one_answer_chat(c, [], role="reason_plan_question")
    assert [k.get("level") for k in c.calls] == [None, "low"]
    assert c.calls[1]["learn"] is False and "learn" not in c.calls[0]
    assert resp.content == "answer" and resp.length_cuts == 1 and not cut_at_allowance(resp)


def test_a_second_cut_is_a_failed_call_and_no_lower_level_means_no_retry():
    c = _Client(_r("length"), _r("length"))
    resp = one_answer_chat(c, [], role="dair")
    assert cut_at_allowance(resp) and resp.length_cuts == 2
    c = _Client(_r("length"), lower=None)
    resp = one_answer_chat(c, [], role="dair")
    assert len(c.calls) == 1 and cut_at_allowance(resp) and resp.length_cuts == 1


def test_the_allowance_has_a_calibration_knob(monkeypatch):
    monkeypatch.setenv("ATLAS_ONE_ANSWER_MAX_TOKENS", "48000")
    c = _Client(_r())
    one_answer_chat(c, [], role="report_answer")
    assert c.calls[0]["max_tokens"] == 48_000


def test_the_composer_falls_back_on_a_runaway_and_records_it(tmp_path, monkeypatch):
    import core.answer_synthesis as A
    from tests.core.test_answer_compose import GRAPH, LEX, _task
    monkeypatch.setenv("ATLAS_ANSWER_COMPOSE", "1")
    (tmp_path / ".atlas").mkdir()
    client = _Client(_r("length", "loop " * 50), _r("length", "loop " * 50))
    monkeypatch.setattr(A, "_compose_client", lambda: client)
    res = A.compose_answer(tmp_path, _task(), GRAPH, [], lexicon=LEX)
    assert res["outcome"] == "fallback" and res["reason"] == "length" and res["length_cuts"] == 2
    assert all(k["max_tokens"] == ONE_ANSWER_MAX_TOKENS for k in client.calls)


def test_a_reason_tool_takes_no_answer_from_a_runaway(monkeypatch):
    import tools.reasoning as R
    client = _Client(_r("length", "loop"), _r("length", "loop"))
    monkeypatch.setattr("agent.llm.LLMHubClient", lambda **kw: client)
    monkeypatch.setattr(R, "REASON_URL", "http://203.0.113.5/v1")
    out = R._ask("system", "user", _tool_name="reason_plan_question")
    assert out["gate"] == "reply_length_cut" and out["length_cuts"] == 2 and not out.get("success")


@pytest.mark.parametrize("path", ["core/answer_synthesis.py", "tools/reasoning.py", "tools/dair.py",
                                  "core/report_projection.py", "core/investigation_orchestrator.py",
                                  "core/case_autofill.py", "agent/review.py"])
def test_every_one_answer_call_goes_through_the_allowance(path):
    """No single-reply role call reaches the transport directly (the
    analyst's turns and the capability probe are not one-answer calls)."""
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / path).read_text(encoding="utf-8")
    assert not re.search(r"\b(?:client|llm_client|self\.client)\.chat\(", text), path


def test_the_switch_off_sends_the_call_as_before(monkeypatch):
    monkeypatch.setenv("ATLAS_ONE_ANSWER_ALLOWANCE", "0")
    c = _Client(_r("length"))
    resp = one_answer_chat(c, [], role="dair")
    assert len(c.calls) == 1 and "max_tokens" not in c.calls[0] and resp.length_cuts == 0
