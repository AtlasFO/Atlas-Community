"""A helper role that the client cut, within one run: the lower level that
answered opens the role's next calls, and a role whose lower level was cut
too is not re-asked again (agent.llm._RUN_LEVEL, _RUN_NO_RUNG). Nothing of
it is persisted or written to level_by_role. A helper request that failed
is not sent again unchanged, and the skipped call still leaves an unusable
reason_call outcome (tools.reasoning._reason_failure_lookup). The effort
level need not bound a model's thinking, and a provider's stream speed
varies, so a slow provider can cut the same request again. Invented prompts
only."""
from __future__ import annotations

import contextlib

import pytest

from agent import llm
from tests.agent.test_llm_transport import MSGS, _chunk, _client, _SSEReply, wire  # noqa: F401


def _streams(monkeypatch, replies):
    sent = []

    @contextlib.contextmanager
    def _stream(method, url, json=None, headers=None, timeout=None):
        sent.append(json)
        yield replies.pop(0)
    monkeypatch.setattr("agent.llm.httpx.stream", _stream)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    return sent


def _cut():
    return _SSEReply([_chunk({"content": "!" * 100}) for _ in range(60)] + [_chunk({}, finish="stop"), "data: [DONE]"])


def _ok():
    return _SSEReply([_chunk({"content": "ok"}), _chunk({}, finish="stop"),
                      _chunk(usage={"completion_tokens": 2}, choices=False), "data: [DONE]"])


def test_the_lower_level_that_answered_opens_the_role_s_next_call(wire, monkeypatch):
    sent = _streams(monkeypatch, [_cut(), _ok(), _ok()])
    c = _client()
    assert c.chat(MSGS, role="reason_hypothesize").content == "ok"
    assert [p.get("reasoning_effort") for p in sent] == [None, "low"]
    c.chat(MSGS, role="reason_hypothesize")
    assert sent[2].get("reasoning_effort") == "low"
    # Run memory only: the learned profile holds no level for the role.
    assert not c.profile.level_by_role.get("reason_hypothesize")


def test_a_role_whose_lower_level_was_cut_too_is_not_re_asked(wire, monkeypatch):
    sent = _streams(monkeypatch, [_cut(), _cut(), _cut(), _ok()])
    c = _client()
    first = c.chat(MSGS, role="reason_evaluate_finding")
    assert first.cut_reason and len(sent) == 2
    second = c.chat(MSGS, role="reason_evaluate_finding")
    assert second.cut_reason and len(sent) == 3          # one reply bound, no re-ask
    assert not c.profile.level_by_role


def test_the_analyst_is_not_a_helper(wire, monkeypatch):
    sent = _streams(monkeypatch, [_cut(), _ok(), _ok()])
    c = _client()
    c.chat(MSGS, role="analyst")
    c.chat(MSGS, role="analyst")
    assert sent[2].get("reasoning_effort") is None


def test_an_operator_level_still_wins(wire, monkeypatch):
    sent = _streams(monkeypatch, [_cut(), _ok(), _ok()])
    c = _client()
    c.chat(MSGS, role="reason_plan_question")
    monkeypatch.setenv("ATLAS_EFFORT_PLAN_QUESTION", "high")
    c.chat(MSGS, role="reason_plan_question")
    assert sent[2].get("reasoning_effort") == "high"


# ── the same failed helper request is not sent again ─────────────────────

@pytest.fixture
def trace(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return log


def test_a_failed_request_is_not_sent_again_and_still_leaves_an_outcome(trace, monkeypatch):
    import tools.reasoning as R
    asked = []

    def _backend(system, user, tool, hypothesis_id="", input_call_ids=None):
        asked.append(user)
        result = {"success": False, "conclusion": "", "directives": {}, "gate": "empty_reason_response",
                  "error": "Model returned empty response: completion budget exhausted by hidden reasoning",
                  "finish_reason": "length", "inputs": {"user_message": user, "system_prompt_kind": tool}}
        R._log_reason(tool, result, input_call_ids=input_call_ids)
        return result
    monkeypatch.setattr(R, "_ask_openai_compat", _backend)
    monkeypatch.setattr(R, "_active_backend", lambda: "openai-compat")
    monkeypatch.setattr(R, "_BACKEND_CONFIG_ERROR", "")
    first = R._ask("sys", "OBSERVATION:\nsvc_kit installed on CORP-WS01", "reason_hypothesize")
    again = R._ask("sys", "OBSERVATION:\nsvc_kit installed on CORP-WS01", "reason_hypothesize")
    assert first["success"] is False and len(asked) == 1
    assert again["success"] is False and again["gate"] == "helper_unavailable"
    assert f"call {first['_atlas_call_id']}" in again["error"]
    outcomes = [e for e in trace._entries if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize"]
    assert [e.get("success") for e in outcomes] == [False, False]
    assert outcomes[-1].get("gate") == "helper_unavailable"
    # A changed request is asked.
    R._ask("sys", "OBSERVATION:\nsvc_kit installed on CORP-WS01 at 2031-01-14 13:02", "reason_hypothesize")
    assert len(asked) == 2


def test_a_transport_failure_without_a_repeat_gate_is_asked_again(trace, monkeypatch):
    import tools.reasoning as R
    asked = []

    def _backend(system, user, tool, hypothesis_id="", input_call_ids=None):
        asked.append(user)
        result = {"success": False, "conclusion": "", "directives": {}, "error": "connection reset",
                  "inputs": {"user_message": user, "system_prompt_kind": tool}}
        R._log_reason(tool, result, input_call_ids=input_call_ids)
        return result
    monkeypatch.setattr(R, "_ask_openai_compat", _backend)
    monkeypatch.setattr(R, "_active_backend", lambda: "openai-compat")
    monkeypatch.setattr(R, "_BACKEND_CONFIG_ERROR", "")
    R._ask("sys", "OBSERVATION:\nx", "reason_hypothesize")
    R._ask("sys", "OBSERVATION:\nx", "reason_hypothesize")
    assert len(asked) == 2


def _backend_of(R, monkeypatch, outcomes):
    """A backend answering each ask with the next outcome, recorded as a run would."""
    asked = []

    def _backend(system, user, tool, hypothesis_id="", input_call_ids=None):
        asked.append(user)
        out = dict(outcomes.pop(0))
        result = {"conclusion": "", "directives": {}, **out,
                  "inputs": {"user_message": user, "system_prompt_kind": tool}}
        R._log_reason(tool, result, input_call_ids=input_call_ids)
        return result
    monkeypatch.setattr(R, "_ask_openai_compat", _backend)
    monkeypatch.setattr(R, "_active_backend", lambda: "openai-compat")
    monkeypatch.setattr(R, "_BACKEND_CONFIG_ERROR", "")
    return asked


def test_an_empty_conclusion_after_a_finished_reply_is_asked_again(trace, monkeypatch):
    """DIRECTIVES only or whitespace: the reply finished, a resend can answer."""
    import tools.reasoning as R
    empty = {"success": False, "gate": "empty_reason_response", "finish_reason": "stop",
             "error": "Model returned no usable conclusion after stripping DIRECTIVES/EVIDENCE_AUDIT blocks"}
    asked = _backend_of(R, monkeypatch, [empty, empty])
    R._ask("sys", "OBSERVATION:\ny", "reason_hypothesize")
    R._ask("sys", "OBSERVATION:\ny", "reason_hypothesize")
    assert len(asked) == 2


def test_a_later_answer_of_the_same_tool_lifts_the_memo(trace, monkeypatch):
    """The backend got faster again: the request that was cut is asked once more."""
    import tools.reasoning as R
    cut = {"success": False, "gate": "reply_length_cut", "finish_reason": "length",
           "error": "the reply ran past the one-answer allowance twice"}
    ok = {"success": True, "conclusion": "VERDICT: SUPPORTED"}
    asked = _backend_of(R, monkeypatch, [cut, ok, ok])
    R._ask("sys", "FINDING:\na", "reason_evaluate_finding")
    R._ask("sys", "FINDING:\nb", "reason_evaluate_finding")
    R._ask("sys", "FINDING:\na", "reason_evaluate_finding")
    assert asked == ["FINDING:\na", "FINDING:\nb", "FINDING:\na"]


def test_the_run_memory_is_cleared_when_a_run_starts():
    from agent.loop import Agent
    from tests.agent.test_loop_reliability import _ScriptedClient, _StubToolbox
    llm._RUN_LEVEL[("case", "p", "m", "reason_plan_question")] = "low"
    llm._RUN_NO_RUNG.add(("case", "p", "m", "reason_hypothesize"))
    Agent(_ScriptedClient([]), _StubToolbox(), case_dir=None, quiet=True)._run_setup("sys", "user")
    assert not llm._RUN_LEVEL and not llm._RUN_NO_RUNG
