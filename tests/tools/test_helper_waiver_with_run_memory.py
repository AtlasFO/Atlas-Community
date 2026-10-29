"""The run memory of failed helper requests (a failed request is not sent
again unchanged) and the helper waiver at the latch's limit together.

A helper whose request failed is asked once; the identical retries the latch
asks for are answered from the run's memory without a model call and still
leave unusable outcomes, so the report gate sees the helper as unavailable
and records the missing synthesis as a limitation; the latch reads the
memo's answer as a non-blocking helper failure. Invented data only."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.usefixtures("todays_report_check")


@pytest.fixture
def trace(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    log.case_dir = lambda: str(tmp_path)
    log.record_dair_call("Report", "", False, "", "", "stay", "")
    log.record_tool_call("vol.psscan", True, False, 0, 0)
    log.record_reason_call("reason_plan", True, "plan", {})
    log.record_reason_call("reason_hypothesize", True, "hyp", {})
    monkeypatch.setattr("core.execution_log.log", log)
    return log


def _backend_from(R, outcomes, asked):
    """A helper backend that answers with the scripted outcomes in turn:
    "cut" (a reply emptied by a cut), "empty" (a finished reply with no
    usable conclusion) or "ok"."""
    it = iter(outcomes)

    def _backend(system, user, tool, hypothesis_id="", input_call_ids=None):
        asked.append(user)
        kind = next(it)
        result = {"success": kind == "ok", "directives": {}, "inputs": {"user_message": user, "system_prompt_kind": tool},
                  "conclusion": "A usable synthesis of the findings." if kind == "ok" else ""}
        if kind == "cut":
            result.update(gate="empty_reason_response", finish_reason="length",
                          error="Model returned empty response: completion budget exhausted by hidden reasoning")
        elif kind == "length_cut":
            result.update(gate="reply_length_cut", finish_reason="length",
                          error="the reply ran past the one-answer allowance twice; no answer was taken from it")
        elif kind == "empty":
            result.update(gate="empty_reason_response", finish_reason="stop", error="no usable conclusion")
        R._log_reason(tool, result, input_call_ids=input_call_ids)
        return result
    return _backend


@pytest.fixture
def helper(monkeypatch):
    import tools.reasoning as R

    def install(outcomes):
        asked: list[str] = []
        monkeypatch.setattr(R, "_ask_openai_compat", _backend_from(R, outcomes, asked))
        monkeypatch.setattr(R, "_active_backend", lambda: "openai-compat")
        monkeypatch.setattr(R, "_BACKEND_CONFIG_ERROR", "")
        return asked
    return install


USER = "FINDINGS:\n[12] LIKELY: jane.doe ran tool.exe on CORP-WS01"


@pytest.mark.parametrize("cut", ["cut", "length_cut"])
def test_memo_answers_count_toward_the_waiver(trace, helper, cut):
    """A cut request (emptied by a cut, or past the one-answer allowance
    twice) is asked once; the identical retries are answered from the run's
    memory and still count, and the limitation says how many reached the
    model."""
    import tools.reasoning as R
    from agent.tool_investigate import IDENTICAL_FAIL_LIMIT, classify_tool_result
    from core.reason_outcome import helper_unavailable
    asked = helper([cut] * 5)
    answers = [R._ask("sys", USER, "reason_synthesize") for _ in range(IDENTICAL_FAIL_LIMIT)]
    assert len(asked) == 1
    assert answers[-1]["gate"] == "helper_unavailable"
    assert helper_unavailable(trace._entries, "reason_synthesize") == IDENTICAL_FAIL_LIMIT
    issue = classify_tool_result("reason_synthesize", json.dumps(answers[-1]))
    assert issue["kind"] == "helper_unavailable" and issue["blocking_finish"] is False
    with patch("core.execution_log.log", trace):
        verdict = R.reason_pre_report_check()
    assert verdict["ready_to_report"] is True
    assert any(d.startswith("reason.synthesize could not run")
               and f"{IDENTICAL_FAIL_LIMIT} requests in a row (1 sent to the model, the others answered "
                   "from the run's memory of a cut)" in d for d in verdict["documented_limitations"])


def test_finished_empty_replies_are_asked_again_and_count(trace, helper):
    """An empty conclusion after a finished reply is sent again (no memo),
    and each such outcome counts toward the same limit."""
    import tools.reasoning as R
    from agent.tool_investigate import IDENTICAL_FAIL_LIMIT
    from core.reason_outcome import helper_unavailable
    asked = helper(["empty"] * IDENTICAL_FAIL_LIMIT)
    for _ in range(IDENTICAL_FAIL_LIMIT):
        R._ask("sys", USER, "reason_synthesize")
    assert len(asked) == IDENTICAL_FAIL_LIMIT
    assert helper_unavailable(trace._entries, "reason_synthesize") == IDENTICAL_FAIL_LIMIT


def test_an_answer_after_a_cut_clears_the_count(trace, helper):
    """A changed request that answers lifts both the memory and the count."""
    import tools.reasoning as R
    from core.reason_outcome import helper_unavailable
    asked = helper(["cut", "ok", "ok"])
    R._ask("sys", USER, "reason_synthesize")
    R._ask("sys", USER, "reason_synthesize")                        # memo: unusable, not sent
    R._ask("sys", USER + ", [15] LIKELY: a second finding", "reason_synthesize")   # changed: answered
    assert len(asked) == 2
    assert helper_unavailable(trace._entries, "reason_synthesize") == 0
    R._ask("sys", USER, "reason_synthesize")                        # the answer lifted the memo
    assert len(asked) == 3
