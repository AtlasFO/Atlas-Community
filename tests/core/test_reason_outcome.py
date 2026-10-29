"""Usable reason-call contract — shared by gates / finish / pre_report."""
from core.reason_outcome import (
    any_usable_reason_call,
    is_usable_reason_call,
)


def test_success_with_conclusion_is_usable():
    assert is_usable_reason_call({
        "type": "reason_call",
        "success": True,
        "conclusion": "Hypothesis: lateral movement via RDP.",
    })


def test_empty_conclusion_not_usable():
    assert not is_usable_reason_call({
        "type": "reason_call",
        "success": True,
        "conclusion": "",
    })


def test_failed_empty_reason_gate_not_usable():
    assert not is_usable_reason_call({
        "type": "reason_call",
        "success": False,
        "conclusion": "",
        "gate": "empty_reason_response",
        "finish_reason": "length",
        "reasoning_tokens": 4096,
    })


def test_length_starved_stub_not_usable():
    assert not is_usable_reason_call({
        "type": "reason_call",
        "success": True,
        "conclusion": "ok",
        "finish_reason": "length",
        "reasoning_tokens": 8000,
    })


def test_presence_only_failed_call_not_counted():
    entries = [{
        "type": "reason_call",
        "tool": "reason_hypothesize",
        "success": False,
        "conclusion": "",
        "gate": "empty_reason_response",
        "call_id": 1,
    }]
    assert not any_usable_reason_call(entries, "reason_hypothesize")


def _rc(tool, ok):
    return {"type": "reason_call", "tool": tool, "success": ok,
            "conclusion": "A usable synthesis of the findings." if ok else "",
            **({} if ok else {"gate": "empty_reason_response"})}


def test_helper_unavailable_counts_outcomes_since_the_last_usable_one():
    from agent.tool_investigate import IDENTICAL_FAIL_LIMIT
    from core.reason_outcome import helper_unavailable
    t = "reason_synthesize"
    assert helper_unavailable([], t) == 0
    fails = [_rc(t, False)] * IDENTICAL_FAIL_LIMIT
    assert helper_unavailable(fails[:-1], t) == 0
    assert helper_unavailable(fails, t) == IDENTICAL_FAIL_LIMIT
    # A late usable reply clears it; failures before it do not count.
    assert helper_unavailable(fails + [_rc(t, True)], t) == 0
    assert helper_unavailable(fails + [_rc(t, True)] + fails[:-1], t) == 0
    # An attempt still running has no outcome and is no failure; another
    # tool's failures are not this one's.
    running = [{"type": "call_initiated", "tool": t}] * 5
    assert helper_unavailable(fails[:-1] + running, t) == 0
    assert helper_unavailable(fails, "reason_plan") == 0
    # A short-circuit that answers "unavailable" without a model call (a
    # memo of a failed prompt) records an unusable outcome too and counts.
    memo = {"type": "reason_call", "tool": t, "success": False, "conclusion": "",
            "gate": "helper_unavailable_memo"}
    assert helper_unavailable(fails[:-1] + [memo], t) == IDENTICAL_FAIL_LIMIT
