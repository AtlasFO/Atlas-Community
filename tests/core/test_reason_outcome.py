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
