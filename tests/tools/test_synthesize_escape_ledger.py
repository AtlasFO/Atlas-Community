"""Synthesize escape must not unlock on exploration progress_stall alone."""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def _fake_log(entries):
    fake = MagicMock()
    fake._entries = list(entries)
    fake.last_n_window.return_value = list(entries)
    fake.gate_window.return_value = list(entries)
    fake.index.return_value = {
        e.get("call_id"): e for e in entries if e.get("call_id")
    }
    fake.record_call_abandoned = MagicMock(return_value=0)
    return fake


def test_budget_wrapup_without_escape_flag_refuses_synthesize():
    from tools import reasoning as r

    dair = {"type": "dair_call", "current_phase": "Triage", "call_id": 1}
    wrap = {
        "type": "budget_wrapup",
        "trigger": "progress_stall",
        "allow_synthesize_escape": False,
        "call_id": 2,
    }
    fake_log = _fake_log([dair, wrap])

    with patch("core.execution_log.log", fake_log), \
            patch("core.investigation_exit.refuse_latch_tripped",
                  return_value=False), \
            patch("core.investigation_exit.record_wrong_phase_refuse"):
        out = r.reason_synthesize(
            findings="x",
            investigation_summary="",
            input_call_ids=[1],
        )
    assert out.get("success") is False
    assert out.get("gate") == "wrong_phase"


def test_budget_wrapup_with_escape_flag_allows_past_phase_gate():
    from tools import reasoning as r

    dair = {"type": "dair_call", "current_phase": "Triage", "call_id": 1}
    wrap = {
        "type": "budget_wrapup",
        "trigger": "progress_stall",
        "allow_synthesize_escape": True,
        "call_id": 2,
    }
    fake_log = _fake_log([dair, wrap])

    with patch("core.execution_log.log", fake_log), \
            patch("core.investigation_exit.refuse_latch_tripped",
                  return_value=False), \
            patch.object(r, "_ask",
                         return_value={"success": True,
                                       "conclusion": "SYNTH OK"}):
        out = r.reason_synthesize(
            findings="x",
            investigation_summary="",
            input_call_ids=[1],
        )
    assert out.get("gate") != "wrong_phase"
    assert out.get("success") is True
