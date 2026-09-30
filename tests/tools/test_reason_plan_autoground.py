"""Plan grounding: an empty evidence_available defaults from the inventory."""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_default_evidence_available_from_inventory():
    from tools.reasoning import _default_evidence_available

    entries = [
        {
            "type": "tool_call",
            "success": True,
            "call_id": 3,
            "cmd": "<py>:misc_inventory_evidence",
            "stdout_excerpt": "20 CSV files, 1 VMDK",
        }
    ]
    elog = MagicMock()
    elog._entries = entries
    elog.case_dir.return_value = None
    with patch("core.execution_log.log", elog):
        text, cids, src = _default_evidence_available()
    assert "20 CSV" in text
    assert cids == [3]
    assert "inventory" in src


def test_reason_plan_empty_arg_autogrounds_without_analyst_error():
    from tools.reasoning import reason_plan

    entries = [{
        "type": "tool_call",
        "success": True,
        "call_id": 3,
        "cmd": "<py>:misc_inventory_evidence",
        "stdout_excerpt": "evidence inventory ok",
    }]
    elog = MagicMock()
    elog._entries = entries
    elog.case_dir.return_value = None

    with patch("core.execution_log.log", elog), \
         patch("tools.reasoning._ask",
               return_value={"success": True, "conclusion": "plan"}) as ask:
        r = getattr(reason_plan, "fn", reason_plan)(
            "Investigate user01", evidence_available=None,
        )
    assert r["success"] is True
    assert r.get("evidence_available_grounded_from")
    user = ask.call_args[0][1]
    assert "evidence inventory ok" in user


def test_reason_plan_refuses_when_no_inventory():
    from tools.reasoning import reason_plan

    elog = MagicMock()
    elog._entries = []
    elog.case_dir.return_value = None
    with patch("core.execution_log.log", elog):
        r = getattr(reason_plan, "fn", reason_plan)(
            "Investigate", evidence_available="",
        )
    assert r["success"] is False
    assert r.get("gate") == "evidence_available_required"
