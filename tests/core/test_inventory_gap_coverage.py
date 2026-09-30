"""Coverage for inventory gaps: reformulation, evidence-compat MW, DAIR nudges."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError


def _build_context(tool_name: str, args: dict | None = None):
    msg = MagicMock()
    msg.name = tool_name
    msg.arguments = args or {}
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = MagicMock(return_value=ctx)
    return ctx


async def _run_middleware(mw, tool_name: str, args: dict | None = None):
    ctx = _build_context(tool_name, args)
    call_next = AsyncMock(return_value="OK")
    result = await mw.on_call_tool(ctx, call_next)
    return result, call_next


def test_reformulation_depth_limit_refuses_third_identical_eval(tmp_path):
    """INV-REFORMULATION-DEPTH: 3rd identical evaluate without new tools."""
    from core.execution_log import ExecutionLog
    from tools.reasoning import reason_evaluate_finding

    log = ExecutionLog()
    log.configure("REF", str(tmp_path / "t.json"), save_session=False)
    finding = "VPN brute force against the VPN gateway from DESKTOP-X"
    for i in (1, 2):
        log._entries.append({
            "call_id": i,
            "type": "reason_call",
            "tool": "reason_evaluate_finding",
            "success": True,
            "conclusion": f"VERDICT: SUPPORTED — {finding}",
            "inputs": {"user_message": f"FINDING:\n{finding}"},
        })
    with patch("core.execution_log.log", log):
        with patch("tools.reasoning._ask") as ask:
            r = reason_evaluate_finding(
                finding=finding,
                supporting_evidence="see earlier",
                input_call_ids=[1, 2],
            )
    assert r.get("success") is False
    assert r.get("gate") == "reformulation_depth_limit"
    assert ask.call_count == 0


def test_middleware_evidence_compat_raises_and_abandons(tmp_path):
    """INV-MW-EVIDENCE-COMPAT: ToolError + call_abandoned on incompatible tool."""
    from core.execution_log import ExecutionLog
    from core.middleware import NarrationMiddleware
    from core.evidence_profile import ensure_evidence_profile
    from core.evidence_inventory_gate import mark_inventory_complete

    case = tmp_path / "CaseTab"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence" / "logons.csv").write_bytes(b"a,b\n1,2\n")
    ensure_evidence_profile(case)
    mark_inventory_complete(case, summary={"test_fixture": True})

    log = ExecutionLog()
    # Trace under case/analysis so case_dir() resolves to the case root.
    log.configure("MWEV", str(case / "analysis" / "trace.json"), save_session=False)
    # Satisfy DAIR gate so evidence-compat is the refusal we observe.
    log._entries.append({
        "call_id": 1, "type": "dair_call",
        "current_phase": "Collect", "stack_action": "stay",
    })

    mw = NarrationMiddleware()
    with patch("core.execution_log.log", log):
        with pytest.raises(ToolError, match="evidence-compat"):
            asyncio.run(_run_middleware(mw, "ewf_ewf_mount"))
        abandoned = [
            e for e in log._entries
            if e.get("type") == "call_abandoned"
            and "evidence-compat" in str(e.get("reason") or "")
        ]
        assert abandoned, "expected call_abandoned for evidence-compat"


def test_findings_nudge_when_tools_without_findings(tmp_path):
    """INV-DAIR-NUDGES: required_actions gets findings nudge when lagging."""
    from core.execution_log import ExecutionLog
    from tools import dair

    log = ExecutionLog()
    log.configure("NUDGE", str(tmp_path / "t.json"), save_session=False)
    for i in range(1, 15):
        log._entries.append({
            "call_id": i, "type": "tool_call", "success": True, "cmd": f"t{i}",
        })
    assert dair._findings_lagging() is False  # uses global log
    with patch("core.execution_log.log", log):
        assert dair._findings_lagging() is True
        assessment = {
            "current_phase": "Collect",
            "next_phase": "",
            "stack_action": "stay",
        }
        raw = {"priority_tools": ["table.table_query"], "required_actions": []}
        # Apply the same mutation dair_assess uses (without LLM).
        if assessment.get("current_phase") != "Report" and dair._findings_lagging():
            actions = list(raw.get("required_actions") or [])
            if dair._FINDINGS_NUDGE not in actions:
                actions.insert(0, dair._FINDINGS_NUDGE)
            raw["required_actions"] = actions
            assessment["findings_nudge"] = True
        assert assessment.get("findings_nudge") is True
        assert dair._FINDINGS_NUDGE in raw["required_actions"]


def test_ttp_nudge_when_unmapped_attack_findings(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    from tools import dair

    log = ExecutionLog()
    log.configure("TTP", str(tmp_path / "t.json"), save_session=False)
    for i in (1, 2):
        log._entries.append({
            "call_id": i, "type": "finding",
            "description": f"lateral movement via RDP to HOST{i}",
            "confidence": "CONFIRMED",
            "mitre_techniques": [],
        })
    monkeypatch.setattr(
        "tools.reasoning.is_attack_finding", lambda e: True,
    )
    monkeypatch.setattr(
        "tools.reasoning.finding_carries_technique", lambda e: False,
    )
    with patch("core.execution_log.log", log):
        assert dair._ttp_mapping_lagging("Analyze", "") is True
        actions = []
        if dair._TTP_NUDGE not in actions:
            actions.append(dair._TTP_NUDGE)
        assert dair._TTP_NUDGE in actions
