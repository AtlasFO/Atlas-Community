"""Deferred-intent recovery: fingerprint, backlog latch, dispositions."""
from __future__ import annotations

import asyncio
import re
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


async def _run_middleware(mw, tool_name: str, args: dict | None = None,
                          call_next_return="OK"):
    ctx = _build_context(tool_name, args)
    call_next = AsyncMock(return_value=call_next_return)
    return await mw.on_call_tool(ctx, call_next), call_next


class TestDeferredIntentHelpers:
    def test_mcp_to_dotted(self):
        from core.deferred_intents import mcp_tool_to_dotted
        assert mcp_tool_to_dotted("strings_strings_grep") == "strings.grep"
        assert mcp_tool_to_dotted("vol_vol_psscan") == "vol.psscan"
        assert mcp_tool_to_dotted("misc_record_finding") == "misc.record_finding"

    def test_fingerprint_stable(self):
        from core.deferred_intents import args_fingerprint
        a = args_fingerprint("strings_strings_grep",
                             {"path": "/a", "pattern": "foo", "x": 1})
        b = args_fingerprint("strings_strings_grep",
                             {"pattern": "foo", "path": "/a", "x": 2})
        assert a == b  # non-fingerprint keys ignored when known keys present

    def test_fingerprint_ignores_path_spelling(self, tmp_path):
        from core.deferred_intents import args_fingerprint
        (tmp_path / "evidence").mkdir()
        (tmp_path / "evidence" / "a.log").write_text("x")
        rel = args_fingerprint("strings_strings_grep",
                               {"path": "evidence/a.log", "pattern": "foo"},
                               case_dir=str(tmp_path))
        absolute = args_fingerprint("strings_strings_grep",
                                    {"path": str(tmp_path / "evidence" / "a.log"),
                                     "pattern": "foo"},
                                    case_dir=str(tmp_path))
        assert rel == absolute

    def test_protocol_marker_detection(self):
        from core.deferred_intents import PROTOCOL_MARKER, is_protocol_block_message
        assert is_protocol_block_message(f"{PROTOCOL_MARKER} blocked")
        assert is_protocol_block_message("no active DAIR batch here")
        assert not is_protocol_block_message("file not found")


class TestDeferredIntentLog:
    def test_create_refresh_dedup(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("DI-001", str(tmp_path / "trace.json"))
        r1 = l.record_deferred_intent(
            "strings_strings_grep",
            {"path": "/e/a", "pattern": "evil"},
            "DAIR window cold",
        )
        assert r1["action"] == "created"
        r2 = l.record_deferred_intent(
            "strings_strings_grep",
            {"path": "/e/a", "pattern": "evil"},
            "DAIR window cold again",
        )
        assert r2["action"] == "refreshed"
        assert r2["call_id"] == r1["call_id"]
        assert r2["block_count"] == 2
        open_n = sum(
            1 for e in l._entries
            if e.get("type") == "deferred_intent" and e.get("status") == "open")
        assert open_n == 1

    def test_backlog_latch_at_cap(self, tmp_path):
        from core.deferred_intents import DEFERRED_BACKLOG_CAP
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("DI-002", str(tmp_path / "trace.json"))
        for i in range(DEFERRED_BACKLOG_CAP):
            l.record_deferred_intent(
                "strings_strings_grep",
                {"path": f"/e/{i}", "pattern": f"p{i}"},
                "cold",
            )
        st = l.deferred_backlog_status()
        assert st["open"] == DEFERRED_BACKLOG_CAP
        assert st["latched"] is True
        # New unique intent while latched → unqueued, open stays at cap
        r = l.record_deferred_intent(
            "strings_strings_grep",
            {"path": "/e/new", "pattern": "extra"},
            "cold",
        )
        assert r["action"] == "unqueued"
        assert l.deferred_backlog_status()["open"] == DEFERRED_BACKLOG_CAP

    def test_dispositions_promote_and_relieve(self, tmp_path):
        from core.deferred_intents import (
            DEFERRED_BACKLOG_CAP,
            DEFERRED_BACKLOG_HYSTERESIS,
        )
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("DI-003", str(tmp_path / "trace.json"))
        ids = []
        for i in range(DEFERRED_BACKLOG_CAP):
            r = l.record_deferred_intent(
                "table_table_query",
                {"query": f"q{i}"},
                "cold",
            )
            ids.append(r["call_id"])
        # Promote two, dismiss three
        disp = (
            [{"call_id": ids[0], "action": "promote", "note": "still relevant"},
             {"call_id": ids[1], "action": "promote", "note": "yes"}]
            + [{"call_id": ids[i], "action": "dismiss", "note": "nope"}
               for i in range(2, 5)]
        )
        result = l.apply_deferred_dispositions(disp, dair_cid=99)
        assert "table.query" in result["promoted_tools"]
        # Still above hysteresis → relieve
        relieved = l.relieve_deferred_backlog(
            reason="test_pressure")
        assert relieved["open_count"] <= DEFERRED_BACKLOG_HYSTERESIS
        assert l.deferred_backlog_status()["latched"] is False

    def test_resolve_on_match(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("DI-004", str(tmp_path / "trace.json"))
        args = {"path": "/x", "pattern": "y"}
        r = l.record_deferred_intent("strings_strings_grep", args, "cold")
        cid = l.resolve_deferred_intent("strings_strings_grep", args)
        assert cid == r["call_id"]
        entry = next(e for e in l._entries if e.get("call_id") == cid)
        assert entry["status"] == "resolved"


class TestMiddlewareDeferredIntent:
    def _case_log(self, tmp_path, case_id):
        from core.execution_log import ExecutionLog
        from core.evidence_inventory_gate import mark_inventory_complete
        case = tmp_path / case_id
        (case / "analysis").mkdir(parents=True)
        (case / "evidence").mkdir(parents=True)
        (case / "evidence" / "mem.dmp").write_bytes(b"PAGEDUMP")
        mark_inventory_complete(case, summary={"test_fixture": True})
        l = ExecutionLog()
        l.configure(case_id, str(case / "analysis" / "trace.json"),
                    save_session=False)
        return l

    def test_block_records_deferred_intent(self, tmp_path):
        from core.middleware import NarrationMiddleware
        from core.deferred_intents import PROTOCOL_MARKER
        # _case_log stamps the evidence-assessment latch (mark_inventory_complete)
        # so the call reaches the DAIR gate instead of being refused earlier by
        # the newer evidence-assessment gate — which is what this test asserts.
        l = self._case_log(tmp_path, "MW-DI-1")
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(21):
            l.record_agent_message("filler")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match=re.escape(PROTOCOL_MARKER)):
                asyncio.run(_run_middleware(mw, "vol_vol_psscan"))
        intents = [e for e in l._entries if e.get("type") == "deferred_intent"]
        assert len(intents) == 1
        assert intents[0]["status"] == "open"
        assert intents[0]["tool"] == "vol_vol_psscan"

    def test_latch_blocks_even_with_fresh_dair(self, tmp_path):
        from core.deferred_intents import DEFERRED_BACKLOG_CAP, PROTOCOL_MARKER
        from core.middleware import NarrationMiddleware
        l = self._case_log(tmp_path, "MW-DI-2")
        for i in range(DEFERRED_BACKLOG_CAP):
            l.record_deferred_intent(
                "strings_strings_grep",
                {"path": f"/p/{i}", "pattern": str(i)},
                "seed",
            )
        assert l.deferred_backlog_status()["latched"]
        # Fresh dair_call — still blocked by latch
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="deferred backlog full"):
                asyncio.run(_run_middleware(mw, "vol_vol_psscan"))


class TestToolboxProtocolInfo:
    def test_protocol_block_renders_as_tool_info(self):
        from agent.toolbox import Toolbox
        from core.deferred_intents import PROTOCOL_MARKER

        class _R:
            is_error = True
            data = None
            content = [type("B", (), {"text": f"{PROTOCOL_MARKER} blocked"})()]

        out = Toolbox._render(_R())
        assert out.startswith("TOOL INFO:")
        assert PROTOCOL_MARKER in out
