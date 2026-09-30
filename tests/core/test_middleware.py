"""Tests for core/middleware.py — narration capture and DAIR gate enforcement."""
import asyncio
import datetime
import re
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from tests.conftest import seed_evidence


def _build_context(tool_name: str, args: dict | None = None):
    """Construct a fake MiddlewareContext that mirrors what fastmcp passes."""
    msg = MagicMock()
    msg.name = tool_name
    msg.arguments = args or {}
    # The middleware does context.copy(message=...) and msg.model_copy(...);
    # make those produce a fresh MagicMock so chains don't blow up.
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = MagicMock(return_value=ctx)
    return ctx


async def _run_middleware(mw, tool_name: str, args: dict | None = None,
                          call_next_return="OK"):
    ctx = _build_context(tool_name, args)
    call_next = AsyncMock(return_value=call_next_return)
    result = await mw.on_call_tool(ctx, call_next)
    return result, call_next


def _dair_gate_case_log(tmp_path, case_id: str):
    """Trace under analysis/ plus a memory stub so evidence-compat allows vol_*.

    Flat tmp_path/trace.json makes case_dir() == tmp_path with present_classes=[],
    and the evidence-compat gate then refuses vol_* before the DAIR gate runs
    (pre-existing fixture gap in upstream DAIR gate tests).

    Also stamps the evidence-inventory latch so these tests isolate DAIR
    behavior (inventory is covered by test_evidence_inventory_gate.py).
    """
    from core.execution_log import ExecutionLog
    from core.evidence_inventory_gate import mark_inventory_complete
    case = tmp_path / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "mem.dmp").write_bytes(b"PAGEDUMP")
    mark_inventory_complete(case, summary={"test_fixture": True})
    log = ExecutionLog()
    log.configure(
        case_id,
        str(case / "analysis" / f"{case_id}_trace.json"),
        save_session=False,
    )
    return log


class TestDairGateMiddleware:
    """dair_required: tools outside the allowlist refused when no recent dair_call."""

    def test_allowlisted_tool_runs_without_dair(self, tmp_path):
        from core.middleware import NarrationMiddleware
        l = _dair_gate_case_log(tmp_path, "MW-001")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.run(
                _run_middleware(mw, "dair_assess")
            )
        # call_next was invoked → tool ran
        assert call_next.await_count == 1
        assert result == "OK"

    def test_cold_start_allows_non_allowlisted_tools(self, tmp_path):
        """Before any dair_call exists, non-allowlisted tools run freely so the
        agent can do the mandatory pre-plan reads."""
        from core.middleware import NarrationMiddleware
        l = _dair_gate_case_log(tmp_path, "MW-002")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.run(
                _run_middleware(mw, "vol_vol_psscan")
            )
        assert call_next.await_count == 1

    def test_non_allowlisted_tool_blocked_after_dair_drops_out(self, tmp_path):
        """Once DAIR has been engaged, falling out of the window blocks tools."""
        from core.middleware import NarrationMiddleware
        from fastmcp.exceptions import ToolError
        l = _dair_gate_case_log(tmp_path, "MW-002b")
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Push the dair_call out of the 20-entry window
        for _ in range(21):
            l.record_agent_message("filler")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="DAIR engaged earlier|no active DAIR|ATLAS_PROTOCOL"):
                asyncio.run(
                    _run_middleware(mw, "vol_vol_psscan")
                )

    def test_non_allowlisted_tool_runs_after_dair(self, tmp_path):
        from core.middleware import NarrationMiddleware
        l = _dair_gate_case_log(tmp_path, "MW-003")
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.run(
                _run_middleware(mw, "vol_vol_psscan")
            )
        assert call_next.await_count == 1

    def test_pre_plan_tools_allowlisted(self):
        """Pre-plan meta reads must be on the DAIR allowlist so they can
        run before the first dair_assess. Forensic parsers (including
        RECmd) are NOT allowlisted — they wait for DAIR + inventory."""
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "ez_ez_recmd_hive" not in DAIR_GATE_ALLOWLIST
        assert "misc_inventory_evidence" in DAIR_GATE_ALLOWLIST
        assert "misc_list_evidence_dir" in DAIR_GATE_ALLOWLIST
        assert "strings_stat_file" in DAIR_GATE_ALLOWLIST

    def test_dair_assess_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "dair_assess" in DAIR_GATE_ALLOWLIST
        assert "dair_dair_assess" in DAIR_GATE_ALLOWLIST

    def test_start_execution_log_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "misc_start_execution_log" in DAIR_GATE_ALLOWLIST

    def test_hash_verify_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "hash_verify_evidence_hash" in DAIR_GATE_ALLOWLIST

    def test_vmdk_chain_info_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "img_vmdk_chain_info" in DAIR_GATE_ALLOWLIST

    def test_reason_plan_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "reason_plan" in DAIR_GATE_ALLOWLIST

    def test_projected_report_allowlisted(self):
        """Close-out writer must not be DAIR-deferred."""
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "misc_write_projected_final_report" in DAIR_GATE_ALLOWLIST
        assert "misc_write_final_report" in DAIR_GATE_ALLOWLIST


class TestAppLevelFailureBaseline:
    """The success-baseline trace entry must reflect app-level refusals
    returned in the tool payload: a gate-refused write_final_report must
    not be logged success:true."""

    def _run(self, tmp_path, case_id, ret):
        from core.execution_log import ExecutionLog
        from core.evidence_inventory_gate import mark_inventory_complete
        from core.middleware import NarrationMiddleware
        mark_inventory_complete(tmp_path, summary={"test_fixture": True})
        l = ExecutionLog()
        l.configure(case_id, str(tmp_path / "trace.json"), save_session=False)
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, _ = asyncio.new_event_loop().run_until_complete(
                _run_middleware(mw, "misc_write_final_report",
                                call_next_return=ret))
        return result, l._entries[-1]

    def test_refusal_dict_logged_as_failure(self, tmp_path):
        refusal = {"success": False,
                   "error": "refused: no reason.pre_report_check call found",
                   "gate": "pre_report_check_required"}
        result, entry = self._run(tmp_path, "MW-BASE1", refusal)
        assert result == refusal
        assert entry["type"] == "tool_call"
        assert entry["cmd"] == "<py>:misc_write_final_report"
        assert entry["success"] is False
        assert "pre_report_check_required" in entry["stderr"]
        assert entry["failure_class"] == "gate_refusal"

    def test_non_gate_failure_classified_as_tool_error(self, tmp_path):
        failure = {"success": False, "error": "hive is corrupt"}
        _, entry = self._run(tmp_path, "MW-BASE1b", failure)
        assert entry["success"] is False
        assert entry["failure_class"] == "tool_error"

    def test_success_dict_still_logged_as_success(self, tmp_path):
        ok = {"success": True, "path": "reports/x.md"}
        result, entry = self._run(tmp_path, "MW-BASE2", ok)
        assert result == ok
        assert entry["success"] is True
        assert "failure_class" not in entry

    def test_non_dict_result_logged_as_success(self, tmp_path):
        _, entry = self._run(tmp_path, "MW-BASE3", "plain text")
        assert entry["success"] is True


class TestValidationErrorEnvelope:
    """Mistyped MCP tool arguments must come back as a structured envelope
    naming the offending fields, not as an unhandled pydantic traceback
    that crashes the call."""

    @staticmethod
    def _pydantic_error():
        import pydantic

        class Args(pydantic.BaseModel):
            trigger: str
            linked_call_id: int

        try:
            Args(trigger="t", linked_call_id="not-an-int")
        except pydantic.ValidationError as e:
            return e
        raise AssertionError("expected a ValidationError")

    def _run_with_error(self, tmp_path, case_id, exc):
        from fastmcp.exceptions import ToolError
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        l = ExecutionLog()
        l.configure(case_id, str(tmp_path / "trace.json"))
        mw = NarrationMiddleware()
        ctx = _build_context("misc_record_self_correction", {"trigger": "t"})

        async def raise_validation(_ctx):
            raise exc

        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError) as ei:
                asyncio.run(mw.on_call_tool(ctx, raise_validation))
        return str(ei.value), l._entries[-1]

    def test_envelope_names_field_expected_type_and_value(self, tmp_path):
        msg, _ = self._run_with_error(tmp_path, "MW-VAL1",
                                      self._pydantic_error())
        assert "misc_record_self_correction" in msg
        assert "linked_call_id" in msg          # offending field
        assert "integer" in msg                 # expected type
        assert "not-an-int" in msg              # received value
        assert "Traceback" not in msg

    def test_trace_entry_is_classified_analyst_error(self, tmp_path):
        _, entry = self._run_with_error(tmp_path, "MW-VAL2",
                                        self._pydantic_error())
        assert entry["type"] == "tool_call"
        assert entry["success"] is False
        assert entry["failure_class"] == "analyst_error"
        assert "linked_call_id" in entry["stderr"]
        assert "Traceback" not in entry["stderr"]

    def test_fastmcp_validation_error_also_wrapped(self, tmp_path):
        from fastmcp.exceptions import ValidationError as FMValidationError
        msg, entry = self._run_with_error(
            tmp_path, "MW-VAL3", FMValidationError("arguments rejected"))
        assert "invalid arguments" in msg
        assert "arguments rejected" in msg
        assert entry["failure_class"] == "analyst_error"

    @pytest.mark.asyncio
    async def test_mistyped_call_to_real_tool_returns_clean_envelope(
            self, tmp_path):
        """End-to-end through fastmcp's own argument validation: in-memory
        client → mounted real tool → middleware. Uses
        misc_record_self_correction, whose linked_call_id is an integer."""
        from fastmcp import FastMCP, Client
        from fastmcp.exceptions import ToolError
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        from tools.misc import mcp as misc_mcp

        srv = FastMCP("envelope-test")
        srv.add_middleware(NarrationMiddleware())
        srv.mount(misc_mcp, namespace="misc")

        l = ExecutionLog()
        l.configure("MW-VAL4", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            async with Client(srv) as client:
                with pytest.raises(ToolError) as ei:
                    await client.call_tool("misc_record_self_correction", {
                        "trigger": "hash mismatch",
                        "prior_belief": "image intact",
                        "new_belief": "image modified",
                        "linked_call_id": "not-an-int",
                    })
        msg = str(ei.value)
        assert "linked_call_id" in msg
        assert "not-an-int" in msg
        assert "Traceback" not in msg
        entry = l._entries[-1]
        assert entry["type"] == "tool_call"
        assert entry["cmd"] == "<py>:misc_record_self_correction"
        assert entry["success"] is False
        assert entry["failure_class"] == "analyst_error"


class TestUtcTimestamps:
    """Execution log timestamps are always UTC (ISO 8601 with +00:00 suffix)."""

    def test_utcnow_helper_returns_utc(self):
        from core.execution_log import _utcnow
        ts = _utcnow()
        # ISO 8601 ending with +00:00 (timezone-aware UTC).
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$", ts)

    def test_tool_call_entry_has_utc_timestamp(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("UTC-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        ts = l._entries[-1]["ts"]
        assert ts.endswith("+00:00")
        # Round-trip parses as a UTC datetime
        parsed = datetime.datetime.fromisoformat(ts)
        assert parsed.utcoffset() == datetime.timedelta(0)

    def test_no_naive_datetime_usage_in_core(self):
        """Lint-style: core/ modules must not call datetime.now() without tz."""
        import pathlib
        offenders = []
        core_dir = pathlib.Path(__file__).parent.parent.parent / "core"
        for py in core_dir.glob("*.py"):
            text = py.read_text()
            # Allow datetime.now(timezone...) but flag bare datetime.now() or
            # datetime.datetime.now() with no argument.
            if re.search(r"datetime\.now\(\s*\)", text):
                offenders.append(str(py))
            if re.search(r"datetime\.datetime\.now\(\s*\)", text):
                offenders.append(str(py))
        assert offenders == [], f"naive datetime.now() in: {offenders}"


class TestForensicBinaryPatterns:
    """Constants used by record_finding's mcp_routing gate."""

    def test_constants_exported(self):
        from core.middleware import FORENSIC_BINARY_PATTERNS, MCP_WRAPPER_HINTS
        assert isinstance(FORENSIC_BINARY_PATTERNS, tuple)
        assert len(FORENSIC_BINARY_PATTERNS) > 5
        assert isinstance(MCP_WRAPPER_HINTS, dict)
        for key, hint in MCP_WRAPPER_HINTS.items():
            assert isinstance(hint, str) and hint, key

    def test_identify_forensic_binary_vol(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary(
            "/usr/local/bin/vol -f mem.img windows.psscan"
        ) == "vol"

    def test_identify_forensic_binary_eztool(self):
        from core.middleware import _identify_forensic_binary
        out = _identify_forensic_binary(
            "dotnet /opt/zimmermantools/EvtxECmd/EvtxECmd.dll -f sec.evtx"
        )
        assert out == "EvtxECmd"

    def test_identify_forensic_binary_tcpdump(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("tcpdump -nn -r capture.pcap") == "tcpdump"

    def test_identify_forensic_binary_returns_none_for_safe_cmd(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("ls /cases/example-case/analysis") is None
        assert _identify_forensic_binary("jq '.entries[0]' trace.json") is None

    def test_identify_forensic_binary_word_boundary(self):
        # Regression: word boundaries prevent matching inside unrelated tokens.
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("evolve --options") is None
        assert _identify_forensic_binary("./icatcher --help") is None
        assert _identify_forensic_binary("./tsk_recover -h") == "tsk_recover"


class TestCasePathResolution:
    """Relative mount_point/output_dir/output_path args must resolve against
    the active case directory, never the MCP server's CWD (the repo root):
    resolved against the CWD, final reports land in <repo>/reports/ and
    mounts are created under <repo>/mnt/."""

    @staticmethod
    def _ctx(tool_name: str, args: dict):
        """Context whose model_copy honors the arguments update, so tests can
        observe the rewritten args that the tool body would receive."""
        def _make(name, arguments):
            msg = MagicMock()
            msg.name = name
            msg.arguments = arguments
            msg.model_copy = lambda update=None: _make(
                name, (update or {}).get("arguments", arguments))
            return msg
        ctx = MagicMock()
        ctx.message = _make(tool_name, args)
        ctx.copy = lambda **kw: MagicMock(message=kw.get("message", ctx.message))
        return ctx

    def _case_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        from core.evidence_inventory_gate import mark_inventory_complete
        case = tmp_path / "cases" / "estate-a"
        (case / "analysis").mkdir(parents=True)
        # Stub disk evidence so evidence-compat allows ewf_* path-resolution tests
        (case / "evidence").mkdir(exist_ok=True)
        (case / "evidence" / "disk.E01").write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
        mark_inventory_complete(case, summary={"test_fixture": True})
        l = ExecutionLog()
        l.configure("ESTATE-A",
                    str(case / "analysis" / "ESTATE-A_trace.json"),
                    save_session=False)
        # Path-resolution tests use ewf_mount_*; disk_open_policy demotes
        # loop/FUSE in Triage / empty phase — orient as Collect.
        l._current_phase = "Collect"
        return l, str(case)

    async def _call(self, mw, ctx):
        captured = {}

        async def capture(inner_ctx):
            captured["args"] = inner_ctx.message.arguments
            return {"success": True}

        await mw.on_call_tool(ctx, capture)
        return captured["args"]

    def test_relative_mount_point_resolved_against_case_dir(self, tmp_path):
        import os
        from core.middleware import NarrationMiddleware
        l, case = self._case_log(tmp_path)
        # ewf_mount_ntfs requires disk evidence, and the evidence-compat gate
        # runs before the case-path rewrite under test here.
        seed_evidence(case, "disk")
        ctx = self._ctx("ewf_mount_ntfs", {
            "ewf_device": "/dev/loop0",
            "mount_point": "mnt/host01",
            "offset_bytes": 1048576,
        })
        with patch("core.execution_log.log", l):
            args = asyncio.run(self._call(NarrationMiddleware(), ctx))
        assert args["mount_point"] == os.path.join(case, "mnt/host01")
        assert args["ewf_device"] == "/dev/loop0"  # non-case params untouched

    def test_relative_report_path_resolved_against_case_dir(self, tmp_path):
        import os
        from core.middleware import NarrationMiddleware
        l, case = self._case_log(tmp_path)
        ctx = self._ctx("misc_write_final_report", {
            "output_path": "reports/ESTATE-A_estate_report.md",
            "content": "# report",
        })
        with patch("core.execution_log.log", l):
            args = asyncio.run(self._call(NarrationMiddleware(), ctx))
        assert args["output_path"] == os.path.join(
            case, "reports/ESTATE-A_estate_report.md")

    def test_absolute_paths_pass_through_unchanged(self, tmp_path):
        from core.middleware import NarrationMiddleware
        l, case = self._case_log(tmp_path)
        wanted = str(tmp_path / "elsewhere" / "out.md")
        ctx = self._ctx("misc_write_final_report",
                        {"output_path": wanted, "content": "x"})
        with patch("core.execution_log.log", l):
            args = asyncio.run(self._call(NarrationMiddleware(), ctx))
        assert args["output_path"] == wanted

    def test_relative_path_without_active_case_refused_loudly(self):
        from fastmcp.exceptions import ToolError
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        unconfigured = ExecutionLog()
        ctx = self._ctx("ez_ez_mftecmd", {
            "mft_path": "/somewhere/$MFT",
            "output_dir": "exports/host01",
        })
        with patch("core.execution_log.log", unconfigured):
            with pytest.raises(ToolError, match="start_execution_log"):
                asyncio.run(self._call(NarrationMiddleware(), ctx))

    def test_start_execution_log_resolves_against_its_case_dir_arg(
            self, tmp_path):
        import os
        from core.middleware import NarrationMiddleware
        case = str(tmp_path / "cases" / "estate-a")
        os.makedirs(os.path.join(case, "analysis"))
        ctx = self._ctx("misc_start_execution_log", {
            "case_id": "ESTATE-A",
            "output_path": "analysis/ESTATE-A_trace.json",
            "case_dir": case,
        })
        args = asyncio.run(self._call(NarrationMiddleware(), ctx))
        assert args["output_path"] == os.path.join(
            case, "analysis/ESTATE-A_trace.json")

    def test_start_execution_log_relative_without_case_dir_refused(
            self, tmp_path, monkeypatch):
        """Relative output_path without case_dir is refused when CWD is not a case."""
        from fastmcp.exceptions import ToolError
        from core.middleware import NarrationMiddleware
        monkeypatch.chdir(tmp_path)  # not a case (no .atlas / CASE.md)
        ctx = self._ctx("misc_start_execution_log", {
            "case_id": "ESTATE-A",
            "output_path": "analysis/ESTATE-A_trace.json",
        })
        with pytest.raises(ToolError, match="case_dir"):
            asyncio.run(self._call(NarrationMiddleware(), ctx))

    def test_start_execution_log_relative_resolves_when_cwd_is_case(
            self, tmp_path, monkeypatch):
        """When atlas has chdir'd into the case, relative analysis/ paths resolve."""
        import os
        from core.middleware import NarrationMiddleware
        case = tmp_path / "CASE-A"
        (case / ".atlas").mkdir(parents=True)
        (case / "analysis").mkdir()
        (case / "CASE.md").write_text("# Case\n")
        monkeypatch.chdir(case)
        ctx = self._ctx("misc_start_execution_log", {
            "case_id": "CASE-A",
            "output_path": "analysis/CASE-A_trace.json",
        })
        args = asyncio.run(self._call(NarrationMiddleware(), ctx))
        assert args["output_path"] == os.path.join(
            str(case), "analysis/CASE-A_trace.json")

    def test_refusal_traced_as_call_abandoned(self, tmp_path, monkeypatch):
        """A case-path refusal is best-effort recorded as call_abandoned when
        the log can accept writes (here: a configured log refusing a relative
        start_execution_log output_path with no case_dir argument)."""
        from fastmcp.exceptions import ToolError
        from core.middleware import NarrationMiddleware
        l, case = self._case_log(tmp_path)
        monkeypatch.chdir(tmp_path)  # not the case dir
        ctx = self._ctx("misc_start_execution_log", {
            "case_id": "X",
            "output_path": "analysis/X_trace.json",
        })
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError):
                asyncio.run(self._call(NarrationMiddleware(), ctx))
        abandoned = [e for e in l._entries if e.get("type") == "call_abandoned"]
        assert abandoned and "case-path gate" in abandoned[-1]["reason"]
