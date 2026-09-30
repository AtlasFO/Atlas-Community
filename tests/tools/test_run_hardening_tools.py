"""Run-hardening regression tests for the tools layer.

Covers:
  - _ez missing-input hard refusal (a nonexistent input must not read as a
    successful parse).
  - ez_evtxecmd parse memo (the same log re-parsed for different event_ids).
  - DAIR summary-vs-trace verification + inapplicable-tool filter +
    Report-entry coverage gate.
  - reason.* reviewer memoization (identical reviewer calls served from the
    trace instead of repeated).
  - record_finding host-consistency lint (a finding naming one host while
    citing another host's evidence).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── _ez missing-input gate ───────────────────────────────────────────────────

class TestMissingInputGate:
    def test_nonexistent_f_path_refused_before_spawn(self, tmp_path):
        from tools.eztools import _ez
        out = _ez("/opt/zimmermantools/AmcacheParser.dll",
                  ["-f", str(tmp_path / "nope" / "Amcache.hve"),
                   "--csv", str(tmp_path)],
                  output_dir=str(tmp_path))
        assert out["success"] is False
        assert out.get("gate") == "missing_input"
        assert "list_evidence_dir" in (out.get("hint") or "")

    def test_existing_input_passes_gate(self, tmp_path):
        """With a real input the gate passes; failure then names the DLL."""
        from tools.eztools import _ez
        hive = tmp_path / "Amcache.hve"
        hive.write_bytes(b"regf" + b"\x00" * 16)
        out = _ez(str(tmp_path / "NoSuchTool.dll"),
                  ["-f", str(hive), "--csv", str(tmp_path)],
                  output_dir=str(tmp_path))
        assert out.get("gate") != "missing_input"


# ── ez_evtxecmd parse memo ───────────────────────────────────────────────────

class TestEvtxParseMemo:
    def test_identical_parse_redirected_to_existing_csv(self, tmp_path):
        from tools.eztools import (
            _evtx_parse_memo_lookup, _evtx_parse_memo_record,
        )
        outdir = tmp_path / "out"
        outdir.mkdir()
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile\x00")
        (outdir / "evtx.csv").write_text("EventId\n4624\n")
        _evtx_parse_memo_record(str(outdir), str(evtx), "4624,4625", "evtx.csv")
        hit = _evtx_parse_memo_lookup(str(outdir), str(evtx), "4625,4624")
        assert hit and hit["gate"] == "parse_memo"
        assert hit["existing_csv"].endswith("evtx.csv")
        assert hit["use_instead"] == "table.table_query"

    def test_full_parse_covers_filtered_requests(self, tmp_path):
        from tools.eztools import (
            _evtx_parse_memo_lookup, _evtx_parse_memo_record,
        )
        outdir = tmp_path / "out"
        outdir.mkdir()
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile\x00")
        (outdir / "full.csv").write_text("EventId\n")
        _evtx_parse_memo_record(str(outdir), str(evtx), None, "full.csv")
        hit = _evtx_parse_memo_lookup(str(outdir), str(evtx), "1102")
        assert hit and "unfiltered parse" in hit["error"]

    def test_new_filter_without_full_parse_allowed(self, tmp_path):
        from tools.eztools import (
            _evtx_parse_memo_lookup, _evtx_parse_memo_record,
        )
        outdir = tmp_path / "out"
        outdir.mkdir()
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile\x00")
        (outdir / "a.csv").write_text("x\n")
        _evtx_parse_memo_record(str(outdir), str(evtx), "4624", "a.csv")
        assert _evtx_parse_memo_lookup(str(outdir), str(evtx), "1102") is None

    def test_deleted_csv_reenables_parse(self, tmp_path):
        from tools.eztools import (
            _evtx_parse_memo_lookup, _evtx_parse_memo_record,
        )
        outdir = tmp_path / "out"
        outdir.mkdir()
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile\x00")
        (outdir / "gone.csv").write_text("x\n")
        _evtx_parse_memo_record(str(outdir), str(evtx), None, "gone.csv")
        (outdir / "gone.csv").unlink()
        assert _evtx_parse_memo_lookup(str(outdir), str(evtx), None) is None


# ── DAIR hardening ───────────────────────────────────────────────────────────

def _log_stub(entries, case_dir=None, path=None):
    stub = MagicMock()
    stub._entries = entries
    stub.case_dir.return_value = case_dir
    stub._path = path
    return stub


class TestDairSummaryVerification:
    def test_fabricated_tool_mention_flagged(self):
        from tools.dair import _summary_fabricated_tools
        entries = [
            {"type": "tool_call", "cmd": "<py>:table_table_query"},
            {"type": "reason_call", "tool": "reason_hypothesize"},
        ]
        with patch("core.execution_log.log", _log_stub(entries)):
            fab = _summary_fabricated_tools(
                "vol.totally_fake_plugin output shows multiple processes; "
                "table.table_query confirmed logons; "
                "misc.write_projected_final_report will close out.")
        # Unknown names are fabrications; known-manifest tools (even not yet
        # executed) are plans, not fabrications.
        assert "vol.totally_fake_plugin" in fab
        assert not any(f.startswith("table.") for f in fab)
        assert "misc.write_projected_final_report" not in fab

    def test_known_manifest_tool_not_fabricated_before_execution(self):
        from tools.dair import _summary_fabricated_tools
        with patch("core.execution_log.log", _log_stub([])):
            fab = _summary_fabricated_tools(
                "Next: misc.write_projected_final_report and table.schema")
        assert fab == set()

    def test_executed_alias_not_flagged(self):
        from tools.dair import _summary_fabricated_tools
        entries = [{"type": "tool_call",
                    "cmd": "<py>:ez_ez_evtxecmd(evtx_path=...)"}]
        with patch("core.execution_log.log", _log_stub(entries)):
            fab = _summary_fabricated_tools("ez.evtxecmd extracted 4624s")
        assert fab == set()

    def test_mcp_tool_name_normalization(self):
        from tools.dair import _mcp_tool_name
        assert _mcp_tool_name("ez.evtxecmd") == "ez_ez_evtxecmd"
        assert _mcp_tool_name("vol.vol_pslist") == "vol_vol_pslist"
        assert _mcp_tool_name("plain") == "plain"


class TestDairInapplicableFilter:
    def test_vol_dropped_without_memory(self, tmp_path):
        from tools import dair
        case = tmp_path / "case"
        (case / "evidence").mkdir(parents=True)
        (case / "evidence" / "logons.csv").write_text("u,p\n")
        (case / "analysis").mkdir()
        with patch.object(dair, "_case_root", return_value=str(case)):
            kept, dropped = dair._filter_inapplicable_tools(
                ["vol.vol_pslist", "table.table_query"])
        assert "vol.vol_pslist" in dropped
        assert "table.table_query" in kept


class TestReportEntryCoverageGate:
    def _case_with_ledger(self, tmp_path):
        from core.coverage_ledger import build_coverage_ledger
        case = tmp_path / "case"
        evid = case / "evidence"
        evid.mkdir(parents=True)
        (case / ".atlas").mkdir()
        (case / "analysis").mkdir()
        (evid / "edr_lateral.csv").write_text("a,b\n1,2\n")
        (evid / "vpn_auth.csv").write_text("a,b\n1,2\n")
        build_coverage_ledger(case)
        return case

    def test_defers_then_exhausts(self, tmp_path):
        from tools import dair
        case = self._case_with_ledger(tmp_path)
        dair._report_gate_deferrals = 0
        try:
            with patch.object(dair, "_case_root", return_value=str(case)):
                notes = [dair._report_entry_coverage_gate()[0]
                         for _ in range(4)]
        finally:
            dair._report_gate_deferrals = 0
        assert all("report_entry_coverage" in n for n in notes[:3])
        assert notes[3] == ""  # deferral budget exhausted — never a deadlock

    def test_ledger_ready_passes(self, tmp_path):
        from core.coverage_ledger import load_ledger, mark_paths, save_ledger
        from tools import dair
        case = self._case_with_ledger(tmp_path)
        led = load_ledger(case)
        mark_paths(case, [u["path"] for u in led["units"].values()],
                   status="probed")
        dair._report_gate_deferrals = 0
        try:
            with patch.object(dair, "_case_root", return_value=str(case)):
                note, _tools = dair._report_entry_coverage_gate()
        finally:
            dair._report_gate_deferrals = 0
        assert note == ""


# ── reason memo ──────────────────────────────────────────────────────────────

class TestReasonMemo:
    def test_identical_reviewer_call_served_from_trace(self):
        from tools.reasoning import _ask
        prior = {
            "type": "reason_call",
            "call_id": 41,
            "tool": "reason_confidence_score",
            "success": True,
            "conclusion": "CONFIDENCE_SCORE:\n{\"tier\": \"LIKELY\"}",
            "directives": {},
            "inputs": {"user_message": "FINDING:\nX\n\nSUPPORTING_EVIDENCE:\nY"},
        }
        stub = _log_stub([prior])
        stub.record_reason_call.return_value = 99
        with patch("core.execution_log.log", stub):
            out = _ask("SYS", "FINDING:\nX\n\nSUPPORTING_EVIDENCE:\nY",
                       _tool_name="reason_confidence_score")
        assert out["cached"] is True
        assert out["cached_from_call_id"] == 41
        assert out["conclusion"].startswith("CONFIDENCE_SCORE")
        # Re-recorded so recency-window gates still see a reviewer call.
        assert stub.record_reason_call.called

    def test_planning_tools_never_memoized(self):
        from tools.reasoning import _reason_memo_lookup
        assert _reason_memo_lookup("reason_hypothesize", "anything") is None

    def test_different_input_not_served(self):
        from tools.reasoning import _reason_memo_lookup
        prior = {
            "type": "reason_call", "tool": "reason_evaluate_finding",
            "success": True, "conclusion": "VERDICT: SUPPORTED",
            "inputs": {"user_message": "OLD"},
        }
        with patch("core.execution_log.log", _log_stub([prior])):
            assert _reason_memo_lookup(
                "reason_evaluate_finding", "NEW") is None


# ── host-consistency lint ────────────────────────────────────────────────────

class TestHostConsistencyLint:
    def _ledger(self, case: Path):
        from core.coverage_ledger import load_ledger, save_ledger
        led = load_ledger(case)
        led["units"] = {
            "u1": {"path": "evidence/raw_extract/FILESRV02-flat.vmdk/"
                           "Windows/System32/winevt/logs/Security.evtx",
                   "status": "unseen", "reason": "canonical_evtx"},
            "u2": {"path": "evidence/EDR_filesrv01_filecreate.csv",
                   "status": "unseen", "reason": "case_root_tabular"},
        }
        save_ledger(case, led)

    def test_wrong_host_attribution_warns(self, tmp_path):
        from tools.misc import _host_consistency_warning
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        self._ledger(case)
        entries = [{
            "call_id": 7, "type": "tool_call",
            "cmd": "dotnet EvtxECmd.dll -f evidence/raw_extract/"
                   "FILESRV02-flat.vmdk/Windows/System32/winevt/logs/"
                   "Security.evtx",
            "stdout": "…",
        }]
        log = _log_stub(entries, case_dir=str(case))
        warning = _host_consistency_warning(
            description=("No relevant Security.evtx events for user01 "
                         "on FILESRV01 in the extracted logs"),
            host="",
            supporting_evidence="",
            input_call_ids=[7],
            linked_call_id=0,
            log=log,
        )
        assert "filesrv01" in warning
        assert "filesrv02" in warning

    def test_matching_host_no_warning(self, tmp_path):
        from tools.misc import _host_consistency_warning
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        self._ledger(case)
        entries = [{
            "call_id": 7, "type": "tool_call",
            "cmd": "<py>:table_table_query(path=evidence/"
                   "EDR_filesrv01_filecreate.csv)",
        }]
        log = _log_stub(entries, case_dir=str(case))
        warning = _host_consistency_warning(
            description="File creation on FILESRV01 by user01",
            host="FILESRV01",
            supporting_evidence="",
            input_call_ids=[7],
            linked_call_id=0,
            log=log,
        )
        assert warning == ""

    def test_no_citations_never_warns(self, tmp_path):
        from tools.misc import _host_consistency_warning
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        self._ledger(case)
        log = _log_stub([], case_dir=str(case))
        assert _host_consistency_warning(
            description="Activity on FILESRV01",
            host="", supporting_evidence="",
            input_call_ids=[], linked_call_id=0, log=log,
        ) == ""
