"""Workflow regression tests: a run that burns its turns on gate rituals
while most coverage-ledger units stay unseen. Root causes covered:

1. pre_report_check never mentioned the coverage ledger → agent did tool
   sweeps instead of probing real evidence. Ledger gaps now lead the
   blocking issues.
2. reason.synthesize was Report-exclusive while pre_report_check demanded a
   fresh synthesize → structural refuse loop. Synthesize now runs from
   Analyze onward; the refuse latch forces Analyze, not Report.
3. Identical input_scale directory refusals repeated with no
   escalation. Repeats now name concrete files inside the error text.
4. batch_run executed MCP tool names as shell commands (gate bypass).
5. coverage.mark_blocked on a directory prefix returned an unhelpful
   error; now explains per-unit semantics and lists contained units.
6. dair_call trace entries did not persist which valve enforced the
   work order — made valve-forced transitions indistinguishable.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


# ── 1. pre_report_check: ledger gaps lead the blockers ───────────────────

class TestPreReportLedgerBlocker:
    def _base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        inst = ExecutionLog()
        inst.configure("PRC-LED", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_reason_call("reason_plan", True, "ok", {})
        inst.record_reason_call("reason_hypothesize", True, "ok", {})
        inst.record_reason_call("reason_synthesize", True, "ok", {})
        return inst

    def test_open_units_block_report(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        inst = self._base_log(tmp_path)
        gaps = ["evidence/vpn_auth.csv", "evidence/vpn_logons.csv"]
        with patch("core.execution_log.log", inst), \
             patch.object(inst, "case_dir", return_value=str(tmp_path)), \
             patch("core.coverage_ledger.ready_for_degraded_exit",
                   return_value=False), \
             patch("core.coverage_ledger.open_unit_paths",
                   return_value=gaps):
            r = reason_pre_report_check()
        hits = [i for i in r["blocking_issues"]
                if "Coverage ledger" in i and "vpn_auth.csv" in i]
        assert hits, r["blocking_issues"]
        # It must point at the cheap resolution paths, not tool sweeps.
        assert "table.table_query" in hits[0]
        assert "coverage.mark_blocked" in hits[0]

    def test_ready_ledger_adds_no_blocker(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        inst = self._base_log(tmp_path)
        with patch("core.execution_log.log", inst), \
             patch.object(inst, "case_dir", return_value=str(tmp_path)), \
             patch("core.coverage_ledger.ready_for_degraded_exit",
                   return_value=True):
            r = reason_pre_report_check()
        assert not any("Coverage ledger" in i for i in r["blocking_issues"])


# ── 2. synthesize callable from Analyze onward ────────────────────────────

class TestSynthesizePhaseWindow:
    def _log_in_phase(self, tmp_path, phase):
        from core.execution_log import ExecutionLog
        inst = ExecutionLog()
        inst.configure("SYN-PH", str(tmp_path / "trace.json"))
        inst.record_dair_call(phase, "", False, "", "", "stay", "")
        return inst

    @pytest.mark.parametrize("phase", ["Analyze", "Scan", "Report"])
    def test_allowed_phases_reach_backend(self, tmp_path, phase):
        from tools import reasoning as rs
        inst = self._log_in_phase(tmp_path, phase)
        with patch("core.execution_log.log", inst), \
             patch.object(rs, "_ask", return_value={"success": True,
                                                    "conclusion": "ok"}) as ask:
            r = rs.reason_synthesize("findings blob")
        assert r.get("success") is True
        assert ask.called

    @pytest.mark.parametrize("phase", ["Triage", "Collect"])
    def test_early_phases_still_refuse(self, tmp_path, phase):
        from tools import reasoning as rs
        inst = self._log_in_phase(tmp_path, phase)
        with patch("core.execution_log.log", inst), \
             patch("core.investigation_exit.refuse_latch_tripped",
                   return_value=False):
            r = rs.reason_synthesize("findings blob")
        assert r.get("success") is False
        assert r.get("gate") == "wrong_phase"
        assert r.get("required_phase") == "Analyze"

    def test_refusal_records_analyze_latch(self, tmp_path):
        """The latch needle must match what dair's valve checks."""
        from tools import reasoning as rs
        from core import investigation_exit as ie
        inst = self._log_in_phase(tmp_path, "Collect")
        with patch("core.execution_log.log", inst), \
             patch("core.investigation_exit.refuse_latch_tripped",
                   return_value=False):
            for _ in range(3):
                rs.reason_synthesize("findings blob")
        with patch("core.execution_log.log", inst):
            assert ie.refuse_latch_tripped(required_phase="Analyze")


# ── 3. input_scale repeat escalation ─────────────────────────────────────

class TestInputScaleRepeatEscalation:
    def _evtx_dir(self, tmp_path):
        d = tmp_path / "logs"
        d.mkdir()
        for i in range(12):
            (d / f"log{i}.evtx").write_bytes(b"ElfFile\x00" + bytes(64))
        return d

    def test_first_refusal_names_files(self, tmp_path):
        from core import input_scale
        d = self._evtx_dir(tmp_path)
        r = input_scale.check("ez_ez_evtxecmd", {"evtx_path": str(d)})
        assert r and r["gate"] == "input_scale"
        assert "REPEATED" not in r["error"]
        # Concrete candidate files are inside the error text itself.
        assert ".evtx" in r["error"]

    def test_repeat_escalates_with_paths_in_error(self, tmp_path):
        from core import input_scale
        from core.execution_log import ExecutionLog
        d = self._evtx_dir(tmp_path)
        inst = ExecutionLog()
        inst.configure("SCALE-R", str(tmp_path / "trace.json"))
        inst.record_call_abandoned(
            "ez_ez_evtxecmd",
            f"input_scale: ez_ez_evtxecmd refused: directory '{d}' has "
            f"12 files; context budget",
        )
        with patch("core.execution_log.log", inst):
            r = input_scale.check("ez_ez_evtxecmd", {"evtx_path": str(d)})
        assert r and r["gate"] == "input_scale"
        assert r["error"].startswith("REPEATED REFUSAL (#2)")
        assert "STOP passing this directory" in r["error"]
        assert ".evtx" in r["error"]


# ── 4. batch_run refuses MCP tool names ──────────────────────────────────

class TestBatchRunMcpNames:
    def test_dotted_mcp_name_refused(self):
        from tools.misc import batch_run
        out = batch_run([{"cmd": ["vol.pslist", "-f", "img.vmdk"]}])
        res = out["results"][0]
        assert res["success"] is False
        assert res.get("gate") == "mcp_name_in_batch"
        assert "MCP tool name" in res["error"]

    def test_force_does_not_override(self):
        from tools.misc import batch_run
        out = batch_run(
            [{"cmd": ["vol.psscan", "-f", "img.vmdk"], "force": True}])
        res = out["results"][0]
        assert res.get("gate") == "mcp_name_in_batch"

    def test_plain_binary_not_caught_by_name_gate(self):
        from tools.misc import batch_run
        out = batch_run([{"cmd": ["true"]}])
        res = out["results"][0]
        assert res.get("gate") != "mcp_name_in_batch"

    def test_shell_pipeline_refused(self):
        from tools.misc import batch_run
        out = batch_run([{"cmd": ["cat", "a.log", "|", "grep", "foo"]}])
        res = out["results"][0]
        assert res["success"] is False
        assert res.get("gate") == "shell_pipeline_unsupported"

    def test_sh_c_pipeline_refused(self):
        from tools.misc import batch_run
        out = batch_run([{"cmd": ["sh", "-c", "cat a.log | grep foo"]}])
        res = out["results"][0]
        assert res.get("gate") == "shell_pipeline_unsupported"


# ── 5. mark_blocked directory-prefix semantics ───────────────────────────

class TestMarkBlockedDirPrefix:
    def _case_with_ledger(self, tmp_path):
        case = tmp_path / "Case"
        (case / ".atlas").mkdir(parents=True)
        ledger = {
            "schema_version": "1.0",
            "units": {
                "u1": {"path": "evidence/tree/a.csv", "status": "unseen",
                       "kind": "tabular", "high_value": True},
                "u2": {"path": "evidence/tree/b.csv", "status": "unseen",
                       "kind": "tabular", "high_value": True},
                "u3": {"path": "evidence/other.csv", "status": "unseen",
                       "kind": "tabular", "high_value": True},
            },
        }
        (case / ".atlas" / "coverage_ledger.json").write_text(
            json.dumps(ledger), encoding="utf-8")
        return case

    def test_directory_prefix_lists_contained_units(self, tmp_path):
        from core.coverage_ledger import mark_unit_blocked
        case = self._case_with_ledger(tmp_path)
        r = mark_unit_blocked(
            case, "evidence/tree",
            reason="vol.pslist unavailable in environment")
        assert r["success"] is False
        assert "directory prefix" in r["error"]
        assert "never a reason to block evidence" in r["error"]
        assert "evidence/tree/a.csv" in r["contained_units"]
        assert "evidence/other.csv" not in r.get("contained_units", [])

    def test_unknown_path_keeps_old_error(self, tmp_path):
        from core.coverage_ledger import mark_unit_blocked
        case = self._case_with_ledger(tmp_path)
        r = mark_unit_blocked(case, "evidence/nope.bin",
                              reason="corrupt file, parser rejects it")
        assert r["success"] is False
        assert "no coverage-ledger unit matches" in r["error"]


# ── 6. dair_call persists work_order_enforced ────────────────────────────

class TestDairEnforcementPersisted:
    def test_field_round_trips(self, tmp_path):
        from core.execution_log import ExecutionLog
        inst = ExecutionLog()
        inst.configure("DAIR-WOE", str(tmp_path / "trace.json"))
        inst.record_dair_call(
            "Collect", "", True, "Analyze", "latch", "push", "focus",
            work_order_enforced="refuse_latch",
        )
        inst.record_dair_call(
            "Analyze", "", False, "", "", "stay", "focus")
        entries = [e for e in inst._entries if e["type"] == "dair_call"]
        assert entries[0].get("work_order_enforced") == "refuse_latch"
        assert "work_order_enforced" not in entries[1]
