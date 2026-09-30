"""Agent-facing evidence-coverage-ledger tools.

The ledger gates degraded exit, so the agent needs a verb to mark a unit
blocked and a view of the ledger (coverage.coverage_report is the MITRE/TTP
view, a different concept). These tests pin the contract:

  * coverage.ledger_status shows units, stats, and the unseen gaps;
  * coverage.mark_blocked requires a real prior probe attempt in the trace
    and a concrete reason — blocked counts toward the exit floor, so an
    agent must not be able to talk a unit into "blocked".
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CaseCov"
    logs = (case / "evidence" / "WS01" / "Windows" / "System32"
            / "winevt" / "Logs")
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    (case / "analysis").mkdir()
    (case / ".atlas").mkdir()
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [], "file_count": 0, "counts": {},
            "absent_classes": [], "present_classes": [], "samples": {},
        }),
        encoding="utf-8",
    )
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(case)
    return case


def _log_for(case: Path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("COV-CASE", str(case / "analysis" / "trace.json"),
                save_session=False)
    return l


REL = "evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"


class TestLedgerStatus:
    def test_status_shows_units_and_gaps(self, tmp_path):
        from tools.coverage import ledger_status
        case = _case(tmp_path)
        log = _log_for(case)
        with patch("core.execution_log.log", log):
            r = ledger_status()
        assert r["success"] is True
        assert r["stats"]["total"] >= 1
        assert REL in r["unseen"]
        assert r["ready_for_degraded_exit"] is False
        assert any(u["path"] == REL and u["status"] == "unseen"
                   for u in r["units"])

    def test_status_requires_active_case(self):
        from tools.coverage import ledger_status
        from core.execution_log import ExecutionLog
        with patch("core.execution_log.log", ExecutionLog()):
            r = ledger_status()
        assert r["success"] is False


class TestMarkBlocked:
    def test_refused_without_prior_attempt(self, tmp_path):
        from tools.coverage import mark_blocked
        case = _case(tmp_path)
        log = _log_for(case)
        with patch("core.execution_log.log", log):
            r = mark_blocked(
                path=REL, reason="file looks corrupt to me")
        assert r["success"] is False
        assert "attempt" in r["error"].lower() or "probe" in r["error"].lower()
        # unit unchanged
        from core.coverage_ledger import load_ledger
        by_path = {u["path"]: u["status"]
                   for u in load_ledger(case)["units"].values()}
        assert by_path[REL] == "unseen"

    def test_accepted_after_failed_probe(self, tmp_path):
        from tools.coverage import mark_blocked
        case = _case(tmp_path)
        log = _log_for(case)
        # A real (failed) probe attempt lands in the trace first.
        log.record_tool_call(
            cmd=f"ez_evtxecmd --file {REL}",
            success=False, truncated=False, retries=0, exit_code=1,
            stderr="file header corrupt")
        with patch("core.execution_log.log", log):
            r = mark_blocked(
                path=REL,
                reason="EvtxECmd failed twice: file header corrupt")
        assert r["success"] is True, r
        assert r["unit"]["status"] == "blocked"
        from core.coverage_ledger import (
            load_ledger, ready_for_degraded_exit,
        )
        by_path = {u["path"]: u["status"]
                   for u in load_ledger(case)["units"].values()}
        assert by_path[REL] == "blocked"
        # blocked counts toward the floor — exit becomes legal, with an
        # auditable note instead of a silent forge.
        assert ready_for_degraded_exit(case) is True

    def test_unknown_path_lists_open_units(self, tmp_path):
        from tools.coverage import mark_blocked
        case = _case(tmp_path)
        log = _log_for(case)
        with patch("core.execution_log.log", log):
            r = mark_blocked(
                path="evidence/nope/missing.evtx",
                reason="never existed in the first place")
        assert r["success"] is False
        assert REL in (r.get("open_units") or [])
