"""Tests for correlate.cross_source_reconciliation MCP wrapper."""
from pathlib import Path
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture
def case_with_sources(tmp_path):
    import json
    import csv
    case = tmp_path / "case"
    wdir = case / "evidence" / "WAZUH_LOGS"
    wdir.mkdir(parents=True)
    (wdir / "alerts.json").write_text(json.dumps({
        "description": "alerts",
        "records": [{
            "timestamp": "2031-02-04T12:00:00+0000",
            "event_id": "4624",
            "src_ip": "203.0.113.10",
            "user": "x",
            "full_log": "Logon Type: 3",
        }],
    }), encoding="utf-8")
    adir = case / "analysis"
    adir.mkdir()
    with open(adir / "security_evtx.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["TimeCreated", "EventId", "Computer", "UserName"])
        w.writeheader()
    (case / "evidence" / "timeline.tsv").write_text(
        "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\n",
        encoding="utf-8",
    )
    return case


class TestCorrelateCrossSource:
    def test_tool_runs_with_active_case(self, case_with_sources):
        from tools.correlate import cross_source_reconciliation

        log = ExecutionLog()
        log.configure("T", str(case_with_sources / "analysis" / "trace.json"),
                      save_session=False)
        with patch("core.execution_log.log", log):
            r = cross_source_reconciliation(profiles=["successful_logon"])
        assert r["success"] is True
        assert "successful_logon" in r["profiles"]

    def test_tool_without_configured_case(self):
        from tools.correlate import cross_source_reconciliation
        log = ExecutionLog()
        # No configure() — case_dir unavailable
        with patch("core.execution_log.log", log):
            r = cross_source_reconciliation()
        assert r["success"] is False
        assert "case" in r.get("error", "").lower()
