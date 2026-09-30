"""A call the citation auto-fill adds to a finding's lineage, because its
output holds a value the finding names, is no basis for the finding's
universal or negative statement: the analyst did not rest the statement on
it and cannot take it out again, since the auto-fill adds it back."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

LNK = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Plan.lnk"
FINDING = (f"Anti-forensics on HOST-A: Eraser was installed and {LNK} still points to the "
           "deleted share file. No log-clear events were recorded.")
EVIDENCE = "Security log query for event 1102: matched_rows 0."


@pytest.fixture(autouse=True)
def _no_side_helpers():
    with patch("tools.misc.tool_program",
               side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def log(case):
    lg = ExecutionLog()
    lg.configure("AUTOFILL", str(case / "trace.json"), save_session=False)
    lg.record_dair_call("Analyze", "", False, "", "", "stay", "")
    return lg


def _record(log, case, **kw):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log), \
         patch("core.claim_graph.resolve_case_dir", return_value=str(case)), \
         patch.object(log, "case_dir", return_value=str(case)):
        return record_finding(**kw)


def _calls(log, lnk_truncated):
    lnk = log.record_tool_call(
        "dotnet /opt/zimmermantools/LECmd.dll -d mnt/host/fs/Users", True, lnk_truncated, 0, 0,
        stdout_excerpt=f"SourceFile: {LNK} Target: share file (deleted)")
    query = log.record_tool_call(
        "<py>:table_table_query", True, False, 0, 0,
        stdout_excerpt='{"success": true, "path": "analysis/security.csv", "where": "EventId=1102", '
                       '"matched_rows": 0, "returned_rows": 0, "rows": []}')
    return lnk, query


def test_the_negative_records_when_only_the_autofill_cites_the_cut_call(log, case, monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    lnk, query = _calls(log, lnk_truncated=True)
    result = _record(log, case, description=FINDING, confidence="SUSPECTED", source="lnk+evtx",
                     linked_call_id=query, input_call_ids=[query], supporting_evidence=EVIDENCE,
                     host="HOST-A")
    assert result.get("gate") != "universal_from_truncated", result
    assert result.get("success") is True, result


def test_the_negative_is_refused_when_the_analyst_cites_the_cut_call(log, case, monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    lnk, query = _calls(log, lnk_truncated=True)
    result = _record(log, case, description=FINDING, confidence="SUSPECTED", source="lnk+evtx",
                     linked_call_id=query, input_call_ids=[query, lnk], supporting_evidence=EVIDENCE,
                     host="HOST-A")
    assert result.get("success") is False and result.get("gate") == "universal_from_truncated"
    assert result.get("incomplete_call_id") == lnk
