"""EvtxECmd's own report of what it processed becomes the parse entry's
``processed`` stamp (output, filter, files with rows kept), and the CSV it
wrote is joined to the index at result time. No report, no stamp. The
stdout below is written from scratch in the tool's public format."""
from __future__ import annotations

import pytest

from core.execution_log import ExecutionLog
from tools import eztools

STDOUT = """Looking for event log files in analysis/extracted/CORP-WS01/Logs
Processing analysis/extracted/CORP-WS01/Logs/Security.evtx...
Chunk count: 3, Iterating records...
Records included: 12 Errors: 0 Events dropped: 4
Processing analysis/extracted/CORP-WS01/Logs/Windows PowerShell.evtx...
Chunk count: 1, Iterating records...
Records included: 0 Errors: 0 Events dropped: 9
Processed 2 files in 0.5 seconds
"""


def test_the_tools_report_is_read_per_file():
    assert eztools.evtx_processed(STDOUT) == [
        {"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx", "rows": 12},
        {"path": "analysis/extracted/CORP-WS01/Logs/Windows PowerShell.evtx", "rows": 0}]
    assert eztools.evtx_processed("Processed 0 files") == []


@pytest.fixture
def log(tmp_path, monkeypatch):
    case = tmp_path / "CASE-A"
    (case / "analysis" / "evtx_csv").mkdir(parents=True)
    lg = ExecutionLog()
    lg.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", lg)
    return lg, case


def test_the_parse_entry_is_stamped_and_its_csv_joined(log, monkeypatch):
    lg, case = log
    csv = case / "analysis" / "evtx_csv" / "CORP-WS01.csv"
    csv.write_text("TimeCreated,EventId,SourceFile\n", encoding="utf-8")
    joined = []
    monkeypatch.setattr("core.contents_index.register_exports", lambda c, paths: joined.extend(paths) or [])
    cid = lg.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/CORP-WS01/Logs", True, False, 0, 0)
    eztools._stamp_evtx_processed({"success": True, "_atlas_call_id": cid, "stdout": STDOUT},
                                  str(case / "analysis" / "evtx_csv"), "CORP-WS01.csv", "4624,4625", None)
    stamp = lg.index().by_call_id[cid]["processed"]
    assert stamp["output"] == "analysis/evtx_csv/CORP-WS01.csv" and stamp["filter"] == "event ids 4624,4625"
    assert stamp["files"][1] == {"path": "analysis/extracted/CORP-WS01/Logs/Windows PowerShell.evtx", "rows": 0}
    assert joined == [str(csv)]


def test_no_report_no_stamp(log):
    lg, case = log
    cid = lg.record_tool_call("dotnet EvtxECmd.dll -f x.evtx", True, False, 0, 0)
    eztools._stamp_evtx_processed({"success": True, "_atlas_call_id": cid, "stdout": "Processed 0 files"},
                                  str(case / "analysis" / "evtx_csv"), "x.csv", None, None)
    assert "processed" not in lg.index().by_call_id[cid]


def test_a_report_of_more_files_than_the_stamp_keeps_says_how_many(log, monkeypatch):
    """The stamp keeps 5000 files; a larger report says its own count, so
    the files past the cut are known to have been processed, not lost."""
    lg, case = log
    monkeypatch.setattr("core.contents_index.register_exports", lambda c, paths: [])
    big = "".join(f"Processing analysis/extracted/CORP-WS01/Logs/log{i:05d}.evtx...\nRecords included: 1\n"
                  for i in range(5003))
    cid = lg.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/CORP-WS01/Logs", True, False, 0, 0)
    eztools._stamp_evtx_processed({"success": True, "_atlas_call_id": cid, "stdout": big},
                                  str(case / "analysis" / "evtx_csv"), "CORP-WS01.csv", None, None)
    stamp = lg.index().by_call_id[cid]["processed"]
    assert len(stamp["files"]) == 5000 and stamp["files_total"] == 5003
    small = lg.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/CORP-WS01/Logs", True, False, 0, 0)
    eztools._stamp_evtx_processed({"success": True, "_atlas_call_id": small, "stdout": STDOUT},
                                  str(case / "analysis" / "evtx_csv"), "CORP-WS01.csv", None, None)
    assert "files_total" not in lg.index().by_call_id[small]["processed"]
