"""The row view keeps every source value, renders a JSON row's 0 and
False as values, and a record view read from the full saved output is not
called cut. Invented rows only (CORP-WS01, jane.doe, 2031 times)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.tool_result_view import render_record_view, render_rows_view

_SYSMON = "Microsoft-Windows-Sysmon/Operational"
_LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def _evtx(channels):
    rows = []
    for i, (ch, eid) in enumerate(channels):
        rows.append({"_sheet": "-", "_row": i + 2, "TimeCreated": f"2031-03-10 14:{i:02d}:00", "Computer": "CORP-WS01",
                     "Channel": ch, "EventId": eid, "UserName": "jane.doe",
                     "PayloadData1": f"ParentImage: C:\\Windows\\explorer.exe Image: C:\\Users\\Public\\tool{i}.exe "
                                     + "CommandLine: " + "x" * 300})
    return rows


def _lines(rows, pattern=None):
    payload = {"success": True, "rows": rows, **({"pattern": pattern} if pattern else {})}
    view = json.loads(render_rows_view(payload, 12000, 5, tool="table_table_query")[0])
    return view, view["rows"]


def test_a_long_channel_keeps_every_event_id_and_the_payload_keeps_its_room():
    mixed = [(_SYSMON, 1), ("Security", 4624), (_LSM, 21), ("Security", 4634)]
    view, lines = _lines(_evtx(mixed))
    assert view["columns"] == "time | Channel | EventId | PayloadData1"
    for line, (ch, eid) in zip(lines, mixed):
        cells = line.split(" | ")
        assert cells[2] == str(eid) and cells[1].endswith(ch[-20:])           # the channel's informative end
        assert len(cells[1]) <= 64 and len(cells[3]) >= 200                   # the payload keeps its share
    _v, short = _lines(_evtx([("Security", 4624), ("System", 7045)]))
    assert _v["columns"] == "time | Channel/EventId | PayloadData1" and "| Security/4624 |" in short[0]
    _v, matched = _lines(_evtx(mixed), pattern=r"tool2\.exe")
    assert len(matched[2].split(" | ")[3]) >= 200


def test_plasos_short_source_pair_stays_joined():
    rows = [{"_sheet": "-", "_row": 1, "date": "03/10/2031", "time": "14:02:10", "source": "LOG",
             "sourcetype": "PowerShell Transcript Event", "desc": "executed by host application powershell"},
            {"_sheet": "-", "_row": 2, "date": "03/10/2031", "time": "14:10:00", "source": "FILE",
             "sourcetype": "Bodyfile", "desc": "c:\\Users\\Public\\u.ps1 Owner identifier: 0"}]
    view, lines = _lines(rows)
    assert "source/sourcetype" in view["columns"] and "| LOG/PowerShell Transcript Event |" in lines[0]


def _proc(pid, ppid, threads, wow):
    return {"CreateTime": f"2031-03-10T08:00:{pid % 60:02d}+00:00", "PID": pid, "PPID": ppid, "Threads": threads,
            "Wow64": wow, "SessionId": 0, "IsHidden": False, "ImageFileName": f"corp-app{pid}.exe", "__children": []}


def _record_view(tmp_path, records, **entry):
    path = tmp_path / "out.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    e = {"stdout_file": str(path), **entry}
    return json.loads(render_record_view({"success": True, "truncated": True, "_atlas_call_id": 9}, e, 12000, 9)[0])


def test_zero_and_false_are_values_and_a_column_of_them_goes_to_the_shared_line(tmp_path):
    view = _record_view(tmp_path, [_proc(4, 0, 0, False), _proc(96, 4, 3, True)])
    first = view["rows"][0].split(" | ")
    assert view["columns"] == "time | PID | PPID | Threads | Wow64 | ImageFileName"
    assert first[1:5] == ["4", "0", "0", "False"]
    assert view["same_in_every_returned_row"] == {"SessionId": "0", "IsHidden": "False"}


def test_a_complete_record_view_of_a_cut_stdout_is_whole_and_a_cut_excerpt_is_not(tmp_path):
    from core.indicators import flat_rows_of
    from tests.tools.test_gate_precision import _ctx
    from tools._gates import universal_from_truncated as uft
    records = [_proc(4 + 4 * i, 4, 3, False) for i in range(6)]
    view = _record_view(tmp_path, records)
    assert "truncated" not in view and view["shown"].startswith("all 6 records this call returned")
    entry = {"type": "tool_call", "call_id": 9, "cmd": "vol -f evidence/corp-ws01.mem -r json windows.pslist",
             "truncated": True, "stdout_file": str(tmp_path / "out.json"), "rows_split": "flat",
             "view_complete": True, "view_rows_shown": 6, "view_rows_returned": 6}
    claim = "No process in the corp-ws01.mem process list is named svc_kit.exe."
    ctx = _ctx(claim, linked_call_id=9, input_call_ids=[9], by_call_id={9: entry})
    assert uft.incomplete_reason(entry) == "" and uft.check(ctx) is None
    cut = {"type": "tool_call", "call_id": 10, "cmd": entry["cmd"], "truncated": True,
           "stdout_excerpt": json.dumps(records[:3])}
    assert flat_rows_of(cut) is None                       # a cut excerpt is never read as the whole output
    assert uft.incomplete_reason(cut) == "its output was truncated"
    refused = uft.check(_ctx(claim, linked_call_id=10, input_call_ids=[10], by_call_id={10: cut}))
    assert refused is not None
