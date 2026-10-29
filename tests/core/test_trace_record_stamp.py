"""A call's own trace entry carries what the call was given and how much of
its result was seen, also when the tool logged that entry itself (an
executor program, an in-process reader); the trace's cut argument text is
read leniently by every reader. Invented paths and values only."""
from __future__ import annotations

from core import middleware
from core.execution_log import ExecutionLog


def _log(tmp_path, monkeypatch):
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return log


def _entry(log, cid):
    return next(e for e in log._entries if e.get("call_id") == cid)


def test_a_self_logged_program_call_gets_its_arguments_and_counts(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    cid = log.record_tool_call("dotnet Parser.dll -d analysis/extracted/CORP-WS01/Logs --csv analysis/out",
                               True, False, 0, 0, action_id=7)
    args = {"evtx_path": "analysis/extracted/CORP-WS01/Logs", "output_dir": "analysis/out"}
    middleware._trace_success_baseline("ez_ez_evtxecmd", 0.1, before,
                                       result={"success": True, "_atlas_call_id": cid, "returned_rows": 12},
                                       args=args, action_id=7)
    assert len(log._entries) == before + 1          # no second record of the call
    e = _entry(log, cid)
    assert '"evtx_path": "analysis/extracted/CORP-WS01/Logs"' in e["args"]
    assert e["result_meta"] == {"returned_rows": 12}


def test_without_a_stamp_only_this_calls_own_entries_are_stamped(tmp_path, monkeypatch):
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    mine = log.record_tool_call("icat -o 2048 evidence/CORP-WS01.img 1234", True, False, 0, 0, action_id=3)
    other = log.record_tool_call("fls -r evidence/CORP-DC01.img", True, False, 0, 0, action_id=4)
    middleware._trace_success_baseline("tsk_tsk_icat", 0.1, before, result={"success": True},
                                       args={"image": "evidence/CORP-WS01.img", "inode": "1234"}, action_id=3)
    assert "CORP-WS01.img" in _entry(log, mine)["args"]
    assert "args" not in _entry(log, other)


def test_a_cut_argument_text_is_read_by_its_pairs(tmp_path):
    from core.export_profile import _export_read
    cut = '{"path": "analysis/out/CORP-WS01.csv", "where": "' + "x" * 380
    entry = {"cmd": "<py>:table_table_query", "mcp_tool": "table_table_query", "args": cut}
    assert _export_read(None, entry) == "analysis/out/CORP-WS01.csv"


def test_an_entry_without_this_calls_action_id_gets_no_stamp(tmp_path, monkeypatch):
    """Only the entries carrying this call's action id are its own: an entry
    another writer logged without an id is never given this call's args."""
    log = _log(tmp_path, monkeypatch)
    before = len(log._entries)
    stray = log.record_tool_call("fls -r evidence/CORP-WS02.img", True, False, 0, 0)
    log._entries[-1].pop("action_id", None)
    middleware._trace_success_baseline("tsk_tsk_icat", 0.1, before, result={"success": True},
                                       args={"image": "evidence/CORP-WS01.img"}, action_id=9)
    assert "args" not in _entry(log, stray)


def test_a_cut_tail_is_a_key_and_never_a_value():
    """A 400-character cut that ends inside a value names a folder above the
    file the call read: the reader keeps the key and drops the value, so no
    copy below that folder is credited and no item closes on it."""
    from core.indicators import _parsed_args
    from core.work_order import _call_view
    cut = '{"pattern": "' + "x" * 300 + '", "file_path": "analysis/extracted/CORP-WS01'
    entry = {"type": "tool_call", "cmd": "<py>:strings_read_text", "args": cut}
    pairs, keys = _parsed_args(entry)
    assert "file_path" in keys and "file_path" not in pairs
    view = _call_view(entry)
    assert "file_path" not in view["args"]
    assert not any("analysis/extracted" in str(i) for k in ("content", "listed", "folder", "folders")
                   for i in view["reads"].get(k, ()))


def test_a_python_call_is_dated_by_the_evidence_its_arguments_name(tmp_path, monkeypatch):
    """The args are stamped before the result is indexed: the evidence index
    takes its reference year from the paths the call names, arguments
    included."""
    from core import evidence_index
    import core.forensic_citation as fc
    log = _log(tmp_path, monkeypatch)
    monkeypatch.setenv("ATLAS_IOC_SIGHTINGS", "1")
    monkeypatch.setattr(fc, "citation_class", lambda e: "evidence")
    seen = {}
    monkeypatch.setattr(evidence_index, "evidence_date", lambda tokens: seen.setdefault("tokens", list(tokens)) and 2031)
    monkeypatch.setattr(evidence_index, "index_output", lambda **kw: seen.setdefault("year", kw.get("reference_year")))
    before = len(log._entries)
    middleware._trace_success_baseline("strings_read_text", 0.1, before, result={"success": True, "text": "line"},
                                       args={"file_path": "evidence/CORP-WS01/syslog"})
    assert any("evidence/CORP-WS01/syslog" in t for t in seen.get("tokens", []))
