"""ATLAS_SOURCE_IN_CASE: a claim's row source becomes a due item
only when the case holds it (a case file, or a listed image's file through
the index's suffix join); a source from a collection the case does not hold
is disclosed once per question, never due. Invented fixtures only
(CORP-WS01, jane.doe, upd.exe, dates in 2031)."""
from __future__ import annotations

import core.execution_log as elog
from core import question_plan as Q
from tests.core.test_contents_index import WS01, _build, _image, _links, _plan, case  # noqa: F401
from tests.core.test_question_plan import _claim, _table_call


def test_only_sources_the_case_holds_become_items(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    log = elog.log
    call = _table_call(case, log, r"upd\.exe", [
        {"host": "CORP-WS01", "desc": "upd.exe logged", "filename": "OS:/C/Windows/System32/winevt/Logs/Security.evtx"},
        {"host": "CORP-WS01", "desc": "upd.exe ran", "filename": "D:/Collections/other/Windows/Prefetch/UPD.EXE-1.pf"}])
    _claim(case, "C0031", "upd.exe ran on CORP-WS01", call)
    made = Q.source_items_for_question(log, str(case), {"id": "task-0001", "related_claim_ids": ["C0031"]})
    due = [i for i in made if i["status"] == "due"]
    assert [(i["target"]["path"], i["target"]["inner_path"]) for i in due] == \
        [("evidence/disk/corp-ws01.raw", "Windows/System32/winevt/Logs/Security.evtx")]
    note = [i for i in made if i["status"] == "dismissed"]
    assert len(note) == 1 and note[0]["outcome"].startswith(
        "rows from a source not found among the case's files or listed images: 1")
    again = Q.source_items_for_question(log, str(case), {"id": "task-0001", "related_claim_ids": ["C0031"]})
    assert len([i for i in log.work_items() if i.get("origin") == "source"]) == 2 and len(again) == 2


def test_a_case_file_tail_resolves_on_the_rows_host_only(case, monkeypatch):
    """Two triage collections held as files repeat the same standard path:
    a row's source is its own host's file; a hostless row matching both is
    in the case but not one file, so it keeps the path as a hint."""
    _links(case, [("CORP-WS01", "evidence/triage/ws01"), ("CORP-WS02", "evidence/triage/ws02")])
    files = ["evidence/triage/ws01/C/Windows/Prefetch/UPD.EXE-1.pf",
             "evidence/triage/ws02/C/Windows/Prefetch/UPD.EXE-1.pf"]
    monkeypatch.setattr(Q, "_case_files", lambda _c: files)
    src = "OS:/C/Windows/Prefetch/UPD.EXE-1.pf"
    assert Q._source_in_case(str(case), "CORP-WS02", src) == {"host": "CORP-WS02", "path": files[1]}
    assert Q._source_in_case(str(case), "CORP-WS01", src) == {"host": "CORP-WS01", "path": files[0]}
    assert Q._source_in_case(str(case), "", src) == {"host": "", "source_hint": src}


def test_an_equal_tail_on_one_host_joins_no_entry():
    import sqlite3
    from core.contents_index import _SuffixJoin
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE entries (id INTEGER, path TEXT, origin TEXT, version_of INTEGER, host TEXT)")
    con.executemany("INSERT INTO entries VALUES (?, ?, 'image', NULL, 'CORP-WS01')", [
        (1, "Windows/System32/winevt/Logs/Security.evtx"),
        (2, "Backup/System32/winevt/Logs/Security.evtx")])
    join = _SuffixJoin(con)
    assert join("CORP-WS01", "C:/Windows/System32/winevt/Logs/Security.evtx".replace("C:/", "")) == 1
    assert join("CORP-WS01", "System32/winevt/Logs/Security.evtx") is None
