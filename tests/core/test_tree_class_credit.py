"""A collected tree's or a loose file's content classes are credited by the
reads of their own files, under the image's rule (core.evidence_disposition
.credit_dispositions, core.contents_index.read_state_by_class ``files``): a
content read reads a file, a parser's own report of a file it processed
leaves it parsed, a listing or a failed read credits nothing. Invented
fixtures only (CORP-WS02, jane.doe)."""
from __future__ import annotations

import json

import core.execution_log as elog
from core.coverage_ledger import build_coverage_ledger, load_ledger, save_ledger
from core.evidence_disposition import credit_dispositions, report_lines
from tests.core.test_contents_index import case  # noqa: F401

LOGS = "evidence/corp-ws02-collection/logs"
SYS, APP = f"{LOGS}/agent.log", f"{LOGS}/agent.old.log"


def _built(case):
    (case / LOGS).mkdir(parents=True)
    for rel in (SYS, APP):
        (case / rel).write_text("2031-03-10 14:00:00 service started\n" * 50)
    (case / "evidence" / "jane.doe-notes.log").write_text("2031-03-10 14:00:00 note\n" * 50)
    led = build_coverage_ledger(case)
    tree = next(i for i in led["items"].values() if i["kind"] == "tree")
    cls = next(c for c in led["classes"].values() if c["item"] == tree["id"] and c["files"] == 2)
    return led, tree, cls


def _call(tool, args, *, success=True, processed=None):
    cid = elog.log.record_tool_call(f"<py>:{tool}", success, False, 0, 0)
    elog.log._entries[-1].update(mcp_tool=tool, args=json.dumps(args))
    if processed:
        elog.log.annotate_tool_call(cid, processed=processed)
    return cid


def _state(case, cid):
    return load_ledger(case)["classes"][cid]


def test_one_file_read_is_partial_with_its_count_and_both_are_read(case):
    _led, tree, cls = _built(case)
    _call("strings_read_text", {"file_path": SYS})
    credit_dispositions(case)
    c = _state(case, cls["id"])
    assert c["state"] == "partial" and c["credited"] == "1 of 2 files read"
    assert any(f"{tree['path']}: {cls['label']} (2):" in ln and "1 of 2 files read" in ln for ln in report_lines(case))
    _call("strings_read_text", {"file_path": APP})
    credit_dispositions(case)
    assert _state(case, cls["id"])["state"] == "read"
    assert load_ledger(case)["items"][tree["id"]]["state"] == "read"          # partial moves on too


def test_a_listing_or_a_failed_read_credits_nothing(case):
    _led, _tree, cls = _built(case)
    _call("strings_file_identify_directory", {"directory": LOGS})
    _call("strings_read_text", {"file_path": SYS}, success=False)
    credit_dispositions(case)
    assert _state(case, cls["id"])["state"] == "pending"


def test_a_file_a_parser_only_processed_is_parsed_never_read(case):
    _led, _tree, cls = _built(case)
    _call("plaso_log2timeline", {"source_path": LOGS}, processed={
        "output": "analysis/logs/out.csv", "filter": "",
        "files": [{"path": SYS, "rows": 12}, {"path": APP, "rows": 3}]})
    credit_dispositions(case)
    c = _state(case, cls["id"])
    assert c["state"] == "parsed" and "2 of 2 files parsed into analysis/logs/out.csv" in c["reason"]


def test_a_loose_file_item_is_read_by_its_read(case):
    led, _tree, _cls = _built(case)
    loose = next(i for i in led["items"].values() if i["kind"] == "file")
    own = [c for c in led["classes"].values() if c["item"] == loose["id"]]
    assert own
    _call("strings_read_text", {"file_path": loose["path"]})
    credit_dispositions(case)
    after = load_ledger(case)
    assert all(after["classes"][c["id"]]["state"] == "read" for c in own)
    assert after["items"][loose["id"]]["state"] == "read"


def test_a_left_class_is_never_changed(case):
    led, _tree, cls = _built(case)
    led["classes"][cls["id"]].update(state="left", reason_kind="outside_window", reason="before the window")
    save_ledger(case, led)
    _call("strings_read_text", {"file_path": SYS})
    _call("strings_read_text", {"file_path": APP})
    credit_dispositions(case)
    assert _state(case, cls["id"])["state"] == "left"


def test_members_that_changed_since_the_build_never_make_it_whole(case, monkeypatch):
    _led, _tree, cls = _built(case)
    from core import evidence_profile as EP
    real = EP.ensure_evidence_profile(str(case))
    one = [f for f in real.get("files") or [] if f.get("path") != APP]
    monkeypatch.setattr(EP, "ensure_evidence_profile", lambda c, **kw: {**real, "files": one})
    _call("strings_read_text", {"file_path": SYS})
    credit_dispositions(case)
    c = _state(case, cls["id"])
    assert c["state"] == "partial" and c["credited"] == "1 of 1 files read"


def test_a_folder_triage_item_closes_once_its_class_is_credited(case):
    from core import evidence_triage as TR
    _led, tree, cls = _built(case)
    entry = TR._work_item(elog.log, case, tree, [cls], "due", "read the collected logs")
    _call("plaso_log2timeline", {"source_path": LOGS}, processed={
        "output": "analysis/logs/out.csv", "filter": "", "files": [{"path": SYS, "rows": 1}]})
    assert TR.sync_triage(elog.log, case) == []                       # parsed is still open
    _call("strings_read_text", {"file_path": SYS})
    assert TR.sync_triage(elog.log, case) == [entry["call_id"]]       # partial is handled, as for an image
    assert next(e for e in elog.log.work_items() if e["call_id"] == entry["call_id"])["status"] == "resolved"


def test_the_credited_count_keeps_its_thousands_and_moves_on_with_the_reads():
    from core.evidence_disposition import _credit_class
    c = {"state": "relevant"}
    assert _credit_class(c, {"total": 2048, "read": 1, "partial": 0})
    assert c["state"] == "partial" and c["credited"] == "1 of 2,048 files read"
    assert not _credit_class(c, {"total": 2048, "read": 1, "partial": 0})          # unchanged
    assert _credit_class(c, {"total": 2048, "read": 2, "partial": 0}) and c["credited"] == "2 of 2,048 files read"
    assert not _credit_class(c, {"total": 2048, "read": 0, "partial": 0, "parsed": 2048})   # never taken back
