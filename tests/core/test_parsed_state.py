"""A class whose files a parser processed and whose rows nobody looked at is
``parsed``: an open state with its next step (query the output), never a
reason. It comes from the parser's own report (the ``processed`` stamp) or
from rows of the class's files in a joined table; a row shown moves it on;
no report and no rows give nothing. Invented fixtures (CORP-WS01, 2031)."""
from __future__ import annotations

import json

import pytest

import core.execution_log as elog
from core import contents_index as ci
from core import work_order as W
from core.coverage_ledger import load_ledger, save_ledger
from core.evidence_disposition import _relevant_not_read, credit_dispositions, report_lines

IMG = "evidence/disk/corp-ws01.raw"
SEC = "Windows/System32/winevt/Logs/Security.evtx"


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_CONTENTS_INDEX", "1")
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis/extracted/evtx/CORP-WS01", "analysis/evtx_csv"):
        (root / d).mkdir(parents=True)
    (root / IMG).write_bytes(b"\0" * 512)
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / IMG), "media_role": "disk", "action": "plan_only",
         "image_type": "raw_or_container"}]}), encoding="utf-8")
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    con = ci._connect(root, create=True)
    ci._insert_entries(con, "CORP-WS01", IMG, [{"path": SEC, "name": "Security.evtx", "inode": "200-128-1",
                                                "volume": 0, "size": 100}], "image")
    ci._meta_set(con, f"image:{IMG}", {"listed": 1, "complete": 1, "host": "CORP-WS01", "volumes": [0]})
    con.commit()
    eid, label = con.execute("SELECT id, class FROM entries").fetchone()
    con.close()
    copy = root / "analysis/extracted/evtx/CORP-WS01/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), eid, 3, 8)
    save_ledger(root, {"units": {}, "items": {"i1": {"path": IMG, "kind": "image", "host": "CORP-WS01",
                                                     "state": "relevant"}},
                       "classes": {"c1": {"id": "c1", "item": "i1", "label": label, "state": "relevant",
                                          "files": 1, "empty": 0}}})
    return root, eid, label


def _parse(log, rows):
    cid = log.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/evtx/CORP-WS01", True, False, 0, 0)
    log.annotate_tool_call(cid, processed={"output": "analysis/evtx_csv/CORP-WS01.csv", "filter": "event ids 4624",
                                           "files": [{"path": "analysis/extracted/evtx/CORP-WS01/Security.evtx",
                                                      "rows": rows}]})
    return cid


def test_a_processed_class_with_no_row_looked_at_is_parsed_and_open(case):
    root, _eid, label = case
    _parse(elog.log, 5)
    credit_dispositions(root)
    c = load_ledger(root)["classes"]["c1"]
    assert c["state"] == "parsed" and "analysis/evtx_csv/CORP-WS01.csv" in c["reason"]
    assert "parsed with event ids 4624 only" in c["reason"] and "no row looked at" in c["reason"]
    assert _relevant_not_read(load_ledger(root)) == 1                     # open, not a reason
    assert any("analysis/evtx_csv/CORP-WS01.csv" in ln and "query it" in ln for ln in report_lines(root))
    work = W.open_work(elog.log, str(root))
    assert work["parsed"][0]["output"] == "analysis/evtx_csv/CORP-WS01.csv"
    lines = W.open_work_lines(work)
    assert W.PARSED_HEAD in lines and any("CORP-WS01: " + label in ln for ln in lines)
    assert ("parsed", "analysis/evtx_csv/CORP-WS01.csv", f"CORP-WS01: {label}") in W.open_work_keys(work)


def test_without_the_parsers_report_or_rows_nothing_is_parsed(case):
    root, _eid, _label = case
    cid = elog.log.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/evtx/CORP-WS01", True, False, 0, 0)
    elog.log.annotate_tool_call(cid, args=json.dumps({"evtx_path": "analysis/extracted/evtx/CORP-WS01"}))
    credit_dispositions(root)
    assert load_ledger(root)["classes"]["c1"]["state"] == "relevant"


def test_rows_of_the_class_in_a_joined_table_make_it_parsed(case):
    root, _eid, _label = case
    csv = root / "analysis/evtx_csv/CORP-WS01.csv"
    csv.write_text("TimeCreated,EventId,Channel,Computer,SourceFile\n"
                   "2031-01-01 00:00:01,4624,Security,CORP-WS01,C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\n",
                   encoding="utf-8")
    ci.register_exports(root, [str(csv)])
    credit_dispositions(root)
    assert load_ledger(root)["classes"]["c1"]["state"] == "parsed"


def test_the_coverage_tab_shows_parsed_with_its_output():
    from dashboard.read_models import _coverage_unit
    u = _coverage_unit({"state": "parsed", "outputs": ["analysis/evtx_csv/CORP-WS01.csv"]})
    assert u["state"] == "parsed" and u["note"] == "analysis/evtx_csv/CORP-WS01.csv"


def test_a_parsed_entry_is_no_never_attempted_gap(case):
    """The report's gaps never say "no read was attempted" for a file a
    parser processed: it is parsed, listed per output under the evidence
    not analysed, with its next step."""
    from core.artifact_value import gap_lines, high_value_state_uncached
    root, eid, _label = case
    _parse(elog.log, 5)
    item = next(i for i in high_value_state_uncached(root)["items"] if i.get("index_id") == eid)
    assert item["state"] == "open" and item["parsed_into"] == "analysis/evtx_csv/CORP-WS01.csv"
    assert not any("Security.evtx" in ln for ln in gap_lines(root))


CSV_HEAD = "TimeCreated,EventId,Channel,Computer,SourceFile\n"
CSV_ROW = "2031-01-01 00:00:01,4624,Security,CORP-WS01,C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\n"


def test_a_view_that_chose_its_columns_still_moves_its_rows_sources_on(case):
    """The usual query names its columns and leaves the source column out:
    the shown rows' ordinals name their sources in the joined table."""
    root, _eid, _label = case
    csv = root / "analysis/evtx_csv/CORP-WS01.csv"
    csv.write_text(CSV_HEAD + CSV_ROW, encoding="utf-8")
    ci.register_exports(root, [str(csv)])
    result = {"path": str(csv), "rows": [{"_sheet": "-", "_row": 1, "TimeCreated": "2031-01-01 00:00:01",
                                          "EventId": "4624"}]}
    assert ci.observe_result(root, "table_table_query", result, None, 61) == 1
    credit_dispositions(root)
    assert load_ledger(root)["classes"]["c1"]["state"] == "partial"
    from core.artifact_value import gap_lines
    assert not any("Security.evtx" in ln for ln in gap_lines(root))        # rows of it were shown


def test_a_filtered_parse_that_kept_no_row_has_its_own_step(case):
    """0 rows matched the filter: no output holds a row of it, so its step
    is a parse without the filter or a leave with that reason, never a
    query of the output."""
    root, _eid, _label = case
    _parse(elog.log, 0)
    credit_dispositions(root)
    c = load_ledger(root)["classes"]["c1"]
    assert c["state"] == "parsed" and c["no_rows"] is True and "0 rows matched event ids 4624" in c["reason"]
    assert "parse without the filter" in c["reason"]
    assert any(ln.startswith("- 0 rows matched event ids 4624") for ln in report_lines(root))
    lines = W.open_work_lines(W.open_work(elog.log, str(root)))
    assert W.PARSED_HEAD not in lines and any(ln.startswith("0 rows matched event ids 4624") for ln in lines)
    assert not any("query" in ln for ln in lines if "0 rows matched" in ln)


def test_a_rows_shown_credit_survives_its_table_being_scanned_again(case):
    """A parse that writes its output anew rescans it: what a view showed
    of a source stays shown, re-linked by the source path to the new rows."""
    root, _eid, _label = case
    csv = root / "analysis/evtx_csv/CORP-WS01.csv"
    csv.write_text(CSV_HEAD + CSV_ROW, encoding="utf-8")
    ci.register_exports(root, [str(csv)])
    result = {"path": str(csv), "rows": [{"_sheet": "-", "_row": 1, "EventId": "4624"}]}
    assert ci.observe_result(root, "table_table_query", result, None, 61) == 1
    csv.write_text(CSV_HEAD + CSV_ROW + CSV_ROW.replace("00:00:01", "00:00:02"), encoding="utf-8")
    assert ci.register_exports(root, [str(csv)]) == ["analysis/evtx_csv/CORP-WS01.csv"]
    credit_dispositions(root)
    assert load_ledger(root)["classes"]["c1"]["state"] == "partial"


def test_a_parse_written_over_by_a_later_parse_is_not_queried_but_parsed_again(case):
    """Two parses into one output file: the later one holds it, so the
    earlier parse's files are in no output. Their class is open with the
    step to parse them again into an output of their own, never "query" the
    file that holds other rows now; a parse into its own output ends it."""
    root, _eid, label = case
    log = elog.log
    _parse(log, 5)
    later = log.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/evtx/CORP-WS02", True, False, 0, 0)
    log.annotate_tool_call(later, processed={"output": "analysis/evtx_csv/CORP-WS01.csv", "filter": "",
                                             "files": [{"path": "analysis/extracted/evtx/CORP-WS02/System.evtx",
                                                        "rows": 3}]})
    assert ci.processed_entries(root) == {} and ci.overwritten_entries(root) == {
        _eid: ("analysis/evtx_csv/CORP-WS01.csv", later)}
    credit_dispositions(root)
    c = load_ledger(root)["classes"]["c1"]
    assert c["state"] == "parsed" and c["overwritten"] == ["analysis/evtx_csv/CORP-WS01.csv"]
    assert "a later parse wrote over" in c["reason"] and "query" not in c["reason"]
    assert any(ln.startswith("- analysis/evtx_csv/CORP-WS01.csv:") and "parse them again" in ln
               for ln in report_lines(root))
    lines = W.open_work_lines(W.open_work(log, str(root)))
    assert W.PARSED_HEAD not in lines
    assert any(ln.startswith('Parsed into "analysis/evtx_csv/CORP-WS01.csv", which a later parse wrote over')
               and f"CORP-WS01: {label}" in ln for ln in lines)
    from core.artifact_value import gap_lines
    assert not any("Security.evtx" in ln for ln in gap_lines(root))      # a parse was attempted
    again = log.record_tool_call("dotnet EvtxECmd.dll -d analysis/extracted/evtx/CORP-WS01", True, False, 0, 0)
    log.annotate_tool_call(again, processed={"output": "analysis/evtx_csv/CORP-WS01-own.csv", "filter": "",
                                             "files": [{"path": "analysis/extracted/evtx/CORP-WS01/Security.evtx",
                                                        "rows": 5}]})
    credit_dispositions(root)
    c = load_ledger(root)["classes"]["c1"]
    assert c["state"] == "parsed" and not c["overwritten"] and c["outputs"] == ["analysis/evtx_csv/CORP-WS01-own.csv"]


def test_the_parsed_deferral_names_the_output_once_and_its_state_is_on_the_trace(case):
    root, _eid, label = case
    cid = _parse(elog.log, 5)
    credit_dispositions(root)
    parsed = W.open_work(elog.log, str(root))["parsed"]
    text = W.parsed_deferral(elog.log, parsed)
    assert text.startswith("atlas_finish deferred for the parsed outputs")
    assert f'- query "analysis/evtx_csv/CORP-WS01.csv": 1 class(es) (parsed with event ids 4624 only): ' \
           f"CORP-WS01: {label}" in text
    assert elog.log.index().by_call_id[cid]["parsed_deferred"] == ["analysis/evtx_csv/CORP-WS01.csv"]
    assert W.parsed_deferral(elog.log, parsed) == ""
    for gone in ({"overwritten": True}, {"no_rows": True}):
        assert W.parsed_deferral(elog.log, [{**parsed[0], "output": "analysis/evtx_csv/other.csv", **gone}]) == ""


# ── a table's sources joined by the file's identity ───────────────────────

def _sources(root):
    with ci._connect(root) as con:
        return [tuple(r) for r in con.execute("SELECT host, entry_id, rows FROM sources")], \
            con.execute("SELECT COUNT(*) FROM entries WHERE origin = 'export'").fetchone()[0]


def test_one_log_whose_rows_carry_two_machine_names_is_one_source_of_its_own_entry(case):
    """An event log's Computer field holds every name the machine had (a
    template name before the rename): the log is still one file, joined to
    the entry its copy was extracted from, and no export entry is made."""
    root, eid, _label = case
    copy = root / "analysis/extracted/evtx/CORP-WS01/Security.evtx"
    csv = root / "analysis/evtx_csv/CORP-WS01.csv"
    csv.write_text(CSV_HEAD + f"2031-01-01 00:00:01,4624,Security,CORP-WS01.corp.example.com,{copy}\n"
                   f"2031-01-01 00:00:02,4624,Security,WIN-TEMPLATE01,{copy}\n", encoding="utf-8")
    ci.register_exports(root, [str(csv)])
    rows, phantoms = _sources(root)
    assert rows == [("CORP-WS01", eid, 2)] and phantoms == 0


def test_a_copy_of_another_hosts_log_joins_that_hosts_entry(case):
    """Rows whose own host cell names one machine, from a copy of another
    machine's log with the same path: the copy decides, not the cell."""
    root, _eid, _label = case
    dc_img = "evidence/disk/corp-dc01.raw"
    (root / dc_img).write_bytes(b"\0" * 512)
    with ci._connect(root) as con:
        ci._insert_entries(con, "CORP-DC01", dc_img, [{"path": SEC, "name": "Security.evtx", "inode": "201-128-1",
                                                       "volume": 0, "size": 100}], "image")
        ci._meta_set(con, f"image:{dc_img}", {"listed": 1, "complete": 1, "host": "CORP-DC01", "volumes": [0]})
        con.commit()
        dc = con.execute("SELECT id FROM entries WHERE image = ?", (dc_img,)).fetchone()[0]
    (root / "analysis/extracted/evtx/CORP-DC01").mkdir(parents=True)
    copy = root / "analysis/extracted/evtx/CORP-DC01/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), dc, 4, 8)
    csv = root / "analysis/evtx_csv/CORP-WS01.csv"
    csv.write_text(CSV_HEAD + f"2031-01-01 00:00:01,4624,Security,CORP-WS01,{copy}\n", encoding="utf-8")
    ci.register_exports(root, [str(csv)])
    assert _sources(root)[0] == [("CORP-DC01", dc, 1)]
    assert ci.resolve_source(root, "CORP-WS01", str(copy))["image"] == dc_img
