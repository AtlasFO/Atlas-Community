"""The row test (tools/_gates/citation_support, ATLAS_CITATION_ROWS): a call
shows a claim when one of its printed rows holds a strong entity of the
claim, not merely what the call was asked to read, with the claim's minute
time in the same row when it states one. Invented fixtures: CORP-WS01,
CORP-WS02, CORP\\jane.doe, 203.0.113.x, dates in 2031."""
from __future__ import annotations

import json

import pytest

from tools._gates import citation_support as cs

HOSTS = ["CORP-WS01", "CORP-WS02"]


def _call(cid, cmd, excerpt="", **extra):
    e = {"type": "tool_call", "call_id": cid, "cmd": cmd, "success": True, "stdout_excerpt": excerpt}
    e.update(extra)
    return e


def _grep(cid, pattern, rows, path="analysis/ws01/timeline.csv", **extra):
    return _call(cid, "<py>:table_table_grep",
                 json.dumps({"success": True, "path": path, "pattern": pattern, "hits": rows,
                             "hit_count": len(rows), "max_hits": 50, "hit_cap_reached": False}),
                 args=json.dumps({"path": path, "pattern": pattern}), **extra)


L2T_ROW = {"date": "03/04/2031", "time": "09:12:49", "timezone": "UTC", "source": "FILE", "sourcetype": "Bodyfile",
           "host": "corp-ws01", "desc": "C:\\Users\\Public\\dropper.exe Owner identifier: 0"}


def supports(stmt, calls, **kw):
    return cs.citation_supports(stmt, calls, tool_calls=calls, hosts=HOSTS, **kw)


def test_an_l2tcsv_row_with_the_file_and_the_moment_supports_the_claim():
    call = _grep(12, r"dropper\.exe", [L2T_ROW])
    assert supports("dropper.exe was created on CORP-WS01 at 2031-03-04 09:12:49 UTC", [call]) is True
    # The entity and the time must share a row.
    split = _grep(13, r"dropper\.exe", [{**L2T_ROW, "time": "11:00:00"},
                                       {**L2T_ROW, "desc": "C:\\Windows\\notepad.exe", "time": "09:12:49"}])
    assert supports("dropper.exe was created at 2031-03-04 09:12", [split]) is False
    # A claim with a time the row does not carry is not shown by it.
    assert supports("dropper.exe was created at 2031-03-04 10:30", [call]) is False


def test_a_zero_row_grep_echoing_the_pattern_shows_nothing():
    call = _grep(14, r"203\.0\.113\.7", [])
    assert supports("the host reached 203.0.113.7", [call]) is False
    shown = _grep(15, r"203\.0\.113\.7", [{"ts": "2031-03-04 09:20:00", "dst": "203.0.113.7:443"}])
    assert supports("the host reached 203.0.113.7", [shown]) is True


def test_event_ids_match_in_an_event_id_position_only():
    stmt = "EID 1149 shows a remote connection"
    assert supports(stmt, [_call(1, "cat evidence/x.log", "record number: 114905 logon")]) is False
    assert supports(stmt, [_call(2, "cat evidence/x.log", "event id 1149 remote desktop services")]) is True
    assert supports(stmt, [_grep(3, "1149", [{"EventId": 1149, "Computer": "CORP-WS01"}])]) is True
    assert supports(stmt, [_grep(4, "1149", [{"ProcessId": 1149, "Message": "service started"}])]) is False
    assert supports(stmt, [_call(5, "cat evidence/x.log", "[1149 / 0x047d] Remote Desktop Services")]) is True


def test_host_affinity_from_the_evidence_path(tmp_path, monkeypatch):
    from core import provenance
    from core.execution_log import ExecutionLog
    case = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (case / sub).mkdir(parents=True)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"},
        {"label": "CORP-WS02", "path": "evidence/ws02", "kind": "folder"}], "hosts": HOSTS}))
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    provenance.reset_cache()
    row = {"TimeCreated": "2031-03-04 09:12:00", "Computer": "ws02", "Message": "dropper.exe started"}
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"path": "evidence/ws02/sec.csv", "hits": [row]}),
                               evidence_ref="evidence/ws02/sec.csv")
    log.annotate_tool_call(cid, args=json.dumps({"path": "evidence/ws02/sec.csv", "pattern": "dropper"}))
    entry = log.index().by_call_id[cid]
    assert cs.citation_supports("dropper.exe ran on CORP-WS01", [entry], tool_calls=[entry], hosts=HOSTS) is False
    assert cs.citation_supports("dropper.exe ran on CORP-WS01 and CORP-WS02", [entry], tool_calls=[entry],
                                hosts=HOSTS) is True
    assert cs.citation_supports("dropper.exe ran", [entry], tool_calls=[entry], hosts=HOSTS) is True
    # Host labels compare case-insensitively on both sides.
    assert cs.citation_supports("dropper.exe ran on corp-ws02", [entry], tool_calls=[entry],
                                hosts=["corp-ws01", "corp-ws02"]) is True


def test_account_forms_match_across_domain_and_mail_spellings():
    row = _grep(6, "jane", [{"ts": "2031-03-04 09:12:00", "user": "corp.example.com\\jane.doe"}])
    assert supports("CORP\\jane.doe logged on", [row]) is True
    mail = _grep(7, "jane", [{"ts": "2031-03-04 09:12:00", "user": "CORP\\jane.doe"}])
    assert supports("jane.doe@corp.example.com logged on", [mail]) is True
    at_form = _grep(16, "jane", [{"ts": "2031-03-04 09:12:00", "user": "jane.doe@corp.example.com"}])
    assert supports("CORP\\jane.doe logged on", [at_form]) is True


def test_a_bare_user_name_or_a_profile_path_is_not_an_account_sighting():
    bare = _grep(17, "jane", [{"ts": "2031-03-04 09:12:00", "msg": "service jane.doe started"}])
    assert supports("CORP\\jane.doe logged on", [bare]) is False
    profile = _grep(18, "jane", [{"ts": "2031-03-04 09:12:00", "path": "C:\\Users\\jane.doe\\NTUSER.DAT"}])
    assert supports("CORP\\jane.doe logged on", [profile]) is False
    other_domain = _grep(19, "jane", [{"ts": "2031-03-04 09:12:00", "user": "OTHER\\jane.doe"}])
    assert supports("CORP\\jane.doe logged on", [other_domain]) is False


def test_the_file_a_grep_was_pointed_at_is_not_shown_by_its_command():
    call = _grep(8, r"logon", [{"ts": "2031-03-04 09:12:00", "msg": "logon ok"}], path="analysis/ws01/Security.csv")
    assert supports("Security.csv holds the logons", [call]) is False
    # A trace entry whose args hold the pattern still lets the rows show the
    # file the pattern names.
    named = _grep(9, r"dropper\.exe", [L2T_ROW])
    assert supports("dropper.exe was created", [named]) is True


def test_a_claim_naming_nothing_checkable_is_not_judged():
    call = _call(10, "cat evidence/x.log", "anything at all")
    assert supports("the archive could not be opened", [call]) is None
    assert supports("the process migration was observed", [call]) is None


def test_the_fallback_needs_name_host_and_time_in_one_row():
    stmt = "The task Updater-Sync ran on CORP-WS01 at 2031-03-04 09:12"
    assert supports(stmt, [_call(11, "cat evidence/ws01/tasks.log",
                                 "2031-03-04 09:12:03 corp-ws01 Task Scheduler started Updater-Sync")]) is True
    assert supports(stmt, [_call(12, "cat evidence/ws01/tasks.log", "Updater-Sync corp-ws01")]) is False
    assert supports(stmt, [_call(13, "cat evidence/ws01/tasks.log", "2031-03-04 09:12:03 Updater-Sync")]) is False


def test_one_fixture_one_verdict(monkeypatch):
    """The same call gives the same answer to citation_supports, the external
    knowledge gate's reader and the indicator reader: a family name only in
    the grep pattern is printed for none of them."""
    from types import SimpleNamespace
    from core import indicators as I
    from tools._gates.external_knowledge_grounding import _cited_tool_text
    call = _grep(20, r"ExampleRAT|203\.0\.113\.7", [{"ts": "2031-03-04 09:12:00", "dst": "203.0.113.7:443"}])
    assert supports("the ExampleRAT beacon reached 203.0.113.7", [call]) is True
    ctx = SimpleNamespace(idx=SimpleNamespace(by_call_id={20: call}), input_call_ids=[20], linked_call_id=0)
    printed = _cited_tool_text(ctx)
    assert "examplerat" not in printed.lower() and "203.0.113.7" in printed
    assert I.printed_text(call) == printed
    assert cs.call_output_text(call) == printed


def test_the_locator_finds_a_call_far_back_and_ranks_by_what_it_shows():
    calls = [_call(i, f"cat evidence/f{i}.log", "nothing here") for i in range(2, 402)]
    calls.insert(0, _grep(1, r"dropper\.exe", [L2T_ROW]))
    calls.append(_grep(402, r"dropper\.exe", [{"ts": "2031-03-05 10:00:00", "desc": "dropper.exe"}]))
    found = cs.locate("dropper.exe was created at 2031-03-04 09:12", calls, HOSTS)
    assert found == [1]
    found = cs.locate("dropper.exe was created", calls, HOSTS)
    assert found == [402, 1]
    assert cs.locate("dropper.exe was created", calls, HOSTS, exclude=[402]) == [1]


def test_citation_status_names_the_one_status():
    shown = _grep(30, r"dropper\.exe", [L2T_ROW])
    other = _call(31, "cat evidence/y.log", "nothing relevant")
    reason = {"type": "reason_call", "call_id": 32, "cmd": "<py>:reason_hypothesize", "stdout_excerpt": "dropper.exe"}
    stmt = "dropper.exe was created at 2031-03-04 09:12"
    assert cs.citation_status(stmt, [shown], [], "", [shown, other], hosts=HOSTS) == ("cited", [], "")
    assert cs.citation_status(stmt, [other], [], "", [shown, other], hosts=HOSTS) == ("located", [30], "")
    assert cs.citation_status(stmt, [other], [], "", [other], hosts=HOSTS) == ("not_shown", [], "")
    assert cs.citation_status(stmt, [reason], [], "", [other, reason], hosts=HOSTS) == ("own_words", [], "")
    assert cs.citation_status("the archive could not be opened", [other], [], "", [other], hosts=HOSTS) == ("not_checkable", [], "")


def test_rows_off_restores_the_anchor_test(monkeypatch):
    monkeypatch.setenv("ATLAS_CITATION_ROWS", "0")
    call = _call(40, "cat evidence/x.log", "anything at all")
    assert supports("the archive could not be opened", [call]) is True
    assert cs._wiring_on() is False
    monkeypatch.setenv("ATLAS_CITATION_ROWS", "1")
    assert cs._wiring_on() is True


def test_a_flagged_statement_is_judged_by_rows_first_and_located():
    """A positive claim with a caveat or a universal word is judged by its
    rows before the absence branch, and located when its citation does not
    show it; a genuine absence with no strong entity is never located."""
    shown = _grep(40, r"dropper\.exe", [L2T_ROW])
    other = _call(41, "cat evidence/y.log", "nothing relevant")
    caveat = "dropper.exe was created at 2031-03-04 09:12; no persistence was found"
    assert cs.is_absence_claim(caveat)
    assert supports(caveat, [shown]) is True
    assert cs.locate(caveat, [shown, other], HOSTS) == [40]
    assert cs.citation_status(caveat, [other], [], "", [shown, other], hosts=HOSTS) == ("located", [40], "")
    absence = "no persistence mechanism was found"
    assert cs.locate(absence, [shown, other], HOSTS) == []
    assert cs.citation_status(absence, [other], [], "", [shown, other], hosts=HOSTS)[0] == "not_shown"


def test_a_claim_naming_only_the_file_its_cited_call_read_is_not_checkable(tmp_path, monkeypatch):
    from core import provenance
    from core.execution_log import ExecutionLog
    case = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence/ws01", ".atlas"):
        (case / sub).mkdir(parents=True)
    (case / "evidence" / "ws01" / "archive.zip").write_text("x")
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    provenance.reset_cache()
    cid = log.record_tool_call("unzip -l evidence/ws01/archive.zip", True, False, 0, 0,
                               stdout_excerpt="invoice.docx\nplan.xlsx")
    read = log.index().by_call_id[cid]
    stmt = "archive.zip holds documents"
    assert cs.citation_status(stmt, [read], [], "", [read], hosts=HOSTS, case_dir=str(case)) == (
        "not_checkable", [], cs.READ_FILE_DETAIL)
    assert cs.locate(stmt, [read], HOSTS, case_dir=str(case)) == []


def test_an_absence_grounded_by_its_cited_search_stays_cited_beside_a_contradicting_row():
    """The cited complete search is judged before any other call's row: a
    row elsewhere holding what the absence calls missing must not relabel
    the finding as located."""
    search = _call(50, "find evidence/ws01/fs -iname dropper.exe", "find: search finished, 0 matches")
    row = _grep(51, r"Temp", [{"ts": "2031-03-04 09:12:00", "path": "C:\\Temp\\dropper.exe"}],
                path="analysis/ws02/mft.csv")
    stmt = "No file named dropper.exe exists on CORP-WS01"
    assert cs.citation_status(stmt, [search], [], "CORP-WS01", [search], hosts=HOSTS) == ("cited", [], "")
    assert cs.citation_status(stmt, [search], [], "CORP-WS01", [search, row], hosts=HOSTS) == ("cited", [], "")


def test_the_read_paths_memo_follows_the_evidence_links(tmp_path, monkeypatch):
    """The hosts behind a call's paths are read again once the case's
    evidence links change."""
    from core import provenance
    from core.execution_log import ExecutionLog
    case = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence/ws02", ".atlas"):
        (case / sub).mkdir(parents=True)
    links = case / ".atlas" / "evidence_links.json"
    links.write_text(json.dumps({"entries": [{"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"}]}))
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    provenance.reset_cache()
    cid = log.record_tool_call("cat evidence/ws02/sec.log", True, False, 0, 0, stdout_excerpt="x")
    entry = log.index().by_call_id[cid]
    assert cs._read_paths(entry, str(case))[1] == frozenset()
    links.write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"},
        {"label": "CORP-WS02", "path": "evidence/ws02", "kind": "folder"}]}))
    assert cs._read_paths(entry, str(case))[1] == frozenset({"corp-ws02"})


def test_the_fallback_name_needs_an_identifier_shape():
    """A plain capitalised word is prose: it never stands for a name that,
    with a minute time, locates a claim. A name carries a hyphen, an
    underscore, a dot, a dollar sign or a digit; a clock range is split."""
    names = cs.claim_terms("Malicious Activity was seen on CORP-WS01 at 2031-03-04 09:12", HOSTS)["names"]
    assert names == set()
    names = cs.claim_terms("The task Updater-Sync and svc_backup ran at 10:16-10:48 on CORP-WS01, "
                           "after Win-10 setup", HOSTS)["names"]
    assert names == {"updater-sync", "svc_backup"}
    row = "2031-03-04 09:12:03 corp-ws01 Malicious Activity summary"
    assert supports("Malicious Activity was seen on CORP-WS01 at 2031-03-04 09:12",
                    [_call(20, "cat evidence/ws01/notes.log", row)]) is None


def test_an_event_id_column_header_is_the_key_for_its_rows():
    """A count table whose header names the event-id field shows the id in
    that column; a bare number elsewhere (a process id) does not, and a
    file-system entry "r/r <id>-128-4" never does."""
    stmt = "EID 4624 logons were counted on CORP-WS01"
    as_json = _call(21, "cat evidence/ws01/counts.json",
                    json.dumps({"success": True, "columns": ["EventID", "Count"], "rows": [[4624, 12], [4625, 3]]}))
    assert supports(stmt, [as_json]) is True
    as_text = _call(22, "cat evidence/ws01/counts.tsv", "EventID\tCount\n4624\t12\n4625\t3\n")
    assert supports(stmt, [as_text]) is True
    pid = _call(23, "cat evidence/ws01/procs.json",
                json.dumps({"success": True, "columns": ["Pid", "Count"], "rows": [[4624, 12]]}))
    assert supports(stmt, [pid]) is False
    wrong_column = _call(24, "cat evidence/ws01/counts.tsv", "EventID\tCount\n4625\t4624\n")
    assert supports(stmt, [wrong_column]) is False
    mft = _call(25, "fls -r evidence/ws01.E01", "r/r 4624-128-4:\tUsers/jane.doe/notes.txt\n")
    assert supports(stmt, [mft]) is False



def test_an_event_id_header_after_summary_lines_keys_the_table_under_it():
    """The header row may stand after preamble lines; the rows under it are
    keyed until the table ends (a row with another number of cells)."""
    stmt = "EID 4624 logons were counted on CORP-WS01"
    text = ("Security log summary for CORP-WS01\nrecords read: 4624\n"
            "event id\tcount\n4625\t3\n4624\t12\n"
            "done in 4624 ms\n")
    assert supports(stmt, [_call(26, "cat evidence/ws01/summary.txt", text)]) is True
    rows, eid_rows = cs.call_view(_call(27, "cat evidence/ws01/summary.txt", text))
    keyed = [rows[i] for i in sorted(eid_rows)]
    assert keyed == ["4625\t3", "4624\t12"]
    # The preamble's "records read: 4624" and the trailer are not event ids.
    pre = _call(28, "cat evidence/ws01/summary.txt", "records read: 4624\nevent id\tcount\n4625\t3\ndone 4624 ms\n")
    assert supports(stmt, [pre]) is False
