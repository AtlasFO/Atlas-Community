"""One identity for "this file of the evidence", whatever form a call wrote
it in (core.evidence_identity), and whole argument paths with spaces.
Invented fixtures only (CORP-WS01, jane.doe, 2031)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import core.execution_log as elog
from core import contents_index as ci
from core.evidence_identity import argument_paths, folder_files, identify

IMG = "evidence/disk/corp-ws01.raw"


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_CONTENTS_INDEX", "1")
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis/extracted/CORP-WS01/Logs", "mnt/CORP-WS01"):
        (root / d).mkdir(parents=True)
    (root / IMG).write_bytes(b"\0" * 512)
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / IMG), "media_role": "disk", "action": "plan_only",
         "image_type": "raw_or_container"}]}), encoding="utf-8")
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    con = ci._connect(root, create=True)
    rows = [{"path": "Windows/System32/winevt/Logs/Security.evtx", "name": "Security.evtx", "inode": "200-128-1",
             "volume": 2048},
            {"path": "Windows/System32/winevt/Logs/Security.evtx", "name": "Security.evtx", "inode": "200-128-1",
             "volume": 206848},
            {"path": "Users/jane.doe/Root - Mailbox/Inbox.txt", "name": "Inbox.txt", "inode": "300-128-1",
             "volume": 206848}]
    ci._insert_entries(con, "CORP-WS01", IMG, rows, "image")
    ci._meta_set(con, f"image:{IMG}", {"listed": 1, "complete": 1, "host": "CORP-WS01",
                                       "volumes": [2048, 206848], "readable": "mnt/CORP-WS01/disk"})
    con.commit()
    ids = {(r[1], r[0]) for r in con.execute("SELECT id, volume FROM entries")}
    con.close()
    return root, {vol: eid for vol, eid in ids}


def _entry(root, vol, path):
    with ci._connect(root) as con:
        return con.execute("SELECT id FROM entries WHERE volume = ? AND path = ?", (vol, path)).fetchone()[0]


def test_a_handle_names_its_entry_and_without_an_offset_every_volume_or_none(case):
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    a, b = _entry(root, 2048, sec), _entry(root, 206848, sec)
    assert identify(root, f"{IMG}@206848::{sec}") == {("entry", b)}
    assert identify(root, f"{IMG}::{sec}") == {("entry", a), ("entry", b)}       # never the first alone
    assert identify(root, f"{IMG}::Windows/nothing.txt") == frozenset()


def test_a_copy_the_readable_form_and_an_icat_argument_list_name_the_entry(case):
    root, _ = case
    inbox = _entry(root, 206848, "Users/jane.doe/Root - Mailbox/Inbox.txt")
    copy = root / "analysis/extracted/CORP-WS01/Inbox.txt"
    copy.write_text("x", encoding="utf-8")
    ci.record_copy(root, str(copy), inbox, 7, 1)
    assert identify(root, "analysis/extracted/CORP-WS01/Inbox.txt") == {("entry", inbox),
                                                                         ("file", "analysis/extracted/CORP-WS01/Inbox.txt")}
    assert identify(root, "mnt/CORP-WS01/disk/Users/jane.doe/Root - Mailbox/Inbox.txt") == {("entry", inbox)}
    assert identify(root, f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1") == {("entry", inbox)}
    assert identify(root, f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300") == {("entry", inbox)}


def test_a_case_folder_names_its_copies_else_its_files_and_the_root_names_nothing(case):
    root, _ = case
    sec = _entry(root, 2048, "Windows/System32/winevt/Logs/Security.evtx")
    logs = root / "analysis/extracted/CORP-WS01/Logs"
    (logs / "Security.evtx").write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(logs / "Security.evtx"), sec, 8, 8)
    assert identify(root, "analysis/extracted/CORP-WS01/Logs") == {("entry", sec)}
    (root / "analysis/notes").mkdir()
    (root / "analysis/notes/a.txt").write_text("a", encoding="utf-8")
    assert identify(root, "analysis/notes") == {("file", "analysis/notes/a.txt")}
    assert identify(root, ".") == frozenset() and identify(root, str(root)) == frozenset()
    assert folder_files(root, "analysis/notes", bound=0) == ([], 1)


def test_an_argument_path_with_a_space_is_one_path():
    entry = {"cmd": "<py>:strings_read_text",
             "args": json.dumps({"file_path": "analysis/ost_export/Root - Mailbox/Inbox/Message00003/Outlook.txt",
                                 "grep": "From|To"})}
    assert argument_paths(entry) == ["analysis/ost_export/Root - Mailbox/Inbox/Message00003/Outlook.txt"]


def test_provenance_reads_the_whole_spaced_path(case, monkeypatch):
    from core import provenance
    root, _ = case
    f = root / "analysis/ost_export/Root - Mailbox/Inbox/Outlook.txt"
    f.parent.mkdir(parents=True)
    f.write_text("x", encoding="utf-8")
    entry = {"cmd": "<py>:strings_read_text", "args": json.dumps({"file_path": str(f.relative_to(root))})}
    toks = provenance.path_tokens(entry, root)
    assert "analysis/ost_export/Root - Mailbox/Inbox/Outlook.txt" in toks
    assert not any(t.endswith("/Root") for t in toks)


def test_the_command_lines_cut_copy_of_a_spaced_path_is_dropped(case):
    from core import provenance
    root, _ = case
    f = root / "analysis/extracted/CORP-WS01/Logs/Windows PowerShell.evtx"
    f.write_bytes(b"ElfFile\0")
    entry = {"cmd": f"dotnet EvtxECmd.dll -f {f} --csv {root}/analysis/out",
             "args": json.dumps({"evtx_path": str(f)})}
    toks = provenance.path_tokens(entry, root)
    assert str(f) in toks and not any(t.endswith("/Logs/Windows") for t in toks)


def test_an_unquoted_spaced_path_in_the_command_line_is_read_whole(case):
    """The argument was a handle the toolbox resolved to a copy; the command
    line holds the copy's path unquoted with its space."""
    from core import provenance
    root, _ = case
    f = root / "analysis/extracted/CORP-WS01/Logs/Windows PowerShell.evtx"
    f.write_bytes(b"ElfFile\0")
    entry = {"cmd": f"dotnet EvtxECmd.dll -f {f} --csv {root}/analysis/out",
             "args": json.dumps({"evtx_path": f"{IMG}::Windows/System32/winevt/Logs/Windows PowerShell.evtx"})}
    toks = provenance.path_tokens(entry, root)
    assert str(f) in toks and not any(t.endswith("/Logs/Windows") for t in toks)


# ── the resolver's cost and the one reader of a call ─────────────

def test_a_lookup_inside_an_image_uses_the_host_path_index(case):
    root, _ = case
    from core.evidence_identity import AT_SQL
    with ci._connect(root) as con:
        plan = " ".join(str(r[-1]) for r in con.execute("EXPLAIN QUERY PLAN " + AT_SQL + " AND volume IS ?",
                                                         ("CORP-WS01", "Windows/x", IMG, 2048)))
    assert "entries_host_path" in plan


def _call(cid, cmd, tool, args=None, **kw):
    return {"type": "tool_call", "call_id": cid, "cmd": cmd, "mcp_tool": tool, "success": True,
            "args": json.dumps(args) if args else None, **kw}


def test_call_reads_splits_content_listed_processed_and_names_the_images(case, monkeypatch):
    from core import evidence_identity as ei
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    a, b = _entry(root, 2048, sec), _entry(root, 206848, sec)
    inbox = _entry(root, 206848, "Users/jane.doe/Root - Mailbox/Inbox.txt")
    # icat's argument list on the readable form: the entry, and the image named in-image
    r = ei.call_reads(root, _call(1, f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", "tsk_icat"))
    assert ("entry", inbox) in r["content"] and IMG in r["images"]
    # an offset-less handle on two volumes credits no content
    r = ei.call_reads(root, _call(2, "<py>:strings_read_text", "strings_read_text", {"path": f"{IMG}::{sec}"}))
    assert r["content"] == frozenset() and {("entry", a), ("entry", b)} <= r["listed"]
    # a copy is read by its entry and names no image; the call's output is no input
    copy = root / "analysis/extracted/CORP-WS01/Logs/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), b, 8, 8)
    out = root / "analysis/out.csv"
    out.write_text("x", encoding="utf-8")
    r = ei.call_reads(root, _call(3, "<py>:strings_read_text", "strings_read_text",
                                  {"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx",
                                   "output_file": "analysis/out.csv"}))
    assert r["content"] == {("entry", b), ("file", "analysis/extracted/CORP-WS01/Logs/Security.evtx")}
    assert r["images"] == frozenset()
    assert ("file", "analysis/out.csv") not in r["content"] | r["listed"]
    # a parser's own report: processed, never content
    r = ei.call_reads(root, _call(4, "<py>:ez_evtxecmd", "ez_evtxecmd",
                                  processed={"output": "analysis/out.csv", "filter": "", "files": [
                                      {"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx", "rows": 3}]}))
    assert ("entry", b) in r["processed"] and r["content"] == frozenset()


def test_a_folder_the_bound_stops_is_listed_and_says_n_of_m(case, monkeypatch):
    from core import evidence_identity as ei
    ei.reset_cache()
    root, _ = case
    d = root / "analysis/notes"
    d.mkdir()
    for n in range(3):
        (d / f"{n}.txt").write_text("a", encoding="utf-8")
    monkeypatch.setattr(ei, "FOLDER_BOUND", 2)
    r = ei.call_reads(root, _call(5, "<py>:strings_read_text", "strings_read_text", {"path": "analysis/notes"}))
    assert r["content"] == frozenset() and len(r["listed"]) == 2
    assert r["cut"] == (("analysis/notes", 2, 3),)


def test_call_reads_answers_a_second_time_from_its_memo(case, monkeypatch):
    from core import evidence_identity as ei
    ei.reset_cache()
    root, _ = case
    e = _call(6, "<py>:strings_read_text", "strings_read_text", {"path": f"{IMG}@2048::Windows/System32/winevt/Logs/Security.evtx"})
    first = ei.call_reads(root, e)
    calls = []
    monkeypatch.setattr(ei, "_call_reads", lambda *a: calls.append(a) or {})
    assert ei.call_reads(root, e) == first and calls == []


# ── an artifact the case can name is read by its identity ───

def test_an_entry_read_only_through_icat_is_read_and_its_twin_on_another_volume_is_not(case):
    from core import evidence_identity as ei
    from core.artifact_value import examined_items
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    a, b = _entry(root, 2048, sec), _entry(root, 206848, sec)
    inbox = _entry(root, 206848, "Users/jane.doe/Root - Mailbox/Inbox.txt")
    elog.log.record_tool_call(cmd=f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", success=True,
                              truncated=False, retries=0, exit_code=0)
    elog.log.record_tool_call(cmd=f"icat -o 206848 {root}/mnt/CORP-WS01/disk 200-128-1", success=True,
                              truncated=False, retries=0, exit_code=0)
    items = [{"name": "Inbox.txt", "lpath": "Users/jane.doe/Root - Mailbox/Inbox.txt", "host": "CORP-WS01",
              "index_id": inbox, "kind": "file"},
             {"name": "Security.evtx", "lpath": sec, "host": "CORP-WS01", "index_id": b, "kind": "file"},
             {"name": "Security.evtx", "lpath": sec, "host": "CORP-WS01", "index_id": a, "kind": "file"}]
    assert examined_items(root, items) == [True, True, False]


def test_a_read_through_one_volumes_handle_does_not_read_the_same_path_on_another(case):
    """The text names the inner path both volumes hold; only the volume the
    handle names was read."""
    from core import evidence_identity as ei
    from core.artifact_value import examined_items
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    a, b = _entry(root, 2048, sec), _entry(root, 206848, sec)
    cid = elog.log.record_tool_call(cmd="<py>:strings_read_text", success=True, truncated=False, retries=0,
                                    exit_code=0)
    elog.log.annotate_tool_call(cid, mcp_tool="strings_read_text",
                                args=json.dumps({"path": f"{IMG}@206848::{sec}"}))
    items = [{"name": "Security.evtx", "lpath": sec, "host": "CORP-WS01", "index_id": i, "kind": "file"}
             for i in (b, a)]
    assert examined_items(root, items) == [True, False]


# ── the coverage ledger reaches a unit by what the call read ─

def test_an_icat_on_the_readable_form_reaches_the_image_and_a_copy_parse_does_not(case):
    from core import evidence_identity as ei
    from core.coverage_ledger import _calls_reaching, build_coverage_ledger, load_ledger, observe_tool_paths
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    build_coverage_ledger(root)
    copy = root / "analysis/extracted/CORP-WS01/Logs/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), _entry(root, 206848, sec), 8, 8)
    parse = {"call_id": 21, "type": "tool_call", "success": True, "mcp_tool": "strings_read_text",
             "cmd": "<py>:strings_read_text",
             "args": json.dumps({"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx"})}
    icat = {"call_id": 22, "type": "tool_call", "success": True, "mcp_tool": "tsk_icat",
            "cmd": f"icat -o 206848 {root}/mnt/CORP-WS01/disk 200-128-1"}
    assert [e["call_id"] for e in _calls_reaching(root, IMG, [parse, icat])] == [22]
    # live, from the typed arguments: the readable form reaches the image unit
    observe_tool_paths(root, tool_name="tsk_icat", success=True,
                       cmd_or_args=json.dumps({"image": f"{root}/mnt/CORP-WS01/disk", "inode": "200-128-1",
                                               "offset": 206848}))
    unit = next(u for u in load_ledger(root)["units"].values() if u.get("path") == IMG)
    assert unit["status"] == "probed"


# ── an evidence item is credited by what the call read ───────

def test_an_icat_on_the_readable_form_examines_the_image_item_and_a_copy_parse_does_not(case):
    from core import evidence_identity as ei
    from core.coverage_ledger import build_coverage_ledger, load_ledger, observe_tool_paths
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    build_coverage_ledger(root)
    copy = root / "analysis/extracted/CORP-WS01/Logs/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), _entry(root, 206848, sec), 8, 8)
    observe_tool_paths(root, tool_name="strings_read_text", success=True,
                       cmd_or_args=json.dumps({"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx"}))
    assert load_ledger(root)["items"][IMG]["status"] == "unseen"
    observe_tool_paths(root, tool_name="tsk_icat", success=True,
                       cmd_or_args=json.dumps({"image": f"{root}/mnt/CORP-WS01/disk", "inode": "200-128-1",
                                               "offset": 206848}))
    item = load_ledger(root)["items"][IMG]
    assert item["status"] == "examined" and item["read_by"]["tool"] == "tsk_icat"


def test_a_search_over_a_folder_probes_no_unit_below_it(case):
    from core import evidence_identity as ei
    from core.coverage_ledger import build_coverage_ledger, is_probe_tool, load_ledger, observe_tool_paths
    ei.reset_cache()
    root, _ = case
    (root / "evidence/logs").mkdir()
    (root / "evidence/logs/auth.csv").write_text("TimeCreated,EventId,UserName\n2031-01-01T00:00:00Z,4624,jane.doe\n",
                                                 encoding="utf-8")
    build_coverage_ledger(root)
    assert is_probe_tool("strings_grep")
    observe_tool_paths(root, tool_name="strings_grep", success=True,
                       cmd_or_args=json.dumps({"path": "evidence/logs", "pattern": "boot"}))
    unit = next(u for u in load_ledger(root)["units"].values() if u.get("path") == "evidence/logs/auth.csv")
    assert unit["status"] == "unseen"
    observe_tool_paths(root, tool_name="strings_grep", success=True,
                       cmd_or_args=json.dumps({"path": "evidence/logs/auth.csv", "pattern": "boot"}))
    unit = next(u for u in load_ledger(root)["units"].values() if u.get("path") == "evidence/logs/auth.csv")
    assert unit["status"] == "probed"


# ── the work order reaches a target by what the call read ────

def _traced(cmd, tool, args=None, **extra):
    cid = elog.log.record_tool_call(cmd=cmd, success=True, truncated=False, retries=0, exit_code=0)
    elog.log.annotate_tool_call(cid, mcp_tool=tool, **({"args": json.dumps(args)} if args else {}), **extra)
    return cid


def test_an_icat_on_the_readable_form_reads_a_planned_target_after_the_fact(case):
    """The trace's own record of an icat (no arguments kept) reads the item's
    target: the recount finds the same read the live close found."""
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, _ = case
    item = elog.log.add_work_item("director", ["task-0001"], "tsk_icat",
                                  {"path": IMG, "inner_path": "Users/jane.doe/Root - Mailbox/Inbox.txt"}, "x")
    cid = _traced(f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", "tsk_icat")
    assert W.later_reads(elog.log, str(root), [item]) == {item["call_id"]: cid}
    assert W.counted_due(elog.log, str(root)) == []


def test_a_target_parsed_before_it_was_planned_says_so_with_the_parses_filter(case):
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, _ = case
    sec = "Windows/System32/winevt/Logs/Security.evtx"
    copy = root / "analysis/extracted/CORP-WS01/Logs/Security.evtx"
    copy.write_bytes(b"ElfFile\0")
    ci.record_copy(root, str(copy), _entry(root, 206848, sec), 8, 8)
    cid = _traced("dotnet EvtxECmd.dll -d analysis/extracted/CORP-WS01/Logs", "ez_evtxecmd",
                  {"directory": "analysis/extracted/CORP-WS01/Logs"},
                  processed={"output": "analysis/out.csv", "filter": "event ids 4624", "files": [
                      {"path": "analysis/extracted/CORP-WS01/Logs/Security.evtx", "rows": 3}]})
    item = elog.log.add_work_item("director", ["task-0001"], "ez_evtxecmd",
                                  {"path": IMG, "inner_path": sec, "handle": f"{IMG}@206848::{sec}"}, "x")
    # A new item is born closed by the earlier parse; one stored by a run
    # whose matcher missed the read says when it was read.
    assert item["status"] == "resolved" and item["basis_call_id"] == cid
    item.update(status="moot", basis_call_id=None, outcome="")
    assert W.counted_due(elog.log, str(root)) == []
    line = next(ln for ln in W.report_lines(elog.log, str(root)) if f"#{item['call_id']} " in ln)
    assert line.endswith(f"parsed with event ids 4624 by call {cid} before it was planned")


def test_a_failed_item_read_later_says_so(case):
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, _ = case
    item = elog.log.add_work_item("director", ["task-0001"], "tsk_icat",
                                  {"path": IMG, "inner_path": "Users/jane.doe/Root - Mailbox/Inbox.txt"}, "x")
    bad = elog.log.record_tool_call(cmd=f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", success=False,
                                    truncated=False, retries=0, exit_code=1, stderr="read error",
                                    failure_class="tool_error")
    elog.log.annotate_tool_call(bad, mcp_tool="tsk_icat")
    elog.log.close_items_for_call("tsk_icat", {}, [elog.log.index().by_call_id[bad]])
    assert item["status"] == "failed"
    good = _traced(f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", "tsk_icat")
    line = next(ln for ln in W.report_lines(elog.log, str(root)) if f"#{item['call_id']} " in ln)
    assert line.endswith(f"read by call {good} after it failed")


def test_a_stored_target_whose_inner_path_is_a_handle_or_the_image_itself_is_read_as_such(case):
    """Targets stored before the director's entries were made true: an inner
    path written as a handle names that file; the image itself as the inner
    path names the image (no file in it), which a read of one file does not
    reach."""
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, _ = case
    inbox = "Users/jane.doe/Root - Mailbox/Inbox.txt"
    as_handle = {"call_id": 900, "status": "moot", "origin": "director", "tool": "tsk_icat", "attempts": [],
                 "target": {"path": IMG.upper().replace("EVIDENCE", "evidence"),
                            "inner_path": f"{IMG}@206848::{inner_lower(inbox)}"}}
    whole = {"call_id": 901, "status": "moot", "origin": "director", "tool": "tsk_mactime", "attempts": [],
             "target": {"path": IMG, "inner_path": IMG}}
    cid = _traced(f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", "tsk_icat")
    view = W._call_view(elog.log.index().by_call_id[cid], case_dir=str(root))
    assert W._reach(as_handle, view, str(root)) == "read"
    assert W._reach(whole, view, str(root)) == ""


def inner_lower(p):
    return p.lower()


def test_a_file_below_a_folder_target_closes_it_only_for_the_items_own_tool(case):
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, _ = case
    item = {"call_id": 902, "status": "due", "origin": "director", "tool": "misc_parse_mailbox", "attempts": [],
            "target": {"path": IMG, "inner_path": "Users/jane.doe"}}
    other = _traced(f"icat -o 206848 {root}/mnt/CORP-WS01/disk 300-128-1", "tsk_icat")
    view = W._call_view(elog.log.index().by_call_id[other], case_dir=str(root))
    assert W._reach(item, view, str(root)) == ""
    own = _traced("<py>:misc_parse_mailbox", "misc_parse_mailbox",
                  {"path": f"{IMG}@206848::Users/jane.doe/Root - Mailbox/Inbox.txt"})
    view = W._call_view(elog.log.index().by_call_id[own], case_dir=str(root))
    assert W._reach(item, view, str(root)) == "read"


# ── icat without an offset, and the copy it writes ───────────────────────

USB = "evidence/usb01.dd"
NOTE = "jane.doe notes 2031\n"


@pytest.fixture
def usb(case):
    """An image without a partition table (its one filesystem at sector 0)
    in the same index as a second image's volume at 2048 holding the same
    inode."""
    root, _ = case
    (root / USB).write_bytes(b"\0" * 512)
    con = ci._connect(root)
    ci._insert_entries(con, "CORP-USB01", USB, [
        {"path": "jane.doe.txt", "name": "jane.doe.txt", "inode": "4", "volume": 0, "size": len(NOTE)},
        {"path": "other.txt", "name": "other.txt", "inode": "4", "volume": 2048, "size": 3}], "image")
    con.commit()
    ci._meta_set(con, f"image:{USB}", {"listed": 1, "complete": 1, "host": "CORP-USB01", "volumes": [0, 2048]})
    ids = {r[1]: r[0] for r in con.execute("SELECT id, volume FROM entries WHERE image = ?", (USB,))}
    con.commit()
    con.close()
    plan = json.loads((root / ".atlas" / "mount_plan.json").read_text(encoding="utf-8"))
    plan["images"].append({"path": str(root / USB), "media_role": "disk", "action": "plan_only",
                           "image_type": "raw_or_container"})
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps(plan), encoding="utf-8")
    return root, ids


def test_icat_without_an_offset_names_the_entry_at_sector_zero(usb):
    from core import evidence_identity as ei
    ei.reset_cache()
    root, ids = usb
    for cmd in (f"icat {USB} 4", f"icat -r {USB} 4", f"icat -f fat {USB} 4", f"/usr/bin/icat {USB} 4"):
        assert identify(root, cmd) == {("entry", ids[0])}, cmd
    assert identify(root, f"icat -o 2048 {USB} 4") == {("entry", ids[2048])}
    assert identify(root, f"fls -l {USB}; sudo icat {USB} 4") == {("entry", ids[0])}
    for cmd in (f"grep icat {USB} 4", f"fls -r {USB} 4", f"istat {USB} 4", f"ricat {USB} 4"):
        assert ("entry", ids[0]) not in identify(root, cmd), cmd


def test_a_failed_offset_less_icat_reads_nothing_in_the_recount(usb):
    """The recount reads the trace's own record: a failed icat reads no
    target, a successful one reads the entry at sector 0 only."""
    from core import evidence_identity as ei
    from core import work_order as W
    ei.reset_cache()
    root, ids = usb
    item = elog.log.add_work_item("director", ["task-0001"], "tsk_icat", {"path": USB, "inner_path": "jane.doe.txt"}, "x")
    failed = elog.log.record_tool_call(cmd=f"icat {USB} 4", success=False, truncated=False, retries=0, exit_code=1)
    elog.log.annotate_tool_call(failed, mcp_tool="tsk_icat")
    assert W.later_reads(elog.log, str(root), [item]) == {}
    cid = _traced(f"icat {USB} 4", "tsk_icat")
    assert W.later_reads(elog.log, str(root), [item]) == {item["call_id"]: cid}
    reads = ei.call_reads(root, elog.log.index().by_call_id[cid])
    assert ("entry", ids[0]) in reads["content"] and ("entry", ids[2048]) not in reads["content"]


def _icat_live(root, out, data, *, cmd=None, inode="4"):
    from core import evidence_identity as ei
    from core.coverage_ledger import observe_tool_paths
    ei.reset_cache()
    p = root / out
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8")
    args = {"image": f"{root}/{USB}", "inode": inode, "output_path": out}
    cid = _traced(cmd or f"icat {USB} {inode}", "tsk_icat", args)
    observe_tool_paths(root, tool_name="tsk_icat", success=True, cmd_or_args=json.dumps(args),
                       result_text=json.dumps({"_atlas_call_id": str(cid), "success": True}))
    return cid


def test_an_icat_output_of_the_entrys_size_is_registered_and_its_read_reads_the_entry(usb):
    import hashlib
    from core import evidence_identity as ei
    from core.coverage_ledger import build_coverage_ledger
    root, ids = usb
    build_coverage_ledger(root)
    cid = _icat_live(root, "analysis/usb/jane.doe.txt", NOTE)
    src = ci.copy_source(root, "analysis/usb/jane.doe.txt")
    assert src["entry_id"] == ids[0] and src["call_id"] == cid
    assert src["sha256"] == hashlib.sha256(NOTE.encode()).hexdigest()
    read = _traced("<py>:strings_read_text", "strings_read_text", {"path": "analysis/usb/jane.doe.txt"})
    ei.reset_cache()
    assert ("entry", ids[0]) in ei.call_reads(root, elog.log.index().by_call_id[read])["content"]


def test_no_copy_of_another_size_or_from_a_call_that_is_no_icat(usb):
    """A slack read writes another size; a transform that reads a copy of
    the entry and writes the same size is no extraction of it."""
    from core import evidence_identity as ei
    from core.coverage_ledger import build_coverage_ledger, observe_tool_paths
    root, ids = usb
    build_coverage_ledger(root)
    _icat_live(root, "analysis/usb/slack.bin", "ab", cmd=f"icat -s {USB} 4")
    assert ci.copy_source(root, "analysis/usb/slack.bin") is None
    _icat_live(root, "analysis/usb/jane.doe.txt", NOTE)
    assert ci.copy_source(root, "analysis/usb/jane.doe.txt")["entry_id"] == ids[0]
    ei.reset_cache()
    (root / "analysis/usb/decoded.txt").write_text(NOTE.swapcase(), encoding="utf-8")
    args = {"path": "analysis/usb/jane.doe.txt", "output_path": "analysis/usb/decoded.txt"}
    cid = _traced("<py>:deob_xor_decode", "deob_xor_decode", args)
    assert ("entry", ids[0]) in ei.call_reads(root, elog.log.index().by_call_id[cid], args)["content"]
    observe_tool_paths(root, tool_name="deob_xor_decode", success=True, cmd_or_args=json.dumps(args),
                       result_text=json.dumps({"_atlas_call_id": str(cid), "success": True}))
    assert ci.copy_source(root, "analysis/usb/decoded.txt") is None


def test_no_copy_of_an_entry_of_unknown_size_or_outside_the_case(usb, tmp_path):
    root, ids = usb
    from core.coverage_ledger import build_coverage_ledger
    with ci._connect(root) as con:
        con.execute("UPDATE entries SET size = NULL WHERE id = ?", (ids[0],))
    build_coverage_ledger(root)
    _icat_live(root, "analysis/usb/jane.doe.txt", NOTE)
    assert ci.copy_source(root, "analysis/usb/jane.doe.txt") is None
    with ci._connect(root) as con:
        con.execute("UPDATE entries SET size = ? WHERE id = ?", (len(NOTE), ids[0]))
    outside = tmp_path / "elsewhere" / "jane.doe.txt"
    _icat_live(root, str(outside), NOTE)
    assert ci.copy_source(root, str(outside)) is None


def test_a_copy_rewritten_by_another_writer_is_no_copy_any_more(usb):
    from core import provenance as P
    root, ids = usb
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    _icat_live(root, "analysis/usb/jane.doe.txt", NOTE)
    assert P._registered_copy(str(root), "analysis/usb/jane.doe.txt")["entry_id"] == ids[0]
    (root / "analysis/usb/jane.doe.txt").write_text(NOTE.upper(), encoding="utf-8")    # same size, other bytes
    assert P._registered_copy(str(root), "analysis/usb/jane.doe.txt") is None
    (root / "analysis/usb/jane.doe.txt").write_text("x", encoding="utf-8")
    assert P._registered_copy(str(root), "analysis/usb/jane.doe.txt") is None


def test_a_copy_above_the_per_file_bound_is_registered_by_its_size_alone(usb, monkeypatch):
    """Hashing a multi-gigabyte extraction inside the tool call is too slow:
    above the per-file input bound the copy is registered by its size and
    the record says so."""
    from core import input_scale
    from core import provenance as P
    from core.coverage_ledger import build_coverage_ledger
    root, ids = usb
    monkeypatch.setattr(input_scale, "MAX_FILE_BYTES", 4)
    build_coverage_ledger(root)
    _icat_live(root, "analysis/usb/jane.doe.txt", NOTE)
    src = ci.copy_source(root, "analysis/usb/jane.doe.txt")
    assert src["entry_id"] == ids[0] and src["sha256"] == ci.SIZE_ONLY
    (root / "analysis/usb/jane.doe.txt").write_text(NOTE.upper(), encoding="utf-8")   # same size: the size decides
    assert P._registered_copy(str(root), "analysis/usb/jane.doe.txt")["entry_id"] == ids[0]
    (root / "analysis/usb/jane.doe.txt").write_text("x", encoding="utf-8")
    assert P._registered_copy(str(root), "analysis/usb/jane.doe.txt") is None
