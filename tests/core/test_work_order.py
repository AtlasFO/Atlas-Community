"""The work order's store and closing rule: items as their own
trace entries, de-duplication by fingerprint, closing by path identity and
tool family, the two refusals that end an item, moot items of closed
questions. Invented fixtures only (CORP-WS01, jane.doe, dates in 2031)."""
from __future__ import annotations

import json

import pytest

from core import work_order as W
from core.execution_log import ExecutionLog


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    (root / "evidence" / "corp-ws01.raw").write_bytes(b"\0")
    (root / "evidence" / "corp-ws01_timeline.csv").write_text("date,time,desc\n", encoding="utf-8")
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return root, log


def _call(log, tool, args, *, ok=True, failure_class="", stderr=""):
    cid = log.record_tool_call(f"<py>:{tool}", ok, False, 0, 0 if ok else 1, stderr=stderr,
                               failure_class=failure_class, stdout_excerpt="out")
    log.annotate_tool_call(cid, args=json.dumps(args, sort_keys=True), mcp_tool=tool)
    return log.index().by_call_id[cid]


def _tasks(root, statuses):
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
        {"tasks": [{"id": t, "status": s, "text": f"question {t}"} for t, s in statuses.items()]}),
        encoding="utf-8")


IMG = "evidence/corp-ws01.raw"
CSV = "evidence/corp-ws01_timeline.csv"


def test_items_are_their_own_entries_and_never_protocol_intents(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "the log")
    assert item["type"] == "work_item" and item["status"] == "due"
    assert log.open_deferred_intents() == [] and log.deferred_backlog_status()["open"] == 0
    from core.forensic_citation import own_words_entry
    assert own_words_entry(item)
    assert item not in log.recent_actions(20)


def test_one_fingerprint_one_item(case):
    root, log = case
    a = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    b = log.add_work_item("director", ["task-0002"], "ez_evtxecmd", {"path": CSV}, "y")
    assert b is a and a["task_ids"] == ["task-0001", "task-0002"]
    p = log.add_work_item("series", [], "", None, "3 of 40 logs read", status="proposed")
    assert log.add_work_item("series", [], "", None, "3 of 40 LOGS read", status="proposed") is p
    idx = log.add_work_item("index", [], "tsk_icat", {"path": IMG, "inner_path": "C/Users/jane.doe/NTUSER.DAT"},
                            "user hive", status="proposed")
    adopted = log.add_work_item("director", ["task-0003"], "tsk_icat",
                                {"path": IMG, "inner_path": "C/Users/jane.doe/NTUSER.DAT"}, "read it")
    assert adopted is idx and idx["status"] == "due" and idx["task_ids"] == ["task-0003"]


def test_a_parser_on_the_case_file_closes_and_a_listing_does_not(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    listing = _call(log, "fs_list_dir", {"path": CSV})
    log.close_items_for_call("fs_list_dir", {"path": CSV}, [listing])
    assert item["status"] == "due" and listing["call_id"] in item["attempts"]
    read = _call(log, "strings_read_text", {"file": CSV})
    assert log.close_items_for_call("strings_read_text", {"file": CSV}, [read]) == [item["call_id"]]
    assert item["status"] == "resolved" and item["basis_call_id"] == read["call_id"]


def test_a_timeline_grep_does_not_close_a_read_of_a_raw_source(case):
    root, log = case
    item = log.add_work_item("source", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    grep = _call(log, "table_table_grep", {"path": CSV, "pattern": "jane.doe"})
    log.close_items_for_call("table_table_grep", {"path": CSV, "pattern": "jane.doe"}, [grep])
    assert item["status"] == "due"


def test_a_search_item_needs_every_term(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "table_grep",
                             {"path": CSV, "pattern": r"jane\.doe|203\.0\.113\.9"}, "x")
    one = _call(log, "table_table_grep", {"path": CSV, "pattern": "jane.doe"})
    log.close_items_for_call("table_table_grep", {"path": CSV, "pattern": "jane.doe"}, [one])
    assert item["status"] == "due"
    both = {"path": CSV, "pattern": r"jane\.doe|203\.0\.113\.9|other"}
    log.close_items_for_call("table_table_grep", both, [_call(log, "table_table_grep", both)])
    assert item["status"] == "resolved"


def test_a_failed_read_closes_as_failed_and_a_gate_refusal_is_not_an_attempt(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "tsk_icat",
                             {"path": IMG, "inner_path": "C/Users/jane.doe/NTUSER.DAT"}, "x")
    args = {"image": IMG, "path": "/Users/jane.doe/NTUSER.DAT"}
    refused = _call(log, "tsk_icat", args, ok=False, failure_class="gate_refusal")
    log.close_items_for_call("tsk_icat", args, [refused])
    assert item["status"] == "due"
    failed = _call(log, "tsk_icat", args, ok=False, failure_class="tool_error", stderr="path not found")
    log.close_items_for_call("tsk_icat", args, [failed])
    assert item["status"] == "failed" and "path not found" in item["outcome"]


def test_an_item_for_a_read_made_before_it_closes_at_creation(case):
    root, log = case
    read = _call(log, "strings_read_text", {"file": CSV})
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    assert item["status"] == "resolved" and item["basis_call_id"] == read["call_id"]
    again = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": CSV}, "x")
    assert again is item and item["status"] == "resolved"


def test_a_hint_only_source_item_closes_on_shared_trailing_segments_never_a_bare_name(case):
    root, log = case
    item = log.add_work_item("source", ["task-0001"], "strings_read_text",
                             {"source_hint": "OS:/C/Users/jane.doe/AppData/Local/Browser/History"}, "rows")
    bare = _call(log, "strings_read_text", {"file": "analysis/History"})
    log.close_items_for_call("strings_read_text", {"file": "analysis/History"}, [bare])
    assert item["status"] == "due"
    args = {"file": "analysis/extracted/Users/jane.doe/AppData/Local/Browser/History"}
    log.close_items_for_call("strings_read_text", args, [_call(log, "strings_read_text", args)])
    assert item["status"] == "resolved"


def test_the_two_refusals_of_the_items_own_call_close_it_as_failed(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "ez_evtxecmd", {"path": CSV}, "x")
    other = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": IMG + ".txt"}, "y")
    ab = log.record_call_abandoned("ez_evtxecmd", "wrong-input-kind gate: a CSV is not an event log")
    entry = log.index().by_call_id[ab]
    log.close_items_for_call("ez_evtxecmd", {"evtx_path": CSV}, [], [entry])
    assert item["status"] == "failed" and item["basis_call_id"] == ab
    assert item["outcome"].startswith("wrong-input-kind gate:")
    assert other["status"] == "due"
    ab2 = log.record_call_abandoned("strings_read_text", "discovery-first gate: list first")
    log.close_items_for_call("strings_read_text", {"file": IMG + ".txt"}, [], [log.index().by_call_id[ab2]])
    assert other["status"] == "due"


def test_a_container_item_needs_its_tool(case):
    root, log = case
    item = log.add_work_item("director", ["task-0001"], "vol_netscan", {"path": "evidence/corp-ws01.mem"}, "x")
    (root / "evidence" / "corp-ws01.mem").write_bytes(b"\0")
    ps = _call(log, "vol_pslist", {"image": "evidence/corp-ws01.mem"})
    log.close_items_for_call("vol_pslist", {"image": "evidence/corp-ws01.mem"}, [ps])
    assert item["status"] == "due"
    ns = _call(log, "vol_netscan", {"image": "evidence/corp-ws01.mem"})
    log.close_items_for_call("vol_netscan", {"image": "evidence/corp-ws01.mem"}, [ns])
    assert item["status"] == "resolved"


def test_dismiss_needs_a_basis_call_that_reached_the_target(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    unrelated = _call(log, "strings_read_text", {"file": "evidence/other.txt"})
    r = log.dispose_work_item(item["call_id"], "dismiss", unrelated["call_id"])
    assert r["ok"] is False and "refused" in r["error"] and item["status"] == "due"
    near = _call(log, "fs_list_dir", {"path": CSV})
    assert log.dispose_work_item(item["call_id"], "dismiss", near["call_id"])["ok"] is True
    assert item["status"] == "dismissed"


def test_closing_a_question_moots_its_plan_items_and_keeps_its_source_items(case):
    root, log = case
    plan = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    src = log.add_work_item("source", ["task-0001"], "strings_read_text",
                            {"source_hint": "C/Windows/System32/winevt/Logs/Security.evtx"}, "rows")
    shared = log.add_work_item("plan", ["task-0001", "task-0002"], "tsk_icat",
                               {"path": IMG, "inner_path": "C/x/y.txt"}, "z")
    part = log.add_work_item("plan", ["task-0003"], "tsk_icat", {"path": IMG, "inner_path": "C/a/b.txt"}, "p")
    _tasks(root, {"task-0001": "answered", "task-0002": "open", "task-0003": "partial"})
    W.moot_items(log, str(root))
    assert plan["status"] == "moot" and src["status"] == "due"
    assert shared["status"] == "due" and part["status"] == "due"
    again = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    assert again is not plan and again["status"] == "due"


def test_items_persist_through_a_reload(case):
    root, log = case
    item = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    read = _call(log, "strings_read_text", {"file": CSV})
    log.close_items_for_call("strings_read_text", {"file": CSV}, [read])
    again = ExecutionLog()
    again.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    got = [e for e in again._entries if e.get("type") == "work_item"]
    assert got and got[0]["status"] == "resolved" and got[0]["call_id"] == item["call_id"]


def test_the_block_shows_up_to_six_items_under_the_bound(case):
    root, log = case
    _tasks(root, {f"task-{k:04d}": "open" for k in range(1, 9)})
    for k in range(1, 9):
        log.add_work_item("plan", [f"task-{k:04d}"], "tsk_icat",
                          {"path": IMG, "inner_path": f"C/Users/jane.doe/f{k}.txt"}, "read the file " * 3)
    text, shown = W.work_order_block(log, str(root), lambda t: ["image", "inner_path"])
    assert 1 <= len(shown) <= 6 and len(text) <= W.BLOCK_CHARS + 200
    assert "more due" in text and 'tsk_icat(image="evidence/corp-ws01.raw", inner_path=' in text
    W.mark_presented(log, shown, set())
    assert all(e["presented"] == 1 and e["unattended"] == 1
               for e in log.work_items() if e["call_id"] in shown)


def test_open_questions_items_rank_before_post_close_source_items(case):
    root, log = case
    _tasks(root, {"task-0001": "answered", "task-0002": "open"})
    src = log.add_work_item("source", ["task-0001"], "strings_read_text",
                            {"source_hint": "C/Windows/System32/winevt/Logs/Security.evtx"}, "rows")
    plan = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": CSV}, "x")
    _text, shown = W.work_order_block(log, str(root), None)
    assert shown == [plan["call_id"], src["call_id"]]


def test_a_source_item_under_a_due_directory_item_is_folded(case):
    root, log = case
    _tasks(root, {"task-0001": "open"})
    d = log.add_work_item("director", ["task-0001"], "tsk_fls",
                          {"path": IMG, "host": "CORP-WS01", "inner_path": "C/Program Files/Mail/Logs"}, "logs")
    s = log.add_work_item("source", ["task-0001"], "strings_read_text",
                          {"host": "CORP-WS01", "source_hint": "C/Program Files/Mail/Logs/trk20310314.log"}, "rows")
    text, shown = W.work_order_block(log, str(root), None)
    assert shown == [d["call_id"]] and f"first read there (#{s['call_id']})" in text
    assert [i["call_id"] for i in W.counted_due(log, str(root))] == [d["call_id"]]


def test_a_refusal_in_an_earlier_session_closes_a_new_item_at_creation(case):
    root, log = case
    log.record_call_abandoned("ez_evtxecmd", "wrong-input-kind gate: a CSV is not an event log",
                              args={"evtx_path": CSV})
    item = log.add_work_item("plan", ["task-0001"], "ez_evtxecmd", {"path": CSV}, "x")
    assert item["status"] == "failed" and item["outcome"].startswith("wrong-input-kind gate:")
    other = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": IMG + ".txt"}, "y")
    assert other["status"] == "due"


def test_moot_items_report_their_ids(case):
    root, log = case
    plan = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    _tasks(root, {"task-0001": "answered"})
    assert W.moot_items(log, str(root)) == [plan["call_id"]]
    assert W.moot_items(log, str(root)) == []


def test_a_dict_priority_entry_is_read_with_its_tool_first(case):
    root, _log = case
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-WS01", "path": IMG}]}), encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    out = W.parse_director_entries({"priority_tools": [
        {"target": "CORP-WS01 C/Windows/Prefetch", "tool": "ez.pecmd"}]}, str(root))
    assert out and out[0]["tool"] == "ez_pecmd" and out[0]["status"] == "due" and out[0]["target"]["path"] == IMG


def test_the_header_lines_stand_when_no_read_is_due(case):
    root, log = case
    text, shown = W.work_order_block(log, str(root), None,
                                     header_lines=["[progress] 20 actions: 3 reads, 2 searches",
                                                   "[estate] jane.doe: 4 rows in 2 of 3 tables"])
    assert shown == [] and text == ("[progress] 20 actions: 3 reads, 2 searches\n"
                                    "[estate] jane.doe: 4 rows in 2 of 3 tables")
    assert W.work_order_block(log, str(root), None) == ("", [])


# ── the one list of open work ────────────────────────────────────────────

def _task_store(root, tasks):
    (root / ".atlas").mkdir(parents=True, exist_ok=True)
    (root / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")


def test_open_parts_list_standard_parts_for_their_umbrella_and_a_question_without_parts(tmp_path):
    from core.request_parts import ensure_parts, ensure_standard_parts
    bare = {"id": "task-0001", "status": "open", "text": "What happened? Was anything malicious?"}
    ensure_parts(bare)
    ensure_standard_parts(bare, ["CORP-WS01"])
    _task_store(tmp_path, [bare, {"id": "task-0002", "status": "open", "text": "Who is jane.doe?"},
                      {"id": "task-0003", "status": "blocked_missing_evidence", "text": "When?"}])
    got = {t["id"]: [p["id"] for p in ps] for t, ps in W.open_question_parts(str(tmp_path))}
    assert got == {"task-0001": ["s1", "s2", "s3", "s4", "s5", "s6"], "task-0002": [""]}
    work = W.open_work(None, str(tmp_path), derived=False)
    assert ("part", "task-0001", "s1") in W.open_work_keys(work) and len(W.open_work_keys(work)) == 7


def test_a_thirty_host_list_is_cut_with_its_counts_said():
    hosts = [f"CORP-WS{n:02d}" for n in range(1, 31)]
    parts = [{"id": f"s{i}", "text": f"affected on {h}", "type": "yes_no"} for i, h in enumerate(hosts * 6, 1)]
    work = {"parts": [({"id": "task-0001"}, parts)] + [({"id": f"task-{n:04d}"}, parts[:1]) for n in range(2, 11)],
            "derived": [], "due": []}
    lines = W.open_work_lines(work)
    assert lines[0].startswith("Question parts still open: read evidence for each, or limit one the evidence "
                               "cannot answer with its basis (misc.update_investigation_task)")
    assert lines[1].startswith("- task-0001: read evidence for s1 affected on CORP-WS01 (yes_no)") and lines[1].endswith(
        "; +174 more parts")
    assert lines[-1] == "- +2 more questions" and len(lines) == 10
    summary = W.open_work_summary(work)
    assert summary.startswith("Open work, which the report states as open: 189 question part(s) in 10 question(s)")
    assert "+174 more" in summary and "+2 more questions" in summary
    assert summary.endswith(f"For the parts: {W.PART_HOW}.")


# ── an item needs a target a call can reach ───────────────────────────────

def test_a_bare_tool_name_from_the_director_is_no_item_and_is_reported(case):
    root, _log = case
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-WS01", "path": IMG}]}), encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    refused: list[str] = []
    out = W.parse_director_entries({"priority_tools": ["ez.mftecmd", "tsk.mactime",
                                                       "ez.evtxecmd CORP-WS01 Windows/System32/winevt/Logs/Security.evtx"]},
                                   str(root), refused)
    assert [(o["status"], o["tool"]) for o in out] == [("due", "ez_evtxecmd")]
    assert out[0]["target"]["path"] == IMG and W.has_target(out[0]["target"])
    assert refused == [f"ez.mftecmd: {W.NOT_TRACKED}", f"tsk.mactime: {W.NOT_TRACKED}"]
    assert W.parse_director_entries({"priority_tools": ["ez.mftecmd"]}, str(root)) == []


def test_has_target_is_the_closing_rule():
    assert not W.has_target(None) and not W.has_target({}) and not W.has_target({"host": "CORP-WS01"})
    assert not W.has_target({"host": "CORP-WS01", "inner_path": "Windows/System32/config/SYSTEM"})
    assert not W.has_target({"path": "./"})
    assert W.has_target({"path": IMG}) and W.has_target({"source_hint": "NTUSER.DAT"})
    call = W._call_view({"type": "tool_call", "cmd": "<py>:ez_evtxecmd", "mcp_tool": "ez_evtxecmd",
                         "args": json.dumps({"image": IMG, "inner_path": "x"})})
    assert not W._reaches({"tool": "ez_evtxecmd", "target": {"host": "CORP-WS01", "inner_path": "x"}}, call, "")


def test_a_promote_that_leaves_no_target_is_refused_and_names_keep(case):
    root, log = case
    series = log.add_work_item("series", [], "", None, "3 of 40 logs read", status="proposed")
    r = log.dispose_work_item(series["call_id"], "promote")
    assert r["ok"] is False and "no target a call can reach" in r["error"] and r["error"].endswith("or keep")
    assert series["status"] == "proposed" and not series["target"].get("path")
    r = log.dispose_work_item(series["call_id"], "promote", target={"host": "CORP-WS01", "inner_path": "Logs/a.log"})
    assert r["ok"] is False and "plus inner_path" in r["error"]
    assert log.dispose_work_item(series["call_id"], "keep", note="later")["ok"] is True
    r = log.dispose_work_item(series["call_id"], "promote", target={"path": IMG, "inner_path": "Logs/a.log"})
    assert r["ok"] is True and series["status"] == "due" and series["target"]["path"] == IMG
    index = log.add_work_item("index", [], "", {"host": "CORP-WS01", "source_hint": "NTUSER.DAT"},
                              "the case index lists NTUSER.DAT", status="proposed")
    assert log.dispose_work_item(index["call_id"], "promote")["ok"] is True and index["status"] == "due"


def test_untracked_entries_join_the_reviews_refused_reads(case):
    root, log = case
    cid = log.record_dair_call("Collect", "", False, "", "", "stay", "", directives={"priority_tools": ["ez.mftecmd"]})
    assert W.note_untracked_entries(log, cid, [f"ez.mftecmd: {W.NOT_TRACKED}"]) is True
    assert W.note_untracked_entries(log, cid, [f"ez.mftecmd: {W.NOT_TRACKED}"]) is True
    entry = next(e for e in log._entries if e.get("type") == "dair_call" and e.get("call_id") == cid)
    assert entry["directives"]["work_items_refused"] == [f"ez.mftecmd: {W.NOT_TRACKED}"]
    assert W.note_untracked_entries(log, 999, ["x"]) is False and W.note_untracked_entries(log, cid, []) is False


def test_a_case_file_named_without_a_host_stays_a_proposal_with_its_target(case):
    """A case file whose name carries no host label, named by the director
    without a host: on a case whose links name hosts a proposal (it has a
    target, so a hosted entry adopts it by fingerprint); on a case with no
    host known, due."""
    root, _log = case
    fw = "evidence/fw_timeline.csv"
    (root / fw).write_text("date,time,desc\n", encoding="utf-8")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-WS01", "path": IMG}]}), encoding="utf-8")
    out = W.parse_director_entries({"priority_tools": [f"strings.read_text {fw}"]}, str(root))
    assert [(o["status"], o["target"]["path"]) for o in out] == [("proposed", fw)]
    assert W.has_target(out[0]["target"])
    (root / ".atlas" / "evidence_links.json").unlink()
    out = W.parse_director_entries({"priority_tools": [f"strings.read_text {fw}"]}, str(root))
    assert [(o["status"], o["target"]["path"]) for o in out] == [("due", fw)]


def test_a_target_read_after_its_question_closed_is_reported_read(case):
    """One recount for the finish and the report: a moot item whose target
    a later call read says so, and a due item a later call read is no
    longer owed (the stored word decides no line)."""
    root, log = case
    _tasks(root, {"task-0001": "open", "task-0002": "open"})
    moot = log.add_work_item("plan", ["task-0001"], "strings_read_text", {"path": CSV}, "x")
    early = log.add_work_item("plan", ["task-0003"], "strings_read_text", {"path": "evidence/notes.txt"}, "x")
    due = log.add_work_item("plan", ["task-0002"], "strings_read_text", {"path": IMG}, "x")
    first = _call(log, "strings_read_text", {"file_path": "evidence/notes.txt"})
    _call(log, "misc_update_investigation_task", {"task_id": "task-0001"})
    _call(log, "misc_update_investigation_task", {"task_id": "task-0003"})
    _tasks(root, {"task-0001": "answered", "task-0002": "open", "task-0003": "answered"})
    W.moot_items(log, str(root))
    late = _call(log, "strings_read_text", {"file_path": CSV})
    lines = W.report_lines(log, str(root))
    assert any(f"#{moot['call_id']}" in ln and f"read by call {late['call_id']} after its question closed" in ln
               for ln in lines)
    # A read before the question's close is no read "after" it.
    assert any(f"#{early['call_id']}" in ln and ln.endswith(f"read by call {first['call_id']}") for ln in lines)
    assert [i["call_id"] for i in W.counted_due(log, str(root))] == [due["call_id"]]
    read = _call(log, "strings_read_text", {"file_path": IMG})
    assert W.counted_due(log, str(root)) == []
    assert any(f"#{due['call_id']}" in ln and f"read by call {read['call_id']}" in ln
               for ln in W.report_lines(log, str(root)))


def test_the_close_out_head_names_one_next_read_by_its_path_and_reader():
    """The first file the open-work list names, verbatim, with the first
    reader the reader table gives for its class; no named file, no next
    read."""
    from core.work_order import CLOSE_OUT_HEAD, close_out_head, next_read
    carve = {"path": "analysis/carve_disk02", "made": "carve", "classes": {"gif": [0, 2], "doc": [0, 1]},
             "sample": {"gif": "analysis/carve_disk02/gif/00004400.gif", "doc": "analysis/carve_disk02/doc/a.doc"},
             "readers": {"gif": [("reader_meta", True), ("reader_two", False)]}, "left": {}, "open": ["gif", "doc"]}
    work = {"parts": [], "derived": [carve], "due": [], "refused": [], "parsed": []}
    assert next_read(work) == ("analysis/carve_disk02/gif/00004400.gif", "reader_meta")
    head = close_out_head(work)
    assert head.startswith(CLOSE_OUT_HEAD)
    assert 'Next: read "analysis/carve_disk02/gif/00004400.gif" with reader_meta.' in head
    carve["open"] = ["doc"]
    assert 'Next: read "analysis/carve_disk02/doc/a.doc". Then' in close_out_head(work)
    carve["open"] = []
    assert next_read(work) is None and "Next:" not in close_out_head(work)
