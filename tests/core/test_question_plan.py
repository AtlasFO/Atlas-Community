"""The work order's sources: the anchors from the
brief's narrative, the plan's validation, the source behind a claim's rows,
absence contradictions as items, the director's vocabulary-free parse and
the order block in the director's input. Invented fixtures only (CORP-WS04,
CORP-HUB01, CORP-SRV02, jane.doe, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import json
import re
from unittest.mock import patch

import pytest

from core import question_plan as Q
from core import work_order as W
from core.execution_log import ExecutionLog

BRIEF = """# Case: CASE-A

## Context
The first host CORP-WS04 was compromised before 2031-03-16; the hub was reached between 03/16/2031 and March 18, 2031.
An admin workstation (the word console is not a host) is out of scope.

## What you already know
- account corp\\jdoe used the tool upd.exe
- traffic to 203.0.113.9

## Evidence Links
| Host | Path |
|---|---|
| CORP-WS04 | evidence/corp-ws04.raw |
| CORP-SRV02 | evidence/corp-srv02.raw |
"""


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    (root / "CASE.md").write_text(BRIEF, encoding="utf-8")
    for name in ("corp-ws04.raw", "corp-srv02.raw"):
        (root / "evidence" / name).write_bytes(b"\0")
    (root / "evidence" / "corp-ws04_timeline.csv").write_text("date,time,desc\n", encoding="utf-8")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"links": [
        {"label": "CORP-WS04", "path": "evidence/corp-ws04.raw"},
        {"label": "CORP-SRV02", "path": "evidence/corp-srv02.raw"}]}), encoding="utf-8")
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return root, log


def test_narrative_sections_leave_out_the_inventories():
    from core.case_knowledge import narrative_sections
    heads = [h for h, _b in narrative_sections(BRIEF)]
    assert "Context" in heads and "Evidence Links" not in heads


def test_anchors_name_the_narratives_hosts_the_briefs_indicators_and_dated_sentences(case):
    root, _log = case
    block = Q.question_anchors(str(root), {"id": "task-0001", "text": "Which account ran upd.exe?"})
    assert "- hosts the question names: none" in block
    assert "- hosts the brief names: CORP-WS04" in block and "CORP-SRV02" not in block
    assert "jdoe" in block and "203.0.113.9" in block
    assert 'dated sentence (brief, Context): "The first host CORP-WS04 was compromised before 2031-03-16;' in block
    assert block.count("dated sentence") == 1          # one sentence carries all three dates


def test_a_graded_case_gets_hosts_and_dated_sentences_and_no_indicator(case):
    root, _log = case
    with patch("core.case_knowledge._graded", return_value=True):
        block = Q.question_anchors(str(root), {"id": "task-0001", "text": "q"})
    assert "203.0.113.9" not in block and "CORP-WS04" in block and "dated sentence" in block


def test_the_plan_reply_is_validated_and_a_case_file_preferred(case):
    root, log = case
    reply = ("Here is the plan:\n" + json.dumps({"reads": [
        {"host": "CORP-WS04", "source": "C/Windows/Prefetch", "tool": "ez.pecmd", "why": "execution"},
        {"host": "CORP-NOPE", "source": "x.txt", "tool": "ez.pecmd", "why": "unknown host"},
        {"host": "CORP-WS04", "source": "evidence/corp-ws04_timeline.csv", "tool": "table.table_grep",
         "pattern": "", "why": "no pattern"},
        {"host": "CORP-WS04", "source": "corp-ws04_timeline.csv", "tool": "table.table_grep",
         "pattern": "upd.exe", "why": "the timeline"},
        {"host": "CORP-WS04", "source": "x", "tool": "nope.tool", "why": "unknown tool"},
        {"host": "CORP-WS04", "source": "C/Users", "tool": "ez.pecmd", "why": "sixth"}]}) + "\nDone.")
    tools = [("ez.pecmd", "Prefetch"), ("table.table_grep", "search tables")]
    with patch("tools.reasoning._ask", return_value={"conclusion": reply, "_atlas_call_id": 7}):
        r = Q.plan_question(log, str(root), {"id": "task-0001", "text": "q"}, tools)
    assert r["reads"] == 6 and r["invalid"] == 3 and len(r["items"]) == 2
    # each refused read keeps why: the run's record says what was wrong with it
    assert [(x["host"], x["tool"]) for x in r["refused"]] == [
        ("CORP-NOPE", "ez.pecmd"), ("CORP-WS04", "table.table_grep"), ("CORP-WS04", "nope.tool")]
    assert "CORP-NOPE is not a host of this case" in r["refused"][0]["why"]
    assert r["refused"][1]["why"] == "a search needs a pattern"
    pre, grep = r["items"]
    assert pre["target"]["path"] == "evidence/corp-ws04.raw" and pre["target"]["inner_path"] == "C/Windows/Prefetch"
    assert grep["target"]["path"] == "evidence/corp-ws04_timeline.csv" and grep["target"]["pattern"] == "upd.exe"
    assert all(i["origin"] == "plan" and i["status"] == "due" for i in r["items"])
    with patch("tools.reasoning._ask", return_value={"conclusion": "I cannot plan this."}):
        r = Q.plan_question(log, str(root), {"id": "task-0002", "text": "q"}, tools)
    assert r["empty"] is True and r["reason"] == "the plan reply held no read"


def test_a_plan_cut_twice_is_an_empty_plan_with_its_reason(case):
    """A length-cut plan reply is asked again one level lower (the
    one-answer allowance in tools.reasoning._ask); a second cut leaves the
    question without a plan, and says why."""
    root, log = case
    cut = {"success": False, "conclusion": "", "gate": "reply_length_cut", "length_cuts": 2,
           "error": "the reply ran past the one-answer allowance twice"}
    with patch("tools.reasoning._ask", return_value=cut):
        r = Q.plan_question(log, str(root), {"id": "task-0003", "text": "q"}, [("ez.pecmd", "Prefetch")])
    assert r["empty"] and "cut at the one-answer allowance twice" in r["reason"]


def test_a_single_image_case_without_host_labels_validates_by_source(case):
    root, log = case
    (root / ".atlas" / "evidence_links.json").unlink()
    (root / "evidence" / "corp-srv02.raw").unlink()
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    v = Q.validate_read(str(root), {"host": "", "source": "C/Users/jane.doe/NTUSER.DAT", "tool": "ez.pecmd"},
                        {"ez.pecmd"})
    assert v and v["target"]["host"] == "" and v["target"]["path"] == "evidence/corp-ws04.raw"


def _table_call(root, log, pattern, rows):
    spill = root / "analysis" / f"spill_{len(log._entries)}.json"
    spill.write_text(json.dumps({"success": True, "hits": rows}), encoding="utf-8")
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt="{}",
                               stdout_file=str(spill))
    log.annotate_tool_call(cid, args=json.dumps({"path": "evidence/corp-ws04_timeline.csv", "pattern": pattern}))
    return cid


def _claim(root, cid, statement, call):
    graph = root / ".atlas" / "claim_graph.json"
    data = json.loads(graph.read_text()) if graph.is_file() else {"nodes": {}, "edges": []}
    data["nodes"][cid] = {"id": cid, "kind": "claim", "status": "new", "statement": statement,
                          "input_call_ids": [call], "host": "CORP-WS04"}
    graph.write_text(json.dumps(data), encoding="utf-8")


def test_the_source_behind_a_claims_rows_becomes_one_item_per_file(case, monkeypatch):
    monkeypatch.setenv("ATLAS_SOURCE_IN_CASE", "0")   # every row source as a hint
    root, log = case
    call = _table_call(root, log, r"https://updates\.example\.net/x|upd\.exe", [
        {"host": "CORP-WS04", "desc": "visit https://updates.example.net/x",
         "filename": "OS:/C/Users/jdoe/AppData/Local/Browser/History"},
        {"host": "CORP-WS04", "desc": "upd.exe started",
         "filename": "OS:/C/Windows/System32/winevt/Logs/Security.evtx"},
        {"host": "CORP-WS04", "desc": "file entry", "filename": "OS:/C/Tools/upd.exe"},
        {"host": "CORP-WS04", "desc": "folder", "filename": "OS:/C/Tools/updates.example.net/"}])
    _claim(root, "C0031", "CORP-WS04 visited https://updates.example.net/x and ran upd.exe", call)
    task = {"id": "task-0001", "related_claim_ids": ["C0031"]}
    made = Q.source_items_for_question(log, str(root), task)
    hints = sorted(i["target"]["source_hint"] for i in made)
    assert hints == ["OS:/C/Tools/upd.exe", "OS:/C/Users/jdoe/AppData/Local/Browser/History",
                     "OS:/C/Windows/System32/winevt/Logs/Security.evtx"]
    assert all(i["origin"] == "source" and i["target"]["host"] == "CORP-WS04" for i in made)
    assert "rows behind C0031 were parsed from" in made[0]["why"]
    assert len(Q.source_items_for_question(log, str(root), task)) == 3
    assert len(log.work_items()) == 3


def test_the_identifier_must_be_what_the_cited_call_searched_for(case):
    root, log = case
    call = _table_call(root, log, r"jane\.doe", [
        {"user": "jane.doe", "desc": "203.0.113.9 contacted", "filename": "OS:/C/Logs/proxy.log"}])
    _claim(root, "C0040", "The workstation contacted 203.0.113.9", call)
    assert Q.source_items_for_question(log, str(root), {"id": "task-0001", "related_claim_ids": ["C0040"]}) == []
    _claim(root, "C0041", "Activity on 2031-03-16 only", call)
    assert Q.source_items_for_question(log, str(root), {"id": "task-0001", "related_claim_ids": ["C0041"]}) == []


def test_absence_contradictions_become_items_on_the_claims_host(case):
    root, log = case
    clash = {"claim_id": "C0050", "artifact": "Security.evtx", "size": 100, "indexed_by": "mft",
             "statement": "no Security.evtx", "host": "CORP-WS04", "claim_host": "CORP-WS04",
             "path": "evidence/corp-ws04.raw"}
    hostless = {**clash, "claim_id": "C0051", "claim_host": "", "host": "", "path": ""}
    with patch("core.artifact_value.contradicted_absence_claims", return_value=[clash, hostless]):
        a, b = Q.absence_items(log, str(root))
    assert a["status"] == "due" and a["target"]["host"] == "CORP-WS04" and a["origin"] == "absence"
    assert b["status"] == "proposed" and b["target"]["source_hint"] == "Security.evtx"
    from core.artifact_value import format_value_nudge
    assert "C0050" in format_value_nudge([], [clash])


def test_the_directors_entries_parse_without_artefact_names(case):
    root, _log = case
    data = {"directives": {"priority_tools": [
        "ez.pecmd | CORP-WS04 C/Windows/Prefetch",
        "vol.pslist CORP-WS04 the beacon",
        "ez.pecmd C/Windows/Prefetch on an unnamed machine",
        "claim.snapshot CORP-WS04"]}}
    refused: list[str] = []
    out = W.parse_director_entries(data, str(root), refused)
    # A host alone and a path on no host leave no target a call can reach:
    # no item (it would never close), the entry reported instead.
    assert [o["status"] for o in out] == ["due"]
    assert out[0]["target"] == {"host": "CORP-WS04", "inner_path": "C/Windows/Prefetch",
                                "path": "evidence/corp-ws04.raw"}
    assert refused == [f"vol.pslist: {W.NOT_TRACKED}", f"ez.pecmd: {W.NOT_TRACKED}"]
    assert "not tracked as work" in W.NOT_TRACKED


def test_a_director_entry_naming_the_image_then_the_file_keeps_both(case):
    """The probe's shape: the director names the image, then the path
    inside it, as dict fields or in one line, or writes the handle."""
    root, _log = case
    want = {"host": "CORP-WS04", "path": "evidence/corp-ws04.raw",
            "inner_path": "C/Windows/System32/winevt/Logs/Security.evtx"}
    data = {"directives": {"priority_tools": [
        {"tool": "ez.evtxecmd", "host": "CORP-WS04", "image": "evidence/corp-ws04.raw",
         "path": "C/Windows/System32/winevt/Logs/Security.evtx", "why": "logons after 2031-03-16"},
        "ez.evtxecmd on CORP-WS04: evidence/corp-ws04.raw C/Windows/System32/winevt/Logs/Security.evtx",
        "ez.evtxecmd evidence/corp-ws04.raw::C/Windows/System32/winevt/Logs/Security.evtx"]}}
    out = W.parse_director_entries(data, str(root))
    assert [o["target"] for o in out] == [want, want, want] and all(o["status"] == "due" for o in out)
    from core.contents_index import image_handles_on
    if image_handles_on():
        assert W.ready_call({"tool": "ez_evtxecmd", "target": want}, ["file_path"]) == (
            'ez_evtxecmd(file_path="evidence/corp-ws04.raw::C/Windows/System32/winevt/Logs/Security.evtx")')


def test_a_host_label_in_a_handle_never_becomes_the_items_path(case, monkeypatch):
    """Without a contents index the handle's image part may be a host
    label: the item gets that host and its image, and the label is never
    taken for a path."""
    root, _log = case
    monkeypatch.setenv("ATLAS_CONTENTS_INDEX", "0")
    data = {"priority_tools": ["ez.evtxecmd CORP-WS04::C/Windows/System32/winevt/Logs/Security.evtx"]}
    (o,) = W.parse_director_entries(data, str(root))
    assert o["target"] == {"host": "CORP-WS04", "path": "evidence/corp-ws04.raw",
                           "inner_path": "C/Windows/System32/winevt/Logs/Security.evtx"}
    # A label that is no host of the case and no image leaves a path inside
    # nothing: no item, the entry reported as not tracked.
    data = {"priority_tools": ["ez.evtxecmd CORP-NONE::C/Windows/System32/winevt/Logs/Security.evtx"]}
    refused: list[str] = []
    assert W.parse_director_entries(data, str(root), refused) == []
    assert refused == [f"ez.evtxecmd: {W.NOT_TRACKED}"]


def test_a_director_entry_matching_a_proposal_adopts_it(case):
    root, log = case
    prop = log.add_work_item("index", [], "ez_pecmd", {"host": "CORP-WS04", "path": "evidence/corp-ws04.raw",
                                                        "inner_path": "C/Windows/Prefetch"}, "x", status="proposed")
    e = W.parse_director_entries({"priority_tools": ["ez.pecmd | CORP-WS04 C/Windows/Prefetch"]}, str(root))[0]
    got = log.add_work_item("director", [], e["tool"], e["target"], e["why"], status=e["status"])
    assert got is prop and prop["status"] == "due"


def test_the_order_block_reaches_the_director_and_its_digest(case):
    root, log = case
    import tools.dair as D
    with patch.object(D, "_case_root", return_value=str(root)):
        before = D._gaps_digest()["work_items"]
        log.add_work_item("plan", ["task-0001"], "ez_pecmd",
                          {"path": "evidence/corp-ws04.raw", "inner_path": "C/Windows/Prefetch"}, "x")
        log.add_work_item("series", [], "", None, "3 of 40 logs read", status="proposed")
        block = D._gaps_block()
        after = D._gaps_digest()["work_items"]
    assert "WORK ORDER (due" in block and "PROPOSED" in block and "series: 3 of 40 logs read" in block
    assert before != after


def test_tools_writing_the_runs_own_output_are_never_readers():
    """The run's own outputs (report writers, the case document, the
    indicator and ATT&CK exports, the trace export) are never readers; the
    evidence format converters read evidence and are."""
    for t in ("misc.write_final_report", "misc.write_projected_final_report", "misc_write_case_document",
              "export.export_iocs", "export_export_navigator", "accuracy_accuracy_export_report",
              "misc_export_execution_log"):
        assert not W.is_reading_tool(t), t
    readers = {t for t, _w in Q.reading_tools()}
    assert not {"misc.write_final_report", "misc.write_projected_final_report"} & readers
    for t in ("ese.esedb_export", "evt.evt_export", "misc.pff_export", "plaso.export_csv"):
        assert W.is_reading_tool(t), t
        assert t in readers, t
    # A tool writing a filtered copy of a capture reads the capture (evidence).
    assert W.is_reading_tool("net_tcpdump_write_filtered")
    # A VMDK flattened to raw is a conversion the coverage ledger does not
    # count as a content read (core.coverage_ledger.reads_content); the
    # own-output rule leaves it alone either way.
    assert not W._OWN_OUTPUT_RE.search(W.listed("img.vmdk_export_raw"))
    assert W.is_reading_tool("ez.evtxecmd")


def _mount_plan(root, images):
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / p), "media_role": "disk", "action": "plan_only", "image_type": "raw_or_container"}
        for p in images]}), encoding="utf-8")


def test_a_handle_source_is_split_into_image_and_inner_path(case):
    root, log = case
    _mount_plan(root, ["evidence/corp-ws04.raw", "evidence/corp-srv02.raw"])
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS04", "path": "evidence/corp-ws04.raw"},
        {"label": "CORP-SRV02", "path": "evidence/corp-srv02.raw"}]}), encoding="utf-8")
    v, why = Q.check_read(str(root), {"host": "", "source": "evidence/corp-ws04.raw::Windows/Prefetch/UPD.EXE-1.pf",
                                      "tool": "ez.pecmd"}, {"ez.pecmd"})
    assert v, why
    assert v["target"]["path"] == "evidence/corp-ws04.raw"
    assert v["target"]["inner_path"] == "Windows/Prefetch/UPD.EXE-1.pf" and v["target"]["host"] == "CORP-WS04"


def test_a_host_finds_its_image_through_the_evidence_links(case):
    root, log = case
    (root / "evidence" / "img-0001.raw").write_bytes(b"\0")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS04", "path": "evidence/img-0001.raw"},
        {"label": "CORP-SRV02", "path": "evidence/corp-srv02.raw"}]}), encoding="utf-8")
    (root / "CASE.md").write_text(BRIEF.split("## Evidence Links")[0], encoding="utf-8")
    (root / "evidence" / "corp-ws04.raw").unlink()
    for cached in (root / ".atlas").glob("evidence_*profile*.json"):
        cached.unlink()                      # the inventory is read again with the new image
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)
    assert W._host_image(str(root), "CORP-WS04") == "evidence/img-0001.raw"


def test_a_failed_line_names_the_call_and_a_blocker_read_its_origin(case, monkeypatch):
    root, log = case
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    item = log.add_work_item("plan", ["task-0001"], "table_table_grep",
                             {"path": "evidence/corp-ws04_timeline.csv", "pattern": "upd.exe"}, "x")
    item.update(status="failed", basis_call_id=77, outcome="unreadable")
    assert "by call 77 (unreadable)" in W.work_order_for_director(log, str(root))
    log.add_work_item("blocker", ["task-0001"], "", {}, "the pre-report check names this question",
                      status="proposed")
    from core.answer_synthesis import _reads_block
    lines = [r["text"] for r in _reads_block({"id": "task-0001"}, root)]
    assert any(t.startswith("blocker the pre-report check names this question: proposed") for t in lines)


# ── a hostless image's reads are checked against its own listing ─────────

def _hostless(root):
    """CASE-A as one image no evidence link ties to a host."""
    (root / ".atlas" / "evidence_links.json").unlink()
    (root / "evidence" / "corp-srv02.raw").unlink()
    from core.coverage_ledger import build_coverage_ledger
    build_coverage_ledger(root)


def _listing(root, image, paths):
    from core import contents_index as ci
    con = ci._connect(root, create=True)
    ci._insert_entries(con, "", image, [{"path": p, "name": p.rsplit("/", 1)[-1], "size": 10} for p in paths],
                       "image")
    con.commit()
    con.close()


def test_a_hostless_image_read_stands_before_its_listing_exists(case):
    root, _log = case
    _hostless(root)
    _listing(root, "evidence/other.raw", ["notes.txt"])      # an index, but no row of this image
    reads, why = Q.check_reads(str(root), {"host": "", "source": "Windows/System32/config/SYSTEM",
                                           "tool": "ez.recmd_hive"}, {"ez.recmd_hive"})
    assert why == "" and reads[0]["target"]["inner_path"] == "Windows/System32/config/SYSTEM"


def test_a_hostless_image_read_its_listing_lacks_is_refused_naming_the_image(case):
    root, _log = case
    _hostless(root)
    _listing(root, "evidence/corp-ws04.raw", ["notes.txt", "$FAT1"])
    reads, why = Q.check_reads(str(root), {"host": "", "source": "Windows/System32/config/SYSTEM",
                                           "tool": "ez.recmd_hive"}, {"ez.recmd_hive"})
    assert reads == [] and "listing of evidence/corp-ws04.raw" in why
    reads, why = Q.check_reads(str(root), {"host": "", "source": "notes.txt", "tool": "strings.read_text"},
                               {"strings.read_text"})
    assert why == "" and reads[0]["target"]["path"] == "evidence/corp-ws04.raw"


def test_a_director_entry_naming_a_file_its_hostless_image_lacks_is_no_item(case):
    root, _log = case
    _hostless(root)
    _listing(root, "evidence/corp-ws04.raw", ["notes.txt"])
    data = {"directives": {"priority_tools": [
        "ez.recmd_hive evidence/corp-ws04.raw Windows/System32/config/SYSTEM",
        "strings.read_text evidence/corp-ws04.raw notes.txt"]}}
    out = W.parse_director_entries(data, str(root))
    assert [o["target"].get("inner_path") for o in out] == ["notes.txt"]


# ── a planned read's tool must take an input a target can reach ─────────

@pytest.mark.parametrize("params, stands", [
    ({"properties": {"pcap_file": {"type": "string"}, "limit": {"type": "integer"}}}, True),
    ({"properties": {"pattern": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}}},
     True),
    ({"properties": {}}, False),
    ({"properties": {"count": {"type": "integer"}}}, False),
])
def test_a_planned_reads_tool_needs_a_string_parameter(case, monkeypatch, params, stands):
    root, _log = case
    monkeypatch.setattr(Q, "_input_schema", lambda tool: params)
    reads, why = Q.check_reads(str(root), {"host": "CORP-WS04", "source": "evidence/corp-ws04_timeline.csv",
                                           "tool": "net.capture_reader"}, {"net.capture_reader"})
    assert bool(reads) is stands
    assert stands or "takes no input that can name a file" in why


def test_a_tool_the_registry_does_not_know_is_not_refused_for_its_schema():
    assert W.takes_target(None) is True
    assert W.takes_target({"properties": {"files": {"type": "array", "items": {"type": "string"}}}}) is True
