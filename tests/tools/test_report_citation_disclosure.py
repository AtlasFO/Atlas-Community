"""The report-time citation check as disclosure (ATLAS_CITATION_DISCLOSURE):
the status written back on the node, the warning, no blocker, no tier
change, the restore of claims an earlier gate lowered, the labelled records.
Invented fixtures only."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import load_graph, save_graph, upsert_claim_from_finding
from core.execution_log import ExecutionLog

ROW = {"TimeCreated": "2031-03-04 09:12:49", "Computer": "CORP-WS01", "EventId": 4688,
       "Message": "A new process has been created: C:\\Users\\Public\\dropper.exe"}
SHOWN = "dropper.exe was started on CORP-WS01 at 2031-03-04 09:12"
UNSHOWN = "ghost.exe was started on CORP-WS01 at 2031-03-04 11:00"


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"}], "hosts": ["CORP-WS01"]}))
    return case


def _log(case):
    from core import provenance
    l = ExecutionLog()
    l.configure("CASE-A", str(case / "analysis" / "trace.json"), save_session=False)
    provenance.reset_cache()
    return l


def _grep(log, rows, path="analysis/ws01/sec.csv"):
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "path": path, "pattern": "x",
                                                          "hits": rows, "hit_count": len(rows)}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"path": path, "pattern": "x"}))
    return cid


def _finding(log, case, statement, cited, tier="LIKELY"):
    fid = log.record_finding(statement, tier, "evtx", cited, "", input_call_ids=[cited], host="CORP-WS01")
    upsert_claim_from_finding(case, statement=statement, confidence=tier, source="evtx", host="CORP-WS01",
                              finding_call_id=fid, linked_call_id=cited, input_call_ids=[cited])
    return fid


def _check(log, apply=True):
    from tools.reasoning import _pre_report_check
    with patch("core.execution_log.log", log):
        return _pre_report_check(apply_remedies=apply)


def test_the_check_discloses_and_writes_the_status_back_without_blocking(case):
    log = _log(case)
    shows = _grep(log, [ROW])
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/o.csv")
    _finding(log, case, SHOWN, other)      # shown only by a later-located call
    _finding(log, case, UNSHOWN, other)    # shown by no call
    before = {n["statement"]: n["confidence"] for n in load_graph(case)["nodes"].values()}
    out = _check(log)
    assert not any("cite calls that do not contain" in i for i in out.get("blocking_issues", []))
    warning = next(w for w in out["warnings"] if w.startswith("Findings no tool output shows"))
    assert "Not blocking" in warning
    nodes = {n["statement"]: n for n in load_graph(case)["nodes"].values()}
    assert nodes[SHOWN]["citation_status"] == "located" and nodes[SHOWN]["located_call_ids"] == [shows]
    assert nodes[UNSHOWN]["citation_status"] == "not_shown" and nodes[UNSHOWN]["located_call_ids"] == []
    assert {n["statement"]: n["confidence"] for n in nodes.values()} == before
    from core.finding_index import f_id_for
    assert (f_id_for(case, nodes[UNSHOWN]["id"]) or nodes[UNSHOWN]["id"]) in warning
    assert not any(e.get("miscited_lineage") for e in log._entries if e.get("type") == "reason_call")
    # The dashboard brief and the report read the same stored status.
    from dashboard.read_models import _node_brief
    assert _node_brief(nodes[SHOWN])["citation_status"] == "located"
    assert _node_brief(nodes[SHOWN])["located_call_ids"] == [shows]


def test_a_not_checkable_finding_gets_no_warning(case):
    log = _log(case)
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}])
    _finding(log, case, "The archive could not be opened by the analyst", other)
    out = _check(log)
    assert not any(w.startswith("Findings no tool output shows") for w in out["warnings"])
    node = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    assert node["citation_status"] == "not_checkable"


def test_the_evidence_gaps_lines_read_the_stored_status(case):
    log = _log(case)
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}])
    _finding(log, case, UNSHOWN, other)
    _check(log)
    from core.report_projection import (bind_claims_to_sections, deterministic_section_generator,
                                         section_context)
    # Through the section's own projection, as the report builds it.
    bind_claims_to_sections(case)
    ctx = section_context(case, "gaps")
    assert any(c.get("citation_status") == "not_shown" for c in ctx["claims"])
    text = deterministic_section_generator(ctx, {"id": "gaps"})
    assert "no tool output in the trace shows what it names (ghost.exe, 2031-03-04 11:00)" in text


def test_a_flagged_claim_bound_to_another_section_still_gets_its_gaps_line(case):
    """The pre-report warning names every flagged finding, so Evidence Gaps
    lists a status line for each, wherever the manifest bound the claim."""
    log = _log(case)
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}])
    _finding(log, case, UNSHOWN, other)
    _check(log)
    from core.report_projection import (bind_claims_to_sections, deterministic_section_generator,
                                         load_manifest, save_manifest, section_context)
    bind_claims_to_sections(case)
    manifest = load_manifest(case)
    gaps = manifest["sections"]["gaps"]
    gaps["claim_ids"], gaps["priority_claim_ids"] = [], []
    save_manifest(case, manifest)
    ctx = section_context(case, "gaps")
    assert ctx["claims"] == [] and len(ctx["flagged_claims"]) == 1
    text = deterministic_section_generator(ctx, {"id": "gaps"})
    assert "no tool output in the trace shows what it names (ghost.exe, 2031-03-04 11:00)" in text


def test_a_legacy_lowered_claim_is_restored_once_inside_apply_remedies(case):
    from core.claim_graph import LOWERING_MARKER, RESTORED_MARKER
    log = _log(case)
    shows = _grep(log, [ROW])
    # The chain: a CONFIRMED twin merged first, then the exact record at LIKELY.
    f1 = log.record_finding(SHOWN + " by the scheduler", "CONFIRMED", "evtx", shows, "", input_call_ids=[shows],
                            host="CORP-WS01")
    f2 = log.record_finding(SHOWN, "LIKELY", "evtx", shows, "", input_call_ids=[shows], host="CORP-WS01")
    upsert_claim_from_finding(case, statement=SHOWN, confidence="LIKELY", source="evtx", host="CORP-WS01",
                              finding_call_id=f2, linked_call_id=shows, input_call_ids=[shows])
    g = load_graph(case)
    node = next(n for n in g["nodes"].values() if n.get("kind") == "claim")
    node["merged_finding_call_ids"] = [f1]
    node["confidence"] = "UNCONFIRMED"
    node["evidence"].append({"artifact": LOWERING_MARKER, "locator": "", "call_id": None})
    save_graph(case, g)
    read_only = _check(log, apply=False)
    assert next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")["confidence"] == "UNCONFIRMED"
    _check(log, apply=True)
    node = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    arts = {e.get("artifact") for e in node["evidence"]}
    assert node["confidence"] == "LIKELY" and RESTORED_MARKER in arts and LOWERING_MARKER not in arts
    assert node["citation_status"] == "cited"
    snapshot = json.dumps(node, sort_keys=True)
    _check(log, apply=True)
    again = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    assert json.dumps({k: v for k, v in again.items() if k != "updated_at"}, sort_keys=True) == \
        json.dumps({k: v for k, v in json.loads(snapshot).items() if k != "updated_at"}, sort_keys=True)
    assert read_only["ready_to_report"] in (True, False)


def test_a_restored_confirmed_claim_shown_only_by_located_calls_comes_back_likely(case):
    from core.claim_graph import LOWERING_MARKER
    log = _log(case)
    shows = _grep(log, [ROW])
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/o.csv")
    fid = log.record_finding(SHOWN, "CONFIRMED", "evtx", other, "", input_call_ids=[other], host="CORP-WS01")
    upsert_claim_from_finding(case, statement=SHOWN, confidence="CONFIRMED", source="evtx", host="CORP-WS01",
                              finding_call_id=fid, linked_call_id=other, input_call_ids=[other])
    g = load_graph(case)
    node = next(n for n in g["nodes"].values() if n.get("kind") == "claim")
    node["confidence"] = "UNCONFIRMED"
    node["evidence"].append({"artifact": LOWERING_MARKER, "locator": "", "call_id": None})
    save_graph(case, g)
    _check(log, apply=True)
    node = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    assert node["confidence"] == "LIKELY" and node["citation_status"] == "located" and node["located_call_ids"] == [shows]


def test_wiring_off_brings_the_blocker_back(case, monkeypatch):
    monkeypatch.setenv("ATLAS_LINEAGE_WIRING", "0")
    log = _log(case)
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}])
    _finding(log, case, UNSHOWN, other)
    out = _check(log, apply=False)
    assert any("cite calls that do not contain the identifiers" in i for i in out["blocking_issues"])
    assert not any(w.startswith("Findings no tool output shows") for w in out["warnings"])


def test_the_cited_records_are_the_rows_that_show_the_claim_and_located_ones_are_labelled(case, monkeypatch):
    from core.evidence_resolver import resolve_claim_evidence
    log = _log(case)
    shows = _grep(log, [ROW, {"TimeCreated": "2031-03-04 17:00:00", "Computer": "CORP-WS01", "EventId": 4688,
                              "Message": "A new process has been created: notepad.exe"}])
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/o.csv")
    fid = log.record_finding(SHOWN, "LIKELY", "evtx", other, "", input_call_ids=[other], host="CORP-WS01")
    upsert_claim_from_finding(case, statement=SHOWN, confidence="LIKELY", source="evtx", host="CORP-WS01",
                              finding_call_id=fid, linked_call_id=other, input_call_ids=[other],
                              located_call_ids=[shows], analyst_call_ids=[other], citation_status="located")
    node = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    windows = {shows: [{"raw_text": json.dumps(ROW) + "\n" + json.dumps({"TimeCreated": "2031-03-04 17:00:00",
                                                                        "Message": "notepad.exe"}),
                        "source_path": "analysis/ws01/sec.csv", "line_start": 1, "event_time": ""}],
               other: [{"raw_text": json.dumps({"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}),
                        "source_path": "analysis/ws01/o.csv", "line_start": 1, "event_time": ""}]}
    monkeypatch.setattr("core.evidence_resolver._windows_for_call_id", lambda root, cid, limit=30: windows.get(cid, []))
    with patch("core.execution_log.log", log):
        pack = resolve_claim_evidence(case, node)
    direct = [e for e in pack.events if e.call_id == shows and e.provenance != "correlated"]
    assert direct and all("dropper.exe" in e.text for e in direct)
    assert all(e.provenance == "located by Atlas" for e in direct)
    assert all(e.provenance == "correlated" for e in pack.events if "notepad" in e.text)


def test_every_reader_judges_host_affinity_with_the_case_hosts(case):
    """A claim about one host is not shown by a call that read another
    host's evidence, also for the readers that pass no hosts: the record-time
    advisory and the pre-report miscitation check read the case's hosts."""
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"},
        {"label": "CORP-WS02", "path": "evidence/ws02", "kind": "folder"}], "hosts": ["CORP-WS01", "CORP-WS02"]}))
    (case / "evidence" / "ws01").mkdir(parents=True)
    (case / "evidence" / "ws01" / "sec.csv").write_text("x")
    (case / "evidence" / "ws02").mkdir(parents=True)
    (case / "evidence" / "ws02" / "sec.csv").write_text("x")
    log = _log(case)
    ws01 = _grep(log, [ROW], path="evidence/ws01/sec.csv")
    ws02 = _grep(log, [dict(ROW, Computer="CORP-WS02")], path="evidence/ws02/sec.csv")
    claim = "dropper.exe was started on CORP-WS02 at 2031-03-04 09:12"
    from tools._gates.citation_support import citation_supports
    from tools.misc import _citation_relevance_advisory
    from tools.reasoning import _miscited_finding_entries
    with patch("core.execution_log.log", log):
        assert citation_supports(claim, [log.index().by_call_id[ws01]],
                                 tool_calls=[log.index().by_call_id[ws01]]) is False
        finding = {"type": "finding", "call_id": 99, "description": claim, "linked_call_id": ws01,
                   "input_call_ids": [ws01]}
        assert _miscited_finding_entries([finding], list(log._entries)) == [finding]
        advisory = _citation_relevance_advisory(claim, [ws01], ws01, log)
        assert advisory and advisory["suggested_call_ids"] == [ws02]
        # The same claim about the host whose evidence the call read is shown.
        same = claim.replace("CORP-WS02", "CORP-WS01")
        assert citation_supports(same, [log.index().by_call_id[ws01]],
                                 tool_calls=[log.index().by_call_id[ws01]]) is True


def test_the_row_cache_keeps_two_cases_apart(tmp_path):
    """Call ids restart per case; a process serving two cases must not hand
    one case's rows to the other's call of the same id and length."""
    from tools._gates.citation_support import call_rows
    rows = []
    for name, value in (("CASE-A", "dropper.exe"), ("CASE-B", "updater.exe")):
        (tmp_path / name / "analysis").mkdir(parents=True)
        log = ExecutionLog()
        log.configure(name, str(tmp_path / name / "analysis" / "trace.json"), save_session=False)
        entry = {"type": "tool_call", "call_id": 1, "cmd": "<py>:table_table_grep",
                 "stdout_excerpt": json.dumps({"success": True, "hits": [{"Image": value}]})}
        with patch("core.execution_log.log", log):
            rows.append(call_rows(entry))
    assert "dropper.exe" in rows[0][0] and "updater.exe" in rows[1][0]
