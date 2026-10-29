"""Lineage by wiring (ATLAS_LINEAGE_WIRING): the analyst's ids stay as cited;
when none of them shows the finding by its rows, the calls of the trace that
do are located and recorded beside them, on the trace entry and the claim
node. Through record_finding with a scratch trace. Invented fixtures only."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import load_graph
from core.execution_log import ExecutionLog

ROW = {"TimeCreated": "2031-03-04 09:12:49", "Computer": "CORP-WS01", "EventId": 4688,
       "Message": "A new process has been created: C:\\Users\\Public\\dropper.exe"}
STATEMENT = "dropper.exe was started on CORP-WS01 at 2031-03-04 09:12 (event id 4688)"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    with patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas" / "evidence_inventory.json").write_text(json.dumps({"complete": True, "summary": {}}))
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"}], "hosts": ["CORP-WS01"]}))
    return case


@pytest.fixture
def log(case):
    from core import provenance
    l = ExecutionLog()
    l.configure("CASE-A", str(case / "analysis" / "trace.json"), save_session=False)
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    provenance.reset_cache()
    return l


def _grep(log, rows, path="analysis/ws01/sec.csv", pattern="dropper"):
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "path": path, "pattern": pattern,
                                                          "hits": rows, "hit_count": len(rows), "max_hits": 50,
                                                          "hit_cap_reached": False}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"path": path, "pattern": pattern}))
    return cid


def _finding(log):
    return [e for e in log._entries if e.get("type") == "finding"][-1]


def test_the_located_call_is_recorded_beside_the_citation(case, log):
    from tools.misc import record_finding
    shows = _grep(log, [ROW])
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/other.csv")
    with patch("core.execution_log.log", log):
        r = record_finding(STATEMENT, "SUSPECTED", "evtx", host="CORP-WS01",
                           linked_call_id=other, input_call_ids=[other])
    assert r["success"] is True, r
    assert r["lineage"] == {"cited": [other], "located_by_atlas": [shows],
                            "note": r["lineage"]["note"]} and "Nothing to do" in r["lineage"]["note"]
    assert "lineage_note" not in r and "citation_advisory" not in r
    f = _finding(log)
    assert f["input_call_ids"] == [other] and f["located_call_ids"] == [shows]
    assert f["citation_status"] == "located"
    node = next(n for n in load_graph(case)["nodes"].values() if n.get("kind") == "claim")
    assert node["located_call_ids"] == [shows] and node["analyst_call_ids"] == [other]
    assert node["citation_status"] == "located"
    assert any(e.get("call_id") == shows and e.get("located") for e in node["evidence"])


def test_a_cited_call_that_shows_the_finding_needs_no_locating(case, log):
    from tools.misc import record_finding
    shows = _grep(log, [ROW])
    with patch("core.execution_log.log", log):
        r = record_finding(STATEMENT, "SUSPECTED", "evtx", host="CORP-WS01",
                           linked_call_id=shows, input_call_ids=[shows])
    assert r["success"] and "lineage" not in r and "citation" not in r
    f = _finding(log)
    assert f["citation_status"] == "cited" and "located_call_ids" not in f


def test_a_finding_no_call_shows_is_recorded_and_told_so(case, log):
    """The statement names an address and a time (no artifact, so the
    relevance gate has nothing to judge) that no call's rows show."""
    from tools.misc import record_finding
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}])
    with patch("core.execution_log.log", log):
        r = record_finding("CORP-WS01 reached 203.0.113.7 at 2031-03-04 11:00", "SUSPECTED", "evtx",
                           host="CORP-WS01", linked_call_id=other, input_call_ids=[other])
    assert r["success"] is True, r
    assert "no call in the trace shows" in r["citation"] and "203.0.113.7" in r["citation"]
    assert _finding(log)["citation_status"] == "not_shown"


def test_the_locator_reaches_a_call_four_hundred_calls_back(case, log):
    from tools.misc import record_finding
    shows = _grep(log, [ROW])
    for i in range(400):
        log.record_tool_call(f"cat evidence/ws01/f{i}.log", True, False, 0, 0, stdout_excerpt="nothing here")
    log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/o.csv")
    with patch("core.execution_log.log", log):
        r = record_finding(STATEMENT, "SUSPECTED", "evtx", host="CORP-WS01",
                           linked_call_id=other, input_call_ids=[other])
    assert r["lineage"]["located_by_atlas"] == [shows]


def test_a_confirmed_finding_shown_only_by_located_calls_is_recorded_likely(case, log, monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
    from tools.misc import record_finding
    shows = _grep(log, [ROW])
    other = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe"}], path="analysis/ws01/o.csv")
    log.record_reason_call("reason_evaluate_finding", True, f"SUPPORTED: {STATEMENT}", {},
                           inputs={"user_message": STATEMENT})
    with patch("core.execution_log.log", log), \
            patch("tools._gates.contracts.failures", lambda name, ctx: []):
        r = record_finding(STATEMENT, "CONFIRMED", "evtx", host="CORP-WS01",
                           linked_call_id=other, input_call_ids=[other],
                           supporting_evidence="sec.csv: dropper.exe 2031-03-04 09:12:49 event id 4688")
    assert r["success"] is True
    # The presence check answers first (a "located" status never passes it).
    assert r["confidence"] == "LIKELY" and r["tier_auto_downgrade_reason"] == "citation_values_not_shown"
    assert r["citation"].startswith("Cite the call whose row shows each") and f"call {shows} shows it" in r["citation"]
    assert _finding(log)["located_call_ids"] == [shows]


def test_the_universal_gate_judges_the_analysts_ids_only(case, log):
    """The located call is a complete view; the cited one was cut. A universal
    statement still rests on what the analyst cited."""
    from tools.misc import record_finding
    _shows = _grep(log, [ROW])
    cut = _grep(log, [{"TimeCreated": "2031-03-05 10:00:00", "Message": "notepad.exe dropper.exe"}],
                path="analysis/ws01/o.csv")
    log.annotate_tool_call(cut, view_truncated=True, view_omitted_rows=40, view_rows_shown=1, view_rows_returned=41)
    with patch("core.execution_log.log", log):
        r = record_finding("No process other than dropper.exe was started on CORP-WS01", "SUSPECTED", "evtx",
                           host="CORP-WS01", linked_call_id=cut, input_call_ids=[cut])
    assert r["success"] is False and r["gate"] == "universal_from_truncated"


def test_lineage_relevance_passes_through_the_located_call(case, log):
    from tools.misc import record_finding
    doc = log.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                               evidence_ref="exports/carved/report.docx",
                               stdout_excerpt="2031-03-04 09:12 report.docx customer list jane.doe@corp.example.com")
    pcap = log.record_tool_call("tcpdump -r evidence/capture.pcap port 21", True, False, 0, 0,
                                stdout_excerpt="3 packets")
    with patch("core.execution_log.log", log):
        r = record_finding("report.docx holds the customer list and names jane.doe@corp.example.com",
                           "SUSPECTED", "carve", linked_call_id=pcap, input_call_ids=[pcap])
    assert r["success"] is True and r["lineage"]["located_by_atlas"] == [doc]
    with patch("core.execution_log.log", log):
        refused = record_finding("ledger.xlsx holds the payroll and names jane.doe@corp.example.com",
                                 "SUSPECTED", "carve", linked_call_id=pcap, input_call_ids=[pcap])
    assert refused["success"] is False and refused["gate"] == "lineage_relevance"


def test_cited_ids_include_the_located_calls_for_the_readers(monkeypatch):
    from tools._gates.citation_support import cited_ids
    f = {"input_call_ids": [3], "linked_call_id": 3, "located_call_ids": [7]}
    assert cited_ids(f) == [3, 7]
    monkeypatch.setenv("ATLAS_LINEAGE_WIRING", "0")
    assert cited_ids(f) == [3]
