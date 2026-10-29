"""A belief a recount put under review (core.coverage_ledger.coverage_review_hits)
is re-validated only on a read of an image the recount corrected, counted by
the recount's own rule; a read that shows the image readable contradicts a
belief saying it was not, and a failed read leads to the way a limitation
that holds is kept: mark the image blocked, then record the limitation again
citing that failed call with supersedes= naming the old belief."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core import coverage_ledger as cl
from core.claim_graph import add_claim, get_node, load_graph, save_graph
from core.dependency_index import mark_needs_review
from tools.claim_tools import revalidate

IMG = "evidence/hosts/CORP-WS01/disk.dd"
TIMELINE = "evidence/supertimeline.csv"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "CASE-A"
    (d / IMG).parent.mkdir(parents=True)
    (d / IMG).write_bytes(b"\0" * 4096)
    (d / TIMELINE).write_text("time,host,event\n2031-03-04 10:12:00,CORP-WS01,logon\n",
                              encoding="utf-8")
    (d / ".atlas").mkdir()
    (d / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    (d / "analysis").mkdir()
    cl.build_coverage_ledger(d)
    return d


def _under_review(case, statement):
    c = add_claim(case, statement, host="CORP-WS01", enforce_validation=False)["node_id"]
    mark_needs_review(case, [c], reason="coverage corrected", hits={c: {"recounted": [IMG]}},
                      reasons={c: cl.recount_review_reason([IMG], {"unblocked": [IMG]})})
    g = load_graph(case)
    g["nodes"][c]["invalidated_at"] = "2020-01-01T00:00:00Z"
    save_graph(case, g)
    return c


@pytest.fixture
def log(case):
    from core.execution_log import ExecutionLog
    lg = ExecutionLog()
    lg.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    lg._entries.clear()
    return lg


def _listing(log):
    return log.record_tool_call("<py>:tsk_tsk_fls", True, False, 0, 0, evidence_ref=IMG,
                                stdout_excerpt="r/r 1290-128-1: Security.evtx\nd/d 64: Users")


def _failed_read(log):
    return log.record_tool_call("<py>:tsk_tsk_fsstat", False, False, 0, 1, evidence_ref=IMG,
                                stderr="Invalid magic value (offset 63)",
                                failure_class="tool_error")


def _timeline(log):
    return log.record_tool_call("<py>:table_table_grep", True, False, 0, 0,
                                evidence_ref=TIMELINE,
                                stdout_excerpt="2031-03-04 10:12:00,CORP-WS01,logon")


def _revalidate(case, log, c, ids):
    with patch("core.execution_log.log", log):
        return revalidate(c, ids, note="image re-read", case_dir=str(case))


def test_a_call_that_did_not_read_the_corrected_image_is_refused(case, log):
    c = _under_review(case, "Logon history on CORP-WS01 could not be determined")
    r = _revalidate(case, log, c, [_timeline(log)])
    assert not r["success"] and "coverage correction of " + IMG in r["error"]
    assert "none of the cited calls read one of them" in r["error"]
    assert get_node(load_graph(case), c)["status"] == "needs_review"


def test_a_cited_partition_table_read_is_told_how_an_image_is_read(case, log):
    c = _under_review(case, "Logon history on CORP-WS01 could not be determined")
    mmls = log.record_tool_call("<py>:tsk_tsk_mmls", True, False, 0, 0, evidence_ref=IMG,
                                stdout_excerpt="DOS Partition Table\n002: 0000000063 NTFS")
    r = _revalidate(case, log, c, [mmls])
    assert not r["success"] and "none of the cited calls read one of them" in r["error"]
    assert "tsk.fls" in r["error"] and "identify an image without reading" in r["error"]


def test_a_failed_read_names_the_way_to_keep_the_limitation(case, log):
    c = _under_review(case, "The CORP-WS01 disk image could not be read")
    r = _revalidate(case, log, c, [_failed_read(log)])
    assert not r["success"]
    for step in ("coverage.mark_blocked", f"misc.record_finding(supersedes={c})"):
        assert step in r["error"]


def test_a_read_contradicting_an_unreadable_image_asks_for_a_supersede(case, log):
    c = _under_review(case, "CORP-WS01 disk image probed/blocked; no event log available")
    r = _revalidate(case, log, c, [_listing(log)])
    assert not r["success"] and "no longer holds" in r["error"]
    assert f"misc.record_finding(supersedes={c})" in r["error"]


def test_a_read_of_the_image_passes_the_coverage_check(case, log):
    c = _under_review(case, "Logon history on CORP-WS01 could not be determined")
    r = _revalidate(case, log, c, [_listing(log)])
    assert "coverage correction" not in str(r.get("error") or "")
    assert "no longer holds" not in str(r.get("error") or "")


def test_a_limitation_that_holds_is_kept_by_a_re_record_that_replaces_it(case, log, tmp_path):
    """The way out the refusal names, end to end, with the image still
    waiting to be opened (so the access-limitation dedupe gate is live): the
    read fails again, the image is marked blocked on that failure, and the
    limitation recorded again with supersedes= replaces the belief. Recorded
    beside it instead, the same note is refused as a duplicate."""
    from core.mount_plan import build_mount_plan
    from tools import coverage as coverage_tools
    from tools.misc import record_finding
    from tools.mitre import _load_json

    build_mount_plan(case, persist=True, auto_mount=False)
    table = tmp_path / "mitre_techniques.json"
    table.write_text(json.dumps({"techniques": {}}), encoding="utf-8")
    _load_json.cache_clear()
    log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    identified = log.record_tool_call("<py>:tsk_tsk_mmls", True, False, 0, 0, evidence_ref=IMG,
                                      stdout_excerpt="DOS Partition Table\n002: 0000000063 NTFS")
    note = ("Documented limitation: disk-level access to the CORP-WS01 disk image was not "
            "achieved, so its event logs were not examined")
    with patch("core.execution_log.log", log), \
            patch.object(log, "case_dir", return_value=str(case)), \
            patch("core.claim_graph.resolve_case_dir", return_value=str(case)), \
            patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/bin/{name}"), \
            patch("tools.correlate.DEFAULT_MITRE_PATH", str(table)):
        first = record_finding(description=note, confidence="UNCONFIRMED", source="tsk.mmls",
                               host="CORP-WS01", linked_call_id=identified,
                               input_call_ids=[identified])
        assert first.get("success"), first
        old = first["claim_id"]
        mark_needs_review(case, [old], reason="coverage corrected",
                          hits={old: {"recounted": [IMG]}},
                          reasons={old: cl.recount_review_reason([IMG], {"unblocked": [IMG]}, old)})
        failed = _failed_read(log)
        refusal = revalidate(old, [failed], note="image re-read", case_dir=str(case))
        assert f"supersedes={old}" in refusal["error"]
        assert coverage_tools.mark_blocked(
            IMG, "tsk.fsstat fails: Invalid magic value at offset 63").get("success")
        again = ("Documented limitation: the CORP-WS01 disk image could not be read; tsk.fsstat "
                 "at offset 63 fails with 'Invalid magic value'")
        kw = dict(confidence="UNCONFIRMED", source="tsk.fsstat", host="CORP-WS01",
                  linked_call_id=failed, input_call_ids=[failed],
                  supporting_evidence="Invalid magic value (offset 63)")
        beside = record_finding(description=again, **kw)
        assert not beside.get("success") and beside.get("gate") == "access_limitation_dedupe"
        replaced = record_finding(description=again, supersedes=old, **kw)
    _load_json.cache_clear()
    assert replaced.get("success"), replaced
    g = load_graph(case)
    assert g["nodes"][old]["status"] == "superseded"
    assert g["nodes"][replaced["claim_id"]]["status"] != "needs_review"
