"""A disk or memory image counts as examined once a call reached a file in
it, never on a call that only identified it (its partition table, its
volume, its symbols). blocked records a read of a unit that failed: it is
refused for a unit a call has read, for one no call has tried, and on calls
a gate turned away or made with invalid arguments; a later successful read
replaces it."""
import json

import pytest

from core import coverage_ledger as cl
from core import evidence_items as ei

IMG = "evidence/images/CORP-DC01.dd"
OTHER = "evidence/images/CORP-WS02.dd"
TABLE = "evidence/vpn_auth.csv"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "CASE-A"
    (d / "evidence" / "images").mkdir(parents=True)
    (d / ".atlas").mkdir()
    for rel in (IMG, OTHER):
        (d / rel).write_bytes(b"\0" * 4096)
    (d / TABLE).write_text("user,src\njane.doe,10.0.0.5\n", encoding="utf-8")
    (d / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    cl.build_coverage_ledger(d)
    return d


def _status(case, rel=IMG):
    led = cl.load_ledger(case)
    unit = next(u for u in led["units"].values() if u["path"] == rel)
    item = ei.find(led, rel)
    return unit["status"], (item or {}).get("status")


def _observe(case, tool, args, ok=True):
    cl.observe_tool_paths(case, tool_name=tool, cmd_or_args=json.dumps(args),
                          success=ok, result_text=json.dumps({"success": ok}))


def _tsk(cid, verb, rel, ok, *, offset=None, stderr="", failure_class=None):
    cmd = f"{verb} -o {offset} {rel}" if offset is not None else f"{verb} {rel}"
    entry = {"type": "tool_call", "call_id": cid, "cmd": cmd,
             "mcp_tool": f"tsk_tsk_{verb}", "success": ok, "stderr": stderr}
    if not ok:
        entry["failure_class"] = failure_class or "tool_error"
    return entry


def test_identification_calls_leave_an_image_unseen_and_a_filesystem_read_examines_it(case):
    for tool in ("tsk_mmls", "tsk_mmstat", "tsk_fsstat", "vol_symbol_check",
                 "ewf_info", "img_vmdk_chain_info"):
        _observe(case, tool, {"image": IMG})
        assert _status(case) == ("unseen", "unseen"), tool
    _observe(case, "tsk_fls", {"image": IMG})
    assert _status(case) == ("probed", "examined")
    assert _status(case, OTHER) == ("unseen", "unseen")
    _observe(case, "tsk_resolve_path", {"image": OTHER, "fs_path": "C/Windows"})
    assert _status(case, OTHER) == ("probed", "examined")


def test_blocked_is_refused_for_an_image_a_call_has_read(case):
    trace = [_tsk(5, "mmls", IMG, True), _tsk(7, "fls", IMG, True, offset=63)]
    r = cl.mark_unit_blocked(case, IMG, reason="filesystem does not open", trace_entries=trace)
    assert r["success"] is False and "was read by call 7" in r["error"]
    assert _status(case)[0] == "unseen"


def test_blocked_needs_a_failed_read_not_an_identification_or_a_refused_call(case):
    only_identified = [_tsk(5, "mmls", IMG, True)]
    refused = [_tsk(6, "fls", IMG, False, offset=63, failure_class="gate_refusal",
                    stderr="[access_disk_budget] stop filesystem enumeration")]
    bad_args = [_tsk(7, "fls", IMG, False, failure_class="analyst_error",
                     stderr="inode: not an integer")]
    for trace in (only_identified, refused, bad_args):
        r = cl.mark_unit_blocked(case, IMG, reason="filesystem does not open", trace_entries=trace)
        assert r["success"] is False and "no tool call in the trace is a failed attempt" in r["error"]
        assert "tsk.fls" in r["error"]
    failed_open = [_tsk(8, "fsstat", IMG, False, offset=63, stderr="Invalid magic value")]
    r = cl.mark_unit_blocked(case, IMG, reason="NTFS boot sector unreadable", trace_entries=failed_open)
    assert r["success"] is True and _status(case) == ("blocked", "blocked")


def test_a_later_read_replaces_blocked(case):
    trace = [_tsk(8, "fls", IMG, False, offset=63, stderr="Invalid sector address")]
    assert cl.mark_unit_blocked(case, IMG, reason="filesystem does not open", trace_entries=trace)["success"]
    _observe(case, "tsk_icat", {"image": IMG, "inode": "1292-128-4", "offset_sectors": 63})
    led = cl.load_ledger(case)
    unit = next(u for u in led["units"].values() if u["path"] == IMG)
    assert (unit["status"], unit["note"]) == ("probed", "")
    assert ei.find(led, IMG)["status"] == "examined"


def test_reads_at_the_first_sector_of_a_partitioned_image_do_not_unlock_blocked(case):
    no_offset = [_tsk(5, "mmls", IMG, True),
                 _tsk(6, "fls", IMG, False, stderr="Cannot determine file system type")]
    r = cl.mark_unit_blocked(case, IMG, reason="filesystem does not open", trace_entries=no_offset)
    assert r["success"] is False and "offset_sectors" in r["error"]
    at_offset = no_offset + [_tsk(7, "fls", IMG, False, offset=2048,
                                  stderr="Cannot determine file system type")]
    assert cl.mark_unit_blocked(case, IMG, reason="filesystem does not open",
                                trace_entries=at_offset)["success"] is True


def test_a_python_tools_offset_is_a_read_at_the_volume(case):
    """A Python tool's record carries its offset in its recorded arguments,
    not on a command line: that read asked the volume, so its failure may
    stand behind blocked; without an offset it asked the first sector."""
    def fls(cid, args):
        return {"type": "tool_call", "call_id": cid, "cmd": "<py>:tsk_tsk_fls",
                "args": json.dumps(args, sort_keys=True), "evidence_ref": IMG,
                "success": False, "failure_class": "tool_error",
                "stderr": "Cannot determine file system type"}
    mmls = _tsk(5, "mmls", IMG, True)
    r = cl.mark_unit_blocked(case, IMG, reason="filesystem does not open",
                             trace_entries=[mmls, fls(6, {"image": IMG})])
    assert r["success"] is False and "offset_sectors" in r["error"]
    r = cl.mark_unit_blocked(case, IMG, reason="filesystem does not open",
                             trace_entries=[mmls, fls(7, {"image": IMG, "offset_sectors": 2048})])
    assert r["success"] is True


def test_the_recount_names_a_blocked_image_a_read_reached_unblocked(case):
    _identified_only_ledger(case)
    _trace(case, [_tsk(5, "mmls", IMG, True), _tsk(9, "fls", IMG, True, offset=63)])
    assert cl.rederive_container_coverage(case)["unblocked"] == [IMG]
    assert _status(case)[0] == "probed"


def test_an_empty_table_is_blockable_on_the_gate_that_reports_it(case):
    trace = [{"type": "tool_call", "call_id": 9, "cmd": "<py>:table_table_schema",
              "evidence_ref": TABLE, "success": False, "failure_class": "gate_refusal",
              "stderr": "[empty_tabular] the file is empty or has no header row"}]
    r = cl.mark_unit_blocked(case, TABLE, reason="the export holds no rows", trace_entries=trace)
    assert r["success"] is True


def test_a_finding_naming_an_unread_image_does_not_answer_it(case):
    _observe(case, "misc_record_finding", {"description": f"activity on {IMG}"})
    assert _status(case)[0] == "unseen"
    _observe(case, "tsk_fls", {"image": IMG})
    _observe(case, "misc_record_finding", {"description": f"activity on {IMG}"})
    assert _status(case)[0] == "answered"


@pytest.mark.parametrize("entry, tool", [
    ({"mcp_tool": "tsk_tsk_mmls", "cmd": "mmls x.dd"}, "tsk_mmls"),
    ({"cmd": "<py>:hash_hash_file"}, "hash_file"),
    ({"cmd": "ez_evtxecmd evidence/Security.evtx"}, "ez_evtxecmd"),
    ({"cmd": "ewfmount evidence/CORP-DC01.E01 mnt/CORP-DC01/ewf"}, ""),
    ({"cmd": "/usr/bin/mount -o ro,loop evidence/CORP-DC01.dd mnt/x"}, ""),
])
def test_the_tool_of_a_trace_entry(entry, tool):
    assert cl._entry_tool(entry) == tool


def _identified_only_ledger(case):
    """Statuses a partition-table read credited: both images counted as
    read, one of them then blocked on it."""
    led = cl.load_ledger(case)
    for u in led["units"].values():
        if u["path"] == IMG:
            u.update(status="blocked", note="blocked by the fixture")
        elif u["path"] == OTHER:
            u["status"] = "probed"
    for rel, cid in ((IMG, "5"), (OTHER, "6")):
        ei.find(led, rel).update(status="examined", calls=[cid],
                                 examined_by={"call_id": cid, "tool": "tsk_mmls"})
    cl.save_ledger(case, led)


def _trace(case, entries):
    (case / "analysis").mkdir(exist_ok=True)
    (case / "analysis" / "CASE-A_trace.json").write_text(
        json.dumps({"case_id": "CASE-A", "entries": entries}), encoding="utf-8")


def test_the_rerun_recounts_images_from_the_trace(case):
    _identified_only_ledger(case)
    _trace(case, [_tsk(5, "mmls", IMG, True), _tsk(6, "mmls", OTHER, True),
                  _tsk(12, "fls", OTHER, True, offset=63)])
    moved = cl.rederive_container_coverage(case)
    assert moved == {"unblocked": [IMG]}
    assert _status(case) == ("unseen", "unseen")
    led = cl.load_ledger(case)
    assert ei.find(led, OTHER)["examined_by"] == {"call_id": "12", "tool": "tsk_fls"}
    assert _status(case, OTHER) == ("probed", "examined")
    assert cl.rederive_container_coverage(case) == {}

    from core.incremental import summarize_work
    work = summarize_work({"case_dir": str(case), "coverage_rederived": moved}, open_tasks=[])
    assert work["pending"] and IMG in work["unexamined_items"]
    assert any("recounted from the trace" in r for r in work["reasons"])


def test_a_failed_read_keeps_an_image_blocked_and_a_case_without_trace_is_left_alone(case):
    _identified_only_ledger(case)
    assert cl.rederive_container_coverage(case) == {}
    assert _status(case)[0] == "blocked"
    _trace(case, [_tsk(5, "mmls", IMG, True),
                  _tsk(7, "fsstat", IMG, False, offset=63, stderr="Invalid magic value")])
    moved = cl.rederive_container_coverage(case)
    assert IMG not in moved.get("unblocked", []) and _status(case)[0] == "blocked"


def test_an_empty_or_unreadable_trace_recounts_nothing(case):
    """A trace with no call in it, or one that would not parse, says nothing
    about what was read; the ledger keeps its statuses."""
    _identified_only_ledger(case)
    before = cl.load_ledger(case)
    for write in (lambda: _trace(case, []),
                  lambda: (case / "analysis" / "CASE-A_trace.json").write_text(
                      "{not json", encoding="utf-8")):
        write()
        assert cl.rederive_container_coverage(case) == {}
        assert cl.load_ledger(case)["units"] == before["units"]
        assert _status(case) == ("blocked", "examined")


def test_plane_a_reports_the_recount(case, monkeypatch):
    from core.incremental import format_plane_a_report, plane_a_scan
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "off")
    _identified_only_ledger(case)
    _trace(case, [_tsk(5, "mmls", IMG, True), _tsk(6, "mmls", OTHER, True)])
    res = plane_a_scan(case, persist=True)
    assert res["coverage_rederived"] == {"demoted": [OTHER], "unblocked": [IMG]}
    assert res["work"]["pending"]
    assert "Coverage recounted from the trace" in format_plane_a_report(res)
