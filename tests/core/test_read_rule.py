"""One read rule over the trace (core.coverage_ledger): a read is a call
whose own tool examines content and whose own outcome is success. A
background job's start stands for the outcome its runner recorded; a
sub-command running the program of a tool that reads no content is named by
that tool; "was it read" is the trace's answer, never a status the ledger
stored. Invented case data only."""
import json
import os
import re

import pytest

from core import coverage_ledger as cl
from core import evidence_items as ei

IMG = "evidence/images/CORP-WS01.vmdk"
RAW = "evidence/images/CORP-WS02.raw"
PCAP = "evidence/net/CORP-FW01.pcap"
JOB = "20310301T081200_plaso_targeted_4242_0"
FIXTURE_IDENTITIES = ("CORP-WS01", "CORP-WS02", "CORP-FW01", "CASE-A", "20310301T081200", "4242")
NO_FS = "Cannot determine file system type"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "CASE-A"
    for sub in ("evidence/images", "evidence/net", ".atlas", "analysis"):
        (d / sub).mkdir(parents=True)
    for rel in (IMG, RAW, PCAP):
        (d / rel).write_bytes(b"\0" * 4096)
    (d / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    cl.build_coverage_ledger(d)
    return d


def _job(case, job_id=JOB, *, exit_code=None, alive=False, log="Unable to scan source: extent missing", **meta):
    """A job directory as tools.jobs_runner leaves it."""
    jd = case / "analysis" / "jobs" / job_id
    jd.mkdir(parents=True)
    (jd / "meta.json").write_text(json.dumps({
        "job_id": job_id, "kind": "plaso_targeted", "argv": ["log2timeline.py", IMG],
        "supervisor_pid": os.getpid() if alive else 0, **meta,
        **({"exit_code": exit_code} if exit_code is not None else {})}), encoding="utf-8")
    if exit_code is not None:
        (jd / "exit_code").write_text(str(exit_code), encoding="utf-8")
    (jd / "stdout.log").write_text(f"starting\n{log}\n", encoding="utf-8")


def _start(cid, rel=IMG, job_id=JOB, tool="plaso_plaso_create_targeted"):
    """The trace entry tools.jobs._start_job writes for a job it started."""
    return {"type": "tool_call", "call_id": cid, "mcp_tool": tool, "success": True, "exit_code": 0,
            "cmd": f"[background job {job_id}] log2timeline.py --storage-file analysis/t.plaso {rel}"}


def _call(cid, cmd, tool, ok, *, exit_code=None, stderr="", failure_class=None, stdout=""):
    e = {"type": "tool_call", "call_id": cid, "cmd": cmd, "mcp_tool": tool, "success": ok,
         "exit_code": (0 if ok else 1) if exit_code is None else exit_code, "stderr": stderr,
         "stdout_excerpt": stdout}
    if not ok:
        e["failure_class"] = failure_class or "tool_error"
    return e


def _reads_failed(case, trace, rel=IMG):
    reads, failed = cl._reads_and_failures(cl._read_attempts(case, trace, {}), [rel])
    return [e["call_id"] for e in reads], failed


def _state(case, rel=IMG):
    led = cl.load_ledger(case)
    unit = next((u for u in led["units"].values() if u["path"] == rel), {})
    return unit, ei.find(led, rel) or {}


# ── a job's start counts by its runner's outcome ─────────────────────────

@pytest.mark.parametrize("job, read, failed", [
    (None, False, False),                                                    # no record of the job
    ({"alive": True}, False, False),                                         # still running
    ({}, False, False),                                                      # runner died, no outcome
    ({"exit_code": 0}, True, False),                                         # finished
    ({"exit_code": 1}, False, True),                                         # failed
    ({"exit_code": -15, "aborted_reason": "cancelled"}, False, False),       # cancelled
    ({"exit_code": -9, "aborted_reason": "disk_low"}, False, False),         # stopped by the disk guard
    ({"exit_code": 1, "view_lost": "the raw view changed under the job"}, False, False),  # transport, not evidence
    ({"exit_code": 3, "stopped_by_atlas": "the run that started the batch is gone"}, False, False),  # any runner's stop
])
def test_a_job_start_counts_by_the_outcome_its_runner_recorded(case, job, read, failed):
    if job is not None:
        _job(case, **job)
    reads, fail = _reads_failed(case, [_start(9)])
    assert (reads == [9]) is read and fail is failed


def test_a_failed_job_is_a_failed_read_the_image_can_be_blocked_on(case):
    _job(case, exit_code=1)
    entry = cl.resolved_entry(case, _start(9))
    assert entry["success"] is False and entry["stderr"] == "Unable to scan source: extent missing"
    r = cl.mark_unit_blocked(case, IMG, reason="log2timeline cannot open the container", trace_entries=[_start(9)])
    assert r["success"] is True


def test_a_finished_job_is_a_read_of_what_it_names(case):
    _job(case, exit_code=0)
    r = cl.mark_unit_blocked(case, IMG, reason="log2timeline cannot open the container", trace_entries=[_start(9)])
    assert r["success"] is False and "was read by call 9" in r["error"]


def test_a_job_outcome_is_looked_up_once_per_pass(case, monkeypatch):
    _job(case, exit_code=1)
    seen = []
    real = cl._job_record
    monkeypatch.setattr(cl, "_job_record", lambda root, job_id: seen.append(job_id) or real(root, job_id))
    cl._read_attempts(case, [_start(9), _start(10), _start(11)], {})
    assert seen == [JOB]


def _collect(cid, ok, job_id=JOB, exit_code=0):
    """The trace entry tools.jobs._collect_impl writes when a job is collected."""
    e = {"type": "tool_call", "call_id": cid, "mcp_tool": "job_job_collect", "success": ok,
         "exit_code": exit_code, "cmd": f"[background job {job_id} collected] log2timeline.py {IMG}"}
    if not ok:
        e["failure_class"] = "tool_error"
    return e


def test_the_collect_record_is_a_call_of_its_own(case):
    collect = _collect(12, True)
    assert cl.resolved_entry(case, collect) is collect                  # no record of the job: as it is
    _job(case, exit_code=1)
    assert _reads_failed(case, [_collect(12, False, exit_code=1)]) == ([], True)


def test_the_collect_of_a_job_atlas_stopped_is_no_attempt_either(case):
    _job(case, exit_code=3, stopped_by_atlas="the run that started the batch is gone")
    collect = _collect(12, False, exit_code=3)
    assert cl.resolved_entry(case, collect) is None
    assert _reads_failed(case, [_start(9), collect]) == ([], False)
    r = cl.mark_unit_blocked(case, IMG, reason="the reader never finished", trace_entries=[_start(9), collect])
    assert r["success"] is False and "no tool call in the trace is a failed attempt" in r["error"]


def test_a_runner_of_atlas_records_its_own_stop_and_the_rule_counts_none(case):
    """A tool the job runner supervises that stops for a reason of Atlas's
    (tools.jobs_runner.record_atlas_stop) and exits non-zero: the runner's
    record says Atlas stopped it, so the job is neither a read nor a failed one."""
    import sys
    from tools import jobs_runner
    jd = case / "analysis" / "jobs" / JOB
    jd.mkdir(parents=True)
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    stop = ("from tools.jobs_runner import record_atlas_stop; "
            "record_atlas_stop('the run that started the batch is gone'); raise SystemExit(3)")
    (jd / "meta.json").write_text(json.dumps({"job_id": JOB, "argv": [sys.executable, "-c", stop],
                                              "needs_sudo": False, "params": {}, "cwd": repo}), encoding="utf-8")
    assert jobs_runner.main(str(jd)) == 0
    meta = json.loads((jd / "meta.json").read_text(encoding="utf-8"))
    assert meta["exit_code"] == 3 and meta["stopped_by_atlas"] == "the run that started the batch is gone"
    assert cl.resolved_entry(case, _start(9)) is None
    assert _reads_failed(case, [_start(9)]) == ([], False)


def test_the_memory_batch_says_its_owner_gone_stop_is_atlas_s(tmp_path, monkeypatch):
    from core import memory_batch as MB
    from tools import memory_batch_runner as runner
    jd = tmp_path / "job"
    jd.mkdir()
    monkeypatch.setenv("ATLAS_JOB_DIR", str(jd))
    monkeypatch.setattr(MB, "owners_gone", lambda _case: [])
    monkeypatch.setattr(MB, "not_run", lambda _case: {})
    man = {"status": str(tmp_path / "status.json"), "case": str(tmp_path)}
    assert runner._stopped_owner_gone(man, {"images": {}}) == 3
    assert (jd / "stopped_by_atlas").read_text(encoding="utf-8") == MB.STOP_OWNER_GONE


# ── a sub-command by its own program ─────────────────────────────────────

@pytest.mark.parametrize("cmd, own", [
    (f"mmls {IMG}", "tsk_mmls"),
    ("sudo mmls /dev/loop9", "tsk_mmls"),
    (f"/usr/bin/fsstat {IMG}", "tsk_fsstat"),
    ("ewfinfo evidence/images/disk.E01", "ewf_info"),
    ("ewfverify evidence/images/disk.E01", "ewf_verify"),
    ("md5deep -r evidence/net", "hash_md5deep_scan"),
])
def test_a_sub_command_of_a_tool_that_reads_nothing_is_named_by_its_program(cmd, own):
    assert cl._entry_tool({"type": "tool_call", "cmd": cmd, "mcp_tool": "tsk_tsk_fls"}) == own


@pytest.mark.parametrize("entry, tool", [
    ({"cmd": f"fls -r {IMG}", "mcp_tool": "tsk_tsk_resolve_path"}, "tsk_resolve_path"),   # a reading program
    ({"cmd": "<py>:tsk_tsk_mmls", "mcp_tool": ""}, "tsk_mmls"),
    ({"cmd": f"[background job {JOB}] mmls {IMG}", "mcp_tool": "plaso_plaso_create_targeted"},
     "plaso_create_targeted"),
    ({"cmd": f"mmls {IMG}"}, ""),                                                         # the pre-run pass
])
def test_other_entries_keep_the_tool_that_ran_them(entry, tool):
    assert cl._entry_tool({"type": "tool_call", **entry}) == tool


def test_a_reader_whose_offset_lookup_answered_without_a_table_read_nothing(case):
    """A filesystem read that failed at sector 0 and the partition-table
    lookup its wrapper ran (silent exit 1, recorded as an answer by older
    builds): no read, one failed read, and the image can be blocked."""
    trace = [_call(11, f"fls {IMG}", "tsk_tsk_fls", False, stderr=NO_FS),
             _call(12, f"mmls {IMG}", "tsk_tsk_fls", True, exit_code=1,
                   stdout="no partition table: the image carries no volume system")]
    assert _reads_failed(case, trace) == ([], True)
    r = cl.mark_unit_blocked(case, IMG, reason="the container format is not readable here", trace_entries=trace)
    assert r["success"] is True


def test_a_partition_table_the_lookup_found_still_refuses_the_block(case):
    table = "DOS Partition Table\n002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)"
    trace = [_call(11, f"fls {IMG}", "tsk_tsk_fls", False, stderr=NO_FS),
             _call(12, f"mmls {IMG}", "tsk_tsk_fls", True, stdout=table)]
    r = cl.mark_unit_blocked(case, IMG, reason="the container format is not readable here", trace_entries=trace)
    assert r["success"] is False and "partition table" in r["error"]


def test_a_filesystem_probe_that_fails_under_the_partition_tool_is_an_open_attempt(case):
    trace = [_call(13, f"fsstat {IMG}", "tsk_tsk_mmls", False, stderr=NO_FS)]
    assert _reads_failed(case, trace) == ([], True)
    assert cl.mark_unit_blocked(case, IMG, reason="no filesystem opens in the container",
                                trace_entries=trace)["success"] is True


# ── was it read: the trace, never a stored status ────────────────────────

def test_a_stored_credit_no_call_backs_does_not_refuse_the_block(case):
    cl.observe_tool_paths(case, tool_name="plaso_create_targeted", cmd_or_args=json.dumps({"evidence_path": IMG}),
                          success=True, result_text=json.dumps({"success": True}))
    unit, item = _state(case)
    assert unit["status"] == "probed" and item["status"] == "examined"
    _job(case, exit_code=1)
    r = cl.mark_unit_blocked(case, IMG, reason="log2timeline cannot open the container", trace_entries=[_start(9)])
    assert r["success"] is True
    unit, item = _state(case)
    assert unit["status"] == "blocked" and not unit.get("read_by")
    assert item["status"] == "blocked" and not item.get("read_by") and not item.get("examined_by")


def test_an_item_that_is_no_unit_is_blocked_by_the_trace_too(case):
    led = cl.load_ledger(case)
    item = ei.find(led, PCAP)
    assert item is not None and item["kind"] == "capture"
    item.update(status="examined", examined_by={"call_id": "", "tool": "net_tcpdump_read"})
    cl.save_ledger(case, led)
    trace = [_call(14, f"tcpdump -r {PCAP}", "net_net_tcpdump_read", False, stderr="truncated dump file")]
    r = cl.mark_unit_blocked(case, PCAP, reason="the capture is truncated", trace_entries=trace)
    assert r["success"] is True and _state(case, PCAP)[1]["status"] == "blocked"


def test_an_item_read_through_another_segment_is_not_blocked(tmp_path):
    d = tmp_path / "CASE-A"
    (d / "evidence" / "archive").mkdir(parents=True)
    (d / ".atlas").mkdir()
    (d / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    first, second = "evidence/archive/CORP-WS01.7z.001", "evidence/archive/CORP-WS01.7z.002"
    for rel in (first, second):
        (d / rel).write_bytes(b"\0" * 64)
    cl.build_coverage_ledger(d)
    led = cl.load_ledger(d)
    assert ei.find(led, first)["segments"] == [second]
    assert not any(u["path"] == first for u in led["units"].values())           # no unit: the item verb
    trace = [_call(40, f"<py>:archive_archive_extract {second}", "archive_archive_extract", True),
             _call(41, f"7z t {first}", "archive_archive_test", False, stderr="CRC failed")]
    r = cl.mark_unit_blocked(d, first, reason="the first volume of the set is damaged", trace_entries=trace)
    assert r["success"] is False and "was read by call 40" in r["error"]


# ── the recount: pure, and the listed/read split ─────────────────────────

def test_the_recount_writes_only_what_differs_and_keeps_listings_apart(case, monkeypatch):
    trace = [_call(20, f"fls -r {IMG}", "tsk_tsk_fls", True),
             _call(21, f"icat {RAW} 41", "tsk_tsk_icat", True)]
    monkeypatch.setattr("core.execution_log.trace_tool_calls", lambda _root: trace)
    moved = cl.rederive_container_coverage(case)
    assert sorted(moved["credited"]) == sorted([IMG, RAW])
    unit, item = _state(case)
    assert item["listed_by"] == {"call_id": "20", "tool": "tsk_fls"} and item.get("read_by") is None
    assert unit["listed_by"] == {"call_id": "20", "tool": "tsk_fls"} and unit.get("read_by") is None
    assert _state(case, RAW)[1]["read_by"] == {"call_id": "21", "tool": "tsk_icat"}
    saves = []
    monkeypatch.setattr(cl, "save_ledger", lambda *a, **k: saves.append(a))
    assert cl.rederive_container_coverage(case) == {} and saves == []


def test_the_recount_demotes_a_credit_no_call_backs_and_clears_its_reads(case, monkeypatch):
    cl.observe_tool_paths(case, tool_name="plaso_create_targeted", cmd_or_args=json.dumps({"evidence_path": IMG}),
                          success=True, result_text=json.dumps({"success": True}))
    assert _state(case)[1].get("read_by")
    _job(case, exit_code=1)
    monkeypatch.setattr("core.execution_log.trace_tool_calls", lambda _root: [_start(9)])
    assert cl.rederive_container_coverage(case) == {"demoted": [IMG]}
    unit, item = _state(case)
    assert unit["status"] == "unseen" and item["status"] == "unseen"
    assert not item.get("read_by") and not item.get("listed_by") and not unit.get("read_by")


def test_the_recount_clears_a_read_record_left_on_an_unseen_item(case, monkeypatch):
    led = cl.load_ledger(case)
    ei.find(led, IMG)["read_by"] = {"call_id": "5", "tool": "tsk_icat"}
    cl.save_ledger(case, led)
    monkeypatch.setattr("core.execution_log.trace_tool_calls",
                        lambda _root: [_call(6, f"icat {RAW} 7", "tsk_tsk_icat", True)])
    cl.rederive_container_coverage(case)
    assert _state(case)[1]["status"] == "unseen" and not _state(case)[1].get("read_by")


# ── the split across a rebuild and a reset ───────────────────────────────

def test_a_rebuild_keeps_the_listed_and_read_records_and_a_reset_drops_them(case):
    cl.observe_tool_paths(case, tool_name="tsk_fls", cmd_or_args=json.dumps({"image": IMG}),
                          success=True, result_text=json.dumps({"success": True}))
    unit, item = _state(case)
    assert unit["listed_by"]["tool"] == item["listed_by"]["tool"] == "tsk_fls"
    cl.build_coverage_ledger(case)
    unit, item = _state(case)
    assert unit["listed_by"]["tool"] == item["listed_by"]["tool"] == "tsk_fls"
    assert not ei.was_read(item) or not ei._honest()
    cl.reset_unit_statuses(case)
    unit, item = _state(case)
    assert not unit.get("listed_by") and not item.get("listed_by") and item["status"] == "unseen"


# ── the disposition follows the read record both ways ────────────────────

def test_a_class_less_items_read_follows_its_read_record(case):
    from core.evidence_disposition import credit_dispositions
    led = cl.load_ledger(case)
    led["classes"] = {}
    item = ei.find(led, IMG)
    item.update(state="pending", read_by={"call_id": "30", "tool": "tsk_icat"})
    cl.save_ledger(case, led)
    credit_dispositions(case)
    item = _state(case)[1]
    assert item["state"] == "read" and item["proof_call_ids"] == ["30"]
    led = cl.load_ledger(case)
    ei.find(led, IMG)["read_by"] = None
    cl.save_ledger(case, led)
    credit_dispositions(case)
    item = _state(case)[1]
    assert item["state"] == "pending" and item["proof_call_ids"] == []


# ── the copies of the rule: a part limitation, the work order ────────────

@pytest.mark.parametrize("job, examined, unreadable", [
    ({"exit_code": 0}, True, False),
    ({"exit_code": 1}, False, True),
    ({"alive": True}, False, False),
])
def test_a_part_limitation_reads_a_cited_job_by_its_outcome(case, monkeypatch, job, examined, unreadable):
    from core import execution_log
    from core.investigation_tasks import _limitation_refusal

    class _Idx:
        by_call_id = {9: _start(9)}
    monkeypatch.setattr(execution_log.log, "index", lambda: _Idx())
    _job(case, **job)
    reason = "the CORP-WS01.vmdk timeline names no remote logon in the window"
    assert (_limitation_refusal(case, {}, "examined", reason, [9]) is None) is examined
    assert (_limitation_refusal(case, {}, "unreadable", reason, [9]) is None) is unreadable


def test_the_part_gate_says_what_counts_as_a_failed_read(case, monkeypatch):
    """unreadable stands on a call that ran on the source and failed; the
    refusal names why each cited call is none: a gate turned it away, a job
    has not finished, a call of no analyst tool."""
    from core import execution_log
    from core.investigation_tasks import _limitation_refusal

    class _Idx:
        by_call_id = {11: _call(11, f"fls {IMG}", "tsk_tsk_fls", False, failure_class="gate_refusal",
                                stderr="[access_disk_budget] stop filesystem enumeration"),
                      12: _call(12, f"fls {IMG}", "tsk_tsk_fls", False, stderr=NO_FS),
                      13: _start(13),
                      14: {"type": "tool_call", "call_id": 14, "cmd": f"fls -r {IMG}", "success": False,
                           "failure_class": "tool_error", "stderr": NO_FS}}
    monkeypatch.setattr(execution_log.log, "index", lambda: _Idx())
    _job(case, alive=True)
    reason = "the CORP-WS01.vmdk container holds no filesystem The Sleuth Kit opens"
    r = _limitation_refusal(case, {}, "unreadable", reason, [11])
    assert r.startswith("unreadable needs a failed read of the source")
    assert "a call a gate turned away" in r and "call 11 was turned away by a gate" in r
    r = _limitation_refusal(case, {}, "unreadable", reason, [13])
    assert "call 13 starts a background job that has not finished" in r
    # A call the pre-run pass made (no analyst tool) is no read for the analyst.
    assert "call 14 is not a read of the source" in _limitation_refusal(case, {}, "unreadable", reason, [14])
    assert _limitation_refusal(case, {}, "unreadable", reason, [11, 12]) is None
    r = _limitation_refusal(case, {}, "examined", reason, [13])
    assert "counts once the job has finished" in r and "call 13 starts a background job" in r


def test_the_per_file_read_state_reads_a_job_start_by_its_outcome(case, monkeypatch):
    from core import artifact_value as av
    monkeypatch.setattr("core.execution_log.trace_entries", lambda _case: [_start(9)])
    _job(case, alive=True)
    assert av._trace_calls(case)[0] == []
    _job(case, job_id=JOB + "1", exit_code=1)
    monkeypatch.setattr("core.execution_log.trace_entries", lambda _case: [_start(9, job_id=JOB + "1")])
    calls = av._trace_calls(case)[0]
    assert [(c["call_id"], c["failed"]) for c in calls] == [(9, True)]


def test_the_memory_structure_credit_reads_a_job_start_by_its_outcome(case, monkeypatch):
    from core.evidence_disposition import _successful_calls
    start = dict(_start(9, tool="vol_vol_pslist"),
                 cmd=f"[background job {JOB}] vol -f evidence/mem/CORP-WS01.mem windows.pslist")
    monkeypatch.setattr("core.execution_log.trace_entries", lambda _case: [start])
    _job(case, alive=True)
    assert _successful_calls(case) == []
    (case / "analysis" / "jobs" / JOB / "exit_code").write_text("0", encoding="utf-8")
    assert len(_successful_calls(case)) == 1


def test_the_run_audit_reads_a_job_start_by_its_outcome(case):
    from devtools.validation import run_audit as ra
    (case / "CASE.md").write_text("# Case\n\n**Case ID:** CASE-A\n", encoding="utf-8")
    (case / "analysis" / "CASE-A_trace.jsonl").write_text(
        json.dumps({"seq": 1, "entry": _start(9)}) + "\n", encoding="utf-8")
    _job(case, alive=True)
    rows = {r["path"]: r for r in ra.leftover(ra.Run(case))["units"]}
    assert rows[IMG]["trace_view"] == "untouched"
    (case / "analysis" / "jobs" / JOB / "exit_code").write_text("0", encoding="utf-8")
    rows = {r["path"]: r for r in ra.leftover(ra.Run(case))["units"]}
    assert rows[IMG]["trace_view"] == "content_read"


@pytest.mark.parametrize("job, status", [({"alive": True}, "due"), ({"exit_code": 0}, "resolved"),
                                         ({"exit_code": 1}, "failed")])
def test_a_work_item_waits_for_the_job_its_call_started(case, job, status):
    from core.work_order import _call_view, _close_by
    _job(case, **job)
    item = {"call_id": 50, "status": "due", "origin": "plan", "tool": "plaso_create_targeted",
            "target": {"path": IMG}, "attempts": []}
    _close_by(item, _call_view(_start(9)), str(case))
    assert item["status"] == status
    assert item["attempts"] == ([9] if status == "due" else [])
    if status == "failed":
        assert item["outcome"] == "Unable to scan source: extent missing"


def test_no_identity_of_these_fixtures_reaches_the_rule():
    """The rule is mechanism: no name these fixtures invent is in its code."""
    import pathlib
    src = pathlib.Path("core/coverage_ledger.py").read_text(encoding="utf-8")
    code = re.sub(r'"""(?:.|\n)*?"""', "", src)
    code = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#")).lower()
    for token in FIXTURE_IDENTITIES:
        assert token.lower() not in code, token
