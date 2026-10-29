"""The writers behind the one read rule (core.coverage_ledger): a job's start
returns the record it stands for and its outcome is the read; a repeat the
job deduplicated and a hand-off to a running job read nothing either; the
collect credits what the job read; the job's meta keeps both writers' keys;
a returned refusal always reaches the trace, once, with the call's action
id; mmls's silent exit is answered by a look at the first sector; a
container refused for good is a failed read. Invented case data only."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core import coverage_ledger as cl
from core import evidence_items as ei

IMG = "evidence/images/CORP-WS03.raw"
MEM = "evidence/images/CORP-WS03.mem"
NO_FS = "Cannot determine file system type"


@pytest.fixture
def case(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    d = tmp_path / "CASE-B"
    for sub in ("evidence/images", ".atlas", "analysis"):
        (d / sub).mkdir(parents=True)
    (d / IMG).write_bytes(b"\0" * (2 << 20))
    (d / MEM).write_bytes(b"\0" * 64)
    (d / ".atlas" / "evidence_inventory.json").write_text(json.dumps({"complete": True, "summary": {}}),
                                                         encoding="utf-8")
    cl.build_coverage_ledger(d)
    log = ExecutionLog()
    log.configure("CASE-B", str(d / "analysis" / "CASE-B_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    monkeypatch.chdir(d)
    return d, log


def _status(d, rel=IMG):
    return (ei.find(cl.load_ledger(d), rel) or {}).get("status")


def _as_tool(tool):
    """Run a block as the middleware does for a call of ``tool``."""
    from core.execution_log import current_mcp_tool

    class _Ctx:
        def __enter__(self):
            self.tok = current_mcp_tool.set(tool)

        def __exit__(self, *exc):
            current_mcp_tool.reset(self.tok)
    return _Ctx()


def _start(d, tool="plaso_plaso_create_targeted"):
    from tools import jobs
    fake = MagicMock()
    fake.pid = os.getpid()                                # a live supervisor: the job runs
    params = {"evidence_path": str(d / IMG), "storage_file": str(d / "analysis" / "t.plaso"),
              "artifact_filters": "WindowsEventLogs", "timezone": "UTC"}
    with _as_tool(tool), patch("tools.jobs.subprocess.Popen", return_value=fake):
        return jobs._start_job("plaso_targeted", params), params


def _finish(d, job_id, code=0, **meta):
    from tools.jobs_runner import merge_meta
    jd = d / "analysis" / "jobs" / job_id
    merge_meta(str(jd), {"exit_code": code, "finished_utc": "2031-03-01T08:30:00Z", **meta})
    (jd / "exit_code").write_text(str(code), encoding="utf-8")


def _observe(d, tool, args, result):
    cl.observe_tool_paths(d, tool_name=tool, cmd_or_args=json.dumps(args), success=True,
                          result_text=json.dumps(result))


# ── a job's start is its record; the record reads by the outcome ───

def test_a_start_returns_its_record_and_credits_nothing_until_the_job_read(case):
    d, log = case
    r, params = _start(d)
    entry = log.index().by_call_id[r["_atlas_call_id"]]
    assert entry["cmd"].startswith(f"[background job {r['job_id']}] ")
    _observe(d, "plaso_create_targeted", params, r)
    assert _status(d) == "unseen"
    _finish(d, r["job_id"])
    _observe(d, "plaso_create_targeted", params, r)
    assert _status(d) == "examined"


def test_a_repeat_the_job_deduplicated_stands_for_that_job(case):
    d, log = case
    first, params = _start(d)
    with patch("tools.jobs._pid_alive", return_value=True):
        again, _ = _start(d)
    assert again["deduplicated"] and again["job_id"] == first["job_id"]
    record = log.index().by_call_id[again["_atlas_call_id"]]
    assert record["cmd"].startswith(f"[background job {first['job_id']}] ")
    _observe(d, "plaso_create_targeted", params, again)
    assert _status(d) == "unseen"
    assert cl.resolved_entry(d, record) is None                 # still running: no read, no attempt


def test_an_autodispatched_call_keeps_the_stamp_of_its_job(case, monkeypatch):
    d, _log = case
    from tools import plaso
    monkeypatch.setenv("ATLAS_AUTODISPATCH_MB", "1")
    fake = MagicMock()
    fake.pid = os.getpid()
    args = {"evidence_path": str(d / IMG), "storage_file": str(d / "analysis" / "t.plaso"),
            "artifact_filters": "WindowsEventLogs"}
    with _as_tool("plaso_plaso_create_targeted"), patch("tools.jobs.subprocess.Popen", return_value=fake):
        r = getattr(plaso.plaso_create_targeted, "fn", plaso.plaso_create_targeted)(**args)
    assert r["deferred"] and r["_atlas_call_id"]
    _observe(d, "plaso_create_targeted", args, r)
    assert _status(d) == "unseen"


def test_a_call_handed_to_the_memory_batch_reads_nothing_while_it_runs(case, monkeypatch):
    """A vol call the running batch answers "deferred" (tools.volatility):
    its result stands for the batch's start, and its own result entry names
    the job, so neither the live credit nor the rule takes it for a read."""
    d, log = case
    from core import middleware
    from tools import volatility
    mem = MEM
    job = "20310301T081200_memory_batch_7_0"
    with _as_tool("vol_vol_pslist"):
        sid = log.record_tool_call(f"[background job {job}] python -m tools.memory_batch_runner analysis/m.json",
                                   True, False, 0, 0)
    jd = d / "analysis" / "jobs" / job
    jd.mkdir(parents=True)
    (jd / "meta.json").write_text(json.dumps({"job_id": job, "start_call_id": sid, "supervisor_pid": os.getpid()}),
                                  encoding="utf-8")
    monkeypatch.setattr("core.memory_batch.queued", lambda case_dir, image, plugin: job)
    answer = volatility._in_batch(str(d), str(d / mem), "windows.pslist")
    assert answer["_atlas_call_id"] == sid
    args = {"memory_image": str(d / mem)}
    _observe(d, "vol_pslist", args, answer)
    assert _status(d, mem) == "unseen"
    before = len(log._entries)
    middleware._trace_success_baseline("vol_vol_pslist", 0.1, before, result=answer, args=args, action_id=5)
    handed = log._entries[-1]
    assert handed["deferred_to_job"] == job and cl.resolved_entry(d, handed) is None
    _finish(d, job)
    assert cl.resolved_entry(d, handed)["success"] is True      # the batch ran: the image was read


def test_a_cancel_record_reads_nothing(case):
    """Not even for a job whose record says it read (it finished by itself
    before the cancel took effect): the job's start and collect carry that
    read, the cancel is none."""
    d, _log = case
    job_id = "20310301T081200_plaso_targeted_7_0"
    (d / "analysis" / "jobs" / job_id).mkdir(parents=True)
    _finish(d, job_id)
    cancel = {"type": "tool_call", "call_id": 40, "mcp_tool": "job_job_cancel", "success": True, "exit_code": -15,
              "cmd": f"[background job {job_id} cancelled] log2timeline.py {IMG}"}
    start = {**cancel, "call_id": 39, "cmd": f"[background job {job_id}] log2timeline.py {IMG}"}
    assert cl.resolved_entry(d, start)["success"] is True        # the job's own record: it read
    assert cl.resolved_entry(d, cancel) is None


# ── the collect credits what the job read ────────────────────────────

def test_the_collect_of_a_finished_job_credits_the_evidence_under_its_start(case):
    from tools import jobs
    d, _log = case
    r, _params = _start(d, tool="job_job_start_plaso_targeted")
    _finish(d, r["job_id"])
    assert _status(d) == "unseen"
    jobs._collect_impl(r["job_id"])
    item = ei.find(cl.load_ledger(d), IMG)
    assert item["status"] == "examined" and item["read_by"]["tool"] == "job_start_plaso_targeted"


@pytest.mark.parametrize("code, meta", [(1, {}), (3, {"stopped_by_atlas": "the run that owned it is gone"})])
def test_the_collect_of_a_failed_or_stopped_job_credits_nothing(case, code, meta):
    from tools import jobs
    d, _log = case
    r, _params = _start(d)
    _finish(d, r["job_id"], code, **meta)
    jobs._collect_impl(r["job_id"])
    assert _status(d) == "unseen"


# ── the job's meta keeps both writers' keys ──────────────────────────

def test_the_runner_keeps_what_the_server_wrote_after_it_started(tmp_path):
    from tools import jobs_runner
    jd = tmp_path / "job"
    jd.mkdir()
    # The tool stands in for the server's second write, made while it runs.
    late = ("import json, os; p = os.path.join(os.environ['ATLAS_JOB_DIR'], 'meta.json'); "
            "m = json.load(open(p)); m['start_call_id'] = 77; json.dump(m, open(p, 'w'))")
    repo = str(Path(__file__).resolve().parents[2])
    (jd / "meta.json").write_text(json.dumps({"job_id": "J1", "argv": [sys.executable, "-c", late],
                                              "needs_sudo": False, "params": {}, "cwd": repo}), encoding="utf-8")
    assert jobs_runner.main(str(jd)) == 0
    meta = json.loads((jd / "meta.json").read_text(encoding="utf-8"))
    assert meta["start_call_id"] == 77 and meta["exit_code"] == 0


def test_the_server_keeps_what_a_quick_runner_wrote(tmp_path):
    from tools.jobs_runner import merge_meta
    jd = tmp_path / "job"
    jd.mkdir()
    (jd / "meta.json").write_text(json.dumps({"job_id": "J2", "argv": ["true"]}), encoding="utf-8")
    merge_meta(str(jd), {"exit_code": 0, "finished_utc": "2031-03-01T08:30:00Z"})        # the runner, first
    merge_meta(str(jd), {"start_call_id": 9, "supervisor_pid": 4242})                     # the server, after
    meta = json.loads((jd / "meta.json").read_text(encoding="utf-8"))
    assert (meta["exit_code"], meta["start_call_id"], meta["argv"]) == (0, 9, ["true"])


# ── a returned refusal reaches the trace once, with its action id ───

def test_a_refusal_after_a_sub_command_gets_its_own_entry(case):
    d, log = case
    from core import middleware
    from core.execution_log import action_key
    before = len(log._entries)
    sub = log.record_tool_call(f"qemu-img info --output=json {d / IMG}", True, False, 0, 0, action_id=21)
    refusal = {"success": False, "error": "Insufficient free space for raw export: need up to 9.0 GB"}
    middleware._trace_success_baseline("img_img_vmdk_export_raw", 0.1, before, result=refusal,
                                       args={"descriptor_path": IMG}, action_id=21)
    added = log._entries[before:]
    assert [e["success"] for e in added] == [True, False]
    entry = added[-1]
    assert entry["cmd"] == "<py>:img_img_vmdk_export_raw" and entry["input_call_ids"] == [sub]
    assert "Insufficient free space" in entry["stderr"] and action_key(entry) == action_key(added[0]) == 21


def test_a_failure_handed_back_as_is_is_not_written_twice(case):
    d, log = case
    from core import middleware
    before = len(log._entries)
    cid = log.record_tool_call(f"fls {d / IMG}", False, False, 0, 1, stderr=NO_FS)
    result = {"success": False, "stderr": NO_FS, "exit_code": 1, "_atlas_call_id": cid}
    middleware._trace_success_baseline("tsk_tsk_fls", 0.1, before, result=result, args={"image": IMG})
    assert len(log._entries) == before + 1


def test_a_failure_wrapped_without_its_stamp_is_written_twice_and_blocks_once(case):
    """The known cost of the rule: two failed entries for one failure, the
    result entry naming the sub-call as its input; the block verb and the
    work order read them unchanged."""
    d, log = case
    from core import middleware
    from core.work_order import _call_view, _close_by
    before = len(log._entries)
    with _as_tool("tsk_tsk_fls"):
        sub = log.record_tool_call(f"fls {IMG}", False, False, 0, 1, stderr=NO_FS)
    middleware._trace_success_baseline("tsk_tsk_fls", 0.1, before, result={"success": False, "error": NO_FS},
                                       args={"image": IMG})
    added = log._entries[before:]
    assert [e["success"] for e in added] == [False, False] and added[-1]["input_call_ids"] == [sub]
    r = cl.mark_unit_blocked(d, IMG, reason="no filesystem in the image opens", trace_entries=list(added))
    assert r["success"] is True
    item = {"call_id": 60, "status": "due", "origin": "plan", "tool": "tsk_fls", "target": {"path": IMG},
            "attempts": []}
    _close_by(item, _call_view(added[0]), str(d))
    assert item["status"] == "failed"


def test_the_middleware_gives_the_result_entry_its_calls_action_id(case):
    """The result entry is written after the call's context is reset, so the
    middleware hands it the call's action id: a sub-command and the refusal
    returned after it are one action (the progress line and the DAIR window
    count actions)."""
    import asyncio
    from core.execution_log import action_key
    from core.middleware import NarrationMiddleware
    d, log = case
    before = len(log._entries)

    async def call_next(_ctx):
        log.record_tool_call(f"fls {d / IMG}", True, False, 0, 0)        # the executor, inside the call
        return {"success": False, "error": NO_FS}

    msg = MagicMock(arguments={"image": IMG})
    msg.name = "tsk_tsk_fls"
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock(message=msg)
    ctx.copy = MagicMock(return_value=ctx)
    asyncio.run(NarrationMiddleware().on_call_tool(ctx, call_next))
    added = [e for e in log._entries[before:] if e.get("type") == "tool_call"]
    assert [e["success"] for e in added] == [True, False]
    assert added[0].get("action_id") and action_key(added[1]) == action_key(added[0])


# ── mmls's silent exit is answered by the first sector ───────────────

def _tsk_run(*results):
    seq = list(results)
    return patch("tools.sleuthkit.run", side_effect=lambda *a, **k: dict(seq.pop(0)))


def _silent_mmls(cid=31):
    return {"success": False, "exit_code": 1, "stdout": "", "stderr": "", "cmd": "mmls x", "_atlas_call_id": cid}


def test_mmls_without_a_table_answers_when_a_filesystem_opens_at_sector_zero(case):
    d, _log = case
    from tools import sleuthkit
    fsstat = {"success": True, "exit_code": 0, "stderr": "", "cmd": "fsstat x", "_atlas_call_id": 32,
              "stdout": "FILE SYSTEM INFORMATION\n--------------------------------------------\nFile System Type: FAT32\n"}
    with _tsk_run(_silent_mmls(), fsstat):
        r = getattr(sleuthkit.tsk_mmls, "fn", sleuthkit.tsk_mmls)(str(d / IMG))
    assert r["success"] is True and r["volume_system"] == "none"
    assert "a FAT32 filesystem opens at sector 0 (fsstat, call 32)" in r["stdout"]
    assert "without offset_sectors" in r["stdout"]


def test_mmls_without_a_table_fails_when_nothing_opens_at_sector_zero(case):
    d, _log = case
    from tools import sleuthkit
    fsstat = {"success": False, "exit_code": 1, "stdout": "", "stderr": NO_FS, "cmd": "fsstat x", "_atlas_call_id": 33}
    with _tsk_run(_silent_mmls(), fsstat):
        r = getattr(sleuthkit.tsk_mmls, "fn", sleuthkit.tsk_mmls)(str(d / IMG))
    assert r["success"] is False and r["_atlas_call_id"] == 33
    assert "no filesystem opens at sector 0 either" in r["error"] and "mark the image blocked" in r["error"]


class TestTheEwfMountWithoutAPartitionTable:
    def _ok(self, stdout=""):
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0, "truncated": False, "cmd": ""}

    def test_a_superfloppy_ewf_device_still_mounts(self, tmp_path):
        from tools.ewf import mount_full_image
        silent = {"success": False, "stdout": "", "stderr": "", "exit_code": 1, "truncated": False, "cmd": "mmls"}
        with patch("tools.ewf.run", side_effect=[self._ok(), silent, self._ok()]), \
                patch("tools.ewf.os.access", return_value=True), \
                patch("tools.ewf._volume_type_at", return_value="ntfs"):
            r = mount_full_image("/fake/CORP-WS03.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is True and r["volume_offset_bytes"] == 0

    def test_an_unreadable_device_gets_the_guidance_not_a_bare_failure(self, tmp_path):
        from tools.ewf import mount_full_image
        silent = {"success": False, "stdout": "", "stderr": "", "exit_code": 1, "truncated": False, "cmd": "mmls"}
        with patch("tools.ewf.run", side_effect=[self._ok(), silent]), patch("tools.ewf.os.access", return_value=False):
            r = mount_full_image("/fake/CORP-WS03.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False and r["gate"] == "non_ntfs" and "tsk.*/plaso/ez.*" in r["stderr"]


# ── a container refused for good is a failed read ────────────────────────

def test_a_container_refused_for_good_is_a_failed_read(case):
    d, log = case
    from core import middleware
    from core import raw_views as rv
    from tools import sleuthkit
    vhd = str(d / "evidence" / "images" / "CORP-WS04.vhd")
    Path(vhd).write_bytes(b"\0" * 64)
    with patch("core.mount_plan.raw_device_for", return_value=(None, "it is a VHD of type 4 (differencing)")), \
            patch("core.paths.active_case_dir", return_value=str(d)):
        _img, refused = sleuthkit._tsk_readable(vhd)
    with patch("core.mount_plan.raw_device_for", return_value=(None, f"{rv.START_FAILED}: busy")), \
            patch("core.paths.active_case_dir", return_value=str(d)):
        _img, later = sleuthkit._tsk_readable(vhd)
    assert refused["failure_class"] == "unsupported_format" and "gate" not in refused
    assert later["gate"] == "image_format"                                    # now, not for good
    before = len(log._entries)
    middleware._trace_success_baseline("tsk_tsk_fls", 0.1, before, result=refused, args={"image": vhd})
    assert cl._failed_attempt(log._entries[-1])
