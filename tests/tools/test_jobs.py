"""Tests for tools/jobs.py — background jobs for long-running tools."""
import json
import signal
import os
import subprocess
import sys
import time
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from tools import jobs
from tools.jobs import (
    _JOB_BUILDERS, _start_job, _load_job, _job_state,
    job_start_plaso_timeline, job_start_bulk_extractor,
    job_status, job_collect, job_cancel, job_list,
)
from tools.plaso import _timeline_cmd, _targeted_cmd
from tools.carving import (_bulk_extractor_cmd, _bulk_extractor_unalloc_cmd,
                           _foremost_cmd, _scalpel_cmd)

# FastMCP wraps @mcp.tool() functions — unwrap to call the plain functions.
def _fn(tool):
    return getattr(tool, "fn", tool)


job_start_plaso_timeline = _fn(job_start_plaso_timeline)
job_start_bulk_extractor = _fn(job_start_bulk_extractor)
job_status = _fn(job_status)
job_collect = _fn(job_collect)
job_cancel = _fn(job_cancel)
job_list = _fn(job_list)


@pytest.fixture
def case_log(tmp_path):
    """Configure the global log so _jobs_root() resolves under tmp."""
    from core.execution_log import log
    trace = tmp_path / "analysis" / "CASE_trace.json"
    trace.parent.mkdir(parents=True)
    log.configure("JOBTEST", str(trace), save_session=False)
    return log


def _fake_popen():
    m = MagicMock()
    m.pid = 12345
    return m


class TestBuilderRegistry:
    def test_registry_argv_matches_sync_tools(self):
        """Regression-lock: a background job runs the EXACT argv the sync
        tool would run."""
        cases = {
            "plaso_timeline": (
                _timeline_cmd,
                dict(evidence_path="/e/img.E01", storage_file="analysis/t.plaso",
                     parsers="mft", timezone="UTC")),
            "plaso_targeted": (
                _targeted_cmd,
                dict(evidence_path="/e/img.E01", storage_file="analysis/t.plaso",
                     artifact_filters="WindowsEventLogs")),
            "bulk_extractor": (
                _bulk_extractor_cmd,
                dict(image_path="/e/img.raw", output_dir="analysis/be",
                     threads=2, scanners="email,url")),
            "bulk_extractor_unalloc": (
                _bulk_extractor_unalloc_cmd,
                dict(unallocated_raw="/e/unalloc.raw", output_dir="analysis/be")),
            "foremost": (
                _foremost_cmd,
                dict(image_path="/e/img.raw", output_dir="analysis/fm",
                     file_types="jpg,pdf")),
            "scalpel": (
                _scalpel_cmd,
                dict(image_path="/e/img.raw", output_dir="analysis/sc")),
        }
        for kind, (sync_builder, params) in cases.items():
            job_builder = _JOB_BUILDERS[kind][0]
            assert job_builder(**params) == sync_builder(**params), kind

    def test_no_shell_strings_in_registry(self):
        checked = 0
        for kind, (builder, needs_sudo, base) in _JOB_BUILDERS.items():
            try:
                if kind == "plaso_timeline":
                    argv = builder("/e", "s.plaso")
                elif kind == "plaso_targeted":
                    argv = builder("/e", "s.plaso", "WindowsMFT")
                else:
                    argv = builder("/e/img.raw", "analysis/out")
            except RuntimeError:
                # The hayabusa builder resolves its binary/rules at build
                # time and raises when they are not provisioned — the case
                # in CI, where install.sh never runs. Nothing to shell-check
                # for a builder that cannot run.
                continue
            assert isinstance(argv, list)
            assert all(isinstance(a, str) for a in argv)
            checked += 1
        assert checked, "no job builders were checkable"


class TestStartJob:
    def test_start_writes_meta_and_traces(self, case_log, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("tools.jobs.subprocess.Popen", return_value=_fake_popen()) as p:
            r = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert r["success"] is True
        assert r["supervisor_pid"] == 12345
        assert "job_id" in r and "bulk_extractor" in r["job_id"]
        # detached launch shape
        _, kwargs = p.call_args
        assert kwargs["start_new_session"] is True
        # meta on disk
        job_dir = tmp_path / "analysis" / "jobs" / r["job_id"]
        meta = json.loads((job_dir / "meta.json").read_text())
        assert meta["argv"][0] == "bulk_extractor"
        assert meta["needs_sudo"] is True
        assert meta["start_call_id"]
        # trace entry
        entries = [e for e in case_log._entries if e.get("type") == "tool_call"]
        assert any("background job started" in e.get("stdout_excerpt", "")
                   for e in entries)

    def test_low_disk_blocks_job_launch(self, case_log, tmp_path, monkeypatch):
        from collections import namedtuple
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_MB", "2048")
        _U = namedtuple("_U", "total used free")
        low = _U(total=100 * 1024**3, used=100 * 1024**3 - 10**8, free=10**8)  # ~95 MB
        with patch("core.diskguard.shutil.disk_usage", return_value=low), \
             patch("tools.jobs.subprocess.Popen") as p:
            r = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert r["success"] is False
        assert r.get("disk_low") is True
        p.assert_not_called()  # supervisor never launched

    def test_remote_mode_returns_structured_error(self, case_log):
        with patch("core.remote.is_enabled", return_value=True), \
             patch("tools.jobs.subprocess.Popen") as p:
            r = job_start_plaso_timeline("/e/img.E01", "analysis/t.plaso")
        assert r["success"] is False
        assert r.get("remote_mode") is True
        p.assert_not_called()

    def test_no_case_context_returns_error(self, tmp_path, monkeypatch):
        from core.execution_log import ExecutionLog
        monkeypatch.chdir(tmp_path)  # no ./analysis
        with patch("tools.jobs._jobs_root", return_value=None), \
             patch("tools.jobs.subprocess.Popen") as p:
            r = job_start_bulk_extractor("/e/img.raw", "out")
        assert r["success"] is False
        assert "execution log" in r["error"]
        p.assert_not_called()

    def test_evidence_output_dir_rejected(self, case_log):
        with pytest.raises(ValueError, match="protected evidence"):
            job_start_bulk_extractor("/e/img.raw", "/cases/x/evidence/out")

    def test_timeout_hint_scales_with_input(self, case_log, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("tools.jobs.subprocess.Popen", return_value=_fake_popen()), \
             patch("tools.jobs.scale_timeout", return_value=99999) as st:
            r = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert r["timeout_hint_seconds"] == 99999
        assert st.call_args[0][1] == "/e/img.raw"


def _make_job_dir(root: Path, job_id: str, *, exit_code=None, stdout=b"",
                  supervisor_pid=99999, kind="bulk_extractor",
                  start_call_id=7) -> Path:
    job_dir = root / job_id
    job_dir.mkdir(parents=True)
    meta = {
        "job_id": job_id, "kind": kind, "cmd": "bulk_extractor -o out img",
        "argv": ["bulk_extractor", "-o", "out", "img"], "needs_sudo": True,
        "params": {"image_path": "img"}, "cwd": str(root),
        "started_utc": "2031-02-04T12:00:00Z", "started_ts": time.time() - 60,
        "timeout_hint_seconds": 7200, "supervisor_pid": supervisor_pid,
        "start_call_id": start_call_id,
    }
    if exit_code is not None:
        meta["exit_code"] = exit_code
        meta["finished_utc"] = "2031-02-04T12:01:00Z"
        (job_dir / "exit_code").write_text(str(exit_code))
    (job_dir / "meta.json").write_text(json.dumps(meta))
    if stdout:
        (job_dir / "stdout.log").write_bytes(stdout)
    return job_dir


class TestStatusCollect:
    def test_status_running(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j1", stdout=b"line1\nline2\n")
        with patch("tools.jobs._pid_alive", return_value=True):
            r = job_status("j1")
        assert r["success"] is True
        assert r["state"] == "running"
        assert r["log_tail"][-1] == "line2"

    def test_status_finished(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j2", exit_code=0, stdout=b"done\n")
        r = job_status("j2")
        assert r["state"] == "finished"

    def test_status_failed(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j3", exit_code=2)
        assert job_status("j3")["state"] == "failed"

    def test_status_aborted_when_supervisor_gone(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j4")
        with patch("tools.jobs._pid_alive", return_value=False):
            assert job_status("j4")["state"] == "aborted"

    def test_status_unknown_job(self, case_log):
        r = job_status("nope")
        assert r["success"] is False
        assert "Unknown job_id" in r["error"]

    def test_status_rejects_path_traversal(self, case_log):
        r = job_status("../../../etc")
        assert r["success"] is False
        assert "Invalid job_id" in r["error"]

    def test_collect_while_running_errors(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j5")
        with patch("tools.jobs._pid_alive", return_value=True):
            r = job_collect("j5")
        assert r["success"] is False
        assert "still running" in r["error"]

    def test_collect_success_caps_and_traces(self, case_log, tmp_path):
        from core.paths import OUTPUT_CAP
        root = tmp_path / "analysis" / "jobs"
        big = b"z" * (OUTPUT_CAP + 500)
        _make_job_dir(root, "j6", exit_code=0, stdout=big)
        r = job_collect("j6")
        assert r["success"] is True
        assert r["truncated"] is True
        assert len(r["stdout"]) <= OUTPUT_CAP + 200  # cap + footer
        assert r["stdout_file"].endswith("stdout.log")
        # trace lineage back to the start entry
        entry = [e for e in case_log._entries if e.get("type") == "tool_call"][-1]
        assert entry["input_call_ids"] == [7]
        assert entry["stdout_file"] == r["stdout_file"]

    def test_collect_failure_reports_exit_code(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j7", exit_code=3, stdout=b"boom\n")
        r = job_collect("j7")
        assert r["success"] is False
        assert r["exit_code"] == 3

    def test_collect_idempotent_logs_once(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j8", exit_code=0, stdout=b"ok\n")
        r1 = job_collect("j8")
        n_entries = len(case_log._entries)
        r2 = job_collect("j8")
        assert r2["already_collected"] is True
        assert len(case_log._entries) == n_entries
        assert r1["exit_code"] == r2["exit_code"]


class TestCancel:
    def test_cancel_running_job(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j9")
        with patch("tools.jobs._pid_alive", return_value=True), \
             patch("tools.jobs._supervisor_mismatch", return_value=""), \
             patch("tools.jobs.os.killpg") as kp:
            r = job_cancel("j9")
        assert r["success"] is True
        kp.assert_called_once()

    def test_a_refused_signal_is_reported_never_escalated(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j10")
        with patch("tools.jobs._pid_alive", return_value=True), \
             patch("tools.jobs._supervisor_mismatch", return_value=""), \
             patch("tools.jobs.os.killpg", side_effect=PermissionError), \
             patch("core.executor.run") as run:
            r = job_cancel("j10")
        assert r["success"] is False and "nothing was escalated" in r["error"]
        run.assert_not_called()

    def test_only_the_jobs_own_supervisor_is_ever_signalled(self, case_log, tmp_path):
        """A pid read back from the job file hours later must still be the
        supervisor this job started: its runner command, its own group, its
        recorded start time."""
        import subprocess
        import sys
        from tools.jobs import _proc_identity, _supervisor_mismatch
        job_dir = tmp_path / "analysis" / "jobs" / "j12"
        job_dir.mkdir(parents=True)
        (job_dir / "meta.json").write_text(json.dumps({"argv": ["sleep", "30"], "needs_sudo": False, "params": {}}))
        repo = str(Path(__file__).resolve().parents[2])
        sup = subprocess.Popen([sys.executable, "-m", "tools.jobs_runner", str(job_dir)], cwd=repo,
                               start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        try:
            start = _proc_identity(sup.pid)[0]
            assert _supervisor_mismatch(job_dir, {"supervisor_pid": sup.pid, "supervisor_start": start}) == ""
            assert "another time" in _supervisor_mismatch(job_dir, {"supervisor_pid": sup.pid, "supervisor_start": "1"})
            assert "another command" in _supervisor_mismatch(job_dir, {"supervisor_pid": other.pid})
            assert "own process group" in _supervisor_mismatch(job_dir, {"supervisor_pid": os.getpgrp()}) \
                or "leads" in _supervisor_mismatch(job_dir, {"supervisor_pid": os.getpgrp()})
            assert "no supervisor" in _supervisor_mismatch(job_dir, {"supervisor_pid": 0})
        finally:
            for p in (sup, other):
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait()

    def test_cancel_finished_job_errors(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "j11", exit_code=0)
        r = job_cancel("j11")
        assert r["success"] is False


class TestJobList:
    def test_lists_jobs_with_state(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "a_done", exit_code=0)
        _make_job_dir(root, "b_run")
        with patch("tools.jobs._pid_alive", return_value=True):
            r = job_list()
        assert r["success"] is True
        assert r["count"] == 2
        states = {j["job_id"]: j["state"] for j in r["jobs"]}
        assert states["a_done"] == "finished"
        assert states["b_run"] == "running"

    def test_empty_when_no_jobs(self, case_log):
        r = job_list()
        assert r["success"] is True
        assert r["jobs"] == []


class TestJobsRunnerIntegration:
    """Real subprocess through the detached supervisor — no SIFT tools."""

    def test_runner_executes_and_records_exit_code(self, tmp_path):
        job_dir = tmp_path / "job"
        job_dir.mkdir()
        meta = {
            "job_id": "it1", "kind": "test", "needs_sudo": False,
            "argv": [sys.executable, "-c", "print('hi from job')"],
            "cwd": str(tmp_path),
        }
        (job_dir / "meta.json").write_text(json.dumps(meta))
        repo_root = os.path.dirname(os.path.dirname(
            os.path.abspath(jobs.__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "tools.jobs_runner", str(job_dir)],
            cwd=repo_root, capture_output=True, timeout=60)
        assert proc.returncode == 0
        assert (job_dir / "exit_code").read_text().strip() == "0"
        assert b"hi from job" in (job_dir / "stdout.log").read_bytes()
        final = json.loads((job_dir / "meta.json").read_text())
        assert final["exit_code"] == 0
        assert "finished_utc" in final

    def _supervised(self, tmp_path, needs_sudo):
        job_dir = tmp_path / "job"
        job_dir.mkdir()
        out = tmp_path / "analysis" / "carve"
        out.mkdir(parents=True)
        (job_dir / "meta.json").write_text(json.dumps({
            "job_id": "it3", "kind": "test", "needs_sudo": needs_sudo,
            "argv": ["carver", "-o", str(out)], "cwd": str(tmp_path),
            "params": {"output_dir": str(out)},
        }))
        proc = MagicMock(pid=1)
        proc.wait.return_value = 0
        return job_dir, out, proc

    def test_runner_hands_a_root_written_output_back_to_the_user(self, tmp_path):
        from tools import jobs_runner
        job_dir, out, proc = self._supervised(tmp_path, needs_sudo=True)
        with patch("tools.jobs_runner.subprocess.Popen", return_value=proc), \
                patch("core.paths.reclaim_output_ownership",
                      return_value=True) as reclaim:
            assert jobs_runner.main(str(job_dir)) == 0
        reclaim.assert_called_once_with(str(out))
        meta = json.loads((job_dir / "meta.json").read_text())
        assert meta["output_reclaimed"] is True and meta["exit_code"] == 0

    def test_runner_leaves_ownership_alone_for_an_unprivileged_job(self, tmp_path):
        from tools import jobs_runner
        job_dir, _out, proc = self._supervised(tmp_path, needs_sudo=False)
        with patch("tools.jobs_runner.subprocess.Popen", return_value=proc), \
                patch("core.paths.reclaim_output_ownership") as reclaim:
            jobs_runner.main(str(job_dir))
        reclaim.assert_not_called()

    @staticmethod
    def _gone(pid, within=10.0):
        end = time.monotonic() + within
        while time.monotonic() < end:
            try:
                with open(f"/proc/{pid}/stat") as fh:
                    if fh.read().rsplit(")", 1)[1].split()[0] == "Z":
                        return True
            except OSError:
                return True
            time.sleep(0.05)
        return False

    def _grandchild_job(self, tmp_path):
        job_dir = tmp_path / "job"
        job_dir.mkdir()
        pidfile = tmp_path / "grandchild.pid"
        (job_dir / "meta.json").write_text(json.dumps({
            "job_id": "it4", "kind": "test", "needs_sudo": False, "cwd": str(tmp_path),
            "argv": ["bash", "-c", f"sleep 300 & echo $! > {pidfile}; wait"]}))
        return job_dir, pidfile

    def test_a_cancel_ends_the_tool_and_what_it_started_and_is_recorded(self, tmp_path):
        """job_cancel signals the supervisor's group; the tool runs in a
        session of its own, so the supervisor stops it with everything it
        started and records the outcome. A second SIGTERM does not cut the
        stop short."""
        job_dir, pidfile = self._grandchild_job(tmp_path)
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(jobs.__file__)))
        sup = subprocess.Popen([sys.executable, "-m", "tools.jobs_runner", str(job_dir)],
                               cwd=repo_root, start_new_session=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.monotonic() + 15
            while not pidfile.exists() and time.monotonic() < end:
                time.sleep(0.05)
            grandchild = int(pidfile.read_text())
            os.killpg(sup.pid, signal.SIGTERM)
            time.sleep(0.2)
            os.killpg(sup.pid, signal.SIGTERM)
            assert sup.wait(timeout=30) == 0
        finally:
            if sup.poll() is None:
                os.killpg(sup.pid, signal.SIGKILL)
                sup.wait()
        assert self._gone(grandchild)
        meta = json.loads((job_dir / "meta.json").read_text())
        assert meta["aborted_reason"] == "cancelled" and "exit_code" in meta
        assert (job_dir / "exit_code").is_file()
        assert jobs._job_state(job_dir, meta) == "aborted"
        assert b"cancelled" in (job_dir / "stdout.log").read_bytes()

    def test_a_disk_abort_ends_what_the_tool_started(self, tmp_path, monkeypatch):
        from tools import jobs_runner
        job_dir, pidfile = self._grandchild_job(tmp_path)
        monkeypatch.setattr(jobs_runner, "_POLL_SECONDS", 0.2)
        monkeypatch.setattr(jobs_runner, "_DISK_POLL_SECONDS", 0)
        monkeypatch.setattr(jobs_runner, "_KILL_GRACE_SECONDS", 2)
        checks = iter([{"ok": True}] * 5)
        monkeypatch.setattr("core.diskguard.check", lambda _p: next(checks, {"ok": False}))
        monkeypatch.setattr("core.diskguard.message", lambda _s, _w: "disk low")
        assert jobs_runner.main(str(job_dir)) == 0
        assert self._gone(int(pidfile.read_text()))
        meta = json.loads((job_dir / "meta.json").read_text())
        assert meta["aborted_reason"] == "disk_low" and "stop_incomplete" not in meta

    def test_runner_missing_tool_records_127(self, tmp_path):
        job_dir = tmp_path / "job"
        job_dir.mkdir()
        (job_dir / "meta.json").write_text(json.dumps({
            "job_id": "it2", "kind": "test", "needs_sudo": False,
            "argv": ["definitely_not_a_real_binary_xyz"], "cwd": str(tmp_path),
        }))
        repo_root = os.path.dirname(os.path.dirname(
            os.path.abspath(jobs.__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "tools.jobs_runner", str(job_dir)],
            cwd=repo_root, capture_output=True, timeout=60)
        assert proc.returncode == 0
        assert (job_dir / "exit_code").read_text().strip() == "127"


# ── blocking waits, dedup, batch_id ────────────────────────────────────

job_wait = _fn(jobs.job_wait)
job_wait_all = _fn(jobs.job_wait_all)


class TestJobWait:
    def test_wait_on_finished_job_collects_immediately(self, case_log,
                                                       tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "w1", exit_code=0, stdout=b"carve done\n")
        r = job_wait("w1", timeout=5)
        assert r["success"] is True
        assert r["state"] == "finished"
        assert "carve done" in r["stdout"]      # collected, not just status
        assert r["waited_seconds"] < 2

    def test_wait_timeout_leaves_job_running(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "w2", stdout=b"working\n")
        with patch("tools.jobs._pid_alive", return_value=True):
            r = job_wait("w2", timeout=1)
        assert r["success"] is False
        assert r["timed_out_wait"] is True
        assert r["state"] == "running"

    def test_wait_collect_false_returns_status_only(self, case_log,
                                                    tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "w3", exit_code=0, stdout=b"done\n")
        r = job_wait("w3", timeout=5, collect=False)
        assert r["state"] == "finished"
        assert "stdout" not in r  # status shape, not collect shape

    def test_wait_unknown_job(self, case_log):
        assert job_wait("nope")["success"] is False


class TestJobWaitAll:
    def test_batch_selection(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        for jid, batch in (("b1", "dair-5"), ("b2", "dair-5"),
                           ("b3", "dair-9")):
            d = _make_job_dir(root, jid, exit_code=0, stdout=b"x" * 300)
            meta = json.loads((d / "meta.json").read_text())
            meta["batch_id"] = batch
            (d / "meta.json").write_text(json.dumps(meta))
        r = job_wait_all(batch_id="dair-5", timeout=5)
        assert sorted(r["jobs"]) == ["b1", "b2"]
        assert r["success"] is True and r["timed_out"] == []

    def test_default_selects_running_jobs(self, case_log, tmp_path):
        root = tmp_path / "analysis" / "jobs"
        _make_job_dir(root, "r1", exit_code=0)   # finished: not selected
        _make_job_dir(root, "r2")                 # running
        with patch("tools.jobs._pid_alive", return_value=True):
            r = job_wait_all(timeout=1)
        assert list(r["jobs"]) == ["r2"]
        assert r["timed_out"] == ["r2"]
        assert r["success"] is False

    def test_no_matching_jobs_is_calm(self, case_log):
        r = job_wait_all(timeout=1)
        assert r["success"] is True and r["jobs"] == {}


class TestDedupAndBatch:
    def test_identical_running_job_dedups(self, case_log, tmp_path,
                                          monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("tools.jobs.subprocess.Popen",
                   return_value=_fake_popen()) as p, \
             patch("tools.jobs._pid_alive", return_value=True):
            first = job_start_bulk_extractor("/e/img.raw", "analysis/be")
            second = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert first.get("deduplicated") is None
        assert second["deduplicated"] is True
        assert second["job_id"] == first["job_id"]
        assert second["state"] == "running"
        assert p.call_count == 1  # only one supervisor launched

    def test_failed_job_does_not_dedup(self, case_log, tmp_path,
                                       monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("tools.jobs.subprocess.Popen",
                   return_value=_fake_popen()) as p, \
             patch("tools.jobs._pid_alive", return_value=False):
            first = job_start_bulk_extractor("/e/img.raw", "analysis/be")
            # mark it failed
            job_dir = tmp_path / "analysis" / "jobs" / first["job_id"]
            (job_dir / "exit_code").write_text("2")
            second = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert second.get("deduplicated") is None
        assert second["job_id"] != first["job_id"]
        assert p.call_count == 2

    def test_batch_id_stamped_from_dair_cid(self, case_log, tmp_path,
                                            monkeypatch):
        monkeypatch.chdir(tmp_path)
        case_log._last_dair_cid = 5
        with patch("tools.jobs.subprocess.Popen",
                   return_value=_fake_popen()):
            r = job_start_bulk_extractor("/e/img.raw", "analysis/be")
        assert r["batch_id"] == "dair-5"
        meta = json.loads((tmp_path / "analysis" / "jobs" / r["job_id"] /
                           "meta.json").read_text())
        assert meta["batch_id"] == "dair-5"


def test_a_sudo_job_that_outlived_sigterm_is_killed_as_root(no_privileged_kill, monkeypatch):
    import subprocess
    from unittest.mock import MagicMock
    from core import privileged_kill as pk
    from tools import jobs_runner as jr
    monkeypatch.setattr(jr, "_signal_group", lambda proc, sig: "sent")

    def _proc():
        p = MagicMock(pid=5151, _atlas_group_start=None)
        p.wait.side_effect = [subprocess.TimeoutExpired("sudo", 1), None]
        return p

    assert jr._terminate(_proc(), via_sudo=True) is True        # sudo refused: disclosed
    assert no_privileged_kill == [["sudo", "-n", "kill", "-KILL", "--", "-5151"]]
    monkeypatch.setattr(pk, "_run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))
    assert jr._terminate(_proc(), via_sudo=True) is False       # root's kill reached it
    assert jr._terminate(_proc(), via_sudo=False) is False      # never escalated
