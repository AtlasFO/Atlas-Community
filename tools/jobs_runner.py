"""Detached supervisor for background forensic jobs.

Launched by tools/jobs.py as `python -m tools.jobs_runner <job_dir>` in its own
session, so it survives MCP server restarts. Runs the tool described in
<job_dir>/meta.json, streams its combined output to <job_dir>/stdout.log, and
records the exit code + finish time back into meta.json — the exit code is
never lost even if nobody is watching when the tool finishes.

Deliberately stdlib-only and import-light: it must start instantly and never
crash on missing optional dependencies. It does NOT import core.execution_log —
trace entries are written server-side at job start and collect time.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

# Disk-space watchdog: how often to check free space while the tool runs, and
# how long to wait for a graceful stop before SIGKILL. core.diskguard is
# stdlib-only (os, shutil), so importing it keeps this supervisor import-light.
_DISK_POLL_SECONDS = 15
_KILL_GRACE_SECONDS = 10
# How often the supervisor looks at its tool and at a cancel request.
_POLL_SECONDS = 1
# A runner of Atlas's own that stops itself for a reason of Atlas's (not of
# the evidence it reads) says why in this file of its job directory; the
# supervisor tells it the directory in ATLAS_JOB_DIR.
STOP_FILE = "stopped_by_atlas"


def record_atlas_stop(reason: str) -> None:
    """For a tool this supervisor runs: record that it stopped for a reason
    of Atlas's (the run that owned it is gone, ...). Nothing outside a job."""
    job_dir = os.environ.get("ATLAS_JOB_DIR")
    if not job_dir:
        return
    try:
        with open(os.path.join(job_dir, STOP_FILE), "w", encoding="utf-8") as fh:
            fh.write(str(reason)[:300])
    except OSError:
        pass


def _utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _signal_group(proc: subprocess.Popen, sig: int) -> str:
    """Signal the process group the tool leads: "sent", "gone" or
    "refused". The group is the pid of the handle this supervisor has held
    since it spawned the tool in a session of its own, so no pid is read
    back from a file and no identity check is needed."""
    try:
        os.killpg(proc.pid, sig)
        return "sent"
    except ProcessLookupError:
        return "gone"
    except PermissionError:
        return "refused"


def _terminate(proc: subprocess.Popen, via_sudo: bool = False) -> bool:
    """Stop the tool and everything it started: SIGTERM to its group (sudo
    relays it to the command it runs), up to the grace for the leader, then
    SIGKILL to whatever is left of the group. Returns True when the stop may
    be incomplete: a command run through sudo that outlived SIGTERM runs as
    root, where a signal from this user does not reach it."""
    if _signal_group(proc, signal.SIGTERM) == "refused":
        # A leader running as root refuses this user's signals: the same
        # NOPASSWD sudo the job was launched with.
        try:
            subprocess.run(["sudo", "kill", f"-{int(signal.SIGTERM)}", str(proc.pid)],
                           stdin=subprocess.DEVNULL, timeout=10)
        except Exception:
            pass
    try:
        proc.wait(timeout=_KILL_GRACE_SECONDS)
        exited = True
    except subprocess.TimeoutExpired:
        exited = False
    probe = _signal_group(proc, 0)
    incomplete = (via_sudo and not exited) or probe == "refused"
    leader_start = getattr(proc, "_atlas_group_start", None)
    # With the leader reaped, only its recorded start time tells our group's
    # number from one handed to another process: no record, no escalation.
    if incomplete and via_sudo and (not exited or isinstance(leader_start, str)):
        # The command sudo runs is out of this user's reach; the grant the
        # job was started with covers kill (core.privileged_kill).
        from core.privileged_kill import kill_group_as_root
        if kill_group_as_root(proc.pid, leader_start):
            incomplete = False
    if not exited or probe == "sent":
        _signal_group(proc, signal.SIGKILL)
        if not exited:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
    return incomplete


def _write_meta(job_dir: str, meta: dict) -> None:
    tmp = os.path.join(job_dir, "meta.json.tmp")
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, os.path.join(job_dir, "meta.json"))


# What the runner records in a job's meta; everything else is the server's.
_RUNNER_KEYS = ("output_reclaimed", "view_lost", "stop_incomplete", "exit_code", "finished_utc",
                "aborted_reason", "aborted_detail", "stopped_by_atlas")


def merge_meta(job_dir: str, updates: dict, base: dict | None = None) -> dict:
    """Write ``updates`` into the job's meta.json and keep every other key
    as the file holds it now: the server records the start (the supervisor,
    the start's trace entry) while a quick job's runner may already record
    the outcome, and neither may drop the other's keys. One writer at a time
    (an exclusive lock beside the file); ``base`` stands in for a meta.json
    that cannot be read."""
    import fcntl
    with open(os.path.join(job_dir, "meta.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(os.path.join(job_dir, "meta.json")) as f:
                meta = json.load(f)
        except (OSError, ValueError):
            meta = dict(base or {})
        meta.update(updates)
        _write_meta(job_dir, meta)
    return meta


def main(job_dir: str) -> int:
    # A cancel (job_cancel's SIGTERM to this supervisor's group) is a request
    # the loop below carries out: the tool runs in a session of its own, so
    # the supervisor stops it and everything it started, and records the
    # outcome. The handler only sets a flag, so a second SIGTERM cannot cut
    # a stop short.
    cancel: list[bool] = []
    try:
        previous = signal.signal(signal.SIGTERM, lambda *_: cancel.append(True))
    except ValueError:   # not the main thread: nothing to install
        previous = None
    try:
        return _supervise(job_dir, cancel)
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


def _supervise(job_dir: str, cancel: list) -> int:
    with open(os.path.join(job_dir, "meta.json")) as f:
        meta = json.load(f)

    argv = list(meta["argv"])
    if meta.get("needs_sudo") and argv[0] != "sudo":
        argv = ["sudo"] + argv

    # Watch free space on the volume the job writes into (its output/storage
    # path, else the job dir). A carve/timeline can fill the disk over hours;
    # the watchdog aborts it before the VM/host runs out of space.
    watch_path = (meta.get("params", {}).get("output_dir")
                  or meta.get("params", {}).get("storage_file")
                  or job_dir)

    log_path = os.path.join(job_dir, "stdout.log")
    exit_code = -1
    aborted_reason = None
    stop_incomplete = False
    via_sudo = os.path.basename(str(argv[0])) == "sudo"
    try:
        with open(log_path, "ab") as log_fh:
            proc = subprocess.Popen(
                argv,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=meta.get("cwd") or None,
                start_new_session=True,
                env={**os.environ, "ATLAS_JOB_DIR": str(job_dir)},
            )
            if via_sudo:
                from core.privileged_kill import start_time
                proc._atlas_group_start = start_time(proc.pid)
            with open(os.path.join(job_dir, "pid"), "w") as f:
                f.write(str(proc.pid))

            # Poll for completion; between polls, carry out a cancel and
            # enforce the disk fail-safe.
            last_disk = time.monotonic()
            while True:
                try:
                    exit_code = proc.wait(timeout=_POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if cancel:
                    log_fh.write(b"\n[jobs_runner] cancelled: stopping the tool and "
                                 b"everything it started\n")
                    log_fh.flush()
                    stop_incomplete = _terminate(proc, via_sudo)
                    exit_code = proc.poll()
                    if exit_code is None:
                        exit_code = -1
                    aborted_reason = "cancelled"
                    break
                if time.monotonic() - last_disk < _DISK_POLL_SECONDS:
                    continue
                last_disk = time.monotonic()
                try:
                    from core import diskguard
                    status = diskguard.check(watch_path)
                except Exception:
                    continue  # never let a guard failure kill a healthy job
                if not status["ok"]:
                    aborted_reason = diskguard.message(status, f"job {job_dir}")
                    log_fh.write(
                        f"\n[jobs_runner] DISK-SPACE ABORT: {aborted_reason}\n"
                        .encode())
                    log_fh.flush()
                    stop_incomplete = _terminate(proc, via_sudo)
                    exit_code = proc.poll()
                    if exit_code is None:
                        exit_code = -1
                    break
    except FileNotFoundError as e:
        with open(log_path, "ab") as log_fh:
            log_fh.write(f"[jobs_runner] tool not found: {e}\n".encode())
        exit_code = 127
    except Exception as e:  # noqa: BLE001 — must always record an outcome
        with open(log_path, "ab") as log_fh:
            log_fh.write(f"[jobs_runner] supervisor error: {e}\n".encode())
        exit_code = -1

    # A tool that ran as root leaves its output root-owned. Hand it back to
    # the user the run belongs to, as the executor does for a foreground
    # run, so later reads and the case clear can reach it.
    out_dir = (meta.get("params") or {}).get("output_dir")
    if meta.get("needs_sudo") and out_dir:
        try:
            from core.paths import reclaim_output_ownership
            reclaimed = reclaim_output_ownership(out_dir)
        except Exception:  # noqa: BLE001 — an outcome is still recorded
            reclaimed = False
        meta["output_reclaimed"] = reclaimed
        if not reclaimed:
            with open(log_path, "ab") as log_fh:
                log_fh.write(
                    f"\n[jobs_runner] could not hand {out_dir} back to the "
                    f"invoking user; it may still be root-owned\n".encode())

    # A raw view the job read whose daemon changed while it ran answered some
    # of its reads with errors: the output is incomplete, whatever the tool's
    # exit code says, so the job fails and nothing credits its reads.
    if meta.get("raw_views"):
        try:
            from core.raw_views import view_lost
            lost = view_lost(meta)
        except Exception:  # noqa: BLE001 - the outcome is still recorded
            lost = ""
        if lost:
            with open(log_path, "ab") as log_fh:
                log_fh.write(f"\n[jobs_runner] {lost}\n".encode())
            meta["view_lost"] = lost
            if exit_code == 0:
                exit_code = 1

    if stop_incomplete:
        with open(log_path, "ab") as log_fh:
            log_fh.write(b"\n[jobs_runner] the tool was stopped, but the command it ran "
                         b"through sudo outlived the stop request and may still be "
                         b"running as root\n")
        meta["stop_incomplete"] = True
    meta["exit_code"] = exit_code
    meta["finished_utc"] = _utcnow()
    if aborted_reason == "cancelled":
        meta["aborted_reason"] = "cancelled"
    elif aborted_reason:
        meta["aborted_reason"] = "disk_low"
        meta["aborted_detail"] = aborted_reason
    # Every stop Atlas made, one record (core.coverage_ledger reads it): a
    # cancel, the disk guard, a raw view lost under the job, or the tool's
    # own stop for a reason of Atlas's. Such an end says nothing about the
    # evidence the job read: no read of it, no failed read.
    try:
        with open(os.path.join(job_dir, STOP_FILE), encoding="utf-8") as fh:
            own_stop = fh.read().strip()
    except OSError:
        own_stop = ""
    stop = (own_stop or ("cancelled" if aborted_reason == "cancelled" else "")
            or (f"disk low: {aborted_reason}" if aborted_reason else "") or str(meta.get("view_lost") or ""))
    if stop:
        meta["stopped_by_atlas"] = stop[:300]
    # Only the runner's own keys: the copy read at the start lacks what the
    # server wrote after it (the start's trace entry, the supervisor).
    merge_meta(job_dir, {k: meta[k] for k in _RUNNER_KEYS if k in meta}, base=meta)
    # Separate sentinel file: cheap existence check for job_status/job_collect.
    with open(os.path.join(job_dir, "exit_code"), "w") as f:
        f.write(str(exit_code))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m tools.jobs_runner <job_dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
