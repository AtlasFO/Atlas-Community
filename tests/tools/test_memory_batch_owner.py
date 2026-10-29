"""The memory batch stops when every run process that owns it is gone,
records why, and a resumed run starts it again. Invented files only; the
"Volatility" here is a small script."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from core import memory_batch as MB
from tests.tools.test_memory_batch import _manifest, env  # noqa: F401 - the fixture

_REPO = str(Path(__file__).resolve().parents[2])


def _slow_vol(tmp_path, marks: Path) -> str:
    """A plugin that notes its pid and session, then runs long."""
    script = tmp_path / "slowvol.py"
    script.write_text(
        "import json, os, sys, time\n"
        "a = sys.argv[1:]\n"
        "if a and a[0] == '--help':\n    print('Volatility 3 Framework 9.9.9'); sys.exit(0)\n"
        f"open({str(marks)!r}, 'a').write(json.dumps({{'pid': os.getpid(), 'sid': os.getsid(0)}}) + '\\n')\n"
        "time.sleep(120)\n")
    vol = tmp_path / "slowvol"
    vol.write_text(f"#!/bin/sh\nexec {sys.executable} {script} \"$@\"\n")
    vol.chmod(0o755)
    return str(vol)


def _alive(pid: int) -> bool:
    st = MB._proc_state(pid)
    return st is not None and st[1] != "Z"


def test_the_batch_stops_when_its_owner_is_gone_and_records_why(env, tmp_path):  # noqa: F811
    case, image, _calls, _vol, syms = env
    marks = tmp_path / "marks.jsonl"
    _manifest(case, image, _slow_vol(tmp_path, marks), syms)
    owner = subprocess.Popen(["sleep", "300"])
    MB.add_owner(case, owner.pid)
    runner = subprocess.Popen([sys.executable, os.path.join(_REPO, "tools", "memory_batch_runner.py"),
                               str(MB.manifest_path(case))], cwd=_REPO, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": _REPO})
    deadline = time.monotonic() + 60
    while not marks.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    plugin = json.loads(marks.read_text().splitlines()[0])
    assert plugin["sid"] == plugin["pid"] != os.getsid(0)          # its own group: never the run's own calls
    owner.kill()
    owner.wait()
    code = runner.wait(timeout=60)
    assert code == 3                                                # not "finished": the registry restarts it
    assert not _alive(plugin["pid"])                                # the plugin's group was stopped
    st = MB.status(case)
    assert st["stopped"] and st["stop_reason"] == MB.STOP_OWNER_GONE and st["not_run"][image]
    (line,) = MB.stop_lines(case)
    assert line.startswith(f"The memory batch was stopped ({MB.STOP_OWNER_GONE}) before it ran: corp-ws01.mem:")


def test_a_live_owner_keeps_the_batch_running_to_its_end(env):  # noqa: F811
    from tools import memory_batch_runner as R
    case, image, _calls, vol, syms = env
    _manifest(case, image, vol, syms)
    MB.add_owner(case)                                              # this test process: alive
    assert R.main(str(MB.manifest_path(case))) == 0
    assert MB.status(case)["state"] == "done" and not MB.status(case).get("stopped")


def test_the_batch_stops_only_when_every_owner_is_gone(env):  # noqa: F811
    case, *_ = env
    gone = subprocess.Popen(["true"])
    gone.wait()
    MB.add_owner(case, gone.pid)
    MB.add_owner(case)                                              # a second run adopts the batch
    assert MB.owners_gone(case) is None


def test_a_zombie_counts_as_gone_and_an_unreadable_proc_as_alive(monkeypatch):
    child = subprocess.Popen(["true"])
    deadline = time.monotonic() + 10
    while MB._proc_state(child.pid) and MB._proc_state(child.pid)[1] != "Z" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert MB.owner_alive({"pid": child.pid, "start": ""}) is False   # exited, not reaped yet
    child.wait()
    monkeypatch.setattr(MB, "_proc_state", lambda pid: ("", ""))
    assert MB.owner_alive({"pid": os.getpid(), "start": "123"}) is True


def test_no_owner_file_keeps_the_batch_running(env):  # noqa: F811
    case, *_ = env
    assert MB.owners_gone(case) is None
    MB.owners_path(case).parent.mkdir(parents=True, exist_ok=True)
    MB.owners_path(case).write_text("not json")
    assert MB.owners_gone(case) is None


def test_owners_written_from_threads_are_all_kept(env):  # noqa: F811
    case, *_ = env
    kids = [subprocess.Popen(["sleep", "30"]) for _ in range(4)]
    try:
        ts = [threading.Thread(target=MB.add_owner, args=(case, k.pid)) for k in kids]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert sorted(o["pid"] for o in json.loads(MB.owners_path(case).read_text())) == sorted(k.pid for k in kids)
    finally:
        for k in kids:
            k.kill()
            k.wait()


def test_a_resumed_runs_first_memory_call_restarts_a_batch_its_owners_left(env, monkeypatch):  # noqa: F811
    case, image, _calls, vol, syms = env
    _manifest(case, image, vol, syms)
    MB._save_status(case, {"stopped": True, "stop_reason": MB.STOP_OWNER_GONE, "state": "stopped",
                           "images": {image: {"plugins": {"windows.info": "done"}}}})
    started = []
    state = {"running": ""}
    monkeypatch.setattr(MB, "_running", lambda c: state["running"])

    def ensure(c, images):
        started.append(images)
        state["running"] = "job-9"
        return {"job_id": "job-9"}
    monkeypatch.setattr(MB, "ensure", ensure)
    MB._RESTARTED.clear()
    walks, _scans = MB.plan()
    assert MB.queued(case, image, walks[0]) == "job-9" and started == [[image]]
    state["running"] = ""
    assert MB.queued(case, image, walks[0]) == "" and len(started) == 1      # once per process


def test_an_owner_that_cannot_be_recorded_leaves_no_stale_owner_list(env, monkeypatch):  # noqa: F811
    case, image, *_ = env
    gone = subprocess.Popen(["true"])
    gone.wait()
    MB.add_owner(case, gone.pid)                                    # an earlier, killed run
    monkeypatch.setattr(MB, "add_owner", lambda c, pid=None: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr("tools.jobs._start_job", lambda kind, params: {"job_id": "job-1"})
    MB.ensure(case, [image])
    assert not MB.owners_path(case).exists() and MB.owners_gone(case) is None    # fail-open: keeps running
