"""The host-wide session beacon names only the run started last. A review
without --case does not follow it while more than one run is alive; a
process that bound no case (an MCP server restarted outside a case, a
probe, an enrichment lookup) never binds or writes the beacon's case."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core import execution_log as elog
from core import run_state


def _run(tmp_path, name, *, pid=None, stopped="running"):
    """A case whose run opened its trace (a beacon) and recorded its state."""
    pid = pid or os.getpid()
    case = tmp_path / "cases" / name
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "CASE.md").write_text(f"# {name}\n", encoding="utf-8")
    trace = case / "analysis" / f"{name}_trace.json"
    trace.write_text(json.dumps({"case_id": name, "entries": []}), encoding="utf-8")
    (case / ".atlas" / "run_status.json").write_text(
        json.dumps({"stopped_reason": stopped, "pid": pid}), encoding="utf-8")
    os.makedirs(elog._BEACON_DIR, exist_ok=True)
    with open(os.path.join(elog._BEACON_DIR, elog._case_key(str(case)) + ".json"), "w") as f:
        json.dump({"pid": pid, "path": str(trace), "ts": "2031-01-02T03:04:05+00:00"}, f)
    return str(case), str(trace)


def _dead_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


def test_the_live_runs_are_the_beacons_whose_run_is_alive(tmp_path):
    a, _ = _run(tmp_path, "CASE-A")
    b, _ = _run(tmp_path, "CASE-B")
    _run(tmp_path, "CASE-C", stopped="finished")
    _run(tmp_path, "CASE-D", pid=_dead_pid())
    assert sorted(run_state.live_runs()) == sorted([a, b])


def test_review_without_a_case_names_the_live_runs(monkeypatch):
    from agent import cli
    monkeypatch.setattr(run_state, "live_runs", lambda: ["/cases/CASE-A", "/cases/CASE-B"])
    with pytest.raises(SystemExit) as stop:
        cli.cmd_review(SimpleNamespace(case=None, trace=None, live=True, json=False,
                                       question=""))
    assert "/cases/CASE-A" in str(stop.value) and "--case" in str(stop.value)


def _beacon(trace):
    with open(elog._SESSION_FILE, "w") as f:
        json.dump({"case_id": "CASE-A", "path": trace}, f)


@pytest.mark.parametrize("live", [0, 1, 2])
def test_a_process_outside_every_case_never_writes_the_beacons_case(tmp_path, monkeypatch, live):
    # The beacon's run finished (0), is live in another process (1), or is
    # one of two live runs (2). Another live process stands for a run (the
    # parent pid is 0 when the suite runs as a container's init process).
    run = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        _, trace = _run(tmp_path, "CASE-A", pid=run.pid if live else _dead_pid(),
                        stopped="running" if live else "finished")
        if live == 2:
            _run(tmp_path, "CASE-B", pid=run.pid)
        _beacon(trace)
        before = open(trace, encoding="utf-8").read()
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.chdir(tmp_path / "elsewhere")
        log = elog.ExecutionLog()
        assert log.case_dir() is None
        with pytest.raises(RuntimeError, match="trace log not configured"):
            log.record_tool_call(cmd="probe --version", success=True, truncated=False, retries=0,
                                 exit_code=0, stderr="", elapsed_seconds=0.0, stdout_excerpt="")
        assert open(trace, encoding="utf-8").read() == before
    finally:
        run.kill()
        run.wait()


def test_an_enrichment_lookup_with_no_case_persists_nowhere(tmp_path, monkeypatch):
    from tools import enrichment
    _, trace = _run(tmp_path, "CASE-A", pid=_dead_pid(), stopped="finished")
    _beacon(trace)
    monkeypatch.setattr(elog.log, "_path", None)
    assert enrichment._analysis_dir() is None
