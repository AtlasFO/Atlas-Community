"""A caller that names no case (review without --case, an MCP server
restarted outside a case, an enrichment lookup with no trace) does not
follow the host-wide session beacon while more than one run is alive: the
beacon names only the run started last."""
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


def _restore(tmp_path, monkeypatch, trace):
    monkeypatch.setattr(elog, "_BINDING_NOTED", set())
    with open(elog._SESSION_FILE, "w") as f:
        json.dump({"case_id": "CASE-A", "path": trace}, f)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.chdir(outside)
    return elog.ExecutionLog()


def test_an_mcp_restore_outside_a_case_does_not_guess(tmp_path, monkeypatch, capsys):
    _, trace = _run(tmp_path, "CASE-A")
    _run(tmp_path, "CASE-B")
    log = _restore(tmp_path, monkeypatch, trace)
    assert log.case_dir() is None and log.case_dir() is None
    assert capsys.readouterr().err.count("session beacon not followed") == 1


def test_an_mcp_restore_into_a_live_run_says_so(tmp_path, monkeypatch, capsys):
    # Another live process stands for the run (the parent pid is 0 when the
    # suite runs as a container's init process).
    run = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        a, trace = _run(tmp_path, "CASE-A", pid=run.pid)
        log = _restore(tmp_path, monkeypatch, trace)
        assert os.path.realpath(log.case_dir()) == os.path.realpath(a)
        assert f"whose run is live in pid {run.pid}" in capsys.readouterr().err
    finally:
        run.kill()
        run.wait()


def test_an_enrichment_lookup_with_no_case_persists_nowhere(monkeypatch):
    from tools import enrichment
    monkeypatch.setattr(elog.log, "_path", None)
    monkeypatch.setattr(run_state, "live_runs", lambda: ["/cases/CASE-A", "/cases/CASE-B"])
    assert enrichment._analysis_dir() is None
