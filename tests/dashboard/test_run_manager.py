"""Tests for dashboard/run_manager.py's build_cmd() — pure argv assembly,
deliberately split out of RunSession.__init__ so it's testable without
spawning a real `atlas run`/`rerun` subprocess (which would try to run an
actual investigation) — and for RunManager.start()'s external-run guard,
which also avoids spawning a subprocess when it correctly blocks."""
from __future__ import annotations

import sys

import pytest

from dashboard import read_models, run_manager


class TestBuildCmd:
    def test_run_mode_uses_json_and_quiet(self):
        cmd = run_manager.build_cmd("/cases/demo", "run", [])
        assert cmd == [sys.executable, "-m", "agent.cli", "run",
                       "--case", "/cases/demo", "--json", "--quiet"]

    def test_rerun_mode_has_no_quiet_flag(self):
        # agent.cli's rerun subparser has no --quiet — passing it would fail
        # argparse with "unrecognized arguments".
        cmd = run_manager.build_cmd("/cases/demo", "rerun", [])
        assert "--quiet" not in cmd
        assert cmd == [sys.executable, "-m", "agent.cli", "rerun",
                       "--case", "/cases/demo", "--json"]

    def test_extra_args_appended_after_base_flags(self):
        cmd = run_manager.build_cmd(
            "/cases/demo", "run", ["--question", "who did it?", "-L", "de"])
        assert cmd[-4:] == ["--question", "who did it?", "-L", "de"]


class TestStartBlocksExternalRun:
    def test_refuses_to_start_over_a_live_external_run(self, tmp_path, monkeypatch):
        (tmp_path / "CASE-B").mkdir()
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: True)
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        with pytest.raises(run_manager.RunError, match="already in progress"):
            mgr.start(str(tmp_path), "CASE-B")
        # The guard must trip before RunSession() ever spawns a Popen —
        # confirmed indirectly: no session got registered.
        assert mgr.get("CASE-B") is None

    def test_starts_normally_when_no_external_run(self, tmp_path, monkeypatch):
        (tmp_path / "CASE-B").mkdir()
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
        # Avoid actually spawning `python -m agent.cli run` — swap in
        # something that exits immediately instead of a real investigation.
        monkeypatch.setattr(run_manager, "build_cmd",
                            lambda case_dir, mode, extra: [sys.executable, "-c", "pass"])
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        sess = mgr.start(str(tmp_path), "CASE-B")
        assert mgr.get("CASE-B") is sess
        sess.proc.wait(timeout=5)


class TestRunStatusPrefersWhatIsAlive:
    """The dashboard keeps a session for a run it started long after that
    run ended. A live run started from the CLI must not be reported as
    that stale session's "finished"."""

    def _dead_session(self, tmp_path, monkeypatch):
        (tmp_path / "CASE-B").mkdir()
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
        monkeypatch.setattr(run_manager, "build_cmd",
                            lambda case_dir, mode, extra: [sys.executable, "-c", "pass"])
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        sess = mgr.start(str(tmp_path), "CASE-B")
        sess.proc.wait(timeout=5)
        monkeypatch.setattr(run_manager, "MANAGER", mgr)
        return mgr

    def _status(self, tmp_path):
        import json
        from types import SimpleNamespace
        from dashboard import app
        resp = app._get_case_run_status(SimpleNamespace(cases_root=str(tmp_path)),
                                        None, {"case": "CASE-B"})
        return json.loads(resp.body)

    def test_a_live_cli_run_outranks_the_dashboards_ended_session(self, tmp_path, monkeypatch):
        self._dead_session(tmp_path, monkeypatch)
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: True)
        monkeypatch.setattr(read_models, "_run_status",
                            lambda case_dir: {"stopped_reason": "running", "turns": 56, "pid": 4242})
        st = self._status(tmp_path)
        assert st["running"] is True and st["external"] is True
        assert st["dashboard_tracked"] is False and st["turns"] == 56

    def test_the_ended_session_is_reported_when_nothing_else_runs(self, tmp_path, monkeypatch):
        self._dead_session(tmp_path, monkeypatch)
        st = self._status(tmp_path)
        assert st["running"] is False and st["dashboard_tracked"] is True

    def test_status_says_whether_the_case_ran_before(self, tmp_path, monkeypatch):
        import json
        self._dead_session(tmp_path, monkeypatch)
        assert self._status(tmp_path)["prior_run"] is False
        atlas = tmp_path / "CASE-B" / ".atlas"
        atlas.mkdir(exist_ok=True)
        (atlas / "run_status.json").write_text(json.dumps(
            {"stopped_reason": "finished", "finish_status": "complete"}))
        assert self._status(tmp_path)["prior_run"] is True


class TestQuickAdd:
    """Questions and facts typed into the start dialog reach the brief
    before the run starts, and never the command line."""

    def test_questions_and_facts_land_in_the_brief(self, tmp_path, monkeypatch):
        import json
        case = tmp_path / "CASE-B"
        case.mkdir()
        (case / "CASE.md").write_text(
            "# Case: CASE-B\n\n**Case ID:** CASE-B\n\n"
            "## Investigation Requests\n\n- What happened?\n\n"
            "## What you already know\n\n", encoding="utf-8")
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
        seen = {}

        def fake_build(case_dir, mode, extra):
            seen["extra"] = extra
            return [sys.executable, "-c", "pass"]
        monkeypatch.setattr(run_manager, "build_cmd", fake_build)
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        sess = mgr.start(str(tmp_path), "CASE-B", mode="rerun", options={
            "new_questions": "Was data taken?\n- Who logged in?\n",
            "new_context": "IP 10.0.0.5 is the print server.",
        })
        sess.proc.wait(timeout=5)
        md = (case / "CASE.md").read_text(encoding="utf-8")
        assert "- Was data taken?" in md and "- Who logged in?" in md
        assert "- IP 10.0.0.5 is the print server." in md
        assert seen["extra"] == []
        store = json.loads((case / ".atlas" / "investigation_tasks.json")
                           .read_text(encoding="utf-8"))
        assert {t["text"] for t in store["tasks"]} == {
            "What happened?", "Was data taken?", "Who logged in?"}


class TestRunOwner:
    """A run the dashboard started is stopped by its starter or an admin."""

    def _started(self, tmp_path, monkeypatch, starter):
        (tmp_path / "CASE-C").mkdir()
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
        monkeypatch.setattr(run_manager, "build_cmd",
                            lambda case_dir, mode, extra: [sys.executable, "-c", "import time; time.sleep(30)"])
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        sess = mgr.start(str(tmp_path), "CASE-C", started_by=starter)
        return mgr, sess

    def test_another_analyst_is_refused_and_the_starter_may_stop(self, tmp_path, monkeypatch):
        mgr, sess = self._started(tmp_path, monkeypatch, "jane.doe")
        try:
            assert sess.status()["started_by"] == "jane.doe"
            with pytest.raises(run_manager.RunForbidden, match="jane.doe or an administrator"):
                mgr.stop("CASE-C", actor="john.roe", actor_role="analyst")
            assert mgr.stop("CASE-C", actor="jane.doe", actor_role="analyst")["success"] is True
        finally:
            sess.proc.kill(); sess.proc.wait(timeout=5)

    def test_an_admin_may_stop_any_run(self, tmp_path, monkeypatch):
        mgr, sess = self._started(tmp_path, monkeypatch, "jane.doe")
        try:
            assert mgr.stop("CASE-C", actor="ops.admin", actor_role="admin")["success"] is True
        finally:
            sess.proc.kill(); sess.proc.wait(timeout=5)

    def test_a_run_without_a_recorded_starter_is_stopped_by_anyone_admitted(self, tmp_path, monkeypatch):
        mgr, sess = self._started(tmp_path, monkeypatch, "")
        try:
            assert mgr.stop("CASE-C", actor="john.roe", actor_role="analyst")["success"] is True
        finally:
            sess.proc.kill(); sess.proc.wait(timeout=5)


def test_a_run_the_dashboard_started_is_listed_before_its_first_status(tmp_path, monkeypatch):
    from dashboard import app as dash_app
    (tmp_path / "CASE-D").mkdir()
    monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
    monkeypatch.setattr(read_models, "active_runs", lambda root: [])
    monkeypatch.setattr(run_manager, "build_cmd",
                        lambda case_dir, mode, extra: [sys.executable, "-c", "import time; time.sleep(30)"])
    mgr = run_manager.RunManager(repo_root=str(tmp_path))
    monkeypatch.setattr(run_manager, "MANAGER", mgr)
    sess = mgr.start(str(tmp_path), "CASE-D", started_by="jane.doe")
    try:
        ctx = type("Ctx", (), {"cases_root": str(tmp_path)})()
        resp = dash_app._get_runs_active(ctx, None, {})
        import json as _json
        running = _json.loads(resp.body)["running"]
        assert running and running[0]["case_dir"] == "CASE-D"
        assert running[0]["started_by"] == "jane.doe" and running[0]["started_at"].endswith("Z")
    finally:
        sess.proc.kill(); sess.proc.wait(timeout=5)


class TestElapsed:
    """A run's elapsed time counts from its start on the server's clock. The
    status file's duration is a per-turn snapshot and stands still while one
    turn runs long."""

    def test_a_live_cli_run_counts_from_its_start_not_the_frozen_snapshot(self, tmp_path, monkeypatch):
        import json
        import time
        from types import SimpleNamespace
        from dashboard import app
        (tmp_path / "CASE-B").mkdir()
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1500))
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: True)
        monkeypatch.setattr(read_models, "_run_status", lambda case_dir: {
            "stopped_reason": "running", "turns": 8, "duration_seconds": 167, "started_at": started})
        st = json.loads(app._get_case_run_status(
            SimpleNamespace(cases_root=str(tmp_path)), None, {"case": "CASE-B"}).body)
        assert st["duration_seconds"] == 167
        assert 1495 <= st["elapsed_seconds"] <= 1510

    def test_the_start_the_dashboard_pressed_reaches_the_run_and_stands(self, tmp_path, monkeypatch):
        import json
        import time
        case = tmp_path / "CASE-B"
        (case / ".atlas").mkdir(parents=True)
        monkeypatch.setattr(read_models, "run_process_alive", lambda case_dir: False)
        monkeypatch.setattr(run_manager, "build_cmd", lambda case_dir, mode, extra: [
            sys.executable, "-c", "import os; print(os.environ.get('ATLAS_RUN_STARTED_AT'))"])
        mgr = run_manager.RunManager(repo_root=str(tmp_path))
        sess = mgr.start(str(tmp_path), "CASE-B")
        sess.proc.wait(timeout=5)
        for _ in range(50):
            if sess.stdout_tail:
                break
            time.sleep(0.05)
        pressed = sess.started_at_utc()
        assert pressed in "".join(sess.stdout_tail)
        later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sess.started_at + 400))
        (case / ".atlas" / "run_status.json").write_text(json.dumps(
            {"stopped_reason": "running", "started_at": later}))
        assert sess.status()["started_at"] == pressed


def test_the_loop_keeps_the_start_it_was_handed(monkeypatch):
    import time
    from agent import loop
    handed = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    monkeypatch.setenv("ATLAS_RUN_STARTED_AT", handed)
    assert loop._run_started_at() == handed
    for bad in ("not a time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 600))):
        monkeypatch.setenv("ATLAS_RUN_STARTED_AT", bad)
        assert loop._run_started_at() != bad
