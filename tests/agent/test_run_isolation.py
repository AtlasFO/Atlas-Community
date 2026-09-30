"""Fresh vs resume run isolation for atlas run."""
from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest


def test_prior_run_is_terminal_detects_finish_status(tmp_path):
    from agent.cli import _prior_run_is_terminal

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    assert _prior_run_is_terminal(case) is False
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "finished",
        "finish_status": "incomplete_coverage",
    }))
    assert _prior_run_is_terminal(case) is True


def test_prepare_run_isolation_auto_clears_after_terminal(tmp_path):
    from agent.cli import _prepare_run_isolation

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "analysis" / "old_trace.json").write_text("{}")
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "finished",
        "finish_status": "complete",
    }))
    args = Namespace(fresh=False, resume=False)
    _prepare_run_isolation(args, case)
    assert not (case / "analysis" / "old_trace.json").exists()
    status = json.loads((case / ".atlas" / "run_status.json").read_text())
    assert status.get("finish_status") == ""
    assert status.get("stopped_reason") == "starting"


def test_prepare_run_isolation_resume_keeps_trace(tmp_path):
    from agent.cli import _prepare_run_isolation

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "analysis" / "old_trace.json").write_text("{}")
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "finished",
        "finish_status": "complete",
    }))
    args = Namespace(fresh=False, resume=True)
    _prepare_run_isolation(args, case)
    assert (case / "analysis" / "old_trace.json").exists()


def test_a_clear_that_leaves_something_behind_stops_the_run(tmp_path):
    from agent.cli import _prepare_run_isolation

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    args = Namespace(fresh=True, resume=False)
    with patch("tools.misc.clear_case_run",
               return_value={"success": False, "cleared_count": 0,
                             "errors": ["Permission denied: analysis/x"]}), \
            pytest.raises(SystemExit):
        _prepare_run_isolation(args, case)


def test_fresh_and_resume_are_mutually_exclusive(tmp_path):
    from agent.cli import _prepare_run_isolation

    args = Namespace(fresh=True, resume=True)
    with pytest.raises(SystemExit):
        _prepare_run_isolation(args, tmp_path)


def test_prepare_run_isolation_clears_leftover_trace_without_status(tmp_path):
    """Crash mid-run leaves a trace but no terminal status — still isolate."""
    from agent.cli import _prepare_run_isolation

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "analysis" / "case_trace.json").write_text("{}")
    args = Namespace(fresh=False, resume=False)
    _prepare_run_isolation(args, case)
    assert not (case / "analysis" / "case_trace.json").exists()
    status = json.loads((case / ".atlas" / "run_status.json").read_text())
    assert status.get("isolation") == "auto_fresh_after_leftover_trace"


def test_clear_case_run_wipes_process_run_caches_keeps_cis(tmp_path):
    """report_projection / path_knowledge are ProcessRun; claim_graph is CIS."""
    from tools.misc import clear_case_run

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "reports").mkdir()
    proj = case / ".atlas" / "report_projection"
    proj.mkdir()
    (proj / "manifest.json").write_text("{}", encoding="utf-8")
    (case / ".atlas" / "path_knowledge.json").write_text(
        json.dumps({"failed_guesses": ["/nope"]}), encoding="utf-8",
    )
    (case / ".atlas" / "context_budget.json").write_text("{}", encoding="utf-8")
    (case / ".atlas" / "claim_graph.json").write_text(
        json.dumps({"claims": [{"id": "c1"}]}), encoding="utf-8",
    )
    (case / ".atlas" / "investigation_tasks.json").write_text(
        json.dumps({"tasks": []}), encoding="utf-8",
    )
    clear_case_run(str(case), clear_memory=False)
    assert not proj.exists()
    assert not (case / ".atlas" / "path_knowledge.json").exists()
    assert not (case / ".atlas" / "context_budget.json").exists()
    assert (case / ".atlas" / "claim_graph.json").exists()
    assert (case / ".atlas" / "investigation_tasks.json").exists()


def test_an_output_dir_run_clears_the_mirror_not_the_case(tmp_path, monkeypatch):
    from agent import cli

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "analysis" / "case_trace.json").write_text("{}")
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "finished", "finish_status": "complete"}))
    mirror = tmp_path / "mirror"
    (mirror / "analysis").mkdir(parents=True)
    (mirror / "analysis" / "case_trace.json").write_text("{}")

    class _Stop(Exception):
        pass

    def _no_run(*a, **k):
        raise _Stop

    monkeypatch.setattr(cli, "_require_sudo_preflight", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_apply_report_language", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_run_investigation", _no_run)
    args = Namespace(fresh=True, resume=False, output_dir=str(mirror))
    with pytest.raises(_Stop):
        cli._run_locked(args, case, lock_fd=-1)
    assert (case / "analysis" / "case_trace.json").exists()
    assert json.loads((case / ".atlas" / "run_status.json").read_text())["finish_status"] == "complete"
    assert not (mirror / "analysis" / "case_trace.json").exists()


def test_a_case_under_a_handling_stop_gets_no_mirror(tmp_path):
    from agent.cli import _prepare_output_dir
    from core.handling_stop import assert_stop

    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    assert_stop(case, "csam", "brief asserts it", frame="subject")
    with pytest.raises(SystemExit) as exc:
        _prepare_output_dir(case, str(tmp_path / "mirror"))
    assert "handling stop" in str(exc.value) and "--resume" in str(exc.value)
    assert not (tmp_path / "mirror").exists()
    # The case itself as the output directory is not a mirror.
    assert _prepare_output_dir(case, str(case)) == case
