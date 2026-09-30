"""A case knows it had a run by the ending the run recorded or by the
trace it left behind; the post-clear marker is neither."""
from __future__ import annotations

import json

from core import run_state


def _case(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    return case


def test_no_state_means_no_prior_run(tmp_path):
    case = _case(tmp_path)
    assert run_state.prior_run_is_terminal(case) is False
    assert run_state.prior_process_artifacts_present(case) is False
    assert run_state.prior_run_exists(case) is False


def test_a_recorded_ending_is_a_prior_run(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "run_status.json").write_text(json.dumps(
        {"stopped_reason": "finished", "finish_status": "complete"}))
    assert run_state.prior_run_is_terminal(case) is True
    assert run_state.prior_run_exists(case) is True


def test_a_crash_with_an_error_status_is_a_prior_run(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "run_status.json").write_text(json.dumps(
        {"stopped_reason": "crashed", "finish_status": "error"}))
    assert run_state.prior_run_is_terminal(case) is True


def test_the_post_clear_marker_is_not_a_prior_run(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "run_status.json").write_text(json.dumps(
        {"stopped_reason": "starting", "finish_status": ""}))
    assert run_state.prior_run_is_terminal(case) is False
    assert run_state.prior_run_exists(case) is False


def test_a_live_run_without_an_ending_is_not_terminal(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "run_status.json").write_text(json.dumps(
        {"stopped_reason": "running", "finish_status": ""}))
    assert run_state.prior_run_is_terminal(case) is False


def test_a_leftover_trace_is_a_prior_run(tmp_path):
    case = _case(tmp_path)
    (case / "analysis").mkdir()
    (case / "analysis" / "X_trace.json").write_text("{}")
    assert run_state.prior_process_artifacts_present(case) is True
    assert run_state.prior_run_exists(case) is True


def test_unreadable_status_is_ignored(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "run_status.json").write_text("{not json")
    assert run_state.prior_run_is_terminal(case) is False
