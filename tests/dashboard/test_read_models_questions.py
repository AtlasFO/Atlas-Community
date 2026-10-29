"""Regression test for dashboard/read_models.py's questions_projection().

Failure class: a case whose CASE.md has Investigation Requests bullets but no
.atlas/investigation_tasks.json yet (a case created by hand, by the CLI, or
by a dashboard without dashboard/case_admin.py's write-side sync — see
tests/dashboard/test_case_admin.py) would show "No investigation
questions" forever in the Questions tab if questions_projection() read only
the task store and nothing reconciled CASE.md into it. load_task_store()
therefore reconciles on every read, not just on the dashboard's own
save/create paths.
"""
from __future__ import annotations

from dashboard import read_models
import pytest


@pytest.fixture(autouse=True)
def _todays_answer_path(monkeypatch):
    """This module pins the answer path before the composer: the scaffold,
    the prose pass, the conclusion lead (ATLAS_ANSWER_COMPOSE=0)."""
    monkeypatch.setenv("ATLAS_ANSWER_COMPOSE", "0")


def test_questions_appear_without_any_prior_sync(tmp_path):
    case_dir = tmp_path / "CASE-B"
    case_dir.mkdir()
    (case_dir / "CASE.md").write_text(
        "# Case: CASE-B\n\n"
        "**Case ID:** CASE-B\n\n"
        "## Investigation Requests\n"
        "- Which host was accessed first?\n"
        "- Was data copied off the network, and if so which files?\n",
        encoding="utf-8",
    )
    # Deliberately no .atlas/ directory at all — the exact reported scenario.
    result = read_models.questions_projection(str(case_dir))
    texts = [q["text"] for q in result["questions"]]
    assert "Which host was accessed first?" in texts
    assert "Was data copied off the network, and if so which files?" in texts
    assert result["total_visible"] == 2


def test_no_case_md_leaves_projection_empty_without_crashing(tmp_path):
    case_dir = tmp_path / "Empty"
    case_dir.mkdir()
    result = read_models.questions_projection(str(case_dir))
    assert result["questions"] == []
