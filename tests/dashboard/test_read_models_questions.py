"""Regression test for dashboard/read_models.py's questions_projection().

Bug: a case whose CASE.md has Investigation Requests bullets but no
.atlas/investigation_tasks.json yet (a case created by hand, by the CLI, or
under a dashboard version that predates dashboard/case_admin.py's write-side
sync — see tests/dashboard/test_case_admin.py) showed "No investigation
questions" forever in the Questions tab: questions_projection() read only
the task store, and nothing had ever reconciled CASE.md into it. Fixed by
having load_task_store() reconcile on every read, not just on the
dashboard's own save/create paths.
"""
from __future__ import annotations

from dashboard import read_models


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
