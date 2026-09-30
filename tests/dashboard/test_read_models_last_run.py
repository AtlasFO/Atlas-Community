"""The Overview's delta line comes from the newest pre-run record."""
from __future__ import annotations

import json

from dashboard import read_models


def _journal(case_dir, run_id, work, finished_at="2026-01-01T00:00:00Z"):
    history = case_dir / ".atlas" / "run_history"
    history.mkdir(parents=True, exist_ok=True)
    (history / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "trigger": "cli", "finished_at": finished_at,
        "work": work, "why_summary": ["evidence_added: a file"],
    }), encoding="utf-8")


def test_no_history_means_no_delta(tmp_path):
    assert read_models.latest_run_journal(str(tmp_path)) is None


def test_the_newest_record_wins(tmp_path):
    _journal(tmp_path, "run-0001", {"pending": True, "reasons": ["first look at 3 evidence files"]})
    _journal(tmp_path, "run-0002", {"pending": False, "reasons": []})
    last = read_models.latest_run_journal(str(tmp_path))
    assert last["run_id"] == "run-0002"
    assert last["work"] == {"pending": False, "reasons": []}
    assert last["finished_at"] == "2026-01-01T00:00:00Z"


def test_a_record_without_work_is_still_reported(tmp_path):
    _journal(tmp_path, "run-0001", None)
    last = read_models.latest_run_journal(str(tmp_path))
    assert last["run_id"] == "run-0001" and last["work"] is None


def test_the_overview_carries_it(tmp_path):
    case = tmp_path / "CASE-B"
    case.mkdir()
    (case / "CASE.md").write_text(
        "# Case: CASE-B\n\n**Case ID:** CASE-B\n\n"
        "## Investigation Requests\n\n- What happened?\n", encoding="utf-8")
    _journal(case, "run-0001", {"pending": True, "reasons": ["1 open question (1 new)"]})
    overview = read_models.case_overview(str(case))
    assert overview["last_run"]["work"]["reasons"] == ["1 open question (1 new)"]
