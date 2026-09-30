"""Belief starvation must not be excused by coverage-only churn."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.run_budget import (
    StallState,
    belief_starvation_active,
    messages_for_turn,
    observe_progress,
)
from core import run_budget as rb


def _case_with_open_tasks(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Was user01 compromised?\n",
        encoding="utf-8",
    )
    from core.investigation_tasks import reconcile_case_md
    reconcile_case_md(case, persist=True)
    return case


def test_belief_starvation_active_with_open_tasks(tmp_path: Path):
    case = _case_with_open_tasks(tmp_path)
    assert belief_starvation_active(case) is True


def test_coverage_only_does_not_reset_streak_when_starved(tmp_path: Path):
    case = _case_with_open_tasks(tmp_path)
    state = StallState(
        last_belief_snapshot={"findings": 0},
        last_coverage_fp=("a",),
        last_exploration_fp=("x",),
        no_progress_streak=5,
    )
    fake_belief = {"findings": 0}
    with patch("core.progress_signature.snapshot", return_value=fake_belief), \
         patch("core.progress_signature.diff") as diff, \
         patch("core.coverage_ledger.coverage_fingerprint",
               return_value=("b",)), \
         patch("core.coverage_ledger.exploration_fingerprint",
               return_value=("x",)), \
         patch("core.coverage_ledger.load_ledger", return_value={"units": {}}), \
         patch("core.coverage_ledger.recent_gate_repair_active",
               return_value=False):
        diff.return_value.changed = False
        out = observe_progress(state, case_dir=case)
    assert out.belief_starvation is True
    assert out.no_progress_streak == 6  # incremented, not reset
    assert out.last_coverage_fp == ("b",)


def test_belief_change_still_resets_when_starved(tmp_path: Path):
    case = _case_with_open_tasks(tmp_path)
    state = StallState(
        last_belief_snapshot={"findings": 0},
        last_coverage_fp=("a",),
        last_exploration_fp=("x",),
        no_progress_streak=5,
    )
    with patch("core.progress_signature.snapshot",
               return_value={"findings": 1}), \
         patch("core.progress_signature.diff") as diff, \
         patch("core.coverage_ledger.coverage_fingerprint",
               return_value=("a",)), \
         patch("core.coverage_ledger.exploration_fingerprint",
               return_value=("x",)), \
         patch("core.coverage_ledger.load_ledger", return_value={"units": {}}), \
         patch("core.coverage_ledger.recent_gate_repair_active",
               return_value=False):
        diff.return_value.changed = True
        out = observe_progress(state, case_dir=case)
    assert out.no_progress_streak == 0


def test_stall_message_includes_belief_starvation_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 2)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 99)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)
    case = _case_with_open_tasks(tmp_path)
    state = StallState(no_progress_streak=2, belief_starvation=True)
    msgs = messages_for_turn(
        state, turn=10, report_written=False, case_dir=case,
    )
    soft = next(m["content"] for m in msgs if "stall soft" in m["content"])
    assert "belief starvation" in soft


def test_task_disposition_lagging_and_deprioritize():
    from tools.dair import (
        _TASK_DISPOSITION_NUDGE,
        _deprioritize_expensive_disk,
        _task_disposition_lagging,
    )
    ordered = _deprioritize_expensive_disk([
        "img.vmdk_export_raw", "table.table_query", "tsk.fls",
    ])
    assert ordered[0] == "table.table_query"
    assert "img.vmdk_export_raw" in ordered
    assert ordered.index("table.table_query") < ordered.index(
        "img.vmdk_export_raw")
    assert _TASK_DISPOSITION_NUDGE
    # Without a live case/trace, lagging is false (fail-closed)
    assert _task_disposition_lagging() is False
