"""A rerun starts the investigator when the pre-run pass found work, says
so when it found none, never starts one under --no-agent, and settles a
session's ending the way a run does."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _args(**over):
    base = {
        "case": None, "diff": None, "list_runs": False, "question": None,
        "withdraw_context": None, "correct_context": None, "dry_run": False,
        "json": False, "full_hash": False, "regenerate_sections": False,
        "assemble_report": False, "report_format": "markdown",
        "no_agent": False, "model": None, "language": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text(
        "**Case ID** RR\n\n## Investigation Requests\n\n- What happened?\n",
        encoding="utf-8")
    return case


def _plane(pending: bool) -> dict:
    return {
        "success": True, "case_id": "RR",
        "work": {"pending": pending,
                 "reasons": ["1 open question (1 new)"] if pending else []},
        "context_reconcile": {"added": [], "reactivated": [], "withdrawn": []},
        "rerun_brief_text": "# Rerun Brief",
    }


def _run_cmd_rerun(case: Path, args, plane: dict, plane_b: MagicMock):
    from agent import cli as cli_mod
    args.case = str(case)
    with patch("core.run_lock.acquire", return_value=None), \
         patch("core.incremental.plane_a_scan", return_value=plane), \
         patch.object(cli_mod, "_open_trace_before_plane_a"), \
         patch.object(cli_mod, "_require_sudo_preflight"), \
         patch.object(cli_mod, "_run_plane_b", plane_b), \
         patch.object(cli_mod, "_finalize_report_snapshots") as snap, \
         patch("core.report_projection.regenerate_sections",
               return_value={"regenerated": []}), \
         patch("core.report_projection.assemble_report",
               return_value={"format": "markdown", "output_path": "x"}):
        cli_mod.cmd_rerun(args)
    return snap


def test_work_starts_the_investigator(tmp_path):
    case = _case(tmp_path)
    plane_b = MagicMock(return_value={"regenerated": []})
    snap = _run_cmd_rerun(case, _args(), _plane(True), plane_b)
    assert plane_b.call_count == 1
    assert snap.call_args.kwargs["trigger"] == "investigate"


def test_no_work_says_so_and_skips_the_investigator(tmp_path, capsys):
    case = _case(tmp_path)
    plane_b = MagicMock()
    _run_cmd_rerun(case, _args(), _plane(False), plane_b)
    plane_b.assert_not_called()
    assert "Nothing new since the previous run" in capsys.readouterr().out


def test_no_agent_never_starts_the_investigator(tmp_path):
    case = _case(tmp_path)
    plane_b = MagicMock()
    snap = _run_cmd_rerun(case, _args(no_agent=True), _plane(True), plane_b)
    plane_b.assert_not_called()
    assert snap.call_args.kwargs["trigger"] == "no-agent"


def test_a_stopped_session_records_its_status_like_a_run(tmp_path):
    from agent import cli as cli_mod
    case = _case(tmp_path)
    agent = SimpleNamespace(
        ui=MagicMock(), stats=None, interactive=False,
        toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
        run=MagicMock(side_effect=KeyboardInterrupt),
    )
    with patch.object(cli_mod, "_make_agent", return_value=agent), \
         patch.object(cli_mod, "_teardown_local_mounts"), \
         patch("agent.prompts.build_system_prompt", return_value="sys"), \
         patch("core.paths.register_answer_keys"), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         pytest.raises(KeyboardInterrupt):
        cli_mod._run_plane_b(_args(), case, _plane(True), "markdown")
    status = json.loads((case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["stopped_reason"] == "keyboard_interrupt"
    assert status["finish_status"] == "interrupted"


def test_rerun_objective_prefers_the_open_questions(tmp_path):
    from agent.prompts import rerun_objective
    from core.investigation_tasks import reconcile_case_md
    case = _case(tmp_path)
    reconcile_case_md(case)
    assert rerun_objective(case, {"evidence": {"added": 1}}) == "What happened?"


def test_rerun_objective_comes_from_the_work_when_nothing_is_open():
    from agent.prompts import rerun_objective
    text = rerun_objective(None, {
        "evidence": {"added": 2, "changed": 0, "removed": 0},
        "claims_to_review": ["C1"],
    })
    assert "Examine the evidence added or changed" in text
    assert "Re-validate the findings marked needs_review" in text
    assert "still hold" in rerun_objective(None, {})


def test_rerun_message_names_the_change_and_the_objective():
    from agent.prompts import initial_rerun_message
    msg = initial_rerun_message(
        brief_text="# Rerun Brief", namespace_summary="ns", case_id="RR",
        question="Was data taken?",
        changes=["1 evidence file added", "1 open question (1 new)"],
        context_added=["IP 10.0.0.5 is the print server."],
        context_withdrawn=[],
    )
    assert "WHY THIS RERUN" in msg and "- 1 evidence file added" in msg
    assert "CASE_QUESTION: Was data taken?" in msg
    assert "- IP 10.0.0.5 is the print server." in msg
    assert "USE THIS CASE ID: RR" in msg and "# Rerun Brief" in msg
    assert "misc_inventory_evidence" in msg and "atlas_finish" in msg
