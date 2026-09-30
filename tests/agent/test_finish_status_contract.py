"""Finish-status contract: complete needs report + successful synthesize."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.loop import Agent


def _agent(case_dir: Path, tool_stats=None):
    a = object.__new__(Agent)
    a.case_dir = case_dir
    a._tool_stats = tool_stats or []
    return a


def _run_finish(a, *, cis, entries):
    log = MagicMock()
    log._entries = entries
    with patch(
        "core.investigation_state.build_current_investigation_state",
        return_value=cis,
    ), patch(
        "core.coverage_ledger.ready_for_degraded_exit", return_value=True,
    ), patch(
        "core.coverage_ledger.coverage_stats",
        return_value={"unseen": 0},
    ), patch(
        "core.coverage_ledger.load_ledger", return_value={},
    ), patch(
        "core.execution_log.log", log,
    ):
        return a._finish_status("finished")


def test_complete_requires_report_and_successful_synthesize(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    assert _run_finish(
        a,
        cis={"has_beliefs": True,
             "counts": {"investigation_tasks_actionable": 0}},
        entries=[{
            "call_id": 1,
            "type": "reason_call",
            "tool": "reason_synthesize",
            "success": True,
            "conclusion": "Attack narrative with evidence.",
        }, {
            "call_id": 2,
            "type": "reason_call",
            "tool": "reason_pre_report_check",
            "success": True,
            "conclusion": "READY_TO_REPORT: true\nAll blockers cleared.",
        }],
    ) == "complete"


def test_ready_false_blocks_complete_despite_report(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    assert _run_finish(
        a,
        cis={"has_beliefs": True,
             "counts": {"investigation_tasks_actionable": 0}},
        entries=[{
            "call_id": 1,
            "type": "reason_call",
            "tool": "reason_synthesize",
            "success": True,
            "conclusion": "Partial narrative with BLOCKERs.",
        }, {
            "call_id": 2,
            "type": "reason_call",
            "tool": "reason_pre_report_check",
            "success": True,
            "conclusion": "READY_TO_REPORT: false\nDisk access incomplete.",
        }],
    ) == "incomplete_coverage"


def test_host_scratch_doc_does_not_count_as_final_report(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "reports").mkdir()
    (case / "reports" / "host_FILESRV01_report.md").write_text(
        "# host scratch\n" + ("x" * 200), encoding="utf-8",
    )
    a = _agent(case, tool_stats=[])
    assert a._report_written() is False


def test_empty_synthesize_blocks_complete(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    assert _run_finish(
        a,
        cis={"has_beliefs": True,
             "counts": {"investigation_tasks_actionable": 0}},
        entries=[{
            "call_id": 1,
            "type": "reason_call",
            "tool": "reason_synthesize",
            "success": False,
            "conclusion": "",
            "gate": "empty_reason_response",
        }],
    ) == "incomplete_coverage"


def test_missing_report_blocks_complete(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[])
    assert _run_finish(
        a,
        cis={"has_beliefs": True,
             "counts": {"investigation_tasks_actionable": 0}},
        entries=[{
            "call_id": 1,
            "type": "reason_call",
            "tool": "reason_synthesize",
            "success": True,
            "conclusion": "Narrative.",
        }],
    ) == "incomplete_coverage"


def test_open_tasks_block_complete(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    assert _run_finish(
        a,
        cis={"has_beliefs": True,
             "counts": {"investigation_tasks_actionable": 3}},
        entries=[{
            "call_id": 1,
            "type": "reason_call",
            "tool": "reason_synthesize",
            "success": True,
            "conclusion": "Narrative.",
        }],
    ) == "incomplete_coverage"


def test_finish_status_exception_is_not_complete(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    with patch(
        "core.investigation_state.build_current_investigation_state",
        side_effect=RuntimeError("boom"),
    ):
        assert a._finish_status("finished") == "incomplete_coverage"


def test_unseen_hv_blocks_complete_despite_soft_floor(tmp_path):
    """Task soft floor must not yield complete while HV units remain unseen."""
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    log = MagicMock()
    log._entries = [{
        "call_id": 1,
        "type": "reason_call",
        "tool": "reason_synthesize",
        "success": True,
        "conclusion": "Narrative.",
    }, {
        "call_id": 2,
        "type": "reason_call",
        "tool": "reason_pre_report_check",
        "success": True,
        "conclusion": "READY_TO_REPORT: true\nOK.",
    }]
    with patch(
        "core.investigation_state.build_current_investigation_state",
        return_value={
            "has_beliefs": True,
            "counts": {"investigation_tasks_actionable": 0},
        },
    ), patch(
        "core.coverage_ledger.ready_for_degraded_exit", return_value=True,
    ), patch(
        "core.coverage_ledger.coverage_stats",
        return_value={"unseen": 17},
    ), patch(
        "core.coverage_ledger.load_ledger", return_value={},
    ), patch(
        "core.investigation_obligations.obligations_met_for_complete",
        return_value=True,
    ), patch(
        "core.execution_log.log", log,
    ):
        assert a._finish_status("finished") == "incomplete_coverage"


def test_unmet_obligations_block_complete(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    a = _agent(case, tool_stats=[{
        "name": "misc_write_projected_final_report",
        "error": None,
        "deliverable_scope": "case",
    }])
    log = MagicMock()
    log._entries = [{
        "call_id": 1,
        "type": "reason_call",
        "tool": "reason_synthesize",
        "success": True,
        "conclusion": "Narrative.",
    }, {
        "call_id": 2,
        "type": "reason_call",
        "tool": "reason_pre_report_check",
        "success": True,
        "conclusion": "READY_TO_REPORT: true\nOK.",
    }]
    with patch(
        "core.investigation_state.build_current_investigation_state",
        return_value={
            "has_beliefs": True,
            "counts": {"investigation_tasks_actionable": 0},
        },
    ), patch(
        "core.coverage_ledger.ready_for_degraded_exit", return_value=True,
    ), patch(
        "core.coverage_ledger.coverage_stats",
        return_value={"unseen": 0},
    ), patch(
        "core.coverage_ledger.load_ledger", return_value={},
    ), patch(
        "core.investigation_obligations.obligations_met_for_complete",
        return_value=False,
    ), patch(
        "core.execution_log.log", log,
    ):
        assert a._finish_status("finished") == "incomplete_coverage"
