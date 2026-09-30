""": KeyboardInterrupt persists run_status=interrupted."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _state_the_analysts_effort(monkeypatch):
    """A run states its analyst's reasoning effort before it starts, so these
    drive `_run_investigation` the way the CLI does. "default" is the
    endpoint's own — these tests are about how a run ends, not how it thinks."""
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "default")


def test_keyboard_interrupt_persists_run_status(tmp_path: Path):
    from agent import cli as cli_mod

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate host\n",
        encoding="utf-8",
    )

    agent = SimpleNamespace(
        ui=MagicMock(),
        stats=None,
        interactive=False,
        toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
        run=MagicMock(side_effect=KeyboardInterrupt),
    )
    args = SimpleNamespace(
        json=False, quiet=False, remote=None, output_dir=None,
        question=None, case_id="",
    )

    with patch.object(cli_mod, "plane_a_scan", create=True), \
         patch("core.incremental.plane_a_scan",
               return_value={"success": True, "case_id": "case"}), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         patch.object(cli_mod, "_configure_remote", return_value=None), \
         patch.object(cli_mod, "_make_agent", return_value=agent), \
         patch.object(cli_mod, "_teardown_local_mounts"), \
         patch.object(cli_mod, "_resolve_case_question",
                      return_value="Investigate host"), \
         patch("agent.prompts.build_system_prompt", return_value="sys"), \
         patch("agent.prompts.initial_user_message", return_value="user"), \
         patch("core.paths.register_answer_keys"), \
         patch("core.brain.answer_key.has_ground_truth", return_value=False):
        with pytest.raises(KeyboardInterrupt):
            cli_mod._run_investigation(args, case, command="run")

    status_path = case / ".atlas" / "run_status.json"
    assert status_path.is_file()
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["finish_status"] == "interrupted"
    assert status["stopped_reason"] == "keyboard_interrupt"


def _base_case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate host\n", encoding="utf-8")
    return case


def _run_with_agent(case: Path, agent, *, expect_sys_exit: bool = False):
    from agent import cli as cli_mod
    args = SimpleNamespace(
        json=False, quiet=False, remote=None, output_dir=None,
        question=None, case_id="",
    )
    with patch.object(cli_mod, "plane_a_scan", create=True), \
         patch("core.incremental.plane_a_scan",
               return_value={"success": True, "case_id": "case"}), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         patch.object(cli_mod, "_configure_remote", return_value=None), \
         patch.object(cli_mod, "_make_agent", return_value=agent), \
         patch.object(cli_mod, "_teardown_local_mounts"), \
         patch.object(cli_mod, "_resolve_case_question",
                      return_value="Investigate host"), \
         patch("agent.prompts.build_system_prompt", return_value="sys"), \
         patch("agent.prompts.initial_user_message", return_value="user"), \
         patch("core.paths.register_answer_keys"), \
         patch("core.brain.answer_key.has_ground_truth", return_value=False):
        if expect_sys_exit:
            with pytest.raises(SystemExit):
                cli_mod._run_investigation(args, case, command="run")
        else:
            with pytest.raises(RuntimeError):
                cli_mod._run_investigation(args, case, command="run")


def test_llm_error_persists_run_status(tmp_path: Path):
    """Regression: a token/context-limit rejection from the LLM API raises
    LLMError, which used to go straight to sys.exit(1) without ever writing
    run_status.json — a dashboard operator with no SSH access saw the run
    just silently stop updating, with no indication anything went wrong."""
    from agent.llm import LLMError
    case = _base_case(tmp_path)
    agent = SimpleNamespace(
        ui=MagicMock(), stats=None, interactive=False,
        toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
        run=MagicMock(side_effect=LLMError("context length exceeded")),
    )
    _run_with_agent(case, agent, expect_sys_exit=True)

    status = json.loads(
        (case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["finish_status"] == "error"
    assert status["stopped_reason"] == "llm_error"
    assert "context length exceeded" in status["error"]


def test_unexpected_crash_persists_run_status(tmp_path: Path):
    """Any other exception (a real bug, not LLMError/KeyboardInterrupt) must
    also leave a record — the dashboard should never see a run just stop
    updating with zero explanation, however it died."""
    case = _base_case(tmp_path)
    agent = SimpleNamespace(
        ui=MagicMock(), stats=None, interactive=False,
        toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
        run=MagicMock(side_effect=RuntimeError("boom")),
    )
    _run_with_agent(case, agent, expect_sys_exit=False)

    status = json.loads(
        (case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["finish_status"] == "error"
    assert status["stopped_reason"] == "crashed"
    assert "boom" in status["error"]


@pytest.mark.parametrize("error,reason,exits", [
    ("llm", "llm_error", True),
    (RuntimeError("boom"), "crashed", False),
])
def test_every_abnormal_ending_still_leaves_a_report(tmp_path: Path,
                                                     monkeypatch, error,
                                                     reason, exits):
    """A run that died on its provider or on a bug owes the same report as
    one that was stopped: both branches used to exit without writing any.
    No model call on this path — the provider may be what ended the run."""
    from agent.llm import LLMError
    from core.report_exit import exit_report_path
    from core.report_projection import load_manifest
    from tests.core.test_audit_fixes import _graph_with_claims
    import core.investigation_state as inv

    case = _base_case(tmp_path)
    _graph_with_claims(case, 2)
    monkeypatch.setattr(inv, "project_report_from_state", MagicMock(
        side_effect=AssertionError("the exit path made a model call")))

    agent = SimpleNamespace(
        ui=MagicMock(), stats=None, interactive=False,
        toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
        run=MagicMock(side_effect=LLMError("context length exceeded")
                      if error == "llm" else error),
    )
    _run_with_agent(case, agent, expect_sys_exit=exits)

    out = exit_report_path(case)
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert f"Written at run end ({reason})" in text
    assert load_manifest(case)["report_stage"] == "deterministic"
