"""Smaller CLI contracts: bare `atlas models` lists the analyst's provider, a
run's trace has one case id from Plane A to the analyst, a short withdrawal
reason is told the rule, and `atlas interactive` takes the run flags."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ── bare `atlas models` ──────────────────────────────────────────────────────

class _ModelsClient:
    asked: list[str] = []

    def __init__(self, provider="", **_):
        _ModelsClient.asked.append(provider)
        self.provider = SimpleNamespace(name=provider)
        self.api_key = "k-123"
        self.key_missing = False    # the client's own key test (LLMHubClient.key_missing)

    def list_models(self):
        return ["corp-model-1", "corp-model-2"]


def test_bare_models_lists_the_analysts_provider(monkeypatch, capsys):
    from agent import cli
    monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "corp-gateway")
    _ModelsClient.asked = []
    with patch("agent.llm.LLMHubClient", _ModelsClient):
        cli.main(["models"])
    out = capsys.readouterr()
    assert _ModelsClient.asked == ["corp-gateway"]
    assert out.out.split() == ["corp-model-1", "corp-model-2"]
    assert "provider: corp-gateway" in out.err


def test_bare_models_without_an_analyst_provider_says_what_to_pass(monkeypatch):
    from agent import cli
    monkeypatch.delenv("ATLAS_AGENT_PROVIDER", raising=False)
    with pytest.raises(SystemExit) as ended:
        cli.main(["models"])
    assert "pass --provider NAME" in str(ended.value.code)


def test_an_explicit_provider_wins(monkeypatch):
    from agent import cli
    monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "corp-gateway")
    _ModelsClient.asked = []
    with patch("agent.llm.LLMHubClient", _ModelsClient):
        cli.main(["models", "--provider", "corp-other"])
    assert _ModelsClient.asked == ["corp-other"]


# ── one case id per run ──────────────────────────────────────────────────────

def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case-dir"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    (case / "CASE.md").write_text(
        "**Case ID:** CASE-A\n\n## Investigation Requests\n\n- What happened?\n", encoding="utf-8")
    return case


def test_the_run_case_id(tmp_path, capsys):
    from agent import cli
    case = _case(tmp_path)
    assert cli._run_case_id(SimpleNamespace(case_id=""), case) == "CASE-A"
    assert cli._run_case_id(SimpleNamespace(case_id="CASE-X"), case) == "CASE-X"
    (case / "analysis" / "CASE-A_trace.json").write_text('{"case_id": "CASE-A", "entries": []}')
    assert cli._run_case_id(SimpleNamespace(case_id="CASE-X", resume=True), case) == "CASE-A"
    assert "does not rename a run in progress" in capsys.readouterr().err
    assert cli._run_case_id(SimpleNamespace(case_id="CASE-X", no_clear=True), case) == "CASE-A"


def test_plane_a_and_the_analyst_share_the_overridden_trace(tmp_path, monkeypatch):
    import core.execution_log as elog
    from agent import cli
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "default")
    case = _case(tmp_path)
    seen = {}

    def _plane(*a, **k):
        seen["plane_trace"] = elog.log.trace_path()
        return {"success": True, "case_id": "CASE-A"}

    def _user_message(*a, **k):
        seen["told"] = k.get("case_id")
        return "user"

    agent = SimpleNamespace(ui=MagicMock(), stats=None, interactive=False,
                            toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
                            run=MagicMock(side_effect=KeyboardInterrupt))
    args = SimpleNamespace(json=False, quiet=False, remote=None, output_dir=None,
                           question=None, case_id="CASE-X")
    with patch("core.incremental.plane_a_scan", _plane), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         patch.object(cli, "_configure_remote", return_value=None), \
         patch.object(cli, "_make_agent", return_value=agent), \
         patch.object(cli, "_teardown_local_mounts"), \
         patch.object(cli, "_resolve_case_question", return_value="What happened?"), \
         patch("agent.prompts.build_system_prompt", return_value="sys"), \
         patch("agent.prompts.initial_user_message", _user_message), \
         patch("core.paths.register_answer_keys"), \
         patch("core.brain.answer_key.has_ground_truth", return_value=False), \
         pytest.raises(KeyboardInterrupt):
        cli._run_investigation(args, case, command="run")
    assert seen["plane_trace"].endswith("CASE-X_trace.json")
    assert seen["told"] == "CASE-X"
    objective = json.loads((case / ".atlas" / "run_objective.json").read_text(encoding="utf-8"))
    assert objective["trace_path"].endswith("CASE-X_trace.json")
    assert not (case / "analysis" / "CASE-A_trace.json").exists()


# ── a short withdrawal reason ────────────────────────────────────────────────

def test_a_short_withdrawal_reason_is_told_the_rule(tmp_path):
    from core import threat_context as tc
    with pytest.raises(tc.IntelError) as raised:
        tc.withdraw(tmp_path, ids=["x"], reason="x")
    assert "at least 4 characters" in str(raised.value)


# ── interactive takes the run flags ──────────────────────────────────────────

def test_interactive_takes_every_run_flag_but_the_machine_ones():
    from agent import cli
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")

    def flags(name):
        return {o for a in sub.choices[name]._actions for o in a.option_strings}

    assert flags("run") - flags("interactive") == {"--quiet", "--json", "--interactive"}
    assert flags("interactive") - flags("run") == set()
    ns = parser.parse_args(["interactive", "--no-brain", "-L", "de"])
    assert ns.no_brain is True and ns.language == "de"
