"""Interactive dialogue mode: the agent may consult the human analyst via the
atlas_ask_analyst meta-tool, and degrades to autonomous work when unattended."""
import pytest

pytest.importorskip("rich")
from agent.loop import Agent  # noqa: E402
from agent.tui import UI  # noqa: E402


def _agent(interactive: bool, ui=None) -> Agent:
    # client/toolbox are unused by the meta-tool path, so stubs are fine.
    return Agent(client=None, toolbox=None, case_dir=None,
                 ui=ui or UI(quiet=True), interactive=interactive)


class TestAskAnalystMetaTool:
    def test_declared_in_meta_tools(self):
        from agent.toolbox import META_TOOLS
        names = {m["function"]["name"] for m in META_TOOLS}
        assert "atlas_ask_analyst" in names

    def test_autonomous_run_returns_proceed_note(self):
        a = _agent(interactive=False)
        out = a._handle_meta("atlas_ask_analyst", {"question": "which host?"})
        assert "interactive mode is off" in out.lower()
        assert "autonomously" in out.lower()

    def test_interactive_prompts_and_returns_guidance(self, monkeypatch):
        ui = UI(quiet=True)
        seen = {}

        def fake_ask(q, c, o):
            seen.update(question=q, context=c, options=o)
            return "focus on host A"

        monkeypatch.setattr(ui, "ask_analyst", fake_ask)
        a = _agent(interactive=True, ui=ui)
        out = a._handle_meta(
            "atlas_ask_analyst",
            {"question": "which host?", "context": "two candidates",
             "options": ["A", "B"]})
        assert out == "[analyst guidance] focus on host A"
        assert seen["question"] == "which host?"
        assert seen["options"] == ["A", "B"]

    def test_interactive_no_answer_falls_back_to_autonomous(self, monkeypatch):
        ui = UI(quiet=True)
        monkeypatch.setattr(ui, "ask_analyst", lambda q, c, o: "")
        a = _agent(interactive=True, ui=ui)
        out = a._handle_meta("atlas_ask_analyst", {"question": "?"})
        assert "did not respond" in out.lower()

    def test_other_meta_tools_unaffected(self):
        a = _agent(interactive=False)
        assert a._handle_meta("definitely_not_meta", {}) is None


class TestInteractiveSystemPrompt:
    def test_note_present_only_when_interactive(self):
        from agent.prompts import build_system_prompt
        assert "INTERACTIVE MODE" not in build_system_prompt(None, interactive=False)
        assert "INTERACTIVE MODE" in build_system_prompt(None, interactive=True)


class TestAskAnalystUI:
    def test_returns_empty_without_tty(self):
        # Under pytest stdin is not a TTY → the prompt must never block.
        assert UI(quiet=True).ask_analyst("who?") == ""


class TestCliWiring:
    def test_interactive_subcommand_dispatches(self):
        import agent.cli as cli
        ns = cli.build_parser().parse_args(["interactive", "-q", "x"])
        assert ns.func is cli.cmd_interactive

    def test_run_has_interactive_flag(self):
        import agent.cli as cli
        ns = cli.build_parser().parse_args(["run", "-q", "x", "--interactive"])
        assert ns.interactive is True

    def test_run_interactive_defaults_off(self):
        import agent.cli as cli
        ns = cli.build_parser().parse_args(["run", "-q", "x"])
        assert ns.interactive is False
