"""Per-turn LLM deadline and the optional run wall clock.

Retries and 429 waits can stack to tens of minutes per turn, and nothing
above them bounds the run. agent.llm enforces a per-turn time budget
(LLMDeadlineError) and agent.loop backs it with an optional wall clock that
reuses the graceful wrap-up path instead of hard-killing the run.
"""
import httpx
import pytest

from agent import loop as loop_mod
from agent.llm import (ChatResponse, LLMDeadlineError, LLMHubClient,
                       ToolCall)
from agent.loop import Agent


class _StubToolbox:
    def openai_tools(self):
        return []

    def namespace_summary(self):
        return ""


class _ScriptedClient:
    """Yields the given responses in order; an Exception instance is raised
    instead of returned."""
    model = "fake-model"
    base_url = "http://fake"
    total_input_tokens = 0
    total_output_tokens = 0

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def chat(self, messages, tools=None):
        self.calls += 1
        item = self.script.pop(0) if self.script else self.script_default()
        if isinstance(item, Exception):
            raise item
        return item

    @staticmethod
    def script_default():
        return ChatResponse(content="nothing more to add")


def _finish_response():
    return ChatResponse(content="", tool_calls=[
        ToolCall(id="1", name="atlas_finish", arguments={"summary": "done"})])


def _agent(client):
    return Agent(client, _StubToolbox(), case_dir=None, quiet=True)


def _wrapup_messages(agent):
    return [m for m in agent.messages
            if m.get("role") == "user"
            and "[budget wrap-up]" in str(m.get("content"))]


class TestWallClock:
    def test_expiry_injects_wrapup_before_the_turn(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 1e-9)
        monkeypatch.setattr(loop_mod, "WALL_GRACE_SECONDS", 3600.0)
        client = _ScriptedClient([_finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")
        assert len(_wrapup_messages(agent)) == 1
        assert agent.stats["stopped_reason"] == "finished"

    def test_grace_exhausted_stops_the_run(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 1e-9)
        monkeypatch.setattr(loop_mod, "WALL_GRACE_SECONDS", 0.0)
        # The model never finishes — the hard deadline must end the run.
        client = _ScriptedClient([])
        agent = _agent(client)
        agent.run("sys", "user")
        assert agent.stats["stopped_reason"] == "wall_clock"
        assert client.calls == 1  # one turn ran, the second was cut off

    def test_disabled_by_zero(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        client = _ScriptedClient([_finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")
        assert _wrapup_messages(agent) == []
        assert agent.stats["stopped_reason"] == "finished"


class TestDeadlineRouting:
    def test_deadline_error_routes_to_wrapup_not_crash(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        client = _ScriptedClient([LLMDeadlineError("budget out"),
                                  _finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")  # must not raise
        assert len(_wrapup_messages(agent)) == 1
        assert agent.stats["stopped_reason"] == "finished"

    def test_second_deadline_after_wrapup_stops_the_run(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        client = _ScriptedClient([LLMDeadlineError("one"),
                                  LLMDeadlineError("two")])
        agent = _agent(client)
        agent.run("sys", "user")
        assert agent.stats["stopped_reason"] == "llm_deadline"


class TestBlockerExtension:
    def test_extends_when_pre_report_blocking(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 2)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 2)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 150)

        class _BlockingAgent(Agent):
            def _pre_report_blocking(self):
                return True

            def _report_written(self):
                return False

        client = _ScriptedClient([
            ChatResponse(content="working"),
            ChatResponse(content="still"),
            _finish_response(),
            _finish_response(),
            _finish_response(),
        ])
        agent = _BlockingAgent(client, _StubToolbox(), case_dir=None,
                               quiet=True)
        agent.run("sys", "user")
        msgs = [m for m in agent.messages
                if m.get("role") == "user"
                and "[blocker extension]" in str(m.get("content"))]
        assert len(msgs) >= 1
        assert agent.stats["stopped_reason"] == "finished"
        assert agent.stats["turns"] > 2

    def test_extends_repeatedly_up_to_max_when_blockers_change(self, monkeypatch):
        """Budget max still applies when Layer-3 identity advances each grant."""
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 1)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 1)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 3)

        fps = iter(["fp-a", "fp-b", "fp-c", "fp-d", "fp-e"])
        monkeypatch.setattr(
            "core.investigation_exit.blocker_fingerprint",
            lambda conclusion="": next(fps, "fp-z"),
        )

        class _BlockingAgent(Agent):
            def _pre_report_blocking(self):
                return True

            def _report_written(self):
                return False

        client = _ScriptedClient([
            ChatResponse(content="t1"),
            ChatResponse(content="t2"),
            ChatResponse(content="t3"),
            ChatResponse(content="t4"),
            ChatResponse(content="t5"),
            ChatResponse(content="t6"),
            ChatResponse(content="t7"),
            ChatResponse(content="t8"),
        ])
        agent = _BlockingAgent(client, _StubToolbox(), case_dir=None,
                               quiet=True)
        agent.run("sys", "user")
        msgs = [m for m in agent.messages
                if m.get("role") == "user"
                and "[blocker extension]" in str(m.get("content"))
                and "denied" not in str(m.get("content"))]
        assert len(msgs) == 3  # 1+1+1 up to max 3
        assert agent.stats["stopped_reason"] in ("quiet", "turn_cap")
        assert agent.stats["turns"] >= 4

    def test_denies_identical_blocker_without_progress(self, monkeypatch):
        """Layer 3: same READY_TO_REPORT:false fingerprint → no re-extension."""
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 1)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 1)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 150)
        monkeypatch.setattr(
            "core.investigation_exit.blocker_fingerprint",
            lambda conclusion="": "same-fp",
        )
        monkeypatch.setattr(
            "core.investigation_exit.knowledge_progressed_since_call_id",
            lambda since: False,
        )

        class _BlockingAgent(Agent):
            def _pre_report_blocking(self):
                return True

            def _report_written(self):
                return False

        client = _ScriptedClient([
            ChatResponse(content="t1"),
            ChatResponse(content="t2"),
            ChatResponse(content="t3"),
            ChatResponse(content="t4"),
            ChatResponse(content="t5"),
        ])
        agent = _BlockingAgent(client, _StubToolbox(), case_dir=None,
                               quiet=True)
        agent.run("sys", "user")
        granted = [m for m in agent.messages
                   if m.get("role") == "user"
                   and "[blocker extension]" in str(m.get("content"))
                   and "denied" not in str(m.get("content"))]
        denied = [m for m in agent.messages
                  if m.get("role") == "user"
                  and "[blocker extension denied]" in str(m.get("content"))]
        assert len(granted) == 1
        assert len(denied) >= 1

    def test_no_extension_without_blockers(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 2)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 40)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 150)

        class _ReadyAgent(Agent):
            def _pre_report_blocking(self):
                return False

            def _report_written(self):
                return False

        client = _ScriptedClient([
            ChatResponse(content="a"),
            ChatResponse(content="b"),
            ChatResponse(content="c"),
            ChatResponse(content="d"),
        ])
        agent = _ReadyAgent(client, _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        msgs = [m for m in agent.messages
                if m.get("role") == "user"
                and "[blocker extension]" in str(m.get("content"))]
        assert msgs == []
        assert agent.stats["stopped_reason"] in ("quiet", "turn_cap")
        assert agent.stats["turns"] <= 2


class TestToolFailureInvestigate:
    def test_atlas_finish_refused_while_investigate_debt(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 5)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)

        class _DebtAgent(Agent):
            def _run_tool(self, tc):
                return (
                    '{"success": false, "incomplete": true, '
                    '"gate": "scan_timeout", "error": "timed out"}'
                )

            def _critical_scan_debt(self):
                return []

        client = _ScriptedClient([
            ChatResponse(content="", tool_calls=[
                ToolCall(id="1", name="misc_evtx_filter",
                         arguments={"path": "/x.evtx"})]),
            # After latch, try to finish — must be refused
            _finish_response(),
            # Clear via dair_assess then finish
            ChatResponse(content="", tool_calls=[
                ToolCall(id="2", name="dair_dair_assess",
                         arguments={"phase": "Collect"})]),
            _finish_response(),
        ])
        # dair_assess goes through _run_tool which we stubbed as timeout —
        # override to succeed for assess.
        agent = _DebtAgent(client, _StubToolbox(), case_dir=None, quiet=True)
        orig = agent._run_tool

        def _run(tc):
            if "dair_assess" in tc.name:
                return '{"success": true, "phase": "Collect"}'
            return orig(tc)

        agent._run_tool = _run
        agent.run("sys", "user")
        refused = [m for m in agent.messages
                   if m.get("role") == "tool"
                   and "atlas_finish refused" in str(m.get("content"))]
        assert refused, "expected atlas_finish refusal while debt open"
        assert agent.stats["stopped_reason"] == "finished"
        inv = [m for m in agent.messages
               if m.get("role") == "user"
               and "[tool-failure investigate]" in str(m.get("content"))]
        assert inv


class TestWrapupMessage:
    def test_wrapup_forbids_partial_retry(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 3)
        monkeypatch.setattr(loop_mod, "WRAPUP_MARGIN", 3)
        client = _ScriptedClient([_finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")
        msgs = _wrapup_messages(agent)
        assert len(msgs) == 1
        text = msgs[0]["content"]
        assert "partial report" in text.lower() or "Do NOT write a partial" in text
        assert "second attempt" not in text.lower()
        assert "blocking_issue" in text


class TestTurnTimeBudget:
    def test_exhausted_budget_raises_deadline_error(self, monkeypatch):
        def _refuse(*args, **kwargs):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx, "post", _refuse)
        client = LLMHubClient(base_url="http://localhost:1", api_key="k",
                              model="m")
        client.turn_time_budget = 0.05
        with pytest.raises(LLMDeadlineError):
            client.chat([{"role": "user", "content": "hi"}])

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_TURN_TIME_BUDGET", "42")
        client = LLMHubClient(base_url="http://x", api_key="k", model="m")
        assert client.turn_time_budget == 42.0


class TestBudgetWrapupTraceMarker:
    """The report gate reads the MCP execution trace, not this JSONL log, so
    the loop mirrors budget wrap-up into the trace with a typed marker the gate
    keys off to relax content-quality blockers (P4 report-gate deadlock)."""

    def test_wrapup_is_stamped_into_the_execution_trace(self, monkeypatch,
                                                        tmp_path):
        from core.execution_log import ExecutionLog
        cfg = ExecutionLog()
        cfg.configure("LOOP-WRAPUP", str(tmp_path / "trace.json"))
        monkeypatch.setattr("core.execution_log.log", cfg)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 1e-9)
        monkeypatch.setattr(loop_mod, "WALL_GRACE_SECONDS", 3600.0)
        agent = _agent(_ScriptedClient([_finish_response()]))
        agent.run("sys", "user")
        assert any(e.get("type") == "budget_wrapup" for e in cfg._entries)

    def test_marker_helper_never_raises_when_log_unconfigured(self):
        # Best-effort: a wrap-up injected before start_execution_log (or in a
        # non-run context) must not take down the loop.
        agent = _agent(_ScriptedClient([_finish_response()]))
        agent._record_budget_wrapup_marker("turn_budget", 7)  # no exception


def _reengage_messages(agent):
    return [m for m in agent.messages
            if m.get("role") == "user"
            and "[dair reengage]" in str(m.get("content"))]


def _quiet_script(n):
    return [ChatResponse(content=f"narrate-{i}") for i in range(n)]


class TestDairReengageOnQuiet:
    """A DAIR window that aged out while the model announced dair_assess in
    prose must not let the quiet valve end the run. Nudge only when deferred
    intents are actually open — genuine quiet (no intents) must stay unchanged."""

    def test_pending_false_when_log_raises(self):
        agent = _agent(_ScriptedClient([]))
        assert agent._dair_reengage_pending() is False

    def test_pending_true_when_open_intents(self, tmp_path, monkeypatch):
        from core.execution_log import ExecutionLog
        cfg = ExecutionLog()
        cfg.configure("DAIR-REENGAGE", str(tmp_path / "trace.json"))
        cfg.record_deferred_intent(
            "search_search_evidence", {"query": "x"},
            blocked_reason="no dair_call in recent window")
        monkeypatch.setattr("core.execution_log.log", cfg)
        agent = _agent(_ScriptedClient([]))
        assert agent._dair_reengage_pending() is True

    def test_genuine_quiet_does_not_inject_reengage(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)

        class _Ready(Agent):
            def _dair_reengage_pending(self):
                return False

            def _report_written(self):
                return False

        agent = _Ready(_ScriptedClient(_quiet_script(8)), _StubToolbox(),
                       case_dir=None, quiet=True)
        agent.run("sys", "user")
        assert _reengage_messages(agent) == []
        assert agent.stats["stopped_reason"] == "quiet"
        assert agent.stats["turns"] <= 4

    def test_open_intents_nudge_before_quiet_death(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        monkeypatch.setattr(loop_mod, "DAIR_REENGAGE_MAX", 2)

        class _Stuck(Agent):
            def _dair_reengage_pending(self):
                return True

            def _report_written(self):
                return False

        agent = _Stuck(_ScriptedClient(_quiet_script(12)), _StubToolbox(),
                       case_dir=None, quiet=True)
        agent.run("sys", "user")
        nudges = _reengage_messages(agent)
        assert len(nudges) == 2
        first_nudge = next(
            i for i, m in enumerate(agent.messages)
            if m.get("role") == "user"
            and "[dair reengage]" in str(m.get("content")))
        first_wrap = next(
            (i for i, m in enumerate(agent.messages)
             if m.get("role") == "user"
             and "[budget wrap-up]" in str(m.get("content"))),
            None)
        assert first_wrap is not None
        assert first_nudge < first_wrap
        # Was "quiet" when this test landed; stopping while the DAIR gate is
        # still holding forensic tools is now labelled "stall" so the
        # operator can tell it apart from a model that simply had nothing
        # left to do (see TestStallAwareQuietPath). The coverage verdict is
        # unchanged — classify_finish_status treats both the same.
        assert agent.stats["stopped_reason"] == "stall"
        assert agent.stats["turns"] > 4

    def test_tool_call_after_nudge_clears_budget(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        monkeypatch.setattr(loop_mod, "DAIR_REENGAGE_MAX", 2)

        class _Recovers(Agent):
            def _dair_reengage_pending(self):
                return True

            def _report_written(self):
                return False

            def _run_tool(self, tc):
                return "ok"

        # Two prose turns → nudge; then dair_assess; then finish.
        client = _ScriptedClient([
            ChatResponse(content="let me call dair_assess"),
            ChatResponse(content="let me call dair_assess"),
            ChatResponse(content="", tool_calls=[
                ToolCall(id="d1", name="dair_dair_assess", arguments={})]),
            _finish_response(),
        ])
        agent = _Recovers(client, _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        assert len(_reengage_messages(agent)) == 1
        assert agent.stats["stopped_reason"] == "finished"


def _continue_messages(agent):
    """The generic 'you went quiet, keep going' nudge (quiet_turns == 1)."""
    return [m for m in agent.messages
            if m.get("role") == "user"
            and "Continue the investigation" in str(m.get("content"))]


class _StalledAgent(Agent):
    """Deferred intents are open — the DAIR window is cold."""

    def _dair_reengage_pending(self):
        return True

    def _report_written(self):
        return False


class _DoneAgent(Agent):
    """Nothing blocked: a genuine 'model has nothing left' quiet turn."""

    def _dair_reengage_pending(self):
        return False

    def _report_written(self):
        return False


def _quiet_run(agent_cls, script, monkeypatch, **kwargs):
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
    monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
    monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
    monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
    agent = agent_cls(_ScriptedClient(script), _StubToolbox(),
                      case_dir=None, quiet=True, **kwargs)
    agent.run("sys", "user")
    return agent


class TestStallAwareQuietPath:
    """A protocol stall (forensic tools blocked on a cold DAIR window) is not
    'the model is done': the first quiet turn must not tell it to write the
    report, the stop must not be labelled 'quiet', and an empty-tool turn
    must record what the model actually returned."""

    def test_first_quiet_turn_names_the_blocker(self, monkeypatch):
        """C1: the very first 'why are you quiet' nudge must demand
        dair_assess while forensic tools are blocked — steering toward the
        report burns the turn on work the model is not allowed to do."""
        agent = _quiet_run(_StalledAgent, _quiet_script(8), monkeypatch)
        first_user_nudge = next(
            m for m in agent.messages[2:] if m.get("role") == "user")
        assert "dair_assess" in str(first_user_nudge.get("content"))

    def test_generic_quiet_keeps_the_plain_continue_message(self, monkeypatch):
        """Guard: with nothing blocked, the pre-existing continue nudge is
        unchanged — a genuinely finished model must not be told to call
        dair_assess."""
        agent = _quiet_run(_DoneAgent, _quiet_script(8), monkeypatch)
        assert _continue_messages(agent)
        for m in _continue_messages(agent):
            assert "dair_assess" not in str(m.get("content"))

    def test_narrated_call_triggers_reengage_without_open_intents(
            self, monkeypatch):
        """A3: the model announcing dair_assess in prose while emitting no
        tool call is itself the stall signal — it fires even before a
        blocked tool has recorded a deferred intent."""
        script = [ChatResponse(content="DAIR window expired again. "
                                       "Let me call dair_assess to refresh it.")
                  for _ in range(8)]
        agent = _quiet_run(_DoneAgent, script, monkeypatch)
        assert _reengage_messages(agent)

    def test_unrelated_prose_does_not_trigger_reengage(self, monkeypatch):
        """Guard for A3's regex: ordinary narration must not be mistaken
        for a narrated dair_assess call."""
        script = [ChatResponse(content="The timeline is assembled and the "
                                       "report covers every host.")
                  for _ in range(8)]
        agent = _quiet_run(_DoneAgent, script, monkeypatch)
        assert _reengage_messages(agent) == []

    def test_stop_is_labelled_stall_when_dair_still_pending(self, monkeypatch):
        """B2: stopping with forensic work still gated is not 'no progress
        detected' — the operator needs to see it was a protocol stall."""
        agent = _quiet_run(_StalledAgent, _quiet_script(12), monkeypatch)
        assert agent.stats["stopped_reason"] == "stall"

    def test_genuine_quiet_still_reports_quiet(self, monkeypatch):
        """Guard: nothing pending → the existing 'quiet' label is kept."""
        agent = _quiet_run(_DoneAgent, _quiet_script(8), monkeypatch)
        assert agent.stats["stopped_reason"] == "quiet"

    def test_quiet_wrapup_names_the_blocker(self, monkeypatch):
        """C1: even the close-out wrap-up must say what is actually
        blocking — while keeping the close-out steps, so a hard stop can
        still produce a report."""
        agent = _quiet_run(_StalledAgent, _quiet_script(12), monkeypatch)
        wrapups = _wrapup_messages(agent)
        assert wrapups
        assert "dair_assess" in str(wrapups[0].get("content"))

    def test_empty_tool_turn_logs_the_raw_message(self, monkeypatch):
        """E1: an empty-tool turn must leave the provider's raw message in
        the transcript — otherwise 'narrated the call' and 'the parser
        dropped the call' are indistinguishable after the fact."""

        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

        raw = {"role": "assistant", "content": "",
               "reasoning": "I should call dair_assess now"}
        script = [ChatResponse(content="", raw_message=raw) for _ in range(8)]
        agent = _quiet_run(_Capturing, script, monkeypatch)
        empty_turns = [r for r in agent.logged
                       if r.get("event") == "assistant" and not r.get("tool_calls")]
        assert empty_turns
        assert any("dair_assess" in str(r.get("raw_message") or "")
                   for r in empty_turns)

    def test_raw_message_is_capped(self, monkeypatch):
        """The transcript is appended every turn — a reasoning dump must
        not be able to balloon it."""

        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

        raw = {"role": "assistant", "content": "", "reasoning": "x" * 50_000}
        script = [ChatResponse(content="", raw_message=raw) for _ in range(8)]
        agent = _quiet_run(_Capturing, script, monkeypatch)
        for r in agent.logged:
            assert len(str(r.get("raw_message") or "")) <= 2_100


class TestCutOffRunTotal:
    """A cut-off spends no rescue and no quiet turn, and its consecutive
    count resets on a real call. A model that alternates between running
    away and calling must not keep that pass for the whole run, or nothing
    ever converges on an exit."""

    class _Capturing(_DoneAgent):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.logged = []

        def _log(self, record):
            self.logged.append(record)

    def test_alternating_cut_offs_stop_being_free(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "CUT_OFF_TOTAL_MAX", 3)
        cut = ChatResponse(content="still thinking", finish_reason="length",
                           output_tokens=8192)
        call = ChatResponse(content="", tool_calls=[
            ToolCall(id="n", name="atlas_list_namespaces", arguments={})])
        agent = _quiet_run(self._Capturing, [cut, call] * 10, monkeypatch)
        cut_events = [r for r in agent.logged if r.get("event") == "reply_cut_off"]
        # The consecutive counter alone would nudge on every one of the ten.
        assert len(cut_events) == 3
        assert [r.get("run_total") for r in cut_events] == [1, 2, 3]

    def test_a_run_below_the_total_is_untouched(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "CUT_OFF_TOTAL_MAX", 12)
        cut = ChatResponse(content="still thinking", finish_reason="length",
                           output_tokens=8192)
        call = ChatResponse(content="", tool_calls=[
            ToolCall(id="n", name="atlas_list_namespaces", arguments={})])
        finish = ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "done"})])
        agent = _quiet_run(self._Capturing, [cut, call, cut, call, finish],
                           monkeypatch)
        cut_events = [r for r in agent.logged if r.get("event") == "reply_cut_off"]
        assert len(cut_events) == 2
        assert agent.stats["stopped_reason"] == "finished"


class TestReplyCutOffByLength:
    """A reply that hits the output-length limit before any call is a
    cut-off, not a stall: it gets its own nudge and spends no rescue."""

    def test_cut_off_reply_is_nudged_and_the_run_goes_on(self, monkeypatch):
        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

        script = [
            ChatResponse(content="Let me analyze carefully:\n1. atlas_load_namespaces (load vol)\n2. then",
                         finish_reason="length", output_tokens=8192),
            ChatResponse(content="", tool_calls=[
                ToolCall(id="f1", name="atlas_finish",
                         arguments={"summary": "done"})]),
        ]
        agent = _quiet_run(_Capturing, script, monkeypatch)
        events = [r.get("event") for r in agent.logged]
        assert "reply_cut_off" in events
        assert "intent_without_call" not in events
        assert any("cut off" in str(m.get("content"))
                   for m in agent.messages if m.get("role") == "user")
        assert agent.stats["stopped_reason"] == "finished"


class TestTheTranscriptKeepsTheRefusalDistinction:
    """A tool that broke and a call refused for its own shape are different
    events: the second ran nothing and damaged nothing. The run separates
    them for its live counters, and the transcript — the record that outlives
    the run — carried neither, so a reader of a finished case saw one error
    rate in the trace and another in the transcript."""

    def _agent(self, stats):
        from agent.loop import Agent
        a = Agent.__new__(Agent)
        a._tool_stats = stats
        return a

    def test_a_refusal_is_marked_as_one(self):
        a = self._agent([{"name": "misc_record_finding", "error": True,
                          "refusal": True}])
        assert a._last_tool_flags("misc_record_finding") == {
            "error": True, "refusal": True}

    def test_a_real_failure_is_not_marked_a_refusal(self):
        a = self._agent([{"name": "tsk_fls", "error": True, "refusal": False}])
        assert a._last_tool_flags("tsk_fls") == {"error": True,
                                                 "refusal": False}

    def test_a_clean_call_carries_both_as_false(self):
        a = self._agent([{"name": "tsk_fls", "error": False,
                          "refusal": False}])
        assert a._last_tool_flags("tsk_fls") == {"error": False,
                                                 "refusal": False}

    def test_another_call_s_flags_are_never_borrowed(self):
        """The stats entry is matched by name, so a path that logs without
        having executed through _run_tool reports nothing rather than the
        previous call's verdict."""
        a = self._agent([{"name": "tsk_fls", "error": True, "refusal": True}])
        assert a._last_tool_flags("strings_grep") == {}

    def test_no_stats_yet_is_not_an_error(self):
        assert self._agent([])._last_tool_flags("tsk_fls") == {}


class TestRunLoopPseudoToolRecovery:
    """`Agent.run()` only ever read `resp.tool_calls`. A model that wrote the
    call as text (<tool_call>…</tool_call>) was treated as a quiet turn and
    the investigation died — even though `run_chat_turn` has recovered
    exactly that shape for chat all along."""

    def test_run_executes_a_pseudo_tool_call(self, monkeypatch):
        executed = []

        class _Recovering(_DoneAgent):
            def _run_tool(self, tc):
                executed.append(tc.name)
                return '{"success": true}'

        script = [
            ChatResponse(content="<tool_call>dair_dair_assess()</tool_call>"),
            ChatResponse(content="", tool_calls=[
                ToolCall(id="f1", name="atlas_finish",
                         arguments={"summary": "done"})]),
        ]
        agent = _quiet_run(_Recovering, script, monkeypatch)
        assert "dair_dair_assess" in executed
        assert agent.stats["stopped_reason"] == "finished"

    def test_a_clean_retry_releases_the_failure_latch(self, monkeypatch):
        """The latch asks for a corrected retry. Once that retry runs clean
        the failure is answered, and the latch must stop replaying it: a
        model told every turn to fix what it has fixed answers in prose,
        and prose without a call is counted as quiet until the run ends."""
        events = []
        results = iter(["TOOL ERROR: bad arguments", '{"success": true}'])

        class _Retrying(_DoneAgent):
            def _run_tool(self, tc):
                return next(results)

            def _log(self, record):
                events.append(record)

        script = [
            ChatResponse(content="<tool_call>ns_tool()</tool_call>"),
            ChatResponse(content='<tool_call>ns_tool(x="1")</tool_call>'),
            _finish_response(),
        ]
        _quiet_run(_Retrying, script, monkeypatch)
        fired = [e["turn"] for e in events
                 if e.get("event") == "tool_failure_investigate"]
        assert fired == [2], fired

    def test_a_text_call_with_a_wide_tool_list_shrinks_the_list_and_retries(self, monkeypatch):
        """No function call arrived although the model wrote one into the
        text: the tool list is the suspect. It is cut by a fifth, coldest
        namespaces first and never below the core, the turn is asked again,
        and the size that answered is remembered for the model."""
        import agent.toolbox as toolbox_mod
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", None)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)

        class _WideToolbox(_StubToolbox):
            sizes = {"misc": 40, "img": 30, "tsk": 30}

            def __init__(self):
                self.loaded = {"misc", "img", "tsk"}
                self.evicted = []

            def schema_count(self, loaded=None):
                ns = self.loaded if loaded is None else loaded
                return 4 + sum(self.sizes[n] for n in ns if n in self.sizes)

            def shrink_to(self, count):
                for ns in ("tsk", "img"):
                    if self.schema_count() <= count:
                        break
                    self.loaded.discard(ns)
                    self.evicted.append(ns)
                return list(self.evicted)

        class _Learning(_ScriptedClient):
            learned = []

            def learn_max_tools(self, count):
                self.learned.append(count)

        events = []

        class _Wide(_DoneAgent):
            def _log(self, record):
                events.append(record)

            def _run_tool(self, tc):
                return '{"success": true}'

        tried = ChatResponse(content="<tool_call>misc:tool()", output_tokens=40,
                             reasoning_tokens=10)
        # One reply that writes the call as text is what a first turn
        # often does with any list; the second at the same size is the
        # pattern that cuts it.
        script = [tried, tried, _finish_response()]
        client = _Learning(script)
        toolbox = _WideToolbox()
        agent = _Wide(client, toolbox, case_dir=None, quiet=True)
        agent.run("sys", "user")
        shrunk = [e for e in events if e.get("event") == "tool_budget_shrunk"]
        assert [(e["sent"], e["kept"], e["evicted"]) for e in shrunk] == [(104, 74, ["tsk"])]
        # Remembered only once a function call arrived at the cut size: the
        # finish call is that proof.
        assert client.learned == [74]
        assert [e["max_tools"] for e in events if e.get("event") == "tool_budget_learned"] == [74]
        assert toolbox.loaded == {"misc", "img"}
        assert agent.stats["stopped_reason"] == "finished"

        # A cut that no function call ever confirms is not remembered.
        events.clear()
        toolbox = _WideToolbox()
        client = _Learning([tried, tried])
        client.learned = []
        _Wide(client, toolbox, case_dir=None, quiet=True).run("sys", "user")
        assert [e["kept"] for e in events if e.get("event") == "tool_budget_shrunk"] == [74]
        assert client.learned == []

        # A failure at a size that already delivered a function call in this
        # run is not the list's fault: nothing is cut and nothing learned.
        events.clear()
        toolbox = _WideToolbox()
        client = _Learning([
            ChatResponse(content="", tool_calls=[
                ToolCall(id="1", name="misc_tool", arguments={})]),
            ChatResponse(content="<tool_call>misc:tool()", output_tokens=40,
                         reasoning_tokens=10),
            _finish_response(),
        ])
        client.learned = []

        class _Executing(_Wide):
            def _run_tool(self, tc):
                return '{"success": true}'

        _Executing(client, toolbox, case_dir=None, quiet=True).run("sys", "user")
        assert [e for e in events if e.get("event") == "tool_budget_shrunk"] == []
        assert client.learned == [] and toolbox.loaded == {"misc", "img", "tsk"}

    def test_a_swallowed_call_is_not_resent_unchanged(self, monkeypatch):
        """An empty reply whose completion count exceeds its reasoning count
        is a dropped call; resending the identical request only repeats the
        drop. A reasoning pass that produced nothing is still retried once."""
        swallowed = ChatResponse(content="", output_tokens=40, reasoning_tokens=10)
        starved = ChatResponse(content="", output_tokens=40, reasoning_tokens=40)
        agent = _quiet_run(_DoneAgent, [swallowed, _finish_response()], monkeypatch)
        assert agent.client.calls == 2
        agent = _quiet_run(_DoneAgent, [starved, starved, _finish_response()], monkeypatch)
        assert agent.client.calls == 3

    def test_a_reply_with_too_many_calls_runs_the_first_ones_and_hands_back_the_rest(self, monkeypatch):
        """One reply of hundreds of calls, run one by one, holds a run for
        hours. The first CALLS_PER_TURN_MAX run; the rest are handed back
        with a note, and the model resends what it still needs."""
        monkeypatch.setattr(loop_mod, "CALLS_PER_TURN_MAX", 5)
        ran = []
        events = []

        class _Counting(_DoneAgent):
            def _run_tool(self, tc):
                ran.append(tc.name)
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        wide = ChatResponse(content="", tool_calls=[
            ToolCall(id=f"c{i}", name="misc_tool", arguments={"i": i}) for i in range(9)])
        agent = _quiet_run(_Counting, [wide, _finish_response()], monkeypatch)
        assert len(ran) == 5
        bounded = [e for e in events if e.get("event") == "batch_bounded"]
        assert [(e["sent"], e["ran"], e["left"]) for e in bounded] == [(9, 5, 4)]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[batch bounded]" in str(m.get("content"))]
        assert len(notes) == 1 and "9 tool calls" in notes[0]["content"]

    def test_a_reply_many_times_over_the_cap_is_logged_as_a_runaway_and_told_so(self, monkeypatch):
        """A reply a little over the cap gets the plain hand-back note. One
        carrying many times the cap is a runaway: still bounded the same
        way, but logged as its own event and told that the unrun calls were
        discarded and that a repeated near-identical call is not progress,
        so the next reply is short."""
        monkeypatch.setattr(loop_mod, "CALLS_PER_TURN_MAX", 5)
        ran = []
        events = []

        class _Counting(_DoneAgent):
            def _run_tool(self, tc):
                ran.append(tc.name)
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        def _wide(n, batch):
            # Distinct arguments per batch: a call repeated as written is
            # answered from memory upstream of _run_tool.
            return ChatResponse(content="", tool_calls=[
                ToolCall(id=f"c{batch}-{i}", name="misc_tool",
                         arguments={"i": i, "batch": batch})
                for i in range(n)])

        runaway_at = loop_mod.BATCH_RUNAWAY_FACTOR * 5
        agent = _quiet_run(
            _Counting,
            [_wide(runaway_at - 1, 1), _wide(runaway_at, 2), _finish_response()],
            monkeypatch)
        assert len(ran) == 10, "the cap runs the same number either way"
        bounded = [e["sent"] for e in events if e.get("event") == "batch_bounded"]
        assert bounded == [runaway_at - 1, runaway_at]
        runaway = [e for e in events if e.get("event") == "batch_runaway"]
        assert [(e["sent"], e["cap"], e["distinct_tools"], e["tools"])
                for e in runaway] == [(runaway_at, 5, 1, ["misc_tool"])]
        notes = [m["content"] for m in agent.messages if m.get("role") == "user"
                 and "[batch bounded]" in str(m.get("content"))]
        assert len(notes) == 2
        assert "discarded" not in notes[0]
        assert "discarded, not queued" in notes[1]
        assert "at most 5 calls" in notes[1]

    def test_the_directors_prescriptions_are_loaded_before_the_next_turn(self, monkeypatch):
        """A call to a tool outside the loaded namespaces never arrives at a
        gateway that checks names, so what the director prescribes is
        brought into the list right after it prescribes it."""
        import json as _json
        from types import SimpleNamespace
        events = []
        loads = []

        class _Box(_StubToolbox):
            def __init__(self):
                self.loaded = {"table"}
                self.namespaces = ["img", "table", "tsk"]
                self.control_names = frozenset({"dair_assess"})
                self.tools = {
                    "img_vmdk_chain_info": SimpleNamespace(namespace="img", listed="img_vmdk_chain_info"),
                    "table_table_query": SimpleNamespace(namespace="table", listed="table_query"),
                    "dair_dair_assess": SimpleNamespace(namespace="dair", listed="dair_assess"),
                }

            def resolve(self, name):
                return {"img.vmdk_chain_info": "img_vmdk_chain_info",
                        "table.table_query": "table_table_query",
                        "dair.dair_assess": "dair_dair_assess"}.get(name)

            def load_with_budget(self, namespaces, keep=()):
                loads.append((list(namespaces), sorted(keep)))
                self.loaded.update(namespaces)
                return {"newly_loaded": list(namespaces), "refused": [], "evicted": []}

        class _Directed(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"current_phase": "Collect", "directives": {
                    "priority_tools": ["img.vmdk_chain_info (all images)",
                                       "table.table_query (accepted rows)"]}})

            def _log(self, record):
                events.append(record)

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id="d1", name="dair_assess", arguments={})]), _finish_response()]
        box = _Box()
        _Directed(_ScriptedClient(script), box, case_dir=None, quiet=True).run("sys", "user")
        # img arrives; table, already loaded but named by the same order,
        # is protected from being the room made for img.
        assert loads == [(["img"], ["img", "table"])] and box.loaded == {"table", "img"}
        assert [e["loaded"] for e in events if e.get("event") == "namespaces_loaded_for_director"] == [["img"]]

    @staticmethod
    def _probing_box(loads):
        """A toolbox at a remembered ceiling of 45 whose only unloaded
        namespace, img, would take the list to 60: a work order naming it
        can only be served by testing the ceiling."""
        from types import SimpleNamespace

        class _Box(_StubToolbox):
            def __init__(self):
                self.loaded = {"table"}
                self.namespaces = ["img", "table"]
                self.control_names = frozenset({"dair_assess"})
                self.tools = {
                    "img_vmdk_chain_info": SimpleNamespace(namespace="img", listed="img_vmdk_chain_info"),
                    "dair_dair_assess": SimpleNamespace(namespace="dair", listed="dair_assess"),
                }
                self.tool_probe_limit = 0
                self.unloaded = []
                self._last_probe = None

            def resolve(self, name):
                return {"img.vmdk_chain_info": "img_vmdk_chain_info",
                        "dair.dair_assess": "dair_dair_assess"}.get(name)

            def schema_count(self, loaded=None):
                ns = self.loaded if loaded is None else loaded
                return 60 if "img" in ns else 45

            def load_with_budget(self, namespaces, keep=()):
                loads.append((list(namespaces), self.tool_probe_limit))
                if self.tool_probe_limit >= 60:
                    self.loaded.update(namespaces)
                    self._last_probe = {"namespace": "img", "count": 60, "floor": 45}
                    return {"newly_loaded": list(namespaces), "refused": [], "evicted": [],
                            "probed": dict(self._last_probe)}
                return {"newly_loaded": [], "evicted": [],
                        "refused": [{"namespace": "img", "would_be_total": 60, "max": 45}]}

            def pop_last_probe(self):
                probe, self._last_probe = self._last_probe, None
                return probe

            def unload(self, namespaces):
                self.unloaded.extend(namespaces)
                for ns in namespaces:
                    self.loaded.discard(ns)
                return list(namespaces)

        return _Box()

    def _probing_run(self, script, monkeypatch, events, loads, learned):
        import json as _json
        import agent.toolbox as toolbox_mod

        class _Directed(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"current_phase": "Collect", "directives": {
                    "priority_tools": ["img.vmdk_chain_info (all images)"]}})

            def _log(self, record):
                events.append(record)

        class _Learning(_ScriptedClient):
            def learn_max_tools(self, count):
                learned.append(count)

        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", 45)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        box = self._probing_box(loads)
        _Directed(_Learning(script), box, case_dir=None, quiet=True).run("sys", "user")
        return box

    def test_a_work_order_past_the_ceiling_tests_it_and_a_call_raises_it(self, monkeypatch):
        """A remembered ceiling may have come from a noisy reply. Once a
        call has arrived in this run, a work order that does not fit goes
        one namespace past the ceiling; a function call at that size is
        the evidence, and the size is remembered for the model."""
        import agent.toolbox as toolbox_mod
        events, loads, learned = [], [], []
        dair = ChatResponse(content="", tool_calls=[ToolCall(id="d1", name="dair_assess", arguments={})])
        work = ChatResponse(content="", tool_calls=[ToolCall(id="w1", name="img_vmdk_chain_info", arguments={})])
        self._probing_run([dair, work, _finish_response()], monkeypatch, events, loads, learned)
        assert loads == [(["img"], 128)]
        probes = [e for e in events if e.get("event") == "tool_budget_probe"]
        assert [(e["from"], e["to"], e["namespace"]) for e in probes] == [(45, 60, "img")]
        assert [e["max_tools"] for e in events if e.get("event") == "tool_budget_raised"] == [60]
        assert learned == [60]
        assert not [e for e in events if e.get("event") == "tool_budget_shrunk"]

    def test_a_probe_made_by_a_call_to_an_unloaded_tool_is_read_after_the_batch(self, monkeypatch):
        """The director is not the only loader: a call to a tool outside
        the list auto-loads its namespace, and the model loads namespaces
        itself. A probe any of them makes is adopted when the batch ends
        and the next reply decides it."""
        import agent.toolbox as toolbox_mod
        events, loads, learned = [], [], []

        class _Learning(_ScriptedClient):
            def learn_max_tools(self, count):
                learned.append(count)

        box = self._probing_box(loads)
        limits_seen = []

        class _AutoLoading(_DoneAgent):
            def _run_tool(self, tc):
                # What toolbox.call() does for a tool outside the list:
                # a budgeted load, which may probe when the loop allows.
                limits_seen.append(self.toolbox.tool_probe_limit)
                if tc.name == "img_vmdk_chain_info":
                    self.toolbox.load_with_budget(["img"])
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
        monkeypatch.setattr(toolbox_mod, "_LEARNED_CEILING", 45)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        first = ChatResponse(content="", tool_calls=[ToolCall(id="a", name="misc_tool", arguments={})])
        auto = ChatResponse(content="", tool_calls=[ToolCall(id="b", name="img_vmdk_chain_info", arguments={})])
        work = ChatResponse(content="", tool_calls=[ToolCall(id="c", name="img_vmdk_chain_info", arguments={})])
        _AutoLoading(_Learning([first, auto, work, _finish_response()]), box,
                     case_dir=None, quiet=True).run("sys", "user")
        # The first reply's call proves the list, so every batch runs with
        # the limit set; the probe the auto-load made was adopted after its
        # batch and the next reply's call raised the ceiling.
        assert limits_seen[:2] == [128, 128]
        assert [(e["from"], e["to"]) for e in events if e.get("event") == "tool_budget_probe"] == [(45, 60)]
        assert learned == [60]

    def test_a_test_that_gets_no_call_returns_to_the_ceiling_and_is_not_repeated(self, monkeypatch):
        """The reply to a tested list that tried to call and got nothing
        through is the answer: the namespace leaves, the ceiling returns,
        no later work order tests that size again in this run, and
        nothing is remembered for the model."""
        import agent.toolbox as toolbox_mod
        events, loads, learned = [], [], []
        dair = ChatResponse(content="", tool_calls=[ToolCall(id="d1", name="dair_assess", arguments={})])
        tried = ChatResponse(content="", output_tokens=40, reasoning_tokens=10)
        box = self._probing_run([dair, tried, dair, _finish_response()],
                                monkeypatch, events, loads, learned)
        failed = [e for e in events if e.get("event") == "tool_budget_probe_failed"]
        assert [(e["at"], e["back_to"], e["namespace"]) for e in failed] == [(60, 45, "img")]
        assert box.unloaded == ["img"] and "img" not in box.loaded
        assert toolbox_mod._LEARNED_CEILING == 45
        # The second work order may load up to 59 only, so img is refused,
        # not tested again.
        assert loads == [(["img"], 128), (["img"], 59)]
        assert learned == [] and not [e for e in events if e.get("event") == "tool_budget_shrunk"]
        assert not [e for e in events if e.get("event") == "tool_budget_raised"]

    def test_a_narrated_call_to_an_unloaded_tool_gets_its_namespace_loaded(self, monkeypatch):
        """A reply that names a tool outside the loaded namespaces and issues
        no call is short of the schema, not of will: the loop loads that
        namespace as it would for a work order and asks for the call."""
        from types import SimpleNamespace
        events, loads = [], []

        class _Box(_StubToolbox):
            def __init__(self):
                self.loaded = {"misc"}
                self.namespaces = ["misc", "tsk"]
                self.control_names = frozenset()
                self.tools = {
                    "tsk_tsk_mmls": SimpleNamespace(namespace="tsk", listed="tsk_mmls",
                                                    alias="tsk.mmls", name="tsk_tsk_mmls"),
                    "misc_tool": SimpleNamespace(namespace="misc", listed="misc_tool",
                                                 alias="misc.tool", name="misc_tool"),
                }

            def resolve(self, name):
                return {"tsk.mmls": "tsk_tsk_mmls", "misc.tool": "misc_tool"}.get(name)

            def load_with_budget(self, namespaces, keep=()):
                loads.append((list(namespaces), sorted(keep)))
                self.loaded.update(namespaces)
                return {"newly_loaded": list(namespaces), "refused": [], "evicted": []}

        class _Narrating(_DoneAgent):
            def _run_tool(self, tc):
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        script = [
            ChatResponse(content="All images ready. Now tsk.mmls on each raw image."),
            ChatResponse(content="", tool_calls=[ToolCall(id="1", name="tsk_mmls", arguments={})]),
            _finish_response(),
        ]
        box = _Box()
        agent = _Narrating(_ScriptedClient(script), box, case_dir=None, quiet=True)
        agent.run("sys", "user")
        assert loads == [(["tsk"], ["tsk"])] and "tsk" in box.loaded
        rescue = [e for e in events if e.get("event") == "intent_without_call"]
        assert [(e["unloaded_namespaces"], e["namespaces_loaded"]) for e in rescue] == [(["tsk"], ["tsk"])]
        notes = [m["content"] for m in agent.messages
                 if m.get("role") == "user" and "[no tool call received]" in str(m.get("content"))]
        assert len(notes) == 1 and "loaded now" in notes[0] and "atlas_load_namespaces" not in notes[0]
        assert agent.stats["stopped_reason"] == "finished"

    def test_a_call_cut_with_the_reply_asks_for_a_shorter_call(self, monkeypatch):
        """Arguments that arrived incomplete because the reply was cut are
        refused as malformed; the loop adds that the reply was cut and what
        to shorten, so the model does not make the same call again."""
        events = []

        class _Refusing(_DoneAgent):
            def _run_tool(self, tc):
                return "ERROR: arguments for 'misc_tool' were not valid JSON"

            def _log(self, record):
                events.append(record)

        cut = ChatResponse(content="", finish_reason="length", tool_calls=[
            ToolCall(id="1", name="misc_tool", arguments={"_malformed_arguments": "{\"a\": [1, 2"})])
        agent = _quiet_run(_Refusing, [cut, _finish_response()], monkeypatch)
        assert [e["tools"] for e in events if e.get("event") == "call_cut_off"] == [["misc_tool"]]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[reply cut off]" in str(m.get("content"))]
        assert len(notes) == 1 and "shorter arguments" in notes[0]["content"]

    def test_the_cut_note_names_the_argument_that_took_the_reply(self, monkeypatch):
        """When the parsed call knows which parameter its cut text was
        writing, the note says so with the size and the tool, and the
        event carries the same, so "shorter" points at one argument."""
        events = []

        class _Refusing(_DoneAgent):
            def _run_tool(self, tc):
                return "ERROR: arguments for 'misc_tool' were not valid JSON"

            def _log(self, record):
                events.append(record)

        cut = ChatResponse(content="", finish_reason="length", tool_calls=[
            ToolCall(id="1", name="misc_tool", arguments={
                "_malformed_arguments": "{\"ids\": [1, 2 … [70000 characters, cut]",
                "_longest_argument": "ids (69990 characters)"})])
        agent = _quiet_run(_Refusing, [cut, _finish_response()], monkeypatch)
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[reply cut off]" in str(m.get("content"))]
        assert len(notes) == 1
        assert "ids (69990 characters) on misc_tool" in notes[0]["content"]
        cut_events = [e for e in events if e.get("event") == "call_cut_off"]
        assert [e["longest_argument"] for e in cut_events] == [["ids (69990 characters) on misc_tool"]]

    def test_repeated_report_pushes_without_a_new_claim_wrap_the_run_up(self, monkeypatch, tmp_path):
        """A run that keeps collecting in Report is pushed toward the report
        every stall; after three pushes with nothing new recorded, the run
        wraps up rather than being pushed forever."""
        events = []

        class _Collecting(_DoneAgent):
            def _run_tool(self, tc):
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

            def _claim_count(self):
                return 5

            def _report_written(self):
                return False

        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 1)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        call = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="misc_tool", arguments={})])
        agent = _Collecting(_ScriptedClient([call] * 6 + [_finish_response()]),
                            _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent._dair_phase = "Report"
        agent.run("sys", "user")
        pushes = [e["turn"] for e in events if e.get("event") == "report_phase_stall"]
        wrap = [e for e in events if e.get("event") == "budget_wrapup" and e.get("trigger") == "report_stall"]
        assert len(pushes) >= 3 and len(wrap) == 1 and wrap[0]["pushes"] == 3
        assert wrap[0]["turn"] == pushes[2]
        assert any("wrapping up now" in str(m.get("content")) for m in agent.messages
                   if m.get("role") == "user")

    def test_findings_recorded_while_the_gates_blockers_stand_do_not_hold_off_the_wrap_up(
            self, monkeypatch, tmp_path):
        """Once the gate has a verdict, another variant of a finding it
        objects to is no move towards the report: three pushes with the same
        blockers wrap the run up however many findings came between them."""
        events = []
        claims = iter(range(5, 500))

        class _Varying(_DoneAgent):
            def _run_tool(self, tc):
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

            def _report_blockers(self):
                return 2

            def _claim_count(self):
                return next(claims)

        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 1)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        call = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="misc_tool", arguments={})])
        agent = _Varying(_ScriptedClient([call] * 6 + [_finish_response()]),
                         _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent._dair_phase = "Report"
        agent.run("sys", "user")
        wrap = [e for e in events if e.get("event") == "budget_wrapup" and e.get("trigger") == "report_stall"]
        assert len(wrap) == 1 and wrap[0]["pushes"] == 3

    def test_a_rerun_reads_open_evidence_in_report_without_being_wrapped_up(
            self, monkeypatch, tmp_path):
        """A rerun's log holds the previous run's gate verdicts; the ladder of
        this run reads only its own. A Report phase in which evidence the gate
        counts as open is read for the first time every turn is never pushed;
        the same phase with nothing read is wrapped up as before."""
        from core.execution_log import log
        for n in (1, 0):
            log.record_reason_call(
                tool="reason_pre_report_check", success=True, directives={},
                conclusion=f"READY_TO_REPORT: {'false' if n else 'true'}\n"
                           f"BLOCKING_ISSUES ({n}): {'floor' if n else 'none'}\nWARNINGS (0): none")

        def run(done):
            events, blockers_seen = [], []

            class _Rerun(_DoneAgent):
                def _run_tool(self, tc):
                    return '{"success": true}'

                def _log(self, record):
                    events.append(record)

                def _claim_count(self):
                    return 5

                def _report_done(self):
                    blockers_seen.append(self._report_blockers())
                    return done()

            call = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="misc_tool", arguments={})])
            agent = _Rerun(_ScriptedClient([call] * 12 + [_finish_response()]),
                           _StubToolbox(), case_dir=tmp_path, quiet=True)
            agent._dair_phase = "Report"
            agent.run("sys", "user")
            assert blockers_seen[0] is None               # the old verdicts are not its own
            return events

        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 1)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        reads = iter(range(1, 10_000))
        reading = run(lambda: frozenset({("unit", f"evidence/CORP-WS{next(reads):04d}.dd")}))
        assert not [e for e in reading if e.get("event") == "report_phase_stall"
                    or e.get("trigger") == "report_stall"]
        idle = run(lambda: frozenset({("unit", "evidence/CORP-WS0007.dd")}))
        assert [e for e in idle if e.get("event") == "budget_wrapup"
                and e.get("trigger") == "report_stall"]

    def test_a_run_wrapped_up_by_another_trigger_still_reaches_the_close_out(
            self, monkeypatch, tmp_path):
        """The report-phase close-out starts from the report-phase wrap-up; a
        run another trigger had wrapped up first (here the wall clock) and
        that then stalls in Report starts the same clock instead of staying
        there for good, and is told once, not wrapped up a second time."""
        events = []

        class _Stalled(_DoneAgent):
            def _run_tool(self, tc):
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

            def _report_blockers(self):
                return 2

            def _claim_count(self):
                return 5

            def _run_pre_report_check(self):
                return {"ready_to_report": False}

        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 2)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 1e-9)
        monkeypatch.setattr(loop_mod, "WALL_GRACE_SECONDS", 1e9)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        call = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="misc_tool", arguments={})])
        agent = _Stalled(_ScriptedClient([call] * 30), _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent._dair_phase = "Report"
        agent.run("sys", "user")
        assert [e["trigger"] for e in events if e.get("event") == "budget_wrapup"] == ["wall_clock"]
        stalls = [e for e in events if e.get("event") == "report_phase_stall"]
        assert [e["reason"] for e in stalls] == ["stalled_after_wrapup"]
        close = [e for e in events if e.get("event") == "report_stall_close_out"]
        assert len(close) == 1 and close[0]["since_wrapup"] == 2 and close[0]["ready"] is False
        assert agent.stats["stopped_reason"] == "report_stall"

    def test_one_hosts_report_does_not_make_the_run_reported(self, monkeypatch, tmp_path):
        """A report writer that produced one host's report, or refused to
        write at all, leaves the case's report owed; the case's own report
        counts."""
        import json as _json

        class _WritingBox(_StubToolbox):
            """The report writer answers with the path it wrote, nothing on
            disk; asked for a path it refuses, the way the report gate does."""
            def call(self, name, arguments):
                if arguments.get("refuse"):
                    return _json.dumps({"success": False, "gate": "pre_report_check_required",
                                        "error": "write refused: not ready"}), False
                return _json.dumps({"success": True, "output_path": arguments["output_path"]}), False

            def resolve(self, name):
                return name

        class _Writing(Agent):
            """Not _DoneAgent: that double pins _report_written to False."""
            def _dair_reengage_pending(self):
                return False

        (tmp_path / "reports").mkdir()
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        host = ChatResponse(content="", tool_calls=[ToolCall(
            id="1", name="misc_write_projected_final_report",
            arguments={"output_path": str(tmp_path / "reports" / "host_WS01_report.md")})])
        agent = _Writing(_ScriptedClient([host, _finish_response()]), _WritingBox(),
                         case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        assert agent._report_written() is False
        refused = ChatResponse(content="", tool_calls=[ToolCall(
            id="3", name="misc_write_projected_final_report", arguments={"refuse": True})])
        agent = _Writing(_ScriptedClient([refused, _finish_response()]), _WritingBox(),
                         case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        assert agent._report_written() is False
        estate = ChatResponse(content="", tool_calls=[ToolCall(
            id="2", name="misc_write_projected_final_report",
            arguments={"output_path": str(tmp_path / "reports" / "estate_report.md")})])
        agent = _Writing(_ScriptedClient([estate, _finish_response()]), _WritingBox(),
                         case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        assert agent._report_written() is True

    def test_three_rounds_of_re_asking_in_report_wrap_the_run_up(self, monkeypatch):
        """Each Report-phase re-ask round is a report push; three of them
        with no new claim between them end in the wrap-up, the same way
        three stalled pushes do."""
        import json as _json
        events = []

        class _Standing(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"current_phase": "Report",
                                    "progress": {"changed": False},
                                    "directives": {"priority_tools": []}})

            def _log(self, record):
                events.append(record)

            def _report_written(self):
                return False

            def _claim_count(self):
                return 5

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = _Standing(_ScriptedClient([ask] * 9 + [_finish_response()]),
                          _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        pushes = [e for e in events if e.get("event") == "report_phase_stall"]
        wrap = [e for e in events if e.get("event") == "budget_wrapup"]
        assert [e["reason"] for e in pushes] == ["director_reask"] * 3
        assert len(wrap) == 1 and wrap[0]["trigger"] == "report_stall" and wrap[0]["pushes"] == 3
        assert any("wrapping up now" in str(m.get("content")) for m in agent.messages
                   if m.get("role") == "user")

    def _standing_in_report(self, events, *, fresh_ready, checked, close_out_ok=True):
        import json as _json

        class _Standing(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"current_phase": "Report",
                                    "progress": {"changed": False},
                                    "directives": {"priority_tools": []}})

            def _log(self, record):
                events.append(record)

            def _report_written(self):
                return False

            def _pre_report_fresh_ready(self):
                return fresh_ready

            def _run_pre_report_check(self):
                return checked

            def _close_out(self, turn, *, reason):
                events.append({"event": "close_out_called", "turn": turn, "reason": reason})
                return close_out_ok

            def _claim_count(self):
                return 5

        return _Standing

    def test_a_ready_gate_in_report_closes_the_run_out_at_once(self, monkeypatch, tmp_path):
        """READY_TO_REPORT: true with no report on disk: the loop writes the
        reports and ends the run instead of waiting for the model to."""
        events = []
        cls = self._standing_in_report(events, fresh_ready=True, checked=None)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = cls(_ScriptedClient([ask] * 6), _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        calls = [e for e in events if e.get("event") == "close_out_called"]
        assert [c["reason"] for c in calls] == ["gate_ready"]
        assert calls[0]["turn"] == 2
        assert agent.stats["stopped_reason"] == "closed_out"

    def test_after_the_wrap_up_the_loop_consults_the_gate_and_closes_out_when_ready(self, monkeypatch, tmp_path):
        """No fresh verdict, wrap-up fired, still nothing written a stall
        later: the loop runs the check itself; ready means the reports are
        written and the run ends as closed out."""
        events = []
        cls = self._standing_in_report(events, fresh_ready=False,
                                       checked={"ready_to_report": True})
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 2)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = cls(_ScriptedClient([ask] * 30), _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        wrap = [e for e in events if e.get("event") == "budget_wrapup"]
        close = [e for e in events if e.get("event") == "report_stall_close_out"]
        assert len(wrap) == 1 and len(close) == 1 and close[0]["ready"] is True
        assert close[0]["turn"] - wrap[0]["turn"] == 2
        assert [e["reason"] for e in events if e.get("event") == "close_out_called"] == ["report_stall"]
        assert agent.stats["stopped_reason"] == "closed_out"

    def test_after_the_wrap_up_a_gate_still_not_ready_ends_the_run_for_the_exit_path(self, monkeypatch, tmp_path):
        events = []
        cls = self._standing_in_report(events, fresh_ready=False,
                                       checked={"ready_to_report": False})
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        monkeypatch.setattr(loop_mod, "REPORT_STALL_TURNS", 2)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = cls(_ScriptedClient([ask] * 30), _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        assert not [e for e in events if e.get("event") == "close_out_called"]
        assert agent.stats["stopped_reason"] == "report_stall"

    def test_re_asking_the_director_after_the_report_names_the_close_out(self, monkeypatch):
        """With the report written and the director standing still in
        Report, the loop names the close-out, not an earlier work order."""
        import json as _json
        events = []

        class _Done(_DoneAgent):
            _last_director_tools = ["tsk.fls (all images)"]

            def _run_tool(self, tc):
                return _json.dumps({"current_phase": "Report",
                                    "progress": {"changed": False},
                                    "directives": {"priority_tools": []}})

            def _log(self, record):
                events.append(record)

            def _report_written(self):
                return True

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = _Done(_ScriptedClient([ask, ask, ask, _finish_response()]),
                      _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        notes = [m["content"] for m in agent.messages if m.get("role") == "user"
                 and "[report phase]" in str(m.get("content"))]
        assert len(notes) == 1 and "atlas_finish" in notes[0]
        assert not any("tsk.fls" in str(m.get("content")) for m in agent.messages
                       if m.get("role") == "user")

    def test_asking_the_director_again_and_again_names_the_action(self, monkeypatch):
        """Three turns whose only call is the director, each answered with an
        unchanged assessment, end with the loop naming what to do: the
        report in the Report phase, the last work order elsewhere."""
        import json as _json
        events = []

        class _Standing(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"current_phase": self._phase_for_test,
                                    "progress": {"changed": False},
                                    "directives": {"priority_tools": []}})

            def _log(self, record):
                events.append(record)

            def _report_written(self):
                return False

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])

        agent = _Standing(_ScriptedClient([ask, ask, ask, _finish_response()]),
                          _StubToolbox(), case_dir=None, quiet=True)
        agent._phase_for_test = "Report"
        agent.run("sys", "user")
        assert [e["streak"] for e in events if e.get("event") == "director_reask_streak"] == [3]
        assert any("[report phase]" in str(m.get("content")) for m in agent.messages
                   if m.get("role") == "user")

        events.clear()
        agent = _Standing(_ScriptedClient([ask, ask, ask, _finish_response()]),
                          _StubToolbox(), case_dir=None, quiet=True)
        agent._phase_for_test = "Collect"
        agent._last_director_tools = ["tsk.fls (all images)"]
        agent.run("sys", "user")
        assert [e["phase"] for e in events if e.get("event") == "director_reask_streak"] == ["Collect"]
        notes = [m["content"] for m in agent.messages if m.get("role") == "user"
                 and "[director re-asked]" in str(m.get("content"))]
        assert len(notes) == 1 and "tsk.fls" in notes[0]

    def _standing_outside_report(self, events, claim_count):
        import json as _json

        class _Standing(_DoneAgent):
            _last_director_tools = ["tsk.fls (all images)"]
            director_calls = 0

            def _run_tool(self, tc):
                self.director_calls += 1
                return _json.dumps({"current_phase": "Collect",
                                    "progress": {"changed": False},
                                    "directives": {"priority_tools": []}})

            def _log(self, record):
                events.append(record)

            def _claim_count(self):
                return claim_count(self)

        return _Standing

    def test_naming_the_work_order_again_with_no_new_claim_asks_for_the_report(self, monkeypatch):
        """Outside Report the first re-ask round names the work order. A
        second round with no claim recorded between them would be the same
        words again, so the loop asks for the report instead; from there
        the report-phase ladder wraps the run up after three such pushes."""
        events = []
        _Standing = self._standing_outside_report(events, lambda self: 5)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = _Standing(_ScriptedClient([ask] * 12 + [_finish_response()]),
                          _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        fires = [e for e in events if e.get("event") == "director_reask_streak"]
        assert [(e["phase"], e["fires"]) for e in fires] == [("Collect", n) for n in (1, 2, 3, 4)]
        notes = [m["content"] for m in agent.messages if m.get("role") == "user"
                 and "[director re-asked]" in str(m.get("content"))]
        assert len(notes) == 1 and "tsk.fls" in notes[0]
        pushes = [e for e in events if e.get("event") == "report_phase_stall"]
        assert [e["reason"] for e in pushes] == ["director_reask"] * 3
        wrap = [e for e in events if e.get("event") == "budget_wrapup"]
        assert len(wrap) == 1 and wrap[0]["trigger"] == "report_stall" and wrap[0]["pushes"] == 3

    def test_a_claim_between_re_ask_rounds_keeps_naming_the_work_order(self, monkeypatch):
        """A claim recorded between two re-ask rounds means the nudge was
        acted on: the count starts over and the work order is named again
        rather than the report."""
        events = []
        _Standing = self._standing_outside_report(
            events, lambda self: self.director_calls // 3)
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        ask = ChatResponse(content="", tool_calls=[ToolCall(id="1", name="dair_assess", arguments={})])
        agent = _Standing(_ScriptedClient([ask] * 6 + [_finish_response()]),
                          _StubToolbox(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        fires = [e for e in events if e.get("event") == "director_reask_streak"]
        assert [e["fires"] for e in fires] == [1, 1]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[director re-asked]" in str(m.get("content"))]
        assert len(notes) == 2
        assert not [e for e in events if e.get("event") == "report_phase_stall"]

    def test_a_dropped_call_at_a_proven_size_names_the_loaded_namespaces(self, monkeypatch):
        """An empty reply with tokens after its thinking, at a list size that
        has delivered calls, is a call the endpoint dropped: the nudge says
        which namespaces are in the list instead of asking blindly."""
        events = []

        class _Holding(_DoneAgent):
            def _claim_count(self):
                return 3

            def _run_tool(self, tc):
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        dropped = ChatResponse(content="", output_tokens=40, reasoning_tokens=10)
        agent = _quiet_run(_Holding, [
            ChatResponse(content="", tool_calls=[ToolCall(id="1", name="misc_tool", arguments={})]),
            dropped, _finish_response()], monkeypatch)
        assert [e["consecutive"] for e in events if e.get("event") == "dropped_call_nudge"] == [1]
        assert not [e for e in events if e.get("event") == "empty_reply_nudge"]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[call did not arrive]" in str(m.get("content"))]
        assert len(notes) == 1 and "load that one namespace" in notes[0]["content"]

    def test_a_narrated_or_nameless_call_is_asked_for_with_the_channel_required(self, monkeypatch):
        """After a reply that narrates its call, and after one whose call
        names no tool, the next request asks for the function channel
        outright; a request after a proper call does not."""
        import json as _json
        seen = []

        class _Recording(_ScriptedClient):
            def chat(self, messages, tools=None, **kw):
                seen.append(kw.get("tool_choice"))
                return super().chat(messages, tools=tools)

        class _Box(_StubToolbox):
            def openai_tools(self):
                return [{"type": "function", "function": {"name": "misc_tool"}}]

        class _Holding(_DoneAgent):
            def _run_tool(self, tc):
                return _json.dumps({"success": True})

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        prose = ChatResponse(content="Let me call misc_tool to list the evidence.")
        nameless = ChatResponse(content="", output_tokens=27, reasoning_tokens=1,
                                tool_calls=[ToolCall(id="", name="", arguments={})])
        call = ChatResponse(content="", tool_calls=[ToolCall(id="2", name="misc_tool", arguments={})])
        agent = _Holding(_Recording([prose, nameless, call, call, _finish_response()]),
                         _Box(), case_dir=None, quiet=True)
        agent.run("sys", "user")
        assert seen[:5] == [None, "required", "required", None, None]

    def test_a_call_that_names_no_tool_never_enters_the_history(self, monkeypatch):
        """A function call with an empty name is not a call. It is dropped
        before the history, the model is told what was wrong, and the list
        size is not blamed for it."""
        events = []
        ran = []

        class _Holding(_DoneAgent):
            def _run_tool(self, tc):
                ran.append(tc.name)
                return '{"success": true}'

            def _log(self, record):
                events.append(record)

        nameless = ChatResponse(content="", output_tokens=27, reasoning_tokens=1,
                                tool_calls=[ToolCall(id="", name="", arguments={})])
        agent = _quiet_run(_Holding, [
            nameless,
            ChatResponse(content="", tool_calls=[ToolCall(id="2", name="misc_tool", arguments={})]),
            _finish_response()], monkeypatch)
        assert ran == ["misc_tool"]
        for m in agent.messages:
            for tc in m.get("tool_calls") or []:
                assert tc["function"]["name"]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[malformed call]" in str(m.get("content"))]
        assert len(notes) == 1
        assert [e["names"] for e in events if e.get("event") == "malformed_call_nudge"] == [[""]]
        assert not [e for e in events if e.get("event") in ("dropped_call_nudge", "empty_reply_nudge")]

    def test_a_call_written_as_call_syntax_runs_under_its_listed_name(self, monkeypatch):
        """The whole call written into the name field runs as the tool it
        names, with the arguments it carried, and the history shows the
        listed name so the model has a proper call to repeat."""
        from agent.toolbox import split_call_syntax
        ran = []

        class _NamingBox(_StubToolbox):
            def resolve(self, name):
                head, _ = split_call_syntax(name)
                return "misc_record_finding" if head in ("misc.record_finding", "misc_record_finding") else None

            def listed_name(self, name):
                return self.resolve(name)

        class _Holding(_DoneAgent):
            def _run_tool(self, tc):
                ran.append((tc.name, dict(tc.arguments)))
                return '{"success": true}'

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        garbled = ChatResponse(content="", tool_calls=[ToolCall(
            id="1", name='misc.record_finding(title="t1")</arg_value>', arguments={})])
        agent = _Holding(_ScriptedClient([garbled, _finish_response()]), _NamingBox(),
                         case_dir=None, quiet=True)
        agent.run("sys", "user")
        assert ran[0] == ("misc_record_finding", {"title": "t1"})
        names = [tc["function"]["name"] for m in agent.messages
                 for tc in (m.get("tool_calls") or [])]
        assert names[0] == "misc_record_finding"

    def test_replies_that_only_load_namespaces_are_pointed_at_the_work_order(self, monkeypatch):
        """Three replies in a row that only load or list namespaces do no
        work; the loop loads what the director asked for and names the
        call to make instead of letting the loading go on."""
        events = []

        class _Loading(_DoneAgent):
            _last_director_tools = ["tsk.mmls (all images)", "table.table_query"]

            def _run_tool(self, tc):
                return "Loaded namespaces: (none). REFUSED (tool-budget): img"

            def _log(self, record):
                events.append(record)

        load = ChatResponse(content="", tool_calls=[
            ToolCall(id="l", name="atlas_load_namespaces", arguments={"namespaces": ["img"]})])
        agent = _quiet_run(_Loading, [load, load, load, _finish_response()], monkeypatch)
        assert [e["streak"] for e in events if e.get("event") == "meta_only_streak"] == [3]
        notes = [m for m in agent.messages if m.get("role") == "user"
                 and "[namespaces only]" in str(m.get("content"))]
        assert len(notes) == 1 and "tsk.mmls" in notes[0]["content"]

    def test_the_live_status_is_stamped_while_the_model_call_is_in_flight(self, monkeypatch):
        """A model request the endpoint holds open used to leave the status
        file untouched for its whole duration; the heartbeat that covered
        tool calls now covers model calls too."""
        import time as _time
        monkeypatch.setattr(loop_mod, "HEARTBEAT_SECONDS", 0.02)
        stamps = []

        class _Slow(_ScriptedClient):
            def chat(self, messages, tools=None):
                _time.sleep(0.15)
                return super().chat(messages, tools)

        class _Stamping(_DoneAgent):
            def _persist_live_status(self):
                stamps.append(_time.monotonic())

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
        monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
        _Stamping(_Slow([_finish_response()]), _StubToolbox(), case_dir=None, quiet=True).run("sys", "user")
        assert len(stamps) >= 3

    def test_a_meta_tool_named_in_planning_prose_is_not_a_call(self):
        """A plan line such as "2. atlas_load_namespaces (unload net; load
        hash, strings)" is prose. Recovering it runs empty loads in the
        turn and, counting as a call, keeps the intent nudge from asking
        for the real calls."""
        agent = Agent.__new__(Agent)
        text = ("Let me prioritize:\n1. dair_assess (required)\n"
                "2. atlas_load_namespaces (unload net; load hash, strings)\n"
                "3. vol_vol_info on DC01 memory\n"
                "Then again atlas_load_namespaces (load vol) if needed.")
        assert agent._recover_tool_calls_from_content(text) == []

    def test_explicit_pseudo_calls_are_recovered_once_each(self):
        agent = Agent.__new__(Agent)
        text = 'atlas_load_namespaces(["vol"]) and again atlas_load_namespaces(["vol"])'
        calls = agent._recover_tool_calls_from_content(text)
        assert [(c.name, c.arguments) for c in calls] == [
            ("atlas_load_namespaces", {"namespaces": ["vol"]})]

    def test_narrated_atlas_finish_is_never_recovered(self, monkeypatch):
        """A model *describing* atlas_finish must not end the investigation.
        Recovering exploratory calls is a rescue; recovering the finish call
        from prose would silently truncate a run."""
        script = [ChatResponse(content="I would now call "
                                       "atlas_finish(summary='all done')")
                  for _ in range(8)]
        agent = _quiet_run(_DoneAgent, script, monkeypatch)
        assert agent.stats["stopped_reason"] != "finished"

    def test_plain_prose_is_untouched(self, monkeypatch):
        """Guard: no tool syntax → the quiet path behaves exactly as before."""
        agent = _quiet_run(_DoneAgent, _quiet_script(8), monkeypatch)
        assert agent.stats["stopped_reason"] == "quiet"


class TestAnEmptyProviderReplyOnARunWithFindings:
    """Two turns without a call enter the quiet ladder, and for a run that
    already holds findings every rung of it is unavailable: the wrap-up round
    is one-shot and usually spent, and the no-work rescue covers only a run
    that has recorded nothing. So two empty replies ended a run with findings
    on the board and no recovery path in existence."""

    def _run(self, monkeypatch, empty_turns, claims=3):
        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

            def _claim_count(self):
                return claims

        # Two scripted replies per empty turn: an empty one is retried once
        # inside the turn before the loop sees it.
        script = [ChatResponse(content="", output_tokens=24)
                  for _ in range(empty_turns * 2)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f1", name="atlas_finish",
                     arguments={"summary": "done"})]))
        return _quiet_run(_Capturing, script, monkeypatch)

    def test_a_run_with_findings_survives_them(self, monkeypatch):
        agent = self._run(monkeypatch, 3)
        assert agent.stats["stopped_reason"] == "finished"
        # Once a run holds findings, an empty reply that generated tokens
        # is read as a dropped call and gets the nudge that names the loaded
        # namespaces; either way the count runs and the run survives.
        assert [r["consecutive"] for r in agent.logged
                if r.get("event") in ("empty_reply_nudge", "dropped_call_nudge")] == [1, 2, 3]

    def test_a_run_holding_nothing_gets_the_rescue_instead(self, monkeypatch):
        """Before a run holds anything the no-work rescue is the right
        instrument and must not be pre-empted — putting this ahead of it
        leaves a run at zero findings with its namespaces never loaded."""
        agent = self._run(monkeypatch, 6, claims=0)
        events = [r.get("event") for r in agent.logged]
        assert "empty_reply_nudge" not in events   # never this path
        assert "no_work_rescue" in events          # the rescue, once reached

    def test_a_real_call_clears_the_count(self, monkeypatch):
        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

            def _claim_count(self):
                return 3

        script = [
            ChatResponse(content="", output_tokens=24),
            ChatResponse(content="", output_tokens=24),
            ChatResponse(content="", tool_calls=[
                ToolCall(id="f1", name="atlas_finish",
                         arguments={"summary": "done"})]),
        ]
        agent = _quiet_run(_Capturing, script, monkeypatch)
        assert [r["consecutive"] for r in agent.logged
                if r.get("event") in ("empty_reply_nudge", "dropped_call_nudge")] == [1]

    def test_a_reply_that_says_something_is_not_this(self, monkeypatch):
        """A reply with words and no call is the intent rescue's business."""
        class _Capturing(_DoneAgent):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.logged = []

            def _log(self, record):
                self.logged.append(record)

            def _claim_count(self):
                return 3

        script = [
            ChatResponse(content="Let me search the MFT CSVs next."),
            ChatResponse(content="", tool_calls=[
                ToolCall(id="f1", name="atlas_finish",
                         arguments={"summary": "done"})]),
        ]
        agent = _quiet_run(_Capturing, script, monkeypatch)
        assert "empty_reply_nudge" not in [r.get("event") for r in agent.logged]


class TestACallWhoseClosingTagWasEaten:
    """An endpoint can stop generation on `</tool_call>` and strip it, so the
    reply carries an opening tag and a whole call with nothing to close it.
    A recovery that requires the closing tag discards every call such a
    model makes, and the run executes nothing at all."""

    def _agent(self):
        from agent.loop import Agent
        return Agent.__new__(Agent)

    def _recovered(self, text):
        return [(t.name, t.arguments)
                for t in self._agent()._recover_tool_calls_from_content(text)]

    def test_a_call_with_no_closing_tag_is_recovered(self):
        assert self._recovered("<tool_call>misc_inventory_evidence()") == [
            ("misc_inventory_evidence", {})]

    def test_its_arguments_survive(self):
        got = self._recovered(
            '<tool_call>misc_start_execution_log(case_id="R", '
            'output_path="analysis/x.json")')
        assert got == [("misc_start_execution_log",
                        {"case_id": "R", "output_path": "analysis/x.json"})]

    def test_two_of_them_in_one_reply(self):
        got = self._recovered(
            '<tool_call>misc_start_execution_log(case_id="R")'
            '<tool_call>misc_inventory_evidence()')
        assert [n for n, _ in got] == ["misc_start_execution_log",
                                       "misc_inventory_evidence"]

    def test_a_namespace_load_survives(self):
        """The call a stalled run needs most: without it no forensic tool is
        in the schema, so nothing else can be called either."""
        assert self._recovered(
            '<tool_call>atlas_load_namespaces(namespaces=["tsk","net"])') == [
            ("atlas_load_namespaces", {"namespaces": ["tsk", "net"]})]

    def test_the_terminated_form_still_works(self):
        assert self._recovered("<tool_call>misc_inventory_evidence()</tool_call>") == [
            ("misc_inventory_evidence", {})]

    def test_a_tool_named_in_a_plan_is_still_prose(self):
        """The tag is required. A numbered plan naming a tool would run
        empty namespace loads in a turn, and must stay unrecovered."""
        assert self._recovered(
            "2. atlas_load_namespaces (unload net; load hash, strings)") == []

    def test_a_prose_mention_with_parentheses_is_still_prose(self):
        assert self._recovered(
            "Next I will call misc_inventory_evidence() to list things.") == []


class TestBlockedToolSpin:
    """The quiet valve keys on 'no tool calls', but the real signal is 'no
    progress'. A model that keeps *calling* DAIR-blocked forensic tools looks
    productive to the valve every turn while achieving nothing — and pseudo-
    tool recovery made that state easier to reach, because a call recovered
    from message text also resets the quiet counter."""

    @staticmethod
    def _blocked_result():
        from core.deferred_intents import PROTOCOL_MARKER
        return (f"{PROTOCOL_MARKER} Tool tsk_fls blocked: no dair_call in "
                "recent window. Call dair_assess next — do NOT retry this "
                "forensic tool until dair_assess promotes it.")

    def _blocked_agent(self, report_written=True):
        blocked = self._blocked_result()

        class _Blocked(Agent):
            def _dair_reengage_pending(self):
                return True

            def _report_written(self):
                return report_written

            def _run_tool(self, tc):
                return blocked

        return _Blocked

    def test_repeated_blocked_batches_stop_the_run(self, monkeypatch):
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"t{i}", name="tsk_fls", arguments={})])
            for i in range(40)]
        agent = _quiet_run(self._blocked_agent(), script, monkeypatch)
        assert agent.stats["stopped_reason"] == "stall"
        assert agent.stats["turns"] < 40, "must not spin through the script"

    def test_recovered_xml_calls_to_a_blocked_tool_also_stop(self, monkeypatch):
        """The exact regression: the call arrives as text, gets recovered,
        comes back protocol-blocked, and used to reset the quiet counter."""
        script = [ChatResponse(content="<tool_call>tsk_fls(image=/e.raw)"
                                       "</tool_call>") for _ in range(40)]
        agent = _quiet_run(self._blocked_agent(), script, monkeypatch)
        assert agent.stats["stopped_reason"] == "stall"
        assert agent.stats["turns"] < 40

    def test_blocked_spin_still_gets_a_wrapup_when_no_report(self, monkeypatch):
        """Never end a spin without asking for the report first."""
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"t{i}", name="tsk_fls", arguments={})])
            for i in range(40)]
        agent = _quiet_run(self._blocked_agent(report_written=False),
                           script, monkeypatch)
        assert _wrapup_messages(agent)
        assert agent.stats["stopped_reason"] == "stall"

    def test_productive_tools_never_trigger_it(self, monkeypatch):
        """Guard: successful tool results must not look like a stall, no
        matter how many turns they take."""
        class _Working(Agent):
            def _dair_reengage_pending(self):
                return True      # intents open, but work IS progressing

            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return '{"success": true}'

        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"t{i}", name="tsk_fls", arguments={})])
            for i in range(12)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(_Working, script, monkeypatch)
        assert agent.stats["stopped_reason"] == "finished"

    def test_a_mixed_batch_is_not_a_blocked_turn(self, monkeypatch):
        """One blocked call alongside one that worked is still progress."""
        blocked = self._blocked_result()

        class _Mixed(Agent):
            def _dair_reengage_pending(self):
                return True

            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return blocked if tc.name == "tsk_fls" else '{"success": true}'

        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"a{i}", name="tsk_fls", arguments={}),
            ToolCall(id=f"b{i}", name="table_table_query", arguments={"sql": f"select {i}"})])
            for i in range(12)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(_Mixed, script, monkeypatch)
        assert agent.stats["stopped_reason"] == "finished"

    def test_a_repeated_identical_call_beside_a_blocked_one_is_not_progress(self, monkeypatch):
        """The same query every turn is answered from memory, not run again;
        a batch of one blocked call and one repeat is a blocked turn."""
        blocked = self._blocked_result()

        class _Mixed(Agent):
            def _dair_reengage_pending(self):
                return True

            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return blocked if tc.name == "tsk_fls" else '{"success": true}'

        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"a{i}", name="tsk_fls", arguments={}),
            ToolCall(id=f"b{i}", name="table_table_query", arguments={"sql": "select 1"})])
            for i in range(12)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(_Mixed, script, monkeypatch)
        assert agent.stats["stopped_reason"] == "stall"
        assert agent.stats["identical_calls_pointed"] >= 5
        assert agent.stats["distinct_tool_calls"] == 1


class TestARefusalRepeatedUnchanged:
    """The identical-call memo points at a result a repeat already has. A
    refused call has no result to point at, so its verbatim repeat passed
    through and met the same refusal word for word, turn after turn."""

    @staticmethod
    def _refusal():
        import json
        return json.dumps({"success": False,
                           "error": "the cited calls are not about this",
                           "gate": "some_gate"}, indent=2)

    def _agent(self):
        refusal = self._refusal()

        class _Refusing(Agent):
            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return refusal

        return _Refusing

    @staticmethod
    def _results(agent):
        return [m["content"] for m in agent.messages if m.get("role") == "tool"
                and str(m.get("tool_call_id", "")).startswith("r")]

    def test_the_second_identical_refusal_is_named_as_a_repeat(self, monkeypatch):
        import json
        args = {"description": "same", "input_call_ids": [3]}
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"r{i}", name="misc_record_finding", arguments=dict(args))])
            for i in range(3)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(), script, monkeypatch)
        results = self._results(agent)
        assert len(results) == 3
        assert "REPEATED REFUSAL" not in results[0]
        assert "REPEATED REFUSAL (#2)" in results[1]
        assert "REPEATED REFUSAL (#3)" in results[2]
        second = json.loads(results[1])
        assert second["previous_turn"] == 1 and second["identical_refusals"] == 2
        assert second["gate"] == "some_gate"
        assert "not about this" in second["error"]   # the gate's remedy stays
        # Still read as a refusal by the head-of-result check the loop uses.
        assert '"success": false' in results[1][:300] and '"gate"' in results[1][:600]

    def test_changed_arguments_are_a_new_refusal(self, monkeypatch):
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"r{i}", name="misc_record_finding",
                     arguments={"description": f"attempt {i}"})])
            for i in range(3)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(), script, monkeypatch)
        results = self._results(agent)
        assert len(results) == 3
        assert not any("REPEATED REFUSAL" in r for r in results)


class TestTrimContextNeverKillsARun:
    """core.llm_check.fit_messages raises ContextBudgetExceededError when the
    system frame alone exceeds the send budget. That is a *chars/4 estimate*
    — it must never be the thing that kills a multi-hour investigation."""

    def test_context_budget_error_is_caught(self, monkeypatch):
        from core.llm_check import ContextBudgetExceededError

        def _boom(*a, **kw):
            raise ContextBudgetExceededError("system prompt too large")

        monkeypatch.setattr("core.llm_check.fit_messages", _boom)
        agent = _agent(_ScriptedClient([_finish_response()]))
        agent.run("sys", "user")  # must not raise
        assert agent.stats["stopped_reason"] == "finished"


class TestFinishRequiresAReport:
    """A run may end via atlas_finish with no official report at all: the
    near-cap wrap-up that would have forced one is gated behind a hard turn
    cap, and the default config has none."""

    def test_first_finish_without_a_report_is_deferred_once(
            self, tmp_path, monkeypatch):
        class _NoReport(Agent):
            def _report_written(self):
                return False

            def _finish_coverage_check(self, *, wall_expired):
                return ""          # coverage satisfied — isolate the report gate

            def _run_tool(self, tc):
                return "ok"

        def _finish(i):
            return ChatResponse(content="", tool_calls=[
                ToolCall(id=f"f{i}", name="atlas_finish",
                         arguments={"summary": "done"})])

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        agent = _NoReport(_ScriptedClient([_finish(0), _finish(1)]),
                          _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        deferrals = [m for m in agent.messages
                     if m.get("role") == "tool"
                     and "deferred" in str(m.get("content")).lower()
                     and "report" in str(m.get("content")).lower()]
        assert len(deferrals) == 1, "exactly one redirect, never a hard block"
        # The SECOND atlas_finish goes through — this is a redirect, not a gate.
        assert agent.stats["stopped_reason"] == "finished"

    def test_finish_with_a_report_is_not_deferred(self, tmp_path, monkeypatch):
        class _HasReport(Agent):
            def _report_written(self):
                return True

            def _finish_coverage_check(self, *, wall_expired):
                return ""

        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
        agent = _HasReport(_ScriptedClient([_finish_response()]),
                           _StubToolbox(), case_dir=tmp_path, quiet=True)
        agent.run("sys", "user")
        assert agent.stats["stopped_reason"] == "finished"
        assert agent.stats["turns"] == 1

    def test_wall_clock_stop_is_never_gated_on_the_report(
            self, tmp_path, monkeypatch):
        """A hard stop must not gain an extra hurdle — same escape the
        coverage deferral already has."""
        class _NoReport(Agent):
            def _report_written(self):
                return False

        agent = _NoReport(_ScriptedClient([]), _StubToolbox(),
                          case_dir=tmp_path, quiet=True)
        assert agent._finish_report_check(wall_expired=True) == ""


class TestIdenticalCallsWithinOneTurn:
    """The memo remembers a successful read-only call the moment it returns,
    so its twin later in the same batch is already pointed at the result:
    identical calls are deduplicated inside a turn, not only across turns."""

    def test_the_twin_in_the_same_batch_is_pointed_not_run(self, monkeypatch):
        import json
        ran = []

        class _Counting(Agent):
            def _report_written(self):
                return True

            def _run_tool(self, tc):
                ran.append(tc.id)
                return json.dumps({"success": True, "rows": [1]})

        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id="q1", name="table_table_query", arguments={"sql": "select 1"}),
            ToolCall(id="q2", name="table_table_query", arguments={"sql": "select 1"}),
            ToolCall(id="q3", name="table_table_query", arguments={"sql": "select 2"})])]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(_Counting, script, monkeypatch)
        assert ran == ["q1", "q3"]
        pointed = [m for m in agent.messages if m.get("role") == "tool"
                   and m.get("tool_call_id") == "q2"]
        assert pointed and '"identical_call"' in pointed[0]["content"]
        assert agent.stats["identical_calls_pointed"] == 1


class TestAPointerAtACutResultNamesTheCut:
    """The identical-call gate points a repeat at the earlier result when
    that result is still in the conversation. When the earlier result was
    cut - the tool truncated it - the conversation holds only its head,
    and "read it there" sends the model back to a part it has already read;
    the repeat was how it asked for the rest. The refusal then names the
    cut, the complete output on disk and the narrower calls."""

    LISTING = ("{\"success\": true, \"stdout\": \"" + "r/r 12263-128-1: file.txt\\n" * 40
               + "\", \"truncated\": true, \"stdout_file\": "
               "\"/case/analysis/tool-output/0001_fls.stdout\", \"_atlas_call_id\": 157}")

    def _agent(self, listing):
        class _Listing(Agent):
            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return listing
        return _Listing

    @staticmethod
    def _tool_results(agent):
        return [m["content"] for m in agent.messages if m.get("role") == "tool"
                and str(m.get("tool_call_id", "")).startswith("l")]

    def test_a_repeat_of_a_truncated_listing_is_told_where_the_rest_is(self, monkeypatch):
        import json
        args = {"image": "mnt/x/ewf1", "inode": 344, "recursive": True}
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"l{i}", name="tsk_fls", arguments=dict(args))]) for i in range(2)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(self.LISTING), script, monkeypatch)
        results = self._tool_results(agent)
        assert len(results) == 2
        second = json.loads(results[1])
        assert second["gate"] == "identical_call"
        assert second["incomplete"] == "its output was truncated"
        assert "/case/analysis/tool-output/0001_fls.stdout" in second["error"]
        assert "still in the conversation" not in second["error"]
        assert second["previous_call_id"] == "157"

    def test_a_repeat_of_a_complete_result_is_still_pointed_at_it(self, monkeypatch):
        import json
        complete = self.LISTING.replace('"truncated": true', '"truncated": false')
        args = {"image": "mnt/x/ewf1", "inode": 344}
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"l{i}", name="tsk_fls", arguments=dict(args))]) for i in range(2)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(complete), script, monkeypatch)
        second = json.loads(self._tool_results(agent)[1])
        assert second["gate"] == "identical_call" and "incomplete" not in second
        assert "still in the conversation" in second["error"]


class TestAReplayOfACutResultNamesTheCut(TestAPointerAtACutResultNamesTheCut):
    """When the earlier result was compacted out of the conversation the
    identical call is replayed from memory. A replay of a cut view shows the
    same part again, so it carries the same note as the pointer: the cut,
    the complete output on disk and the advice to narrow the call."""

    def _agent(self, listing):
        class _Compacted(Agent):
            def _report_written(self):
                return True

            def _run_tool(self, tc):
                return listing

            def _result_still_in_context(self, tool_call_id):
                return False
        return _Compacted

    def test_a_replay_of_a_truncated_listing_is_told_where_the_rest_is(self, monkeypatch):
        args = {"image": "mnt/x/ewf1", "inode": 344, "recursive": True}
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"l{i}", name="tsk_fls", arguments=dict(args))]) for i in range(2)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(self.LISTING), script, monkeypatch)
        results = self._tool_results(agent)
        assert len(results) == 2
        assert results[1].startswith("[replayed from turn")
        head = results[1].split("]\n", 1)[0]
        assert "its output was truncated" in head and "shows the same part" in head
        assert "/case/analysis/tool-output/0001_fls.stdout" in head
        assert results[1].endswith(self.LISTING)

    def test_a_replay_of_a_complete_result_carries_no_note(self, monkeypatch):
        complete = self.LISTING.replace('"truncated": true', '"truncated": false')
        args = {"image": "mnt/x/ewf1", "inode": 344}
        script = [ChatResponse(content="", tool_calls=[
            ToolCall(id=f"l{i}", name="tsk_fls", arguments=dict(args))]) for i in range(2)]
        script.append(ChatResponse(content="", tool_calls=[
            ToolCall(id="f", name="atlas_finish", arguments={"summary": "x"})]))
        agent = _quiet_run(self._agent(complete), script, monkeypatch)
        head = self._tool_results(agent)[1].split("]\n", 1)[0]
        assert head.startswith("[replayed from turn") and "shows the same part" not in head

    def test_a_repeat_of_a_truncated_listing_is_told_where_the_rest_is(self, monkeypatch):
        pytest.skip("the pointer branch is the parent class's case")

    def test_a_repeat_of_a_complete_result_is_still_pointed_at_it(self, monkeypatch):
        pytest.skip("the pointer branch is the parent class's case")


class TestAStandingNudgeIsNotRepeated:
    """A steering message re-derived from unchanged state says nothing new
    while its last copy still stands in the conversation; it is repeated
    only when it changed or compaction took the copy away."""

    def _agent_like(self, messages, index):
        return type("A", (), {"messages": messages, "_nudge_index": index})()

    def test_the_same_text_still_in_place_stands(self):
        a = self._agent_like([{"role": "user", "content": "[artifact value] read X"}], {"artifact_value_nudge": 0})
        assert Agent._nudge_stands(a, "artifact_value_nudge", "[artifact value] read X")

    def test_a_changed_text_or_a_stubbed_copy_does_not(self):
        a = self._agent_like([{"role": "user", "content": "[artifact value] read X"}], {"artifact_value_nudge": 0})
        assert not Agent._nudge_stands(a, "artifact_value_nudge", "[artifact value] read X and Y")
        from core.llm_check import _TURN_STUB
        a.messages[0]["content"] = _TURN_STUB
        assert not Agent._nudge_stands(a, "artifact_value_nudge", "[artifact value] read X")

    def test_no_earlier_nudge_of_that_kind_does_not_stand(self):
        a = self._agent_like([], {})
        assert not Agent._nudge_stands(a, "artifact_value_nudge", "anything")


class TestWallClockReachesTheStallDetector:
    """Once an operator-set wall clock has run out, the stall detector is told
    so, which is what lets its force-report nudge fire on the clock (it keys
    on ``wall_clock or ledger_ok``)."""

    def _recording_detector(self, monkeypatch):
        seen = []

        def detector(state, *, turn, report_written, case_dir=None, wall_clock=False):
            seen.append(wall_clock)
            return []
        monkeypatch.setattr(loop_mod, "stall_messages_for_turn", detector)
        return seen

    def test_expired_clock_is_passed_from_the_next_turn(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 1e-9)
        monkeypatch.setattr(loop_mod, "WALL_GRACE_SECONDS", 3600.0)
        seen = self._recording_detector(monkeypatch)
        client = _ScriptedClient([ChatResponse(content="looking"), _finish_response()])
        _agent(client).run("sys", "user")
        assert seen[0] is False and seen[1:] and all(seen[1:])

    def test_no_clock_never_reports_expiry(self, monkeypatch):
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        seen = self._recording_detector(monkeypatch)
        client = _ScriptedClient([ChatResponse(content="looking"), _finish_response()])
        _agent(client).run("sys", "user")
        assert seen and not any(seen)


class TestLostTurn:
    """A provider that drops the reply on every attempt of one request loses
    the turn, not the run: the turn is asked again after a pause, and only
    repeated loss of the same turn wraps the run up."""

    @staticmethod
    def _no_sleep(monkeypatch):
        slept = []
        monkeypatch.setattr(loop_mod.time, "sleep", lambda s: slept.append(s))
        return slept

    def test_one_lost_request_is_asked_again_and_the_run_goes_on(self, monkeypatch):
        from agent.llm import LLMTransportError
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        slept = self._no_sleep(monkeypatch)
        client = _ScriptedClient([LLMTransportError("peer closed connection"),
                                  _finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")
        assert client.calls == 2 and slept == [loop_mod.LOST_TURN_PAUSE]
        assert _wrapup_messages(agent) == []
        assert agent.stats["stopped_reason"] == "finished"
        # the failed attempt added nothing to the conversation
        assert sum(1 for m in agent.messages if m.get("role") == "assistant") == 1

    def test_repeated_loss_of_one_turn_wraps_the_run_up(self, monkeypatch):
        from agent.llm import LLMTransportError
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        slept = self._no_sleep(monkeypatch)
        lost = [LLMTransportError(f"lost {i}") for i in range(loop_mod.LOST_TURN_RETRIES + 1)]
        client = _ScriptedClient(lost + [_finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")  # must not raise
        assert slept == [loop_mod.LOST_TURN_PAUSE * 2 ** i for i in range(loop_mod.LOST_TURN_RETRIES)]
        assert len(_wrapup_messages(agent)) == 1
        assert agent.stats["stopped_reason"] == "finished"

    def test_a_request_error_is_not_retried(self, monkeypatch):
        from agent.llm import LLMError
        monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
        slept = self._no_sleep(monkeypatch)
        client = _ScriptedClient([LLMError("HTTP 401 from http://fake: unauthorized")])
        agent = _agent(client)
        with pytest.raises(LLMError):
            agent.run("sys", "user")
        assert slept == [] and client.calls == 1


class TestFirewallRefusalInTheLoop:
    """A firewall refusal drops the largest tool output from context, puts
    the stub in its place and asks again; smaller outputs stay, and a stub is
    never swapped a second time."""

    def test_the_largest_output_is_swapped_and_the_turn_asked_again(self, monkeypatch):
        from agent.llm import WAFBlockedError
        monkeypatch.setattr(loop_mod.time, "sleep", lambda _s: None)
        seen = []

        class _Client(_ScriptedClient):
            def chat(self, messages, tools=None):
                seen.append([m["content"] for m in messages if m.get("role") == "tool"])
                return super().chat(messages, tools)

        big, small = "x" * 5000, "y" * 300
        agent = _agent(_Client([WAFBlockedError("HTTP 418"), ChatResponse(content="ok")]))
        agent.messages = [{"role": "user", "content": "go"},
                          {"role": "tool", "tool_call_id": "1", "content": small},
                          {"role": "tool", "tool_call_id": "2", "content": big}]
        assert agent._chat_waf_tolerant().content == "ok"
        assert seen == [[small, big], [small, loop_mod.WAF_STUB]]

    def test_with_nothing_left_to_drop_the_refusal_surfaces(self, monkeypatch):
        from agent.llm import WAFBlockedError
        monkeypatch.setattr(loop_mod.time, "sleep", lambda _s: None)
        agent = _agent(_ScriptedClient([WAFBlockedError("HTTP 418")]))
        agent.messages = [{"role": "user", "content": "go"},
                          {"role": "tool", "tool_call_id": "1", "content": loop_mod.WAF_STUB}]
        with pytest.raises(WAFBlockedError):
            agent._chat_waf_tolerant()


def test_a_narrated_call_whose_namespace_cannot_be_loaded_names_the_way_back(monkeypatch):
    """When the toolbox refuses the load (its list is full), the reply is
    not told the namespace is loaded: it is told which call brings it back."""
    from types import SimpleNamespace
    events = []

    class _Box(_StubToolbox):
        def __init__(self):
            self.loaded = {"misc"}
            self.namespaces = ["misc", "tsk"]
            self.control_names = frozenset()
            self.tools = {
                "tsk_tsk_mmls": SimpleNamespace(namespace="tsk", listed="tsk_mmls",
                                                alias="tsk.mmls", name="tsk_tsk_mmls"),
            }

        def resolve(self, name):
            return {"tsk.mmls": "tsk_tsk_mmls"}.get(name)

        def load_with_budget(self, namespaces, keep=()):
            return {"newly_loaded": [], "refused": [{"namespace": n} for n in namespaces],
                    "evicted": []}

    class _Narrating(_DoneAgent):
        def _run_tool(self, tc):
            return '{"success": true}'

        def _log(self, record):
            events.append(record)

    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
    monkeypatch.setattr(loop_mod, "MAX_TURNS", 0)
    monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_TURNS", 0)
    monkeypatch.setattr(loop_mod, "BLOCKER_EXTENSION_MAX", 0)
    script = [
        ChatResponse(content="All images ready. Now tsk.mmls on each raw image."),
        _finish_response(),
    ]
    agent = _Narrating(_ScriptedClient(script), _Box(), case_dir=None, quiet=True)
    agent.run("sys", "user")
    rescue = [e for e in events if e.get("event") == "intent_without_call"]
    assert [(e["unloaded_namespaces"], e["namespaces_loaded"]) for e in rescue] == [(["tsk"], [])]
    notes = [m["content"] for m in agent.messages
             if m.get("role") == "user" and "[no tool call received]" in str(m.get("content"))]
    assert len(notes) == 1
    assert 'atlas_load_namespaces(["tsk"])' in notes[0] and "loaded now" not in notes[0]
