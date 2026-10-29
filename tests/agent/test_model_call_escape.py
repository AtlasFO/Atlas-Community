"""The stuck-run escape (ATLAS_MODEL_CALL_ESCAPE, ATLAS_REFUSAL_ACCOUNTING,
ATLAS_TOOL_CHOICE_VALUE_MEMORY): provider
error events, stream cuts with their records, one attempt for a long cut,
the runaway step, learn=False, the lost ledger rows, the remembered
tool_choice value, and the analyst loop's rungs. Invented fixtures only;
no model is called."""
from __future__ import annotations

import contextlib
import json
import os
from types import SimpleNamespace

import pytest

from agent import llm
from agent import loop as loop_mod
from agent.llm import ChatResponse, LLMDeadlineError, LLMHubClient, LLMStatusError, LLMTransportError, ToolCall
from agent.loop import Agent

MSGS = [{"role": "user", "content": "hi"}]
TOOLS = [{"type": "function", "function": {"name": "t", "description": "d",
                                            "parameters": {"type": "object", "properties": {}}}}]


def _chunk(delta=None, finish=None, usage=None, choices=True, extra=None):
    body = {"id": "s1", "object": "chat.completion.chunk", "model": "m",
            "choices": ([{"index": 0, "delta": delta or {}, "finish_reason": finish}] if choices else [])}
    if usage is not None:
        body["usage"] = usage
    body.update(extra or {})
    return "data: " + json.dumps(body)


DONE = [_chunk({"reasoning_content": "Thinking about it."}), _chunk({"content": "ok"}),
        _chunk({}, finish="stop"), _chunk(usage={"prompt_tokens": 5, "completion_tokens": 2}, choices=False),
        "data: [DONE]"]


class _Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.slept.append(round(s, 1))

    def time(self):
        return self.t


class _SSE:
    """A streamed reply; ``run`` seconds pass on the clock while it streams,
    and a stream without a finish fails as an early end."""

    def __init__(self, lines, clock, run=0.0):
        self.status_code = 200
        self.headers = {"content-type": "text/event-stream"}
        self.text = ""
        self._lines = lines
        self._clock = clock
        self._run = run

    def iter_lines(self):
        self._clock.t += self._run
        yield from self._lines

    def read(self):
        return b""


@pytest.fixture
def wire(monkeypatch, tmp_path):
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    monkeypatch.setenv("ATLAS_USAGE_DB", str(tmp_path / "usage.db"))
    for var in [k for k in os.environ if k.startswith("ATLAS_EFFORT_") or k.endswith("_THINKING")]:
        monkeypatch.delenv(var, raising=False)
    llm.clear_api_compat_cache(memory_only=True)
    llm._REPLY_RECORD.clear()
    llm._STREAMED_THINKING.clear()
    clock = _Clock()
    monkeypatch.setattr(llm, "time", clock)
    state = SimpleNamespace(clock=clock, replies=[], sent=[])

    @contextlib.contextmanager
    def _stream(method, url, json=None, headers=None, timeout=None):
        state.sent.append(json)
        yield state.replies.pop(0)

    monkeypatch.setattr("agent.llm.httpx.stream", _stream)
    return state


def _client():
    return LLMHubClient(base_url="http://h/v1", api_key="k", model="m")


def _cut(wire, run=1.0, lines=None):
    return _SSE(lines if lines is not None else [_chunk({"content": "He"})], wire.clock, run)


# ── transport (T1 to T6) ─────────────────────────────────────────────────

def test_a_provider_error_event_is_a_failure(monkeypatch):
    lines = [_chunk({"content": "partial"}), _chunk(extra={"error": {"message": "upstream overloaded"}}),
             "data: [DONE]"]
    with pytest.raises(llm.httpx.RemoteProtocolError, match="upstream overloaded"):
        llm.assemble_stream(lines)
    with pytest.raises(llm.httpx.RemoteProtocolError, match="error"):
        llm.assemble_stream([_chunk({"content": "x"}, finish="error"), "data: [DONE]"])
    monkeypatch.setenv("ATLAS_MODEL_CALL_ESCAPE", "0")
    body = llm.assemble_stream(lines)
    assert llm.parse_response(body).content == "partial"


def test_a_failed_stream_read_is_a_stream_cut_with_its_record(wire):
    wire.replies = [_cut(wire, run=12.0, lines=[": keepalive", ": keepalive", _chunk({"content": "abc"})])]
    with pytest.raises(llm.StreamCut) as info:
        _client()._request("http://h/v1/chat/completions", {"stream": True}, 30)
    cut = info.value
    assert cut.elapsed == 12.0 and cut.chars == 3 and cut.keepalives == 2
    assert isinstance(cut, llm.httpx.RemoteProtocolError)


def test_a_fast_cut_keeps_four_attempts_without_a_final_sleep(wire):
    from core import usage_ledger
    wire.replies = [_cut(wire) for _ in range(4)]
    with usage_ledger.context(case_id="CASE-A", run_id="r1"):
        with pytest.raises(LLMTransportError) as info:
            _client().chat(MSGS, role="analyst")
    err = info.value
    assert err.kind == "cut" and err.runaway is False and len(err.attempts) == 4
    assert wire.clock.slept == [4, 8, 16]
    rows = usage_ledger.daily_rows("2000-01-01")
    assert rows[0]["lost"] == 4 and rows[0]["calls"] == 0


def test_a_long_cut_goes_to_the_caller_after_one_attempt_and_a_runaway_is_named(wire):
    client = _client()
    llm._REPLY_RECORD[("", "m", "analyst")] = 90.0
    wire.replies = [_cut(wire, run=200.0)]
    with pytest.raises(LLMTransportError) as info:
        client.chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is True and info.value.long is True and len(info.value.attempts) == 1
    wire.replies = [_cut(wire, run=150.0)]
    with pytest.raises(LLMTransportError) as info:
        client.chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is False and info.value.long is True and len(info.value.attempts) == 1


def test_a_long_cut_under_a_short_record_is_not_a_runaway(wire):
    llm._REPLY_RECORD[("", "m", "analyst")] = 20.0
    wire.replies = [_cut(wire, run=80.0)]
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is False and len(info.value.attempts) == 1


def test_a_silent_cut_is_no_runaway_when_the_model_streams_its_thinking(wire):
    llm._REPLY_RECORD[("", "m", "analyst")] = 90.0
    llm._STREAMED_THINKING.add(("", "m"))
    wire.replies = [_cut(wire, run=300.0, lines=[])]
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is False
    llm._STREAMED_THINKING.clear()
    wire.replies = [_cut(wire, run=300.0, lines=[])]
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is True


def test_a_runaway_cut_is_asked_again_one_level_lower_and_teaches_nothing(wire):
    client = _client()
    llm._REPLY_RECORD[("", "m", "analyst")] = 90.0
    wire.replies = [_cut(wire, run=200.0), _SSE(DONE, wire.clock, 5.0)]
    resp = client.chat(MSGS, role="analyst", level="high")
    assert resp.content == "ok"
    assert client.ladder_events[-1]["cut"] == "provider" and client.ladder_events[-1]["level"] == "low"
    assert llm.resolve_api_compat("", "m").level_by_role == {}
    # A runaway, then a runaway on the re-ask: raised.
    wire.replies = [_cut(wire, run=200.0), _cut(wire, run=200.0)]
    with pytest.raises(LLMTransportError) as info:
        client.chat(MSGS, role="analyst", level="high")
    assert info.value.runaway is True
    # A runaway, then a fast cut on the re-ask: four attempts, then not a runaway.
    wire.replies = [_cut(wire, run=200.0)] + [_cut(wire) for _ in range(4)]
    with pytest.raises(LLMTransportError) as info:
        client.chat(MSGS, role="analyst", level="high")
    assert info.value.runaway is False and len(info.value.attempts) >= 4
    # The first attempt's long cut is still reported to the caller.
    assert info.value.long is True


def test_no_lower_level_raises_at_once(wire):
    llm._REPLY_RECORD[("", "m", "analyst")] = 90.0
    wire.replies = [_cut(wire, run=200.0)]
    with pytest.raises(LLMTransportError):
        _client().chat(MSGS, role="analyst", level="minimal")
    assert wire.replies == []


@pytest.mark.parametrize("level, values, expected", [
    (None, (), "low"), ("high", (), "low"), ("low", (), "minimal"), ("minimal", (), None),
    ("none", (), None), ("xhigh", ("xhigh", "medium", "low"), "low"),
])
def test_the_next_lower_level(level, values, expected):
    profile = llm.ApiCompatProfile(effort_values=values)
    assert LLMHubClient._lower_level(level, profile, cut=True) == expected
    assert LLMHubClient._lower_level("low", llm.ApiCompatProfile(thinking_control=llm.THINKING_NONE),
                                     cut=True) is None


def test_the_rate_limit_budget_is_a_transport_error(wire, monkeypatch):
    monkeypatch.setattr(llm, "RATE_LIMIT_WAIT_BUDGET", 1.0)
    limited = SimpleNamespace(status_code=429, headers={"retry-after": "30"}, text="slow down", read=lambda: b"")
    wire.replies = [limited]
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst")
    assert info.value.kind == "rate_limit"
    monkeypatch.setenv("ATLAS_MODEL_CALL_ESCAPE", "0")
    wire.replies = [limited]
    with pytest.raises(llm.LLMError) as info:
        _client().chat(MSGS, role="analyst")
    assert not isinstance(info.value, LLMTransportError)


def test_the_reply_record_is_shared_between_clients(wire):
    wire.replies = [_SSE(DONE, wire.clock, 75.0)]
    _client().chat(MSGS, role="analyst")
    assert llm._REPLY_RECORD[("", "m", "analyst")] == 75.0
    wire.replies = [_cut(wire, run=200.0, lines=[])]
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst", level="minimal")
    assert info.value.runaway is False      # thinking text streamed: a silent cut proves nothing
    assert ("", "m") in llm._STREAMED_THINKING


def test_learn_false_leaves_the_compat_cache_untouched(wire, tmp_path):
    cache = tmp_path / "compat.json"
    starved = [_chunk({"reasoning_content": "x" * 10}), _chunk({}, finish="length"),
               _chunk(usage={"completion_tokens": 8192, "reasoning_tokens": 8193}, choices=False), "data: [DONE]"]
    wire.replies = [_SSE(starved, wire.clock), _SSE(DONE, wire.clock)]
    before = cache.read_bytes() if cache.exists() else b""
    _client().chat(MSGS, role="analyst", level="high", learn=False)
    after = cache.read_bytes() if cache.exists() else b""
    assert after == before
    wire.replies = [_SSE(starved, wire.clock), _SSE(DONE, wire.clock)]
    _client().chat(MSGS, role="analyst", level="high")
    assert cache.exists() and cache.read_bytes() != before     # the same climb with learn=True persists


# ── the ledger ───────────────────────────────────────────────────────────

def test_lost_rows_are_counted_apart(tmp_path, monkeypatch):
    from core import usage_ledger
    monkeypatch.setenv("ATLAS_USAGE_DB", str(tmp_path / "usage.db"))
    with usage_ledger.context(case_id="CASE-A", run_id="r1"):
        usage_ledger.record(role="analyst", provider="p", model="m", input_tokens=100, output_tokens=10)
        for _ in range(3):
            usage_ledger.record(role="analyst", provider="p", model="m", input_tokens=0, output_tokens=0,
                                usage_reported=False, status="lost")
        for _ in range(2):
            usage_ledger.record(role="analyst", provider="p", model="only-lost", input_tokens=0,
                                output_tokens=0, usage_reported=False, status="lost")
    rows = {r["model"]: r for r in usage_ledger.daily_rows("2000-01-01")}
    assert rows["m"]["calls"] == 1 and rows["m"]["lost"] == 3 and rows["m"]["unreported"] == 0
    assert rows["only-lost"]["calls"] == 0 and rows["only-lost"]["lost"] == 2
    agg = usage_ledger.aggregate(list(rows.values()), "month", {})
    assert agg["total"]["lost"] == 5 and agg["total"]["calls"] == 1
    assert len(agg["unpriced_models"]) == 1 and not any("only-lost" in m for m in agg["unpriced_models"])
    tot = usage_ledger.totals("CASE-A")
    assert tot["calls"] == 1 and tot["lost"] == 5 and tot["input_tokens"] == 100


# ── the refused tool_choice value ──────────────────────────────────

def test_a_refused_tool_choice_value_is_remembered_not_the_parameter(monkeypatch):
    body = json.dumps({"error": {"message": "tool_choice 'required' is not supported"}})
    payload = {"model": "m", "messages": MSGS, "tools": TOOLS, "tool_choice": "required"}
    out, profile = llm.adapt_payload_for_400(payload, body, profile=llm.ApiCompatProfile())
    assert out["tool_choice"] == "auto" and profile.tool_choice_rejected == ("required",)
    assert "tool_choice" not in profile.drop_params
    built = llm.build_chat_payload(model="m", messages=MSGS, tools=TOOLS, profile=profile, tool_choice="required")
    assert built["tool_choice"] == "auto"
    built = llm.build_chat_payload(model="m", messages=MSGS, tools=TOOLS, profile=profile, tool_choice="none")
    assert built["tool_choice"] == "none"
    auto = dict(payload, tool_choice="auto")
    out, profile = llm.adapt_payload_for_400(auto, body.replace("'required'", "'auto'"),
                                             profile=llm.ApiCompatProfile())
    assert "tool_choice" not in out and "tool_choice" in profile.drop_params
    monkeypatch.setenv("ATLAS_TOOL_CHOICE_VALUE_MEMORY", "0")
    out, profile = llm.adapt_payload_for_400(payload, body, profile=llm.ApiCompatProfile())
    assert "tool_choice" not in out and profile.tool_choice_rejected == ()


def test_the_rejected_values_round_trip():
    profile = llm.ApiCompatProfile(tool_choice_rejected=("required",))
    assert llm.ApiCompatProfile.from_dict(profile.to_dict()).tool_choice_rejected == ("required",)
    assert llm.ApiCompatProfile.from_dict({"completion_limit": "max_tokens"}).tool_choice_rejected == ()


# ── the analyst's escape ─────────────────────────────────────────────────

class _Toolbox:
    def openai_tools(self):
        return TOOLS

    def namespace_summary(self):
        return ""


def _reply(content="", calls=()):
    return ChatResponse(content=content, tool_calls=[ToolCall(id=f"c{i}", name=n, arguments={})
                                                     for i, n in enumerate(calls)],
                        finish_reason="tool_calls" if calls else "stop", input_tokens=1, output_tokens=1)


class _Client:
    """Scripted outcomes; records each request's messages, tools and keywords."""
    model = "fake-model"
    base_url = "http://fake"
    total_input_tokens = 0
    total_output_tokens = 0

    def __init__(self, script, *, levels=("low", "minimal", None)):
        self.script = list(script)
        self.calls: list[dict] = []
        self.ladder_events: list[dict] = []
        self.transport_events: list[dict] = []
        self._levels = list(levels)

    def chat(self, messages, tools=None, role=None, **kw):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools, **kw})
        self.ladder_events = []
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def next_lower_level(self, role, level=None):
        order = ["high", "low", "minimal"]
        if level is None:
            return "low"
        i = order.index(level) if level in order else -1
        return order[i + 1] if 0 <= i < len(order) - 1 else None


def _fast(n=1):
    return LLMTransportError("cut", kind="cut", attempts=[{"seconds": 3, "kind": "cut", "chars": 0}] * n)


def _long():
    return LLMTransportError("cut", kind="cut", long=True, attempts=[{"seconds": 95, "kind": "cut", "chars": 0}])


@pytest.fixture
def agent(tmp_path, monkeypatch):
    slept = []
    monkeypatch.setattr(loop_mod.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)

    def make(script, answered=True, quiet=True, **kw):
        client = _Client(script, **kw)
        a = Agent(client, _Toolbox(), case_dir=tmp_path, quiet=quiet)
        a._answered_in_process = answered
        a.messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "brief"}]
        a._slept = slept
        a._events = []
        a._log = lambda rec: a._events.append(dict(rec))
        return a, client
    return make


def test_one_fast_loss_is_resent_unchanged_and_recovers(agent, capsys):
    a, client = agent([_fast(), _reply("done", ["t"])])
    n = len(a.messages)
    resp = a._chat_turn_asked_again(3)
    assert resp.tool_calls and a._slept == [60.0]
    assert client.calls[1]["tools"] == TOOLS and client.calls[1].get("learn") is False
    assert "level" not in client.calls[1]
    kinds = [e["event"] for e in a._events]
    assert "llm_turn_lost" in kinds and "llm_turn_recovered" in kinds
    assert len(a.messages) == n + 1
    assert "model call answered after 1 lost request" in capsys.readouterr().err


def test_fast_losses_climb_the_rungs_and_never_wrap_up(agent):
    summary = _reply("1. CORP-WS01 ran dropper.exe, shown by the timeline call.\nNext: read the prefetch.")
    a, client = agent([_fast(), _fast(), _fast(), _fast(), summary, _reply("", ["t"])])
    original = [dict(m) for m in a.messages]
    resp = a._chat_turn_asked_again(4)
    assert resp.tool_calls
    assert a._slept == [60.0, 120.0, 240.0, 300.0]
    c = client.calls
    assert "level" not in c[1] and c[1]["tools"] == TOOLS                       # rung 0
    assert c[2]["level"] == "low" and c[2]["tools"] == TOOLS                     # rung 1
    assert c[3]["tools"] is None and "[model call failed]" in c[3]["messages"][-1]["content"]   # rung 2
    assert c[4]["tools"] is None and "shortened for this request" in c[4]["messages"][-1]["content"]  # rung 3
    assert c[4]["messages"][0] == original[0] and c[4]["messages"][1]["content"] == "brief"
    assert c[5]["tools"] == TOOLS and c[5]["tool_choice"] == "required"         # the follow-up
    assert all(call.get("learn") is False for call in c[1:])
    assert any(e.get("escape") == "progress_summary" for e in a._events)
    assert not any(m.get("content", "").startswith("[model call failed]") for m in a.messages)
    assert not any("budget_wrapup" == e["event"] for e in a._events)


def test_a_long_loss_starts_at_the_level_rung(agent):
    a, client = agent([_long(), _reply("", ["t"])])
    a._chat_turn_asked_again(2)
    assert client.calls[1]["level"] == "low"


def test_a_long_loss_after_chat_stepped_down_goes_to_the_progress_ask(agent):
    a, client = agent([_long(), _reply("summary line"), _reply("", ["t"])])
    original = client.chat

    def chat(messages, tools=None, role=None, **kw):
        out = original(messages, tools=tools, role=role, **kw)
        return out
    client.chat = chat
    client.ladder_events = [{"cut": "provider", "level": "low"}]
    real = Agent._chat_turn

    def turn(self):
        try:
            return real(self)
        except LLMTransportError:
            self.client.ladder_events = [{"cut": "provider", "level": "low"}]
            raise
    a._chat_turn = turn.__get__(a)
    a._chat_turn_asked_again(2)
    assert client.calls[1]["tools"] is None


def test_a_deadline_is_a_runaway_loss_with_the_escape_on(agent):
    a, client = agent([LLMDeadlineError("budget"), _reply("", ["t"])])
    a._chat_turn_asked_again(2)
    assert client.calls[1]["level"] == "low"


def test_a_summary_with_calls_is_the_turns_reply_and_an_empty_one_goes_to_the_follow_up(agent):
    a, client = agent([_fast(), _fast(), _fast(), _reply("", ["t"])])
    resp = a._chat_turn_asked_again(2)
    assert resp.tool_calls and len(client.calls) == 4
    # An empty summary (after _chat_turn's own identical retry) goes straight to the follow-up.
    b, client2 = agent([_fast(), _fast(), _fast(), _reply(""), _reply(""), _reply("", ["t"])])
    b._chat_turn_asked_again(2)
    assert client2.calls[-1]["tool_choice"] == "required"
    assert not any(e.get("escape") == "progress_summary" for e in b._events)


def test_the_intent_rescues_tool_choice_survives_a_resend(agent):
    a, client = agent([_fast(), _reply("", ["t"])])
    a._tool_choice_next = "required"
    a._chat_turn_asked_again(2)
    assert client.calls[0].get("tool_choice") == "required" and client.calls[1].get("tool_choice") == "required"


def test_the_run_status_carries_the_activity_during_a_pause(agent, tmp_path):
    a, client = agent([_fast(), _reply("", ["t"])])
    seen = []
    a._persist_live_status = lambda: seen.append(a.ui.run_state.get("activity"))
    a._chat_turn_asked_again(2)
    assert seen and "model call lost 1x" in seen[0] and "unchanged" in seen[0]


def test_before_the_first_answer_two_re_asks_then_a_clean_stop(agent, capsys):
    a, client = agent([_fast(), _fast(), _fast()], answered=False)
    a._answered_before = None
    with pytest.raises(LLMTransportError):
        a._chat_turn_asked_again(1)
    assert len(client.calls) == 3 and all(c["tools"] == TOOLS and "level" not in c for c in client.calls)
    assert "before the first reply" in capsys.readouterr().err


def test_a_transcript_with_an_answer_is_a_resumed_run(agent, tmp_path):
    (tmp_path / "analysis").mkdir(exist_ok=True)
    (tmp_path / "analysis" / "agent_transcript_20310304T101500Z.jsonl").write_text(
        json.dumps({"event": "assistant", "turn": 1}) + "\n")
    (tmp_path / "analysis" / "chat_transcript_20310304T101500Z.jsonl").write_text("")
    a, client = agent([_fast(), _fast(), _fast(), _reply("", ["t"])], answered=False)
    a._answered_before = None
    a.transcript_path = None
    resp = a._chat_turn_asked_again(1)
    assert resp.tool_calls
    b, _c = agent([], answered=False)
    (tmp_path / "analysis" / "agent_transcript_20310304T101500Z.jsonl").unlink()
    (tmp_path / "analysis" / "chat_transcript_20310305T101500Z.jsonl").write_text(
        json.dumps({"event": "assistant", "turn": 1}) + "\n")
    b._answered_before = None
    b.transcript_path = None
    assert b._answered_in_run() is False


def test_a_400_on_the_tool_less_ask_falls_back_to_tool_choice_none(agent):
    a, client = agent([_fast(), _fast(), _fast(), LLMStatusError("HTTP 400", status=400),
                       _reply("summary"), _reply("", ["t"])])
    a._chat_turn_asked_again(2)
    assert client.calls[3]["tools"] is None
    assert client.calls[4]["tools"] == TOOLS and client.calls[4]["tool_choice"] == "none"
    b, client2 = agent([_fast(), _fast(), _fast(), LLMStatusError("HTTP 401", status=401)])
    with pytest.raises(LLMStatusError):
        b._chat_turn_asked_again(2)


def test_the_wall_clock_stops_the_escape(agent, monkeypatch):
    a, client = agent([_fast(), _reply("", ["t"])])
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 10.0)
    a._run_start = loop_mod.time.monotonic() - 10_000
    with pytest.raises(LLMTransportError):
        a._chat_turn_asked_again(2)
    assert a._escape_stop == "wall_clock"


def test_a_minimal_client_skips_what_it_cannot_do(agent):
    class Minimal:
        def __init__(self, script):
            self.script = list(script)
            self.calls = []

        def chat(self, messages, tools=None, role=None):
            self.calls.append(tools)
            item = self.script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
    a, _ = agent([])
    a.client = Minimal([_long(), _reply("summary"), _reply("", ["t"])])
    resp = a._chat_turn_asked_again(2)
    assert resp.tool_calls and a.client.calls[1] is None    # no level rung: straight to the progress ask


def test_the_escape_alert_after_the_operator_time(agent, monkeypatch, capsys):
    monkeypatch.setenv("ATLAS_ESCAPE_ALERT_SECONDS", "1")
    clock = iter([0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0])
    real = loop_mod.time.monotonic
    monkeypatch.setattr(loop_mod.time, "monotonic", lambda: next(clock, real()))
    a, _ = agent([_fast(), _fast(), _reply("", ["t"])])
    a._persist_live_status = lambda: None
    a._chat_turn_asked_again(2)
    assert "have been failing" in capsys.readouterr().err


# ── refusal accounting and the tool_choice memory in the loop ────────────

def test_the_latch_message_is_superseded(agent, monkeypatch):
    a, _ = agent([])
    monkeypatch.setenv("ATLAS_REFUSAL_ACCOUNTING", "1")
    a._nudge("belief_starvation_latch", "[latch] record a finding")
    a._nudge("belief_starvation_latch", "[latch] record a finding")
    assert sum(1 for m in a.messages if m.get("content") == "[latch] record a finding") == 1


def test_a_rejected_required_is_logged_once(agent):
    a, client = agent([_reply("", ["t"]), _reply("", ["t"])])
    client.profile = llm.ApiCompatProfile(tool_choice_rejected=("required",))
    for _ in range(2):
        a._tool_choice_next = "required"
        a._chat_turn()
    assert [e["event"] for e in a._events].count("tool_choice_unavailable") == 1


def test_the_run_stops_cleanly_before_its_first_answer(tmp_path, monkeypatch, capsys):
    """No wrap-up message and no budget_wrapup event or marker: the run
    stops with the error, through warn even when quiet; also with a trace
    that holds pre-run tool calls and no reply."""
    monkeypatch.setattr(loop_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)
    from agent.loop import _WRAPUP_MSG
    client = _Client([_fast(), _fast(), _fast()])
    a = Agent(client, _Toolbox(), case_dir=None, quiet=True)
    a.run("sys", "user")
    assert a.stats["stopped_reason"] == "llm_transport"
    assert not any(_WRAPUP_MSG[:40] in str(m.get("content")) for m in a.messages)
    assert "agent stopped (llm_transport)" in capsys.readouterr().err


def test_an_unreachable_provider_is_kind_connect_and_a_silent_one_kind_read(wire, monkeypatch):
    def raising(exc):
        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            raise exc
            yield
        return _stream
    monkeypatch.setattr("agent.llm.httpx.stream", raising(llm.httpx.ConnectError("name lookup failed")))
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst")
    assert info.value.kind == "connect"
    monkeypatch.setattr("agent.llm.httpx.stream", raising(llm.httpx.ReadTimeout("no reply")))
    with pytest.raises(LLMTransportError) as info:
        _client().chat(MSGS, role="analyst")
    assert info.value.kind == "read"


def test_the_waf_stub_acts_on_the_shortened_copy(agent):
    from agent.llm import WAFBlockedError
    a, client = agent([])
    big = "x" * 500
    a.messages.append({"role": "tool", "tool_call_id": "c1", "content": big})
    copy_ = [dict(m) for m in a.messages]
    a._escape_messages = copy_
    client.script = [WAFBlockedError("blocked"), _reply("", ["t"])]
    a._chat_waf_tolerant()
    assert a.messages[-1]["content"] == big and copy_[-1]["content"] == loop_mod.WAF_STUB


def test_rung_three_keeps_each_trimmed_results_source(agent):
    a, _client = agent([])
    a.messages[:] = [
        {"role": "user", "content": "the case brief"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "table_table_grep",
                          "arguments": json.dumps({"path": "evidence/corp-ws01.csv", "pattern": "jane.doe"})}}]},
        {"role": "tool", "tool_call_id": "c1", "content": '{"_atlas_call_id": 41, "rows": []}' + " " * 400},
        {"role": "user", "content": "go on"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "misc_tool", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c2", "content": "recent"},
        {"role": "user", "content": "go on"}]
    a._escape_request(3, None, None, losses=1)
    trimmed = [m for m in a._escape_messages if m.get("tool_call_id") == "c1"][0]["content"]
    assert trimmed.startswith("[trimmed: table_table_grep(path=evidence/corp-ws01.csv, pattern=jane.doe), call 41")


def test_with_a_read_due_the_follow_up_names_the_ready_call(agent, monkeypatch):
    summary = _reply("1. CORP-WS01 ran dropper.exe, shown by the timeline call.\nNext: read the prefetch.")
    a, client = agent([_fast(), _fast(), _fast(), _fast(), summary, _reply("", ["t"])])
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    shown = []
    monkeypatch.setattr("core.work_order.shortest_ready",
                        lambda log, case_dir=None, params_of=None: ('ez.pecmd(directory="C/Windows/Prefetch")', 7))
    monkeypatch.setattr("core.work_order.mark_presented", lambda log, ids, moved: shown.append((ids, moved)))
    a._chat_turn_asked_again(4)
    assert client.calls[5]["messages"][-1]["content"] == (
        '[next step] Run this next, as one function call: ez.pecmd(directory="C/Windows/Prefetch")')
    assert shown == [([7], {7})]
    monkeypatch.setattr("core.work_order.shortest_ready", lambda log, case_dir=None, params_of=None: (
        "read img.raw::C/Windows/Prefetch (pass the handle as the file argument of a parser for its type)", 8))
    assert a._escape_follow_up() == ("[next step] Read this next with one function call: img.raw::C/Windows/"
                                     "Prefetch (pass the handle as the file argument of a parser for its type)")
    monkeypatch.setenv("ATLAS_WORK_ORDER", "0")
    assert a._escape_follow_up().startswith("[next step] Now issue that next step")
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    monkeypatch.setattr("core.work_order.shortest_ready", lambda log, case_dir=None, params_of=None: ("", None))
    assert a._escape_follow_up().startswith("[next step] Now issue that next step")
