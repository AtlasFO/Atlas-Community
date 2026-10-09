"""The one transport: what every role gets from LLMHubClient.chat().

No fixed completion cap, a thinking level spelled the way the endpoint takes
it, a starvation ladder that climbs once per install rather than once per
run, and a 400 negotiation that keeps the thinking option instead of dropping
it. Every case here is a table of scripted replies against captured
requests; the reply shapes follow the fixtures in tests/fixtures/llm/.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from agent import llm
from agent.llm import (EXPLICIT_CAP, THINKING_BUDGET, THINKING_ENABLE,
                       THINKING_NONE, THINKING_REASONING_OBJECT,
                       THINKING_TYPE, ApiCompatProfile, LLMHubClient,
                       build_chat_payload)
from core import llmhub

MSGS = [{"role": "user", "content": "hi"}]
TOOLS = [{"type": "function", "function": {"name": "t", "description": "d",
                                            "parameters": {"type": "object", "properties": {}}}}]


class _Reply:
    def __init__(self, body, status=200, text=""):
        self._body = body
        self.status_code = status
        self.text = text
        self.headers = {}

    def json(self):
        return self._body


def _starved(finish="length"):
    return {"choices": [{"message": {"content": "", "reasoning_content": "…"},
                         "finish_reason": finish}],
            "usage": {"completion_tokens": 8192, "reasoning_tokens": 8193}}


def _answered(reasoning_tokens=0):
    usage = {"completion_tokens": 3}
    if reasoning_tokens:
        usage["reasoning_tokens"] = reasoning_tokens
    return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": usage}


@pytest.fixture
def wire(monkeypatch, tmp_path):
    """Scripted replies in, captured requests out, a fresh compat cache."""
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    for var in [k for k in os.environ
                if k.startswith("ATLAS_EFFORT_") or k.endswith("_THINKING")
                or k == "ATLAS_LLM_MAX_OUTPUT_TOKENS"]:
        monkeypatch.delenv(var, raising=False)
    llm.clear_api_compat_cache(memory_only=True)
    state = SimpleNamespace(sent=[], replies=[])

    def _post(url, json=None, headers=None, timeout=None):
        state.sent.append(json)
        return state.replies.pop(0) if state.replies else _Reply(_answered())

    monkeypatch.setattr("agent.llm.httpx.post", _post)
    return state


def _client(model="m"):
    return LLMHubClient(base_url="http://h/v1", api_key="k", model=model)


class TestNoCapByDefault:
    def test_nothing_is_sent_unless_asked(self, wire):
        _client().chat(MSGS)
        assert "max_tokens" not in wire.sent[0]
        assert "max_completion_tokens" not in wire.sent[0]

    def test_the_operator_ceiling_is_sent(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_LLM_MAX_OUTPUT_TOKENS", "4096")
        _client().chat(MSGS)
        assert wire.sent[0]["max_tokens"] == 4096

    def test_an_explicit_argument_wins(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_LLM_MAX_OUTPUT_TOKENS", "4096")
        _client().chat(MSGS, max_tokens=256)
        assert wire.sent[0]["max_tokens"] == 256


class TestStarvationLadder:
    """Measured on the hub: the same prompt starved at 8192 and answered
    with no cap; one that still starves answers at a bounded level."""

    def test_a_role_that_answers_is_never_bounded(self, wire):
        c = _client()
        c.chat(MSGS, role="reason_synthesize")
        assert "reasoning_effort" not in wire.sent[0]
        assert c.ladder_events == []

    def test_a_default_cut_off_gets_an_explicit_ceiling_once(self, wire):
        wire.replies[:] = [_Reply(_starved("length"))]
        c = _client()
        resp = c.chat(MSGS, role="reason_synthesize")
        assert resp.content == "ok"
        assert "max_tokens" not in wire.sent[0]
        assert wire.sent[1]["max_tokens"] == EXPLICIT_CAP
        assert c.ladder_events[0]["rung"] == "explicit_cap"
        assert c.profile.needs_explicit_cap is True
        # Remembered: the next call starts with the ceiling.
        c.chat(MSGS, role="reason_synthesize")
        assert wire.sent[2]["max_tokens"] == EXPLICIT_CAP

    def test_the_level_that_answered_is_where_the_role_opens_from_then_on(self, wire):
        """A starvation the endpoint itself reported is evidence about the
        model at that level: the rung that answered is remembered per
        role, the next call opens there without climbing, and a later
        starvation climbs on from it rather than from the top."""
        wire.replies[:] = [_Reply(_starved("stop")), _Reply(_starved("stop"))]
        c = _client()
        resp = c.chat(MSGS, role="reason_synthesize", max_tokens=8192)
        assert resp.content == "ok"
        levels = [p.get("reasoning_effort") for p in wire.sent]
        assert levels == [None, "high", "low"]
        assert [e["rung"] for e in c.ladder_events] == ["lower_level", "lower_level"]
        assert c.profile.level_by_role == {"reason_synthesize": "low"}
        c.chat(MSGS, role="reason_synthesize", max_tokens=8192)
        assert wire.sent[3]["reasoning_effort"] == "low"
        assert c.ladder_events == []
        # Another role is not held to it.
        c.chat(MSGS, role="dair", max_tokens=8192)
        assert "reasoning_effort" not in wire.sent[4]
        # A further starvation climbs on from the remembered rung.
        wire.replies[:] = [_Reply(_starved("stop"))]
        c.chat(MSGS, role="reason_synthesize", max_tokens=8192)
        assert [p.get("reasoning_effort") for p in wire.sent[5:]] == ["low", "minimal"]
        assert c.profile.level_by_role == {"reason_synthesize": "minimal"}

    def test_the_learned_level_is_read_back_by_a_new_process(self, wire):
        wire.replies[:] = [_Reply(_starved("stop"))]
        _client().chat(MSGS, role="dair", max_tokens=8192)
        assert wire.sent[1]["reasoning_effort"] == "high"
        llm._compat_mem.clear()
        llm._compat_loaded = False
        _client().chat(MSGS, role="dair", max_tokens=8192)
        assert wire.sent[2]["reasoning_effort"] == "high"

    def test_a_rung_reached_through_a_cut_the_client_made_is_not_remembered(self, wire):
        """A reply the client closed for runaway thinking, or that the
        connection cut, says nothing sure about the level: the rescue
        serves that call with less thinking (never "high", which from an
        unset level would be more), and the next one opens where it did."""
        wire.replies[:] = [_Reply({**_starved("length"), "atlas_cut": "thinking_bound"})]
        c = _client()
        resp = c.chat(MSGS, role="dair", max_tokens=8192)
        assert resp.content == "ok"
        assert [p.get("reasoning_effort") for p in wire.sent] == [None, "low"]
        assert c.profile.level_by_role == {}
        c.chat(MSGS, role="dair", max_tokens=8192)
        assert "reasoning_effort" not in wire.sent[2]

    def test_a_level_that_answered_only_with_compacted_input_is_not_remembered(self, wire):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            effort_values=("none", "high")), persist=False)
        wire.replies[:] = [_Reply(_starved("stop")), _Reply(_starved("stop"))]
        c = _client()
        c.chat(MSGS, role="dair", max_tokens=8192,
               compact=lambda msgs: [{"role": "user", "content": "short"}])
        assert c.ladder_events[-1]["rung"] == "compact_input"
        assert c.profile.level_by_role == {}

    def test_a_configured_level_wins_over_a_learned_one(self, wire, monkeypatch):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            level_by_role={"dair": "low"}), persist=False)
        monkeypatch.setenv("ATLAS_EFFORT_DAIR", "high")
        _client().chat(MSGS, role="dair")
        assert wire.sent[0]["reasoning_effort"] == "high"

    def test_a_provider_pin_wins_over_a_learned_level(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "http://h/v1")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "k")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_MODEL", "m")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_THINKING", "high")
        llm.remember_api_compat("gw", "m", ApiCompatProfile(
            level_by_role={"dair": "low"}), persist=False)
        LLMHubClient(provider="gw").chat(MSGS, role="dair")
        assert wire.sent[0]["reasoning_effort"] == "high"

    def test_the_ladder_stays_inside_the_values_the_endpoint_listed(self, wire):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            effort_values=("none", "high")), persist=False)
        wire.replies[:] = [_Reply(_starved("stop")), _Reply(_starved("stop"))]
        c = _client()
        c.chat(MSGS, role="dair", max_tokens=8192,
               compact=lambda msgs: [{"role": "user", "content": "short"}])
        levels = [p.get("reasoning_effort") for p in wire.sent]
        assert levels[:2] == [None, "high"]
        # "low" is not on the list, so the next rung is the compacted input.
        assert wire.sent[2]["messages"] == [{"role": "user", "content": "short"}]
        assert c.ladder_events[-1]["rung"] == "compact_input"

    def test_a_starved_call_with_no_way_out_returns_the_starved_reply(self, wire):
        wire.replies[:] = [_Reply(_starved("stop"))] * 6
        resp = _client().chat(MSGS, role="dair", max_tokens=8192)
        assert resp.starved is True
        assert resp.content == ""
        assert "reasoning_tokens=8193" in resp.starved_reason()

    def test_a_configured_level_is_what_a_call_opens_with(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_EFFORT_DAIR", "high")
        _client().chat(MSGS, role="dair")
        assert wire.sent[0]["reasoning_effort"] == "high"

    def test_a_provider_pin_applies_when_no_role_override_exists(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "http://h/v1")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "k")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_MODEL", "m")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_THINKING", "low")
        LLMHubClient(provider="gw").chat(MSGS, role="dair")
        assert wire.sent[0]["reasoning_effort"] == "low"

    def test_thinking_is_remembered_as_observed(self, wire):
        wire.replies[:] = [_Reply(_answered(reasoning_tokens=12))]
        c = _client()
        assert c.profile.reasoning_observed is False
        c.chat(MSGS)
        assert c.profile.reasoning_observed is True


class TestEffortNegotiation:
    """A 400 about the level keeps the level; only a 400 about the option
    drops the option."""

    def test_a_listed_value_is_taken_instead_of_dropping_the_option(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_EFFORT_DAIR", "low")
        wire.replies[:] = [_Reply({}, 400, '{"error":{"message":"reasoning_effort=low is not '
                                             'supported by Mistral models. Supported values are: '
                                             "['none', 'high'].\"}}")]
        c = _client()
        c.chat(MSGS, role="dair")
        assert wire.sent[0]["reasoning_effort"] == "low"
        assert wire.sent[1]["reasoning_effort"] == "high"
        assert c.profile.effort_values == ("none", "high")

    def test_a_model_that_cannot_stop_thinking_is_asked_for_the_least(self, wire):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            reasoning_effort="none"), persist=False)
        wire.replies[:] = [_Reply({}, 400, '{"error":{"message":"Reasoning is mandatory for '
                                             'this endpoint and cannot be disabled."}}')]
        c = _client()
        c.chat(MSGS, tools=TOOLS)
        assert wire.sent[0]["reasoning_effort"] == "none"
        assert wire.sent[1]["reasoning_effort"] == "low"
        assert c.profile.reasoning_effort is None

    def test_a_cap_below_the_thinking_budget_is_raised_and_remembered(self, wire):
        wire.replies[:] = [_Reply({}, 400, '{"error":{"message":"`max_tokens` must be greater '
                                             'than `thinking.budget_tokens`."}}')]
        c = _client()
        c.chat(MSGS, max_tokens=512)
        assert wire.sent[0]["max_tokens"] == 512
        assert wire.sent[1]["max_tokens"] == EXPLICIT_CAP
        assert c.profile.needs_explicit_cap is True

    def test_an_option_named_as_unsupported_is_dropped_and_remembered(self, wire):
        wire.replies[:] = [_Reply({}, 400, '{"error": "response_format is not supported"}')]
        c = _client()
        c.chat(MSGS, response_format={"type": "json_object"})
        assert "response_format" in wire.sent[0]
        assert "response_format" not in wire.sent[1]
        assert "response_format" in c.profile.drop_params


class TestThinkingControls:
    """One level, spelled the way each endpoint takes it."""

    def _body(self, control, level="low", tools=None):
        return build_chat_payload(model="m", messages=MSGS, tools=tools,
                                  profile=ApiCompatProfile(thinking_control=control),
                                  thinking_level=level)

    def test_reasoning_object_for_openrouter(self):
        assert self._body(THINKING_REASONING_OBJECT)["reasoning"] == {"effort": "low"}

    def test_thinking_type_for_zai_and_deepseek(self):
        body = self._body(THINKING_TYPE)
        assert body["thinking"] == {"type": "enabled"}
        assert body["reasoning_effort"] == "low"
        assert self._body(THINKING_TYPE, "none")["thinking"] == {"type": "disabled"}

    def test_enable_thinking_for_dashscope(self):
        assert self._body(THINKING_ENABLE)["enable_thinking"] is True
        assert self._body(THINKING_ENABLE, "none")["enable_thinking"] is False

    def test_budget_for_anthropic_compat(self):
        assert self._body(THINKING_BUDGET, "high")["thinking"] == {
            "type": "enabled", "budget_tokens": 16384}

    def test_no_control_sends_nothing(self):
        body = self._body(THINKING_NONE)
        assert not any(k in body for k in ("reasoning_effort", "reasoning", "thinking",
                                           "enable_thinking"))

    def test_default_level_sends_nothing(self):
        assert "reasoning_effort" not in self._body(llm.THINKING_REASONING_EFFORT, "default")

    def test_a_pinned_none_keeps_its_pin_on_tool_turns_only(self):
        prof = ApiCompatProfile(reasoning_effort="none")
        with_tools = build_chat_payload(model="m", messages=MSGS, tools=TOOLS,
                                        profile=prof, thinking_level="high")
        assert with_tools["reasoning_effort"] == "none"
        bare = build_chat_payload(model="m", messages=MSGS, profile=prof,
                                  thinking_level="high")
        assert bare["reasoning_effort"] == "high"


class TestProfileRoundTrip:
    def test_new_fields_survive_the_cache(self):
        prof = ApiCompatProfile(thinking_control=THINKING_TYPE, effort_values=("low", "high"),
                                echo_fields=("reasoning_content",), needs_explicit_cap=True,
                                reasoning_observed=True, level_by_role={"agent": "high"})
        back = ApiCompatProfile.from_dict(prof.to_dict())
        assert back.thinking_control == THINKING_TYPE
        assert back.effort_values == ("low", "high")
        assert back.echo_fields == ("reasoning_content",)
        assert back.needs_explicit_cap and back.reasoning_observed
        assert back.level_by_role == {"agent": "high"}

    def test_a_learned_level_that_is_not_a_role_to_level_map_is_dropped(self):
        assert ApiCompatProfile.from_dict({"level_by_role": ["high"]}).level_by_role == {}
        back = ApiCompatProfile.from_dict(
            {"level_by_role": {"agent": 3, "dair": "", "report": "low"}})
        assert back.level_by_role == {"report": "low"}

    def test_a_level_an_older_cache_pinned_per_role_is_not_read(self):
        """A cache written when the ladder still pinned its rescue level
        per role loads without that pin."""
        back = ApiCompatProfile.from_dict({"effort_by_role": {"agent": "low"}})
        assert "effort_by_role" not in back.to_dict()

    def test_an_old_cache_entry_still_loads(self):
        back = ApiCompatProfile.from_dict({"completion_limit": "max_completion_tokens",
                                           "send_temperature": False, "drop_params": []})
        assert back.completion_limit == "max_completion_tokens"
        assert back.thinking_control == llm.THINKING_REASONING_EFFORT
        assert back.max_tools is None

    def test_the_learned_tool_count_survives_the_cache(self):
        back = ApiCompatProfile.from_dict(ApiCompatProfile(max_tools=96).to_dict())
        assert back.max_tools == 96
        assert ApiCompatProfile.from_dict({"max_tools": "lots"}).max_tools is None


class _SSEReply:
    """A streamed reply: the lines a gateway sends, one event per line."""

    def __init__(self, lines, status=200, fail_after=None):
        self.status_code = status
        self.headers = {"content-type": "text/event-stream"}
        self._lines = list(lines)
        self._fail_after = fail_after
        self.text = ""

    def iter_lines(self):
        for i, line in enumerate(self._lines):
            if self._fail_after is not None and i >= self._fail_after:
                raise llm.httpx.ReadTimeout("no chunk for too long")
            yield line

    def read(self):
        return b""


def _chunk(delta=None, finish=None, usage=None, choices=True):
    body = {"id": "s1", "object": "chat.completion.chunk", "model": "m",
            "choices": ([{"index": 0, "delta": delta or {}, "finish_reason": finish}]
                        if choices else [])}
    if usage is not None:
        body["usage"] = usage
    return "data: " + __import__("json").dumps(body)


_TOOL_STREAM = [
    _chunk({"role": "assistant", "content": ""}),
    _chunk({"reasoning_content": "The user wants "}),
    _chunk({"reasoning_content": "a call."}),
    _chunk({"tool_calls": [{"id": "call_1", "index": 0, "type": "function",
                            "function": {"name": "t", "arguments": ""}}]}),
    _chunk({"tool_calls": [{"index": 0, "function": {"arguments": "{\"word\": "}}]}),
    _chunk({"tool_calls": [{"index": 0, "function": {"arguments": "\"hello\"}"}}]}),
    _chunk({}, finish="tool_calls"),
    _chunk(usage={"prompt_tokens": 161, "completion_tokens": 31, "reasoning_tokens": 21},
           choices=False),
    "",
    "data: [DONE]",
]


class TestStreaming:
    """A chat completion is streamed so the read timeout guards silence
    between chunks, not the length of a reply, and the stream folds back
    into the one body shape the parser reads."""

    def test_a_stream_folds_into_one_reply(self):
        body = llm.assemble_stream(_TOOL_STREAM)
        parsed = llm.parse_response(body)
        assert [(tc.name, tc.arguments) for tc in parsed.tool_calls] == [("t", {"word": "hello"})]
        assert parsed.finish_reason == "tool_calls" and parsed.content == ""
        assert parsed.reasoning == "The user wants a call."
        assert (parsed.input_tokens, parsed.output_tokens, parsed.reasoning_tokens) == (161, 31, 21)

    def test_text_deltas_are_joined_in_order(self):
        body = llm.assemble_stream([_chunk({"content": "Hel"}), _chunk({"content": "lo"}),
                                    _chunk({}, finish="stop"), "data: [DONE]"])
        assert llm.parse_response(body).content == "Hello"

    def test_the_client_streams_by_default_and_reads_the_folded_reply(self, wire, monkeypatch):
        import contextlib
        seen = {}

        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            seen["payload"] = json
            seen["timeout"] = timeout
            yield _SSEReply(_TOOL_STREAM)

        monkeypatch.setattr("agent.llm.httpx.stream", _stream)
        parsed = _client().chat(MSGS, tools=TOOLS)
        assert seen["payload"]["stream"] is True
        assert seen["payload"]["stream_options"] == {"include_usage": True}
        assert [tc.name for tc in parsed.tool_calls] == ["t"]

    def test_silence_mid_stream_is_retried_from_the_start(self, wire, monkeypatch):
        import contextlib
        replies = [_SSEReply(_TOOL_STREAM, fail_after=3), _SSEReply(_TOOL_STREAM)]
        attempts = []

        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            attempts.append(1)
            yield replies.pop(0)

        monkeypatch.setattr("agent.llm.httpx.stream", _stream)
        monkeypatch.setattr(llm.time, "sleep", lambda s: None)
        parsed = _client().chat(MSGS, tools=TOOLS)
        assert len(attempts) == 2 and [tc.name for tc in parsed.tool_calls] == ["t"]

    def test_a_stream_cut_off_before_it_finished_is_retried(self, wire, monkeypatch):
        """A connection that closes with no finish reason and no [DONE]
        delivered no reply: the client asks again rather than handing the
        loop an empty or half-written one."""
        import contextlib
        cut = [_chunk({"role": "assistant", "content": ""}), _chunk({"content": "Hel"})]
        replies = [_SSEReply(cut), _SSEReply(_TOOL_STREAM)]
        attempts = []

        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            attempts.append(1)
            yield replies.pop(0)

        monkeypatch.setattr("agent.llm.httpx.stream", _stream)
        monkeypatch.setattr(llm.time, "sleep", lambda s: None)
        parsed = _client().chat(MSGS, tools=TOOLS)
        assert len(attempts) == 2 and [tc.name for tc in parsed.tool_calls] == ["t"]
        with pytest.raises(llm.httpx.RemoteProtocolError):
            llm.assemble_stream(cut)

    def test_a_stream_cut_after_real_output_is_a_cut_reply(self):
        """Output that ran past the threshold and then lost its connection
        is a reply the gateway cut, not a lost one: it comes back as if the
        output limit had been reached, and a second attempt is not made."""
        long = [_chunk({"role": "assistant", "content": ""}),
                _chunk({"content": "x" * 3000})]
        parsed = llm.parse_response(llm.assemble_stream(long))
        assert parsed.finish_reason == "length" and len(parsed.content) == 3000
        assert parsed.cut_reason == "stream_end"

    def test_unparseable_arguments_are_kept_only_in_part(self):
        """A call whose arguments are not JSON is refused with its head; the
        whole string never goes back into the history as the call made."""
        raw = "{\"a\": [" + ", ".join(str(i) for i in range(20000))
        body = {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "t", "arguments": raw}}]},
            "finish_reason": "tool_calls"}], "usage": {}}
        args = llm.parse_response(body).tool_calls[0].arguments
        kept = args["_malformed_arguments"]
        assert len(kept) < llm.MALFORMED_ARGUMENTS_KEEP + 60
        assert kept.startswith(raw[:100]) and kept.endswith("characters, cut]")

    def test_a_cut_argument_text_names_the_parameter_that_took_most_of_it(self):
        """The head of a cut argument text says nothing about which
        parameter ran away; the parsed call names the one whose value
        spans the most characters, with its size, so a retry knows what
        to shorten. A text short enough to keep whole carries no note."""
        ids = ", ".join(str(i) for i in range(20000))
        raw = "{\"summary\": \"short\", \"input_call_ids\": [" + ids
        body = {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "t", "arguments": raw}}]},
            "finish_reason": "length"}], "usage": {}}
        args = llm.parse_response(body).tool_calls[0].arguments
        assert args["_longest_argument"] == f"input_call_ids ({len(ids) + 1} characters)"
        assert "_longest_argument" not in llm.malformed_arguments("{\"a\": [1, 2")

    def test_the_longest_argument_is_measured_at_the_top_level_only(self):
        """Keys inside a nested value and quotes escaped inside a string
        are part of the value they sit in, never parameters of their own;
        an object that closed cleanly and a text cut inside a string both
        measure."""
        assert llm.longest_argument('{"a": [1, 2], "b": 3}') == ("a", 6)
        assert llm.longest_argument('{"a": {"b": "xxxxxxxxxx"}, "c": "yy"}') == ("a", 19)
        assert llm.longest_argument('{"a": "q\\"uote", "b": "1"}') == ("a", 9)
        assert llm.longest_argument('{"a": "x", "b": "abc def ghi') == ("b", 12)
        assert llm.longest_argument("{oops") == ("", 0)

    def test_thinking_far_past_the_roles_own_record_is_cut(self):
        """Thinking that runs past the limit with no answer begun closes
        the stream and reads as a cut reply; the same amount with an
        answer under way is left alone."""
        consumed = []

        def _lines(chunks):
            for c in chunks:
                consumed.append(1)
                yield c
        thinking = [_chunk({"reasoning_content": "still weighing it "})] * 40
        body = llm.assemble_stream(_lines(thinking + [_chunk({}, finish="stop"), "data: [DONE]"]),
                                   reasoning_limit=100)
        assert body["choices"][0]["finish_reason"] == "length" and len(consumed) < 40
        assert llm.parse_response(body).cut_reason == "thinking_bound"
        assert llm.parse_response(llm.assemble_stream(_TOOL_STREAM)).cut_reason == ""
        consumed.clear()
        answering = [_chunk({"content": "The answer "})] + thinking
        body = llm.assemble_stream(_lines(answering + [_chunk({}, finish="stop"), "data: [DONE]"]),
                                   reasoning_limit=100)
        assert body["choices"][0]["finish_reason"] == "stop" and len(consumed) == 43

    def test_the_limit_is_set_by_what_the_role_completed_before(self, wire, monkeypatch):
        """No limit before a role has answered; afterwards a reply whose
        thinking runs past three times that answer's thinking is cut and
        handed to the starvation ladder."""
        import contextlib
        seen = []

        def _reply(chars):
            # Thinking without a short period: a repeated character would
            # read as degenerate, which is a different cut.
            text = "".join(f"{i}," for i in range(chars))[:chars]
            return _SSEReply([_chunk({"reasoning_content": text}),
                              _chunk({"content": "ok"}), _chunk({}, finish="stop"),
                              _chunk(usage={"completion_tokens": 3}, choices=False),
                              "data: [DONE]"])
        floor = llm.REASONING_RUNAWAY_FLOOR_CHARS
        replies = [_reply(100), _reply(floor)] + [_reply(3 * floor + 1)] * 8

        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            seen.append(1)
            yield replies.pop(0)

        monkeypatch.setattr("agent.llm.httpx.stream", _stream)
        monkeypatch.setattr(llm.time, "sleep", lambda s: None)
        client = _client()
        first = client.chat(MSGS, role="analyst")
        assert first.content == "ok" and client._reasoning_seen["analyst"] == 100
        # A trivial first reply sets no bound: the next one, thinking far
        # more, still answers, and becomes the record.
        warm = client.chat(MSGS, role="analyst")
        assert warm.content == "ok" and client._reasoning_seen["analyst"] == floor
        # Past three times a substantial record the reply is cut before its
        # answer, and the ladder tries again.
        second = client.chat(MSGS, role="analyst")
        assert second.content == "" and second.finish_reason == "length"
        assert len(seen) >= 4          # two answered calls plus the ladder's rungs
        # Another role starts without a limit.
        other = client.chat(MSGS, role="dair")
        assert other.content == "ok"

    def test_a_gateway_that_answers_a_stream_request_with_a_plain_body_is_read_as_such(self, wire):
        # The shared fixture routes stream requests to the plain fake reply.
        parsed = _client().chat(MSGS)
        assert parsed.content == "ok" and wire.sent[0]["stream"] is True

    def test_streaming_can_be_switched_off(self, wire, monkeypatch):
        monkeypatch.setenv("ATLAS_LLM_STREAM", "0")
        _client().chat(MSGS)
        assert "stream" not in wire.sent[0]


class TestReplyBounds:
    """A streamed reply is bounded in time by its share of the budget and
    in shape by a repetition check; a cut the client makes is re-asked once
    with less thinking and then returned, and never teaches the profile
    that the endpoint needs a cap."""

    def _clock(self, monkeypatch, start=0.0, step=1.0):
        state = {"now": start}

        def _monotonic():
            state["now"] += step
            return state["now"]
        monkeypatch.setattr(llm.time, "monotonic", _monotonic)
        return state

    def test_a_keepalive_only_stream_is_cut_at_the_deadline(self, monkeypatch):
        """Comment lines and blanks never carry a delta, so the clock is
        read before the event filter: an endless keepalive stream ends at
        the deadline instead of holding the request open."""
        self._clock(monkeypatch)

        def _keepalives():
            while True:
                yield ": keepalive"
                yield ""
        body = llm.assemble_stream(_keepalives(), deadline=5.0)
        parsed = llm.parse_response(body)
        assert parsed.cut_reason == "deadline" and parsed.finish_reason == "length"
        assert parsed.content == "" and parsed.starved

    def test_a_deadline_with_output_begun_keeps_the_head_and_drops_an_empty_call(self, monkeypatch):
        self._clock(monkeypatch)
        piece = "".join(chr(ord("a") + (i * 7) % 26) for i in range(200))
        lines = [_chunk({"content": piece}) for _ in range(30)]
        lines.append(_chunk({"tool_calls": [{"id": "c1", "index": 0, "type": "function",
                                             "function": {"name": "t", "arguments": ""}}]}))
        lines += [_chunk({"content": piece}) for _ in range(30)]
        body = llm.assemble_stream(lines + [_chunk({}, finish="stop"), "data: [DONE]"],
                                   deadline=40.0)
        parsed = llm.parse_response(body)
        assert parsed.cut_reason == "deadline" and parsed.finish_reason == "length"
        assert 0 < len(parsed.content) <= llm.CUT_CONTENT_KEEP
        assert parsed.tool_calls == [] and not parsed.starved

    def test_a_periodic_stream_is_cut_and_its_text_dropped(self):
        bangs = [_chunk({"content": "!" * 100}) for _ in range(60)]
        consumed = []

        def _lines(chunks):
            for c in chunks:
                consumed.append(1)
                yield c
        body = llm.assemble_stream(_lines(bangs + [_chunk({}, finish="stop"), "data: [DONE]"]))
        parsed = llm.parse_response(body)
        assert parsed.cut_reason == "degenerate" and parsed.finish_reason == "length"
        assert parsed.content == "" and parsed.starved and len(consumed) < 60
        # The same period inside the thinking is caught before any answer.
        thinking = [_chunk({"reasoning_content": "over and over "}) for _ in range(400)]
        body = llm.assemble_stream(thinking + [_chunk({"content": "late"}), _chunk({}, finish="stop"),
                                               "data: [DONE]"])
        parsed = llm.parse_response(body)
        assert parsed.cut_reason == "degenerate" and parsed.reasoning == "" and parsed.content == ""
        # Long text without a short period is left alone.
        prose = [_chunk({"content": f"line {i} of the story, {i * i} words in; "}) for i in range(400)]
        parsed = llm.parse_response(llm.assemble_stream(prose + [_chunk({}, finish="stop"), "data: [DONE]"]))
        assert parsed.cut_reason == "" and parsed.finish_reason == "stop"

    def _streams(self, monkeypatch, replies):
        import contextlib
        sent = []

        @contextlib.contextmanager
        def _stream(method, url, json=None, headers=None, timeout=None):
            sent.append(json)
            yield replies.pop(0)
        monkeypatch.setattr("agent.llm.httpx.stream", _stream)
        monkeypatch.setattr(llm.time, "sleep", lambda s: None)
        return sent

    @staticmethod
    def _degenerate():
        return _SSEReply([_chunk({"content": "!" * 100}) for _ in range(60)]
                         + [_chunk({}, finish="stop"), "data: [DONE]"])

    @staticmethod
    def _ok():
        return _SSEReply([_chunk({"content": "ok"}), _chunk({}, finish="stop"),
                          _chunk(usage={"completion_tokens": 2}, choices=False), "data: [DONE]"])

    def test_a_client_cut_is_re_asked_once_with_less_thinking(self, wire, monkeypatch):
        sent = self._streams(monkeypatch, [self._degenerate(), self._ok(), self._ok()])
        c = _client()
        reply = c.chat(MSGS, role="analyst")
        assert reply.content == "ok" and len(sent) == 2
        # From an unset level the re-ask skips "high"; nothing learned.
        assert sent[0].get("reasoning_effort") is None
        assert sent[1].get("reasoning_effort") == "low"
        assert "max_tokens" not in sent[1]
        assert c.profile.needs_explicit_cap is False
        rungs = [e["rung"] for e in c.ladder_events]
        assert rungs == ["lower_level"]
        c.chat(MSGS, role="analyst")
        assert sent[2].get("reasoning_effort") is None and "max_tokens" not in sent[2]

    def test_a_second_cut_in_the_same_call_returns_the_reply(self, wire, monkeypatch):
        sent = self._streams(monkeypatch, [self._degenerate(), self._degenerate(), self._ok()])
        c = _client()
        reply = c.chat(MSGS, role="analyst")
        assert len(sent) == 2
        assert reply.starved and reply.content == "" and reply.cut_reason == "degenerate"
        assert reply.finish_reason == "length"
        assert c.ladder_events[-1]["rung"] == "cut_returned"
        assert c.profile.needs_explicit_cap is False
        assert all("max_tokens" not in p for p in sent)

    def test_the_reply_deadline_is_a_share_of_the_budget(self, wire, monkeypatch):
        seen = {}

        def _assemble(lines, *, reasoning_limit=0, deadline=None):
            seen["deadline"] = deadline
            return {"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"},
                                 "finish_reason": "stop"}], "usage": {"completion_tokens": 2}}
        monkeypatch.setattr(llm, "assemble_stream", _assemble)
        self._streams(monkeypatch, [self._ok()])
        state = self._clock(monkeypatch, step=0.0)
        c = _client()
        c.turn_time_budget = 100.0
        c.chat(MSGS, role="analyst")
        assert seen["deadline"] == pytest.approx(state["now"] + 100.0 * llm.REPLY_SHARE)


class TestEnvOverrideKeepsWhatWasLearned:
    """An environment override forces one dimension of the profile; the
    rest of what the cache learned about the model, the tool ceiling
    above all, stays and survives the next store."""

    def test_the_tool_ceiling_survives_an_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
        llm.clear_api_compat_cache(memory_only=True)
        llm.remember_api_compat("p", "m", llm.ApiCompatProfile(
            completion_limit="max_tokens", send_temperature=True,
            max_tools=54, reasoning_observed=True))
        monkeypatch.setenv("ATLAS_LLM_ALLOW_TEMPERATURE", "0")
        resolved = llm.resolve_api_compat("p", "m")
        assert resolved.source == "env" and resolved.send_temperature is False
        assert resolved.max_tools == 54 and resolved.reasoning_observed is True
        # A later store of the resolved profile keeps the ceiling on disk.
        llm.remember_api_compat("p", "m", resolved)
        llm._compat_mem.clear()
        llm._compat_loaded = False           # read the file back like a new process
        monkeypatch.delenv("ATLAS_LLM_ALLOW_TEMPERATURE")
        assert llm.resolve_api_compat("p", "m").max_tools == 54


class TestTheCompatFileIsShared:
    """Runs, the dashboard and the CLI all read and write one file. A save
    writes what this process learned over what is on disk; it never dumps
    its memory over another process's learning, and never overwrites a
    file it could not read."""

    @staticmethod
    def _new_process():
        llm._compat_mem.clear()
        llm._compat_dirty.clear()
        llm._compat_loaded = False

    def test_two_processes_learning_different_models_keep_both(self, tmp_path, monkeypatch):
        path = tmp_path / "compat.json"
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(path))
        self._new_process()
        llm.remember_api_compat("p", "a", llm.ApiCompatProfile(max_tools=54))
        self._new_process()                       # a second process starts, reads the file
        llm._load_compat_cache()
        # ... while a third process (the first, still running) learns more.
        json_now = __import__("json").loads(path.read_text())
        json_now["models"]["p|a"]["max_tools"] = 60
        path.write_text(__import__("json").dumps(json_now))
        llm.remember_api_compat("p", "b", llm.ApiCompatProfile(reasoning_observed=True))
        on_disk = __import__("json").loads(path.read_text())["models"]
        assert on_disk["p|a"]["max_tools"] == 60          # not clobbered by the stale copy
        assert on_disk["p|b"]["reasoning_observed"] is True
        self._new_process()
        assert llm.resolve_api_compat("p", "a").max_tools == 60

    def test_a_file_that_cannot_be_read_is_not_overwritten(self, tmp_path, monkeypatch):
        path = tmp_path / "compat.json"
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(path))
        self._new_process()
        path.write_text("{not json")
        llm.remember_api_compat("p", "a", llm.ApiCompatProfile(max_tools=54))
        assert path.read_text() == "{not json"
        assert llm.resolve_api_compat("p", "a").max_tools == 54   # kept in memory


class TestLearnedToolCount:
    """The client remembers the schema count a model answered at, per
    provider and model; the loop moves it down after a cut that answered
    and up after a test past it that answered."""

    def test_learn_moves_on_evidence_in_both_directions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
        llm.clear_api_compat_cache(memory_only=True)
        client = llm.LLMHubClient(base_url="http://h", api_key="k", model="m")
        assert client.learned_max_tools() is None
        client.learn_max_tools(100)
        assert client.learned_max_tools() == 100
        client.learn_max_tools(120)
        assert client.learned_max_tools() == 120
        client.learn_max_tools(80)
        assert client.learned_max_tools() == 80
        assert (tmp_path / "compat.json").is_file()


class TestEndpointPaths:
    """A bare host gets /v1; any base that carries a path is appended to."""

    @pytest.mark.parametrize("base, chat", [
        ("https://api.deepseek.com", "https://api.deepseek.com/v1/chat/completions"),
        ("https://generativelanguage.googleapis.com/v1beta/openai",
         "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
        ("https://api.z.ai/api/paas/v4/", "https://api.z.ai/api/paas/v4/chat/completions"),
        ("https://api.llama.com/compat/v1", "https://api.llama.com/compat/v1/chat/completions"),
        ("http://localhost:11434", "http://localhost:11434/v1/chat/completions"),
    ])
    def test_chat_url(self, base, chat):
        assert llmhub.build_chat_url(base) == chat

    def test_models_url_follows_the_same_rule(self):
        assert (llmhub.build_models_url("https://generativelanguage.googleapis.com/v1beta/openai")
                == "https://generativelanguage.googleapis.com/v1beta/openai/models")


class TestKeylessLocalEndpoint:
    def test_an_explicit_endpoint_without_a_key_sends_no_auth_header(self, wire, monkeypatch):
        seen = {}

        def _post(url, json=None, headers=None, timeout=None):
            seen.update(headers or {})
            return _Reply(_answered())

        monkeypatch.setattr("agent.llm.httpx.post", _post)
        LLMHubClient(base_url="http://localhost:8000/v1", api_key="", model="m").chat(MSGS)
        assert "Authorization" not in seen


def test_the_wire_can_be_dumped_for_reading(wire, monkeypatch, tmp_path):
    """With ATLAS_LLM_WIRE_DIR set, every request is written next to the
    reply it got, so a run whose replies the loop cannot use can be read
    from the wire itself."""
    where = tmp_path / "wire"
    monkeypatch.setenv("ATLAS_LLM_WIRE_DIR", str(where))
    _client().chat(MSGS, role="dair")
    files = sorted(f.name for f in where.iterdir())
    assert any(f.endswith(".request.json") for f in files)
    assert any(f.endswith((".stream.txt", ".reply.txt")) for f in files)
    request = json.loads(next(where.glob("*.request.json")).read_text())
    assert request["messages"] == MSGS


def test_a_required_tool_choice_reaches_the_wire(wire):
    """The loop can ask for the function channel outright; by default the
    choice stays with the model."""
    tools = [{"type": "function", "function": {"name": "t", "parameters": {"type": "object"}}}]
    c = _client()
    c.chat(MSGS, tools=tools)
    c.chat(MSGS, tools=tools, tool_choice="required")
    assert wire.sent[0]["tool_choice"] == "auto"
    assert wire.sent[1]["tool_choice"] == "required"


_REFUSED_BUDGET = ('{"type":"error","error":{"type":"invalid_request_error","message":'
                   '"\\"thinking.type.enabled\\" is not supported for this model. Use '
                   '\\"thinking.type.adaptive\\" and \\"output_config.effort\\" to control '
                   'thinking behavior."}}')
_REFUSED_DISABLED = _REFUSED_BUDGET.replace("thinking.type.enabled", "thinking.type.disabled")


class TestARefusedThinkingObject:
    """A model that refuses the thinking object itself (the vendor's documented
    400) is driven without one from then on; a cap below the budget is a
    different 400 and still raises the cap."""

    def test_a_refused_budget_is_dropped_and_remembered(self, wire):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            thinking_control=THINKING_BUDGET), persist=False)
        wire.replies[:] = [_Reply({}, 400, _REFUSED_BUDGET)]
        c = _client()
        assert c.chat(MSGS, role="reason_cite_check").content == "ok"
        assert wire.sent[0]["thinking"] == {"type": "enabled", "budget_tokens": 2048}
        assert "thinking" not in wire.sent[1]
        assert c.profile.thinking_control == THINKING_NONE
        assert c.profile.needs_explicit_cap is False
        c.chat(MSGS, role="reason_cite_check")
        assert "thinking" not in wire.sent[2]

    def test_a_refused_disabled_object_is_dropped(self):
        payload = {"model": "m", "messages": MSGS, "thinking": {"type": "disabled"}}
        out, prof = llm.adapt_payload_for_400(payload, _REFUSED_DISABLED)
        assert "thinking" not in out and prof.thinking_control == THINKING_NONE

    def test_a_cap_below_the_budget_keeps_the_thinking(self):
        payload = {"model": "m", "messages": MSGS, "max_tokens": 512,
                   "thinking": {"type": "enabled", "budget_tokens": 2048}}
        out, prof = llm.adapt_payload_for_400(
            payload, '{"error":{"message":"`max_tokens` must be greater than '
                     '`thinking.budget_tokens`."}}')
        assert out["thinking"] == payload["thinking"] and out["max_tokens"] == EXPLICIT_CAP
        assert prof.thinking_control != THINKING_NONE

    def test_a_payload_without_thinking_is_left_alone(self):
        assert llm.adapt_payload_for_400({"model": "m", "messages": MSGS}, _REFUSED_BUDGET) is None

    def test_the_learned_control_survives_the_cache_round_trip(self):
        prof = ApiCompatProfile.from_dict(ApiCompatProfile(thinking_control=THINKING_NONE).to_dict())
        assert prof.thinking_control == THINKING_NONE

    def test_the_anthropic_preset_sends_no_temperature(self, wire):
        body = build_chat_payload(model="example-model", messages=MSGS, provider="anthropic")
        assert "temperature" not in body

    def test_no_level_rungs_for_a_model_without_a_thinking_control(self, wire):
        llm.remember_api_compat("default", "m", ApiCompatProfile(
            thinking_control=THINKING_NONE), persist=False)
        wire.replies[:] = [_Reply(_starved("stop"))]
        c = _client()
        try:
            c.chat(MSGS, role="reason_synthesize", max_tokens=8192)
        except llm.LLMError:
            pass
        assert "lower_level" not in [e["rung"] for e in c.ladder_events]
        assert len(wire.sent) == 1
