"""The Anthropic Messages dialect: request translation, the three cache
breakpoints, the event stream folded through the one transport, usage, stop
reasons and refusals. The event streams are written from the vendor's
documented sequences; every name and value is invented."""
from __future__ import annotations

import contextlib
import json

import pytest

from agent import llm
from core import messages_api as ma

SYSTEM = {"role": "system", "content": "You are a forensic analyst on case CASE-A."}
BRIEF = {"role": "user", "content": "Brief: host CORP-WS01, user jane.doe, 2031-03-01."}


def _turn(n: int) -> list[dict]:
    return [{"role": "assistant", "content": "", "tool_calls": [
                {"id": f"toolu_{n}a", "type": "function",
                 "function": {"name": "list_processes", "arguments": "{\"image\": \"m.img\"}"}},
                {"id": f"toolu_{n}b", "type": "function",
                 "function": {"name": "read_table", "arguments": "{\"path\": \"t.csv\"}"}}]},
            {"role": "tool", "tool_call_id": f"toolu_{n}a", "content": f"pid {n} System"},
            {"role": "tool", "tool_call_id": f"toolu_{n}b", "content": f"row {n}: 10.0.0.5"}]


TOOLS = [{"type": "function", "function": {"name": "list_processes", "description": "d1",
                                           "parameters": {"type": "object", "properties": {"image": {"type": "string"}}}}},
         {"type": "function", "function": {"name": "read_table", "description": "d2",
                                           "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}]


def _wire(messages, **kw):
    return ma.to_wire({"model": "claude-x", "messages": messages, **kw}, llm.EXPLICIT_CAP)


def _marked(body) -> list[str]:
    """Where the breakpoints sit: "system", or "<turn>.<block>:<type>"."""
    out = ["system" for b in body.get("system") or [] if "cache_control" in b]
    for t, turn in enumerate(body["messages"]):
        out += [f"{t}.{i}:{b['type']}" for i, b in enumerate(turn["content"]) if "cache_control" in b]
    return out


# ── the request ──────────────────────────────────────────────────────────

def test_the_analyst_shape_gets_three_breakpoints_none_on_the_nudge():
    nudge = {"role": "user", "content": "Record what bears on the case."}
    body = _wire([SYSTEM, BRIEF, *_turn(1), nudge], tools=TOOLS, tool_choice="auto")
    assert _marked(body) == ["system", "0.0:text", "2.1:tool_result"]
    assert body["messages"][2]["content"][2] == {"type": "text", "text": "Record what bears on the case."}
    assert all(b["cache_control"] == {"type": "ephemeral"} for b in body["system"])
    assert "cache_control" not in body                       # no automatic top-level caching


def test_a_one_shot_call_marks_only_the_system():
    assert _marked(_wire([SYSTEM, BRIEF])) == ["system"]


def test_two_trailing_nudges_keep_the_tail_breakpoint_on_the_last_tool_result():
    body = _wire([SYSTEM, BRIEF, *_turn(1), {"role": "user", "content": "a"}, {"role": "user", "content": "b"}])
    assert _marked(body)[-1] == "2.1:tool_result"


def test_the_next_turn_keeps_the_cached_prefix_byte_for_byte():
    """Turn t+1 stubs turn t's nudge and appends a turn: everything up to
    turn t's tail breakpoint is unchanged (the markers aside), so the entry
    turn t wrote is read."""
    t1 = _wire([SYSTEM, BRIEF, *_turn(1), {"role": "user", "content": "nudge one"}], tools=TOOLS)
    t2 = _wire([SYSTEM, BRIEF, *_turn(1), {"role": "user", "content": "(retired)"}, *_turn(2),
                {"role": "user", "content": "nudge two"}], tools=TOOLS)

    def plain(blocks):
        return [{k: v for k, v in b.items() if k != "cache_control"} for b in blocks]
    prefix = [plain(m["content"]) for m in t1["messages"][:2]] + [plain(t1["messages"][2]["content"][:2])]
    again = [plain(m["content"]) for m in t2["messages"][:2]] + [plain(t2["messages"][2]["content"][:2])]
    assert json.dumps(plain(t1["system"])) == json.dumps(plain(t2["system"]))
    assert json.dumps(prefix) == json.dumps(again)
    assert json.dumps(t1["tools"]) == json.dumps(t2["tools"])


def test_tools_serialize_the_same_bytes_every_time():
    assert json.dumps(_wire([SYSTEM, BRIEF], tools=TOOLS)["tools"]) == \
        json.dumps(_wire([SYSTEM, BRIEF], tools=json.loads(json.dumps(TOOLS)))["tools"])
    assert [t["name"] for t in _wire([SYSTEM, BRIEF], tools=TOOLS)["tools"]] == ["list_processes", "read_table"]


def test_only_the_leading_system_message_is_hoisted():
    late = {"role": "system", "content": "A late operator note."}
    body = _wire([SYSTEM, BRIEF, late, {"role": "user", "content": "go"}])
    assert [b["text"] for b in body["system"]] == [SYSTEM["content"]]
    assert body["messages"][0]["content"][1] == {"type": "text", "text": "A late operator note."}


def test_whitespace_only_text_is_no_block():
    body = _wire([SYSTEM, BRIEF, {"role": "assistant", "content": "\n\n", "tool_calls": _turn(1)[0]["tool_calls"]},
                  *_turn(1)[1:]])
    assistant = body["messages"][1]["content"]
    assert [b["type"] for b in assistant] == ["tool_use", "tool_use"]


def test_thinking_and_echo_fields_never_reach_the_wire():
    turn = _turn(1)
    turn[0] = {**turn[0], "content": "Reading.", "reasoning_content": "private chain", "reasoning": "x"}
    text = json.dumps(_wire([SYSTEM, BRIEF, *turn]))
    assert "private chain" not in text and '"thinking"' not in text


def test_choice_effort_cap_and_what_is_never_sent():
    body = _wire([SYSTEM, BRIEF], tools=TOOLS, tool_choice="required", reasoning_effort="low",
                 response_format={"type": "json_object"}, stream=True, stream_options={"include_usage": True})
    assert body["tool_choice"] == {"type": "any"} and body["output_config"] == {"effort": "low"}
    assert body["max_tokens"] == llm.EXPLICIT_CAP and body["stream"] is True
    for absent in ("response_format", "stream_options", "thinking", "temperature", "reasoning_effort"):
        assert absent not in body
    assert _wire([SYSTEM, BRIEF], max_tokens=512)["max_tokens"] == 512


# ── the stream ───────────────────────────────────────────────────────────

def _ev(kind, **data):
    return [f"event: {kind}", "data: " + json.dumps({"type": kind, **data})]


DOC_STREAM = [
    *_ev("message_start", message={"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
                                   "content": [], "usage": {"input_tokens": 1000, "cache_creation_input_tokens": 200,
                                                            "cache_read_input_tokens": 90000, "output_tokens": 1}}),
    # thinking with display "omitted": an empty thinking_delta and a signature
    *_ev("content_block_start", index=0, content_block={"type": "thinking", "thinking": "", "signature": ""}),
    *_ev("content_block_delta", index=0, delta={"type": "thinking_delta", "thinking": ""}),
    *_ev("content_block_delta", index=0, delta={"type": "signature_delta", "signature": "c2lnbmF0dXJl"}),
    *_ev("content_block_stop", index=0),
    *_ev("ping"),
    *_ev("content_block_start", index=1, content_block={"type": "text", "text": ""}),
    *_ev("content_block_delta", index=1, delta={"type": "text_delta", "text": "Reading the "}),
    *_ev("content_block_delta", index=1, delta={"type": "text_delta", "text": "process list."}),
    *_ev("content_block_stop", index=1),
    *_ev("content_block_start", index=2, content_block={"type": "tool_use", "id": "toolu_9", "name": "list_processes", "input": {}}),
    *_ev("content_block_delta", index=2, delta={"type": "input_json_delta", "partial_json": ""}),
    *_ev("content_block_delta", index=2, delta={"type": "input_json_delta", "partial_json": "{\"image\":"}),
    *_ev("content_block_delta", index=2, delta={"type": "input_json_delta", "partial_json": " \"m.img\"}"}),
    *_ev("content_block_stop", index=2),
    *_ev("message_delta", delta={"stop_reason": "tool_use", "stop_sequence": None},
         usage={"output_tokens": 50, "output_tokens_details": {"thinking_tokens": 30}}),
    *_ev("message_stop"),
]


def _fold(lines):
    return llm.parse_response(llm.assemble_stream(ma.chunks(lines)))


def test_the_documented_stream_folds_to_one_reply():
    r = _fold(DOC_STREAM)
    assert r.content == "Reading the process list."
    assert [(c.id, c.name, c.arguments) for c in r.tool_calls] == [("toolu_9", "list_processes", {"image": "m.img"})]
    assert r.finish_reason == "tool_calls" and r.refusal is None
    # input = uncached + written + read; cached = read
    assert (r.input_tokens, r.cached_tokens, r.cache_write_tokens, r.output_tokens, r.reasoning_tokens) == \
        (91200, 90000, 200, 50, 30)
    stats: dict = {}
    llm.assemble_stream(ma.chunks(DOC_STREAM), stats=stats)
    assert stats["keepalives"] == 1                          # the ping


def test_a_message_delta_overrides_the_start_counts():
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 5}}),
             *_ev("content_block_start", index=0, content_block={"type": "text", "text": ""}),
             *_ev("content_block_delta", index=0, delta={"type": "text_delta", "text": "ok"}),
             *_ev("message_delta", delta={"stop_reason": "end_turn"},
                  usage={"input_tokens": 7, "cache_read_input_tokens": 3, "output_tokens": 2}),
             *_ev("message_stop")]
    r = _fold(lines)
    assert (r.input_tokens, r.cached_tokens, r.output_tokens) == (10, 3, 2)


@pytest.mark.parametrize("stop, finish", [("end_turn", "stop"), ("stop_sequence", "stop"), ("tool_use", "tool_calls"),
                                          ("max_tokens", "length"),
                                          ("model_context_window_exceeded", "context_window_exceeded"),
                                          ("pause_turn", "pause")])
def test_every_documented_stop_reason_maps(stop, finish):
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 1}}),
             *_ev("content_block_start", index=0, content_block={"type": "text", "text": ""}),
             *_ev("content_block_delta", index=0, delta={"type": "text_delta", "text": "partial"}),
             *_ev("message_delta", delta={"stop_reason": stop}, usage={"output_tokens": 2}),
             *_ev("message_stop")]
    assert _fold(lines).finish_reason == finish


def test_a_full_context_window_is_neither_a_cut_nor_starved():
    """The window ended the reply, not the completion limit: no ladder step,
    no cut-off ask."""
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 1}}),
             *_ev("content_block_start", index=0, content_block={"type": "thinking", "thinking": ""}),
             *_ev("message_delta", delta={"stop_reason": "model_context_window_exceeded"},
                  usage={"output_tokens": 9, "output_tokens_details": {"thinking_tokens": 9}}),
             *_ev("message_stop")]
    r = _fold(lines)
    assert r.finish_reason != "length" and r.starved is False


def test_null_usage_counts_never_replace_reported_ones():
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x",
                                            "usage": {"input_tokens": 40, "cache_read_input_tokens": 30}}),
             *_ev("message_delta", delta={"stop_reason": "end_turn"},
                  usage={"input_tokens": None, "cache_read_input_tokens": None, "output_tokens": 3}),
             *_ev("message_stop")]
    r = _fold(lines)
    assert (r.input_tokens, r.cached_tokens, r.output_tokens) == (70, 30, 3)


def test_a_refusal_drops_partial_output_and_says_why():
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 400}}),
             *_ev("content_block_start", index=0, content_block={"type": "text", "text": ""}),
             *_ev("content_block_delta", index=0, delta={"type": "text_delta", "text": "Here is how"}),
             *_ev("message_delta", delta={"stop_reason": "refusal", "stop_details": {
                 "type": "refusal", "category": "cyber", "explanation": "declined"}}, usage={"output_tokens": 3}),
             *_ev("message_stop")]
    r = _fold(lines)
    assert (r.content, r.tool_calls, r.finish_reason) == ("", [], "refusal")
    assert r.refusal == {"category": "cyber", "explanation": "declined"} and not r.starved
    body = ma.to_chat_body({"type": "message", "id": "m", "content": [], "stop_reason": "refusal",
                            "stop_details": {"type": "refusal", "category": None, "explanation": None},
                            "usage": {"input_tokens": 412, "output_tokens": 0}})
    r = llm.parse_response(body)
    assert r.finish_reason == "refusal" and r.refusal == {"category": None, "explanation": None}


def test_a_chat_content_filter_is_a_refusal_too():
    r = llm.parse_response({"choices": [{"message": {"content": "cut"}, "finish_reason": "content_filter"}]})
    assert (r.content, r.finish_reason) == ("", "refusal") and r.refusal is not None


def test_a_mid_stream_error_event_fails_the_stream():
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {}}),
             *_ev("content_block_start", index=0, content_block={"type": "text", "text": ""}),
             *_ev("content_block_delta", index=0, delta={"type": "text_delta", "text": "half"}),
             *_ev("error", error={"type": "overloaded_error", "message": "Overloaded"})]
    with pytest.raises(llm.httpx.RemoteProtocolError, match="Overloaded"):
        llm.assemble_stream(ma.chunks(lines))


def test_unknown_event_types_are_skipped():
    lines = [*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 1}}),
             *_ev("some_future_event", payload={"x": 1}),
             *_ev("content_block_start", index=0, content_block={"type": "text", "text": "ok"}),
             *_ev("message_delta", delta={"stop_reason": "end_turn"}, usage={"output_tokens": 1}),
             *_ev("message_stop")]
    assert _fold(lines).content == "ok"


def test_a_plain_body_reads_like_the_stream():
    body = {"type": "message", "id": "m", "model": "claude-x", "stop_reason": "tool_use",
            "content": [{"type": "thinking", "thinking": "", "signature": "s"}, {"type": "text", "text": "Reading."},
                        {"type": "tool_use", "id": "toolu_1", "name": "read_table", "input": {"path": "t.csv"}}],
            "usage": {"input_tokens": 10, "cache_creation_input_tokens": 5, "cache_read_input_tokens": 0,
                      "output_tokens": 4}}
    r = llm.parse_response(ma.to_chat_body(body))
    assert (r.content, r.tool_calls[0].arguments, r.input_tokens, r.cache_write_tokens) == \
        ("Reading.", {"path": "t.csv"}, 15, 5)


def test_the_wire_names_of_a_refused_effort_adapt_the_chat_request():
    text = ma.canonical_error('{"type":"error","error":{"type":"invalid_request_error","message":'
                              '"output_config.effort \'xhigh\' is not supported when thinking is disabled '
                              'on this model. Use effort \'high\' or below, or enable thinking."}}')
    out, _prof = llm.adapt_payload_for_400({"model": "m", "messages": [BRIEF], "reasoning_effort": "xhigh"}, text)
    assert "reasoning_effort" not in out


# ── through the client ───────────────────────────────────────────────────

@pytest.fixture
def native(monkeypatch, tmp_path):
    monkeypatch.setenv("ATLAS_PROVIDERS", "claude-a")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_BASE_URL", "https://api.anthropic.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_PRESET", "anthropic")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_MODEL", "claude-x")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_API_KEY", "k-test")
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    sent: list = []
    replies: list = []

    class Reply:
        status_code = 200
        headers = {"content-type": "text/event-stream"}
        text = ""

        def __init__(self, lines):
            self.lines = lines

        def iter_lines(self):
            return iter(self.lines)

        def read(self):
            return b""

    @contextlib.contextmanager
    def stream(method, url, json=None, headers=None, timeout=None):
        sent.append({"url": url, "body": json, "headers": headers})
        yield Reply(replies.pop(0) if replies else DOC_STREAM)

    monkeypatch.setattr(llm.httpx, "stream", stream)
    return sent, replies


def test_a_native_provider_speaks_messages_with_its_key_header(native):
    sent, _ = native
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], role="")
    call = sent[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "k-test" and "Authorization" not in call["headers"]
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    assert call["body"]["max_tokens"] == llm.EXPLICIT_CAP


@pytest.mark.parametrize("level, sent_effort", [("high", "high"), ("minimal", "low"), ("none", "low"), ("max", "max")])
def test_levels_go_out_as_effort_low_to_max(native, monkeypatch, level, sent_effort):
    sent, _ = native
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", level)
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF])
    assert sent[0]["body"]["output_config"] == {"effort": sent_effort} and "thinking" not in sent[0]["body"]


def test_the_ladder_steps_high_to_low_and_stops(native):
    profile = llm.resolve_api_compat("claude-a", "claude-x")
    assert profile.needs_explicit_cap is True
    assert llm.LLMHubClient._lower_level("high", profile, cut=False) == "low"
    assert llm.LLMHubClient._lower_level("low", profile, cut=False) is None


def test_a_forced_tool_choice_is_auto_on_the_models_that_refuse_it(native, monkeypatch):
    sent, _ = native
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_MODEL", "claude-sonnet-5-5")
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], tools=TOOLS, tool_choice="required")
    assert sent[0]["body"]["tool_choice"] == {"type": "auto"}
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_MODEL", "claude-haiku-4-5")
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "high")
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], tools=TOOLS, tool_choice="required")
    assert sent[1]["body"]["tool_choice"] == {"type": "any"} and "output_config" not in sent[1]["body"]


def test_a_refusal_is_a_ledger_row_of_its_own(native, monkeypatch, tmp_path):
    from core import usage_ledger
    _, replies = native
    replies.append([*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 400}}),
                    *_ev("message_delta", delta={"stop_reason": "refusal", "stop_details": {"category": "cyber"}},
                         usage={"output_tokens": 0}),
                    *_ev("message_stop")])
    with usage_ledger.context(case_id="CASE-A", run_id="r1"):
        r = llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF])
    assert r.finish_reason == "refusal" and r.refusal["category"] == "cyber"
    rows = usage_ledger.daily_rows("2000-01-01")
    assert [(row["calls"], row["input"]) for row in rows] == [(1, 400)]


def test_an_old_learned_shape_does_not_carry_into_the_messages_dialect(native):
    """A shape learned on the OpenAI-compatible layer (before profiles
    recorded their seed) starts again from the native profile; what was
    observed of the model stays."""
    llm.remember_api_compat("claude-a", "claude-x", llm.ApiCompatProfile(
        thinking_control=llm.THINKING_NONE, max_tools=40, reasoning_observed=True), persist=False)
    key = llm._compat_key("claude-a", "claude-x")
    llm._compat_mem[key] = llm.replace(llm._compat_mem[key], seed="")      # as stored before seeds
    profile = llm.resolve_api_compat("claude-a", "claude-x")
    assert profile.thinking_control == llm.THINKING_OUTPUT_CONFIG
    assert (profile.max_tools, profile.reasoning_observed) == (40, True)


def test_a_messages_override_on_a_chat_profile_knows_the_cap_it_sends(native, monkeypatch):
    """_API=messages on a provider bound to a chat profile (a gateway that
    speaks Messages, registered as Other): the request carries the explicit
    cap, so a reply starved at it steps the level instead of being sent again
    at the same cap as if the endpoint's default had cut it."""
    sent, replies = native
    monkeypatch.delenv("ATLAS_PROVIDER_CLAUDE_A_PRESET")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_BASE_URL", "https://gw.example.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_API", "messages")
    replies.append([*_ev("message_start", message={"id": "m", "model": "claude-x", "usage": {"input_tokens": 50}}),
                    *_ev("content_block_start", index=0, content_block={"type": "thinking", "thinking": ""}),
                    *_ev("content_block_delta", index=0, delta={"type": "thinking_delta", "thinking": "..."}),
                    *_ev("message_delta", delta={"stop_reason": "max_tokens"}, usage={"output_tokens": 65536}),
                    *_ev("message_stop")])
    client = llm.LLMHubClient(provider="claude-a")
    client.chat([SYSTEM, BRIEF])
    assert sent[0]["url"] == "https://gw.example.com/v1/messages"
    assert sent[0]["body"]["max_tokens"] == llm.EXPLICIT_CAP
    assert "explicit_cap" not in [ev["rung"] for ev in client.ladder_events]


def test_an_instance_named_anthropic_at_a_gateway_stays_on_chat(monkeypatch):
    """Name binding never moves a gateway to the Messages API: only an
    instance at the profile's own host, or one whose _PRESET names it."""
    from core import providers
    monkeypatch.setenv("ATLAS_PROVIDERS", "anthropic")
    monkeypatch.setenv("ATLAS_PROVIDER_ANTHROPIC_API_KEY", "k-test")
    monkeypatch.setenv("ATLAS_PROVIDER_ANTHROPIC_BASE_URL", "https://gw.example.com/v1")
    assert (providers.resolve("anthropic").api, providers.resolve("anthropic").profile) == (providers.CHAT_API, "custom")
    monkeypatch.setenv("ATLAS_PROVIDER_ANTHROPIC_PRESET", "anthropic")
    assert providers.resolve("anthropic").api == providers.MESSAGES_API
    monkeypatch.delenv("ATLAS_PROVIDER_ANTHROPIC_PRESET")
    monkeypatch.setenv("ATLAS_PROVIDER_ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
    assert providers.resolve("anthropic").api == providers.MESSAGES_API


def test_a_named_output_maximum_is_sent_at_once_and_remembered(native, monkeypatch):
    """The 4.5 models take at most 64000 output tokens: the first call's 400
    names the maximum, the call goes again with it, and the next call starts
    there."""
    sent, replies = native
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_MODEL", "claude-haiku-4-5")
    real_stream = llm.httpx.stream

    class Refused:
        status_code = 400
        headers = {"content-type": "application/json"}
        text = ('{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: 65536 > 64000, '
                'which is the maximum allowed number of output tokens for claude-haiku-4-5-20251001"}}')

        def iter_lines(self):
            return iter(())

        def read(self):
            return self.text.encode()

        def json(self):
            return json.loads(self.text)

    first = []

    @contextlib.contextmanager
    def stream(method, url, json=None, headers=None, timeout=None):
        if not first:
            first.append(json)
            sent.append({"url": url, "body": json, "headers": headers})
            yield Refused()
            return
        with real_stream(method, url, json=json, headers=headers, timeout=timeout) as r:
            yield r

    monkeypatch.setattr(llm.httpx, "stream", stream)
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], role="")
    llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], role="")
    assert [c["body"]["max_tokens"] for c in sent] == [65536, 64000, 64000]


def test_the_ledger_row_carries_the_cache_writes(native):
    from core import usage_ledger
    with usage_ledger.context(case_id="CASE-A", run_id="r1"):
        llm.LLMHubClient(provider="claude-a").chat([SYSTEM, BRIEF], role="")
    (row,) = usage_ledger.daily_rows("2000-01-01")
    assert (row["input"], row["cached"], row["cache_write"]) == (91200, 90000, 200)


def test_the_pacer_counts_what_anthropics_rate_limit_counts(native, monkeypatch):
    """Input tokens per minute count the uncached input and the cache writes,
    never the cache reads: the pacer records those, and estimates the next
    request without the prefix the last reply read from the cache."""
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "400000")
    client = llm.LLMHubClient(provider="claude-a")
    client.chat([SYSTEM, BRIEF], role="")
    assert [tok for _ts, tok in client._spend] == [1000 + 200]           # 91200 in, 90000 read
    assert client._paced(95_000, client._last_cache_reads, client.profile) == 5_000
