"""Responses API mapping and opt-in selection. No network."""
from __future__ import annotations

import json

import pytest


def test_parse_llm_api_defaults_to_chat():
    from core.providers import CHAT_API, RESPONSES_API, parse_llm_api

    assert parse_llm_api(None) == CHAT_API
    assert parse_llm_api("") == CHAT_API
    assert parse_llm_api("chat") == CHAT_API
    assert parse_llm_api("completions") == CHAT_API
    assert parse_llm_api("nonsense") == CHAT_API
    assert parse_llm_api("responses") == RESPONSES_API
    assert parse_llm_api("Response") == RESPONSES_API


def test_provider_api_defaults_chat_even_for_gpt5(monkeypatch):
    from core import providers

    monkeypatch.setenv("ATLAS_PROVIDERS", "openai")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_MODEL", "gpt-5.4")
    monkeypatch.delenv("ATLAS_PROVIDER_OPENAI_API", raising=False)
    p = providers.resolve("openai")
    assert p.api == providers.CHAT_API
    assert p.chat_url().endswith("/chat/completions")


def test_provider_opt_in_responses(monkeypatch):
    from core import providers

    monkeypatch.setenv("ATLAS_PROVIDERS", "openai")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_API", "responses")
    p = providers.resolve("openai")
    assert p.api == providers.RESPONSES_API
    assert p.chat_url().endswith("/v1/responses")


def test_llmhub_stays_chat_unless_llmhug_api_set(monkeypatch):
    from core import providers

    monkeypatch.delenv("LLMHUB_API", raising=False)
    assert providers.resolve("llmhub").api == providers.CHAT_API
    monkeypatch.setenv("LLMHUB_API", "responses")
    assert providers.resolve("llmhub").api == providers.RESPONSES_API


def test_openrouter_compatible_url_is_not_responses(monkeypatch):
    from core import providers

    monkeypatch.setenv("ATLAS_PROVIDERS", "openrouter")
    monkeypatch.setenv(
        "ATLAS_PROVIDER_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_MODEL", "openai/gpt-5")
    monkeypatch.delenv("ATLAS_PROVIDER_OPENROUTER_API", raising=False)
    p = providers.resolve("openrouter")
    assert p.api == providers.CHAT_API


def test_build_responses_url():
    from core import llmhub

    assert llmhub.build_responses_url("https://api.openai.com/v1") == (
        "https://api.openai.com/v1/responses")
    assert llmhub.build_responses_url("https://api.openai.com") == (
        "https://api.openai.com/v1/responses")
    assert llmhub.build_responses_url(
        "https://api.openai.com/v1/chat/completions") == (
        "https://api.openai.com/v1/responses")
    assert llmhub.build_responses_url(
        "https://llm-server.llmhub.t-systems.net/v2") == (
        "https://llm-server.llmhub.t-systems.net/v2/responses")


def test_tools_flatten():
    from core.responses_api import tools_to_responses

    tools = [{
        "type": "function",
        "function": {
            "name": "misc_write_final_report",
            "description": "Write report",
            "parameters": {"type": "object", "properties": {}},
        },
    }]
    out = tools_to_responses(tools)
    assert out[0]["type"] == "function"
    assert out[0]["name"] == "misc_write_final_report"
    assert "function" not in out[0]
    assert out[0]["strict"] is False


def test_messages_to_input_keeps_system_as_instructions():
    from core.responses_api import messages_to_responses_input

    instr, items = messages_to_responses_input([
        {"role": "system", "content": "PLAYBOOK"},
        {"role": "user", "content": "investigate"},
        {"role": "assistant", "content": "",
         "tool_calls": [{
             "id": "call_1", "type": "function",
             "function": {"name": "hash_file", "arguments": '{"p":"a"}'},
         }]},
        {"role": "tool", "tool_call_id": "call_1", "content": "digest"},
    ])
    assert instr == "PLAYBOOK"
    assert items[0] == {"role": "user", "content": "investigate"}
    assert items[1]["type"] == "function_call"
    assert items[1]["call_id"] == "call_1"
    assert items[1]["name"] == "hash_file"
    assert items[2] == {
        "type": "function_call_output",
        "call_id": "call_1",
        "output": "digest",
    }


def test_replay_stored_responses_items():
    from core.responses_api import messages_to_responses_input

    stored = [
        {"type": "reasoning", "id": "rs_1", "summary": []},
        {"type": "function_call", "call_id": "call_9",
         "name": "ez_ez_evtxecmd", "arguments": "{}"},
    ]
    _, items = messages_to_responses_input([
        {"role": "assistant", "content": "", "_responses_items": stored},
        {"role": "tool", "tool_call_id": "call_9", "content": "csv ready"},
    ])
    assert items[0]["type"] == "reasoning"
    assert items[1]["type"] == "function_call"
    assert items[2]["type"] == "function_call_output"


def test_parse_text_and_usage():
    from agent.llm import parse_responses

    body = {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "hello"}],
        }],
        "usage": {"input_tokens": 11, "output_tokens": 3},
    }
    r = parse_responses(body)
    assert r.content == "hello"
    assert r.tool_calls == []
    assert r.input_tokens == 11
    assert r.output_tokens == 3
    assert r.finish_reason == "stop"
    assert r.responses_items[0]["type"] == "message"


def test_parse_function_calls_and_malformed_args():
    from agent.llm import parse_responses

    body = {
        "object": "response",
        "status": "completed",
        "output": [
            {"type": "reasoning", "summary": []},
            {
                "type": "function_call",
                "call_id": "call_abc",
                "name": "atlas_load_namespaces",
                "arguments": '{"namespaces":["table"]}',
            },
            {
                "type": "function_call",
                "call_id": "call_bad",
                "name": "misc_write_final_report",
                "arguments": "{not json",
            },
        ],
        "usage": {"input_tokens": 40, "output_tokens": 8},
    }
    r = parse_responses(body)
    assert r.finish_reason == "tool_calls"
    assert r.tool_calls[0].id == "call_abc"
    assert r.tool_calls[0].arguments == {"namespaces": ["table"]}
    assert r.tool_calls[1].arguments["_malformed_arguments"] == "{not json"


def test_parse_incomplete_and_error():
    from agent.llm import LLMError, parse_responses

    r = parse_responses({
        "status": "incomplete",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "cut"}],
        }],
        "usage": {},
    })
    assert r.finish_reason == "length"
    with pytest.raises(LLMError, match="Responses API error"):
        parse_responses({
            "status": "failed",
            "output": [],
            "error": {"message": "boom"},
        })


def test_parse_rejects_garbage():
    from agent.llm import LLMError, parse_responses

    with pytest.raises(LLMError, match="Malformed"):
        parse_responses(["not", "an", "object"])


def test_payload_is_stateless():
    from core.responses_api import build_responses_payload

    p = build_responses_payload(
        model="gpt-5.4",
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ],
        max_tokens=1024,
        tools=[{
            "type": "function",
            "function": {"name": "t", "description": "d",
                         "parameters": {"type": "object"}},
        }],
    )
    assert p["store"] is False
    assert p["max_output_tokens"] == 1024
    assert p["instructions"] == "sys"
    assert "messages" not in p
    assert "previous_response_id" not in p
    assert p["tools"][0]["name"] == "t"


class _FakeResp:
    def __init__(self, status, body, text=""):
        self.status_code = status
        self._body = body
        self.text = text or json.dumps(body)
        self.headers = {}

    def json(self):
        return self._body


def test_client_default_chat_for_gpt5(monkeypatch):
    from agent.llm import LLMHubClient

    monkeypatch.setenv("ATLAS_PROVIDERS", "openai")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_MODEL", "gpt-5.4")
    monkeypatch.delenv("ATLAS_PROVIDER_OPENAI_API", raising=False)
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp(200, {
            "choices": [{
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        })

    monkeypatch.setattr("httpx.post", fake_post)
    r = LLMHubClient(provider="openai").chat(
        [{"role": "user", "content": "hi"}])
    assert captured["url"].endswith("/chat/completions")
    assert "messages" in captured["json"]
    assert r.content == "ok"


def test_client_responses_tool_roundtrip(monkeypatch):
    from agent.llm import LLMHubClient

    monkeypatch.setenv("ATLAS_PROVIDERS", "openai")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_MODEL", "gpt-5.4")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_API", "responses")
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp(200, {
            "id": "resp_x",
            "object": "response",
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call_99",
                "name": "hash_file",
                "arguments": '{"path":"/e"}',
            }],
            "usage": {"input_tokens": 9, "output_tokens": 4},
        })

    monkeypatch.setattr("httpx.post", fake_post)
    tools = [{
        "type": "function",
        "function": {
            "name": "hash_file",
            "description": "hash",
            "parameters": {"type": "object", "properties": {}},
        },
    }]
    r = LLMHubClient(provider="openai").chat(
        [
            {"role": "system", "content": "gates"},
            {"role": "user", "content": "hash it"},
        ],
        tools=tools,
    )
    assert captured["url"].endswith("/responses")
    assert captured["json"]["store"] is False
    assert captured["json"]["instructions"] == "gates"
    assert captured["json"]["tools"][0]["name"] == "hash_file"
    assert r.tool_calls[0].id == "call_99"
    assert r.tool_calls[0].name == "hash_file"
    assert r.input_tokens == 9
    assert r.responses_items[0]["type"] == "function_call"


def test_other_provider_unaffected_when_openai_opts_in(monkeypatch):
    from core import providers

    monkeypatch.setenv("ATLAS_PROVIDERS", "openai,local")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENAI_API", "responses")
    monkeypatch.setenv("ATLAS_PROVIDER_LOCAL_BASE_URL", "http://localhost:8000/v1")
    monkeypatch.delenv("ATLAS_PROVIDER_LOCAL_API", raising=False)
    assert providers.resolve("local").api == providers.CHAT_API
    assert providers.resolve("openai").api == providers.RESPONSES_API


def test_a_configured_level_reaches_the_responses_body():
    """The same per-role level the Completions body carries as a flat field.
    Without it the setting was silently dropped for every provider on this
    API, which is the one place it could be set and have no effect at all."""
    from core.responses_api import build_responses_payload
    body = build_responses_payload(
        model="m", messages=[{"role": "user", "content": "hi"}],
        reasoning_effort="high")
    assert body["reasoning"] == {"effort": "high"}


def test_the_endpoints_own_level_sends_nothing():
    from core.responses_api import build_responses_payload
    for value in ("default", "", None):
        body = build_responses_payload(
            model="m", messages=[{"role": "user", "content": "hi"}],
            reasoning_effort=value)
        assert "reasoning" not in body


def test_the_completions_only_pin_is_not_carried_here():
    """"none" exists on Completions so a reasoning model can call function
    tools. This API has no such restriction and no such value."""
    from core.responses_api import build_responses_payload
    body = build_responses_payload(
        model="m", messages=[{"role": "user", "content": "hi"}],
        reasoning_effort="none")
    assert "reasoning" not in body
