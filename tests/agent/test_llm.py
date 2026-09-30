"""Tests for agent/llm.py and core/llmhub.py — no network."""
import json

import pytest

from core import llmhub
from agent.llm import parse_response, rate_limit_delay, LLMError, LLMHubClient


class TestBuildChatUrl:
    def test_llmhub_v2_base(self):
        assert llmhub.build_chat_url("https://llm-server.llmhub.t-systems.net/v2") == \
            "https://llm-server.llmhub.t-systems.net/v2/chat/completions"

    def test_bare_host_gets_v1(self):
        assert llmhub.build_chat_url("https://api.openai.com") == \
            "https://api.openai.com/v1/chat/completions"

    def test_full_endpoint_passthrough(self):
        url = "http://localhost:8000/v1/chat/completions"
        assert llmhub.build_chat_url(url) == url

    def test_trailing_slash(self):
        assert llmhub.build_chat_url("http://localhost:8000/v1/") == \
            "http://localhost:8000/v1/chat/completions"

    def test_models_url_from_chat_endpoint(self):
        assert llmhub.build_models_url(
            "https://llm-server.llmhub.t-systems.net/v2/chat/completions") == \
            "https://llm-server.llmhub.t-systems.net/v2/models"


class TestApiKeyAliases:
    def test_tsystems_alias(self, monkeypatch):
        monkeypatch.delenv("LLMHUB_API_KEY", raising=False)
        monkeypatch.setenv("TSYSTEMS_API_KEY", "tsi-key")
        assert llmhub.api_key() == "tsi-key"

    def test_llmhub_wins(self, monkeypatch):
        monkeypatch.setenv("LLMHUB_API_KEY", "hub-key")
        monkeypatch.setenv("TSYSTEMS_API_KEY", "tsi-key")
        assert llmhub.api_key() == "hub-key"


class TestRateLimitDelay:
    HUB_429 = ('{"detail":"Rate limit exceeded: Model example-model - '
               'Input TPM 120 / 100 - Output TPM 10 / 50 - '
               'RPM 3 / 5. Please try again in 33.30 seconds."}')

    def test_hub_body_hint_wins(self):
        assert rate_limit_delay(self.HUB_429, {}, attempt=0) == 35.30

    def test_retry_after_header_wins_over_body(self):
        assert rate_limit_delay(self.HUB_429, {"retry-after": "10"},
                                attempt=0) == 11.0

    def test_fallback_backoff_without_hints(self):
        assert rate_limit_delay("nope", {}, attempt=1) == 4
        assert rate_limit_delay("", {}, attempt=10) == 30

    def test_hint_capped(self):
        assert rate_limit_delay("try again in 900 seconds", {},
                                attempt=0) == 120.0


class TestInputTpmPacing:
    def test_budget_from_env(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "12345")
        assert LLMHubClient().input_tpm_budget == 12345

    def test_pace_noop_under_budget(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "1000")
        c = LLMHubClient()
        c._record_spend(400)
        c._pace(400)  # 800 < 1000 — must not sleep
        assert len(c._spend) == 1

    def test_pace_disabled(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        c = LLMHubClient()
        c._record_spend(10_000_000)
        assert c._spend == c._spend.__class__()  # nothing recorded
        c._pace(10_000_000)  # returns immediately

    def test_pace_waits_for_window(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "1000")
        c = LLMHubClient()
        slept = []
        monkeypatch.setattr("agent.llm.time.sleep", slept.append)
        c._record_spend(900)
        c._pace(400)  # would be 1300 > 1000 — must wait out the oldest entry
        assert slept and 0 < slept[0] <= 61
        assert not c._spend  # entry evicted after the wait


class TestAnalystReasoningEffort:
    """A model that reasons draws it from the same completion budget as the
    answer. Asked for more thought than the budget holds, it returns a reply
    that is all reasoning and no tool call — every turn, for a whole run. The
    size is configuration, not detection: a model's name does not say how
    much it thinks, and two models of one family differ by an order of
    magnitude on the same question."""

    def _payload(self, monkeypatch, tools=True, **env):
        import os as _os
        for var in [k for k in _os.environ if k.startswith("ATLAS_EFFORT_")]:
            monkeypatch.delenv(var, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        c = LLMHubClient(base_url="http://h/v1", api_key="k",
                         model="Some-Thinking-Model-1", provider="llmhub")
        sent = {}

        def _post(url, json=None, headers=None, timeout=None):
            sent.update(json or {})

            class _R:
                status_code = 200
                text = ""

                @staticmethod
                def json():
                    return {"choices": [{"message": {"role": "assistant",
                                                     "content": "ok"},
                                         "finish_reason": "stop"}],
                            "usage": {}}
            return _R()

        monkeypatch.setattr("agent.llm.httpx.post", _post)
        tool_schema = [{"type": "function",
                        "function": {"name": "t", "description": "d",
                                     "parameters": {"type": "object",
                                                    "properties": {}}}}]
        c.chat([{"role": "user", "content": "hi"}],
               tools=tool_schema if tools else None)
        return sent

    def test_the_configured_effort_is_sent(self, monkeypatch):
        sent = self._payload(monkeypatch, ATLAS_EFFORT_AGENT="low")
        assert sent["reasoning_effort"] == "low"

    def test_unset_leaves_the_endpoint_default(self, monkeypatch):
        assert "reasoning_effort" not in self._payload(monkeypatch)

    def test_default_spelling_is_not_sent_as_a_value(self, monkeypatch):
        sent = self._payload(monkeypatch, ATLAS_EFFORT_AGENT="default")
        assert "reasoning_effort" not in sent

    def test_it_is_sent_with_and_without_tools(self, monkeypatch):
        """A level governs thinking, not tool calling: the reason, director
        and report roles send it on bare completions. A gateway that refuses
        it says so in a 400, which the adapter answers by dropping it for
        that model."""
        sent = self._payload(monkeypatch, tools=False, ATLAS_EFFORT_AGENT="low")
        assert sent["reasoning_effort"] == "low"

    def test_an_endpoint_that_pins_a_value_is_not_overruled(self, monkeypatch,
                                                            tmp_path):
        """A profile carrying "none" states what the endpoint requires
        alongside Atlas's function tools, not a preference. Overriding it sent
        the configured level, took a 400, let the adapter restore "none", and
        overrode it again next call, so every tool-carrying request paid a
        refusal round-trip for the life of the run."""
        import os as _os
        for var in [k for k in _os.environ if k.startswith("ATLAS_EFFORT_")]:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        monkeypatch.setenv("ATLAS_EFFORT_AGENT", "high")
        sent = {}

        def _post(url, json=None, headers=None, timeout=None):
            sent.update(json or {})

            class _R:
                status_code = 200
                text = ""

                @staticmethod
                def json():
                    return {"choices": [{"message": {"role": "assistant",
                                                     "content": "ok"},
                                         "finish_reason": "stop"}],
                            "usage": {}}
            return _R()

        monkeypatch.setattr("agent.llm.httpx.post", _post)
        c = LLMHubClient(base_url="https://api.example/v1", api_key="k",
                         model="gpt-5.6-example", provider="openai")
        c.chat([{"role": "user", "content": "hi"}],
               tools=[{"type": "function",
                       "function": {"name": "t", "description": "d",
                                    "parameters": {"type": "object",
                                                   "properties": {}}}}])
        assert sent["reasoning_effort"] == "none"

    def test_an_endpoint_without_a_pin_still_takes_the_configured_level(
            self, monkeypatch):
        """The yield above is to a stated requirement only. Everything else
        keeps the level, which is every endpoint until one objects."""
        assert self._payload(monkeypatch,
                             ATLAS_EFFORT_AGENT="high")["reasoning_effort"] == "high"

    def test_the_analyst_setting_does_not_move_the_other_roles(self, monkeypatch):
        import os as _os
        for var in [k for k in _os.environ if k.startswith("ATLAS_EFFORT_")]:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("ATLAS_EFFORT_AGENT", "low")
        assert llmhub.reasoning_effort_for("agent") == "low"
        assert llmhub.reasoning_effort_for("dair") is None
        assert llmhub.reasoning_effort_for("reason_synthesize") is None


class TestParseResponse:
    def _body(self, message, finish="stop", usage=None):
        return {"choices": [{"message": message, "finish_reason": finish}],
                "usage": usage or {}}

    def test_plain_content(self):
        r = parse_response(self._body({"role": "assistant", "content": "hi"},
                                      usage={"prompt_tokens": 3,
                                             "completion_tokens": 1}))
        assert r.content == "hi"
        assert r.tool_calls == []
        assert (r.input_tokens, r.output_tokens) == (3, 1)

    def test_reasoning_is_never_promoted_into_the_answer(self):
        # A reply whose only text is its thinking is an empty reply. Promoting
        # the thinking fed a model's deliberation into the history, the trace
        # and the report as if it were the conclusion.
        r = parse_response(self._body(
            {"role": "assistant", "content": None,
             "reasoning_content": "thinking..."}))
        assert r.content == ""
        assert r.reasoning == "thinking..."
        assert r.thinking_observed is True

    def test_tool_call_string_arguments(self):
        r = parse_response(self._body({
            "role": "assistant", "content": "",
            "tool_calls": [{"id": "c1", "type": "function",
                            "function": {"name": "vol_vol_pslist",
                                         "arguments": '{"memory_image": "m.img"}'}}],
        }))
        assert r.tool_calls[0].name == "vol_vol_pslist"
        assert r.tool_calls[0].arguments == {"memory_image": "m.img"}

    def test_tool_call_malformed_arguments_survive(self):
        r = parse_response(self._body({
            "role": "assistant", "content": "",
            "tool_calls": [{"id": "c1", "type": "function",
                            "function": {"name": "t", "arguments": "{oops"}}],
        }))
        assert "_malformed_arguments" in r.tool_calls[0].arguments

    def test_tool_calls_null(self):
        # LLM Hub / GLM returns "tool_calls": null rather than omitting it
        r = parse_response(self._body({"role": "assistant", "content": "OK",
                                       "tool_calls": None}))
        assert r.tool_calls == []

    def test_malformed_body_raises(self):
        with pytest.raises(LLMError):
            parse_response({"error": "nope"})


class TestChatPayloadCompat:
    def setup_method(self):
        from agent.llm import clear_api_compat_cache
        clear_api_compat_cache(memory_only=True)

    def test_default_is_classic_openai_compatible(self, tmp_path, monkeypatch):
        from agent.llm import build_chat_payload, clear_api_compat_cache
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        monkeypatch.setenv("ATLAS_LLM_COMPAT_SOFT_HINTS", "0")
        clear_api_compat_cache()
        p = build_chat_payload(
            model="some-vendor-chat-v3",
            provider="acme",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=512,
            temperature=0.1,
        )
        assert p["max_tokens"] == 512
        assert p["temperature"] == 0.1
        assert "max_completion_tokens" not in p

    def test_soft_hint_gpt5_then_learn_persists(self, tmp_path, monkeypatch):
        from agent.llm import (
            build_chat_payload,
            clear_api_compat_cache,
            remember_api_compat,
            resolve_api_compat,
            ApiCompatProfile,
        )
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        monkeypatch.delenv("ATLAS_LLM_MAX_COMPLETION_TOKENS", raising=False)
        clear_api_compat_cache()
        soft = resolve_api_compat("openai", "gpt-5.6-example")
        assert soft.completion_limit == "max_completion_tokens"
        remember_api_compat(
            "openai", "gpt-5.6-example",
            ApiCompatProfile(
                completion_limit="max_completion_tokens",
                send_temperature=False,
                source="learned",
            ),
        )
        # Soft hints off — learned still wins
        monkeypatch.setenv("ATLAS_LLM_COMPAT_SOFT_HINTS", "0")
        clear_api_compat_cache(memory_only=True)
        from agent.llm import _load_compat_cache
        # force reload from disk
        import agent.llm as llm
        llm._compat_loaded = False
        learned = resolve_api_compat("openai", "gpt-5.6-example")
        assert learned.completion_limit == "max_completion_tokens"
        assert learned.source == "learned"
        p = build_chat_payload(
            model="gpt-5.6-example",
            provider="openai",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=100,
        )
        assert "max_completion_tokens" in p
        assert "temperature" not in p

    def test_adapt_payload_for_400_openai_style(self):
        from agent.llm import adapt_payload_for_400

        payload = {
            "model": "gpt-5.6-example",
            "messages": [],
            "max_tokens": 100,
            "temperature": 0.2,
        }
        err = (
            "Unsupported parameter: 'max_tokens' is not supported with this "
            "model. Use 'max_completion_tokens' instead."
        )
        result = adapt_payload_for_400(payload, err)
        assert result is not None
        patched, prof = result
        assert patched["max_completion_tokens"] == 100
        assert "max_tokens" not in patched
        assert prof.completion_limit == "max_completion_tokens"

    def test_adapt_drops_arbitrary_unsupported_param(self):
        from agent.llm import adapt_payload_for_400

        payload = {
            "model": "vendor-x",
            "messages": [],
            "max_tokens": 50,
            "top_p": 0.9,
            "temperature": 0.2,
        }
        err = "Unsupported parameter: 'top_p'."
        result = adapt_payload_for_400(payload, err)
        assert result is not None
        patched, prof = result
        assert "top_p" not in patched
        assert patched["max_tokens"] == 50
        # a review: a bare drop with no rename (unlike
        # max_tokens→max_completion_tokens, reconstructable from `patched`'s
        # own shape) must be tracked in the learned profile — otherwise
        # build_chat_payload adds "top_p" straight back next turn and the
        # provider 400s again, forever.
        assert prof.drop_params == ("top_p",)

    def test_learned_drop_params_applied_on_next_payload(self, tmp_path, monkeypatch):
        """Round-trip: a param dropped by 400-adaptation must not reappear
        in the next payload built for the same provider+model."""
        from agent.llm import (
            adapt_payload_for_400, build_chat_payload, clear_api_compat_cache,
            remember_api_compat,
        )

        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        clear_api_compat_cache()
        payload = {
            "model": "vendor-x", "messages": [], "max_tokens": 50,
            "top_p": 0.9,
        }
        patched, prof = adapt_payload_for_400(
            payload, "Unsupported parameter: 'top_p'.")
        remember_api_compat("vendor-x-provider", "vendor-x", prof)
        next_payload = build_chat_payload(
            model="vendor-x", provider="vendor-x-provider",
            messages=[{"role": "user", "content": "hi"}],
        )
        assert "top_p" not in next_payload

    def test_adapt_temperature_rejection(self):
        from agent.llm import adapt_payload_for_400

        payload = {
            "model": "o3-mini",
            "messages": [],
            "max_completion_tokens": 50,
            "temperature": 0.2,
        }
        err = "Unsupported value: 'temperature' is not supported with this model."
        result = adapt_payload_for_400(payload, err)
        assert result is not None
        patched, prof = result
        assert "temperature" not in patched
        assert prof.send_temperature is False

    def test_adapt_gpt5_tools_sets_reasoning_effort_none(self):
        from agent.llm import adapt_payload_for_400

        payload = {
            "model": "gpt-5.6-example",
            "messages": [],
            "max_completion_tokens": 100,
            "tools": [{"type": "function", "function": {"name": "read_file"}}],
            "tool_choice": "auto",
        }
        err = (
            "Function tools with reasoning_effort are not supported for "
            "example-model in /v1/chat/completions. To use function tools, "
            "use /v1/responses or set reasoning_effort to 'none'."
        )
        result = adapt_payload_for_400(payload, err)
        assert result is not None
        patched, prof = result
        assert patched["reasoning_effort"] == "none"
        assert patched["tools"]
        assert prof.reasoning_effort == "none"

    def test_gpt5_tools_send_reasoning_effort_none(self, tmp_path, monkeypatch):
        from agent.llm import build_chat_payload, clear_api_compat_cache

        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        monkeypatch.delenv("ATLAS_LLM_MAX_COMPLETION_TOKENS", raising=False)
        clear_api_compat_cache()
        tools = [{"type": "function", "function": {"name": "read_file"}}]
        with_tools = build_chat_payload(
            model="gpt-5.6-example",
            provider="openai",
            messages=[{"role": "user", "content": "hi"}],
            tools=tools,
            max_tokens=100,
        )
        assert with_tools["reasoning_effort"] == "none"
        assert with_tools["tools"] == tools
        without = build_chat_payload(
            model="gpt-5.6-example",
            provider="openai",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=100,
        )
        assert "reasoning_effort" not in without

    def test_hub_glm_tools_omit_reasoning_effort(self, tmp_path, monkeypatch):
        from agent.llm import build_chat_payload, clear_api_compat_cache

        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        monkeypatch.setenv("ATLAS_LLM_COMPAT_SOFT_HINTS", "0")
        clear_api_compat_cache()
        p = build_chat_payload(
            model="GLM-5.2",
            provider="llmhub",
            messages=[{"role": "user", "content": "hi"}],
            tools=[{"type": "function", "function": {"name": "read_file"}}],
            max_tokens=256,
        )
        assert "reasoning_effort" not in p
        assert p["max_tokens"] == 256

    def test_llmhub_glm_stays_classic(self, tmp_path, monkeypatch):
        from agent.llm import (
            build_chat_payload,
            clear_api_compat_cache,
            resolve_api_compat,
        )
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        monkeypatch.delenv("ATLAS_LLM_MAX_COMPLETION_TOKENS", raising=False)
        clear_api_compat_cache()
        prof = resolve_api_compat("llmhub", "GLM-5.2")
        assert prof.completion_limit == "max_tokens"
        assert prof.send_temperature is True
        p = build_chat_payload(
            model="GLM-5.2",
            provider="llmhub",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=256,
            temperature=0.2,
        )
        assert p["max_tokens"] == 256
        assert p["temperature"] == 0.2

    def test_openai_and_llmhub_profiles_are_isolated(self, tmp_path, monkeypatch):
        from agent.llm import (
            ApiCompatProfile,
            clear_api_compat_cache,
            remember_api_compat,
            resolve_api_compat,
        )
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "c.json"))
        clear_api_compat_cache()
        remember_api_compat(
            "openai", "gpt-5.6-example",
            ApiCompatProfile(
                completion_limit="max_completion_tokens",
                send_temperature=False,
            ),
        )
        # Same model id on llmhub must not inherit OpenAI's learned dialect
        # unless separately learned (hub may still host that id someday).
        import agent.llm as llm
        llm._compat_loaded = False
        hub = resolve_api_compat("llmhub", "gpt-5.6-example")
        # soft hint may apply for gpt-5 name, but key is separate from openai
        oai = resolve_api_compat("openai", "gpt-5.6-example")
        assert oai.completion_limit == "max_completion_tokens"
        assert oai.source == "learned"
        assert hub.source in ("soft", "default", "learned")

    def test_hub_detail_json_error_normalized(self):
        from agent.llm import adapt_payload_for_400, normalize_error_body

        body = json.dumps({
            "detail": (
                "Unsupported parameter: 'max_tokens'. "
                "Use 'max_completion_tokens' instead."
            ),
        })
        assert "max_completion_tokens" in normalize_error_body(body)
        result = adapt_payload_for_400(
            {"model": "x", "messages": [], "max_tokens": 10},
            body,
        )
        assert result is not None
        assert "max_completion_tokens" in result[0]


class TestTurnTimeBudget:
    """A caller whose call runs under its own deadline passes it, so the
    reply cut and the lower rungs of the ladder fit inside."""

    def test_the_argument_sets_the_budget_and_the_environment_applies_without_it(self, monkeypatch):
        from agent.llm import LLMHubClient, REPLY_SHARE
        monkeypatch.setenv("ATLAS_AGENT_TURN_TIME_BUDGET", "1200")
        assert LLMHubClient(provider="llmhub", turn_time_budget=10).turn_time_budget == 10
        assert 10 * REPLY_SHARE == 5
        assert LLMHubClient(provider="llmhub").turn_time_budget == 1200


def test_the_reasoning_client_learns_under_the_resolved_provider(monkeypatch):
    """Their backend variable becomes the transport kind once the provider is
    resolved; the client must still be told the provider's name, so the
    request shape is learned under the key the analyst uses."""
    import tools.reasoning as reasoning
    from core.paths import REASON_TIMEOUT
    seen = {}

    class _Stop(Exception):
        pass

    def _fake_client(**kw):
        seen.update(kw)
        raise _Stop

    monkeypatch.setattr(reasoning, "REASON_PROVIDER", "llmhub")
    monkeypatch.setattr(reasoning, "REASON_BACKEND", "openai-compat")
    monkeypatch.setattr(reasoning, "REASON_URL", "http://hub.example.invalid/v1")
    monkeypatch.setattr("agent.llm.LLMHubClient", _fake_client)
    try:
        reasoning._ask_openai_compat("sys", "user", "reason_evaluate_finding")
    except _Stop:
        pass
    assert seen.get("provider") == "llmhub"
    assert seen.get("turn_time_budget") == REASON_TIMEOUT


class TestFirewallRefusal:
    """A gateway's web application firewall answers 418, or 403 with a
    notice naming the firewall. Both are WAFBlockedError, which the loop
    answers by dropping the offending tool output; a plain 403 (a key
    without access) stays an ordinary error the operator has to see."""

    def _chat(self, monkeypatch, status, text):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        monkeypatch.setattr("agent.llm.time.sleep", lambda _s: None)

        def _post(url, json=None, headers=None, timeout=None):
            class _R:
                status_code = status
                headers = {}
            _R.text = text
            return _R()

        monkeypatch.setattr("agent.llm.httpx.post", _post)
        LLMHubClient(base_url="http://h/v1", api_key="k", model="m",
                     provider="custom").chat([{"role": "user", "content": "hi"}])

    @pytest.mark.parametrize("status,text", [
        (418, ""),
        (403, "<html>Request blocked by the Web Application Firewall</html>"),
        (403, '{"error": "WAF policy violation"}'),
        (403, "<title>403 Forbidden</title> AWS WAF"),
        (403, "Access denied by ExampleWAF (reference 0a1b2c)"),
    ])
    def test_a_firewall_refusal_is_recognised(self, monkeypatch, status, text):
        from agent.llm import WAFBlockedError
        with pytest.raises(WAFBlockedError):
            self._chat(monkeypatch, status, text)

    @pytest.mark.parametrize("text", [
        '{"error": "model not allowed for this key"}',
        '{"error": "quota exceeded for wafer-scale-model"}',
        '{"error": "forbidden", "request_id": "req_9wafx1"}',
        '{"error": "forbidden", "request_id": "req_9waf"}',
    ])
    def test_a_plain_forbidden_is_not_a_firewall_refusal(self, monkeypatch, text):
        from agent.llm import WAFBlockedError
        with pytest.raises(LLMError) as err:
            self._chat(monkeypatch, 403, text)
        assert not isinstance(err.value, WAFBlockedError)
        assert "HTTP 403" in str(err.value)
