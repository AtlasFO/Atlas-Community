"""Model context probe — live /models metadata, no catalogue."""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_probe(monkeypatch, tmp_path):
    from core import model_context as mc

    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_CACHE", str(tmp_path / "cache.json"))
    monkeypatch.delenv("ATLAS_MODEL_CONTEXT_TOKENS", raising=False)
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_PROBE", "1")
    monkeypatch.setenv("ATLAS_CONTEXT_AUTO_CHARS", "1")
    monkeypatch.delenv("ATLAS_CONTEXT_CHARS_LOCK", raising=False)
    monkeypatch.delenv("ATLAS_AGENT_CONTEXT_CHARS", raising=False)
    mc.clear_probed_window()
    from core.llm_check import reset_session
    reset_session()
    yield
    mc.clear_probed_window()
    reset_session()


def test_extract_openrouter_context_length():
    from core.model_context import extract_context_tokens

    entry = {
        "id": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "context_length": 1_000_000,
        "top_provider": {"context_length": 1_000_000, "max_completion_tokens": 65536},
    }
    n, src = extract_context_tokens(entry)
    assert n == 1_000_000
    assert src == "context_length"


def test_extract_nested_top_provider_only():
    from core.model_context import extract_context_tokens

    entry = {
        "id": "x",
        "top_provider": {"context_length": 512_288},
    }
    n, src = extract_context_tokens(entry)
    assert n == 512_288
    assert src == "top_provider.context_length"


def test_extract_vllm_max_model_len():
    from core.model_context import extract_context_tokens

    n, src = extract_context_tokens({"id": "local", "max_model_len": 32768})
    assert n == 32768
    assert src == "max_model_len"


def test_match_prefers_exact_free_variant():
    from core.model_context import match_model_entry

    entries = [
        {"id": "nvidia/nemotron-3-ultra-550b-a55b", "context_length": 512288},
        {"id": "nvidia/nemotron-3-ultra-550b-a55b:free", "context_length": 1000000},
    ]
    hit = match_model_entry(
        entries, "nvidia/nemotron-3-ultra-550b-a55b:free")
    assert hit["id"].endswith(":free")
    assert hit["context_length"] == 1000000


def test_probe_live_applies_window_and_chars(monkeypatch):
    from core import model_context as mc
    from core import context_budget as cb

    payload = {
        "data": [
            {
                "id": "qwen/qwen3.7-flash",
                "context_length": 1_000_000,
            }
        ]
    }

    def fake_fetch(*, base_url, headers, timeout=20.0, paging="none"):
        return payload["data"]

    monkeypatch.setattr(mc, "fetch_models_payload", fake_fetch)
    result = mc.probe_and_apply(
        type("P", (), {
            "name": "llmhub",
            "base_url": "https://openrouter.ai/api/v1",
            "model": "qwen/qwen3.7-flash",
            "headers": lambda self: {"Authorization": "Bearer x"},
        })(),
        "qwen/qwen3.7-flash",
    )
    assert result.success
    assert result.window_tokens == 1_000_000
    assert mc.get_probed_window() == 1_000_000
    assert cb.resolve_window_tokens(model="qwen/qwen3.7-flash") == 1_000_000
    # Auto chars ≈ 1M * 4 * 0.75
    assert int(os.environ["ATLAS_AGENT_CONTEXT_CHARS"]) == 3_000_000


def test_env_override_beats_probe(monkeypatch):
    from core import model_context as mc
    from core import context_budget as cb

    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "64000")

    def boom(**kwargs):
        raise AssertionError("should not network")

    monkeypatch.setattr(mc, "fetch_models_payload", boom)
    result = mc.probe_model_context(
        base_url="https://example.test/v1",
        headers={},
        model="anything",
    )
    assert result.source == "env_override"
    assert result.window_tokens == 64000
    mc.apply_window(64000, source="env_override", adapt_chars=False)
    assert cb.resolve_window_tokens() == 64000


def test_cache_fallback_on_network_error(monkeypatch, tmp_path):
    from core import model_context as mc

    mc._write_cache_entry(
        "https://example.test/v1",
        "m1",
        256000,
        source_field="context_length",
        provider="llmhub",
    )

    def boom(**kwargs):
        raise RuntimeError("offline")

    monkeypatch.setattr(mc, "fetch_models_payload", boom)
    result = mc.probe_model_context(
        base_url="https://example.test/v1",
        headers={},
        model="m1",
    )
    assert result.success
    assert result.source == "cache"
    assert result.window_tokens == 256000


def test_chars_lock_prevents_auto_raise(monkeypatch):
    from core import model_context as mc

    monkeypatch.setenv("ATLAS_AGENT_CONTEXT_CHARS", "160000")
    monkeypatch.setenv("ATLAS_CONTEXT_CHARS_LOCK", "1")
    assert mc.adapt_agent_context_chars(1_000_000) is None
    assert os.environ["ATLAS_AGENT_CONTEXT_CHARS"] == "160000"


def test_chars_shrink_for_small_window(monkeypatch):
    from core import model_context as mc

    monkeypatch.setenv("ATLAS_AGENT_CONTEXT_CHARS", "400000")
    n = mc.adapt_agent_context_chars(16_000)
    assert n == 48_000
    assert os.environ["ATLAS_AGENT_CONTEXT_CHARS"] == "48000"


def test_reject_tiny_context_values():
    from core.model_context import extract_context_tokens

    n, _ = extract_context_tokens({"max_tokens": 2048})
    assert n is None


def test_probe_and_apply_network_failure_reports_not_success(monkeypatch):
    """A conservative guessed window is still installed on a network failure
    (so send budgets exist), but success must say False — it is not a
    confirmed probe, and nothing should mistake it for one. Must NOT be
    GLM-5.2's 1M-token product default: that default applied to an unknown
    (possibly much smaller) model would under-trim outgoing requests and let
    the provider silently head-truncate them."""
    from core import model_context as mc

    def boom(**kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(mc, "fetch_models_payload", boom)
    warnings = []
    result = mc.probe_and_apply(
        type("P", (), {
            "name": "custom",
            "base_url": "https://example.test/v1",
            "model": "some-local-8b",
            "headers": lambda self: {},
        })(),
        "some-local-8b",
        warn=warnings.append,
    )
    assert result.success is False
    assert result.source == "conservative_fallback"
    assert result.window_tokens == mc._CONSERVATIVE_FALLBACK_WINDOW
    assert result.window_tokens < 1_000_000
    assert warnings


def test_conservative_fallback_window_fits_the_real_system_prompt():
    """The fallback window must be able to hold Atlas's own playbook.

    A window whose send budget is smaller than the assembled system prompt
    makes fit_messages unable to fit *anything* — every run whose model
    probe fails would fail on turn 1. The first conservative value chosen
    (32k) was below the real ~25k-token prompt and did exactly that.
    """
    import pathlib

    from agent.prompts import build_system_prompt
    from core import model_context as mc
    from core.llm_check import _SEND_FRACTION, estimate_messages_tokens

    prompt = build_system_prompt(pathlib.Path("case-template"),
                                 interactive=False)
    prompt_tokens = estimate_messages_tokens(
        [{"role": "system", "content": prompt}])
    budget = int(mc._CONSERVATIVE_FALLBACK_WINDOW * _SEND_FRACTION)
    # Headroom for the case seed, evidence catalog and tool schemas that
    # ride along with the playbook — the prompt must not merely squeak in.
    assert prompt_tokens * 2 < budget, (
        f"system prompt is ~{prompt_tokens} tokens but the conservative "
        f"fallback send budget is only {budget}")


def test_an_alias_matches_its_newest_dated_snapshot_and_nothing_else():
    """Anthropic's list names a 4.5 model only by its dated snapshot; a model
    whose id merely starts with the alias is another model."""
    from core.model_context import match_model_entry

    entries = [{"id": "vendor-m-4-5-20310101", "max_input_tokens": 200_000},
               {"id": "vendor-m-4-5-20310301", "max_input_tokens": 210_000},
               {"id": "vendor-m-4-5-5", "max_input_tokens": 1_000_000},
               {"id": "other-m-2031-03-01", "context_length": 128_000}]
    assert match_model_entry(entries, "vendor-m-4-5")["id"] == "vendor-m-4-5-20310301"
    assert match_model_entry(entries, "other-m")["id"] == "other-m-2031-03-01"
    assert match_model_entry(entries, "vendor-m-4") is None


# What each provider's model list states, as its docs show the entry (values
# invented): the window is read, never an output cap beside it; a list that
# states no window reads as none (the probe falls back).
@pytest.mark.parametrize("provider, entry, expected", [
    ("anthropic", {"id": "m", "type": "model", "max_input_tokens": 1_000_000, "max_tokens": 128_000},
     (1_000_000, "max_input_tokens")),
    ("litellm-anthropic-shape", {"id": "m", "type": "model", "max_input_tokens": 200_000, "max_tokens": 64_000},
     (200_000, "max_input_tokens")),
    ("litellm", {"id": "m", "object": "model", "max_input_tokens": 200_000, "max_output_tokens": 64_000},
     (200_000, "max_input_tokens")),
    ("openrouter", {"id": "v/m", "context_length": 262_144,
                    "top_provider": {"context_length": 131_072, "max_completion_tokens": 32_768}},
     (262_144, "context_length")),
    ("groq", {"id": "m", "object": "model", "context_window": 131_072, "max_completion_tokens": 32_768},
     (131_072, "context_window")),
    ("together", {"id": "o/m", "type": "chat", "context_length": 131_072}, (131_072, "context_length")),
    ("mistral", {"id": "m", "object": "model", "max_context_length": 131_072,
                 "capabilities": {"completion_chat": True}}, (131_072, "max_context_length")),
    ("deepseek", {"id": "m", "context_window": 131_072, "max_output_tokens": 8_192}, (131_072, "context_window")),
    ("xai", {"id": "m", "context_length": 256_000}, (256_000, "context_length")),
    ("vllm", {"id": "m", "object": "model", "max_model_len": 32_768, "root": "m"}, (32_768, "max_model_len")),
    ("llmhub", {"id": "M", "meta_data": {"max_sequence_length": 1_000_000}},
     (1_000_000, "meta_data.max_sequence_length")),
    ("openai, azure-openai, ollama, cerebras", {"id": "m", "object": "model", "created": 1, "owned_by": "x"},
     (None, "")),
    ("llama.cpp: training context, not the served window", {"id": "m", "meta": {"n_ctx_train": 131_072}},
     (None, "")),
])
def test_each_providers_model_list_gives_its_window(provider, entry, expected):
    from core.model_context import extract_context_tokens

    assert extract_context_tokens(entry) == expected, provider


def test_the_probe_sends_the_providers_own_headers(monkeypatch):
    """Anthropic's model list answers only with its version header."""
    from types import SimpleNamespace

    from core import model_context as mc

    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen.update(headers or {})
        return SimpleNamespace(status_code=200, text="", json=lambda: {"data": [
            {"id": "m", "max_input_tokens": 1_000_000, "max_tokens": 128_000}]})

    monkeypatch.setattr("httpx.get", fake_get)
    provider = SimpleNamespace(base_url="https://api.example.com/v1", name="p", model="m",
                               headers=lambda: {"x-api-key": "k", "anthropic-version": "2023-06-01"},
                               headers_extra=(("anthropic-version", "2023-06-01"),))
    result = mc.probe_and_apply(provider, "m")
    assert seen.get("anthropic-version") == "2023-06-01"
    assert (result.window_tokens, result.source_field) == (1_000_000, "max_input_tokens")


# ── a model list in pages (Anthropic's: limit, after_id, has_more, last_id) ──

class _TwoPages:
    """A list of two pages, as a cursor-paged model list answers."""

    def __init__(self):
        self.asked = []

    def __call__(self, url, headers=None, timeout=None, params=None):
        from types import SimpleNamespace
        self.asked.append(dict(params or {}))
        after = (params or {}).get("after_id")
        body = ({"data": [{"id": "m-1", "max_input_tokens": 200_000, "max_tokens": 64_000}],
                 "has_more": True, "first_id": "m-1", "last_id": "m-1"} if after is None else
                {"data": [{"id": "m-2", "max_input_tokens": 1_000_000, "max_tokens": 128_000}],
                 "has_more": False, "first_id": "m-2", "last_id": "m-2"})
        return SimpleNamespace(status_code=200, text="", json=lambda: body)


def test_a_paged_model_list_is_read_to_its_end(monkeypatch):
    from core import llmhub
    pages = _TwoPages()
    monkeypatch.setattr("httpx.get", pages)
    _resp, entries = llmhub.get_models("https://api.example.com/v1", {}, paging="after_id")
    assert [e["id"] for e in entries] == ["m-1", "m-2"]
    assert pages.asked == [{"limit": 1000}, {"limit": 1000, "after_id": "m-1"}]
    pages.asked.clear()
    _resp, entries = llmhub.get_models("https://api.example.com/v1", {})          # no paging: one request
    assert [e["id"] for e in entries] == ["m-1"] and pages.asked == [{}]


def test_a_repeated_cursor_ends_the_reading(monkeypatch):
    from types import SimpleNamespace
    from core import llmhub
    calls = []

    def same(url, headers=None, timeout=None, params=None):
        calls.append(params)
        return SimpleNamespace(status_code=200, text="", json=lambda: {
            "data": [{"id": "m-1"}], "has_more": True, "last_id": "m-1"})
    monkeypatch.setattr("httpx.get", same)
    _resp, entries = llmhub.get_models("https://api.example.com/v1", {}, paging="after_id")
    assert len(calls) == 2 and len(entries) == 2


def test_a_model_on_the_second_page_is_found_everywhere_the_list_is_read(monkeypatch):
    """The context probe, the listing, Test connection and provider use all
    read every page, so a model past the first one is never "unknown"."""
    from types import SimpleNamespace
    from agent import cli
    from agent.llm import LLMHubClient
    from core import llm_setup, model_context as mc, providers
    monkeypatch.setattr("httpx.get", _TwoPages())
    monkeypatch.setenv("ATLAS_PROVIDERS", "claude-a")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_BASE_URL", "https://api.anthropic.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_PRESET", "anthropic")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_MODEL", "m-2")
    monkeypatch.setenv("ATLAS_PROVIDER_CLAUDE_A_API_KEY", "k-test")
    p = providers.resolve("claude-a")
    assert p.models_paging == "after_id"
    result = mc.probe_and_apply(p, "m-2")
    assert (result.source, result.window_tokens) == ("live", 1_000_000)
    assert LLMHubClient(provider="claude-a").list_models() == ["m-1", "m-2"]
    assert llm_setup.probe(p.base_url, p.api_key, profile_id="anthropic").models == ["m-1", "m-2"]
    cli.cmd_provider_use(SimpleNamespace(name="claude-a", model="", role="analyst", no_probe=False,
                                         dry_run=True))       # exits when m-2 is not in the list
