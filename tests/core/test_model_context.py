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

    def fake_fetch(*, base_url, headers, timeout=20.0):
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
