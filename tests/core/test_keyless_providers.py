"""A provider bound to a profile that takes no key (a local server) is ready
without one, everywhere a key used to be demanded; a provider whose profile
needs a key, the fallback included, is still refused without it
(core.providers.Provider.key_missing). Invented endpoints only."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from core import providers

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def env(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("ATLAS_PROVIDER") or k in ("ATLAS_AGENT_PROVIDER", "ATLAS_REVIEW_PROVIDER"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ATLAS_PROVIDERS", "ollama,gw,mygw")
    monkeypatch.setenv("ATLAS_PROVIDER_OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OLLAMA_MODEL", "llama-local")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_PRESET", "openrouter")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_MODEL", "vendor/model-a")
    monkeypatch.setenv("ATLAS_PROVIDER_MYGW_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_MYGW_MODEL", "model-b")
    return monkeypatch


def test_a_keyless_profile_misses_no_key_and_a_keyed_one_and_the_fallback_do(env):
    assert providers.resolve("ollama").needs_api_key is False
    assert providers.resolve("ollama").key_missing is False
    assert providers.resolve("gw").key_missing is True
    assert providers.resolve("mygw").profile == "custom" and providers.resolve("mygw").key_missing is True
    env.setenv("ATLAS_PROVIDER_GW_API_KEY", "k-123")
    assert providers.resolve("gw").key_missing is False


def test_the_client_asks_the_same_test(env):
    from agent.llm import LLMHubClient
    assert LLMHubClient(provider="ollama").key_missing is False
    assert LLMHubClient(provider="gw").key_missing is True
    assert LLMHubClient(provider="gw", api_key="k-123").key_missing is False
    assert LLMHubClient(base_url="http://127.0.0.1:8000/v1").key_missing is False


def test_a_keyless_provider_is_sent_a_chat_with_no_auth_header(env, monkeypatch):
    from agent.llm import LLMError, LLMHubClient
    sent = []

    class Stop(Exception):
        pass

    def fake(*a, **kw):
        sent.append(kw.get("headers") or {})
        raise Stop()
    monkeypatch.setattr(httpx, "post", fake)
    monkeypatch.setattr(httpx, "stream", fake)
    with pytest.raises(Stop):
        LLMHubClient(provider="ollama").chat([{"role": "user", "content": "hi"}])
    assert sent and not any(k.lower() == "authorization" for k in sent[0])
    with pytest.raises(LLMError, match="refusing to send an unauthenticated chat request"):
        LLMHubClient(provider="gw").chat([{"role": "user", "content": "hi"}])


def test_the_run_start_and_the_reviewer_take_a_keyless_provider(env, monkeypatch, tmp_path):
    """The run's provider, model and key check is _analyst_client, which every
    session start passes before any step that changes the case."""
    from agent import cli

    class Passed(BaseException):        # past the probe's own "except Exception"
        pass
    env.setenv("ATLAS_AGENT_PROVIDER", "ollama")
    monkeypatch.setattr("core.model_context.probe_and_apply", lambda *a, **k: (_ for _ in ()).throw(Passed()))
    with pytest.raises(Passed):
        cli._analyst_client(SimpleNamespace(model="", quiet=True))
    env.setenv("ATLAS_AGENT_PROVIDER", "gw")
    with pytest.raises(SystemExit, match="no API key for provider 'gw'"):
        cli._analyst_client(SimpleNamespace(model="", quiet=True))
    env.setenv("ATLAS_REVIEW_PROVIDER", "ollama")
    assert cli._build_reviewer_client(SimpleNamespace(review_model="", model="")).provider.name == "ollama"
    env.setenv("ATLAS_REVIEW_PROVIDER", "gw")
    with pytest.raises(SystemExit, match="no API key"):
        cli._build_reviewer_client(SimpleNamespace(review_model="", model=""))


def test_the_model_list_and_provider_use_take_a_keyless_provider(env, monkeypatch, capsys):
    from agent import cli
    from agent.llm import LLMHubClient

    class Passed(Exception):
        pass
    monkeypatch.setattr(LLMHubClient, "list_models", lambda self: (_ for _ in ()).throw(Passed()))
    with pytest.raises(Passed):
        cli.cmd_models(SimpleNamespace(provider="ollama", json=False))
    with pytest.raises(SystemExit, match="no API key configured"):
        cli.cmd_models(SimpleNamespace(provider="gw", json=False))
    use = dict(role="analyst", model="", no_probe=True, dry_run=True, env=False)
    cli.cmd_provider_use(SimpleNamespace(name="ollama", **use))
    assert "--dry-run: nothing written" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="has no API key"):
        cli.cmd_provider_use(SimpleNamespace(name="gw", **use))


def test_answer_composition_has_a_client_for_a_keyless_provider(env):
    from core import answer_synthesis
    env.setenv("ATLAS_AGENT_PROVIDER", "ollama")
    answer_synthesis._COMPOSE_CLIENTS.held = None
    assert answer_synthesis._compose_client() is not None
    env.setenv("ATLAS_AGENT_PROVIDER", "gw")
    answer_synthesis._COMPOSE_CLIENTS.held = None
    assert answer_synthesis._compose_client() is None


def test_no_caller_decides_on_the_key_by_itself():
    """Every gate asks key_missing; none tests the key's truth on its own."""
    gate = re.compile(r"if not (?:client|provider|self)\.api_key\b|not provider\.api_key or")
    files = [p for d in ("agent", "core", "dashboard", "tools", "plugins", "devtools")
             for p in sorted((REPO / d).rglob("*.py"))]
    hits = [(str(f.relative_to(REPO)), n) for f in files
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1) if gate.search(line)]
    assert hits == []


def test_the_dashboard_list_says_a_keyless_provider_needs_no_key(env):
    from dashboard import config_llm
    assert config_llm._provider_summary("ollama")["needs_api_key"] is False
    assert config_llm._provider_summary("gw")["needs_api_key"] is True
    assert config_llm._provider_summary("nosuch")["needs_api_key"] is True
