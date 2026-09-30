"""Provider selection, AUTH_PREFIX, and model-id safety — cases A–J.

No network. Covers three failure shapes: implicit llmhub fallback,
empty AUTH_PREFIX stripping Bearer, and browser-autofill 'Admin' as a model id.

Importers: pytest only. Callers: none in production. APIs under test are the
existing providers.resolve/role_name/assigned, llm_setup.probe, config_llm.save,
and model_context.probe_model_context. No new schemas.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core import llm_setup as ls
from core import providers
from dashboard import config_llm


@pytest.fixture
def clean_roles(monkeypatch):
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    for var in (
        "ATLAS_AGENT_PROVIDER", "ATLAS_REVIEW_PROVIDER",
        "ATLAS_REPORT_PROVIDER", "REASON_BACKEND", "DAIR_BACKEND",
        "LLMHUB_API_KEY", "LLMHUB_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


def _openrouter(monkeypatch, *, prefix=None, model="openai/gpt-4o-mini"):
    monkeypatch.setenv("ATLAS_PROVIDERS", "OpenRouter")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_BASE_URL",
                       "https://openrouter.ai/api/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_MODEL", model)
    monkeypatch.delenv("ATLAS_PROVIDER_OPENROUTER_AUTH_HEADER", raising=False)
    if prefix is None:
        monkeypatch.delenv("ATLAS_PROVIDER_OPENROUTER_AUTH_PREFIX",
                           raising=False)
    else:
        monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_AUTH_PREFIX", prefix)


class TestA_NoImplicitHub:
    def test_empty_resolve_is_not_llmhub(self, clean_roles):
        with pytest.raises(providers.ProviderNotConfigured, match="no model provider configured"):
            providers.resolve("")

    def test_unset_role_is_empty_not_llmhub(self, clean_roles):
        assert providers.role_name("ATLAS_AGENT_PROVIDER") == ""
        assert "llmhub" not in providers.assigned()

    def test_client_without_provider_does_not_become_hub(self, clean_roles):
        from agent.llm import LLMHubClient
        client = LLMHubClient()
        with pytest.raises(providers.ProviderNotConfigured):
            client.provider


class TestB_ExplicitHubStillWorks:
    def test_resolve_llmhub(self, clean_roles, monkeypatch):
        monkeypatch.setenv("LLMHUB_API_KEY", "hub-key")
        monkeypatch.setenv("LLMHUB_MODEL", "GLM-5.2")
        p = providers.resolve("llmhub")
        assert p.name == "llmhub"
        assert p.api_key == "hub-key"
        assert p.model == "GLM-5.2"
        assert p.headers()["Authorization"] == "Bearer hub-key"

    def test_role_selects_hub(self, clean_roles, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "llmhub")
        assert providers.role_name("ATLAS_AGENT_PROVIDER") == "llmhub"
        assert providers.assigned() == ["llmhub"]


class TestCD_AuthPrefixBearer:
    def test_c_missing_prefix_is_bearer(self, clean_roles, monkeypatch):
        _openrouter(monkeypatch, prefix=None)
        headers = providers.resolve("OpenRouter").headers()
        assert headers["Authorization"] == "Bearer sk-or-test"

    def test_d_empty_prefix_is_still_bearer(self, clean_roles, monkeypatch):
        _openrouter(monkeypatch, prefix="")
        headers = providers.resolve("OpenRouter").headers()
        assert headers["Authorization"] == "Bearer sk-or-test"
        assert not headers["Authorization"].startswith("sk-or-test")

    def test_probe_empty_prefix_sends_bearer(self, monkeypatch):
        seen = {}

        def fake_get(url, headers=None, timeout=20.0):
            seen["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"data": [{"id": "openai/gpt-4o-mini"}]}
            return resp

        monkeypatch.setattr("httpx.get", fake_get)
        result = ls.probe("https://openrouter.ai/api/v1", "sk-or-test",
                          auth_prefix="")
        assert result.ok
        assert seen["headers"]["Authorization"] == "Bearer sk-or-test"


class TestE_CustomAuthPrefix:
    def test_explicit_custom_prefix(self, clean_roles, monkeypatch):
        _openrouter(monkeypatch, prefix="Token ")
        headers = providers.resolve("OpenRouter").headers()
        assert headers["Authorization"] == "Token sk-or-test"

    def test_custom_header_blank_prefix_is_bare_token(self, clean_roles,
                                                      monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://gw.example/v1")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "abc")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_AUTH_HEADER", "X-API-Key")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_AUTH_PREFIX", "")
        headers = providers.resolve("gw").headers()
        assert headers["X-API-Key"] == "abc"
        assert "Authorization" not in headers


class TestFG_ModelProbe:
    def test_f_valid_model_probe_succeeds(self, monkeypatch, tmp_path):
        from core import model_context as mc

        monkeypatch.setenv("ATLAS_MODEL_CONTEXT_CACHE",
                           str(tmp_path / "cache.json"))
        monkeypatch.setenv("ATLAS_MODEL_CONTEXT_PROBE", "1")
        monkeypatch.delenv("ATLAS_MODEL_CONTEXT_TOKENS", raising=False)
        mc.clear_probed_window()

        def fake_fetch(*, base_url, headers, timeout=20.0):
            return [{"id": "openai/gpt-4o-mini", "context_length": 128000}]

        monkeypatch.setattr(mc, "fetch_models_payload", fake_fetch)
        result = mc.probe_model_context(
            base_url="https://openrouter.ai/api/v1",
            headers={"Authorization": "Bearer sk"},
            model="openai/gpt-4o-mini",
            provider="OpenRouter",
            use_cache_on_failure=False,
        )
        assert result.success
        assert result.source == "live"
        assert result.window_tokens == 128000

    def test_g_unknown_model_is_not_a_silent_fallback(self, monkeypatch,
                                                      tmp_path):
        from core import model_context as mc

        monkeypatch.setenv("ATLAS_MODEL_CONTEXT_CACHE",
                           str(tmp_path / "cache.json"))
        monkeypatch.setenv("ATLAS_MODEL_CONTEXT_PROBE", "1")
        monkeypatch.delenv("ATLAS_MODEL_CONTEXT_TOKENS", raising=False)
        mc.clear_probed_window()
        mc._write_cache_entry(
            "https://openrouter.ai/api/v1", "Admin", 64000,
            source_field="context_length", provider="OpenRouter",
        )

        def fake_fetch(*, base_url, headers, timeout=20.0):
            return [{"id": "openai/gpt-4o-mini", "context_length": 128000}]

        monkeypatch.setattr(mc, "fetch_models_payload", fake_fetch)
        result = mc.probe_model_context(
            base_url="https://openrouter.ai/api/v1",
            headers={"Authorization": "Bearer sk"},
            model="Admin",
            provider="OpenRouter",
            use_cache_on_failure=True,
        )
        assert result.success is False
        assert result.source == "unknown_model"
        assert "Admin" in result.error
        assert not result.window_tokens


class TestH_AdminIsNotAModel:
    def test_identity_ids_are_detected(self):
        assert ls.is_identity_model_id("Admin")
        assert ls.is_identity_model_id("admin")
        assert ls.is_identity_model_id("ANALYST")
        assert ls.is_identity_model_id("viewer")
        assert not ls.is_identity_model_id("openai/gpt-4o-mini")
        assert not ls.is_identity_model_id("GLM-5.2")

    def test_openrouter_preset_does_not_insert_admin(self):
        preset = ls.preset("openrouter")
        assert preset.default_model == ""
        assert not ls.is_identity_model_id(preset.default_model)

    def test_dashboard_html_does_not_prefill_admin_as_model(self):
        html = Path(__file__).resolve().parents[2].joinpath(
            "dashboard", "config.html").read_text(encoding="utf-8")
        assert 'id="llm-model"' in html
        assert 'name="atlas-llm-model-id"' in html
        assert 'autocomplete="off"' in html
        assert "admin/analyst/viewer" in html
        model_block = html.split('id="llm-model"', 1)[1].split("</div>", 1)[0]
        assert 'value="Admin"' not in model_block


class TestI_DashboardDoesNotWriteEmptyPrefix:
    def test_openrouter_save_omits_auth_prefix(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("", encoding="utf-8")
        monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        result = config_llm.save_provider({
            "preset_id": "openrouter", "name": "OpenRouter",
            "base_url": "https://openrouter.ai/api/v1",
            "model": "openai/gpt-4o-mini",
            "roles": ["analyst"], "skip_probe": True,
        })
        for key in result["updates"]:
            monkeypatch.delenv(key, raising=False)
        assert "AUTH_PREFIX" not in result["updates"]
        assert "AUTH_PREFIX" not in (tmp_path / ".env").read_text()
        assert result["updates"]["ATLAS_AGENT_PROVIDER"] == "OpenRouter"

    def test_admin_model_is_rejected_on_save(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("", encoding="utf-8")
        monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
        with pytest.raises(config_llm.ConfigError, match="dashboard role"):
            config_llm.save_provider({
                "preset_id": "openrouter", "name": "OpenRouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "Admin",
                "roles": ["analyst"], "skip_probe": True,
            })


class TestJ_ExistingExplicitConfigs:
    def test_named_gateway_still_resolves(self, clean_roles, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw-b")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_B_BASE_URL",
                           "https://gw.example/llm/b/v1")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_B_API_KEY", "gw-token")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_B_MODEL", "b-model-1")
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw-b")
        p = providers.resolve("gw-b")
        assert p.model == "b-model-1"
        assert p.headers()["Authorization"] == "Bearer gw-token"
        assert providers.assigned() == ["gw-b"]
        assert "llmhub" not in providers.assigned()


class TestIncompleteConfigErrors:
    def test_reason_unset_is_not_llmhub(self):
        from tools.reasoning import _active_backend, reason_hypothesize
        with patch("tools.reasoning.REASON_BACKEND", ""), \
             patch("tools.reasoning.REASON_URL", ""):
            assert _active_backend() == ""
            result = reason_hypothesize("observation")
        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_dair_unset_is_not_llmhub(self):
        from tools.dair import _active_backend, dair_assess
        with patch("tools.dair.DAIR_BACKEND", ""), \
             patch("tools.dair.DAIR_URL", ""):
            assert _active_backend() == ""
            result = dair_assess("findings")
        assert result["success"] is False
        assert "not configured" in result["error"]
