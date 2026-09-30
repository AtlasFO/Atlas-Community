"""Tests for core/providers.py — named model providers. No network.

The load-bearing test here is TestDefaultUnchanged: registering a second
provider must not move an installation that registers none.
"""
import pytest
from unittest.mock import patch

from core import llmhub, providers
from agent.llm import LLMHubClient, LLMError

GATEWAY = "https://gw.example/llm/b/v1"


@pytest.fixture
def two_providers(monkeypatch):
    """The configuration this feature was built for: two gateway routes."""
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw-a,gw-b")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_B_BASE_URL", GATEWAY)
    monkeypatch.setenv("ATLAS_PROVIDER_GW_B_API_KEY", "gw-token")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_B_MODEL", "b-model-1")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_A_BASE_URL",
                       "https://gw.example/llm/a/v1")


class TestDefaultUnchanged:
    """Nothing may move for an installation that declares no providers."""

    def test_no_declarations_means_only_llmhub(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        assert providers.names() == ["llmhub"]
        assert providers.declared() == []

    def test_default_mirrors_llmhub_module(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        monkeypatch.setenv("LLMHUB_API_KEY", "hub-key")
        provider = providers.resolve("llmhub")
        assert provider.name == "llmhub"
        assert provider.base_url == llmhub.base_url()
        assert provider.api_key == llmhub.api_key()
        assert provider.model == llmhub.model()

    def test_empty_name_is_not_configured(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        with pytest.raises(providers.ProviderNotConfigured):
            providers.resolve("")

    def test_llmhub_resolves_even_when_undeclared(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        assert providers.resolve("llmhub").base_url == llmhub.base_url()

    def test_default_client_headers_are_unchanged_bearer(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
        monkeypatch.setenv("LLMHUB_API_KEY", "hub-key")
        headers = LLMHubClient(provider="llmhub")._headers()
        assert headers["Authorization"] == "Bearer hub-key"
        assert headers["Content-Type"] == "application/json"


class TestEnvVarNaming:
    def test_dash_becomes_underscore_and_upper(self):
        assert providers.var("gw-b", "BASE_URL") == \
            "ATLAS_PROVIDER_GW_B_BASE_URL"

    def test_already_upper_is_stable(self):
        assert providers.var("GW_B", "MODEL") == \
            "ATLAS_PROVIDER_GW_B_MODEL"

    def test_api_key_env_names_follow_declarations(self, two_providers):
        assert providers.api_key_env_names() == [
            "ATLAS_PROVIDER_GW_A_API_KEY",
            "ATLAS_PROVIDER_GW_B_API_KEY",
        ]


class TestDeclared:
    def test_order_preserved(self, two_providers):
        assert providers.declared() == ["gw-a", "gw-b"]
        assert providers.names() == [
            "llmhub", "gw-a", "gw-b"]

    def test_whitespace_and_blanks_tolerated(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", " a , , b ,")
        assert providers.declared() == ["a", "b"]

    def test_duplicates_collapse(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "a,a,b")
        assert providers.declared() == ["a", "b"]

    def test_llmhub_is_implicit_not_duplicated(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "llmhub,a")
        assert providers.declared() == ["a"]
        assert providers.names() == ["llmhub", "a"]

    def test_malformed_entries_are_reported_not_silently_dropped(
            self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "good,bad name,-lead")
        assert providers.declared() == ["good"]
        assert providers.malformed() == ["bad name", "-lead"]


class TestUnknownProvider:
    def test_undeclared_name_raises_and_lists_the_valid_ones(
            self, two_providers):
        with pytest.raises(providers.UnknownProvider) as excinfo:
            providers.resolve("gw-v")  # typo
        message = str(excinfo.value)
        assert "gw-v" in message
        # The point of the exception: it has to say what would have worked.
        assert "gw-b" in message
        assert "llmhub" in message

    def test_declared_without_base_url_raises(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "half-configured")
        monkeypatch.delenv("ATLAS_PROVIDER_HALF_CONFIGURED_BASE_URL",
                           raising=False)
        with pytest.raises(providers.UnknownProvider) as excinfo:
            providers.resolve("half-configured")
        assert "ATLAS_PROVIDER_HALF_CONFIGURED_BASE_URL" in str(excinfo.value)


class TestResolveNamed:
    def test_fields(self, two_providers):
        provider = providers.resolve("gw-b")
        assert provider.name == "gw-b"
        assert provider.base_url == GATEWAY
        assert provider.api_key == "gw-token"
        assert provider.model == "b-model-1"

    def test_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY + "/")
        assert providers.resolve("gw").base_url == GATEWAY

    def test_missing_model_stays_empty(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY)
        monkeypatch.delenv("ATLAS_PROVIDER_GW_MODEL", raising=False)
        assert providers.resolve("gw").model == ""


class TestUrlBuilding:
    """The gateway routes end in /v1, which core/llmhub.py already handles."""

    def test_gateway_v1_chat_url(self, two_providers):
        assert providers.resolve("gw-b").chat_url() == \
            GATEWAY + "/chat/completions"

    def test_gateway_v1_models_url(self, two_providers):
        assert providers.resolve("gw-b").models_url() == \
            GATEWAY + "/models"

    def test_llmhub_route_too(self, two_providers):
        assert providers.resolve("gw-a").models_url() == \
            "https://gw.example/llm/a/v1/models"


class TestHeaders:
    def test_bearer_by_default(self, two_providers):
        headers = providers.resolve("gw-b").headers()
        assert headers["Authorization"] == "Bearer gw-token"

    def test_custom_header_and_prefix(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY)
        monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "abc")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_AUTH_HEADER", "X-API-Key")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_AUTH_PREFIX", "")
        headers = providers.resolve("gw").headers()
        assert headers["X-API-Key"] == "abc"
        assert "Authorization" not in headers

    def test_blank_authorization_prefix_is_bearer(self, monkeypatch):
        """Unset and blank AUTH_PREFIX on Authorization both mean Bearer.

        An empty assignment in .env used to strip 'Bearer ' and OpenRouter
        answered 401 Missing Authentication header.
        """
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY)
        monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "abc")
        monkeypatch.delenv("ATLAS_PROVIDER_GW_AUTH_PREFIX", raising=False)
        assert providers.resolve("gw").headers()["Authorization"] == "Bearer abc"
        monkeypatch.setenv("ATLAS_PROVIDER_GW_AUTH_PREFIX", "")
        assert providers.resolve("gw").headers()["Authorization"] == "Bearer abc"

    def test_no_auth_header_without_a_key(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY)
        monkeypatch.delenv("ATLAS_PROVIDER_GW_API_KEY", raising=False)
        assert "Authorization" not in providers.resolve("gw").headers()


class TestRoleName:
    def test_unset_role_is_empty(self, monkeypatch):
        monkeypatch.delenv("ATLAS_AGENT_PROVIDER", raising=False)
        assert providers.role_name("ATLAS_AGENT_PROVIDER") == ""

    def test_first_set_var_wins(self, monkeypatch):
        monkeypatch.setenv("ATLAS_REPORT_PROVIDER", "a")
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "b")
        assert providers.role_name("ATLAS_REPORT_PROVIDER",
                                   "ATLAS_AGENT_PROVIDER") == "a"

    def test_falls_through_empty_var(self, monkeypatch):
        monkeypatch.setenv("ATLAS_REPORT_PROVIDER", "")
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "b")
        assert providers.role_name("ATLAS_REPORT_PROVIDER",
                                   "ATLAS_AGENT_PROVIDER") == "b"


class TestClientProviderSelection:
    """The gap this feature closes: analyst and reviewer could not previously
    be pointed at another endpoint at all."""

    def test_client_follows_named_provider(self, two_providers):
        client = LLMHubClient(provider="gw-b")
        assert client.base_url == GATEWAY
        assert client.api_key == "gw-token"
        assert client.model == "b-model-1"

    def test_constructor_override_beats_provider(self, two_providers):
        client = LLMHubClient(provider="gw-b", model="other")
        assert client.model == "other"

    def test_chat_url_targets_the_gateway(self, two_providers):
        client = LLMHubClient(provider="gw-b")
        assert llmhub.build_chat_url(client.base_url) == \
            GATEWAY + "/chat/completions"

    def test_named_provider_never_inherits_the_hub_model(self, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", GATEWAY)
        monkeypatch.delenv("ATLAS_PROVIDER_GW_MODEL", raising=False)
        monkeypatch.setenv("LLMHUB_MODEL", "GLM-5.2")
        client = LLMHubClient(provider="gw")
        # Inheriting GLM-5.2 here would send a model id the gateway's own
        # catalogue never had, and record it in the trace as if intended.
        with pytest.raises(LLMError) as excinfo:
            client.model
        assert "ATLAS_PROVIDER_GW_MODEL" in str(excinfo.value)

    def test_unknown_provider_surfaces_on_use(self, two_providers):
        client = LLMHubClient(provider="nope")
        with pytest.raises(providers.UnknownProvider):
            client.base_url


class TestBackendPositiveList:
    """An unrecognised REASON_BACKEND/DAIR_BACKEND used to fall through to
    openai-compat silently. With a second endpoint registered that would run
    the reviewer against the wrong model and label it correctly."""

    def test_reason_rejects_an_unknown_backend(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_BACKEND", "gw-b-typo"), \
             patch("tools.reasoning._BACKEND_CONFIG_ERROR", ""):
            result = reason_hypothesize("observation")
        assert result["success"] is False
        assert "not a known backend" in result["error"]
        assert "openai-compat" in result["error"]

    def test_reason_still_accepts_openai_compat(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            assert _active_backend() == "openai-compat"

    def test_reason_reports_an_unresolvable_provider(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_BACKEND", "openai-compat"), \
             patch("tools.reasoning._BACKEND_CONFIG_ERROR",
                   "REASON_BACKEND is unusable: unknown model provider 'x'"):
            result = reason_hypothesize("observation")
        assert result["success"] is False
        assert "unusable" in result["error"]

    def test_reason_claude_tombstone_survives(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_BACKEND", "claude"):
            result = reason_hypothesize("observation")
        assert result["success"] is False
        assert "no longer supported" in result["error"]

    def test_dair_rejects_an_unknown_backend(self):
        from tools.dair import dair_assess
        with patch("tools.dair.DAIR_BACKEND", "gw-b-typo"), \
             patch("tools.dair._BACKEND_CONFIG_ERROR", ""):
            result = dair_assess("some findings")
        assert result["success"] is False
        assert "not a known backend" in result["error"]

    def test_dair_claude_tombstone_survives(self):
        from tools.dair import dair_assess
        with patch("tools.dair.DAIR_BACKEND", "claude"):
            result = dair_assess("some findings")
        assert result["success"] is False
        assert "no longer supported" in result["error"]


class TestProviderCli:
    """`atlas provider use` is the supported way to switch. If a role name here
    drifts from the env var the resolver reads, the switch writes a variable
    nothing consults — and `doctor` would still report the old provider."""

    def test_role_map_covers_every_model_surface(self):
        from agent.cli import PROVIDER_ROLE_VARS
        assert PROVIDER_ROLE_VARS == {
            "analyst": "ATLAS_AGENT_PROVIDER",
            "reviewer": "ATLAS_REVIEW_PROVIDER",
            "report": "ATLAS_REPORT_PROVIDER",
            # reason/dair reuse the vars that already accept a provider name,
            # rather than introducing a second way to say the same thing.
            "reason": "REASON_BACKEND",
            "dair": "DAIR_BACKEND",
        }

    def test_role_vars_are_the_ones_the_resolver_reads(self, two_providers,
                                                       monkeypatch):
        from agent.cli import PROVIDER_ROLE_VARS
        for var in PROVIDER_ROLE_VARS.values():
            monkeypatch.setenv(var, "gw-b")
        assert providers.role_name("ATLAS_AGENT_PROVIDER") == "gw-b"
        assert providers.role_name("ATLAS_REVIEW_PROVIDER") == "gw-b"
        assert providers.role_name("ATLAS_REPORT_PROVIDER",
                                   "ATLAS_AGENT_PROVIDER") == "gw-b"

    def test_parser_accepts_the_documented_invocation(self):
        from agent import cli
        args = cli.build_parser().parse_args(
            ["provider", "use", "gw-b", "--role", "reviewer",
             "--model", "b-model-1", "--dry-run"])
        assert args.name == "gw-b"
        assert args.role == "reviewer"
        assert args.model == "b-model-1"
        assert args.dry_run is True
        assert args.no_probe is False
        assert args.func is cli.cmd_provider_use

    def test_parser_defaults_to_all_roles_with_probe_on(self):
        from agent import cli
        args = cli.build_parser().parse_args(["provider", "use", "llmhub"])
        assert args.role == "all"
        assert args.no_probe is False

    def test_parser_rejects_an_unknown_role(self):
        from agent import cli
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(
                ["provider", "use", "llmhub", "--role", "typo"])

    def test_provider_list_is_wired(self):
        from agent import cli
        args = cli.build_parser().parse_args(["provider", "list"])
        assert args.func is cli.cmd_provider_list


class TestSecretsKeyring:
    def test_provider_keys_are_keyring_managed(self, two_providers):
        from core import secrets
        keys = secrets.managed_keys()
        assert "ATLAS_PROVIDER_GW_B_API_KEY" in keys
        # The static list must survive alongside the derived names.
        assert "LLMHUB_API_KEY" in keys

    def test_no_duplicates_when_a_name_collides(self, monkeypatch):
        from core import secrets
        monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
        keys = secrets.managed_keys()
        assert len(keys) == len(set(keys))
