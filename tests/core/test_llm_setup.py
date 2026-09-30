"""Tests for core/llm_setup.py — the logic behind `atlas provider setup`.

No network here (probe() is exercised via its error path only, which needs
no live endpoint); everything else is pure data/string manipulation and is
tested as such.
"""
import pytest

from core import llm_setup as ls
from core import providers


class TestPresets:
    def test_every_preset_is_reachable_by_id(self):
        for p in ls.PRESETS:
            assert ls.preset(p.id) is p

    def test_unknown_preset_raises_with_known_ids_listed(self):
        with pytest.raises(KeyError, match="llmhub"):
            ls.preset("does-not-exist")

    def test_no_preset_is_pre_selected(self):
        assert sum(1 for p in ls.PRESETS if p.default_choice) == 0

    def test_llmhub_remains_a_selectable_preset(self):
        hub = ls.preset("llmhub")
        assert hub.id == "llmhub"
        assert "GLM-5.2" in hub.default_model
        assert "GLM-5.2" in hub.notes

    def test_openrouter_preset_has_no_default_model(self):
        orouter = ls.preset("openrouter")
        assert orouter.base_url == "https://openrouter.ai/api/v1"
        assert orouter.default_model == ""
        assert not ls.is_identity_model_id(orouter.default_model)

    def test_local_preset_does_not_require_a_key(self):
        assert ls.preset("local").needs_api_key is False

    def test_openai_preset_notes_the_responses_api_gap(self):
        # Regression guard: don't silently drop this caveat in a future edit.
        assert "Responses API" in ls.preset("openai").notes


class TestValidateName:
    def test_default_name_always_valid(self):
        assert ls.validate_name(providers.DEFAULT_NAME) is None

    def test_empty_name_rejected(self):
        assert ls.validate_name("") is not None
        assert ls.validate_name("   ") is not None

    @pytest.mark.parametrize("name", ["openai", "my-gateway", "gw_1", "a1"])
    def test_well_formed_names_accepted(self, name):
        assert ls.validate_name(name) is None

    @pytest.mark.parametrize("name", ["bad name", "-leading-dash", "has/slash"])
    def test_malformed_names_rejected(self, name):
        assert ls.validate_name(name) is not None


class TestKeyEnvVar:
    def test_default_provider_uses_llmhub_var(self):
        assert ls.key_env_var(providers.DEFAULT_NAME) == "LLMHUB_API_KEY"

    def test_named_provider_uses_provider_var(self):
        assert ls.key_env_var("my-gateway") == "ATLAS_PROVIDER_MY_GATEWAY_API_KEY"


class TestRegisterProviderUpdates:
    def test_llmhub_writes_llmhub_vars_only(self):
        choice = ls.SetupChoice(preset_id="llmhub", base_url="https://hub/v2",
                                model="GLM-5.2")
        updates = ls.register_provider_updates(choice)
        assert updates == {
            "LLMHUB_BASE_URL": "https://hub/v2",
            "LLMHUB_MODEL": "GLM-5.2",
        }

    def test_llmhub_without_model_omits_model_key(self):
        choice = ls.SetupChoice(preset_id="llmhub", base_url="https://hub/v2")
        updates = ls.register_provider_updates(choice)
        assert "LLMHUB_MODEL" not in updates

    def test_named_provider_writes_namespaced_vars(self):
        choice = ls.SetupChoice(preset_id="openai", name="my-openai",
                                base_url="https://api.openai.com/v1",
                                model="gpt-4o")
        updates = ls.register_provider_updates(choice)
        assert updates == {
            "ATLAS_PROVIDER_MY_OPENAI_BASE_URL": "https://api.openai.com/v1",
            "ATLAS_PROVIDER_MY_OPENAI_MODEL": "gpt-4o",
        }

    def test_named_provider_defaults_to_preset_id_when_no_name_given(self):
        choice = ls.SetupChoice(preset_id="openai", base_url="https://x/v1")
        updates = ls.register_provider_updates(choice)
        assert "ATLAS_PROVIDER_OPENAI_BASE_URL" in updates

    def test_missing_base_url_raises(self):
        choice = ls.SetupChoice(preset_id="openai", name="x")
        with pytest.raises(ValueError, match="base URL"):
            ls.register_provider_updates(choice)

    def test_invalid_name_raises(self):
        choice = ls.SetupChoice(preset_id="openai", name="bad name!",
                                base_url="https://x/v1")
        with pytest.raises(ValueError):
            ls.register_provider_updates(choice)

    def test_auth_header_and_prefix_only_written_when_set(self):
        choice = ls.SetupChoice(preset_id="custom", name="gw",
                                base_url="https://x/v1",
                                auth_header="X-Api-Key", auth_prefix="")
        updates = ls.register_provider_updates(choice)
        assert updates["ATLAS_PROVIDER_GW_AUTH_HEADER"] == "X-Api-Key"
        assert "ATLAS_PROVIDER_GW_AUTH_PREFIX" not in updates

        bare = ls.SetupChoice(preset_id="custom", name="gw2",
                              base_url="https://x/v1")
        assert "ATLAS_PROVIDER_GW2_AUTH_HEADER" not in ls.register_provider_updates(bare)
        assert "ATLAS_PROVIDER_GW2_AUTH_PREFIX" not in ls.register_provider_updates(bare)


class TestDeclaredProvidersUpdate:
    def test_new_name_is_added(self):
        assert ls.declared_providers_update(["existing"], "new") == {
            "ATLAS_PROVIDERS": "existing,new"
        }

    def test_already_declared_name_is_a_noop(self):
        assert ls.declared_providers_update(["already-there"], "already-there") == {}

    def test_default_name_is_never_added(self):
        assert ls.declared_providers_update([], providers.DEFAULT_NAME) == {}

    def test_empty_existing_list(self):
        assert ls.declared_providers_update([], "first") == {
            "ATLAS_PROVIDERS": "first"
        }


class TestRoleUpdates:
    def test_all_roles(self):
        updates = ls.role_updates("gw", tuple(ls.PROVIDER_ROLE_VARS), env={})
        assert updates == {
            "ATLAS_AGENT_PROVIDER": "gw",
            "ATLAS_REVIEW_PROVIDER": "gw",
            "ATLAS_REPORT_PROVIDER": "gw",
            "REASON_BACKEND": "gw",
            "DAIR_BACKEND": "gw",
        }

    def test_subset_of_roles(self):
        updates = ls.role_updates("gw", ("analyst", "reason"), env={})
        assert updates == {
            "ATLAS_AGENT_PROVIDER": "gw",
            "REASON_BACKEND": "gw",
        }

    def test_unknown_role_ignored_not_raised(self):
        assert ls.role_updates("gw", ("not-a-real-role",)) == {}

    def test_unchecking_a_role_clears_its_env_var(self, monkeypatch):
        # This is the actual dashboard bug: previously role_updates() only
        # ever added assignments, never removed one — unchecking a role for
        # a provider that currently has it had zero effect on .env.
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw")
        updates = ls.role_updates("gw", ())
        assert updates == {"ATLAS_AGENT_PROVIDER": ""}

    def test_role_on_a_different_provider_is_left_untouched(self, monkeypatch):
        monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "someone-else")
        updates = ls.role_updates("gw", ())
        assert "ATLAS_REVIEW_PROVIDER" not in updates

    def test_reassigning_a_subset_clears_the_rest(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw")
        monkeypatch.setenv("REASON_BACKEND", "gw")
        updates = ls.role_updates("gw", ("analyst",), env={})
        assert updates == {"ATLAS_AGENT_PROVIDER": "gw", "REASON_BACKEND": ""}


class TestRoleModelOverrides:
    """A role's *_MODEL variable outranks its provider's model, so assigning
    the role has to clear it — otherwise the assignment is written, shown in
    the dashboard, and never followed by a run."""

    def test_assigning_a_role_clears_its_model_override(self):
        updates = ls.role_updates("gw", ("reason",),
                                  env={"REASON_MODEL": "old/model"})
        assert updates == {"REASON_BACKEND": "gw", "REASON_MODEL": ""}

    def test_every_assigned_role_with_an_override_is_cleared(self):
        env = {"ATLAS_AGENT_MODEL": "a", "REASON_MODEL": "b",
               "DAIR_MODEL": "c", "ATLAS_REVIEW_MODEL": "d"}
        updates = ls.role_updates("gw", tuple(ls.PROVIDER_ROLE_VARS), env=env)
        for var in ls.ROLE_MODEL_VARS.values():
            assert updates[var] == ""

    def test_override_of_an_unassigned_role_is_left_alone(self):
        updates = ls.role_updates("gw", ("reason",),
                                  env={"DAIR_MODEL": "other/model"})
        assert "DAIR_MODEL" not in updates

    def test_blank_override_is_not_rewritten(self):
        updates = ls.role_updates("gw", ("analyst",),
                                  env={"ATLAS_AGENT_MODEL": "   "})
        assert "ATLAS_AGENT_MODEL" not in updates

    def test_report_role_has_no_override_of_its_own(self):
        assert "report" not in ls.ROLE_MODEL_VARS
        updates = ls.role_updates("gw", ("report",),
                                  env={"ATLAS_AGENT_MODEL": "a"})
        assert updates == {"ATLAS_REPORT_PROVIDER": "gw"}

    def test_shadowing_model_vars_lists_only_the_ones_set(self):
        env = {"REASON_MODEL": "a", "ATLAS_REVIEW_MODEL": "b", "DAIR_MODEL": ""}
        assert ls.shadowing_model_vars(env) == {
            "reason": "REASON_MODEL", "reviewer": "ATLAS_REVIEW_MODEL"}

    def test_shadowing_model_vars_can_be_asked_about_some_roles(self):
        env = {"REASON_MODEL": "a", "ATLAS_REVIEW_MODEL": "b"}
        assert ls.shadowing_model_vars(env, ("reviewer",)) == {
            "reviewer": "ATLAS_REVIEW_MODEL"}


class TestRolesLosingCoverage:
    def test_role_dropped_from_new_roles_is_reported(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw")
        assert ls.roles_losing_coverage("gw", ()) == ["analyst"]

    def test_role_kept_in_new_roles_is_not_reported(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw")
        assert ls.roles_losing_coverage("gw", ("analyst",)) == []

    def test_role_on_a_different_provider_is_not_this_providers_loss(self, monkeypatch):
        monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "someone-else")
        assert ls.roles_losing_coverage("gw", ()) == []

    def test_deleting_a_provider_reports_every_role_it_covers(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "gw")
        monkeypatch.setenv("DAIR_BACKEND", "gw")
        assert set(ls.roles_losing_coverage("gw", ())) == {"analyst", "dair"}


class TestProbe:
    def test_unreachable_host_reports_failure_not_exception(self):
        # No network in this sandbox either way, but a malformed/unroutable
        # URL must degrade to ProbeResult, never raise.
        result = ls.probe("http://127.0.0.1:1", "")
        assert isinstance(result, ls.ProbeResult)
        assert result.ok is False
        assert result.error


class _FakeResponse:
    """The three things probe_reasoning reads off an httpx response."""

    def __init__(self, body, status_code=200, text=""):
        self._body = body
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._body


def _openai_shape(content, finish_reason="stop", completion_tokens=2,
                  reasoning_tokens=0):
    """Thinking counted under completion_tokens_details, as OpenAI sends it."""
    return {
        "choices": [{"message": {"content": content},
                     "finish_reason": finish_reason}],
        "usage": {"completion_tokens": completion_tokens,
                  "completion_tokens_details": {
                      "reasoning_tokens": reasoning_tokens}},
    }


def _gateway_shape(content, thinking="", reasoning_tokens=0):
    """The other shape in the wild: no completion_tokens_details object, the
    count straight on usage, and the thinking itself in a message field."""
    message = {"role": "assistant", "content": content, "tool_calls": None}
    if thinking:
        message["reasoning_content"] = thinking
    return {
        "choices": [{"message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 19, "total_tokens": 119,
                  "completion_tokens": 100, "prompt_tokens_details": None,
                  "reasoning_tokens": reasoning_tokens},
    }


class TestProbeCapabilities:
    """Three short calls say what a model can do; the role checkboxes and the
    Thinking setting are chosen against the answer, never against a name."""

    @staticmethod
    def _wire(monkeypatch, replies, listing_ok=True):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        monkeypatch.setattr(ls, "probe", lambda *a, **k: ls.ProbeResult(
            ok=listing_ok, status=200 if listing_ok else 404, url="u",
            models=["m"] if listing_ok else []))
        seq = list(replies)
        sent = []

        def _post(url, json=None, headers=None, timeout=None):
            sent.append(json)
            body = seq.pop(0) if seq else replies[-1]
            return _FakeResponse(body)

        monkeypatch.setattr("agent.llm.httpx.post", _post)
        return sent

    @staticmethod
    def _tool_reply():
        return {"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "list_processes", "arguments": "{\"image\": \"m\"}"}}]},
            "finish_reason": "tool_calls"}],
            "usage": {"completion_tokens": 9}}

    def test_a_thinking_model_that_calls_tools_may_serve_every_role(self, monkeypatch):
        sent = self._wire(monkeypatch, [
            _gateway_shape("ok", thinking="one word", reasoning_tokens=12),
            self._tool_reply(),
            _openai_shape("ok"),
        ])
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m", provider_name="gw")
        assert caps.ok and caps.answered and caps.reachable
        assert caps.tool_calling is True
        assert caps.thinking_observed is True
        assert caps.thinking_field == "reasoning_content"
        assert caps.control_accepted is True
        assert sent[2]["reasoning_effort"] == "low"
        assert "analyst" in caps.roles_allowed()

    def test_a_plain_model_is_not_asked_for_a_level(self, monkeypatch):
        sent = self._wire(monkeypatch, [_openai_shape("ok"), self._tool_reply()])
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.thinking_observed is False
        assert caps.control_accepted is None
        assert len(sent) == 2

    def test_no_tool_call_keeps_the_analyst_role_off(self, monkeypatch):
        self._wire(monkeypatch, [_openai_shape("ok"), _openai_shape("I would list them.")])
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.tool_calling is False
        assert "analyst" not in caps.roles_allowed()
        assert "reviewer" in caps.roles_allowed()

    def test_a_starved_first_answer_still_counts_as_thinking(self, monkeypatch):
        self._wire(monkeypatch, [_openai_shape("", finish_reason="length",
                                               completion_tokens=256, reasoning_tokens=256)])
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.thinking_observed is True

    def test_an_unlisted_catalogue_is_not_a_failure(self, monkeypatch):
        self._wire(monkeypatch, [_openai_shape("ok"), self._tool_reply()], listing_ok=False)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.ok is True and caps.reachable is False

    def test_a_transport_failure_degrades_instead_of_raising(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        monkeypatch.setattr(ls, "probe", lambda *a, **k: ls.ProbeResult(
            ok=True, status=200, url="u", models=[]))

        def _boom(*a, **k):
            raise RuntimeError("connection reset")

        monkeypatch.setattr("agent.llm.httpx.post", _boom)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.ok is False
        assert "connection reset" in caps.error

    def test_no_model_reports_the_listing_only(self, monkeypatch):
        self._wire(monkeypatch, [])
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "  ")
        assert caps.ok is True and caps.answered is False


class TestPresetProfiles:
    def test_vendor_presets_declare_their_shape(self):
        assert ls.preset_profile("deepseek")["echo_fields"] == ("reasoning_content",)
        assert ls.preset_profile("zai")["thinking_control"] == "thinking_type"
        assert ls.preset_profile("openrouter")["thinking_control"] == "reasoning_object"
        assert ls.preset_profile("custom") == {}
        assert ls.preset_profile("nope") == {}

    def test_thinking_is_written_only_when_pinned(self):
        auto = ls.register_provider_updates(ls.SetupChoice(
            preset_id="custom", name="gw", base_url="https://gw.example/v1"))
        assert "ATLAS_PROVIDER_GW_THINKING" not in auto
        low = ls.register_provider_updates(ls.SetupChoice(
            preset_id="deepseek", name="ds", base_url="https://api.deepseek.com",
            thinking="low"))
        assert low["ATLAS_PROVIDER_DS_THINKING"] == "low"
        assert low["ATLAS_PROVIDER_DS_PRESET"] == "deepseek"

    def test_an_unknown_level_is_refused(self):
        with pytest.raises(ValueError):
            ls.register_provider_updates(ls.SetupChoice(
                preset_id="custom", name="gw", base_url="https://gw.example/v1",
                thinking="max"))
