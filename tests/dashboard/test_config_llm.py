"""Tests for dashboard/config_llm.py — the Config page's provider save handler.

Guards the 401 failure class after a Config-page save:
dashboard/config.html sends auth_prefix only for the Other profile, so most
Config-page saves submit a payload without that key. save_provider() must not collapse
that "field omitted" None into "" (`auth_prefix or ""`) before handing it to
core.llm_setup.SetupChoice — "" there is a distinct, deliberate choice
("send the bare token, no Bearer") that core.llm_setup.register_provider_updates()
writes to .env, while None means "leave AUTH_PREFIX alone". The coercion would
make every provider saved through the Config page get an
ATLAS_PROVIDER_<NAME>_AUTH_PREFIX= line it never asked for, which any
OpenAI-compatible gateway (OpenRouter included) rejects outright — the
request goes out as `Authorization: <token>` instead of
`Authorization: Bearer <token>`.

No network here: every case passes skip_probe=True, mirroring how the wizard/
Config page only probes when an api_key is supplied (see save_provider's
docstring).
"""
import pytest

from dashboard import config_llm


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """An isolated .env plus a config_llm pointed at it, so a save can't
    touch the real repo's .env or leak env vars into other tests."""
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    return tmp_path


def _forget(monkeypatch, updates):
    # save_provider() also pokes os.environ directly ("this process's own
    # env, for immediate effect") — clean those up so one test can't bleed
    # into the next.
    for key in updates:
        monkeypatch.delenv(key, raising=False)


class TestSaveProviderAuthPrefix:
    def test_omitted_auth_prefix_writes_no_env_line(self, repo, monkeypatch):
        """Exactly what dashboard/config.html actually submits: no
        auth_prefix key in the payload at all."""
        result = config_llm.save_provider({
            "preset_id": "custom", "name": "testgw",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True,
        })
        _forget(monkeypatch, result["updates"])

        assert "ATLAS_PROVIDER_TESTGW_AUTH_PREFIX" not in result["updates"]
        assert "AUTH_PREFIX" not in (repo / ".env").read_text()

    def test_explicit_empty_auth_prefix_is_not_written(self, repo, monkeypatch):
        """Blank prefix is 'use the default', not 'write AUTH_PREFIX=': the
        emptied field removes a prefix the file held."""
        (repo / ".env").write_text("ATLAS_PROVIDER_TESTGW2_AUTH_PREFIX=Token \n", encoding="utf-8")
        result = config_llm.save_provider({
            "preset_id": "custom", "name": "testgw2",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "auth_prefix": "",
        })
        _forget(monkeypatch, result["updates"])

        assert result["updates"].get("ATLAS_PROVIDER_TESTGW2_AUTH_PREFIX") is None
        assert "AUTH_PREFIX" not in (repo / ".env").read_text()

    def test_admin_is_rejected_as_a_model_id(self, repo, monkeypatch):
        with pytest.raises(config_llm.ConfigError, match="dashboard role"):
            config_llm.save_provider({
                "preset_id": "openrouter", "name": "OpenRouter",
                "base_url": "https://openrouter.ai/api/v1", "model": "Admin",
                "roles": ["analyst"], "skip_probe": True,
            })

    def test_explicit_auth_prefix_is_written_verbatim(self, repo, monkeypatch):
        result = config_llm.save_provider({
            "preset_id": "custom", "name": "testgw3",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "auth_prefix": "Token ",
        })
        _forget(monkeypatch, result["updates"])

        assert result["updates"]["ATLAS_PROVIDER_TESTGW3_AUTH_PREFIX"] == "Token "


class TestSaveProviderRoleCoverage:
    def test_unchecking_the_only_role_is_refused(self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "onlyone",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": ["analyst"], "skip_probe": True,
        })
        _forget(monkeypatch, saved["updates"])
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "onlyone")

        with pytest.raises(config_llm.ConfigError, match="analyst"):
            config_llm.save_provider({
                "preset_id": "custom", "name": "onlyone",
                "base_url": "https://gw.example/v1", "model": "m1",
                "roles": [], "skip_probe": True,
            })
        # Refused cleanly — the role assignment survives untouched.
        assert config_llm.providers.role_name("ATLAS_AGENT_PROVIDER") == "onlyone"
        monkeypatch.delenv("ATLAS_AGENT_PROVIDER", raising=False)

    def test_force_true_confirms_the_role_gap_anyway(self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "onlyone2",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": ["analyst"], "skip_probe": True,
        })
        _forget(monkeypatch, saved["updates"])
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "onlyone2")

        result = config_llm.save_provider({
            "preset_id": "custom", "name": "onlyone2",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "force": True,
        })
        assert result["success"] is True
        _forget(monkeypatch, result["updates"])
        assert config_llm.providers.role_name("ATLAS_AGENT_PROVIDER") == ""


class TestAddWithoutRole:
    def test_a_new_provider_saves_with_no_role_and_leaves_the_roles_alone(
            self, repo, monkeypatch):
        """Adding a model for later: no role checked, a name of its own."""
        for var in ("ATLAS_AGENT_PROVIDER", "ATLAS_REVIEW_PROVIDER",
                    "ATLAS_REPORT_PROVIDER", "REASON_BACKEND", "DAIR_BACKEND"):
            monkeypatch.setenv(var, "llmhub")
        result = config_llm.save_provider({
            "preset_id": "llmhub", "name": "llmhub-2",
            "base_url": "https://gw.example/v2", "model": "m2",
            "roles": [], "skip_probe": True,
        })
        listed = {p["name"]: p for p in config_llm.list_providers()["providers"]}
        _forget(monkeypatch, result["updates"])
        assert listed["llmhub-2"]["model"] == "m2" and listed["llmhub-2"]["roles"] == []
        assert config_llm.providers.role_name("ATLAS_AGENT_PROVIDER") == "llmhub"

    def test_saving_an_existing_provider_without_its_roles_says_what_it_does(
            self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "holder",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": ["analyst"], "skip_probe": True,
        })
        _forget(monkeypatch, saved["updates"])
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "holder")
        with pytest.raises(config_llm.ConfigError) as err:
            config_llm.save_provider({
                "preset_id": "custom", "name": "holder",
                "base_url": "https://gw.example/v1", "model": "m2",
                "roles": [], "skip_probe": True,
            })
        text = str(err.value)
        assert "existing provider" in text and "new name" in text
        # the page offers its confirmation on this phrase
        assert "force=true" in text
        monkeypatch.delenv("ATLAS_AGENT_PROVIDER", raising=False)


class TestDeleteProvider:
    def test_deletes_a_provider_with_no_roles_assigned(self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "gone",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True,
        })

        monkeypatch.setattr("core.secrets.keyring_has", lambda k: False)
        result = config_llm.delete_provider("gone")

        assert result["success"] is True and result["removed"] == "gone"
        assert "key_left_in_keyring" not in result and "left_unusable" not in result
        assert "gone" not in config_llm.providers.declared()
        assert "gone" not in (repo / ".env").read_text().split("ATLAS_PROVIDERS=")[1].splitlines()[0]
        _forget(monkeypatch, saved["updates"])

    def test_refuses_to_delete_a_provider_still_covering_a_role(self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "busy",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": ["analyst"], "skip_probe": True,
        })
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "busy")

        with pytest.raises(config_llm.ConfigError, match="analyst"):
            config_llm.delete_provider("busy")

        # Refused cleanly — provider is still declared, role still assigned.
        assert "busy" in config_llm.providers.declared()
        _forget(monkeypatch, saved["updates"])
        monkeypatch.delenv("ATLAS_AGENT_PROVIDER", raising=False)

    def test_refuses_to_delete_the_builtin_default(self, repo):
        with pytest.raises(config_llm.ConfigError, match="built in"):
            config_llm.delete_provider("llmhub")

    def test_refuses_to_delete_an_unknown_provider(self, repo):
        with pytest.raises(config_llm.ConfigError, match="no such provider"):
            config_llm.delete_provider("never-existed")


class TestListProvidersHidesUnusedHub:
    def _clear_hub_state(self, monkeypatch):
        monkeypatch.delenv("LLMHUB_API_KEY", raising=False)
        for var in config_llm.ls.PROVIDER_ROLE_VARS.values():
            monkeypatch.delenv(var, raising=False)

    def test_hides_llmhub_when_unused(self, repo, monkeypatch):
        self._clear_hub_state(monkeypatch)

        names = [p["name"] for p in config_llm.list_providers()["providers"]]

        assert "llmhub" not in names

    def test_shows_llmhub_once_a_key_is_set(self, repo, monkeypatch):
        self._clear_hub_state(monkeypatch)
        monkeypatch.setenv("LLMHUB_API_KEY", "sk-test")

        names = [p["name"] for p in config_llm.list_providers()["providers"]]

        assert "llmhub" in names

    def test_shows_llmhub_once_a_role_is_assigned(self, repo, monkeypatch):
        self._clear_hub_state(monkeypatch)
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "llmhub")

        names = [p["name"] for p in config_llm.list_providers()["providers"]]

        assert "llmhub" in names


class TestRoleModelOverrides:
    """Saving a provider for a role must also clear that role's model
    override in .env: the override is read before the provider's model, so
    leaving it in place shows an assignment the run does not follow."""

    def test_saving_a_role_clears_its_override_in_the_env_file(
            self, repo, monkeypatch):
        (repo / ".env").write_text("REASON_MODEL=stale/model\n",
                                   encoding="utf-8")
        result = config_llm.save_provider({
            "preset_id": "custom", "name": "revgw",
            "base_url": "https://gw.example/v1", "model": "fresh/model",
            "roles": ["reason"], "skip_probe": True,
        })
        _forget(monkeypatch, result["updates"])

        assert result["updates"]["REASON_MODEL"] == ""
        assert "REASON_MODEL=\n" in (repo / ".env").read_text()

    def test_override_the_dashboard_never_loaded_is_still_cleared(
            self, repo, monkeypatch):
        """The file is the authority, not this process's environment: the
        dashboard may have started before the override was added by hand."""
        (repo / ".env").write_text("DAIR_MODEL=added/after/start\n",
                                   encoding="utf-8")
        monkeypatch.delenv("DAIR_MODEL", raising=False)
        result = config_llm.save_provider({
            "preset_id": "custom", "name": "dairgw",
            "base_url": "https://gw.example/v1", "model": "fresh/model",
            "roles": ["dair"], "skip_probe": True,
        })
        _forget(monkeypatch, result["updates"])

        assert result["updates"]["DAIR_MODEL"] == ""

    def test_list_providers_reports_a_remaining_override(
            self, repo, monkeypatch):
        (repo / ".env").write_text("ATLAS_REVIEW_MODEL=hand/edited\n",
                                   encoding="utf-8")
        monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "revgw2")
        monkeypatch.setenv("ATLAS_PROVIDERS", "revgw2")
        monkeypatch.setenv("ATLAS_PROVIDER_REVGW2_BASE_URL",
                           "https://gw.example/v1")
        monkeypatch.setenv("ATLAS_PROVIDER_REVGW2_MODEL", "provider/model")

        entries = config_llm.list_providers()["model_overrides"]
        assert {e["role"] for e in entries} == {"reviewer"}
        entry = entries[0]
        assert entry["var"] == "ATLAS_REVIEW_MODEL"
        assert entry["model"] == "hand/edited"
        assert entry["provider"] == "revgw2"
        assert entry["provider_model"] == "provider/model"

    def test_no_overrides_reports_nothing(self, repo):
        (repo / ".env").write_text("", encoding="utf-8")
        assert config_llm.list_providers()["model_overrides"] == []


class TestThinkingSetting:
    """One setting per provider: how hard its models are asked to think."""

    def test_a_pinned_level_is_written_and_listed(self, repo, monkeypatch):
        saved = config_llm.save_provider({
            "preset_id": "custom", "name": "thinker",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "thinking": "low",
        })
        assert saved["updates"]["ATLAS_PROVIDER_THINKER_THINKING"] == "low"
        row = next(p for p in config_llm.list_providers()["providers"]
                   if p["name"] == "thinker")
        assert row["thinking"] == "low"
        assert row["reasoning_observed"] is False
        _forget(monkeypatch, saved["updates"])

    def test_back_to_auto_clears_the_pin(self, repo, monkeypatch):
        first = config_llm.save_provider({
            "preset_id": "custom", "name": "thinker2",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "thinking": "high",
        })
        second = config_llm.save_provider({
            "preset_id": "custom", "name": "thinker2",
            "base_url": "https://gw.example/v1", "model": "m1",
            "roles": [], "skip_probe": True, "thinking": "auto",
        })
        assert second["updates"]["ATLAS_PROVIDER_THINKER2_THINKING"] == ""
        _forget(monkeypatch, first["updates"])
        _forget(monkeypatch, second["updates"])

    def test_an_unknown_level_is_refused(self, repo):
        with pytest.raises(config_llm.ConfigError):
            config_llm.save_provider({
                "preset_id": "custom", "name": "thinker3",
                "base_url": "https://gw.example/v1", "model": "m1",
                "roles": [], "skip_probe": True, "thinking": "max",
            })


class TestSaveProbeGate:
    """A save makes no model call. GET /models vouches for the model, or a
    Test connection that got an answer from it for these same base URL,
    model and profile does (the form's ``tested``): a vendor whose listing
    speaks another dialect, or lists only part of its catalogue, saves after
    that test."""

    def _fake(self, monkeypatch, *, listing_ok, models=(), answered):
        from core import llm_setup as ls

        def fake_probe(base_url, api_key, **kw):
            return ls.ProbeResult(ok=listing_ok, status=200 if listing_ok else 400,
                                  url=base_url + "/models", models=list(models),
                                  error="" if listing_ok else "version header required")

        def fake_caps(base_url, api_key, model, **kw):
            raise AssertionError("a save made a model call")

        monkeypatch.setattr(ls, "probe", fake_probe)
        monkeypatch.setattr(ls, "probe_capabilities", fake_caps)

    def _save(self, model="m1", tested=None):
        return config_llm.save_provider({
            "preset_id": "custom", "name": "gatetest",
            "base_url": "https://gw.example/v1", "model": model,
            "roles": [], "api_key": "k-test", "store_key_in": "env",
            **({"tested": tested} if tested else {}),
        })

    TESTED = {"base_url": "https://gw.example/v1", "model": "m1", "profile": "custom"}

    def test_failed_listing_saves_after_a_test_of_these_values(self, repo, monkeypatch):
        self._fake(monkeypatch, listing_ok=False, answered=True)
        with pytest.raises(config_llm.ConfigError, match="press Test connection"):
            self._save()
        assert (repo / ".env").read_text() == ""
        result = self._save(tested=self.TESTED)
        _forget(monkeypatch, result["updates"])
        assert result["success"]
        assert "GATETEST" in (repo / ".env").read_text()

    def test_unlisted_model_saves_after_a_test_of_these_values(self, repo, monkeypatch):
        self._fake(monkeypatch, listing_ok=True, models=["other-a", "other-b"],
                   answered=True)
        with pytest.raises(config_llm.ConfigError):
            self._save()
        result = self._save(tested=self.TESTED)
        _forget(monkeypatch, result["updates"])
        assert result["success"]

    def test_a_test_of_other_values_vouches_for_nothing(self, repo, monkeypatch):
        self._fake(monkeypatch, listing_ok=False, answered=False)
        for other in ({**self.TESTED, "base_url": "https://other.example/v1"}, {**self.TESTED, "model": "m2"},
                      {**self.TESTED, "profile": "openrouter"}):
            with pytest.raises(config_llm.ConfigError):
                self._save(tested=other)
        assert (repo / ".env").read_text() == ""

    def test_listed_model_saves_without_a_chat_call(self, repo, monkeypatch):
        self._fake(monkeypatch, listing_ok=True, models=["m1"], answered=False)
        result = self._save()
        _forget(monkeypatch, result["updates"])
        assert result["success"]
