"""Reading and writing the per-role reasoning level from the Settings page."""
import os

import pytest

from dashboard import config_effort


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """A scratch .env the module writes to, with the process environment
    cleared of levels so a developer's own settings cannot decide a result."""
    path = tmp_path / ".env"
    path.write_text("ATLAS_AGENT_PROVIDER=llmhub\n", encoding="utf-8")
    monkeypatch.setattr(config_effort, "_env_path", lambda: path)
    for var in [k for k in list(os.environ) if k.startswith("ATLAS_EFFORT_")]:
        monkeypatch.delenv(var, raising=False)
    return path


class TestSettings:
    def test_lists_every_role_with_its_level(self, env_file):
        data = config_effort.settings()
        assert data["values"] == ["default", "low", "medium", "high"]
        roles = {r["role"]: r for r in data["roles"]}
        assert "agent" in roles and "dair" in roles
        assert roles["agent"]["label"] == "Analyst"
        assert roles["agent"]["blurb"]

    def test_reads_the_file_rather_than_the_process(self, env_file, monkeypatch):
        """The dashboard outlives an edit to .env, so a value written after it
        started must still be what the page shows."""
        env_file.write_text("ATLAS_EFFORT_AGENT=high\n", encoding="utf-8")
        monkeypatch.setenv("ATLAS_EFFORT_AGENT", "low")
        roles = {r["role"]: r for r in config_effort.settings()["roles"]}
        assert roles["agent"]["value"] == "high"


class TestSave:
    def test_writes_the_levels_to_the_file(self, env_file):
        result = config_effort.save({"roles": {"agent": "high", "dair": "low"}})
        assert result["success"] is True
        text = env_file.read_text(encoding="utf-8")
        assert "ATLAS_EFFORT_AGENT=high" in text
        assert "ATLAS_EFFORT_DAIR=low" in text

    def test_the_saved_levels_come_back(self, env_file):
        config_effort.save({"roles": {"agent": "medium"}})
        roles = {r["role"]: r for r in config_effort.settings()["roles"]}
        assert roles["agent"]["value"] == "medium"
        assert roles["agent"]["effective"] == "medium"

    def test_this_process_sees_the_save(self, env_file):
        """A run started from the dashboard process reads the environment, so
        a save that only reached the file would not apply to it."""
        config_effort.save({"roles": {"agent": "low"}})
        assert os.environ["ATLAS_EFFORT_AGENT"] == "low"

    def test_an_unknown_level_is_refused_and_writes_nothing(self, env_file):
        before = env_file.read_text(encoding="utf-8")
        with pytest.raises(ValueError):
            config_effort.save({"roles": {"agent": "maximum"}})
        assert env_file.read_text(encoding="utf-8") == before

    def test_an_unknown_role_is_refused(self, env_file):
        with pytest.raises(ValueError):
            config_effort.save({"roles": {"nonesuch": "low"}})

    def test_an_empty_form_changes_nothing(self, env_file):
        before = env_file.read_text(encoding="utf-8")
        assert config_effort.save({"roles": {}})["updates"] == {}
        assert env_file.read_text(encoding="utf-8") == before

    def test_other_settings_on_the_file_survive(self, env_file):
        """The file is shared with every other settings card, so a save here
        must not rewrite what another one owns."""
        config_effort.save({"roles": {"agent": "high"}})
        assert "ATLAS_AGENT_PROVIDER=llmhub" in env_file.read_text(encoding="utf-8")


class TestAnalystEndpointNote:
    def test_an_unresolvable_provider_leaves_the_levels_usable(
            self, env_file, monkeypatch):
        """Whether a provider resolves is the LLM card's business. A failure
        there must not take the level table down with it."""
        monkeypatch.setenv("ATLAS_AGENT_PROVIDER", "no-such-provider")
        data = config_effort.settings()
        assert data["analyst_endpoint"]["pinned"] is False
        assert len(data["roles"]) > 1
