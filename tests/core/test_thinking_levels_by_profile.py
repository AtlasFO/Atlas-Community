"""A provider is pinned only to a thinking level its bound profile lists.

A pinned level is sent as written, so a level the vendor does not document
reaches it as a 400. The one writer refuses it, the wizard and the Settings
select offer only the levels the profile takes, and doctor names a level
stored before the check. Invented provider names and a user profile only.
"""
from __future__ import annotations

import pytest

from core import llm_setup as ls
from core import provider_profiles, providers

RULED = """schema = 1
id = "ruled"
label = "Ruled gateway"
dialect = "chat"

[connection]
base_url = "https://ruled.example.com/v1"

[models."deep-*".reasoning]
levels = { high = "high" }
"""


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    folder = tmp_path / "profiles"
    folder.mkdir()
    (folder / "ruled.toml").write_text(RULED, encoding="utf-8")
    monkeypatch.setenv("ATLAS_PROVIDER_PROFILES_DIR", str(folder))
    provider_profiles.load(reload=True)
    yield
    monkeypatch.delenv("ATLAS_PROVIDER_PROFILES_DIR")
    provider_profiles.load(reload=True)


def _save(preset, thinking, model="m-1", name="gw_a"):
    return ls.register_provider_updates(ls.SetupChoice(
        preset_id=preset, name=name, base_url="https://gw.example.com/v1", model=model,
        thinking=thinking))


class TestWriter:
    def test_a_level_the_profile_does_not_list_is_refused_with_the_ones_it_takes(self):
        with pytest.raises(ValueError) as e:
            _save("zai", "medium")
        assert "low or high" in str(e.value) and "'medium'" in str(e.value)
        assert "auto lets Atlas learn one" in str(e.value)

    @pytest.mark.parametrize("level", ["low", "high", "auto"])
    def test_a_listed_level_and_auto_save(self, level):
        updates = _save("zai", level)
        assert updates.get(providers.var("gw_a", "THINKING")) == (None if level == "auto" else level)

    def test_a_profile_without_levels_takes_all_four(self):
        for level in providers.THINKING_VALUES:
            _save("custom", level)

    def test_only_high_where_the_profile_takes_none_and_high(self):
        assert ls.levels_for("mistral") == ("auto", "high")
        with pytest.raises(ValueError, match="takes high"):
            _save("mistral", "low")

    def test_a_model_rule_decides_for_its_model(self, profiles):
        assert ls.levels_for("ruled", "other-1") == providers.THINKING_VALUES
        assert ls.levels_for("ruled", "deep-2") == ("auto", "high")
        _save("ruled", "medium", model="other-1")
        with pytest.raises(ValueError, match="for deep-2"):
            _save("ruled", "medium", model="deep-2")


def test_presets_carry_the_selectable_levels():
    from dashboard import config_llm
    by_id = {p["id"]: p for p in config_llm.presets()}
    assert by_id["zai"]["levels"] == ["auto", "low", "high"]
    assert by_id["custom"]["levels"] == list(providers.THINKING_VALUES)


def test_doctor_names_a_stored_level_the_profile_does_not_take(monkeypatch):
    from agent import cli
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw_a,gw_b")
    for name, preset, level in (("gw_a", "zai", "medium"), ("gw_b", "zai", "high")):
        monkeypatch.setenv(providers.var(name, "BASE_URL"), "https://gw.example.com/v1")
        monkeypatch.setenv(providers.var(name, "MODEL"), "m-1")
        monkeypatch.setenv(providers.var(name, "API_KEY"), "k-test")
        monkeypatch.setenv(providers.var(name, "PRESET"), preset)
        monkeypatch.setenv(providers.var(name, "THINKING"), level)
    assert cli._untaken_levels(providers) == [("gw_a", "medium", ("auto", "low", "high"))]


def test_the_wizard_refuses_an_untaken_level_before_writing(tmp_path, monkeypatch, capsys):
    from agent import cli
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    monkeypatch.setattr("agent.prompts.REPO_ROOT", tmp_path)
    menu = ls.presets()
    index = next(i for i, p in enumerate(menu, 1) if p.id == "zai")
    asked = []

    def _ask(prompt, default=""):
        asked.append(prompt)
        if prompt.startswith("Choice"):
            return str(index)
        if prompt.startswith("Model id"):
            return "m-1"
        if prompt.startswith("Thinking level"):
            return "medium"
        return default

    monkeypatch.setattr(cli, "_ask", _ask)
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: "k-test")
    monkeypatch.setattr(cli, "_ask_yn", lambda prompt, default_yes=True:
                        False if prompt.startswith("Test") else default_yes)
    with pytest.raises(SystemExit) as e:
        cli.cmd_provider_setup(None)
    assert "Nothing was written" in str(e.value) and "auto, low, high" in str(e.value)
    assert any(p.startswith("Thinking level for this provider (auto/low/high;") for p in asked)
    assert env.read_text(encoding="utf-8") == ""
