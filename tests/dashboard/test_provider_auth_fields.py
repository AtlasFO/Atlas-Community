"""The Auth header and Auth prefix fields of the Other (custom) profile: the
dashboard writes them, an emptied field removes the setting, a save under
another profile never touches them, and the wizard asks for them only for
Other. Invented names and hosts only."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from core import providers
from dashboard import config_llm

ROOT = Path(__file__).resolve().parents[2]
NAME = "gw_other"
HEADER, PREFIX = providers.var(NAME, "AUTH_HEADER"), providers.var(NAME, "AUTH_PREFIX")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    # Every variable a save writes into this process's env is restored after.
    for suffix in providers.INSTANCE_SUFFIXES:
        monkeypatch.setenv(providers.var(NAME, suffix), "")
        monkeypatch.delenv(providers.var(NAME, suffix))
    monkeypatch.setenv("ATLAS_PROVIDERS", "")
    monkeypatch.delenv("ATLAS_PROVIDERS")
    return tmp_path


def _save(preset="custom", **extra):
    return config_llm.save_provider({"name": NAME, "base_url": "https://gw.example.com/v1", "model": "m-1",
                                     "preset_id": preset, "api_key": "", "skip_probe": True, **extra})


def test_other_writes_the_header_and_prefix_and_an_emptied_field_removes_them(repo):
    _save(auth_header="X-Gateway-Key", auth_prefix="Token ")
    text = (repo / ".env").read_text()
    assert f"{HEADER}=X-Gateway-Key" in text and PREFIX in text
    assert config_llm._provider_summary(NAME)["auth_header"] == "X-Gateway-Key"
    _save(auth_header="", auth_prefix="")
    text = (repo / ".env").read_text()
    assert HEADER not in text and PREFIX not in text
    assert config_llm._provider_summary(NAME)["auth_header"] == ""


def test_a_save_without_the_fields_keeps_a_header_set_by_hand(repo):
    _save(auth_header="X-Gateway-Key")
    _save(preset="openrouter")
    assert f"{HEADER}=X-Gateway-Key" in (repo / ".env").read_text()


def test_the_page_sends_the_auth_fields_only_for_other_and_shows_the_profile_text():
    html = (ROOT / "dashboard/config.html").read_text(encoding="utf-8")
    assert html.count("data-custom-auth hidden") == 2
    assert "if ($('llm-preset').value !== CUSTOM_PRESET) return {};" in html
    assert html.count("...authFields()") == 2               # Test connection and Save
    # The profile's own words go in as text, never as markup.
    assert re.search(r"\$\('llm-preset-about'\)\.textContent = preset", html)
    assert 'aria-describedby="llm-preset-about"' in html


@pytest.mark.parametrize("answers, header, prefix, note", [
    ({"Auth header": "X-Gateway-Key", "Auth prefix": "-"}, "X-Gateway-Key", None, False),
    ({"Auth header": "Authorization", "Auth prefix": "Token"}, "Authorization", "Token ", False),
    ({"Auth header": "Authorization", "Auth prefix": "Bearer"}, "", None, False),
    ({"Auth header": "Authorization", "Auth prefix": "-"}, "", None, True),
])
def test_the_wizard_asks_other_for_the_auth_header(repo, monkeypatch, capsys, answers, header, prefix, note):
    from agent import cli
    from core import llm_setup as ls
    monkeypatch.setattr("agent.prompts.REPO_ROOT", repo)
    menu = ls.presets()
    index = next(i for i, p in enumerate(menu, 1) if p.id == "custom")
    seen = {}

    def _ask(prompt, default=""):
        if prompt.startswith("Choice"):
            return str(index)
        if prompt.startswith("Provider name"):
            return NAME
        if prompt.startswith("Base URL"):
            return "https://gw.example.com/v1"
        if prompt.startswith("Model id"):
            return "m-1"
        for start, answer in answers.items():
            if prompt.startswith(start):
                return answer
        return default

    def _register(choice):
        seen["choice"] = choice
        raise ValueError("stop here")

    monkeypatch.setattr(cli, "_ask", _ask)
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: "")
    monkeypatch.setattr(cli, "_ask_yn", lambda prompt, default_yes=True:
                        False if prompt.startswith("Test") else default_yes)
    monkeypatch.setattr(ls, "register_provider_updates", _register)
    with pytest.raises(SystemExit):
        cli.cmd_provider_setup(None)
    assert seen["choice"].auth_header == header and seen["choice"].auth_prefix == prefix
    assert ("needs a provider profile file" in capsys.readouterr().out) is note


def test_the_wizard_does_not_ask_another_profile_for_the_header(repo, monkeypatch):
    from agent import cli
    from core import llm_setup as ls
    monkeypatch.setattr("agent.prompts.REPO_ROOT", repo)
    menu = ls.presets()
    index = next(i for i, p in enumerate(menu, 1) if p.id == "openrouter")
    asked = []

    def _ask(prompt, default=""):
        asked.append(prompt)
        return str(index) if prompt.startswith("Choice") else (default or "m-1")

    monkeypatch.setattr(cli, "_ask", _ask)
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: "")
    monkeypatch.setattr(cli, "_ask_yn", lambda prompt, default_yes=True:
                        False if prompt.startswith("Test") else default_yes)
    monkeypatch.setattr(ls, "register_provider_updates", lambda choice: (_ for _ in ()).throw(ValueError("stop")))
    with pytest.raises(SystemExit):
        cli.cmd_provider_setup(None)
    assert not [p for p in asked if p.startswith("Auth")]


def _load(monkeypatch, path):
    """This process's environment as a start that loads ``path`` sees it."""
    from dotenv import dotenv_values
    for key, value in dotenv_values(path).items():
        monkeypatch.setenv(key, value)


def test_a_saved_prefix_keeps_its_space_after_a_load_from_the_file(repo, monkeypatch):
    _save(auth_header="X-Gateway-Key", auth_prefix="Token ", api_key="k-test-1", store_key_in="env")
    for var in (HEADER, PREFIX, providers.var(NAME, "API_KEY")):
        monkeypatch.delenv(var, raising=False)
    _load(monkeypatch, repo / ".env")
    assert providers.resolve(NAME).headers()["X-Gateway-Key"] == "Token k-test-1"


def test_the_wizard_prefix_keeps_its_space_after_a_load_from_the_file(repo, monkeypatch):
    from agent import cli
    from core import llm_setup as ls
    monkeypatch.setattr("agent.prompts.REPO_ROOT", repo)
    index = next(i for i, p in enumerate(ls.presets(), 1) if p.id == "custom")
    answers = {"Choice": str(index), "Provider name": NAME, "Base URL": "https://gw.example.com/v1",
               "Model id": "m-1", "Auth header": "X-Gateway-Key", "Auth prefix": "Token"}

    def _ask(prompt, default=""):
        return next((a for start, a in answers.items() if prompt.startswith(start)), default)

    monkeypatch.setattr(cli, "_ask", _ask)
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: "k-test-2")
    monkeypatch.setattr(cli, "_ask_yn", lambda prompt, default_yes=True:
                        False if prompt.startswith(("Test", "Store")) else default_yes)
    cli.cmd_provider_setup(None)
    assert f'{PREFIX}="Token "' in (repo / ".env").read_text(encoding="utf-8")
    for var in (HEADER, PREFIX, providers.var(NAME, "API_KEY")):
        monkeypatch.delenv(var, raising=False)
    _load(monkeypatch, repo / ".env")
    assert providers.resolve(NAME).headers()["X-Gateway-Key"] == "Token k-test-2"
