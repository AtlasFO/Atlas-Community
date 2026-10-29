"""The provider writer refuses a profile id no file defines, before any
probe, and remembers the chosen profile for every provider but the
fallback's, so a profile that later disappears makes the provider unusable
with the reason (core.llm_setup.register_provider_updates). Invented names."""
from __future__ import annotations

import pytest

from core import llm_setup as ls
from core import provider_profiles, providers


def _choice(preset, name="gw"):
    return ls.SetupChoice(preset_id=preset, name=name, base_url="https://llm.example.com/v1", model="m")


def test_an_unknown_profile_is_refused_with_the_known_ones():
    with pytest.raises(ValueError, match="no provider profile 'nosuch'; known: .*openrouter"):
        ls.register_provider_updates(_choice("nosuch"))


def test_the_dashboard_refuses_it_before_any_probe(tmp_path, monkeypatch):
    from dashboard import config_llm
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    monkeypatch.setattr(config_llm, "probe", lambda *a, **k: pytest.fail("probed"))
    with pytest.raises(config_llm.ConfigError, match="no provider profile 'nosuch'"):
        config_llm.save_provider({"name": "gw", "base_url": "https://llm.example.com/v1", "model": "m",
                                  "preset_id": "nosuch", "api_key": "k-1"})
    assert (tmp_path / ".env").read_text() == ""


def test_the_profile_is_remembered_also_when_the_name_says_it():
    assert ls.register_provider_updates(_choice("openrouter", name="openrouter"))[
        "ATLAS_PROVIDER_OPENROUTER_PRESET"] == "openrouter"
    assert "ATLAS_PROVIDER_GW_PRESET" not in ls.register_provider_updates(_choice("custom"))


def test_a_remembered_profile_that_disappears_makes_the_provider_unusable(tmp_path, monkeypatch):
    prof = tmp_path / "profiles"
    prof.mkdir()
    (prof / "acme.toml").write_text('schema = 1\nid = "acme"\nlabel = "Acme"\ndialect = "chat"\n'
                                    '[connection]\nbase_url = "https://llm.example.com/v1"\n', encoding="utf-8")
    monkeypatch.setenv("ATLAS_PROVIDER_PROFILES_DIR", str(prof))
    provider_profiles.load(reload=True)
    try:
        for k, v in ls.register_provider_updates(_choice("acme", name="acme")).items():
            monkeypatch.setenv(k, v)
        monkeypatch.setenv("ATLAS_PROVIDERS", "acme")
        assert providers.resolve("acme").profile == "acme"
        (prof / "acme.toml").unlink()
        provider_profiles.load(reload=True)
        with pytest.raises(providers.UnknownProvider, match="PRESET='acme' names no provider profile"):
            providers.resolve("acme")
    finally:
        provider_profiles.load(reload=True)
