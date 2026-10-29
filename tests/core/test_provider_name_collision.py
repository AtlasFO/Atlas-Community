"""Two provider names with one variable stem (case, "-" and "_") cannot both
exist: a new one is refused at the writer, and a pair a hand edit made is
unusable on both sides with the other named (core.providers.colliding_name).
Invented names and endpoints only."""
from __future__ import annotations

import pytest

from core import llm_setup as ls
from core import providers


@pytest.fixture
def declared(monkeypatch):
    def set_(names: str):
        monkeypatch.setenv("ATLAS_PROVIDERS", names)
        for n in names.split(","):
            stem = n.upper().replace("-", "_")
            monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_BASE_URL", "https://llm.example.com/v1")
            monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_MODEL", "model-a")
    return set_


def _choice(name):
    return ls.SetupChoice(preset_id="custom", name=name, base_url="https://other.example.com/v1", model="b")


@pytest.mark.parametrize("have,new", [("Claude-Code", "claude-code"), ("a-b", "a_b"), ("gw", "GW")])
def test_a_name_that_would_share_settings_is_refused_at_the_writer(declared, have, new):
    declared(have)
    with pytest.raises(ValueError, match=f"share its settings with the provider '{have}'"):
        ls.register_provider_updates(_choice(new))


def test_the_same_name_saved_again_is_an_edit(declared):
    declared("Claude-Code")
    assert ls.register_provider_updates(_choice("Claude-Code"))["ATLAS_PROVIDER_CLAUDE_CODE_BASE_URL"]


def test_a_name_spelled_like_a_built_in_is_refused(declared):
    declared("gw")
    with pytest.raises(ValueError, match="'llmhub'"):
        ls.register_provider_updates(_choice("LLMHUB"))


def test_a_pair_already_in_the_file_is_unusable_on_both_sides(declared):
    declared("a-b,a_b")
    for name, other in (("a-b", "a_b"), ("a_b", "a-b")):
        with pytest.raises(providers.UnknownProvider, match=f"shares its variables .* with the provider '{other}'"):
            providers.resolve(name)


def test_the_dashboard_save_writes_nothing_for_a_colliding_name(tmp_path, monkeypatch, declared):
    from dashboard import config_llm
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    declared("Claude-Code")
    with pytest.raises(config_llm.ConfigError, match="share its settings"):
        config_llm.save_provider({"name": "claude-code", "base_url": "http://127.0.0.1:1/v1", "model": "other",
                                  "skip_probe": True, "preset_id": "custom"})
    assert (tmp_path / ".env").read_text() == ""
