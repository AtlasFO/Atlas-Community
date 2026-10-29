"""ATLAS_PROVIDER_PROFILES_DIR: ``~`` is expanded, and a relative folder is
taken under the Atlas folder, never the working directory (which can be a
case folder). Invented profiles only."""
from __future__ import annotations

import pytest

from core import provider_profiles as pp


def _profile(folder, label):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "acme.toml").write_text(
        f'schema = 1\nid = "acme"\nlabel = "{label}"\ndialect = "chat"\n\n'
        '[connection]\nbase_url = "https://llm.example.com/v1"\n', encoding="utf-8")


@pytest.fixture(autouse=True)
def _fresh_catalog():
    yield
    pp.load(reload=True)


def test_a_home_relative_folder_is_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    _profile(tmp_path / "home" / "profiles", "From home")
    monkeypatch.setenv(pp.DIR_ENV, "~/profiles")
    assert pp.user_dir() == tmp_path / "home" / "profiles"
    assert pp.load(reload=True).profiles["acme"].label == "From home"


def test_a_relative_folder_is_taken_under_the_atlas_folder_not_the_cwd(tmp_path, monkeypatch):
    monkeypatch.setattr(pp, "REPO", tmp_path / "atlas")
    _profile(tmp_path / "atlas" / "my-profiles", "From the Atlas folder")
    _profile(tmp_path / "case" / "my-profiles", "From the case folder")
    monkeypatch.chdir(tmp_path / "case")
    monkeypatch.setenv(pp.DIR_ENV, "my-profiles")
    assert pp.user_dir() == tmp_path / "atlas" / "my-profiles"
    assert pp.load(reload=True).profiles["acme"].label == "From the Atlas folder"


def test_an_absolute_folder_is_used_as_given(tmp_path, monkeypatch):
    _profile(tmp_path / "abs", "Absolute")
    monkeypatch.setenv(pp.DIR_ENV, str(tmp_path / "abs"))
    assert pp.user_dir() == tmp_path / "abs"
    assert pp.load(reload=True).profiles["acme"].label == "Absolute"
