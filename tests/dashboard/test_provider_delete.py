"""Removing a provider deletes every variable of it, its key included, and
its keyring copy and learned request shapes, by exact name; what it could
not remove is said (dashboard/config_llm.py delete_provider, core.envfile
set_values with None). Invented names, keys and endpoints only."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from core import envfile, providers
from dashboard import config_llm

REPO = Path(__file__).resolve().parents[2]
GW = {"ATLAS_PROVIDER_GW_BASE_URL": "https://llm.example.com/v1", "ATLAS_PROVIDER_GW_MODEL": "m-a",
      "ATLAS_PROVIDER_GW_THINKING": "high", "ATLAS_PROVIDER_GW_API": "chat",
      "ATLAS_PROVIDER_GW_API_KEY": "k-gw-123", "ATLAS_PROVIDER_GW_PRESET": "openrouter",
      "ATLAS_PROVIDER_GW_AUTH_HEADER": "X-Gw-Key", "ATLAS_PROVIDER_GW_AUTH_PREFIX": "Token "}
GW_B = {"ATLAS_PROVIDER_GW_B_BASE_URL": "https://other.example.com/v1", "ATLAS_PROVIDER_GW_B_MODEL": "m-b",
        "ATLAS_PROVIDER_GW_B_API_KEY": "k-gwb-456"}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    env = {"ATLAS_PROVIDERS": "gw,gw_b", **GW, **GW_B}
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()) + "# ATLAS_PROVIDER_GW_API_KEY=k-old\n",
                                   encoding="utf-8")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
    (tmp_path / "compat.json").write_text(json.dumps({"schema_version": 1, "models": {
        "gw|m-a": {"max_tools": 40}, "gw_b|m-b": {"max_tools": 60}}}), encoding="utf-8")
    from agent import llm
    llm.clear_api_compat_cache(memory_only=True)
    llm._compat_loaded = False
    monkeypatch.setattr("core.secrets.keyring_has", lambda k: False)
    return tmp_path


def test_a_removal_leaves_no_variable_of_the_provider_and_touches_no_other(repo):
    result = config_llm.delete_provider("gw")
    text = (repo / ".env").read_text()
    assert "ATLAS_PROVIDER_GW_" not in text.replace("ATLAS_PROVIDER_GW_B_", "")
    assert all(f"{k}={v}\n" in text for k, v in GW_B.items())
    assert not any(k in envfile.read_values(repo / ".env") for k in GW)
    assert not any(k in os.environ for k in GW)
    assert result["learned_dropped"] == 1
    cache = json.loads((repo / "compat.json").read_text())["models"]
    assert "gw|m-a" not in cache and "gw_b|m-b" in cache


def test_a_name_added_again_finds_no_old_key(repo, monkeypatch):
    config_llm.delete_provider("gw")
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw_b,gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://new.example.com/v1")
    assert config_llm._provider_summary("gw")["key_set"] is False


def test_a_key_left_in_the_keyring_is_said(repo, monkeypatch):
    monkeypatch.setattr("core.secrets.keyring_has", lambda k: k == "ATLAS_PROVIDER_GW_API_KEY")
    monkeypatch.setattr("core.secrets.keyring_clear", lambda k: False)
    assert config_llm.delete_provider("gw")["key_left_in_keyring"] == "ATLAS_PROVIDER_GW_API_KEY"
    monkeypatch.setattr("core.secrets.keyring_clear", lambda k: True)


def test_removing_one_of_a_colliding_pair_names_the_other(tmp_path, monkeypatch):
    env = {"ATLAS_PROVIDERS": "a-b,a_b", "ATLAS_PROVIDER_A_B_BASE_URL": "https://llm.example.com/v1"}
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr("core.secrets.keyring_has", lambda k: False)
    assert config_llm.delete_provider("a-b")["left_unusable"] == "a_b"


def test_none_removes_every_assignment_and_nothing_else(tmp_path):
    p = tmp_path / ".env"
    p.write_text("A=1\nK=one\n# K=commented\nB=2\nK=two\n", encoding="utf-8")
    envfile.set_values(p, {"K": None})
    assert p.read_text() == "A=1\nB=2\n"


def test_every_instance_suffix_in_the_code_is_in_the_removal_list():
    pattern = re.compile(r"\b(?:var|instance_var)\(\s*[^,()]+,\s*\"([A-Z_]+)\"\s*\)")
    found = set()
    for d in ("core", "agent", "dashboard", "tools"):
        for f in (REPO / d).rglob("*.py"):
            found |= set(pattern.findall(f.read_text(encoding="utf-8", errors="replace")))
    assert found and found <= set(providers.INSTANCE_SUFFIXES), sorted(found - set(providers.INSTANCE_SUFFIXES))


def test_doctor_names_variables_a_removal_left(tmp_path, monkeypatch):
    from agent import cli
    (tmp_path / ".env").write_text("ATLAS_PROVIDERS=gw_b\nATLAS_PROVIDER_GW_B_MODEL=m\nATLAS_PROVIDER_OLD_API_KEY=k-x\n"
                                   "ATLAS_PROVIDER_OLD_BASE_URL=https://x.example.com/v1\n"
                                   "ATLAS_PROVIDER_PROFILES_DIR=/srv/profiles\n", encoding="utf-8")
    monkeypatch.setattr("agent.prompts.REPO_ROOT", tmp_path)
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw_b")
    from core import provider_profiles
    assert cli._orphan_instance_vars(providers, provider_profiles) == [
        "ATLAS_PROVIDER_OLD_API_KEY", "ATLAS_PROVIDER_OLD_BASE_URL"]
