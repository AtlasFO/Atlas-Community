"""Every value the env file gets is one line, as its readers split lines
(str.splitlines breaks on CR, LF, the rest of C0, DEL, C1 such as U+0085,
U+2028 and U+2029), and a provider field holds nothing the env loader
rewrites (``${``, a quote at either end): core.envfile.set_values,
core.llm_setup.field_error. Invented values only."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core import envfile
from core import llm_setup as ls

BREAKS = ["\n", "\r", "\x00", "\t", "\x7f", "\x85", " ", " "]


@pytest.fixture
def env_file(tmp_path):
    p = tmp_path / ".env"
    p.write_text("ATLAS_PROVIDERS=gw\nOTHER=1\n", encoding="utf-8")
    return p


@pytest.mark.parametrize("ch", BREAKS)
def test_the_writer_refuses_a_value_that_would_be_two_lines(env_file, ch):
    before = env_file.read_bytes()
    with pytest.raises(ValueError, match="nothing was written"):
        envfile.set_values(env_file, {"ATLAS_PROVIDER_GW_MODEL": f"model-a{ch}INJECTED=1"})
    assert env_file.read_bytes() == before


@pytest.mark.parametrize("key", ["A-B", "A=B", "1A", "A B", ""])
def test_the_writer_refuses_a_key_that_is_no_variable_name(env_file, key):
    with pytest.raises(ValueError):
        envfile.set_values(env_file, {key: "1"})


def test_a_plain_value_is_written(env_file):
    envfile.set_values(env_file, {"ATLAS_PROVIDER_GW_MODEL": "vendor/model-a:free"})
    assert "ATLAS_PROVIDER_GW_MODEL=vendor/model-a:free" in env_file.read_text()


def _choice(**kw):
    base = dict(preset_id="custom", name="gw", base_url="https://llm.example.com/v1", model="model-a")
    return ls.SetupChoice(**{**base, **kw})


@pytest.mark.parametrize("field", ["base_url", "model", "auth_header", "auth_prefix"])
@pytest.mark.parametrize("bad", ["\nX=1", " X=1", "\x85X=1", "${HOME}", "'quoted", "quoted\""])
def test_a_provider_field_that_the_env_file_would_change_is_refused(field, bad):
    good = {"base_url": "https://llm.example.com/v1", "model": "model-a", "auth_header": "X-Gw-Key",
            "auth_prefix": "Token "}
    value = bad if bad.startswith("'") else good[field] + bad
    with pytest.raises(ValueError):
        ls.register_provider_updates(_choice(**{field: value}))


def test_a_header_name_follows_the_profile_rule():
    with pytest.raises(ValueError, match="not a header name"):
        ls.register_provider_updates(_choice(auth_header="X Gw Key"))
    updates = ls.register_provider_updates(_choice(auth_header="X-Gw-Key", auth_prefix="Token "))
    assert updates["ATLAS_PROVIDER_GW_AUTH_HEADER"] == "X-Gw-Key"


def test_the_dashboard_save_refuses_and_writes_nothing(tmp_path, monkeypatch):
    from dashboard import config_llm
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    for data in ({"model": "model-a X=1"}, {"api_key": "k-1\nX=1"}):
        with pytest.raises(config_llm.ConfigError):
            config_llm.save_provider({"name": "gw", "base_url": "https://llm.example.com/v1", "model": "model-a",
                                      "skip_probe": True, "preset_id": "custom", **data})
        assert (tmp_path / ".env").read_text() == ""


def test_provider_use_refuses_a_model_that_breaks_the_line(monkeypatch):
    from agent import cli
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "k-1")
    with pytest.raises(SystemExit, match="cannot be saved"):
        cli.cmd_provider_use(SimpleNamespace(name="gw", role="analyst", model="model-a X=1",
                                             no_probe=True, dry_run=True, env=False))


def test_the_wizard_refuses_a_key_with_a_control_character_before_writing(tmp_path, monkeypatch):
    from agent import cli
    from core import llm_setup as ls
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    monkeypatch.setattr("agent.prompts.REPO_ROOT", tmp_path)
    index = next(i for i, p in enumerate(ls.presets(), 1) if p.id == "openrouter")
    monkeypatch.setattr(cli, "_ask", lambda prompt, default="":
                        str(index) if prompt.startswith("Choice") else (default or "m-1"))
    monkeypatch.setattr(cli, "_ask_secret", lambda prompt: "k-test\x1bpart")
    monkeypatch.setattr(cli, "_ask_yn", lambda prompt, default_yes=True: default_yes)
    with pytest.raises(SystemExit, match="cannot be saved"):
        cli.cmd_provider_setup(None)
    assert env.read_text(encoding="utf-8") == ""


# Values read back by the env loader exactly as they were written.
ROUND = ["Token ", "  lead", "a #b", "'quoted'", '"dq"', "back\\slash 'x' ", "plain-1", "", "w\\\\ "]


def test_every_value_reads_back_through_the_loader_as_written(tmp_path):
    from dotenv import dotenv_values
    env = tmp_path / ".env"
    env.write_text("# a comment\nKEEP=1\n", encoding="utf-8")
    updates = {f"ATLAS_T{i}": v for i, v in enumerate(ROUND)}
    envfile.set_values(env, updates)
    assert {k: v for k, v in dotenv_values(env, interpolate=False).items() if k != "KEEP"} == updates
    assert envfile.read_values(env) == {"KEEP": "1", **updates}
    text = env.read_text(encoding="utf-8")
    assert "ATLAS_T6=plain-1\n" in text and 'ATLAS_T0="Token "\n' in text


def test_a_value_is_replaced_in_place_quoted_or_not(tmp_path):
    env = tmp_path / ".env"
    env.write_text("A=1\nB=x\n", encoding="utf-8")
    envfile.set_values(env, {"A": "Token "})
    envfile.set_values(env, {"A": "plain"})
    assert env.read_text(encoding="utf-8") == "A=plain\nB=x\n"


def test_a_secret_loses_a_pastes_edge_whitespace(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("", encoding="utf-8")
    monkeypatch.setenv("ATLAS_TEST_KEY", "")
    assert envfile.save_secret_value(tmp_path, env, "ATLAS_TEST_KEY", "  k-test-1 ", "env") == {"stored": "env"}
    assert envfile.read_values(env) == {"ATLAS_TEST_KEY": "k-test-1"}
    assert envfile.save_secret_value(tmp_path, env, "ATLAS_TEST_KEY", "   ", "env") == {"stored": "skip"}
    assert envfile.read_values(env) == {"ATLAS_TEST_KEY": "k-test-1"}


def test_a_key_that_breaks_a_line_is_refused_before_any_check(tmp_path, monkeypatch):
    from dashboard import config_llm
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    probed = []
    monkeypatch.setattr(config_llm, "probe", lambda *a, **k: probed.append(a) or {"ok": True, "models": []})
    with pytest.raises(config_llm.ConfigError, match="API key cannot be saved"):
        config_llm.save_provider({"name": "gw_k", "preset_id": "custom", "base_url": "https://gw.example.com/v1",
                                  "model": "m-1", "api_key": "k-1\nINJECTED=1"})
    assert probed == [] and (tmp_path / ".env").read_text(encoding="utf-8") == ""


def _read_double_quoted(line: str) -> tuple[str, str]:
    """A reader independent of python-dotenv, with the double-quote rule of
    the shell and systemd's EnvironmentFile: a backslash takes the next
    character literally. A value not in double quotes is taken as it is."""
    key, raw = line.split("=", 1)
    if not raw.startswith('"'):
        return key, raw
    out, i = [], 1
    while raw[i] != '"':
        if raw[i] == "\\":
            i += 1
        out.append(raw[i])
        i += 1
    assert raw[i + 1:] == "", line
    return key, "".join(out)


@pytest.mark.parametrize("value", ROUND)
def test_a_written_line_reads_back_under_the_shell_and_systemd_rule(value):
    assert _read_double_quoted(envfile._line("ATLAS_T", value)) == ("ATLAS_T", value)
