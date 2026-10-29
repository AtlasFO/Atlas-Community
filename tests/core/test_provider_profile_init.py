"""`atlas provider profile init <id>` copies a shipped profile, comments
included, into the user folder so it loads as it is; `profile path` names
the folders. Runs against a scratch user folder only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent import cli
from core import provider_profiles as pp

SHIPPED = sorted(p.stem for p in pp.SHIPPED_DIR.glob("*.toml"))


@pytest.fixture
def folder(tmp_path, monkeypatch):
    target = tmp_path / "mine"
    monkeypatch.setenv(pp.DIR_ENV, str(target))
    pp.load(reload=True)
    yield target
    monkeypatch.delenv(pp.DIR_ENV)
    pp.load(reload=True)


def _init(pid, force=False):
    cli.cmd_provider_profile_init(SimpleNamespace(id=pid, force=force))


@pytest.mark.parametrize("pid", [p for p in SHIPPED if p != pp.FALLBACK])
def test_every_copy_loads_as_it_is(folder, pid, capsys):
    _init(pid)
    copy = (folder / f"{pid}.toml").read_text(encoding="utf-8")
    assert copy.splitlines()[0] == f"#:schema {(pp.SHIPPED_DIR / 'schema.json').resolve().as_uri()}"
    assert f'id = "{pid}"' in copy and "# Must equal the file name without .toml." in copy
    lines = [line.strip() for line in copy.splitlines()]
    assert "[env]" not in lines and not [line for line in lines if line.startswith("implicit")]
    catalog = pp.load(reload=True)
    assert pid not in catalog.errors and pid in catalog.profiles
    assert "WARNING" not in capsys.readouterr().out


def test_an_implicit_profile_is_copied_without_what_a_user_file_may_not_set(folder):
    _init("llmhub")
    copy = (folder / "llmhub.toml").read_text(encoding="utf-8")
    assert "LLMHUB_BASE_URL" not in copy and "Selectable as" not in copy
    assert "[connection]" in copy
    assert pp.load(reload=True).profiles["llmhub"].implicit is True     # still from the shipped file


def test_custom_and_unknown_ids_are_refused(folder):
    with pytest.raises(SystemExit, match="cannot be changed by a file"):
        _init(pp.FALLBACK)
    with pytest.raises(SystemExit, match="no shipped provider profile 'acme'"):
        _init("acme")
    assert not folder.exists()


def test_an_existing_file_is_kept_unless_forced(folder):
    _init("openai")
    (folder / "openai.toml").write_text('schema = 1\nid = "openai"\nlabel = "Mine"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="exists"):
        _init("openai")
    assert 'label = "Mine"' in (folder / "openai.toml").read_text()
    _init("openai", force=True)
    assert 'label = "Mine"' not in (folder / "openai.toml").read_text()


def test_path_names_both_folders(folder, capsys):
    cli.cmd_provider_profile_path(SimpleNamespace())
    out = capsys.readouterr().out
    assert str(folder) in out and "not created yet" in out and pp.DIR_ENV in out
    assert str(pp.SHIPPED_DIR) in out and "schema.json" in out


def test_the_parser_wires_both_commands():
    parser = cli.build_parser()
    args = parser.parse_args(["provider", "profile", "init", "openai"])
    assert args.func is cli.cmd_provider_profile_init and args.id == "openai"
    assert parser.parse_args(["provider", "profile", "path"]).func is cli.cmd_provider_profile_path
