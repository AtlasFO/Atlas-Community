"""Passwordless-sudo preflight for atlas run / train."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.sudo_preflight import (
    check_passwordless_sudo,
    require_passwordless_sudo,
    sudoers_script_hint,
)


def test_check_ok_when_probes_pass(monkeypatch):
    def fake_run(argv, **kw):
        class P:
            returncode = 0
            stderr = ""
            stdout = ""
        return P()

    monkeypatch.setattr("core.sudo_preflight.subprocess.run", fake_run)
    monkeypatch.setattr(
        "core.sudo_preflight._resolve_probe_bin", lambda n: f"/usr/sbin/{n}",
    )
    ok, details = check_passwordless_sudo()
    assert ok
    assert any("true" in d for d in details)


def test_check_fails_when_true_needs_password(monkeypatch):
    def fake_run(argv, **kw):
        class P:
            returncode = 1
            stderr = "sudo: a password is required"
            stdout = ""
        return P()

    monkeypatch.setattr("core.sudo_preflight.subprocess.run", fake_run)
    ok, details = check_passwordless_sudo()
    assert not ok
    assert any("FAIL" in d for d in details)


def test_require_exits_with_script_hint(monkeypatch):
    monkeypatch.setattr(
        "core.sudo_preflight.check_passwordless_sudo",
        lambda: (False, ["sudo -n true → FAIL"]),
    )
    with pytest.raises(SystemExit) as exc:
        require_passwordless_sudo()
    assert exc.value.code == 2


def test_require_skip_flag_and_env(monkeypatch):
    monkeypatch.setattr(
        "core.sudo_preflight.check_passwordless_sudo",
        lambda: (_ for _ in ()).throw(AssertionError("should not probe")),
    )
    require_passwordless_sudo(skip=True)
    monkeypatch.setenv("ATLAS_SKIP_SUDO_CHECK", "1")
    require_passwordless_sudo(skip=False)


def test_hint_mentions_atlas_sudoers():
    hint = sudoers_script_hint()
    assert "atlas-sudoers" in hint
    assert "share/atlas-sudoers.in" in hint


def test_cli_run_aborts_without_sudo(tmp_path, monkeypatch):
    from agent import cli
    from argparse import Namespace

    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("# Case\n", encoding="utf-8")
    # A disk image is what makes root necessary; a case of CSV exports
    # skips the preflight altogether.
    (case / "evidence" / "host.E01").write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
    monkeypatch.setattr(
        cli, "_resolve_case", lambda *_a, **_k: case,
    )
    monkeypatch.setattr(
        "core.sudo_preflight.check_passwordless_sudo",
        lambda: (False, ["sudo -n true → FAIL (password required)"]),
    )
    args = Namespace(
        case=str(case), skip_sudo_check=False, no_capture_brain=False,
        capture_brain=False, no_brain=False, resume=False, fresh=False,
        language=None,
    )
    monkeypatch.setattr(cli, "_apply_brain_flags", lambda a: None)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_run(args)
    assert exc.value.code == 2
