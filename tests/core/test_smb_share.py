"""Tests for core/smb_share.py — the Python side of the SMB network share
feature. No real Samba/sudo involved: every privileged call to
bin/atlas-smb-share goes through subprocess.run, which is mocked here.
"""
import json
import subprocess

import pytest

from core import smb_share


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["atlas-smb-share"], returncode=returncode, stdout=stdout, stderr=stderr)


class TestStatus:
    def test_package_not_installed_short_circuits_without_subprocess(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: False)
        called = []
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(1))
        result = smb_share.status()
        assert result["installed"] is False
        assert result["error"] is None
        assert called == []  # never shells out when samba isn't even present

    def test_sudo_permission_denied_returns_dict_not_raise(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(1, stderr="sudo: a password is required"))
        result = smb_share.status()
        assert result["installed"] is False
        assert "password" in result["error"]

    def test_missing_wrapper_returns_dict_not_raise(self, monkeypatch, tmp_path):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        monkeypatch.setattr(smb_share, "_WRAPPER", tmp_path / "does-not-exist")
        result = smb_share.status()
        assert result["installed"] is False
        assert "missing" in result["error"]

    def test_enabled_status_parses_json(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        payload = {"installed": True, "enabled": True, "service_active": True,
                   "share_name": "atlas-cases", "share_path": "/home/x/cases",
                   "share_user": "x", "password_set": True}
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(0, stdout=json.dumps(payload)))
        result = smb_share.status()
        assert result["enabled"] is True
        assert result["share_path"] == "/home/x/cases"
        assert result["error"] is None

    def test_garbage_output_returns_dict_not_raise(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(0, stdout="not json"))
        result = smb_share.status()
        assert result["installed"] is False
        assert "unexpected" in result["error"]


class TestEnable:
    def test_refuses_when_package_not_installed(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: False)
        with pytest.raises(smb_share.ShareError, match="not installed"):
            smb_share.enable()

    def test_refuses_when_cases_root_missing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        missing = tmp_path / "does-not-exist"
        monkeypatch.setattr(smb_share, "_cases_root", lambda: str(missing))
        with pytest.raises(smb_share.ShareError, match="does not exist"):
            smb_share.enable()

    def test_calls_wrapper_with_cases_root_and_username(self, monkeypatch, tmp_path):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        monkeypatch.setattr(smb_share, "_cases_root", lambda: str(tmp_path))
        monkeypatch.setattr(smb_share, "_current_username", lambda: "alice")
        # enable() calls status() again at the end to return fresh state, so
        # this needs to record every call, not just the last.
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return _completed(0, stdout=json.dumps({
                "installed": True, "enabled": True, "service_active": True,
                "share_name": "atlas-cases", "share_path": str(tmp_path),
                "share_user": "alice", "password_set": False}))

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = smb_share.enable()
        assert calls[0][-3:] == ["enable", str(tmp_path), "alice"]
        assert result["enabled"] is True

    def test_wrapper_failure_raises_with_stderr(self, monkeypatch, tmp_path):
        monkeypatch.setattr(smb_share, "_package_installed", lambda: True)
        monkeypatch.setattr(smb_share, "_cases_root", lambda: str(tmp_path))
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(1, stderr="testparm failed"))
        with pytest.raises(smb_share.ShareError, match="testparm failed"):
            smb_share.enable()


class TestDisable:
    def test_calls_wrapper_disable(self, monkeypatch):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(0, stdout="disabled")

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(smb_share, "_package_installed", lambda: False)
        smb_share.disable()
        assert captured["cmd"][-1] == "disable"

    def test_failure_raises(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(1, stderr="boom"))
        with pytest.raises(smb_share.ShareError, match="boom"):
            smb_share.disable()


class TestSetPassword:
    def test_rejects_empty_password(self):
        with pytest.raises(smb_share.ShareError, match="required"):
            smb_share.set_password("")

    def test_sends_password_twice_on_stdin(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_current_username", lambda: "alice")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["input"] = kwargs.get("input")
            return _completed(0, stdout="password set for alice")

        monkeypatch.setattr(subprocess, "run", fake_run)
        smb_share.set_password("hunter2")
        assert captured["cmd"][-2:] == ["set-password", "alice"]
        assert captured["input"] == "hunter2\nhunter2\n"

    def test_failure_raises(self, monkeypatch):
        monkeypatch.setattr(smb_share, "_current_username", lambda: "alice")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _completed(1, stderr="smbpasswd failed"))
        with pytest.raises(smb_share.ShareError, match="smbpasswd failed"):
            smb_share.set_password("hunter2")



class TestCurrentUsername:
    def test_uses_the_password_database(self, monkeypatch):
        import os
        import pwd
        for var in ("LOGNAME", "USER", "LNAME", "USERNAME"):
            monkeypatch.delenv(var, raising=False)
        assert smb_share._current_username() == pwd.getpwuid(os.geteuid()).pw_name

    def test_falls_back_to_the_login_environment(self, monkeypatch):
        def no_entry(uid):
            raise KeyError(uid)
        monkeypatch.setattr(smb_share.pwd, "getpwuid", no_entry)
        monkeypatch.setenv("LOGNAME", "user01")
        assert smb_share._current_username() == "user01"

    def test_raises_share_error_when_nothing_knows(self, monkeypatch):
        def no_entry(uid):
            raise KeyError(uid)
        monkeypatch.setattr(smb_share.pwd, "getpwuid", no_entry)
        for var in ("LOGNAME", "USER", "LNAME", "USERNAME"):
            monkeypatch.delenv(var, raising=False)
        with pytest.raises(smb_share.ShareError):
            smb_share._current_username()
