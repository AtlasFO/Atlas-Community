"""Remote-SIFT execution: config, path remapping, SSH argv, the remote runner,
executor delegation, and rsync bracketing. No live VM — SSH/rsync subprocesses
are mocked; the point is the wiring, not the network."""
import os
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _clear_remote_env(monkeypatch):
    for k in ("ATLAS_REMOTE_SIFT", "ATLAS_REMOTE_MODE", "ATLAS_REMOTE_WORKSPACE",
              "ATLAS_REMOTE_LOCAL_ROOT"):
        monkeypatch.delenv(k, raising=False)


def _enable(monkeypatch, mode="copy", ws="/remote/ws", root="/home/u/case"):
    monkeypatch.setenv("ATLAS_REMOTE_SIFT", "sift")
    monkeypatch.setenv("ATLAS_REMOTE_MODE", mode)
    monkeypatch.setenv("ATLAS_REMOTE_WORKSPACE", ws)
    monkeypatch.setenv("ATLAS_REMOTE_LOCAL_ROOT", root)


class FakeProc:
    def __init__(self, rc=0, out=b"remote output\n", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


_RESOLVED = {"user": "atlas", "host": "10.0.0.9", "port": 22,
             "identity": "/home/u/.ssh/id"}


class TestConfig:
    def test_disabled_by_default(self):
        from core import remote
        assert remote.remote_config() is None
        assert remote.is_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        cfg = remote.remote_config()
        assert cfg["host"] == "sift" and cfg["mode"] == "copy"
        assert cfg["workspace"] == "/remote/ws"
        assert remote.is_enabled() is True

    def test_invalid_mode_falls_back_to_resident(self, monkeypatch):
        from core import remote
        _enable(monkeypatch, mode="bogus")
        assert remote.remote_config()["mode"] == "resident"

    def test_default_mode_and_workspace(self, monkeypatch):
        from core import remote
        monkeypatch.setenv("ATLAS_REMOTE_SIFT", "sift")
        cfg = remote.remote_config()
        assert cfg["mode"] == "resident"
        assert cfg["workspace"].endswith("atlas-workspace")


class TestRemap:
    def test_copy_remaps_paths_under_local_root(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        cfg = remote.remote_config()
        out = remote.remap_argv(
            ["vol", "-f", "/home/u/case/evidence/mem.raw", "pslist"], cfg)
        assert out == ["vol", "-f", "/remote/ws/evidence/mem.raw", "pslist"]

    def test_passthrough_for_non_local_tokens(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        cfg = remote.remote_config()
        out = remote.remap_argv(["/usr/local/bin/vol", "--help"], cfg)
        assert out == ["/usr/local/bin/vol", "--help"]

    def test_resident_mode_never_remaps(self, monkeypatch):
        from core import remote
        _enable(monkeypatch, mode="resident")
        cfg = remote.remote_config()
        argv = ["vol", "-f", "/home/u/case/evidence/mem.raw"]
        assert remote.remap_argv(argv, cfg) == argv
        assert remote.remote_cwd(None, cfg) == "/remote/ws"

    def test_cwd_remapped_in_copy_mode(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        cfg = remote.remote_config()
        assert remote.remote_cwd("/home/u/case/analysis", cfg) == \
            "/remote/ws/analysis"


class TestBuildRemoteArgv:
    def test_ssh_argv_shape_and_quoting(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        cfg = remote.remote_config()
        ssh_argv, pretty = remote.build_remote_argv(
            ["vol", "-f", "/home/u/case/evidence/m e.raw"], cfg, _RESOLVED,
            "/home/u/case")
        assert ssh_argv[0] == "ssh"
        assert "atlas@10.0.0.9" in ssh_argv
        assert ssh_argv[-3:-1] == ["sh", "-lc"]
        inner = ssh_argv[-1]
        assert inner.startswith("cd /remote/ws")
        # Hostile spaces are quoted, remapped to the workspace.
        assert "/remote/ws/evidence/'m e.raw'" in inner \
            or "'/remote/ws/evidence/m e.raw'" in inner
        assert pretty.startswith("[remote:sift]")


class TestRunRemote:
    def test_success_result_schema(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        with patch("core.remote.subprocess.run", return_value=FakeProc()):
            r = remote.run_remote(["vol", "pslist"], cwd="/home/u/case")
        assert r["success"] is True
        assert r["source"] == "remote_sift"
        assert r["host"] == "sift"
        assert "remote output" in r["stdout"]
        assert r["cmd"].startswith("[remote:sift]")

    def test_nonzero_exit_is_failure(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        with patch("core.remote.subprocess.run",
                   return_value=FakeProc(rc=1, out=b"", err=b"boom")):
            r = remote.run_remote(["vol", "pslist"])
        assert r["success"] is False
        assert "boom" in r["stderr"]

    def test_stdout_file_writes_locally(self, monkeypatch, tmp_path):
        from core import remote
        _enable(monkeypatch)
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        out = tmp_path / "artifact.csv"
        with patch("core.remote.subprocess.run", return_value=FakeProc()):
            r = remote.run_remote(["icat", "img", "5"], stdout_file=str(out))
        assert r["output_path"] == str(out)
        assert r["success"] is True

    def test_over_cap_stdout_spills_to_file(self, monkeypatch):
        import os
        from core import remote
        from core.paths import OUTPUT_CAP
        _enable(monkeypatch)
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        big = b"r" * (OUTPUT_CAP + 500)
        with patch("core.remote.subprocess.run",
                   return_value=FakeProc(out=big)):
            r = remote.run_remote(["strings", "img"], line_cap=None)
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP
        assert "stdout_file" in r
        assert os.path.getsize(r["stdout_file"]) == len(big)

    def test_under_cap_no_spill(self, monkeypatch):
        from core import remote
        _enable(monkeypatch)
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        with patch("core.remote.subprocess.run", return_value=FakeProc()):
            r = remote.run_remote(["vol", "pslist"])
        assert "stdout_file" not in r

    def test_disabled_returns_error_not_crash(self):
        from core import remote
        r = remote.run_remote(["vol", "pslist"])
        assert r["success"] is False
        assert "disabled" in r["stderr"]

    def test_bad_host_config_is_captured(self, monkeypatch):
        from core import remote
        from core.ssh import SSHConfigError
        _enable(monkeypatch)

        def _boom(h):
            raise SSHConfigError("host 'sift' not found")
        monkeypatch.setattr(remote, "_resolve_host", _boom)
        r = remote.run_remote(["vol", "pslist"])
        assert r["success"] is False
        assert "not found" in r["stderr"]


class TestExecutorDelegation:
    def test_local_passthrough_when_disabled(self):
        # Remote off → run() executes locally exactly as before.
        from core import executor
        r = executor.run(["echo", "hi"])
        assert r["success"] is True
        assert "hi" in r["stdout"]

    def test_run_delegates_when_enabled(self, monkeypatch):
        from core import executor, remote
        _enable(monkeypatch, mode="resident")
        sentinel = {"success": True, "stdout": "REMOTE", "stderr": "",
                    "exit_code": 0, "truncated": False, "cmd": "vol",
                    "retries": 0, "source": "remote_sift"}
        called = {}

        def _fake(cmd, **kw):
            called["cmd"] = cmd
            return dict(sentinel)
        monkeypatch.setattr(remote, "run_remote", _fake)
        r = executor.run(["vol", "pslist"])
        assert r["stdout"] == "REMOTE"
        assert r["source"] == "remote_sift"
        assert called["cmd"] == ["vol", "pslist"]


class TestRsyncBracketing:
    def test_evidence_sync_skipped_in_resident_mode(self, monkeypatch):
        from core import remote
        _enable(monkeypatch, mode="resident")
        cfg = remote.remote_config()
        assert remote.sync_evidence_up(cfg)["skipped"] == "resident mode"
        assert remote.sync_outputs_back(cfg)["skipped"] == "resident mode"

    def test_evidence_sync_builds_rsync_in_copy_mode(self, monkeypatch, tmp_path):
        from core import remote
        root = tmp_path / "case"
        (root / "evidence").mkdir(parents=True)
        _enable(monkeypatch, mode="copy", root=str(root))
        cfg = remote.remote_config()
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        calls = []

        def _rec(argv, **kw):
            calls.append(argv)
            return FakeProc()
        with patch("core.remote.subprocess.run", _rec):
            r = remote.sync_evidence_up(cfg)
        assert r["success"] is True
        # One rsync push whose destination is the workspace on the VM.
        rsyncs = [c for c in calls if c and c[0] == "rsync"]
        assert rsyncs and any("atlas@10.0.0.9:/remote/ws/" in tok
                              for c in rsyncs for tok in c)

    def test_outputs_sync_pulls_three_subdirs(self, monkeypatch, tmp_path):
        from core import remote
        _enable(monkeypatch, mode="copy", root=str(tmp_path / "case"))
        cfg = remote.remote_config()
        monkeypatch.setattr(remote, "_resolve_host", lambda h: _RESOLVED)
        with patch("core.remote.subprocess.run", return_value=FakeProc()):
            r = remote.sync_outputs_back(cfg)
        assert r["success"] is True
        assert set(r["subdirs"]) == {"analysis", "exports", "reports"}
