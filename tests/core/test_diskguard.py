"""Tests for the disk-space fail-safe (core/diskguard.py) and its wiring
into the executor and background-job launcher."""
import io
import os
from collections import namedtuple
from unittest.mock import patch, MagicMock

import pytest

from core import diskguard
from core.executor import run

_Usage = namedtuple("_Usage", "total used free")


def _usage(free_gb, total_gb=100):
    g = 1024 ** 3
    total = total_gb * g
    free = int(free_gb * g)
    return _Usage(total=total, used=total - free, free=free)


# ── diskguard.check / guard ──────────────────────────────────────────────────

class TestCheck:
    def test_ample_space_is_ok(self):
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(50)):
            s = diskguard.check("/some/dir")
        assert s["ok"] is True
        assert s["free_mb"] > 0

    def test_below_mb_floor_blocks(self, monkeypatch):
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_MB", "2048")
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_PCT", "0")
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(0.5)):
            s = diskguard.check("/x")
        assert s["ok"] is False
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(0.5)):
            assert diskguard.is_low("/x") is True

    def test_percent_floor_blocks_on_large_volume(self, monkeypatch):
        # 5 GB free on a 100 GB disk = 5%; a 10% floor must block despite the
        # absolute free space exceeding a small MB floor.
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_MB", "1024")
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_PCT", "10")
        with patch("core.diskguard.shutil.disk_usage",
                   return_value=_usage(5, total_gb=100)):
            s = diskguard.check("/x")
        assert s["ok"] is False

    def test_floor_is_the_larger_of_mb_and_pct(self, monkeypatch):
        # 3 GB free, 100 GB disk (3%). MB floor 2 GB passes, pct floor 5% fails.
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_MB", "2048")
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_PCT", "5")
        with patch("core.diskguard.shutil.disk_usage",
                   return_value=_usage(3, total_gb=100)):
            assert diskguard.check("/x")["ok"] is False

    def test_stat_failure_fails_open(self):
        with patch("core.diskguard.shutil.disk_usage", side_effect=OSError("boom")):
            s = diskguard.check("/x")
        assert s["ok"] is True  # never wedge a run over an unstattable path

    def test_guard_raises_when_low(self, monkeypatch):
        monkeypatch.setenv("ATLAS_MIN_FREE_DISK_MB", "2048")
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(0.1)):
            with pytest.raises(diskguard.DiskSpaceError):
                diskguard.guard("/x", "carve")

    def test_guard_silent_when_ample(self):
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(50)):
            diskguard.guard("/x", "carve")  # no raise

    def test_probe_walks_up_to_existing_ancestor(self, tmp_path):
        missing = str(tmp_path / "does" / "not" / "exist")
        assert os.path.exists(diskguard._probe_path(missing))


# ── executor preflight ───────────────────────────────────────────────────────

def _fake_popen(returncode=0, stdout=b"ok", stderr=b""):
    m = MagicMock()
    m.stdout = io.BytesIO(stdout)
    m.stderr = io.BytesIO(stderr)
    m.wait.return_value = returncode
    return m


class TestExecutorPreflight:
    def test_low_disk_blocks_run_without_launching(self):
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(0.1)), \
             patch("core.executor.subprocess.Popen") as mock_popen:
            r = run(["echo", "hi"], output_dir="analysis/x")
        assert r["success"] is False
        assert r["disk_low"] is True
        mock_popen.assert_not_called()

    def test_ample_disk_allows_run(self):
        with patch("core.diskguard.shutil.disk_usage", return_value=_usage(50)), \
             patch("core.executor.subprocess.Popen",
                   return_value=_fake_popen(0, b"hi")):
            r = run(["echo", "hi"])
        assert r["success"] is True
        assert "disk_low" not in r
