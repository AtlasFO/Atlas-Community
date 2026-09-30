"""Tests for core/mounts.py — mount detection and safe teardown."""
import os
from unittest.mock import patch

from core import mounts


def _write_proc(tmp_path, mountpoints):
    """Write a fake /proc/mounts with the given mountpoints (field 2)."""
    lines = [f"/dev/loop0 {mp} ntfs ro,norecovery 0 0" for mp in mountpoints]
    f = tmp_path / "proc_mounts"
    f.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return str(f)


class TestFindMountsUnder:
    def test_finds_mount_at_and_under_path(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "cases" / "szechuan"))
        proc = _write_proc(tmp_path, [
            f"{base}/mnt/ewf_dc01",
            f"{base}/mnt/dc01",
            "/mnt/unrelated",
        ])
        found = mounts.find_mounts_under(base, proc)
        assert set(found) == {f"{base}/mnt/ewf_dc01", f"{base}/mnt/dc01"}

    def test_orders_innermost_first(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        proc = _write_proc(tmp_path, [
            f"{base}/mnt",
            f"{base}/mnt/vss/inner",
            f"{base}/mnt/vss",
        ])
        found = mounts.find_mounts_under(base, proc)
        # deepest path first so nested mounts unmount without EBUSY
        assert found == [
            f"{base}/mnt/vss/inner",
            f"{base}/mnt/vss",
            f"{base}/mnt",
        ]

    def test_sibling_prefix_not_matched(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "foo"))
        proc = _write_proc(tmp_path, [f"{base}bar/mnt", f"{base}/mnt"])
        found = mounts.find_mounts_under(base, proc)
        assert found == [f"{base}/mnt"]           # foobar/mnt excluded

    def test_octal_escapes_decoded(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        # kernel encodes a space in the mountpoint as \040
        f = tmp_path / "proc_mounts"
        f.write_text(f"/dev/loop0 {base}/my\\040mnt ntfs ro 0 0\n",
                     encoding="utf-8")
        found = mounts.find_mounts_under(base, str(f))
        assert found == [f"{base}/my mnt"]

    def test_missing_proc_file_returns_empty(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        found = mounts.find_mounts_under(base, str(tmp_path / "nonexistent"))
        assert found == []


class TestUnmountAllUnder:
    def test_lazy_fallback_when_plain_umount_fails(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        proc = _write_proc(tmp_path, [f"{base}/mnt/dc01"])
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            # plain umount fails (busy); lazy umount -l succeeds and clears it
            if cmd[:2] == ["umount", "-l"]:
                _write_proc(tmp_path, [])          # kernel drops the mount
                return {"success": True, "stderr": ""}
            return {"success": False, "stderr": "target is busy"}

        with patch("core.executor.run", side_effect=fake_run):
            result = mounts.unmount_all_under(base, proc)

        assert ["umount", f"{base}/mnt/dc01"] in calls
        assert ["umount", "-l", f"{base}/mnt/dc01"] in calls
        assert result["unmounted"] == [f"{base}/mnt/dc01"]
        assert result["failed"] == []
        assert result["remaining"] == []

    def test_reports_remaining_when_unmount_fails(self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        proc = _write_proc(tmp_path, [f"{base}/mnt/dc01"])

        def fake_run(cmd, **kw):
            return {"success": False, "stderr": "device is busy"}

        with patch("core.executor.run", side_effect=fake_run):
            result = mounts.unmount_all_under(base, proc)

        assert result["unmounted"] == []
        assert result["failed"] == [
            {"mount": f"{base}/mnt/dc01", "error": "device is busy"}
        ]
        assert result["remaining"] == [f"{base}/mnt/dc01"]

    def test_unconfigured_trace_raise_does_not_crash_the_clear(self,
                                                               tmp_path):
        # clear_case_run unmounts BEFORE any trace log is configured;
        # record_tool_call's _require_configured then raises out of run()
        # AFTER the umount subprocess already executed. The teardown must
        # trust the /proc/mounts re-scan, not crash (a crash here leaves a
        # stale fuse mount that makes `atlas train` unlaunchable).
        base = os.path.realpath(str(tmp_path / "case"))
        proc = _write_proc(tmp_path, [f"{base}/mnt/dc01"])

        def raising_run(cmd, **kw):
            _write_proc(tmp_path, [])  # the umount itself DID succeed
            raise RuntimeError("trace log not configured — cannot record")

        with patch("core.executor.run", side_effect=raising_run):
            result = mounts.unmount_all_under(base, proc)

        assert result["unmounted"] == [f"{base}/mnt/dc01"]
        assert result["failed"] == []
        assert result["remaining"] == []

    def test_unconfigured_trace_raise_with_stuck_mount_reports_failure(
            self, tmp_path):
        base = os.path.realpath(str(tmp_path / "case"))
        proc = _write_proc(tmp_path, [f"{base}/mnt/dc01"])

        def raising_run(cmd, **kw):
            raise RuntimeError("trace log not configured")

        with patch("core.executor.run", side_effect=raising_run):
            result = mounts.unmount_all_under(base, proc)

        assert result["unmounted"] == []
        assert len(result["failed"]) == 1
        assert "unlogged" in result["failed"][0]["error"]
        assert result["remaining"] == [f"{base}/mnt/dc01"]
