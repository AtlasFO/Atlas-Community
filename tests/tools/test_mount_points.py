"""Tests for mount-point creation and vshadowmount permissions.

Two defects are guarded here: an unprivileged os.makedirs on /mnt/ewf_pc
crashed ewf.mount_full_image with a raw PermissionError, and a root-owned
vshadowmount FUSE mount was unreadable to the analyst process.
"""
import os
import pytest
from unittest.mock import patch

from core.paths import ensure_mount_point


class TestEnsureMountPoint:
    def test_creates_normal_directory(self, tmp_path):
        target = str(tmp_path / "mnt" / "ewf")
        assert ensure_mount_point(target) is None
        assert os.path.isdir(target)

    def test_permission_error_falls_back_to_sudo_mkdir(self, run_ok):
        with patch("core.paths.os.makedirs", side_effect=PermissionError), \
             patch("core.executor.run", return_value=run_ok) as m:
            assert ensure_mount_point("/srv/atlas-mounts/ewf_pc") is None
        m.assert_called_once_with(["mkdir", "-p", "/srv/atlas-mounts/ewf_pc"], needs_sudo=True)

    def test_sudo_failure_returns_guidance_not_traceback(self):
        failed = {"success": False, "stdout": "", "stderr": "mkdir: cannot create",
                  "exit_code": 1, "truncated": False}
        with patch("core.paths.os.makedirs", side_effect=PermissionError), \
             patch("core.executor.run", return_value=failed):
            res = ensure_mount_point("/srv/atlas-mounts/ewf_pc")
        assert res is not None and res["success"] is False
        assert "case-relative mount point" in res["stderr"]

    def test_system_mount_tree_is_refused_without_creating_anything(self):
        # /mnt is protected like evidence: the executor would refuse the
        # root-owned directory as "evidence modified" right after creating
        # it, so the refusal comes first and says what to use instead.
        with patch("core.paths.os.makedirs", side_effect=PermissionError), \
             patch("core.executor.run") as never_run:
            res = ensure_mount_point("/mnt/ewf_pc")
        never_run.assert_not_called()
        assert res["success"] is False
        assert "<case>/mnt/" in res["stderr"]


class TestMountToolsUseEnsureMountPoint:
    def test_ewf_mount_returns_error_dict_on_unwritable_mountpoint(self):
        from tools.ewf import ewf_mount
        err = {"success": False, "stderr": "Cannot create mount point", "stdout": "",
               "exit_code": 1, "truncated": False}
        with patch("tools.ewf.ensure_mount_point", return_value=err) as m, \
             patch("tools.ewf.run") as never_run:
            res = ewf_mount("/case/evidence/img.E01", "/mnt/ewf_pc")
        assert res is err
        never_run.assert_not_called()
        m.assert_called_once_with("/mnt/ewf_pc")

    def test_mount_full_image_checks_both_mountpoints(self):
        from tools.ewf import mount_full_image
        err = {"success": False, "stderr": "Cannot create mount point", "stdout": "",
               "exit_code": 1, "truncated": False}
        with patch("tools.ewf.ensure_mount_point", side_effect=[None, err]), \
             patch("tools.ewf.run") as never_run:
            res = mount_full_image("/case/evidence/img.E01", "/mnt/ewf", "/mnt/fs")
        assert res is err
        never_run.assert_not_called()

    def test_vshadow_mount_passes_allow_other(self, run_ok, tmp_path):
        from tools.imaging import vshadow_mount
        mp = str(tmp_path / "vss")
        with patch("tools.imaging.run", return_value=run_ok) as m:
            vshadow_mount("/case/mnt/ewf/ewf1", mp)
        cmd = m.call_args[0][0]
        assert cmd[0] == "vshadowmount"
        assert cmd[1:3] == ["-X", "allow_other"]
        assert m.call_args[1] == {"needs_sudo": True}
