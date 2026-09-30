"""Tests for tools/imaging.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.imaging.run", return_value=run_ok) as m:
        yield m


class TestVshadow:
    def test_vshadow_mount(self, mock_run, tmp_path):
        from tools.imaging import vshadow_mount
        vshadow_mount("/dev/sda1", str(tmp_path / "vss"))
        assert "vshadowmount" in mock_run.call_args[0][0]

    def test_vshadow_list(self, mock_run, tmp_path):
        from tools.imaging import vshadow_list
        vshadow_list(str(tmp_path))
        assert "ls" in mock_run.call_args[0][0]

    def test_vshadow_umount(self, mock_run, tmp_path):
        from tools.imaging import vshadow_umount
        vshadow_umount(str(tmp_path / "vss"))
        assert "umount" in mock_run.call_args[0][0]


class TestBdeMout:
    def test_bde_mount_password(self, mock_run, tmp_path):
        from tools.imaging import bde_mount
        bde_mount("/evidence/bitlocker.img", str(tmp_path / "bde"), recovery_password="123456-789012")
        cmd = mock_run.call_args[0][0]
        assert "bdemount" in cmd
        assert "-r" in cmd

    def test_bde_mount_keyfile(self, mock_run, tmp_path):
        from tools.imaging import bde_mount
        bde_mount("/evidence/bitlocker.img", str(tmp_path / "bde"), recovery_key_file="/keys/key.bek")
        cmd = mock_run.call_args[0][0]
        assert "-k" in cmd

    def test_bde_info(self, mock_run):
        from tools.imaging import bde_info
        bde_info("/evidence/bitlocker.img")
        assert "bdeinfo" in mock_run.call_args[0][0]


class TestXmount:
    def test_xmount_image(self, mock_run, tmp_path):
        from tools.imaging import xmount_image
        xmount_image("/evidence/image.E01", str(tmp_path / "xmount"))
        cmd = mock_run.call_args[0][0]
        assert "xmount" in cmd
        assert "--in" in cmd
        assert "--out" in cmd

    def test_xmount_umount(self, mock_run, tmp_path):
        from tools.imaging import xmount_umount
        xmount_umount(str(tmp_path / "xmount"))
        assert "fusermount" in mock_run.call_args[0][0]


class TestPhotorec:
    def test_photorec_output_safe(self):
        from tools.imaging import photorec_carve
        with pytest.raises(Exception):
            photorec_carve("/evidence/image.E01", "/cases/example/evidence/carved")

    def test_photorec_allowed(self, mock_run, tmp_path):
        from tools.imaging import photorec_carve
        out = str(tmp_path / "carved")
        photorec_carve("/evidence/image.E01", out)
        cmd = mock_run.call_args[0][0]
        assert "photorec" in cmd

    def test_photorec_file_types(self, mock_run, tmp_path):
        from tools.imaging import photorec_carve
        out = str(tmp_path / "carved")
        photorec_carve("/evidence/image.E01", out, file_types="jpg,pdf")
        cmd = mock_run.call_args[0][0]
        assert "jpg" in " ".join(cmd)


class TestLosetup:
    def test_losetup_create(self, mock_run):
        from tools.imaging import losetup_create
        losetup_create("/evidence/image.img")
        cmd = mock_run.call_args[0][0]
        assert "losetup" in cmd
        assert "--show" in cmd

    def test_losetup_create_with_offset(self, mock_run):
        from tools.imaging import losetup_create
        losetup_create("/evidence/image.img", offset_bytes=1048576)
        cmd = mock_run.call_args[0][0]
        assert "-o" in cmd
        assert "1048576" in cmd

    def test_losetup_list(self, mock_run):
        from tools.imaging import losetup_list
        losetup_list()
        assert "losetup" in mock_run.call_args[0][0]

    def test_losetup_detach_outside_a_case_runs_nothing(self, mock_run, monkeypatch):
        from tools.imaging import losetup_detach
        monkeypatch.setattr("core.paths.active_case_dir", lambda: None)
        result = losetup_detach("/dev/loop0")
        assert result["success"] is False
        assert mock_run.call_args is None


class TestChainInfoAnswersAboutTheDiskAsked:
    def test_corroboration_follows_the_named_disk(self, mock_run, tmp_path):
        """Keyed to analysis_targets[0], the qemu-img corroboration described
        the directory's *first* disk whatever the caller named — so asking
        about disk B returned disk A's chain under a generic key."""
        from tools.imaging import vmdk_chain_info

        disk_a = tmp_path / "HOST-A.vmdk"
        disk_b = tmp_path / "HOST-B.vmdk"
        for d in (disk_a, disk_b):
            d.write_text("# Disk DescriptorFile\n", encoding="utf-8")

        targets = [
            {"recommended_descriptor": str(disk_a)},
            {"recommended_descriptor": str(disk_b)},
        ]
        with patch("core.vmdk.analyze_vm_dir",
                   return_value={"success": True, "analysis_targets": targets}), \
             patch("tools.imaging.shutil.which", return_value="/usr/bin/qemu-img"):
            res = vmdk_chain_info(str(disk_b))

        assert res["qemu_img_backing_chain_of"] == str(disk_b), \
            "the corroboration must describe the disk that was asked about"
        assert str(disk_b) in mock_run.call_args[0][0]
        # And the caller is told one call covers the whole directory.
        assert res["scope"] == "directory"
        assert "sibling disk needs no second call" in res["scope_note"]
