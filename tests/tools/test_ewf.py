"""Tests for tools/ewf.py."""
import pytest
from unittest.mock import patch, call


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.ewf.run", return_value=run_ok) as m:
        yield m


MMLS_OUTPUT = (
    "DOS Partition Table\n"
    "Offset Sector: 0\n"
    "Units are in 512-byte sectors\n"
    "\n"
    "      Slot      Start        End          Length       Description\n"
    "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
    "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
    "002:  000:000   0000002048   0004194303   0004192256   NTFS (0x07)\n"
)


class TestEwfBasicTools:
    def test_ewf_info(self, mock_run):
        from tools.ewf import ewf_info
        ewf_info("/fake/image.E01")
        assert "ewfinfo" in mock_run.call_args[0][0]

    def test_ewf_verify(self, mock_run):
        from tools.ewf import ewf_verify
        ewf_verify("/fake/image.E01")
        assert "ewfverify" in mock_run.call_args[0][0]

    def test_ewf_mount(self, mock_run, tmp_path):
        from tools.ewf import ewf_mount
        ewf_mount("/fake/image.E01", str(tmp_path / "ewf"))
        assert "ewfmount" in mock_run.call_args[0][0]

    def test_ewf_umount(self, mock_run, tmp_path):
        from tools.ewf import ewf_umount
        ewf_umount(str(tmp_path / "ewf"))
        assert "umount" in mock_run.call_args[0][0]

    def test_umount_filesystem(self, mock_run, tmp_path):
        from tools.ewf import umount_filesystem
        umount_filesystem(str(tmp_path / "ntfs"))
        assert "umount" in mock_run.call_args[0][0]


class TestMountNtfs:
    def test_readonly_mounts(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=1048576)
        cmd = mock_run.call_args[0][0]
        assert "mount" in cmd
        assert any("ro" in x for x in cmd)

    def test_offset_in_options(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=2097152)
        cmd = mock_run.call_args[0][0]
        assert any("2097152" in x for x in cmd)

    def test_read_write_blocked(self):
        from tools.ewf import mount_ntfs
        r = mount_ntfs("/mnt/ewf/ewf1", "/tmp/ntfs", offset_bytes=0, read_only=False)
        assert r["success"] is False
        assert "Read-only" in r["stderr"]


class TestMountFullImage:
    def _ok(self, stdout=""):
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0, "truncated": False, "cmd": ""}

    def _fail(self, stderr="error"):
        return {"success": False, "stdout": "", "stderr": stderr, "exit_code": 1, "truncated": False, "cmd": ""}

    def test_success_path(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = str(tmp_path / "ewf")
        fs_mp = str(tmp_path / "fs")
        side = [self._ok(), self._ok(MMLS_OUTPUT), self._ok()]
        with patch("tools.ewf.run", side_effect=side) as m:
            r = mount_full_image("/fake/image.E01", ewf_mp, fs_mp)
        assert r["success"] is True
        assert r["ntfs_offset_sectors"] == 2048
        assert r["ntfs_offset_bytes"] == 2048 * 512

    def test_ewfmount_failure_short_circuits(self, tmp_path):
        from tools.ewf import mount_full_image
        with patch("tools.ewf.run", return_value=self._fail("ewfmount: no device")):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False

    def test_mmls_failure_short_circuits(self, tmp_path):
        from tools.ewf import mount_full_image
        side = [self._ok(), self._fail("mmls: read error")]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False

    def test_no_ntfs_partition_detected(self, tmp_path):
        from tools.ewf import mount_full_image
        mmls_no_ntfs = "Slot  Start  End  Length  Description\n000  0  2047  2048  Linux\n"
        side = [self._ok(), self._ok(mmls_no_ntfs)]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False
        assert r.get("gate") == "non_ntfs"
        assert "NTFS" in r["stderr"]

    def test_ewf_device_path_constructed(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = str(tmp_path / "ewf")
        side = [self._ok(), self._ok(MMLS_OUTPUT), self._ok()]
        with patch("tools.ewf.run", side_effect=side) as m:
            mount_full_image("/fake/image.E01", ewf_mp, str(tmp_path / "fs"))
        # Second call (mmls) should reference ewf_mp/ewf1
        mmls_cmd = m.call_args_list[1][0][0]
        assert "ewf1" in mmls_cmd[-1]


class TestMountNtfsReuse:
    """clear_case_run preserves live evidence mounts, so mount_ntfs must
    reuse an existing mount of the same image at the same mount point
    (ntfs-3g refuses to mount the same backing file twice). A mount at a
    *different* path — e.g. another case whose evidence symlink resolves to
    the same file, which would otherwise reuse that case's mount silently —
    gets a fresh mount attempt at the requested point first, with a loud
    flagged reuse only as fallback."""

    def test_same_mount_point_reused_silently(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mp = str(tmp_path / "ntfs")
        with patch("tools.ewf._existing_mount_of",
                   return_value=(mp, "/dev/loop7", 1048576)):
            r = mount_ntfs("/evid/img.raw", mp, offset_bytes=1048576)
        assert r["success"] is True
        assert r["reused"] is True
        assert r["mount_point"] == mp
        assert "warning" not in r
        mock_run.assert_not_called()

    def test_same_mount_point_fuse_unknown_offset_reused_with_note(
            self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mp = str(tmp_path / "ntfs")
        with patch("tools.ewf._existing_mount_of",
                   return_value=(mp, "/evid/img.raw", None)):
            r = mount_ntfs("/evid/img.raw", mp, offset_bytes=1048576)
        assert r["success"] is True and r["reused"] is True
        assert "could not be verified" in r["stdout"]
        mock_run.assert_not_called()

    def test_foreign_mount_point_gets_own_mount_when_os_allows(
            self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        requested = str(tmp_path / "ntfs")
        with patch("tools.ewf._existing_mount_of",
                   return_value=("/other-case/mnt/host01", "/dev/loop7", 1048576)):
            r = mount_ntfs("/evid/img.raw", requested, offset_bytes=1048576)
        assert r["success"] is True
        assert "reused" not in r
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "mount"
        assert cmd[-1] == requested

    def test_foreign_mount_point_falls_back_to_flagged_reuse(
            self, mock_run, run_fail, tmp_path):
        from tools.ewf import mount_ntfs
        requested = str(tmp_path / "ntfs")
        mock_run.return_value = run_fail  # OS refuses the second mount
        with patch("tools.ewf._existing_mount_of",
                   return_value=("/other-case/mnt/host01", "/dev/loop7", 1048576)):
            r = mount_ntfs("/evid/img.raw", requested, offset_bytes=1048576)
        assert r["success"] is True
        assert r["reused"] is True
        assert r["warning"] == "reused_foreign_mount_point"
        assert r["mount_point"] == "/other-case/mnt/host01"
        assert "different case" in r["stdout"]

    def test_offset_mismatch_fails_with_guidance(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        with patch("tools.ewf._existing_mount_of",
                   return_value=("/case/mnt/host01", "/dev/loop7", 512)):
            r = mount_ntfs("/evid/img.raw", str(tmp_path / "ntfs"),
                           offset_bytes=1048576)
        assert r["success"] is False
        assert "different offset" in r["stderr"]
        mock_run.assert_not_called()

    def test_no_existing_mount_falls_through_to_mount(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        with patch("tools.ewf._existing_mount_of", return_value=None):
            mount_ntfs("/evid/img.raw", str(tmp_path / "ntfs"),
                       offset_bytes=1048576)
        assert "mount" in mock_run.call_args[0][0]

    def test_existing_mount_of_matches_fuse_source(self, tmp_path):
        from tools.ewf import _existing_mount_of
        img = tmp_path / "img.raw"
        img.write_bytes(b"x")
        mounts = tmp_path / "mounts"
        mounts.write_text(
            f"sysfs /sys sysfs rw 0 0\n"
            f"{img} /case/mnt/host01 fuseblk ro,relatime 0 0\n")
        hit = _existing_mount_of(str(img), mounts_file=str(mounts))
        assert hit == ("/case/mnt/host01", str(img), None)

    def test_existing_mount_of_none_when_absent(self, tmp_path):
        from tools.ewf import _existing_mount_of
        mounts = tmp_path / "mounts"
        mounts.write_text("sysfs /sys sysfs rw 0 0\n")
        assert _existing_mount_of(str(tmp_path / "img.raw"),
                                  mounts_file=str(mounts)) is None


GPT_MMLS = (
    "GUID Partition Table (EFI)\n"
    "Offset Sector: 0\n"
    "Units are in 512-byte sectors\n"
    "\n"
    "      Slot      Start        End          Length       Description\n"
    "000:  Meta      0000000000   0000000000   0000000001   Safety Table\n"
    "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
    "002:  Meta      0000000001   0000000001   0000000001   GPT Header\n"
    "003:  Meta      0000000002   0000000033   0000000032   Partition Table\n"
    "004:  000       0000002048   0000206847   0000204800   EFI system partition\n"
    "005:  001       0000206848   0000239615   0000032768   Microsoft reserved partition\n"
    "006:  002       0000239616   0030417012   0030177397   Basic data partition\n"
    "007:  003       0030418944   0031453183   0001034240   \n"
)


class TestExposedDeviceAndGptDetection:
    """The exposed device must be readable by the analyst, and a GPT disk's
    "Basic data partition" is NTFS or not by its boot sector, not its label."""

    def test_ewfmount_exposes_the_device_to_other_users(self, mock_run, tmp_path):
        from tools.ewf import ewf_mount
        ewf_mount("/fake/image.E01", str(tmp_path / "ewf"))
        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["ewfmount", "-X", "allow_other"]

    def test_gpt_basic_data_partition_is_mounted_when_device_unreadable(self, tmp_path):
        from tools.ewf import mount_full_image
        ok = {"success": True, "stdout": "", "stderr": "", "exit_code": 0, "truncated": False, "cmd": ""}
        side = [ok, dict(ok, stdout=GPT_MMLS), ok]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/win10.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is True
        assert r["ntfs_offset_sectors"] == 239616

    def test_boot_sector_decides_between_unlabelled_partitions(self, tmp_path):
        from tools.ewf import _largest_mountable_volume
        # The larger "basic data" volume is exFAT; the smaller one is NTFS,
        # and a disk with an NTFS volume mounts it as before.
        table = (
            "Units are in 512-byte sectors\n"
            "004:  000       0000000002   0000000009   0000000008   Basic data partition\n"
            "005:  001       0000000012   0000000015   0000000004   Basic data partition\n"
        )
        dev = tmp_path / "ewf1"
        raw = bytearray(512 * 20)
        raw[2 * 512 + 3:2 * 512 + 11] = b"EXFAT   "
        raw[12 * 512 + 3:12 * 512 + 11] = b"NTFS    "
        dev.write_bytes(bytes(raw))
        assert _largest_mountable_volume(table, str(dev)) == (12, 4, 512, "ntfs")

    def test_sector_size_is_read_from_the_table(self, tmp_path):
        from tools.ewf import _largest_mountable_volume
        table = ("Units are in 4096-byte sectors\n"
                 "002:  000:000   0000000256   0000004095   0000003840   NTFS (0x07)\n")
        assert _largest_mountable_volume(table, "/nonexistent") == (256, 3840, 4096, "ntfs")

    def test_linux_only_disk_is_still_non_ntfs(self, tmp_path):
        from tools.ewf import _largest_mountable_volume
        table = ("Units are in 512-byte sectors\n"
                 "002:  000:000   0000002048   0004194303   0004192256   Linux (0x83)\n")
        assert _largest_mountable_volume(table, "/nonexistent") is None

    def test_mount_ntfs_refuses_an_offset_without_an_ntfs_boot_sector(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        dev = tmp_path / "ewf1"
        raw = bytearray(512 * 8)
        raw[4 * 512 + 3:4 * 512 + 11] = b"NTFS    "
        dev.write_bytes(bytes(raw))
        r = mount_ntfs(str(dev), str(tmp_path / "fs"), offset_bytes=2 * 512)
        assert r["success"] is False
        assert "No NTFS boot sector" in r["stderr"]
        assert f"byte offset {4 * 512} (start sector 4)" in r["stderr"]  # the off-by-one hint
        mock_run.assert_not_called()
        assert mount_ntfs(str(dev), str(tmp_path / "fs"), offset_bytes=4 * 512)["success"] is True


def _fat_boot_sector(label=b"        "):
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSDOS5.0"
    boot[11:13] = (512).to_bytes(2, "little")
    boot[13] = 8                      # sectors per cluster
    boot[14:16] = (32).to_bytes(2, "little")
    boot[16] = 2                      # FATs
    boot[21] = 0xF8                   # fixed-disk media descriptor
    boot[82:90] = label
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


class TestRemovableMediaVolumes:
    """USB keys and cards are exFAT or FAT, often without a partition table;
    auto-mount opens them read-only instead of recording a failed disk."""

    def _ok(self, stdout=""):
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0, "truncated": False, "cmd": ""}

    def _device(self, tmp_path, sectors, at):
        dev_dir = tmp_path / "ewf"
        dev_dir.mkdir()
        raw = bytearray(512 * sectors)
        for sector, boot in at.items():
            raw[sector * 512:sector * 512 + 512] = boot
        (dev_dir / "ewf1").write_bytes(bytes(raw))
        return str(dev_dir)

    def test_a_0x07_volume_that_is_exfat_mounts_as_exfat(self, tmp_path):
        from tools.ewf import mount_full_image
        exfat = bytearray(512)
        exfat[3:11] = b"EXFAT   "
        ewf_mp = self._device(tmp_path, 300, {128: bytes(exfat)})
        table = ("DOS Partition Table\nUnits are in 512-byte sectors\n"
                 "002:  000:000   0000000128   0000000299   0000000172   NTFS / exFAT (0x07)\n")
        with patch("tools.ewf.run", side_effect=[self._ok(table), self._ok()]) as m:
            r = mount_full_image("/fake/key.E01", ewf_mp, str(tmp_path / "fs"))
        cmd = m.call_args_list[-1][0][0]
        assert cmd[:3] == ["mount", "-t", "exfat"] and "ro,loop,offset=65536" in cmd[4]
        assert r["success"] is True and r["fs_type"] == "exfat"
        assert "ntfs_offset_bytes" not in r and r["volume_offset_bytes"] == 65536

    def test_a_partitionless_fat_key_mounts_from_the_start(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = self._device(tmp_path, 64, {0: _fat_boot_sector()})
        failed_mmls = {"success": False, "stdout": "", "stderr": "Cannot determine partition type",
                       "exit_code": 1, "truncated": False, "cmd": ""}
        with patch("tools.ewf.run", side_effect=[failed_mmls, self._ok()]) as m:
            r = mount_full_image("/fake/card.E01", ewf_mp, str(tmp_path / "fs"))
        cmd = m.call_args_list[-1][0][0]
        assert cmd[:3] == ["mount", "-t", "vfat"] and "ro,loop,offset=0" in cmd[4]
        assert r["success"] is True and r["fs_type"] == "fat"

    def test_fat_is_read_from_its_parameters_not_its_label(self, tmp_path):
        from tools.ewf import _volume_type_at
        dev = tmp_path / "dev"
        dev.write_bytes(_fat_boot_sector(label=b"        ") + bytes(512))
        assert _volume_type_at(str(dev), 0) == "fat"
        mbr_like = bytearray(_fat_boot_sector())
        mbr_like[13] = 3                  # not a power-of-two cluster
        dev.write_bytes(bytes(mbr_like))
        assert _volume_type_at(str(dev), 0) is None


def test_a_tsk_read_of_the_ewf_device_opens_its_image(tmp_path):
    import json
    from core.evidence_access import record_open_from_tool
    atlas = tmp_path / ".atlas"
    atlas.mkdir()
    image = str(tmp_path / "evidence" / "key.E01")
    (atlas / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": image, "basename": "key.E01", "mount_stem": "key", "status": "mount_failed"}]}))
    record_open_from_tool(tmp_path, tool_name="tsk_fls",
                          cmd_or_args="fls -r -o 128 mnt/key/ewf/ewf1", success=True)
    plan = json.loads((atlas / "mount_plan.json").read_text())
    assert plan["images"][0]["status"] == "opened"

