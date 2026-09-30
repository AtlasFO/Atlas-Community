"""Mounting exposes evidence without writing it: a read-only mount, an
unmount and the FUSE exposers pass the write guard and are not snapshotted
(the mount point changes by design), while a writable mount of evidence is
still refused."""
import os

from core.evidence_guard import (
    _writes, evidence_changes, refuse_evidence_write, snapshot_evidence_refs,
)


def _case_mounts(tmp_path):
    ewf = tmp_path / "case" / "mnt" / "img" / "ewf"
    fs = tmp_path / "case" / "mnt" / "img" / "fs"
    ewf.mkdir(parents=True)
    fs.mkdir(parents=True)
    (ewf / "ewf1").write_bytes(b"\x00" * 16)
    return str(ewf / "ewf1"), str(fs)


def test_read_only_mount_under_the_case_is_not_a_write(tmp_path):
    dev, fs = _case_mounts(tmp_path)
    cmd = ["sudo", "mount", "-o", "ro,loop,norecovery,offset=1048576", dev, fs]
    assert _writes(cmd) is False
    assert refuse_evidence_write(cmd) is None
    assert refuse_evidence_write(["sudo", "mount", "-r", dev, fs]) is None


def test_writable_mount_of_evidence_is_still_refused(tmp_path):
    dev, fs = _case_mounts(tmp_path)
    cmd = ["sudo", "mount", "-o", "loop,offset=1048576", dev, fs]
    assert _writes(cmd) is True
    assert refuse_evidence_write(cmd)["gate"] == "evidence_write_refused"


def test_umount_and_fuse_exposers_pass(tmp_path):
    dev, fs = _case_mounts(tmp_path)
    assert refuse_evidence_write(["sudo", "umount", fs]) is None
    e01 = str(tmp_path / "case" / "evidence" / "disk.E01")
    assert refuse_evidence_write(
        ["sudo", "ewfmount", "-X", "allow_other", e01, os.path.dirname(dev)]) is None


def test_the_mount_point_changing_is_not_evidence_modified(tmp_path):
    dev, fs = _case_mounts(tmp_path)
    cmd = ["sudo", "mount", "-o", "ro,loop,offset=1048576", dev, fs]
    before = snapshot_evidence_refs(cmd)
    assert before == {}
    os.utime(fs, None)
    (tmp_path / "case" / "mnt" / "img" / "fs" / "Windows").mkdir()  # the volume's root appears
    assert evidence_changes(before, cmd) == []


def test_a_writer_touching_the_same_tree_is_still_caught(tmp_path):
    dev, fs = _case_mounts(tmp_path)
    cmd = ["touch", os.path.join(fs, "marker")]
    before = snapshot_evidence_refs(cmd)
    assert before, "a writer's evidence refs are still snapshotted"
    open(os.path.join(fs, "marker"), "w").close()
    assert any(c["change"] == "created" for c in evidence_changes(before, cmd))
