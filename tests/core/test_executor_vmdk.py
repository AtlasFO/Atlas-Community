"""Executor-level VMDK snapshot warning: any subprocess tool touching a
base VMDK that is shadowed by snapshot deltas gets an advisory field."""
import pytest

from core.executor import run, run_with_output_file


BASE_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=aabbccdd
parentCID=ffffffff
createType="vmfs"
RW 4096 VMFS "HOST-flat.vmdk"
"""

DELTA_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=11223344
parentCID=aabbccdd
createType="vmfsSparse"
parentFileNameHint="HOST.vmdk"
RW 4096 VMFSSPARSE "HOST-000001-delta.vmdk"
"""


@pytest.fixture
def snapshotted_vm(tmp_path):
    (tmp_path / "HOST.vmdk").write_text(BASE_DESCRIPTOR)
    (tmp_path / "HOST-flat.vmdk").write_bytes(b"\x00" * 512)
    (tmp_path / "HOST-000001.vmdk").write_text(DELTA_DESCRIPTOR)
    return tmp_path


def test_run_warns_on_frozen_base(snapshotted_vm):
    r = run(["echo", str(snapshotted_vm / "HOST-flat.vmdk")])
    assert r["success"] is True
    assert "FROZEN" in r["vmdk_snapshot_warning"]
    assert "img_vmdk_chain_info" in r["vmdk_snapshot_warning"]


def test_run_warns_on_base_descriptor(snapshotted_vm):
    r = run(["echo", str(snapshotted_vm / "HOST.vmdk")])
    assert "vmdk_snapshot_warning" in r


def test_run_silent_on_chain_top(snapshotted_vm):
    r = run(["echo", str(snapshotted_vm / "HOST-000001.vmdk")])
    assert "vmdk_snapshot_warning" not in r


def test_run_silent_without_deltas(tmp_path):
    p = tmp_path / "solo.vmdk"
    p.write_text(BASE_DESCRIPTOR)
    r = run(["echo", str(p)])
    assert "vmdk_snapshot_warning" not in r


def test_run_silent_on_non_vmdk(tmp_path):
    r = run(["echo", "hello"])
    assert "vmdk_snapshot_warning" not in r


def test_run_with_output_file_warns(snapshotted_vm, tmp_path):
    out = tmp_path / "analysis" / "out.bin"
    r = run_with_output_file(
        ["echo", str(snapshotted_vm / "HOST-flat.vmdk")],
        output_path=str(out), mode="w")
    assert "vmdk_snapshot_warning" in r
