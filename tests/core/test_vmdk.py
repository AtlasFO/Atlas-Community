"""Tests for core/vmdk.py — VMDK descriptor / snapshot-chain parsing."""
import os
import struct

import pytest

from core.vmdk import (
    analyze_vm_dir,
    parse_descriptor,
    parse_vmsd,
    parse_vmx_disks,
    read_descriptor_text,
    sibling_deltas,
    snapshot_warning,
)


BASE_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=aabbccdd
parentCID=ffffffff
createType="vmfs"

# Extent description
RW 20971520 VMFS "VM01-flat.vmdk"

ddb.adapterType = "lsilogic"
ddb.virtualHWVersion = "17"
"""

DELTA_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=11223344
parentCID=aabbccdd
createType="vmfsSparse"
parentFileNameHint="VM01.vmdk"

# Extent description
RW 20971520 VMFSSPARSE "VM01-000001-delta.vmdk"
"""

DELTA2_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=55667788
parentCID=11223344
createType="vmfsSparse"
parentFileNameHint="VM01-000001.vmdk"

# Extent description
RW 20971520 VMFSSPARSE "VM01-000004-delta.vmdk"
"""

VMSD = """.encoding = "UTF-8"
snapshot.lastUID = "5"
snapshot.numSnapshots = "1"
snapshot0.uid = "1"
snapshot0.filename = "VM01-Snapshot1.vmsn"
snapshot0.displayName = "snapshot-01"
snapshot0.createTimeHigh = "417975"
snapshot0.createTimeLow = "1339467776"
snapshot0.numDisks = "1"
snapshot0.disk0.fileName = "VM01.vmdk"
snapshot0.disk0.node = "scsi0:0"
"""

VMX = """.encoding = "UTF-8"
config.version = "8"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "VM01-000004.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"
ide1:0.present = "TRUE"
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "ubuntu.iso"
sata0:1.present = "FALSE"
sata0:1.fileName = "detached.vmdk"
"""


@pytest.fixture
def vm_dir(tmp_path):
    """A VM directory: base + two snapshot deltas + vmsd + vmx."""
    (tmp_path / "VM01.vmdk").write_text(BASE_DESCRIPTOR)
    (tmp_path / "VM01-flat.vmdk").write_bytes(b"\x00" * 4096)
    (tmp_path / "VM01-000001.vmdk").write_text(DELTA_DESCRIPTOR)
    (tmp_path / "VM01-000001-delta.vmdk").write_bytes(b"\x00" * 1024)
    (tmp_path / "VM01-000004.vmdk").write_text(DELTA2_DESCRIPTOR)
    (tmp_path / "VM01-000004-delta.vmdk").write_bytes(b"\x00" * 1024)
    (tmp_path / "VM01.vmsd").write_text(VMSD)
    (tmp_path / "VM01.vmx").write_text(VMX)
    return tmp_path


class TestParseDescriptor:
    def test_base_has_no_parent(self):
        d = parse_descriptor(BASE_DESCRIPTOR)
        assert d["cid"] == "aabbccdd"
        assert d["has_parent"] is False
        assert d["create_type"] == "vmfs"
        assert d["extents"] == [{
            "access": "RW", "sectors": 20971520, "type": "VMFS",
            "filename": "VM01-flat.vmdk"}]

    def test_delta_parent_hint(self):
        d = parse_descriptor(DELTA_DESCRIPTOR)
        assert d["has_parent"] is True
        assert d["parent_cid"] == "aabbccdd"
        assert d["parent_hint"] == "VM01.vmdk"

    def test_windows_style_parent_hint_basename(self):
        d = parse_descriptor(DELTA_DESCRIPTOR.replace(
            'parentFileNameHint="VM01.vmdk"',
            'parentFileNameHint="C:\\\\VMs\\\\VM01.vmdk"'))
        assert d["parent_hint"] == "VM01.vmdk"


class TestReadDescriptorText:
    def test_plain_text_descriptor(self, tmp_path):
        p = tmp_path / "d.vmdk"
        p.write_text(BASE_DESCRIPTOR)
        assert "# Disk DescriptorFile" in read_descriptor_text(str(p))

    def test_embedded_kdmv_descriptor(self, tmp_path):
        # Hosted sparse extent: KDMV header, descriptor at sector 1, size 1.
        header = b"KDMV" + struct.pack("<IIQQQQ", 1, 3, 819200, 128, 1, 1)
        blob = header.ljust(512, b"\x00") \
            + DELTA_DESCRIPTOR.encode().ljust(512, b"\x00")
        p = tmp_path / "sparse.vmdk"
        p.write_bytes(blob)
        text = read_descriptor_text(str(p))
        assert "parentFileNameHint" in text

    def test_flat_extent_yields_empty(self, tmp_path):
        p = tmp_path / "x-flat.vmdk"
        p.write_bytes(b"\x00" * 2048)
        assert read_descriptor_text(str(p)) == ""

    def test_missing_file_yields_empty(self, tmp_path):
        assert read_descriptor_text(str(tmp_path / "nope.vmdk")) == ""


class TestParseVmsd:
    def test_snapshot_metadata(self):
        snaps = parse_vmsd(VMSD)
        assert len(snaps) == 1
        s = snaps[0]
        assert s["display_name"] == "snapshot-01"
        assert s["disks"] == ["VM01.vmdk"]
        # createTimeHigh/Low combine to microseconds since epoch (UTC).
        micros = (417975 << 32) | 1339467776
        import datetime as dt
        expect = dt.datetime.fromtimestamp(
            micros / 1_000_000, tz=dt.timezone.utc).strftime("%Y-%m-%d")
        assert s["created_utc"].startswith(expect)

    def test_negative_create_time_low_is_masked(self):
        snaps = parse_vmsd(VMSD.replace('"1339467776"', '"-1339467776"'))
        assert snaps[0]["created_utc"]  # parse survives signed low word


class TestParseVmx:
    def test_attached_disks_only(self):
        disks = parse_vmx_disks(VMX)
        assert disks == ["VM01-000004.vmdk"]  # no iso, no present=FALSE


class TestSiblingDeltas:
    def test_base_descriptor_sees_deltas(self, vm_dir):
        deltas = sibling_deltas(str(vm_dir / "VM01.vmdk"))
        assert deltas == ["VM01-000001.vmdk", "VM01-000004.vmdk"]

    def test_flat_extent_sees_deltas(self, vm_dir):
        deltas = sibling_deltas(str(vm_dir / "VM01-flat.vmdk"))
        assert deltas == ["VM01-000001.vmdk", "VM01-000004.vmdk"]

    def test_delta_path_returns_empty(self, vm_dir):
        assert sibling_deltas(str(vm_dir / "VM01-000004.vmdk")) == []

    def test_other_disk_not_matched(self, tmp_path):
        (tmp_path / "a.vmdk").write_text(BASE_DESCRIPTOR)
        (tmp_path / "b-000001.vmdk").write_text(DELTA_DESCRIPTOR)
        assert sibling_deltas(str(tmp_path / "a.vmdk")) == []

    def test_no_deltas_no_warning(self, tmp_path):
        (tmp_path / "solo.vmdk").write_text(BASE_DESCRIPTOR)
        assert snapshot_warning(str(tmp_path / "solo.vmdk")) == ""

    def test_warning_names_chain_tool(self, vm_dir):
        w = snapshot_warning(str(vm_dir / "VM01-flat.vmdk"))
        assert "FROZEN" in w
        assert "img_vmdk_chain_info" in w

    def test_symlinked_file_still_sees_deltas(self, vm_dir, tmp_path):
        # misc.symlink_evidence / network-share staging: a symlink to the
        # flat extent must still resolve to the real dir with the deltas.
        link = tmp_path / "staged-flat.vmdk"
        link.symlink_to(vm_dir / "VM01-flat.vmdk")
        deltas = sibling_deltas(str(link))
        assert deltas == ["VM01-000001.vmdk", "VM01-000004.vmdk"]
        assert "FROZEN" in snapshot_warning(str(link))

    def test_symlinked_vm_dir_resolves(self, vm_dir, tmp_path):
        link_dir = tmp_path / "evidence-vm"
        link_dir.symlink_to(vm_dir, target_is_directory=True)
        r = analyze_vm_dir(str(link_dir))
        assert r["success"] is True
        assert r["analysis_targets"][0]["base_frozen"] is True


class TestAnalyzeVmDir:
    def test_chain_topology(self, vm_dir):
        r = analyze_vm_dir(str(vm_dir))
        assert r["success"] is True
        assert r["chains_top_to_base"] == [[
            "VM01-000004.vmdk",
            "VM01-000001.vmdk",
            "VM01.vmdk",
        ]]

    def test_recommended_target_is_chain_top(self, vm_dir):
        r = analyze_vm_dir(str(vm_dir))
        t = r["analysis_targets"][0]
        assert t["recommended_descriptor"].endswith("VM01-000004.vmdk")
        assert t["base_frozen"] is True
        assert t["vmx_attached"] is True

    def test_warning_mentions_snapshot_date(self, vm_dir):
        r = analyze_vm_dir(str(vm_dir))
        assert len(r["warnings"]) == 1
        assert "snapshot-01" in r["warnings"][0]
        assert "FROZEN" in r["warnings"][0]

    def test_snapshots_parsed(self, vm_dir):
        r = analyze_vm_dir(str(vm_dir))
        assert r["snapshots"][0]["display_name"] == "snapshot-01"
        assert r["vmx_attached_disks"] == ["VM01-000004.vmdk"]

    def test_no_snapshots_no_warnings(self, tmp_path):
        (tmp_path / "clean.vmdk").write_text(BASE_DESCRIPTOR.replace(
            "VM01-flat.vmdk", "clean-flat.vmdk"))
        (tmp_path / "clean-flat.vmdk").write_bytes(b"\x00" * 512)
        r = analyze_vm_dir(str(tmp_path))
        assert r["success"] is True
        assert r["warnings"] == []
        assert r["analysis_targets"][0]["base_frozen"] is False

    def test_broken_chain_warns(self, tmp_path):
        (tmp_path / "orphan-000001.vmdk").write_text(DELTA_DESCRIPTOR)
        r = analyze_vm_dir(str(tmp_path))
        assert any("broken" in w for w in r["warnings"])

    def test_missing_dir_fails_cleanly(self, tmp_path):
        r = analyze_vm_dir(str(tmp_path / "nope"))
        assert r["success"] is False

    def test_cid_fallback_when_hint_missing(self, tmp_path):
        (tmp_path / "VM01.vmdk").write_text(BASE_DESCRIPTOR)
        (tmp_path / "VM01-flat.vmdk").write_bytes(b"\x00" * 512)
        (tmp_path / "VM01-000001.vmdk").write_text(
            DELTA_DESCRIPTOR.replace(
                'parentFileNameHint="VM01.vmdk"\n', ""))
        r = analyze_vm_dir(str(tmp_path))
        assert r["chains_top_to_base"] == [[
            "VM01-000001.vmdk", "VM01.vmdk"]]
