"""Raw views of disk containers (core.raw_views): the pinned format, the
one-node-at-a-time probe and its refusals, the plan's view, fold and
refusal per container, the view's lifecycle, the readers that take a
view for a container, the teardown and the jobs that read a view.

No test here runs qemu: qemu-img's JSON and the daemons are invented.
tests/core/test_raw_views_vm.py runs the real tools where they exist."""
from __future__ import annotations

import errno
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from core import raw_views as rv


# ── invented files ────────────────────────────────────────────────────────

MBR = bytes(446) + bytes([0x80, 0, 0, 0, 0x07, 0, 0, 0]) + struct.pack("<II", 2048, 4096) + bytes(48) + b"\x55\xaa"


def _write(path: Path, head: bytes, size: int = 4096) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(head + bytes(max(0, size - len(head))))
    return str(path)


def _qcow2(path: Path, version: int = 3, incompat: int = 0) -> str:
    head = bytearray(104)
    head[0:4] = b"QFI\xfb"
    head[4:8] = struct.pack(">I", version)
    head[72:80] = struct.pack(">Q", incompat)
    return _write(path, bytes(head))


def _vdi(path: Path, image_type: int = 1) -> str:
    head = bytearray(0x200)
    head[0:40] = b"<<< invented VirtualBox Disk Image >>>\n\x00"
    head[0x40:0x44] = b"\x7f\x10\xda\xbe"
    head[0x4C:0x50] = struct.pack("<I", image_type)
    return _write(path, bytes(head))


def _vhd(path: Path, disk_type: int = 3, current: int = 10_000_384) -> str:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    footer[28:32] = b"vpc "
    footer[48:56] = struct.pack(">Q", current)
    footer[60:64] = struct.pack(">I", disk_type)
    body = bytes(footer) + bytes(4096) + bytes(footer)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return str(path)


def _descriptor(path: Path, extents: list[str], parent_cid: str = "ffffffff", hint: str = "") -> str:
    lines = ["# Disk DescriptorFile", "version=1", "CID=0a1b2c3d", f'parentCID={parent_cid}',
             'createType="monolithicFlat"']
    if hint:
        lines.append(f'parentFileNameHint="{hint}"')
    lines += [f'RW 8192 FLAT "{e}" 0' for e in extents]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


class FakeQemu:
    """qemu-img info by (path, format): every call recorded."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.calls: list[tuple[str, str]] = []

    def __call__(self, path, fmt):
        self.calls.append((path, fmt))
        answer = self.answers.get(path)
        if answer is None:
            return None, f"Could not open '{path}': No such file or directory"
        return answer, ""


# ── the pinned format ─────────────────────────────────────────────────────

def test_the_name_and_the_magic_pin_the_format(tmp_path):
    assert rv.pinned_format(_write(tmp_path / "a.vmdk", b"KDMV"))[0] == "vmdk"
    assert rv.pinned_format(_descriptor(tmp_path / "b.vmdk", ["b-flat.vmdk"]))[0] == "vmdk"
    assert rv.pinned_format(_write(tmp_path / "c-flat.vmdk", MBR)) == ("raw", "")
    assert rv.pinned_format(_vhd(tmp_path / "d.vhd"))[0] == "vpc"
    assert rv.pinned_format(_write(tmp_path / "e.vhd", MBR)) == ("raw", "")
    assert rv.pinned_format(_write(tmp_path / "f.vhdx", b"vhdxfile"))[0] == "vhdx"
    assert rv.pinned_format(_qcow2(tmp_path / "g.qcow2"))[0] == "qcow2"
    assert rv.pinned_format(_qcow2(tmp_path / "h.img"))[0] == "qcow2"
    assert rv.pinned_format(_write(tmp_path / "i.img", MBR)) == ("raw", "")
    assert rv.pinned_format(_vdi(tmp_path / "j.vdi"))[0] == "vdi"


def test_a_name_that_says_raw_is_never_probed_as_a_container(tmp_path):
    # The old format-probing attack: a raw-named file whose first bytes are a
    # QCOW2 header naming a host file.
    assert rv.pinned_format(_qcow2(tmp_path / "CORP-WS01.dd")) == ("raw", "")
    assert rv.pinned_format(_qcow2(tmp_path / "CORP-WS01.raw")) == ("raw", "")
    assert rv.pinned_format(_qcow2(tmp_path / "CORP-WS01.001")) == ("raw", "")


def test_a_header_its_name_does_not_allow_is_refused(tmp_path):
    for name, head in (("a.vhdx", MBR), ("b.vdi", b"QFI\xfb\x00\x00\x00\x03"), ("c.qcow2", MBR)):
        fmt, why = rv.pinned_format(_write(tmp_path / name, head))
        assert fmt == "" and why, name
    fmt, why = rv.pinned_format(_write(tmp_path / "d-delta.vmdk", b"COWD"))
    assert fmt == "" and "COWD" in why


def test_a_qcow_of_version_one_has_no_view(tmp_path):
    c = rv.probe(_qcow2(tmp_path / "old.qcow", version=1))
    assert c["unsupported"] and not c["chain"] and not c["refused"]


# ── the probe ─────────────────────────────────────────────────────────────

def _info(fmt: str, path: str, size: int = 67_108_864, **extra) -> dict:
    return {"format": fmt, "filename": path, "virtual-size": size, "actual-size": 1_048_576, **extra}


def test_a_renamed_sparse_vmdk_is_one_node(tmp_path, monkeypatch):
    top = _write(tmp_path / "ev" / "CORP-WS01.vmdk", b"KDMV")
    q = FakeQemu({top: _info("vmdk", top, **{"format-specific": {"type": "vmdk", "data": {
        "extents": [{"filename": top}]}}})})
    monkeypatch.setattr(rv, "_qemu_info", q)
    c = rv.probe(top)
    assert [n["path"] for n in c["chain"]] == [top] and not c["parts"] and not c["refused"]
    assert q.calls == [(top, "vmdk")]
    assert set(c["files"]) == {top}


def test_split_extents_in_the_folder_are_parts(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    top = _descriptor(ev / "CORP-FS01.vmdk", ["CORP-FS01-s001.vmdk", "CORP-FS01-s002.vmdk"])
    parts = [_write(ev / f"CORP-FS01-s00{i}.vmdk", b"KDMV") for i in (1, 2)]
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("vmdk", top, **{"format-specific": {
        "type": "vmdk", "data": {"extents": [{"filename": p} for p in parts]}}})}))
    c = rv.probe(top)
    assert c["parts"] == sorted(parts) and len(c["chain"]) == 1


@pytest.mark.parametrize("how", ["absolute", "dotdot", "symlink", "fifo"])
def test_an_extent_outside_the_folder_or_not_a_file_is_refused(tmp_path, monkeypatch, how):
    ev = tmp_path / "ev"
    outside = _write(tmp_path / "outside" / "secret.bin", b"invented-secret-2031")
    if how == "absolute":
        name = outside
    elif how == "dotdot":
        name = str(ev / ".." / "outside" / "secret.bin")
    elif how == "symlink":
        (ev).mkdir(parents=True, exist_ok=True)
        os.symlink(outside, ev / "CORP-WS01-flat.vmdk")
        name = str(ev / "CORP-WS01-flat.vmdk")
    else:
        ev.mkdir(parents=True, exist_ok=True)
        os.mkfifo(ev / "CORP-WS01-flat.vmdk")
        name = str(ev / "CORP-WS01-flat.vmdk")
    top = _descriptor(ev / "CORP-WS01.vmdk", [os.path.basename(name)])
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("vmdk", top, **{"format-specific": {
        "type": "vmdk", "data": {"extents": [{"filename": name}]}}})}))
    c = rv.probe(top)
    assert c["refused"].startswith("an extent names") and not c["chain"]
    # The refusal is kept by the image's and its folder's identity only.
    assert set(c["files"]) == {os.path.realpath(top), os.path.realpath(os.path.dirname(top))}


@pytest.mark.parametrize("backing", ["nbd://127.0.0.1:10809/x", "http://203.0.113.7/base.qcow2",
                                     'json:{"driver": "file", "filename": "/etc/hostname"}'])
def test_a_backing_that_is_not_a_plain_file_is_refused_unprobed(tmp_path, monkeypatch, backing):
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    q = FakeQemu({top: _info("qcow2", top, **{"backing-filename": backing, "full-backing-filename": backing})})
    monkeypatch.setattr(rv, "_qemu_info", q)
    c = rv.probe(top)
    assert "not a plain file" in c["refused"]
    assert q.calls == [(top, "qcow2")]     # the backing is never opened


def test_a_backing_chain_in_the_folder_is_probed_node_by_node_pinned(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    base = _qcow2(ev / "base.qcow2")
    top = _qcow2(ev / "CORP-WS01.qcow2")
    q = FakeQemu({
        top: _info("qcow2", top, **{"backing-filename": "base.qcow2", "full-backing-filename": base,
                                   "backing-filename-format": "qcow2"}),
        base: _info("qcow2", base)})
    monkeypatch.setattr(rv, "_qemu_info", q)
    c = rv.probe(top)
    assert [n["path"] for n in c["chain"]] == [top, base]
    assert q.calls == [(top, "qcow2"), (base, "qcow2")]
    graph = rv.node_graph(c["chain"])
    assert graph["file"]["filename"] == top and graph["read-only"] is True
    assert graph["backing"]["file"]["filename"] == base and graph["backing"]["backing"] is None
    assert rv.json_filename(c["chain"]).startswith("json:{")


def test_a_backing_named_raw_by_its_header_but_qcow2_by_its_name_is_refused(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    base = _qcow2(ev / "base.qcow2")
    top = _qcow2(ev / "CORP-WS01.qcow2")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("qcow2", top, **{
        "backing-filename": base, "full-backing-filename": base, "backing-filename-format": "raw"})}))
    assert "header says the backing file is raw" in rv.probe(top)["refused"]


def test_a_backing_chain_that_loops_is_refused(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    a, b = _qcow2(ev / "a.qcow2"), _qcow2(ev / "b.qcow2")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({
        a: _info("qcow2", a, **{"backing-filename": b, "full-backing-filename": b}),
        b: _info("qcow2", b, **{"backing-filename": a, "full-backing-filename": a})}))
    assert rv.probe(a)["refused"] == "its backing chain loops"


def test_a_qcow2_with_an_external_data_file_is_refused_before_qemu(tmp_path, monkeypatch):
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2", incompat=0b100)
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    assert "external data file" in rv.probe(top)["refused"] and q.calls == []


def test_a_vmdk_delta_without_a_parent_hint_is_refused(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    _write(ev / "CORP-WS01-000001-flat.vmdk", MBR)
    top = _descriptor(ev / "CORP-WS01-000001.vmdk", ["CORP-WS01-000001-flat.vmdk"], parent_cid="0a1b2c3d")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("vmdk", top)}))
    assert "without a parent qemu can find" in rv.probe(top)["refused"]


def test_a_vmdk_delta_whose_parent_changed_is_refused(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    _write(ev / "CORP-WS01-flat.vmdk", MBR)
    _write(ev / "CORP-WS01-000001-flat.vmdk", MBR)
    base = _descriptor(ev / "CORP-WS01.vmdk", ["CORP-WS01-flat.vmdk"])           # CID 0a1b2c3d
    top = _descriptor(ev / "CORP-WS01-000001.vmdk", ["CORP-WS01-000001-flat.vmdk"],
                      parent_cid="99999999", hint="CORP-WS01.vmdk")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({
        top: _info("vmdk", top, **{"backing-filename": "CORP-WS01.vmdk", "full-backing-filename": base}),
        base: _info("vmdk", base)}))
    assert "the parent changed after the snapshot" in rv.probe(top)["refused"]


def test_vhd_and_vdi_of_a_differencing_type_are_refused(tmp_path, monkeypatch):
    vhd = _vhd(tmp_path / "ev" / "a.vhd", disk_type=4)
    vdi = _vdi(tmp_path / "ev" / "b.vdi", image_type=4)
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({vhd: _info("vpc", vhd), vdi: _info("vdi", vdi)}))
    assert "VHD of type 4" in rv.probe(vhd)["refused"]
    assert "VDI of type 4" in rv.probe(vdi)["refused"]


def test_a_vhd_qemu_sizes_short_states_the_cut(tmp_path, monkeypatch):
    vhd = _vhd(tmp_path / "ev" / "a.vhd", disk_type=3, current=10_000_384)
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({vhd: _info("vpc", vhd, size=9_830_400)}))
    c = rv.probe(vhd)
    assert not c["refused"] and any("169984 bytes" in n for n in c["notes"])


def test_internal_qcow2_snapshots_are_named(tmp_path, monkeypatch):
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("qcow2", top, snapshots=[
        {"id": "1", "name": "before-update-2031"}, {"id": "2", "name": "after-update-2031"}])}))
    notes = rv.probe(top)["notes"]
    assert any("2 internal snapshot(s) (before-update-2031, after-update-2031)" in n for n in notes)


def test_a_same_size_swap_with_its_time_set_back_is_seen(tmp_path, monkeypatch):
    """A swapped descriptor of the same size whose modify time was set back
    keeps size and mtime; its change time (and inode) cannot be set back."""
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("qcow2", top)}))
    c = rv.probe(top)
    st = os.stat(top)
    swapped = tmp_path / "ev" / "swap.tmp"
    swapped.write_bytes(Path(top).read_bytes()[:-1] + b"\x01")
    os.replace(swapped, top)
    os.utime(top, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert os.path.getsize(top) == st.st_size and not rv.probe_is_current(c)


def test_a_stored_probe_is_current_until_a_file_changes(tmp_path, monkeypatch):
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({top: _info("qcow2", top)}))
    c = rv.probe(top)
    assert rv.probe_is_current(c)
    os.utime(top, (2_000_000_000, 2_000_000_000))
    assert not rv.probe_is_current(c)


# ── the plan ──────────────────────────────────────────────────────────────

@pytest.fixture
def views(monkeypatch):
    monkeypatch.setenv("ATLAS_RAW_VIEWS", "1")
    monkeypatch.setattr(rv, "host_support", lambda: "")


def _entries(root: Path, *paths: str) -> list[dict]:
    from core.mount_plan import _assign_mount_stems, _classify_image
    images = [_classify_image(Path(p)) for p in paths]
    _assign_mount_stems(root, images)
    return images


def test_tops_parts_and_earlier_states_in_the_plan(tmp_path, monkeypatch, views):
    from core.mount_plan import _classify_containers
    ev = Path(os.path.realpath(tmp_path)) / "evidence"
    flat = _write(ev / "CORP-WS01-flat.vmdk", MBR)
    base = _descriptor(ev / "CORP-WS01.vmdk", ["CORP-WS01-flat.vmdk"])
    delta = _write(ev / "CORP-WS01-000001.vmdk", b"KDMV")
    chains = {
        delta: {"format": "vmdk", "chain": [{"path": delta, "format": "vmdk", "virtual_size": 8, "actual_size": 1},
                                            {"path": base, "format": "vmdk", "virtual_size": 8, "actual_size": 1}],
                "parts": [flat], "notes": [], "refused": "", "unsupported": "", "files": {delta: "x"}},
        base: {"format": "vmdk", "chain": [{"path": base, "format": "vmdk", "virtual_size": 8, "actual_size": 1}],
               "parts": [flat], "notes": [], "refused": "", "unsupported": "", "files": {base: "x"}},
        flat: {"format": "raw", "chain": [], "parts": [], "notes": [], "refused": "", "unsupported": "",
               "files": {}},
    }
    monkeypatch.setattr(rv, "probe", lambda p: dict(chains[os.path.realpath(p)]))
    root = Path(os.path.realpath(tmp_path))
    images = _entries(root, delta, base, flat)
    _classify_containers(root, images)
    by = {os.path.basename(i["path"]): i for i in images}
    top, earlier, part = by["CORP-WS01-000001.vmdk"], by["CORP-WS01.vmdk"], by["CORP-WS01-flat.vmdk"]
    assert top["recommended_tool"] == "tsk.mmls" and "raw view mnt/" in top["reason"]
    assert earlier["earlier_state_of"] == "evidence/CORP-WS01-000001.vmdk"
    assert "read on demand, not listed at intake" in earlier["reason"]
    assert part["action"] == "skip" and part["reason"].startswith("part of evidence/CORP-WS01")

    from core import contents_index as ci
    from core.mount_plan import save_mount_plan
    save_mount_plan(root, {"images": images})
    listed = [os.path.basename(i["path"]) for i in ci._disk_images(root)]
    assert listed == ["CORP-WS01-000001.vmdk"]


def test_a_refused_container_is_access_failed_with_the_reason(tmp_path, monkeypatch, views):
    from core.mount_plan import _classify_containers
    top = _qcow2(tmp_path / "evidence" / "CORP-WS01.qcow2")
    monkeypatch.setattr(rv, "probe", lambda p: {"format": "qcow2", "chain": [], "parts": [], "notes": [],
                                                "refused": "Could not open backing file: invented", "files": {}})
    images = _entries(tmp_path, top)
    _classify_containers(tmp_path, images)
    img = images[0]
    assert img["status"] == "access_failed" and img["opened_tool"] == "raw_view"
    assert "Could not open backing file" in img["access_error"] and "not opened" in img["reason"]


def test_without_views_on_this_host_the_route_is_the_copy(tmp_path, monkeypatch):
    from core.mount_plan import _classify_containers
    monkeypatch.setenv("ATLAS_RAW_VIEWS", "1")
    monkeypatch.setattr(rv, "host_support", lambda: "fusermount3 is not installed")
    monkeypatch.setattr(rv, "probe", lambda p: pytest.fail("no probe without views"))
    images = _entries(tmp_path, _write(tmp_path / "evidence" / "a.vmdk", b"KDMV"),
                      _qcow2(tmp_path / "evidence" / "b.qcow2"))
    _classify_containers(tmp_path, images)
    assert "img.vmdk_export_raw" in images[0]["reason"] and "no raw views" in images[0]["reason"]
    assert images[1]["recommended_tool"] == "img.vmdk_export_raw"


def test_with_views_off_the_plan_is_left_as_it_was(tmp_path, monkeypatch):
    from core.mount_plan import _classify_containers
    monkeypatch.setattr(rv, "probe", lambda p: pytest.fail("no probe with views off"))
    images = _entries(tmp_path, _write(tmp_path / "evidence" / "a.vmdk", b"KDMV"))
    before = json.dumps(images, sort_keys=True)
    _classify_containers(tmp_path, images)
    assert json.dumps(images, sort_keys=True) == before


# ── one view's lifecycle ──────────────────────────────────────────────────

def _case_with_container(tmp_path: Path) -> tuple[Path, dict, str]:
    from core.mount_plan import save_mount_plan
    root = tmp_path / "CASE"
    top = _qcow2(root / "evidence" / "CORP-WS01.qcow2")
    entry = {"path": top, "basename": "CORP-WS01.qcow2", "stem": "CORP-WS01", "mount_stem": "CORP-WS01",
             "media_role": "disk", "image_type": "qcow2", "action": "plan_only",
             "container": {"format": "qcow2", "chain": [{"path": top, "format": "qcow2",
                                                         "virtual_size": 8, "actual_size": 1}],
                           "parts": [], "notes": [], "refused": "", "unsupported": "", "files": {}}}
    save_mount_plan(root, {"images": [entry]})
    return root, entry, top


class Host:
    """The view's world: the mount table, the daemons (alive or not), their
    starts, what the started daemon opened, and the re-probe right before a
    start (the stored probe by default: nothing changed)."""

    def __init__(self, monkeypatch, state="absent", daemons=(), start_ok=True, alive=(), container=None,
                 outside=""):
        self.state, self.daemons, self.start_ok = state, list(daemons), start_ok
        self.alive, self.container, self.outside = set(alive), container, outside
        self.started, self.stopped, self.unmounted, self.probed = [], [], [], []
        monkeypatch.setenv("ATLAS_RAW_VIEWS", "1")
        monkeypatch.setattr(rv, "host_support", lambda: "")
        monkeypatch.setattr(rv, "view_state", lambda p: self.state)
        monkeypatch.setattr(rv, "mounted", lambda p: self.state != "absent")
        monkeypatch.setattr(rv, "daemons", lambda proc="/proc": list(self.daemons))
        monkeypatch.setattr(rv, "_alive", lambda pid: pid in self.alive)
        monkeypatch.setattr(rv, "_stop", self._stop)
        monkeypatch.setattr(rv, "fuse_unmount", self._unmount)
        monkeypatch.setattr(rv, "_start", self._start)
        monkeypatch.setattr(rv, "probe", self._probe)
        monkeypatch.setattr(rv, "opened_outside", lambda pid, top_dir, proc="/proc": self.outside)

    def _probe(self, path):
        self.probed.append(path)
        if self.container is not None:
            return json.loads(json.dumps(self.container))
        from core.mount_plan import load_mount_plan
        return dict(load_mount_plan(Path(path).parents[1])["images"][0]["container"])

    def _stop(self, pids):
        self.stopped.extend(pids)
        self.alive -= set(pids)
        self.daemons = [d for d in self.daemons if d["pid"] not in pids]

    def _unmount(self, path):
        self.unmounted.append(path)
        self.state = "absent"
        return True

    def _start(self, chain, view):
        self.started.append((chain[0]["path"], view))
        if not self.start_ok:
            return "Failed to mount FUSE session to export"
        self.state = "live"
        self.alive.add(4242)
        self.daemons = [{"pid": 4242, "mountpoint": rv._norm(view), "source": chain[0]["path"]}]
        return ""


def test_a_live_recorded_view_is_reused_without_a_start(tmp_path, monkeypatch):
    from core.mount_plan import live_raw_view, save_mount_plan
    root, entry, top = _case_with_container(tmp_path)
    view = rv.view_path(root, entry)
    entry["mount_result"] = {"raw_view": view, "raw_view_source": top, "raw_view_pid": 4242}
    save_mount_plan(root, {"images": [entry]})
    host = Host(monkeypatch, state="live", alive={4242})
    assert live_raw_view(root, top) == view
    assert rv.ensure(root, entry) == (view, "") and not host.started and not host.probed


def test_a_recorded_view_whose_daemon_died_is_restarted(tmp_path, monkeypatch):
    # A stat answers "live" from the FUSE attribute cache for about a second
    # after the daemon died; the recorded pid tells.
    from core.mount_plan import live_raw_view, save_mount_plan
    root, entry, top = _case_with_container(tmp_path)
    view = rv.view_path(root, entry)
    entry["mount_result"] = {"raw_view": view, "raw_view_source": top, "raw_view_pid": 999}
    save_mount_plan(root, {"images": [entry]})
    host = Host(monkeypatch, state="live")
    assert live_raw_view(root, top) == ""          # the copy tool does not take it for up either
    assert rv.ensure(root, entry) == (view, "")
    assert host.unmounted == [view] and host.started


def test_a_reused_view_clears_the_failure_an_earlier_start_recorded(tmp_path, monkeypatch):
    from core.mount_plan import load_mount_plan, save_mount_plan
    root, entry, top = _case_with_container(tmp_path)
    view = rv.view_path(root, entry)
    entry.update(status="access_failed", opened_tool="raw_view", access_error="exited -15",
                 mount_result={"raw_view": view, "raw_view_source": top, "raw_view_pid": 4242})
    save_mount_plan(root, {"images": [entry]})
    Host(monkeypatch, state="live", alive={4242})
    assert rv.ensure(root, entry) == (view, "")
    img = load_mount_plan(root)["images"][0]
    assert "status" not in img and "access_error" not in img


def test_one_reader_at_a_time_holds_the_views_lock(tmp_path, monkeypatch):
    import fcntl
    root, entry, top = _case_with_container(tmp_path)
    host = Host(monkeypatch)
    held = []

    def _start(chain, view):
        lock = os.open(os.path.join(os.path.dirname(view), rv.LOCK_NAME), os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(False)
        except BlockingIOError:
            held.append(True)                       # another holder: ensure()'s own lock
        finally:
            os.close(lock)
        return Host._start(host, chain, view)

    monkeypatch.setattr(rv, "_start", _start)
    assert rv.ensure(root, entry)[0] and held == [True]


def test_a_container_that_changed_since_the_plan_is_not_started(tmp_path, monkeypatch):
    from core.mount_plan import load_mount_plan
    root, entry, top = _case_with_container(tmp_path)
    swapped = dict(entry["container"], chain=[], files={top: "x"},
                   refused="an extent names '/elsewhere/secret.bin', which lies outside the image's folder")
    host = Host(monkeypatch, container=swapped)
    view, why = rv.ensure(root, entry)
    assert view is None and "outside the image's folder" in why and not host.started
    img = load_mount_plan(root)["images"][0]
    assert img["container"]["refused"] and img["status"] == "access_failed"


def test_a_clean_change_is_started_only_once_it_is_checked_twice(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    grown = json.loads(json.dumps(entry["container"]))
    grown["chain"][0]["virtual_size"] = 16
    host = Host(monkeypatch, container=grown)
    view, why = rv.ensure(root, entry)
    assert view is None and why.startswith(rv.START_FAILED) and not host.started
    from core.mount_plan import _container_entry
    again = _container_entry(root, top)                # the next read: stored == fresh now
    assert rv.ensure(root, again)[0] and host.started


def test_a_daemon_that_opened_a_file_outside_the_folder_is_stopped(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    host = Host(monkeypatch, outside="/elsewhere/secret.bin")
    view, why = rv.ensure(root, entry)
    assert view is None and "opened /elsewhere/secret.bin" in why
    assert 4242 in host.stopped and host.unmounted


def test_opened_outside_reads_what_the_daemon_holds(tmp_path):
    folder = tmp_path / "ev"
    inside = _write(folder / "CORP-WS01.qcow2", b"QFI\xfb")
    outside = _write(tmp_path / "elsewhere" / "secret.bin", b"x")
    fd = tmp_path / "proc" / "123" / "fd"
    fd.mkdir(parents=True)
    os.symlink(inside, fd / "3")
    os.symlink("/dev/null", fd / "4")
    assert rv.opened_outside(123, str(folder), proc=str(tmp_path / "proc")) == ""
    os.symlink(outside, fd / "5")
    assert rv.opened_outside(123, str(folder), proc=str(tmp_path / "proc")) == outside


def test_opened_outside_counts_a_disk_held_outside_the_folder(tmp_path, monkeypatch):
    import stat as st
    folder = tmp_path / "ev"
    folder.mkdir()
    fd = tmp_path / "proc" / "123" / "fd"
    fd.mkdir(parents=True)
    os.symlink("/dev/invented-disk", fd / "7")
    real_stat = os.stat

    def _stat(path, *a, **k):
        if str(path).endswith("/fd/7"):
            return os.stat_result((st.S_IFBLK | 0o660, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return real_stat(path, *a, **k)

    monkeypatch.setattr(rv.os, "stat", _stat)
    assert rv.opened_outside(123, str(folder), proc=str(tmp_path / "proc")) == "/dev/invented-disk"


def test_an_absent_view_is_started_and_recorded(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    host = Host(monkeypatch)
    view, why = rv.ensure(root, entry)
    assert view == str(root / "mnt" / "CORP-WS01" / "disk") and why == "" and host.started
    assert os.path.isfile(view)                      # the mountpoint file
    from core.mount_plan import load_mount_plan
    mr = load_mount_plan(root)["images"][0]["mount_result"]
    assert mr["raw_view"] == view and mr["raw_view_source"] == top and mr["raw_view_pid"] == 4242


def test_a_stale_view_is_unmounted_before_its_file_is_touched(tmp_path, monkeypatch):
    # After SIGKILL of its daemon the view answers every stat with ENOTCONN;
    # only the mount table knows it, and opening it to create it would fail.
    root, entry, top = _case_with_container(tmp_path)
    host = Host(monkeypatch, state="stale")
    real_open = open
    view = rv.view_path(root, entry)

    def _open(path, *a, **k):
        if str(path) == view and host.state == "stale":
            raise OSError(errno.ENOTCONN, "Transport endpoint is not connected")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", _open)
    assert rv.ensure(root, entry) == (view, "")
    assert host.unmounted == [view] and host.started


def test_a_daemon_serving_another_file_at_the_view_is_stopped(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    view = rv.view_path(root, entry)
    other = {"pid": 77, "mountpoint": rv._norm(view), "source": "/elsewhere/CORP-DC01.qcow2"}
    host = Host(monkeypatch, state="live", daemons=[other])
    assert rv.ensure(root, entry) == (view, "")
    assert 77 in host.stopped and host.started


def test_a_lost_start_race_reuses_the_winners_view(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    view = rv.view_path(root, entry)
    host = Host(monkeypatch, start_ok=False)

    def _start(chain, v):
        host.state = "live"
        host.daemons = [{"pid": 5150, "mountpoint": rv._norm(v), "source": top}]
        return "Failed to mount FUSE session to export"

    monkeypatch.setattr(rv, "_start", _start)
    assert rv.ensure(root, entry) == (view, "")


def test_a_failed_start_is_recorded_and_returned_never_raised(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    Host(monkeypatch, start_ok=False)
    view, why = rv.ensure(root, entry)
    assert view is None and "Failed to mount FUSE session" in why
    from core.mount_plan import load_mount_plan
    img = load_mount_plan(root)["images"][0]
    assert img["status"] == "access_failed" and "Failed to mount" in img["mount_result"]["view_error"]


def test_a_container_without_a_chain_has_no_view(tmp_path, monkeypatch):
    root, entry, top = _case_with_container(tmp_path)
    entry["container"] = {"format": "vpc", "chain": [], "refused": "it is a VHD of type 4"}
    host = Host(monkeypatch)
    assert rv.ensure(root, entry) == (None, "it is a VHD of type 4") and not host.started


# ── the readers ───────────────────────────────────────────────────────────

def test_a_view_path_a_result_named_resolves_to_its_container(tmp_path, monkeypatch):
    from core.mount_plan import raw_device_for
    root, entry, top = _case_with_container(tmp_path)
    Host(monkeypatch)
    view = str(root / "mnt" / "CORP-WS01" / "disk")
    assert not os.path.exists(view)                  # stale or gone: exists says False
    assert raw_device_for(root, view) == (view, "")
    assert raw_device_for(root, top) == (view, "")
    assert raw_device_for(root, str(root / "evidence" / "other.dd")) == (None, "")


def test_the_index_and_tsk_read_the_view_and_plaso_too(tmp_path, monkeypatch):
    from core import contents_index as ci
    from tools import plaso, sleuthkit
    root, entry, top = _case_with_container(tmp_path)
    Host(monkeypatch)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(root))
    view = str(root / "mnt" / "CORP-WS01" / "disk")
    assert ci._readable(root, top) == (view, "")
    assert sleuthkit._tsk_readable(top) == (view, None)
    assert plaso._targeted_cmd(top, "/tmp/x.plaso", "WindowsEventLogs")[-1] == view
    assert plaso._timeline_cmd(str(root / "evidence" / "CORP-WS01.E01"), "/tmp/x.plaso")[-1].endswith(".E01")


def test_a_container_without_a_view_is_refused_with_the_reason(tmp_path, monkeypatch):
    from core import contents_index as ci
    from tools import sleuthkit
    root, entry, top = _case_with_container(tmp_path)
    Host(monkeypatch, start_ok=False)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(root))
    readable, why = ci._readable(root, top)
    assert readable == "" and "Failed to mount FUSE session" in why
    _img, refusal = sleuthkit._tsk_readable(top)
    assert refusal["gate"] == "image_format" and "Failed to mount FUSE session" in refusal["error"]


def test_a_failed_view_start_inside_a_tsk_call_leaves_one_failed_attempt(tmp_path, monkeypatch):
    """The view start is no trace entry: the TSK tool's own refusal is the
    record, a failed attempt on the image, and nothing reads as a read."""
    from core import middleware
    from core.execution_log import ExecutionLog
    from tools import sleuthkit
    root, entry, top = _case_with_container(tmp_path)
    Host(monkeypatch, start_ok=False)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(root))
    log = ExecutionLog()
    log.configure("CASE", str(tmp_path / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    before = len(log._entries)
    fls = getattr(sleuthkit.tsk_fls, "fn", sleuthkit.tsk_fls)
    result = fls(top)
    middleware._trace_success_baseline("tsk_tsk_fls", 0.1, before, result=result, args={"image": top})
    added = log._entries[before:]
    assert [e["type"] for e in added] == ["tool_call"]
    assert added[0]["cmd"] == "<py>:tsk_tsk_fls" and added[0]["success"] is False
    assert top in json.dumps(added[0])                # the attempt names the image
    assert not any(e.get("success") for e in added)


def test_each_cause_of_a_missing_view_has_its_own_next_step():
    host = rv.read_refusal("evidence/a.vmdk", f"{rv.NO_HOST_VIEWS}: fusermount3 is not installed")
    start = rv.read_refusal("evidence/a.vmdk", f"{rv.START_FAILED}: Failed to mount FUSE session")
    refused = rv.read_refusal("evidence/a.vhd", "it is a VHD of type 4 (differencing or other)")
    assert "img.vmdk_export_raw copies it" in host and "Run the read again" not in host
    assert "Run the read again" in start
    assert "a copy would read it the same way" in refused and "No tsk.* tool reads it" in refused
    assert "Next: try plaso" in refused
    assert "when this host" not in host + start + refused     # no condition left for the reader


# ── the index keeps only a settled failure ────────────────────────────────

def _index_case(tmp_path, monkeypatch, listing: dict, readable: str):
    from core import contents_index as ci
    calls = []

    def _list(root, image, readable=None, reason="", progress=None):
        calls.append(image)
        return dict(listing, call_ids=[1])

    monkeypatch.setattr(ci, "_list_image", _list)
    monkeypatch.setattr(ci, "_readable", lambda root, image: (readable, ""))
    monkeypatch.setattr(ci, "_trace_call_ids", lambda root: {1})
    monkeypatch.setattr(ci, "_source_fp", lambda root, image: "fp-1")
    return calls


@pytest.mark.parametrize("reason,settled,kept", [
    ("no filesystem The Sleuth Kit can open", True, True),
    ("the raw view stopped answering (its daemon is gone)", False, False),
    ("listing timed out", False, False),
])
def test_a_failed_listing_is_kept_only_when_settled(tmp_path, monkeypatch, reason, settled, kept):
    from core import contents_index as ci
    from core.mount_plan import save_mount_plan
    root = tmp_path / "CASE"
    img = _write(root / "evidence" / "CORP-WS01.dd", MBR)
    save_mount_plan(root, {"images": [{"path": img, "media_role": "disk", "action": "plan_only"}]})
    listing = {"rows": [], "listed": False, "complete": False, "reason": reason, "volumes": [],
               "settled": settled}
    calls = _index_case(tmp_path, monkeypatch, listing, img)
    con = ci._connect(root, create=True)
    out = {"listed": [], "failed": [], "kept": []}
    ci._build_images(con, root, out)
    ci._build_images(con, root, out)
    assert len(calls) == (1 if kept else 2)


def test_a_failed_listing_of_the_container_is_listed_again_through_its_view(tmp_path, monkeypatch):
    from core import contents_index as ci
    from core.mount_plan import save_mount_plan
    root = tmp_path / "CASE"
    img = _write(root / "evidence" / "CORP-WS01.vmdk", b"KDMV")
    save_mount_plan(root, {"images": [{"path": img, "media_role": "disk", "action": "plan_only"}]})
    listing = {"rows": [], "listed": False, "complete": False, "volumes": [], "settled": True,
               "reason": "no filesystem The Sleuth Kit can open"}
    calls = _index_case(tmp_path, monkeypatch, listing, img)
    con = ci._connect(root, create=True)
    out = {"listed": [], "failed": [], "kept": []}
    ci._build_images(con, root, out)                 # read through the container: settled there
    monkeypatch.setattr(ci, "_readable", lambda root, image: (str(root / "mnt" / "x" / "disk"), ""))
    ci._build_images(con, root, out)                 # a view now: listed again
    assert len(calls) == 2


# ── teardown ──────────────────────────────────────────────────────────────

def _proc(tmp_path: Path, pid: int, argv: list[str]) -> None:
    d = tmp_path / "proc" / str(pid)
    d.mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")


def test_daemons_are_found_by_their_command_line(tmp_path):
    view = str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")
    export = json.dumps({"type": "fuse", "mountpoint": view, "writable": False})
    block = json.dumps({"driver": "qcow2", "file": {"driver": "file", "filename": "/ev/CORP-WS01.qcow2"}})
    _proc(tmp_path, 300, ["/usr/bin/qemu-storage-daemon", "--daemonize", "--blockdev", block, "--export", export])
    _proc(tmp_path, 301, ["/usr/bin/sleep", "100"])
    _proc(tmp_path, 302, ["/usr/bin/qemu-storage-daemon", "--blockdev", block, "--export",
                          f"type=fuse,id=w,node-name=top,mountpoint={view}2,writable=on"])
    found = rv.daemons(str(tmp_path / "proc"))
    assert found == [{"pid": 300, "mountpoint": rv._norm(view), "source": "/ev/CORP-WS01.qcow2", "writable": False},
                     {"pid": 302, "mountpoint": rv._norm(view + "2"), "source": "/ev/CORP-WS01.qcow2",
                      "writable": "on"}]


def test_stop_under_stops_the_case_daemons_by_command_line_and_spares(tmp_path, monkeypatch):
    case = tmp_path / "CASE"
    a, b = str(case / "mnt" / "a" / "disk"), str(case / "mnt" / "b" / "disk")
    other = str(tmp_path / "OTHER" / "mnt" / "c" / "disk")
    monkeypatch.setattr(rv, "daemons", lambda proc="/proc": [
        {"pid": 1, "mountpoint": rv._norm(a), "source": ""}, {"pid": 2, "mountpoint": rv._norm(b), "source": ""},
        {"pid": 3, "mountpoint": rv._norm(other), "source": ""}])
    stopped = []
    monkeypatch.setattr(rv, "_stop", stopped.extend)
    assert rv.stop_under(str(case), spare={b}) == [1] and stopped == [1]


def test_teardown_unmounts_own_fuse_without_root_and_keeps_a_jobs_view(tmp_path, monkeypatch):
    from core import mounts
    base = os.path.realpath(str(tmp_path / "CASE"))
    view, kept = f"{base}/mnt/a/disk", f"{base}/mnt/b/disk"
    uid = os.getuid()
    proc = tmp_path / "proc_mounts"
    proc.write_text("".join(f"/dev/fuse {mp} fuse rw,user_id={uid},group_id={uid} 0 0\n" for mp in (view, kept)))
    stops, unmounts = [], []
    monkeypatch.setattr(rv, "stop_under", lambda path, spare=frozenset(): stops.append((path, set(spare))))

    def _fuse(mp):
        unmounts.append(mp)
        proc.write_text(f"/dev/fuse {kept} fuse rw,user_id={uid},group_id={uid} 0 0\n")
        return True

    monkeypatch.setattr(rv, "fuse_unmount", _fuse)
    monkeypatch.setattr("core.executor.run", lambda *a, **k: pytest.fail("no sudo umount for an own FUSE mount"))
    result = mounts.unmount_all_under(base, str(proc), spare={kept})
    assert unmounts == [view] and result["unmounted"] == [view] and stops == [(base, {kept})]


# ── root and a user's FUSE mount ──────────────────────────────────────────

def test_a_root_tool_on_a_view_is_refused_before_sudo(tmp_path, monkeypatch):
    view = str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")
    uid = os.getuid()
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(rv._norm(view), "fuse", ["rw", f"user_id={uid}"])])
    refusal = rv.sudo_refusal(["bulk_extractor", "-o", "/tmp/out", view])
    assert refusal["gate"] == "sudo_reads_user_fuse" and "tsk.*" in refusal["error"]
    assert rv.sudo_refusal(["umount", view]) is None
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(rv._norm(view), "fuse", ["rw", f"user_id={uid}",
                                                                              "allow_other"])])
    assert rv.sudo_refusal(["bulk_extractor", view]) is None

    from core import executor
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(rv._norm(view), "fuse", ["rw", f"user_id={uid}"])])
    monkeypatch.setattr(executor, "_log_tool", lambda r: None)
    monkeypatch.setattr(executor, "_sudo_auth_preflight", lambda cmd: pytest.fail("sudo is never asked"))
    res = executor.run(["foremost", "-i", view, "-o", str(tmp_path / "out")], needs_sudo=True)
    assert res["success"] is False and res["gate"] == "sudo_reads_user_fuse"


# ── background jobs ───────────────────────────────────────────────────────

def test_a_job_records_the_views_it_reads_and_the_teardown_spares_them(tmp_path, monkeypatch):
    case = tmp_path / "CASE"
    view = str(case / "mnt" / "CORP-WS01" / "disk")
    monkeypatch.setattr(rv, "daemons", lambda proc="/proc": [{"pid": 4242, "mountpoint": rv._norm(view),
                                                              "source": "x"}])
    reads = rv.views_named(case, ["log2timeline.py", "--storage-file", "/tmp/x.plaso", view,
                                  json.dumps({"items": [{"device": view}]})])
    assert reads == {"mnt_paths": [view], "raw_views": [{"path": view, "pid": 4242}]}

    job_dir = case / "analysis" / "jobs" / "20310101T000000_plaso_targeted_1_1"
    job_dir.mkdir(parents=True)
    runner = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "tools.jobs_runner",
                               str(job_dir)])
    try:
        (job_dir / "meta.json").write_text(json.dumps({"supervisor_pid": runner.pid, **reads}))
        assert rv.held_by_running_jobs(case) == {view}
        (job_dir / "exit_code").write_text("0")
        assert rv.held_by_running_jobs(case) == set()
    finally:
        runner.kill()
        runner.wait()


def test_a_job_whose_view_lost_its_daemon_fails(tmp_path, monkeypatch):
    view = str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")
    monkeypatch.setattr(rv, "daemons", lambda proc="/proc": [{"pid": 9, "mountpoint": rv._norm(view), "source": ""}])
    monkeypatch.setattr(rv, "view_state", lambda p: "live")
    assert rv.view_lost({"raw_views": [{"path": view, "pid": 9}]}) == ""
    assert "stopped while it ran" in rv.view_lost({"raw_views": [{"path": view, "pid": 8}]})

    from tools import jobs_runner
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "meta.json").write_text(json.dumps({
        "argv": [sys.executable, "-c", "pass"], "needs_sudo": False, "params": {},
        "raw_views": [{"path": view, "pid": 8}]}))
    jobs_runner.main(str(job_dir))
    meta = json.loads((job_dir / "meta.json").read_text())
    assert (job_dir / "exit_code").read_text() == "1" and "stopped while it ran" in meta["view_lost"]


# ── the copy fallback ─────────────────────────────────────────────────────

def test_the_copy_is_refused_while_a_view_serves_the_disk(tmp_path, monkeypatch):
    from tools import imaging
    root, entry, top = _case_with_container(tmp_path)
    monkeypatch.setattr(rv, "probe", lambda p: dict(entry["container"]))
    monkeypatch.setattr(imaging, "_open_case_dir", lambda: str(root))
    monkeypatch.setattr("core.mount_plan.live_raw_view", lambda case, p: str(root / "mnt" / "CORP-WS01" / "disk"))
    fn = getattr(imaging.vmdk_export_raw, "fn", imaging.vmdk_export_raw)
    res = fn(top, str(root / "analysis" / "exports" / "CORP-WS01.raw"))
    assert res["gate"] == "raw_view_live" and "force_reexport=True" in res["error"]


def test_the_copy_keeps_the_floor_and_reads_the_checked_graph(tmp_path, monkeypatch):
    from tools import imaging
    root, entry, top = _case_with_container(tmp_path)
    monkeypatch.setattr(rv, "probe", lambda p: dict(entry["container"]))
    monkeypatch.setattr(imaging, "_open_case_dir", lambda: str(root))
    monkeypatch.setattr("core.mount_plan.live_raw_view", lambda case, p: "")
    monkeypatch.setattr(imaging, "_sparse_files_supported", lambda d: False)
    ran = []
    monkeypatch.setattr(imaging, "run", lambda cmd, **k: ran.append(cmd) or {"success": True})
    monkeypatch.setattr("core.mount_plan.register_exported_image", lambda *a, **k: None)
    total = 10 * 1024 ** 3
    monkeypatch.setattr(imaging.shutil, "disk_usage", lambda p: type("U", (), {"free": 1024 ** 3 + 100,
                                                                              "total": total})())
    monkeypatch.setattr("core.diskguard.check", lambda p: {"required_bytes": 1024 ** 3})
    fn = getattr(imaging.vmdk_export_raw, "fn", imaging.vmdk_export_raw)
    out = str(root / "analysis" / "exports" / "CORP-WS01.raw")
    res = fn(top, out)                               # 8 bytes needed + a 1 GiB floor: fits
    assert ran and ran[0][:4] == ["qemu-img", "convert", "-O", "raw"] and ran[0][4].startswith("json:{")
    monkeypatch.setattr("core.diskguard.check", lambda p: {"required_bytes": 1024 ** 3 + 1000})
    res = fn(top, out, force_reexport=True)
    assert res["success"] is False and "the case volume keeps free" in res["error"]


def test_no_case_identifiers_are_baked_into_the_module():
    """The module knows formats, qemu and FUSE; no host, user or file of any
    case reaches its logic."""
    src = Path("core/raw_views.py").read_text()
    code = re.sub(r'"""(?:.|\n)*?"""', "", src)
    code = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("#")).lower()
    for token in ("corp-ws01", "corp-fs01", "corp-dc01", "jane.doe", "203.0.113", "2031"):
        assert token not in code, token


# ── review fixes: no views on the host, the VHD copy qemu reads, root bypasses ──

def test_on_a_host_without_views_the_readers_name_the_copy(tmp_path, monkeypatch):
    from core import contents_index as ci
    from core.mount_plan import _classify_containers, save_mount_plan
    from tools import sleuthkit
    monkeypatch.setenv("ATLAS_RAW_VIEWS", "1")
    monkeypatch.setattr(rv, "host_support", lambda: "fusermount3 is not installed")
    root = Path(os.path.realpath(tmp_path)) / "CASE"
    vmdk = _write(root / "evidence" / "CORP-WS01.vmdk", b"KDMV")
    vhdx = _write(root / "evidence" / "CORP-WS02.vhdx", b"vhdxfile")
    images = _entries(root, vmdk, vhdx)
    _classify_containers(root, images)
    save_mount_plan(root, {"images": images})
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(root))
    _img, refusal = sleuthkit._tsk_readable(vmdk)
    assert refusal and "img.vmdk_export_raw copies it" in refusal["error"]
    readable, why = ci._readable(root, vhdx)
    assert readable == "" and why.startswith(rv.NO_HOST_VIEWS)


def test_the_vhd_type_is_checked_in_the_copy_qemu_reads(tmp_path, monkeypatch):
    path = tmp_path / "ev" / "CORP-WS01.vhd"
    _vhd(path, disk_type=3)
    data = bytearray(path.read_bytes())
    data[60:64] = struct.pack(">I", 4)               # the start copy says differencing, the end dynamic
    path.write_bytes(bytes(data))
    monkeypatch.setattr(rv, "_qemu_info", FakeQemu({str(path): _info("vpc", str(path))}))
    assert "VHD of type 4" in rv.probe(str(path))["refused"]


def test_root_is_refused_on_a_view_however_the_command_names_it(tmp_path, monkeypatch):
    view = str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")
    os.makedirs(os.path.dirname(view))
    Path(view).write_bytes(b"")
    uid = os.getuid()
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(os.path.realpath(view), "fuse", ["rw", f"user_id={uid}"])])
    link = tmp_path / "link-to-view"
    os.symlink(view, link)
    for argv, cwd in ((["foremost", "-i", str(link)], None),
                      (["foremost", f"-i{view}"], None),
                      (["sh", "-c", f"cat {view} > /dev/null"], None),
                      (["foremost", "-i", "mnt/CORP-WS01/disk"], str(tmp_path / "CASE"))):
        assert rv.sudo_refusal(argv, cwd), argv


def test_a_refused_probe_is_kept_until_the_image_or_its_folder_changes(tmp_path, monkeypatch):
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    q = FakeQemu({top: _info("qcow2", top, **{"backing-filename": "nbd://127.0.0.1:10809/x"})})
    monkeypatch.setattr(rv, "_qemu_info", q)
    c = rv.probe(top)
    assert c["refused"] and rv.probe_is_current(c)
    _write(tmp_path / "ev" / "CORP-WS01-new.qcow2", b"QFI\xfb")    # a file added beside it
    assert not rv.probe_is_current(c)


# ── review fixes: the guards no other test would miss ─────────────────────

def test_probes_and_starts_never_run_through_the_executor(tmp_path, monkeypatch):
    """A view's probe and start are infrastructure, never an executor entry
    that the ledger could read as a read of the image."""
    def _executor(*a, **k):
        raise AssertionError("core.executor.run called")

    monkeypatch.setattr("core.executor.run", _executor)
    calls = []

    def _sub(argv, **k):
        calls.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"format": "qcow2"}), stderr="")

    monkeypatch.setattr(rv.subprocess, "run", _sub)
    top = _qcow2(tmp_path / "ev" / "CORP-WS01.qcow2")
    assert rv._qemu_info(top, "qcow2")[0] == {"format": "qcow2"}
    assert rv._start([{"path": top, "format": "qcow2"}], str(tmp_path / "mnt" / "x" / "disk")) == ""
    assert {"qemu-storage-daemon"} <= set(calls)


def test_the_run_end_teardown_keeps_what_running_jobs_read(tmp_path, monkeypatch):
    from agent import cli
    held = {str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")}
    monkeypatch.setattr("core.raw_views.held_by_running_jobs", lambda case: set(held))
    seen = {}

    def _unmount(path, proc_mounts=None, spare=frozenset()):
        seen.update(path=path, spare=set(spare))
        return {"unmounted": [], "failed": [], "remaining": []}

    monkeypatch.setattr("core.mounts.unmount_all_under", _unmount)
    ui = type("UI", (), {"info": lambda self, m: None, "warn": lambda self, m: None})()
    cli._teardown_local_mounts(tmp_path / "CASE", ui)
    assert seen == {"path": str(tmp_path / "CASE"), "spare": held}


def test_a_root_job_on_a_view_is_refused_at_its_start(tmp_path, monkeypatch):
    from tools import jobs
    view = str(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk")
    uid = os.getuid()
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(rv._norm(view), "fuse", ["rw", f"user_id={uid}"])])
    monkeypatch.setattr(jobs, "_jobs_root", lambda: pytest.fail("refused before any job dir"))
    res = jobs._start_job("bulk_extractor", {"image_path": view, "output_dir": str(tmp_path / "out")})
    assert res["success"] is False and res["gate"] == "sudo_reads_user_fuse"


def test_a_read_through_the_view_opens_its_image_and_nothing_like_it_does(tmp_path):
    from core.evidence_access import record_open_from_tool
    from core.mount_plan import load_mount_plan, save_mount_plan
    root = tmp_path / "CASE"
    a = _qcow2(root / "evidence" / "CORP-WS01.qcow2")
    b = _qcow2(root / "evidence" / "CORP-WS02.qcow2")
    save_mount_plan(root, {"images": [
        {"path": a, "basename": "CORP-WS01.qcow2", "stem": "CORP-WS01", "mount_stem": "CORP-WS01",
         "media_role": "disk", "access_gated": True, "action": "plan_only"},
        {"path": b, "basename": "CORP-WS02.qcow2", "stem": "CORP-WS02", "mount_stem": "CORP-WS02",
         "media_role": "disk", "access_gated": True, "action": "plan_only"}]})
    for near in ("mnt/CORP-WS01/disk-x", "mnt/CORP-WS01/diskette"):
        record_open_from_tool(root, tool_name="tsk_fls", cmd_or_args=json.dumps({"image": near}), success=True)
        assert not any(i.get("status") == "opened" for i in load_mount_plan(root)["images"]), near
    record_open_from_tool(root, tool_name="tsk_fls", cmd_or_args=json.dumps({"image": "mnt/CORP-WS01/disk"}),
                          success=True)
    status = {i["basename"]: i.get("status") for i in load_mount_plan(root)["images"]}
    assert status == {"CORP-WS01.qcow2": "opened", "CORP-WS02.qcow2": None}


# ── the plan written by several processes at once ────────────────────────

def test_processes_recording_views_at_once_keep_every_entry(tmp_path):
    """Readers in several processes record their views and failures on the
    plan at once (a run, a dashboard chat, the copy tool). Every entry and
    every process's last write must survive: no torn plan read and saved
    back empty, no update saved over by a writer that never loaded it."""
    import sys
    from core.mount_plan import load_mount_plan, save_mount_plan
    root = tmp_path / "CASE"
    paths = [_qcow2(root / "evidence" / f"CORP-WS{n:02d}.qcow2") for n in range(1, 7)]
    save_mount_plan(root, {"images": [{"path": p, "basename": Path(p).name, "media_role": "disk",
                                       "action": "plan_only"} for p in paths]})
    repo = Path(__file__).resolve().parents[2]
    child = (
        "import sys; sys.path.insert(0, sys.argv[1]); from core import raw_views as rv\n"
        "root, path = sys.argv[2], sys.argv[3]\n"
        "view = path + '.view'\n"
        "for n in range(40):\n"
        "    rv._record(root, {'path': path}, view, path, 1000 + n)\n"
        "    rv._fail(root, {'path': path}, f'invented failure {n}')\n"
        "rv._record(root, {'path': path}, view, path, 999999)\n")
    procs = [subprocess.Popen([sys.executable, "-c", child, str(repo), str(root), p],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for p in paths]
    errors = [p.communicate(timeout=240)[1] for p in procs]
    assert all(p.returncode == 0 for p in procs), errors
    images = {i["path"]: i for i in load_mount_plan(root)["images"]}
    assert sorted(images) == sorted(paths)
    assert all(images[p]["mount_result"]["raw_view_pid"] == 999999 for p in paths), \
        {Path(p).name: images[p].get("mount_result") for p in paths}


# ── the evidence guard and a raw view's clock ─────────────────────────────

def _served(monkeypatch, view: Path, source: str, *, writable=False, daemons: int = 1, mounts: int = 1):
    """``view`` as qemu-storage-daemon pid 4242 of this user serves it."""
    mp = rv._norm(str(view))
    monkeypatch.setattr(rv, "daemons", lambda proc="/proc": [
        {"pid": 4242, "mountpoint": mp, "source": source, "writable": writable}] * daemons)
    monkeypatch.setattr(rv, "_proc_mounts", lambda: [(mp, "fuse", ["rw", "nosuid", "nodev"])] * mounts)
    monkeypatch.setattr(rv, "held_files", lambda pid, proc="/proc": [source] if pid == 4242 else [])


def test_the_evidence_guard_compares_a_live_views_source_in_its_place(tmp_path, monkeypatch):
    """qemu's FUSE export reports the current time as a view's mtime on every
    stat; the guard's before/after lstat would call every read through a view
    an evidence modification. A live read-only view is replaced by the files
    its daemon reads; the lock beside it and anything else is compared."""
    from core import evidence_guard
    root = tmp_path / "CASE"
    source = _write(root / "evidence" / "CORP-WS01.qcow2", b"QFI\xfb", size=16)
    view = root / "mnt" / "CORP-WS01" / "disk"
    lock = view.with_name(rv.LOCK_NAME)
    other = root / "mnt" / "CORP-WS01" / "notes.txt"
    for f in (view, lock, other):
        _write(f, b"x", size=16)
    _served(monkeypatch, view, source)
    cmd = ["fls", "-r", "-o", "2048", str(view)]
    before = evidence_guard.snapshot_evidence_refs(cmd)
    assert str(view) not in before and {source, str(lock), str(other)} <= set(before)
    os.utime(view, ns=(1, 2))                         # the daemon's clock moves on
    assert evidence_guard.evidence_changes(before, cmd) == []
    for f in (source, str(lock), str(other)):        # the evidence behind it, the lock, a file beside it
        os.utime(f, ns=(3, 4))
        assert evidence_guard.evidence_changes(before, cmd) == [{"path": f, "change": "modified"}], f
        before = evidence_guard.snapshot_evidence_refs(cmd)


@pytest.mark.parametrize("served", [
    {"writable": True}, {"writable": None}, {"writable": "off"},   # a writable export, or not said false
    {"daemons": 2}, {"daemons": 0},                                # two daemons there, or none
    {"mounts": 2}, {"mounts": 0},                                  # a mount on top, or not mounted
])
def test_a_view_not_served_read_only_by_one_daemon_is_compared_as_itself(tmp_path, monkeypatch, served):
    view = _write(tmp_path / "CASE" / "mnt" / "CORP-WS01" / "disk", b"x", size=16)
    _served(monkeypatch, Path(view), str(tmp_path / "CASE" / "evidence" / "CORP-WS01.qcow2"), **served)
    assert rv.view_sources(view) is None


def test_only_a_disk_under_mnt_can_be_a_view(tmp_path, monkeypatch):
    elsewhere = tmp_path / "CASE" / "evidence" / "CORP-WS01" / "disk"
    _served(monkeypatch, elsewhere, "/x")
    assert rv.view_sources(str(elsewhere)) is None
    lock = tmp_path / "CASE" / "mnt" / "CORP-WS01" / rv.LOCK_NAME
    _served(monkeypatch, lock, "/x")
    assert rv.view_sources(str(lock)) is None


def test_a_path_the_second_snapshot_misses_is_read_again(tmp_path, monkeypatch):
    """A view that stops mid-command drops its sources from the second
    snapshot: unchanged files are not reported removed."""
    from core import evidence_guard
    root = tmp_path / "CASE"
    source = _write(root / "evidence" / "CORP-WS01.qcow2", b"QFI\xfb", size=16)
    view = _write(root / "mnt" / "CORP-WS01" / "disk", b"x", size=16)
    _served(monkeypatch, Path(view), source)
    cmd = ["fls", view]
    before = evidence_guard.snapshot_evidence_refs(cmd)
    monkeypatch.setattr(rv, "daemons", lambda proc="/proc": [])
    changes = evidence_guard.evidence_changes(before, cmd)
    assert {"path": source, "change": "removed"} not in changes
    assert [c["path"] for c in changes] == [view]     # the view itself is new to the comparison


def test_held_files_are_the_regular_files_a_process_holds(tmp_path):
    held = _write(tmp_path / "ev" / "CORP-WS01.qcow2", b"QFI\xfb", size=16)
    fd = tmp_path / "proc" / "77" / "fd"
    fd.mkdir(parents=True)
    os.symlink(held, fd / "3")
    os.symlink(str(tmp_path / "ev"), fd / "4")       # a directory is no source
    assert rv.held_files(77, proc=str(tmp_path / "proc")) == [held]


# ── a VMDK's extents are checked before any qemu call ──────────────────

def _sparse_with_descriptor(path: Path, extent_name: str, capacity: int = 8192, desc_size: int = 2,
                            line: str = "") -> str:
    """A hosted sparse extent (KDMV) whose embedded descriptor names
    ``extent_name`` (or holds ``line``): descriptor at sector 1. With
    capacity 0 qemu reads that descriptor as a full one and opens its
    extents."""
    head = bytearray(512)
    head[0:4] = b"KDMV"
    struct.pack_into("<I", head, 4, 1)
    struct.pack_into("<Q", head, 12, capacity)
    struct.pack_into("<QQ", head, 28, 1, desc_size)
    desc = ('# Disk DescriptorFile\nversion=1\nCID=0a1b2c3d\nparentCID=ffffffff\n'
            f'createType="monolithicSparse"\n{line or f"RW 8192 SPARSE {chr(34)}{extent_name}{chr(34)}"}\n').encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(head) + desc.ljust(1024, b"\0") + bytes(2048))
    return str(path)


@pytest.mark.parametrize("name", ["nbd://127.0.0.1:10809/x", "http://203.0.113.7/x.vmdk",
                                  'json:{"driver": "file", "filename": "/etc/hostname"}'])
def test_a_network_extent_is_refused_before_any_qemu_call(tmp_path, monkeypatch, name):
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    text = _descriptor(tmp_path / "ev" / "CORP-WS01.vmdk", [name])
    sparse = _sparse_with_descriptor(tmp_path / "ev" / "CORP-WS02.vmdk", name)
    # A json: name holds quotes, which no strict extent line can: refused as
    # a line qemu may read another way.
    words = "another way" if '"' in name else "not a plain file"
    for top in (text, sparse):
        assert words in rv.probe(top)["refused"], top
    assert q.calls == []


def test_an_absolute_or_missing_extent_is_refused_before_any_qemu_call(tmp_path, monkeypatch):
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    inside = _write(tmp_path / "ev" / "CORP-WS01-flat.vmdk", MBR)
    absolute = _descriptor(tmp_path / "ev" / "CORP-WS01.vmdk", [inside])
    missing = _descriptor(tmp_path / "ev" / "CORP-WS02.vmdk", ["CORP-WS02-flat.vmdk"])
    assert "an absolute path" in rv.probe(absolute)["refused"]
    assert "cannot be opened" in rv.probe(missing)["refused"]
    assert q.calls == []


def test_a_renamed_sparse_file_keeps_its_stale_extent_name(tmp_path, monkeypatch):
    """qemu reads a sparse file as its own one extent: the name its embedded
    descriptor gives (from before a rename) need not exist."""
    top = _sparse_with_descriptor(tmp_path / "ev" / "CORP-WS01.vmdk", "orig.vmdk")
    q = FakeQemu({top: _info("vmdk", top, **{"format-specific": {"type": "vmdk", "data": {
        "extents": [{"filename": top}]}}})})
    monkeypatch.setattr(rv, "_qemu_info", q)
    c = rv.probe(top)
    assert not c["refused"] and q.calls == [(top, "vmdk")]


def test_opened_outside_counts_any_socket_the_daemon_holds(tmp_path, monkeypatch):
    import stat as st
    folder = tmp_path / "ev"
    folder.mkdir()
    fd = tmp_path / "proc" / "123" / "fd"
    fd.mkdir(parents=True)
    os.symlink("socket:[4242]", fd / "11")
    real_stat = os.stat

    def _stat(path, *a, **k):
        if str(path).endswith("/fd/11"):
            return os.stat_result((st.S_IFSOCK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return real_stat(path, *a, **k)

    monkeypatch.setattr(rv.os, "stat", _stat)
    assert rv.opened_outside(123, str(folder), proc=str(tmp_path / "proc")) == "socket:[4242]"


def _text_vmdk(path: Path, body: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(('# Disk DescriptorFile\nversion=1\nCID=0a1b2c3d\nparentCID=ffffffff\n'
                      'createType="monolithicFlat"\n' + body).encode())
    return str(path)


@pytest.mark.parametrize("form,words", [
    ("signed sectors", "another way"), ("no space before the type", "another way"),
    ("no space before the name", "another way"), ("after 70 KiB of comments", "an absolute path"),
    ("CR line ends", "an absolute path"),
    ("a capacity-0 sparse file with descriptor size 0", "lies outside the image's folder"),
    ("a name over qemu's 511 bytes", "another way"), ("past the window with no NUL", "runs past"),
    ("a FIFO named by a capacity-0 sparse file", "not a regular file"),
    ("a sparse extent holding a descriptor of its own", "a descriptor of its own")])
def test_an_extent_qemu_could_read_another_way_is_refused_before_any_qemu_call(tmp_path, monkeypatch, form, words):
    """qemu reads a descriptor with sscanf, up to 1 MiB, from a sparse file's
    descriptor offset whatever its size field says: a check that reads any of
    these forms otherwise lets qemu open a file outside the folder before the
    check after the open can refuse. Each is refused from the file alone."""
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    ev = tmp_path / "ev"
    outside = _write(tmp_path / "outside.bin", MBR)
    flat = _write(ev / "CORP-WS01-flat.vmdk", MBR)
    top = ev / "CORP-WS01.vmdk"
    if form == "signed sectors":
        _text_vmdk(top, f'RW +2048 FLAT "{outside}" 0\n')
    elif form == "no space before the type":
        _text_vmdk(top, f'RW 2048FLAT "{outside}" 0\n')
    elif form == "no space before the name":
        _text_vmdk(top, f'RW 2048 FLAT"{outside}" 0\n')
    elif form == "after 70 KiB of comments":
        _text_vmdk(top, "# padding padding padding padding\n" * 2100 + f'RW 2048 FLAT "{outside}" 0\n')
    elif form == "CR line ends":
        top.write_bytes(('# Disk DescriptorFile\rversion=1\rcreateType="monolithicFlat"\r'
                         f'RW 2048 FLAT "{outside}" 0\r').encode())
    elif form == "a capacity-0 sparse file with descriptor size 0":
        _sparse_with_descriptor(top, "../outside.bin", capacity=0, desc_size=0)
    elif form == "a name over qemu's 511 bytes":
        _text_vmdk(top, f'RW 2048 FLAT "{"sub/" * 128}../../{os.path.basename(flat)}" 0\n')
    elif form == "past the window with no NUL":
        _text_vmdk(top, "# x\n" * 262_144 + 'RW 2048 FLAT "CORP-WS01-flat.vmdk" 0\n')
    elif form == "a FIFO named by a capacity-0 sparse file":
        os.mkfifo(ev / "queue.vmdk")
        _sparse_with_descriptor(top, "queue.vmdk", capacity=0)
    else:
        _sparse_with_descriptor(ev / "CORP-WS01-s001.vmdk", "../outside.bin", capacity=0)
        _text_vmdk(top, 'RW 8192 SPARSE "CORP-WS01-s001.vmdk"\n')
    assert words in rv.probe(str(top))["refused"], form
    assert q.calls == []


def test_extent_lines_in_the_strict_form_still_open(tmp_path, monkeypatch):
    """Tabs, a ZERO extent, comments and lines whose first word is no access
    mode pass the check; the extents are then qemu's to open."""
    ev = tmp_path / "ev"
    _write(ev / "CORP-WS01-flat.vmdk", MBR)
    top = _text_vmdk(ev / "CORP-WS01.vmdk", '# RW 1 FLAT "/elsewhere" 0\nddb.adapterType = "lsilogic"\n'
                                            'RW\t2048\tFLAT\t"CORP-WS01-flat.vmdk"\t0\nRW 2048 ZERO\n')
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    rv.probe(top)
    # A descriptor past 64 KiB is read to its end, as qemu reads it (1 MiB).
    long = _text_vmdk(ev / "CORP-WS02.vmdk", "# padding padding padding padding\n" * 2100
                      + 'RW 2048 FLAT "CORP-WS01-flat.vmdk" 0\n')
    rv.probe(long)
    assert q.calls == [(top, "vmdk"), (long, "vmdk")]


@pytest.mark.parametrize("kind", ["VMFSSPARSE", "SESPARSE", "FLAT"])
def test_an_extent_of_any_type_holding_a_descriptor_is_refused_before_any_qemu_call(tmp_path, monkeypatch, kind):
    """qemu reads more than SPARSE extents through its sparse opener, which
    takes a capacity-0 sparse file for a descriptor and opens what it names:
    whatever the line's type says, such a file is refused."""
    q = FakeQemu({})
    monkeypatch.setattr(rv, "_qemu_info", q)
    ev = tmp_path / "ev"
    _write(tmp_path / "outside.bin", MBR)
    _sparse_with_descriptor(ev / "CORP-WS01-s001.vmdk", "../outside.bin", capacity=0)
    top = _text_vmdk(ev / "CORP-WS01.vmdk", f'RW 8192 {kind} "CORP-WS01-s001.vmdk"{" 0" if kind == "FLAT" else ""}\n')
    assert "a descriptor of its own" in rv.probe(top)["refused"]
    assert q.calls == []
