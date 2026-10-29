"""Raw views on a real host: qemu-img, qemu-storage-daemon over FUSE and the
Sleuth Kit on invented disk images. Skipped where any of them is missing
(the test VM has them; a container without /dev/fuse has not).

The positive set (a renamed sparse VMDK, a QCOW2 overlay on its base, a
VHDX, a VDI) is planned, listed by the contents index through its views
and read by the Sleuth Kit through the container's own path. The hostile
set is refused without contact or a byte from outside its folder: QCOW2
backings on nbd:// and http:// (a local listener counts connections), a
VMDK extent that is a symlink out of the folder and one named ../, a
raw-named file that is a QCOW2 with an outside backing, a VMDK delta
without its parent hint, and a VHD qemu sizes by CHS geometry (the cut is
stated). The teardown leaves no daemon and no mount."""
from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import threading
from pathlib import Path

import pytest

_TOOLS = ("qemu-img", "qemu-io", "qemu-storage-daemon", "fusermount3", "mmls", "fls", "sfdisk", "mke2fs")
pytestmark = pytest.mark.skipif(
    any(shutil.which(t) is None for t in _TOOLS) or not os.access("/dev/fuse", os.R_OK | os.W_OK),
    reason="needs qemu-utils, FUSE, the Sleuth Kit, sfdisk and mke2fs")


def _sh(*argv: str) -> None:
    subprocess.run(argv, check=True, capture_output=True, timeout=120)


def _raw_disk(path: Path) -> None:
    """16 MiB: one ext4 partition holding invented files."""
    src = path.parent / "src"
    (src / "Users" / "jane.doe" / "Documents").mkdir(parents=True)
    (src / "Users" / "jane.doe" / "Documents" / "budget-2031.txt").write_text("invented 2031\n")
    _sh("truncate", "-s", "16M", str(path))
    subprocess.run(["sfdisk", "-q", str(path)], input=b"label: dos\nstart=2048, type=83\n", check=True,
                   capture_output=True, timeout=60)
    _sh("mke2fs", "-q", "-F", "-t", "ext4", "-E", "offset=1048576,nodiscard", "-d", str(src), str(path), "15M")
    shutil.rmtree(src)


class _Listener:
    """A TCP listener on 127.0.0.1 that counts the connections it gets."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.count = 0
        self.stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
                self.count += 1
                conn.close()
            except OSError:
                continue

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.sock.close()


def _fix_vhd_footer(footer: bytearray, current: int) -> bytes:
    footer[28:32] = b"vpc "               # Virtual PC: qemu sizes by CHS geometry
    footer[48:56] = struct.pack(">Q", current)
    footer[64:68] = b"\0\0\0\0"
    footer[64:68] = struct.pack(">I", (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


@pytest.fixture
def case(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    from core import raw_views
    monkeypatch.setenv("ATLAS_RAW_VIEWS", "1")
    raw_views._local_support.cache_clear()
    root = tmp_path / "CASE"
    ev = root / "evidence"
    ev.mkdir(parents=True)
    (root / "analysis").mkdir()
    log = ExecutionLog()
    log.configure("CASE", str(root / "analysis" / "CASE_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(root))
    yield root
    from core import mounts
    mounts.unmount_all_under(str(root))


def test_views_open_the_containers_and_refuse_the_hostile_ones(case, tmp_path):
    from core import contents_index, mounts, raw_views
    from core.mount_plan import build_mount_plan, ensure_raw_views, load_mount_plan, raw_device_for
    from tools import sleuthkit
    ev = case / "evidence"
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)

    # positive set
    _sh("qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(raw), str(ev / "orig.vmdk"))
    (ev / "orig.vmdk").rename(ev / "CORP-WS01.vmdk")                      # the descriptor still says orig.vmdk
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(ev / "CORP-WS02-base.qcow2"))
    _sh("qemu-img", "create", "-q", "-f", "qcow2", "-b", "CORP-WS02-base.qcow2", "-F", "qcow2",
        str(ev / "CORP-WS02.qcow2"))
    # A pattern in the gap before the partition, written into the overlay only.
    _sh("qemu-io", "-f", "qcow2", "-c", "write -P 0x41 65536 4096", str(ev / "CORP-WS02.qcow2"))
    _sh("qemu-img", "convert", "-f", "raw", "-O", "vhdx", str(raw), str(ev / "CORP-WS03.vhdx"))
    _sh("qemu-img", "convert", "-f", "raw", "-O", "vdi", str(raw), str(ev / "CORP-WS04.vdi"))

    # hostile set
    outside = tmp_path / "outside" / "secret.bin"
    outside.parent.mkdir()
    outside.write_bytes(b"invented-outside-bytes-2031" * 40000)
    listener = _Listener()
    try:
        for name, url in (("CORP-H1.qcow2", f"nbd://127.0.0.1:{listener.port}/x"),
                          ("CORP-H2.qcow2", f"http://127.0.0.1:{listener.port}/base.raw")):
            _sh("qemu-img", "create", "-q", "-f", "qcow2", "-u", "-b", url, "-F", "raw", str(ev / name), "16M")
        os.symlink(outside, ev / "CORP-H3-flat.vmdk")
        (ev / "CORP-H3.vmdk").write_text('# Disk DescriptorFile\nversion=1\nCID=0a1b2c3d\nparentCID=ffffffff\n'
                                         'createType="monolithicFlat"\nRW 2048 FLAT "CORP-H3-flat.vmdk" 0\n')
        (ev / "CORP-H4.vmdk").write_text('# Disk DescriptorFile\nversion=1\nCID=0a1b2c3e\nparentCID=ffffffff\n'
                                         'createType="monolithicFlat"\nRW 2048 FLAT "../../outside/secret.bin" 0\n')
        _sh("qemu-img", "create", "-q", "-f", "qcow2", "-u", "-b", str(outside), "-F", "raw",
            str(ev / "CORP-H5.dd"), "1M")
        _sh("qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(raw), str(ev / "CORP-H6.vmdk"))
        _sh("qemu-img", "create", "-q", "-f", "vmdk", "-b", "CORP-H6.vmdk", "-F", "vmdk",
            str(ev / "CORP-H6-000001.vmdk"))
        delta = (ev / "CORP-H6-000001.vmdk").read_bytes()
        hint = b'parentFileNameHint="CORP-H6.vmdk"'
        assert hint in delta
        (ev / "CORP-H6-000001.vmdk").write_bytes(delta.replace(hint, b"#" + hint[1:]))
        _sh("qemu-img", "convert", "-f", "raw", "-O", "vpc", str(raw), str(ev / "CORP-H7.vhd"))
        vhd = bytearray((ev / "CORP-H7.vhd").read_bytes())
        footer = bytearray(vhd[-512:])
        cyl, heads, sectors = struct.unpack(">HBB", bytes(footer[56:60]))
        current = cyl * heads * sectors * 512 + 169_984
        fixed = _fix_vhd_footer(footer, current)
        vhd[-512:] = fixed
        vhd[:512] = fixed
        (ev / "CORP-H7.vhd").write_bytes(bytes(vhd))

        build_mount_plan(case, persist=True, auto_mount=False)
        views = ensure_raw_views(case)
        assert listener.count == 0                                        # no contact, probing or starting
    finally:
        listener.close()

    by = {Path(i["path"]).name: i for i in load_mount_plan(case)["images"]}
    for name in ("CORP-WS01.vmdk", "CORP-WS02.qcow2", "CORP-WS03.vhdx", "CORP-WS04.vdi", "CORP-H6.vmdk"):
        assert by[name]["recommended_tool"] == "tsk.mmls", (name, by[name].get("reason"))
        assert views[f"evidence/{name}"].endswith("/disk"), views
    assert by["CORP-WS02-base.qcow2"]["earlier_state_of"] == "evidence/CORP-WS02.qcow2"
    for name, words in (("CORP-H1.qcow2", "not a plain file"), ("CORP-H2.qcow2", "not a plain file"),
                        ("CORP-H3.vmdk", "outside the image's folder"),
                        ("CORP-H4.vmdk", "outside the image's folder"),
                        ("CORP-H6-000001.vmdk", "without a parent qemu can find")):
        assert by[name]["status"] == "access_failed" and words in by[name]["access_error"], (name, by[name])
    assert by["CORP-H5.dd"].get("container") is None                       # raw by name: never probed
    assert "169984 bytes" in by["CORP-H7.vhd"]["reason"]

    # the readers: the Sleuth Kit through the container's own path, the index through the views
    view, why = raw_device_for(case, ev / "CORP-WS02.qcow2")
    with open(view, "rb") as f:
        f.seek(65536)
        assert f.read(2) == b"AA"                                         # the overlay's write: chain applied
    for name in ("CORP-H1.qcow2", "CORP-H3.vmdk", "CORP-H6-000001.vmdk"):
        dev, why = raw_device_for(case, ev / name)
        assert dev is None and why
    assert sleuthkit._tsk_readable(str(ev / "CORP-H5.dd")) == (str(ev / "CORP-H5.dd"), None)
    resolved, refusal = sleuthkit._tsk_readable(str(ev / "CORP-WS01.vmdk"))
    assert refusal is None and resolved.endswith("/disk")
    listing = subprocess.run(["fls", "-r", "-o", "2048", resolved], capture_output=True, text=True, timeout=60)
    assert "budget-2031.txt" in listing.stdout

    built = contents_index.build(case)
    listed = set(built["listed"])
    assert {"evidence/CORP-WS01.vmdk", "evidence/CORP-WS02.qcow2", "evidence/CORP-WS03.vhdx",
            "evidence/CORP-WS04.vdi"} <= listed
    assert "evidence/CORP-WS02-base.qcow2" not in listed                  # an earlier state: on demand
    hits = contents_index.find(case, pattern="budget-2031")
    assert hits["total"] >= 4

    # nothing of the outside file was read through any view
    for d in raw_views.daemons():
        assert d["source"] != str(outside)

    mounts.unmount_all_under(str(case))
    base = os.path.realpath(str(case))
    assert not [d for d in raw_views.daemons() if d["mountpoint"].startswith(base + os.sep)]
    assert not mounts.find_mounts_under(base)


def test_a_killed_daemon_leaves_a_stale_view_the_next_read_restarts(case, tmp_path):
    import signal
    import time
    from core import raw_views
    from core.mount_plan import build_mount_plan, raw_device_for
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(case / "evidence" / "CORP-WS01.qcow2"))
    build_mount_plan(case, persist=True, auto_mount=False)
    view, _ = raw_device_for(case, case / "evidence" / "CORP-WS01.qcow2")
    pid = next(d["pid"] for d in raw_views.daemons() if d["mountpoint"] == raw_views._norm(view))
    os.kill(pid, signal.SIGKILL)
    for _ in range(50):
        if raw_views.view_state(view) == "stale":
            break
        time.sleep(0.05)
    assert raw_views.view_state(view) == "stale"
    again, why = raw_device_for(case, view)                               # the view's own path, stale
    assert again == view and why == "" and raw_views.view_state(view) == "live"


def test_a_container_swapped_after_the_plan_is_never_served(case, tmp_path):
    """The plan probed clean files; a descriptor rewritten to an outside
    extent (same size, its modify time set back) and a QCOW2 replaced by one
    with an outside data file are checked again before any daemon opens
    them: refused, and no daemon holds an outside file."""
    from core import raw_views
    from core.mount_plan import build_mount_plan, ensure_raw_views, load_mount_plan, raw_device_for
    from tools import sleuthkit
    ev = case / "evidence"
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)
    shutil.copy(raw, ev / "CORP-WS05-flat.vmdk")
    head = ('# Disk DescriptorFile\nversion=1\nCID=0a1b2c3d\nparentCID=ffffffff\n'
            'createType="monolithicFlat"\n')
    desc = head + 'RW 32768 FLAT "CORP-WS05-flat.vmdk" 0\n' + "#" * 400 + "\n"
    (ev / "CORP-WS05.vmdk").write_text(desc)
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(ev / "CORP-WS06.qcow2"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"SECRETSECRET" * 1400000)
    build_mount_plan(case, persist=True, auto_mount=False)
    tops = [i for i in load_mount_plan(case)["images"]
            if Path(i["path"]).name in ("CORP-WS05.vmdk", "CORP-WS06.qcow2")]
    assert len(tops) == 2 and all((i.get("container") or {}).get("chain") for i in tops)

    st = os.stat(ev / "CORP-WS05.vmdk")
    core = head + f'RW 32768 FLAT "{outside / "secret.bin"}" 0\n'
    swapped = core + "#" * (len(desc) - len(core) - 1) + "\n"
    assert len(swapped) == len(desc)                               # same size, time set back
    (ev / "CORP-WS05.vmdk").write_text(swapped)
    os.utime(ev / "CORP-WS05.vmdk", ns=(st.st_atime_ns, st.st_mtime_ns))
    _sh("qemu-img", "create", "-q", "-f", "qcow2", "-o", f"data_file={outside / 'data.raw'},data_file_raw=on",
        str(tmp_path / "work" / "swap.qcow2"), "16M")
    os.replace(tmp_path / "work" / "swap.qcow2", ev / "CORP-WS06.qcow2")

    # No plan rebuild in between: the check before the start refuses them, so
    # no daemon opens them at all (the audit of what a started daemon opened
    # is the second line, not the one that answers here).
    # The descriptor's absolute extent is refused from its text, before qemu.
    for name, words in (("CORP-WS05.vmdk", "an absolute path"),
                        ("CORP-WS06.qcow2", "external data file")):
        _img, refusal = sleuthkit._tsk_readable(str(ev / name))
        assert refusal and words in refusal["error"] and "its daemon opened" not in refusal["error"], \
            (name, refusal)
        assert raw_device_for(case, ev / name)[0] is None
    build_mount_plan(case, persist=True, auto_mount=False)        # and after one
    assert ensure_raw_views(case) == {}
    for d in raw_views.daemons():
        fd_dir = f"/proc/{d['pid']}/fd"
        held = {os.path.realpath(os.path.join(fd_dir, f)) for f in os.listdir(fd_dir)}
        assert not any(h.startswith(str(outside)) for h in held)


def test_six_readers_at_once_share_one_view(case, tmp_path):
    """Six processes ask for the same view at once, three times: each gets
    the view, one daemon serves it, and no failure stays on the plan."""
    import json
    import sys
    from core import mounts, raw_views
    from core.mount_plan import build_mount_plan, load_mount_plan
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)
    top = case / "evidence" / "CORP-WS07.qcow2"
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(top))
    build_mount_plan(case, persist=True, auto_mount=False)
    repo = Path(__file__).resolve().parents[2]
    child = ("import json, sys; sys.path.insert(0, sys.argv[1]); "
             "from core.mount_plan import raw_device_for; print(json.dumps(raw_device_for(sys.argv[2], sys.argv[3])))")
    env = dict(os.environ, ATLAS_RAW_VIEWS="1")
    for _round in range(3):
        procs = [subprocess.Popen([sys.executable, "-c", child, str(repo), str(case), str(top)], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(6)]
        results = [json.loads(p.communicate(timeout=120)[0].strip().splitlines()[-1]) for p in procs]
        views = {r[0] for r in results}
        assert len(views) == 1 and None not in views and all(r[1] == "" for r in results), results
        view = views.pop()
        assert len([d for d in raw_views.daemons() if d["mountpoint"] == raw_views._norm(view)]) == 1
        img = next(i for i in load_mount_plan(case)["images"] if i["path"].endswith("CORP-WS07.qcow2"))
        assert img.get("status") != "access_failed", img
        mounts.unmount_all_under(str(case))
        assert not [d for d in raw_views.daemons() if d["mountpoint"] == raw_views._norm(view)]


def test_reads_through_a_view_pass_the_evidence_guard(case, tmp_path, monkeypatch):
    """The executor compares an evidence path's lstat before and after each
    command; qemu's FUSE export reports the current time as the view's mtime
    once the kernel's attribute cache (about 1 s) runs out. Each guarded
    command here waits 1.2 s after its first snapshot, as a long read does: a
    TSK tool through the executor on the view succeeds, and the index lists
    the image complete, with no evidence-modified refusal."""
    import json
    import time
    from core import contents_index, evidence_guard
    from core.mount_plan import build_mount_plan, ensure_raw_views
    from tools import sleuthkit
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)
    top = case / "evidence" / "CORP-WS08.qcow2"
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(top))
    build_mount_plan(case, persist=True, auto_mount=False)
    assert ensure_raw_views(case)["evidence/CORP-WS08.qcow2"].endswith("/disk")
    real, calls = evidence_guard.snapshot_evidence_refs, []

    def aging(cmd):
        snap = real(cmd)
        calls.append(1)
        if len(calls) % 2:                            # the snapshot taken before the command
            time.sleep(1.2)
        return snap

    monkeypatch.setattr(evidence_guard, "snapshot_evidence_refs", aging)
    fls = getattr(sleuthkit.tsk_fls, "fn", sleuthkit.tsk_fls)
    res = fls(str(top), offset_sectors=2048)
    assert res.get("success") is True and "budget-2031.txt" in json.dumps(res), res
    assert "EVIDENCE MODIFIED" not in json.dumps(res)
    contents_index.build(case)
    con = contents_index._connect(case)
    meta = contents_index._meta_get(con, "image:evidence/CORP-WS08.qcow2")
    con.close()
    assert meta.get("listed") == 1 and meta.get("complete") == 1, meta
    assert "EVIDENCE MODIFIED" not in str(meta.get("reason"))
    assert calls                                       # the guard ran on these commands


def test_network_extents_are_refused_with_no_qemu_call(case, monkeypatch):
    """A VMDK descriptor naming nbd:// and http:// extents: refused by the
    descriptor check before any qemu-img call, and nothing connects."""
    from core import raw_views
    from core.mount_plan import build_mount_plan, load_mount_plan
    listener = _Listener()
    seen = []
    real = raw_views._qemu_info
    monkeypatch.setattr(raw_views, "_qemu_info", lambda p, f: seen.append(p) or real(p, f))
    try:
        for name, scheme in (("CORP-N1.vmdk", "nbd"), ("CORP-N2.vmdk", "http")):
            (case / "evidence" / name).write_text(
                '# Disk DescriptorFile\nversion=1\nCID=0a1b2c3d\nparentCID=ffffffff\n'
                f'createType="monolithicFlat"\nRW 2048 FLAT "{scheme}://127.0.0.1:{listener.port}/x" 0\n')
        build_mount_plan(case, persist=True, auto_mount=False)
        time_waited = 0.0
        import time
        while time_waited < 1.0:                       # a late connection would still be counted
            time.sleep(0.1)
            time_waited += 0.1
        assert listener.count == 0
    finally:
        listener.close()
    by = {Path(i["path"]).name: i for i in load_mount_plan(case)["images"]}
    for name in ("CORP-N1.vmdk", "CORP-N2.vmdk"):
        assert by[name]["status"] == "access_failed" and "not a plain file" in by[name]["access_error"]
    assert not [p for p in seen if p.endswith(("CORP-N1.vmdk", "CORP-N2.vmdk"))]


def test_a_writable_export_at_a_view_path_is_compared(case):
    """A FUSE export started by anything but Atlas's own view start, with
    writable on, at mnt/<stem>/disk: the guard compares it as itself, so a
    write through it is reported."""
    import json
    import time
    from core import evidence_guard, raw_views
    src = case / "evidence" / "CORP-WS09.raw"
    src.write_bytes(bytes(1 << 20))
    view = case / "mnt" / "CORP-WS09" / "disk"
    view.parent.mkdir(parents=True)
    view.touch()
    _sh("qemu-storage-daemon", "--daemonize",
        "--blockdev", json.dumps({"driver": "raw", "node-name": "top",
                                  "file": {"driver": "file", "filename": str(src)}}),
        "--export", json.dumps({"type": "fuse", "id": "w", "node-name": "top", "mountpoint": str(view),
                                "writable": True, "allow-other": "off"}))
    assert raw_views.mounted(str(view)) and raw_views.view_sources(str(view)) is None
    cmd = ["fls", str(view)]
    before = evidence_guard.snapshot_evidence_refs(cmd)
    with open(view, "r+b") as fh:
        fh.write(b"\x01")
    time.sleep(1.2)                                   # past the kernel's attribute cache
    changes = evidence_guard.evidence_changes(before, cmd)
    assert {"path": str(view), "change": "modified"} in changes, changes


def test_a_command_naming_only_a_view_covers_its_source_and_lock(case, tmp_path):
    """The view's own stat is left out; the file its daemon reads and the
    lock beside it are compared in its place."""
    from core import evidence_guard, raw_views
    from core.mount_plan import build_mount_plan, ensure_raw_views
    raw = tmp_path / "work" / "disk.raw"
    raw.parent.mkdir()
    _raw_disk(raw)
    top = case / "evidence" / "CORP-WS10.qcow2"
    _sh("qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(top))
    build_mount_plan(case, persist=True, auto_mount=False)
    view = os.path.join(str(case), ensure_raw_views(case)["evidence/CORP-WS10.qcow2"])    # as a tool names it
    lock = os.path.join(os.path.dirname(view), raw_views.LOCK_NAME)
    cmd = ["fls", "-o", "2048", view]
    before = evidence_guard.snapshot_evidence_refs(cmd)
    assert view not in before and os.path.realpath(top) in before and lock in before, sorted(before)
    assert evidence_guard.evidence_changes(before, cmd) == []
    os.utime(top, ns=(1, 2))
    assert evidence_guard.evidence_changes(before, cmd) == [{"path": os.path.realpath(top), "change": "modified"}]
