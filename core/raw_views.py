"""Read-only raw views of virtual-disk containers (VMDK, VHD, VHDX, QCOW2, VDI).

The Sleuth Kit build Atlas runs on reads raw images only, and plaso's VMDK
reader finds a split or renamed VMDK's extents by the names its descriptor
gives. qemu-storage-daemon (qemu-utils) exports a container's disk as one
read-only regular file over FUSE, without root, with a snapshot chain
applied: ``<case>/mnt/<stem>/disk``. Every reader that is handed the
container reads that file instead (core.mount_plan.raw_device_for), so a
case of many images needs no free space for copies.

A container is untrusted input: it names other files (VMDK extents, a
backing chain, a QCOW2 data file), and qemu opens what it names, network
protocols included. Here qemu never guesses a format (it is pinned from the
file's name and magic), a node is probed without its backing, every file a
node names must be a regular file under the top image's folder before the
next node is probed, and the daemon is started on an explicit node graph
built from the checked paths, not on what the headers say at start time.
Formats whose parent qemu does not apply (a differencing VHD or VDI, a
VMDK delta without a parent hint) are refused rather than shown with zeros
where the parent's data belongs.

View daemons are infrastructure, not reads: they run as plain subprocesses,
never through the executor, so no trace entry stands for a read that read
nothing; their state lives in the image's mount-plan entry. Stdlib only at
import time: the detached job supervisor imports this module.
"""
from __future__ import annotations

import fcntl
import functools
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

VIEW_NAME = "disk"
LOCK_NAME = ".disk.lock"      # beside the view: one reader at a time checks, starts and records it
# The formats a view is made for: the drivers whose read-only export of the
# whole disk was exercised on qemu 8.2 (monolithic, split, flat and stream
# VMDK and VMDK deltas; dynamic VHD; VHDX; QCOW2 with backing chains;
# dynamic VDI). Any other format qemu could read gets no view.
VIEW_FORMATS = frozenset({"vmdk", "vpc", "vhdx", "qcow2", "vdi"})
LABELS = {"vmdk": "VMDK", "vpc": "VHD", "vhdx": "VHDX", "qcow2": "QCOW2", "vdi": "VDI",
          "qcow": "QCOW version 1", "raw": "raw"}
# Formats whose qemu driver takes a backing node.
_COW_FORMATS = frozenset({"vmdk", "qcow2"})
# The names that say "container"; every other name is read as raw and never
# probed, the old qemu format-probing attack (a raw image whose first bytes
# are a QCOW2 header naming a host file) needs a name qemu may guess for.
_CONTAINER_EXT = frozenset({".vmdk", ".vhd", ".vhdx", ".qcow2", ".qcow", ".img", ".vdi"})
# A behaviour guard per probe of an untrusted header, not a run limit: a
# header can make qemu-img allocate or loop (the CVE-2015-5162 class).
_PROBE_LIMITS = ("--as=1073741824", "--cpu=30")
_PROBE_TIMEOUT = 60      # a FIFO named as an extent would block an open forever
_START_TIMEOUT = 60
_STOP_WAIT = 3.0
_PROTOCOL_RE = re.compile(r"^[^:/\\]*:")   # qemu's own test: a colon before any separator
# Why a container has no view, as the readers tell the three apart: the
# host serves none (a copy is the way), the daemon did not start (a retry,
# then a copy), or the container itself is refused (the probe's reason; a
# copy reads it the same way).
NO_HOST_VIEWS = "this host serves no raw views"
START_FAILED = "its raw view did not start"


def views_on() -> bool:
    """ATLAS_RAW_VIEWS (default on): containers are read through raw views.
    Off, a container is read as it is."""
    from core.envfile import env_flag
    return env_flag("ATLAS_RAW_VIEWS", True)


@functools.lru_cache(maxsize=1)
def _local_support() -> str:
    for prog in ("qemu-img", "qemu-storage-daemon", "fusermount3"):
        if not shutil.which(prog):
            return f"{prog} is not installed"
    if not os.access("/dev/fuse", os.R_OK | os.W_OK):
        return "/dev/fuse cannot be opened by this user"
    try:
        out = subprocess.run(["qemu-storage-daemon", "--help"], capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return f"qemu-storage-daemon --help failed ({e})"
    if "type=]fuse" not in out:
        return "this qemu-storage-daemon has no FUSE export"
    return ""


def host_support() -> str:
    """Why this host cannot serve raw views, "" when it can."""
    try:
        from core import remote
        if remote.is_enabled():
            return "tools run on a remote host, views are local"
    except Exception:  # noqa: BLE001 - no remote config: local
        pass
    return _local_support()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _one_line(text: str, limit: int = 300) -> str:
    text = " ".join(str(text or "").split())
    return text.replace("qemu-img: ", "").replace("qemu-storage-daemon: ", "")[:limit]


def _fp(path: str) -> str:
    """A file's identity for a stored probe: inode, size, and modify and
    change times in nanoseconds (a change time cannot be set back)."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    return f"{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"


def _fp_dir(path: str) -> str:
    """A folder's identity: its own times and the names it holds (a time
    has the kernel's coarse tick; a file added within it shows in the
    names)."""
    try:
        names = sorted(os.listdir(path))
    except OSError:
        return ""
    digest = hashlib.sha1("\0".join(names).encode("utf-8", "surrogateescape")).hexdigest()[:16]
    return f"{_fp(path)}:{digest}"


# ── what a file is ────────────────────────────────────────────────────────

def pinned_format(path: str) -> tuple[str, str]:
    """The one format qemu may read ``path`` as, from its name and its first
    bytes (public format facts): "raw" for a file the Sleuth Kit reads as it
    is, a qemu driver name, or "" with why the file is not what its name
    says."""
    ext = os.path.splitext(str(path))[1].lower()
    if ext not in _CONTAINER_EXT:
        return "raw", ""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError as e:
        return "", f"its header cannot be read ({e.strerror or e})"
    if ext == ".vmdk":
        if head[:4] == b"COWD":
            return "", "it is a VMDK delta extent (COWD) without its descriptor"
        if head[:4] == b"KDMV" or head.lstrip()[:21] == b"# Disk DescriptorFile":
            return "vmdk", ""
        return "raw", ""                    # a flat extent: the disk's bytes as they are
    if ext == ".vhd":
        # Dynamic and differencing VHDs copy their footer to the start; a
        # fixed VHD is the disk's bytes followed by its footer.
        return ("vpc", "") if head[:8] == b"conectix" else ("raw", "")
    if ext == ".vhdx":
        return ("vhdx", "") if head[:8] == b"vhdxfile" else ("", "it has no VHDX signature")
    if ext == ".vdi":
        return ("vdi", "") if head[0x40:0x44] == b"\x7f\x10\xda\xbe" else ("", "it has no VDI signature")
    if head[:4] == b"QFI\xfb":              # .qcow2, .qcow, .img
        version = struct.unpack(">I", head[4:8])[0] if len(head) >= 8 else 0
        return ("qcow2", "") if version in (2, 3) else ("qcow", f"it is a QCOW image of version {version}")
    return ("raw", "") if ext == ".img" else ("", "it has no QCOW signature")


# What qemu reads of a VMDK descriptor (block/vmdk.c vmdk_read_desc): at most
# this many bytes, up to the first NUL.
_DESC_WINDOW = (1 << 20) - 1
_EXTENT_ACCESS = frozenset({"RW", "RDONLY", "NOACCESS"})
# The one extent-line form this check reads, the way qemu's sscanf reads it
# (vmdk_parse_extents): unsigned sectors, a known type, a quoted name of at
# most qemu's 511 bytes (none for ZERO), an optional unsigned offset.
_EXTENT_LINE_RE = re.compile(
    r'[ \t]*(?:RW|RDONLY|NOACCESS)[ \t]+[0-9]+[ \t]+'
    r'(?:ZERO|(FLAT|SPARSE|VMFS|VMFSSPARSE|SESPARSE|VMFSRDM|VMFSRAW)[ \t]+"([^"\r\n]{1,511})")'
    r'(?:[ \t]+[0-9]+)?[ \t]*')


def _sparse_header(head: bytes) -> tuple[int, int]:
    """(capacity, descriptor offset in bytes) of a KDMV header."""
    capacity, = struct.unpack_from("<Q", head, 12)
    desc_sectors, = struct.unpack_from("<Q", head, 28)
    return capacity, desc_sectors * 512


def _vmdk_descriptor(path: str) -> tuple[str, bool, str]:
    """(text, opened, refusal): the descriptor text of a VMDK read the way
    qemu reads it: at most _DESC_WINDOW bytes, up to the first NUL, from the
    start of a text descriptor or, in a sparse (KDMV) file, from its
    descriptor offset whenever that is nonzero, its size field ignored.
    ``opened`` when qemu opens the extents the text names: a text
    descriptor's, a sparse file's of capacity 0. Refused when no NUL ends
    the text within the window and the file goes on."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
            start, opened = 0, True
            if head[:4] == b"KDMV":
                if len(head) < 44:
                    return "", False, "its sparse header is cut short"
                capacity, start = _sparse_header(head)
                if not start:
                    return "", False, ""
                opened = capacity == 0
            f.seek(start)
            data = f.read(_DESC_WINDOW + 1)
    except (OSError, OverflowError) as e:
        return "", False, f"its descriptor cannot be read ({getattr(e, 'strerror', None) or e})"
    text, nul, _rest = data.partition(b"\0")
    if not nul and len(data) > _DESC_WINDOW:
        return "", False, "its descriptor runs past what qemu reads of it"
    return text.decode("utf-8", "surrogateescape"), opened, ""


def _holds_descriptor(path: str) -> bool:
    """A sparse extent qemu reads as a descriptor of its own (capacity 0
    and a descriptor offset), whose extents it would open too."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return True
    if head[:4] != b"KDMV" or len(head) < 44:
        return False
    capacity, start = _sparse_header(head)
    return capacity == 0 and start != 0


def _extents_refusal(path: str, top_dir: str) -> str:
    """The extents a VMDK's descriptor names, checked before any qemu call
    and whichever qemu runs. Every line qemu could take for an extent (its
    first word RW, RDONLY or NOACCESS) must be in the strict form, or the
    file is refused: qemu's sscanf reads other forms its own way. No extent
    may name a protocol, json: or an absolute path. An extent qemu opens (a
    text descriptor's, a capacity-0 sparse file's) must be a regular file
    inside the image's folder and, whatever its type, no sparse file holding
    a descriptor of its own. A sparse file of nonzero capacity is read as
    its own one extent, so the name its embedded descriptor gives (stale
    after a rename) need not exist."""
    text, opened, why = _vmdk_descriptor(path)
    if why:
        return why
    top = top_dir.rstrip(os.sep) + os.sep
    base_dir = os.path.dirname(path)
    for line in text.splitlines():
        first = line.split(None, 1)
        if not first or first[0] not in _EXTENT_ACCESS:
            continue
        m = _EXTENT_LINE_RE.fullmatch(line)
        if not m:
            return f"its descriptor holds an extent line qemu may read another way: {line.strip()[:80]!r}"
        name = m.group(2)
        if name is None:                          # a ZERO extent names no file
            continue
        if name.startswith("json:") or _PROTOCOL_RE.match(name):
            return f"an extent names {name!r}, which is not a plain file"
        if os.path.isabs(name):
            return f"an extent names {name!r}, an absolute path"
        if not opened:
            if not os.path.realpath(os.path.join(base_dir, name)).startswith(top):
                return f"an extent names {name!r}, which lies outside the image's folder"
            continue
        real, ref = _contained(top_dir, base_dir, name)
        if ref:
            return f"an extent {ref}"
        # Whatever its type says: qemu reads more than SPARSE extents through
        # its sparse opener, which takes such a file for a descriptor.
        if _holds_descriptor(real):
            return f"an extent names {name!r}, a sparse file holding a descriptor of its own"
    return ""


def _precheck(path: str, fmt: str, top_dir: str = "") -> str:
    """A refusal read from the file before qemu opens it."""
    if fmt == "vmdk":
        return _extents_refusal(path, top_dir or os.path.dirname(path))
    if fmt != "qcow2":
        return ""
    try:
        with open(path, "rb") as f:
            head = f.read(80)
    except OSError as e:
        return f"its header cannot be read ({e.strerror or e})"
    if len(head) >= 80 and struct.unpack(">I", head[4:8])[0] >= 3 \
            and struct.unpack(">Q", head[72:80])[0] & 0b100:
        return "it is a QCOW2 image with an external data file, which Atlas does not open"
    return ""


def _qemu_info(path: str, fmt: str) -> tuple[Optional[dict], str]:
    argv = ["qemu-img", "info", "--output=json", "-U", "-f", fmt, path]
    if shutil.which("prlimit"):
        argv = ["prlimit", *_PROBE_LIMITS, "--", *argv]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_PROBE_TIMEOUT,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, f"qemu-img info did not finish within {_PROBE_TIMEOUT} s"
    except OSError as e:
        return None, f"qemu-img info could not run ({e})"
    if p.returncode != 0:
        return None, _one_line(p.stderr) or f"qemu-img info exit {p.returncode}"
    try:
        info = json.loads(p.stdout)
    except ValueError:
        return None, "qemu-img info printed no JSON"
    return (info, "") if isinstance(info, dict) else (None, "qemu-img info printed no JSON object")


def _postcheck(path: str, fmt: str, info: dict) -> tuple[str, list[str]]:
    """(refusal, notes) from what qemu says and the header's own fields."""
    notes: list[str] = []
    virtual = int(info.get("virtual-size") or 0)
    try:
        if fmt == "vpc":
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                head = f.read(512)
                f.seek(max(0, size - 512))
                tail = f.read(512)
            # qemu reads the copy at the start when there is one, the end
            # footer otherwise; a type is checked in every copy there is.
            copies = [c for c in (head, tail) if c[:8] == b"conectix"]
            if not copies:
                return "its VHD footer is missing", notes
            for copy in copies:
                disk_type = struct.unpack(">I", copy[60:64])[0]
                if disk_type not in (2, 3):
                    return (f"it is a VHD of type {disk_type} (differencing or other): qemu reads it "
                            "without its parent, so the view would show zeros where the parent's data "
                            "is"), notes
            current = struct.unpack(">Q", copies[0][48:56])[0]
            if current > virtual:
                notes.append(f"the view ends {current - virtual} bytes before the size the VHD states "
                             f"({current}): qemu sizes this VHD by its CHS geometry, so its last "
                             f"{current - virtual} bytes are not readable")
        elif fmt == "vdi":
            with open(path, "rb") as f:
                head = f.read(0x50)
            image_type = struct.unpack("<I", head[0x4C:0x50])[0]
            if image_type not in (1, 2):
                return (f"it is a VDI of type {image_type} (differencing or undo): qemu reads it without "
                        "its parent, so the view would show zeros where the parent's data is"), notes
        elif fmt == "vmdk":
            from core.vmdk import parse_descriptor, read_descriptor_text
            desc = parse_descriptor(read_descriptor_text(path))
            if desc["has_parent"] and not info.get("backing-filename"):
                return ("it is a VMDK delta (its descriptor names a parent CID) without a parent "
                        "qemu can find (no parentFileNameHint), so the view would show zeros where "
                        "the parent's data is"), notes
        elif fmt == "qcow2":
            snaps = [str(s.get("name") or s.get("id") or "") for s in info.get("snapshots") or []
                     if isinstance(s, dict)]
            if snaps:
                notes.append(f"{len(snaps)} internal snapshot(s) ({', '.join(snaps[:5])}"
                             f"{', ...' if len(snaps) > 5 else ''}): the view shows the current state only")
    except (OSError, struct.error) as e:
        return f"its header cannot be read ({e})", notes
    return "", notes


def _cid_mismatch(delta: str, parent: str) -> str:
    """Why a VMDK delta does not belong to the parent its hint names: the
    delta records its parent's content id (parentCID) and qemu refuses every
    read when the parent's CID differs (the parent changed after the
    snapshot); "" when they match or a CID cannot be read."""
    from core.vmdk import parse_descriptor, read_descriptor_text
    want = parse_descriptor(read_descriptor_text(delta))["parent_cid"]
    have = parse_descriptor(read_descriptor_text(parent))["cid"]
    if want and have and want != have:
        return (f"its parent {os.path.basename(parent)} has content id {have}, the delta was made "
                f"on {want}: the parent changed after the snapshot, and qemu refuses every read")
    return ""


def _contained(top_dir: str, base_dir: str, name: str) -> tuple[str, str]:
    """(real path, refusal): a file a container names must be a regular
    file under the top image's folder, named as a path, not a protocol."""
    raw = str(name or "")
    if raw.startswith("json:") or _PROTOCOL_RE.match(raw):
        return "", f"names {raw!r}, which is not a plain file"
    real = os.path.realpath(raw if os.path.isabs(raw) else os.path.join(base_dir, raw))
    if not real.startswith(top_dir.rstrip(os.sep) + os.sep):
        return "", f"names {raw!r}, which lies outside the image's folder"
    try:
        st = os.stat(real)
    except OSError as e:
        return "", f"names {raw!r}, which cannot be opened ({e.strerror or e})"
    if not stat.S_ISREG(st.st_mode):
        return "", f"names {raw!r}, which is not a regular file"
    return real, ""


def probe(path: str) -> dict[str, Any]:
    """What a container is and how its view is built: ``format`` (pinned),
    ``chain`` (top first: path, format, virtual and actual size; empty when
    refused), ``parts`` (extent files the top reads), ``notes``,
    ``refused`` or ``unsupported`` (why there is no view) and ``files``
    (fingerprints of every file read, to tell a stale probe)."""
    top = os.path.realpath(str(path))
    fmt, why = pinned_format(top)
    out: dict[str, Any] = {"format": fmt, "chain": [], "parts": [], "notes": [], "refused": "",
                           "unsupported": "", "files": {}, "probed_at": _utcnow()}
    top_dir = os.path.dirname(top)
    if fmt == "raw":
        return out
    # A refusal stays until the image or its folder changes (a file added,
    # removed or renamed beside it): a probe that waited out a FIFO named as
    # an extent is not repeated on every plan build.
    settled = {top: _fp(top), top_dir: _fp_dir(top_dir)}
    if not fmt:
        out.update(refused=why, files=settled)
        return out
    if fmt not in VIEW_FORMATS:
        out.update(unsupported=f"{why}: Atlas makes no raw view of this format", files=settled)
        return out
    node_path, node_fmt, seen = top, fmt, set()
    chain: list[dict] = []
    parts: list[str] = []
    refused = ""
    while not refused:
        if node_path in seen:
            refused = "its backing chain loops"
            break
        seen.add(node_path)
        if node_fmt == "raw":
            st = os.stat(node_path)
            chain.append({"path": node_path, "format": "raw", "virtual_size": st.st_size,
                          "actual_size": st.st_blocks * 512})
            break
        refused = _precheck(node_path, node_fmt, top_dir)
        if refused:
            break
        info, err = _qemu_info(node_path, node_fmt)
        if err:
            refused = err
            break
        refused, notes = _postcheck(node_path, node_fmt, info)
        if refused:
            break
        base_dir = os.path.dirname(node_path)
        extents = ((info.get("format-specific") or {}).get("data") or {}).get("extents") or []
        for ext in extents:
            name = str((ext or {}).get("filename") or "")
            if not name or os.path.realpath(name) == node_path:
                continue
            real, ref = _contained(top_dir, base_dir, name)
            if ref:
                refused = f"an extent {ref}"
                break
            parts.append(real)
        if refused:
            break
        chain.append({"path": node_path, "format": node_fmt,
                      "virtual_size": int(info.get("virtual-size") or 0),
                      "actual_size": int(info.get("actual-size") or 0)})
        out["notes"] += notes
        stored = str(info.get("backing-filename") or "")
        if not stored:
            break
        if node_fmt not in _COW_FORMATS:
            refused = f"its {LABELS[node_fmt]} header names a backing file, which qemu does not apply"
            break
        if _PROTOCOL_RE.match(stored) or stored.startswith("json:"):
            refused = f"its backing file {stored!r} is not a plain file"
            break
        real, ref = _contained(top_dir, base_dir, str(info.get("full-backing-filename") or stored))
        if ref:
            refused = f"its backing file {ref}"
            break
        next_fmt, why = pinned_format(real)
        stated = str(info.get("backing-filename-format") or "")
        if not next_fmt or (next_fmt not in VIEW_FORMATS and next_fmt != "raw"):
            refused = f"its backing file {os.path.basename(real)} is refused: {why or next_fmt}"
        elif stated and stated != next_fmt:
            refused = (f"its header says the backing file is {stated}, the file's name and "
                       f"signature say {next_fmt}")
        elif node_fmt == next_fmt == "vmdk":
            refused = _cid_mismatch(node_path, real)
        node_path, node_fmt = real, next_fmt
    if refused:
        out.update(refused=refused, files=settled)
        return out
    out["chain"] = chain
    out["parts"] = sorted(set(parts))
    out["files"] = {p: _fp(p) for p in [n["path"] for n in chain] + out["parts"]}
    return out


def probe_is_current(container: dict) -> bool:
    """Whether a stored probe still describes the files (none changed)."""
    files = container.get("files") or {}
    return bool(files) and all((_fp_dir(p) if os.path.isdir(p) else _fp(p)) == fp for p, fp in files.items())


def node_graph(chain: list[dict], i: int = 0) -> dict:
    """The explicit qemu node graph of a checked chain: every node read-only,
    its file by the checked path, a COW node's backing given (or none), so
    nothing a header says at open time adds a file."""
    n = chain[i]
    node: dict[str, Any] = {"driver": n["format"], "read-only": True,
                            "file": {"driver": "file", "filename": n["path"], "read-only": True,
                                     "locking": "off"}}
    if n["format"] in _COW_FORMATS:
        node["backing"] = node_graph(chain, i + 1) if i + 1 < len(chain) else None
    return node


def json_filename(chain: list[dict]) -> str:
    """The checked graph as a qemu-img filename (json: pseudo-protocol)."""
    return "json:" + json.dumps(node_graph(chain))


# ── the mount table and the daemons ───────────────────────────────────────

def _proc_mounts() -> list[tuple[str, str, list[str]]]:
    """(mountpoint, fstype, options) of every line of /proc/mounts."""
    from core.mounts import _unescape_mountpoint
    out = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split(" ")
                if len(parts) >= 4:
                    out.append((_unescape_mountpoint(parts[1]), parts[2], parts[3].split(",")))
    except OSError:
        pass
    return out


def _norm(path: str) -> str:
    """A path in the kernel's spelling without touching its last part (a
    stale FUSE file answers every stat with ENOTCONN)."""
    p = os.path.abspath(str(path))
    return os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p))


def mounted(path: str) -> bool:
    want = _norm(path)
    return any(mp == want for mp, _t, _o in _proc_mounts())


def view_sources(path: str) -> Optional[list[str]]:
    """The files a live raw view reads, for the evidence guard to compare in
    the view's place (core.evidence_guard): qemu's FUSE export reports the
    current time as the view's mtime and ctime on every stat. Only for a
    mnt/<stem>/disk mounted once and served by exactly one
    qemu-storage-daemon of this user that exports it with writable false;
    None for anything else (a writable export, a second mount on top, a
    placeholder), which is compared as itself."""
    p = _norm(path)
    if os.path.basename(p) != VIEW_NAME or os.path.basename(os.path.dirname(os.path.dirname(p))) != "mnt":
        return None
    hits = [d for d in daemons() if d["mountpoint"] == p]
    if len(hits) != 1 or hits[0]["writable"] is not False:
        return None
    if [mp for mp, _t, _o in _proc_mounts()].count(p) != 1:
        return None
    return held_files(hits[0]["pid"]) or None


def held_files(pid: int, proc: str = "/proc") -> list[str]:
    """The regular files a process holds open."""
    fd_dir = f"{proc}/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return []
    out = set()
    for fd in fds:
        link = os.path.join(fd_dir, fd)
        try:
            if stat.S_ISREG(os.stat(link).st_mode):
                out.add(os.readlink(link))
        except OSError:
            continue
    return sorted(out)


def view_state(path: str) -> str:
    """"live", "stale" (in the mount table, answers no stat: its daemon
    died) or "absent". The mount table is the only truth: a stale view is
    neither a file nor a mount to os.path."""
    if not mounted(path):
        return "absent"
    try:
        return "live" if os.stat(path).st_size > 0 else "stale"
    except OSError:
        return "stale"


def _arg_json(value: str) -> dict:
    try:
        data = json.loads(value)
    except ValueError:
        data = dict(kv.split("=", 1) for kv in value.split(",") if "=" in kv)
    return data if isinstance(data, dict) else {}


def daemons(proc: str = "/proc") -> list[dict]:
    """This user's qemu-storage-daemon processes: pid, export mountpoint and
    the top file of the node they export, read from /proc. Found by their
    command line, so a daemon whose mount was taken away is found too."""
    out = []
    uid = os.getuid()
    try:
        pids = sorted((d for d in os.listdir(proc) if d.isdigit()), key=int)
    except OSError:
        return out
    for d in pids:
        try:
            if os.stat(f"{proc}/{d}").st_uid != uid:
                continue
            with open(f"{proc}/{d}/cmdline", "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        if not argv or os.path.basename(argv[0]) != "qemu-storage-daemon":
            continue
        mountpoint, source, writable = "", "", None
        for flag, value in zip(argv, argv[1:]):
            if flag == "--export":
                export = _arg_json(value)
                mountpoint = str(export.get("mountpoint") or "")
                writable = export.get("writable")
            elif flag == "--blockdev":
                node = _arg_json(value)
                f = node.get("file")
                source = str((f or {}).get("filename") if isinstance(f, dict) else node.get("file.filename") or "")
        if mountpoint:
            out.append({"pid": int(d), "mountpoint": _norm(mountpoint), "source": source, "writable": writable})
    return out


def _stop(pids: list[int]) -> None:
    """TERM (the daemon unmounts its export), KILL what outlives a short wait."""
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.monotonic() + _STOP_WAIT
    left = list(pids)
    while left and time.monotonic() < deadline:
        time.sleep(0.05)
        left = [p for p in left if _alive(p)]
    for pid in left:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    try:   # a zombie answers signal 0 until reaped
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def fuse_unmount(path: str) -> bool:
    """Unmount a FUSE mount of this user without root: plain, then lazy
    (a reader still holding it open). True when it left the mount table."""
    for args in (["-u"], ["-uz"]):
        try:
            subprocess.run(["fusermount3", *args, path], capture_output=True, timeout=30,
                           stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass
        if not mounted(path):
            return True
    return False


def stop_under(path: str, spare: frozenset[str] | set[str] = frozenset()) -> list[int]:
    """Stop every view daemon of this user whose export lies at or under
    ``path``, except the ones serving a spared path. Found by command line,
    not by the mount table: a daemon whose mount was unmounted from outside
    is still running and still holds the evidence open."""
    base = os.path.realpath(str(path)).rstrip(os.sep)
    kept = {_norm(s) for s in spare}
    pids = [d["pid"] for d in daemons()
            if (d["mountpoint"] == base or d["mountpoint"].startswith(base + os.sep))
            and d["mountpoint"] not in kept]
    _stop(pids)
    return pids


# ── one image's view ──────────────────────────────────────────────────────

def view_path(root: str | os.PathLike, entry: dict) -> str:
    from core.mount_plan import mount_dir_for
    return os.path.join(mount_dir_for(root, str(entry.get("path") or ""), entry), VIEW_NAME)


def _start(chain: list[dict], view: str) -> str:
    """Start the daemon; "" when it is up, else its error."""
    graph = node_graph(chain)
    graph["node-name"] = "top"
    export = {"type": "fuse", "id": "view", "node-name": "top", "mountpoint": view,
              "writable": False, "allow-other": "off"}
    argv = ["qemu-storage-daemon", "--daemonize", "--blockdev", json.dumps(graph),
            "--export", json.dumps(export)]
    # stderr to a file, not a pipe: the daemon keeps no pipe of ours open.
    with tempfile.TemporaryFile() as err:
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                               timeout=_START_TIMEOUT)
        except subprocess.TimeoutExpired:
            return f"qemu-storage-daemon did not start within {_START_TIMEOUT} s"
        except OSError as e:
            return f"qemu-storage-daemon could not run ({e})"
        err.seek(0)
        text = err.read().decode("utf-8", "replace")
    return "" if p.returncode == 0 else (_one_line(text) or f"qemu-storage-daemon exit {p.returncode}")


def _serving(view: str, source: str) -> Optional[int]:
    want = _norm(view)
    hits = [d for d in daemons() if d["mountpoint"] == want]
    return hits[0]["pid"] if len(hits) == 1 and hits[0]["source"] == source else None


def ensure(root: str | os.PathLike, entry: dict) -> tuple[Optional[str], str]:
    """The live view of a container's plan entry, started when it is not
    up, or (None, why there is none). Never raises: a failure is recorded
    on the entry and returned."""
    c = entry.get("container") or {}
    if not c.get("chain"):
        if c.get("no_views"):
            return None, f"{NO_HOST_VIEWS}: {c['no_views']}"
        return None, str(c.get("refused") or c.get("unsupported") or "")
    if not views_on():
        return None, "raw views are switched off (ATLAS_RAW_VIEWS)"
    why = host_support()
    if why:
        return None, f"{NO_HOST_VIEWS}: {why}"
    view = view_path(root, entry)
    source = c["chain"][0]["path"]
    if _reusable(entry, view, source):
        _clear_own_failure(root, entry)
        return view, ""
    try:
        os.makedirs(os.path.dirname(view), exist_ok=True)
        lock = os.open(os.path.join(os.path.dirname(view), LOCK_NAME), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as e:
        return None, _fail(root, entry, f"{START_FAILED}: its folder {os.path.dirname(view)} cannot be "
                                        f"prepared ({e.strerror or e})")
    try:
        # One reader at a time checks, stops, starts and records this view
        # (a run and a dashboard chat read one case at once); a reader that
        # waited here finds the view the first one started.
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _ensure_locked(root, entry, view, source)
    finally:
        os.close(lock)


def _reusable(entry: dict, view: str, source: str) -> bool:
    """The recorded view is up and its daemon is alive. The mount table and
    a stat are not enough: the kernel answers a stat from its FUSE attribute
    cache for about a second after the daemon died."""
    mr = entry.get("mount_result") or {}
    try:
        pid = int(mr.get("raw_view_pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    return (mr.get("raw_view") == view and mr.get("raw_view_source") == source and pid > 1
            and _alive(pid) and view_state(view) == "live")


def _ensure_locked(root, entry: dict, view: str, source: str) -> tuple[Optional[str], str]:
    try:
        from core.mount_plan import _container_entry
        current = _container_entry(root, str(entry.get("path") or ""))
    except Exception:  # noqa: BLE001 - the caller's copy of the entry stands
        current = None
    if current is not None:              # what another reader left in the plan
        entry.clear()
        entry.update(current)
    c = entry.get("container") or {}
    if not c.get("chain") or c["chain"][0]["path"] != source:
        return None, _fail(root, entry, f"{START_FAILED}: its plan entry changed while it was read; "
                                        "the next read takes the new one")
    if _reusable(entry, view, source):
        _clear_own_failure(root, entry)
        return view, ""
    if view_state(view) == "live":
        pid = _serving(view, source)
        if pid:
            _record(root, entry, view, source, pid)
            return view, ""
    # The files are checked again right before the daemon opens them: a
    # descriptor or header changed since the plan probed it could name a
    # file outside the folder that qemu reads at start.
    fresh = probe(source)
    fresh["v"] = c.get("v")
    if not _same_probe(fresh, c):
        entry["container"] = fresh
        try:
            from core.mount_plan import update_image
            update_image(root, str(entry.get("path") or ""), container=fresh)
        except Exception:  # noqa: BLE001
            pass
        if fresh.get("refused") or fresh.get("unsupported"):
            return None, _fail(root, entry, str(fresh.get("refused") or fresh.get("unsupported")))
        return None, _fail(root, entry, f"{START_FAILED}: its files changed since they were checked; "
                                        "the next read checks them again")
    try:
        _stop([d["pid"] for d in daemons() if d["mountpoint"] == _norm(view)])
        if mounted(view):
            fuse_unmount(view)
        with open(view, "ab"):
            pass
    except OSError as e:
        return None, _fail(root, entry, f"{START_FAILED}: its mountpoint {view} cannot be prepared "
                                        f"({e.strerror or e})")
    err = _start(c["chain"], view)
    pid = _serving(view, source) if view_state(view) == "live" else None
    if not pid:
        return None, _fail(root, entry, f"{START_FAILED}: {err or 'qemu-storage-daemon exported nothing'}")
    outside = opened_outside(pid, os.path.dirname(source))
    if outside:
        _stop([pid])
        if mounted(view):
            fuse_unmount(view)
        return None, _fail(root, entry, f"its daemon opened {outside}, which lies outside the image's "
                                        "folder")
    _record(root, entry, view, source, pid)
    return view, ""


_PROBE_KEYS = ("format", "chain", "parts", "files", "refused", "unsupported")


def _same_probe(a: dict, b: dict) -> bool:
    return all(a.get(k) == b.get(k) for k in _PROBE_KEYS)


def opened_outside(pid: int, top_dir: str, proc: str = "/proc") -> str:
    """A regular file or block device the daemon holds open outside the
    image's folder, or any socket it holds (a view daemon holds none: a
    socket is a connection a header made it open), "" when there is none:
    what it opened, read after the start, so no header can add a file or a
    connection the probe did not see."""
    base = os.path.realpath(top_dir).rstrip(os.sep) + os.sep
    fd_dir = f"{proc}/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return ""
    for fd in fds:
        link = os.path.join(fd_dir, fd)
        try:
            target = os.readlink(link)
            mode = os.stat(link).st_mode
        except OSError:
            continue
        if stat.S_ISSOCK(mode):
            return target
        # A file or a disk: a block device outside the folder is as outside
        # as a file (Atlas run as root, or a user in the disk group).
        if not (stat.S_ISREG(mode) or stat.S_ISBLK(mode)):
            continue
        if target.startswith("/memfd:"):
            continue
        if not os.path.realpath(target.removesuffix(" (deleted)")).startswith(base):
            return target
    return ""


def _clear_own_failure(root, entry: dict) -> None:
    """A view that is up undoes the access failure an earlier start of it
    recorded (another reader's, or this one's before a retry)."""
    if not (entry.get("opened_tool") == "raw_view" and entry.get("status") == "access_failed"):
        return
    keys = ("status", "access_error", "opened_tool", "opened_at")
    for key in keys:
        entry.pop(key, None)
    try:
        from core.mount_plan import update_image
        update_image(root, str(entry.get("path") or ""), drop=keys)
    except Exception:  # noqa: BLE001
        pass


def _record(root, entry: dict, view: str, source: str, pid: int) -> None:
    mr = dict(entry.get("mount_result") or {})
    mr.update(raw_view=view, raw_view_source=source, raw_view_pid=pid, raw_view_started=_utcnow())
    mr.pop("view_error", None)
    entry["mount_result"] = mr
    clear = entry.get("opened_tool") == "raw_view" and entry.get("status") == "access_failed"
    if clear:
        for key in ("status", "access_error", "opened_tool", "opened_at"):
            entry.pop(key, None)
    try:
        from core.mount_plan import update_image
        update_image(root, str(entry.get("path") or ""), mount_result=mr,
                     drop=("status", "access_error", "opened_tool", "opened_at") if clear else ())
    except Exception:  # noqa: BLE001 - the view stands; the plan catches up on the next build
        pass


def _fail(root, entry: dict, reason: str) -> str:
    mr = dict(entry.get("mount_result") or {})
    mr["view_error"] = reason
    entry["mount_result"] = mr
    try:
        from core.mount_plan import mark_image_access_failed, update_image
        update_image(root, str(entry.get("path") or ""), mount_result=mr)
        mark_image_access_failed(root, str(entry.get("path") or ""), error=reason, tool="raw_view")
    except Exception:  # noqa: BLE001
        pass
    return reason


def read_refusal(image: str, why: str) -> str:
    """What a reader tells the analyst about a container without a view,
    by cause: each cause has its own next step, so none is a condition the
    reader has to weigh."""
    if why.startswith(NO_HOST_VIEWS):
        return (f"{image} is a disk container the Sleuth Kit reads only as a raw image, and {why}. "
                "img.vmdk_export_raw copies it to a raw image the Sleuth Kit reads; the copy needs "
                "the disk's size in free space.")
    if why.startswith(START_FAILED):
        return (f"{image} cannot be read now: {why}. Run the read again; if it fails again, "
                "img.vmdk_export_raw copies the disk to a raw image (it needs the disk's size in "
                "free space).")
    return (f"{image} cannot be read: {why}. No tsk.* tool reads it, and a copy would read it the "
            "same way (img.vmdk_export_raw refuses it too). Next: try plaso on it (plaso reads some "
            "containers itself); if that fails too, mark the image blocked with this reason.")


# ── background jobs ───────────────────────────────────────────────────────

def views_named(case_dir: str | os.PathLike, texts: list[str]) -> dict[str, Any]:
    """The paths under the case's mnt/ a job's command or manifest names,
    and the raw views among them with the daemon serving each: a job keeps
    them through the run-end teardown and fails if a view it read died."""
    roots = {os.path.abspath(str(case_dir)), os.path.realpath(str(case_dir))}
    pattern = "|".join(re.escape(os.path.join(r, "mnt") + os.sep) for r in roots)
    paths = sorted({m.group(0) for t in texts
                    for m in re.finditer(f"(?:{pattern})" + r"[^\s\"',]+", str(t or ""))})
    running = daemons() if paths else []
    views = [{"path": p, "pid": d["pid"]} for p in paths for d in running if d["mountpoint"] == _norm(p)]
    return {"mnt_paths": paths, "raw_views": views}


def held_by_running_jobs(case_dir: str | os.PathLike) -> set[str]:
    """The mnt/ paths running background jobs of the case read."""
    held: set[str] = set()
    for meta_path in Path(case_dir).glob("analysis/jobs/*/meta.json"):
        job_dir = meta_path.parent
        if (job_dir / "exit_code").exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            pid = int(meta.get("supervisor_pid") or 0)
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().decode("utf-8", "replace")
        except (OSError, ValueError, TypeError):
            continue
        if pid > 1 and _alive(pid) and "tools.jobs_runner" in cmd and str(job_dir) in cmd:
            held.update(str(p) for p in meta.get("mnt_paths") or [])
    return held


def view_lost(meta: dict) -> str:
    """Why a finished job's output is incomplete: a raw view it read lost
    the daemon it had when the job started; "" when none did."""
    for v in meta.get("raw_views") or []:
        path, pid = str(v.get("path") or ""), v.get("pid")
        alive = [d["pid"] for d in daemons() if d["mountpoint"] == _norm(path)]
        if pid not in alive or view_state(path) != "live":
            return (f"the raw view {path} this job read stopped while it ran (its daemon {pid} is "
                    "gone), so its output is incomplete")
    return ""


# ── tools run as root ─────────────────────────────────────────────────────

_MOUNT_ADMIN = frozenset({"umount", "fusermount", "fusermount3"})


_ABS_IN_ARG = re.compile(r"/[^\s'\"]+")


def _arg_paths(arg: str, cwd: str) -> set[str]:
    """The paths an argument names, resolved as the kernel will: the
    argument itself (against the command's working directory) and every
    absolute path inside it (a glued option such as -i/path, --out=/path, a
    command string for sh -c). realpath is not strict, so a stale mount
    in the path does not raise."""
    found = set(_ABS_IN_ARG.findall(arg))
    if arg and not arg.startswith("-"):
        found.add(arg if os.path.isabs(arg) else os.path.join(cwd, arg))
    return {os.path.realpath(p) for p in found}


def sudo_refusal(argv: list[str], cwd: str | None = None) -> Optional[dict]:
    """A refusal for a command that will run as root and names a path on a
    FUSE mount of this user without allow_other (a raw view among them):
    root is refused there, so the tool would fail on its input."""
    if not argv or os.path.basename(str(argv[0])) in _MOUNT_ADMIN:
        return None
    uid = f"user_id={os.getuid()}"
    fuse = [mp for mp, fstype, opts in _proc_mounts()
            if fstype.startswith("fuse") and uid in opts and "allow_other" not in opts]
    if not fuse:
        return None
    here = cwd or os.getcwd()
    for arg in argv[1:]:
        for p in _arg_paths(str(arg), here):
            mp = next((m for m in fuse if p == m or p.startswith(m.rstrip(os.sep) + os.sep)), "")
            if mp:
                tok = p
                return {
                    "success": False, "gate": "sudo_reads_user_fuse", "failure_class": "gate_refusal",
                    "error": (
                        f"{os.path.basename(str(argv[0]))} runs as root, and root cannot read {tok}: it "
                        "lies on a FUSE mount this user serves (a raw view Atlas makes of a disk "
                        "container is one), which refuses every other user. Read the disk with the "
                        "tools that run without root: tsk.*, plaso, the contents index. A tool that "
                        "must run as root needs a file copy of the disk: img.vmdk_export_raw on the "
                        "container with force_reexport=True, when the case volume has room for it."),
                }
    return None
