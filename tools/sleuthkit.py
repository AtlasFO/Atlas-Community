"""The Sleuth Kit — filesystem navigation and timeline tools.

File-backed TSK reads (mmls/fsstat/fls/icat/…) do NOT need sudo: they open
image files via userspace I/O. Privilege belongs to mount/loop/carve tools
(ewf/imaging/carving). Wrappers historically forced needs_sudo=True for
FUSE ewf1 nodes, which contradicted playbook disk_open_policy ("prefer
tsk.mmls — no sudo") and blocked non-interactive hosts.
"""
import functools
import importlib.util
import inspect
import os
import re
import sys
from datetime import date, timedelta
from typing import Optional
from fastmcp import FastMCP
from core import (run, run_with_output_file, output_safe, DEFAULT_TIMEOUT,
                  VOL_TIMEOUT, PLASO_TIMEOUT, scale_timeout)
from core.paths import (assert_output_safe, MIN_THROUGHPUT_MB_S,
                        missing_program_result, program_argv, tool_program)

mcp = FastMCP("sleuthkit")

# Metadata-walking TSK ops (fsstat/fls/icat) read only a fraction of the
# image (MFT, bitmaps, one file's runs), so their budget scales with image
# size at ~10x the full-read throughput assumption: a 200 GB image on a
# network mount gets ~17 min instead of a fixed 600 s that provably
# times out there, without granting the multi-hour
# budget a full-read op would get.
_METADATA_THROUGHPUT_MB_S = max(MIN_THROUGHPUT_MB_S, 1) * 10


def _offset_args(image: str, offset_sectors: Optional[int]) -> list[str]:
    """``-o`` for the given offset, or for the offset remembered for this
    image when none was given (the volume a previous call succeeded on)."""
    if offset_sectors:
        return ["-o", str(offset_sectors)]
    try:
        from core.mount_plan import volume_offset
        from core.paths import active_case_dir
        known = volume_offset(active_case_dir(), image)
    except Exception:  # noqa: BLE001
        known = None
    return ["-o", str(known)] if known else []


def _note_volume(image: str, offset_sectors: Optional[int], res: dict) -> dict:
    """After a filesystem call: remember an offset that worked; on failure,
    point at the offset that worked before when the call named another, or
    else, when the address asked for is outside the filesystem's range, at
    finding the file by its path."""
    if not isinstance(res, dict):
        return res
    try:
        from core.mount_plan import note_volume_offset, volume_offset
        from core.paths import active_case_dir
        cd = active_case_dir()
        if cd and res.get("success") and offset_sectors:
            note_volume_offset(cd, image, int(offset_sectors))
        elif cd and not res.get("success") and offset_sectors:
            # A call that names no offset reads at the remembered one
            # (_offset_args), so only a named offset can be another volume.
            known = volume_offset(cd, image)
            if known and int(offset_sectors) != known:
                res["hint"] = (
                    f"the filesystem on this image was read successfully at "
                    f"offset_sectors={known} earlier; this call used "
                    f"{offset_sectors} — a different volume."
                )
    except Exception:  # noqa: BLE001
        pass
    if not res.get("success"):
        hint = _address_range_hint(res)
        if hint:
            res.setdefault("hint", hint)
    return res


# The Sleuth Kit's answer for a metadata address outside the filesystem's
# range: icat, istat, ffind and jcat name the range's last address ("too
# large") or its first ("too small"); fls reports the failed directory walk
# that every filesystem driver's range check produces.
_ADDRESS_RANGE_RE = re.compile(
    r"(?:Metadata address|Inode(?: value)?) (?:is )?too (large|small) for image \((\d+)\)")
_WALK_RANGE_RE = re.compile(r"Invalid walk range \([^)]*dir_open_meta\b")


def _address_range_hint(res: dict) -> Optional[str]:
    """What to do with an address this filesystem does not have. Addresses
    belong to one filesystem, so a number taken from a timeline, another
    image or another copy of the volume finds nothing here, or another file;
    the file's path in this image gives its address here. The action comes
    first: a failure latch quotes a hint's first 200 characters."""
    text = str(res.get("stderr") or res.get("error") or "")
    m = _ADDRESS_RANGE_RE.search(text)
    if m:
        bound = f" ({'last' if m.group(1) == 'large' else 'first'} address {m.group(2)})"
    elif _WALK_RANGE_RE.search(text):
        bound = ""
    else:
        return None
    return (f"metadata address outside this filesystem's range{bound}: find the file by "
            "its path in this image (tsk.resolve_path, or tsk.fls of its folder) and use "
            "the address it returns. Addresses belong to one filesystem: a number from a "
            "timeline, another image, another copy of this volume or another volume of "
            "this image (offset_sectors) does not apply here.")



def _metadata_timeout(image: str) -> int:
    return scale_timeout(VOL_TIMEOUT, image,
                         min_throughput_mb_s=_METADATA_THROUGHPUT_MB_S)


# ── The image argument ────────────────────────────────────────────────────
#
# The Sleuth Kit reads raw images; an Expert Witness container is readable
# only through the libewf image type, which this build may lack, and then
# TSK reports the compressed container as "possible encryption (high
# entropy)". The tools below therefore read an EWF image through the raw
# device ewfmount exposes when one is mounted, and say what to mount when
# none is. A filesystem tool given a whole-disk image without an offset
# finds the volume itself when the partition table names exactly one.

_MMLS_ROW_RE = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")
_NOT_A_VOLUME_RE = re.compile(r"(?i)\bmeta\b|unallocated|primary table|safety table|gpt header|extended|table")
_NO_FS_RE = re.compile(r"(?i)cannot determine file system type")


@functools.lru_cache(maxsize=1)
def tsk_image_types() -> frozenset[str]:
    """The image types this Sleuth Kit build reads (``mmls -i list``),
    probed once per process. A build with libewf lists ``ewf`` and reads an
    Expert Witness image without a mounted device; the distribution
    packages often list only ``raw``. The contents index and the readers
    below share this one probe, so the index never offers an image the
    readers would refuse."""
    try:
        import subprocess
        argv = program_argv("mmls") or ["mmls"]
        proc = subprocess.run([*argv, "-i", "list"], capture_output=True, text=True, timeout=20)
    except Exception:  # noqa: BLE001 - no Sleuth Kit: no native types
        return frozenset()
    text = f"{proc.stdout}\n{proc.stderr}"
    # The list prints one type per line, its name first ("raw (Single or
    # split raw file (dd))", "ewf (Expert Witness Format (EnCase))").
    return frozenset(m.group(1).lower() for m in re.finditer(r"(?m)^\s*([A-Za-z0-9_]+)\s+\(", text))


def _tsk_readable(image: str) -> tuple[str, Optional[dict]]:
    """``(image to read, refusal)``: an Expert Witness image is replaced by
    its mounted raw device, or read natively when this Sleuth Kit build
    reads EWF (``tsk_image_types``); when neither, the refusal names what
    to mount. A disk container (VMDK, VHD, VHDX, QCOW2, VDI), or the path of
    its raw view, is replaced by the live view (started when it is down);
    one without a view is refused with the reason. Anything else is read as
    given."""
    try:
        from core.mount_plan import (device_for_mount_point, ewf_device_for, is_ewf_image,
                                     raw_device_for)
        from core.paths import active_case_dir
    except Exception:  # noqa: BLE001
        return image, None
    if image and not is_ewf_image(image):
        view, why = raw_device_for(active_case_dir(), image)
        if view:
            return view, None
        if why:
            from core.raw_views import NO_HOST_VIEWS, START_FAILED, read_refusal
            refusal = {"success": False, "error": read_refusal(image, why), "image": image}
            if why.startswith((NO_HOST_VIEWS, START_FAILED)):
                refusal["gate"] = "image_format"          # this host, or now: no word on the image
            else:
                # The container itself is refused for good (its chain, its
                # type): this read failed on the image and counts as the
                # failed read the image can be blocked on.
                refusal["failure_class"] = "unsupported_format"
            return image, refusal
    if not image or not os.path.exists(image):
        return image, None
    if os.path.isdir(image):
        # A mounted filesystem directory is not an image: TSK reads the
        # device under it. The files themselves are readable in place.
        device = device_for_mount_point(active_case_dir(), image)
        if device:
            return device, None
        return image, {
            "success": False,
            "gate": "image_format",
            "error": (
                f"{image} is a directory (a mounted filesystem), not a disk image. "
                "Read its files in place (misc.list_evidence_dir, strings.*, table.*, "
                "the artifact parsers) or run this tool on the raw device the "
                "filesystem was mounted from - the mount plan names it - with the "
                "volume's offset_sectors from tsk.mmls."),
            "image": image,
        }
    if not is_ewf_image(image):
        return image, None
    device = ewf_device_for(active_case_dir(), image)
    if device:
        return device, None
    if "ewf" in tsk_image_types():
        return image, None
    return image, {
        "success": False,
        "gate": "image_format",
        "error": (
            f"{image} is an Expert Witness container; the Sleuth Kit reads raw images, so "
            "run it on the raw device ewfmount exposes: mount the image with "
            "ewf.ewf_mount(image, mount_point) (or ewf.mount_full_image for an NTFS "
            "volume) and pass <mount_point>/ewf1 as the image, with the volume's "
            "offset_sectors from tsk.mmls on that device. Not an encrypted volume: "
            "the container is compressed."),
        "image": image,
    }


def _single_volume_offset(image: str, timeout: int) -> tuple[Optional[int], list[str]]:
    """The start sector of the one filesystem volume a partition table
    names, or None with the volumes listed when there are several or none."""
    res = run(["mmls", image], needs_sudo=False, timeout=timeout)
    volumes: list[tuple[int, str]] = []
    for line in (res.get("stdout") or "").splitlines():
        m = _MMLS_ROW_RE.match(line)
        if m and not _NOT_A_VOLUME_RE.search(m.group(6)):
            volumes.append((int(m.group(3)), m.group(6).strip()))
    listed = [f"offset_sectors={start}: {desc}" for start, desc in volumes]
    return (volumes[0][0], listed) if len(volumes) == 1 else (None, listed)


def _reads_image(fn):
    """For a tool whose first argument is an image: read an EWF image through
    its raw device, and find the volume when the image has exactly one and
    the call named no offset."""
    names = list(inspect.signature(fn).parameters)
    # position of offset_sectors among the arguments after the image
    offset_at = names.index("offset_sectors") - 1 if "offset_sectors" in names else None

    def _offset_given(args, kwargs):
        if "offset_sectors" in kwargs:
            return kwargs["offset_sectors"]
        return args[offset_at] if offset_at is not None and len(args) > offset_at else None

    @functools.wraps(fn)
    def wrapper(image: str, *args, **kwargs):
        resolved, refusal = _tsk_readable(image)
        if refusal:
            return refusal
        res = fn(resolved, *args, **kwargs)
        # A tool may fold the program's stderr into its own "error".
        if (offset_at is not None and isinstance(res, dict) and not res.get("success")
                and _NO_FS_RE.search(str(res.get("stderr") or res.get("error") or ""))
                and not _offset_given(args, kwargs)):
            start, listed = _single_volume_offset(resolved, _metadata_timeout(resolved))
            if start is not None:
                args_l = list(args)
                if len(args_l) > offset_at:
                    args_l[offset_at] = start
                else:
                    kwargs["offset_sectors"] = start
                retry = fn(resolved, *args_l, **kwargs)
                if isinstance(retry, dict):
                    retry["offset_sectors_used"] = start
                res = retry
            elif listed:
                res["hint"] = ("the image has a partition table; name the volume: "
                               + "; ".join(listed))
        if resolved != image and isinstance(res, dict):
            res["image_resolved"] = {"from": image, "to": resolved}
        return res
    return wrapper


def _image_missing(image: str) -> dict | None:
    """A refusal that names the images this case has, when ``image`` is not
    a file on disk. A model that writes an export's name from memory gets
    the real names back instead of the library's stat error."""
    if not image or os.path.exists(image):
        return None
    known: list[str] = []
    try:
        from core.execution_log import log as _elog
        from core.mount_plan import load_mount_plan
        case = str(_elog.case_dir() or "")
        if case:
            for img in load_mount_plan(case).get("images") or []:
                path = str(img.get("path") or "")
                if path and os.path.isabs(path):
                    path = os.path.relpath(path, case)
                name = path or str(img.get("basename") or "")
                if name and name not in known:
                    known.append(name)
    except Exception:  # noqa: BLE001 - the refusal stands without the list
        pass
    return {
        "success": False,
        "gate": "image_not_found",
        "error": f"image not found: {image!r}. "
                 + (f"Images this case knows: {', '.join(known)}." if known
                    else "Discover the image path first (misc.list_evidence_dir)."),
    }


def _access_workflow_refuse(tool_name: str) -> dict | None:
    """Refuse deep disk / fls-streak while the winevt work order is pending."""
    try:
        from core.access_workflow import refuse_deep_disk_until_winevt
        from core.execution_log import log as _elog
        case_dir = None
        try:
            case_dir = _elog.case_dir()
        except Exception:
            case_dir = None
        refuse = refuse_deep_disk_until_winevt(case_dir, tool_name)
        if refuse:
            gate = (
                "access_disk_budget"
                if "access_disk_budget" in refuse
                else "access_work_order_pending"
            )
            return {
                "success": False,
                "gate": gate,
                "failure_class": "gate_refusal",
                "error": refuse,
            }
    except Exception:
        pass
    return None


@mcp.tool()
@output_safe
@_reads_image
def tsk_mmls(image: str) -> dict:
    """Display partition table (MBR and GPT) — get sector offsets for mounting.

    An image without a volume system (a superfloppy layout, a reformatted
    removable key) whose filesystem opens at its first sector is a normal
    answer, not a failure: the result then says so and the next step is
    tsk.fsstat / tsk.fls on the image itself, with no offset. When no
    filesystem opens there either, the result is a failure that says so.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    timeout = _metadata_timeout(image)
    res = run(["mmls", image], needs_sudo=False, timeout=timeout)
    if (res.get("success") or res.get("exit_code") != 1
            or str(res.get("stdout") or "").strip() or str(res.get("stderr") or "").strip()):
        return res
    # mmls exits 1 without a word both for a volume with no partition table
    # and for a file it cannot read at all; a filesystem at the first sector
    # tells the two apart (fsstat: a trace entry of its own, an open attempt).
    fs = run(["fsstat", image], needs_sudo=False, timeout=timeout)
    if fs.get("success"):
        m = re.search(r"File System Type:\s*(\S+)", str(fs.get("stdout") or ""))
        kind = f"a {m.group(1)} filesystem" if m else "a filesystem"
        return {**fs, "volume_system": "none", "stdout": (
            f"no partition table: the image holds no volume system, and {kind} opens at sector 0 "
            f"(fsstat, call {fs.get('_atlas_call_id')}). Read it with tsk.fls / tsk.fsstat / tsk.resolve_path "
            "on the image without offset_sectors.")}
    why = " ".join(str(fs.get("stderr") or fs.get("error") or "").split())[:200] or f"exit {fs.get('exit_code')}"
    return {**fs, "success": False, "error": (
        f"mmls finds no partition table, and no filesystem opens at sector 0 either (fsstat: {why}; call "
        f"{fs.get('_atlas_call_id')}). The Sleuth Kit cannot read this image as it is: it holds a layout The Sleuth "
        "Kit does not know (an encrypted volume, a logical volume manager, a container such as APFS), a format "
        "this build cannot open, or damage. Look at its first sectors (strings.hexdump), try a reader of that "
        "format, or mark the image blocked with this reason.")}


@mcp.tool()
@output_safe
@_reads_image
def tsk_fsstat(image: str, offset_sectors: Optional[int] = None) -> dict:
    """
    Filesystem metadata: NTFS version, cluster size, MFT offset, volume ID.
    offset_sectors: sector offset from mmls output (required for partitioned images).
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["fsstat"]
    cmd += _offset_args(image, offset_sectors)
    cmd.append(image)
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=_metadata_timeout(image)))


@mcp.tool()
@output_safe
@_reads_image
def tsk_fls(
    image: str,
    offset_sectors: Optional[int] = None,
    inode: Optional[int] = None,
    recursive: bool = True,
    deleted_only: bool = False,
    bodyfile: bool = False,
) -> dict:
    """
    List files and directories in a disk image, including deleted entries (marked *).
    offset_sectors: from mmls output.
    inode: list a specific directory by inode number; omit it for the root
        directory (on NTFS the root is inode 5 — inode 2 is $LogFile and
        0 is $MFT, neither lists anything).
    recursive: recurse into subdirectories.
    bodyfile: output in mactime bodyfile format for timeline creation.
    deleted_only: show only deleted entries.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    blocked = _access_workflow_refuse("tsk.fls")
    if blocked:
        return blocked
    cmd = ["fls"]
    if recursive:
        cmd.append("-r")
    if bodyfile:
        cmd += ["-m", "/"]
    if deleted_only:
        cmd.append("-d")
    cmd += _offset_args(image, offset_sectors)
    cmd.append(image)
    if inode is not None:
        cmd.append(str(inode))
    res = _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=_metadata_timeout(image)))
    return _spill_as_summary(res, image, bodyfile)


# A spilled listing's summary, by spill path and size: parsing a large
# spill again for the same call output is the cost this saves.
_SPILL_SUMMARIES: dict[tuple, list[str]] = {}


def _spill_as_summary(res: dict, image: str, bodyfile: bool) -> dict:
    """A listing cut at the output cap comes back as the directory summary
    of the whole spill (ATLAS_LISTING_SHAPE) instead of its first lines;
    the spill path stays in the result for paging."""
    spill = str((res or {}).get("stdout_file") or "")
    if not (res.get("truncated") and spill and os.path.isfile(spill)):
        return res
    from core.contents_index import directory_summary, listing_shape_on, parse_bodyfile, summary_lines
    if not listing_shape_on():
        return res
    try:
        key = (spill, os.path.getsize(spill))
        lines = _SPILL_SUMMARIES.get(key)
        if lines is None:
            with open(spill, "r", encoding="utf-8", errors="replace") as fh:
                entries = parse_bodyfile(fh) if bodyfile else _fls_entries(fh)
            for e in entries:
                e.setdefault("image", image)
            shape = directory_summary(entries)
            lines = [f"{shape['total_files']:,} files in {shape['total_dirs']:,} directories "
                     "(the whole listing, summarised)"] + summary_lines(shape)
            while len(_SPILL_SUMMARIES) >= 64:
                _SPILL_SUMMARIES.pop(next(iter(_SPILL_SUMMARIES)))
            _SPILL_SUMMARIES[key] = lines
    except (OSError, ValueError):
        return res
    out = dict(res)
    out["stdout"] = "\n".join(lines)
    out["listing_summary"] = True
    out["note"] = (f"The listing was longer than the output cap: above is one line per directory of the whole "
                   f"listing; the full listing is at {spill}.")
    return out


def _fls_entries(lines) -> list[dict]:
    """``fls -r`` lines (depth as leading '+') as entries with full paths."""
    stack: list[str] = []
    out: list[dict] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        depth = len(line) - len(line.lstrip("+"))
        m = _FLS_LINE_RE.match(line.lstrip("+ ").strip())
        if not m:
            continue
        typ, deleted, _meta, _attr, _seq, name = m.groups()
        name = name.strip()
        del stack[depth:]
        path = "/".join([*stack, name])
        if typ.startswith("d") or typ.endswith("d"):
            stack.append(name)
            out.append({"path": path, "is_dir": 1})
        else:
            out.append({"path": path, "is_dir": 0, "deleted": bool(deleted)})
    return out


@mcp.tool()
@_reads_image
def tsk_resolve_path(
    image: str,
    fs_path: str,
    offset_sectors: Optional[int] = None,
    root_inode: Optional[int] = None,
) -> dict:
    """
    Resolve a path *inside* a disk image to its inode by walking the
    directories one level at a time (case-insensitive), e.g.
    fs_path="Windows/System32/winevt/Logs". Returns the inode of the final
    component and, for a directory, its listing — the navigation step the
    access workflow asks for before tsk.icat / ez.evtxecmd, and one that
    never counts as a whole-tree enumeration.
    offset_sectors: from mmls output.
    root_inode: start directory (default: the filesystem root).
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    parts = [c for c in str(fs_path or "").replace("\\", "/").split("/") if c and c != "."]
    if not parts:
        return {"success": False, "error": "fs_path is empty"}
    current: Optional[int] = root_inode
    walked: list[dict] = []
    for depth, name in enumerate(parts):
        cmd = ["fls"]
        cmd += _offset_args(image, offset_sectors)
        cmd.append(image)
        if current is not None:
            cmd.append(str(current))
        entries = _listing(image, offset_sectors, current)
        if entries is None:
            res = run(cmd, needs_sudo=False, timeout=_metadata_timeout(image))
            if not res.get("success"):
                return _note_volume(image, offset_sectors, {
                    "success": False, "error": res.get("stderr") or "fls failed",
                    "stderr": res.get("stderr") or "", "walked": walked,
                    "cmd": " ".join(cmd)})
            entries = _remember_listing(image, offset_sectors, current,
                                        _parse_fls(_full_stdout(res)))
        hit = next((e for e in entries if e["name"].casefold() == name.casefold()), None)
        if hit is None:
            near = [e["name"] for e in entries
                    if name.casefold()[:3] in e["name"].casefold()][:10]
            # A component that is not there is the lookup's answer, not a
            # failure of the lookup: the gate says so to the failure latch.
            return {"success": False, "gate": "path_not_found",
                    "resolved": "/".join(parts[:depth]),
                    "missing": name, "walked": walked,
                    "siblings": [e["name"] for e in entries][:40], "near": near,
                    "error": f"{name!r} not found under {'/'.join(parts[:depth]) or '/'}"}
        walked.append({"name": hit["name"], "inode": hit["inode"], "type": hit["type"],
                       "deleted": hit["deleted"]})
        current = hit["meta"]
    last = walked[-1]
    out = {"success": True, "path": "/".join(w["name"] for w in walked),
           "inode": last["inode"], "meta_addr": current, "type": last["type"],
           "deleted": last["deleted"], "walked": walked}
    if last["type"].startswith("d"):
        entries = _listing(image, offset_sectors, current)
        if entries is None:
            cmd = ["fls"] + _offset_args(image, offset_sectors) + [image, str(current)]
            res = run(cmd, needs_sudo=False, timeout=_metadata_timeout(image))
            if res.get("success"):
                entries = _remember_listing(image, offset_sectors, current,
                                            _parse_fls(_full_stdout(res)))
        if entries is not None:
            out["entries"] = entries[:400]
    return _note_volume(image, offset_sectors, out)


@mcp.tool()
def tsk_index_find(
    pattern: str = "",
    host: str = "",
    image: str = "",
    under: str = "",
    state: str = "",
    limit: int = 40,
    offset: int = 0,
    summary: Optional[bool] = None,
) -> dict:
    """
    Find files inside the case's disk images in the contents index built
    at intake (every image listed once with fls), without running fls.
    pattern: case-insensitive substring or glob over the path inside the
        image, e.g. "sysmon" or "*.evtx".
    host: a host label.
    image: an image path (for an image no host is linked to, or one image of
        a host).
    under: a directory prefix inside the image.
    state: unread, partial (timeline rows shown), read or skipped (no
        export covers it).
    Each row gives the image, the path inside it, size, times, the inode
    and the export rows that cover it; total is exact, offset pages.
    summary: when more files match than limit, the result is one line per
        directory (file count, extensions, oldest and newest time, examples,
        a handle) instead of a cut row list; true always, false never.
    Answers "does this host's image hold a file like this?" in one call.
    """
    from core.contents_index import _public_row, find, index_on
    from core.paths import active_case_dir
    if not index_on():
        return {"success": False, "error": "the contents index is off in this run (ATLAS_CONTENTS_INDEX)"}
    for name, value in (("host", host), ("image", image)):
        if "::" in str(value or ""):
            # A handle is what a parser reads, not a place to search.
            return {"success": False, "gate": "handle_in_search",
                    "error": (f"{name} holds an image handle ({value}); pass the handle as the file argument "
                              "of a parser to read that file, or the image path alone "
                              f"(image=\"{str(value).split('::', 1)[0]}\") to search inside it here")}
    if state and state not in ("unread", "partial", "read", "skipped"):
        return {"success": False, "error": "state must be one of unread, partial, read, skipped"}
    case = active_case_dir()
    if not case:
        return {"success": False, "error": "no active case"}
    limit = max(1, min(int(limit or 40), 200))
    offset = max(0, int(offset or 0))
    from core.contents_index import directory_summary, find_summary, listing_shape_on, summary_lines
    # A first page over the limit gets the summary; a later page (offset)
    # is rows, as asked.
    shape_wanted = summary is not False and listing_shape_on() and (summary or not offset)
    if state and shape_wanted:
        # The read state comes from the trace, not the table, so the state
        # filter reads every candidate row once: one pass serves the count,
        # the page and the summary.
        every = find(case, pattern=pattern, host=image or host, under=under, state=state,
                     limit=1 << 62, offset=0)
        res = {"total": every["total"], "rows": every["rows"][offset:offset + limit]}
    else:
        every = None
        res = find(case, pattern=pattern, host=image or host, under=under, state=state, limit=limit,
                   offset=offset)
    if shape_wanted and (summary or res["total"] > limit) and res["total"]:
        # The shape of the matches instead of a cut row list: a directory
        # per line, drilled into with under=.
        if every is not None:
            shape = directory_summary(every["rows"])
        else:
            shape = find_summary(case, pattern=pattern, host=image or host, under=under)
        return {"success": True, "host": image or host, "pattern": pattern, "total": res["total"],
                "summary": summary_lines(shape), "total_dirs": shape["total_dirs"],
                "note": ("One line per directory. List one directory's files with under=<directory> "
                         "(and host=), or pass summary=false for rows; a handle is the file argument "
                         "of a parser.")}
    out = {"success": True, "host": image or host, "pattern": pattern, "total": res["total"],
           "offset": offset, "rows": [_public_row(r) for r in res["rows"]]}
    if not res["total"]:
        from core.contents_index import failed_images, listed_images
        out["listed_images"] = len(listed_images(case))
        failed = failed_images(case)
        if failed:
            out["not_listed"] = [f"{img}: {why}" for img, why in failed[:10]]
    elif res["total"] > offset + len(out["rows"]):
        out["next_offset"] = offset + len(out["rows"])
    from core.contents_index import image_handles_on
    out["note"] = ("Pass a handle as the file argument of any parser; the file is extracted first."
                   if image_handles_on() else
                   "Extract a file with tsk.icat(image, inode, output_path) and parse the copy.")
    return out


# Directory listings read while resolving paths, by image, offset and
# directory. An image does not change while a run reads it, so a walk that
# starts at the root again lists the root from here instead of running fls
# and logging the same listing once more. Bounded; oldest entries leave.
_LISTINGS: dict[tuple, list[dict]] = {}
_LISTINGS_MAX = 4096


def _listing_key(image: str, offset_sectors, inode) -> Optional[tuple]:
    try:
        st = os.stat(image)
    except OSError:
        return None
    return (os.path.realpath(image), st.st_size, st.st_mtime_ns,
            None if offset_sectors is None else int(offset_sectors),
            None if inode is None else int(inode))


def _listing(image: str, offset_sectors, inode) -> Optional[list[dict]]:
    key = _listing_key(image, offset_sectors, inode)
    return None if key is None else _LISTINGS.get(key)


def _remember_listing(image: str, offset_sectors, inode, entries: list[dict]) -> list[dict]:
    key = _listing_key(image, offset_sectors, inode)
    if key is not None:
        while len(_LISTINGS) >= _LISTINGS_MAX:
            _LISTINGS.pop(next(iter(_LISTINGS)))
        _LISTINGS[key] = entries
    return entries


def _full_stdout(res: dict) -> str:
    """The whole output of a call: the executor keeps only a capped preview
    in ``stdout`` and spills the rest to ``stdout_file``. Walking a directory
    of a few thousand entries on the preview alone reported ``winevt`` as
    missing under System32."""
    spill = res.get("stdout_file") or ""
    if spill and os.path.isfile(spill):
        try:
            with open(spill, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            pass
    return res.get("stdout") or ""


_FLS_LINE_RE = re.compile(r"^([-a-z]/[-a-z])\s+(\*\s+)?(\d+)(?:-(\d+)-(\d+))?:\s+(.*)$")


def _parse_fls(stdout: str) -> list[dict]:
    """``r/r 1234-128-1: name`` / ``d/d * 39-144-1: name`` → dicts."""
    out: list[dict] = []
    for line in (stdout or "").splitlines():
        m = _FLS_LINE_RE.match(line.strip())
        if not m:
            continue
        typ, deleted, meta, _attr, _seq, name = m.groups()
        out.append({"type": typ, "deleted": bool(deleted), "meta": int(meta),
                    "inode": line.strip().split(":", 1)[0].split()[-1],
                    "name": name.strip()})
    return out


@mcp.tool()
@output_safe
@_reads_image
def tsk_istat(image: str, inode: int, offset_sectors: Optional[int] = None) -> dict:
    """
    Display inode metadata: MAC times, size, allocated blocks, file type.
    offset_sectors: from mmls output.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["istat"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(inode)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


@mcp.tool()
@output_safe
@_reads_image
def tsk_icat(
    image: str,
    inode: str,
    output_path: str,
    offset_sectors: Optional[int] = None,
    recover_deleted: bool = False,
    slack_space: bool = False,
) -> dict:
    """
    Extract file content by inode number to output_path.
    inode: can be a number or 'number-stream-id' for ADS (e.g. '11-128-4').
    recover_deleted: attempt recovery of deleted file data.
    slack_space: extract file slack space.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["icat"]
    if recover_deleted:
        cmd.append("-r")
    if slack_space:
        cmd.append("-s")
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(inode)]
    return _note_volume(image, offset_sectors, run_with_output_file(
        cmd, output_path=output_path, mode="wb",
        timeout=_metadata_timeout(image), needs_sudo=False,
    ))


@mcp.tool()
@output_safe
@_reads_image
def tsk_ils(
    image: str,
    offset_sectors: Optional[int] = None,
    orphan_only: bool = False,
    unallocated_only: bool = False,
    allocated_only: bool = False,
) -> dict:
    """
    List inodes in a filesystem.
    orphan_only: unlinked inodes (deleted files with no directory entry).
    unallocated_only: only unallocated inodes.
    allocated_only: only allocated inodes.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["ils"]
    if orphan_only:
        cmd.append("-p")
    elif unallocated_only:
        cmd.append("-A")
    elif allocated_only:
        cmd.append("-a")
    cmd += _offset_args(image, offset_sectors)
    cmd.append(image)
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=DEFAULT_TIMEOUT))


@mcp.tool()
@output_safe
@_reads_image
def tsk_ffind(image: str, inode: int, offset_sectors: Optional[int] = None) -> dict:
    """Find the filename(s) for a given inode number."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["ffind"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(inode)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


@mcp.tool()
@output_safe
@_reads_image
def tsk_blkls(
    image: str,
    output_path: str,
    offset_sectors: Optional[int] = None,
    unallocated_only: bool = True,
) -> dict:
    """
    Extract raw disk blocks for carving.
    unallocated_only: extract only unallocated blocks (default — for carving).
    output_path: destination file for raw block data.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["blkls"]
    if unallocated_only:
        cmd.append("-A")
    cmd += _offset_args(image, offset_sectors)
    cmd.append(image)
    return run_with_output_file(
        cmd, output_path=output_path, mode="wb",
        timeout=scale_timeout(VOL_TIMEOUT, image), needs_sudo=False,
    )


@mcp.tool()
@output_safe
@_reads_image
def tsk_recover(
    image: str,
    output_dir: str,
    offset_sectors: Optional[int] = None,
    include_unallocated: bool = False,
    dir_inode: Optional[int] = None,
    whole_volume: bool = False,
) -> dict:
    """
    Extract the files of one directory tree from a disk image.
    dir_inode: the directory to extract (from tsk.resolve_path / tsk.fls);
        its subtree is written under output_dir with paths preserved.
    whole_volume: extract every file of the volume instead — an operation
        of minutes to hours that writes the whole volume to output_dir; it
        has to be requested explicitly.
    include_unallocated: also recover deleted/unallocated files.
    Single files: tsk.icat.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    if dir_inode is None and not whole_volume:
        return {
            "success": False,
            "gate": "recover_scope",
            "failure_class": "gate_refusal",
            "error": (
                "tsk_recover without dir_inode extracts EVERY file of the "
                "volume (minutes to hours, the volume's size on disk). Pass "
                "dir_inode=<directory inode from tsk.resolve_path or tsk.fls> "
                "to extract one directory tree, tsk.icat for a single file, "
                "or whole_volume=True if the full extraction is intended."
            ),
        }
    cmd = ["tsk_recover"]
    if include_unallocated:
        cmd.append("-e")
    else:
        cmd.append("-a")
    cmd += _offset_args(image, offset_sectors)
    if dir_inode is not None:
        cmd += ["-d", str(dir_inode)]
    cmd += [image, output_dir]
    return run(cmd, needs_sudo=False,
               timeout=scale_timeout(VOL_TIMEOUT*3, image), output_dir=output_dir)


@mcp.tool()
@output_safe
def tsk_mactime(
    bodyfile: str,
    output_path: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    csv_output: bool = True,
) -> dict:
    """
    Generate a MAC timeline from a bodyfile (output of fls -m).
    start_date / end_date: filter to a date range, format YYYY-MM-DD.
    csv_output: produce comma-separated output (easier for analysis).
    """
    from core.input_kind import refuse_non_bodyfile
    refusal = refuse_non_bodyfile(bodyfile)
    if refusal:
        return refusal
    cmd = ["mactime", "-b", bodyfile, "-z", "UTC"]
    if csv_output:
        cmd.append("-d")
    if start_date:
        cmd.append(start_date)
    if end_date:
        cmd.append(end_date)
    if output_path:
        return run_with_output_file(
            cmd, output_path=output_path, mode="w", timeout=VOL_TIMEOUT,
        )
    return run(cmd, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
@_reads_image
def tsk_blkcat(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Extract raw content of a specific data block."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["blkcat"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(block_number)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


@mcp.tool()
@output_safe
@_reads_image
def tsk_blkstat(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Display statistics on a specific data block (allocation status, containing file)."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["blkstat"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(block_number)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


@mcp.tool()
@output_safe
@_reads_image
def tsk_blkcalc(image: str, block_number: int, offset_sectors: Optional[int] = None) -> dict:
    """Convert between disk and image block addresses."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["blkcalc"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(block_number)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


@mcp.tool()
@output_safe
@_reads_image
def tsk_mmcat(image: str, partition_slot: int) -> dict:
    """Output the contents of a partition slot (raw partition data)."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    return run(["mmcat", image, str(partition_slot)], needs_sudo=False)


@mcp.tool()
@output_safe
@_reads_image
def tsk_mmstat(image: str) -> dict:
    """Display statistics about the volume system (disk layout metadata)."""
    _missing = _image_missing(image)
    if _missing:
        return _missing
    return run(["mmstat", image], needs_sudo=False)


@mcp.tool()
@output_safe
def tsk_hfind(
    hash_db: str,
    hash_value: str,
    lookup_type: str = "md5",
) -> dict:
    """
    Look up a file hash in a hash database (NSRL, hashkeeper, md5sum format).
    hash_db: path to the hash database file.
    hash_value: the hash to look up.
    lookup_type: 'md5', 'sha1', 'nsrl-md5', 'nsrl-sha1'.
    """
    return run(["hfind", "-f", lookup_type, hash_db, hash_value])


@mcp.tool()
@output_safe
@_reads_image
def tsk_sigfind(image: str, signature_hex: str, offset_sectors: Optional[int] = None) -> dict:
    """
    Find a hex byte signature in a disk image.
    signature_hex: hex string to search for e.g. 'MZ' header = '4D5A'.
    Useful for locating hidden PE files or deleted MBR signatures.

    Sleuthkit CLI order is ``sigfind [opts] <hex_signature> <image>``.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    blocked = _access_workflow_refuse("tsk.sigfind")
    if blocked:
        return blocked
    cmd = ["sigfind"]
    cmd += _offset_args(image, offset_sectors)
    # Hex signature BEFORE image — swapped args made sigfind treat
    # ``analysis/...`` as the signature (first invalid hex digit → ``n``).
    cmd += [signature_hex, image]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=scale_timeout(VOL_TIMEOUT, image)))


@mcp.tool()
@output_safe
@_reads_image
def tsk_sorter(
    image: str,
    output_dir: str,
    offset_sectors: Optional[int] = None,
    category: Optional[str] = None,
) -> dict:
    """
    Sort files from a disk image into categories based on file type.
    output_dir: destination for sorted file categories.
    category: limit to a specific category e.g. 'images', 'exec', 'audio', 'documents'.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["sorter", "-d", output_dir]
    cmd += _offset_args(image, offset_sectors)
    if category:
        cmd += ["-s", category]
    cmd.append(image)
    return run(cmd, needs_sudo=False,
               timeout=scale_timeout(VOL_TIMEOUT, image), output_dir=output_dir)


@mcp.tool()
@output_safe
@_reads_image
def tsk_jls(image: str, offset_sectors: Optional[int] = None) -> dict:
    """
    List journal entries from an ext3/ext4 filesystem.
    Useful for recovering deleted files on Linux disk images.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["jls"]
    cmd += _offset_args(image, offset_sectors)
    cmd.append(image)
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=DEFAULT_TIMEOUT))


@mcp.tool()
@output_safe
@_reads_image
def tsk_jcat(image: str, journal_inode: int, offset_sectors: Optional[int] = None) -> dict:
    """
    Output the contents of an ext3/ext4 journal entry by inode number.
    Use after tsk_jls to inspect a specific journal block.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    cmd = ["jcat"]
    cmd += _offset_args(image, offset_sectors)
    cmd += [image, str(journal_inode)]
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False))


# INDXParse lists a slack entry only when its four timestamps fall inside a
# validity window; the pinned release closes it at a fixed date (its
# NTATTR_DIRECTORY_INDEX_SLACK_ENTRY.is_valid). The runner moves the upper
# bound to a year past the day of the call, when it can import the package.
_INDX_STOCK_WINDOW = ("1990-01-01", "2024-01-01")
_INDX_RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_indxparse_window.py")


@mcp.tool()
@output_safe
def tsk_indxparse(index_path: str, output_path: Optional[str] = None) -> dict:
    """
    Parse a directory's NTFS index ($I30 INDX records) with INDXParse.py and
    recover the entries left in its slack: files the directory once listed
    that were deleted or renamed, which MFTECmd and Vol3 miss.

    index_path: the directory's $I30 index allocation stream, extracted from
        the image with tsk.icat <image> '<dir-inode>-160' (and the volume's
        offset_sectors) into analysis/. Not the $MFT: deleted MFT records are
        ez.mftecmd's job.
    output_path: optional output destination (analysis/exports/reports).
    """
    blocked = _access_workflow_refuse("tsk.indxparse")
    if blocked:
        return blocked
    prog = tool_program("INDXParse.py")
    if not prog:
        return missing_program_result(
            "tsk.tsk_indxparse", "INDXParse.py",
            "installed by install.sh (pip into the venv, pinned in install-versions.env)")
    # On a remote SIFT host the file and the program are over there: this
    # process can neither read the one nor patch the other.
    from core import remote as _remote
    local = not _remote.is_enabled()
    from core.input_kind import refuse_non_indx
    wrong = refuse_non_indx(index_path) if local else None
    if wrong:
        return wrong
    # INDXParse.py [-c | -b] [-d] [-v] [-t {dir,sdh,sii}] filename:
    # -d adds the entries found in slack space; the input is positional.
    if local and importlib.util.find_spec("indxparse") is not None:
        window = (_INDX_STOCK_WINDOW[0], (date.today() + timedelta(days=365)).isoformat())
        cmd = [sys.executable, _INDX_RUNNER, window[1], "-d", index_path]
    else:
        window = _INDX_STOCK_WINDOW
        cmd = [*program_argv(prog), "-d", index_path]
    result = run(cmd, timeout=600)
    if result.get("success"):
        result["slack_window"] = {"from": window[0], "to": window[1]}
        result["coverage_note"] = (
            f"Slack entries are listed only when all four of their timestamps fall between "
            f"{window[0]} and {window[1]}; a deletion stamped outside that window is not "
            "listed, so a name missing here is no evidence that it never existed.")
    if output_path and result.get("success") and result.get("stdout"):
        try:
            with open(output_path, "w") as f:
                f.write(result["stdout"])
            result["output_path"] = output_path
        except OSError as e:
            result["write_error"] = str(e)
    return result
