"""The Sleuth Kit — filesystem navigation and timeline tools.

File-backed TSK reads (mmls/fsstat/fls/icat/…) do NOT need sudo: they open
image files via userspace I/O. Privilege belongs to mount/loop/carve tools
(ewf/imaging/carving). Wrappers historically forced needs_sudo=True for
FUSE ewf1 nodes, which contradicted playbook disk_open_policy ("prefer
tsk.mmls — no sudo") and blocked non-interactive hosts.
"""
import functools
import inspect
import os
import re
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
    point at the offset that worked before when the call used another."""
    try:
        from core.mount_plan import note_volume_offset, volume_offset
        from core.paths import active_case_dir
        cd = active_case_dir()
        if not cd or not isinstance(res, dict):
            return res
        if res.get("success") and offset_sectors:
            note_volume_offset(cd, image, int(offset_sectors))
        elif not res.get("success"):
            known = volume_offset(cd, image)
            if known and int(offset_sectors or 0) != known:
                res["hint"] = (
                    f"the filesystem on this image was read successfully at "
                    f"offset_sectors={known} earlier; this call used "
                    f"{offset_sectors or 'no offset'} — a different volume."
                )
    except Exception:  # noqa: BLE001
        pass
    return res



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


def _tsk_readable(image: str) -> tuple[str, Optional[dict]]:
    """``(image to read, refusal)``: an Expert Witness image is replaced by
    its mounted raw device; when none exposes it the refusal names what to
    mount. Anything else is read as given."""
    try:
        from core.mount_plan import device_for_mount_point, ewf_device_for, is_ewf_image
        from core.paths import active_case_dir
    except Exception:  # noqa: BLE001
        return image, None
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
        if (offset_at is not None and isinstance(res, dict) and not res.get("success")
                and _NO_FS_RE.search(str(res.get("stderr") or ""))
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
    """B6/I3: refuse deep disk / fls-streak while winevt work-order pending."""
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
    removable key) is a normal answer, not a failure: the result then says
    so and the next step is tsk.fsstat / tsk.fls on the image itself, with
    no offset.
    """
    _missing = _image_missing(image)
    if _missing:
        return _missing
    return run(["mmls", image], needs_sudo=False,
               timeout=_metadata_timeout(image))


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
    return _note_volume(image, offset_sectors, run(cmd, needs_sudo=False, timeout=_metadata_timeout(image)))


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
                return {"success": False, "error": res.get("stderr") or "fls failed",
                        "walked": walked, "cmd": " ".join(cmd)}
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
    return run_with_output_file(
        cmd, output_path=output_path, mode="wb",
        timeout=_metadata_timeout(image), needs_sudo=False,
    )


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


@mcp.tool()
@output_safe
def tsk_indxparse(mft_path: str, output_path: Optional[str] = None) -> dict:
    """
    Parse NTFS $INDX records (directory index slack) using INDXParse.py.
    Recovers deleted directory entries that MFTECmd and Vol3 miss.

    mft_path: path to the $MFT file (or any file containing $INDX records).
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
    # INDXParse.py [-c | -b] [-d] [-v] [-t {dir,sdh,sii}] filename:
    # -d adds the entries found in slack space; the input is positional.
    cmd = [*program_argv(prog), "-d", mft_path]
    result = run(cmd, timeout=600)
    if output_path and result.get("success") and result.get("stdout"):
        try:
            with open(output_path, "w") as f:
                f.write(result["stdout"])
            result["output_path"] = output_path
        except OSError as e:
            result["write_error"] = str(e)
    return result
