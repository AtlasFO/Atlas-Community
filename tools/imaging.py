"""Image mounting tools — vshadowmount, xmount, bdemount, photorec, VMDK."""
import json
import math
import os
import shutil
import tempfile
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe, ensure_mount_point, VOL_TIMEOUT
from core.paths import assert_output_safe

mcp = FastMCP("imaging")


# ── VMware VMDK snapshot chains ───────────────────────────────────────────────

@mcp.tool()
@output_safe
def vmdk_chain_info(path: str) -> dict:
    """Report the VMware snapshot chain for a .vmdk file or a VM directory.

    RUN THIS FIRST for any VMDK evidence, before mmls/fls/mounting. When
    snapshot deltas (X-000001.vmdk, …) exist, the base/-flat extent is
    FROZEN at the moment the first snapshot was taken — all later disk
    writes live only in the delta chain, so analyzing the flat extent
    silently shows an old system state. The result names the chain-top
    descriptor to analyze (`analysis_targets[].recommended_descriptor`),
    snapshot names/creation dates from the .vmsd, and the disk the .vmx
    actually attaches. Cheap even on network storage: reads descriptor
    text and stat() only, never extent data.
    """
    p = os.path.abspath(os.path.expanduser(path))
    is_file = not os.path.isdir(p)
    directory = os.path.dirname(p) if is_file else p
    from core.vmdk import analyze_vm_dir
    result = analyze_vm_dir(directory)
    # The report covers every descriptor in the directory, so say so: on a
    # case with two images the model called this once per disk and got the
    # same answer twice.
    result["scope"] = "directory"
    result["scope_note"] = (
        f"Every VMDK in {directory} is reported below — one call covers the "
        "whole directory, a sibling disk needs no second call."
    )
    # Corroborate with qemu-img (the chain-aware reader on this box);
    # best-effort — descriptor parsing above is the source of truth.
    try:
        targets = result.get("analysis_targets") or []
        chosen = None
        if is_file:
            # Corroborate the disk that was asked about. Keyed to
            # analysis_targets[0] this returned the *first* disk in the
            # directory whatever the caller named, so asking about disk B
            # produced disk A's chain under a generic key.
            for t in targets:
                desc = str(t.get("recommended_descriptor") or "")
                if desc and (os.path.abspath(desc) == p
                             or os.path.basename(desc) == os.path.basename(p)):
                    chosen = t
                    break
        chosen = chosen or (targets[0] if targets else None)
        if result.get("success") and chosen and shutil.which("qemu-img"):
            descriptor = chosen["recommended_descriptor"]
            q = run(["qemu-img", "info", "--backing-chain", "--output=json",
                     descriptor],
                    timeout=60, line_cap=None)
            if q.get("success"):
                result["qemu_img_backing_chain"] = q["stdout"][:4096]
                # Always name the disk the corroboration belongs to.
                result["qemu_img_backing_chain_of"] = descriptor
    except Exception:
        pass
    return result


def _sparse_files_supported(directory: str) -> bool:
    """Whether a hole in a file under ``directory`` costs no blocks: a raw
    image written there holds only the data the source has."""
    try:
        fd, probe = tempfile.mkstemp(dir=directory, prefix=".sparse-probe-")
    except OSError:
        return False
    try:
        size = 4 * 1024 * 1024
        os.ftruncate(fd, size)
        return os.fstat(fd).st_blocks * 512 < size
    except OSError:
        return False
    finally:
        os.close(fd)
        try:
            os.unlink(probe)
        except OSError:
            pass


def _image_sizes(descriptor_path: str) -> tuple[int, int]:
    """(virtual size, bytes allocated across the whole snapshot chain) of a
    disk image, 0 where qemu-img does not say."""
    info = run(["qemu-img", "info", "--output=json", "--backing-chain",
                descriptor_path], timeout=60, line_cap=None)
    if not info.get("success"):
        return 0, 0
    try:
        data = json.loads(info["stdout"])
    except (ValueError, TypeError):
        return 0, 0
    chain = data if isinstance(data, list) else [data]
    chain = [c for c in chain if isinstance(c, dict)]
    if not chain:
        return 0, 0
    try:
        virtual = int(chain[0].get("virtual-size") or 0)
        allocated = sum(int(c.get("actual-size") or 0) for c in chain)
    except (ValueError, TypeError):
        return 0, 0
    return virtual, allocated


def _open_case_dir() -> str:
    """The case the execution log is open on, or '' outside a run."""
    try:
        from core.execution_log import log as _elog
        return str(_elog.case_dir() or "")
    except Exception:  # noqa: BLE001 - no log, no case
        return ""


@mcp.tool()
@output_safe
def vmdk_export_raw(
    descriptor_path: str,
    output_path: str = "",
    force_frozen_base: bool = False,
    force_reexport: bool = False,
) -> dict:
    """Flatten a VMDK (applying its full snapshot chain) into a local raw image.

    Uses `qemu-img convert` on the given descriptor: all snapshot deltas
    below it are merged, and the result is a raw image that TSK/mount tools
    can open (this build's TSK and xmount cannot read VMDK natively). Also
    the supported way to stage a LOCAL working copy of network-mounted VMDK
    evidence. Pass the chain-top descriptor from img_vmdk_chain_info — a
    base descriptor shadowed by deltas is refused unless
    force_frozen_base=True (pre-snapshot state, deliberate choice only).
    Long-running on large disks; the timeout scales with the virtual size.

    output_path may be omitted: the image is then written as
    analysis/exports/<descriptor stem>.raw under the open case.

    When a prior export for this descriptor already exists (mount_plan or
    non-empty output_path), the call is refused unless force_reexport=True —
    next step is tsk.mmls, not another multi-GB convert.
    """
    descriptor_path = os.path.abspath(os.path.expanduser(descriptor_path))
    if not output_path:
        case = _open_case_dir()
        if not case:
            return {"success": False, "error":
                    "output_path is required when no case is open: name the "
                    "raw image to write, e.g. analysis/exports/<name>.raw."}
        stem = os.path.splitext(os.path.basename(descriptor_path))[0]
        output_path = os.path.join(case, "analysis", "exports", stem + ".raw")
    assert_output_safe(output_path)
    output_path = os.path.abspath(os.path.expanduser(output_path))

    from core.vmdk import snapshot_warning
    frozen = snapshot_warning(descriptor_path)
    if frozen and not force_frozen_base:
        return {"success": False, "gate": "vmdk_frozen_base",
                "error": frozen + " Pass force_frozen_base=True only to "
                "deliberately analyze the pre-snapshot state."}

    # cost gate: do not re-flatten multi-GB VMDKs already exported.
    if not force_reexport:
        existing_path = None
        try:
            from core.execution_log import log as _elog
            _case = _elog.case_dir()
            if _case:
                from core.mount_plan import find_export_for_source
                hit = find_export_for_source(_case, descriptor_path)
                if hit:
                    existing_path = str(hit.get("path") or "")
        except Exception:
            existing_path = None
        if not existing_path and os.path.isfile(output_path):
            try:
                if os.path.getsize(output_path) > 1_048_576:
                    existing_path = output_path
            except OSError:
                pass
        if existing_path and os.path.isfile(existing_path):
            return {
                "success": False,
                "gate": "export_already_satisfied",
                "error": (
                    f"Raw export already present at {existing_path!r} for "
                    f"{descriptor_path!r}. Next: tsk.mmls → tsk.fls (not "
                    f"losetup/xmount, not another convert). Pass "
                    f"force_reexport=True only to deliberately rebuild."
                ),
                "output_path": existing_path,
                "recommended_next_tool": "tsk.mmls",
            }

    virtual_size, allocated = _image_sizes(descriptor_path)

    out_parent = os.path.dirname(os.path.abspath(output_path)) or "."
    os.makedirs(out_parent, exist_ok=True)
    if virtual_size:
        try:
            free = shutil.disk_usage(out_parent).free
        except OSError:
            free = None
        # A mid-copy disk-full leaves a half-written image that TSK opens
        # without complaint and silently truncates, so the space is checked
        # up front. convert writes holes where the source has none, so on a
        # filesystem that keeps holes the output cannot hold more than the
        # source's allocated bytes; elsewhere it grows to the virtual size.
        need = virtual_size
        if allocated and _sparse_files_supported(out_parent):
            need = min(virtual_size, allocated + allocated // 10)
        if free is not None and free < need:
            return {"success": False, "error":
                    f"Insufficient free space for raw export: need up to "
                    f"{need / 1024**3:.1f} GB "
                    f"({virtual_size / 1024**3:.1f} GB virtual, "
                    f"{allocated / 1024**3:.1f} GB allocated in the source), "
                    f"{free / 1024**3:.1f} GB free under {out_parent}. "
                    f"Free space or export to another volume."}

    from core.paths import MIN_THROUGHPUT_MB_S
    tp = max(MIN_THROUGHPUT_MB_S, 1)
    timeout = max(VOL_TIMEOUT, math.ceil(virtual_size / (tp * 1_048_576)))
    # No sudo: qemu-img reads the descriptor directly (no mount) and writes
    # into analysis/. Running it under sudo would risk a password-prompt hang
    # and leave a root-owned output image — exactly the sudo failure mode the
    # playbook warns against for read-directly tools.
    result = run(["qemu-img", "convert", "-O", "raw",
                  descriptor_path, output_path],
                 timeout=timeout, output_dir=out_parent)
    if not result.get("success"):
        # A convert that stopped short leaves a raw image that opens and
        # reads as complete; nothing must find it later as a finished
        # export.
        try:
            if os.path.isfile(output_path):
                os.unlink(output_path)
                result["partial_output_removed"] = output_path
        except OSError:
            pass
    if result.get("success"):
        result["output_path"] = output_path
        result["virtual_size_bytes"] = virtual_size
        result["note"] = (
            "Raw image contains the FULL state as of the given descriptor "
            "(snapshot chain applied). Next: tsk.mmls → tsk.fls (required "
            "orientation). Avoid xmount/losetup as the Triage default on "
            "multi‑GB raw."
        )
        # Access-plan handoff: analysis/*.raw is invisible to evidence/
        # scans — register so DAIR/mount_plan next-step is tsk.mmls.
        try:
            from core.execution_log import log as _elog
            _case = _elog.case_dir()
            if _case:
                from core.mount_plan import register_exported_image
                register_exported_image(
                    _case, output_path, source=descriptor_path,
                )
                result["mount_plan_registered"] = True
                result["recommended_next_tool"] = "tsk.mmls"
        except Exception:
            result["mount_plan_registered"] = False
    if frozen:
        result["vmdk_snapshot_warning"] = frozen
    return result


# ── Volume Shadow Copies ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vshadow_mount(
    image_or_device: str,
    mount_point: str,
) -> dict:
    """
    Mount Volume Shadow Copies (VSS) from a disk image or device using vshadowmount.
    Exposes shadow copies as vshadow1, vshadow2, ... under mount_point.
    Each shadow copy can then be mounted individually with mount_ntfs().
    """
    err = ensure_mount_point(mount_point)
    if err:
        return err
    # allow_other: the mount runs as root; without it the unprivileged
    # analyst process cannot read the vshadow* entries it exposes.
    return run(["vshadowmount", "-X", "allow_other", image_or_device, mount_point],
               needs_sudo=True)


@mcp.tool()
@output_safe
def vshadow_list(mount_point: str) -> dict:
    """
    List mounted Volume Shadow Copies after vshadow_mount.
    Shows available vshadow1, vshadow2, etc. entries.
    """
    return run(["ls", "-la", mount_point])


@mcp.tool()
@output_safe
def vshadow_umount(mount_point: str) -> dict:
    """Unmount a vshadowmount mount point."""
    return run(["umount", mount_point], needs_sudo=True)


# ── BitLocker ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def bde_mount(
    image_path: str,
    mount_point: str,
    recovery_password: Optional[str] = None,
    recovery_key_file: Optional[str] = None,
) -> dict:
    """
    Mount a BitLocker-encrypted image or partition using bdemount.
    Provide either recovery_password (48-digit key) or recovery_key_file path.
    After mounting, run mount_ntfs() on mount_point/bde1 with offset=0.
    """
    err = ensure_mount_point(mount_point)
    if err:
        return err
    cmd = ["bdemount"]
    if recovery_password:
        cmd += ["-r", recovery_password]
    elif recovery_key_file:
        cmd += ["-k", recovery_key_file]
    cmd += [image_path, mount_point]
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def bde_info(image_path: str) -> dict:
    """Display BitLocker encryption information from an image."""
    return run(["bdeinfo", image_path])


# ── xmount (multi-format image mounting) ──────────────────────────────────────

@mcp.tool()
@output_safe
def xmount_image(
    input_image: str,
    mount_point: str,
    input_format: str = "ewf",
    output_format: str = "raw",
) -> dict:
    """
    Mount a disk image in any format as a raw device using xmount.
    input_format: 'ewf' (E01), 'aff', 'raw' (others depend on the installed
    xmount input libraries — this build supports ewf/aaff/aewf/aff/raw ONLY).
    output_format: 'raw' (default) — exposes as /mount_point/<image>.dd.
    Useful when a tool doesn't support E01 natively (pass the raw file instead).
    NOT for VMDK: use img_vmdk_chain_info + img_vmdk_export_raw → tsk.mmls
    instead — xmount here has no vmdk input support, and a base VMDK with
    snapshots must be opened chain-aware anyway. Demoted in Triage until
    TSK orientation (prefer tsk.mmls on exported raw).
    """
    err = ensure_mount_point(mount_point)
    if err:
        return err
    cmd = [
        "xmount",
        "--in", input_format, input_image,
        "--out", output_format,
        mount_point,
    ]
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def xmount_umount(mount_point: str) -> dict:
    """Unmount an xmount mount point."""
    return run(["fusermount", "-u", mount_point])


# ── PhotoRec (non-interactive carving) ────────────────────────────────────────

@mcp.tool()
@output_safe
def photorec_carve(
    image_path: str,
    output_dir: str,
    file_types: Optional[str] = None,
    partition: Optional[int] = None,
) -> dict:
    """
    Carve files from a disk image by file signature using PhotoRec (non-interactive mode).
    output_dir: destination directory for recovered files.
    file_types: comma-separated type extensions to recover e.g. 'jpg,pdf,doc,zip'.
    partition: partition number to scan (0 = whole disk, default).

    Note: PhotoRec creates numbered subdirectories (recup_dir.1, recup_dir.2, ...) inside output_dir.
    For large images this can take hours and recover thousands of files.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Build photorec command-line (non-interactive via /cmd option)
    cmd = ["photorec", "/d", output_dir, "/cmd", image_path]

    if partition is not None:
        cmd += [f"partition_p{partition}"]

    if file_types:
        # Disable all then enable specific types
        types_str = ",".join(file_types.split(","))
        cmd += [f"fileopt,disable_all,enable,{types_str}"]

    cmd.append("search")

    return run(cmd, needs_sudo=True, timeout=14400, output_dir=output_dir)


# ── Partition tools ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def partprobe_refresh(device: str) -> dict:
    """Inform the OS of partition table changes on a device."""
    return run(["partprobe", device], needs_sudo=True)


@mcp.tool()
@output_safe
def losetup_create(image_path: str, offset_bytes: Optional[int] = None) -> dict:
    """
    Create a loop device from a disk image (alternative to mount -o loop).
    Returns the loop device path (e.g. /dev/loop0).

    Demoted in Triage until tsk.mmls/fls orientation — prefer tsk.mmls on
    exported raw (see .atlas/mount_plan.json). Requires passwordless sudo;
    non-interactive password prompts fail fast.
    """
    cmd = ["losetup", "-f", "--show"]
    if offset_bytes:
        cmd += ["-o", str(offset_bytes)]
    cmd.append(image_path)
    return run(cmd, needs_sudo=True)


@mcp.tool()
@output_safe
def losetup_list() -> dict:
    """List all active loop devices."""
    return run(["losetup", "-l"])


# Where the kernel reports a loop device's backing file.
_LOOP_BACKING_FILE = "/sys/block/loop{n}/loop/backing_file"


@mcp.tool()
@output_safe
def losetup_detach(loop_device: str) -> dict:
    """Detach a loop device (e.g. /dev/loop0) whose image lies in this case.

    Other runs on the host hold loop devices of their own, so only a
    /dev/loopN backed by a file under the case directory, or under the real
    path of its evidence/, is detached. An image attached from /mnt, /media
    or an evidence root outside the case cannot be detached by the agent."""
    import re
    from pathlib import Path
    from core.paths import active_case_dir
    m = re.fullmatch(r"/dev/loop(\d+)", str(loop_device or "").strip())
    if not m:
        return {"success": False,
                "error": f"not a loop device: {loop_device!r} (expected /dev/loopN)"}
    case = active_case_dir()
    if not case:
        return {"success": False,
                "error": "no investigation is in progress: a loop device is "
                         "detached only by the case that attached it"}
    try:
        backing = Path(_LOOP_BACKING_FILE.format(n=m.group(1))).read_text(
            encoding="utf-8", errors="replace").strip()
    except OSError:
        return {"success": False, "error": f"{loop_device} is not attached"}
    real = os.path.realpath(backing.removesuffix(" (deleted)"))
    roots = {os.path.realpath(case), os.path.realpath(os.path.join(case, "evidence"))}
    if not any(real == r or real.startswith(r + os.sep) for r in roots):
        return {"success": False,
                "error": f"{loop_device} is backed by {backing}, outside this case; "
                         "another run may be using it"}
    return run(["losetup", "-d", loop_device], needs_sudo=True)
