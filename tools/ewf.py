"""EWF / Expert Witness Format tools — mount and verify E01 images."""
import re
import subprocess
import os
from typing import Optional
from fastmcp import FastMCP
from core import run, ensure_mount_point, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT, scale_timeout

mcp = FastMCP("ewf")


@mcp.tool()
def ewf_info(image: str) -> dict:
    """Display E01 image metadata: acquisition hash, timestamps, notes, examiner info."""
    return run(["ewfinfo", image])


@mcp.tool()
def ewf_verify(image: str) -> dict:
    """
    Verify E01 image integrity by recomputing and comparing MD5/SHA1 hashes.
    Must complete without errors before analysis proceeds.
    """
    return run(["ewfverify", image], timeout=scale_timeout(VOL_TIMEOUT*6, image))


@mcp.tool()
def ewf_mount(image: str, mount_point: str) -> dict:
    """
    Mount an E01/EWF image as a raw device at mount_point.
    For multi-segment images (E01/E02/...) specify the first segment only.
    After mounting, run tsk_mmls against mount_point/ewf1 to get partition offsets.
    """
    err = ensure_mount_point(mount_point)
    if err:
        return err
    return run(_ewfmount_cmd(image, mount_point), needs_sudo=True)


def _ewfmount_cmd(image: str, mount_point: str) -> list[str]:
    # allow_other: the mount runs as root; without it the exposed device is
    # readable by root alone and every tool the unprivileged analyst runs
    # against it (mmls, fls, plaso) fails with "permission denied".
    return ["ewfmount", "-X", "allow_other", image, mount_point]


_MMLS_UNITS_RE = re.compile(r"Units are in (\d+)-byte sectors")
_MMLS_ROW_RE = re.compile(r"^\s*\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)$")


def _oem_id_at(device: str, byte_offset: int) -> Optional[bytes]:
    """The 8-byte OEM id of the boot sector at byte_offset; None when the
    device cannot be read there."""
    try:
        with open(device, "rb") as f:
            f.seek(byte_offset)
            return f.read(11)[3:11]
    except OSError:
        return None


# The boot-sector reader is shared with the evidence classifier, which
# tells a disk image from a memory image by the same on-disk facts.
from core.artifact_kind import sane_fat_bpb as _sane_fat_bpb  # noqa: E402,F401
from core.artifact_kind import volume_type_at as _volume_type_at  # noqa: E402


def _largest_mountable_volume(mmls_stdout: str, ewf_device: str
                              ) -> Optional[tuple[int, int, int, str]]:
    """``(start_sector, length_sectors, sector_size, fs)`` of the volume
    auto-mount opens, or None: the largest NTFS volume when the disk has one,
    so a Windows system disk mounts as it always has, else the largest exFAT
    or FAT volume (a USB key, a memory card).

    The type comes from each volume's boot sector: a DOS table's "NTFS /
    exFAT (0x07)" and a GPT "Basic data partition" both stand for NTFS and
    exFAT alike. When the device cannot be read, a volume the table labels
    NTFS or basic data is taken as NTFS.
    """
    m = _MMLS_UNITS_RE.search(mmls_stdout)
    sector_size = int(m.group(1)) if m else 512
    readable = os.access(ewf_device, os.R_OK)
    best: dict[str, tuple[int, int]] = {}
    for line in mmls_stdout.splitlines():
        row = _MMLS_ROW_RE.match(line)
        if not row:
            continue
        slot, start, _end, length, desc = row.groups()
        start, length = int(start), int(length)
        if slot == "Meta" or slot.startswith("-") or length <= 0:
            continue
        if readable:
            fs = _volume_type_at(ewf_device, start * sector_size)
        else:
            fs = ("ntfs" if ("NTFS" in desc or "0x07" in desc or "Basic data partition" in desc)
                  else None)
        if fs and (fs not in best or length > best[fs][1]):
            best[fs] = (start, length)
    if "ntfs" in best:
        return (*best["ntfs"], sector_size, "ntfs")
    others = [(length, fs, start) for fs, (start, length) in best.items()]
    if others:
        length, fs, start = max(others)
        return (start, length, sector_size, fs)
    return None


def _mount_fat_volume(ewf_device: str, mount_point: str, offset_bytes: int, fs: str) -> dict:
    """Mount an exFAT or FAT volume read-only with the kernel's driver. A
    read-only loop mount of the read-only EWF device writes nothing: neither
    driver replays a journal, and a read-only mount leaves the volume's
    dirty flag as it found it."""
    existing = _existing_mount_of(ewf_device)
    if existing:
        mp, src, offset = existing
        if (os.path.realpath(mp) == os.path.realpath(mount_point)
                and (offset is None or offset == offset_bytes)):
            return {"success": True, "reused": True, "mount_point": mp,
                    "stdout": f"{ewf_device} is already mounted read-only at {mp}; reusing it"}
    err = ensure_mount_point(mount_point)
    if err:
        return err
    fstype = "exfat" if fs == "exfat" else "vfat"
    result = run(["mount", "-t", fstype, "-o", f"ro,loop,offset={offset_bytes},noexec,nosuid,nodev",
                  ewf_device, mount_point], needs_sudo=True)
    if result.get("success"):
        result["mount_point"] = mount_point
    return result


@mcp.tool()
def ewf_umount(mount_point: str) -> dict:
    """Unmount an EWF mount point."""
    return run(["umount", mount_point], needs_sudo=True)


def _existing_mount_of(source: str, mounts_file: str = "/proc/mounts"):
    """Return (mount_point, mount_source, offset_or_None) if `source` — or a
    loop device backed by it — is already mounted somewhere, else None.

    ntfs-3g/fuseblk mounts record the backing file itself as the source;
    kernel loop mounts record /dev/loopN, whose backing file and offset are
    exposed under /sys/block/loopN/loop/. The offset is None when it cannot
    be determined (fuse mounts)."""
    real = os.path.realpath(source)
    try:
        with open(mounts_file) as f:
            mounts = [line.split()[:2] for line in f if len(line.split()) >= 2]
    except OSError:
        return None
    for src, mp in mounts:
        mp = mp.replace("\\040", " ")
        if os.path.realpath(src) == real:
            return mp, src, None
        if src.startswith("/dev/loop"):
            loop = os.path.basename(src)
            try:
                with open(f"/sys/block/{loop}/loop/backing_file") as bf:
                    backing = bf.read().strip()
            except OSError:
                continue
            if os.path.realpath(backing) != real:
                continue
            offset = None
            try:
                with open(f"/sys/block/{loop}/loop/offset") as of:
                    offset = int(of.read().strip())
            except (OSError, ValueError):
                pass
            return mp, src, offset
    return None


@mcp.tool()
def mount_ntfs(
    ewf_device: str,
    mount_point: str,
    offset_bytes: int,
    read_only: bool = True,
) -> dict:
    """
    Mount an NTFS partition from a raw EWF device.
    offset_bytes: byte offset = sector_start * sector_size (from mmls output).
    Always mounts read-only. Adds norecovery to prevent NTFS journal replay.
    A relative mount_point is resolved against the active case directory.
    If the same image is already mounted at the requested mount_point (e.g.
    a mount preserved across clear_case_run), it is reused instead of
    failing. If it is mounted elsewhere (e.g. by another case sharing the
    same evidence file), a fresh mount at mount_point is attempted first;
    only when the OS refuses is the foreign mount reused, flagged with
    warning=reused_foreign_mount_point.
    """
    if not read_only:
        return {"success": False, "stderr": "Read-only mount is required for evidence integrity."}
    # clear_case_run deliberately preserves live evidence mounts, so a rerun
    # on a mounted case would otherwise open with a guaranteed failure:
    # ntfs-3g refuses to mount the same backing file twice ("is already
    # mounted"), even at a different mount point.
    options = f"ro,loop,norecovery,offset={offset_bytes}"
    # A wrong offset (a slipped multiplication, the EFI partition) earns a
    # kernel "wrong fs type" and another slow turn; when the device is
    # readable, look at the boot sector first and say what is there.
    oem = _oem_id_at(ewf_device, offset_bytes) if os.access(ewf_device, os.R_OK) else None
    if oem is not None and oem != b"NTFS    ":
        # An off-by-one sector (the previous partition's end instead of this
        # one's start) is the usual slip: look a few sectors either way.
        near = next((o for o in range(max(0, offset_bytes - 8 * 512), offset_bytes + 9 * 512, 512)
                     if o != offset_bytes and _oem_id_at(ewf_device, o) == b"NTFS    "), None)
        hint = (f" An NTFS boot sector is at byte offset {near} (start sector {near // 512})."
                if near is not None else "")
        return {
            "success": False,
            "stderr": (
                f"No NTFS boot sector at byte offset {offset_bytes} of "
                f"{ewf_device} (found {oem!r}).{hint} The offset is the "
                "partition's start sector from mmls multiplied by the sector "
                "size; mount_full_image picks the largest NTFS volume itself."),
        }
    existing = _existing_mount_of(ewf_device)
    if existing:
        mp, src, offset = existing
        if offset is not None and offset != offset_bytes:
            return {
                "success": False,
                "stderr": (
                    f"{ewf_device} is already mounted at {mp} with a "
                    f"different offset ({offset}, requested {offset_bytes}). "
                    f"Unmount it first (umount_filesystem) to mount another "
                    f"partition of this image."),
            }
        offset_note = (
            "" if offset is not None else
            " Note: the existing mount's partition offset could not "
            "be verified (fuse mount); if you need a different "
            "offset, unmount first.")
        if os.path.realpath(mp) == os.path.realpath(mount_point):
            return {
                "success": True,
                "reused": True,
                "mount_point": mp,
                "stdout": (
                    f"{ewf_device} is already mounted read-only at {mp} "
                    f"(source {src}); reusing the existing mount — use {mp} as "
                    f"the filesystem root." + offset_note),
            }
        # Same image mounted at a DIFFERENT path — likely another case's
        # mount: two cases' evidence symlinks can resolve to one backing
        # file. Honor the requested mount point with its own mount
        # when the OS allows it; only when it refuses (ntfs-3g mounts the
        # same backing file once), fall back to a loud, flagged reuse.
        err = ensure_mount_point(mount_point)
        if err is None:
            res = run(
                ["mount", "-o", options, ewf_device, mount_point],
                needs_sudo=True,
            )
            if res.get("success"):
                return res
        return {
            "success": True,
            "reused": True,
            "mount_point": mp,
            "warning": "reused_foreign_mount_point",
            "stdout": (
                f"{ewf_device} is already mounted read-only at {mp} (source "
                f"{src}), and a second mount at the requested {mount_point} "
                f"was refused by the OS. Reusing the existing mount: use "
                f"{mp} as the filesystem root, NOT {mount_point}. If {mp} "
                f"belongs to a different case, unmount it first "
                f"(umount_filesystem {mp}) and re-run mount_ntfs to mount "
                f"under this case." + offset_note),
        }
    err = ensure_mount_point(mount_point)
    if err:
        return err
    return run(
        ["mount", "-o", options, ewf_device, mount_point],
        needs_sudo=True,
    )


@mcp.tool()
def umount_filesystem(mount_point: str) -> dict:
    """Unmount a mounted filesystem."""
    return run(["umount", mount_point], needs_sudo=True)


@mcp.tool()
def mount_full_image(image_e01: str, ewf_mount_point: str, fs_mount_point: str) -> dict:
    """
    Convenience: mount an E01 image end-to-end.
    1. ewfmount the E01 to ewf_mount_point (exposes ewf1)
    2. Read the partition table via mmls (a partitionless volume, as on
       many USB keys, is read at the device's start)
    3. Mount, read-only, the largest NTFS volume, or on a disk without one
       the largest exFAT or FAT volume, to fs_mount_point (idempotent reuse
       when already mounted). The result names the file system (fs_type).

    An image with none of these volumes returns success=False with
    gate=non_ntfs: use tsk.*/plaso on the EWF device, which stays exposed;
    it is not a fatal Plane A failure.
    """
    for mp in (ewf_mount_point, fs_mount_point):
        err = ensure_mount_point(mp)
        if err:
            return err

    ewf_device = os.path.join(ewf_mount_point, "ewf1")

    # Step 1: ewfmount (reuse when ewf1 already exposed — teardown/remount hygiene)
    if os.path.exists(ewf_device):
        ewf_result = {
            "success": True,
            "reused": True,
            "stdout": f"reusing existing EWF device at {ewf_device}",
        }
    else:
        ewf_result = run(_ewfmount_cmd(image_e01, ewf_mount_point), needs_sudo=True)
        if not ewf_result["success"]:
            return ewf_result

    # Step 2: mmls for the volumes. A volume without a partition table (a
    # key or card formatted whole) makes mmls fail or list nothing; its boot
    # sector is then at the start of the device.
    mmls_result = run(["mmls", ewf_device], needs_sudo=True)
    best = (_largest_mountable_volume(mmls_result["stdout"], ewf_device)
            if mmls_result["success"] else None)
    if best is None and os.access(ewf_device, os.R_OK):
        whole = _volume_type_at(ewf_device, 0)
        if whole:
            best = (0, 0, 512, whole)
    if best is None and not mmls_result["success"]:
        return mmls_result
    if best is None:
        return {
            "success": False,
            "gate": "non_ntfs",
            "stderr": (
                "No NTFS, exFAT or FAT volume found in the mmls output or at "
                "the device's start. Use tsk.*/plaso/ez.* against the EWF "
                "device or image for other file systems."
            ),
            "mmls": mmls_result["stdout"],
            "ewf_device": ewf_device,
        }

    offset_sectors, _length, sector_size, fs = best
    offset_bytes = offset_sectors * sector_size

    # Step 3: mount read-only, NTFS through the idempotent helper (reuse /
    # foreign-mount warnings), exFAT and FAT through the kernel driver.
    if fs == "ntfs":
        mount_result = mount_ntfs(ewf_device, fs_mount_point, offset_bytes, read_only=True)
        mount_result["ntfs_offset_bytes"] = offset_bytes
        mount_result["ntfs_offset_sectors"] = offset_sectors
    else:
        mount_result = _mount_fat_volume(ewf_device, fs_mount_point, offset_bytes, fs)
    mount_result["fs_type"] = fs
    mount_result["volume_offset_bytes"] = offset_bytes
    mount_result["ewf_device"] = ewf_device
    if ewf_result.get("reused"):
        mount_result["ewf_reused"] = True
    return mount_result
