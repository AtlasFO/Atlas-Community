"""Generic artifact-kind helpers — disk images vs raw databases vs files.

Used by evidence profile, mount_plan, and evidence_access so Access Stage
hardness applies only to real disk/container images — not to application
databases or forensic extracts that happen to use ``.raw`` / ``.bin``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, os.PathLike]

# Path/name tokens that mark non-disk binaries even when the extension is
# .raw/.bin/.img (SRUM/EseDB/pagefile/etc.). Keep semantic, not case-specific.
_NON_DISK_RAW_NAME_RE = re.compile(
    r"(?i)("
    r"srudb|srum|"
    r"windows\.edb|webcachev\d*|ese\.|"
    r"ntds\.dit|ntds\.jfm|"
    r"hiberfil|pagefile|swapfile|"
    r"memory\.dmp|mdmp$|"
    r"amcache\.hve|"
    r"\.edb$|\.dit$|\.jfm$|\.dat$"
    r")"
)

_NON_DISK_DIR_TOKENS = frozenset({
    "srum", "registry", "prefetch", "amcache",
    "webcache", "ese", "edb", "swap", "pagefile", "hiberfil",
    "crashdumps", "minidump",
})

_DISK_IMAGE_EXT = frozenset({
    ".e01", ".ex01", ".s01", ".l01", ".aff", ".afd", ".afm",
    ".vmdk", ".vhd", ".vhdx", ".qcow", ".qcow2",
    ".dd", ".iso",
})

_AMBIGUOUS_RAW_EXT = frozenset({".raw", ".bin", ".img"})

# Continuation segments of a split image (.E02 … .E99, .Ex02 …, .L02, .S02):
# the first segment stands for the set, the opener reads the rest itself.
# Note: digits only — a set past 99 segments (.EAA …) is not folded.
_SEGMENT_CONTINUATION_RE = re.compile(r"\.(?:e|ex|l|lx|s)(?!01$)\d{2}$", re.I)


def is_ewf_continuation_segment(path: PathLike) -> bool:
    """True for the second and later segments of a split EWF/L01/S01 set,
    which are opened through the first segment and are not evidence units
    of their own."""
    return bool(_SEGMENT_CONTINUATION_RE.search(Path(str(path)).name))


def _norm_parts(path: PathLike) -> tuple[str, list[str]]:
    p = Path(str(path))
    name = p.name.casefold()
    parts = [x.casefold() for x in p.parts]
    return name, parts


def is_non_disk_container(path: PathLike) -> bool:
    """True when path is a raw/bin-like file that is not a disk image."""
    name, parts = _norm_parts(path)
    suf = Path(str(path)).suffix.casefold()
    if suf in _DISK_IMAGE_EXT:
        return False
    if _NON_DISK_RAW_NAME_RE.search(name):
        return True
    if suf in _AMBIGUOUS_RAW_EXT and (_NON_DISK_DIR_TOKENS & set(parts)):
        return True
    # Compound names like SRUDB.INTEG.RAW — suffix .raw, stem carries SRUDB
    stem = Path(str(path)).stem.casefold()
    if suf in _AMBIGUOUS_RAW_EXT and _NON_DISK_RAW_NAME_RE.search(stem):
        return True
    return False


def is_access_gated_disk_media(path: PathLike) -> bool:
    """True when Access Stage / mount_plan should treat the path as disk media."""
    if not path:
        return False
    if is_non_disk_container(path):
        return False
    name, _parts = _norm_parts(path)
    suf = Path(str(path)).suffix.casefold()
    if suf in _DISK_IMAGE_EXT:
        return True
    # Multi-part E01: foo.E02
    if len(name) > 4 and name[-4] == "." and name[-3] == "e" and name[-2:].isdigit():
        return True
    if suf in _AMBIGUOUS_RAW_EXT:
        # Ambiguous raw that survived non-disk filters — caller may still
        # apply depth heuristics; default yes only for shallow evidence paths
        # handled in evidence_profile.classify_path.
        return True
    return False


def media_role_for_path(path: PathLike) -> str:
    """``disk`` | ``database`` | ``file`` — coarse role for mount/access."""
    if is_non_disk_container(path):
        return "database"
    if is_access_gated_disk_media(path):
        return "disk"
    return "file"


# ── What the first bytes of an image say ─────────────────────────────────
#
# On-disk format signatures: where a partition table, a file system's boot
# block, a disk container or a memory dump format puts its magic. Public
# format knowledge (the specifications and the parsers that read them), not
# knowledge of any case. A name says nothing about what a .raw or .img holds;
# its first sectors do.

_HEAD_BYTES = 4096

_DISK_MAGICS = (
    (512, b"EFI PART"),                # GPT header behind its protective MBR
    (3, b"-FVE-FS-"),                  # BitLocker volume
    (0, b"LUKS\xba\xbe"),              # LUKS
    (0, b"XFSB"),                      # XFS superblock
    (32, b"NXSB"),                     # APFS container superblock
    (0, b"vhdxfile"),                  # VHDX
    (0, b"conectix"),                  # VHD, footer copy of a dynamic disk
    (0, b"QFI\xfb"),                    # QCOW
    (0, b"KDMV"),                      # VMDK sparse extent
    (0, b"EVF\x09\x0d\x0a\xff\x00"),    # EWF
)
_MEMORY_MAGICS = (
    (0, b"PAGEDUMP"), (0, b"PAGEDU64"),    # Windows crash dump, 32/64-bit
    (0, b"EMiL"),                          # LiME
    # Windows hibernation file, before and after resume
    (0, b"hibr"), (0, b"HIBR"), (0, b"wake"), (0, b"WAKE"), (0, b"RSTR"), (0, b"rstr"),
)


def sane_fat_bpb(boot: bytes) -> bool:
    """A FAT BIOS parameter block whose fields make sense. The FAT type label
    in the boot sector is informational and often blank on media formatted
    outside Windows, so the parameters decide: a sector size, a power-of-two
    cluster, reserved sectors, one or two FATs and a media descriptor."""
    per_sector = int.from_bytes(boot[11:13], "little")
    per_cluster = boot[13]
    reserved = int.from_bytes(boot[14:16], "little")
    return (per_sector in (512, 1024, 2048, 4096)
            and per_cluster in (1, 2, 4, 8, 16, 32, 64, 128)
            and reserved >= 1 and boot[16] in (1, 2) and boot[21] >= 0xF0)


def _volume_type(boot: bytes) -> Optional[str]:
    """The file system whose boot sector ``boot`` is: "ntfs", "exfat" or
    "fat", or None. NTFS and exFAT name themselves in the OEM field, and a
    FAT volume carries the 0x55AA boot signature with a sane parameter block."""
    if len(boot) < 512:
        return None
    if boot[3:11] == b"NTFS    ":
        return "ntfs"
    if boot[3:11] == b"EXFAT   ":
        return "exfat"
    if boot[510:512] == b"\x55\xaa" and sane_fat_bpb(boot):
        return "fat"
    return None


def volume_type_at(device: str, byte_offset: int) -> Optional[str]:
    """The file system whose boot sector sits at byte_offset (_volume_type),
    or None, also when the device cannot be read there."""
    try:
        with open(device, "rb") as f:
            f.seek(byte_offset)
            boot = f.read(512)
    except OSError:
        return None
    return _volume_type(boot)


def _dos_partition_table(head: bytes) -> bool:
    """A DOS partition table: the 0x55AA marker, four entries whose status
    byte is 0x00 or 0x80, at least one of them typed. A memory page that
    happens to end in 0x55AA rarely has all four status bytes right."""
    if len(head) < 512 or head[510:512] != b"\x55\xaa":
        return False
    entries = [head[446 + 16 * i:462 + 16 * i] for i in range(4)]
    return all(e[0] in (0x00, 0x80) for e in entries) and any(e[4] for e in entries)


def _ext_superblock(head: bytes) -> bool:
    """ext2/3/4: the 0xEF53 magic at 1080 and a block-size exponent the
    format allows (two magic bytes alone match one random page in 65536)."""
    return (len(head) >= 1084 and head[1080:1082] == b"\x53\xef"
            and int.from_bytes(head[1048:1052], "little") <= 6)


def _hfs_volume_header(head: bytes) -> bool:
    """HFS+/HFSX: the signature at 1024 and the version that goes with it."""
    return (len(head) >= 1028 and head[1024:1026] in (b"H+", b"HX")
            and int.from_bytes(head[1026:1028], "big") in (4, 5))


def _elf_core(head: bytes) -> bool:
    """An ELF core file (a virtual machine's or a kernel's memory), read in
    the byte order the header declares."""
    if len(head) < 18 or head[:4] != b"\x7fELF" or head[5] not in (1, 2):
        return False
    return int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") == 4


def head_signature(path: PathLike) -> str:
    """What the first sectors of ``path`` hold: "disk" (a partition table, a
    file system boot block, a disk container), "memory" (a memory dump
    format), "minidump" (a process's user-mode minidump, which no memory
    tool reads) or "" when no signature matches."""
    try:
        with open(path, "rb") as f:
            head = f.read(_HEAD_BYTES)
    except OSError:
        return ""

    def at(offset: int, magic: bytes) -> bool:
        return head[offset:offset + len(magic)] == magic

    if any(at(o, m) for o, m in _MEMORY_MAGICS) or _elf_core(head):
        return "memory"
    if at(0, b"MDMP"):
        return "minidump"
    if (_dos_partition_table(head) or _volume_type(head[:512])
            or any(at(o, m) for o, m in _DISK_MAGICS)
            or _ext_superblock(head) or _hfs_volume_header(head)):
        return "disk"
    # A fixed VHD keeps its only footer in the last sector.
    try:
        size = os.path.getsize(path)
        if size >= 1024:
            with open(path, "rb") as f:
                f.seek(size - 512)
                if f.read(8) == b"conectix":
                    return "disk"
    except OSError:
        pass
    return ""
