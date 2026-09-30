"""Generic artifact-kind helpers — disk images vs raw databases vs files.

Used by evidence profile, mount_plan, and evidence_access so Access Stage
hardness applies only to real disk/container images — not to application
databases or forensic extracts that happen to use ``.raw`` / ``.bin``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Union

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
