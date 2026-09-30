"""Evidence arrives in sets — answering from part of one is unsound.

Log rotations, chunked exports and per-host copies of the same artifact are
*series*: ``2024-05-01.log`` through ``2024-05-08.log`` is one week of
firewall traffic, not eight unrelated files. An analyst who reads two of
them and concludes "no external destinations appear in the firewall logs"
has not examined the firewall logs; they have examined a quarter of them.

The claim such a partial read produces (that the logs held only management
traffic and showed no exfiltration) is recorded UNCONFIRMED and then marks
the data-exfiltration question *answered*.

Partial coverage of a series is more dangerous than no coverage: no
coverage is visibly a gap, while partial coverage looks like the work was
done. This module makes that asymmetry explicit.

Series are discovered structurally, not from a list of known log names: a
set is files sharing a directory whose names match once their varying run
of digits is masked out. That generalises to rotations, numbered chunks,
dated exports and per-host duplicates without naming any of them.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

# A series needs enough members that "some of them" is a real claim about
# coverage. Two files that differ by a digit are usually a pair, not a set.
MIN_SERIES_MEMBERS = 3

# Directories whose contents are Atlas's own output, not source evidence.
_SKIP_DIRS = frozenset({"tool-output", ".atlas", "reports", "exports"})

_DIGITS_RE = re.compile(r"\d+")

# Segments of one split image (.E01/.E02…, .Ex01, .L01, .S01) are consumed
# together by whatever opens the first segment: one evidence unit, not a
# set of files to be read one by one.
_SEGMENT_EXT_RE = re.compile(r"\.(e|ex|l|lx|s)\d{2,}$", re.I)


def series_key(rel_path: str) -> Optional[tuple[str, str]]:
    """``(directory, masked name)`` identifying the series a file belongs to.

    The mask replaces every run of digits with ``#``, so ``2024-05-01.log``
    and ``2024-05-08.log`` share the key ``#-#-#.log`` while
    ``firewall.log`` and ``dns.log`` do not collide.
    """
    norm = str(rel_path or "").replace("\\", "/").strip("/")
    if not norm:
        return None
    parts = norm.split("/")
    if any(p in _SKIP_DIRS for p in parts):
        return None
    directory = "/".join(parts[:-1])
    name = parts[-1]
    if _SEGMENT_EXT_RE.search(name):
        return None  # a split image's segments are one unit, not a series
    if not _DIGITS_RE.search(name):
        return None  # nothing varies — not a member of a numbered series
    return directory, _DIGITS_RE.sub("#", name)


def group_series(
    rel_paths: Iterable[str],
    *,
    min_members: int = MIN_SERIES_MEMBERS,
) -> dict[tuple[str, str], list[str]]:
    """Group paths into series, dropping anything too small to be one."""
    groups: dict[tuple[str, str], list[str]] = {}
    for rel in rel_paths:
        key = series_key(rel)
        if key is None:
            continue
        groups.setdefault(key, []).append(str(rel))
    return {k: sorted(v) for k, v in groups.items() if len(v) >= min_members}


def partially_examined_series(
    case_dir: str | os.PathLike,
    *,
    min_members: int = MIN_SERIES_MEMBERS,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Series where some members were read and others never were.

    Only *partial* coverage is reported. A series nobody touched is an
    ordinary unexamined-evidence gap that the coverage and artifact-value
    obligations already carry; a series that was half read is the case that
    silently masquerades as finished work.
    """
    root = Path(case_dir)
    rels: list[str] = []
    # Shared case-wide scanner, not rglob — rglob does not descend into a
    # symlinked directory, which is how real evidence is attached to a case
    #
    try:
        from core.evidence_catalog import iter_case_files
        for rel, abs_p in iter_case_files(root, ("evidence", "analysis")):
            try:
                if abs_p.stat().st_size > 0:
                    rels.append(rel)
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        return []
    groups = group_series(rels, min_members=min_members)
    if not groups:
        return []

    try:
        from core.investigation_obligations import _load_trace_tool_blobs
        blob = " ".join(_load_trace_tool_blobs(root)).lower()
    except Exception:  # noqa: BLE001
        blob = ""
    if not blob:
        return []

    def _touched(rel: str) -> bool:
        low = rel.lower()
        return low in blob or low.rsplit("/", 1)[-1] in blob

    out: list[dict[str, Any]] = []
    for (directory, mask), members in sorted(groups.items()):
        examined = [m for m in members if _touched(m)]
        missed = [m for m in members if m not in examined]
        if not examined or not missed:
            continue  # untouched entirely, or fully covered
        out.append({
            "directory": directory or ".",
            "pattern": mask,
            "total": len(members),
            "examined": len(examined),
            "unexamined": missed,
        })
    out.sort(key=lambda s: (-len(s["unexamined"]), s["directory"]))
    return out[:limit]


def format_series_nudge(series: Iterable[dict[str, Any]]) -> str:
    """Tell the model which sets it has only partly read."""
    items = list(series)
    if not items:
        return ""
    lines = [
        "[partial evidence set] You have drawn on some members of these "
        "evidence series and never opened the others. A conclusion from "
        "part of a set is a conclusion about that part only — read the "
        "remaining members, or state why they cannot change the answer in "
        "a disposition (misc.record_agent_message with disposition=True), "
        "not in a finding:",
    ]
    for s in items[:6]:
        lines.append(
            f"- {s['directory']}/{s['pattern']}: {s['examined']} of "
            f"{s['total']} examined")
        for miss in s["unexamined"][:6]:
            lines.append(f"    unexamined: {miss}")
    return "\n".join(lines)
