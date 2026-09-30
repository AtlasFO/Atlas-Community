"""Detect critical forensic scans that timed out / truncated without a retry.

Used by ``reason.pre_report_check`` so the agent cannot advance to Report after
an incomplete EVTX/auth enumeration (a large Security log scanned with a
short timeout returns truncated output, and an investigator who moves on
reports on the part that was seen).

The Timeline Builder does **not** cover this — it only packages collected
events. Incomplete scans must be retried with a narrower strategy.

A later non-truncated success on the same ``.evtx`` (exact path identity,
or a successful EvtxECmd/Hayabusa/Chainsaw whose command covers that file
or its parent directory) clears the debt. Bare basename matches across
host trees do **not** clear debt.
"""
from __future__ import annotations

import os
import re
from typing import Any

from core.auth_ontology import CHAINSAW_EVTX, critical_auth_scan_regex

# Tools / cmds that enumerate authentication / session evidence.
# Match tool invocations, not incidental path segments (a truncated
# grep whose path merely contained a tool name would otherwise count as
# unresolved critical debt and block Report). EID list comes
# from core.auth_ontology, not a hand-copied literal — see
# tests/core/test_auth_ontology_consolidation.py.
_CRITICAL_SCAN_RE = critical_auth_scan_regex()

# Structured extractors that count as clearing auth/session debt even when
# they operate on a directory rather than a single .evtx file.
_ALT_AUTH_TOOL_RE = re.compile(
    r"(?:evtxecmd|" + CHAINSAW_EVTX + r"|hayabusa)",
    re.IGNORECASE,
)

_PATH_RE = re.compile(
    r"(/[^\s\"']+\.evtx)|((?:[A-Za-z]:)?[^\s\"']+\.evtx)",
    re.IGNORECASE,
)

# Directory-style args: EvtxECmd -d, chainsaw/hayabusa input dirs.
_DIR_FLAG_RE = re.compile(
    r"(?:(?:^|[\s\"'])(?:-d|--directory|--evtx-dir|-f)\s+|"
    r"(?:evtx_dir|evtx_path|input)=)"
    r"([^\s\"']+)",
    re.IGNORECASE,
)

def _cmd_blob(entry: dict) -> str:
    parts = [
        str(entry.get("cmd") or ""),
        str(entry.get("mcp_tool") or ""),
        str(entry.get("stderr") or ""),
    ]
    return " ".join(parts)


def _evtx_path_key(cmd: str) -> str:
    m = _PATH_RE.search(cmd or "")
    if not m:
        return ""
    return os.path.normpath(m.group(0))


def _all_evtx_paths(cmd: str) -> list[str]:
    return [os.path.normpath(m.group(0)) for m in _PATH_RE.finditer(cmd or "")]


def _clearing_prefixes(cmd: str) -> set[str]:
    """Directory paths from a successful alt auth tool that cover child .evtx."""
    prefixes: set[str] = set()
    blob = cmd or ""
    for m in _DIR_FLAG_RE.finditer(blob):
        raw = m.group(1).rstrip("/\\")
        if raw.lower().endswith(".evtx"):
            # -f file.evtx — parent dir still covers siblings; keep file's parent
            prefixes.add(os.path.normpath(os.path.dirname(raw) or raw))
        else:
            prefixes.add(os.path.normpath(raw))
    for p in _all_evtx_paths(blob):
        parent = os.path.dirname(p)
        if parent:
            prefixes.add(os.path.normpath(parent))
    return prefixes


def _path_covered(path: str, cleared_paths: set[str],
                  cleared_prefixes: set[str]) -> bool:
    if not path:
        return False
    norm = os.path.normpath(path)
    if norm in cleared_paths:
        return True
    for pref in cleared_prefixes:
        if not pref:
            continue
        pref_n = os.path.normpath(pref)
        if norm == pref_n or norm.startswith(pref_n + os.sep):
            return True
    return False


def unresolved_critical_scan_timeouts(entries: list[dict[str, Any]]) -> list[dict]:
    """Return critical truncated scans that were never successfully retried.

    A later non-truncated successful tool_call on the same ``.evtx`` path
    (exact path identity, or EvtxECmd/Hayabusa/Chainsaw covering that file
    or its parent directory) clears the debt. Same-basename files under a
    different host/tree do not clear it.
    """
    truncated: list[dict] = []
    for e in entries:
        if e.get("type") != "tool_call":
            continue
        if not e.get("truncated"):
            continue
        blob = _cmd_blob(e)
        if not _CRITICAL_SCAN_RE.search(blob):
            continue
        truncated.append(e)

    if not truncated:
        return []

    cleared_paths: set[str] = set()
    cleared_prefixes: set[str] = set()
    for e in entries:
        if e.get("type") != "tool_call":
            continue
        if e.get("truncated"):
            continue
        if not e.get("success"):
            continue
        blob = _cmd_blob(e)
        if not _CRITICAL_SCAN_RE.search(blob):
            continue
        for key in _all_evtx_paths(blob):
            cleared_paths.add(key)
        if _ALT_AUTH_TOOL_RE.search(blob):
            cleared_prefixes |= _clearing_prefixes(blob)

    unresolved: list[dict] = []
    for e in truncated:
        blob = _cmd_blob(e)
        key = _evtx_path_key(blob)
        if key and _path_covered(key, cleared_paths, cleared_prefixes):
            continue
        if not key:
            # No path on the truncated call — only clear if we have a global
            # alt-tool success with any clearing prefix/path (rare).
            if cleared_paths or cleared_prefixes:
                continue
        unresolved.append({
            "call_id": e.get("call_id"),
            "cmd": (e.get("cmd") or "")[:160],
            "mcp_tool": e.get("mcp_tool"),
            "elapsed_seconds": e.get("elapsed_seconds"),
            "path": key or None,
        })
    return unresolved


def format_blocking_issue(unresolved: list[dict]) -> str:
    n = len(unresolved)
    samples = []
    for u in unresolved[:3]:
        cid = u.get("call_id")
        path = u.get("path") or "evtx"
        samples.append(f"call_id={cid} ({os.path.basename(path) if path else u.get('mcp_tool')})")
    sample_txt = "; ".join(samples)
    return (
        f"Critical auth/session scan(s) timed out or truncated without a "
        f"successful non-truncated retry ({n}): {sample_txt}. "
        f"Do NOT advance to Report. Diagnose why (file size vs wall_clock_budget, "
        f"too-broad EventID set, full-file stream) and retry with a narrower "
        f"strategy: (1) ez.evtxecmd with event_ids and time_start/time_end "
        f"(UTC) around the case window, then table.table_query on its CSV for "
        f"EID 4624/4625/4723, or (2) misc.chainsaw_hunt. "
        f"A non-truncated success on the same .evtx path (or EvtxECmd/"
        f"Hayabusa/Chainsaw covering that file or its parent directory) "
        f"clears this blocker — not a same-named file under another tree."
    )
