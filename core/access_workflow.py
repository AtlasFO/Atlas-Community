"""Access workflow — consume mount_plan next_work_order (B6 / I3).

After disk media is opened, deep carving (sigfind / blind FS hunt) must wait
until the export work-order's Security-event-log step is disposed: searched
in trace (in whichever layout the media uses, core.eventlog_layout), ledger
unit probed|answered|blocked, or mark_blocked.

This is **one** consumer of work-order intent — not a finish veto and not an
EVTX filename obligation list.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

# Tools deferred until winevt step is disposed (deep / blind disk hunt).
DEEP_DISK_TOOLS = frozenset({
    "tsk.sigfind",
    "tsk_sigfind",
    "tsk.sigfind_ascii",
    "tsk_sigfind_ascii",
    "tsk.indxparse",
    "tsk_indxparse",
    "tsk.tsk_indxparse",
})

# Orientation fls is allowed; a streak while winevt WO is pending is the B6 tunnel.
MAX_FLS_WHILE_WINEVT_PENDING = 3

# The work order names the Security event log; older plans name the EVTX
# layout only, so both spellings are recognised.
_WINEVT_WO_RE = re.compile(
    r"(?i)(?:winevt|security\.evtx|secevent\.evt|evtxecmd|ez\.evtxecmd|"
    r"security event log)"
)


def _case_root(case_dir: str | os.PathLike | None) -> Optional[Path]:
    if not case_dir:
        return None
    try:
        return Path(case_dir).resolve()
    except Exception:
        return None


def _load_mount_plan(root: Path) -> dict[str, Any]:
    p = root / ".atlas" / "mount_plan.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def opened_media_with_winevt_work_order(
    case_dir: str | os.PathLike | None,
) -> list[dict[str, Any]]:
    """Opened images whose next_work_order / reason still lists winevt."""
    root = _case_root(case_dir)
    if root is None:
        return []
    plan = _load_mount_plan(root)
    out: list[dict[str, Any]] = []
    for img in plan.get("images") or []:
        if not isinstance(img, dict):
            continue
        st = str(img.get("status") or "")
        if st not in ("opened", "mounted") and not img.get("opened_tool"):
            continue
        wo_blob = " ".join(str(x) for x in (img.get("next_work_order") or []))
        reason = str(img.get("reason") or "")
        if _WINEVT_WO_RE.search(wo_blob) or _WINEVT_WO_RE.search(reason):
            out.append(img)
    return out


def _trace_cmd_blobs(root: Path) -> list[dict[str, str]]:
    analysis = root / "analysis"
    if not analysis.is_dir():
        return []
    out: list[dict[str, str]] = []
    for p in sorted(analysis.glob("*_trace.jsonl"))[-2:]:
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    e = row.get("entry") if isinstance(row.get("entry"), dict) else row
                    if not isinstance(e, dict):
                        continue
                    blob = " ".join(
                        str(e.get(k) or "")
                        for k in ("cmd", "mcp_tool", "tool", "args")
                    )
                    if e.get("success") is False or e.get("failure_class"):
                        continue      # a refused or failed call is not a listing
                    if blob.strip():
                        # What the call printed says which event-log layout
                        # the media has; what it ran says what was searched.
                        out.append({"cmd": blob,
                                    "out": str(e.get("stdout_excerpt") or "")})
        except Exception:
            continue
    return out


def _security_log_names() -> tuple[str, ...]:
    from core.eventlog_layout import LAYOUTS
    return tuple(l.security_log.lower() for l in LAYOUTS)


def _winevt_ledger_disposed(root: Path) -> bool:
    """True when a Security-log HV unit (either layout) is probed|answered|blocked."""
    try:
        from core.coverage_ledger import load_ledger
        ledger = load_ledger(root)
        units = (ledger.get("units") or {}).values()
    except Exception:
        return False
    names = _security_log_names()
    for key in ((ledger.get("meta") or {}).get("blocked_work_orders") or {}):
        k = str(key).lower()
        if "winevt" in k or k.endswith(names):
            return True
    for u in units:
        if not isinstance(u, dict):
            continue
        path = str(u.get("path") or "").lower().replace("\\", "/")
        if "winevt" not in path and not path.endswith(names):
            continue
        if str(u.get("status") or "") in ("probed", "answered", "blocked"):
            return True
    return False


def winevt_work_order_pending(case_dir: str | os.PathLike | None) -> bool:
    """Opened disk with winevt in work-order, not yet searched/disposed."""
    root = _case_root(case_dir)
    if root is None:
        return False
    opened = opened_media_with_winevt_work_order(root)
    if not opened:
        return False
    if _winevt_ledger_disposed(root):
        return False
    try:
        from core.evidence_access import winevt_search_attempted_in_cmds
        if winevt_search_attempted_in_cmds(_trace_cmd_blobs(root)):
            return False
    except Exception:
        pass
    return True


def _count_fls_in_trace(root: Path) -> int:
    n = 0
    for blob in _trace_cmd_blobs(root):
        cmd = (blob.get("cmd") or "").lower()
        if not ("tsk_fls" in cmd or "tsk.fls" in cmd
                or re.search(r"(?<![\w])fls(?![\w])", cmd)):
            continue
        # Descending into one directory by inode is navigation — the way
        # winevt/Logs is reached. Only whole-tree or root listings are the
        # "enumeration tunnels" this cap exists for. Refused calls used to
        # count too, so every refusal tightened the cap that caused it
        #
        if re.search(r"fls\b[^|]*\s\d+\s*$", cmd) and " -r" not in cmd:
            continue
        n += 1
    return n


def _is_fls_tool(tool_name: str) -> bool:
    norm = (tool_name or "").strip().lower().replace("-", "_")
    return norm in {
        "tsk.fls", "tsk_fls", "tsk.tsk_fls", "tsk_tsk_fls", "fls",
    } or norm.endswith(".fls") or norm.endswith("_fls")


def refuse_deep_disk_until_winevt(
    case_dir: str | os.PathLike | None,
    tool_name: str,
) -> Optional[str]:
    """Hard gate for deep disk / fls-streak while winevt work-order is pending."""
    norm = (tool_name or "").strip()
    dotted = norm.replace("_", ".", 1)
    underscored = norm.replace(".", "_", 1)
    deep = (
        norm in DEEP_DISK_TOOLS
        or dotted in DEEP_DISK_TOOLS
        or underscored in DEEP_DISK_TOOLS
    )
    if not winevt_work_order_pending(case_dir):
        return None
    if deep:
        return (
            "access_work_order_pending: disk media is opened with the Security "
            "event log still on next_work_order and not yet searched or "
            f"ledger-disposed. Search {_demand(case_dir)} (or "
            "coverage.mark_blocked after a real attempt) before deep signature/"
            "carving tools (tsk.sigfind / indxparse)."
        )
    # B6: allow orientation fls, then budget further FS enumeration.
    if _is_fls_tool(tool_name):
        root = _case_root(case_dir)
        if root is None:
            return None
        fls_n = _count_fls_in_trace(root)
        if fls_n >= MAX_FLS_WHILE_WINEVT_PENDING:
            return (
                f"access_disk_budget: {fls_n} tsk.fls calls already recorded "
                f"while the Security event log remains on next_work_order (cap "
                f"{MAX_FLS_WHILE_WINEVT_PENDING}). Stop filesystem enumeration "
                f"tunnels — tsk.resolve_path(image, fs_path=<the log directory>) "
                "gives the directory inode, then tsk.fls on that inode (targeted "
                f"listings do not count here); the log to reach is "
                f"{_demand(case_dir)}, or coverage.mark_blocked after a real "
                "attempt, before more whole-tree fls."
            )
    return None


def _demand(case_dir: str | os.PathLike | None) -> str:
    """The event-log search the work order asks for, phrased for the layout
    the trace has shown; both layouts when it has shown neither."""
    from core.eventlog_layout import LAYOUTS, demand, layouts_in_evidence
    root = _case_root(case_dir)
    blobs = _trace_cmd_blobs(root) if root is not None else []
    return demand(layouts_in_evidence(blobs) or LAYOUTS)


def prioritize_tools_for_access_workflow(
    case_dir: str | os.PathLike | None,
    priority_tools: list,
) -> list:
    """When winevt WO pending, put winevt path tools first and deep disk last."""
    tools = list(priority_tools or [])
    if not winevt_work_order_pending(case_dir):
        return tools
    prefer = (
        "tsk.fls",
        "tsk.mmls",
        "tsk.icat",
        "ez.evtxecmd",
        "ez.ez_evtxecmd",
        "evt.evt_export",
        "misc.list_evidence_dir",
    )
    deep = (
        "tsk.sigfind",
        "tsk_sigfind",
        "strings.strings_grep",
    )
    head = [t for t in prefer if t in tools or str(t).replace(".", "_") in tools]
    # keep existing order for others, deep at end
    mid = []
    tail = []
    head_set = {str(x) for x in head}
    for t in tools:
        name = str(t)
        if name in head_set or name.replace("_", ".", 1) in head_set:
            continue
        if name in deep or name.replace("_", ".", 1) in {
                "tsk.sigfind", "strings.strings_grep"}:
            tail.append(t)
        else:
            mid.append(t)
    # Ensure prefer tools appear even if not previously listed
    for p in prefer:
        if p not in head and p not in mid and p not in tail:
            head.append(p)
    return head + mid + tail
