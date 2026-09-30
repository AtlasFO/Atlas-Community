"""Evidence Access Stage — sole query authority for accessibility questions.

Durable writers remain in ``mount_plan`` (media) and ``evidence_catalog``
(presence). This module never persists its own SoT JSON.

Stages for access-gated media (disk images / exports)::

    absent | planned | staged | opened | access_failed

Direct on-disk evidence (CSV, EVTX already under evidence/) is ``direct``.

Presence ≠ access ≠ probe coverage ≠ artifact_ready ≠ claim completeness —
callers must not treat those stores as interchangeable.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

# Normalised access stages exposed to all consumers.
STAGES = frozenset({
    "direct",
    "absent",
    "planned",
    "staged",
    "opened",
    "access_failed",
})

# Media that still needs an open attempt before filesystem analysis is honest.
_PENDING_OPEN = frozenset({"absent", "planned", "staged"})

_DISK_EXT_RE = re.compile(
    r"\.(?:raw|dd|img|iso|vhd|vhdx|vmdk|e01|ex01)$", re.I
)


def _is_access_gated_media_entry(img: dict[str, Any]) -> bool:
    """False for non-disk artifacts that must not block Access Stage / READY."""
    if img.get("access_gated") is False or img.get("action") == "skip":
        return False
    if str(img.get("image_type") or "") == "non_disk_artifact":
        return False
    path = str(img.get("path") or "")
    if not path:
        return True
    try:
        from core.artifact_kind import is_non_disk_container
        if is_non_disk_container(path):
            return False
    except Exception:
        pass
    return True
_TSK_OPEN_TOOLS = frozenset({
    "tsk_mmls", "tsk.mmls", "tsk_fls", "tsk.fls",
    "tsk_fsstat", "tsk.fsstat",
    # MCP toolbox doubles the namespace: tsk + tsk_mmls → tsk_tsk_mmls
    "tsk_tsk_mmls", "tsk_tsk_fls", "tsk_tsk_fsstat",
})


def _case_root(case_dir: str | os.PathLike | None) -> Optional[Path]:
    if not case_dir:
        return None
    try:
        return Path(case_dir).resolve()
    except Exception:
        return None


def _path_exists(root: Path, path_s: str) -> bool:
    if not path_s:
        return False
    p = Path(path_s)
    if p.is_file() and p.stat().st_size >= 0:
        return True
    cand = root / path_s
    return cand.is_file()


def normalize_media_status(raw_status: str | None, *, file_exists: bool) -> str:
    """Map mount_plan status strings onto Access Stage vocabulary."""
    st = (raw_status or "").strip().lower()
    if not file_exists:
        # Exported/mounted records whose backing file was wiped → absent.
        if st in ("exported", "mounted", "opened", "staged", ""):
            return "absent"
        if st in ("mount_failed", "access_failed", "open_failed"):
            return "access_failed"
        return "absent"
    if st in ("opened", "mounted"):
        return "opened"
    if st in ("exported", "staged"):
        return "staged"
    if st in ("mount_failed", "access_failed", "open_failed"):
        return "access_failed"
    # plan_only / unset / unknown with file present
    return "planned"


def media_entries(case_dir: str | os.PathLike | None) -> list[dict[str, Any]]:
    """Return mount_plan images annotated with ``access_stage`` + existence."""
    root = _case_root(case_dir)
    if root is None:
        return []
    try:
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(root)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for img in plan.get("images") or []:
        if not isinstance(img, dict):
            continue
        if not _is_access_gated_media_entry(img):
            continue
        path = str(img.get("path") or "")
        exists = _path_exists(root, path)
        stage = normalize_media_status(img.get("status"), file_exists=exists)
        entry = dict(img)
        entry["access_stage"] = stage
        entry["file_exists"] = exists
        out.append(entry)
    return out


def stage_for_path(
    case_dir: str | os.PathLike | None,
    path: str,
) -> str:
    """Access stage for one path (media via mount_plan, else direct/absent)."""
    root = _case_root(case_dir)
    if root is None or not path:
        return "absent"
    path_s = str(path)
    # Prefer mount_plan media match (absolute or basename).
    try:
        abs_p = str(Path(path_s).resolve()) if Path(path_s).exists() else path_s
    except Exception:
        abs_p = path_s
    base = os.path.basename(path_s)
    for img in media_entries(root):
        ip = str(img.get("path") or "")
        if ip == path_s or ip == abs_p or os.path.basename(ip) == base:
            return str(img.get("access_stage") or "planned")
        src = str(img.get("source") or "")
        if src and (src == path_s or os.path.basename(src) == base):
            return str(img.get("access_stage") or "planned")

    # Direct evidence: present on disk (and optionally catalogued).
    if _path_exists(root, path_s):
        try:
            from core.artifact_kind import is_non_disk_container
            if is_non_disk_container(path_s):
                return "direct"
        except Exception:
            pass
        if _DISK_EXT_RE.search(path_s):
            # Disk-like file not yet on mount_plan — treat as planned.
            return "planned"
        return "direct"
    # Catalog current?
    try:
        from core.evidence_catalog import load_catalog
        cat = load_catalog(root)
        for u in (cat.get("units") or {}).values():
            if not isinstance(u, dict):
                continue
            up = str(u.get("path") or "")
            if up == path_s or os.path.basename(up) == base:
                if u.get("status") == "current" and _path_exists(root, up):
                    return "direct" if not _DISK_EXT_RE.search(up) else "planned"
                return "absent"
    except Exception:
        pass
    return "absent"


def profile_has_disk(case_dir: str | os.PathLike | None) -> bool:
    root = _case_root(case_dir)
    if root is None:
        return False
    try:
        from core.evidence_profile import ensure_evidence_profile
        profile = ensure_evidence_profile(root, refresh=False)
        present = set(profile.get("present_classes") or [])
        if "disk" in present:
            return True
    except Exception:
        pass
    return bool(media_entries(root))


def _vmdk_chain_tokens(path: str) -> set[str]:
    """Descriptor + flat extent tokens for a VMDK path (or its basename).

    qemu-img flatten of ``VM01.vmdk`` leaves both the descriptor and
    ``VM01-flat.vmdk`` as mount_plan rows. Settling only the descriptor
    would leave the flat extent ``planned`` forever.
    """
    out: set[str] = set()
    if not path:
        return out
    try:
        abs_p = os.path.abspath(os.path.expanduser(path))
    except Exception:
        abs_p = path
    base = os.path.basename(abs_p)
    out.add(abs_p)
    out.add(base)
    lower = base.lower()
    if not lower.endswith(".vmdk"):
        return out
    stem = base[:-5]
    if stem.lower().endswith("-flat"):
        stem = stem[: -len("-flat")]
    parent = os.path.dirname(abs_p)
    for name in (f"{stem}.vmdk", f"{stem}-flat.vmdk"):
        out.add(name)
        if parent:
            out.add(os.path.join(parent, name))
    return out


def _terminal_export_sources(entries: list[dict[str, Any]]) -> set[str]:
    """Basenames/paths satisfied by an export that is opened OR access_failed.

    A durable open attempt on the flattened raw settles the source VMDK chain
    (descriptor + ``*-flat.vmdk`` extents) for pending-open / exit purposes —
    success and honest failure both end the "must still call tsk.mmls" loop.
    """
    out: set[str] = set()
    for e in entries:
        stage = e.get("access_stage")
        if stage not in ("opened", "access_failed"):
            continue
        src = str(e.get("source") or "")
        if src:
            out |= _vmdk_chain_tokens(src)
        p = str(e.get("path") or "")
        if p:
            out.add(os.path.abspath(os.path.expanduser(p)))
            out.add(os.path.basename(p))
            if p.lower().endswith(".vmdk"):
                out |= _vmdk_chain_tokens(p)
    return out


def pending_media_open(
    case_dir: str | os.PathLike | None,
) -> list[dict[str, Any]]:
    """Media entries still awaiting a successful open (or whose file vanished).

    A source VMDK is not pending when its exported raw is opened or
    access_failed (durable open attempt recorded).
    """
    entries = media_entries(case_dir)
    satisfied = _terminal_export_sources(entries)
    pending: list[dict[str, Any]] = []
    for e in entries:
        if e.get("access_stage") not in _PENDING_OPEN:
            continue
        path = str(e.get("path") or "")
        try:
            abs_p = os.path.abspath(os.path.expanduser(path)) if path else ""
        except Exception:
            abs_p = path
        base = os.path.basename(path)
        if abs_p in satisfied or base in satisfied:
            continue
        # Extent / descriptor sibling of a settled VMDK chain.
        if path and (_vmdk_chain_tokens(path) & satisfied):
            continue
        pending.append(e)
    return pending


def media_blocks_degraded_exit(case_dir: str | os.PathLike | None) -> bool:
    """True when access-gated disk media still needs open before exit floor."""
    if not profile_has_disk(case_dir):
        return False
    entries = media_entries(case_dir)
    if not entries:
        # Profile says disk but no mount_plan rows — still block until planned.
        return True
    # Opened or access_failed on the export settles linked source VMDKs.
    if any(e.get("access_stage") in ("opened", "access_failed") for e in entries):
        return bool(pending_media_open(case_dir))
    # All entries already access_failed → do not block (attempt recorded).
    if all(e.get("access_stage") == "access_failed" for e in entries):
        return False
    return bool(pending_media_open(case_dir))


def media_access_summary(
    case_dir: str | os.PathLike | None,
) -> dict[str, Any]:
    entries = media_entries(case_dir)
    by_stage: dict[str, int] = {}
    for e in entries:
        st = str(e.get("access_stage") or "planned")
        by_stage[st] = by_stage.get(st, 0) + 1
    pending = pending_media_open(case_dir)
    return {
        "has_disk": profile_has_disk(case_dir),
        "by_stage": by_stage,
        "pending_open": [
            {
                "path": e.get("path"),
                "access_stage": e.get("access_stage"),
                "recommended_tool": e.get("recommended_tool"),
                "status": e.get("status"),
            }
            for e in pending
        ],
        "blocks_exit": media_blocks_degraded_exit(case_dir),
    }


def disk_media_staged_or_better(case_dir: str | os.PathLike | None) -> bool:
    """True when any disk media is staged/opened (intake exists for task gate)."""
    for e in media_entries(case_dir):
        if e.get("access_stage") in ("staged", "opened", "planned"):
            if e.get("file_exists") or e.get("access_stage") == "planned":
                # planned with file OR staged/opened
                if e.get("access_stage") == "planned" and not e.get("file_exists"):
                    continue
                return True
        if e.get("access_stage") == "staged" and e.get("file_exists"):
            return True
    # evidence_links disk entries
    root = _case_root(case_dir)
    if root is None:
        return False
    try:
        links_path = root / ".atlas" / "evidence_links.json"
        if links_path.is_file():
            import json
            data = json.loads(links_path.read_text(encoding="utf-8"))
            for ent in data.get("entries") or []:
                if isinstance(ent, dict) and str(ent.get("kind") or "").lower() == "disk":
                    return True
    except Exception:
        pass
    return False


def _task_text_is_diskish(task_text: str) -> bool:
    text = (task_text or "").casefold()
    return any(
        tok in text
        for tok in (
            "vmdk", "disk image", "raw image", "tsk.", "fileserver",
            "filesystem", "mmls", "fls", "mount",
        )
    )


def disk_access_terminal(case_dir: str | os.PathLike | None) -> bool:
    """True when every pending disk open is settled (opened or access_failed)."""
    if not profile_has_disk(case_dir):
        return True
    return not pending_media_open(case_dir) and bool(media_entries(case_dir))


def refuse_blocked_missing_evidence(
    case_dir: str | os.PathLike | None,
    task_text: str,
) -> Optional[str]:
    """Return refusal text when disk intake is staged — not 'missing evidence'."""
    if not _task_text_is_diskish(task_text):
        return None
    if not disk_media_staged_or_better(case_dir):
        return None
    pending = pending_media_open(case_dir)
    sample = pending[0] if pending else (media_entries(case_dir) or [{}])[0]
    path = sample.get("path") or "mount_plan entry"
    stage = sample.get("access_stage") or "n/a"
    nxt = sample.get("recommended_tool") or "n/a"
    return (
        "refusing blocked_missing_evidence: disk media is present "
        f"({path}; access_stage={stage}, recommended={nxt}). Open it with "
        "tsk.mmls/tsk.fls (or unload schemas to load the tsk namespace) — do "
        "not mark the task missing-evidence while the image is staged."
    )


def refuse_diskish_answered(
    case_dir: str | os.PathLike | None,
    task_text: str,
) -> Optional[str]:
    """Refuse answered while disk media is still pending open.

    A disk task answered from tabular output alone while the image's raw
    export stays staged is dishonest completion. Allow ``partial`` (honest
    incomplete) or answered after opened/access_failed.
    """
    if not _task_text_is_diskish(task_text):
        return None
    if not profile_has_disk(case_dir):
        return None
    pending = pending_media_open(case_dir)
    if not pending:
        return None
    sample = pending[0]
    return (
        "refusing answered: disk media is still pending open "
        f"({sample.get('path')}; access_stage={sample.get('access_stage')}). "
        "Open with tsk.mmls/tsk.fls, or use status=partial after a durable "
        "access_failed is recorded on mount_plan — do not close the disk "
        "reconstruction task from tabular evidence alone."
    )


_ACCESS_LIMITATION_RE = re.compile(
    r"(?:access[_ -]?failed|disk[- ]level|tsk\.?mmls|non-interactive sudo|"
    r"sudo.*(?:required|password)|parsing.*(?:blocked|unresolvable)|"
    r"evtx.*(?:not (?:present|parsed)|absent)|"
    r"documented limitation|investigation limitation)",
    re.I,
)


def refuse_duplicate_access_limitation(
    case_dir: str | os.PathLike | None,
    description: str,
    *,
    existing_finding_texts: list[str] | None = None,
) -> Optional[str]:
    """Refuse another UNCONFIRMED finding that only restates Access Stage."""
    desc = description or ""
    if not _ACCESS_LIMITATION_RE.search(desc):
        return None
    # Once stage is terminal, one structural note is enough — block piles.
    terminal = disk_access_terminal(case_dir) or any(
        e.get("access_stage") == "access_failed" for e in media_entries(case_dir)
    )
    pending = pending_media_open(case_dir)
    if not terminal and not pending:
        return None
    prior = existing_finding_texts or []
    prior_hits = sum(1 for t in prior if _ACCESS_LIMITATION_RE.search(t or ""))
    if prior_hits >= 1 and (terminal or pending):
        return (
            "refusing duplicate access/limitation finding: Access Stage already "
            f"recorded ({'terminal' if terminal else 'pending open'}). "
            "Cite mount_plan / evidence_access once in Limitations — do not "
            "spawn additional UNCONFIRMED clones."
        )
    return None


# Directory names that say where a case keeps things, not which medium a
# path belongs to.
_MEDIA_LABEL_STOP = frozenset({
    "evidence", "analysis", "exports", "reports", "cases", "case", "home",
    "mnt", "media", "tmp", "var", "opt", "image", "images", "disk", "raw",
    "export", "exported", "mount", "mounted", "data",
})


def media_labels(entry: dict[str, Any]) -> set[str]:
    """The names by which a claim or a tool call refers to this medium: the
    image's file name and stem, the directory it was collected under (the
    operator's label for the host), the segments of its stem that carry a
    digit or a mark, and the mount point it was opened at."""
    labels: set[str] = set()

    def _add(tok: str, min_len: int = 3) -> None:
        tok = (tok or "").strip().lower()
        if len(tok) >= min_len and not tok.isdigit() and tok not in _MEDIA_LABEL_STOP:
            labels.add(tok)

    for key in ("path", "source"):
        raw = str(entry.get(key) or "").replace("\\", "/").rstrip("/")
        if not raw:
            continue
        parts = raw.split("/")
        base = parts[-1]
        stem = base.rsplit(".", 1)[0] if "." in base else base
        _add(base)
        _add(stem)
        if len(parts) >= 2:
            _add(parts[-2], 2)          # the collection directory: a deliberate label
        # Segments of the stem and of the directory that carry a digit or a
        # mark name a host or a medium ("rm#3", "dc01"); plain words ("data",
        # "cdrive") and image extensions written as words ("e01") do not.
        for seg in re.split(r"[_\-\s]+", stem + " " + (parts[-2] if len(parts) >= 2 else "")):
            if re.search(r"[\d#]", seg) and not _DISK_EXT_RE.search("." + seg):
                _add(seg)
    mount = ((entry.get("mount_result") or {}).get("mount_point")
             or entry.get("mount_point") or "")
    for seg in str(mount).replace("\\", "/").strip("/").split("/")[-2:]:
        _add(seg)
    return labels


def media_named_in(entry: dict[str, Any], text: str) -> bool:
    """Whether ``text`` (a claim, its evidence, the calls it cites) refers to
    this medium by one of its labels, as a whole word."""
    low = (text or "").lower()
    if not low:
        return False
    return any(re.search(rf"(?<![\w]){re.escape(label)}(?![\w])", low)
               for label in media_labels(entry))


def absence_escape_blocked_by_access(
    case_dir: str | os.PathLike | None,
    about_text: str = "",
) -> Optional[str]:
    """Refuse prose 'absent from evidence' when disk media was never opened.

    Distinguishes never-opened (staged/planned) from inspected-absent.
    ``access_failed`` does not block the escape (collection genuinely failed).

    ``about_text`` - the claim, its supporting evidence and the calls it
    cites - scopes the check to the media the claim is about: an absence
    asserted of an opened image is not blocked because some other image in
    the case is still waiting to be opened (media_named_in). A claim that
    names no medium at all is judged against every pending one, as before.
    """
    root = _case_root(case_dir)
    if root is None:
        return None
    if not profile_has_disk(root):
        return None
    entries = media_entries(root)
    pending = pending_media_open(root)
    if entries and not pending:
        return None
    if not entries:
        # Disk class present but nothing planned yet — still block escape.
        sample, stage = "disk image", "planned"
    else:
        if about_text:
            named = [e for e in entries if media_named_in(e, about_text)]
            named_pending = [e for e in pending if media_named_in(e, about_text)]
            if named and not named_pending:
                return None
            if named_pending:
                pending = named_pending
        sample = (pending[0] if pending else {}).get("path") or "disk image"
        stage = (pending[0] if pending else {}).get("access_stage") or "planned"
    return (
        f"access_not_opened: disk media is {stage} ({sample}) — cannot treat "
        "event-log / filesystem sources as 'absent from evidence' until the "
        "image is opened (tsk.mmls/tsk.fls) or access_failed is recorded."
    )


def winevt_search_attempted_in_cmds(cmds: list) -> bool:
    """True when the trace shows a search of a Windows event log, in
    whichever layout the media uses (core.eventlog_layout). A search of the
    extracted $MFT for the log directory, a path resolution to it and a
    parse of a log are all real attempts, so the check reads the command,
    the tool name and the arguments, not the bare command line alone."""
    from core.eventlog_layout import search_attempted
    return search_attempted(cmds or [])


def absence_escape_blocked_for_winevt(
    case_dir: str | os.PathLike | None,
    cmds: list | None = None,
    claim_text: str = "",
) -> Optional[str]:
    """Block 'the event log is absent' when disk is opened but the log of
    the layout this media uses was never searched.

    Complements :func:`absence_escape_blocked_by_access` (never-opened case).
    The layout is derived from the evidence (core.eventlog_layout): a trace
    that listed the legacy .Evt logs is asked for a legacy search, one that
    listed winevt/Logs for an EVTX search, and the claim's own words decide
    when the trace shows neither. When nothing establishes a layout there
    is no requirement to state, and the escape is not blocked: a demand for
    artifacts the media cannot hold would never be satisfied.
    """
    from core.eventlog_layout import demand, layouts_in_evidence, search_attempted
    root = _case_root(case_dir)
    if root is None:
        return None
    if not profile_has_disk(root):
        return None
    entries = media_entries(root)
    if not entries:
        return None
    pending = pending_media_open(root)
    if pending:
        # Never-opened path is handled by absence_escape_blocked_by_access.
        return None
    opened = any(e.get("access_stage") == "opened" for e in entries)
    if not opened:
        return None
    layouts = layouts_in_evidence(cmds or [], claim_text)
    if not layouts:
        return None
    if search_attempted(cmds or [], layouts):
        return None
    return (
        "eventlog_not_searched: disk media is opened but the trace never "
        f"searched the Windows event log this media uses. Search {demand(layouts)} "
        "before claiming it is absent from evidence."
    )


def staged_media_basenames(case_dir: str | os.PathLike | None) -> list[str]:
    """Basenames of staged/opened/planned media for DAIR evidence grounding."""
    names: list[str] = []
    for e in media_entries(case_dir):
        if e.get("access_stage") in ("planned", "staged", "opened"):
            p = str(e.get("path") or "")
            if p:
                names.append(os.path.basename(p).lower())
            src = str(e.get("source") or "")
            if src:
                names.append(os.path.basename(src).lower())
    return names


def export_raw_registered(case_dir: str | os.PathLike | None) -> bool:
    """True when a staged/exported raw still exists on disk."""
    for e in media_entries(case_dir):
        if e.get("origin") == "export_raw" and e.get("file_exists"):
            if e.get("access_stage") in ("staged", "opened", "planned"):
                return True
    return False


def any_media_opened(case_dir: str | os.PathLike | None) -> bool:
    return any(e.get("access_stage") == "opened" for e in media_entries(case_dir))


def _normalize_tsk_tool_name(tool_name: str) -> str:
    """Collapse MCP double-prefix names: tsk_tsk_mmls → tsk_mmls."""
    n = (tool_name or "").strip().replace(".", "_")
    while n.startswith("tsk_tsk_"):
        n = "tsk_" + n[len("tsk_tsk_"):]
    return n


def is_tsk_open_tool(tool_name: str) -> bool:
    n = (tool_name or "").strip()
    if not n:
        return False
    if n in _TSK_OPEN_TOOLS:
        return True
    norm = _normalize_tsk_tool_name(n)
    if norm in _TSK_OPEN_TOOLS or norm.replace("_", ".", 1) in _TSK_OPEN_TOOLS:
        return True
    # Bare stem: mmls / fls / fsstat after namespace strip
    stem = norm
    if stem.startswith("tsk_"):
        stem = stem[4:]
    return stem in ("mmls", "fls", "fsstat")


def parse_tool_result_success(result_text: str) -> tuple[bool, str]:
    """Interpret agent-facing tool result text into (success, error_snippet).

    JSON bodies with ``success: false`` (incl. failure_class=sudo_auth) must
    not be treated as success merely because they lack a TOOL ERROR prefix.
    """
    text = (result_text or "").strip()
    if not text:
        return False, "empty tool result"
    if text.startswith(("TOOL ERROR", "ERROR")):
        return False, text[:300]
    try:
        import json
        # Toolbox may wrap JSON; find first object.
        start = text.find("{")
        if start >= 0:
            data = json.loads(text[start:])
            if isinstance(data, dict) and "success" in data:
                ok = bool(data.get("success"))
                err = str(
                    data.get("stderr")
                    or data.get("error")
                    or data.get("failure_class")
                    or ""
                )[:300]
                return ok, err
    except Exception:
        pass
    # Non-JSON success path (rare for MCP tools).
    if '"success": false' in text.lower() or '"success":false' in text.lower():
        return False, text[:300]
    return True, ""


def record_open_from_tool(
    case_dir: str | os.PathLike | None,
    *,
    tool_name: str,
    cmd_or_args: str,
    success: bool,
    error: str = "",
) -> Optional[dict[str, Any]]:
    """Persist opened / access_failed on mount_plan after TSK (or similar) tools."""
    root = _case_root(case_dir)
    if root is None or not is_tsk_open_tool(tool_name):
        return None
    # Extract a path-like token from args/cmd.
    blob = cmd_or_args or ""
    candidates: list[str] = []
    for m in re.finditer(
        r'["\']([^"\']+\.(?:raw|dd|img|vmdk|e01|ex01|vhd|vhdx|iso))["\']',
        blob,
        re.I,
    ):
        candidates.append(m.group(1))
    if not candidates:
        for m in re.finditer(
            r'(/[^\s"\']+\.(?:raw|dd|img|vmdk|e01|ex01|vhd|vhdx|iso))',
            blob,
            re.I,
        ):
            candidates.append(m.group(1))
    if not candidates:
        # The raw device ewfmount exposes (mnt/<stem>/ewf/ewf1) is what the
        # mount helpers tell the analyst to run TSK against when a volume
        # does not mount; reading it opens the image it belongs to.
        stems = {m.group(1) for m in re.finditer(r'mnt/([^/\s"\']+)/ewf/ewf\d+', blob)}
        if stems:
            try:
                from core.mount_plan import _mount_stem, load_mount_plan
                for img in load_mount_plan(root).get("images") or []:
                    if _mount_stem(img) in stems and img.get("path"):
                        candidates.append(str(img["path"]))
            except Exception:  # noqa: BLE001 - an unreadable plan leaves the fallback below
                pass
    if not candidates:
        # Fall back: mark first staged/planned export if only one exists.
        pending = [
            e for e in media_entries(root)
            if e.get("access_stage") in ("staged", "planned") and e.get("file_exists")
        ]
        if len(pending) == 1:
            candidates = [str(pending[0].get("path"))]
    if not candidates:
        return None
    image_path = candidates[0]
    try:
        from core.mount_plan import mark_image_opened, mark_image_access_failed
        if success:
            return mark_image_opened(root, image_path, tool=tool_name)
        return mark_image_access_failed(
            root, image_path, error=error or f"{tool_name} failed", tool=tool_name,
        )
    except Exception:
        return None
