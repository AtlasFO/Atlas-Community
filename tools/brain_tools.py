"""Contextual Brain retrieval for the live investigator.

``brain.consult`` treats the Brain as a searchable forensic wiki: the agent
asks only when relevant, receives a few ranked notes, and skips notes already
returned earlier in the same run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

mcp = FastMCP("brain")

_CONSULT_STATE = "analysis/brain_consulted.json"
_DEFAULT_LIMIT = 3
_MAX_LIMIT = 5
_SNIPPET_CHARS = 900


def _case_dir() -> Path | None:
    try:
        from core import execution_log as _elog
        cd = (_elog.case_dir() or "").strip()
        if cd:
            return Path(cd)
    except Exception:
        pass
    cwd = Path.cwd()
    if (cwd / "CASE.md").is_file() or (cwd / ".atlas").is_dir():
        return cwd
    return None


def _active_case_ids(case_dir: Path | None) -> set[str]:
    if case_dir is None:
        return set()
    try:
        from agent.prompts import _case_identifiers
        return set(_case_identifiers(case_dir))
    except Exception:
        return {case_dir.name.lower()}


def _same_case(meta: dict, active_ids: set[str]) -> bool:
    if not active_ids:
        return False
    try:
        from agent.prompts import _same_case as _sc
        return _sc(meta, active_ids)
    except Exception:
        origin = (meta or {}).get("origin") or {}
        cid = str(origin.get("case_id") or "").lower()
        return bool(cid and cid in active_ids)


def _load_consulted(case_dir: Path | None) -> set[str]:
    if case_dir is None:
        return set()
    path = case_dir / _CONSULT_STATE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("paths") or [])
    except (OSError, json.JSONDecodeError, TypeError):
        return set()


def _save_consulted(case_dir: Path | None, paths: set[str]) -> None:
    if case_dir is None:
        return
    path = case_dir / _CONSULT_STATE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "paths": sorted(paths),
    }, indent=2) + "\n", encoding="utf-8")


def consult_brain(query: str,
                  context: str = "",
                  limit: int = _DEFAULT_LIMIT,
                  force: bool = False,
                  case_dir: Path | None = None) -> dict[str, Any]:
    """Search durable Brain notes for ``query`` (+ optional ``context``).

    Returns a compact payload the agent can apply immediately. Empty ``notes``
    means continue the investigation without Brain help.
    """
    if os.environ.get("ATLAS_NO_BRAIN"):
        return {"ok": True, "notes": [], "count": 0,
                "reason": "ATLAS_NO_BRAIN", "query": query}

    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "query is required",
                "notes": [], "count": 0}

    case_dir = case_dir or _case_dir()
    active_ids = _active_case_ids(case_dir)
    consulted = set() if force else _load_consulted(case_dir)

    lim = max(1, min(int(limit or _DEFAULT_LIMIT), _MAX_LIMIT))
    search_q = q
    if context and context.strip():
        search_q = f"{q} {context.strip()[:200]}"

    try:
        from core.brain.search import search
        from core.brain.store import brain_root
        if not brain_root().is_dir():
            return {"ok": True, "notes": [], "count": 0,
                    "reason": "no_brain", "query": q}
        raw = search(search_q,
                     types=["concept", "tool", "technique", "actor", "memory"],
                     limit=lim * 4)
    except Exception as e:
        return {"ok": False, "error": f"{e.__class__.__name__}: {e}",
                "notes": [], "count": 0, "query": q}

    notes = []
    newly: set[str] = set()
    for hit in raw:
        if _same_case(hit.meta or {}, active_ids):
            continue
        if hit.rel_path in consulted:
            continue
        # Skip inbox candidates — only durable knowledge.
        if str(hit.rel_path).startswith("inbox/"):
            continue
        body = (hit.body or "").strip()
        if body.startswith("# "):
            body = body.split("\n", 1)[1].strip() if "\n" in body else ""
        notes.append({
            "title": hit.title,
            "path": hit.rel_path,
            "type": hit.type,
            "score": round(float(hit.score), 1),
            "snippet": hit.snippet,
            "body": body[:_SNIPPET_CHARS],
            "knowledge_kind": str((hit.meta or {}).get("knowledge_kind") or ""),
        })
        newly.add(hit.rel_path)
        if len(notes) >= lim:
            break

    if newly and case_dir is not None:
        _save_consulted(case_dir, consulted | newly)

    return {
        "ok": True,
        "query": q,
        "notes": notes,
        "count": len(notes),
        "skipped_already_consulted": len(consulted),
        "hint": ("No matching Brain notes — continue normally."
                 if not notes else
                 "Apply relevant lessons; do not treat as case evidence."),
    }


@mcp.tool()
def consult(query: str,
            context: str = "",
            limit: int = 3,
            force: bool = False) -> dict:
    """Consult Atlas's cross-case Brain (forensic wiki) for reusable lessons.

    Call when approaching an artifact class, tool, or technique where prior
    DFIR experience might help — e.g. EVTX analysis, Volatility plugins,
    Scheduled Tasks persistence, prefetch interpretation.

    Returns zero or more short notes. If notes is empty, continue the
    investigation normally. Do not re-consult the same topic unless force=true.
    Never write to the Brain from this tool.
    """
    return consult_brain(query, context=context, limit=limit, force=force)


@mcp.tool()
def search_notes(query: str, limit: int = 5) -> dict:
    """Search durable Brain notes (CLI-equivalent of ``atlas brain search``).

    Prefer ``brain.consult`` during investigations — it dedups per run and
    excludes same-case provenance. Use this for broader exploration.
    """
    return consult_brain(query, limit=limit, force=True)
