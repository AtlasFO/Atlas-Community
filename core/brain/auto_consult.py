"""Proactive Brain consultation on forensic tool use.

``brain.consult`` remains available for explicit agent calls. This module
additionally consults the Brain **once per topic per run** when a matching
forensic tool succeeds — so EVTX / MFT / Chainsaw / persistence work gets
wiki hints without relying on the LLM to remember to ask.

Token-efficient: skips when disabled, when no notes match, when the topic
was already consulted, and never consults on Brain tools themselves.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# topic_id → (search query, human label)
# Matched against the MCP tool name (underscored). First hit wins.
_TOPIC_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"evtx|chainsaw|sigma_hunt|hayabusa", re.I),
     "windows event log EVTX analysis gotchas", "EVTX / event logs"),
    (re.compile(r"prefetch|amcache|shimcache|srum", re.I),
     "Windows execution artifacts Prefetch Amcache", "execution artifacts"),
    (re.compile(r"schtask|scheduled.?task|atjobs|task_scheduler", re.I),
     "Scheduled Tasks persistence investigation", "Scheduled Tasks / persistence"),
    (re.compile(r"\bmft\b|fls_|icat_|istat_|tsk_.*mft|parse_mft", re.I),
     "NTFS MFT analysis lessons", "MFT / NTFS"),
    (re.compile(r"regripper|recmd|registry|amcache_parser|shellbags", re.I),
     "Windows registry forensic analysis", "registry"),
    (re.compile(r"vol_|volatility|memprocfs", re.I),
     "Volatility memory forensics gotchas", "memory / Volatility"),
    (re.compile(r"plaso|psort|timeline", re.I),
     "plaso timeline analysis workflow", "timeline / plaso"),
    (re.compile(r"yara|yarascan", re.I),
     "YARA hunting in DFIR investigations", "YARA"),
    (re.compile(r"browser|chrome|firefox|edge_history|webcache", re.I),
     "browser forensics artifacts", "browser"),
    (re.compile(r"usn|journal", re.I),
     "USN journal forensic analysis", "USN journal"),
    (re.compile(r"lnk|jump.?list|automatic.?destinations", re.I),
     "LNK and Jump List forensics", "LNK / Jump Lists"),
    (re.compile(r"persistence|autoruns|services_svc", re.I),
     "Windows persistence mechanisms DFIR", "persistence"),
]

_SKIP_TOOLS = re.compile(
    r"^(brain_|atlas_|reason_|dair_|accuracy_|job_|claim_|"
    r"misc_start_execution|misc_export_execution|misc_record_|"
    r"misc_inventory|misc_current_investigation|misc_update_investigation|"
    r"misc_write_|misc_serve_dashboard)",
    re.I,
)

_TOPICS_STATE = "analysis/brain_auto_topics.json"
_MAX_NOTES = 2
_MAX_BODY = 500
_MAX_BLOCK = 1800


def auto_consult_enabled() -> bool:
    if (os.environ.get("ATLAS_NO_BRAIN") or "").strip().lower() in (
            "1", "true", "yes", "on"):
        return False
    if (os.environ.get("ATLAS_NO_BRAIN_AUTO") or "").strip().lower() in (
            "1", "true", "yes", "on"):
        return False
    return True


def topic_for_tool(tool_name: str) -> tuple[str, str] | None:
    """Return (topic_id, query) for a tool, or None if not a consult trigger."""
    name = (tool_name or "").strip()
    if not name or _SKIP_TOOLS.search(name):
        return None
    for pattern, query, label in _TOPIC_RULES:
        if pattern.search(name):
            # Stable id from label slug
            tid = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
            return tid, query
    return None


def _case_dir() -> Path | None:
    try:
        from core import execution_log as _elog
        cd = (_elog.case_dir() or "").strip()
        if cd:
            return Path(cd)
    except Exception:
        pass
    return None


def _load_topics(case_dir: Path) -> set[str]:
    path = case_dir / _TOPICS_STATE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("topics") or [])
    except (OSError, json.JSONDecodeError, TypeError):
        return set()


def _save_topics(case_dir: Path, topics: set[str]) -> None:
    path = case_dir / _TOPICS_STATE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"topics": sorted(topics)}, indent=2) + "\n",
                    encoding="utf-8")


def format_wiki_block(notes: list[dict], *, label: str, query: str) -> str:
    lines = [
        "",
        "────────────────────────────────────────",
        f"BRAIN WIKI (auto · {label})",
        f"Prior cross-case lessons for: {query}",
        "Advisory only — verify against this case's evidence.",
        "",
    ]
    for n in notes:
        title = n.get("title") or n.get("path") or "note"
        path = n.get("path") or ""
        body = (n.get("body") or n.get("snippet") or "").strip()[:_MAX_BODY]
        lines.append(f"• {title} (`{path}`)")
        if body:
            lines.append(body)
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"
    return text[:_MAX_BLOCK]


def consult_for_tool(tool_name: str,
                     case_dir: Path | None = None) -> dict[str, Any] | None:
    """If this tool warrants a first-time topic consult, return a wiki block.

    Returns ``None`` when no enrichment should be attached.
    """
    if not auto_consult_enabled():
        return None
    hit = topic_for_tool(tool_name)
    if not hit:
        return None
    topic_id, query = hit
    raw = case_dir if case_dir is not None else _case_dir()
    if raw is None:
        return None
    case_dir = Path(raw) if not isinstance(raw, Path) else raw
    seen = _load_topics(case_dir)
    if topic_id in seen:
        return None

    # Mark topic claimed even if empty — avoids re-searching every call.
    seen.add(topic_id)
    try:
        _save_topics(case_dir, seen)
    except OSError:
        pass

    try:
        from tools.brain_tools import consult_brain
        result = consult_brain(query, limit=_MAX_NOTES, case_dir=case_dir)
    except Exception:
        return None
    notes = (result or {}).get("notes") or []
    if not notes:
        return {"topic": topic_id, "query": query, "notes": [], "block": None}

    # Resolve label from topic_id
    label = topic_id.replace("-", " ")
    for _pat, _q, lab in _TOPIC_RULES:
        tid = re.sub(r"[^a-z0-9]+", "-", lab.lower()).strip("-")
        if tid == topic_id:
            label = lab
            break
    block = format_wiki_block(notes, label=label, query=query)
    return {"topic": topic_id, "query": query, "notes": notes, "block": block}


def append_text_to_result(result: Any, text: str) -> Any:
    """Best-effort append of a text block onto an MCP tool result."""
    if not text:
        return result
    try:
        # FastMCP / MCP CallToolResult-style
        content = getattr(result, "content", None)
        if content is not None:
            try:
                from mcp.types import TextContent
                new_c = list(content) + [TextContent(type="text", text=text)]
                return result.model_copy(update={"content": new_c})
            except Exception:
                pass
        if isinstance(result, dict):
            out = dict(result)
            prev = str(out.get("brain_wiki") or "")
            out["brain_wiki"] = (prev + text).strip()
            # Also surface in a common string field agents already read.
            for key in ("stdout", "message", "result"):
                if isinstance(out.get(key), str) and out[key]:
                    out[key] = out[key].rstrip() + "\n" + text
                    break
            else:
                out.setdefault("message", text)
            return out
        if isinstance(result, str):
            return result.rstrip() + "\n" + text
    except Exception:
        return result
    return result


def maybe_enrich_tool_result(tool_name: str, result: Any,
                             case_dir: Path | None = None) -> Any:
    """Middleware hook: attach Brain wiki block when appropriate."""
    info = consult_for_tool(tool_name, case_dir=case_dir)
    if not info or not info.get("block"):
        return result
    return append_text_to_result(result, info["block"])
