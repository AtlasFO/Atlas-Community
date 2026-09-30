"""Mapper dispatch — tool output → readers → forensic mapper → builder."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from plugins.timeline_builder.builder import TimelineBuilder
from plugins.timeline_builder.config import TimelineConfig
from plugins.timeline_builder.mapper.forensic import MapContext, map_record
from plugins.timeline_builder.mapper.readers import (
    read_inline_rows,
    reader_for_path,
    rows_from_json_payload,
)

# MCP tools that never produce forensic timeline evidence
_SKIP_TOOL_PREFIXES = (
    "dair_", "reason_", "coverage_", "accuracy_", "misc_record_",
    "misc_start_", "misc_write_", "misc_export_", "misc_serve_",
    "misc_clear_", "monitor_", "respond_", "correlate_",
)

_FINALIZE_TOOLS = frozenset({
    "misc_write_final_report",
    "misc_write_projected_final_report",
    "misc_export_execution_log",
})


def extract_payload(result: Any) -> dict | None:
    """Normalize MCP tool return value to a dict."""
    if isinstance(result, dict):
        return result
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        return sc
    content = getattr(result, "content", None)
    if not content:
        return None
    for block in content:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _should_skip_tool(tool_name: str) -> bool:
    base = tool_name.split(".")[-1] if "." in tool_name else tool_name
    return any(base.startswith(p) or tool_name.startswith(p) for p in _SKIP_TOOL_PREFIXES)


def _artifact_paths(args: dict, payload: dict) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for key in ("output_csv", "path", "mft_csv_path", "system_hive_csv", "file_path"):
        for src in (payload, args):
            v = src.get(key) if isinstance(src, dict) else None
            if isinstance(v, str) and v and os.path.isfile(v) and v not in seen:
                seen.add(v)
                paths.append(v)
    return paths


def process_tool_result(
    tool_name: str,
    args: dict,
    result: Any,
    *,
    evidence_ref: str = "",
    call_id: str = "",
) -> int:
    """Map one tool invocation. Returns count of events appended."""
    if _should_skip_tool(tool_name):
        return 0
    payload = extract_payload(result)
    if not payload or payload.get("success") is False:
        return 0

    try:
        from core.execution_log import log
        case_dir = log.case_dir()
    except Exception:
        case_dir = None
    if not case_dir:
        return 0

    builder = TimelineBuilder.for_case(case_dir)
    if builder is None:
        return 0

    config = TimelineConfig.load(Path(case_dir))
    ctx = MapContext(
        original_tool=tool_name,
        evidence_reference=evidence_ref,
        call_id=call_id,
    )
    count = 0

    for path in _artifact_paths(args, payload):
        reader_cls = reader_for_path(path)
        if reader_cls is None:
            continue
        for rec in reader_cls.read_rows(path, max_rows=config.max_rows_per_artifact):
            ev = map_record(rec, ctx, config)
            if ev:
                if isinstance(ev, list):
                    for item in ev:
                        builder.append(item)
                        count += 1
                else:
                    builder.append(ev)
                    count += 1

    inline = rows_from_json_payload(payload)
    if inline:
        ap = str(args.get("path") or payload.get("path") or "")
        for rec in read_inline_rows(inline, artifact_path=ap):
            ev = map_record(rec, ctx, config)
            if ev:
                if isinstance(ev, list):
                    for item in ev:
                        builder.append(item)
                        count += 1
                else:
                    builder.append(ev)
                    count += 1

    return count


def should_finalize(tool_name: str, result: Any) -> bool:
    if tool_name not in _FINALIZE_TOOLS:
        return False
    payload = extract_payload(result)
    return bool(payload and payload.get("success") is not False)
