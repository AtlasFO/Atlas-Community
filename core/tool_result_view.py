"""Agent-facing tool result compaction for context-budget stewardship.

When a tool wrote durable artifacts but stdout was truncated for the LLM,
rewrite the payload to ``gate: artifact_ready`` so the investigate latch
does not treat success-as-truncation as a reason to re-run the same parse.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any


_ARTIFACT_KEYS = (
    "output_path", "output_file", "csv_path", "json_path",
    "produced", "produced_files", "artifact_paths", "files_written",
)

# Keys that can only mean "this tool wrote that file". ``csv_path`` and
# ``json_path`` are ambiguous across the tree — export_tools.write_iocs
# reports a file it created, antiforensics.af_event_log_clear reports the CSV
# it *read* — and a detector's verdict was being replaced by "Parse/write
# succeeded … do NOT re-run this parser", so the question it answers stayed
# unanswered however often it was asked. A small, complete result is only
# compacted away when the tool says it produced something.
_PRODUCED_KEYS = (
    "output_path", "output_file",
    "produced", "produced_files", "artifact_paths", "files_written",
)

# Disk / container media — never advertise table.* against these paths.
_DISK_MEDIA_EXTS = frozenset({
    ".raw", ".dd", ".img", ".vmdk", ".e01", ".ex01", ".vhd", ".vhdx",
    ".qcow2", ".iso", ".bin",
})
_TABULAR_EXTS = frozenset({
    ".csv", ".tsv", ".tab", ".xlsx", ".xlsm", ".jsonl", ".json",
})


def _existing_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if isinstance(p, str) and p and os.path.isfile(p):
            out.append(p)
    return out


def _collect_artifact_paths(
    data: dict[str, Any], keys: tuple[str, ...] = _ARTIFACT_KEYS,
) -> list[str]:
    found: list[str] = []
    for key in keys:
        val = data.get(key)
        if isinstance(val, str):
            found.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    found.append(item)
                elif isinstance(item, dict):
                    for k in ("path", "file", "output_path"):
                        if isinstance(item.get(k), str):
                            found.append(item[k])
    # EvtxECmd / EZ style: output_dir + output_file
    out_dir = data.get("output_dir")
    out_file = data.get("output_file")
    if isinstance(out_dir, str) and isinstance(out_file, str):
        found.append(os.path.join(out_dir, out_file))
    # Nested result wrappers
    for nest in ("result", "data", "meta"):
        inner = data.get(nest)
        if isinstance(inner, dict):
            found.extend(_collect_artifact_paths(inner, keys))
    # Dedupe preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for p in found:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return _existing_paths(uniq)


def _ext(path: str) -> str:
    return os.path.splitext(path or "")[1].lower()


def _is_disk_media(path: str) -> bool:
    return _ext(path) in _DISK_MEDIA_EXTS


def _is_tabular_artifact(path: str) -> bool:
    return _ext(path) in _TABULAR_EXTS


def _has_data_rows(path: str) -> bool:
    """True when a *text tabular* file has at least one data row.

    Binary disk images must not count — reading "lines" from .raw is
    meaningless and previously forced table.* compaction of VMDK exports.
    """
    if _is_disk_media(path) or not _is_tabular_artifact(path):
        return False
    try:
        with open(path, "rb") as fh:
            fh.readline()
            for line in fh:
                if line.strip():
                    return True
    except OSError:
        return False
    return False


def _disk_ready_payload(
    data: dict[str, Any],
    usable: list[str],
    *,
    truncated: bool,
    force: bool,
) -> dict[str, Any]:
    next_tool = (
        data.get("recommended_next_tool")
        or "tsk.mmls"
    )
    note = (data.get("note") or "").strip()
    summary = (
        "Disk/raw image materialised; agent-facing stdout compacted. "
        f"Next: {next_tool} → tsk.fls (filesystem orientation). "
        "Do NOT query this path with table.* — it is not a CSV/JSON export. "
        "Do NOT re-run the exporter on the same input."
    )
    if note:
        summary = summary + " " + note[:400]
    stats = {
        "artifact_count": len(usable),
        "bytes": sum(os.path.getsize(p) for p in usable if os.path.isfile(p)),
        "artifact_kind": "disk_media",
    }
    return {
        "success": True,
        "gate": "artifact_ready",
        "mode": "disk_open" if force else "compact",
        "truncated": truncated or force,
        "artifact_paths": usable,
        "summary": summary,
        "stats": stats,
        "recommended_next_tool": next_tool,
        "mount_plan_registered": data.get("mount_plan_registered"),
        "hint": (
            f"Call {next_tool} on the raw/image path. "
            "table.* is only for CSV/TSV/XLSX/JSONL under evidence/ or analysis/."
        ),
    }


def compact_if_artifact_ready(
    data: dict[str, Any],
    *,
    force: bool = False,
) -> dict[str, Any] | None:
    """If truncated but artifacts exist, return a compact artifact_ready dict.

    When ``force`` is True (disk-first large parse), compact whenever any
    durable artifact exists — even if stdout was not truncated.

    Returns None when no rewrite is needed.
    """
    if not isinstance(data, dict):
        return None
    if data.get("gate") in ("input_scale", "context_budget", "artifact_ready"):
        return None
    truncated = bool(data.get("truncated"))
    artifacts = _collect_artifact_paths(data)
    if not artifacts:
        return None

    disk_arts = [p for p in artifacts if _is_disk_media(p)]
    tabular_arts = [p for p in artifacts if _is_tabular_artifact(p)]

    # Disk/raw export path — kind-aware compact (preserve TSK next-step).
    if disk_arts and not tabular_arts:
        stdout = str(data.get("stdout") or "")
        huge_stdout = len(stdout) > 8_000
        if not force and not truncated and not huge_stdout:
            # Still compact when the tool already declared a next-step /
            # mount_plan registration (export_raw success).
            if not (data.get("recommended_next_tool")
                    or data.get("mount_plan_registered")
                    or data.get("note")):
                return None
        return _disk_ready_payload(
            data, disk_arts, truncated=truncated or huge_stdout, force=force,
        )

    # Prefer rewrite when truncated OR when stdout is huge noise but CSV exists
    stdout = str(data.get("stdout") or "")
    huge_stdout = len(stdout) > 8_000
    if not force and not truncated and not huge_stdout:
        # Still compact bulk successes that already wrote CSVs with rows —
        # but only on paths the tool says it *produced*. A detector that
        # merely reports the CSV it read keeps its own answer; nothing needs
        # protecting here, since the payload is small and complete.
        produced = _collect_artifact_paths(data, _PRODUCED_KEYS)
        if not any(_has_data_rows(p) for p in produced):
            return None
    usable = [
        p for p in artifacts
        if (os.path.isfile(p) and (
            _has_data_rows(p) or (
                _is_tabular_artifact(p) and os.path.getsize(p) > 0
            ) or force))
    ]
    # Never list raw disk paths in a table.*-oriented compact payload.
    usable = [p for p in usable if not _is_disk_media(p)]
    if not usable:
        return None
    stats = {
        "artifact_count": len(usable),
        "bytes": sum(os.path.getsize(p) for p in usable if os.path.isfile(p)),
        "artifact_kind": "tabular",
    }
    profiles = []
    try:
        from core.coverage import profile_tabular
        for p in usable[:3]:
            if p.lower().endswith((".csv", ".tsv", ".tab")):
                profiles.append(profile_tabular(p))
    except Exception:
        profiles = []
    if profiles:
        # Keep agent payload small: drop empty top_values noise
        slim = []
        for pr in profiles:
            slim.append({
                k: pr.get(k)
                for k in (
                    "path", "bytes", "rows", "columns",
                    "time_column", "time_min", "time_max", "top_values",
                )
                if pr.get(k) not in (None, {}, [], 0, "")
            })
        stats["profiles"] = slim
    return {
        "success": True,
        "gate": "artifact_ready",
        "mode": "disk_first" if force else "compact",
        "truncated": truncated or huge_stdout or force,
        "artifact_paths": usable,
        "summary": (
            "Parse/write succeeded; agent-facing stdout compacted for context. "
            "Query artifact_paths with table.table_query / table_grep. "
            "Do NOT re-run this parser on the same input."
            + (
                " Disk-first: full coverage (if needed) is table.* row/time "
                "windows on these artifacts — not a raw re-dump."
                if force else ""
            )
        ),
        "stats": stats,
        "hint": data.get("hint") or (
            "Use table.* on the CSV/JSON artifact; full tool stdout is in "
            "the execution trace / spill if needed."
        ),
    }


def maybe_compact_rendered(text: str) -> str:
    """Best-effort: if rendered tool JSON is truncate+artifact, rewrite it."""
    raw = (text or "").strip()
    if not raw:
        return text
    prefix = ""
    blob = raw
    if raw.startswith("TOOL ERROR:") or raw.startswith("TOOL INFO:"):
        nl = raw.find("\n")
        if nl < 0:
            return text
        prefix = raw[:nl + 1]
        blob = raw[nl + 1:]
    if not blob.lstrip().startswith("{"):
        return text
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        # Truncated JSON — try to detect artifact paths via regex
        paths = re.findall(
            r'"(?:output_path|csv_path|artifact_paths)"\s*:\s*"([^"]+)"',
            blob,
        )
        if "truncated" in blob and paths:
            compact = {
                "success": True,
                "gate": "artifact_ready",
                "truncated": True,
                "artifact_paths": _existing_paths(paths),
                "summary": (
                    "Tool output was truncated in chat but artifacts were "
                    "written. Query them with table.*; do not re-run."
                ),
            }
            return prefix + json.dumps(compact, indent=2)
        return text
    if not isinstance(data, dict):
        return text
    compact = compact_if_artifact_ready(data)
    if compact is None:
        return text
    return prefix + json.dumps(compact, indent=2)
