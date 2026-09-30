"""Full-coverage chunk planning — last resort when bootstrap left the LLM dark.

Prefer **one disk parse → chunked ``table.*`` queries** over re-running bulk
parsers. Applies to any durable tabular artifact (CSV/TSV/JSONL), not only
EVTX. Raw sources without an artifact get coarse time/byte *hints* for a
second-pass tool call when the tool supports narrowing.
"""
from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Any, Optional

from core.envfile import env_int

# Row windows sized for small-context models (~few KB of preview per chunk).
_MIN_ROWS = env_int("ATLAS_COVERAGE_MIN_ROWS", 2000)
_MAX_ROWS = env_int("ATLAS_COVERAGE_MAX_ROWS", 15000)
_MAX_CHUNKS = env_int("ATLAS_COVERAGE_MAX_CHUNKS", 40)

_TIME_COL_RE = re.compile(
    r"(?i)^(time|timestamp|datetime|date|timecreated|recordid|@timestamp)$"
)


def _row_chunk_size(available_tool_tokens: int) -> int:
    # ~8 chars/token rough for CSV cells; aim for ~1/4 of tool budget per chunk.
    budget_chars = max(8_000, int(available_tool_tokens) * 2)
    rows = budget_chars // 120
    return max(_MIN_ROWS, min(_MAX_ROWS, rows))


def profile_tabular(path: str, sample_rows: int = 2000) -> dict[str, Any]:
    """Lightweight CSV/TSV profile for artifact_ready summaries."""
    p = Path(path)
    out: dict[str, Any] = {
        "path": str(p),
        "bytes": 0,
        "rows": 0,
        "columns": [],
        "time_column": None,
        "time_min": None,
        "time_max": None,
        "top_values": {},
    }
    try:
        out["bytes"] = p.stat().st_size
    except OSError:
        return out
    if not p.is_file() or out["bytes"] == 0:
        return out

    delim = "\t" if p.suffix.lower() in {".tsv", ".tab"} else ","
    try:
        with open(p, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter=delim)
            try:
                header = next(reader)
            except StopIteration:
                return out
            cols = [c.strip() for c in header]
            out["columns"] = cols[:40]
            time_idx = None
            for i, c in enumerate(cols):
                if _TIME_COL_RE.match(c.strip()):
                    time_idx = i
                    out["time_column"] = c.strip()
                    break
            # Prefer common EVTX enrichment names
            if time_idx is None:
                for pref in ("TimeCreated", "Timestamp", "datetime", "DateTime"):
                    for i, c in enumerate(cols):
                        if c.strip().lower() == pref.lower():
                            time_idx = i
                            out["time_column"] = c.strip()
                            break
                    if time_idx is not None:
                        break

            # Frequency on first categorical-ish column (EventID / etc.)
            cat_idx = None
            for pref in ("EventId", "EventID", "Id", "Channel", "UserName",
                         "TargetUserName", "AccountName"):
                for i, c in enumerate(cols):
                    if c.strip().lower() == pref.lower():
                        cat_idx = i
                        break
                if cat_idx is not None:
                    break

            counts: dict[str, int] = {}
            tmin = tmax = None
            n = 0
            for row in reader:
                n += 1
                if time_idx is not None and time_idx < len(row):
                    val = (row[time_idx] or "").strip()
                    if val:
                        if tmin is None or val < tmin:
                            tmin = val
                        if tmax is None or val > tmax:
                            tmax = val
                if cat_idx is not None and cat_idx < len(row) and n <= sample_rows:
                    key = (row[cat_idx] or "").strip() or "(empty)"
                    counts[key] = counts.get(key, 0) + 1
                if n >= 2_000_000:  # hard safety
                    break
            out["rows"] = n
            out["time_min"] = tmin
            out["time_max"] = tmax
            if counts:
                top = sorted(counts.items(), key=lambda kv: -kv[1])[:12]
                out["top_values"] = {
                    cols[cat_idx] if cat_idx is not None else "field": top
                }
    except (OSError, csv.Error, UnicodeError):
        pass
    return out


def plan_tabular_coverage(
    csv_path: str,
    *,
    available_tool_tokens: int = 8000,
    profile: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Chunk a parsed CSV into table.* query windows (full coverage ladder)."""
    prof = profile or profile_tabular(csv_path)
    rows = int(prof.get("rows") or 0)
    if rows <= 0:
        return []
    chunk = _row_chunk_size(available_tool_tokens)
    chunks: list[dict[str, Any]] = []

    # Prefer time windows when we have a span (more DFIR-natural than offsets).
    tcol = prof.get("time_column")
    tmin, tmax = prof.get("time_min"), prof.get("time_max")
    if tcol and tmin and tmax and tmin != tmax and rows > chunk:
        # Equal-count approximation: N windows by row order still using LIMIT;
        # also emit time-bounded greps as optional hints.
        n_windows = min(_MAX_CHUNKS, max(1, (rows + chunk - 1) // chunk))
        for i in range(n_windows):
            offset = i * chunk
            chunks.append({
                "kind": "row_window",
                "path": csv_path,
                "offset": offset,
                "limit": chunk,
                "tool_hint": "table.table_query",
                "arguments": {
                    "path": csv_path,
                    "limit": chunk,
                    # table_query may ignore offset — document as hint for grep/slice tools
                    "where": [],
                },
                "note": (
                    f"Coverage window {i + 1}/{n_windows}: rows "
                    f"{offset}..{offset + chunk - 1} of {rows}. "
                    f"Time span in file ≈ {tmin} .. {tmax} ({tcol})."
                ),
            })
        return chunks

    n_windows = min(_MAX_CHUNKS, max(1, (rows + chunk - 1) // chunk))
    for i in range(n_windows):
        offset = i * chunk
        chunks.append({
            "kind": "row_window",
            "path": csv_path,
            "offset": offset,
            "limit": chunk,
            "tool_hint": "table.table_query",
            "arguments": {"path": csv_path, "limit": chunk},
            "note": (
                f"Coverage window {i + 1}/{n_windows}: examine up to {chunk} "
                f"rows (window index {i}). Use table_grep with patterns from "
                f"prior windows before advancing."
            ),
        })
    return chunks


def plan_source_coverage_hints(
    source_path: str,
    *,
    tool_hint: str = "",
    available_tool_tokens: int = 8000,
) -> list[dict[str, Any]]:
    """When no CSV exists yet: advise artifact_only parse, not blind re-dumps."""
    try:
        size = os.path.getsize(source_path)
    except OSError:
        size = 0
    return [{
        "kind": "artifact_only_parse",
        "path": source_path,
        "bytes": size,
        "tool_hint": tool_hint or "ez.evtxecmd",
        "note": (
            "No tabular artifact yet. Run a single disk-first parse on this "
            "path (stdout will be compacted to artifact_ready + profile). "
            "Full coverage then continues via table.* windows on the CSV — "
            "not by re-chunking the raw source into the LLM context."
        ),
        "available_for_tool_output_tokens": available_tool_tokens,
    }]


def find_related_artifacts(case_dir: str, source_hint: str = "") -> list[str]:
    """Discover analysis/*.csv that can serve coverage queries."""
    root = Path(case_dir)
    analysis = root / "analysis"
    if not analysis.is_dir():
        return []
    found: list[str] = []
    from core.evidence_catalog import iter_output_files
    for p in iter_output_files(analysis):
        if p.suffix.lower() != ".csv":
            continue
        try:
            if p.stat().st_size < 64:
                continue
        except OSError:
            continue
        found.append(str(p))
        if len(found) >= 30:
            break
    return found


def should_offer_full_coverage(case_dir: str) -> bool:
    """True when bootstrap likely left the investigation dark.

    Heuristic (deterministic, no LLM): open tasks exist, little/no claim
    conclusions, and at least one analysis CSV (disk-first already ran) or
    large evidence still only postponed.
    """
    root = Path(case_dir)
    try:
        from core.investigation_tasks import load_tasks, ACTIONABLE_STATUSES
        tasks = load_tasks(root).get("tasks") or []
        actionable = [
            t for t in tasks
            if (t.get("status") in ACTIONABLE_STATUSES)
        ]
        if not actionable:
            return False
    except Exception:
        return False

    conclusions = 0
    try:
        import json
        cg = root / ".atlas" / "claim_graph.json"
        if cg.is_file():
            data = json.loads(cg.read_text(encoding="utf-8"))
            for n in (data.get("nodes") or []):
                if (n.get("kind") or "") in ("conclusion", "finding"):
                    if (n.get("status") or "") not in ("withdrawn", "superseded"):
                        conclusions += 1
    except Exception:
        pass
    if conclusions >= 3:
        return False

    arts = find_related_artifacts(str(root))
    return bool(arts)
