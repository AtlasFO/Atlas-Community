"""The rows a tool call showed the model, as record identities.

An item's progress counts the records its calls showed that no item of the
run showed before (agent.frontier.FrontierRun._own_reads). A record is
named by where it lives, never by how it was rendered:

- a table row that carries its place (``_row``, tools/tabular.py) is
  (source, sheet, row): the same record under another column list, pattern
  or sort is the same record;
- a row that names the earlier output and line it was found in (a search
  over the trace's outputs) is that window;
- a line of a line-row tool (a strings search) is (source, line text);
- any other structured row is a digest of its content, Atlas's own
  bookkeeping keys and the call's echoed arguments left out.

Aggregate rows (group counts) name no record: a new filter or grouping
gives new counts of the same records, so they give no credit.

Only rows the model was shown count: a compact row view's selection
(``view_row_ids``: a dict row's ``_row`` or its 0-based place, a line's
1-based place, core.tool_result_view), or every row of a JSON result the
model received whole. A cut text result names no row.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional

# Tools whose rows are counts over groups of records, not records
# (tools/tabular.table_pivot, core/stack).
AGGREGATE_TOOLS = frozenset({"table_table_pivot", "table.table_pivot", "table_pivot"})
ROW_LIST_KEYS = ("hits", "rows", "matches", "results")
_SOURCE_ARGS = ("path", "file", "file_path", "evidence_path", "image", "image_path")


def _digest(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=8).hexdigest()


def _source(arguments: dict, data: dict) -> str:
    """The file the rows come from, one spelling per file: a path that
    exists is taken as its real path (relative or absolute alike)."""
    import os
    src = next((data[k] for k in ("path", "file") if isinstance(data.get(k), str) and data[k]), "") or next(
        (v for k in _SOURCE_ARGS if isinstance(v := (arguments or {}).get(k), str) and v), "")
    try:
        return os.path.realpath(src) if src and os.path.exists(src) else src
    except (OSError, ValueError):
        return src


def _echo(arguments: dict) -> tuple[set[str], set[str]]:
    keys = {str(k) for k in (arguments or {})}
    values = set()
    for v in (arguments or {}).values():
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, (str, int, float)) and str(x).strip():
                values.add(str(x).strip().casefold())
    return keys, values


def _key(row: Any, i: int, source: str, arguments: dict) -> Optional[str]:
    from core.table_rows import INTERNAL_KEYS
    if isinstance(row, str):
        line = " ".join(row.split())
        return f"l|{source}|{line}" if line else None
    if not isinstance(row, dict):
        return None
    if "_row" in row:
        return f"r|{source}|{row.get('_sheet', '')}|{row.get('_row')}"
    if row.get("call_id") is not None and row.get("line_start") is not None:
        return f"w|{row.get('call_id')}|{row.get('line_start')}"
    keys, values = _echo(arguments)
    kept = {k: v for k, v in row.items() if k not in INTERNAL_KEYS and k not in keys
            and not (isinstance(v, str) and v.strip().casefold() in values)}
    if not kept:
        return None
    return "c|" + source + "|" + json.dumps(kept, sort_keys=True, ensure_ascii=False, default=str)


def row_keys(tool: str, arguments: dict, data: Any, shown_ids: Optional[Iterable] = None) -> list[str]:
    """The identities (short digests) of the rows of ``data`` the model was
    shown: those ``shown_ids`` names (a view's selection), else every row."""
    if tool in AGGREGATE_TOOLS or not isinstance(data, dict) or data.get("success") is False:
        return []
    rows = next((data[k] for k in ROW_LIST_KEYS if isinstance(data.get(k), list)), None)
    if not rows:
        return []
    wanted = None if shown_ids is None else set(shown_ids)
    source = _source(arguments, data)
    out: list[str] = []
    for i, row in enumerate(rows):
        if wanted is not None:
            place = (i + 1) if isinstance(row, str) else (row.get("_row", i) if isinstance(row, dict) else None)
            if place not in wanted:
                continue
        k = _key(row, i, source, arguments)
        if k:
            out.append(_digest(k))
    return list(dict.fromkeys(out))


def source_of(arguments: dict, data: Any) -> str:
    """The file a call's rows come from, in the one spelling row_keys uses."""
    return _source(arguments or {}, data if isinstance(data, dict) else {})


def from_text(tool: str, arguments: dict, text: str) -> list[str]:
    """The row identities of a result the model received as text: every
    row of a whole JSON object; none of a cut or plain text."""
    s = str(text or "").strip()
    if not s.startswith("{"):
        return []
    try:
        data = json.loads(s)
    except ValueError:
        return []
    return row_keys(tool, arguments, data)
