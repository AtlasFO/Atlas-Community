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
    meaningless and would force table.* compaction of VMDK exports.
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


def shown_as_written(data: dict[str, Any]) -> bool:
    """An incomplete result (a call cut at its deadline) reaches the model
    as written: its resume and note are the point of it. The one rule for
    every compaction or row view of a result."""
    from core.timeout import inprocess_deadline_on
    return bool(isinstance(data, dict) and data.get("incomplete") is True and inprocess_deadline_on())


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
    if shown_as_written(data):
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
            # A cut result keeps its stamp when it led with one (a dict
            # result's first key): it stands for the same call.
            stamp = re.match(r'\s*\{\s*"_atlas_call_id"\s*:\s*(\d+)', blob)
            compact = {
                **({"_atlas_call_id": int(stamp.group(1))} if stamp else {}),
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
    if data.get("_atlas_call_id") is not None:
        compact = {"_atlas_call_id": data["_atlas_call_id"], **compact}     # the same call
    return prefix + json.dumps(compact, indent=2)


# ── the compact row view ─────────────────────────────────────────────────
#
# A result's row list rendered as compact JSON that fits the session's limit
# by construction: one row per line, no row cut in its middle, nothing in an
# unseen middle. The trace keeps the tool's full dict; this is what the
# model reads. Capability stays in the tools, presentation here.

# The tools whose row results take the view and carry the call id. Other
# tools that return row lists keep the plain text path until measured.
ROW_VIEW_TOOLS = frozenset({"table_table_grep", "table_table_query", "strings_strings_grep",
                            "search_search_evidence"})
ROW_LIST_KEYS = ("hits", "rows", "matches", "results")
# Payload keys the view restates (the rows, the alternatives block become the
# term lines) or that are bulky.
_VIEW_DROP_KEYS = frozenset(ROW_LIST_KEYS) | {"alternatives", "schema_columns", "terms", "terms_with_no_row",
                                               "distribution", "sources"}
# The keys a text reader needs when the header must shrink (the control
# invariants, the call id, the counts); the rest is in the trace.
_CONTROL_KEEP = frozenset({"_atlas_call_id", "success", "gate", "path", "pattern", "matched_rows",
                           "returned_rows", "valid_zero", "hit_cap_reached", "scan_capped",
                           "_arguments_adjusted", "_instruction_like_text"})
# The parameters each tool's "next" hint may name, by the switch that adds
# them. A test reads each tool's signature and pins that every name exists (after
# "table.table_pivot", on table_pivot: the count of every match the
# truncation remedy also names).
_QUERY_REST = ("a narrower filter: where=[...]; a count of every match by a column: "
               "table.table_pivot group_by=[<column>] where=[...]")
_NEXT_HINTS = {
    "table_table_grep": {"pattern": "one term alone: pattern=<term>"},
    "table_table_query": {"where": _QUERY_REST},
    "strings_strings_grep": {"pattern": "one pattern alone: pattern=<p>"},
    "search_search_evidence": {"query": "a narrower query: query=<term>", "tool": "one tool's output: tool=<name>"},
}


# ATLAS_TABLE_TIME_ARGS: the table tools take a period; the hint
# names it first. Paging (offset, order) and output_csv stay parameters but
# are not offered as the way to the rest: a page of a large match set says
# nothing about which page holds anything, and a file of every row is read
# back by the same capped tools.
_NEXT_HINTS_TIME = {
    "table_table_grep": {"time_start": "one period: time_start=/time_end=",
                         "pattern": "one term alone: pattern=<term>"},
    "table_table_query": {"time_start": "one period: time_start=/time_end=", "where": _QUERY_REST},
}


def next_hints(tool: str) -> dict:
    """The calls that show the rest of a tool's result, by parameter name,
    for the parameters the tool has at the current switch state."""
    from core.envfile import env_flag
    if env_flag("ATLAS_TABLE_TIME_ARGS", True) and tool in _NEXT_HINTS_TIME:
        return _NEXT_HINTS_TIME[tool]
    return _NEXT_HINTS.get(tool, {})


def _view_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_RESULT_VIEW")


def _distribution_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_RESULT_DISTRIBUTION")


def _scalar_header(payload: dict, call_id, notes: list[str] | None,
                   instruction_hits: list[str] | None) -> list[tuple[str, object]]:
    """The scalars of the dict in its order, the call id first and success
    second; strings clipped at 400 characters; a list or dict longer than
    200 characters left out and named under omitted_keys."""
    out: list[tuple[str, object]] = []
    if call_id is not None:
        out.append(("_atlas_call_id", call_id))
    if "success" in payload:
        out.append(("success", payload["success"]))
    omitted = []
    for k, v in payload.items():
        if k in _VIEW_DROP_KEYS or k in ("_atlas_call_id", "success"):
            continue
        if isinstance(v, (bool, int, float)) or v is None:
            out.append((k, v))
        elif isinstance(v, str):
            out.append((k, v if len(v) <= 400 else v[:399] + "\u2026"))
        elif isinstance(v, (list, dict)) and len(json.dumps(v, default=str)) <= 200:
            out.append((k, v))
        else:
            omitted.append(k)
    if omitted:
        out.append(("omitted_keys", omitted))
    if notes:
        out.append(("_arguments_adjusted", list(notes)))
    if instruction_hits:
        from agent.toolbox import _INSTRUCTION_TEXT_NOTE
        out.append(("_instruction_like_text", {"snippets": list(instruction_hits), "note": _INSTRUCTION_TEXT_NOTE}))
    return out


def _assemble(header, dist, terms, not_returned, empty, unsettled, same, columns, shown, lines, nxt) -> str:
    items = [json.dumps(k) + ": " + json.dumps(v, ensure_ascii=False, default=str) for k, v in header]
    items.append('"shown": ' + json.dumps(shown, ensure_ascii=False))
    if dist:
        items.append('"distribution": [\n' + ",\n".join(json.dumps(t, ensure_ascii=False) for t in dist) + "\n]")
    if terms:
        items.append('"terms": [\n' + ",\n".join(json.dumps(t, ensure_ascii=False) for t in terms) + "\n]")
    if not_returned:
        items.append('"terms_matched_not_returned": ' + json.dumps(not_returned, ensure_ascii=False))
    if empty:
        items.append('"terms_with_no_row": ' + json.dumps(empty, ensure_ascii=False))
    if unsettled:
        items.append('"terms_not_settled": ' + json.dumps(unsettled))
    if same:
        items.append('"same_in_every_returned_row": ' + json.dumps(
            {k: (v if len(v) <= 120 else v[:119] + "\u2026") for k, v in same.items()}, ensure_ascii=False))
    if columns:
        items.append('"columns": ' + json.dumps(columns, ensure_ascii=False))
    items.append('"rows": [\n' + ",\n".join(json.dumps(ln, ensure_ascii=False) for ln in lines) + "\n]")
    if nxt:
        items.append('"next": ' + json.dumps(nxt, ensure_ascii=False))
    return "{\n" + ",\n".join(items) + "\n}"


def _next_hint(tool: str, payload: dict, alts) -> str:
    if tool == RECORD_VIEW:
        # A plugin's records come whole in one call (no page to ask for):
        # the rest is read from the call's saved output.
        cid = payload.get("_atlas_call_id") or "<this call>"
        from core.stack import stack_on
        return (f'the rows not shown are in call {cid}\'s saved output: table.table_pivot path="call:{cid}" '
                'group_by=[<column>] where=[...] lists them by any column' if stack_on() else
                f"the rows not shown are in call {cid}'s saved output, not in this view")
    bits = []
    hints = next_hints(tool)
    for name, text in hints.items():
        if name == "pattern" and len(alts) < 2:
            continue
        bits.append(text)
    return "; ".join(bits)


def _window_text(payload: dict, survey: bool = False) -> str:
    """The period a windowed call searched and the matching rows outside
    it, or that it had none."""
    start, end, every = payload.get("time_start"), payload.get("time_end"), payload.get("matched_rows_all")
    if (start or end) and isinstance(every, int):
        outside = max(0, every - int(payload.get("matched_rows") or 0))
        return f"window: {start or 'the first row'} .. {end or 'the last row'} ({outside} matching rows outside it)"
    return "window: none (every matching row of the file)" if survey else "window: none"


def _shown_sentence(payload: dict, shown: int, returned: int, matched, capped: bool,
                    scan_capped: bool, complete: bool, selection_note: str) -> str:
    if complete:
        return f"all {returned} matching rows, listed oldest first; {_window_text(payload)}"
    rank = f"; #n = place in the time order of the {returned}" if shown < returned else ""
    if isinstance(matched, int) and matched > returned:
        # The tool counted every match and returned a run of them in the
        # call's order (a filter's first rows, a sort, a page): the search
        # did not stop, and the rest are unseen wherever they fall.
        first = int(payload.get("offset") or 0) + 1
        bound = "; the scan stopped at its row bound, so the count covers the rows scanned" if scan_capped else ""
        return (f"{shown} of {matched} matching rows ({returned} returned: rows {first} to {first + returned - 1} "
                f"of the {matched} in the call's order, not a sample of them); listed oldest first; "
                f"{_window_text(payload)}{bound}{rank}")
    if capped or scan_capped:
        where = ("the scan stopped at its row bound" if scan_capped and not capped
                 else "the search stopped")
        head = (f"{shown} of the {returned} returned rows" if shown < returned
                else f"all {returned} returned rows")
        return (f"{head}; the {returned} are the first matching rows in file order, where {where}, "
                f"not a sample of the whole file; how many rows match in all is not known; listed oldest first"
                f"{rank}")
    return (f"{shown} of {returned} returned rows (all {returned} matching rows): {selection_note}; "
            f"listed oldest first; #n = place in the time order of the {returned}")


def _record_sentence(payload: dict, shown: int, returned: int, complete: bool, selection_note: str,
                     timed: int) -> str:
    """``shown`` for a record view: the call returned its whole output, no
    search matched anything. The order is said as the view sorts it
    (order_rank): by time only the records that carry one (``timed`` of
    them), the others in the order the call returned them."""
    if timed >= returned:
        order, rank = "listed oldest first", f"#n = place in the time order of the {returned}"
    elif timed:
        order = (f"the {timed} records with a time listed oldest first, the others after them in the order the "
                 "call returned them")
        rank = "#n = place in that order"
    else:
        order, rank = "listed in the order the call returned them", "#n = place in that order"
    if complete:
        return f"all {returned} records this call returned (its whole output), {order}"
    cid = payload.get("_atlas_call_id") or "this call"
    note = selection_note if timed else selection_note.replace("the time order", "the order returned")
    return (f"{shown} of the {returned} records this call returned (its whole output): {note}; {order}; {rank}; "
            f"the rest are in call {cid}'s saved output")


def _counted_sentence(payload: dict, shown: int, returned: int, matched: int, complete: bool,
                      selection_note: str) -> str:
    """``shown`` for a result whose tool counted every match."""
    unit = "matching lines (counted by line)" if payload.get("count_basis") == "lines" else "matching rows"
    in_file = payload.get("order") == "file"
    listed = "listed in file order (the file is not in time order)" if in_file else "listed oldest first"
    rank = "file order" if in_file else "time order"
    bound = ("; the scan stopped at its row bound, so the count covers the rows scanned"
             if payload.get("scan_capped") else "")
    if complete:
        return f"all {matched} {unit}, {listed}; {_window_text(payload)}{bound}"
    if payload.get("selection") == "survey":
        return (f"{shown} of {matched} {unit} ({returned} returned): {selection_note}; {listed}; "
                f"{_window_text(payload, survey=True)}{bound}; #n = place in the {rank} of the {matched}")
    return (f"{shown} of {matched} {unit} ({returned} returned): {selection_note}; {listed}; "
            f"{_window_text(payload)}{bound}; "
            f"#n = place in the {rank} of the {matched}")


def _render_table(payload: dict, rows: list[dict], bound: int, call_id, notes, instruction_hits,
                  tool: str) -> tuple[str, dict]:
    from core import table_rows as T
    alts = T.split_alternatives(payload.get("pattern"), True) if isinstance(payload.get("pattern"), str) else []
    lay = T.Layout(rows, bound)
    times = [T.row_moment(r, lay.tcols) or None for r in rows]
    groups = ["/".join(T.cell(r.get(c)) for c in lay.scols) for r in rows]
    tsets = [T.term_set(r, alts) if alts else set() for r in rows]
    rx = None
    if isinstance(payload.get("pattern"), str):
        try:
            rx = re.compile(payload["pattern"], re.IGNORECASE)
        except re.error:
            rx = None
    capped = bool(payload.get("hit_cap_reached") or payload.get("payload_capped"))
    scan_capped = bool(payload.get("scan_capped"))
    matched = payload.get("matched_rows")
    header = _scalar_header(payload, call_id, notes, instruction_hits)
    counted = payload.get("selection") in ("survey", "all") and isinstance(matched, int)
    basis = "the returned rows only" if (capped or scan_capped or (isinstance(matched, int) and matched > len(rows))) \
        else "all matching rows"
    if counted and isinstance(payload.get("distribution"), dict):
        # The tool counted every match: its distribution is exact.
        dist = payload["distribution"] if _distribution_on() else None
    else:
        dist = T.distribution(range(len(rows)), times, groups, tsets, alts, basis) if _distribution_on() else None
    counted_terms = payload.get("terms") if counted and isinstance(payload.get("terms"), list) else None
    if counted_terms is not None and len(alts) > 1:
        terms = T.count_term_lines(counted_terms, dist["by_term"] if dist else None)
        empty = []
    else:
        terms, empty = T.term_lines(alts, times, groups, tsets, dist["by_term"] if dist else None) \
            if len(alts) > 1 else ([], [])
    # Absence honesty: a term with no returned row is "no row" only when the
    # whole file was read for it. A capped search's alternatives block says
    # which terms match rows that were not returned and which match none; a
    # scan that stopped at its row bound settles nothing.
    not_returned: list[str] = []
    unsettled = 0
    blk = payload.get("alternatives") if isinstance(payload.get("alternatives"), dict) else None
    if counted_terms is not None and len(alts) > 1:
        returned_terms = {alts[a][0] for s in tsets for a in s}
        not_returned = [t["term"] for t in counted_terms if t.get("rows") and t["term"] not in returned_terms]
        if scan_capped:
            with_rows = {t["term"] for t in counted_terms}
            unsettled = sum(1 for src, _r in alts if src not in with_rows)
        else:
            empty = list(payload.get("terms_with_no_row") or [])
    elif scan_capped:
        unsettled, empty = len(empty), []
    elif capped:
        matched_terms = set(blk.get("matched") or []) if blk else set()
        unmatched = set(blk.get("unmatched") or []) if blk else set()
        not_returned = [t for t in empty if t in matched_terms]
        unsettled = sum(1 for t in empty if t not in matched_terms and t not in unmatched)
        empty = [t for t in empty if t in unmatched]
    if counted and all(isinstance(r.get("_n"), int) for r in rows):
        order_rank = {i: rows[i]["_n"] for i in range(len(rows))}    # the place among every match
    else:
        order_rank = {i: k + 1 for k, i in enumerate(
            sorted(range(len(rows)), key=lambda i: (times[i] is None, times[i] or "", i)))}
    dist_level = next((lv for lv in (0, 1, 2) if len("\n".join(T.distribution_lines(dist, lv))) <= bound // 3), 2)
    selection_note = ("the first row of each term, the first row of each source, the last row of each term, "
                      "the rest spread over the time order")

    def build(k: int):
        nonlocal selection_note
        sel = T.select(len(rows), times, tsets, groups, k, len(alts))
        idx = sorted((i for _t, i in sel), key=lambda i: order_rank[i])
        lines, _members = T.collapse(lay, rows, idx, order_rank, rx)
        complete = not capped and not scan_capped and len(idx) >= len(rows) \
            and (not isinstance(matched, int) or matched <= len(rows))
        shown = (_record_sentence(payload, len(idx), len(rows), complete, selection_note,
                                  sum(1 for t in times if t)) if tool == RECORD_VIEW
                 else _counted_sentence(payload, len(idx), len(rows), matched, complete, selection_note) if counted
                 else _shown_sentence(payload, len(idx), len(rows), matched, capped, scan_capped, complete,
                                      selection_note))
        nxt = _next_hint(tool, payload, alts) if not complete else ""
        dist_lines = T.distribution_lines(dist, dist_level) if dist_level < 3 else []
        text = _assemble(header, dist_lines, terms, not_returned, empty, unsettled,
                         lay.same, lay.header_line(), shown, lines, nxt)
        return text, idx, complete

    # The header (scalars, shown, distribution, term lines) may take half the
    # limit, so rows keep the other half. It degrades in steps that keep
    # every count and every absence fact.
    for step in range(8):
        if len(build(0)[0]) <= bound // 2:
            break
        if step == 0:
            header = [(k, v[:119] + "\u2026" if isinstance(v, str) and len(v) > 120 else v) for k, v in header]
        elif step == 1:
            header = [(k, v) for k, v in header if k in _CONTROL_KEEP]
        elif step == 2:
            dist_level = max(dist_level, 1)
        elif step == 3:
            dist_level = 2
        elif step == 4:
            terms = [t.split(" (", 1)[0] for t in terms]
        elif step == 5:
            if terms:
                terms = [T.clip_head("terms with rows: " + ", ".join(
                    t.split(": ", 1)[0] + " " + t.split(": ", 1)[1].split(" ", 1)[0] for t in terms), 300)]
            empty = empty if len(json.dumps(empty)) <= 300 else [T.clip_head(", ".join(empty), 300)]
            not_returned = (not_returned if len(json.dumps(not_returned)) <= 300
                            else [T.clip_head(", ".join(not_returned), 300)])
        elif step == 6:
            dist_level = 3   # no distribution lines at all
        elif step == 7:
            selection_note = "a selection across the time order"
    lo, hi = 0, len(rows)
    best = build(0)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        text, idx, complete = build(mid)
        if len(text) <= bound:
            lo, best = mid, (text, idx, complete)
        else:
            hi = mid - 1
    text, idx, complete = best
    shown_terms = sorted({src for a, (src, _rx) in enumerate(alts) if any(a in tsets[i] for i in idx)})
    row_ids = [rows[i].get("_row", i) for i in idx]
    # The view's "#n" ordinals (place in the time order) of the rows it shows,
    # each with the row's id: a quote of a collapsed line ("#a-#b xN") names
    # its member rows through them (agent.frontier, IncidentMap.rows_for_ordinals).
    ordinals = {str(order_rank[i]): rows[i].get("_row", i) for i in idx}
    note = {"view_rows_returned": len(rows), "view_rows_shown": len(idx), "view_row_ids": row_ids,
            "view_ordinals": ordinals, "view_terms_shown": shown_terms, "view_complete": complete}
    if len(idx) < len(rows):
        note.update(view_truncated=True, view_omitted_rows=len(rows) - len(idx))
    return text, note


def _render_lines(payload: dict, rows: list[str], bound: int, call_id, notes, instruction_hits,
                  tool: str) -> tuple[str, dict]:
    from core import table_rows as T
    pats = payload.get("pattern")
    pats = pats if isinstance(pats, list) else ([pats] if pats else [])
    alts = []
    for p in pats:
        try:
            alts.append((str(p), re.compile(str(p), re.IGNORECASE)))
        except re.error:
            pass
    tsets = [{i for i, (_s, rx) in enumerate(alts) if rx.search(r)} for r in rows]
    header = _scalar_header(payload, call_id, notes, instruction_hits)
    per = payload.get("matches_by_pattern") if isinstance(payload.get("matches_by_pattern"), dict) else None
    terms = [f"{p}: {c} lines" for p, c in (per or {}).items() if c]
    empty = [p for p, c in (per or {}).items() if not c]
    width = max(120, min(300, bound // 30))

    # strings_grep lists the ASCII matches, then the UTF-16 matches
    # (tools/strings_tools.py), so its lines are not in file order.
    order = "in output order: ASCII strings, then UTF-16" if tool == "strings_strings_grep" else "in output order"

    def build(k: int):
        sel = T.select(len(rows), [None] * len(rows), tsets, [""] * len(rows), k, len(alts))
        idx = sorted(i for _t, i in sel)
        lines = [f"#{i + 1} " + T.kwic(rows[i], alts[0][1] if alts else None, width) for i in idx]
        complete = k >= len(rows)
        shown = (f"all {len(rows)} lines, {order}" if complete else
                 f"{len(idx)} of {len(rows)} lines: the first and last line of each pattern, the rest spread "
                 f"{order}; #n = place in the result")
        nxt = _next_hint(tool, payload, alts) if not complete else ""
        return _assemble(header, [], terms, [], empty, 0, {}, "", shown, lines, nxt), idx, complete

    lo, hi = 0, len(rows)
    best = build(0)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        text, idx, complete = build(mid)
        if len(text) <= bound:
            lo, best = mid, (text, idx, complete)
        else:
            hi = mid - 1
    text, idx, complete = best
    note = {"view_rows_returned": len(rows), "view_rows_shown": len(idx), "view_row_ids": [i + 1 for i in idx],
            "view_terms_shown": sorted({alts[a][0] for i in idx for a in tsets[i]}), "view_complete": complete}
    if not complete:
        note.update(view_truncated=True, view_omitted_rows=len(rows) - len(idx))
    return text, note


def render_rows_view(data: dict, limit: int, call_id, notes: list[str] | None = None, *,
                     instruction_hits: list[str] | None = None, tool: str = "") -> tuple[str, dict] | None:
    """The compact view of an allow-listed row result and the trace
    annotation of what it shows (view_rows_returned, view_rows_shown,
    view_row_ids, view_terms_shown, view_truncated with view_omitted_rows,
    view_complete), or None when the result is a refusal, holds no row list
    or an empty one, the tool is not allow-listed, ATLAS_RESULT_VIEW is
    off, or no row fits beside the header within ``limit``: those keep
    the plain text path. The view is valid JSON of at most
    ``limit`` characters, ``_atlas_call_id`` first and ``success`` second."""
    if not _view_on() or tool not in ROW_VIEW_TOOLS or not isinstance(data, dict):
        return None
    if data.get("success") is False or data.get("gate"):
        return None
    key = next((k for k in ROW_LIST_KEYS if isinstance(data.get(k), list)), None)
    if key is None or not data[key]:
        return None
    rows = data[key]
    if all(isinstance(r, dict) for r in rows):
        text, note = _render_table(data, rows, limit, call_id, notes, instruction_hits, tool)
    elif all(isinstance(r, str) for r in rows):
        text, note = _render_lines(data, rows, limit, call_id, notes, instruction_hits, tool)
    else:
        return None
    if len(text) > limit:
        return None   # the header alone passes the bound: the plain text path keeps the result readable
    if not note.get("view_rows_shown"):
        return None   # no row fits beside the header: the plain cut text shows more than a view of none
    return text, note


# The view of a result whose saved output is a JSON array of records (a
# plugin's JSON rendering): the tool name it renders under for its hint.
RECORD_VIEW = "record_view"


def render_record_view(data: dict, entry: dict, limit: int, call_id, notes: list[str] | None = None, *,
                       instruction_hits: list[str] | None = None) -> tuple[str, dict] | None:
    """The compact row view of a result whose call saved a JSON array of
    records: its records split by core.indicators.flat_rows_of (nested
    records as rows of their own, with their depth), the result's own
    scalars (its note, command, flags) in the header, the output text itself
    left out; the trace annotation marks the split ("rows_split": "flat") so
    the map reads the same rows. None when the output is no record array,
    the result is a refusal, a deferred reply or one shown as written, or
    the view does not fit: the plain text path keeps those. The trigger is the
    output's shape, never a tool or a plugin name."""
    if not _view_on() or not isinstance(data, dict) or not isinstance(entry, dict):
        return None
    if data.get("success") is False or data.get("gate") or data.get("deferred") or shown_as_written(data):
        return None
    from core.indicators import flat_rows_of
    rows = flat_rows_of(entry)
    if not rows:
        return None
    # "truncated" says the in-memory stdout was cut; with a spill file the
    # rows are the full saved output, so it no longer describes what is shown.
    whole = ("stdout", "stdout_file", "_atlas_call_id") + (("truncated",) if entry.get("stdout_file") else ())
    payload = {"_atlas_call_id": call_id, **{k: v for k, v in data.items() if k not in whole}}
    text, note = _render_table(payload, rows, limit, call_id, notes, instruction_hits, RECORD_VIEW)
    if len(text) > limit or not note.get("view_rows_shown"):
        return None
    note["rows_split"] = "flat"
    return text, note
