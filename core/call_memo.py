"""Run-wide memory of what a tool call already answered.

Evidence is read-only for the length of a run, so a read-only tool asked the
same question about the same unchanged input gives the same answer. The model
still asks again: after compaction it no longer holds the result, and a path
written two ways (``evidence/x.log`` and its absolute form) looked like two
different questions. This module gives both forms one key, ties the key to
the inputs' size and modification time so a regenerated artifact is read
afresh, and keeps every successful answer for the whole run.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable

# Tools whose answer moves without any input file moving: live hosts,
# watchers, background jobs, the growing search index, trace-derived
# correlations and exports. A repeat of these is a new question.
VOLATILE_TOOL_RE = re.compile(
    r"^(?:live|monitor|velo|respond|jobs?|search|correlate|accuracy|export)_"
    r"|enrichment_status|_hypothes|_findings?$|_ioc_|_pivots?$",
    re.IGNORECASE,
)

# Task statuses that still need work; mirrored from core.investigation_tasks
# to keep this module free of case-state imports.
# How much of a belief is restated. Enough to recognise it and act on it,
# not so much that a case with dozens of them crowds out the evidence the
# next turn needs.
_CLAIM_CHARS = 240

_OPEN_TASK_STATUSES = frozenset({
    "open", "in_progress", "partial", "reopened", "blocked_missing_evidence",
})

_PATHISH_RE = re.compile(r"[\\/]|^~(?:/|$)")
_TRACE_CALL_ID_RE = re.compile(r'"(?:_atlas_)?call_id"\s*:\s*"?(\d+)')
# Atlas's own stamp on a tool result, written after the tool's output: a
# result that leads with a long stdout carries it well past the head.
_ATLAS_CALL_ID_RE = re.compile(r'"_atlas_call_id"\s*:\s*"?(\d+)')


def trace_call_id_of(result: str) -> str:
    """The trace call id stamped on a rendered tool result, "" when none."""
    found = _ATLAS_CALL_ID_RE.search(result[-600:]) if result else None
    if found is None:
        found = _TRACE_CALL_ID_RE.search(result[:800] if result else "")
    return found.group(1) if found else ""


# Arguments naming where a tool writes. They are canonicalised like any
# path but never part of the input signature: the file a tool produced
# changing is not the question changing.
_OUTPUT_KEY_RE = re.compile(r"(?:^|_)(?:out|output|dest|destination|save)(?:_|$)",
                            re.IGNORECASE)


def memoable(tool_name: str) -> bool:
    """Whether a repeat of this tool can be answered from memory."""
    return not VOLATILE_TOOL_RE.search(tool_name or "")


def _resolve(value: str, case_dir: str | None) -> str | None:
    """The real path a path-like argument names, if it exists."""
    expanded = os.path.expanduser(value)
    candidates = [expanded]
    if case_dir and not os.path.isabs(expanded):
        candidates.insert(0, os.path.join(case_dir, expanded))
    for candidate in candidates:
        try:
            if os.path.exists(candidate):
                return os.path.realpath(candidate)
        except (OSError, ValueError):
            continue
    return None


def _path_typed(key: str) -> bool:
    """Parameters the tool layer declares as input paths are paths however
    they are spelled, slash or not."""
    try:
        from core.paths import INPUT_PATH_PARAM_NAMES
    except Exception:  # noqa: BLE001
        return False
    return key in INPUT_PATH_PARAM_NAMES


def _canonical_value(value: Any, case_dir: str | None, paths: list[str],
                     *, is_input: bool = True, typed: bool = False) -> Any:
    if isinstance(value, str):
        value = value.strip()
        if not is_input:
            return value
        if ((typed or _PATHISH_RE.search(value)) and "\n" not in value
                and len(value) < 4096):
            real = _resolve(value, case_dir)
            if real:
                paths.append(real)
                return real
        return value
    if isinstance(value, list):
        return [_canonical_value(v, case_dir, paths, is_input=is_input, typed=typed)
                for v in value]
    return value


def canonical_args(args: dict | None,
                   case_dir: str | os.PathLike | None = None,
                   ) -> tuple[dict[str, Any], list[str]]:
    """Arguments with every existing path in its real form, plus those paths.

    Private (underscore) and empty arguments are dropped, strings stripped,
    so the same question asked with cosmetic differences has one form.
    """
    case = str(case_dir) if case_dir else None
    canon: dict[str, Any] = {}
    paths: list[str] = []
    for key in sorted((args or {}).keys(), key=str):
        if str(key).startswith("_"):
            continue
        value = args[key]
        if value is None or value == "":
            continue
        canon[str(key)] = _canonical_value(
            value, case, paths,
            is_input=not _OUTPUT_KEY_RE.search(str(key)),
            typed=_path_typed(str(key)))
    return canon, paths


def input_signature(paths: Iterable[str]) -> str:
    """Size and modification time of every input: a regenerated artifact is
    a different question, unchanged evidence the same one."""
    parts = []
    for path in sorted(set(paths)):
        try:
            st = os.stat(path)
        except OSError:
            parts.append(f"{path}:missing")
            continue
        parts.append(f"{path}:{st.st_size}:{st.st_mtime_ns}")
    return "|".join(parts)


def call_key(tool: str, args: dict | None,
             case_dir: str | os.PathLike | None = None) -> tuple[str, str]:
    """One key for every way of asking the same tool the same question."""
    canon, paths = canonical_args(args, case_dir)
    blob = json.dumps(canon, sort_keys=True, default=str, ensure_ascii=False)
    signature = input_signature(paths)
    return (tool or "", blob + ("\n" + signature if signature else ""))


def _short(value: Any, limit: int = 40) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _detail(canon: dict[str, Any], paths: list[str], limit: int = 90) -> str:
    """The non-path arguments, compact: what distinguishes this call from
    the other calls on the same input."""
    parts = []
    for key, value in canon.items():
        if isinstance(value, str) and value in paths:
            continue
        if isinstance(value, list) and value and all(
                isinstance(v, str) and v in paths for v in value):
            continue
        parts.append(f"{key}={_short(value)}")
    text = " ".join(parts)
    return text if len(text) <= limit else text[:limit - 1] + "…"


@dataclass
class MemoEntry:
    turn: int
    tool_call_id: str
    result: str
    tool: str
    target: str
    detail: str
    trace_call_id: str = ""
    hits: int = 0


@dataclass
class RefusalEntry:
    turn: int        # the first identical refusal
    gate: str
    hits: int = 1    # identical refusals so far, this one included


class CallMemo:
    """Every successful read-only call of a run, by canonical key, and every
    gate refusal by the call and the gate that refused it."""

    def __init__(self, case_dir: str | os.PathLike | None = None) -> None:
        self.case_dir = str(case_dir) if case_dir else None
        self._entries: dict[tuple[str, str], MemoEntry] = {}
        self._refusals: dict[tuple[str, str, str], RefusalEntry] = {}
        self.replays = 0    # answered from memory after compaction
        self.pointers = 0   # pointed at a result still in the conversation

    def __len__(self) -> int:
        return len(self._entries)

    def key(self, tool: str, args: dict | None) -> tuple[str, str]:
        return call_key(tool, args, self.case_dir)

    def get(self, key: tuple[str, str]) -> MemoEntry | None:
        return self._entries.get(key)

    def put(self, key: tuple[str, str], *, turn: int, tool_call_id: str,
            result: str, tool: str, args: dict | None) -> MemoEntry | None:
        """Remember a successful answer. A call that reads a directory is
        not kept: a file added two levels down leaves the directory's own
        mtime untouched, so its listing cannot be told stale."""
        canon, paths = canonical_args(args, self.case_dir)
        if any(os.path.isdir(p) for p in paths):
            return None
        entry = MemoEntry(
            turn=turn, tool_call_id=tool_call_id, result=result, tool=tool,
            target=self._display_path(paths[0]) if paths else "",
            detail=_detail(canon, paths),
            trace_call_id=trace_call_id_of(result),
        )
        self._entries[key] = entry
        return entry

    def refused(self, key: tuple[str, str], gate: str, *,
                turn: int) -> RefusalEntry:
        """Remember a refusal the way a success is remembered. A refused call
        changed nothing, so the same call meeting the same gate again is the
        same refusal; the entry counts how often, for the loop to say so
        instead of repeating the first refusal word for word. Stateful tools
        are not exempt here: a repeat of a refusal advances no state."""
        entry = self._refusals.get(key + (gate,))
        if entry is None:
            entry = RefusalEntry(turn=turn, gate=gate)
            self._refusals[key + (gate,)] = entry
        else:
            entry.hits += 1
        return entry

    def entries(self) -> list[MemoEntry]:
        return list(self._entries.values())

    def _display_path(self, path: str) -> str:
        if self.case_dir:
            try:
                rel = os.path.relpath(path, self.case_dir)
                if not rel.startswith(".."):
                    return rel
            except ValueError:
                pass
        return path


def render_index(memo: CallMemo, *, findings: int | None = None,
                 tasks: Iterable[dict] | None = None,
                 pivots_open: int | None = None, limit: int = 30,
                 identical: Iterable[dict] | None = None,
                 unrecorded: Iterable[dict] | None = None,
                 unrecorded_bulk: Iterable[dict] | None = None,
                 claims: Iterable[dict] | None = None,
                 claims_limit: int = 24) -> str:
    """What the run has already established, for the model to reuse.

    Bounded: the most recent distinct calls, one line each, the beliefs
    recorded so far, and counts. The trace keeps everything; the claim graph
    keeps the beliefs, and misc.current_investigation_state reads it back.
    """
    entries = sorted(memo.entries(), key=lambda e: e.turn, reverse=True)
    lines = [
        "[Already established in this run - reuse these results, do not run them again]",
        f"Distinct successful tool calls: {len(entries)}; repeats answered "
        f"from memory: {memo.replays + memo.pointers}.",
    ]
    if entries:
        lines.append("Most recent (trace call id / tool / input / turn / arguments):")
        for e in entries[:limit]:
            call = f"call {e.trace_call_id}" if e.trace_call_id else "call -"
            line = f"  {call} / {e.tool} / {e.target or '-'} / t{e.turn}"
            if e.detail:
                line += f" / {e.detail}"
            if e.hits:
                line += f" / asked {e.hits + 1}x"
            lines.append(line)
        if len(entries) > limit:
            lines.append(f"  ... {len(entries) - limit} earlier calls are in the trace.")
    copies = list(identical or [])
    if copies:
        lines.append("Same content under several paths (one file, not several):")
        for g in copies[:6]:
            paths = list(g.get("paths") or [])
            line = f"  {str(g.get('sha256') or '')[:12]}: " + ", ".join(paths[:4])
            if len(paths) > 4:
                line += f" and {len(paths) - 4} more"
            lines.append(line)
    unrec = list(unrecorded or [])
    if unrec:
        lines.append("Indicators seen repeatedly but named by no finding or "
                     "disposition yet - record each that matters in a finding "
                     "(one may name several), and rule the rest out in a "
                     "disposition (misc.record_agent_message with "
                     "disposition=True, naming the values), not in a finding:")
        for d in unrec:
            lines.append(f"  {d.get('value')} ({d.get('kind')}, {d.get('calls')} calls)")
    bulk = list(unrecorded_bulk or [])
    if bulk:
        # Not a request: a population this size is not ruled on one by one,
        # and which of it belongs in a finding is the analyst's judgement.
        from core.ioc_pivots import describe_unrecorded_bulk
        lines.append("Recurring in the evidence in bulk and named by no finding, "
                     "not asked for one by one: " + describe_unrecorded_bulk(bulk)
                     + ". Whether any of them belongs in a finding is your call.")
    # What the run has concluded, not merely how many times it concluded
    # something. A count is what a compacted conversation leaves the model
    # holding, and a model that cannot see its own beliefs spends its turns
    # reconstructing them from a transcript that no longer carries them,
    # while the statements themselves sit unread in the claim graph.
    beliefs = [b for b in (claims or []) if str(b.get("statement") or "").strip()]
    if beliefs:
        lines.append("Recorded so far - your own beliefs, restated because the "
                     "conversation above may no longer carry them. Each stands "
                     "on the evidence behind its id, not on being repeated here:")
        for b in beliefs[:claims_limit]:
            tier = str(b.get("confidence") or "").upper() or "?"
            text = " ".join(str(b.get("statement") or "").split())
            if len(text) > _CLAIM_CHARS:
                text = text[:_CLAIM_CHARS - 1].rstrip() + "…"
            lines.append(f"  {b.get('id') or '-'} [{tier}] {text}")
        if len(beliefs) > claims_limit:
            lines.append(f"  ... {len(beliefs) - claims_limit} more in "
                         "misc.current_investigation_state.")
    state = []
    if findings is not None:
        state.append(f"findings recorded: {findings}")
    if tasks is not None:
        rows = list(tasks)
        open_ids = [str(t.get("id")) for t in rows
                    if t.get("status") in _OPEN_TASK_STATUSES]
        closed = len(rows) - len(open_ids)
        item = f"questions closed: {closed}/{len(rows)}"
        if open_ids:
            item += (f" (open: {', '.join(open_ids[:8])}; close each with "
                     "misc.update_investigation_task(task_id, status, "
                     "related_claim_ids=[...]) as soon as a belief answers it)")
        state.append(item)
    if pivots_open:
        state.append(f"indicators not yet searched: {pivots_open}")
    if state:
        lines.append("State: " + "; ".join(state) + ".")
    # Order matters here. After a compaction the first thing needed is the
    # run's own state, which is on disk in full and cheap to read; a search
    # over evidence answers a different question and was reached for instead
    # when it was the only thing named.
    lines.append("To see the whole of what you have established, including the "
                 "evidence behind each belief: misc.current_investigation_state. "
                 "For a detail from an earlier result: "
                 "search.search_evidence(query) finds it and cites the call id; "
                 "the trace holds the full output.")
    return "\n".join(lines)
