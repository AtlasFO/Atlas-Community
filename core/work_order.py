"""The work order: reads the run owes, kept as ``work_item`` trace
entries beside the deferred-intent records.

An item names a read (a file, a path inside an image, a search of a table)
and why it is owed. It is shown to the analyst every turn as a ready call
until a call reads its target or fails to, or the question it serves is
closed. Items are filled by the per-question plan, the director, the source
behind a claim's timeline rows, absence contradictions and (proposed, for the
director) index artefacts, reviewer lines and partly read series. Code never
maps a question to an artefact: it validates names against what exists and
closes items by path identity.

Every function takes the log and edits under its lock; an edited entry is
marked with ``_touched`` so a second writer of the trace keeps the newer copy.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

ORIGINS = ("plan", "director", "source", "absence", "index", "blocker", "reason", "series",
           "corroboration", "triage", "join_hit", "view_row_opened", "host_pass", "followup", "synthesis")
OPEN = frozenset({"proposed", "due"})
# source_ref["closed_by"] of an item no call closes, only its executor.
EXECUTOR = "executor"
# "parsed": a folder parse by the item's own tool reached its target and the
# parser reports no files it processed: the planned call ran, nothing says
# the file was read (the coverage ledger keeps it unread).
CLOSED = frozenset({"resolved", "failed", "dismissed", "parsed"})
PARSED_UNREPORTED = "parsed, no report of what it processed"
# Origins whose items ask for the artefact that dates, explains or
# contradicts what a claim rests on: they stay due after the question closes.
SURVIVES_CLOSE = frozenset({"source", "absence", "triage"})
_ORIGIN_RANK = {"plan": 0, "director": 1, "source": 2, "absence": 3}
# The two gate refusals that say an item's own ready call can never run on
# this case; the middleware's call_abandoned reason starts with the gate name.
CLOSING_REFUSALS = ("wrong-input-kind gate:", "evidence-compat gate:")
BLOCK_CHARS = 1700
BLOCK_ITEMS = 6
UNATTENDED_DEMOTE = 3

# Tools that search with a pattern rather than read a file: universal tool
# name shapes of the table, strings and evidence-search namespaces.
_SEARCH_TOOL_RE = re.compile(r"(?:^|_)(?:grep|query|search|pivot)(?:_|$)")
# Argument names that carry a search pattern.
_PATTERN_KEYS = ("pattern", "patterns", "query", "regex", "expression", "where", "term", "terms")
# Argument names a tool takes its file, image and inner path by, in the
# order a ready call fills them (argument names of the tool schemas).
_FILE_PARAMS = ("image", "image_path", "file_path", "csv_path", "path", "file", "evidence_path",
                "input_path", "target", "source", "directory")
_INNER_PARAMS = ("inner_path", "path", "file_path", "target_path")


# ── tool families ─────────────────────────────────────────────────────────

def listed(tool: str) -> str:
    from core.coverage_ledger import listed_tool_name
    return listed_tool_name(tool or "")


def is_reading_tool(tool: str) -> bool:
    """A tool that reads content or searches, and is not one of the run's
    own-words tools (claims, reasoning, the director, record keeping)."""
    from core.coverage_ledger import reads_content
    from core.forensic_citation import own_words_entry
    name = listed(tool)
    if not name:
        return False
    ns = name.split("_", 1)[0]
    if own_words_entry({"type": "tool_call", "cmd": f"<py>:{ns}_{name}"}):
        return False
    # A tool that writes the run's own output (a report, the case document,
    # the indicator or ATT&CK export, the trace export) reads no evidence.
    # A format converter whose input is an evidence file (an ESE, EVT or
    # PST export, a VMDK to raw, a plaso CSV) reads content and stays.
    if _OWN_OUTPUT_RE.search(name):
        return False
    return reads_content(name) or tool_kind(name) == "search"


# The names of the tools that write the run's own outputs (their lexical
# shape: the export namespace, a write_ of a report or document, an export
# of a report or of the execution log).
_OWN_OUTPUT_RE = re.compile(r"^export_|(?:^|_)write_\w*(?:report|document)|_export_(?:report|execution_log)$")


def tool_kind(tool: str) -> str:
    """``search``, ``listing`` or ``read`` for a tool name."""
    from core.coverage_ledger import is_listing_tool
    name = listed(tool)
    if _SEARCH_TOOL_RE.search(name):
        return "search"
    if is_listing_tool(name):
        return "listing"
    return "read"


# ── normalisation ─────────────────────────────────────────────────────────

def _norm_path(p: str) -> str:
    from core.coverage_ledger import _norm_rel
    return _norm_rel(str(p or "")).casefold() if p else ""


def _norm_inner(p: str) -> str:
    """An inner path case-folded, one separator, no leading slash, source
    label or drive (core.evidence_identity.norm_inner)."""
    from core.evidence_identity import norm_inner
    return norm_inner(p)


def _shares_tail(a: str, b: str) -> bool:
    """Two paths that share their trailing segments at a segment boundary,
    with at least one separator on the shorter side; a bare file name never
    matches (_any_path_match's rule: a name on one host is not the same name
    on another)."""
    a, b = _norm_inner(a), _norm_inner(b)
    if not a or not b:
        return False
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    if "/" not in short:
        return False
    return long_ == short or long_.endswith("/" + short)


def _pattern_terms(pattern: str) -> list[str]:
    """The terms of a search pattern: its top-level alternatives with regex
    escapes removed, case-folded."""
    from core.table_rows import split_alternatives
    alts = split_alternatives(str(pattern or "")) if pattern else []
    terms = [re.sub(r"\\(.)", r"\1", src).casefold() for src, _rx in alts] or (
        [str(pattern).casefold()] if pattern else [])
    return sorted(t for t in dict.fromkeys(terms) if t)


def fingerprint(origin: str, tool: str, target: dict | None, why: str = "", extra_key: str = "") -> str:
    """The kind of work and its normalised target; for a search its terms;
    for a whole container (no inner path) also the tool; a proposal without
    a target by its origin and case-folded ``why``, or by ``extra_key`` when
    its source names one. A parser choice on a file does not split an
    item."""
    t = target or {}
    kind = tool_kind(tool) if tool else "read"
    path = _norm_path(t.get("path") or "")
    inner = _norm_inner(t.get("inner_path") or "")
    hint = _norm_inner(t.get("source_hint") or "")
    host = str(t.get("host") or "").casefold()
    if not (path or inner or hint):
        # A target-less item is its origin and why, unless its source gives
        # it an identity of its own (extra_key): then a reworded why (a
        # gate's text, a name list that grew) is still the same item.
        key = {"origin": origin} if extra_key else {"origin": origin, "why": " ".join(str(why or "").casefold().split())}
    else:
        key = {"kind": kind, "host": host if (hint and not path) else "", "path": path,
               "inner": inner, "hint": hint if not (path or inner) else ""}
        if kind == "search":
            key["terms"] = _pattern_terms(t.get("pattern") or "")
        if path and not inner and not hint and kind != "search" and _is_container(path):
            key["tool"] = listed(tool)
    if extra_key:
        # An item that must stand apart from the same read asked for by
        # another source (an evidence triage item, a reopen of one).
        key["key"] = extra_key
    blob = json.dumps(key, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


_CONTAINER_EXT_RE = re.compile(
    r"\.(?:e0[1-9]|ex01|raw|dd|img|vmdk|vhdx?|iso|mem|vmem|dmp|lime|aff4?|qcow2?|001)$", re.IGNORECASE)


_MEMORY_EXT_RE = re.compile(r"\.(?:mem|vmem|dmp|lime)$", re.IGNORECASE)


def _is_container(path: str) -> bool:
    """A disk or memory image by its file shape (image extensions are
    format knowledge, not case knowledge)."""
    return bool(_CONTAINER_EXT_RE.search(str(path or "")))


# ── the store ─────────────────────────────────────────────────────────────

def _log_items(log) -> list[dict]:
    return [e for e in log._entries if e.get("type") == "work_item"]


def work_items(log, statuses: Iterable[str] | None = None, task_id: str | None = None) -> list[dict]:
    with log._lock:
        want = set(statuses) if statuses else None
        return [e for e in _log_items(log)
                if (want is None or e.get("status") in want)
                and (task_id is None or task_id in (e.get("task_ids") or []))]


def add_work_item(log, origin: str, task_ids: Iterable[str], tool: str, target: dict | None, why: str,
                  args: dict | None = None, status: str = "due", source_ref: dict | None = None,
                  case_dir: str | None = None, extra_key: str = "") -> dict:
    """Create an item, or return the open one with the same fingerprint
    (adding the task ids, and raising a proposal to due when this source
    makes it due). A resolved, failed or dismissed fingerprint is returned
    as it is and never re-opened; a moot one may be created again. A new
    item runs the matcher once over the existing trace and is created closed
    when a call already read its target or failed to."""
    from core.execution_log import _touched, _utcnow
    from core.deferred_intents import mcp_tool_to_dotted
    task_ids = [str(t) for t in task_ids or [] if t]
    fp = fingerprint(origin, tool, target, why, extra_key)
    with log._lock:
        for e in _log_items(log):
            if e.get("fingerprint") != fp or e.get("status") == "moot":
                continue
            if e.get("status") in OPEN:
                changed = False
                for t in task_ids:
                    if t not in e["task_ids"]:
                        e["task_ids"].append(t)
                        changed = True
                if status == "due" and e.get("status") == "proposed":
                    e["status"] = "due"
                    e["promoted_by"] = origin
                    changed = True
                if changed:
                    _touched(e)
                    log._index_version += 1
                    log._flush()
            return e
        t = dict(target or {})
        for k in ("host", "path", "inner_path", "source_hint", "pattern", "window"):
            t.setdefault(k, "" if k != "window" else None)
        entry: dict[str, Any] = {
            "call_id": log._next_id(), "type": "work_item", "ts": _utcnow(),
            "origin": origin, "status": status, "task_ids": task_ids,
            "tool": listed(tool) if tool else "",
            "priority_tool": mcp_tool_to_dotted(tool) if tool and "." not in tool else (tool or ""),
            "target": t, "args": args, "args_summary": _summary(tool, t),
            "fingerprint": fp, "why": str(why or "")[:400], "source_ref": source_ref,
            "presented": 0, "unattended": 0, "attempts": [],
            "folded_into": None, "folded": [],
            "basis_call_id": None, "closed_by_tool": "", "outcome": "",
        }
        if t.get("path") or t.get("inner_path") or t.get("source_hint"):
            case = case_dir or _case_dir(log)
            from core.forensic_citation import own_words_entry
            for e in log._entries:
                if e.get("type") == "tool_call" and not own_words_entry(e):
                    if _close_by(entry, _call_view(e), case):
                        break
                elif _refused_ready_call(entry, e, case):
                    # A resumed run: its own ready call was refused for good
                    # in an earlier session; it is not shown to be refused again.
                    break
        log._append_entry(entry)
        return entry


def _refused_ready_call(item: dict, abandoned: dict, case_dir: str) -> bool:
    """Close ``item`` as failed when ``abandoned`` is a wrong-input-kind or
    evidence-compat refusal of its own ready call (same tool, reaching its
    target); True when it closed."""
    from core.execution_log import _touched
    if (abandoned.get("type") != "call_abandoned" or item.get("status") not in OPEN
            or not str(abandoned.get("reason") or "").startswith(CLOSING_REFUSALS)
            or not item.get("tool") or listed(str(abandoned.get("tool") or "")) != item["tool"]):
        return False
    view = _call_view({"type": "tool_call", "call_id": abandoned.get("call_id"),
                       "mcp_tool": abandoned.get("tool"), "cmd": f"<py>:{abandoned.get('tool')}",
                       "args": abandoned.get("args") or "{}"}, case_dir=case_dir)
    if not _reaches(item, view, case_dir):
        return False
    item["status"] = "failed"
    item["basis_call_id"] = abandoned.get("call_id")
    item["closed_by_tool"] = item["tool"]
    item["outcome"] = str(abandoned.get("reason") or "")[:300]
    _touched(item)
    return True


def _summary(tool: str, t: dict) -> str:
    bits = [str(t.get(k)) for k in ("host", "path", "inner_path", "source_hint") if t.get(k)]
    if t.get("pattern"):
        bits.append(f"pattern {t['pattern']}")
    return " ".join(bits)[:240]


def _case_dir(log) -> str:
    try:
        return str(log.case_dir() or "")
    except Exception:  # noqa: BLE001
        return ""


def dispose_work_item(log, item_id: int, action: str, basis_call_id: int | None = None,
                      target: dict | None = None, note: str = "") -> dict:
    """``promote`` (a proposal becomes due, optionally with a target),
    ``keep`` (a note), ``dismiss`` (only with a basis call that reached the
    target and read it or failed to; a reason alone is refused)."""
    from core.execution_log import _touched
    from core.forensic_citation import own_words_entry
    # Only the basis call's reads are worked out, not every call's.
    basis = None
    if action == "dismiss":
        with log._lock:
            entry = next((e for e in log._entries if e.get("type") == "tool_call"
                          and e.get("call_id") == basis_call_id), None)
        if entry is not None and not own_words_entry(entry):
            basis = _call_view(entry, case_dir=_case_dir(log))
    with log._lock:
        item = next((e for e in _log_items(log) if e.get("call_id") == item_id), None)
        if item is None:
            return {"ok": False, "error": f"no work item #{item_id}"}
        if item.get("status") not in OPEN:
            # A closed item keeps its record (a failure, a read, a basis):
            # no ruling rewrites it.
            return {"ok": False, "error": (f"#{item_id} is {item.get('status')}: closed items take no ruling; "
                                           "rulings are for due and proposed items")}
        if action == "promote":
            merged = {**item.get("target", {}), **(target or {})}
            if not has_target(merged):
                # A due item no call can reach never closes: it would hold
                # the run and be shown every turn. The ruling that stands
                # for such a proposal is keep.
                return {"ok": False, "error": (f"promote of #{item_id} refused: no target a call can reach; give "
                                               "path (the image) plus inner_path, or a case host that has one "
                                               "image plus inner_path; or keep")}
            if target:
                item["target"] = merged
                item["args_summary"] = _summary(item.get("tool", ""), item["target"])
            if item.get("status") == "proposed":
                item["status"] = "due"
        elif action == "keep":
            item["keep_note"] = str(note or "")[:300]
        elif action == "dismiss":
            if basis is None or not _reaches(item, basis, _case_dir(log)):
                return {"ok": False, "error": (f"dismiss of #{item_id} refused: call {basis_call_id} neither "
                                               "read nor failed to read its target")}
            item["status"] = "dismissed"
            item["basis_call_id"] = basis_call_id
            item["note"] = str(note or "")[:300]
        else:
            return {"ok": False, "error": f"unknown action {action!r}"}
        _touched(item)
        log._index_version += 1
        log._flush()
        return {"ok": True, "item": item}


def resolve_items(log, origin: str, source_ref: dict, outcome: str, status: str = "resolved") -> list[int]:
    """Close the open items of ``origin`` whose source_ref holds every key
    of ``source_ref`` as ``status`` (resolved: a condition outside the
    trace was met, such as a view row filling; moot: the reason for the
    item went, such as the row leaving its view). Returns the ids closed."""
    from core.execution_log import _touched
    done: list[int] = []
    with log._lock:
        for e in _log_items(log):
            ref = e.get("source_ref") or {}
            if e.get("origin") == origin and e.get("status") in OPEN and all(ref.get(k) == v for k, v in source_ref.items()):
                e["status"], e["outcome"] = status, outcome
                _touched(e)
                done.append(e["call_id"])
        if done:
            log._index_version += 1
            log._flush()
    return done


def close_item(log, item_id: int, status: str, outcome: str, call_ids: Iterable[int] = ()) -> dict | None:
    """Close one item as its executor ended it (the frontier: ``resolved``
    when it yielded, ``dismissed`` when not, ``failed`` on an error), with
    the calls it made as the basis. An item a call of its own already
    closed keeps that status; the run's record is added either way."""
    from core.execution_log import _touched
    with log._lock:
        item = next((e for e in _log_items(log) if e.get("call_id") == item_id), None)
        if item is None:
            return None
        if item.get("status") in OPEN:
            item["status"] = status
            item["outcome"] = str(outcome or "")[:300]
        item["item_calls"] = [int(c) for c in call_ids][:200]
        _touched(item)
        log._index_version += 1
        log._flush()
        return item


def moot_items(log, case_dir: str | None) -> list[int]:
    """Items of plan, director and proposal origins whose every question has
    left the actionable set become moot, with the call that closed the last
    one; source and absence items stay. Returns the ids that changed."""
    from core.execution_log import _touched
    tasks = _task_status(case_dir)
    if not tasks:
        return []
    from core.investigation_tasks import ACTIONABLE_STATUSES
    closer = _task_close_calls(log)
    n: list[int] = []
    with log._lock:
        for e in _log_items(log):
            if e.get("status") not in OPEN or e.get("origin") in SURVIVES_CLOSE:
                continue
            ids = [t for t in e.get("task_ids") or [] if t in tasks]
            if not ids or any(tasks[t] in ACTIONABLE_STATUSES for t in ids):
                continue
            e["status"] = "moot"
            e["moot_by_call_id"] = max((closer.get(t, 0) for t in ids), default=0) or None
            _touched(e)
            n.append(e["call_id"])
        if n:
            log._index_version += 1
            log._flush()
    return n


def _task_status(case_dir: str | None) -> dict[str, str]:
    if not case_dir:
        return {}
    try:
        from core.investigation_tasks import load_tasks
        return {str(t.get("id")): str(t.get("status") or "") for t in load_tasks(case_dir).get("tasks") or []
                if isinstance(t, dict) and t.get("id")}
    except Exception:  # noqa: BLE001
        return {}


def _task_close_calls(log) -> dict[str, int]:
    """The last call that updated each question (the call a moot item names)."""
    out: dict[str, int] = {}
    for e in log._entries:
        if e.get("type") == "tool_call" and "update_investigation_task" in str(e.get("cmd") or "") + str(
                e.get("mcp_tool") or ""):
            m = re.search(r"task-\d+", str(e.get("args") or ""))
            if m:
                out[m.group(0)] = int(e.get("call_id") or 0)
    return out


def retire_protocol_intents(log, note: str) -> int:
    """Open and prescribed protocol intents of a resumed trace become
    ``retired`` (no deferral: nothing will ever re-run them)."""
    from core.execution_log import _touched
    n = 0
    with log._lock:
        for e in log._entries:
            if e.get("type") == "deferred_intent" and e.get("status") in ("open", "prescribed"):
                e["status"] = "retired"
                e["note"] = note
                _touched(e)
                n += 1
        if n:
            log._deferred_latch = False
            log._index_version += 1
            log._flush()
    return n


# ── the matcher ───────────────────────────────────────────────────────────

def _call_view(entry: dict, args: dict | None = None, *, case_dir: str | None = None, resolver=None) -> dict:
    """What a trace call read and named (core.evidence_identity.call_reads),
    its tool and its pattern text. ``args``: the typed arguments when the
    caller has them (live)."""
    from core.coverage_ledger import _entry_tool
    from core.evidence_identity import call_args, call_reads
    typed = args
    args = call_args(entry, args)
    tool = _entry_tool(entry) or listed(str(entry.get("mcp_tool") or ""))
    case = case_dir or _active_case()
    reads = call_reads(case, entry, typed, resolver=resolver) if case else {}
    pattern = " ".join(str(args.get(k)) for k in _PATTERN_KEYS if args.get(k))
    pattern = re.sub(r"\\(.)", r"\1", pattern).casefold()
    return {"entry": entry, "tool": listed(tool), "reads": reads, "pattern": pattern, "args": args,
            "typed": typed, "case": case}


def _active_case() -> str:
    try:
        from core.paths import active_case_dir
        return active_case_dir() or ""
    except Exception:  # noqa: BLE001
        return ""


def takes_target(schema: dict | None) -> bool:
    """Whether a tool's input schema lets a call carry an item's target:
    _reaches finds the target among a call's string arguments, whatever
    their names (_call_view), so a tool with no string-valued parameter can
    never close an item. Unknown (None) is no refusal.
    ponytail: any string parameter counts, also one that cannot name a file
    (a job id, a pattern); such a tool's item passes and still never closes.
    A schema-declared input role per parameter is the upgrade."""
    if schema is None:
        return True

    def stringy(v: Any) -> bool:
        if not isinstance(v, dict):
            return False
        if v.get("type") == "string":
            return True
        if v.get("type") == "array":
            return stringy(v.get("items"))
        return any(stringy(x) for x in (v.get("anyOf") or v.get("oneOf") or []))
    return any(stringy(v) for v in (schema.get("properties") or {}).values())


def has_target(target: dict | None) -> bool:
    """Whether a target is one a call can reach, so an item on it can
    close: a case path (normalised; a bare "./" is none), or a source
    hint. A host alone, or an inner path without the image it is in, is
    not: ``_reaches`` matches a call by exactly these two values, so an
    item without them stays open for good."""
    t = target or {}
    return bool(_norm_path(t.get("path") or "") or t.get("source_hint"))


_TARGETS: dict[tuple, dict] = {}


def _target(item: dict, case_dir: str, resolver=None) -> dict:
    """What an item's target names (core.evidence_identity): its handle, else
    its path and inner path, else its path; ``image`` for an image-wide
    target (an image and no file inside it), ``folder`` for a case folder.
    A source hint alone (a file of a kind on a host) names no one file."""
    from core.evidence_identity import Resolver
    t = item.get("target") or {}
    own = resolver is None
    r = resolver or Resolver(case_dir)
    try:
        key = (r.generation, json.dumps(t, sort_keys=True, default=str))
        hit = _TARGETS.get(key)
        if hit is not None:
            return hit
        path, inner, handle = str(t.get("path") or ""), str(t.get("inner_path") or ""), str(t.get("handle") or "")
        out: dict = {"ids": frozenset(), "image": "", "folder": "", "hint": str(t.get("source_hint") or ""),
                     "host": str(t.get("host") or "")}
        # The image as the case names it (a director may write it in another
        # case); an inner path that is the image itself names no file in it
        # (parse_director_entries' rule, for an item stored before it).
        img = r.match_image(_norm_path(path)) if path else None
        if img and inner and (_norm_inner(inner) == _norm_inner(path) or r.match_image(_norm_path(inner))):
            inner = ""
        if handle:
            n = r.name(handle)
            out["ids"] = n.ids | n.inner
        elif path and inner and r.name(inner).inner:
            # An inner path written as a handle or under the readable form
            # (an item stored before parse_director_entries made it true).
            n = r.name(inner)
            out["ids"] = n.ids | n.inner
        elif path and inner:
            image = img["rel"] if img else (r.name(path).image or (_norm_path(path) if _is_container(path) else ""))
            n = r.name(f"{image}::{inner.lstrip('/')}" if image else f"{path.rstrip('/')}/{inner.lstrip('/')}")
            out["ids"] = n.ids | n.inner | ({("inner", image, _norm_inner(inner))} if image else frozenset())
        elif path and img:
            out["image"] = img["rel"]              # an image, no file inside it
        elif path:
            n = r.name(path)
            if n.folder:
                out["folder"], out["ids"] = _norm_path(path), n.ids
            elif n.image and (n.image in r.meta() or _is_container(n.image)) \
                    and not any(k == "entry" for k, _i in n.ids) and not n.paths:
                out["image"] = n.image             # an image, no file inside it
            else:
                out["ids"] = n.ids | n.paths       # a mount path: also the case path
        if len(_TARGETS) > 20_000:
            _TARGETS.clear()
        _TARGETS[key] = out
        return out
    finally:
        if own:
            r.close()


def _reach(item: dict, call: dict, case_dir: str, resolver=None) -> str:
    """How a call reached an item's target, by what the call read (its
    ``reads``, core.evidence_identity.call_reads) against what the target
    names (_target): "read" (a file of the target by name), "processed"
    (its parser reported processing it), "swept" (a folder holding the target that
    the call was pointed at, with no report of what it processed), "listed"
    (named only), "" (not reached). A search must also carry the target's
    pattern terms; an image-wide item is reached by an in-image name of the
    image, and closed only by its own tool."""
    t = item.get("target") or {}
    if not has_target(t):
        return ""
    reads = call.get("reads") or {}
    if case_dir and call.get("case") != case_dir:
        from core.evidence_identity import call_reads
        reads = call_reads(case_dir, call["entry"], call.get("typed"), resolver=resolver)
    tg = _target(item, case_dir, resolver)
    kind = tool_kind(item.get("tool") or "")
    level = ""
    if tg["image"]:
        if tg["image"] in reads.get("images", ()):
            level = "read" if not item.get("tool") or kind == "search" or call["tool"] == item["tool"] else ""
    elif tg["folder"]:
        if tg["folder"] in {_norm_path(f) for f in reads.get("folders", ())}:
            level = "read"
    elif tg["ids"]:
        ids = tg["ids"]
        for key, name in (("content", "read"), ("processed", "processed"), ("folder", "swept"),
                          ("listed", "listed")):
            how = _meets(ids, reads.get(key, frozenset()))
            # A file below a folder the item names is the item's work only
            # when its own tool read it: another reader of one file there
            # did not do what the item plans.
            if how == "below" and item.get("tool") and kind != "search" and call["tool"] != item["tool"]:
                how = ""
            if how:
                level = name
                break
    elif tg["hint"]:
        level = _hint_reach(tg, reads, case_dir, resolver)
    if level and kind == "search":
        terms = _pattern_terms(t.get("pattern") or "")
        if any(term not in call["pattern"] for term in terms):
            return ""
        return "read"
    return level


def _meets(target: frozenset, got: frozenset) -> str:
    """How what a call read meets a target's identities: "same" (one in
    common), "below" (a path inside an image below the target's path in it:
    a file of the folder the target names), "" (not at all)."""
    if target & got:
        return "same"
    inner = [(i[1], i[2]) for i in target if i[0] == "inner"]
    below = bool(inner) and any(g[0] == "inner" and any(g[1] == img and g[2].startswith(p + "/")
                                                        for img, p in inner) for g in got)
    return "below" if below else ""


def _hint_reach(tg: dict, reads: dict, case_dir: str, resolver=None) -> str:
    """A source hint (a file of a kind on a host, by the tail of its path)
    against the paths of what the call read: an entry by its path in the
    image on the target's host, a case file by its path."""
    from core.evidence_identity import Resolver
    host = tg["host"].casefold()
    own = resolver is None
    r = resolver or Resolver(case_dir)
    try:
        for key, level in (("content", "read"), ("processed", "read"), ("folder", "swept"), ("listed", "listed")):
            idents = reads.get(key, frozenset())
            entries = [x[1] for x in idents if x[0] == "entry"]
            where = r.where(entries) if entries else {}
            for k, i in (x for x in idents if len(x) == 2):
                if k == "entry":
                    h, _img, _vol, p = where.get(i) or ("", "", None, "")
                    if host and str(h or "").casefold() != host:
                        continue
                    if _shares_tail(tg["hint"], str(p or "")):
                        return level
                elif k == "file" and _shares_tail(tg["hint"], str(i)):
                    from core.forensic_citation import host_mentioned
                    if not host or host_mentioned(tg["host"], str(i)):
                        return level
            for ident in idents:
                if ident[0] == "inner" and _shares_tail(tg["hint"], ident[2]) and (not host or _image_host(
                        case_dir, ident[1]) == host):
                    return level
        return ""
    finally:
        if own:
            r.close()


def _image_host(case_dir: str, image: str) -> str:
    """The host an image stands for (the Evidence Links), case-folded."""
    try:
        from core.evidence_links import host_for_image
        from core.forensic_citation import host_mentioned  # noqa: F401
        return str(host_for_image(image, case_dir) or "").casefold()
    except Exception:  # noqa: BLE001
        return ""


def _reaches(item: dict, call: dict, case_dir: str) -> bool:
    """Whether a call reaches an item's target at all (_reach): named, read
    or parsed. Whether it closes the item is _close_by's question."""
    return bool(_reach(item, call, case_dir))


def _closes(item: dict, call: dict) -> bool:
    """The tool family: a content read closes a read item, a listing a
    listing item, a search a search item; a timeline grep never closes a
    read of a raw source."""
    from core.coverage_ledger import reads_content
    kind = tool_kind(item.get("tool") or "")
    ckind = tool_kind(call["tool"])
    if kind == "search":
        return ckind == "search"
    if kind == "listing":
        return ckind in ("listing", "read") and (ckind == "listing" or reads_content(call["tool"]))
    return ckind == "read" and reads_content(call["tool"])


def _outcome(entry: dict) -> str | None:
    """``resolved``, ``failed`` or None (not an attempt: a gate refusal, a
    protocol block, an argument error, a call a stop cut short)."""
    from core.coverage_ledger import _failed_attempt
    if entry.get("incomplete") is True:
        from core.timeout import inprocess_deadline_on
        if inprocess_deadline_on():
            return None          # cut at its deadline: an attempt, the item stays open
    if entry.get("success") is True:
        return "resolved"
    if _failed_attempt(entry):
        return "failed"
    return None


def _close_by(item: dict, call: dict, case_dir: str, *, closing_call_id: int | None = None) -> bool:
    """Close ``item`` by ``call`` when the call reaches its target with the
    right tool family and was an attempt; else record the call under
    ``attempts`` when it reached the target. True when the item closed."""
    from core.execution_log import _touched
    level = _reach(item, call, case_dir) if item.get("status") in OPEN else ""
    if item.get("status") not in OPEN or item.get("origin") == "triage" \
            or (item.get("source_ref") or {}).get("closed_by") == EXECUTOR \
            or not level:
        # An evidence triage item closes when its classes are credited from
        # the evidence (core.evidence_triage.sync_triage), never by one call;
        # an item an executor runs (the frontier's host passes, folded joins,
        # follow-ups and syntheses) closes only when its run ends
        # (close_item): a read of its host is part of its work, not its end.
        return False
    # The call as the read rule sees it (core.coverage_ledger.resolved_entry):
    # a background job's start is no outcome while the job runs.
    from core.coverage_ledger import resolved_entry
    cid = closing_call_id or call["entry"].get("call_id")
    entry = resolved_entry(case_dir, call["entry"])
    outcome = _outcome(entry) if entry is not None else None
    closing = level in ("read", "processed") or (level == "listed" and tool_kind(item.get("tool") or "") == "listing") \
        or (level == "swept" and call["tool"] == item.get("tool"))
    if outcome and closing and _closes(item, call):
        swept = level == "swept" and outcome == "resolved"
        item["status"] = "parsed" if swept else outcome
        item["basis_call_id"] = cid
        item["closed_by_tool"] = call["tool"]
        item["outcome"] = (PARSED_UNREPORTED if swept else "" if outcome == "resolved" else
                           str(entry.get("stderr") or entry.get("error") or entry.get("stdout_excerpt") or "")[:300])
        _touched(item)
        return True
    if cid and cid not in item["attempts"]:
        item["attempts"].append(cid)
        _touched(item)
    return False


def close_items_for_call(log, tool: str, args: dict | None, call_entries: list[dict],
                         abandoned: list[dict] | None = None, *, closing_call_id: int | None = None,
                         case_dir: str | None = None) -> list[int]:
    """Close the open items a just-run call reached (the hook inside the
    loop's _run_tool and its memo replay branch). ``call_entries``: the
    trace entries the call wrote (its tool_call). ``abandoned``: the
    call_abandoned entries written during the call; a wrong-input-kind or
    evidence-compat refusal of an item's own ready call closes the item as
    failed with the refusal as outcome. Returns the ids closed."""
    case_dir = case_dir if case_dir is not None else _case_dir(log)
    closed: list[int] = []
    # What each call read, worked out once before the items are walked.
    views = [_call_view(e, dict(args) if args else None, case_dir=case_dir)
             for e in call_entries if e.get("type") == "tool_call"]
    with log._lock:
        items = [e for e in _log_items(log) if e.get("status") in OPEN]
        if not items:
            return closed
        refusal = next((a for a in abandoned or []
                        if str(a.get("reason") or "").startswith(CLOSING_REFUSALS)), None)
        if refusal is not None:
            refused = {**refusal, "tool": refusal.get("tool") or tool,
                       "args": refusal.get("args") or json.dumps(dict(args or {}), default=str)}
            for item in items:
                if _refused_ready_call(item, refused, case_dir):
                    closed.append(item["call_id"])
        for view in views:
            for item in items:
                if _close_by(item, view, case_dir, closing_call_id=closing_call_id):
                    closed.append(item["call_id"])
        log._index_version += 1
        log._flush()
    return closed


# ── presentation ──────────────────────────────────────────────────────────

def counted(item: dict, tasks: dict[str, str]) -> bool:
    """An item that holds the run (settle, wait, neglect, the close-out):
    a due item of an actionable question, or a due source or absence item
    of any question. Moot, proposed and folded items never hold it."""
    from core.investigation_tasks import ACTIONABLE_STATUSES
    if item.get("status") != "due" or item.get("folded_into"):
        return False
    if item.get("origin") == "triage" and (item.get("source_ref") or {}).get("classes"):
        # The classes stand in the open-work list on their own, each with a
        # read and a leave; the bundle's line (an image-wide target no call
        # closes) is not shown or counted, and closes by credit.
        return False
    if item.get("origin") in SURVIVES_CLOSE:
        return True
    ids = item.get("task_ids") or []
    return not ids or not tasks or any(tasks.get(t, "open") in ACTIONABLE_STATUSES for t in ids)


def _rank(items: list[dict], tasks: dict[str, str], resolved_tasks: set[str]) -> list[dict]:
    """Items of actionable questions before source and absence items whose
    every question is closed; round-robin across questions (questions with
    no resolved item first, then by the oldest due item); inside a question
    by origin, then age; an item unattended three times moves behind the
    other items of its question."""
    from core.investigation_tasks import ACTIONABLE_STATUSES

    def open_q(it: dict) -> bool:
        ids = it.get("task_ids") or []
        return not ids or not tasks or any(tasks.get(t, "open") in ACTIONABLE_STATUSES for t in ids)
    groups: dict[str, list[dict]] = {}
    for it in items:
        q = (it.get("task_ids") or ["-"])[0]
        groups.setdefault(q, []).append(it)
    for q in groups:
        groups[q].sort(key=lambda it: (int(it.get("unattended") or 0) >= UNATTENDED_DEMOTE,
                                       _ORIGIN_RANK.get(it.get("origin"), 9), it.get("call_id") or 0))
    order = sorted(groups, key=lambda q: (q in resolved_tasks, min(i.get("call_id") or 0 for i in groups[q])))
    out: list[dict] = []
    for tier in (True, False):
        queues = [[i for i in groups[q] if open_q(i) == tier] for q in order]
        while any(queues):
            for qu in queues:
                if qu:
                    out.append(qu.pop(0))
    return out


def _item_handle(target: dict) -> str:
    """The image handle that reads a target inside an image, when image
    handles are on: the target's own, or its image and inner path."""
    try:
        from core.contents_index import image_handles_on
        if not image_handles_on():
            return ""
    except Exception:  # noqa: BLE001
        return ""
    if target.get("handle"):
        return str(target["handle"])
    if target.get("path") and target.get("inner_path") and _is_container(_norm_path(target["path"])):
        return f"{target['path']}::{str(target['inner_path']).lstrip('/')}"
    return ""


def ready_call(item: dict, params: Iterable[str] | None = None) -> str:
    """The item as a call the analyst can make: ``args`` when the source
    gave them, else the target by the tool's own argument names; without
    the schema, the tool and its target."""
    tool = item.get("tool") or ""
    t = item.get("target") or {}
    handle = _item_handle(t)
    if not tool:
        # No tool named by the source (a timeline row's file, an index
        # entry): the read is the analyst's choice of reader.
        # Evidence-derived names (a handle, a path) are shown quoted and
        # escaped (core.coverage_ledger.shown_name): the name is the evidence's.
        from core.coverage_ledger import shown_name
        if handle:
            return f"read {shown_name(handle)} (pass the handle as the file argument of a parser for its type)"
        return f"read {shown_name(item.get('args_summary') or '?')} (a tool that reads its content)"
    if item.get("args"):
        return f"{tool}({', '.join(f'{k}={json.dumps(v)}' for k, v in item['args'].items())})"
    names = list(params or [])

    def place(t: dict) -> str:
        bits: list[str] = []
        used: set[str] = set()

        def put(value: str, candidates: tuple[str, ...]) -> bool:
            for c in candidates:
                if c in names and c not in used:
                    bits.append(f"{c}={json.dumps(value)}")
                    used.add(c)
                    return True
            return False
        ok = True
        if t.get("path"):
            ok = put(t["path"], _FILE_PARAMS)
        if t.get("inner_path"):
            ok = put(t["inner_path"], _INNER_PARAMS) and ok
        elif t.get("source_hint") and not t.get("path"):
            ok = put(t["source_hint"], _FILE_PARAMS) and ok
        if t.get("pattern"):
            ok = put(t["pattern"], _PATTERN_KEYS) and ok
        return f"{tool}({', '.join(bits)})" if names and ok and bits else ""
    # A tool that takes the image and the inner path gets both; a reader
    # that takes one file reads it through its handle.
    call = place(t)
    if not call and handle:
        call = place({**{k: v for k, v in t.items() if k not in ("path", "inner_path", "source_hint")},
                      "path": handle})
    from core.coverage_ledger import shown_name
    return call or f"{tool} on {shown_name(item.get('args_summary') or '?')}"


def _line(n: int, item: dict, params, folded: dict[int, dict]) -> str:
    q = ",".join(item.get("task_ids") or []) or "no question"
    origin = {"plan": "question plan", "director": "director", "absence": "absence check",
              "source": "source of the rows"}.get(item.get("origin"), item.get("origin"))
    if item.get("origin") == "absence" and (item.get("source_ref") or {}).get("claim_id"):
        origin += f", claim {item['source_ref']['claim_id']}"
    from core.coverage_ledger import shown_name
    head = f"{n}. #{item['call_id']} {q} ({origin}): {ready_call(item, params)}"
    lines = [head, f"   why: {shown_name(str(item.get('why') or '')[:200], quote=False)}"]
    for fid in item.get("folded") or []:
        f = folded.get(fid)
        if f is not None and f.get("status") == "due":
            lines.append(f"   first read there (#{fid}): "
                         f"{shown_name((f.get('target') or {}).get('source_hint') or '')}")
            break
    return "\n".join(lines)


def fold(items: list[dict]) -> None:
    """A source item whose hint lies under a due plan or director item's
    directory target on the same host is shown inside that item (in memory,
    for this presentation; the trace keeps both entries)."""
    dirs = [i for i in items if i.get("origin") in ("plan", "director") and i.get("status") == "due"
            and tool_kind(i.get("tool") or "") != "search"]
    for it in items:
        it.setdefault("folded", [])
    for src in items:
        if src.get("origin") != "source" or src.get("status") != "due":
            continue
        hint = _norm_inner((src.get("target") or {}).get("source_hint") or "")
        for d in dirs:
            dt = d.get("target") or {}
            base = _norm_inner(dt.get("inner_path") or "")
            same_host = str(dt.get("host") or "").casefold() == str((src.get("target") or {}).get("host")
                                                                     or "").casefold()
            if base and same_host and (("/" + base + "/") in ("/" + hint)):
                src["folded_into"] = d["call_id"]
                if src["call_id"] not in d["folded"]:
                    d["folded"].append(src["call_id"])
                break


def work_order_block(log, case_dir: str | None, params_of=None, *, header_lines: Iterable[str] = ()) -> tuple[str, list[int]]:
    """The per-turn block and the ids it shows: up to six items in rank
    order while the block stays under BLOCK_CHARS, at least one."""
    moot_items(log, case_dir)
    tasks = _task_status(case_dir)
    with log._lock:
        items = [dict(e) for e in _log_items(log)]
    due = [i for i in items if i.get("status") == "due"]
    for i in due:
        i["folded_into"] = None
        i["folded"] = []
    fold(due)
    shown_pool = [i for i in due if not i.get("folded_into") and counted(i, tasks)]
    if not shown_pool:
        # No read due: the header lines (the director's note, the progress
        # line, the estate counts) are shown on their own counters still.
        return "\n".join(str(h) for h in header_lines if h), []
    resolved_tasks = {t for i in items if i.get("status") == "resolved" for t in i.get("task_ids") or []}
    ranked = _rank(shown_pool, tasks, resolved_tasks)
    planned = [i for i in items if i.get("status") not in ("proposed", "moot")]
    done = sum(1 for i in planned if i.get("status") == "resolved")
    failed = sum(1 for i in planned if i.get("status") == "failed")
    from core.investigation_tasks import ACTIONABLE_STATUSES
    with_items = {t for i in items for t in i.get("task_ids") or []}
    no_read = sorted(t for t, s in tasks.items() if s in ACTIONABLE_STATUSES and t in with_items
                     and t not in resolved_tasks)
    head = [*header_lines,
            f"[work order] {done} of {len(planned)} planned reads done, {failed} failed."
            + (f" Questions with no read yet: {', '.join(no_read[:8])}." if no_read else ""),
            "Run these next; each item closes when a call reads its target or fails to:"]
    by_id = {i["call_id"]: i for i in due}
    lines: list[str] = []
    shown: list[int] = []
    for n, it in enumerate(ranked[:BLOCK_ITEMS], start=1):
        params = params_of(it.get("tool") or "") if params_of else None
        line = _line(n, it, params, by_id)
        if shown and len("\n".join(head + lines + [line])) > BLOCK_CHARS:
            break
        lines.append(line)
        shown.append(it["call_id"])
    rest = ranked[len(shown):]
    if rest:
        qs = sorted({t for i in rest for t in i.get("task_ids") or []})
        tail = sum(1 for i in rest if i.get("origin") in SURVIVES_CLOSE
                   and not any(tasks.get(t, "open") in ACTIONABLE_STATUSES for t in i.get("task_ids") or []))
        lines.append(f"{len(rest)} more due ({', '.join(qs[:6])}"
                     + (f"; {tail} of them sources of answered questions" if tail else "") + ").")
    return "\n".join(head + lines), shown


def mark_presented(log, shown: list[int], moved: set[int]) -> None:
    """Count a presentation; an item shown in a turn without moving gains
    ``unattended`` (it orders items and decides nothing else)."""
    from core.execution_log import _touched
    if not shown:
        return
    with log._lock:
        for e in _log_items(log):
            if e.get("call_id") in shown:
                e["presented"] = int(e.get("presented") or 0) + 1
                if e["call_id"] not in moved:
                    e["unattended"] = int(e.get("unattended") or 0) + 1
                _touched(e)
        log._index_version += 1
        log._flush()


# ponytail: views keyed by the entry and its revision; a copy the index ties
# to its entry after the call was viewed is not seen until the entry changes.
_VIEWS: dict[tuple, dict] = {}


def _cached_view(entry: dict, case_dir: str | None = None, resolver=None) -> dict:
    key = (id(entry), entry.get("call_id"), entry.get("_rev"), entry.get("args"), case_dir)
    view = _VIEWS.get(key)
    if view is None:
        if len(_VIEWS) > 20_000:
            _VIEWS.clear()
        view = _VIEWS[key] = _call_view(entry, case_dir=case_dir, resolver=resolver)
    return view


def reads_of(log, case_dir: str | None, items: list[dict]) -> dict[int, dict]:
    """For each due, moot or failed item, the call that read its target as
    the live close reads one (the target reached, the closing tool family,
    a resolved outcome), from the trace, whenever it ran: the one recount
    the finish's due list and the report's lines share. {item id: {"call",
    "how" ("read"; "parsed": its parser reported processing it;
    "unreported": a folder parse by the item's own tool that reports
    nothing), "when" ("after", "before": the target was read before
    the item was planned; for a failed item a read after its failure),
    "filter" (the parse's own filter, from its processed stamp)}}. A read
    after the item wins over one before it. An item the triage or an
    executor closes is not recounted (_close_by's rule)."""
    todo = [i for i in items if i.get("status") in ("due", "moot", "failed") and i.get("origin") != "triage"
            and (i.get("source_ref") or {}).get("closed_by") != EXECUTOR]
    if not todo or not case_dir:
        return {}
    from core.coverage_ledger import resolved_entry
    from core.evidence_identity import Resolver
    from core.forensic_citation import own_words_entry
    with log._lock:
        entries = [e for e in log._entries if e.get("type") == "tool_call"]
    out: dict[int, dict] = {}
    with Resolver(case_dir) as r:
        calls = [_cached_view(e, case_dir, r) for e in entries if not own_words_entry(e)]
        for item in todo:
            born = int(item.get("call_id") or 0)
            after_of = int(item.get("basis_call_id") or 0) if item.get("status") == "failed" else born
            best = None
            for call in calls:
                cid = int(call["entry"].get("call_id") or 0)
                if item.get("status") == "failed" and cid <= after_of:
                    continue
                level = _reach(item, call, case_dir, r) if _closes(item, call) else ""
                if level not in ("read", "processed", "swept") \
                        or (level == "swept" and call["tool"] != item.get("tool")):
                    continue
                entry = resolved_entry(case_dir, call["entry"])
                if entry is None or _outcome(entry) != "resolved":
                    continue
                stamp = call["entry"].get("processed") if isinstance(call["entry"].get("processed"), dict) else {}
                hit = {"call": cid, "how": {"swept": "unreported", "processed": "parsed"}.get(level, "read"),
                       "when": "after" if cid > born else "before",
                       "filter": str(stamp.get("filter") or "") if stamp else ""}
                if hit["when"] == "after":
                    best = hit
                    break
                best = best or hit
            if best is not None:
                out[item["call_id"]] = best
    return out


def later_reads(log, case_dir: str | None, items: list[dict]) -> dict[int, int]:
    """{item id: the call that read its target} (reads_of)."""
    return {k: v["call"] for k, v in reads_of(log, case_dir, items).items()}


def counted_due(log, case_dir: str | None) -> list[dict]:
    tasks = _task_status(case_dir)
    with log._lock:
        items = [dict(e) for e in _log_items(log)]
    # A due item whose target a call read is no longer owed (reads_of),
    # whether the read came after the item or before it was planned.
    read = later_reads(log, case_dir, [i for i in items if i.get("status") == "due"])
    due = [i for i in items if i.get("status") == "due" and i.get("call_id") not in read]
    for i in due:
        i["folded_into"] = None
        i["folded"] = []
    fold(due)
    return [i for i in due if counted(i, tasks)]


def closed_ids(log) -> frozenset:
    """Items closed or moot: each is movement for the report ladder."""
    with log._lock:
        return frozenset(("item", e["call_id"]) for e in _log_items(log)
                         if e.get("status") in CLOSED | {"moot"})


def shortest_ready(log, case_dir: str | None = None, params_of=None) -> tuple[str, int | None]:
    """The first counted due item as a ready call and its id, ("", None)
    when none."""
    items = counted_due(log, case_dir or _case_dir(log))
    if not items:
        return "", None
    tasks = _task_status(case_dir or _case_dir(log))
    first = _rank(items, tasks, set())[0]
    return ready_call(first, params_of(first.get("tool") or "") if params_of else None), first.get("call_id")


def shortest_ready_call(log, case_dir: str | None = None, params_of=None) -> str:
    """The first counted due item as a ready call, "" when none."""
    return shortest_ready(log, case_dir, params_of)[0]


def report_lines(log, case_dir: str | None = None) -> list[str]:
    """Evidence Gaps lines for the reads the order planned and did not get:
    due (shown N times), failed, moot, proposed and never adopted."""
    with log._lock:
        items = [dict(e) for e in _log_items(log)]
    # The same recount as the finish's due list: a due or moot item a later
    # call read says so, whatever its stored word.
    read = reads_of(log, case_dir if case_dir is not None else _case_dir(log), items)
    out: list[str] = []
    for i in items:
        what = f"#{i['call_id']} {','.join(i.get('task_ids') or []) or '-'} {i.get('tool') or ''} " \
               f"{i.get('args_summary') or ''}".strip()
        st = i.get("status")
        if i.get("call_id") in read:
            hit = read[i["call_id"]]
            closer = int(i.get("moot_by_call_id") or 0)
            verb = "read" if hit["how"] == "read" else "parsed" + (f" with {hit['filter']}" if hit["filter"] else "")
            if hit["how"] == "unreported":
                verb += " (no report of what it processed)"
            when = (" before it was planned" if hit["when"] == "before"
                    else " after it failed" if st == "failed"
                    else " after its question closed" if st == "moot" and closer and hit["call"] > closer else "")
            out.append(f"- Planned reads: {what}: {verb} by call {hit['call']}{when}")
        elif st == "parsed":
            out.append(f"- Planned reads: {what}: parsed by call {i.get('basis_call_id')}, which reports no "
                       "files it processed: not counted read")
        elif st == "due":
            note = (f"shown {i.get('presented', 0)} times, {len(i.get('attempts') or [])} calls near it, "
                    "never read" if i.get("attempts") else f"shown {i.get('presented', 0)} times, not attempted")
            out.append(f"- Planned reads not done: {what}: {note}")
        elif st == "failed":
            out.append(f"- Planned reads not done: {what}: failed: {i.get('outcome') or 'no output'} "
                       f"(call {i.get('basis_call_id')})")
        elif st == "moot":
            # An item a question's close made moot names that call; one made
            # moot for another reason gives its outcome.
            why = (i["outcome"] if i.get("outcome") and not i.get("moot_by_call_id") else
                   f"the question was closed by call {i.get('moot_by_call_id') or '?'}")
            out.append(f"- Planned reads not done: {what}: not read: {why}")
        elif st == "proposed":
            who = {"blocker": "the reviewer", "index": "the case index", "series": "the series check"}.get(
                i.get("origin"), i.get("origin"))
            out.append(f"- Planned reads not done: {what}: proposed by {who}, not adopted"
                       + (f": {i['keep_note']}" if i.get("keep_note") else ""))
    return out


# ── what the run still owes: one list for the close-out ─────────────────

def open_question_parts(case_dir: str | None) -> list[tuple[dict, list[dict]]]:
    """(question, its open parts) for each actionable question that has one:
    the standard parts stand for their umbrella, which is never listed beside
    them; a question without parts stands for itself unless it is blocked on
    missing evidence (dispositioned)."""
    if not case_dir:
        return []
    from core.investigation_tasks import actionable_tasks
    from core.request_parts import open_parts
    out: list[tuple[dict, list[dict]]] = []
    for t in actionable_tasks(case_dir):
        parts = [p for p in t.get("parts") or [] if isinstance(p, dict)]
        if not parts:
            if t.get("status") != "blocked_missing_evidence":
                out.append((t, [{"id": "", "text": str(t.get("text") or ""), "type": ""}]))
            continue
        pending = open_parts(t)
        if any(p.get("kind") == "standard" for p in parts):
            pending = [p for p in pending if p.get("kind") != "umbrella"]
        if pending:
            out.append((t, pending))
    return out


# ── refused findings: a refused finding stays on the table ───────────────

# Gates whose objection is that a value or a name the finding states is in no
# cited output: such a finding is withdrawn or grounded, never just recorded
# again. Every other refusal is about form or scope (a universal, an
# absence, the tier, the evaluation): recorded again without the objected
# sentence, or with the count or evaluation the refusal named.
_GROUNDING_GATES = frozenset({"citation_support", "confidence_and_citation", "lineage_relevance"})


# Gates whose objection is about the form or the scope of the content: a
# universal, an absence, the tier and its evaluation, an attribution. With
# the grounding gates these are the content gates; a refused finding is open
# work only when one of them refused it. A dedupe, a note sent to the
# messages, a protocol step (DAIR, routing, lineage, supersedes) is no
# finding left unrecorded: recording it again is refused again.
_FORM_GATES = frozenset({"universal_from_truncated", "negative_completeness", "negative_from_truncated",
                         "confirmed_requires_supported_evaluate", "confirmed_requires_linked_call_id",
                         "indicator_absence", "attribution_required"})


def _grounding_gate(gate: str) -> bool:
    return gate.endswith("_grounding") or gate in _GROUNDING_GATES


def _content_gate(gate: str) -> bool:
    return gate in _FORM_GATES or _grounding_gate(gate)


def refusal_call_id(old_id: object) -> int | None:
    """The refusal's call id as claim.supersede's old_id names it: "182" or
    "call 182" (the form the open-work line writes); None for a claim id."""
    text = str(old_id or "").strip()
    text = text[4:].strip() if text.casefold().startswith("call") else text
    return int(text) if text.isdigit() else None


_ABBREVIATION_RE = re.compile(r"(?:[a-z]\.)+[a-z]?")


def _same(a: str) -> str:
    return " ".join(re.sub(r"[\W_]+", " ", a or "").split()).casefold()


def refused_findings(log, case_dir: str | None) -> tuple[list[dict], list[dict]]:
    """(open, withdrawn): the record_finding refusals of the trace that no
    later accepted finding covers and no later withdrawal names, and those
    withdrawn. Covered = every name (core.entities.names_in) of the
    sentences no gate objected to (of all its sentences when those name
    nothing) stands in a later accepted finding; computed from the trace on
    each read, nothing stored; no model word but a withdrawal with its
    reason clears one."""
    from core.entities import NamePool, names_in
    from core.indicators import _parsed_args
    from tools._gates.universal_from_truncated import split_sentences
    with log._lock:
        entries = list(log._entries)
    refusals: dict[str, dict] = {}
    findings: list[dict] = []
    withdrawals: dict[int, tuple[int, str]] = {}
    for e in entries:
        cmd = str(e.get("cmd") or "")
        if e.get("type") == "finding":
            findings.append(e)
        elif e.get("type") != "tool_call":
            continue
        elif e.get("refused_description") and cmd.endswith("record_finding"):
            # The same text refused again is one refusal: its latest.
            refusals[_same(str(e["refused_description"]))] = e
        elif cmd.endswith("claim_supersede") and e.get("success") is True:
            args = _parsed_args(e)[0]
            old = refusal_call_id(args.get("old_id")) if isinstance(args, dict) else None
            if old is not None and not str(args.get("new_id") or "").strip():
                withdrawals[old] = (int(e.get("call_id") or 0), str(args.get("reason") or "")[:300])
    lex: set[str] = set()
    try:
        from core.forensic_citation import known_case_hosts
        lex = {h.lower() for h in known_case_hosts(case_dir)} if case_dir else set()
    except Exception:  # noqa: BLE001
        lex = set()
    still, gone = [], []
    for r in sorted(refusals.values(), key=lambda x: int(x.get("call_id") or 0)):
        rid = int(r.get("call_id") or 0)
        desc = str(r["refused_description"])
        gates = [str(g) for g in r.get("refused_gates") or []]
        if not any(_content_gate(g) for g in gates):
            continue
        item = {"call_id": rid, "gates": gates, "description": desc,
                "grounding": any(_grounding_gate(g) for g in gates),
                "objected": [str(s) for s in r.get("objected_sentences") or []],
                "steps": [s for s in r.get("gate_steps") or [] if isinstance(s, dict)]}
        w = withdrawals.get(rid)
        if w and w[0] > rid:
            gone.append({**item, "withdrawn_by": w[0], "reason": w[1]})
            continue
        objected = {_same(s) for s in r.get("objected_sentences") or []}
        sentences = split_sentences(desc)
        names = set().union(*(names_in(s, lex) for s in sentences if _same(s) not in objected)) if sentences else set()
        if not names:
            names = names_in(desc, lex)
        # An abbreviation ("i.e.", "e.g.") has the inner-separator shape of a
        # name and names nothing.
        names = {n for n in names if not _ABBREVIATION_RE.fullmatch(n)}
        # ponytail: the cover pools every later accepted finding, so names
        # scattered over unrelated findings cover a refusal; the upgrade is to
        # count a finding toward the cover only when it shares two or more of
        # the refused names (pinned in tests/core/test_open_work_refused.py).
        later = [str(f.get("description") or "") for f in findings if int(f.get("call_id") or 0) > rid]
        pool = NamePool.from_texts(later)
        missing = sorted(n for n in names if not pool.covers(n))
        if later and not missing:
            continue
        still.append({**item, "missing": missing})
    return still, gone


REFUSED_HEAD = ("Findings refused and not recorded again come before the due reads; each stays listed until a "
                "finding records its content, or until claim.supersede(old_id=\"<call>\", reason=...) withdraws it "
                "with its reason:")


def refused_lines(refused: list[dict], *, limit: int = 6, chars: int = 200) -> list[str]:
    """One line per refused finding, those with the most names not yet on
    the record first: its call, the gates, its text (JSON-quoted and cut to
    ``chars`` with a middle ellipsis, as every evidence-derived text in a
    block Atlas writes, core.coverage_ledger.shown_name; the whole text stays
    on the refusal entry), its next step and every name not yet on the
    record."""
    lines = [REFUSED_HEAD] if refused else []
    refused = sorted(refused, key=lambda r: (-len(r.get("missing") or []), r["call_id"]))
    for r in refused[:limit]:
        from core.coverage_ledger import shown_name
        text = shown_name(" ".join(r["description"].split()), limit=chars)
        step = ("a value or a name in it is in no cited output: withdraw it, or read what shows it and record "
                "it again citing that read" if r["grounding"] else
                "record it again without the objected sentence, or with the count or evaluation the refusal named")
        missing = f"; not yet on the record: {', '.join(r['missing'])}" if r.get("missing") else ""
        lines.append(f"- call {r['call_id']} ({', '.join(r['gates']) or 'refused'}): {text}: {step}{missing}")
    if len(refused) > limit:
        lines.append(f"- +{len(refused) - limit} more refused findings")
    return lines


def refused_deferral(log, refused: list[dict]) -> str:
    """The finish deferral of one open refused finding not deferred on yet,
    the one with the most names not on the record first, or "". The
    deferral is recorded on the refusal's own trace entry (finish_deferred):
    each refused finding defers the finish once, before the open-work list,
    and the model cannot clear it except by recording or withdrawing. The
    state belongs to the finding's text: the same text refused again is not
    deferred on again (a reworded finding is a new one). The line quotes the
    objected sentences and what each other gate asked for, so it says what
    to change after the refusal itself has left the context."""
    with log._lock:
        done = {_same(str(e.get("refused_description") or "")) for e in log._entries
                if e.get("type") == "tool_call" and e.get("finish_deferred") and e.get("refused_description")}
    for r in sorted(refused, key=lambda r: (-len(r.get("missing") or []), r["call_id"])):
        entry = (log.index().by_call_id or {}).get(int(r["call_id"]))
        if not isinstance(entry, dict) or _same(r["description"]) in done:
            continue
        log.annotate_tool_call(int(r["call_id"]), finish_deferred=True)
        line = refused_lines([r])[1][2:]
        # The objected sentences and the gates' steps quote analyst and
        # evidence text: JSON-quoted with a middle ellipsis (shown_name), so a
        # quote mark or a sentence in them never reads as Atlas's own words,
        # and a long step keeps its tail (the cheaper alternative it offers).
        from core.coverage_ledger import shown_name
        said = ""
        if r.get("objected"):
            said += " Objected: " + "; ".join(shown_name(" ".join(s.split())) for s in r["objected"]) + "."
        if r.get("steps"):
            said += " Gates asked: " + " | ".join(
                f"[{s.get('gate')}] {shown_name(str(s.get('step') or ''))}" for s in r["steps"])
        return ("atlas_finish deferred for one refused finding (not a hard stop; atlas_finish called again goes "
                f"on): {line}.{said}")
    return ""


def parsed_deferral(log, parsed: list[dict], *, outputs: int = 6) -> str:
    """The finish deferral of the parsed outputs no row of which was looked
    at (parsed_outputs), one combined deferral naming each output with its
    query step, after the refused findings' own deferrals and before the
    open-work list; or "". It fires once per set of outputs: the outputs it
    named are recorded on the trace (``parsed_deferred`` on the latest tool
    call), so the same outputs again, or fewer, do not defer again, and a
    new output defers once more. Classes no output holds a row of (0 rows
    matched, or the output written over) have no query step and are left
    to the list."""
    from core.coverage_ledger import shown_name
    todo = [o for o in parsed if o.get("output") and not o.get("no_rows") and not o.get("overwritten")]
    if not todo:
        return ""
    with log._lock:
        done = {str(x) for e in log._entries if e.get("type") == "tool_call" for x in e.get("parsed_deferred") or []}
        anchor = next((e for e in reversed(log._entries) if e.get("type") == "tool_call" and e.get("call_id")), None)
    names = {o["output"] for o in todo}
    if anchor is None or names <= done:
        return ""
    log.annotate_tool_call(int(anchor["call_id"]),
                           parsed_deferred=sorted(names | {str(x) for x in anchor.get("parsed_deferred") or []}))
    lines = ["atlas_finish deferred for the parsed outputs no row of which was looked at (not a hard stop; "
             "atlas_finish called again goes on). Query each with table.table_query (path=<output>, a where= on "
             "the class's source) for what it can answer; a class stays open until a row of it is shown or it is "
             "left with its reason (coverage.set_evidence_disposition):"]
    for o in todo[:outputs]:
        more = f", +{len(o['classes']) - 8}" if len(o["classes"]) > 8 else ""
        filt = f" (parsed with {'; '.join(o['filters'][:2])} only)" if o.get("filters") else ""
        lines.append(f"- query {shown_name(o['output'])}: {len(o['classes'])} class(es){filt}: "
                     + ", ".join(o["classes"][:8]) + more)
    if len(todo) > outputs:
        lines.append(f"- +{len(todo) - outputs} more parsed outputs")
    return "\n".join(lines)


def refused_report_lines(log, case_dir: str | None) -> list[str]:
    """Evidence Gaps lines: each refused finding still open, and each one
    withdrawn with its reason."""
    still, gone = refused_findings(log, case_dir)
    out = [f"- Refused finding not recorded: call {r['call_id']} ({', '.join(r['gates'])}): "
           f"{' '.join(r['description'].split())[:300]}" for r in still]
    out += [f"- Refused finding withdrawn: refused at call {r['call_id']} ({', '.join(r['gates'])}), withdrawn by "
            f"call {r['withdrawn_by']}: {r['reason'] or 'no reason given'}" for r in gone]
    return out


def open_work(log, case_dir: str | None, *, derived: bool = True) -> dict[str, Any]:
    """What the run still owes, the one list the finish, the report gate and
    the director's open parts read: the open question parts
    (open_question_parts), the extracted outputs with a file class no call
    read (core.coverage_ledger.extracted_outputs; ``derived`` False leaves
    them out), the counted due reads and the refused findings not recorded
    again (refused_findings). Each source fails open."""
    try:
        parts = open_question_parts(case_dir)
    except Exception:  # noqa: BLE001
        parts = []
    outputs: list[dict] = []
    if derived and case_dir:
        try:
            from core.coverage_ledger import extracted_outputs
            outputs = [o for o in extracted_outputs(case_dir, readers=True) if o["open"]]
        except Exception:  # noqa: BLE001
            outputs = []
    try:
        due = counted_due(log, case_dir) if log is not None and case_dir else []
    except Exception:  # noqa: BLE001
        due = []
    try:
        refused = refused_findings(log, case_dir)[0] if log is not None else []
    except Exception:  # noqa: BLE001
        refused = []
    try:
        parsed = parsed_outputs(case_dir) if derived and case_dir else []
    except Exception:  # noqa: BLE001
        parsed = []
    try:
        classes = open_classes(case_dir) if case_dir else []
    except Exception:  # noqa: BLE001
        classes = []
    return {"parts": parts, "derived": outputs, "due": due, "refused": refused, "parsed": parsed,
            "classes": classes}


# ── the content classes with neither a read nor a reason ───────────────

def host_yield_order(case_dir: str | None, hosts: Iterable[str]) -> list[str]:
    """``hosts`` in the order the open questions and the brief name them
    (most named first), then the hosts the findings name, then the rest
    as given: the order the host-first view uses (core.contents_index),
    from the case's own texts, never a list of artefacts."""
    labels = list(dict.fromkeys(str(h) for h in hosts if h))
    if not case_dir or len(labels) < 2:
        return labels
    try:
        from core.contents_index import _claim_hosts, _mentions, _seed_texts
        questions, brief = _seed_texts(case_dir)
        in_q, in_b = _mentions(labels, questions), _mentions(labels, brief)
        claims = _claim_hosts(case_dir)
        named = {h.casefold(): n for h, n in claims.items()}
    except Exception:  # noqa: BLE001
        return labels
    return sorted(labels, key=lambda h: (-in_q[h], -in_b[h], -named.get(h.casefold(), 0), labels.index(h)))


def open_classes(case_dir: str | None) -> list[dict[str, Any]]:
    """One entry per class label with neither a read credited nor a reason,
    grouped over the hosts that hold it: {label, handle, hosts [(host,
    files, id)], score, readers, installed}, hosts in yield order and
    labels by the best yield: the host the open questions and the brief
    name first, then the class's artefact score (the index's own, format
    knowledge), a reader installed before none, fewer files first. Reads
    the ledger; the readers come from the class's member names
    (core.evidence_leave.unit_readers), never from an index query."""
    from core.coverage_ledger import load_ledger
    from core.evidence_disposition import undecided_classes
    from core.evidence_leave import label_handle, unit_readers
    ledger = load_ledger(case_dir)
    units = undecided_classes(ledger)
    if not units:
        return []
    from core.evidence_depth import unit_host
    items = ledger.get("items") or {}
    order = host_yield_order(case_dir, [unit_host(c, items) for c in units])
    rank = {h: i for i, h in enumerate(order)}
    try:
        from tools.tool_capabilities import _not_installed, is_installed
        gone = _not_installed()
    except Exception:  # noqa: BLE001
        gone, is_installed = set(), (lambda r, g=None: True)
    try:
        from core.evidence_depth import class_tiers
        tiers = class_tiers(case_dir, ledger)
    except Exception:  # noqa: BLE001
        tiers = {}
    groups: dict[str, dict[str, Any]] = {}
    readers_of: dict[str, tuple[list[str], bool]] = {}
    for c in units:
        label = str(c.get("label") or "")
        g = groups.setdefault(label, {"label": label, "handle": label_handle(label), "hosts": [], "score": 0,
                                      "readers": [], "installed": False, "known": True, "tier": "hard"})
        g["hosts"].append((unit_host(c, items), int(c.get("files") or 0), str(c.get("id")),
                           tiers.get(str(c.get("id")), "hard")))
        g["score"] = max(g["score"], int(c.get("score") or 0))
        if label not in readers_of:
            try:
                readers_of[label] = unit_readers(case_dir, "class", c, items.get(c.get("item")) or {})
            except Exception:  # noqa: BLE001
                readers_of[label] = ([], False)
        readers, known = readers_of[label]
        g["known"] = g["known"] and known
        if readers and not g["readers"]:
            g["readers"] = [r for r in readers if is_installed(r, gone)][:3] or readers[:3]
            g["installed"] = any(is_installed(r, gone) for r in readers)
    from core.evidence_depth import TIERS
    out = list(groups.values())
    for g in out:
        g["hosts"].sort(key=lambda h: (rank.get(h[0], len(rank)), h[1]))
        g["tier"] = min((h[3] for h in g["hosts"]), key=TIERS.index)
    # Hosts in scope first, then the cheap tier, then higher yield, a reader
    # installed, fewer files.
    out.sort(key=lambda g: (min(rank.get(h[0], len(rank)) for h in g["hosts"]), TIERS.index(g["tier"]),
                            -g["score"], not g["installed"], min(h[1] for h in g["hosts"]), g["label"]))
    return out


def open_class_keys(work: dict[str, Any]) -> frozenset:
    """The undecided classes by identity, apart from open_work_keys: the
    class guard reads them on its own step (agent.loop class_deferral)."""
    return frozenset(("class", h[2]) for g in work.get("classes") or [] for h in g["hosts"])


CLASS_HEAD = ("Content classes with neither a read nor a reason, by label (hosts in yield order with file counts, "
              "the cost tier, the reader): read one file of a class, or leave the label with an observation from a "
              "read on that host: coverage.set_evidence_disposition(unit=\"<label>\", state=\"left\", "
              "reason_kind=\"unlikely_to_help\", reason=\"<a fact the read showed on this host that makes the "
              "class unlikely to help>\", proof=[<call id of that read>]); hosts= names some hosts only; one call "
              "leaves the label on every host whose read it cites. A question being answered is never the reason. "
              "The run cannot end while one stands; ledger_status lists them all:")


def class_lines(work: dict[str, Any], *, limit: int = 12, chars: int = BLOCK_CHARS) -> list[str]:
    """The class block: one line per label, its hosts with file counts in
    yield order and the reader to use, cut at ``limit`` labels or ``chars``
    with the count of the rest."""
    from core.coverage_ledger import shown_name
    groups = work.get("classes") or []
    if not groups:
        return []
    lines = [CLASS_HEAD]
    used = len(CLASS_HEAD)
    shown = 0
    for g in groups:
        hosts = g["hosts"]
        where = ", ".join(f"{h or 'no host'} ({n})" for h, n, _i, _t in hosts[:4]) + (
            f", +{len(hosts) - 4} hosts" if len(hosts) > 4 else "")
        # No reader: the table declares none for a known format, or no
        # channel declares the format at all (the registry's gap, said so).
        reader = ((" reader: " + ", ".join(g["readers"][:2])) if g.get("readers") else
                  " reader: not declared" if g.get("known") is False else " reader: none registered")
        line = f"- {shown_name(g['handle'], quote=True)}: {where}; {g.get('tier', 'hard')};{reader}"
        if shown and used + len(line) > chars:
            break
        lines.append(line)
        used += len(line)
        shown += 1
        if shown >= limit:
            break
    rest = len(groups) - shown
    if rest > 0:
        lines.append(f"- +{rest} more labels on {len({h[0] for g in groups[shown:] for h in g['hosts']})} host(s); "
                     "coverage.ledger_status lists them")
    return lines


def class_count_line(work: dict[str, Any], case_dir: str | None = None) -> str:
    """One line with the undecided classes per host and the depth of
    analysis per host (core.evidence_depth), "" when none is undecided."""
    per: dict[str, int] = {}
    for g in work.get("classes") or []:
        for h, _n, _i, _t in g["hosts"]:
            per[h or "no host"] = per.get(h or "no host", 0) + 1
    if not per:
        return ""
    total = sum(per.values())
    depth = ""
    if case_dir:
        try:
            from core.evidence_depth import depth_by_host, depth_line
            depth = depth_line(depth_by_host(case_dir))
        except Exception:  # noqa: BLE001
            depth = ""
    return (f"[coverage] {total} content class(es) on {len(per)} host(s) have neither a read nor a reason ("
            + ", ".join(f"{h}: {n}" for h, n in list(per.items())[:8])
            + (f", +{len(per) - 8} hosts" if len(per) > 8 else "")
            + "); the run cannot end while one stands; coverage.ledger_status lists them."
            + (f" Depth per host (decided/total): {depth}." if depth else ""))


def parsed_outputs(case_dir: str | None) -> list[dict[str, Any]]:
    """The parser outputs whose rows nobody looked at, one per output file:
    {output, classes ["<host or item>: <class>"], filters}, from the
    disposition's ``parsed`` classes (core.evidence_disposition), largest
    first. Open work with its next step: query the output. Classes no output
    holds a row of are their own groups, never "query": those 0 rows matched
    the parse's filter (``no_rows``), and those parsed into an output a later
    parse wrote over (``overwritten``, its output named)."""
    from core.coverage_ledger import load_ledger
    ledger = load_ledger(case_dir) if case_dir else {}
    items = ledger.get("items") or {}
    by_out: dict[str, dict[str, Any]] = {}
    for c in (ledger.get("classes") or {}).values():
        if not isinstance(c, dict) or c.get("state") != "parsed":
            continue
        item = items.get(c.get("item")) or {}
        key = "" if c.get("no_rows") else (c.get("outputs") or ["?"])[0]
        if c.get("no_rows"):
            key = "\0" + "; ".join(c.get("parse_filters") or [])
        elif c.get("overwritten"):
            key = "\1" + c["overwritten"][0]
        o = by_out.setdefault(key, {"classes": [], "filters": set()})
        o["classes"].append(f"{item.get('host') or item.get('path') or c.get('item')}: {c.get('label')}")
        o["filters"].update(c.get("parse_filters") or [])
    return [{"output": "" if k.startswith("\0") else k.removeprefix("\1"), "no_rows": k.startswith("\0"),
             "overwritten": k.startswith("\1"), "classes": sorted(v["classes"]), "filters": sorted(v["filters"])}
            for k, v in sorted(by_out.items(), key=lambda kv: (-len(kv[1]["classes"]), kv[0]))]


PARSED_HEAD = ("Parsed outputs no row of which was looked at: query each with table.table_query (path=<output>, a "
               "where= on the class's source) for what it can answer; a class stays open until a row of it is "
               "shown or it is left with a reason:")


def open_work_keys(work: dict[str, Any]) -> frozenset:
    """The list's items by identity: a question part, an extracted output's
    class, a due item, a refused finding."""
    return frozenset([("part", str(t.get("id")), str(p.get("id") or "")) for t, ps in work["parts"] for p in ps]
                     + [("derived", o["path"], c) for o in work["derived"] for c in o["open"]]
                     + [("item", i.get("call_id")) for i in work["due"]]
                     + [("refused", r["call_id"]) for r in work.get("refused") or []]
                     + [("parsed", ("overwritten " if o.get("overwritten") else "")
                         + (o["output"] or "; ".join(o.get("filters") or [])), c)
                        for o in work.get("parsed") or [] for c in o["classes"]])


def _part_label(p: dict) -> str:
    from core.coverage_ledger import shown_name
    text = shown_name(" ".join(str(p.get("text") or "").split())[:60], quote=False)
    return " ".join(x for x in (str(p.get("id") or ""), text) if x) + (f" ({p['type']})" if p.get("type") else "")


# The next step each open part offers, the same for every reader: a read,
# or a limitation with its basis. No answer is invited here (a value bound
# at the finish fits the part no better than the reads behind it).
PART_HOW = ("read evidence for each, or limit one the evidence cannot answer with its basis "
            "(misc.update_investigation_task)")


def next_read(work: dict[str, Any]) -> tuple[str, str] | None:
    """The first file the open-work list names a read of, with the first
    installed reader the reader table gives for its class ("" when none):
    one action a small model can take as it stands."""
    for o in work.get("derived") or []:
        sample, readers = o.get("sample") or {}, o.get("readers") or {}
        for k in o.get("open") or []:
            if k in sample:
                names = [str(n) for n, _meta in readers.get(k) or []]
                return str(sample[k]), names[0] if names else ""
    return None


CLOSE_OUT_HEAD = "The report gate passed. Before the loop writes the reports, this work is still open."


def close_out_head(work: dict[str, Any]) -> str:
    """The head of the open work when the gate-ready close-out gives it: the
    one next read, by its path and reader, then the way out."""
    from core.coverage_ledger import shown_name
    nxt = next_read(work)
    if nxt is None:
        return (CLOSE_OUT_HEAD + " Act on it, or call atlas_finish to end the run now; the report states what "
                "stays open.")
    path, reader = nxt
    return (CLOSE_OUT_HEAD + f" Next: read {shown_name(path)}" + (f" with {reader}" if reader else "")
            + ". Then read the next file the list names, or call atlas_finish to end the run now; the report "
            "states what stays open.")


def open_work_lines(work: dict[str, Any], *, questions: int = 8, per_question: int = 6,
                    outputs: int = 6) -> list[str]:
    """The open parts and the extracted outputs' unread classes, at most
    ``questions`` x ``per_question`` parts and ``outputs`` folders, each cut
    saying how many more there are. Each line names its next step: a part a
    read or a limitation with its basis (never an answer), a class a read of
    one named file (core.coverage_ledger.EXTRACTED_OPEN_HEAD)."""
    from core.coverage_ledger import EXTRACTED_OPEN_HEAD, extracted_lines
    # A refused finding is listed first: it is the run's own result, lost
    # unless recorded or withdrawn, and a reader works a list from the top.
    lines: list[str] = refused_lines(work.get("refused") or [])
    if work["parts"]:
        lines.append(f"Question parts still open: {PART_HOW}; a part left open is stated as open in the report:")
        for t, ps in work["parts"][:questions]:
            more = f"; +{len(ps) - per_question} more parts" if len(ps) > per_question else ""
            lines.append(f"- {t.get('id')}: read evidence for "
                         + "; ".join(_part_label(p) for p in ps[:per_question]) + more)
        if len(work["parts"]) > questions:
            lines.append(f"- +{len(work['parts']) - questions} more questions")
    if work["derived"]:
        lines.append(EXTRACTED_OPEN_HEAD)
        lines += [f"- {ln}" for ln in extracted_lines(work["derived"][:outputs], only_open=True)]
        if len(work["derived"]) > outputs:
            lines.append(f"- +{len(work['derived']) - outputs} more extracted outputs")
    if work.get("parsed"):
        from core.coverage_ledger import shown_name
        queried = [o for o in work["parsed"] if not o.get("no_rows") and not o.get("overwritten")]
        if queried:
            lines.append(PARSED_HEAD)
        for o in queried[:outputs]:
            more = f", +{len(o['classes']) - 8}" if len(o["classes"]) > 8 else ""
            filt = f" (parsed with {'; '.join(o['filters'][:2])} only)" if o["filters"] else ""
            lines.append(f"- {shown_name(o['output'])}: {len(o['classes'])} class(es){filt}: "
                         + ", ".join(o["classes"][:8]) + more)
        if len(queried) > outputs:
            lines.append(f"- +{len(queried) - outputs} more parsed outputs")
        for o in [o for o in work["parsed"] if o.get("overwritten")][:outputs]:
            more = f", +{len(o['classes']) - 8}" if len(o["classes"]) > 8 else ""
            lines.append(f"Parsed into {shown_name(o['output'])}, which a later parse wrote over, for "
                         f"{len(o['classes'])} class(es) (" + ", ".join(o["classes"][:8]) + more + "): parse them "
                         "again into an output of their own (output_file), or leave each with that reason "
                         "(coverage.set_evidence_disposition)")
        for o in [o for o in work["parsed"] if o.get("no_rows")][:outputs]:
            more = f", +{len(o['classes']) - 8}" if len(o["classes"]) > 8 else ""
            lines.append(f"0 rows matched {'; '.join(o['filters'][:2]) or 'the parse'} for {len(o['classes'])} "
                         "class(es) (" + ", ".join(o["classes"][:8]) + more + "): parse without the filter, or "
                         "leave each with that reason (coverage.set_evidence_disposition)")
    if work.get("classes"):
        lines += class_lines(work)
    return lines


def open_work_summary(work: dict[str, Any], *, questions: int = 8, per_question: int = 6) -> str:
    """The report gate's one line on the list's parts and due reads, "" when
    neither is open."""
    bits: list[str] = []
    if work["parts"]:
        n = sum(len(ps) for _t, ps in work["parts"])
        ids = "; ".join(f"{t.get('id')} " + ", ".join(str(p.get("id") or "the question") for p in ps[:per_question])
                        + (f", +{len(ps) - per_question} more" if len(ps) > per_question else "")
                        for t, ps in work["parts"][:questions])
        if len(work["parts"]) > questions:
            ids += f"; +{len(work['parts']) - questions} more questions"
        bits.append(f"{n} question part(s) in {len(work['parts'])} question(s) ({ids})")
    if work["due"]:
        bits.append(f"{len(work['due'])} planned read(s) due, each listed as not read")
    if work.get("refused"):
        bits.append(f"{len(work['refused'])} refused finding(s) not recorded again (calls "
                    + ", ".join(str(r["call_id"]) for r in work["refused"][:8]) + "): record each again, or withdraw "
                    "it with claim.supersede(old_id=\"<call>\", reason=...)")
    if work.get("classes"):
        n = sum(len(g["hosts"]) for g in work["classes"])
        hosts = {h[0] for g in work["classes"] for h in g["hosts"]}
        cheap = sum(1 for g in work["classes"] for h in g["hosts"] if h[3] == "cheap")
        bits.append(f"{n} content class(es) on {len(hosts)} host(s) with neither a read nor a reason"
                    + (f", {cheap} of them cheap" if cheap else "") + ": read one file of each, or leave its "
                    "label with an observation from a read on that host (coverage.set_evidence_disposition); the "
                    "run cannot end while one stands")
    if not bits:
        return ""
    how = f" For the parts: {PART_HOW}." if work["parts"] else ""
    return "Open work, which the report states as open: " + "; ".join(bits) + "." + how


# ── the director (its prompt with the order appended) ───────────────────

def work_order_for_director(log, case_dir: str | None) -> str:
    """The order as the director sees it (appended to the gaps block):
    due items in the analyst's rank (up to 12), failed items newest first
    (up to 6), proposals by origin newest first (up to 12), each section
    ending with how many more there are."""
    moot_items(log, case_dir)
    tasks = _task_status(case_dir)
    with log._lock:
        items = [dict(e) for e in _log_items(log)]
    view = ""
    try:
        from core.contents_index import host_view, host_view_on
        if case_dir and host_view_on():
            view = host_view(case_dir)
    except Exception:  # noqa: BLE001
        view = ""
    if not items and not view:
        return ""
    due = [i for i in items if i.get("status") == "due"]
    for i in due:
        i["folded_into"], i["folded"] = None, []
    fold(due)
    resolved_tasks = {t for i in items if i.get("status") == "resolved" for t in i.get("task_ids") or []}
    ranked = _rank([i for i in due if counted(i, tasks)], tasks, resolved_tasks)
    failed = sorted((i for i in items if i.get("status") == "failed"), key=lambda i: -(i.get("call_id") or 0))
    order = {"series": 0, "blocker": 1, "index": 2, "director": 3, "reason": 4}
    # Within one origin newest first; the map's joins most specific first.
    proposed = sorted((i for i in items if i.get("status") == "proposed"),
                      key=lambda i: (order.get(i.get("origin"), 5),
                                     (i.get("source_ref") or {}).get("rarity", 0) if i.get("origin") == "join_hit" else 0,
                                     -(i.get("call_id") or 0)))

    def row(i: dict) -> str:
        return (f"- #{i['call_id']} {','.join(i.get('task_ids') or []) or '-'} {i.get('priority_tool') or i.get('tool')}"
                f" {i.get('args_summary') or ''}".rstrip())
    lines: list[str] = []
    if ranked:
        lines.append("WORK ORDER (due; id, question, tool, target, shown/attempts):")
        lines += [row(i) + f" (shown {i.get('presented', 0)}, attempts {len(i.get('attempts') or [])})"
                  for i in ranked[:12]]
        if len(ranked) > 12:
            lines.append(f"- {len(ranked) - 12} more due")
    if failed:
        lines.append("FAILED:")
        lines += [row(i) + (f" by call {i['basis_call_id']}" if i.get("basis_call_id") else "")
                  + f" ({str(i.get('outcome') or 'no output')[:80]})" for i in failed[:6]]
        if len(failed) > 6:
            lines.append(f"- {len(failed) - 6} more failed")
    if proposed or view:
        lines.append("PROPOSED (name a priority tool with host and path to adopt one; it then becomes due):")
        lines += [f"- #{i['call_id']} {i.get('origin')}: " + (str(i.get("why") or "")[:120] if not i.get("args_summary")
                  else f"{i.get('priority_tool') or i.get('tool')} {i.get('args_summary')}") for i in proposed[:12]]
        if len(proposed) > 12:
            lines.append(f"- {len(proposed) - 12} more proposed")
        if view:
            # The map: what is unread inside the images, host by host.
            lines.append(view)
    return "\n".join(lines)


def order_digest(log) -> list[str]:
    """Every open or failed item id with its status, for the standing
    assessment's signature: a changed order is never answered from it."""
    with log._lock:
        return sorted(f"{e['call_id']}:{e.get('status')}" for e in _log_items(log)
                      if e.get("status") in OPEN | {"failed"})


_PATH_SHAPED_RE = re.compile(r"[\w.$~-]*[\\/][^\s|,;\"']+|\b[\w.$~-]+\.[A-Za-z0-9]{1,5}\b")


NOT_TRACKED = ("no closable target (name the image path, or a host with one image, and the inner path); "
               "not tracked as work")


def parse_director_entries(data: dict, case_dir: str | None, refused: list[str] | None = None) -> list[dict]:
    """The director's output as items, without any artefact vocabulary:
    an entry that names a case host, a tool that reads content or searches
    a table and a path-shaped token is a due item with that target; a case
    file named without a host is a proposal with that target. A case whose
    links name no host takes a path-shaped token that is a case file as a
    due target. An entry that leaves no target a call can reach
    (has_target: a tool name alone, a host alone, a host whose image is
    not one) makes no item: an item no call closes would stay open for
    good. Such an entry is appended to ``refused`` as "<tool>: <NOT_TRACKED>"
    so the next review shows it; the tool name still reaches the analyst
    through the directives. A path the host's listing lacks makes no item
    either (an invented path)."""
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir) if case_dir else []
    raw: list[str] = []
    # The argument names each entry gives (a key of an entry written as an
    # object, or "name=value" / "name: value" in its text), by entry text.
    given: dict[str, set[str]] = {}
    holders = [data.get("directives") or {}, data] if isinstance(data, dict) else []
    for holder in holders:
        for entry in (holder.get("priority_tools") or []) if isinstance(holder, dict) else []:
            if isinstance(entry, dict):
                # The tool first, whatever key order the director wrote.
                tool = str(entry.get("tool") or entry.get("name") or "")
                rest = [str(v) for k, v in entry.items() if k not in ("tool", "name") and isinstance(v, (str, int))]
                raw.append(" | ".join([tool, *rest]) if tool else " | ".join(rest))
                given.setdefault(raw[-1], set()).update(str(k) for k in entry)
            elif isinstance(entry, str):
                raw.append(entry)
        if raw:
            break
    focus = [str(p) for p in (data.get("focus_paths") or (data.get("directives") or {}).get("focus_paths") or [])
             if isinstance(p, str)] if isinstance(data, dict) else []
    out: list[dict] = []
    for text in raw:
        tool = re.split(r"[\s|(]", text.strip(), maxsplit=1)[0]
        name = listed(tool)
        if not is_reading_tool(name):
            continue
        rest = text[len(tool):]
        host = next((h for h in hosts if host_mentioned(h, rest)), "")
        paths = [m.group(0).strip("`'\"()[]") for m in _PATH_SHAPED_RE.finditer(rest)]
        if not paths and len(raw) == 1:
            paths = [p for p in focus]
        tasks = re.findall(r"task-\d+", text)
        target: dict = {"host": host}
        # A path under an image's readable form (the device the image was
        # read through) is that image and the path inside it; the image
        # itself named as the inner path is no inner path.
        named_image = ""
        if case_dir:
            from core.evidence_identity import image_path
            kept = []
            for p in paths:
                hit = image_path(case_dir, p) if "::" not in p else None
                if hit:
                    named_image = named_image or hit[0]
                    if hit[1]:
                        kept.append(hit[1])
                    continue
                kept.append(p)
            paths = kept
        handle = next((p for p in paths if "::" in p), "")
        case_files = [p for p in paths if "::" not in p and case_dir and _is_case_file(case_dir, p)]
        inner = [p for p in paths if "::" not in p and p not in case_files]
        if handle:
            # An image handle names the image and the path inside it.
            parts = None
            try:
                from core.contents_index import handle_parts
                parts = handle_parts(case_dir, handle) if case_dir else None
            except Exception:  # noqa: BLE001
                parts = None
            image, _sep, within = handle.partition("::")
            image = image.split("@", 1)[0]
            # The image part is a case image (resolved by the index's image
            # list, or a case file), else a host label: never the path.
            img = (parts or {}).get("image") if (parts or {}).get("matched") else ""
            if not img and case_dir and _is_case_file(case_dir, image):
                img = image
            if not img:
                host = host or next((h for h in hosts if host_mentioned(h, image)), "")
                img = _host_image(case_dir, host) if host else ""
            if img:
                target["path"] = img
            target["inner_path"] = (parts or {}).get("inner_path") or within.strip("/")
            if img and not target["inner_path"]:
                found = _whole_image_input(case_dir, tool, img, refused)
                if found is None:
                    continue
                target["inner_path"] = found
            if (parts or {}).get("host"):
                host = host or parts["host"]
            target["host"] = host
        elif case_files:
            if _is_container(case_files[0]) and not inner:
                found = _whole_image_input(case_dir, tool, case_files[0], refused)
                if found is None:
                    continue
                inner = [found] if found else inner
            if _is_container(case_files[0]) and not inner:
                missing = _missing_arguments(name, text, given.get(text, set()))
                if missing:
                    if refused is not None:
                        refused.append(_needs(tool, missing, case_files[0]))
                    continue
            target["path"] = case_files[0]
            if _is_container(case_files[0]) and inner:
                # The image first, then the file inside it: both are kept,
                # when the image's listing holds the file (the host's, else
                # the image's own), as every planned read's must
                # (question_plan.check_reads); with no listing, as written.
                if case_dir:
                    try:
                        from core.contents_index import holds_path
                        if holds_path(case_dir, host, inner[0], image="" if host else case_files[0]) is False:
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                target["inner_path"] = inner[0]
        elif inner:
            # A path inside the host's image stands only when the host's
            # listing holds it, as every planned read's does
            # (question_plan.check_reads); with no listing indexed, or a
            # listing that is not complete, as written. A path a complete
            # listing lacks is refused with its reason (an invented one
            # would be due and never close).
            img = named_image or (_host_image(case_dir, host) if host else "")
            if (host or img) and case_dir:
                try:
                    from core.contents_index import holds_path
                    from core.evidence_identity import listing_complete
                    if holds_path(case_dir, host, inner[0], image="" if host else img) is False \
                            and img and listing_complete(case_dir, img):
                        if refused is not None:
                            refused.append(f"{tool}: '{inner[0]}' is not in the complete listing of {img}")
                        continue
                except Exception:  # noqa: BLE001
                    pass
            target["inner_path"] = inner[0]
            if img:
                target["path"] = img
        elif named_image:
            # The image alone: a reader of one declared file in it reads
            # that file, or nothing when the listing lacks it; a tool whose
            # schema requires an argument the entry does not give is
            # refused, naming it, never made image-wide (any call on the
            # image would close it).
            found = _whole_image_input(case_dir, tool, named_image, refused)
            if found is None:
                continue
            missing = [] if found else _missing_arguments(name, text, given.get(text, set()))
            if missing:
                if refused is not None:
                    refused.append(_needs(tool, missing, named_image))
                continue
            target["path"] = named_image
            if found:
                target["inner_path"] = found
        if not has_target(target):
            if refused is not None:
                refused.append(f"{tool}: {NOT_TRACKED}")
            continue
        # A case file named without a host, on a case whose links name
        # hosts, stays a proposal (adoptable by its fingerprint).
        status = "due" if host or (not hosts and target.get("path")) else "proposed"
        out.append({"origin": "director", "status": status, "tool": name, "target": target,
                    "task_ids": tasks, "why": text.strip()[:300]})
    return out


def _whole_image_input(case_dir: str | None, tool: str, image: str, refused: list[str] | None) -> str | None:
    """A director entry naming a whole image for a reader of one declared
    file in it (question_plan.image_input, as every planned read's): that
    file's inner path, "" when the entry stands as named, None when the
    image's complete listing holds no such file (the reason appended to
    ``refused``)."""
    if not case_dir:
        return ""
    from core.question_plan import image_input
    found, absent = image_input(case_dir, tool, image)
    if absent:
        if refused is not None:
            refused.append(f"{tool}: {absent}")
        return None
    return found


_GIVEN_ARG_RE = re.compile(r"\b([A-Za-z_]\w*)\s*[=:]")


def _missing_arguments(tool: str, text: str, given: set[str]) -> list[str]:
    """The required arguments of a tool's registered schema that a director
    entry naming the image alone does not give: the image fills the
    argument a ready call would put it in (the first of _FILE_PARAMS the
    tool takes, as ready_call places a target's path); where the tool writes (an
    output path, an output file name, a mount point) the call supplies
    itself; an argument the entry names ("name=value", or a key of an entry
    written as an object) is given. What is left is an object inside the
    image (an inode, a path in it) or what a scan searches for (its rules,
    its filters). Unknown tools miss nothing."""
    try:
        from core.paths import _OUTPUT_PARAM_NAMES, MOUNT_PARAM_NAMES, OUTPUT_NAME_PARAM_NAMES
        from tools.tool_capabilities import registered_tool_schemas
        written = set(_OUTPUT_PARAM_NAMES) | set(OUTPUT_NAME_PARAM_NAMES) | set(MOUNT_PARAM_NAMES)
        named = set(given) | set(_GIVEN_ARG_RE.findall(text))
        for name, schema, *_rest in registered_tool_schemas():
            if name == tool or name.endswith("_" + tool):
                need = [r for r in schema.get("required") or [] if r not in written]
                takes = set(schema.get("properties") or {}) | set(need)
                filled = next((c for c in _FILE_PARAMS if c in takes), None)
                return [r for r in need if r != filled and r not in named]
    except Exception:  # noqa: BLE001
        return []
    return []


def _needs(tool: str, missing: list[str], image: str) -> str:
    return f"{tool}: needs {', '.join(missing)}, which {image} alone does not give; name it in the entry"


def note_untracked_entries(log, call_id: int | None, texts: list[str]) -> bool:
    """Record the director entries its review made no item of with that
    review's own directives (``work_items_refused`` on the dair_call
    entry), the list the next review shows as refused at the last review.
    True when the entry was found."""
    from core.execution_log import _touched
    if not texts or not call_id:
        return False
    with log._lock:
        entry = next((e for e in log._entries if e.get("type") == "dair_call" and e.get("call_id") == call_id), None)
        if entry is None:
            return False
        directives = entry.get("directives")
        if not isinstance(directives, dict):
            directives = entry["directives"] = {}
        held = list(directives.get("work_items_refused") or [])
        directives["work_items_refused"] = held + [t for t in texts if t not in held]
        _touched(entry)
        log._index_version += 1
        log._flush()
    return True


def _is_case_file(case_dir: str, p: str) -> bool:
    import os
    root = os.path.realpath(str(case_dir))
    q = p if os.path.isabs(p) else os.path.join(root, p)
    return os.path.isfile(q) and os.path.realpath(q).startswith(root + os.sep)


def _host_image(case_dir: str | None, host: str) -> str:
    """The disk image the evidence ties to ``host``, case-relative: the one
    the Evidence Links tie to it, else the one whose path names it; "" when
    none or several."""
    if not case_dir or not host:
        return ""
    try:
        from core.coverage_ledger import load_ledger
        from core.forensic_citation import host_mentioned
        units = (load_ledger(case_dir).get("units") or {}).values()
        disks = [str(u.get("path")) for u in units if isinstance(u, dict) and _is_container(str(u.get("path") or ""))
                 and not _MEMORY_EXT_RE.search(str(u.get("path") or ""))]
        try:
            from core.evidence_links import host_for_image
            linked = [p for p in disks if (host_for_image(p, case_dir) or "").casefold() == host.casefold()]
        except Exception:  # noqa: BLE001
            linked = []
        if len(linked) == 1:
            return linked[0]
        from core.evidence_links import host_of_path, host_of_path_on
        if host_of_path_on():
            found = [p for p in disks if host_of_path(case_dir, p).casefold() == host.casefold()]
        else:
            found = [p for p in disks if host_mentioned(host, p)]
        return found[0] if len(found) == 1 else ""
    except Exception:  # noqa: BLE001
        return ""
