"""Depth of analysis per host: the tiers of the evidence classes and how
many of each a host has decided.

A tier is a cost band from evidence properties, never a list of artefacts:
the calls it takes to read the class (one for a reader that takes a folder
or a list of files, one per file for a per-file reader: the reader's own
schema, capability wiring) times the median seconds that reader took in
this run (a default per call where it has not run yet); hard when no
installed reader takes it or every installed reader of it failed on its
item in this run; medium when no channel of the reader table declares its
format at all (nothing can be said to lack). The band edges are this
module's own constants: a cheap class is done in about one call, a medium
one in a few, a hard one needs a long parse, an extraction or a reader
Atlas does not have. The band is fixed when the class is first tiered
(stored on the class unit, never lowered later), so the list shown to a
small model does not reorder as timings arrive; a failure of every
installed reader on the class's item moves it to hard. Yield is apart: the class's artefact-value
score (core.artifact_value, Atlas's public format knowledge) and whether
an open question's scope touches the host; it orders the classes shown,
it never gates anything. A WMI repository or a few ETL files are cheap by
cost; their place in the order comes from their yield, which is where
lesser evidence differs from the quick wins.

Decided = read, partly read or left with a kind. The depth is stated
wherever the run is judged (the block header, the director's note, the
pre-report warning, the report, the Coverage tab, a host-wide question's
answer) and gates nothing: depth is stated, not forced.
"""
from __future__ import annotations

import os
import statistics
from typing import Any

TIERS = ("cheap", "medium", "hard")
# Band edges in estimated seconds of reading the whole class (files times
# the reader's median seconds per call): about one call's worth is cheap,
# a few calls medium, beyond that hard. Written here once, with the
# reasoning above; nothing else carries them.
CHEAP_SECONDS = 90.0
MEDIUM_SECONDS = 900.0
# A reader that has not run in this run yet: its cost per call is unknown
# and taken as this many seconds (an extraction plus a parse).
DEFAULT_SECONDS_PER_CALL = 8.0
DECIDED = ("read", "partial", "walked", "swept", "left", "parsed")


def reader_seconds(entries: list[dict] | None) -> dict[str, float]:
    """{listed reader name: median elapsed seconds} over the run's successful
    calls (core.execution_log entries)."""
    from core.coverage_ledger import _entry_tool, listed_tool_name
    by: dict[str, list[float]] = {}
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        secs = e.get("elapsed_seconds")
        if not secs:
            continue
        name = _entry_tool(e)
        if name:
            by.setdefault(listed_tool_name(name), []).append(float(secs))
    return {k: statistics.median(v) for k, v in by.items() if v}


def reader_takes_many(reader: str, tools: list | None = None) -> bool:
    """Whether a reader takes a folder or a list of files in one call (its
    schema's input parameter is an array, or names a folder)."""
    from core.coverage_ledger import listed_tool_name
    from tools.tool_capabilities import input_format_param, registered_tool_schemas
    tools = tools if tools is not None else registered_tool_schemas()
    want = listed_tool_name(reader)
    for entry in tools:
        if listed_tool_name(entry[0]) != want:
            continue
        schema = entry[1] or {}
        param = input_format_param(schema)
        prop = (schema.get("properties") or {}).get(param) or {}
        if str(prop.get("type") or "") == "array" or param.endswith(("_dir", "_folder", "_dirs")) \
                or "folder" in str(prop.get("description") or "").lower()[:80]:
            return True
        return False
    return False


def class_tier(files: int, readers: list[str], installed: bool, seconds: dict[str, float] | None = None,
               *, many: bool = False, failed: bool = False, known: bool = True) -> str:
    """The tier of a class from the calls its readers take and their cost:
    ``many`` when a reader takes the class in one call, ``failed`` when
    every installed reader of it failed on it in this run. ``known`` False:
    no channel of the reader table declares the class's format, so no
    reader can be said to lack: medium, never hard for want of one."""
    if failed:
        return "hard"
    if not readers:
        return "hard" if known else "medium"
    if not installed:
        return "hard"
    from core.coverage_ledger import listed_tool_name
    per_call = min((seconds or {}).get(listed_tool_name(r), DEFAULT_SECONDS_PER_CALL) for r in readers)
    calls = 1 if many else max(1, int(files or 0))
    cost = calls * per_call
    if cost <= CHEAP_SECONDS:
        return "cheap"
    if cost <= MEDIUM_SECONDS:
        return "medium"
    return "hard"


def failed_reads(case_dir, entries: list[dict] | None, items: dict[str, Any]) -> dict[str, set[str]]:
    """{item id: listed names of the readers that failed on it in this run}:
    a failed read attempt (core.coverage_ledger.failed_read_attempt) counts
    for the item whose path its command or arguments name, or whose host
    its paths belong to (core.evidence_links.host_of_path); never for
    another host's item, so one failed parse on one host moves no other
    host's class."""
    import json
    from core.coverage_ledger import _blob_paths, _entry_tool, failed_read_attempt, listed_tool_name
    from core.evidence_links import host_of_path
    out: dict[str, set[str]] = {}
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or not failed_read_attempt(e):
            continue
        name = _entry_tool(e)
        if not name:
            continue
        args = e.get("args")
        blob = str(e.get("cmd") or "") + " " + (args if isinstance(args, str) else
                                                 json.dumps(args, ensure_ascii=False, default=str) if args else "")
        low = blob.casefold()
        hosts = {str(host_of_path(case_dir, p) or "").casefold() for p in _blob_paths(blob)} - {""}
        for iid, it in (items or {}).items():
            if not isinstance(it, dict):
                continue
            base = str(it.get("path") or "").rsplit("/", 1)[-1].casefold()
            host = str(it.get("host") or "").casefold()
            if (base and base in low) or (host and host in hosts):
                out.setdefault(str(iid), set()).add(listed_tool_name(name))
    return out


# {case dir: (key, tiers)}: the last answer per case, keyed by the ledger's
# version, its stored bands and the trace's length, so the callers on the
# hot path (every load_tasks, the Coverage tab, the count line) pay once
# per change.
_TIER_CACHE: dict[str, tuple[tuple, dict[str, str]]] = {}


def class_tiers(case_dir, ledger: dict[str, Any] | None = None, *, store: bool = False) -> dict[str, str]:
    """{class id: tier} for every class of the ledger. The band stored on
    the class unit when it was first tiered is read first; readers are
    resolved (by member names, core.evidence_leave.unit_readers; the
    reader timings and the failed reads from the run's trace) only for a
    class without one, or one whose item gained a failed read. With
    ``store`` the computed bands are written onto the units (the credit
    pass does this under the store lock) and a class every installed reader
    of which failed on its item moves to hard; a band is never lowered. A
    ``store`` call never reads the cache."""
    from core.coverage_ledger import listed_tool_name, load_ledger
    ledger = ledger if ledger is not None else load_ledger(case_dir)
    classes = {str(cid): c for cid, c in (ledger.get("classes") or {}).items() if isinstance(c, dict)}
    items = ledger.get("items") or {}
    try:
        from core.execution_log import log
        with log._lock:
            entries = list(log._entries)
    except Exception:  # noqa: BLE001
        entries = []
    key = (str(ledger.get("updated_at") or ""), len(entries),
           tuple((cid, str(c.get("tier") or "")) for cid, c in classes.items()))
    cached = _TIER_CACHE.get(str(case_dir))
    if not store and cached and cached[0] == key:
        return dict(cached[1])
    failed = failed_reads(case_dir, entries, items)
    seconds: dict[str, float] | None = None
    env: dict[str, Any] = {}
    by_label: dict[str, tuple[list[str], list[str], bool, bool]] = {}

    def resolve(label: str, c: dict[str, Any]) -> tuple[list[str], list[str], bool, bool]:
        """(readers, installed readers, takes many, known) of a label, once."""
        if label in by_label:
            return by_label[label]
        if not env:
            try:
                from tools.tool_capabilities import _not_installed, is_installed, registered_tool_schemas
                env.update(gone=_not_installed(), tools=registered_tool_schemas(), is_installed=is_installed)
            except Exception:  # noqa: BLE001
                env.update(gone=set(), tools=[], is_installed=lambda r, g=None: True)
        from core.evidence_leave import unit_readers
        try:
            readers, known = unit_readers(case_dir, "class", c, items.get(c.get("item")) or {})
        except Exception:  # noqa: BLE001
            readers, known = [], False
        inst = [r for r in readers if env["is_installed"](r, env["gone"])]
        many = any(reader_takes_many(r, env["tools"]) for r in inst)
        by_label[label] = (readers, inst, many, known)
        return by_label[label]

    out: dict[str, str] = {}
    for cid, c in classes.items():
        label = str(c.get("label") or "")
        stored = str(c.get("tier") or "")
        item_failed = failed.get(str(c.get("item")), set())
        if stored in TIERS and not item_failed:
            tier = stored
        else:
            readers, inst, many, known = resolve(label, c)
            broke = bool(inst) and all(listed_tool_name(r) in item_failed for r in inst)
            if stored in TIERS:
                tier = "hard" if broke else stored
            elif (items.get(c.get("item")) or {}).get("kind") == "memory":
                tier = "cheap"
            else:
                if seconds is None:
                    seconds = reader_seconds(entries)
                tier = class_tier(int(c.get("files") or 0), inst or readers, bool(inst), seconds,
                                  many=many, failed=broke, known=known)
        if store and tier != stored:
            c["tier"] = tier
        out[cid] = tier
    if not store:
        _TIER_CACHE[str(case_dir)] = (key, dict(out))
    return out


def unit_host(unit: dict[str, Any], items: dict[str, Any] | None) -> str:
    """The name a class or item stands under wherever the depth is said:
    its host, else the item's own file name (an image or a file the
    Evidence Links tie to no host is named by itself, never "no host")."""
    host = str(unit.get("host") or "")
    if host:
        return host
    item = (items or {}).get(str(unit.get("item") or "")) if unit.get("level") == "class" else unit
    path = str((item or {}).get("path") or "")
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def item_labels(items: dict[str, Any] | None) -> dict[str, str]:
    """{item id: the name its units count under}: unit_host's name (the
    host, else the file name), except that two hostless items sharing a
    file name in different folders count under their relative paths."""
    items = items or {}
    names = {str(iid): unit_host(it, items) for iid, it in items.items() if isinstance(it, dict)}
    shared = {n for n in names.values() if n and list(names.values()).count(n) > 1}
    return {iid: (str(items[iid].get("path") or n) if n in shared and not items[iid].get("host") else n)
            for iid, n in names.items()}


def depth_by_host(case_dir, ledger: dict[str, Any] | None = None,
                  tiers: dict[str, str] | None = None) -> dict[str, dict[str, tuple[int, int]]]:
    """{host or item name: {tier: (decided, total)}} over the ledger's
    classes (item_labels names them). An item the index yields no class for
    (an image of files the class rules do not shape, a loose file) stands
    in the count by itself as one cheap class, decided with the item."""
    from core.coverage_ledger import load_ledger
    ledger = ledger if ledger is not None else load_ledger(case_dir)
    tiers = tiers if tiers is not None else class_tiers(case_dir, ledger)
    items = ledger.get("items") or {}
    labels = item_labels(items)
    out: dict[str, dict[str, list[int]]] = {}
    with_classes: set[str] = set()
    for cid, c in (ledger.get("classes") or {}).items():
        if not isinstance(c, dict):
            continue
        with_classes.add(str(c.get("item") or ""))
        tier = tiers.get(cid, "hard")
        slot = out.setdefault(labels.get(str(c.get("item") or ""), unit_host(c, items)),
                              {t: [0, 0] for t in TIERS})[tier]
        slot[1] += 1
        if c.get("state") in DECIDED:
            slot[0] += 1
    for iid, it in items.items():
        if not isinstance(it, dict) or str(iid) in with_classes:
            continue
        slot = out.setdefault(labels.get(str(iid), unit_host(it, items)), {t: [0, 0] for t in TIERS})["cheap"]
        slot[1] += 1
        if it.get("state") in DECIDED:
            slot[0] += 1
    return {h: {t: (v[0], v[1]) for t, v in d.items()} for h, d in out.items()}


def depth_line(depth: dict[str, dict[str, tuple[int, int]]], hosts: list[str] | None = None, limit: int = 8) -> str:
    """"host: cheap 6/6, medium 2/9, hard 0/5; ..." for the hosts given (all
    when None), "" when the ledger has no classes."""
    names = [h for h in (hosts if hosts is not None else list(depth)) if h in depth]
    bits = []
    for h in names[:limit]:
        d = depth[h]
        bits.append(f"{h or 'no host'}: " + ", ".join(f"{t} {d[t][0]}/{d[t][1]}" for t in TIERS if d[t][1]))
    if len(names) > limit:
        bits.append(f"+{len(names) - limit} hosts")
    return "; ".join(bits)


def depth_reached(depth: dict[str, dict[str, tuple[int, int]]], hosts: list[str], upto: str = "medium") -> bool:
    """Whether every host of ``hosts`` has its tiers up to ``upto`` decided
    (a host with no classes in the ledger counts as reached)."""
    want = TIERS[:TIERS.index(upto) + 1]
    for h in hosts:
        d = depth.get(h)
        if not d:
            continue
        if any(d[t][0] < d[t][1] for t in want):
            return False
    return True


def scope_hosts(case_dir, task: dict[str, Any]) -> list[str]:
    """The hosts a question's scope resolves to: the hosts its standard
    parts name, else every evidence host the ledger knows; minus the hosts
    an item leave placed outside the case (other_scope)."""
    from core.coverage_ledger import load_ledger
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    named = [str(p.get("host")) for p in parts if p.get("host")]
    ledger = load_ledger(case_dir)
    items = [i for i in (ledger.get("items") or {}).values() if isinstance(i, dict)]
    outside = {str(i.get("host") or "") for i in items if i.get("state") == "left" and i.get("reason_kind") == "other_scope"}
    hosts = named or sorted({str(i.get("host") or "") for i in items if i.get("host")})
    return [h for h in dict.fromkeys(hosts) if h and h not in outside]


def host_wide(case_dir, task: dict[str, Any]) -> bool:
    """A host-wide question, by structure: its parts carry no single named
    artefact, value or host of their own (no value or relation part of a
    typed value kind; a narrative, list or yes-no part does not bound a
    question), and its scope resolves to several hosts. Never by the
    question's wording."""
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    if not parts:
        return False
    for p in parts:
        if p.get("kind") in ("value", "relation") and str(p.get("type") or "") not in ("narrative", "yes_no", "list"):
            return False
        if p.get("kind") == "value" and p.get("host"):
            return False
    return len(scope_hosts(case_dir, task)) >= 2


def task_depth(case_dir, task: dict[str, Any]) -> tuple[bool, str]:
    """(reached, line) for a host-wide question: whether its scope's hosts
    have their cheap and medium tiers decided, and the depth line to print
    beside its answer. (True, "") for a question that is not host-wide."""
    if not host_wide(case_dir, task):
        return True, ""
    hosts = scope_hosts(case_dir, task)
    depth = depth_by_host(case_dir)
    return depth_reached(depth, hosts), depth_line(depth, hosts)
