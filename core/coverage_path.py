"""The coverage path (convergence design 4.3): the evidence classes no
question reads (the triage's coverage and read-later classes) are not read
by the model one by one. In the background, beside the items:

1. each class's files are parsed by the first installed reader of the
   class's format (the readers table), through the toolbox like any call,
   and the current attacker values are swept over those outputs (the
   evidence index of saved outputs); no model;
2. one tool-less classification call per evidence item covers all its
   parsed classes: the case, the item's survey line, per class its parse
   summary and sweep hits; the reply says per class: it serves a question
   part, it holds an attacker hit to read, or nothing;
3. a class that serves a part or holds a hit becomes a read item (with the
   parts as its tasks); every other is credited "swept": parsed and swept
   for the attacker values known then, not read by the model, and
   disclosed so. A swept class whose outputs hold an attacker value found
   later is opened again as a read.

Its lane: one coverage pass at a time beside the items (a lane of one,
outside the analyst's calls), started only once the memory batch's first
pass is done (memory first: two heavy readers never share the case disk),
pausing before each parse while an item-thread call runs, its tool
processes at the lowest CPU priority; each parse's files and seconds are
logged, so the first run measures the lane's cost.

``ATLAS_COVERAGE_PATH`` switches it; off by default until that cost is
measured.
Its parses are stamped as coverage in the trace and earn no read credit; a
class is swept only for the files parsed, and only when every output was
searched whole; the run's end never waits for it.
"""
from __future__ import annotations

from core.store_lock import locked as _locked

import json
import os
import time
from typing import Any, Optional

# The wait between checks while an item-thread call runs.
PAUSE = 0.5
SWEPT_REASON = ("{n} of {m} file(s) parsed and swept for the attacker values known at {when}, not read by the "
                "model")


def coverage_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_COVERAGE_PATH", False)


def open_classes(log, ledger: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Per evidence item, its classes the coverage path takes: carried by a
    triage read item that serves no question (coverage) or was set to be
    read later, still unread, and not parsed yet."""
    wanted: set[str] = set()
    for e in log.work_items():
        ref = e.get("source_ref") or {}
        if e.get("origin") != "triage" or ref.get("kind") != "evidence":
            continue
        if e.get("status") == "proposed" or (e.get("status") == "due" and not e.get("task_ids")):
            wanted |= {str(c) for c in ref.get("classes") or []}
    out: dict[str, list[dict[str, Any]]] = {}
    for cid in sorted(wanted):
        c = (ledger.get("classes") or {}).get(cid)
        if isinstance(c, dict) and c.get("state") in ("pending", "relevant") and not c.get("coverage"):
            out.setdefault(str(c.get("item")), []).append(c)
    return out


def held(log, ledger: dict[str, Any]) -> set[int]:
    """The coverage read items the coverage path has not taken yet: not run
    as reads meanwhile (their classes get parsed and swept first)."""
    out = set()
    classes = ledger.get("classes") or {}
    for e in log.work_items():
        ref = e.get("source_ref") or {}
        if (e.get("origin") == "triage" and ref.get("kind") == "evidence" and e.get("status") == "due"
                and not e.get("task_ids") and any(isinstance(classes.get(c), dict) and not classes[c].get("coverage")
                                                  and classes[c].get("state") in ("pending", "relevant")
                                                  for c in ref.get("classes") or [])):
            out.add(int(e["call_id"]))
    return out


def single_input_reader(readers: list[str], registry: list[tuple]) -> tuple[str, str]:
    """``(reader, its input parameter)`` for the first of ``readers`` whose
    schema requires exactly one parameter, the one that names the file:
    a parse here carries the file and nothing else, so a reader that also
    requires an output folder or a key is skipped. The schema is found by
    the listed name, whatever spelling the reader came in. ("", "") when
    none qualifies."""
    from core.coverage_ledger import listed_tool_name
    schemas = {listed_tool_name(n): sc for n, sc, *_ in registry}
    for reader in readers:
        schema = schemas.get(listed_tool_name(reader)) or {}
        props = (schema.get("properties") or {})
        required = [p for p in (schema.get("required") or []) if p in props]
        if len(required) == 1 and (props.get(required[0]) or {}).get("type", "string") == "string":
            return reader, required[0]
    return "", ""


def parse_class(toolbox, case_dir, item: dict[str, Any], c: dict[str, Any]) -> dict[str, Any]:
    """Parse a class's files with its format's first installed reader that
    takes the file alone (single_input_reader):
    {"reader", "calls", "files", "rows", "error"}."""
    from core.call_memo import trace_call_id_of
    from core.contents_index import class_handles
    from core.evidence_leave import readers_for, unit_format
    from tools.tool_capabilities import _not_installed, is_installed, registered_tool_schemas
    fmt = unit_format(case_dir, "class", c, item)
    gone = _not_installed()
    readers = [r for r in readers_for(fmt) if is_installed(r, gone)]
    if not readers:
        return {"reader": "", "calls": [], "files": 0, "rows": 0, "error": f"no installed reader for {fmt or '?'}"}
    reader, param = single_input_reader(readers, registered_tool_schemas())
    if not reader:
        return {"reader": "", "calls": [], "files": 0, "rows": 0,
                "error": f"no single-input reader for {fmt or '?'} ({', '.join(readers[:4])} need more than the file)"}
    handles, total = class_handles(case_dir, str(item.get("host") or ""), str(c.get("label") or ""),
                                   limit=max(1, int(c.get("files") or 0)))
    from core.execution_log import call_source
    from core.memory_batch import foreground_busy
    calls, rows, errors, parsed = [], 0, [], 0
    started = time.monotonic()
    token = call_source.set("coverage")
    try:
        from core.executor import _STOP_EVENT
        for h in handles:
            while foreground_busy(case_dir) and not _STOP_EVENT.is_set():
                time.sleep(PAUSE)                         # the item thread's call first
            if _STOP_EVENT.is_set():
                break                                     # the run is stopping: no further parse
            text, _loaded = toolbox.call(reader, {param: h}, budget_free=True)
            cid = trace_call_id_of(text)
            failed = str(text).startswith("ERROR")
            try:
                data = json.loads(text[text.index("{"):text.rindex("}") + 1])
                for k in ("row_count", "rows_total", "count", "total"):
                    if isinstance(data.get(k), int):
                        rows += data[k]
                        break
                else:
                    rows += next((len(data[k]) for k in ("rows", "records", "hits", "results")
                                  if isinstance(data.get(k), list)), 0)
                if data.get("success") is False:
                    failed = True
                    errors.append(str(data.get("error") or "")[:120])
            except ValueError:
                pass
            if str(cid).isdigit() and not failed:
                calls.append(int(cid))
                parsed += 1
    finally:
        call_source.reset(token)
    return {"reader": reader, "calls": calls, "files": len(handles), "parsed": parsed, "of": total, "rows": rows,
            "error": "; ".join(errors[:3]), "seconds": round(time.monotonic() - started, 1)}


def _scan_file(path: str, wanted: list[str]) -> set[str]:
    """The values a file holds (case-insensitive), read in chunks with an
    overlap, so a value across a chunk border is found and no output is too
    large to search."""
    low = [w.lower() for w in wanted]
    keep = max(len(w) for w in low) - 1
    found: set[str] = set()
    tail = ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            text = tail + chunk.lower()
            found |= {w for w, lw in zip(wanted, low) if w not in found and lw in text}
            tail = text[-keep:] if keep > 0 else ""
    return found


def _outputs(text: str) -> tuple[list[str], bool]:
    """(the files a parse's result names that are not its evidence input,
    whether every output it names can be searched). Every string value of
    the result that is an existing path counts, whatever its field: a file
    outside the case's evidence is an output to search; a folder outside
    it with no named file inside is an output that cannot be searched; a
    result that opens as JSON but does not parse cannot be read whole."""
    body = text.strip()
    if not body.startswith("{"):
        return [], True
    try:
        data = json.loads(body)
    except ValueError:
        return [], False
    try:
        from core.paths import active_case_dir
        evidence = os.path.realpath(os.path.join(str(active_case_dir() or ""), "evidence"))
    except Exception:  # noqa: BLE001
        evidence = ""
    files: list[str] = []
    dirs: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and v.startswith("/") and len(v) < 4096 and os.path.exists(v):
            real = os.path.realpath(v)
            if evidence and (real == evidence or real.startswith(evidence + os.sep)):
                return                                    # the parse's input, read by the parse itself
            (files if os.path.isfile(real) else dirs).append(real)
    walk(data)
    files = list(dict.fromkeys(files))
    unsearched = [d for d in dirs if not any(f.startswith(d + os.sep) for f in files)]
    return files, not unsearched


def sweep_calls(values: list[str], calls: list[int]) -> tuple[list[str], bool]:
    """(the attacker values the full outputs of ``calls`` hold, whether
    every output was searched whole). A call's output is its saved full
    copy (or its text when that was never cut, shorter than the trace's
    excerpt) and every file its result names outside the evidence. An
    output that cannot be read whole leaves the sweep not whole."""
    wanted = [v for v in values if len(v) >= 3]
    if not wanted or not calls:
        return [], True
    try:
        from core.execution_log import TRACE_EXCERPT_CHARS, log
        by_id = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        return [], False
    found: set[str] = set()
    whole = True
    for cid in calls:
        e = by_id.get(int(cid))
        if not isinstance(e, dict):
            whole = False
            continue
        f = str(e.get("stdout_file") or "")
        excerpt = str(e.get("stdout_excerpt") or "")
        try:
            if f and os.path.isfile(f):
                found |= _scan_file(f, wanted)
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            elif e.get("truncated") or len(excerpt) >= TRACE_EXCERPT_CHARS:
                whole, text = False, ""
            else:
                found |= {v for v in wanted if v.lower() in excerpt.lower()}
                text = excerpt
            written, searchable = _outputs(text)
            whole = whole and searchable
            for out in written:
                found |= _scan_file(out, wanted)
        except OSError:
            whole = False
    return [v for v in values if v in found], whole


def classify_text(case_dir, item: dict[str, Any], survey: str, parsed: dict[str, dict]) -> str:
    """The classification call's message: the case, the item's survey line,
    per class its parse summary and its sweep hits, the question parts."""
    from core.evidence_triage import _part_lines
    from core.frontier_prompts import case_block
    lines = [case_block(case_dir), "", f"EVIDENCE ITEM {item.get('path')} ({item.get('host') or 'no host'})",
             survey[:1500], "", "ITS CLASSES, PARSED AND SWEPT (no model has read them):"]
    for label, p in parsed.items():
        lines.append(f"- {label}: {p.get('parsed', p['files'])} of {p.get('of', p['files'])} file(s) parsed by "
                     f"{p['reader'] or '-'}, "
                     f"{p['rows']} row(s); attacker values found: {', '.join(p['hits']) or 'none'}"
                     + (f"; errors: {p['error']}" if p.get("error") else ""))
    parts = _part_lines(case_dir)
    if parts:
        lines += ["", "QUESTION PARTS:", *parts]
    return "\n".join(x for x in lines if x is not None)


COVERAGE_SYS = (
    "You decide, for each content class of one evidence item, whether a model should read it. Code has parsed "
    "each class and searched the outputs for the attacker values known so far; no model has read them. Per "
    "class say serves (it can answer one of the question parts listed: name their ids), hit (the attacker "
    "values found in it need reading), or nothing (it can answer no listed part and holds no attacker value). "
    "A class you mark nothing is recorded as parsed and swept, not read, and opened again if a later attacker "
    "value is found in it. Call submit_coverage.")
COVERAGE_SUBMIT = {"type": "function", "function": {
    "name": "submit_coverage", "description": "Your decision per class.",
    "parameters": {"type": "object", "properties": {"classes": {"type": "array", "items": {
        "type": "object", "properties": {
            "label": {"type": "string"},
            "decision": {"type": "string", "enum": ["serves", "hit", "nothing"]},
            "serves": {"type": "array", "items": {"type": "string"}}},
        "required": ["label", "decision"]}}}, "required": ["classes"]}}}


@_locked
def apply(log, case_dir, item: dict[str, Any], parsed: dict[str, dict], reply: Optional[dict],
          values: list[str]) -> dict[str, list[str]]:
    """Record the classification: read items for classes that serve or hold
    a hit (a hit stands whatever the reply says), "swept" for the rest that
    had files parsed and every output searched whole. A class with no
    parsed file (no installed reader, every parse failed) or an output not
    searched whole stays pending, its carrying item left to be read."""
    from core.coverage_ledger import load_ledger, save_ledger
    from core.evidence_triage import _serving_tasks, _work_item
    tasks_of = _serving_tasks(case_dir)
    said = {str(d.get("label") or "").casefold(): d for d in (reply or {}).get("classes") or [] if isinstance(d, dict)}
    led = load_ledger(case_dir)
    by_label = {str(c.get("label")): c for c in (led.get("classes") or {}).values()
                if isinstance(c, dict) and c.get("item") == item["id"]}
    now = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    out: dict[str, list[str]] = {"read": [], "swept": [], "unparsed": []}
    reads: list[tuple[dict, list[str]]] = []
    taken: set[str] = set()
    for label, p in parsed.items():
        c = by_label.get(label)
        if c is None:
            continue
        d = said.get(label.casefold()) or {}
        tasks = tasks_of(d.get("serves")) if d.get("decision") == "serves" else []
        c["coverage"] = {"reader": p["reader"], "calls": p["calls"][:200], "files": p["files"],
                         "parsed": int(p.get("parsed") or 0), "rows": p["rows"], "values": sorted(values)[:400],
                         "at": now, "hits": p["hits"], "whole": bool(p.get("whole", True)),
                         "error": str(p.get("error") or "")[:300]}
        if p["hits"] or tasks or d.get("decision") == "hit":
            reads.append((c, tasks))
            out["read"].append(c["id"])
            taken.add(c["id"])
        elif int(p.get("parsed") or 0) and p.get("whole", True):
            c.update(state="swept", reason=SWEPT_REASON.format(n=p["parsed"], m=p.get("of") or p["files"], when=now))
            out["swept"].append(c["id"])
            taken.add(c["id"])
        else:
            out["unparsed"].append(c["id"])
    save_ledger(case_dir, led)
    # The coverage and read-later items that carried these classes are
    # taken over: the classes are swept or have read items of their own.
    from core.work_order import close_item
    mine = taken
    from core.frontier_queue import RUNNING
    for e in log.work_items():
        ref = e.get("source_ref") or {}
        if int(e.get("call_id") or 0) in RUNNING:
            continue                                     # an item run now is closed by its own run
        if (e.get("origin") == "triage" and ref.get("kind") == "evidence" and e.get("status") in ("due", "proposed")
                and (e.get("status") == "proposed" or not e.get("task_ids"))
                and set(ref.get("classes") or []) and set(ref.get("classes") or []) <= mine):
            close_item(log, e["call_id"], "resolved", "taken by the coverage path")
    for c, tasks in reads:
        _work_item(log, case_dir, item, [c], "due", f"coverage: read {c['label']}"
                   + (f" (attacker values found: {', '.join(c['coverage']['hits'][:4])})" if c["coverage"]["hits"]
                      else ""), tasks)
    return out


@_locked
def reopen_swept(log, case_dir, values: list[str]) -> list[str]:
    """A swept class whose parsed outputs hold an attacker value found since
    its sweep is opened again as a read; one whose outputs hold none
    acknowledges the values."""
    from core.coverage_ledger import load_ledger, save_ledger
    from core.evidence_triage import _work_item
    led = load_ledger(case_dir)
    opened, changed = [], False
    for c in (led.get("classes") or {}).values():
        if not isinstance(c, dict) or c.get("state") != "swept":
            continue
        cov = c.get("coverage") or {}
        new = [v for v in values if v not in set(cov.get("values") or [])]
        if not new:
            continue
        hits, whole = sweep_calls(new, list(cov.get("calls") or []))
        cov["values"] = sorted(set(cov.get("values") or []) | set(new))[:400]
        changed = True
        if hits or not whole:
            c.update(state="pending", reason=(f"reopened: the attacker value {hits[0]} is in its parsed output"
                                              if hits else "reopened: its parsed output could not be searched "
                                              "whole for a value found later"))
            c["reopened"] = int(c.get("reopened") or 0) + 1
            opened.append(c)
    if changed:
        save_ledger(case_dir, led)
    for c in opened:
        item = (led.get("items") or {}).get(c.get("item")) or {}
        if item:
            _work_item(log, case_dir, item, [c], "due", f"coverage: read {c['label']} ({c['reason']})")
    return [c["id"] for c in opened]


def run_pass(agent, case_dir, attacker_values: list[str]) -> dict[str, Any]:
    """One coverage pass over every evidence item with open classes:
    parse, sweep, one classification call each, record. Returns counts."""
    from agent.item_executor import ItemSpec, run_item
    from core.coverage_ledger import load_ledger
    from core.execution_log import log
    from core.evidence_survey import survey_item
    from core.memory_batch import pass1_running
    if pass1_running(case_dir):
        return {"waiting": "the memory batch's first pass"}
    reopened = reopen_swept(log, case_dir, attacker_values)
    ledger = load_ledger(case_dir)
    done = {"items": 0, "read": 0, "swept": 0, "reopened": len(reopened), "parses": []}
    for iid, classes in open_classes(log, ledger).items():
        item = (ledger.get("items") or {}).get(iid)
        if not isinstance(item, dict) or item.get("kind") != "image":
            continue                                     # memory classes are the memory batch's
        parsed: dict[str, dict] = {}
        for c in classes:
            p = parse_class(agent.toolbox, case_dir, item, c)
            p["hits"], p["whole"] = sweep_calls(attacker_values, p["calls"])
            parsed[str(c["label"])] = p
            # The lane's cost, per class: what the first run measures.
            done["parses"].append({"item": iid, "class": c["label"], "reader": p["reader"], "files": p["files"],
                                   "parsed": p.get("parsed", 0), "seconds": p.get("seconds", 0.0)})
        try:
            survey = str(survey_item(case_dir, ledger, item).get("text") or "")
        except Exception:  # noqa: BLE001
            survey = ""
        try:
            ran = run_item(agent, ItemSpec(kind="coverage", system=COVERAGE_SYS,
                                           user=classify_text(case_dir, item, survey, parsed), core_tools=[],
                                           submit=COVERAGE_SUBMIT), turn=getattr(agent, "_turn", 0))
            reply = ran.submit
        except Exception:  # noqa: BLE001 - without the call, hits are still read and the rest swept
            reply = None
        res = apply(log, case_dir, item, parsed, reply, attacker_values)
        done["items"] += 1
        done["read"] += len(res["read"])
        done["swept"] += len(res["swept"])
    return done
