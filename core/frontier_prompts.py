"""The frontier's model-read text: per item kind a constant
system text (so the provider caches it), the item text rendered from the
work item and the incident map, the kind's tool list and its submit schema.

Model-read, so live probes on both cell models check it. Nothing here
names an artefact, a log, an event id or a tool for a question: the system
texts say what an item is and what a submit must carry; the item text
carries the target, the map's state and the readers menu, which is derived
from the registry (tools.tool_capabilities.readers_block).

Each submit schema holds only the fields its kind uses (shorter schemas,
fewer errors at the small-model tier). The model never types map ids: an
entity is named by kind and value, a basis by call id and a verbatim
quote. Recording, task links and map writes are code's (agent.frontier).
"""
from __future__ import annotations

import re
from typing import Any

# The tools every reading item starts with: the table readers, the search of
# the files the images hold and the read of one such file by inode. Listed
# first and constant, so the cached prefix stands; picked readers follow.
READ_CORE = ["table.table_grep", "table.table_query", "table.table_pivot", "tsk.tsk_index_find", "tsk.tsk_icat"]
# Readers an item may swap in: MAX_READERS of them. Only the memory image's
# readers fold: its plugins (one per memory structure) take one place
# together, up to MAX_READER_TOOLS tools in all. A plain item stays at ten
# schemas with the core, the meta tool and the submit; a memory pass may
# reach thirteen.
MAX_READERS = 3
MAX_READER_TOOLS = 6
USE_READERS = "item_use_readers"
KINDS = ("host_pass", "join_hit", "view_row_opened", "plan", "followup", "synthesis")

_COMMON = (
    "You work one item of a digital-forensics investigation: a short task with its own tools. Read what the item "
    "needs, then call {submit} once to end it. You record nothing yourself: code records what your submit "
    "carries, after the same checks every finding passes.\n"
    "Every finding, label, event and observation carries a basis: the call id of a tool call and a short quote "
    "copied exactly from that call's output; for a numbered row (\"#n ...\"), the quote starts with its #n and "
    "holds a value only that row shows. Cite only calls named in the item or made in it. A quote that is not "
    "in the call's output drops that basis. Name an entity by its kind (host, account, file, endpoint) and its "
    "value as the evidence writes it. Label attacker only what the evidence ties to the intrusion, benign what it "
    "shows to be normal, unknown when it does not settle. The brief tells what the user knows; it is not evidence. "
    "An account or host the brief calls the organisation's can still be used by the attacker: judge each action's "
    "side from its own rows. Label such an account or host attacker with attacker_from at the attacker's first "
    "action with it (its earlier activity stays the organisation's), label the action's other entities by their "
    "own rows, and record it as a finding; a label that disagrees with the brief is kept beside the brief's "
    "statement, never refused. For an event, you say which side is the source and "
    "which the destination; code never guesses a direction. Times are UTC as the evidence states them.\n"
    "When the tools listed cannot read a format, the item lists readers by format: call {use_readers} with up to "
    "{max_readers} of them (the memory image's plugins count as one, {max_tools} tools in all); they replace "
    "the readers added before.\n"
    "State only what the cited rows show, one observation per finding.\n"
    "If the item shows nothing new, say what you examined in `examined` and submit; an empty item is a result.")

_SYS = {
    "host_pass": (
        "This item is one host's pass. Work in this order. First, how the attacker reached this host: the inbound "
        "connection, logon or transfer, or a row showing where the access came from; this is `arrival`, and the "
        "submit requires it, as an anchor (a statement with its time and basis, recorded as a finding with the "
        "same checks) or as the calls that found none. Then what was done "
        "on the host after the arrival, what was left there, and the connections out of it. Activity earlier "
        "than the arrival is argued from its own evidence, never assumed to be the attacker's."),
    "join_hit": (
        "This item is a host already passed on which attacker values have since been seen. Read the rows that "
        "hold them on this host and label what they show; record a finding when the rows show an action."),
    "view_row_opened": (
        "This item is one open row of a question's view. A value you find for the row is submitted as a finding "
        "(the statement with the value, its basis, the entities it names): that finding is what fills the row's "
        "cells. Use `examined` only when you looked and the evidence holds nothing for the row; a value you saw "
        "and did not submit as a finding leaves the row open. Fill the open rows from the evidence. Declare a "
        "corrected view in `view` only when this one asks for the wrong kind of row or the wrong columns for the "
        "question: a view narrowed by a label not yet written leaves no row to fill."),
    "plan": (
        "This item is one planned read for a question. Run the read named in the item, or a narrower one "
        "of the same source, and report what it shows."),
    "followup": (
        "This item follows a note code raised on earlier work: a contradiction, a refusal, an activity before "
        "a host's start, or work an earlier item left. Do what the note asks and report what the evidence says, "
        "including when it confirms the earlier reading."),
    "synthesis": (
        "This item reads the whole incident map at once. You have no tools: name what the separate items "
        "could not see. Two labels or events that cannot both hold go into `contradictions`. A read that would "
        "close a gap goes into `proposals`, each with its target: the host and the source or search terms. A "
        "proposal without a target is dropped. You write no narrative."),
}

_BASIS = {"type": "array", "description": "the calls this rests on, each with a quote copied from its output",
          "items": {"type": "object", "properties": {
              "call_id": {"type": "integer"},
              "quote": {"type": "string", "description": (
                  "a short exact excerpt of that call's output; for a numbered row, its #n first, then a "
                  "value only that row shows")}},
              "required": ["call_id", "quote"]}}
_REF = {"type": "object", "description": "an entity by kind and value",
        "properties": {"kind": {"type": "string", "enum": ["host", "account", "file", "endpoint"]},
                       "value": {"type": "string"}, "host": {"type": "string"}},
        "required": ["kind", "value"]}
_FIELDS: dict[str, dict[str, Any]] = {
    "findings": {"type": "array", "description": "what the evidence shows, one statement each", "items": {
        "type": "object", "properties": {
            "statement": {"type": "string"}, "host": {"type": "string"},
            "confidence": {"type": "string", "enum": ["confirmed", "likely", "possible"], "description": (
                "confirmed: every cited row shows the whole statement, and an evaluator must support it; likely: "
                "the rows show it but one kind of record is read as a stronger fact (a file present read as "
                "run); possible: the rows suggest it")},
            "time": {"type": "string"}, "basis": _BASIS,
            "entities": {"type": "array", "items": _REF, "description": "the entities the statement names"},
            "bears_on": {"type": "array", "items": {"type": "string"}, "description": (
                "what the finding serves: a question part by its id (task-0001/p1), which the finding is then "
                "linked to and must answer (a question id alone names no part), or an attacker value already "
                "labelled that the finding itself names; "
                "leave it empty only when the finding's own entities include one you label attacker. A finding "
                "that serves none is kept as an observation, not a finding")}},
        "required": ["statement", "basis", "bears_on"]}},
    "labels": {"type": "array", "description": "a label per entity the evidence settles", "items": {
        "type": "object", "properties": {
            "ref": _REF, "label": {"type": "string", "enum": ["attacker", "benign", "unknown"]},
            "attacker_from": {"type": "string", "description": "for a host or account: when the attacker first "
                                                               "acted on it (the time of that first row)"},
            "basis": _BASIS, "why": {"type": "string"}},
        "required": ["ref", "label", "basis"]}},
    "events": {"type": "array", "description": "actions with a time on a host", "items": {
        "type": "object", "properties": {
            "host": {"type": "string"}, "time": {"type": "string"},
            "kind": {"type": "string", "enum": ["logon", "process", "file_write", "file_delete", "connection",
                                                "persistence", "access", "other"]},
            "verb": {"type": "string", "description": "your own word for the action"},
            "actor": _REF, "object": _REF, "src": _REF, "dst": _REF, "basis": _BASIS},
        "required": ["host", "time", "kind", "basis"]}},
    "observations": {"type": "array", "description": "facts worth keeping that are not findings", "items": {
        "type": "object", "properties": {"text": {"type": "string"}, "host": {"type": "string"},
                                         "time": {"type": "string"}, "basis": _BASIS},
        "required": ["text", "basis"]}},
    "leads": {"type": "array", "description": "reads another item should run", "items": {
        "type": "object", "properties": {
            "tool": {"type": "string"}, "host": {"type": "string"},
            "source": {"type": "string", "description": "the file or table to read"},
            "pattern": {"type": "string", "description": "search terms, for a search"},
            "why": {"type": "string"}},
        "required": ["tool", "why"]}},
    "view": {"type": "object", "description": (
        "a corrected view of this row's question part: what its answer ranges over and which columns it "
        "shows; code fills the rows"), "properties": {
        "over": {"type": "string", "description": "host, account, file, endpoint, or event:<event kind>"},
        "where": {"type": "object", "properties": {
            "label": {"type": "string", "enum": ["attacker", "benign", "unknown"]}, "host": {"type": "string"},
            "after": {"type": "string"}, "before": {"type": "string"}}},
        "columns": {"type": "array", "items": {"type": "string"}}},
        "required": ["over"]},
    "examined": {"type": "object", "description": "the calls you made and what they showed", "properties": {
        "call_ids": {"type": "array", "items": {"type": "integer"}}, "why": {"type": "string"}}},
    "arrival": {"type": "object", "description": (
        "how the attacker reached this host: `anchor` with a statement of what shows the arrival, the inbound "
        "event or the time the attacker first acted here (attacker_from), and its basis, recorded as a finding; "
        "or `examined` with the calls that found none"), "properties": {
        "anchor": {"type": "object", "properties": {
            "statement": {"type": "string", "description": "what the evidence shows about the arrival, one "
                                                            "sentence with the time"},
            "confidence": {"type": "string", "enum": ["confirmed", "likely", "possible"]},
            "event": {"type": "object", "properties": {
                "time": {"type": "string"},
                "kind": {"type": "string", "enum": ["logon", "connection", "access", "other"]},
                "src": _REF, "dst": _REF, "actor": _REF}},
            "attacker_from": {"type": "string"}, "basis": _BASIS}, "required": ["statement", "confidence", "basis"]},
        "examined": {"type": "object", "properties": {
            "call_ids": {"type": "array", "items": {"type": "integer"}}, "why": {"type": "string"}}}}},
    "proposals": {"type": "array", "description": "reads that would close a gap, each with a target", "items": {
        "type": "object", "properties": {
            "tool": {"type": "string", "description": "one of the item's READING TOOLS, by its name there"},
            "host": {"type": "string"},
            "source": {"type": "string", "description": "a file or handle on the host, or one of its CONTENT "
                                                        "CLASSES"},
            "pattern": {"type": "string"}, "why": {"type": "string"}},
        "required": ["tool", "host", "why"]}},
    "contradictions": {"type": "array", "description": "pairs that cannot both hold", "items": {
        "type": "object", "properties": {"text": {"type": "string"}, "host": {"type": "string"}},
        "required": ["text"]}},
}
SUBMIT_FIELDS = {
    "host_pass": ("arrival", "findings", "labels", "events", "observations", "leads", "examined"),
    "join_hit": ("findings", "labels", "examined"),
    "view_row_opened": ("findings", "labels", "events", "observations", "leads", "view", "examined"),
    "plan": ("findings", "labels", "events", "observations", "leads", "examined"),
    "followup": ("findings", "labels", "events", "observations", "leads", "examined"),
    "synthesis": ("proposals", "contradictions"),
}
_REQUIRED = {"host_pass": ["arrival"]}


BRIEF_SYS = (
    "You read a case brief before any evidence is read. List the entities the brief itself names (hosts, "
    "accounts, files, network addresses) whose side it states: attacker for what it says the attacker used, "
    "brought or controlled; benign for what it says belongs to the responders, the administrators' routine work, "
    "or a known false positive. Give each with the brief's sentence its side rests on, copied exactly. Leave out "
    "every entity whose side the brief does not state, and add nothing the brief does not name. Then call "
    "submit_brief.")
BRIEF_SUBMIT = {"type": "function", "function": {
    "name": "submit_brief", "description": "The entities the brief names, with their stated side.",
    "parameters": {"type": "object", "properties": {"entities": {"type": "array", "items": {
        "type": "object", "properties": {
            "kind": {"type": "string", "enum": ["host", "account", "file", "endpoint"]},
            "value": {"type": "string"}, "side": {"type": "string", "enum": ["attacker", "benign"]},
            "sentence": {"type": "string", "description": "the brief's sentence, copied exactly"}},
        "required": ["kind", "value", "side", "sentence"]}}}, "required": ["entities"]}}}


def submit_name(kind: str) -> str:
    return f"submit_{kind}"


def submit_schema(kind: str) -> dict[str, Any]:
    """The kind's submit tool: only the fields it uses."""
    params: dict[str, Any] = {"type": "object",
                              "properties": {f: _FIELDS[f] for f in SUBMIT_FIELDS[kind]}}
    if kind != "synthesis":
        params["properties"]["partial"] = {
            "type": "boolean", "description": "true to record what you have now and go on with the item"}
    if kind in _REQUIRED:
        params["required"] = list(_REQUIRED[kind])
    return {"type": "function", "function": {
        "name": submit_name(kind), "description": "End this item with what it found.", "parameters": params}}


USE_READERS_SCHEMA = {"type": "function", "function": {
    "name": USE_READERS,
    "description": (f"Add up to {MAX_READERS} readers from the item's readers-by-format lines to your tools "
                    f"(the memory image's plugins count as one; {MAX_READER_TOOLS} tools in all)."),
    "parameters": {"type": "object", "properties": {
        "names": {"type": "array", "items": {"type": "string"}, "description": "reader tool names"}},
        "required": ["names"]}}}


def system_text(kind: str) -> str:
    common = _COMMON.format(submit=submit_name(kind), use_readers=USE_READERS, max_readers=MAX_READERS,
                            max_tools=MAX_READER_TOOLS)
    if kind == "synthesis":
        common = common.split("\nWhen the tools listed")[0]
    return common + "\n\n" + _SYS[kind]


def core_tools(kind: str) -> list[str]:
    return [] if kind == "synthesis" else list(READ_CORE)


def memory_reader_names() -> set[str]:
    """The memory image's readers (its plugins), the only readers that fold."""
    try:
        from tools.tool_capabilities import MEMORY_FORMAT, readers_by_format, registered_tool_schemas
        return set(readers_by_format(registered_tool_schemas()).get(MEMORY_FORMAT) or [])
    except Exception:  # noqa: BLE001
        return set()


def pick_readers(names: Any, menu: set[str], folded: set[str] | None = None) -> tuple[list[str], str]:
    """The readers an item_use_readers call adds (known reading tools in
    the given order, at most MAX_READERS places, where the readers in
    ``folded`` (default: the memory image's plugins) share one place per
    namespace, and MAX_READER_TOOLS tools in all) and the reply."""
    folded = memory_reader_names() if folded is None else folded
    asked = [str(n) for n in (names if isinstance(names, list) else [names]) if str(n or "").strip()]
    known = [n for n in dict.fromkeys(asked) if n in menu]

    def place(n: str) -> str:
        return "ns:" + re.split(r"[._]", n, maxsplit=1)[0] if n in folded else n
    picked: list[str] = []
    for n in known:
        if len({place(p) for p in picked + [n]}) <= MAX_READERS and len(picked) < MAX_READER_TOOLS:
            picked.append(n)
    unknown = [n for n in asked if n not in menu]
    reply = (f"added: {', '.join(picked)}" if picked else "added none")
    if unknown:
        reply += f"; not readers of this run: {', '.join(unknown[:6])}"
    if len(picked) < len(known):
        reply += (f"; at most {MAX_READERS} readers per item (the memory image's plugins count as one), "
                  f"{MAX_READER_TOOLS} tools in all")
    return picked, reply


def reader_names() -> list[str]:
    """The readers item_use_readers may add: every tool of the readers menu
    (the same table readers_block prints) and the plain-text readers, never
    another tool."""
    try:
        from tools.tool_capabilities import readers_by_format, registered_tool_schemas, text_readers
        return sorted({n for names in readers_by_format(registered_tool_schemas()).values() for n in names}
                      | set(text_readers()))
    except Exception:  # noqa: BLE001
        return []


def _host_lines(case_dir, host: str) -> list[str]:
    out: list[str] = []
    try:
        from core.contents_index import listing_digest
        lines = listing_digest(case_dir, hosts=[host]).get("lines") or []
        if lines:
            out += ["WHAT THE HOST'S IMAGE HOLDS (structure only):", *[str(x) for x in lines]]
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.evidence_leave import _host_exports
        ex = _host_exports(case_dir, host)
        if ex:
            out += ["TABLES OF THE HOST:", *[f"- {e}" for e in ex[:40]]]
            if len(ex) > 40:
                out.append(f"- and {len(ex) - 40} more (table_query lists them)")
    except Exception:  # noqa: BLE001
        pass
    return out


def _entity_values(m, ids: list[int]) -> list[str]:
    try:
        by_id = {e["entity_id"]: e for e in m.attacker_entities(proposals=True)}
    except Exception:  # noqa: BLE001
        return []
    return [f"{by_id[i]['kind']} {by_id[i]['value']}" for i in ids if i in by_id]


def _task_part(case_dir, task_id: str, part_id: str) -> tuple[str, str]:
    try:
        from core.investigation_tasks import load_tasks
        for t in load_tasks(case_dir).get("tasks") or []:
            if str(t.get("id")) == str(task_id):
                part = next((p for p in t.get("parts") or [] if isinstance(p, dict)
                             and str(p.get("id")) == str(part_id)), {})
                return str(t.get("text") or ""), str(part.get("text") or "")
    except Exception:  # noqa: BLE001
        pass
    return "", ""


def _view_lines(case_dir, m, ref: dict[str, Any]) -> list[str]:
    try:
        v = next((v for v in m.views() if v["view_id"] == ref.get("view_id")), None)
    except Exception:  # noqa: BLE001
        v = None
    if not v:
        return []
    keys = [str(k) for k in ref.get("rows") or []] or [str(ref.get("row_key"))]
    cols = (v.get("spec") or {}).get("columns") or []
    q, part = _task_part(case_dir, str(v["task_id"]), str(v["part_id"]))
    lines = [f"QUESTION {v['task_id']}: {q}", f"PART {v['part_id']}: {part}",
             f"OPEN ROWS ({len(keys)}): {', '.join(keys)}",
             "A value found for a row goes in findings; examined is for rows where nothing was found."]
    if cols:
        lines.append(f"COLUMNS: {', '.join(str(c) for c in cols)}")
    for row in v.get("rows") or []:
        if str(row.get("row_key")) not in keys:
            continue
        # An open cell carries the word "open" (or "proposed") as its value:
        # only a cell that is not open is filled.
        filled = {k: c for k, c in (row.get("cells") or {}).items()
                  if isinstance(c, dict) and c.get("value") and not c.get("open")}
        if filled:
            lines.append(f"ROW {row.get('row_key')}, CELLS ALREADY FILLED: "
                         + "; ".join(f"{k} = {c['value']}" for k, c in filled.items()))
    return lines + _row_source_lines(case_dir, m, v, keys)


# How many source lines a view item lists (a display bound, with the count
# it leaves out, as the host pass's table list).
VIEW_SOURCE_LINES = 40


def _row_source_lines(case_dir, m, v: dict[str, Any], keys: list[str]) -> list[str]:
    """Where the open rows' evidence is (structure only): the exports that
    hold rows of the rows' hosts, the widest first, and the exports the
    index ties to no host."""
    try:
        from core.evidence_leave import exports_of_hosts, unattributed_exports
        by_row = m.row_hosts(v["view_id"], keys)
        hosts = sorted({h for hs in by_row.values() for h in hs})
        found = exports_of_hosts(case_dir, hosts)
        loose = [e for e in unattributed_exports(case_dir) if e not in {x for x, _n in found}]
    except Exception:  # noqa: BLE001
        return []
    if not found and not loose:
        return []
    out = ["SOURCES FOR THESE ROWS (structure only; the tables that hold rows of the rows' hosts):"]
    out += [f"- {e} ({n} of the {len(hosts)} rows' hosts)" for e, n in found[:VIEW_SOURCE_LINES]]
    if len(found) > VIEW_SOURCE_LINES:
        out.append(f"- and {len(found) - VIEW_SOURCE_LINES} more (table_query lists them)")
    if loose:
        room = max(5, VIEW_SOURCE_LINES - len(found))
        out.append("- tables with no host attributed (estate-wide or unknown): " + ", ".join(loose[:room])
                   + (f", and {len(loose) - room} more" if len(loose) > room else ""))
    unplaced = sum(1 for k in keys if not by_row.get(k))
    if unplaced:
        out.append(f"- {unplaced} of the {len(keys)} open rows stand on no host the map knows")
    return out


def case_block(case_dir, budget: int | None = None, rest: int = 0) -> str:
    """CASE.md as the user wrote it, the first part of every item's and
    every triage call's message (a fixed block per run, so it stays in the
    cached prefix). Whole whenever it fits beside the message's ``rest``
    characters and the room an item's later rounds take (its digest share
    and as much again for its last round and note); only a brief that does
    not fit is shortened: its sections in order, each to its share, named,
    and never a section that holds a question."""
    try:
        from core.investigation_tasks import read_case_markdown
        text = read_case_markdown(case_dir).strip()
    except Exception:  # noqa: BLE001
        text = ""
    if not text:
        return ""
    if budget is None:
        try:
            from agent.item_executor import DIGEST_SHARE
            from agent.loop import context_char_budget
            window = context_char_budget()
            budget = max(2000, int(window * (1 - 2 * DIGEST_SHARE)) - int(rest))
        except Exception:  # noqa: BLE001
            budget = 12000
    head = "THE CASE (the brief as the user wrote it):"
    if len(text) <= budget:
        return f"{head}\n{text}"
    try:
        from core.investigation_tasks import parse_case_request_items
        asks = [str(r.get("first_line") or "").strip() for r in parse_case_request_items(text)]
    except Exception:  # noqa: BLE001
        asks = []
    sections = [x for x in re.split(r"(?m)^(?=#{1,3} )", text) if x.strip()]
    keep = [any(a and a in sec for a in asks) for sec in sections]
    left = budget - sum(len(sec) for sec, k in zip(sections, keep) if k)
    cut_n = sum(1 for k in keep if not k)
    out, shortened = [], []
    for sec, k in zip(sections, keep):
        if not k:
            share = max(200, left // max(1, cut_n))
            if len(sec) > share:
                shortened.append(sec.strip().splitlines()[0].lstrip("# ")[:80])
                sec = sec[:share].rsplit("\n", 1)[0] + "\n[shortened]\n"
            left -= len(sec)
            cut_n -= 1
        out.append(sec)
    return f"{head}\n" + "".join(out).rstrip() + (f"\n(Shortened to fit: {'; '.join(shortened)})" if shortened else "")


def with_case(case_dir, body: str) -> str:
    """The case block, fit beside ``body``, then the body."""
    case = case_block(case_dir, rest=len(body))
    return f"{case}\n\n{body}" if case else body


def purpose_line(case_dir, item: dict[str, Any], m) -> str:
    """What the item serves: a question part, a host's attacker activity,
    the note it follows, the whole map, or coverage of an evidence class."""
    kind = str(item.get("_origin") or item.get("origin") or "")
    ref = item.get("source_ref") or {}
    host = str(ref.get("host") or (item.get("target") or {}).get("host") or "")
    if kind in ("host_pass", "join_hit"):
        return f"PURPOSE: the attacker's activity on {host}, from its arrival on"
    if kind == "synthesis":
        return "PURPOSE: the whole incident map: what cannot both hold, and what no item has read yet"
    if kind == "followup":
        return "PURPOSE: the note below, raised on earlier work"
    task = str((item.get("task_ids") or [""])[0])
    if task:
        part_id = str(ref.get("part_id") or "")
        if kind == "view_row_opened" and m is not None:
            try:
                v = next((v for v in m.views() if v["view_id"] == ref.get("view_id")), {})
                part_id = str(v.get("part_id") or part_id)
            except Exception:  # noqa: BLE001
                pass
        q, part = _task_part(case_dir, task, part_id)
        return (f"PURPOSE: question {task}" + (f" part {part_id}" if part_id else "") + f": {part or q}")
    return ("PURPOSE: coverage of an evidence class: no question and no attacker value names this read; record "
            "only what bears on the case")


def _early_lead(e: dict[str, Any]) -> str:
    """An early sighting as a plain lead: what, where, when, before what."""
    what = (f"{e.get('kind')} {e.get('display') or e.get('value')}" if e.get("display") or e.get("value")
            else f"event {e.get('event_id')}" if e.get("event_id") is not None else str(e.get("subject") or ""))
    return f"{what} on {e.get('host')} at {e.get('time')}, before {e.get('anchor')}"


def item_text(case_dir, item: dict[str, Any], m, readers: str = "") -> str:
    """The item's user message: the case, its purpose, what it is about,
    the map's state around its focus, the host's listing and tables, the
    readers menu."""
    kind = str(item.get("origin") or "")
    ref = item.get("source_ref") or {}
    target = item.get("target") or {}
    host = str(ref.get("host") or target.get("host") or "")
    lines = [f"ITEM {item.get('call_id')} ({kind})", purpose_line(case_dir, item, m), str(item.get("why") or "")]
    if kind in ("host_pass", "join_hit"):
        vals = _entity_values(m, [int(e) for e in ref.get("entities") or [] if str(e).isdigit()])
        lines += [f"HOST: {host}"] + (["ATTACKER VALUES SEEN ON IT:", *[f"- {v}" for v in vals]] if vals else [])
    elif kind == "view_row_opened":
        lines += _view_lines(case_dir, m, ref)
    elif kind == "plan":
        where = target.get("path") or target.get("source_hint") or host
        lines += [f"READ: {item['tool'] + ' on ' if item.get('tool') else ''}{where}"
                  + (f" for {target['pattern']}" if target.get("pattern") else "")]
        if item.get("task_ids"):
            q, _p = _task_part(case_dir, str(item["task_ids"][0]), "")
            if q:
                lines.append(f"QUESTION: {q}")
    elif kind == "followup":
        if ref.get("call_id"):
            lines.append(f"THE NOTE'S CALL: {ref['call_id']}")
        if ref.get("issues"):
            lines += ["THE REPORT GATE'S OPEN ISSUES:", *[f"- {i}" for i in ref["issues"]]]
        if ref.get("kind") == "continuation":
            if ref.get("note"):
                lines += ["THE EARLIER ITEM'S NOTE (verified):", *[f"- {n.get('fact')} [call {n.get('call_id')}]"
                                                                  for n in ref["note"]]]
            if ref.get("digest"):
                lines += ["", str(ref["digest"])]
    if ref.get("early") and kind in ("host_pass", "join_hit"):
        # Leads for the pass, never the followup's instruction.
        lines += ["EARLY SIGHTINGS (leads: attacker values seen here before the attacker's first activity the map "
                  "knows):", *[f"- {_early_lead(e)}" for e in ref["early"][:30]]]
    elif ref.get("early"):
        lines += ["EARLY SIGHTINGS (before the attacker's first activity the map knows there):",
                  *[f"- {e.get('note') or e.get('subject')}" for e in ref["early"][:30]]]
    if len(ref.get("refused") or []) > 1:
        lines += ["THE FINDINGS REFUSED:", *[f"- {r.get('why')}" for r in ref["refused"][:20]]]
    budget = 32000 if kind == "synthesis" else 12000
    try:
        state = m.summary({"host": host} if host else {}, budget_chars=budget) if m is not None else ""
    except Exception:  # noqa: BLE001
        state = ""
    if state:
        lines += ["", "THE INCIDENT MAP NOW:", state]
    if kind == "synthesis" and m is not None:
        try:
            open_rows = [f"- {v['task_id']} part {v['part_id']}: row {r['row_key']} open"
                         for v in m.views(open_only=True) for r in v.get("rows") or []]
        except Exception:  # noqa: BLE001
            open_rows = []
        if open_rows:
            lines += ["", "OPEN VIEW ROWS:", *open_rows[:60]]
        try:
            from core.execution_log import log
            blockers = [str(i.get("why") or "") for i in log.work_items(statuses=("proposed",))
                        if i.get("origin") == "blocker"]
        except Exception:  # noqa: BLE001
            blockers = []
        if blockers:
            lines += ["", "GAPS A SYNTHESIS NAMED, WITH NO READ YET (give each a target or leave it):",
                      *[f"- {b}" for b in blockers[:30]]]
    if host and kind != "synthesis":
        hl = _host_lines(case_dir, host)
        if hl:
            lines += ["", *hl]
    if readers and kind != "synthesis":
        lines += ["", readers]
    if kind == "synthesis":
        lines += ["", "READING TOOLS (a proposal names one of these; any other name is dropped):",
                  ", ".join(proposal_tools())]
        classes = _class_lines(case_dir)
        if classes:
            lines += ["CONTENT CLASSES BY HOST (a proposal's source may name one; code reads its files):", *classes]
        dropped = (item.get("source_ref") or {}).get("dropped") or []
        if dropped:
            lines += ["PROPOSALS OF THE LAST SYNTHESIS THAT WERE DROPPED, AND WHY:", *[f"- {d}" for d in dropped]]
        if readers:
            lines.append(readers)
    return with_case(case_dir, "\n".join(x for x in lines if x is not None))


def _class_lines(case_dir) -> list[str]:
    """One line per host: the content-class labels of its evidence."""
    try:
        from core.coverage_ledger import load_ledger
        led = load_ledger(case_dir)
    except Exception:  # noqa: BLE001
        return []
    host_of = {iid: str(i.get("host") or "") for iid, i in (led.get("items") or {}).items() if isinstance(i, dict)}
    by_host: dict[str, set[str]] = {}
    for c in (led.get("classes") or {}).values():
        if isinstance(c, dict) and c.get("label") and host_of.get(c.get("item")):
            by_host.setdefault(host_of[c["item"]], set()).add(str(c["label"]))
    return [f"- {h}: {', '.join(sorted(labels)[:12])}" for h, labels in sorted(by_host.items())[:40]]


def proposal_tools() -> list[str]:
    """The tools a synthesis proposal may name: the reading core and the
    readers menu, those the plan's read check takes (reading tools)."""
    try:
        from core import question_plan as Q
        from core.work_order import listed
        reading = {listed(t) for t, _w in Q.reading_tools()}
    except Exception:  # noqa: BLE001
        return []
    return [n for n in dict.fromkeys(READ_CORE + reader_names()) if listed(n) in reading]


def item_spec(case_dir, item: dict[str, Any], m, readers: str | None = None, menu: list[str] | None = None):
    """The executor's ItemSpec for a frontier item of a reading kind or the
    synthesis (the triage item is core.evidence_triage's)."""
    from agent.item_executor import ItemSpec
    kind = str(item.get("origin") or "")
    if kind not in KINDS:
        raise ValueError(f"no frontier text for item kind {kind!r}")
    if readers is None:
        try:
            from core.artifact_value import TEXT_FORMATS
            from tools.tool_capabilities import readers_block, text_readers
            readers = readers_block()
            text = text_readers()
            if readers and text:
                readers += f"\n- plain text ({', '.join(TEXT_FORMATS)}): {', '.join(text)}"
        except Exception:  # noqa: BLE001
            readers = ""
    if kind == "synthesis":
        menu = []
    elif menu is None:
        menu = reader_names()
    return ItemSpec(kind=kind, system=system_text(kind), user=item_text(case_dir, item, m, readers),
                    core_tools=core_tools(kind), submit=submit_schema(kind), menu=list(menu))
