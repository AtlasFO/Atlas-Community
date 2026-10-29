"""The frontier queue: the work order's items, generated from
the incident map's change feed, in the frontier's order. No second store:
items are the work order's own (core.work_order), with the frontier's
origins; their state across a restart is the trace plus
``.atlas/frontier_state.json`` (the feed cursor; wiped on a fresh start).

From the feed, per change kind (the payload is the row's ``fields``):
- entity_labeled as attacker: the entity joins the batch the sweep counts
  (core.frontier_sweep), once per generation pass;
- join_hit that is specific (contents_index.is_specific), or a
  host_attacker_event: a host_pass item for a host not yet passed (its
  entities gathered on one item), else one join_hit item per passed host
  folding every entity joined there since;
- view_row_opened: the map's own view items (declared views only);
- evidence_item_pending: no item here. The triage pass
  (core.evidence_triage.triage_pending) asks for every pending unit with no
  triage record, and a reopened unit gets its due item from the leave code;
  their "triage" read items are the queue's triage items, so a second item
  per unit would count as a triage record and skip the ask;
- seen_before_start, account_before_start, label_conflict: a followup item
  carrying the map's note;
- host_without_inbound and window_changed: no item (shown in the host's
  state; a moved window re-ranks the due items).
Order: triage, host_pass (hosts with more specific entities first),
join_hit, view_row_opened, plan, followup; synthesis only when nothing else
is due. Order decides what comes first, never what is left out.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from core.work_order import EXECUTOR

STATE_NAME = "frontier_state.json"
_FOLLOWUP_KINDS = ("seen_before_start", "account_before_start", "label_conflict")


def state_path(case_dir) -> Path:
    return Path(case_dir).resolve() / ".atlas" / STATE_NAME


def load_state(case_dir) -> dict[str, Any]:
    try:
        data = json.loads(state_path(case_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(case_dir, state: dict[str, Any]) -> None:
    p = state_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True, default=str), encoding="utf-8")
    os.replace(tmp, p)


def _open_item(log, origin: str, key: str, value: Any) -> dict[str, Any] | None:
    for e in log.work_items():
        if e.get("origin") == origin and e.get("status") in ("due", "proposed") \
                and (e.get("source_ref") or {}).get(key) == value:
            return e
    return None


def passed_hosts(log) -> set[str]:
    """Hosts whose host_pass item was run to its end (resolved or
    dismissed)."""
    # A pass that failed (an error, not a reading) leaves its host unpassed:
    # the next join there raises a host pass again.
    return {str((e.get("source_ref") or {}).get("host") or "") for e in log.work_items()
            if e.get("origin") == "host_pass" and e.get("status") in ("resolved", "dismissed")} - {""}


def _extend(log, item: dict[str, Any], entities: list[int], why: str) -> None:
    from core.execution_log import _touched
    ref = dict(item.get("source_ref") or {})
    have = list(ref.get("entities") or [])
    new = [e for e in entities if e not in have]
    if not new:
        return
    with log._lock:
        ref["entities"] = have + new
        item["source_ref"] = ref
        item["why"] = why[:400]
        _touched(item)
        log._index_version += 1
        log._flush()


def _host_item(log, m, origin: str, host: str, entities: list[int], why: str, n: int = 0) -> dict[str, Any]:
    """The open host_pass (or folded join_hit) item of a host, created or
    extended with ``entities``."""
    open_one = _open_item(log, origin, "host", host)
    if open_one is not None:
        _extend(log, open_one, entities, why)
        return open_one
    # The target names the host only: a host pass is analysis the executor
    # closes, not a read of the host's image, so no call that reads the
    # image may close it (the work order closes an item whose path or hint
    # a call reached).
    target = {"host": host}
    ref = {"kind": origin, "host": host, "entities": list(entities), "closed_by": EXECUTOR}
    return log.add_work_item(origin, [], "", target, why, status="due", source_ref=ref,
                             extra_key=f"{origin}:{host}:{n}")


def _closed_count(log, origin: str, host: str) -> int:
    return sum(1 for e in log.work_items() if e.get("origin") == origin
               and (e.get("source_ref") or {}).get("host") == host
               and e.get("status") not in ("due", "proposed"))


def generate(log, case_dir: str | os.PathLike, state: dict[str, Any] | None = None,
             sweeper=None) -> dict[str, Any]:
    """Consume the feed after the state's cursor: run the sweep over the
    newly labelled attacker entities, create and fold the items. Returns
    {"cursor", "items", "swept"}; the state is updated and saved."""
    from core import incident_map
    from core.contents_index import is_specific
    m = incident_map.open(case_dir)
    state = state if state is not None else load_state(case_dir)
    if m is None:
        return {"cursor": state.get("cursor", 0), "items": [], "swept": {}}
    changes, cursor = m.changes_since(int(state.get("cursor") or 0))
    swept = {}
    labelled = [c["fields"] for c in changes if c["kind"] == "entity_labeled"
                and c["fields"].get("label") == "attacker"]
    if labelled:
        batch = [{"entity_id": f["entity_id"], "value": f["value"], "kind": f.get("kind")} for f in labelled]
        if sweeper is not None:
            # The caller counts in the background; the sightings it writes
            # later raise their joins in the feed for a later pass.
            swept = sweeper(batch) or {}
        else:
            from core.frontier_sweep import sweep
            swept = sweep(case_dir, log, batch)
            more, cursor = m.changes_since(cursor)      # the sweep's sightings raise joins
            changes += more
    attackers = {e["entity_id"]: e for e in m.attacker_entities()}
    per_host: dict[str, list[int]] = {}
    for c in changes:
        f = c["fields"]
        if c["kind"] == "join_hit" and f.get("entity_id") in attackers and is_specific(f["k"], f["n"]):
            per_host.setdefault(f["host"], []).append(int(f["entity_id"]))
        elif c["kind"] == "host_attacker_event" and f.get("host"):
            per_host.setdefault(f["host"], [])
    made = _host_items(log, m, per_host, attackers)
    made += view_parts(log, m)
    for c in changes:
        if c["kind"] in _FOLLOWUP_KINDS:
            try:
                note = m.note_text(c)
            except Exception:  # noqa: BLE001
                note = c["kind"]
            made.append(_followup(log, m, c, note)["call_id"])
    state["cursor"] = cursor
    save_state(case_dir, state)
    return {"cursor": cursor, "items": list(dict.fromkeys(made)), "swept": swept}


# The window notes, folded per host: what a followup carries is the list of
# early sightings ("early") on one host, never one item per entity.
WINDOW_KINDS = ("seen_before_start", "account_before_start")


def _started(item: dict[str, Any]) -> bool:
    """An item the frontier has begun to run: its text is built, so what is
    added to it now is never read."""
    return bool((item.get("source_ref") or {}).get("started"))


def _add_early(log, item: dict[str, Any], entry: dict[str, Any], why: str = "") -> None:
    from core.execution_log import _touched
    with log._lock:
        ref = dict(item.get("source_ref") or {})
        have = list(ref.get("early") or [])
        if entry.get("subject") not in {e.get("subject") for e in have}:
            ref["early"] = have + [entry]
            item["source_ref"] = ref
            if why:
                item["why"] = why[:400]
            _touched(item)
            log._index_version += 1
            log._flush()


def _early_entry(m, c: dict[str, Any], note: str) -> dict[str, Any]:
    f = c["fields"]
    entry = {k: f.get(k) for k in ("entity_id", "event_id", "account", "host", "time", "anchor",
                                    "from_estate_start") if f.get(k) is not None}
    entry.update(subject=_subject(c["kind"], f), change=c["kind"], seq=c.get("seq"), note=str(note)[:300])
    if f.get("entity_id") is not None:
        try:
            with m._read() as con:
                r = con.execute("SELECT kind, key, display FROM entities WHERE eid = ?",
                                (int(f["entity_id"]),)).fetchone()
            if r is not None:
                entry.update(kind=r["kind"], value=r["key"], display=r["display"])
        except Exception:  # noqa: BLE001
            pass
    return entry


def _window_subject(c: dict[str, Any]) -> str:
    f = c["fields"]
    return f"{c['kind']}:{f.get('host') or str(f.get('account') or '').casefold()}"


def _window_item(log, subject: str, other_than: int = 0) -> dict[str, Any] | None:
    """The open, not yet begun followup of one window kind on one host."""
    return next((e for e in log.work_items() if e.get("origin") == "followup" and e.get("status") == "due"
                 and (e.get("source_ref") or {}).get("subject") == subject and not _started(e)
                 and e["call_id"] != other_than), None)


def _window_why(item: dict[str, Any], subject: str, adding: int = 1) -> str:
    n = len((item.get("source_ref") or {}).get("early") or []) + adding
    return (f"{n} early sightings on {subject.split(':', 1)[1]}: say for each why it is the attacker's there, or the "
            "owner's")


def _pass_for(log, m, c: dict[str, Any]) -> dict[str, Any] | None:
    """The host pass an early sighting rides: only one on a host with no
    start of its own (the estate start is the bound). The open pass not yet
    begun; for a host passed without a start, a pass again for its arrival
    (the n counter). None otherwise (no pass on the host, or its pass is
    running): the host's window followup then."""
    f = c["fields"]
    host = str(f.get("host") or "")
    if c["kind"] != "seen_before_start" or not f.get("from_estate_start") or not host:
        return None
    open_pass = _open_item(log, "host_pass", "host", host)
    # One pass again per host: a re-pass that ended and left the host without
    # a start leaves later sightings to the host's window followup.
    repassed = any(e.get("origin") == "host_pass" and (e.get("source_ref") or {}).get("host") == host
                   and (e.get("source_ref") or {}).get("repass") and e.get("status") not in ("due", "proposed")
                   for e in log.work_items())
    if open_pass is None and host in passed_hosts(log) and not repassed:
        why = (f"pass {host} again: how the attacker reached it (its arrival is not stated yet); the early "
               "sightings below are the leads")
        open_pass = _host_item(log, m, "host_pass", host, [], why, n=_closed_count(log, "host_pass", host))
        _set_ref(log, open_pass, repass=True)
    return open_pass if open_pass is not None and not _started(open_pass) else None


def _followup(log, m, c: dict[str, Any], note: str) -> dict[str, Any]:
    """The item a map note goes to. An early sighting on a host with no
    start of its own rides that host's pass (_pass_for). Every other window
    note joins its host's (an account's) one open followup of its kind,
    begun or not decided by the item's own start mark. A label conflict
    keeps one item per subject."""
    f = c["fields"]
    host = str(f.get("host") or "")
    if c["kind"] in WINDOW_KINDS:
        entry = _early_entry(m, c, note)
        open_pass = _pass_for(log, m, c)
        if open_pass is not None:
            _add_early(log, open_pass, entry)
            return open_pass
        subject = _window_subject(c)
        e = _window_item(log, subject)
        if e is not None:
            _add_early(log, e, entry, why=_window_why(e, subject))
            return e
        n = sum(1 for e in log.work_items() if e.get("origin") == "followup"
                and (e.get("source_ref") or {}).get("subject") == subject and e.get("status") not in ("due", "proposed"))
        return log.add_work_item("followup", [], "", {"host": host}, note, status="due",
                                 source_ref={"kind": "followup", "closed_by": EXECUTOR, "change": c["kind"],
                                             "seq": c["seq"], "subject": subject, "host": host, "fields": f,
                                             "early": [entry]},
                                 extra_key=f"followup:{subject}:{n}")
    subject = _subject(c["kind"], f)
    n = sum(1 for e in log.work_items() if e.get("origin") == "followup"
            and (e.get("source_ref") or {}).get("subject") == subject and e.get("status") not in ("due", "proposed"))
    return log.add_work_item("followup", [], "", {"host": host}, note, status="due",
                             source_ref={"kind": "followup", "closed_by": EXECUTOR, "change": c["kind"],
                                         "seq": c["seq"], "subject": subject, "fields": f},
                             extra_key=f"followup:{subject}:{n}")


def premise(log, m, item: dict[str, Any]) -> bool:
    """Before an item with early sightings runs: each is checked from the
    map, no model call (IncidentMap.early_holds); the ones no longer
    holding are taken off, with what changed. A followup left with none
    closes ("premise gone: ..."); a pass keeps running. False when the item
    was closed."""
    from core.work_order import close_item
    ref = item.get("source_ref") or {}
    early = list(ref.get("early") or [])
    if not early or m is None:
        return True
    kept, gone = [], []
    for e in early:
        try:
            holds, why = m.early_holds(e)
        except Exception:  # noqa: BLE001 - a check that cannot run keeps the lead
            holds, why = True, ""
        (kept if holds else gone).append(e if holds else {**e, "gone": why})
    if not gone:
        return True
    _set_ref(log, item, early=kept, premise_gone=list(ref.get("premise_gone") or []) + gone)
    if kept or item.get("origin") != "followup":
        return True
    close_item(log, item["call_id"], "moot", ("premise gone: " + "; ".join(g["gone"] for g in gone))[:300])
    return False


def _set_why(log, item: dict[str, Any], why: str) -> None:
    from core.execution_log import _touched
    with log._lock:
        item["why"] = why[:400]
        _touched(item)
        log._index_version += 1
        log._flush()


def _fold_into(log, src: dict[str, Any], dest: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    from core.execution_log import _touched
    from core.work_order import close_item
    for e in entries:
        _add_early(log, dest, e)
    close_item(log, src["call_id"], "moot", f"folded into #{dest['call_id']}")
    with log._lock:
        src["folded_into"] = dest["call_id"]
        dest["folded"] = list(dict.fromkeys([*(dest.get("folded") or []), src["call_id"]]))
        _touched(src)
        _touched(dest)
        log._index_version += 1
        log._flush()


def fold_open(log, case_dir, state: dict[str, Any]) -> dict[str, int]:
    """Once per state (a resume of a run whose followups were raised one per
    entity): every open window followup is folded by the rules new ones
    follow (_followup), refusal followups per item and gate, and the
    premise is checked. The folded items close as moot with "folded into
    #n" and folded_into set, so no count reads them as work done; the trace
    keeps them. Returns {"input", "open", "folded", "gone"}."""
    from core import incident_map
    out = {"input": 0, "open": 0, "folded": 0, "gone": 0}
    if state.get("folded"):
        return out
    m = incident_map.open(case_dir)
    items = [e for e in log.work_items() if e.get("origin") == "followup" and e.get("status") == "due"]
    out["input"] = len(items)
    for e in items:
        ref = e.get("source_ref") or {}
        if ref.get("change") in WINDOW_KINDS and m is not None:
            c = {"kind": ref["change"], "fields": ref.get("fields") or {}, "seq": ref.get("seq")}
            entries = list(ref.get("early") or []) or [_early_entry(m, c, str(e.get("why") or ""))]
            subject = _window_subject(c)
            dest = _pass_for(log, m, c) or _window_item(log, subject, other_than=e["call_id"])
            if dest is None:
                # the host's first: it becomes the host's item
                _set_ref(log, e, subject=subject, host=str(c["fields"].get("host") or ""), early=entries)
                continue
            _fold_into(log, e, dest, entries)
            if dest.get("origin") == "followup":
                _set_why(log, dest, _window_why(dest, subject, adding=0))
        elif ref.get("kind") == "refusal":
            dest = next((d for d in log.work_items() if d.get("origin") == "followup" and d.get("status") == "due"
                         and d["call_id"] != e["call_id"] and (d.get("source_ref") or {}).get("kind") == "refusal"
                         and (d.get("source_ref") or {}).get("item") == ref.get("item")
                         and (d.get("source_ref") or {}).get("gate") == ref.get("gate")
                         and d["call_id"] < e["call_id"]), None)
            if dest is not None:
                dref = dest.get("source_ref") or {}
                refused = list(dref.get("refused") or [{"why": str(dest.get("why") or ""), "ask": dref.get("ask")}])
                _set_ref(log, dest, refused=refused + [{"why": str(e.get("why") or ""), "ask": ref.get("ask")}])
                _fold_into(log, e, dest, [])
                _set_why(log, dest, f"{len(refused) + 1} findings of item {ref.get('item')} refused twice by "
                                    f"{ref.get('gate')}: repair each from its rows, or let it go")
    for e in log.work_items():
        if e.get("status") == "due" and (e.get("source_ref") or {}).get("early"):
            premise(log, m, e)
    for e in items:
        cur = next((x for x in log.work_items() if x["call_id"] == e["call_id"]), e)
        if cur.get("folded_into"):
            out["folded"] += 1
        elif str(cur.get("outcome") or "").startswith("premise gone"):
            out["gone"] += 1
        elif cur.get("status") == "due":
            out["open"] += 1
    state["folded"] = True
    save_state(case_dir, state)
    return out


def seed(log, case_dir: str | os.PathLike, state: dict[str, Any]) -> dict[str, Any]:
    """A fresh start with a kept map: the first items come from the current
    state, never from replaying the feed (whose old labels may no longer be
    current). The feed's head is taken first, then the current attacker
    entities are swept, their specific hosts get their items, and the open
    rows of declared views theirs; the cursor is set to that head, so only
    what changes after it raises items. Pending evidence is the triage
    pass's. Returns {"cursor", "items", "swept"}."""
    from core import incident_map
    from core.contents_index import is_specific
    m = incident_map.open(case_dir)
    if m is None:
        return {"cursor": int(state.get("cursor") or 0), "items": [], "swept": {}}
    head = m.head()
    entities = m.attacker_entities()
    swept = {}
    if entities:
        from core.frontier_sweep import sweep
        swept = sweep(case_dir, log, [{"entity_id": e["entity_id"], "value": e["value"], "kind": e["kind"]}
                                      for e in entities])
        entities = m.attacker_entities()                 # with the sweep's sightings
    attackers = {e["entity_id"]: e for e in entities}
    n = max(1, len(m._hosts()))
    per_host: dict[str, list[int]] = {}
    for e in entities:
        hosts = [h for h in e.get("hosts") or [] if h]
        if hosts and is_specific(len(hosts), n):
            for h in hosts:
                per_host.setdefault(h, []).append(int(e["entity_id"]))
    try:
        # Hosts with an attacker event of their own (the map's first
        # attacker time per host), the state host_attacker_event raises in
        # the feed; never the hosts a sighting alone reaches, where a common
        # value would pass every host.
        with m._read() as con:
            firsts = m._meta(con, "host_first", {}) or {}
        for h in firsts:
            per_host.setdefault(h, [])
    except Exception:  # noqa: BLE001
        pass
    made = _host_items(log, m, per_host, attackers)
    made += view_parts(log, m)
    state["cursor"] = head
    save_state(case_dir, state)
    return {"cursor": head, "items": list(dict.fromkeys(made)), "swept": swept}


def _host_items(log, m, per_host: dict[str, list[int]], attackers: dict[int, dict[str, Any]]) -> list[int]:
    """Per host with specific attacker values: its host_pass (not yet
    passed) or one folded join_hit (passed)."""
    passed = passed_hosts(log)
    made: list[int] = []
    for host, ents in sorted(per_host.items()):
        ents = sorted(set(ents))
        names = ", ".join(str(attackers[e]["value"]) for e in ents[:6] if e in attackers)
        if host not in passed:
            why = (f"pass {host}: how the attacker reached it, then what was done there"
                   + (f"; attacker values seen there: {names}" if names else ""))
            made.append(_host_item(log, m, "host_pass", host, ents, why,
                                   n=_closed_count(log, "host_pass", host))["call_id"])
        elif ents:
            why = f"label the rows of attacker values on {host}, joined since its pass: {names}"
            made.append(_host_item(log, m, "join_hit", host, ents, why,
                                   n=_closed_count(log, "join_hit", host))["call_id"])
    return made


def _subject(kind: str, fields: dict[str, Any]) -> str:
    """What a map note is about: the entity and host of an early sighting,
    the account of an early event, the target of a label conflict."""
    if kind == "seen_before_start":
        if fields.get("event_id") is not None:          # the event variant
            return f"{kind}:v{fields.get('event_id')}:{fields.get('host')}"
        return f"{kind}:e{fields.get('entity_id')}:{fields.get('host')}"
    if kind == "account_before_start":
        return f"{kind}:{str(fields.get('account') or '').casefold()}"
    return f"{kind}:{fields.get('ref')}"


# The rows one view item names: what a small model reads and works through
# in one item. A fit per item, never a cap: every open row gets an item.
VIEW_ROWS_PER_ITEM = 40


def _set_ref(log, e: dict[str, Any], **fields: Any) -> None:
    from core.execution_log import _touched
    with log._lock:
        ref = dict(e.get("source_ref") or {})
        ref.update(fields)
        e["source_ref"] = ref
        _touched(e)
        log._index_version += 1
        log._flush()


def view_parts(log, m) -> list[int]:
    """The open rows of every declared view as items of their question part
    (origin view_row_opened), at most VIEW_ROWS_PER_ITEM rows each; an
    item's rows are exactly the rows its text names. A row is held by the
    item that has it: a due item keeps its rows that are still open (it
    resolves when none is), a closed one keeps its rows unless a row filled
    or left after it and opened again (a reopened row gets a new item).
    Rows no item holds get new items. The per-row items of an older trace
    fold into the part items."""
    from core.work_order import EXECUTOR, close_item
    try:
        views = [v for v in m.views() if v.get("declared_by") != "default"]
    except Exception:  # noqa: BLE001
        return []
    for e in log.work_items(statuses=("due", "proposed")):
        if e.get("origin") == "view_row_opened" and (e.get("source_ref") or {}).get("kind") == "view_row":
            close_item(log, e["call_id"], "moot", "folded into its question part's view items")
    items = [e for e in log.work_items() if e.get("origin") == "view_row_opened"
             and (e.get("source_ref") or {}).get("kind") == "view_part"]
    made: list[int] = []
    for v in views:
        task, part = str(v["task_id"]), str(v["part_id"])
        rows = [str(r["row_key"]) for r in v.get("rows") or [] if r.get("status") == "open"]
        open_rows = set(rows)
        mine = [e for e in items if (e.get("source_ref") or {}).get("task_id") == task
                and (e.get("source_ref") or {}).get("part_id") == part]
        held: set[str] = set()
        due: list[tuple[dict, list[str]]] = []
        for e in mine:
            ref = e.get("source_ref") or {}
            have = [str(r) for r in ref.get("rows") or []]
            if e.get("status") in ("due", "proposed"):
                keep = [r for r in have if r in open_rows]
                due.append((e, keep))
                held |= set(keep)
                continue
            settled = set(ref.get("settled") or [])
            now_settled = {r for r in have if r not in open_rows} - settled
            if now_settled:
                _set_ref(log, e, settled=sorted(settled | now_settled))
                settled |= now_settled
            held |= {r for r in have if r not in settled}
        fresh = [r for r in rows if r not in held]
        for e, keep in due:
            # New rows join a due item while it has room.
            room = max(0, VIEW_ROWS_PER_ITEM - len(keep))
            keep, fresh = keep + fresh[:room], fresh[room:]
            ref = e.get("source_ref") or {}
            if not keep:
                close_item(log, e["call_id"], "resolved", "the part's rows filled or left its view")
            elif keep != [str(r) for r in ref.get("rows") or []] or ref.get("view_id") != v["view_id"]:
                _set_ref(log, e, rows=keep, view_id=v["view_id"])
                e["why"] = f"{task} part {part}: {len(keep)} open row(s) of its view"
        for i in range(0, len(fresh), VIEW_ROWS_PER_ITEM):
            chunk = fresh[i:i + VIEW_ROWS_PER_ITEM]
            ref = {"kind": "view_part", "closed_by": EXECUTOR, "task_id": task, "part_id": part,
                   "view_id": v["view_id"], "rows": chunk}
            e = log.add_work_item("view_row_opened", [task], "", None,
                                  f"{task} part {part}: {len(chunk)} open row(s) of its view", status="due",
                                  source_ref=ref, extra_key=f"view_part:{task}:{part}:{len(mine) + len(made)}")
            made.append(e["call_id"])
    return made


# The frontier's order is by purpose: the attacker's hosts first, then what
# serves an open question, then the follow-ups, then the synthesis, last
# the coverage reads no question or attacker value names.
# After them, the classes whose leave did not hold: read when nothing else
# is due, and always before the run can end (the stop needs no item due).
_PURPOSE_RANK = {"host_pass": 0, "question": 1, "join_hit": 2, "followup": 2, "synthesis": 3, "coverage": 4,
                 "refused_leave": 5}
# How many model calls each pool beside the item thread (the question plans,
# the stateless triage) runs at once. They run in parallel beside the one
# item thread; ATLAS_BESIDE_WORKERS sets it.
BESIDE_WORKERS = 4


# The work item the frontier runs now (its id while it runs): the threads
# beside it never close it.
RUNNING: set[int] = set()


def beside_workers() -> int:
    import os
    try:
        return max(1, int(os.environ.get("ATLAS_BESIDE_WORKERS") or BESIDE_WORKERS))
    except ValueError:
        return BESIDE_WORKERS


def _purpose(item: dict[str, Any]) -> str:
    if (item.get("source_ref") or {}).get("after") == "refused_leave":
        return "refused_leave"
    origin = str(item.get("origin") or "")
    if origin in ("host_pass", "join_hit", "followup", "synthesis"):
        return origin
    return "question" if item.get("task_ids") else "coverage"


def rank_context(m, case_dir) -> dict[str, Any]:
    """What the quick-win tier reads, once per ordering: whether the map
    still has no attacker entity (the bootstrap), the parsed tables the
    contents index knows, and the questions with an open part."""
    ctx: dict[str, Any] = {"bootstrap": False, "exports": set(), "open_tasks": set()}
    if m is None or not case_dir:
        return ctx
    try:
        ctx["bootstrap"] = not m.attacker_entities()
    except Exception:  # noqa: BLE001
        return ctx
    if not ctx["bootstrap"]:
        return ctx
    try:
        from core.contents_index import export_paths
        ctx["exports"] = export_paths(case_dir)
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.investigation_tasks import load_tasks
        ctx["open_tasks"] = {str(t.get("id")) for t in load_tasks(case_dir).get("tasks") or []
                             if any(isinstance(p, dict) and p.get("status") == "open" for p in t.get("parts") or [])
                             or (not t.get("parts") and str(t.get("status") or "open") == "open")}
    except Exception:  # noqa: BLE001
        pass
    return ctx


def _quick(item: dict[str, Any], exports: set[str]) -> bool:
    """A read of evidence already in table form (a parsed export, or a
    folder holding them; a plan's source named by its file name matches the
    export of that name): a property of the evidence, never a name."""
    target = item.get("target") or {}
    for c in (str(target.get("path") or "").strip("/"), str(target.get("source_hint") or "").strip("/")):
        if c and any(e == c or e.startswith(c + "/") or e.endswith("/" + c) for e in exports):
            return True
    return False


def _rank_key(item: dict[str, Any], ctx: dict[str, Any] | None = None) -> tuple:
    purpose = _purpose(item)
    ents = len((item.get("source_ref") or {}).get("entities") or [])
    tier = _PURPOSE_RANK[purpose]
    if ctx and ctx.get("bootstrap") and purpose == "question" \
            and set(item.get("task_ids") or []) & ctx["open_tasks"] \
            and (_quick(item, ctx["exports"])
                 or (item.get("origin") == "plan" and set(item.get("task_ids") or []) & ctx.get("quick_tasks", set()))):
        # Quick wins first, only until the first attacker entity: a read of
        # parsed tables that serves an open part produces the first values
        # the sweep then scales. A planned read of a slower source keeps its
        # own rank, except beside a quick read of its own question: the
        # model's choice is never put below those.
        tier = -1
    return (tier, -ents if purpose == "host_pass" else 0, int(item.get("call_id") or 0))


def due_items(log, ctx: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every due item, in the frontier's order (``ctx`` from rank_context
    adds the quick-win tier): no origin is left without a runner."""
    due = [e for e in log.work_items() if e.get("status") == "due"]
    if ctx and ctx.get("bootstrap"):
        ctx = {**ctx, "quick_tasks": {t for e in due if e.get("origin") != "plan" and _quick(e, ctx["exports"])
                                      for t in e.get("task_ids") or []}}
    return sorted(due, key=lambda e: _rank_key(e, ctx))


def next_item(log) -> dict[str, Any] | None:
    due = due_items(log)
    return due[0] if due else None
