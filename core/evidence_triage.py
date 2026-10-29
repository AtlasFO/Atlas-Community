"""Evidence triage (ATLAS_EVIDENCE_DISPOSITION): every pending item
and content class enters the work order (origin "triage").

The triage call is one short stateless call per item: its survey (2 to 4
KB), the facts its leave kinds need (the incident's earliest stated start,
the hosts in scope, whether a reader takes each class) and its classes in;
a few decisions out, each naming the classes it covers by label: read_now,
read_later, or left with a kind, a reason and proof. ``triage_call`` only
asks; ``apply_triage`` records the reply code-side, so the call can move to
a queue of stateless calls unchanged.

Per evidence item the order gets one due item naming its classes to read
now (and the ones nobody decided), and one proposed item for those to read
later; each closes when its classes are credited or left. A left decision
passes the leave checks (core.evidence_leave) or the class stays to be
read. Read and partial come from the evidence (credit_dispositions), never
from a closed item.
"""
from __future__ import annotations

from core.store_lock import locked as _locked

import json
import re
import threading
from typing import Any, Callable, Optional

TRIAGE_SYS = (
    "You triage one piece of evidence of a digital-forensics case before it is analysed. You get what code saw in "
    "it (its survey), the facts a leave needs and its content classes by label. Decide for its classes: read_now "
    "(they can answer the case's questions or show the attacker), read_later (worth reading once the first reads "
    "are done), or left (they cannot help, with one kind and its proof). Kinds: outside_window (the data ends "
    "before the earliest stated start below), other_scope (the host is not among the hosts in scope below and "
    "shares no account with them), duplicate_of (proof: the other item's path), unrelated_content (no reader "
    "takes any of them). Unreadable is never a triage decision: it follows from failed reads. Code checks every "
    "left decision. For classes to read, name in serves the question parts they can answer (their ids from the "
    "list below), or coverage when none. Classes you do not name are read. When the item has no classes, decide "
    "for the item.\n"
    "Answer with JSON only: {\"item\":{\"decision\":\"\",\"kind\":\"\",\"reason\":\"\",\"proof\":[],"
    "\"serves\":[]},\"decisions\":[{\"decision\":\"\",\"classes\":[\"<label>\"],\"kind\":\"\",\"reason\":\"\","
    "\"proof\":[],\"serves\":[]}]}"
)
DECISIONS = ("read_now", "read_later", "left")

# The triage as one call of the executor (agent/item_executor.py): the same
# decisions through its submit tool, from the survey and the case alone (it
# classifies, it never investigates). No artefact is named.
TRIAGE_ITEM_SYS = TRIAGE_SYS.split("\nAnswer with JSON only:")[0] + (
    " Call submit_triage with your decisions, each naming its classes by label.")
_DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": list(DECISIONS)},
        "classes": {"type": "array", "items": {"type": "string"},
                    "description": "the class labels this decision covers"},
        "kind": {"type": "string", "description": "for left: the leave kind"},
        "reason": {"type": "string"},
        "proof": {"type": "array", "items": {"type": "string"},
                  "description": "for left: call ids, or the other item's path for duplicate_of"},
        "serves": {"type": "array", "items": {"type": "string"},
                   "description": "for classes to read: the question parts they can answer (task-0001/p1), "
                                  "or coverage"},
    },
    "required": ["decision"],
}
TRIAGE_SUBMIT = {"type": "function", "function": {
    "name": "submit_triage",
    "description": "End the triage of this evidence item with your decisions.",
    "parameters": {"type": "object", "properties": {
        "decisions": {"type": "array", "items": _DECISION_SCHEMA,
                      "description": "decisions for the item's content classes, by label"},
        "item": {**_DECISION_SCHEMA, "description": "the decision for an item that has no classes"},
        "examined": {"type": "object", "properties": {
            "call_ids": {"type": "array", "items": {"type": "integer"}},
            "why": {"type": "string"}},
            "description": "the calls you made and what they showed"},
    }}}}


def triage_items_on() -> bool:
    """ATLAS_TRIAGE_ITEMS: the triage runs as an executor item (tools, then
    a submit) when the loop hands its agent over; off: one stateless call."""
    from core.envfile import env_flag
    return env_flag("ATLAS_TRIAGE_ITEMS", True)


def triage_spec(case_dir, ledger: dict[str, Any], item: dict[str, Any], survey: str):
    """One classification call: no tools, the survey and the case in, the
    decisions out."""
    from agent.item_executor import ItemSpec
    user = f"ITEM ID {item['id']}\n" + triage_message(case_dir, ledger, item, survey)
    return ItemSpec(kind="triage", system=TRIAGE_ITEM_SYS, user=user, core_tools=[], submit=TRIAGE_SUBMIT)


def reply_from_submit(args: dict[str, Any] | None) -> dict[str, Any]:
    """A submit_triage call's arguments in parse_triage's shape."""
    return parse_triage(json.dumps({"item": (args or {}).get("item") or {},
                                    "decisions": (args or {}).get("decisions") or []}))
_EVIDENCE_KEY = "evidence:{item}:{status}:{n}"


def _pending_classes(ledger: dict[str, Any], item_id: str) -> list[dict[str, Any]]:
    return [c for c in (ledger.get("classes") or {}).values()
            if isinstance(c, dict) and c.get("item") == item_id and c.get("state") == "pending"]


def triage_message(case_dir, ledger: dict[str, Any], item: dict[str, Any], survey: str) -> str:
    from core.evidence_leave import _named_hosts, unit_readers, window_start
    lines = []
    from core.frontier_prompts import case_block
    case = case_block(case_dir)
    if case:
        lines += [case, ""]
    try:
        start = window_start(case_dir)
    except Exception:  # noqa: BLE001
        start = ""
    try:
        scope = sorted(h.upper() for h in _named_hosts(case_dir))
    except Exception:  # noqa: BLE001
        scope = []
    lines += [f"EARLIEST STATED START: {start or 'none stated'}",
              f"HOSTS IN SCOPE: {', '.join(scope[:30]) or 'none named'}"]
    try:
        from core.evidence_leave import scope_facts
        facts = scope_facts(case_dir, item)
    except Exception:  # noqa: BLE001
        facts = []
    if facts:
        lines += ["THIS ITEM (what the leave checks read):", *[f"- {f}" for f in facts]]
    parts = _part_lines(case_dir)
    if parts:
        lines += ["QUESTION PARTS (what serves names):", *parts]
    lines += ["", "SURVEY:", survey, "", "CLASSES:"]
    for c in _pending_classes(ledger, item["id"]):
        try:
            reader = "yes" if unit_readers(case_dir, "class", c, item)[0] or item.get("kind") == "memory" \
                else "no"
        except Exception:  # noqa: BLE001
            reader = "?"
        lines.append(f"- {c['label']} ({c['files']} files; reader: {reader}){_memory_ways(item, c)}")
    if lines[-1] == "CLASSES:":
        lines.append("- (none)")
    return "\n".join(lines)


def _memory_ways(item: dict[str, Any], c: dict[str, Any]) -> str:
    """For a memory structure: its fast walk first, and its scan offered as
    the deeper read (it also finds unlinked and freed objects)."""
    if item.get("kind") != "memory":
        return ""
    from core.evidence_disposition import MEMORY_STRUCTURES, first_walk, memory_cost
    plugins = MEMORY_STRUCTURES.get(c.get("label")) or ()
    walk = first_walk(plugins)
    scans = [p for p in plugins if memory_cost(p) == "scan"]
    return ((f"; walk: {walk}" if walk else "")
            + (f"; deeper: {scans[0]} finds unlinked and freed objects" if scans else ""))


def parse_triage(text: str) -> dict[str, Any]:
    """{"item": {...}, "decisions": [{"decision", "classes", ...}]} of a
    triage reply; prose around the JSON is ignored, an unknown decision is
    dropped. The older shape (a decision per class id) is read too."""
    s = str(text or "")
    for m in re.finditer(r"\{", s):
        depth = 0
        for i in range(m.start(), len(s)):
            depth += {"{": 1, "}": -1}.get(s[i], 0)
            if depth == 0:
                try:
                    data = json.loads(s[m.start():i + 1])
                except ValueError:
                    break
                if isinstance(data, dict) and ("decisions" in data or "classes" in data or "item" in data):
                    item = data.get("item") if isinstance(data.get("item"), dict) else {}
                    decisions = [d for d in data.get("decisions") or [] if isinstance(d, dict)
                                 and d.get("decision") in DECISIONS]
                    if isinstance(data.get("classes"), dict):
                        decisions += [{**d, "classes": [k]} for k, d in data["classes"].items()
                                      if isinstance(d, dict) and d.get("decision") in DECISIONS]
                    return {"item": item if item.get("decision") in DECISIONS else {}, "decisions": decisions}
                break
    return {"item": {}, "decisions": []}


def triage_call(system: str, user: str, ask: Optional[Callable[..., dict]] = None) -> str:
    """The stateless call: the reply text, nothing recorded."""
    if ask is None:
        from tools.reasoning import _ask as ask
    return str((ask(system, user, _tool_name="reason_triage_evidence") or {}).get("conclusion") or "")


def _work_item(log, case_dir, item: dict[str, Any], classes: list[dict[str, Any]], status: str, why: str,
               task_ids: list[str] | None = None, after: str = "") -> dict:
    """The item's triage work item carrying ``classes`` (none: the item
    itself). It stands apart from any other read of the same image (its own
    fingerprint key), and a closed one is never reused: a new one carries
    the next count. ``after`` marks an item ranked after every other one."""
    target = {"host": item.get("host") or "", "path": item["path"]}
    ref = {"kind": "evidence", "item": item["id"], "classes": [c["id"] for c in classes],
           **({"after": after} if after else {})}
    n = 0
    while True:
        entry = log.add_work_item("triage", list(task_ids or []), "", target, why, status=status, source_ref=ref,
                                  extra_key=_EVIDENCE_KEY.format(item=item["id"], status=after or status, n=n))
        if entry.get("status") in ("due", "proposed"):
            if entry.get("source_ref") != ref:
                from core.execution_log import _touched
                with log._lock:
                    entry["source_ref"] = ref
                    entry["why"] = why[:400]
                    _touched(entry)
                    log._index_version += 1
                    log._flush()
            return entry
        n += 1


def _units_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """The (item, class) refs a triage item carries."""
    ref = entry.get("source_ref") or {}
    if entry.get("origin") != "triage" or ref.get("kind") != "evidence":
        return []
    classes = ref.get("classes") or ([ref["class"]] if ref.get("class") else [])
    return [{"item": ref.get("item"), "class": c} for c in classes] or [{"item": ref.get("item"), "class": None}]


def reopen_item(log, case_dir, item: dict[str, Any], unit: dict[str, Any] | None, why: str) -> dict:
    """A due triage item for a reopened unit; never changes an item of
    another origin, never rewrites a closed one."""
    return _work_item(log, case_dir, item, [unit] if unit is not None else [], "due", why)


def _resolve(item_classes: list[dict[str, Any]], keys: list) -> list[dict[str, Any]]:
    """The classes a decision names, by exact label or id."""
    by = {c["label"].casefold(): c for c in item_classes} | {c["id"]: c for c in item_classes}
    out = []
    for k in keys or []:
        c = by.get(str(k)) or by.get(str(k).casefold())
        if c is not None and c not in out:
            out.append(c)
    return out


def apply_triage(log, case_dir, ledger: dict[str, Any], item: dict[str, Any], reply: dict[str, Any],
                 final: bool = True) -> dict:
    """Record one triage reply code-side. Returns {"left", "refused",
    "items"}. A left decision that does not hold keeps its class pending:
    with ``final`` False it is only reported (the caller sends it back once),
    with ``final`` the class is marked triage_refused, a triage record that
    stays pending and is disclosed. The classes to read carry the question
    parts their decision serves as the read item's tasks."""
    from core.evidence_leave import set_disposition
    classes = _pending_classes(ledger, item["id"])
    out: dict[str, Any] = {"left": [], "refused": [], "items": []}
    tasks_of = _serving_tasks(case_dir)
    if not classes:
        d = reply.get("item") or {}
        if d.get("decision") == "left":
            r = set_disposition(case_dir, item["path"], "left", str(d.get("kind") or ""), str(d.get("reason") or ""),
                                list(d.get("proof") or []))
            if r.get("success"):
                out["left"].append(item["path"])
                return out
            out["refused"].append((item["path"], r.get("error", "")))
            if not final:
                return out
        if d.get("decision") in ("read_now", "read_later"):
            set_disposition(case_dir, item["path"], "relevant", reason=str(d.get("reason") or "")[:300])
        status = "proposed" if d.get("decision") == "read_later" else "due"
        out["items"].append(_work_item(log, case_dir, item, [], status, f"triage: read {item['path']}",
                                       tasks_of(d.get("serves")))["call_id"])
        return out
    now, later, decided, serves_now, serves_later = [], [], set(), [], []
    refused: list[dict[str, Any]] = []
    for d in reply.get("decisions") or []:
        named = [c for c in _resolve(classes, list(d.get("classes") or [])) if c["id"] not in decided]
        decided |= {c["id"] for c in named}
        if d.get("decision") == "left":
            for c in named:
                r = set_disposition(case_dir, c["id"], "left", str(d.get("kind") or ""), str(d.get("reason") or ""),
                                    list(d.get("proof") or []))
                if r.get("success"):
                    out["left"].append(c["id"])
                else:
                    out["refused"].append((c["id"], r.get("error", "")))
                    refused.append({**c, "_error": r.get("error", "")})
        elif d.get("decision") == "read_later":
            later += named
            serves_later += tasks_of(d.get("serves"))
        else:
            now += named
            serves_now += tasks_of(d.get("serves"))
    undecided = [c for c in classes if c["id"] not in decided]
    now += undecided                                           # undecided: read
    if refused and final:
        _mark_refused(case_dir, refused)
        # A leave that did not hold is a sign the class may matter: it is
        # read, after everything else (core.frontier_queue's last rank).
        labels = ", ".join(c["label"] for c in refused[:8]) + (
            f" and {len(refused) - 8} more" if len(refused) > 8 else "")
        out["items"].append(_work_item(log, case_dir, item, refused, "due",
                                       f"triage: read {labels}, whose leave did not hold", [],
                                       after="refused_leave")["call_id"])
    for c in now + later:
        set_disposition(case_dir, c["id"], "relevant")
    if now:
        labels = ", ".join(c["label"] for c in now[:8]) + (f" and {len(now) - 8} more" if len(now) > 8 else "")
        out["items"].append(_work_item(log, case_dir, item, now, "due", f"triage: read {labels}",
                                       list(dict.fromkeys(serves_now)))["call_id"])
    if later:
        labels = ", ".join(c["label"] for c in later[:8]) + (f" and {len(later) - 8} more" if len(later) > 8 else "")
        out["items"].append(_work_item(log, case_dir, item, later, "proposed",
                                       f"triage: read later {labels}", list(dict.fromkeys(serves_later)))["call_id"])
    return out


def _part_lines(case_dir) -> list[str]:
    """One line per open question part: its id and text."""
    try:
        from core.investigation_tasks import ACTIONABLE_STATUSES, load_tasks
        out = []
        for t in load_tasks(case_dir).get("tasks") or []:
            if str(t.get("status") or "open") not in ACTIONABLE_STATUSES:
                continue
            parts = [p for p in t.get("parts") or [] if isinstance(p, dict) and p.get("id")]
            if parts:
                out += [f"- {t['id']}/{p['id']}: {str(p.get('text') or '')[:160]}" for p in parts]
            else:
                out.append(f"- {t['id']}: {str(t.get('text') or '')[:160]}")
        return out[:60]
    except Exception:  # noqa: BLE001
        return []


def _serving_tasks(case_dir):
    """A function from a decision's serves to the task ids it names (an
    existing question or part; coverage and unknown ids name none)."""
    try:
        from core.investigation_tasks import load_tasks
        known = {}
        for t in load_tasks(case_dir).get("tasks") or []:
            tid = str(t.get("id") or "")
            if tid:
                known[tid.casefold()] = tid
                for p in t.get("parts") or []:
                    if isinstance(p, dict) and p.get("id"):
                        known[f"{tid}/{p['id']}".casefold()] = tid
    except Exception:  # noqa: BLE001
        known = {}

    def tasks(serves) -> list[str]:
        out = []
        for x in serves if isinstance(serves, list) else []:
            tid = known.get(re.sub(r"\s+", "", str(x)).replace("#", "/").casefold())
            if tid and tid not in out:
                out.append(tid)
        return out
    return tasks


@_locked
def _mark_refused(case_dir, refused: list[dict[str, Any]]) -> None:
    """Classes whose leave did not hold after the send-back: pending, with
    the refusal kept as their triage record (disclosed as pending)."""
    from core.coverage_ledger import load_ledger, save_ledger
    led = load_ledger(case_dir)
    for c in refused:
        unit = (led.get("classes") or {}).get(c["id"])
        if isinstance(unit, dict) and unit.get("state") == "pending":
            unit["triage_refused"] = str(c.get("_error") or "")[:300]
    save_ledger(case_dir, led)


def triage_pending(log, case_dir, *, ask: Optional[Callable[..., dict]] = None, workers: int = 0,
                   on_start: Optional[Callable[[int], None]] = None, agent: Any = None) -> list[dict]:
    """Survey and triage every pending item with no triage record (the
    beside workers' count of calls at a time); returns the per-item
    outcomes."""
    from concurrent.futures import ThreadPoolExecutor
    from core.coverage_ledger import load_ledger
    from core.evidence_survey import survey_all
    ledger = load_ledger(case_dir)
    done = triaged_items(log, ledger)
    todo = [i for i in (ledger.get("items") or {}).values()
            if isinstance(i, dict) and i.get("state") == "pending" and i["id"] not in done]
    if not todo:
        return []
    if on_start:
        on_start(len(todo))
    surveys = survey_all(case_dir, ledger)
    if agent is not None and triage_items_on():
        return _triage_as_items(log, case_dir, ledger, todo, surveys, agent)

    def one(item):
        user = f"ITEM ID {item['id']}\n" + triage_message(case_dir, ledger, item,
                                                          surveys.get(item["id"], {}).get("text", ""))
        return item, parse_triage(triage_call(TRIAGE_SYS, user, ask))
    from core.frontier_queue import beside_workers
    with ThreadPoolExecutor(max_workers=workers or beside_workers()) as pool:
        replies = list(pool.map(one, todo))
    out = []
    for item, reply in replies:
        led = load_ledger(case_dir)          # each apply sees the dispositions the previous ones wrote
        fresh = (led.get("items") or {}).get(item["id"]) or item
        try:
            out.append({"item": item["id"], **apply_triage(log, case_dir, led, fresh, reply)})
        except Exception as e:  # noqa: BLE001 - re-triaged on a later pass: it has no record yet
            out.append({"item": item["id"], "left": [], "refused": [], "items": [], "error": str(e)[:200]})
    return out


def _triage_as_items(log, case_dir, ledger: dict[str, Any], todo: list[dict], surveys: dict, agent) -> list[dict]:
    """Each pending item through the executor, one at a time (an item's
    calls share the run's per-call path, so items do not run in parallel)."""
    from agent.item_executor import run_item
    from core.coverage_ledger import load_ledger
    out = []
    applied: dict[str, list[dict]] = {}

    def on_submit_for(item):
        def on_submit(args, run, final):
            # Applied as it comes; a leave that does not hold goes back
            # once with its refusal, then its class stays pending.
            led = load_ledger(case_dir)
            fresh = (led.get("items") or {}).get(item["id"]) or item
            last = final or bool(applied.get(item["id"]))
            res = apply_triage(log, case_dir, led, fresh, reply_from_submit(args), final=last)
            applied.setdefault(item["id"], []).append(res)
            if res["refused"] and not last:
                labels = {cid: c.get("label") for cid, c in (led.get("classes") or {}).items() if isinstance(c, dict)}
                return ("These leaves do not hold: " + "; ".join(f"{labels.get(ref, ref)}: {err[:300]}"
                                                                 for ref, err in res["refused"])
                        + ". Decide again for those classes only: read_now, read_later, or left with a kind and "
                          "proof that hold.")
            return None
        return on_submit
    for item in todo:
        spec = triage_spec(case_dir, ledger, item, surveys.get(item["id"], {}).get("text", ""))
        try:
            ran = run_item(agent, spec, turn=getattr(agent, "_turn", 0), on_submit=on_submit_for(item))
        except Exception as e:  # noqa: BLE001
            # The item could not run: logged once per run, and this item is
            # triaged by the one stateless call instead, so it is not tried
            # again on every pass.
            if not getattr(agent, "_triage_item_failed_logged", False):
                agent._triage_item_failed_logged = True
                try:
                    agent._log({"event": "triage_item_failed", "item": item["id"], "error": str(e)[:200]})
                except Exception:  # noqa: BLE001
                    pass
            user = f"ITEM ID {item['id']}\n" + triage_message(case_dir, ledger, item,
                                                              surveys.get(item["id"], {}).get("text", ""))
            led = load_ledger(case_dir)
            fresh = (led.get("items") or {}).get(item["id"]) or item
            out.append({"item": item["id"], "end": "stateless",
                        **apply_triage(log, case_dir, led, fresh, parse_triage(triage_call(TRIAGE_SYS, user)))})
            continue
        try:
            agent._log({"event": "item_run", "kind": "triage", "item": item["id"], "end": ran.end,
                        "rounds": ran.rounds, "calls": ran.calls[:40], "stuck_rounds": ran.stuck_rounds,
                        "off_list": ran.refused_off_list})
        except Exception:  # noqa: BLE001
            pass
        results = applied.get(item["id"]) or []
        if not results:                                      # no submit taken: its classes are read
            led = load_ledger(case_dir)
            fresh = (led.get("items") or {}).get(item["id"]) or item
            results = [apply_triage(log, case_dir, led, fresh, reply_from_submit(None))]
        merged: dict[str, Any] = {"left": [], "refused": [], "items": []}
        for res in results:
            for k in merged:
                merged[k] += list(res.get(k) or [])
        out.append({"item": item["id"], "end": ran.end, **merged})
    return out


def triaged_items(log, ledger: dict[str, Any]) -> set[str]:
    """Items with a triage record: a triage work item, or a disposition
    other than pending on the item or one of its classes. An item whose
    call ran but left no record is triaged again."""
    out: set[str] = {str(r.get("item")) for e in log.work_items() for r in _units_of(e)}
    out |= {str(c.get("item")) for c in (ledger.get("classes") or {}).values()
            if isinstance(c, dict) and c.get("triage_refused")}
    for c in (ledger.get("classes") or {}).values():
        # A class code left (all its files empty) is no triage record.
        if isinstance(c, dict) and c.get("state") != "pending" \
                and not (c.get("state") == "left" and not c.get("reason_kind")):
            out.add(str(c.get("item")))
    out |= {iid for iid, i in (ledger.get("items") or {}).items() if isinstance(i, dict) and i.get("state") != "pending"}
    return out


_SYNC_LOCK = threading.Lock()


def sync_triage(log, case_dir) -> list[int]:
    """Bring triage work items and dispositions together: the evidence's
    reads credit the units (credit_dispositions); a triage item whose
    classes are all read, partly read or left closes (resolved, or
    dismissed when all were left). Returns the ids of the items that
    changed."""
    from core.coverage_ledger import load_ledger
    from core.evidence_disposition import credit_dispositions
    from core.execution_log import _touched
    with _SYNC_LOCK:
        credit_dispositions(case_dir)
        ledger = load_ledger(case_dir)
        classes, items = ledger.get("classes") or {}, ledger.get("items") or {}
        changed = []
        for e in log.work_items():
            refs = _units_of(e)
            if not refs or e.get("status") not in ("due", "proposed"):
                continue
            units = [classes.get(r["class"]) if r.get("class") else items.get(r.get("item")) for r in refs]
            units = [u for u in units if isinstance(u, dict)]
            states = {u.get("state") for u in units}
            if not units or states & {"pending", "relevant", "parsed"}:
                continue
            with log._lock:
                e["status"] = "dismissed" if states == {"left"} else "resolved"
                e["outcome"] = ("its classes were left" if states == {"left"}
                                else "its classes were credited from the reads")
                _touched(e)
                log._index_version += 1
                log._flush()
            changed.append(e["call_id"])
        return changed
