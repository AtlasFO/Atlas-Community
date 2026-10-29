"""The item executor: one work item is one short
conversation, started fresh, on its own short tool list, ending when the
model calls the item's submit tool.

Every tool call goes through the run's per-call path (Agent._call_once):
the memo, work-item closing, the coverage ledger, the repeated-refusal
marking. The item lists its own tools (budget_free), at most a constant
core per kind, a few readers and the submit tool.

Each request is rebuilt, in a fixed order: the system text, the item
text, a digest of the item's earlier calls (code-written: tool,
arguments, rows and first rows, newer calls given more room), the running
note (facts the model noted with item_note, each quote verified against
its call's output), and the last round with its full outputs. Earlier
outputs stay in the trace, citable by call id.

Guards, all behavioural, none a count of the run:
- progress per round is a verified note fact on a row not noted before, or
  what the item's ``progress`` callback says changed (a new claim, a new
  label, anchor or view cell, a record no item of the run was shown
  before: ``ItemRun.shown_rows``); rows returned again are not progress.
  ITEM_PATIENCE rounds without progress end the item with a
  forced submit (the submit tool only, tool choice required): the first
  number before the item's first progress, the second after it;
- when the request reaches the model's context budget the next request is
  the forced submit (end "context_fit");
- a call to a tool off the item's list is refused inside the item.

Two in-item answers: ``item_use_readers`` (offered when the spec has a
readers menu) swaps up to frontier_prompts.MAX_READERS readers into the
list after the core, so the cached prefix stands; ``on_submit(args, run,
final)`` checks a submit and returns a reply that sends the item back to
the model (a refusal it can repair), or None to end it. A forced round's
submit that is refused gets one repair round, also forced; that round's
submit is final, and the round is skipped when its request does not fit
or its call fails. A forced round that brings no submit (a model that
called tools it was not offered) gets one more forced round from the
budget an unreadable submit uses, its calls answered, none run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ItemSpec:
    """One item: its kind, system text, item text, its core tools (names,
    first and constant per kind) and its submit tool (a function schema)."""
    kind: str
    system: str
    user: str
    core_tools: list[str]
    submit: dict[str, Any]
    readers: list[str] = field(default_factory=list)
    menu: list[str] = field(default_factory=list)     # readers item_use_readers may add

    @property
    def submit_name(self) -> str:
        return str(self.submit["function"]["name"])


@dataclass
class ItemRun:
    """What one item did: its submit's arguments (None when it ended
    without one), how it ended, the calls it made, its rounds."""
    submit: Optional[dict[str, Any]]
    end: str
    calls: list[int] = field(default_factory=list)
    ran_calls: list[int] = field(default_factory=list)   # calls this item ran (not replays of earlier ones)
    shown_rows: dict[int, list[str]] = field(default_factory=dict)   # clean call id -> rows it showed
    shown_sources: dict[int, str] = field(default_factory=dict)      # clean call id -> the file those rows are of
    rounds: int = 0
    stuck_rounds: int = 0
    refused_off_list: int = 0
    submits: int = 0
    readers: list[str] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    seen: dict[int, str] = field(default_factory=dict)   # call id -> the result text the model was shown
    notes: list[dict[str, Any]] = field(default_factory=list)   # verified note facts
    unread_entries: list[str] = field(default_factory=list)     # submit entries that were no object, named
    progressed: bool = False
    digest: str = ""


_ASK_SUBMIT = "Call {name} now with what you have found, to end this item."
_ONLY_SUBMIT = "not run: only {name} is offered in this round; call it now with what you have found."
_OFF_LIST = ("{tool} is not on this item's list ({tools}); use one of them, or call {submit} to end the item.")
NOTE_TOOL = "item_note"
NOTE_SCHEMA = {"type": "function", "function": {
    "name": NOTE_TOOL,
    "description": ("Keep facts for the rest of this item: each with the call id and a quote copied from that "
                    "call's output (for a numbered row, its #n first); a quote not in it is dropped. Earlier outputs leave the conversation; the "
                    "note and a digest of them stay. A fact noted on a row not noted before counts as this "
                    "item's progress, as a record shown for the first time does."),
    "parameters": {"type": "object", "properties": {"add": {"type": "array", "items": {
        "type": "object", "properties": {"fact": {"type": "string"}, "call_id": {"type": "integer"},
                                         "quote": {"type": "string"}},
        "required": ["fact", "call_id", "quote"]}}}, "required": ["add"]}}}
# Rounds without progress an item may take: before its first progress, and
# after it. In the run these numbers come from, rounds without progress
# before a productive round had a median of 1 and a 75th percentile of 2;
# 6 and 3 leave room above that. Raise them if a probe or a run shows
# productive work cut; ATLAS_ITEM_PATIENCE overrides ("6,3").
ITEM_PATIENCE = (6, 3)
# The share of the model's window the digest of earlier calls may take.
DIGEST_SHARE = 0.25


def patience() -> tuple[int, int]:
    import os
    raw = str(os.environ.get("ATLAS_ITEM_PATIENCE") or "").replace(" ", "")
    try:
        before, after = (int(x) for x in raw.split(",", 1))
        return max(1, before), max(1, after)
    except ValueError:
        return ITEM_PATIENCE


def _chars(messages: list[dict]) -> int:
    return sum(len(str(m.get("content") or "")) + len(json.dumps(m.get("tool_calls") or [])) for m in messages)


def _budget() -> int:
    from agent.loop import context_char_budget
    return context_char_budget()


def _tools(agent, spec: ItemSpec, readers: list[str], note: bool) -> list[dict]:
    from core.frontier_prompts import USE_READERS_SCHEMA
    names = list(dict.fromkeys([*spec.core_tools, *readers]))
    return (agent.toolbox.schemas_for(names) + ([USE_READERS_SCHEMA] if spec.menu else [])
            + ([NOTE_SCHEMA] if note else []) + [spec.submit])


def _rows_of(result: str) -> tuple[int, list[str], bool]:
    """(row count, the rows as lines, whether the output holds rows) of a
    rendered tool result."""
    try:
        data = json.loads(result[result.index("{"):result.rindex("}") + 1])
    except ValueError:
        data = None
    if isinstance(data, dict):
        for k in ("rows", "hits", "matches", "results"):
            if isinstance(data.get(k), list):
                return len(data[k]), [r if isinstance(r, str) else json.dumps(r, default=str) for r in data[k]], True
    lines = [ln for ln in str(result or "").splitlines() if ln.strip()]
    return len(lines), lines, False


def digest(calls: list[dict[str, Any]], budget: int) -> tuple[str, set[int]]:
    """The code-written digest of earlier calls: per call its id, tool,
    arguments, row count and first rows, newer calls given more room
    (weights rising with recency) within ``budget`` characters. Returns the
    text and the call ids whose rows were cut."""
    if not calls:
        return "", set()
    weights = list(range(1, len(calls) + 1))
    total = sum(weights)
    lines, cut = ["EARLIER CALLS OF THIS ITEM (a digest; each call id stays citable, and repeating a call is "
                  "free):"], set()
    for c, w in zip(calls, weights):
        room = max(300, budget * w // total)
        n, rows, _structured = _rows_of(c["result"])
        head = f"- call {c['call_id'] or '?'} {c['tool']} {json.dumps(c['args'], default=str)[:200]}: {n} row(s)"
        body, used = [], len(head)
        for r in rows:
            if used + len(r) + 4 > room:
                cut.add(int(c["call_id"] or 0))
                body.append(f"    ... {n - len(body)} more")
                break
            body.append(f"    {r}")
            used += len(r) + 5
        lines += [head, *body]
    return "\n".join(lines), cut


def run_item(agent, spec: ItemSpec, *, role: str = "analyst", turn: int = 0,
             on_submit: Optional[Callable[[dict, "ItemRun", bool], Optional[str]]] = None,
             progress: Optional[Callable[["ItemRun"], Any]] = None,
             verify_note: Optional[Callable[[int, str, "ItemRun"], Optional[str]]] = None,
             on_empty: Optional[Callable[["ItemRun"], str]] = None) -> ItemRun:
    """Run one item to its submit (or a forced one). ``progress(run)``
    returns a token of the state the item itself changed; a round
    progresses when its token is one this item has not seen before (a state
    flipped back and forth counts once). Without it a round that ran a call
    counts. ``verify_note``
    gives a quote's row reference in its call's output (None to drop it);
    without it the item has no note tool. ``on_empty(run)`` gives the line
    the request after a round without progress carries (a behaviour signal
    the model can act on, never a count it is cut by)."""
    from core.frontier_prompts import USE_READERS, pick_readers
    readers = list(spec.readers)
    note_on = verify_note is not None
    tools = _tools(agent, spec, readers, note_on)
    allowed = {t["function"]["name"] for t in tools}
    run = ItemRun(submit=None, end="")
    before_first, after_first = patience()
    empty = 0
    earlier: list[dict[str, Any]] = []       # the calls of rounds before the last
    last: list[dict] = []                    # the last round: assistant message, tool replies, asks
    last_calls: list[dict[str, Any]] = []
    noted: set[tuple[int, str]] = set()
    seen_tokens: set = set()
    reread: set[int] = set()                  # call ids whose cut output was re-read once
    budget = _budget()
    repairing = False                         # an extra forced round after a forced submit is running
    # Two one-round budgets per item after a forced submit: one to read a
    # submit that could not be read, one to repair a read submit's refusal.
    read_repair_used = refusal_repair_used = False
    last_empty = False                        # the round before made no progress
    while True:
        cut: set[int] = set()
        messages = [{"role": "system", "content": spec.system}, {"role": "user", "content": spec.user}]
        if earlier:
            text, cut = digest(earlier, int(budget * DIGEST_SHARE))
            messages.append({"role": "user", "content": text})
        if run.notes:
            messages.append({"role": "user", "content": "YOUR NOTE (verified facts):\n" + "\n".join(
                f"- {n['fact']} [call {n['call_id']}, {n['row_ref']}]" for n in run.notes)})
        messages += last
        fit = _chars(messages) >= budget
        if repairing and fit:
            # The repair request does not fit: the forced submit stays final,
            # as it was before the repair round existed.
            run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
            return run
        limit = after_first if run.progressed else before_first
        forced = empty >= limit or fit or repairing
        if forced:
            # Said in words too: a provider that refuses a forced tool choice
            # still reads the instruction.
            messages.append({"role": "user", "content": _ASK_SUBMIT.format(name=spec.submit_name)})
        if last_empty and not forced and on_empty is not None:
            line = on_empty(run)
            if line:
                messages.append({"role": "user", "content": line})
        sent = [spec.submit] if forced else tools
        if progress is not None:
            seen_tokens.add(progress(run))
        try:
            resp = agent.client.chat(messages, tools=sent, role=role, tool_choice="required" if forced else None)
        except Exception:
            if not repairing:
                raise
            # The repair round's call failed: the item ends as its forced
            # round did; the caller closes what is still refused.
            run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
            return run
        run.rounds += 1
        tin, tout = int(getattr(resp, "input_tokens", 0) or 0), int(getattr(resp, "output_tokens", 0) or 0)
        run.input_tokens += tin
        run.output_tokens += tout
        try:
            # One record per model call, so a run's calls can be counted and
            # sized whichever loop made them.
            agent._log({"event": "item_call", "kind": spec.kind, "round": run.rounds, "tools": len(sent),
                        "forced": forced, "input_tokens": tin, "output_tokens": tout})
        except Exception:  # noqa: BLE001
            pass
        refusal = getattr(resp, "refusal", None)
        if refusal is not None:
            # Declined by the provider: the item ends here, never asked again
            # as a round without progress.
            agent._log({"event": "model_refusal", "kind": spec.kind, "round": run.rounds,
                        "category": refusal.get("category"), "explanation": refusal.get("explanation")})
            run.end = "declined"
            run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
            return run
        calls = list(resp.tool_calls or [])
        msg: dict[str, Any] = {"role": "assistant", "content": resp.content or ""}
        if calls:
            msg["tool_calls"] = [{"id": tc.id, "type": "function",
                                  "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                                 for tc in calls]
        earlier += last_calls
        last, last_calls = [msg], []
        progressed = False
        neutral = False
        submitted = next((tc for tc in calls if tc.name == spec.submit_name), None)
        if submitted is not None:
            args, unread, named = read_submit(spec, submitted.arguments, log=agent._log)
            run.submits += 1
            if not repairing:                  # a repair keeps the forced round's end
                run.end = "context_fit" if fit else ("forced" if forced else "submitted")
            elif run.end == "stuck":           # the retry of a forced round that brought no submit
                run.end = "forced"
            if unread:
                # Not read: told, never dropped. run.submit keeps the last
                # submit that was read, so no caller iterates an unread string.
                reply = unread
            else:
                run.submit = args
                reply = on_submit(run.submit, run, forced) if on_submit is not None else None
                if named:
                    # The entries that were no object are named, never dropped
                    # in silence: in the reply when the item goes on, in the
                    # item's record when it ends.
                    run.unread_entries += named
                    if reply is not None:
                        reply = f"{reply} Also not read: {'; '.join(named)}."
            if reply is None:
                run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
                return run
            if forced:
                # A forced submit answered with a reply gets one more forced
                # round from the budget it needs: an unread submit the read
                # budget (then the refusal budget), a read and refused one the
                # refusal budget. Both spent, the item ends: at most two extra
                # rounds per item.
                if unread and not read_repair_used:
                    read_repair_used = True
                elif not refusal_repair_used:
                    refusal_repair_used = True
                else:
                    run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
                    return run
                repairing = True
            # The submit is answered inside the item (a refusal to repair, or
            # a partial submit recorded): every call of the round gets its
            # reply, the submit's says what was taken.
            for tc in calls:
                last.append({"role": "tool", "tool_call_id": tc.id, "content": reply if tc is submitted else
                             "not run: a submit ends the round; call it again if still needed"})
        elif forced:
            # A forced round that yields no submit: none of its calls runs.
            # It gets one more forced round from the read budget (the submit
            # did not arrive, as with one that could not be read), each call
            # answered that only the submit is offered; never the refusal
            # budget, which stays for a submit the gates refuse. Spent, the
            # item ends. A repair round without a submit keeps its end.
            if not repairing:
                run.end = "context_fit" if fit else "stuck"
            if read_repair_used:
                run.digest = digest(earlier, int(budget * DIGEST_SHARE))[0]
                return run
            read_repair_used = repairing = True
            for tc in calls:
                last.append({"role": "tool", "tool_call_id": tc.id,
                             "content": _ONLY_SUBMIT.format(name=spec.submit_name)})
        elif not calls:
            last.append({"role": "user", "content": _ASK_SUBMIT.format(name=spec.submit_name)})
        else:
            ran_new, rereads = False, []
            for tc in calls:
                cid = 0
                if tc.name == USE_READERS and spec.menu:
                    from core.frontier_prompts import USE_READERS_SCHEMA
                    rargs, result, _named = read_local(USE_READERS, USE_READERS_SCHEMA["function"]["parameters"],
                                                       tc.arguments)
                    picked = []
                    if not result:
                        picked, result = pick_readers(rargs.get("names"), set(spec.menu))
                    if picked and picked != readers:
                        readers = picked                       # a swap: the core stays first
                        tools = _tools(agent, spec, readers, note_on)
                        allowed = {t["function"]["name"] for t in tools}
                        run.readers = list(readers)
                        ran_new = True
                elif tc.name == NOTE_TOOL and note_on:
                    kept, dropped = 0, 0
                    nargs, unread, named = read_local(NOTE_TOOL, NOTE_SCHEMA["function"]["parameters"], tc.arguments)
                    for f in nargs.get("add") or []:
                        try:
                            ncid = int(f.get("call_id"))
                        except (TypeError, ValueError):
                            dropped += 1
                            continue
                        row = verify_note(ncid, str(f.get("quote") or ""), run)
                        if not row:
                            dropped += 1
                            continue
                        if (ncid, row) not in noted:
                            noted.add((ncid, row))
                            run.notes.append({"fact": str(f.get("fact") or "")[:400], "call_id": ncid,
                                              "row_ref": row})
                            progressed = True
                        kept += 1
                    result = unread or (f"noted {kept}"
                                        + (f"; dropped {dropped}: a quote not in its call's output" if dropped else "")
                                        + (f"; not noted: {'; '.join(named)}" if named else ""))
                elif tc.name not in allowed:
                    run.refused_off_list += 1
                    result = _OFF_LIST.format(tool=tc.name, tools=", ".join(sorted(allowed - {spec.submit_name})),
                                              submit=spec.submit_name)
                else:
                    out = agent._call_once(tc.name, tc.arguments or {}, turn=turn, tool_call_id=tc.id,
                                           in_context=lambda _id: False, budget_free=True)
                    result = out["result"]
                    if out["kind"] == "ran" and "REPEATED REFUSAL" not in result[:400]:
                        ran_new = True
                    cid = _call_id(result)
                    if out["kind"] in ("replayed", "pointer"):
                        rereads.append(cid)
                    if cid:
                        run.calls.append(cid)
                        if out["kind"] == "ran":
                            run.ran_calls.append(cid)
                            if out.get("ran_clean") and out.get("shown_rows"):
                                run.shown_rows[cid] = list(out["shown_rows"])
                                if out.get("shown_source"):
                                    run.shown_sources[cid] = str(out["shown_source"])
                        run.seen[cid] = result
                last.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                if tc.name not in (USE_READERS, NOTE_TOOL):
                    last_calls.append({"call_id": cid, "tool": tc.name, "args": tc.arguments or {},
                                       "result": result})
            if progress is None and ran_new:
                progressed = True
            # A re-read of an output the digest shows cut is no empty round,
            # the first time per call: a second re-read of it is one.
            neutral = bool(rereads) and all(c in cut and c not in reread for c in rereads)
            reread |= {c for c in rereads if c in cut}
        if progress is not None:
            token = progress(run)
            if token not in seen_tokens:
                progressed = True
                seen_tokens.add(token)
        last_empty = not progressed and not neutral
        if progressed:
            run.progressed = True
            empty = 0
        elif not neutral:
            empty += 1
            run.stuck_rounds += 1


def read_submit(spec: ItemSpec, raw: Any,
                log: Optional[Callable[[dict], Any]] = None) -> tuple[dict[str, Any], str, list[str]]:
    """The submit's arguments through read_local: a submit whose object
    lists hold no object at all is not read (nothing of it can be applied)."""
    return read_local(spec.submit_name, (spec.submit.get("function") or {}).get("parameters") or {}, raw, log,
                      kind=spec.kind, whole=True)


def _object_elements(args: dict[str, Any], schema: dict[str, Any]) -> tuple[list[str], bool]:
    """Each array field whose items the schema declares as objects, read
    element by element: a JSON string of an object is that object; any
    other element is taken out and named by its place (from 1), its type
    and the object's fields. (the names, whether an object is left in any
    such field or given as an object field)."""
    from core.tool_arg_coerce import _schema_types
    named: list[str] = []
    held = False
    for key, prop in (schema.get("properties") or {}).items():
        if not isinstance(prop, dict) or key not in args:
            continue
        value = args[key]
        if "object" in _schema_types(prop) and isinstance(value, dict):
            held = True
        items = prop.get("items") if isinstance(prop.get("items"), dict) else {}
        if not isinstance(value, list) or "object" not in _schema_types(items):
            continue
        fields = ", ".join((items.get("properties") or {}).keys())
        kept = []
        for i, el in enumerate(value, 1):
            if isinstance(el, str) and el.lstrip()[:1] == "{":
                try:
                    decoded = json.loads(el)
                except ValueError:
                    decoded = None
                el = decoded if isinstance(decoded, dict) else el
            if isinstance(el, dict):
                kept.append(el)
                continue
            shown = " ".join(str(el).split())[:60]
            named.append(f"{key} item {i} came as {type(el).__name__} ({shown!r}): send it as an object"
                         + (f" with {fields}" if fields else ""))
        args[key] = kept
        held = held or bool(kept)
    return named, held


def read_local(name: str, schema: dict[str, Any], raw: Any, log: Optional[Callable[[dict], Any]] = None,
               kind: str = "", whole: bool = False) -> tuple[dict[str, Any], str, list[str]]:
    """The arguments of a tool the item answers itself (its submit,
    item_note, item_use_readers) as the tool's schema declares them
    (core.tool_arg_coerce, the coercion the MCP path uses: a list sent as a
    JSON string, nested fields too): (the arguments, why they could not be
    read, "" when they were; the elements taken out of object lists, each
    named). Not read: arguments that are no JSON at all, or a field that is
    still not the array or object its schema declares. An element of an
    object list that is no object is taken out and named, never the whole
    call refused for it; ``whole`` (the submit): not read when no object is
    left at all. No argument shape a model sends ever raises here."""
    from core.tool_arg_coerce import _schema_types, coerce_tool_arguments
    args = dict(raw or {}) if isinstance(raw, dict) else {}
    what = "submit" if whole else "call"
    if args.get("_not_object"):
        return {}, (f"not read: the arguments of {name} must be a JSON object; got {args['_not_object']}. "
                    f"Resubmit {name} with an object of its fields."), []
    if "_malformed_arguments" in args:
        longest = str(args.get("_longest_argument") or "")
        return {}, (f"not read: the arguments of {name} are not valid JSON (cut or broken)"
                    + (f"; {longest} took most of them: shorten it" if longest else "")
                    + f". Resubmit {name} with valid JSON arguments."), []
    declared = set((schema.get("properties") or {}).keys())
    if args and declared and not (set(args) & declared):
        # The whole submit wrapped in one string under a key of its own (a
        # transport wrapper or the model's): that string, when it is an
        # object holding this submit's fields, is the submit. Never keyed on
        # the wrapper's name.
        inner = None
        if len(args) == 1:
            (key, value), = args.items()
            if isinstance(value, str):
                try:
                    inner = json.loads(value)
                except ValueError:
                    inner = None
                if isinstance(inner, dict) and set(inner) & declared:
                    if log is not None:
                        try:
                            log({"event": "item_submit_unwrapped", "kind": kind, "key": key,
                                 "chars": len(value)})
                        except Exception:  # noqa: BLE001
                            pass
                    args = inner
                else:
                    inner = None
    given = sorted(args)
    args, _notes = coerce_tool_arguments(args, schema)
    if given and declared and not (set(args) & declared):
        # Keys given, none of them this submit's (after a guessed name is
        # renamed): told, never read as an empty submit.
        return {}, (f"not read: none of {name}'s fields were given (got: {', '.join(given)[:200]}). "
                    f"Resubmit {name} with its fields: {', '.join(sorted(declared))}."), []
    wrong = []
    for key, prop in (schema.get("properties") or {}).items():
        if key not in args or args[key] is None or not isinstance(prop, dict):
            continue                                   # absent or null: nothing given
        types, value = _schema_types(prop), args[key]
        if ({"array", "object"} & types and not (("array" in types and isinstance(value, list))
                                                  or ("object" in types and isinstance(value, dict)))
                and not (isinstance(value, str) and "string" in types)):
            want = " or ".join(t for t in ("array", "object") if t in types)
            shown = " ".join(str(value).split())[:80]
            wrong.append(f"{key} must be an {want}; it came as {type(value).__name__} ({shown!r})"
                         + _tail_diagnosis(key, value, types, declared))
    if wrong:
        return {}, (f"not read: {'; '.join(wrong)}. Nothing of this {what} was applied. "
                    + (f"Resubmit {name}" if whole else f"Call {name} again")
                    + " with those fields in their declared types."), []
    named, held = _object_elements(args, schema)
    if whole and named and not held:
        return {}, (f"not read: {'; '.join(named)}. Nothing of this submit was applied: none of it is an object. "
                    f"Resubmit {name} with each entry as an object."), []
    return args, "", named


def _tail_diagnosis(key: str, value: Any, types: set, declared: set) -> str:
    """What a string field holds when it starts with a complete value of
    its declared type and goes on: the value's size, the rest's length and
    the submit's own fields named in the rest. A diagnosis only: nothing of
    it is applied (the rest may carry the labels that decide what the
    leading value means)."""
    import re as _re
    if not isinstance(value, str):
        return ""
    text = value.lstrip()
    try:
        lead, end = json.JSONDecoder().raw_decode(text)
    except ValueError:
        return ""
    if not (("array" in types and isinstance(lead, list)) or ("object" in types and isinstance(lead, dict))):
        return ""
    tail = text[end:].strip()
    if not tail:
        return ""
    named = [k for k in dict.fromkeys(_re.findall(r'"(\w+)"\s*:', tail)) if k in declared and k != key]
    size = f"{len(lead)} item(s)" if isinstance(lead, list) else f"{len(lead)} field(s)"
    return (f"; it holds a complete {type(lead).__name__} of {size} followed by {len(tail)} characters of other "
            f"content" + (f" ({', '.join(named)} written inside {key})" if named else "")
            + ": send each field as its own argument")


def _call_id(result: str) -> int:
    """The trace call id a tool result carries, 0 when none."""
    try:
        from core.call_memo import trace_call_id_of
        v = trace_call_id_of(result)
        return int(v) if str(v or "").isdigit() else 0
    except Exception:  # noqa: BLE001
        return 0
