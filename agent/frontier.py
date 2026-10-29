"""The frontier run (ATLAS_LOOP=frontier): the work order as a queue of
short items, each one fresh conversation through the item executor, and
code that records what an item's submit carries.

``SubmitApplier`` is the code side of one item's submit, in this order:
1. basis check: a cited call must be the item's own or one its item names;
   a quote of a numbered view resolves to the line the model read and,
   through that line's "#n", to its saved row (m.marker_rows); any other
   quote becomes the incident map's row reference (m.row_ref_for); a quote
   the call's output does not hold drops that basis entry;
2. a label on an entity a finding names becomes that finding's typed row
   (side and attacker_from), so one submit never writes a typed row and a
   contradicting map label for the same entity;
3. findings go through the run's per-call path as misc.record_finding
   (every record gate runs); a first refusal goes back into the item, the
   same finding refused again is not recorded, the labels and events that
   rest on it are written unknown with the gate's note, and a followup item
   carries the refusal;
4. a finding from a view row or a plan item is linked to its question
   (investigation_tasks.update_task) by code;
5. other labels, events and observations go to the map one by one; a label
   no finding carries is a proposal there;
6. leads and synthesis proposals pass question_plan.validate_read and
   become plan items; contradictions become followup items;
7. a view row item's ``examined`` limits its part when the row is the
   part's only open one, else it is kept as an observation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

# Map entity kind to a finding's typed-row side and type. Sides follow the
# record path's vocabulary; "benign" is the owner's own (victim) side.
_SIDE = {"attacker": "attacker", "benign": "victim", "unknown": "undetermined"}
_TIER = {"confirmed": "CONFIRMED", "likely": "LIKELY", "possible": "SUSPECTED"}
_RECORD = "misc.record_finding"


def _parse(result: str) -> dict[str, Any]:
    """The JSON object a rendered tool result carries ({} when none)."""
    s = str(result or "")
    a, b = s.find("{"), s.rfind("}")
    if a < 0 or b <= a:
        return {}
    try:
        d = json.loads(s[a:b + 1])
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _row_type(kind: str, value: str) -> str:
    """A map entity's kind as a typed row's type (the shape of the value
    decides between the forms one kind takes: a path or a bare name, an
    address, a URL or a domain)."""
    if kind == "file":
        return "path" if ("\\" in value or "/" in value) else "file"
    if kind == "endpoint":
        if "://" in value:
            return "url"
        try:
            ipaddress.ip_address(value.split("%", 1)[0])
            return "ip"
        except ValueError:
            return "domain"
    return kind if kind in ("host", "account") else "pattern"


def _ref_key(ref: Any) -> tuple[str, str] | None:
    if not isinstance(ref, dict) or not str(ref.get("value") or "").strip():
        return None
    return str(ref.get("kind") or ""), " ".join(str(ref["value"]).split()).casefold()


def _fold(text: str) -> str:
    return " ".join(str(text or "").split()).lower()


_VIEW_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?\S*$")
_CLIP_RE = re.compile(r"\u2026|\.\.\.")


# Lines Atlas adds to a tool's output (bracketed notes, and the keys of its
# own annotations: notes, hints, gate texts, errors): never evidence a
# quote may stand on. Atlas's own wiring, no evidence vocabulary.
_ANNOTATION_RE = re.compile(r'^\s*(?:\[.*\]\s*$|"?(?:notes?|hints?|repair_hint|gate|error|warning|advisory|'
                            r'refusal|instruction)"?\s*[:=])', re.IGNORECASE)


def _norm(text: str) -> str:
    """Folded, with JSON's escaped backslash read as one: the rendered view
    is JSON text, the saved row its values."""
    return _fold(str(text or "")).replace("\\\\", "\\")


_COMMON_KEY = '"same_in_every_returned_row"'


def _words(text: str) -> str:
    """A text's words alone (quotes, braces and separators dropped), folded:
    a named line compared with the line it names."""
    return " ".join(re.sub(r"[{}\[\]\"':,|]", " ", _norm(text)).split())


def _view_quote(quote: str) -> str:
    """A quote of a rendered row as the shown text holds it: with or
    without the row's "#n " marker, its own trailing clip mark dropped."""
    q = _norm(quote).strip().strip(",").strip('"')
    q = re.sub(r"^#\d+\s+", "", q)
    return re.sub(r"(?:\u2026|\.\.\.)\s*$", "", q).strip()


def _common_line(shown: str) -> str:
    return next((ln for ln in str(shown or "").splitlines() if ln.lstrip().startswith(_COMMON_KEY)), "")


def _common_cells(shown: str) -> list[str]:
    """The values of the view's line of cells every returned row shares."""
    line = _common_line(shown)
    try:
        body = json.loads(line.split(":", 1)[1].strip().rstrip(","))
    except (ValueError, IndexError):
        return []
    return [str(v).rstrip("\u2026") for v in body.values() if str(v).strip()] if isinstance(body, dict) else []


def _shown_evidence(text: str) -> str:
    """The shown result without the lines Atlas added to it."""
    return "\n".join(line for line in str(text or "").splitlines() if not _ANNOTATION_RE.match(line))


def _cells(quote: str) -> list[str]:
    """The cell values of a quoted line of a rendered table view, as the
    saved row holds them: split at the column separator, the view's row
    marker dropped, the view's own renderings left out (its normalised
    time, the "-" of an empty cell), a clipped cell by its longest piece."""
    text = str(quote or "").strip().strip(",").strip('"').replace("\\\\", "\\")
    parts = [p.strip() for p in re.split(r"\s*\|\s*", text) if p.strip()]
    if parts:
        parts[0] = re.sub(r"^#\d+\s*", "", parts[0]).strip()
    out = []
    for p in parts:
        piece = max(_CLIP_RE.split(p), key=len).strip()
        if piece and piece != "-" and not _VIEW_TIME_RE.match(piece):
            out.append(piece)
    # Too little to name one row: one short cell matches many.
    return out if len(out) >= 2 or any(len(c) >= 4 for c in out) else []


# A refusal as an item reads it (_item_refusal): the headline, the
# evaluator's reason, and every further objection named.
_REFUSAL_CHARS = 1800
# Entries per list in one frontier_submit record (findings, labels, events);
# past it the record says how many more there were.
_TRAIL_MAX = 60
_EVAL_GATE = "confirmed_requires_supported_evaluate"


def _first_sentence(text: Any, limit: int) -> str:
    """The text up to its first sentence end, within ``limit``."""
    t = " ".join(str(text or "").split())
    m = re.search(r"(?<=[.;])\s", t)
    t = t[:m.start()] if m and m.start() > 40 else t
    return _cut(t, limit)


def _cut(text: Any, limit: int) -> str:
    """The one cut rule (core.text_bounds.cut): never inside a word."""
    from core.text_bounds import cut
    return cut(text, limit)


def _said(f: dict[str, Any]) -> str:
    """A finding's statement as its identity: spacing and case folded."""
    return " ".join(str(f.get("statement") or "").split()).casefold()


def _bears_set(f: dict[str, Any]) -> set[str]:
    return {re.sub(r"\s+", "", str(b)).casefold() for b in f.get("bears_on") or [] if str(b).strip()}


def _item_refusal(d: dict[str, Any]) -> str:
    """record_finding's refusal for an item model, within _REFUSAL_CHARS:
    never an objection dropped (each further gate keeps its name and first
    sentence; the room is shared before joining, nothing is cut after), the
    headline kept whole while there is room (its repair instruction often
    sits after the first sentence) and shortened only by what the list
    needs, a challenging evaluator's reason carried, and the item's own
    paths instead of a tool the item does not list (the evaluation runs
    when a finding is recorded)."""
    others = [o for o in d.get("also_refused_by") or [] if isinstance(o, dict)]
    detail = str(d.get("detail_gate") or d.get("gate") or "")
    head = str(d.get("error") or "").split(" ALSO REFUSED BY", 1)[0]
    ev = d.get("evaluation") if isinstance(d.get("evaluation"), dict) else {}
    verdict = str(d.get("evaluate_verdict") or ev.get("verdict") or "").upper()
    reason = _cut(ev.get("text") or d.get("evidence") or "", 400)
    if detail == _EVAL_GATE and ev.get("error"):
        # It ran and failed: said as that, never as an evaluation still to run.
        head = (f"the evaluation it needs at CONFIRMED could not run ({_cut(ev['error'], 200)})"
                + (f"; it answered: {reason}" if reason else "")
                + "; state only what the rows show at a lower tier, or resubmit it")
    elif detail == _EVAL_GATE and verdict in ("CHALLENGED", "UNCERTAIN"):
        head = (f"an evaluator answered {verdict} for it at CONFIRMED" + (f" ({reason})" if reason else "")
                + "; cite rows that show the whole statement, state only what the rows show, or lower the tier")
    elif detail == _EVAL_GATE and ev and verdict != "SUPPORTED":
        head = ("the evaluation answered without a verdict line" + (f" ({reason})" if reason else "")
                + "; cite rows that show the whole statement, state only what the rows show, or lower the tier")
    elif detail == _EVAL_GATE:
        head = ("CONFIRMED needs a SUPPORTED evaluation, which runs when the finding is recorded"
                + (" and did not run because the further objection(s) stand: fix them" if others else "")
                + "; or state only what the rows show, or lower the tier")
    names = [str(o.get("detail_gate") or o.get("gate") or "") for o in others]
    texts = [("CONFIRMED needs a SUPPORTED evaluation, which runs on record once the rest is fixed" if g == _EVAL_GATE
              else " ".join(str(o.get("error") or "").split())) for g, o in zip(names, others)]
    sep = "; "
    # The room each further objection gets: its name always, its first
    # sentence within an equal share of what the headline's floor leaves.
    head_floor = min(len(head), 300)
    share = max(0, (_REFUSAL_CHARS - head_floor - len(sep) * len(others)) // max(1, len(others)))
    lines = []
    for g, t in zip(names, texts):
        label = f"also [{g}] "
        lines.append(label + _first_sentence(t, max(1, min(300, share - len(label)))) if share > len(label)
                     else label.rstrip())
    room = _REFUSAL_CHARS - sum(len(x) + len(sep) for x in lines)
    return sep.join([_cut(head, max(1, room))] + lines)


# A collapsed line of a rendered table view: "#a-#b xN ..." stands for N rows.
_COLLAPSED_RE = re.compile(r"^#\d+(?:-#\d+|(?:,#\d+)+)\s+x(\d+)\b")
# Its parts: the ordinals (a range or a list), the count, the first and last time.
_COLLAPSED_PARTS_RE = re.compile(r"^#(\d+)(?:-#(\d+)|((?:,#\d+)+))\s+x(\d+)\s+"
                                 r"(\d{4}-\d{2}-\d{2}[ T][\d:.]+Z?)\s+\.\.\s+(\d{4}-\d{2}-\d{2}[ T][\d:.]+Z?)")


def _collapsed_parts(quote: str) -> tuple[list[int], int, str, str] | None:
    """(ordinals, count, first time, last time) of a quoted collapsed line;
    None when the quote is not one or its count disagrees with its ordinals."""
    m = _COLLAPSED_PARTS_RE.match(str(quote or "").strip().strip('"'))
    if not m:
        return None
    a = int(m.group(1))
    ords = list(range(a, int(m.group(2)) + 1)) if m.group(2) else [a] + [int(x) for x in re.findall(r"\d+", m.group(3))]
    n = int(m.group(4))
    return (ords, n, m.group(5), m.group(6)) if len(ords) == n else None


def _view_rows(shown: str) -> list[str] | None:
    """The row lines of a rendered view (its "rows" list), decoded; None
    when the shown text is no view. A note before the view (a replay's)
    is not part of it."""
    s = str(shown or "")
    try:
        data = json.loads(s[s.index("{"):s.rindex("}") + 1])
    except ValueError:
        return None
    rows = data.get("rows") if isinstance(data, dict) else None
    return [str(r) for r in rows] if isinstance(rows, list) else None


# A quote's (or a view line's) row marker: "#n" for one row, never a
# collapsed line's "#a-#b".
_MARKER_RE = re.compile(r"^#(\d+)(?=\s|$)")


def _pieces(quote: str) -> tuple[str, list[str]]:
    """(the row marker a quote starts with, "" when none; the quote's
    pieces): its cells at the view's column separator, each cut where the
    view clipped it or the model left a part out ("…", "..."), with a
    quote's wrapping, a list comma and the "-" of an empty cell dropped."""
    q = str(quote or "").strip().strip(",").strip().strip('"').strip()
    m = _MARKER_RE.match(q)
    q = q[m.end():] if m else q
    out: list[str] = []
    for cell in re.split(r"\s*\|\s*", q):
        out += [p.strip().strip(",").strip() for p in _CLIP_RE.split(cell)]
    return (m.group(1) if m else ""), [p for p in out if p and p != "-"]


def _unslashed(text: str) -> str:
    """A text with each run of backslashes read as one and the backslash
    before a quote dropped: the forms escaping gives one text (a model that
    copies the escaped result into its JSON arguments halves each run)."""
    return re.sub(r'\\(?=")', "", re.sub(r"\\{2,}", lambda m: "\\", str(text or "")))


def _held(piece: str, line: str) -> bool:
    """A quote's piece is in a view line in any form the model was shown
    the line: decoded (the item's digest) or JSON-escaped (the round's
    result text: a backslash doubled, a quote escaped), however many
    backslashes its copy kept; case and whitespace folded."""
    p = _fold(_unslashed(piece))
    return bool(p) and (p in _fold(_unslashed(line))
                        or p in _fold(_unslashed(json.dumps(line, ensure_ascii=False)[1:-1])))


def _view_header(shown: str) -> str:
    """A rendered view without its row lines: its counts, shared line,
    distribution and notes."""
    s = str(shown or "")
    try:
        data = json.loads(s[s.index("{"):s.rindex("}") + 1])
    except ValueError:
        return ""
    return json.dumps({k: v for k, v in data.items() if k != "rows"}, ensure_ascii=False) \
        if isinstance(data, dict) else ""


def _view_shared(shown: str) -> tuple[dict[str, str], set[str]]:
    """(the cells every returned row of a view shares, as the view shows
    them; the view's column names, the shared ones included): the shared
    cells belong to every shown row, a row is its line and them."""
    s = str(shown or "")
    try:
        data = json.loads(s[s.index("{"):s.rindex("}") + 1])
    except ValueError:
        return {}, set()
    if not isinstance(data, dict):
        return {}, set()
    same = data.get(_COMMON_KEY.strip('"'))
    shared = {str(k): str(v) for k, v in same.items()} if isinstance(same, dict) else {}
    cols = {c.strip() for c in re.split(r"\s*\|\s*|/", str(data.get("columns") or "")) if c.strip()}
    return shared, (cols | set(shared)) - {"time"}


class _Part(str):
    """A quote's part; ``column``: the shared column a "<column> <value>"
    piece named, whose cell alone can hold it."""
    column: str = ""


def _parts(pieces: list[str], keys: set[str], shared: dict[str, str] | None = None) -> list[str]:
    """The evidence a quote's pieces carry: a "<column> <value>" piece (a
    space, ":" or "=" between) by its value, bound to that column when it
    is a shared one. A column name alone, or one with a value shorter than
    four characters, carries none and is left out: a name is no evidence."""
    out = []
    names = sorted(keys, key=len, reverse=True)
    for p in pieces:
        low = _fold(p)
        k = next((k for k in names if low == _fold(k) or re.match(re.escape(_fold(k)) + r"\s*[:=\s]", low)), None)
        if k is None:
            out.append(_Part(p))
            continue
        rest = p.strip()[len(k):].lstrip(" :=").strip()
        if len(rest) >= 4:
            part = _Part(rest)
            part.column = k if k in (shared or {}) else ""
            out.append(part)
    return out


def _on_line(part: str, line: str) -> bool:
    """A part is on the line itself: never one bound to a shared column."""
    return not getattr(part, "column", "") and _held(part, line)


def _held_row(part: str, line: str, shared: dict[str, str]) -> bool:
    """A quote's part is in a shown row: its line, or a cell every row
    shares (only its own column's cell when the quote named the column)."""
    column = getattr(part, "column", "")
    if column:
        return _held(part, shared.get(column, ""))
    return _held(part, line) or any(_held(part, v) for v in shared.values())


def _view_timed(shown: str) -> bool:
    """Whether a view's lines lead with their time cell (its columns begin
    with "time")."""
    s = str(shown or "")
    try:
        data = json.loads(s[s.index("{"):s.rindex("}") + 1])
    except ValueError:
        return False
    return isinstance(data, dict) and str(data.get("columns") or "").startswith("time")


def _quote_fold(text: str) -> str:
    """A text with its two quote characters read as one: a model copies a
    JSON key as 'key' or "key"."""
    return str(text or "").replace("'", '"')


def _is_time(piece: str) -> bool:
    return bool(_VIEW_TIME_RE.match(piece)) and ":" in piece


def _marks(lines: list[str]) -> str:
    """The view lines by their markers ("#3, #7"), at most eight named."""
    names = [str(ln).split(" ", 1)[0] for ln in lines]
    return ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")


def _quote_times(quote: str) -> tuple[list[str], list[str]]:
    """(the view-rendered times, the other cells) of a quoted rendered row,
    its "#n" marker dropped: the times _cells leaves out, for the row lookup
    by time (IncidentMap.row_ref_for_time)."""
    text = str(quote or "").strip().strip(",").strip('"').replace("\\\\", "\\")
    parts = [p.strip() for p in re.split(r"\s*\|\s*", text) if p.strip()]
    if parts:
        parts[0] = re.sub(r"^#\d+\s*", "", parts[0]).strip()
    times, others = [], []
    for p in parts:
        piece = max(_CLIP_RE.split(p), key=len).strip()
        if not piece or piece == "-":
            continue
        (times if _VIEW_TIME_RE.match(piece) and ":" in piece else others).append(piece)
    return times, others


def _anchor_problems(anchor: dict[str, Any]) -> list[str]:
    """What an arrival anchor lacks for its finding: its confidence, and a
    time that parses (attacker_from is a time; the source host or address
    is the event's src)."""
    from core.incident_map import _iso
    out = []
    if str(anchor.get("confidence") or "").lower() not in _TIER:
        out.append("needs its confidence (confirmed, likely or possible), what its basis shows")
    ev = anchor.get("event") if isinstance(anchor.get("event"), dict) else {}
    if anchor.get("attacker_from") and not _iso(str(anchor["attacker_from"])):
        out.append(f"has attacker_from {str(anchor['attacker_from'])[:60]!r}, which is no time: attacker_from is "
                   "the time the attacker first acted on this host, written YYYY-MM-DD HH:MM:SS; a source host or "
                   "address goes in the event's src")
    if ev.get("time") and not _iso(str(ev["time"])):
        out.append(f"has an event time {str(ev['time'])[:60]!r} that is no time (write YYYY-MM-DD HH:MM:SS)")
    if not ev.get("time") and not anchor.get("attacker_from"):
        out.append("needs a time: the event's time or attacker_from")
    return out


# The gate a finding is sent back by when its bears_on names a question id and
# no part (agent.frontier.SubmitApplier._findings).
_BARE = "bears_on_question_id"


def _part_ids(case_dir: str) -> set[str]:
    """Every question ("task-0001") and part ("task-0001/p1"), folded."""
    try:
        from core.investigation_tasks import load_tasks
        out = set()
        for t in load_tasks(case_dir).get("tasks") or []:
            tid = str(t.get("id") or "").casefold()
            if tid:
                out.add(tid)
                out |= {f"{tid}/{str(p.get('id') or '').casefold()}" for p in t.get("parts") or []
                        if isinstance(p, dict) and p.get("id")}
        return out
    except Exception:  # noqa: BLE001
        return set()


def _ints(xs: Any) -> list[int]:
    out = []
    for x in xs if isinstance(xs, list) else []:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            continue
    return out


class SubmitApplier:
    """The on_submit of one item (agent.item_executor.run_item)."""

    def __init__(self, agent, case_dir: str, m, item: dict[str, Any], kind: str, turn: int = 0):
        self.agent, self.case, self.m, self.item, self.kind, self.turn = agent, str(case_dir), m, item, kind, turn
        self.arrival_done = False                     # the arrival taken (recorded, examined or missing)
        self.take_arrival = False
        self.arrival_asked = False
        self.confidence_asked = False
        self.arrival_owed = ""                         # an arrival held for a bad anchor field, what is wrong
        self.pending: list[dict[str, Any]] = []        # findings refused once, waiting for their repair
        self.recorded: list[dict[str, Any]] = []       # recorded findings: claim, entity keys, basis calls, sides
        self.challenged: dict[tuple[str, str], dict] = {}  # shared per run by FrontierRun
        self.consumed: set[tuple[str, str]] = set()    # entities a recorded finding carries as typed rows
        self.effects: set[tuple] = set()               # the state this item itself changed (yield, progress)
        self.cited_rows: set[str] = set()              # rows the item's recorded claims cite
        self.submits = 0                               # this item's submits so far (frontier_submit)
        self._trail: dict[str, list] | None = None     # the current submit's outcomes, for its record
        # Where a label or event dict was held, for the record only: kept beside the dict (never on it, so
        # nothing of it reaches the map, the claim or run.submit), with the dict itself so its id stays its own.
        self._holds: dict[int, tuple[dict, dict[str, str]]] = {}
        self._event_claim = ""                         # the claim _put_event labelled its event from
        self.out: dict[str, Any] = {"findings": 0, "labels": 0, "events": 0, "observations": 0, "items": 0,
                                    "proposals": 0, "claims": [], "refused": [], "dropped": [], "notes": []}
        ref = item.get("source_ref") or {}
        self.named = set(_ints([ref.get("call_id")] + list(ref.get("call_ids") or [])))
        # The view rows the item's text names: what "examined" can cover.
        self.shown_rows = {str(k) for k in ref.get("rows") or []} or (
            {str(ref["row_key"])} if ref.get("row_key") else set())

    # ── basis ────────────────────────────────────────────────────────────

    def _basis(self, entries: Any, run) -> tuple[list[dict[str, Any]], list[str]]:
        """Each basis entry resolved to the saved rows it names (or dropped
        with the reason), and one frontier_basis record per entry: what was
        cited, what it resolved to and how, for an exact replay."""
        kept: list[dict[str, Any]] = []
        for b in entries if isinstance(entries, list) else []:
            n = len(self.out["dropped"])
            self._via = "saved"
            got, _q = self._resolve([b], run)
            kept += got
            log = getattr(self.agent, "_log", None)
            if callable(log) and isinstance(b, dict):
                log({"event": "frontier_basis", "item": self.item.get("call_id"), "call_id": b.get("call_id"),
                     "quote": str(b.get("quote") or "")[:4000], "kept": [k["row_ref"] for k in got],
                     "via": self._via if got else "", "cited_as": sorted({k["call_id"] for k in got}),
                     "why": " ".join(self.out["dropped"][n:])[:600]})
        return kept, [k["quote"] for k in kept]

    def _resolve(self, entries: Any, run) -> tuple[list[dict[str, Any]], list[str]]:
        allowed = set(run.calls) | self.named
        kept: list[dict[str, Any]] = []
        for b in entries if isinstance(entries, list) else []:
            if not isinstance(b, dict):
                continue
            try:
                cid = int(b.get("call_id"))
            except (TypeError, ValueError):
                self.out["dropped"].append(f"a basis entry names no call id: {str(b)[:80]}")
                continue
            quote = str(b.get("quote") or "")
            if cid not in allowed:
                self.out["dropped"].append(f"call {cid} is neither this item's nor named by it")
                continue
            shown_side = self._shown_row(cid, quote, run, allowed)
            if shown_side is not None:
                # A numbered view decides on the side the model read: the
                # saved-side matching below never outvotes it.
                got, why = shown_side
                if why:
                    self.out["dropped"].append(why)
                kept += got
                continue
            row = self.m.row_ref_for(cid, quote) if self.m is not None else None
            if not row:
                # The model quotes what it was shown: the rendered result
                # (a table view joins a row's cells). An exact quote of that
                # text, never of what Atlas added to it, stands only when it
                # maps back to a saved row holding its cells.
                raw_shown = _shown_evidence(str((getattr(run, "seen", None) or {}).get(cid) or ""))
                shown, q = _norm(raw_shown), _view_quote(quote)
                cells = _cells(quote)
                common_line = _common_line(raw_shown)
                # A quote clipped like the view clips ("\u2026", or a typed "...")
                # is compared by its longest piece, as _cells reads a cell.
                rest = _words(max(_CLIP_RE.split(re.sub(r"(?i)same[\s_]+in[\s_]+every[\s_]+returned[\s_]+row",
                                                         " ", quote)), key=len))
                if common_line and rest and rest in _words(common_line):
                    # The view's line of cells every returned row shares,
                    # quoted or named: what the quote says beyond the line's
                    # name must be in that line. It holds for any row of the
                    # call through its values, and the line itself, never
                    # the model's wording, is kept as the quote.
                    # A cell named whole, or a piece of a cell the quote clipped
                    # ("Column | <the value's head>..."): the line's own value.
                    pieces = [_norm(x) for x in re.split(r"\s*\|\s*", max(_CLIP_RE.split(quote), key=len))
                              if len(x.strip()) >= 4]
                    cells = [v for v in _common_cells(raw_shown)
                             if _norm(v) in _norm(quote) or any(pc in _norm(v) for pc in pieces)]
                    # the same floor as a row's cells: enough to name a row
                    cells = cells if len(cells) >= 2 or any(len(c) >= 4 for c in cells) else []
                    q, quote = "", common_line.strip().rstrip(",")
                row = (self.m.row_ref_for_cells(cid, cells)
                       if self.m is not None and cells and (not q or q in shown) else None)
                why = f"the quote {quote[:60]!r} is not in call {cid}'s output"
                collapsed = _COLLAPSED_RE.match(str(quote or "").strip().strip('"'))
                rows_shown = _view_rows(raw_shown)
                # Only a line the call's view rendered: its marker and count
                # stand at the head of one of the shown row lines.
                rendered = bool(collapsed) and any(
                    (m2 := _COLLAPSED_RE.match(str(r).strip())) and m2.group(0) == collapsed.group(0)
                    for r in rows_shown or [])
                parts = _collapsed_parts(quote) if collapsed and rendered and not row else None
                members = (self.m.rows_for_ordinals(cid, parts[0], parts[2], parts[3])
                           if parts and self.m is not None else [])
                if members:
                    # A collapsed line of the view names its member rows: each
                    # becomes a basis entry, verified by its ordinals, count and
                    # first and last time against the view's own record.
                    kept += [{"call_id": cid, "row_ref": ref, "quote": quote} for ref in members]
                    continue
                if not row and collapsed:
                    # A collapsed line of the view stands for several rows: no
                    # one row is it, and a statement about them cites each.
                    why = (f"the quote {quote[:60]!r} is a collapsed line of call {cid}: it stands for "
                           f"{collapsed.group(1)} rows, so it names no one row; cite each row the statement rests on "
                           "by its own values (a narrower read shows them one by one)")
                elif not row and self.m is not None and (not q or q in shown):
                    # A rendered row quoted by its marker and time: the time
                    # names the row when exactly one saved row of the call
                    # holds it (compared in the view's own time form), with
                    # the quote's other cells. Only when the cells alone named
                    # none, so no quote maps less than before.
                    times, others = _quote_times(quote)
                    if times:
                        row, n = self.m.row_ref_for_time(cid, times, others)
                        if not row and n > 1:
                            why = (f"the quote {quote[:60]!r} names {n} rows of call {cid} at that time; quote a "
                                   "value of the one row meant")
                if (not row and not collapsed and why.endswith("output") and q
                        and _quote_fold(q) in _quote_fold(shown)
                        and not any(q in _norm(r) for r in rows_shown or [])):
                    # A line of the result's header (a count, a summary, a key
                    # of the result), view or not: it is in the output, and
                    # it names no row. Only the refusal's words depend on it.
                    why = self._header_refusal(cid, quote)
                if not row and why == f"the quote {quote[:60]!r} is not in call {cid}'s output":
                    # The text is in no row of this call: the item may have
                    # read it in another call (a file one call wrote, read by
                    # the next), or another item did.
                    got, why = self._elsewhere(cid, quote, allowed)
                    if got:
                        kept += got
                        continue
                if not row:
                    self.out["dropped"].append(why)
                    continue
            kept.append({"call_id": cid, "row_ref": row, "quote": quote})
        return kept, [k["quote"] for k in kept]

    def _elsewhere(self, cid: int, quote: str, allowed: set) -> tuple[list[dict[str, Any]], str]:
        """A quote no row of the cited call holds, looked up in the item's
        other calls (whatever their output's shape): re-cited to the one
        call and the one row that hold it whole, when the quote can name a
        line (twelve characters or more, a word of four or more); else the
        holders named. None of the item's: the call of another item that
        holds it, named so it can be read here. (kept, why)."""
        why = f"the quote {quote[:60]!r} is not in call {cid}'s output"
        if self.m is None:
            return [], why
        holders = []
        for oc in sorted(allowed):
            try:
                refs = self.m.row_refs_for(oc, quote) if oc != cid else []
            except Exception:  # noqa: BLE001 - an output that cannot be read holds nothing here
                refs = []
            if refs:
                holders.append((oc, refs))
        text = " ".join(str(quote or "").split())
        named = len(text) >= 12 and re.search(r"[^\W_]{4,}", text) is not None
        if len(holders) == 1 and len(holders[0][1]) == 1 and named:
            oc, refs = holders[0]
            self._via = "recited"
            return [{"call_id": oc, "row_ref": refs[0], "quote": quote, "recited_from": cid}], ""
        if holders:
            where = ", ".join(f"call {oc}" + (f" ({len(refs)} lines)" if len(refs) > 1 else "")
                              for oc, refs in holders[:8])
            return [], (f"{why}; it is in {where}: " + ("cite the call it is in, with more of the line meant"
                                                         if named else "quote more of the line, enough to name it"))
        try:
            other = self.m.call_holding(quote, set(allowed), self.__dict__.setdefault("_holding_texts", {}))
        except Exception:  # noqa: BLE001 - the lookup only words the refusal
            other = 0
        if other:
            return [], f"{why}; it is in call {other} of another item: read it in this item to cite it"
        return [], why

    def _header_refusal(self, cid: int, quote: str) -> str:
        """Why a line of a call's header names no basis row, with the way to
        one: a count across tables (the table search's sources) points to
        the per-table search; a call that returned no row to examined."""
        head = f"the quote {quote[:60]!r} is a line of call {cid}'s header (a count or a summary)"
        entry = self.m._entry(cid) if self.m is not None else None
        try:
            from core.indicators import _parsed_args
            args = _parsed_args(entry)[0] if entry else {}
        except Exception:  # noqa: BLE001
            args = {}
        if isinstance(args, dict) and args.get("sources"):
            return (f"{head}: a count across tables names no row; grep one table without sources for its rows "
                    "and cite those")
        if entry is not None and not self.m._rows(entry)[1]:
            return (f"{head}: call {cid} returned no row; a count names none: put call {cid} in examined for what "
                    "it did not find, or cite a row of a call that returned one")
        return (f"{head}: a count names no row; a statement about a count cites the rows counted (with one row, "
                "that row)")

    def _marker_rows(self, cid: int) -> dict[str, tuple[str, bool]]:
        cache = self.__dict__.setdefault("_marker_cache", {})
        if cid not in cache:
            cache[cid] = self.m.marker_rows(cid) if self.m is not None else {}
        return cache[cid]

    def _shown_row(self, cid: int, quote: str, run, allowed: set) -> tuple[list[dict[str, Any]], str] | None:
        """A quote of a numbered view resolved on the side the model read:
        the view line that holds every piece of the quote, mapped to its
        saved row through the view's own record of its "#n"
        (IncidentMap.marker_rows), never by searching the saved output for
        the view's rendering of a row. (kept entries, "") when it resolves,
        ([], why) when it is refused, None when the call shows no numbered
        view with its record, the quote is the view's shared line, a
        collapsed line or its header, or no line of the item's views holds
        it: the saved-side path decides then."""
        seen = getattr(run, "seen", None) or {}
        raw = str(seen.get(cid) or "")
        lines = _view_rows(raw)
        q = str(quote or "").strip().strip('"')
        if (not lines or not self._marker_rows(cid) or _COLLAPSED_RE.match(q)
                or re.search(r"(?i)same[\s_]+in[\s_]+every[\s_]+returned[\s_]+row", q)):
            return None
        marker, pieces = _pieces(quote)
        shared, keys = _view_shared(raw)
        timed = _view_timed(raw)
        parts = _parts(pieces, keys, shared)
        if pieces and not parts:
            return [], (f"the quote {quote[:60]!r} names no value of call {cid}: a column name is no evidence; quote "
                        "the values the row shows")
        for p in parts:
            # A part named by a shared column whose cell does not hold it,
            # though another shared cell does: told which column holds it.
            column = getattr(p, "column", "")
            if column and not _held(p, shared.get(column, "")):
                other = next((k for k, v in shared.items() if k != column and _held(p, v)), "")
                if other:
                    return [], (f"the quote {quote[:60]!r} names {column} of call {cid}: {column} shows "
                                f"{_cut(shared[column], 80)!r}; {str(p)[:60]!r} is under {other}")
        bare = bool(marker) and all(_is_time(p) for p in pieces)        # "#n <time>" exactly
        if len(lines) > 1 and parts and shared and all(_held_row(p, "", shared) for p in parts):
            # Every part is a shared value, in a view of several rows: true of
            # every row, so never refused. The line the parts tell apart by
            # _take's rule (a time on it, or a part of four characters or
            # more no other line holds), when exactly one; else the shared
            # line's own path. In a view of one row its cells are that
            # row's, read below.
            told = [ln for ln in lines if any(_on_line(p, ln) and (
                _is_time(p) or (len(p) >= 4 and not any(_on_line(p, o) for o in lines if o != ln))) for p in parts)]
            taken = self._take(cid, told[0], lines, parts, bool(marker), quote, shared, bare, timed) if len(told) == 1 \
                else None
            if taken and taken[0]:
                return taken
            # The shared line: true of any row, kept as the first saved row
            # holding the cells the parts are in, with the line itself as
            # the quote (as the shared line's path keeps it).
            cells = [v for k, v in shared.items() if any(getattr(p, "column", "") == k or
                                                           (not getattr(p, "column", "") and _held(p, v))
                                                           for p in parts)]
            row = self.m.row_ref_for_cells(cid, cells) if cells else None
            if not row:
                return None
            self._via = "shared"
            return [{"call_id": cid, "row_ref": row, "quote": _common_line(raw).strip().rstrip(",")}], ""
        if not parts:
            return ([], f"a row marker alone names no row of call {cid}: quote a value of row #{marker} with it")\
                if marker else None
        hit = [ln for ln in lines if all(_held_row(p, ln, shared) for p in parts)]
        line = next((ln for ln in lines if (mk := _MARKER_RE.match(ln)) and mk.group(1) == marker), None) \
            if marker else None
        if marker and line is not None and line in hit:
            return self._take(cid, line, lines, parts, True, quote, shared, bare, timed)
        if hit and marker:
            return [], (f"row #{marker} of call {cid} " + (f"reads {_cut(line, 200)!r}" if line else "is not shown")
                        + f"; the quote {quote[:60]!r} is in {_marks(hit)}: cite the row the quote is in")
        if len(hit) == 1:
            return self._take(cid, hit[0], lines, parts, False, quote, shared, timed=timed)
        if hit:
            return [], (f"the quote {quote[:60]!r} is in {len(hit)} rows of call {cid} ({_marks(hit)}): start the "
                        "quote with the #n of the row meant and a value only that row shows")
        if all(_held(p, _view_header(raw)) for p in parts):
            return None                                  # a line of the view's header
        # No row of the cited call holds it: the same row as another view of
        # the item shows it (a page that clips a long cell around its own
        # match shows other parts of it than the next page).
        found = []
        for oc in seen:
            ol = _view_rows(seen.get(oc)) if oc != cid and oc in allowed else None
            if ol and self._marker_rows(oc):
                oshared, okeys = _view_shared(str(seen.get(oc) or ""))
                oparts = _parts(pieces, okeys, oshared)
                found += [(oc, ln, ol, oparts, oshared) for ln in ol
                          if oparts and all(_held_row(p, ln, oshared) for p in oparts)]
        if marker:
            same = [f for f in found if (mk := _MARKER_RE.match(f[1])) and mk.group(1) == marker]
            if found and not same:
                # The quoted marker names none of these lines: the same
                # conflict as a marker another line of the cited call holds.
                return [], (f"row #{marker} of call {cid} " + (f"reads {_cut(line, 200)!r}" if line else
                                                                "is not shown")
                            + f"; the quote {quote[:60]!r} is in "
                            + ", ".join(f"call {f[0]} {_marks([f[1]])}" for f in found[:8])
                            + ": cite the call and row the quote is in")
            found = same
        if len(found) == 1:
            oc, ln, ol, oparts, oshared = found[0]
            taken = self._take(oc, ln, ol, oparts, bool(marker), quote, oshared, bare,
                               _view_timed(str(seen.get(oc) or "")))
            if taken is None:
                return None
            got, why = taken
            for g in got:
                g["recited_from"] = cid
            self._via = "recited" if got else self._via
            return got, why
        if found:
            return [], (f"the quote {quote[:60]!r} is in no row of call {cid}; it is in "
                        + ", ".join(f"call {f[0]} {_marks([f[1]])}" for f in found[:8])
                        + ": cite the call and row meant")
        if marker:
            return [], (f"row #{marker} of call {cid} " + (f"reads {_cut(line, 200)!r}" if line else "is not shown")
                        + f"; the quote {quote[:60]!r} is not in it: quote the row cited")
        return None

    def _take(self, cid: int, line: str, lines: list[str], parts: list[str], marked: bool,
              quote: str, shared: dict[str, str] | None = None,
              bare: bool = False, timed: bool = False) -> tuple[list[dict[str, Any]], str] | None:
        """The saved row(s) of the one view line a quote names. In a view of
        several lines, a part on the line itself must tell it from the
        others: a time (other lines at that second lack another part of the
        quote, or the marker names the line), or a part of four characters
        or more no other line holds; the shared cells belong to every line
        and never tell one apart. In a view of one line, the quote must hold
        a value of the row (four characters or more, its time aside), unless
        it is exactly the line's marker and time (``bare``). The line and the shared
        cells the quote named are kept as the quote, never the model's
        words. None when the view's record does not vouch for the line's
        row."""
        shared = shared or {}
        others = [ln for ln in lines if ln != line]
        if others:
            on_line = [p for p in parts if _on_line(p, line)]
            # The line's own time cell is its time in whatever form the view
            # writes it (a view without the date column writes the clock
            # alone): it tells the line apart only when no other line holds
            # the whole quote.
            cell = str(line).split(" ", 1)[-1].split(" | ", 1)[0].strip() if timed else ""
            whole = sum(1 for ln in lines if all(_held_row(p, ln, shared) for p in parts)) == 1
            if not any(_is_time(p) or (whole and cell and _fold(p) == _fold(cell))
                       or (len(p) >= 4 and not any(_on_line(p, o) for o in others)) for p in on_line):
                near = [ln for ln in lines if any(_on_line(p, ln) for p in parts)] or others
                return [], (f"the quote {quote[:60]!r} names no one row of call {cid}: each part of it is also in "
                            f"{_marks(near)}; quote a value only the row meant shows, with its #n first")
        elif not (bare or any(not _is_time(p) and len(p) >= 4 for p in parts)):
            return [], (f"the quote {quote[:60]!r} names no value of the row of call {cid}: quote a value the row "
                        "shows (its line or the cells every row shares)")
        named = [f"{k}: {v}" for k, v in shared.items()
                 if any(getattr(p, "column", "") == k or (not getattr(p, "column", "") and _held(p, v)
                                                           and not _held(p, line)) for p in parts)]
        kept_quote = _cut(" | ".join([line, *named]), 600)
        mk = _MARKER_RE.match(line)
        if mk is None:
            # A collapsed line: its member rows, verified by the view's record.
            parts = _collapsed_parts(line)
            members = self.m.rows_for_ordinals(cid, parts[0], parts[2], parts[3]) if parts else []
            if not members:
                return [], (f"the quote {quote[:60]!r} is a collapsed line of call {cid} that does not verify; cite "
                            "each row the statement rests on (a narrower read shows them one by one)")
            self._via = "line"
            return [{"call_id": cid, "row_ref": r, "quote": kept_quote} for r in members], ""
        ref, exact = self._marker_rows(cid).get(mk.group(1), ("", False))
        if ref and not exact:
            # A row the record names by its place, not its id: its line must
            # show what the saved row holds.
            text = _fold(_unslashed(self.m.row_text(ref) or ""))
            ref = ref if any(len(o) >= 4 and _fold(_unslashed(o)) in text for o in _quote_times(line)[1]) else ""
        if not ref:
            return None                       # the record does not vouch for the row: the saved side decides
        self._via = "marker" if marked else "line"
        return [{"call_id": cid, "row_ref": ref, "quote": kept_quote}], ""

    # ── entry point ──────────────────────────────────────────────────────

    def __call__(self, args: dict[str, Any], run, final: bool) -> str | None:
        """A submit, and one frontier_submit record of it: its size, each
        finding's outcome and each label's and event's route (written, held
        for a refused finding, released through which finding). The record
        never touches the submit: what it cannot write is dropped."""
        self.submits += 1
        head: dict[str, Any] = {"submit": self.submits}
        try:
            head.update({"round": int(getattr(run, "rounds", 0) or 0), "forced": bool(final),
                         "repair": bool(self.pending), "partial": bool(args.get("partial")) and not final,
                         # the item's so far; the round's own are in the item_call record before this one
                         "item_output_tokens": int(getattr(run, "output_tokens", 0) or 0),
                         **{f"{k}_sent": len(args.get(k)) if isinstance(args.get(k), list) else 0
                            for k in ("findings", "labels", "events")}})
            head["args_chars"] = -1                      # args json cannot encode
            head["args_chars"] = len(json.dumps(args, default=str))   # before _rest adds _basis to its dicts
        except Exception:  # noqa: BLE001
            pass
        self._trail = {"findings": [], "labels": [], "events": []}
        try:
            reply = self._submit(args, run, final)
        finally:
            trail, self._trail = self._trail, None
        self._log_trail("frontier_submit", {**head, "reply_none": reply is None}, trail)
        return reply

    def _log_trail(self, event: str, head: dict[str, Any], trail: dict[str, list] | None) -> None:
        try:
            log = getattr(self.agent, "_log", None)
            if not callable(log) or trail is None:
                return
            rec = {"event": event, "item": self.item.get("call_id"), **head}
            for part, got in trail.items():
                rec[part] = got[:_TRAIL_MAX]
                if len(got) > _TRAIL_MAX:
                    rec[part + "_more"] = len(got) - _TRAIL_MAX
            log(rec)
        except Exception:  # noqa: BLE001 - a record that cannot be written never fails the submit
            pass

    def _mark(self, part: str, what: dict[str, Any]) -> None:
        """One line of the current submit's record; outside a submit (the
        brief's labels) or on any error, nothing."""
        try:
            if self._trail is not None:
                self._trail[part].append(what)
        except Exception:  # noqa: BLE001
            pass

    def _fmark(self, i: int, f: dict[str, Any], basis: list | None, prior: dict | None, outcome: str,
               **more: Any) -> None:
        try:
            self._mark("findings", {"n": i + 1, "said": _cut(f.get("statement"), 200),
                                    "confidence": str(f.get("confidence") or "")[:20],
                                    "bears_on": [str(b)[:40] for b in f.get("bears_on") or []][:6],
                                    "basis": len(f.get("basis") or []) if isinstance(f.get("basis"), list) else 0,
                                    "kept": len(basis or []), "repairs": (prior or {}).get("at") or "",
                                    "outcome": outcome, **more})
        except Exception:  # noqa: BLE001
            pass

    def _hold(self, obj: dict[str, Any], p: dict[str, Any], keys: list[tuple]) -> dict[str, str]:
        """Note where ``obj`` waits: the pending entry, and whether by a
        shared entity or only a shared basis call (_resting's two ways)."""
        by = "entity" if set(keys) & set(p.get("keys") or []) else "call"
        tag = {"on": str(p.get("at") or ""), "held_by": by}
        self._holds.setdefault(id(obj), (obj, tag))
        return tag

    def _held_for(self, obj: dict[str, Any]) -> str:
        got = self._holds.get(id(obj))
        return got[1]["on"] if got and got[0] is obj else ""

    def _lmark(self, lab: dict[str, Any], outcome: str, **more: Any) -> None:
        k = _ref_key(lab.get("ref")) or ("", "")
        self._mark("labels", {"ref": f"{k[0]}:{k[1]}"[:120], "label": str(lab.get("label") or "unknown")[:20],
                              "outcome": outcome, **more})

    def _emark(self, ev: dict[str, Any], outcome: str, **more: Any) -> None:
        self._mark("events", {"host": str(ev.get("host") or "")[:60], "time": str(ev.get("time") or "")[:40],
                              "kind": str(ev.get("kind") or "")[:40], "outcome": outcome, **more})

    def _submit(self, args: dict[str, Any], run, final: bool) -> str | None:
        """A submit, final or partial (``partial``: recorded now, the item
        goes on). Every submit goes through the same rules: the arrival, the
        refusal path and bears_on."""
        partial = bool(args.get("partial")) and not final
        self._holding_texts = {}                     # the outputs this submit's refusals read (call_holding)
        waiting_arrival = self.kind == "host_pass" and not self.arrival_done
        if waiting_arrival and not partial and not args.get("arrival") and not self.arrival_asked and not final:
            self.arrival_asked = True
            return ("refused: arrival is required. Resubmit with arrival: the anchor (the inbound event or the "
                    "time the attacker first acted here, with its basis), or examined with the calls that found "
                    "none. Nothing of this submit was recorded.")
        anchor = (args.get("arrival") or {}).get("anchor") if isinstance(args.get("arrival"), dict) else None
        held = ""
        if waiting_arrival and isinstance(anchor, dict) and not self.confidence_asked and not final:
            wrong = _anchor_problems(anchor)
            if wrong:
                # What decides whether the arrival anchors the window (its
                # tier, its time) is never assumed: sent back once. Only the
                # arrival is held; the rest of the submit is taken.
                self.confidence_asked = self.arrival_asked = True
                held = "; ".join(wrong)
                self.arrival_owed = held
                args = {k: v for k, v in args.items() if k != "arrival"}
        labels = [x for x in args.get("labels") or [] if isinstance(x, dict)]
        findings = [x for x in args.get("findings") or [] if isinstance(x, dict)]
        before = self.out["findings"]
        if self.pending:
            repairs, self.pending = self.pending, []
            replies = []
            # An arrival the gates refused is repaired by the `arrival` field,
            # whatever arrival_done says: taken out of the positional repairs
            # and given the refused attempt as its prior, so a second refusal
            # is refused twice.
            prior_arrival = next((p for p in repairs if (p.get("finding") or {}).get("_arrival")), None)
            if args.get("arrival") and (waiting_arrival or prior_arrival is not None):
                # The arrival first, as a finding of its own, so the repairs
                # keep their places.
                if prior_arrival is not None:
                    repairs.remove(prior_arrival)
                self.arrival_done = self.take_arrival = True
                self.arrival_owed = ""
                arrival = self._arrival_finding(args.get("arrival"))
                if arrival is not None:
                    replies += self._findings([arrival[0]], [arrival[1]], run,
                                              repairs=[prior_arrival] if prior_arrival is not None else [],
                                              positional=True)
                elif prior_arrival is not None:
                    self.pending.append(prior_arrival)       # an unusable resubmit: the refusal stands
                elif not isinstance(args["arrival"].get("examined"), dict):
                    self._arrival_missing()
                self._arrival(args.get("arrival"), run)
            arrival_pending = list(self.pending)
            self.pending = []
            replies += self._findings(findings, labels, run, repairs=repairs)
            self.pending += self._unpaired               # refused ones no resent finding repairs
            self.pending = arrival_pending + self.pending
        else:
            self.take_arrival = False
            if waiting_arrival and args.get("arrival"):
                self.arrival_done = self.take_arrival = True
                arrival = self._arrival_finding(args.get("arrival"))
                if arrival is not None:
                    findings, labels = findings + [arrival[0]], labels + [arrival[1]]
                elif not isinstance(args["arrival"].get("examined"), dict):
                    self._arrival_missing()
            elif waiting_arrival and not partial and not held:
                self.arrival_done = True
                self._arrival_missing()
            replies = self._findings(findings, labels, run, repairs=[])
            self._rest(args, labels, run)
        refusal = ("; ".join(replies) + ". Resubmit only the refused finding(s), repaired, in findings; the rest "
                   "of your submit is kept.") if self.pending and replies else None
        owed = getattr(self, "arrival_owed", "")
        if owed and not self.arrival_done:
            # The held arrival, said exactly: which field, what goes there.
            ask = (("the arrival was not taken: its anchor " + owed + ". " if held else
                    "the arrival is still owed: its anchor " + owed + ". ")
                   + 'Resubmit the arrival alone ({"arrival": {...}}) with that field fixed; the rest of this '
                     "submit was recorded" + ("" if not refusal else " except the refused finding(s) above"))
            refusal = (refusal + " " if refusal else "") + ask + "."
            if not partial:
                return refusal
        if partial:
            return refusal or (f"recorded: {self.out['findings'] - before} new finding(s)"
                               + (f"; {'; '.join(replies)}" if replies else "")
                               + ". Go on with the item; submit without partial to end it.")
        if not self.pending:
            self.finish()
            return None
        # Final or not, refused findings get their repair: a forced submit's
        # one repair round (agent.item_executor.run_item); what stays refused
        # is closed by finish() when the item ends.
        return refusal

    def finish(self) -> None:
        """Findings still refused when the item ends: refused twice; one
        sent back only for naming a question id is an observation. Called
        after the item's last submit, it logs what it wrote as one
        frontier_submit_close record."""
        closing = self._trail is None and bool(self.pending)
        if closing:
            self._trail = {"findings": [], "labels": [], "events": []}
        try:
            self._finish()
        finally:
            if closing:
                trail, self._trail = self._trail, None
                self._log_trail("frontier_submit_close", {"after": self.submits}, trail)

    def _finish(self) -> None:
        for p in self.pending:
            if p.get("gate") == _BARE and p.get("basis") and not p.get("record_refused"):
                self._observe(p.get("finding") or {}, p["basis"], int(p.get("index") or 1) - 1,
                              "it named a question id, not a part, and was not resubmitted")
                self._fmark(int(p.get("index") or 1) - 1, p.get("finding") or {}, p["basis"], p, "observation",
                            why="named a question id, not resubmitted")
                continue
            self._refused_twice(p)
        self.pending = []

    # ── findings ─────────────────────────────────────────────────────────

    def _rows(self, f: dict[str, Any], labels: list[dict[str, Any]]) -> tuple[list[dict], list[tuple]]:
        by_key = {k: lab for lab in labels if (k := _ref_key(lab.get("ref")))}
        rows, keys = [], []
        for ref in f.get("entities") or []:
            k = _ref_key(ref)
            if k is None:
                continue
            lab = by_key.get(k) or {}
            row = {"type": _row_type(k[0], str(ref["value"])), "value": str(ref["value"]),
                   "side": _SIDE.get(str(lab.get("label") or "unknown"), "undetermined")}
            if lab.get("attacker_from") and row["type"] in ("host", "account"):
                row["attacker_from"] = str(lab["attacker_from"])
            rows.append(row)
            keys.append(k)
        return rows, keys

    def _pair(self, findings: list[dict], repairs: list[dict]) -> tuple[list[dict | None], set[int], list[dict]]:
        """The refused entry each resent finding repairs, by its statement
        only, never by position or by shared rows (a model resends its whole
        submit, and the findings of one item cite the same few calls: any
        overlap would pair a finding with another's entry and release that
        entry's labels through it). Each entry once; an empty statement pairs
        with nothing. A reworded repair is judged as new, and its old entry
        stays pending and ends refused twice. A resent finding the item
        recorded already is skipped. (priors aligned with ``findings``, the
        indices of the already recorded ones, the entries no finding
        repairs.)"""
        recorded = {r.get("said") for r in self.recorded if r.get("said")}
        priors: list[dict | None] = [None] * len(findings)
        free = list(repairs)
        skipped = {i for i, f in enumerate(findings) if _said(f) in recorded}
        for i, f in enumerate(findings):
            if i in skipped or not _said(f):
                continue
            p = next((p for p in free if _said(p.get("finding") or {}) == _said(f)), None)
            if p is not None:
                priors[i] = p
                free.remove(p)
        return priors, skipped, free

    def _findings(self, findings: list[dict], labels: list[dict], run, repairs: list[dict],
                  positional: bool = False) -> list[str]:
        replies: list[str] = []
        if positional:
            priors, skipped = [repairs[i] if i < len(repairs) else None for i in range(len(findings))], set()
            self._unpaired = list(repairs[len(findings):])
        else:
            priors, skipped, self._unpaired = self._pair(findings, repairs)
        for i, f in enumerate(findings):
            if i in skipped:
                was = next(r for r in self.recorded if r.get("said") == _said(f))
                changed = (str(f.get("confidence") or "").lower() != was.get("tier")
                           or _bears_set(f) != was.get("bears"))
                replies.append(f"finding {i + 1} is already recorded" + (
                    "; its changed tier or bears_on was not applied: the recorded finding stands as it was"
                    if changed else ""))
                self._fmark(i, f, None, None, "already_recorded", changed=changed)
                continue
            prior = priors[i]
            # A repair's own labels win; the first submit's labels for the
            # same entities stand where the repair repeats none.
            pool = list((prior or {}).get("labels") or []) + labels
            basis, quotes = self._basis(f.get("basis"), run)
            rows, keys = self._rows(f, pool)
            entry = {"finding": {**f, "_arrival": f.get("_arrival") or (prior or {}).get("finding", {}).get("_arrival")},
                     "keys": keys, "calls": {b["call_id"] for b in basis}, "index": i + 1,
                     "labels": [lab for lab in pool if _ref_key(lab.get("ref")) in keys],
                     "events": (prior or {}).get("events", []), "deferred_labels": (prior or {}).get(
                         "deferred_labels", []), "at": f"{self.submits}:{i + 1}"}
            served, parts = self._bears(f, rows)
            entry["serves_parts"] = (prior or {}).get("serves_parts", parts) if not parts else parts
            entry["basis"] = basis
            # Carried across repairs: the question-id send-back happens once per
            # finding, and a record refusal after an earlier one is the second.
            entry["bare_sent"] = bool((prior or {}).get("bare_sent"))
            entry["record_refused"] = bool((prior or {}).get("record_refused"))
            if basis and not served:
                bare = self._bare_ids(f)
                if bare and not entry["bare_sent"]:
                    # A question id names no part: sent back once with the
                    # question's parts; after that it is an observation.
                    entry.update(gate=_BARE, error=self._bare_reply(bare), bare_sent=True)
                    self.pending.append(entry)
                    self.out["refused"].append({"index": i + 1, "gate": _BARE})
                    replies.append(f"finding {i + 1} refused ({_BARE}): {entry['error'][:600]}")
                    self._fmark(i, f, basis, prior, "sent_back", gate=_BARE)
                    continue
                if entry["bare_sent"]:
                    replies.append(self._observe(f, basis, i, "it serves no question part, no attacker value it "
                                                 "holds and no entity you label attacker"))
                    self._fmark(i, f, basis, prior, "observation", why="serves no part after its send-back")
                    continue
            if basis and not prior and not served:
                # It serves no question and takes no side: kept as an
                # observation with its evidence, never a claim.
                replies.append(self._observe(f, basis, i, "it names no question part, no attacker value it "
                                             "holds and no entity you label attacker"))
                self._fmark(i, f, basis, prior, "observation", why="serves no part and takes no side")
                continue
            if not basis:
                gate, err = "basis", "no basis entry is left (" + "; ".join(self.out["dropped"][-3:]) + ")"
            else:
                gate, err, claim = self._record(f, basis, quotes, rows)
                if not gate:
                    # A finding the record path folds as a duplicate adds no
                    # state; only a new one counts.
                    if claim and entry["serves_parts"]:
                        refused = self._serve_parts(claim, entry["serves_parts"])
                        if refused:
                            # Named parts were all it served, and none takes it.
                            self._withdraw(claim, refused)
                            replies.append(self._observe(f, basis, i, refused))
                            self._fmark(i, f, basis, prior, "observation", claim=claim, why=_cut(refused, 160))
                            self._release(entry, "")
                            continue
                    self.out["findings"] += int(bool(claim))
                    self.consumed |= set(keys)
                    if claim:
                        self._cited(claim, basis)
                        self.out["claims"].append(claim)
                        self.recorded.append({"claim": claim, "keys": set(keys), "calls": entry["calls"],
                                              "said": _said(f), "tier": str(f.get("confidence") or "").lower(),
                                              "bears": _bears_set(f),
                                              "attacker": {k for k, r in zip(keys, rows) if r["side"] == "attacker"},
                                              "arrival": bool(entry["finding"].get("_arrival"))})
                        note = self._link(claim)
                        if note:
                            replies.append(f"finding {i + 1} was recorded as {claim}; {note}")
                    self._fmark(i, f, basis, prior, "recorded" if claim else "duplicate", claim=claim)
                    self._release(entry, claim)
                    continue
            entry.update(gate=gate, error=err)
            if entry["record_refused"]:
                self._fmark(i, f, basis, prior, "refused_twice", gate=gate)
                self._refused_twice(entry)
                continue
            entry["record_refused"] = True
            self.pending.append(entry)
            self._fmark(i, f, basis, prior, "refused", gate=gate)
            self.out["refused"].append({"index": i + 1, "gate": gate})
            replies.append(f"finding {i + 1} refused ({gate}): {err[:_REFUSAL_CHARS]}")
        return replies

    def _bears(self, f: dict[str, Any], rows: list[dict]) -> tuple[bool, list[str]]:
        """(serves, parts): whether a finding serves the case (bears_on), and
        the question parts it serves only by naming them. It serves when it
        is the arrival, has an attacker-side row of its own, or names a
        labelled attacker value that its own entities or its statement hold.
        A named part is only a claim: code links the recorded finding to it
        through the part gates (_serve_parts), and a finding no named part
        takes is an observation."""
        if f.get("_arrival") or any(self._serving_row(f, r) for r in rows):
            return True, []
        named = [str(b).strip() for b in f.get("bears_on") or [] if str(b).strip()]
        if not named:
            return False, []
        values = set()
        if self.m is not None:
            try:
                values = {_fold(e["value"]) for e in self.m.attacker_entities(proposals=True)}
            except Exception:  # noqa: BLE001
                values = set()
        own = {_fold(r.get("value") or "") for r in rows} | {
            _fold((e or {}).get("value") or "") for e in f.get("entities") or [] if isinstance(e, dict)}
        said = _fold(f.get("statement") or "")
        if any(_fold(b) in values and (_fold(b) in own or _fold(b) in said) for b in named):
            return True, []
        known = _part_ids(self.case)
        parts = [p for p in dict.fromkeys(re.sub(r"\s+", "", b).replace("#", "/").casefold() for b in named)
                 if p in known and "/" in p]
        return bool(parts), parts

    def _serving_row(self, f: dict[str, Any], r: dict[str, Any]) -> bool:
        """Whether an attacker-side row of a finding makes it serve. The
        item's own host (and the finding's) never does: it is the subject of
        every row of the item and says nothing of this row's relevance. A host
        or account the attacker took over (attacker_from) does only for a
        finding at or after that time: before it, its activity is the
        organisation's; a finding with no time does not serve through it."""
        if r.get("side") != "attacker":
            return False
        if r.get("type") == "host":
            own = {str(h).casefold() for h in (f.get("host"), (self.item.get("source_ref") or {}).get("host"),
                                                (self.item.get("target") or {}).get("host")) if h}
            if str(r.get("value") or "").casefold() in own:
                return False
        since = r.get("attacker_from")
        if since and r.get("type") in ("host", "account"):
            from core.incident_map import _iso
            from core.incident_window import leading_time
            start = _iso(since)
            if not start:
                # An attacker_from that is no time names no takeover: nothing
                # tells the account's own activity from the attacker's, so the
                # row makes no finding serve.
                return False
            when = _iso(f.get("time")) or leading_time(str(f.get("time") or "")) or leading_time(
                str(f.get("statement") or ""))
            return bool(when) and when >= start
        return True

    def _bare_ids(self, f: dict[str, Any]) -> list[str]:
        """The question ids (no part) a finding's bears_on names."""
        known = _part_ids(self.case)
        named = [re.sub(r"\s+", "", str(b)).replace("#", "/").casefold() for b in f.get("bears_on") or []]
        return [b for b in dict.fromkeys(named) if b in known and "/" not in b]

    def _bare_reply(self, bare: list[str]) -> str:
        """The question's parts by id, and that a part is named only for a
        finding that answers it."""
        from core.investigation_tasks import load_tasks
        tasks = {str(t.get("id") or "").casefold(): t for t in load_tasks(self.case).get("tasks") or []}
        listed = []
        for b in bare:
            t = tasks.get(b) or {}
            listed += [f"{t.get('id')}/{p.get('id')} ({str(p.get('text') or '')[:120]})"
                       for p in t.get("parts") or [] if isinstance(p, dict) and p.get("id")]
        return (f"{', '.join(bare)} names a question, not one of its parts"
                + (f"; its parts: {'; '.join(listed[:12])}" if listed else "")
                + ". Name a part in bears_on only for a finding that answers that part. A row that answers none "
                  "stays an observation, which is a result: resubmit it with bears_on empty")

    def _serve_parts(self, claim: str, parts: list[str]) -> str:
        """Link a recorded finding to the parts it names. An open part goes
        through update_task's part gates and is answered by it. An answered
        part takes it as support only when it passes the part's own answer
        test (request_parts.assign on that part): naming an existing id is
        never enough. "" when one took it, else why none did."""
        from core.investigation_tasks import load_tasks, update_task
        why = []
        tasks = {str(t.get("id") or "").casefold(): t for t in load_tasks(self.case).get("tasks") or []}
        for ref in parts:
            tid, _sep, pid = ref.partition("/")
            task = tasks.get(tid) or {}
            own = [p for p in task.get("parts") or [] if isinstance(p, dict)]
            part = next((p for p in own if str(p.get("id") or "").casefold() == pid), None)
            try:
                if part is not None and part.get("status") == "open":
                    r = update_task(self.case, str(task.get("id")), parts={str(part.get("id")): {"claim_ids": [claim]}})
                elif part is not None and self._answers(claim, task, part):
                    r = update_task(self.case, str(task.get("id")), related_claim_ids=list(
                        task.get("related_claim_ids") or []) + [claim])
                else:
                    r = {"success": False, "error": f"{claim} does not answer part {pid or '?'}"}
            except Exception as e:  # noqa: BLE001
                r = {"success": False, "error": str(e)}
            if r.get("success") is not False:
                return ""
            why.append(f"{ref}: {str(r.get('error') or '')[:300]}")
        return "no part it names takes it (" + "; ".join(why) + ")"

    def _answers(self, claim: str, task: dict, part: dict) -> bool:
        """Whether the belief answers this part by the part's own test
        (request_parts.assign on a copy with the part open, the belief named
        for it): its kind's value, or its words for a yes/no or narrative
        part."""
        import json as _json
        from core.investigation_tasks import _graph_nodes, _known_hosts
        from core.request_parts import assign
        if not isinstance(part, dict) or part.get("kind") == "umbrella":
            return False
        probe = _json.loads(_json.dumps({"text": task.get("text"), "parts": task.get("parts") or []}))
        pid = str(part.get("id"))
        for p in probe["parts"]:
            if isinstance(p, dict):
                p["status"] = "open" if str(p.get("id")) == pid else "answered"
        return pid in assign(probe, _graph_nodes(self.case), [claim], known_hosts=_known_hosts(self.case),
                             explicit={pid: [claim]}, lenient=True)

    def _withdraw(self, claim: str, why: str) -> None:
        from core.claim_graph import supersede
        try:
            supersede(self.case, claim, reason=("kept as an observation: the finding served only the question "
                                                f"parts it named, and {why}")[:1000])
        except Exception:  # noqa: BLE001
            pass

    def _observe(self, f: dict[str, Any], basis: list[dict], i: int, why: str) -> str:
        """Keep a finding as an observation with its evidence; the reply."""
        r = self.m.add_observation(str(f.get("statement") or ""), f.get("host") or None,
                                   f.get("time") or None, basis) if self.m is not None else {}
        self._count_obs(r)
        said = f"finding {i + 1} was kept as an observation: {why}"
        self.out["notes"].append(said)
        return said

    def _record(self, f: dict[str, Any], basis: list[dict], quotes: list[str],
                rows: list[dict]) -> tuple[str, str, str]:
        """(gate, error, claim id): gate "" when recorded."""
        calls = list(dict.fromkeys(b["call_id"] for b in basis))
        args = {"description": str(f.get("statement") or ""),
                "confidence": _TIER.get(str(f.get("confidence") or "").lower(), "LIKELY"),
                "host": str(f.get("host") or (self.item.get("source_ref") or {}).get("host") or ""),
                "linked_call_id": calls[0], "input_call_ids": calls,
                "supporting_evidence": ""}
        args["supporting_evidence"] = self._evidence(basis, args["description"])
        if rows:
            args["indicators"] = rows
        # A statement an evaluator challenged at this tier goes to it again
        # only with a row it has not judged yet (outside the union of the
        # rows of every challenged submit of the statement): a subset or a
        # reshuffle of judged rows is refused here. Digits are kept (a time
        # or a count changes the claim); a reworded statement is a new key,
        # and the evaluator judges it again.
        key = (" ".join(args["description"].split()).casefold(), args["confidence"])
        rows = {str(b.get("row_ref") or f"{b['call_id']}:{b.get('quote') or ''}") for b in basis}
        seen = self.challenged.get(key)
        if seen is not None and rows <= seen["rows"]:
            return ("challenged_before", f"an evaluator already challenged this statement at "
                    f"{args['confidence']} on the rows {', '.join(sorted(seen['rows'])[:12])}: {seen['text'][:_REFUSAL_CHARS]}. "
                    "Cite a row it has not judged, split the statement into what each row shows, or lower its "
                    "tier", "")
        out = self.agent._call_once(_RECORD, args, turn=self.turn, budget_free=True,
                                    in_context=lambda _id: False)
        d = _parse(out.get("result", ""))
        if d.get("success") is True:
            return "", "", "" if d.get("duplicate") else str(d.get("claim_id") or "")
        text = _item_refusal(d) if d.get("error") else str(out.get("result") or "")[:1200]
        # The evaluator's structured verdict only: a gate message that
        # quotes the word is no verdict.
        verdict = d.get("evaluate_verdict") or (d.get("evaluation") if isinstance(d.get("evaluation"), dict)
                                                else {}).get("verdict")
        if str(verdict or "").upper() in ("CHALLENGED", "UNCERTAIN"):
            judged = self.challenged.setdefault(key, {"rows": set(), "text": ""})
            judged["rows"] |= rows
            # the evaluator's own words, when it gave them, not the gate's
            ev_text = (d.get("evaluation") or {}).get("text") if isinstance(d.get("evaluation"), dict) else ""
            judged["text"] = _cut(ev_text, 600) if ev_text else text
        return str(d.get("gate") or out.get("kind") or "refused"), text, ""

    def _evidence(self, basis: list[dict], statement: str = "") -> str:
        """The finding's supporting evidence fit to its share of the
        evaluator's window, the statement counted in it: each cited row
        whole while the total fits, else its quote, and the rows beyond
        that counted. A fit rule, never a choice of rows."""
        room = int(_evaluator_chars() * EVIDENCE_SHARE) - len(statement)
        lines, used, more = [], 0, 0
        for b in basis:
            for text in (f"[call {b['call_id']}] {self._full_row(b)}", f"[call {b['call_id']}] {b.get('quote') or ''}"):
                if used + len(text) + 1 <= room:
                    lines.append(text)
                    used += len(text) + 1
                    break
            else:
                more += 1
        if more:
            lines.append(f"({more} more row(s) cited)")
        return "\n".join(lines)

    def _full_row(self, b: dict[str, Any]) -> str:
        """The whole row a quote resolves to (every value the row shows,
        for the evidence checks and the evaluator), else the quote."""
        if b.get("row_ref") and self.m is not None:
            try:
                row = self.m.row_text(str(b["row_ref"]))
                if row:
                    return row[:2000]
            except Exception:  # noqa: BLE001
                pass
        return str(b.get("quote") or "")

    def _link(self, claim: str) -> str:
        """Link a recorded finding to the item's question; the refusal text,
        "" when linked or nothing to link."""
        from core.investigation_tasks import load_tasks, update_task
        if self.kind not in ("view_row_opened", "plan") or not self.item.get("task_ids"):
            return ""
        task_id = str(self.item["task_ids"][0])
        try:
            if self.kind == "view_row_opened":
                part = self._view_part()
                if not part:
                    return ""
                r = update_task(self.case, task_id, parts={part: {"claim_ids": [claim]}})
            else:
                task = next((t for t in load_tasks(self.case).get("tasks") or [] if str(t.get("id")) == task_id), {})
                r = update_task(self.case, task_id,
                                related_claim_ids=list(task.get("related_claim_ids") or []) + [claim])
        except Exception as e:  # noqa: BLE001
            return f"its link to {task_id} failed: {e}"[:300]
        if r.get("success") is False:
            self.out["notes"].append(f"link {claim} to {task_id}: {r.get('error')}"[:300])
            return f"it does not answer {task_id}: {str(r.get('error') or '')[:400]}"
        return ""

    def _view_part(self) -> str:
        ref = self.item.get("source_ref") or {}
        try:
            v = next((v for v in self.m.views() if v["view_id"] == ref.get("view_id")), None)
        except Exception:  # noqa: BLE001
            v = None
        return str((v or {}).get("part_id") or "")

    def _refused_twice(self, entry: dict[str, Any]) -> None:
        """Not recorded: the labels and events resting on it are written
        unknown with the gate's note, and a followup carries the refusal."""
        gate, err = str(entry.get("gate") or "refused"), str(entry.get("error") or "")
        note = f"its finding was refused twice ({gate})"
        if (entry.get("finding") or {}).get("_arrival"):
            self._arrival_missing()
        for lab in entry.get("labels", []) + entry.get("deferred_labels", []):
            ok = self._write_label(lab, label="unknown", note=note)
            self._lmark(lab, "unknown_refused_twice" if ok else "failed", held_for=self._held_for(lab),
                        through=entry.get("at", ""))
        for ev in entry.get("events", []):
            vid = self._write_event(ev)
            if vid:
                self.m.label(f"v:{vid}", "unknown", note=note)
            self._emark(ev, "unknown_refused_twice" if vid else "failed", held_for=self._held_for(ev),
                        through=entry.get("at", ""))
        f = entry.get("finding") or {}
        calls = sorted(entry.get("calls") or [])
        host = str(f.get("host") or (self.item.get("source_ref") or {}).get("host") or "")
        why = f"a finding refused twice by {gate}: {str(f.get('statement') or '')[:160]}. The gate said: {err[:300]}"
        # A follow-up of a refusal whose finding the same gate refuses again
        # raises no further one: a reworded statement would escape the key
        # below and chain follow-ups without end.
        mine = self.item.get("source_ref") or {}
        if mine.get("kind") == "refusal" and mine.get("gate") == gate:
            self.out["notes"].append(f"finding {entry.get('index')} kept out ({gate}) again; no new follow-up")
            return
        # Keyed by the gate and the statement, never by the item: the same
        # finding refused again by the same gate returns this item (open or
        # closed), so a model that resubmits it cannot chain new follow-ups.
        said = hashlib.sha1(" ".join(str(f.get("statement") or "").split()).casefold().encode()).hexdigest()[:16]
        entry = {"said": said, "why": why, "ask": err[:400], "call_ids": calls}
        log = self.agent_log()
        held = next((e for e in log.work_items() if e.get("origin") == "followup"
                     and (e.get("source_ref") or {}).get("kind") == "refusal"
                     and (e.get("source_ref") or {}).get("gate") == gate
                     and said in {r.get("said") for r in (e.get("source_ref") or {}).get("refused") or []}), None)
        if held is None:
            # One followup per item and gate, listing its refused findings:
            # the open one takes this finding too.
            held = next((e for e in log.work_items() if e.get("origin") == "followup" and e.get("status") == "due"
                         and (e.get("source_ref") or {}).get("kind") == "refusal"
                         and (e.get("source_ref") or {}).get("gate") == gate
                         and (e.get("source_ref") or {}).get("item") == self.item.get("call_id")), None)
            if held is not None:
                from core import frontier_queue as Q
                refused = list((held.get("source_ref") or {}).get("refused") or []) + [entry]
                Q._set_ref(log, held, refused=refused)
                Q._set_why(log, held, f"{len(refused)} findings refused twice by {gate}: repair each from its "
                                      "rows, or let it go")
        made = held or log.add_work_item(
            "followup", list(self.item.get("task_ids") or []), "", {"host": host}, why, status="due",
            source_ref={"kind": "refusal", "closed_by": "executor", "gate": gate, "call_id": calls[0] if calls else 0,
                        "call_ids": calls, "ask": err[:400], "item": self.item.get("call_id"), "refused": [entry]},
            extra_key=f"refusal:{gate}:{said}")
        self._made(made)
        self.out["notes"].append(f"finding {entry.get('index')} kept out ({gate}); followup #{made.get('call_id')}")

    def _release(self, entry: dict[str, Any], claim: str = "") -> None:
        """A repaired finding's deferred labels and events go to the map;
        the events labelled from the findings now recorded."""
        for lab in entry.get("deferred_labels", []):
            if _ref_key(lab.get("ref")) in self.consumed:
                self._lmark(lab, "a_finding_row", held_for=self._held_for(lab), through=entry.get("at", ""))
                continue
            ok = self._write_label(lab)
            self.out["labels"] += int(ok)
            self._lmark(lab, "released" if ok else "failed", held_for=self._held_for(lab),
                        through=entry.get("at", ""), claim=claim)
        for ev in entry.get("events", []):
            vid = self._put_event(ev)
            self._emark(ev, "released" if vid else "failed", held_for=self._held_for(ev),
                        through=entry.get("at", ""), claim=self._event_claim)

    @staticmethod
    def agent_log():
        from core.execution_log import log
        return log

    # ── the rest of a submit ─────────────────────────────────────────────

    def _resting(self, keys: list[tuple], calls: set[int]) -> dict[str, Any] | None:
        """The pending finding an entry rests on: one of its entities, or a
        basis call it shares."""
        for p in self.pending:
            if set(keys) & set(p.get("keys") or []) or (calls and calls & set(p.get("calls") or [])):
                return p
        return None

    def _entity(self, ref: Any, host: str = "") -> int:
        k = _ref_key(ref)
        if k is None or k[0] not in ("host", "account", "file", "endpoint"):
            return 0
        try:
            return int(self.m.upsert_entity(k[0], str(ref["value"]), host=str(ref.get("host") or host or "")))
        except Exception:  # noqa: BLE001
            return 0

    def _write_label(self, lab: dict[str, Any], label: str | None = None, note: str = "") -> bool:
        eid = self._entity(lab.get("ref"))
        if not eid:
            return False
        basis = lab.get("_basis") or []
        said = label or str(lab.get("label") or "unknown")
        r = self.m.label(f"e:{eid}", said, basis, note=note or str(lab.get("why") or "")[:300])
        if r.get("ok"):
            self.effects.add(("label", eid, said))
        return bool(r.get("ok"))

    def _write_event(self, ev: dict[str, Any]) -> int:
        host = str(ev.get("host") or "")
        ids = {r: self._entity(ev.get(r), host) or None for r in ("actor", "object", "src", "dst")}
        r = self.m.add_event(host, str(ev.get("time") or ""), str(ev.get("kind") or "other"),
                             actor=ids["actor"], object=ids["object"], basis=ev.get("_basis") or [],
                             src=ids["src"], dst=ids["dst"], verb=str(ev.get("verb") or ""))
        if not r.get("ok"):
            self.out["notes"] += [f"event on {host}: {n}" for n in r.get("notes") or []][:3]
            return 0
        ev["_new"] = not r.get("existing")
        return int(r.get("event_id") or 0)

    def _put_event(self, ev: dict[str, Any]) -> int:
        """Write an event and label it from the findings recorded in this
        item: the arrival event with the arrival's claim; any other event
        with the claim of a recorded finding it rests on (a shared entity or
        basis call) whose row for one of its entities is attacker-side.
        Else it stays unlabelled: nothing is labelled without a claim."""
        self._event_claim = ""
        vid = self._write_event(ev)
        if not vid:
            return 0
        self.out["events"] += int(bool(ev.get("_new")))
        if ev.get("_new"):
            self.effects.add(("event", vid))
        keys = {k for r in ("actor", "object", "src", "dst") if (k := _ref_key(ev.get(r)))}
        calls = {b["call_id"] for b in ev.get("_basis") or [] if isinstance(b, dict) and "call_id" in b}
        for rec in reversed(self.recorded):
            if ev.get("_arrival_event"):
                hit = rec["arrival"]
            else:
                hit = bool(rec["attacker"] & keys) and (bool(rec["keys"] & keys) or bool(rec["calls"] & calls))
            if hit:
                self.m.label(f"v:{vid}", "attacker", ev.get("_basis") or [], note="its finding is the attacker's",
                             claim_id=rec["claim"])
                self._event_claim = rec["claim"]
                break
        return vid

    def _rest(self, args: dict[str, Any], labels: list[dict], run) -> None:
        if self.m is None:
            return
        for lab in labels:
            k = _ref_key(lab.get("ref"))
            if k is None or k in self.consumed:
                if k is not None:
                    self._lmark(lab, "a_finding_row")
                continue                                  # a recorded finding's typed row
            lab["_basis"], _q = self._basis(lab.get("basis"), run)
            p = self._resting([k], {b["call_id"] for b in lab["_basis"]})
            if p is not None:
                if lab not in p["labels"]:
                    p.setdefault("deferred_labels", []).append(lab)
                self._lmark(lab, "held", **self._hold(lab, p, [k]))
                continue
            eid = self._entity(lab.get("ref"))
            seen = bool(eid) and ("label", eid, str(lab.get("label") or "unknown")) in self.effects
            ok = self._write_label(lab)
            if ok and not seen:                           # a resubmitted label counts once
                self.out["labels"] += 1
            self._lmark(lab, "written" if ok else "failed")
        for ev in args.get("events") or []:
            if not isinstance(ev, dict):
                continue
            ev["_basis"], _q = self._basis(ev.get("basis"), run)
            keys = [k for r in ("actor", "object", "src", "dst") if (k := _ref_key(ev.get(r)))]
            p = self._resting(keys, {b["call_id"] for b in ev["_basis"]})
            if p is not None:
                p["events"].append(ev)
                self._emark(ev, "held", **self._hold(ev, p, keys))
                continue
            vid = self._put_event(ev)
            self._emark(ev, "written" if vid else "failed", claim=self._event_claim)
        for ob in args.get("observations") or []:
            if not isinstance(ob, dict):
                continue
            basis, _q = self._basis(ob.get("basis"), run)
            r = self.m.add_observation(str(ob.get("text") or ""), ob.get("host") or None, ob.get("time") or None,
                                       basis)
            self._count_obs(r)
        self._arrival(args.get("arrival") if self.take_arrival else None, run)
        for lead in list(args.get("leads") or []) + list(args.get("proposals") or []):
            self._lead(lead, proposal=lead in (args.get("proposals") or []))
        for i, c in enumerate(args.get("contradictions") or []):
            if isinstance(c, dict) and str(c.get("text") or "").strip():
                made = self.agent_log().add_work_item(
                    "followup", [], "", {"host": str(c.get("host") or "")}, str(c["text"])[:400], status="due",
                    source_ref={"kind": "contradiction", "closed_by": "executor", "item": self.item.get("call_id")},
                    extra_key="contradiction:" + hashlib.sha1(re.sub(r"\d+", "#", " ".join(
                        str(c["text"]).split()).casefold()).encode()).hexdigest()[:16])
                self._made(made)
        if self.kind == "view_row_opened":
            self._view(args.get("view"), args.get("examined"))

    def _arrival_finding(self, arrival: Any) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """A host pass's arrival anchor as a finding of its own, recorded
        through record_finding like any other: its statement and basis, the
        host and the arrival event's entities, and a host row (the owner's
        side) whose attacker_from is the arrival time, the row the incident
        window anchors a host by. None without an anchor with a statement."""
        if self.kind != "host_pass" or not isinstance(arrival, dict) or not isinstance(arrival.get("anchor"), dict):
            return None
        anchor = arrival["anchor"]
        host = str((self.item.get("source_ref") or {}).get("host") or "")
        ev = anchor.get("event") if isinstance(anchor.get("event"), dict) else {}
        from core.incident_map import _iso
        when = next((str(t) for t in (ev.get("time"), anchor.get("attacker_from")) if t and _iso(str(t))), "")
        tier = str(anchor.get("confidence") or "").lower()
        if not host or not str(anchor.get("statement") or "").strip() or not when or tier not in _TIER:
            return None                       # an unstated confidence or time never anchors
        entities = [{"kind": "host", "value": host}] + [ev[r] for r in ("actor", "src", "dst", "object")
                                                         if isinstance(ev.get(r), dict) and ev[r].get("value")]
        finding = {"statement": str(anchor["statement"]), "host": host, "basis": anchor.get("basis"),
                   "confidence": tier, "entities": entities, "_arrival": True}
        row = {"ref": {"kind": "host", "value": host}, "label": "benign", "attacker_from": when}
        return finding, row

    def _arrival_missing(self) -> None:
        """A host pass that ends without an arrival it could record (none
        given after the send-back, an anchor still without its tier or
        time, or its finding refused twice): said in the item's record,
        never taken as given. Nothing is written to the map, so an empty
        pass does not count as one that yielded; the host keeps no stated
        start, which the stop record and the reports disclose."""
        host = str((self.item.get("source_ref") or {}).get("host") or "")
        self.out["arrival_missing"] = True
        self.out["notes"].append(f"the pass of {host} ended without an arrival it could record")

    def _arrival(self, arrival: Any, run) -> None:
        if self.kind != "host_pass" or not isinstance(arrival, dict):
            return
        host = str((self.item.get("source_ref") or {}).get("host") or "")
        anchor = arrival.get("anchor") if isinstance(arrival.get("anchor"), dict) else None
        if anchor:
            basis, _q = self._basis(anchor.get("basis"), run)
            ev = anchor.get("event") if isinstance(anchor.get("event"), dict) else None
            if ev and ev.get("time"):
                event = {**ev, "host": host, "kind": ev.get("kind") or "access", "_basis": basis,
                         "verb": ev.get("verb") or "arrival", "_arrival_event": True}
                waiting = next((p for p in self.pending if p["finding"].get("_arrival")), None)
                if waiting is not None:
                    waiting["events"].append(event)        # labelled once its finding is recorded
                else:
                    self._put_event(event)
            if ev and ev.get("time"):
                self._chain_check(host, ev)
            elif anchor.get("attacker_from") and not any(r["arrival"] for r in self.recorded):
                r = self.m.add_observation(f"the attacker first acted on {host} at {anchor['attacker_from']}",
                                           host, str(anchor["attacker_from"]), basis)
                self._count_obs(r)
        elif isinstance(arrival.get("examined"), dict):
            ex = arrival["examined"]
            text = f"no inbound edge found on {host}: {str(ex.get('why') or '')[:300]}"
            r = self.m.add_observation(text, host, None, [{"call_id": c} for c in _ints(ex.get("call_ids"))])
            self._count_obs(r)

    def _chain_check(self, host: str, ev: dict[str, Any]) -> None:
        """An arrival from another case host at a time before that host's
        own start cannot both hold: one of the two is wrong. A note and a
        follow-up, never a change of either."""
        src = ev.get("src") if isinstance(ev.get("src"), dict) else ev.get("actor")
        if not isinstance(src, dict) or src.get("kind") != "host":
            return
        try:
            other = self.m.case_host(src.get("value"))
            starts = (self.m.window().get("hosts") or {}).get(other) or []
        except Exception:  # noqa: BLE001
            return
        from core.incident_map import _iso
        when = _iso(str(ev.get("time") or ""))
        start = str(starts[0][0]) if starts else ""
        if not other or other == host or not when or not start or _iso(start) <= when:
            return
        text = (f"the arrival on {host} from {other} at {when} precedes {other}'s own start {start}: either the "
                f"arrival's source or {other}'s start is wrong")
        self.out["notes"].append(text)
        self._made(self.agent_log().add_work_item(
            "followup", list(self.item.get("task_ids") or []), "", {"host": host}, text, status="due",
            source_ref={"kind": "chain", "closed_by": "executor", "host": host, "from": other},
            extra_key=f"chain:{host}:{other}"))

    def _lead(self, lead: Any, proposal: bool) -> None:
        """A lead or a synthesis proposal as plan items, through the plan's
        read check. A proposal's source may also be a content class of the
        host's evidence (the triage's class labels): code resolves it to
        that class's files on the host. A proposal neither resolves is
        dropped with its reason, which the next synthesis reads."""
        from core import question_plan as Q
        if not isinstance(lead, dict) or not str(lead.get("why") or "").strip():
            return
        why = str(lead.get("why"))[:80]
        if proposal and not (lead.get("host") and (lead.get("source") or lead.get("pattern"))):
            self._drop(f"proposal {why!r}: no target (a host and a source or search terms)", proposal)
            return
        tools = {t for t, _w in Q.reading_tools()}
        read = {k: lead.get(k) for k in ("tool", "host", "source", "pattern", "why") if lead.get(k)}
        reads, why_not = Q.check_reads(self.case, read, tools)
        if not reads:
            self._drop(f"{'proposal' if proposal else 'lead'} {why!r}: {why_not}", proposal)
            return
        for v in reads:
            self._made(self.agent_log().add_work_item(
                "plan", list(self.item.get("task_ids") or []), v["tool"], v["target"], v["why"],
                source_ref={"kind": "lead", "item": self.item.get("call_id")}))
        self.out["proposals"] += int(proposal)

    def _made(self, entry: dict[str, Any] | None) -> None:
        """Counted once per item: a resubmitted lead returns the same one."""
        key = ("item", int(entry["call_id"])) if isinstance(entry, dict) and entry.get("call_id") else None
        if key is not None and key in self.effects:
            return
        self.out["items"] += 1
        if key is not None:
            self.effects.add(key)

    def _drop(self, text: str, proposal: bool) -> None:
        self.out["dropped"].append(text)
        if proposal:
            self.out.setdefault("proposals_dropped", []).append(text[:300])

    def _view(self, view: Any, examined: Any) -> None:
        part = self._view_part()
        task_id = str((self.item.get("task_ids") or [""])[0])
        if isinstance(view, dict) and part and task_id:
            r = self.m.declare_view(task_id, part, view)
            self.out["notes"] += [f"view: {n}" for n in r.get("notes") or []][:3]
            self._hold_redeclared(task_id, part)
        if self.out["findings"] or not isinstance(examined, dict) or not part:
            return
        ids = _ints(examined.get("call_ids"))
        why = str(examined.get("why") or "")
        ref = self.item.get("source_ref") or {}
        try:
            # The part's current view (a re-declaration replaces it) against
            # the rows the item was shown: examined never covers a row the
            # model did not see.
            v = next((v for v in self.m.views() if str(v["task_id"]) == task_id and str(v["part_id"]) == part), {})
            others = [r for r in v.get("rows") or [] if r.get("status") == "open"
                      and str(r.get("row_key")) not in self.shown_rows]
        except Exception:  # noqa: BLE001
            others = [None]
        if not others and ids and len(why) >= 20:
            from core.investigation_tasks import update_task
            r = update_task(self.case, task_id, parts={part: {"limitation": {
                "basis": "examined", "reason": why, "call_ids": ids}}})
            if r.get("success") is not False:
                self.effects.add(("limitation", task_id, part))
                return
            self.out["notes"].append(f"limitation of {task_id} {part}: {r.get('error')}"[:300])
        r = self.m.add_observation(f"row {ref.get('row_key')} of {task_id} {part}: {why}"[:600], None, None,
                                   [{"call_id": c} for c in ids])
        self._count_obs(r)

    def _hold_redeclared(self, task_id: str, part: str) -> None:
        """The rows of a view this part's own item re-declared are held by
        this item: a re-declaration never raises a follow-on item for the
        same part (rows left open are disclosed as empty rows)."""
        from core.execution_log import _touched
        try:
            v = next((v for v in self.m.views() if str(v["task_id"]) == task_id and str(v["part_id"]) == part), None)
        except Exception:  # noqa: BLE001
            v = None
        if not v:
            return
        log = self.agent_log()
        rows = [str(r["row_key"]) for r in v.get("rows") or [] if r.get("status") == "open"]
        with log._lock:
            ref = dict(self.item.get("source_ref") or {})
            ref["rows"] = list(dict.fromkeys([str(r) for r in ref.get("rows") or []] + rows))
            self.item["source_ref"] = ref
            live = next((e for e in log.work_items() if e.get("call_id") == self.item.get("call_id")), None)
            if live is not None:
                live["source_ref"] = ref
                _touched(live)
                log._index_version += 1
                log._flush()

    def yielded(self) -> bool:
        """The item changed state of its own: a claim on rows it had not
        cited, a label, an event, an observation or an item it wrote."""
        return bool(self.effects)

    def _count_obs(self, r: dict[str, Any]) -> None:
        """Counted once per observation: a resubmitted one upserts the same."""
        if not r.get("ok"):
            return
        key = ("observation", int(r.get("entity_id") or 0))
        if r.get("entity_id") and key in self.effects:
            return
        self.out["observations"] += 1
        if r.get("entity_id"):
            self.effects.add(key)

    def _cited(self, claim: str, basis: list[dict]) -> None:
        """A recorded claim is an effect only when its basis holds a row no
        earlier claim of this item cited (a reworded claim is none)."""
        rows = {str(b.get("row_ref") or f"{b.get('call_id')}:{b.get('quote')}") for b in basis}
        if rows - self.cited_rows:
            self.effects.add(("claim", claim))
        self.cited_rows |= rows


# The evaluator's evidence room, shared with the evaluate tool's cited rows.
from core.model_context import EVIDENCE_SHARE, evaluator_chars as _evaluator_chars  # noqa: E402
# Beside threads the run's end never waits for (their unfinished work stays
# pending and disclosed).
_NOT_AWAITED = frozenset({"coverage"})


class FrontierRun:
    """The frontier loop over one Agent (its client, toolbox, ui, log, per
    call path and close-out are the Agent's own). One pass per item: the
    triage pass and the question plans (the conversation loop's own
    sources), the queue generated from the map's feed, then the first due
    item run to its submit and closed. When nothing is due and the map's
    semantic fingerprint changed since the last synthesis, a synthesis item
    reads the whole map. The run stops when no item is due and no synthesis
    is due: no count, clock or token limit (design 2.7)."""

    def __init__(self, agent):
        self.a = agent
        self.case = str(agent.case_dir or "")
        self.turn = 0
        self.m = None
        self.ran: dict[str, int] = {}
        self.findings = 0
        self.sweeps: list[dict[str, Any]] = []      # sweeps counting in the background
        self.state: dict[str, Any] = {}
        self.besides: dict[str, Any] = {}           # the triage and the plans, beside the items
        # Statements an evaluator challenged, by tier: the rows it judged and its words.
        self.challenged: dict[tuple[str, str], dict] = {}
        # The records the run's items were shown (row identities, core.shown_rows,
        # and copied index entries), each credited to the first item shown it:
        # one set per run, so a later item or a continuation that shows the same
        # records again under other arguments reads nothing new. In memory: a
        # resumed run credits them once more (more patience, never less).
        self.read_owner: dict[str, int] = {}
        self.read_count: dict[int, int] = {}
        self.read_calls: set[int] = set()
        self.read_by_source: dict[str, set[str]] = {}   # file -> its records shown to the run

    def run(self) -> str:
        from core import frontier_queue as Q
        from core import incident_map
        from core.execution_log import log
        a = self.a
        self.m = incident_map.open(self.case) if self.case else None
        state = self.state = Q.load_state(self.case) if self.case else {}
        fresh = state.get("mode") != "frontier"
        if self.case and fresh:
            state = self.state = {"mode": "frontier", "cursor": 0}
            seeded = Q.seed(log, self.case, state)
            a._log({"event": "frontier_seed", "cursor": seeded["cursor"], "items": seeded["items"][:60],
                    "swept": seeded.get("swept") or {}})
        if self.case and not fresh:
            try:
                folded = Q.fold_open(log, self.case, state)
                if folded.get("input"):
                    a._log({"event": "frontier_fold", **folded})
            except Exception as e:  # noqa: BLE001 - a fold that fails leaves the queue as it was
                a._log({"event": "frontier_fold_failed", "error": str(e)[:200]})
        a._log({"event": "frontier_start", "fresh": fresh, "cursor": state.get("cursor", 0)})
        self._brief_item(state)
        self._intake()
        stopped = "finished"
        while self.case:
            self.turn += 1
            a._turn = self.turn
            a.stats["turns"] = self.turn
            self._pass(state)
            item = self._next_item()
            if item is None and (self.sweeps or self._busy_beside()):
                # Nothing to run while counts, the triage or the plans are
                # still at work: wait for them, apply them, and let what they
                # make raise items. Never for the coverage path: what it has
                # not parsed by the end stays pending and is disclosed.
                self._collect(wait=True)
                for name, t in list(self.besides.items()):
                    if name not in _NOT_AWAITED:
                        t.join()
                continue
            item = item or self._synthesis(state)
            if item is None:
                verdict = self._report_gate(state)
                if verdict == "item":
                    continue
                stopped = verdict
                break
            self._run_one(item)
        a._log({"event": "frontier_stop", "items": dict(self.ran), "findings": self.findings,
                "stopped": stopped, "left": self._left(state)})
        summary = (f"frontier: {sum(self.ran.values())} item(s) run "
                   f"({', '.join(f'{k} {v}' for k, v in sorted(self.ran.items())) or 'none'}), "
                   f"{self.findings} finding(s) recorded")
        return a._run_end(self.turn, stopped, summary)

    def _left(self, state: dict[str, Any]) -> dict[str, Any]:
        """What the stop leaves, measured: items due and proposed (any
        origin), feed changes not consumed, pending evidence units, triage
        items closed without a yield, whether the current state was
        synthesised."""
        from core.execution_log import log
        items = log.work_items()
        out: dict[str, Any] = {
            "due": sum(1 for i in items if i.get("status") == "due"),
            "proposed": sum(1 for i in items if i.get("status") == "proposed"),
            "triage_dismissed": sum(1 for i in items if i.get("origin") == "triage" and i.get("status") == "dismissed"),
        }
        try:
            out["feed_unconsumed"] = len(self.m.changes_since(int(state.get("cursor") or 0))[0]) if self.m else 0
            out["synthesis_current"] = bool(self.m) and self.m.fingerprint() in (state.get("synthesised") or [])
            if self.m:
                from core.incident_window import window_in_frame
                from core.indicators import frame_for
                out["hosts_without_arrival"] = list(
                    window_in_frame(self.m.window(), frame_for(self.case)).get("unanchored") or [])
            else:
                out["hosts_without_arrival"] = []
        except Exception:  # noqa: BLE001
            pass
        try:
            from core.coverage_ledger import load_ledger
            led = load_ledger(self.case)
            out["pending_units"] = sum(1 for level in ("items", "classes")
                                       for u in (led.get(level) or {}).values()
                                       if isinstance(u, dict) and u.get("state") == "pending")
        except Exception:  # noqa: BLE001
            pass
        return out

    def _brief_item(self, state: dict[str, Any]) -> None:
        """Once per brief (again when CASE.md changes): one tool-less call
        lists the entities the brief names with the side it states, and code
        writes them to the map as labels stated by the brief (held like
        beliefs: a finding against one raises a label conflict and a
        follow-up). Code holds no names; an entity whose sentence is not in
        the brief, or whose value its sentence does not hold, is dropped."""
        import hashlib
        from agent.item_executor import ItemSpec, run_item
        from core import frontier_queue as Q
        from core.frontier_prompts import BRIEF_SUBMIT, BRIEF_SYS, case_block
        from core.incident_map import BRIEF
        block = case_block(self.case) if self.case else ""
        if not block or self.m is None:
            return
        digest = hashlib.sha1(block.encode("utf-8")).hexdigest()[:16]
        if state.get("brief_hash") == digest:
            return
        try:
            ran = run_item(self.a, ItemSpec(kind="brief", system=BRIEF_SYS, user=block, core_tools=[],
                                            submit=BRIEF_SUBMIT), turn=0)
        except Exception as e:  # noqa: BLE001 - the run goes on without the brief's labels
            self.a._log({"event": "frontier_brief_failed", "error": str(e)[:200]})
            return
        text = _fold(block)
        written, dropped = 0, 0
        before = self.m.brief_labels() if isinstance(ran.submit, dict) else {}
        stated: set[str] = set()
        for e in (ran.submit or {}).get("entities") or []:
            if not isinstance(e, dict):
                continue
            value, sentence = str(e.get("value") or "").strip(), str(e.get("sentence") or "")
            if (e.get("kind") not in ("host", "account", "file", "endpoint") or e.get("side") not in ("attacker",
                                                                                                        "benign")
                    or not value or _fold(sentence) not in text or _fold(value) not in _fold(sentence)):
                dropped += 1
                continue
            try:
                eid = self.m.upsert_entity(e["kind"], value)
                self.m.label(f"e:{eid}", e["side"], [], note=f"stated by the brief: {sentence[:300]}",
                             claim_id=BRIEF, _by=BRIEF)
                stated.add(f"e:{eid}")
                written += 1
            except Exception:  # noqa: BLE001
                dropped += 1
        # A label an earlier brief stated that this one no longer states is
        # the user's statement no more.
        for target in sorted(set(before) - stated):
            try:
                self.m.label(target, "unknown", [], note="no longer stated by the brief", claim_id=BRIEF, _by=BRIEF)
            except Exception:  # noqa: BLE001
                pass
        state["brief_hash"] = digest
        Q.save_state(self.case, state)
        self.a._log({"event": "frontier_brief", "labels": written, "dropped": dropped})

    def _intake(self) -> None:
        """The evidence inventory, when no run has taken it: the plans and
        the triage start from it (the conversation loop's analyst calls it
        first)."""
        try:
            from core.evidence_inventory_gate import inventory_satisfied
            if self.case and not inventory_satisfied(self.case):
                self.a._call_once("misc.inventory_evidence", {}, turn=0, budget_free=True,
                                  in_context=lambda _id: False)
        except Exception as e:  # noqa: BLE001
            self.a._log({"event": "frontier_intake_failed", "error": str(e)[:200]})

    def _pass(self, state: dict[str, Any]) -> None:
        """The item sources, each failing open: the triage pass, the
        per-question plans and re-plans, the queue from the feed."""
        from core import frontier_queue as Q
        from core.execution_log import log
        a = self.a
        self._collect()
        try:
            from core.investigation_tasks import load_tasks
            tasks = [t for t in load_tasks(self.case).get("tasks") or [] if isinstance(t, dict) and t.get("id")]
        except Exception:  # noqa: BLE001
            tasks = []
        # The evidence triage and the question plans are model calls of their
        # own: neither is a stage the items wait for. Each runs beside the
        # items, one at a time per kind, and what it makes joins the queue.
        self._beside("triage", lambda turn: a._triage_evidence(turn, self.case))
        try:
            from core.deferred_intents import work_order_plan_on
            if work_order_plan_on():
                self._beside("plan", lambda turn: a._plan_questions(turn, self.case, tasks))
        except Exception as e:  # noqa: BLE001
            a._log({"event": "work_order_plan_failed", "turn": self.turn, "error": str(e)[:200]})
        a._claim_source_items(self.turn, self.case, tasks)
        try:
            from core.coverage_path import coverage_on, run_pass
            if coverage_on():
                values = [str(e["value"]) for e in self.m.attacker_entities()] if self.m is not None else []
                self._beside("coverage", lambda turn: a._log({"event": "frontier_coverage", "turn": turn,
                                                               **run_pass(a, self.case, values)}))
        except Exception as e:  # noqa: BLE001
            a._log({"event": "frontier_coverage_failed", "turn": self.turn, "error": str(e)[:200]})
        self._adopt_lookups()
        try:
            made = Q.generate(log, self.case, state, sweeper=self._sweeper)
            if made["items"] or made["swept"]:
                a._log({"event": "frontier_sweep", "turn": self.turn, "items": made["items"][:60],
                        "swept": made["swept"]})
        except Exception as e:  # noqa: BLE001
            a._log({"event": "frontier_queue_failed", "turn": self.turn, "error": str(e)[:200]})

    def _next_item(self) -> dict[str, Any] | None:
        """The first due item, except the coverage reads the coverage path
        has not taken yet (their classes are parsed and swept first) while
        any other item is due."""
        from core import frontier_queue as Q
        from core.execution_log import log
        skip: set[int] = set()
        try:
            from core.coverage_path import coverage_on, held
            if coverage_on():
                from core.coverage_ledger import load_ledger
                skip = held(log, load_ledger(self.case))
        except Exception:  # noqa: BLE001
            skip = set()
        ctx = Q.rank_context(self.m, self.case)
        due = Q.due_items(log, ctx)
        # The coverage path's held reads wait only while other work is due:
        # with nothing else left they run as model reads, so the run's end
        # (which never waits for the coverage lane) leaves no class untouched.
        # An item with early sightings is checked from the map first (no
        # model call): one whose every sighting no longer holds closes.
        due = [i for i in due if not (i.get("source_ref") or {}).get("early") or Q.premise(log, self.m, i)]
        item = next((i for i in due if int(i["call_id"]) not in skip), None) or (due[0] if due else None)
        # Why the item came now, for the trace (frontier_item_start).
        self._rank = Q._rank_key(item, ctx)[0] if item is not None else None
        return item

    def _beside(self, name: str, fn) -> None:
        """Run ``fn(turn)`` in a thread of its own unless the last one of
        this kind still runs; its failure is logged, never raised."""
        import threading
        running = self.besides.get(name)
        if running is not None and running.is_alive():
            return
        turn = self.turn

        def work() -> None:
            try:
                fn(turn)
            except Exception as e:  # noqa: BLE001
                self.a._log({"event": f"frontier_{name}_failed", "turn": turn, "error": str(e)[:200]})
        t = threading.Thread(target=work, name=f"atlas-frontier-{name}", daemon=True)
        self.besides[name] = t
        t.start()

    def _busy_beside(self) -> bool:
        """A beside thread the stop waits for is at work."""
        return any(t.is_alive() for name, t in self.besides.items() if name not in _NOT_AWAITED)

    def _sweeper(self, batch: list[dict[str, Any]]) -> dict[str, Any]:
        """The batch sweep of newly labelled attacker values. With
        ATLAS_ESTATE_COUNT_ASYNC (the estate count's switch) the tables are
        read in a thread of their own, as the estate count's are, and the
        result is applied on this thread at the next pass (_collect); items
        run meanwhile. Off, the sweep runs here."""
        import threading
        from core import frontier_sweep as S
        from core.deferred_intents import estate_count_async_on
        from core.execution_log import log
        job = S.prepare(self.case, log, batch)
        if job is None:
            return {}
        if not estate_count_async_on():
            return S.apply(log, S.count(job))
        job["thread"] = threading.Thread(target=S.count, args=(job,), name="atlas-frontier-sweep", daemon=True)
        self.sweeps.append(job)
        job["thread"].start()
        self.a._log({"event": "frontier_sweep_started", "turn": self.turn, "entities": job["entities"],
                     "tables": len(job["tables"])})
        return {"started": job["entities"]}

    def _collect(self, wait: bool = False) -> None:
        """Apply every finished background sweep (``wait``: every one)."""
        from core import frontier_sweep as S
        from core.execution_log import log
        for job in list(self.sweeps):
            if wait:
                job["thread"].join()
            if job["thread"].is_alive():
                continue
            self.sweeps.remove(job)
            try:
                r = S.apply(log, job)
                self.a._log({"event": "frontier_sweep_applied", "turn": self.turn, **r})
            except Exception as e:  # noqa: BLE001
                self.a._log({"event": "frontier_sweep_failed", "turn": self.turn, "error": str(e)[:200]})

    def _adopt_lookups(self) -> None:
        """A look-up a record gate proposed (origin reason: a ready call
        with its target) is adopted at once: the director that adopts it in
        the conversation loop is off here. A proposal without a target (a
        synthesis blocker) stays proposed; the synthesis item lists it."""
        from core.execution_log import log
        from core.work_order import dispose_work_item
        for i in log.work_items(statuses=("proposed",)):
            if i.get("origin") == "reason" and i.get("tool"):
                dispose_work_item(log, i["call_id"], "promote")

    def _synthesis(self, state: dict[str, Any]) -> dict[str, Any] | None:
        """A synthesis item when the map's semantic state is one no synthesis
        has read yet, else None (the stop). Every state read is kept, so a
        state the run returns to (a label flipped and flipped back) is not
        read again: it gives the stateless reader nothing new."""
        from core import frontier_queue as Q
        from core.execution_log import log
        if self.m is None:
            return None
        fp = self.m.fingerprint()
        read = list(state.get("synthesised") or [])
        if fp in read:
            return None
        state["synthesised"] = read + [fp]
        Q.save_state(self.case, state)
        return log.add_work_item("synthesis", [], "", None,
                                 "read the whole incident map: what cannot both hold, and the reads that would "
                                 "close a gap", status="due",
                                 source_ref={"kind": "synthesis", "closed_by": "executor",
                                             "dropped": list(state.get("proposals_dropped") or [])[:12]},
                                 extra_key=f"synthesis:{fp}")

    def _run_one(self, item: dict[str, Any]) -> None:
        """Run one item; while it runs it is marked RUNNING, so a beside
        thread (the coverage path) never closes it under the item."""
        from core.frontier_queue import RUNNING
        cid = int(item.get("call_id") or 0)
        RUNNING.add(cid)
        try:
            self._run_one_inner(item)
        finally:
            RUNNING.discard(cid)

    def _run_one_inner(self, item: dict[str, Any]) -> None:
        from agent.item_executor import run_item
        from core.execution_log import log
        from core.frontier_prompts import item_spec
        from core.work_order import close_item
        a = self.a
        origin = str(item.get("origin") or "")
        host = str((item.get("source_ref") or {}).get("host") or (item.get("target") or {}).get("host") or "")
        # An item of an origin with no frontier kind of its own (the evidence
        # triage's read items, the sources and absences behind claims, index
        # and series reads, a promoted look-up) runs as a planned read.
        from core.frontier_prompts import KINDS
        spec_item = item if origin in KINDS else {**item, "origin": "plan", "_origin": origin}
        self.ran[origin] = self.ran.get(origin, 0) + 1
        from core import frontier_queue as _Q
        _Q._set_ref(log, item, started=self.turn)          # its text is built now: nothing added later is read
        a._log({"event": "frontier_item_start", "turn": self.turn, "item": item["call_id"], "kind": origin,
                "tier": getattr(self, "_rank", None),
                "host": host})
        try:
            a.ui.set_run_state(activity=f"{origin.replace('_', ' ')} {host}".strip())
            a._persist_live_status()
        except Exception:  # noqa: BLE001
            pass
        if self.m is not None:
            self.m.sync()                                        # the map at the item's start
        applier = None
        try:
            spec = item_spec(self.case, spec_item, self.m)
            applier = SubmitApplier(a, self.case, self.m, item, spec.kind, self.turn)
            applier.challenged = self.challenged

            def verify_note(cid: int, quote: str, run) -> str | None:
                kept, _q = applier._basis([{"call_id": cid, "quote": quote}], run)
                return (kept[0].get("row_ref") or f"{cid}#shown") if kept else None
            ran = run_item(a, spec, turn=self.turn, on_submit=applier,
                           progress=lambda run: self._progress(applier, run),
                           verify_note=verify_note if spec.core_tools else None,   # a tool-less item reads nothing
                           on_empty=self._empty_note if spec.core_tools else None)
            applier.finish()
            if spec.kind == "host_pass" and not applier.arrival_done:
                applier._arrival_missing()                   # it ended without any submit taken
        except Exception as e:  # noqa: BLE001 - one item failing never ends the run
            if applier is not None:
                try:
                    applier.finish()                 # refused findings still become followups
                except Exception:  # noqa: BLE001
                    pass
            close_item(log, item["call_id"], "failed", f"error: {e}"[:300])
            a._log({"event": "frontier_item_end", "turn": self.turn, "item": item["call_id"], "kind": origin,
                    "end": "error", "error": str(e)[:300]})
            return
        out = applier.out
        self.findings += out["findings"]
        if origin == "synthesis":
            # What the next synthesis is told about this one's lost proposals.
            from core import frontier_queue as Q
            self.state["proposals_dropped"] = list(out.get("proposals_dropped") or [])
            Q.save_state(self.case, self.state)
        # Only the item's own effects: the threads beside it change the map
        # and the ledger too (core.frontier_queue's beside workers).
        yielded = applier.yielded() or self._own_reads(ran, int(item.get("call_id") or 0)) > 0
        if yielded and (ran.end == "context_fit" or (ran.end in ("stuck", "forced") and ran.progressed)):
            # Continuation, not truncation: an item the guard or the window
            # ended after it made progress hands its note and digest to one
            # follow-up. Yield-gated, so a continuation that gets nowhere
            # opens none.
            log.add_work_item("followup", list(item.get("task_ids") or []), "", {"host": host},
                              f"continue item {item['call_id']} ({origin}): it ended ({ran.end}) before it was done",
                              status="due",
                              source_ref={"kind": "continuation", "closed_by": "executor", "item": item["call_id"],
                                          "host": host, "call_ids": ran.calls[:40], "note": ran.notes[:60],
                                          "digest": ran.digest[:12000]},
                              extra_key=f"continuation:{item['call_id']}")
        status = "resolved" if yielded else "dismissed"
        close_item(log, item["call_id"], status, f"{ran.end}: {out['findings']} finding(s), {out['labels']} label(s), "
                   f"{out['events']} event(s), {out['items']} item(s)", ran.calls)
        if self.m is not None:
            self.m.sync()                                        # and at its end
        a._log({"event": "frontier_item_end", "turn": self.turn, "item": item["call_id"], "kind": origin,
                "end": ran.end, "rounds": ran.rounds, "calls": ran.calls[:60], "submits": ran.submits,
                "stuck_rounds": ran.stuck_rounds, "off_list": ran.refused_off_list, "readers": ran.readers,
                "rows_credited": self.read_count.get(int(item.get("call_id") or 0), 0),
                "input_tokens": ran.input_tokens, "output_tokens": ran.output_tokens,
                "yield": {k: out[k] for k in ("findings", "labels", "events", "observations", "items", "proposals")},
                "claims": out["claims"][:20], "refused": out["refused"][:20], "dropped": out["dropped"][:20],
                "unread_entries": ran.unread_entries[:20],
                "notes": out["notes"][:20], "status": status, "arrival_missing": bool(out.get("arrival_missing"))})

    def _progress(self, applier, run) -> tuple:
        """What a round of the item itself may change: its own effects (a
        claim on rows it had not cited, a label, an event, an observation,
        an item) and the evidence its own calls read. Never global state:
        the threads beside the item change the map and the ledger too."""
        return (len(applier.effects), self._own_reads(run, int(applier.item.get("call_id") or 0)))

    def _own_reads(self, run, item_id: int) -> int:
        """The records this item was the first of the run to be shown: the
        rows its own clean calls showed (ItemRun.shown_rows) and the index
        entries they copied out. A replayed call is another call's read and
        ran nothing (ran_calls holds only calls this item ran), and a record
        an earlier item was shown is never this item's: the count only grows
        with records new to the run, a finite set over the case."""
        fresh = [int(c) for c in list(getattr(run, "ran_calls", None) or []) if int(c) not in self.read_calls]
        if fresh:
            keys: list[str] = []
            shown = getattr(run, "shown_rows", None) or {}
            sources = getattr(run, "shown_sources", None) or {}
            for cid in fresh:
                keys += list(shown.get(cid) or [])
                if sources.get(cid):
                    self.read_by_source.setdefault(sources[cid], set()).update(shown.get(cid) or [])
            if self.case:
                try:
                    from core.contents_index import copied_entries
                    keys += [f"copy:{e}" for e in copied_entries(self.case, fresh)]
                except Exception:  # noqa: BLE001
                    pass
            for k in keys:
                if k not in self.read_owner:
                    self.read_owner[k] = item_id
                    self.read_count[item_id] = self.read_count.get(item_id, 0) + 1
            self.read_calls |= set(fresh)
        return self.read_count.get(item_id, 0)

    # How many sources the empty-round line names (a display bound).
    EMPTY_LINE_SOURCES = 6

    def _empty_note(self, run) -> str:
        """The line the request after a round without progress carries: that
        it showed nothing new to the run, what counts, and per table this
        item read how many of its records no item has been shown (the
        contents index's row count against the run's shown records).
        Structure only: never what to look for."""
        line = ("The last round showed no record new to this run. Note what it showed with item_note (a fact on "
                "a row not noted before counts), read records not yet shown, or submit.")
        mine = list(dict.fromkeys((getattr(run, "shown_sources", None) or {}).values()))
        if not mine or not self.case:
            return line
        try:
            from core.contents_index import _rel, export_facts
            facts = export_facts(self.case)
        except Exception:  # noqa: BLE001
            return line
        left = []
        for src in mine:
            rel = _rel(Path(self.case), src)
            total = int((facts.get(rel) or {}).get("rows") or 0)
            seen = len(self.read_by_source.get(src) or ())
            if total and seen < total:
                left.append(f"{rel}: {total - seen} of {total} records not yet shown")
        if left:
            line += " Not yet shown: " + "; ".join(left[:self.EMPTY_LINE_SOURCES]) + (
                f"; and {len(left) - self.EMPTY_LINE_SOURCES} more" if len(left) > self.EMPTY_LINE_SOURCES else "") + "."
        return line

    def _report_gate(self, state: dict[str, Any]) -> str:
        """The queue is empty: the report gate decides. Ready, the reports
        are written through the loop's own close-out ("closed_out"). Not
        ready, its blocking issues become one follow-up item and the loop
        goes on ("item"), unless the same issues were already turned into
        an item once (their normalised text is kept): then the run ends
        "finished" and the exit path writes what the findings support."""
        import hashlib
        from core import frontier_queue as Q
        from core.execution_log import log
        a = self.a
        try:
            checked = a._run_pre_report_check()
            if checked is not None and not checked.get("ready_to_report"):
                checked = a._close_out_spine(self.turn, checked, need_dair=False)
            ready = bool(checked.get("ready_to_report")) if checked else a._pre_report_ready()
            if ready:
                if state.pop("gate_open", None) is not None:
                    Q.save_state(self.case, state)
                return "closed_out" if a._close_out(self.turn, reason="frontier_done") else "finished"
            issues = [str(x) for x in (checked or {}).get("blocking_issues") or [] if str(x).strip()]
        except Exception as e:  # noqa: BLE001
            a._log({"event": "close_out_failed", "turn": self.turn, "error": str(e)[:200]})
            return "finished"
        if not issues:
            return "finished"
        # Counts in an issue's text change with every pass (calls, findings):
        # they are not what makes it the same issue.
        key = hashlib.sha1("\n".join(sorted(re.sub(r"\d+", "#", " ".join(i.split()).casefold())
                                             for i in issues)).encode()).hexdigest()[:16]
        seen = list(state.get("gate_verdicts") or [])
        # The open issues are kept for the disclosure and the exit report's
        # limitations, whichever way the run ends from here.
        state["gate_open"] = [i[:400] for i in issues[:20]]
        if key in seen:
            Q.save_state(self.case, state)
            a._log({"event": "frontier_gate_repeat", "turn": self.turn, "issues": issues[:20]})
            return "finished"
        state["gate_verdicts"] = seen + [key]
        Q.save_state(self.case, state)
        log.add_work_item("followup", [], "", {"host": ""}, ("the report gate is not ready: " + "; ".join(issues))[:400],
                          status="due", source_ref={"kind": "report_gate", "closed_by": "executor",
                                                    "issues": [i[:300] for i in issues[:20]]},
                          extra_key=f"report_gate:{key}")
        a._log({"event": "frontier_gate_items", "turn": self.turn, "issues": issues[:20]})
        return "item"
