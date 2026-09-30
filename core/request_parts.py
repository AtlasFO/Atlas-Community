"""The parts of an investigation request, and whether each is answered.

A request asks for several things at once ("image integrity, operating
system, install date, timezone, ..."). Each thing is a part with a kind of
value it asks for (core.answer_values), and a part is answered by a linked
belief that carries a value of that kind in the clause that names the part,
limited when the analyst states a basis (absent, examined without result,
unreadable, out of scope), or open. A task's status is derived from its
parts by a total rule: with no open part, answered when at least one part
is answered, else blocked on missing evidence whatever the bases; with an
open part, partial when another part is answered or limited, else open.

The split here is deterministic: one part per child bullet, else one per
top-level item of the request's body (split outside parentheses at
semicolons, arrows and commas; a conjunction splits a comma-list item of
single words, or a phrase followed by a determiner), guidance sentences
dropped, a parenthesised list opened into parts. A model split with code
anchoring may replace it on the run's writer path; parts keep their status
by text across re-splits.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from core.answer_values import VALUE_TYPES, bind, type_for

PART_KINDS = ("value", "relation", "umbrella", "standard")
PART_STATUSES = ("open", "answered", "limited")
LIMITATION_BASES = ("source_absent", "examined", "unreadable", "out_of_scope")
SPLIT_VERSION = "det-1"

_GUIDANCE_RE = re.compile(
    r"(?i)^\s*(?:beware|note|nb|keep\b|do not|don't|never|see\b|per\b|e\.g\.|i\.e\.|cf\.|hint|"
    r"remember|beachte|hinweis)")
# A part that opens with a question word asks for that kind of thing,
# whatever nouns follow ("who owns the machine" asks for a name).
_QUESTION_TYPES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rx, re.I), kind) for rx, kind in (
        (r"^(?:who|whom|whose|wer|wessen)\b", "name"),
        (r"^(?:when|wann)\b", "datetime"),
        (r"^(?:where|wo)\b", "path"),
        (r"^(?:how\s+many|how\s+much|wie\s*viele)\b", "count"),
        (r"^(?:whether|is|are|was|were|did|does|has|have|had|can|could|any|ob|ist|sind|war|"
         r"waren|wurde|wurden|gab|gibt|hat|haben)\b", "yes_no"),
    ))
_LIST_QUESTION_RE = re.compile(r"(?i)^(?:which|what|welche[rs]?|was)\b")
_LIST_PAREN_RE = re.compile(r"\(([^()]*,[^()]*)\)")
_INCLUDING_PAREN_RE = re.compile(r"\((?:including|incl\.|such as|especially|z\.\s?B\.)\s+([^()]+)\)", re.I)
_OTHER_PAREN_RE = re.compile(r"\([^()]*\)")
_ARROW_RE = re.compile(r"\s*(?:→|->|=>|›)\s*")
_DETERMINER_AND_RE = re.compile(
    r"(?i)\s+(?:and|und)\s+(?=(?:the|a|an|its|their|which|where|whether|whose|die|der|das|den|dem|welche[rs]?)\b)")
_SINGLE_AND_RE = re.compile(r"(?i)^\s*(\S+)\s+(?:and|und|\+|/|&)\s+(\S+)\s*$")
_LEAD_VERB_RE = re.compile(
    r"(?i)^(?:locate|identify|determine|recover|establish|reconstruct|characteri[sz]e|list|name|"
    r"find|extract|show|assess|describe|explain|check|verify|confirm|bound|use|and|then)\b\s*")


def _split_re_outside_parens(text: str, rx: re.Pattern[str]) -> list[str]:
    """Split at the regex's matches that lie outside parentheses."""
    out, pos, depth = [], 0, 0
    opens = [(m.start(), 1 if m.group(0) == "(" else -1) for m in re.finditer(r"[()]", text)]
    def _depth_at(i: int) -> int:
        d = 0
        for at, delta in opens:
            if at < i:
                d = max(0, d + delta)
        return d
    for m in rx.finditer(text):
        if _depth_at(m.start()) == 0:
            out.append(text[pos:m.start()])
            pos = m.end()
    out.append(text[pos:])
    return [p for p in (x.strip() for x in out) if p]


def _split_outside_parens(text: str, seps: Iterable[str]) -> list[str]:
    out, depth, cur = [], 0, []
    i = 0
    seps = list(seps)
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0:
            hit = next((s for s in seps if text.startswith(s, i)), None)
            if hit:
                out.append("".join(cur))
                cur = []
                i += len(hit)
                continue
        cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [p for p in (x.strip() for x in out) if p]


def _open_parens(item: str) -> tuple[str, list[str]]:
    """The item without its parentheticals, and the parts a parenthesised
    list or an "including ..." aside adds. Other asides (guidance, a
    descriptor) are dropped."""
    extra: list[str] = []
    def _list(m):
        extra.extend(p.strip(" .") for p in m.group(1).split(",") if p.strip(" ."))
        return " "
    def _incl(m):
        extra.extend(p.strip(" .") for p in re.split(r",|\band\b", m.group(1)) if p.strip(" ."))
        return " "
    item = _INCLUDING_PAREN_RE.sub(_incl, item)
    item = _LIST_PAREN_RE.sub(lambda m: _list(m) if not _GUIDANCE_RE.match(m.group(1)) else " ", item)
    item = _OTHER_PAREN_RE.sub(" ", item)
    return " ".join(item.split()).strip(" ,;."), [e for e in extra if not _GUIDANCE_RE.match(e)]


_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")
_TOP_SEPS = re.compile(r"\s*;\s*|\s+—\s+|\s+–\s+|\s+\+\s+|\s*(?:→|->|=>|›)\s*")
# A subordinate clause that gives context asks for nothing of its own.
_CONTEXT_TAIL_RE = re.compile(
    r"(?i),?\s+(?:given that|given|assuming(?: that)?|knowing that|since|because|as long as|"
    r"provided that|unter der annahme|da|weil|sofern)\b.*$")
_QWORD_AND_RE = re.compile(r"(?i)^(when|where|how|wann|wo|wie)\s+(?:and|und)\s+(.+)$")


def top_level_items(body: str) -> list[str]:
    """The things a request body lists, in order."""
    body = " ".join(str(body or "").split())
    items: list[str] = []
    for sentence in _SENTENCE_RE.split(body):
        if _GUIDANCE_RE.match(sentence):
            continue
        sentence = _CONTEXT_TAIL_RE.sub("", sentence)
        for chunk in _split_re_outside_parens(sentence, _TOP_SEPS):
            comma_items = _split_re_outside_parens(chunk, re.compile(r",\s*"))
            listed = len(comma_items) > 1
            for sub in comma_items:
                sub = sub.strip(" .?")
                if not sub:
                    continue
                # "A, IP and MAC, and which card": a conjunction inside a
                # comma-list item of single words is two items, and so is
                # "when and with which credentials"; a conjunction before a
                # determiner is two items anywhere.
                m = _SINGLE_AND_RE.match(sub)
                if listed and m:
                    items += [m.group(1), m.group(2)]
                    continue
                q = _QWORD_AND_RE.match(sub)
                if q:
                    items += [q.group(1), q.group(2)]
                    continue
                items += _split_re_outside_parens(sub, _DETERMINER_AND_RE)
    out: list[str] = []
    for item in items:
        item = re.sub(r"(?i)^(?:and|und|or|oder|plus)\s+", "", item.strip(" .?—–"))
        head, extra = _open_parens(item)
        while True:
            stripped = _LEAD_VERB_RE.sub("", head).strip(" .?—–")
            if stripped == head or not stripped:
                break
            head = stripped
        if head and not _GUIDANCE_RE.match(head):
            out.append(head)
        out += extra
    return [x for x in dict.fromkeys(out) if x]


def _default_type(request_text: str) -> str:
    from core.answer_synthesis import question_kind
    return {"yes_no": "yes_no", "count": "count", "who": "name", "when": "datetime",
            "enumeration": "list"}.get(question_kind(request_text), "name")


def split_request(text: str, children: list[str] | None = None) -> list[dict[str, Any]]:
    """The deterministic split of a request into parts."""
    from core.answer_synthesis import is_general_question, request_body
    body = request_body(text)
    items = [c for c in (children or []) if c] or top_level_items(body) or [body]
    if len(items) == 1 and is_general_question(text):
        return [_part("p1", items[0], "narrative", "umbrella")]
    default = _default_type(text)
    parts: list[dict[str, Any]] = []
    for i, item in enumerate(items, 1):
        by_question = next((k for rx, k in _QUESTION_TYPES if rx.match(item)), None)
        by_table = None if by_question else type_for(item)
        kind_type = by_question or by_table or ("list" if _LIST_QUESTION_RE.match(item) else default)
        typed_by = "question" if by_question else "table" if by_table else "default"
        if kind_type == "relation":
            parts.append(_part(f"p{i}", item, "relation", "relation", typed_by))
        elif kind_type in ("yes_no",):
            parts.append(_part(f"p{i}", item, "yes_no", "value", typed_by))
        else:
            parts.append(_part(f"p{i}", item, kind_type, "value", typed_by))
    return parts


def _part(pid: str, text: str, type_: str, kind: str, typed_by: str = "table") -> dict[str, Any]:
    # A part whose words name no kind ("Task one", "personal artefacts")
    # is typed by default and answered by a belief that speaks to it; a
    # part that names its kind is answered only by a value of that kind.
    return {"id": pid, "text": text, "type": type_, "kind": kind, "typed_by": typed_by,
            "status": "open", "claim_ids": [], "value": "", "limitation": {}}


def ensure_parts(task: dict[str, Any], children: list[str] | None = None,
                 *, source: str = "deterministic") -> bool:
    """Give ``task`` its parts when it has none, or re-split it when its
    text changed; parts whose text is unchanged keep their status. Returns
    True when the task changed."""
    text = str(task.get("text") or "")
    have = task.get("parts") or []
    stamp = task.get("parts_for") or ""
    if have and stamp == _norm(text):
        return False
    fresh = split_request(text, children)
    old_by_text = {_norm(p.get("text")): p for p in have if isinstance(p, dict)}
    for p in fresh:
        old = old_by_text.get(_norm(p["text"]))
        if old:
            for k in ("status", "claim_ids", "value", "limitation"):
                p[k] = old.get(k, p[k])
    task["parts"] = fresh
    task["parts_for"] = _norm(text)
    task["parts_source"] = source
    task["parts_version"] = SPLIT_VERSION
    return True


def _norm(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip()).casefold()


# ── status ────────────────────────────────────────────────────────────────

def derive_status(task: dict[str, Any], *, keep_markers: bool = True) -> str:
    """The task's status from its parts (total): see the module docstring.
    A task without parts keeps its stored status, and so do the operator
    markers ``dropped`` and ``reopened`` until the next update of the task
    (``keep_markers=False``)."""
    stored = str(task.get("status") or "open")
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    if not parts or stored == "dropped" or (keep_markers and stored == "reopened"):
        return stored
    open_ = [p for p in parts if p.get("status") == "open"]
    answered = [p for p in parts if p.get("status") == "answered"]
    limited = [p for p in parts if p.get("status") == "limited"]
    if not open_:
        return "answered" if answered else "blocked_missing_evidence"
    if answered or limited:
        return "partial"
    return "in_progress" if task.get("related_claim_ids") else "open"


def open_parts(task: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in (task.get("parts") or []) if isinstance(p, dict) and p.get("status") == "open"]


# ── assignment ────────────────────────────────────────────────────────────

def _current(nodes: dict[str, dict], ids: Iterable[str]) -> list[dict[str, Any]]:
    out = []
    for cid in ids:
        n = nodes.get(str(cid))
        if not isinstance(n, dict):
            continue
        if n.get("kind") not in ("claim", "conclusion", "observation"):
            continue
        if str(n.get("status") or "") in ("superseded", "withdrawn", "dropped"):
            continue
        out.append(n)
    return out


# Verbs that ask whether something is there without naming it ("whether the
# machine carries viruses"): a part is answered by what it asks about, never
# by its verb alone.
_PRESENCE_VERB_RE = re.compile(
    r"^(?:carr(?:y|ies|ied|ying)|contain(?:s|ed|ing)?|hold(?:s|ing)?|held|show(?:s|ed|n|ing)?|"
    r"includ(?:e|es|ed|ing)|exist(?:s|ed|ing)?|appear(?:s|ed|ing)?|occur(?:s|red|ring)?|"
    r"us(?:e|es|ed|ing))$")


def part_words(part_text: str) -> set[str]:
    """What a part asks about: its qualifier (core.answer_values), presence
    and linking verbs set aside."""
    from core.answer_values import qualifier
    return {w for w in qualifier(part_text) if not _PRESENCE_VERB_RE.match(w)}


# A presence question can name a class of thing where a belief names a
# member of it ("whether the machine carries viruses" is answered by a trojan
# detection). Security tooling is no member: "no anti-virus is installed"
# says nothing about what the machine carries.
_CLASS_MEMBERS: tuple[tuple[frozenset[str], re.Pattern[str]], ...] = (
    (frozenset({"virus", "viruses", "viren", "malware", "schadsoftware"}),
     re.compile(r"(?i)(?<![a-z-])(?:virus(?:es)?|viren|malware|schadsoftware|trojan\w*|worms?|"
                r"ransomware|backdoors?|rootkits?|spyware|keyloggers?|infect\w*)(?![a-z])")),
)


def carries_part(part_text: str, text: str) -> bool:
    """Whether ``text`` carries the part's words the way the value binder
    requires a qualifier: all of them up to two, at least half when more.
    A word naming a class is carried by a member of it."""
    from core.answer_values import _same_word, _tokens
    words = part_words(part_text)
    if not words:
        return False
    need = len(words) if len(words) <= 2 else (len(words) + 1) // 2
    toks, core = _tokens(text), _tokens(part_text)

    def carried(word: str) -> bool:
        if any(_same_word(word, t, core) for t in toks):
            return True
        return any(word in keys and rx.search(text) for keys, rx in _CLASS_MEMBERS)
    return sum(1 for w in words if carried(w)) >= need


# A lead sentence that opens with a verdict ("Yes -", "No,", "Nein:") answers a
# yes/no question; "No anti-virus software ..." opens with a determiner.
_VERDICT_OPEN_RE = re.compile(r"(?i)^\W*(?:yes|no|ja|nein)\s*(?:[\u2014\u2013:;,.!]|-\s)")


def _answers_yes_no(part_text: str, request_text: str, node: dict[str, Any], *, named: bool,
                    sole: bool = False) -> bool:
    """A yes/no part is answered by a belief that carries what the part asks
    about: in its headline (the first clause of its lead sentence) when it
    is only linked to the task, in any clause when the analyst named it for
    the part. A word the belief mentions in passing (a list of search terms)
    is no answer on its own. Only a part with no words of its own ("if so")
    is read against the request's text; a gap never answers. The request's
    only part is also answered by a belief that opens with a verdict, linked
    or named: tied to that request, it can answer nothing else."""
    from core.answer_synthesis import GAP, classify_statement, first_sentence
    from core.answer_values import clauses
    if not part_words(part_text):
        return _yes_no_answers(part_text, request_text, node)
    stmt = str(node.get("statement") or "")
    if classify_statement(stmt) == GAP:
        return False
    if sole and _VERDICT_OPEN_RE.match(first_sentence(stmt)):
        return True
    if named:
        return any(carries_part(part_text, c) for c, _off in clauses(stmt))
    head = clauses(first_sentence(stmt))
    return bool(head) and carries_part(part_text, head[0][0])


# The kinds whose recogniser reads every way prose states the value: a
# dotted quad, a colon-hex run, user@domain, a hex digest, a dotted site
# name. A belief it reads no such value in states none, so the analyst's
# link alone does not answer such a part. The other kinds keep the link:
# a name, an account, a path, a date or a count has phrasings no pattern
# reads ("the morning of the fifth", "a dozen").
STRICT_VALUE_TYPES = frozenset({"ip", "mac", "email", "hash", "domain"})


def _clause_answers(part_text: str, node: dict[str, Any], refuse: tuple[str, ...]) -> bool:
    """A clause of the belief carries the part's words, in a statement whose
    kind is not in ``refuse``. The statement is the clause up to the next
    semicolon or sentence end, a "label: facts" pair read as one: a belief
    that walks through several parts is judged part by part, not by its
    lead."""
    from core.answer_synthesis import classify_statement
    from core.answer_values import clauses
    stmt = " ".join(str(node.get("statement") or "").split())
    pieces = clauses(stmt)
    for i, (clause, off) in enumerate(pieces):
        if not carries_part(part_text, clause):
            continue
        j = i
        while j + 1 < len(pieces) and ":" in stmt[pieces[j][1] + len(pieces[j][0]):pieces[j + 1][1]]:
            j += 1
        if classify_statement(stmt[off:pieces[j][1] + len(pieces[j][0])]) not in refuse:
            return True
    return False


def _speaks_to_value_part(part_text: str, node: dict[str, Any]) -> bool:
    """An analyst-named belief answers a value part whose value the binder
    cannot read when a clause carries the part's words in a statement that is
    neither a gap nor an absence: an absence cannot supply a value; it is a
    limitation, not an answer."""
    from core.answer_synthesis import ABSENCE, GAP
    return _clause_answers(part_text, node, (GAP, ABSENCE))


def _yes_no_answers(part_text: str, request_text: str, node: dict[str, Any]) -> bool:
    """The belief speaks to the part (or, for a part that is the request
    itself, to the request); a gap statement never answers."""
    from core.answer_synthesis import GAP, classify_statement, first_sentence, speaks_to
    stmt = str(node.get("statement") or "")
    if classify_statement(stmt) == GAP:
        return False
    lead = first_sentence(stmt)
    host = str(node.get("host") or "")
    if speaks_to(part_text, lead, host, strict=True):
        return True
    return bool(request_text) and speaks_to(request_text, lead, host, strict=True)


def _relation_answers(request_text: str, node: dict[str, Any]) -> bool:
    from core.answer_synthesis import _relates, _relation_sides, first_sentence
    sides = _relation_sides(request_text)
    if sides is None:
        return False
    return _relates(first_sentence(str(node.get("statement") or "")), sides)


_NEGATED_CLAUSE_RE = re.compile(
    r"(?i)\b(?:no|not|never|none|neither|without|absent|missing|unknown|could not|cannot|"
    r"nicht|kein|keine|keinen|nie|ohne|fehlt|unbekannt)\b")


# A part's kind and the indicator types that state a value of it. Both
# vocabularies are Atlas's own (core.answer_values.TYPES and
# core.indicators.TYPES); the table wires one to the other.
_INDICATOR_TYPES_FOR = {
    "ip": ("ip",), "mac": ("mac",), "domain": ("domain",), "email": ("email",),
    "hash": ("hash",), "account": ("account",), "host": ("host",),
    "path": ("path", "file"), "identifier": ("serial", "credential_id", "cloud_resource"),
}


def _typed_values(node: dict[str, Any], part_type: str) -> list[str]:
    """The values the belief types as indicators of the part's kind."""
    from core.indicators import rows_of
    wanted = _INDICATOR_TYPES_FOR.get(part_type, ())
    return [str(r.get("value") or "") for r in rows_of(node) if r.get("type") in wanted]


def _value_answers(part: dict[str, Any], request_text: str, node: dict[str, Any],
                   known_hosts: Iterable[str], *, explicit: bool = False) -> str | None:
    """The value a belief carries for the part, or None: a gap statement
    never answers, and a clause that states an absence answers no value
    part even when another clause of the same belief states a value. The
    analyst naming the belief (``explicit``) waives the part's qualifier."""
    from core.answer_synthesis import ABSENCE, GAP, classify_statement
    stmt = str(node.get("statement") or "")
    part_type = str(part.get("type") or "")
    value, clause = bind(str(part.get("text") or ""), part_type, stmt,
                         question=request_text, known_hosts=known_hosts, explicit=explicit,
                         prefer=_typed_values(node, part_type))
    if not value:
        return None
    # The clause that carries the value must state it: one that says the
    # thing was not examined, or is absent, states no value.
    if classify_statement(clause) in (GAP, ABSENCE) or _NEGATED_CLAUSE_RE.search(clause):
        return None
    return value


def assign(task: dict[str, Any], nodes: dict[str, dict], claim_ids: Iterable[str] | None = None,
           *, known_hosts: Iterable[str] = (), explicit: dict[str, list[str]] | None = None,
           lenient: bool = False) -> list[str]:
    """Answer the task's open parts from its linked beliefs (or ``claim_ids``)
    with the typed test; ``explicit`` maps part ids to the claim ids the
    analyst named, which is the only way a relation part is answered. A
    part answered by a lexical test (yes/no, an umbrella, or a part typed by
    default because its words name no kind) closes only when ``lenient``
    (the analyst's own update), never by record-time linking alone; a part
    that names its kind closes as soon as a linked belief carries the
    value. Returns the ids of the parts answered now."""
    request_text = str(task.get("text") or "")
    ids = list(claim_ids) if claim_ids is not None else list(task.get("related_claim_ids") or [])
    linked = _current(nodes, ids)
    done: list[str] = []
    for part in task.get("parts") or []:
        if not isinstance(part, dict) or part.get("status") != "open":
            continue
        pid = str(part.get("id"))
        named = _current(nodes, (explicit or {}).get(pid) or [])
        kind = str(part.get("kind") or "value")
        typ = str(part.get("type") or "")
        if kind == "relation":
            hit = next((n for n in named if _relation_answers(request_text, n)), None)
            if hit:
                _answer(part, hit, ""); done.append(pid)
            continue
        candidates = named or linked
        if part.get("host"):
            # A per-host standard part is answered by that host's beliefs.
            h = str(part["host"]).casefold()
            candidates = [n for n in candidates
                          if str(n.get("host") or "").casefold() == h
                          or h in str(n.get("statement") or "").casefold()]
        # A reading (an observation) answers a part only by a value of its
        # kind, never by a lexical test.
        lexical = [n for n in candidates if str(n.get("kind") or "") != "observation"]
        if kind == "umbrella" and any(p.get("kind") == "standard" for p in task.get("parts") or []):
            continue   # an umbrella with sub-questions follows them (settle_umbrella)
        if kind == "umbrella" or typ in ("narrative", "yes_no"):
            # A lexical test (the belief speaks to the part) closes a part
            # only on the analyst's own update, never by linking alone. A
            # standard sub-question is judged on its own words, never on
            # the umbrella request's.
            req = "" if kind == "standard" else request_text
            if lenient or named:
                if typ == "yes_no" and kind == "value":
                    sole = sum(isinstance(p, dict) for p in task.get("parts") or []) == 1
                    test = lambda n: _answers_yes_no(str(part.get("text")), req, n, named=bool(named),  # noqa: E731
                                                     sole=sole)
                else:
                    test = lambda n: _yes_no_answers(str(part.get("text")), req, n)  # noqa: E731
                hit = next((n for n in lexical if test(n)), None)
                if hit:
                    _answer(part, hit, ""); done.append(pid)
            continue
        if typ in VALUE_TYPES:
            if part.get("typed_by") == "default":
                if lenient or named:
                    # A part whose words name no kind is judged on those
                    # words: a belief about the request's topic ("file
                    # transfers", the request's label) does not answer the
                    # part "FTP" unless it speaks to FTP. Only a part with no
                    # words of its own falls back to the request, as a yes/no
                    # part does (_answers_yes_no).
                    own = part_words(str(part.get("text") or ""))
                    req = "" if kind == "standard" or own else request_text
                    hit = next((n for n in lexical if _yes_no_answers(str(part.get("text")), req, n)), None)
                    if hit:
                        _answer(part, hit, ""); done.append(pid)
                    elif named and own:
                        # A belief the analyst named for the part answers it
                        # through any clause that carries the part's words (a
                        # belief that walks through several parts names each
                        # in turn); a belief only linked to the task needs
                        # them in its lead. As in the lead test, only a gap is
                        # no answer: the part asks about a topic, and "none
                        # was found" is what the analyst determined. Marked,
                        # so the report and a successor keep the link.
                        from core.answer_synthesis import GAP
                        hit = next((n for n in lexical if _clause_answers(str(part.get("text")), n, (GAP,))), None)
                        if hit:
                            _answer(part, hit, "")
                            part["bound_by"] = "analyst"
                            done.append(pid)
                continue
            for n in candidates:
                value = _value_answers(part, request_text, n, known_hosts, explicit=bool(named))
                if value:
                    _answer(part, n, value); done.append(pid)
                    break
            else:
                # The analyst named the belief and the binder reads no value
                # of the part's kind in it: the link answers the part when the
                # belief carries what the part asks about. It is marked, so
                # the report and the reviewer see an answer taken on the
                # analyst's link rather than on a read value.
                hit = None if typ in STRICT_VALUE_TYPES else next(
                    (n for n in named if str(n.get("kind") or "") != "observation"
                     and _speaks_to_value_part(str(part.get("text")), n)), None)
                if hit:
                    _answer(part, hit, "")
                    part["bound_by"] = "analyst"
                    done.append(pid)
    settle_umbrella(task)
    return done


def settle_umbrella(task: dict[str, Any]) -> bool:
    """The narrative part of an umbrella request follows its standard
    parts: answered once every standard part is answered or limited and
    at least one is answered, limited when all are limited. Returns True
    when it changed."""
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    umbrella = next((p for p in parts if p.get("kind") == "umbrella"), None)
    standard = [p for p in parts if p.get("kind") == "standard"]
    if umbrella is None or not standard:
        return False
    if any(p.get("status") == "open" for p in standard):
        # A sub-question reopened: the umbrella is open again.
        if umbrella.get("status") != "open":
            umbrella["status"] = "open"; umbrella["claim_ids"] = []; umbrella["value"] = ""; umbrella["limitation"] = {}
            return True
        return False
    if any(p.get("status") == "answered" for p in standard):
        umbrella["status"] = "answered"
        umbrella["claim_ids"] = sorted({c for p in standard for c in (p.get("claim_ids") or [])})
        umbrella["value"] = ""
        umbrella["limitation"] = {}
    else:
        limit(umbrella, "examined", "every standard sub-question was examined without an answer", [])
    return True


def _answer(part: dict[str, Any], node: dict[str, Any], value: str) -> None:
    from core.answer_values import STRONG_TYPES
    part["status"] = "answered"
    part["claim_ids"] = [str(node.get("id"))]
    # Only an exact kind of value is printed as the answer; a name or a
    # list item reads better through its belief's own headline.
    part["value"] = value if str(part.get("type")) in STRONG_TYPES else ""
    part["limitation"] = {}
    part.pop("bound_by", None)


def clear_gone(task: dict[str, Any], nodes: dict[str, dict]) -> list[str]:
    """Reopen parts whose answering beliefs are gone. Returns their ids."""
    reopened = []
    for part in task.get("parts") or []:
        if not isinstance(part, dict) or part.get("status") != "answered" or part.get("kind") == "umbrella":
            continue
        if not _current(nodes, part.get("claim_ids") or []):
            part["status"] = "open"
            part["claim_ids"] = []
            part["value"] = ""
            reopened.append(str(part.get("id")))
    settle_umbrella(task)
    return reopened


def carry(task: dict[str, Any], old_id: str, new_id: str, nodes: dict[str, dict],
          *, known_hosts: Iterable[str] = ()) -> list[str]:
    """A part answered by ``old_id`` is re-tested against ``new_id``; it stays
    answered by the successor when the test holds, else it reopens."""
    changed = []
    for part in task.get("parts") or []:
        if not isinstance(part, dict) or old_id not in (part.get("claim_ids") or []):
            continue
        linked = part.get("kind") == "relation" or part.get("bound_by") == "analyst"
        part["status"] = "open"; part["claim_ids"] = []; part["value"] = ""
        part.pop("bound_by", None)
        # A part the analyst's link answered stays linked to the successor.
        assign(task, nodes, [new_id], known_hosts=known_hosts, lenient=True,
               explicit={str(part.get("id")): [new_id]} if linked else None)
        changed.append(str(part.get("id")))
    return changed


def limit(part: dict[str, Any], basis: str, reason: str, call_ids: Iterable[int] = ()) -> None:
    part["status"] = "limited"
    part["claim_ids"] = []
    part["value"] = ""
    part["limitation"] = {"basis": basis, "reason": str(reason or "").strip(),
                          "call_ids": [int(c) for c in call_ids if str(c).strip().isdigit()]}


def summary_lines(task: dict[str, Any]) -> list[str]:
    """One line per part for digests and refusals."""
    out = []
    for p in task.get("parts") or []:
        if not isinstance(p, dict):
            continue
        st = p.get("status")
        if st == "answered":
            val = f": {p.get('value')}" if p.get("value") else ""
            how = " (analyst link, no typed value)" if p.get("bound_by") == "analyst" else ""
            out.append(f"{p['id']} {p['text']} ({p['type']}) answered{val}{how} [{', '.join(p.get('claim_ids') or [])}]")
        elif st == "limited":
            lim = p.get("limitation") or {}
            out.append(f"{p['id']} {p['text']} ({p['type']}) not determined: {lim.get('basis')} — {lim.get('reason')}")
        else:
            out.append(f"{p['id']} {p['text']} ({p['type']}) open")
    return out


# ── standard sub-questions of an umbrella request ─────────────────────────
#
# The executive questions every incident report answers, as incident-response
# knowledge (like core.ir_playbook), never case knowledge. An umbrella
# request ("what happened on the hosts?") gets them as standard parts, per
# computer for the host-level ones, with a gate first: a host answered "not
# affected" by an absence finding closes its other standard parts as limited.
_STANDARD: dict[str, list[tuple[str, str, bool]]] = {
    # intent: (part text, type, per_host)
    "happened": [
        ("affected", "yes_no", True),
        ("initial activity", "datetime", True),
        ("attacker actions", "list", True),
        ("persistence", "path", True),
        ("lateral movement to another host", "host", True),
        ("last activity", "datetime", True),
    ],
    "data_taken": [
        ("data taken", "yes_no", False),
        ("the files or data sets taken", "list", False),
        ("the channel", "name", False),
        ("the destination", "domain", False),
        ("when the data left", "datetime", False),
    ],
    "access": [
        ("the access vector", "name", False),
        ("the account used", "account", False),
        ("the source address", "ip", False),
        ("when access was gained", "datetime", False),
    ],
    "attack_type": [
        ("the incident type", "name", False),
        ("the family or tooling", "name", False),
        ("the actor attribution", "name", False),
    ],
}
_INTENT_RES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rx, re.I), key) for rx, key in (
        (r"\b(?:what (?:happened|occurred|went on)|passiert|geschehen|vorgefallen|geschah|ablauf|verlauf)\b", "happened"),
        (r"\b(?:data|daten|files?|dateien|information)\b.*\b(?:stolen|taken|exfil|leak|left|gestohlen|entwendet|abgeflossen|abgezogen)|\b(?:exfiltrat)", "data_taken"),
        (r"\b(?:gain(?:ed)?|obtain(?:ed)?|got|get)\b.*\b(?:access|zugang|zugriff)|\b(?:initial|first)\s+access|\bhow did the attacker\b|\bzugang\b|\bzugriff\b|\beingedrungen\b", "access"),
        (r"\b(?:what (?:type|kind) of attack|which attack|art (?:des|von) angriff|angriffsart|type of incident)\b", "attack_type"),
    ))
GATE_TEXTS = frozenset({"affected", "data taken"})


def umbrella_intent(text: str) -> str | None:
    body = " ".join(str(text or "").split())
    for rx, key in _INTENT_RES:
        if rx.search(body):
            return key
    return None


def standard_parts(request_text: str, hosts: Iterable[str]) -> list[dict[str, Any]]:
    """The standard parts an umbrella request gets: per computer host for
    the host-level questions (estate-level when no host is known), estate
    level for the rest. Empty for a request whose intent is not in the
    table."""
    intent = umbrella_intent(request_text)
    if not intent:
        return []
    hosts = [h for h in dict.fromkeys(str(h).strip() for h in hosts) if h]
    out: list[dict[str, Any]] = []
    n = 0
    for text, typ, per_host in _STANDARD[intent]:
        scopes = hosts if (per_host and hosts) else [""]
        for host in scopes:
            n += 1
            label = f"{text} on {host}" if host else text
            part = _part(f"s{n}", label, typ, "standard", "table")
            part["host"] = host
            part["gate"] = text in GATE_TEXTS
            out.append(part)
    return out


def ensure_standard_parts(task: dict[str, Any], hosts: Iterable[str]) -> bool:
    """Give a task whose request has a table intent its standard parts once
    (kept by text across reconciles): an umbrella keeps its narrative part
    beside them; a request whose own split has at most two parts ("Did
    data get stolen, and if yes which one?") takes the intent's parts in
    place of its own, which carry the gate and the items. Returns True when
    the task changed."""
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    if not parts:
        return False
    text = str(task.get("text") or "")
    umbrella = any(p.get("kind") == "umbrella" for p in parts)
    own = [p for p in parts if p.get("kind") not in ("standard", "umbrella")]
    if not umbrella and (umbrella_intent(text) is None or len(own) > 2):
        return False
    have = {_norm(p.get("text")) for p in parts if p.get("kind") == "standard"}
    fresh = [p for p in standard_parts(text, hosts) if _norm(p["text"]) not in have]
    if not fresh:
        return False
    if umbrella:
        task["parts"] = parts + fresh
        return True
    # The own parts give way to the table's, statuses carried by text.
    old_by_text = {_norm(p.get("text")): p for p in own}
    for p in fresh:
        o = old_by_text.get(_norm(p["text"]))
        if o:
            for k in ("status", "claim_ids", "value", "limitation"):
                p[k] = o.get(k, p[k])
    task["parts"] = [p for p in parts if p.get("kind") == "standard"] + fresh
    return True


def close_unaffected_hosts(task: dict[str, Any], nodes: dict[str, dict]) -> list[str]:
    """A per-host gate answered "not affected" by an absence finding on that
    host closes the host's other standard parts as limited (basis
    examined, citing the finding's calls). Returns the ids closed."""
    from core.answer_synthesis import ABSENCE, classify_statement
    closed: list[str] = []
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    for gate in parts:
        if not gate.get("gate") or gate.get("status") != "answered" or not gate.get("host"):
            continue
        node = next((nodes.get(c) for c in gate.get("claim_ids") or [] if nodes.get(c)), None)
        if not node or classify_statement(str(node.get("statement") or "")) != ABSENCE:
            continue
        calls: list[int] = []
        for ev in node.get("evidence") or []:
            if isinstance(ev, dict) and str(ev.get("call_id") or "").strip().isdigit():
                calls.append(int(ev["call_id"]))
        for key in ("source_finding_call_id", "finding_call_id"):
            if str(node.get(key) or "").strip().isdigit():
                calls.append(int(node[key]))
        calls = list(dict.fromkeys(calls))[:6]
        for p in parts:
            if p is gate or p.get("host") != gate.get("host") or p.get("status") != "open":
                continue
            limit(p, "examined", f"host not affected: {str(node.get('statement') or '')[:120]}", calls)
            closed.append(str(p.get("id")))
    return closed
