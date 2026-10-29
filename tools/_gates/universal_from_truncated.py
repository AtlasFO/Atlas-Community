"""Gate: a statement about *all* rows, or about something being *absent*,
cannot rest on a result the analyst saw only part of.

``negative_from_truncated`` guards UNCONFIRMED findings that name a
truncated ``linked_call_id``. A finding such as "all successful logons were
interactive; no network logons detected", recorded from a ``table_query``
whose matching rows were shown in part, is wrong when the one network
logon lies beyond the visible window.
The tier does not matter: a universal or negative statement is wrong the
moment one unseen row contradicts it. A positive observation of a row that
*was* seen is unaffected.
"""
from __future__ import annotations

import json
import re
from typing import Optional

# Words that make a statement universal or negative — grammar (English and
# German), not knowledge about any case.
_UNIVERSAL_RE = re.compile(
    r"(?i)(?:\b(?:all|every|each|only|none|no|never|always|exclusively|"
    r"alle|jede[rs]?|sämtliche|nur|kein[es]?|nie|niemals|immer|ausschließlich)\b"
    r"|\b(?:not|nicht|weder)\b.{0,40}\b(?:observed|detected|found|present|seen|"
    r"recorded|beobachtet|gefunden|festgestellt|vorhanden)\b"
    r"|\b(?:were|was|is|are|sind|ist|wurden|wurde)\s+(?:not|nicht)\b)")

_COUNT_RE = re.compile(
    r'"(matched_rows|returned_rows|hit_count|max_hits)"\s*:\s*(\d+)')
# A table scan stopped at an operator's row bound, as a result that carries
# only the row count it stopped at says it.
_SCAN_CAP_RE = re.compile(r'"scan_capped_at"\s*:\s*(\d+)')

# Text a finding quotes from the evidence - a message body, a command line,
# a log line - is the source's words, not the analyst's: "all data" inside
# a quoted email quantifies nothing the analyst claims about rows.
_QUOTED_RE = re.compile(
    r"(?:^|[\s(\[])[\"'\u201c\u2018`]([^\"'\u201c\u201d\u2018\u2019`\n]{2,300})"
    r"[\"'\u201d\u2019`](?=$|[\s.,;:)\]!?])")


# "cannot be confirmed or excluded", "could not be determined", "none can be
# ruled out": the analyst's inability to conclude. No unseen row can make a
# hedge false, so it is not a statement about all rows or about absence -
# it is how a question is parked. The verbs are epistemic (about concluding),
# not about the evidence ("could not be recovered" stays a claim).
_HEDGE_RE = re.compile(
    r"(?i)\b(?:can\s*not|cannot|could\s+not|can't|couldn't|unable\s+to|"
    r"(?:none|neither)\s+can|(?:is|are|was|were|remains?)\s+not)\s+(?:be\s+)?"
    r"(?:\w+\s+){0,2}?(?:confirmed|excluded|refuted|determined|established|"
    r"verified|resolved|ruled\s+out|proven|concluded|attributed|assessed|"
    r"decided|settled|known)\b(?:\s+(?:or|nor)\s+(?:be\s+)?\w+)?")


# A conditional clause states no fact: "is purged if no owner replies"
# reports a rule, and its "no" is the condition's, not an absence the
# analyst claims. Stripped only where the main clause stands apart from it:
# a condition that trails its main clause, or a leading one a comma closes.
# A leading condition with no comma ("If data had left, the log would show
# it and it shows none" written without one) strips nothing: the main
# clause and its absence would go with it. English and German
# subordinators: grammar.
_COND_WORDS = r"(?:if|unless|wenn|falls|sofern)"
_TRAILING_COND_RE = re.compile(
    rf"(?i)(?<=\w)\s+{_COND_WORDS}\b[^,;]*?(?=[,;]|[.!?](?:\s|$)|$)")
_LEADING_COND_RE = re.compile(rf"(?i)(?:^|(?<=[.;!?]\s))\s*{_COND_WORDS}\b[^,;.!?]*,")


def _drop_conditions(text: str) -> str:
    return _TRAILING_COND_RE.sub(" ", _LEADING_COND_RE.sub(" ", text))


# The analyst's own progress ("no copy record has been examined so far", "we
# have not parsed the mail store"): a negation, an auxiliary and a reading
# verb as the clause's predicate, and no evidence predicate in the clause;
# a passive predicate ("has not been read", "was not examined") with a
# perspective marker, any predicate with the analyst as subject. An active
# clause with a marker names its own subject ("the user has not opened the
# attachment yet"): a claim about the evidence. It says how far the
# run got, which the finish's open-work list accounts, not what the evidence
# holds. "No transfer appears in the logs reviewed so far" (an evidence
# predicate), "no exfiltration was found in the examined logs" (the reading
# verb an adjective), "the mail was not read by the user" (an agent) and
# "no file was opened" (no marker) are claims about the evidence and stay.
# English and German grammar, not knowledge about any case.
_PROGRESS_NEG_RE = re.compile(r"(?i)\b(?:not|no|never|nor|nothing|none|nicht|kein\w*|nie)\b")
_PROGRESS_PREDICATE_RE = re.compile(
    r"(?i)\b(?:has|have|had|was|were|is|are|been|be|wurde|wurden|worden|ist|sind|hat|haben|war|waren)\b"
    r"(?:\s+[\w-]+){0,3}?\s+(?:read|examined|reviewed|checked|opened|parsed|searched|queried|collected|"
    r"recovered|analy[sz]ed|inspected|looked\s+at|gelesen|geprüft|untersucht|ausgewertet|geöffnet|"
    r"durchsucht|analysiert)\b")
_PASSIVE_PREDICATE_RE = re.compile(
    r"(?i)\b(?:been|was|were|is|are|be|wurde|wurden|worden)\b(?:\s+[\w-]+){0,2}?\s+(?:read|examined|reviewed|"
    r"checked|opened|parsed|searched|queried|collected|recovered|analy[sz]ed|inspected|looked\s+at|gelesen|"
    r"geprüft|untersucht|ausgewertet|geöffnet|durchsucht|analysiert)\b")
_EVIDENCE_PREDICATE_RE = re.compile(
    r"(?i)\b(?:appears?|appeared|shows?|showed|shown|found|seen|observed|detected|exists?|existed|present|"
    r"occurred|recorded|logged|beobachtet|gefunden|festgestellt|vorhanden|zeigt|erscheint)\b")
_PROGRESS_MARKER_RE = re.compile(
    r"(?i)\b(?:yet|so\s+far|to\s+date|at\s+this\s+(?:point|stage)|in\s+this\s+(?:analysis|run|investigation)|"
    r"noch|bisher|bislang|"
    # the run's own means: "with the passphrases tried", "using the extractors installed"
    r"(?:with|using)\s+the\s+(?:[\w-]+\s+){0,3}(?:tried|attempted|used|run|available|installed))\b")
_ANALYST_SUBJECT_RE = re.compile(
    r"(?i)^\s*(?:we|i|the\s+analyst|the\s+analysis|this\s+analysis|the\s+investigation|this\s+run|atlas|"
    r"wir|ich|die\s+analyse)\b")
_BY_AGENT_RE = re.compile(r"(?i)\b(?:by|von|durch)\s+(?!the\s+analys|this\s+run|atlas\b)\w")
_CLAUSE_SPLIT_RE = re.compile(r"(?i)([;,.!?]\s+|\s+(?:and|but|while|whereas|und|aber|während)\s+)")


def _progress(clause: str) -> bool:
    return bool(_PROGRESS_NEG_RE.search(clause) and _PROGRESS_PREDICATE_RE.search(clause)
                and not _EVIDENCE_PREDICATE_RE.search(clause) and not _BY_AGENT_RE.search(clause)
                and (_ANALYST_SUBJECT_RE.search(clause)
                     or (_PROGRESS_MARKER_RE.search(clause) and _PASSIVE_PREDICATE_RE.search(clause))))


def _drop_progress(text: str) -> str:
    """The text without the clauses that state the analyst's own progress."""
    pieces = _CLAUSE_SPLIT_RE.split(text)
    return "".join(" " if i % 2 == 0 and _progress(piece) else piece for i, piece in enumerate(pieces))


def analysts_words(text: str) -> str:
    """The statement with its quotations of source text, its epistemic
    hedges, its conditional clauses and its statements of the analyst's own
    progress removed: what the analyst claims about the evidence."""
    return _drop_progress(_drop_conditions(_HEDGE_RE.sub(" ", _QUOTED_RE.sub(" ", text or ""))))


def _outside_window(meta: dict) -> str:
    """A windowed search is complete only for its window: when the file
    holds matching rows outside it, a statement about the file was not
    seen whole (a zero-row window included)."""
    every, inside = meta.get("matched_rows_all"), meta.get("matched_rows")
    if not isinstance(every, int) or not isinstance(inside, int) or every <= inside:
        return ""
    period = f"{meta.get('time_start') or 'the first row'} to {meta.get('time_end') or 'the last row'}"
    return f"it searched only {period}; {every - inside} of the file's {every} matching rows lie outside it"


def incomplete_reason(entry: dict) -> str:
    """Why the analyst did not see everything a tool result held, or ''
    when nothing was withheld."""
    # A record view read from the spill file showed the full saved output:
    # its "truncated" is the in-memory stdout's, and the view's own
    # completeness below decides.
    from_spill = entry.get("rows_split") == "flat" and bool(entry.get("stdout_file"))
    if entry.get("truncated") and not from_spill:
        return "its output was truncated"
    window = _outside_window(entry.get("result_meta") or {})
    if window:
        return window
    if entry.get("view_complete") is True:
        # The view showed every matching row of the file (or of the stated
        # window): the one definition of a complete view.
        return ""
    if entry.get("view_omitted_rows"):
        return (f"the analyst was shown {int(entry.get('view_rows_shown') or 0)} of the "
                f"{int(entry.get('view_rows_returned') or 0)} rows the tool returned")
    if entry.get("view_truncated"):
        # The tool returned everything; the copy shown in the conversation
        # kept the head and the tail and left out the middle. Rows in that
        # middle were never seen, so the tool's own complete flag does not
        # settle a statement about all rows.
        omitted = int(entry.get("view_omitted_chars") or 0)
        span = f"{omitted} characters" if omitted else "part of it"
        return (f"the analyst was shown only its first and last parts; {span} "
                "in the middle were never shown (the tool itself returned "
                "everything)")
    body = " ".join(str(entry.get(k) or "")
                    for k in ("output", "result", "stdout"))
    meta = entry.get("result_meta") or {}
    scanned = meta.get("scanned_rows")
    capped = bool(meta.get("scan_capped"))
    if not capped:
        m = _SCAN_CAP_RE.search(f"{body} {entry.get('stdout_excerpt') or ''}")
        if m:
            capped, scanned = True, int(m.group(1))
    if capped:
        return (f"it scanned only the first {scanned} rows of the file"
                if isinstance(scanned, int) and scanned else
                "it stopped scanning before the end of the file")
    nums: dict[str, int] = {}
    for key in ("matched_rows", "returned_rows", "hit_count", "max_hits"):
        if isinstance(meta.get(key), int):
            nums[key] = meta[key]
    for key, val in _COUNT_RE.findall(body):
        nums.setdefault(key, int(val))
    m, r = nums.get("matched_rows"), nums.get("returned_rows")
    if m is not None and r is not None and r < m:
        return f"it returned {r} of {m} matching rows"
    if m is not None and r is not None and r == m:
        from core.envfile import env_flag
        if env_flag("ATLAS_TABLE_SURVEY"):
            # Both counts are exact under every count path: a search that
            # matched exactly max_hits rows returned all of them.
            return ""
    h, x = nums.get("hit_count"), nums.get("max_hits")
    if h is not None and x is not None and 0 < x <= h:
        return f"it stopped at the {x}-hit cap"
    return ""


def rest_of_result_hint(entry: dict, spill: str, cid=None) -> str:
    """Where the rows the analyst did not see are: for a table tool's result
    (whose spill is JSON that a text grep reads as the wrong input kind), the
    narrower calls that return every matching row, naming only parameters
    and result fields that tool has; for a compact view of another tool, the
    view's own narrowing parameters; for an executor tool, its spilled
    output; else a count."""
    from core.tool_result_view import _NEXT_HINTS, next_hints
    cmd = str(entry.get("cmd") or "")
    tool = cmd[len("<py>:"):] if cmd.startswith("<py>:") else ""
    tail = (" The complete result is in the trace; a text search over its spilled JSON is the "
            "wrong input kind.")
    from core.envfile import env_flag
    # ATLAS_TABLE_TIME_ARGS: a period shows the rest too.
    paged = env_flag("ATLAS_TABLE_TIME_ARGS", True)
    if tool == "table_table_query":
        return ("Narrow the call so every matching row is returned (returned_rows == "
                "matched_rows): a narrower where= filter, or count with table.table_pivot(group_by=…)."
                + (" One period: time_start=/time_end=." if paged else "") + tail)
    if tool == "table_table_grep":
        return ("Narrow the call so every matching row is returned: one term alone "
                "(pattern=<term>), or count with table.table_pivot(group_by=…)."
                + (" One period: time_start=/time_end=." if paged else "") + tail)
    if tool.startswith("table_"):
        return "Narrow the call until its whole result fits, or count with table.table_pivot(group_by=…)." + tail
    if "view_rows_shown" in entry and tool in _NEXT_HINTS:
        return "Narrow the call so every row is shown: " + "; ".join(next_hints(tool).values()) + "."
    if spill:
        where = f"of call {cid} " if cid is not None else ""
        return (f"The complete output {where}is on disk at {spill}; a strings.strings_grep or "
                "search.search_evidence over that output finds every line.")
    return ("Count with table.table_pivot(group_by=…) or narrow where= until every matching row "
            "is returned (returned_rows == matched_rows).")


def is_universal_or_negative(text: str) -> bool:
    """Whether the analyst's own statement is about all rows or about an
    absence; words quoted from the evidence do not count."""
    return bool(_UNIVERSAL_RE.search(analysts_words(text)))


def split_sentences(text: str) -> list[str]:
    """A statement's sentences: split after . ; ! ? followed by space, so the
    dots inside an address, a path or a file name never split."""
    return [s for s in re.split(r"(?<=[.;!?])\s+", " ".join((text or "").split())) if s]


def _universal_sentences(text: str) -> list[str]:
    """The sentences that make the statement universal or negative. A
    finding often states several things; only these rest on complete views."""
    return [s for s in split_sentences(text) if is_universal_or_negative(s)]


def _same_words(a: str, b: str) -> bool:
    """Equal once spacing and punctuation are set aside."""
    def norm(x: str) -> str:
        return " ".join(re.sub(r"[\W_]+", " ", x or "").split()).casefold()
    return norm(a) == norm(b)


# A number of a sentence as a term ("4624", "25,292", "10:53"; "4724/4723"
# reads as two): numbers name events, counts and times a row can show.
_NUMBER_TERM_RE = re.compile(r"\d[\d,.:-]*\d|\d{3,}")
_PLAIN_WORD_RE = re.compile(r"[A-Za-z][\w.$\\-]{3,}")


def _request_text(entry: dict) -> str:
    """What the call was asked to read: its command, arguments and evidence path."""
    args = entry.get("args")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {"raw": args}
    vals = " ".join(str(v) for v in args.values()) if isinstance(args, dict) else str(args or "")
    return f"{entry.get('cmd') or ''} {entry.get('evidence_ref') or ''} {vals}".lower()


def _specific_terms(sentence: str, terms: dict | None = None) -> set[str]:
    """The sentence's own specific terms: entities, identifier and artifact
    names, numbers (lower case, three characters or more)."""
    from core.entities import artifact_tokens
    from .citation_support import claim_terms
    terms = terms if terms is not None else claim_terms(sentence)
    specific = {e.split(":", 1)[1].lower() for e in terms["strong"]} | set(terms["names"])
    specific |= {a.lower() for a in artifact_tokens(sentence)}
    specific |= {n.replace(",", "") for n in _NUMBER_TERM_RE.findall(sentence)}
    return {t for t in specific if len(t) >= 3}


def _about(sentence: str, entry: dict, ctx) -> bool:
    """Whether a truncated call is about a universal sentence the artifact
    rule binds to it. A sentence that states an absence stays bound: what it
    says is missing is by its nature not in the rows the call printed, so
    no test on its terms can tell that the call did not search for it. A
    universal that is no absence ("only X", "all N Y") is about the call when
    a specific term of it (an entity, an identifier or artifact name, a
    number, a case host) stands in the call's request or printed rows, or a
    plain word of it stands in the request (the searched pattern, the read
    path); one that names no such term is about no one call ("all three
    captures carry transfers"). Only a selective search can show that it is
    not about the sentence (_selective_search): an unfiltered read, query or
    parse of an artifact holds the sentence's terms in its unseen rows if
    anywhere, so it stays bound by the artifact rule."""
    if "absence" in _what_it_states(sentence):
        return True
    from core.evidence_resolver import _ANCHOR_STOP
    from .citation_support import _read_paths, claim_terms
    terms = claim_terms(sentence)
    specific = _specific_terms(sentence, terms)
    request = _request_text(entry)
    try:
        from .citation_support import call_rows
        rows = " ".join(call_rows(entry)).lower().replace(",", "")
    except Exception:  # noqa: BLE001 - rows that cannot be read show nothing
        rows = ""
    if any(t in request or t in rows for t in specific):
        return True
    hosts = {h.lower() for h in terms["hosts"]}
    if hosts:
        try:
            _excluded, call_hosts = _read_paths(entry, getattr(ctx, "case_dir", None))
        except Exception:  # noqa: BLE001
            call_hosts = frozenset()
        if hosts & {h.lower() for h in call_hosts}:
            return True
    stop = {w.lower() for w in _ANCHOR_STOP}
    words = {w.lower().rstrip(".,;:") for w in _PLAIN_WORD_RE.findall(sentence)} - stop
    if words & {w for w in re.split(r"[^a-z0-9._$-]+", request) if len(w) >= 4}:
        return True
    if not specific and not hosts:
        return False
    return not _selective_search(entry)


def _selective_search(entry: dict) -> bool:
    """A search tool (core.work_order.tool_kind) given a pattern or filter:
    what it returned is what matched the request, so a term the request does
    not name is outside it. A call without one reads the whole artifact."""
    from core.work_order import _PATTERN_KEYS, tool_kind
    tool = str(entry.get("mcp_tool") or entry.get("cmd") or "").strip()
    tool = tool[len("<py>:"):] if tool.startswith("<py>:") else tool
    if tool_kind(tool.split()[0] if tool else "") != "search":
        return False
    args = entry.get("args")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return False
    return isinstance(args, dict) and any(args.get(k) for k in _PATTERN_KEYS)


def check(ctx) -> Optional[dict]:
    desc = ctx.description or ""
    sentences = _universal_sentences(desc)
    if not sentences:
        return None
    from core.entities import artifact_tokens
    from core.forensic_citation import own_words_entry
    from .lineage_relevance import entry_text
    # A statement about all rows of one artifact does not rest on a cited
    # call that read a different artifact, however incomplete that call's
    # view was. Each universal or negative sentence is judged on the
    # artifacts it names itself; one that names none is judged on the whole
    # finding and its evidence, as lineage_relevance does. When either side
    # names nothing, the call is taken as a basis.
    described = artifact_tokens(
        f"{desc} {getattr(ctx, 'supporting_evidence', '') or ''}")
    scopes = [artifact_tokens(s) or described for s in sentences]
    # The statement rests on the calls the analyst cited. The ids Atlas
    # added (a value's source found by the citation auto-fill, calls about
    # the named artifacts put in place of irrelevant ones) are readings of
    # rows that were seen, not the basis of a universal, and the analyst
    # cannot take them out again. Only when the analyst cited nothing are
    # the inferred ids the basis.
    analyst = [int(c) for c in (getattr(ctx, "analyst_call_ids", None) or []) if c]
    if analyst:
        cids = analyst
    else:
        cids = [int(c) for c in (ctx.input_call_ids or []) if c]
        if ctx.linked_call_id:
            cids.append(int(ctx.linked_call_id))
    for cid in dict.fromkeys(cids):
        entry = ctx.idx.by_call_id.get(cid)
        if not isinstance(entry, dict) or entry.get("type") != "tool_call":
            continue
        # The unseen middle this gate guards against is unseen evidence. A
        # call that returned the run's own state - a claim snapshot, the
        # investigation state, a coverage report - holds no evidence rows,
        # however much of it the conversation left out.
        if own_words_entry(entry):
            continue
        why = incomplete_reason(entry)
        if not why:
            continue
        named = artifact_tokens(entry_text(entry, include_file=True))
        # A sentence rests on this call only when the call is about it: the
        # artifact scopes meet (or one side names none), and the call's
        # request or seen rows hold a term of the sentence's own (_about).
        # Never wider than the artifact rule alone: no new binding.
        bound = [s for s, scope in zip(sentences, scopes)
                 if (not named or not scope or scope & named) and _about(s, entry, ctx)]
        if not bound:
            continue
        tool = str(entry.get("cmd") or entry.get("tool") or "?")[:80]
        spill = str(entry.get("stdout_file") or "")
        complete_hint = rest_of_result_hint(entry, spill, cid)
        from core.envfile import env_flag
        if env_flag("ATLAS_UNIVERSAL_GATE_V2"):
            refusal = _refusal_v2(ctx, desc, bound, cid, tool, why, complete_hint)
            if any(not _specific_terms(s) for s in bound):
                # A sentence that names nothing may rest on another search:
                # paging this call is then no answer.
                refusal["error"] += (f" A sentence that names nothing call {cid} read may rest on another "
                                     "search: cite that complete search (input_call_ids) in place of "
                                     f"call {cid}.")
            return refusal
        rewrite = narrow_statement(desc)
        if not _same_words(rewrite, desc):
            return {
                "success": False,
                "gate": "universal_from_truncated",
                "error": (
                    "This finding states what is true of all rows, or that "
                    f"something is absent, but call {cid} ({tool}) is not a "
                    f"complete view: {why}. One unseen row can make such a "
                    f"statement false. {complete_hint} Or re-record now what was "
                    "actually seen, for example: "
                    f"{rewrite!r}"
                ),
                "description": desc,
                "confidence": ctx.confidence,
                "incomplete_call_id": cid,
                "suggested_rewrite": rewrite,
                "objected_sentences": sentences,
            }
        # No narrower wording can be derived: name the words that make the
        # statement universal or negative instead of offering it back.
        trigger = _UNIVERSAL_RE.search(analysts_words(sentences[0]))
        words = " ".join(trigger.group(0).split()) if trigger else ""
        return {
            "success": False,
            "gate": "universal_from_truncated",
            "error": (
                f"The words {words!r} in {sentences[0][:160]!r} make this finding "
                "a statement about all rows or about an absence, but call "
                f"{cid} ({tool}) is not a complete view: {why}. One unseen row "
                f"can make such a statement false. {complete_hint} Or state what "
                "the cited calls show without that universal or absence, or "
                "leave this call out if the statement does not rest on it."
            ),
            "description": desc,
            "confidence": ctx.confidence,
            "incomplete_call_id": cid,
            "objected_sentences": sentences,
        }
    return None


_EVERY_ROW_RE = re.compile(
    r"(?i)\b(?:all|every|each|only|always|exclusively|alle|jede[rs]?|sämtliche|nur|immer|"
    r"ausschließlich)\b")


def _what_it_states(sentence: str) -> str:
    """"something about every row", "an absence", or both: which of the
    two kinds of words the analyst's own sentence carries."""
    own = analysts_words(sentence)
    every = bool(_EVERY_ROW_RE.search(own))
    absent = bool(_UNIVERSAL_RE.search(_EVERY_ROW_RE.sub(" ", own)))
    if every and absent:
        return "something about every row and an absence"
    return "an absence" if absent else "something about every row"


def _refusal_v2(ctx, desc: str, sentences: list[str], cid: int, tool: str, why: str,
                complete_hint: str) -> dict:
    """The refusal without a rewrite: each universal sentence named, the
    count first; a prescription sentence routed to the recommendations.
    A suggested wording would be copied back as the finding, true or not."""
    hint = complete_hint[:1].lower() + complete_hint[1:] if complete_hint else ""
    parts, factual = [], []
    for sentence in sentences:
        quoted = sentence if len(sentence) <= 200 else sentence[:197] + "..."
        if is_prescription(sentence):
            parts.append(
                f"The sentence '{quoted}' is a recommendation, not a statement about the evidence: "
                "record it with claim.add_recommendation(action=..., basis_ids=<the claim ids it rests "
                "on>) and keep the finding to what the cited rows show.")
        else:
            factual.append(f"'{quoted}' states {_what_it_states(sentence)}")
    if factual:
        lead = ("The sentence " + factual[0]) if len(factual) == 1 else (
            "The sentences " + "; ".join(factual))
        parts.insert(0, (
            f"{lead}, but call {cid} ({tool}) is not a complete view: {why}. One unseen row can make "
            f"such a statement false. Count first: {hint} Then record what the count shows, or state "
            "what the shown rows show without the universal or the absence, or leave call "
            f"{cid} out if the statement does not rest on it."))
    return {
        "success": False,
        "gate": "universal_from_truncated",
        "error": " ".join(parts),
        "description": desc,
        "confidence": ctx.confidence,
        "incomplete_call_id": cid,
        # The sentences the objection is about: the rest of the finding
        # stands (core.work_order.refused_findings keeps it on the table).
        "objected_sentences": list(sentences),
    }


_UNIVERSAL_WORD_RE = re.compile(
    r"(?i)\b(all|every|each|sämtliche|alle|jede[rs]?)\b(?=\s+\w)")
_ONLY_RE = re.compile(r"(?i)\b(only|exclusively|nur|ausschließlich)\s+")
_ABSENCE_SENTENCE_RE = re.compile(
    r"(?i)[^.;]*\b(?:no|none|never|not|nicht|kein[es]?|nie)\b[^.;]*(?:observed|"
    r"detected|found|present|seen|recorded|beobachtet|gefunden|festgestellt|"
    r"vorhanden)[^.;]*[.;]?")


def narrow_statement(text: str) -> str:
    """The same finding restricted to what a partial view supports:
    universal quantifiers become "the listed/observed", "only" is dropped,
    and sentences asserting absence are removed."""
    out = _ABSENCE_SENTENCE_RE.sub("", text or "")
    out = _UNIVERSAL_WORD_RE.sub("the observed", out)
    out = _ONLY_RE.sub("", out)
    return " ".join(out.split()).strip(" ,;") or (text or "").strip()


# ── prescriptions (ATLAS_UNIVERSAL_GATE_V2) ─────────────────────────────
#
# A recommendation ("Reset every account", "every domain password should be
# rotated") quantifies over what a responder does, not over rows of the
# evidence. The rule is narrow on purpose, so that a modal frame does not
# launder a fact ("It should be noted that every workstation beaconed",
# "Responders must assume all hosts were accessed"): the main clause is
# headed by an imperative or a normative modal before the universal word,
# or the universal word opens the subject and only the subject stands
# between it and the modal; no complementiser stands between them; no
# finite verb follows the universal word in its clause (the modal group's
# own passive participle aside); no absence; every universal word of the
# sentence is judged, a comma followed by a complementiser ends the clause,
# and a modal followed by a state or epistemic verb is not normative.
# English and German grammar, not knowledge about any case. Used by the
# conclusion door too; record_finding exempts nothing.
# ponytail: suffix test for verbs; a reduced relative ("every account listed in")
# reads as finite, so that prescription gets the count remedy instead of the
# routing one (still refused, never exempted); a tagger would lift the ceiling.

_P_MODAL_RE = re.compile(r"(?i)\b(?:must|should|needs? to|ought to|(?:is|are) required to|recommend(?:ed|s)?|"
                         r"muss|müssen|sollte|sollten|soll|sollen)\b")
_P_UNIVERSAL_RE = re.compile(r"(?i)\b(?:all|every|each|only|exclusively|alle|jede[rs]?|sämtliche|nur|"
                             r"ausschließlich)\b")
_P_ABSENCE_RE = re.compile(
    r"(?i)\b(?:none|no|never|kein[es]?|nie|niemals)\b"
    r"|\b(?:not|nicht|weder)\b.{0,40}\b(?:observed|detected|found|present|seen|"
    r"recorded|beobachtet|gefunden|festgestellt|vorhanden)\b"
    r"|\b(?:were|was|is|are|sind|ist|wurden|wurde)\s+(?:not|nicht)\b")
_P_COMPLEMENTISER_RE = re.compile(r"(?i)\b(?:that|as|whether|if|because|since|which|dass|ob|weil|da)\b")
_P_CLAUSE_END_RE = re.compile(r"(?i);|,\s*(?:that|as|whether|if|because|since|which|dass|ob|weil|da)\b")
_P_AUX_RE = re.compile(r"(?i)^(?:was|were|is|are|has|have|had|did|does|do|been|being|wurde|wurden|ist|sind|hat|"
                       r"haben|war|waren)$")
# A word read as a finite verb after the universal word: past tense or a
# third-person form; the plurals of the nouns a prescription quantifies over
# are not verbs (a suffix test, the stated ceiling of the rule).
_P_FINITE_RE = re.compile(r"(?i)^(?:[a-z]{3,}ed|[a-z]{4,}s)$")
_P_NOT_VERBS = frozenset({
    "this", "was", "is", "as", "plus", "across", "its", "has", "does", "always", "less", "unless", "us",
    "accounts", "hosts", "passwords", "systems", "files", "logs", "events", "sessions", "users", "workstations",
    "servers", "domains", "credentials", "indicators", "addresses", "processes", "services", "tasks", "keys",
    "beacons", "connections", "attempts", "logons", "shares", "artifacts", "artefacts", "backups", "copies",
    "devices", "machines", "endpoints", "mailboxes", "tokens", "certificates", "rules", "policies", "groups",
    "need", "needed", "red", "bed", "shed", "seed", "feed", "speed"})
_P_STATE_VERBS = frozenset({"show", "shows", "indicate", "indicates", "appear", "appears", "seem", "seems",
                            "mean", "means"})
_P_NOT_PARTICIPLE = frozenset({"the", "a", "an", "this", "that", "these", "those", "considered", "likely",
                               "unlikely", "true", "false", "able", "responsible", "due", "present", "absent",
                               "possible", "clear"})
_P_FIRST_NOT_VERB = frozenset({"the", "this", "that", "these", "those", "it", "we", "they", "all", "every",
                               "each", "only", "a", "an", "our", "their", "its", "he", "she", "i", "you"})


def _p_has_verb(text: str) -> bool:
    for t in re.findall(r"[A-Za-zÄÖÜäöüß]+", text):
        tl = t.lower()
        if _P_AUX_RE.match(t):
            return True
        if _P_FINITE_RE.match(t) and tl not in _P_NOT_VERBS and not tl.endswith(("ness", "less", "ous", "ss")):
            return True
    return False


def _p_normative(clause: str, modal: re.Match) -> bool:
    """A modal followed by a state or epistemic verb ("should show", "should
    be considered", "must be the origin") states, it does not prescribe."""
    after = re.findall(r"[A-Za-zÄÖÜäöüß]+", clause[modal.end():])
    if not after:
        return True
    if after[0].lower() in _P_STATE_VERBS:
        return False
    if after[0].lower() == "be":
        return len(after) > 1 and after[1].lower() not in _P_NOT_PARTICIPLE
    return True


def _p_clause(text: str, pos: int) -> tuple[str, int]:
    """The clause around offset ``pos`` and ``pos`` inside it: ";" and a
    comma followed by a complementiser are clause boundaries."""
    start, end = 0, len(text)
    for m in _P_CLAUSE_END_RE.finditer(text):
        if m.end() <= pos:
            start = m.end()
        elif m.start() >= pos:
            end = m.start()
            break
    return text[start:end], pos - start


def _p_universal_prescribed(clause: str, uni: re.Match) -> bool:
    words = clause.split()
    head_imperative = (len(words) >= 2 and re.match(r"^[A-ZÄÖÜ][a-zäöüß]+$", words[0]) is not None
                       and words[0].lower() not in _P_FIRST_NOT_VERB
                       and any(_P_UNIVERSAL_RE.fullmatch(w.strip(",")) or w.lower() in ("the", "a", "an")
                               for w in words[1:3])
                       and uni.start() <= len(" ".join(words[:3])))
    modal = _P_MODAL_RE.search(clause)

    def tail(start: int) -> str:
        rest = clause[start:]
        m = re.search(r"[,:]| and | or | but ", rest)
        return rest[: m.start()] if m else rest
    if head_imperative:
        between, after = clause[len(words[0]):uni.start()], tail(uni.end())
    elif modal and modal.start() < uni.start():
        if not _p_normative(clause, modal):
            return False
        between, after = clause[modal.end():uni.start()], tail(uni.end())
    elif modal and modal.start() > uni.end():
        between = clause[uni.end():modal.start()]
        if _p_has_verb(between) or not _p_normative(clause, modal):
            return False
        after = re.sub(r"(?i)^\s*(?:be|been|get)\s+[a-zäöüß]+\b", " ", tail(modal.end()))
    else:
        return False
    if _P_COMPLEMENTISER_RE.search(between):
        return False
    return not _p_has_verb(after)


def is_prescription(sentence: str) -> bool:
    """A sentence that prescribes what a responder does over every item
    (a recommendation), not one that states something about every row of
    the evidence. See the rule above; narrow so a modal frame launders no
    fact."""
    s = analysts_words(sentence or "").strip().rstrip(".!")
    if not s or _P_ABSENCE_RE.search(s):
        return False
    unis = list(_P_UNIVERSAL_RE.finditer(s))
    if not unis:
        return False
    judged = 0
    for uni in unis:
        # "not only", "not all", "nicht alle" negate the universal: no claim over every item to judge
        if re.search(r"(?i)\b(?:not|nicht)\s+$", s[:uni.start()]):
            continue
        judged += 1
        clause, at = _p_clause(s, uni.start())
        m = _P_UNIVERSAL_RE.match(clause, at)
        if m is None or not _p_universal_prescribed(clause, m):
            return False
    return judged > 0
