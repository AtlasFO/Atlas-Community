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


def analysts_words(text: str) -> str:
    """The statement with its quotations of source text and its epistemic
    hedges removed: what the analyst claims about the evidence."""
    return _HEDGE_RE.sub(" ", _QUOTED_RE.sub(" ", text or ""))


def incomplete_reason(entry: dict) -> str:
    """Why the analyst did not see everything a tool result held, or ''
    when nothing was withheld."""
    if entry.get("truncated"):
        return "its output was truncated"
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
    h, x = nums.get("hit_count"), nums.get("max_hits")
    if h is not None and x is not None and 0 < x <= h:
        return f"it stopped at the {x}-hit cap"
    return ""


def is_universal_or_negative(text: str) -> bool:
    """Whether the analyst's own statement is about all rows or about an
    absence; words quoted from the evidence do not count."""
    return bool(_UNIVERSAL_RE.search(analysts_words(text)))


def _universal_sentences(text: str) -> list[str]:
    """The sentences that make the statement universal or negative. A
    finding often states several things; only these rest on complete views."""
    sentences = re.split(r"(?<=[.;!?])\s+", " ".join((text or "").split()))
    return [s for s in sentences if is_universal_or_negative(s)]


def _same_words(a: str, b: str) -> bool:
    """Equal once spacing and punctuation are set aside."""
    def norm(x: str) -> str:
        return " ".join(re.sub(r"[\W_]+", " ", x or "").split()).casefold()
    return norm(a) == norm(b)


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
        if named and all(scope and not (scope & named) for scope in scopes):
            continue
        tool = str(entry.get("cmd") or entry.get("tool") or "?")[:80]
        spill = str(entry.get("stdout_file") or "")
        complete_hint = (
            f"The complete output of call {cid} is on disk at {spill}; a "
            "strings.strings_grep or table.table_grep over that file counts "
            "every row." if spill else
            "Count with table.table_pivot(group_by=…) or narrow where= until "
            "every matching row is returned (returned_rows == matched_rows).")
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
        }
    return None


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
