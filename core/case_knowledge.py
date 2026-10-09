"""What the analyst already knows — an optional CASE.md section Atlas reads.

Investigators rarely start blind: an alert named an address, a hash came
with the ticket, someone suspects ransomware, the admin host is known. This
module reads that prior knowledge from a ``## What you already know``
section of CASE.md and puts it to three uses. The indicators in it become
search obligations from the first turn (``core.ioc_pivots`` seeds its ledger
from here, and its nudge quotes the statement that names each one). Each
top-level bullet becomes an analyst-context entry with an id
(``core.analyst_context``). And the section reaches the model as the PRIOR
KNOWLEDGE block of the system prompt, statement by statement, under one
contract that run, rerun and chat share.

The contract is deliberately narrow. Every statement is the analyst's word,
not evidence. A suspicion or an indicator says where to look first: a hit
is a finding that cites the call which found it, a miss is a coverage
statement and never exoneration, a theory is a hypothesis to test. A
statement about the environment (a known host, a service account, expected
activity) informs interpretation and is no allowlist. Which kind a
statement is, the model decides; nothing here classifies it. Nothing in
this section is ever recorded as a finding on its own, and nothing here is
promoted into the brain.

HTML comments in the section are the template's documentation and are read
by nothing. A fenced block is the analyst's pasted data (an indicator list,
a log excerpt): it is read whole, for indicators and by the model, but not
split into facts.

Graded cases — those shipping an answer key — are left alone: a hint in
the brief would make the run's score unmeasurable. The section is still
shown to the model there, but no indicator is seeded from it, and the
prompt does not say why.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# Headings that mark the section, compared case-insensitively after
# stripping emphasis. The first alias is the one the template uses.
SECTION_TITLES = frozenset({
    "what you already know",
    "what we already know",
    "prior knowledge",
    "known indicators",
    "analyst notes",
    "background",
})

ORIGIN = "case_md"

# How the model reads every statement of the section, in every mode. The
# rerun message and the rerun brief point here rather than restating it.
CONTRACT = (
    "These are the analyst's statements from before this evidence was "
    "opened, as they wrote them. Each is the analyst's word, not evidence, "
    "and never becomes a finding by being repeated. Decide for each "
    "statement what it is; one statement can be both:\n"
    "- A suspicion, a theory or an indicator seen elsewhere (an address "
    "from an alert, a hash, an account thought compromised, a time window) "
    "says where to look first. Test a theory as a hypothesis "
    "(reason.hypothesize). A hit in this case's evidence is a finding that "
    "cites the call that found it; no hit is a coverage statement, never "
    "exoneration.\n"
    "- A statement about the environment (a known admin host, a service "
    "account, expected activity) informs how you read what you find. It is "
    "not a blind allowlist: known infrastructure and trusted accounts can "
    "still be used maliciously, so judge the activity, not the name.\n"
    "Where a statement with an id (ac-NNNN) shaped a hypothesis, a finding "
    "or a disposition, cite that id in the text."
)

# The block's size bound, the threat context's (core.threat_context
# PROMPT_BYTES): a section grown by many reruns is cut at a line, and the
# cut says where the rest stands.
_BLOCK_CHARS = 6000


def is_section_title(heading: re.Match) -> bool:
    """Whether a heading match (``_HEADING_RE``) opens the section."""
    return heading.group(1).strip().strip("*_ ").casefold() in SECTION_TITLES


def section_text(markdown: str) -> str:
    """The body of the prior-knowledge section as written, HTML comments
    removed; empty when CASE.md has no such section. Fenced blocks stay,
    and a heading-like line inside one (a shell comment) does not end the
    section. A thematic break the brief puts between this section and the
    next one is not part of it."""
    from core.investigation_tasks import (_HEADING_RE, _THEMATIC_BREAK_RE, fenced_flags,
                                          strip_html_comments)

    if not markdown or not markdown.strip():
        return ""
    lines = strip_html_comments(markdown).splitlines()
    out: list[tuple[str, bool]] = []
    inside = False
    for line, fenced in zip(lines, fenced_flags(lines)):
        heading = None if fenced else _HEADING_RE.match(line)
        if heading:
            inside = is_section_title(heading)
            continue
        if inside:
            out.append((line, fenced))
    while out and (not out[-1][0].strip()
                   or (not out[-1][1] and _THEMATIC_BREAK_RE.match(out[-1][0]))):
        out.pop()
    return "\n".join(line for line, _ in out).strip()


def replace_section_body(markdown: str, replacement: str) -> str:
    """``markdown`` with the body of every prior-knowledge section replaced
    by ``replacement``, headings kept: the brief as a prompt shows it when
    the section is rendered in a block of its own."""
    from core.investigation_tasks import _HEADING_RE, fenced_flags

    lines = markdown.splitlines()
    out: list[str] = []
    inside = False
    for line, fenced in zip(lines, fenced_flags(lines)):
        heading = None if fenced else _HEADING_RE.match(line)
        if heading:
            inside = is_section_title(heading)
            out += [line, "", replacement, ""] if inside else [line]
        elif not inside:
            out.append(line)
    return "\n".join(out)


def _graded(case_dir: str | os.PathLike) -> bool:
    try:
        from core.brain.answer_key import has_ground_truth
        return has_ground_truth(Path(case_dir))
    except Exception:  # noqa: BLE001 — a probe failure must not hide the section
        return False


def read(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Everything the section provides for this case.

    ``present``     the section exists and has content
    ``text``        its body, as written
    ``indicators``  ``{ioc: ORIGIN}`` for every pivotable indicator in it
    ``seeded``      whether those indicators are handed to the pivot ledger
    ``reason``      why not, when ``seeded`` is False
    """
    from core.investigation_tasks import read_case_markdown

    text = section_text(read_case_markdown(case_dir))
    out: dict[str, Any] = {"present": bool(text), "text": text,
                           "indicators": {}, "seeded": False, "reason": ""}
    if not text:
        return out
    if _graded(case_dir):
        out["reason"] = "graded case: an answer key ships with it"
        return out
    out["indicators"] = _indicators(case_dir, text)
    out["seeded"] = bool(out["indicators"])
    return out


def _indicators(case_dir: str | os.PathLike, text: str,
                own: set[str] | None = None) -> dict[str, str]:
    """Pivotable indicators named in ``text``, keyed the way the pivot
    ledger keys them. The case's own file names are not indicators."""
    from core.entities import extract
    from core.ioc_pivots import _is_pivotable, case_file_names, ioc_type, ioc_value

    if own is None:
        own = case_file_names(case_dir)
    found: dict[str, str] = {}
    for ent in sorted(extract(text)):
        if not _is_pivotable(ent):
            continue
        if ioc_type(ent) in ("file", "path"):
            base = ioc_value(ent).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            if base.casefold() in own:
                continue
        found[ent] = ORIGIN
    return found


def prior_indicators(case_dir: str | os.PathLike) -> dict[str, str]:
    """``{ioc: ORIGIN}`` to seed the pivot ledger with; empty when the
    section is absent or the case is graded."""
    return read(case_dir).get("indicators") or {}


def _entry_ids(case_dir: str | os.PathLike) -> dict[str, str]:
    """``{fingerprint: id}`` of the active analyst-context entries the
    section's bullets became."""
    from core.analyst_context import list_context
    from core.investigation_tasks import fingerprint_text

    out: dict[str, str] = {}
    for e in list_context(case_dir, active_only=True):
        if e.get("origin") == ORIGIN:
            fp = str(e.get("fingerprint") or fingerprint_text(e.get("text") or ""))
            out.setdefault(fp, str(e.get("id") or ""))
    return out


def _rendered_statements(case_dir: str | os.PathLike) -> str:
    """The section as written, comments removed, each top-level bullet
    outside a fence led by the id of its analyst-context entry; then the
    active entries that did not come from the section. Empty when there
    is nothing to show."""
    from core.analyst_context import list_context
    from core.investigation_tasks import (
        fenced_flags,
        fingerprint_text,
        open_fence,
        read_case_markdown,
    )

    lines = section_text(read_case_markdown(case_dir)).splitlines()
    ids = _entry_ids(case_dir) if lines else {}
    out: list[str] = []
    stated: set[str] = set()
    for line, fenced in zip(lines, fenced_flags(lines)):
        fact = None if fenced else _bullet_text(line)
        if fact:
            stated.add(fingerprint_text(fact))
        eid = ids.get(fingerprint_text(fact)) if fact else None
        out.append(f"- [{eid}] {fact}" if eid else line)
    # Entries written before the section was their source (no origin)
    # stand until withdrawn; a fresh run must see them too, once.
    others = [e for e in list_context(case_dir, active_only=True)
              if e.get("origin") != ORIGIN and str(e.get("text") or "").strip()
              and fingerprint_text(str(e.get("text"))) not in stated]
    if others:
        out += ["", "Also standing, given outside CASE.md:"]
        out += [f"- [{e.get('id')}] {str(e.get('text')).strip()}" for e in others]
    body = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
    if len(body) > _BLOCK_CHARS:
        cut = body.rfind("\n", 0, _BLOCK_CHARS)
        kept = body[:cut if cut > 0 else _BLOCK_CHARS]
        # A cut inside pasted data closes its fence, or the block's end
        # and everything after it would read as code.
        fence = open_fence(kept.splitlines())
        body = (kept + (f"\n{fence * 3}" if fence else "")
                + f"\n(cut at {_BLOCK_CHARS} characters; the rest stands in CASE.md "
                "under 'What you already know')")
    return body


def prompt_note(case_dir: str | os.PathLike, *, chat: bool = False) -> str:
    """The PRIOR KNOWLEDGE block of the system prompt: the contract, then
    the statements themselves. Chat has no pivot nudge, so its block does
    not promise one. Empty when there is nothing to show."""
    body = _rendered_statements(case_dir)
    if not body:
        return ""
    lines = [
        "────────────────────────────────────────────────────────",
        "# PRIOR KNOWLEDGE (CASE.md, 'What you already know')",
        "",
        CONTRACT,
    ]
    named = len(read(case_dir).get("indicators") or {})
    if named and not chat:
        from core.ioc_pivots import MAX_PIVOTS
        lines.append(f"{min(named, MAX_PIVOTS)} indicator(s) named here are "
                     "seeded as search obligations against the sources that can "
                     "hold them: the [ioc pivot] nudge lists each one with the "
                     "statement that names it until it is searched.")
    lines += ["", "<<<PRIOR KNOWLEDGE", body, "PRIOR KNOWLEDGE>>>", ""]
    return "\n".join(lines)


def indicator_statements(case_dir: str | os.PathLike) -> dict[str, dict[str, str]]:
    """``{ioc: {"id": ..., "text": ...}}``: for each indicator the section
    names, the statement it stands in — its top-level bullet (with the
    entry id when it has one; an indented line belongs to the bullet
    above), or the line of prose or pasted data. The pivot nudge quotes
    it, so a hit is judged against what the analyst said."""
    from core.investigation_tasks import fenced_flags, fingerprint_text, read_case_markdown
    from core.ioc_pivots import case_file_names

    lines = section_text(read_case_markdown(case_dir)).splitlines()
    if not lines:
        return {}
    ids = _entry_ids(case_dir)
    own = case_file_names(case_dir)
    out: dict[str, dict[str, str]] = {}
    stmt: dict[str, str] | None = None
    for line, fenced in zip(lines, fenced_flags(lines)):
        if not line.strip():
            continue
        fact = None if fenced else _bullet_text(line)
        if fact:
            stmt = {"id": ids.get(fingerprint_text(fact), ""), "text": fact}
        elif fenced or stmt is None or not line[:1].isspace():
            stmt = {"id": "", "text": line.strip()}
        for ioc in _indicators(case_dir, line, own):
            out.setdefault(ioc, stmt)
    return out


# ── the section as a list of facts ───────────────────────────────────────
#
# A fact is one top-level bullet of the section. Bullets are what the
# template asks for and what the autofill shapes the section into; prose
# still reaches the model through the prompt, but only a bullet is a fact
# Atlas can follow as it changes. Facts are matched by their words alone,
# spacing and case aside, the way requests are matched to tasks.

SECTION_HEADING = "## What you already know"


def section_span(lines: list[str], titles: frozenset[str]) -> tuple[int, int] | None:
    """``(heading_idx, end_idx)`` of the first section whose title is in
    ``titles``; ``end_idx`` is the next heading or the end of the text. A
    heading-like line inside a fenced block or an HTML comment is none."""
    from core.investigation_tasks import _HEADING_RE, fenced_flags

    commented = comment_line_indexes(lines)
    fenced = fenced_flags(["" if i in commented else line for i, line in enumerate(lines)])
    start: int | None = None
    for i, line in enumerate(lines):
        hm = None if (fenced[i] or i in commented) else _HEADING_RE.match(line)
        if not hm:
            continue
        if start is not None:
            return start, i
        if hm.group(1).strip().strip("*_ ").casefold() in titles:
            start = i
    return (start, len(lines)) if start is not None else None


def comment_line_indexes(lines: list[str]) -> set[int]:
    """Indexes of the lines that belong to HTML comments. Line-level: a
    comment opened mid-line takes the whole line."""
    out: set[int] = set()
    inside = False
    for i, line in enumerate(lines):
        opened = "<!--" in line
        if inside or opened:
            out.add(i)
        if opened and "-->" not in line[line.find("<!--") + 4:]:
            inside = True
        elif "-->" in line:
            inside = False
    return out


def comment_lines(lines: list[str]) -> list[str]:
    """The lines of ``lines`` that belong to HTML comments, in order."""
    keep = comment_line_indexes(lines)
    return [line for i, line in enumerate(lines) if i in keep]


def _key(text: str) -> str:
    from core.investigation_tasks import normalize_request_text
    return normalize_request_text(text)


def _bullet_text(line: str) -> str | None:
    """The text of a top-level bullet or numbered item; None otherwise."""
    from core.investigation_tasks import _BULLET_RE, _strip_inline_emphasis

    # _BULLET_RE reads no thematic break as a bullet.
    bm = _BULLET_RE.match(line)
    if not bm or len(line) - len(line.lstrip(" \t")) >= 2:
        return None
    return _strip_inline_emphasis(bm.group(1).strip()) or None


def _clean(items: Any) -> list[str]:
    """Bullet markers and surrounding space dropped; empties and repeats gone."""
    from core.investigation_tasks import _BULLET_RE

    out: list[str] = []
    seen: set[str] = set()
    for item in items or []:
        text = str(item or "").strip()
        bm = _BULLET_RE.match(text)
        if bm:
            text = bm.group(1).strip()
        key = _key(text)
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def facts_in(markdown: str) -> list[str]:
    """The facts the section states, one per top-level bullet outside a
    fenced block, as written with emphasis removed."""
    from core.investigation_tasks import fenced_flags

    lines = section_text(markdown).splitlines()
    out: list[str] = []
    for line, fenced in zip(lines, fenced_flags(lines)):
        text = None if fenced else _bullet_text(line)
        if text and text not in out:
            out.append(text)
    return out


def facts(case_dir: str | os.PathLike) -> list[str]:
    from core.investigation_tasks import read_case_markdown
    return facts_in(read_case_markdown(case_dir))


def append_facts_text(markdown: str, new_facts: Any) -> str:
    """The text with ``new_facts`` appended as bullets at the end of the
    section, skipping any already there. A brief without the section gets
    it at the end, so a fact is never dropped for want of a heading."""
    have = {_key(f) for f in facts_in(markdown)}
    add = [f for f in _clean(new_facts) if _key(f) not in have]
    if not add:
        return markdown
    bullets = [f"- {f}" for f in add]
    lines = markdown.splitlines()
    span = section_span(lines, SECTION_TITLES)
    if span is None:
        base = markdown.rstrip("\n")
        return ((base + "\n\n") if base else "") + SECTION_HEADING + "\n\n" \
            + "\n".join(bullets) + "\n"
    start, end = span
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    spliced = lines[:end] + bullets + [""] + lines[end:]
    return "\n".join(spliced).rstrip("\n") + "\n"


def remove_fact_text(markdown: str, fact: str) -> str:
    """The text without the bullet that states ``fact``; unchanged when no
    bullet does. Example bullets inside the section's comments and lines
    of a fenced block stay."""
    from core.investigation_tasks import fenced_flags

    cleaned = _clean([fact])
    if not cleaned:
        return markdown
    want = _key(cleaned[0])
    lines = markdown.splitlines()
    span = section_span(lines, SECTION_TITLES)
    if span is None:
        return markdown
    start, end = span
    commented = comment_line_indexes(lines)
    fenced = fenced_flags(["" if i in commented else line for i, line in enumerate(lines)])
    for i in range(start + 1, end):
        if i in commented or fenced[i]:
            continue
        text = _bullet_text(lines[i])
        if text and _key(text) == want:
            del lines[i]
            return "\n".join(lines).rstrip("\n") + "\n"
    return markdown


def append_facts(case_dir: str | os.PathLike, new_facts: Any) -> list[str]:
    """Append to the case file; returns the facts actually added."""
    from core.investigation_tasks import read_case_markdown, write_case_markdown

    md = read_case_markdown(case_dir)
    before = {_key(f) for f in facts_in(md)}
    out = append_facts_text(md, new_facts)
    if out == md:
        return []
    write_case_markdown(case_dir, out)
    return [f for f in facts_in(out) if _key(f) not in before]


def remove_fact(case_dir: str | os.PathLike, fact: str) -> bool:
    """Drop the bullet stating ``fact`` from the case file; False when none did."""
    from core.investigation_tasks import read_case_markdown, write_case_markdown

    md = read_case_markdown(case_dir)
    out = remove_fact_text(md, fact)
    if out == md:
        return False
    write_case_markdown(case_dir, out)
    return True
