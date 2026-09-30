"""What the analyst already knows — an optional CASE.md section Atlas reads.

Investigators rarely start blind: an alert named an address, a hash came
with the ticket, someone suspects ransomware. This module reads that prior
knowledge from a ``## What you already know`` section of CASE.md and puts
it to two uses. The indicators in it become search obligations from the
first turn (``core.ioc_pivots`` seeds its ledger from here), and the prose
reaches the model as leads through a short block in the system prompt.

The epistemic contract is deliberately narrow. An indicator here says the
analyst *suspects* it — nothing about whether it appears in this evidence.
A hit is a finding that cites the call which found it; a miss is a
coverage statement and never exoneration; a hypothesis is something to
test, not a conclusion. Nothing in this section is ever recorded as a
finding on its own, and nothing here is promoted into the brain.

Graded cases — those shipping an answer key — are left alone: a hint in
the brief would make the run's score unmeasurable. The section is still
shown to the model there (CASE.md is injected whole), but no indicator is
seeded from it.
"""
from __future__ import annotations

import os
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


def section_text(markdown: str) -> str:
    """The body of the prior-knowledge section, comments and fences
    removed; empty when CASE.md has no such section."""
    from core.investigation_tasks import _HEADING_RE, _strip_noncontent_markdown

    if not markdown or not markdown.strip():
        return ""
    lines: list[str] = []
    inside = False
    for line in _strip_noncontent_markdown(markdown).splitlines():
        heading = _HEADING_RE.match(line)
        if heading:
            title = heading.group(1).strip().strip("*_ ").casefold()
            inside = title in SECTION_TITLES
            continue
        if inside:
            lines.append(line)
    return "\n".join(lines).strip()


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


def _indicators(case_dir: str | os.PathLike, text: str) -> dict[str, str]:
    """Pivotable indicators named in ``text``, keyed the way the pivot
    ledger keys them. The case's own file names are not indicators."""
    from core.entities import extract
    from core.ioc_pivots import _is_pivotable, case_file_names, ioc_type, ioc_value

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


def prompt_note(case_dir: str | os.PathLike) -> str:
    """The block the system prompt carries when the section is present:
    what the analyst's prior knowledge is allowed to mean."""
    info = read(case_dir)
    if not info.get("present"):
        return ""
    n = len(info.get("indicators") or {})
    if info.get("seeded"):
        seeded = (f"{n} indicator(s) from it are seeded as search obligations "
                  "and will appear in the [ioc pivot] nudge until searched.")
    elif info.get("reason"):
        seeded = f"No indicator was seeded from it ({info['reason']})."
    else:
        seeded = "It names no indicator Atlas could seed a search from."
    return (
        "────────────────────────────────────────────────────────\n"
        "# PRIOR KNOWLEDGE (CASE.md, 'What you already know')\n\n"
        "The section above this line carries the analyst's prior knowledge: "
        "suspicions and indicators seen outside this evidence. It sets where "
        "to look first and nothing more. An indicator there attests suspicion, "
        "not presence — a hit in this case's evidence is a finding citing the "
        "call that found it; no hit is a coverage statement, never exoneration. "
        "A stated theory is a hypothesis to test with reason.hypothesize, not "
        "a conclusion. Never record the section's own content as a finding.\n"
        f"{seeded}\n"
    )


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
    ``titles``; ``end_idx`` is the next heading or the end of the text."""
    from core.investigation_tasks import _HEADING_RE

    start: int | None = None
    for i, line in enumerate(lines):
        hm = _HEADING_RE.match(line)
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
    """The facts the section states, one per top-level bullet, as written
    with emphasis removed."""
    out: list[str] = []
    for line in section_text(markdown).splitlines():
        text = _bullet_text(line)
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
    bullet does. Example bullets inside the section's comments stay."""
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
    for i in range(start + 1, end):
        if i in commented:
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
