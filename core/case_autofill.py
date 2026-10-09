"""AI-assisted autofill for CASE.md's Evidence Links table.

Two-phase, LLM-light by design:

1. ``build_proposal`` deterministically inventories ``evidence/`` (reusing
   core.evidence_profile's classifier) and splits files into confident rows
   (extension maps cleanly to a CASE.md Kind) vs. ``unsure`` items (class
   "file" — the classifier itself couldn't place it).
2. ``ask_llm_about_unsure`` sends only the unsure items to the connected LLM
   (the same analyst-role provider a run uses — see agent/cli.py's
   ATLAS_AGENT_PROVIDER convention) in one batched call. The model either
   answers confidently or returns a short question — it is told not to guess.

Applying a proposal is pure text-splicing (``splice_case_md``, no LLM, no
disk I/O) so both the CLI and the dashboard can preview the exact CASE.md
text before anything is written — the dashboard button routes the result
through the existing case_md editor/Save flow rather than writing directly.

Never touches ``## Investigation Requests`` beyond appending the standard
question when the section has no real bullets yet, or a request the analyst wrote into *What you already know*
by mistake — the Evidence Links table and that section are the only
content this module rewrites.

The prior-knowledge section (``core.case_knowledge``) is free text, but the
parsers behind it reward a shape: one bullet per fact, Windows accounts as
``DOMAIN\\user``, a request stated as a request. ``ask_llm_to_reformat_prior_knowledge``
asks the model for that shape without dropping a fact, and reports any
indicator the rewrite lost so the operator sees it before inserting.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.evidence_links import (
    _HEADING_RE,
    _SECTION_HEADINGS,
    _is_separator_row,
    _norm_kind,
    _split_row_cells,
    parse_evidence_links,
    read_case_md,
)
from core.case_knowledge import (
    SECTION_TITLES,
    comment_lines,
    section_span,
    section_text,
)
from core.entities import extract
from core.evidence_profile import build_evidence_profile
from core.investigation_tasks import _SECTION_HEADINGS as _REQUEST_TITLES
from core.investigation_tasks import parse_case_requests, unclosed_fence

STANDARD_REQUEST = "What happened on the Host(s)?"

# evidence_profile file classes -> CASE.md's documented Kind vocabulary.
# Anything not listed here (in practice just "file") is genuinely ambiguous
# and goes to the LLM/operator rather than being guessed.
_CLASS_TO_KIND = {
    "disk": "disk",
    "memory": "memory",
    "pcap": "pcap",
    "windows_eventlog": "evtx",
    "tabular": "tabular",
    "email": "other",
}

_PLACEHOLDER_RE = re.compile(r"^<.*>$")

_AUTOFILL_SYSTEM_PROMPT = (
    "You help populate a DFIR case file's Evidence Links table. You are "
    "given evidence files whose type a mechanical classifier could not "
    "place. For each one, either answer confidently or ask the investigator "
    "a short question — never guess if you are not reasonably sure what the "
    "file is.\n\n"
    "Reply with ONLY a JSON array, one object per input item, same order:\n"
    '{"label": "<short host/device name>", '
    '"kind": "disk|memory|pcap|tabular|evtx|principal|other", '
    '"notes": "<brief note, or empty>", '
    '"question": "<empty if confident, else a short question for the '
    'investigator>"}'
)


_PRIOR_KNOWLEDGE_SYSTEM_PROMPT = (
    "You tidy the 'What you already know' section of a DFIR case file. It "
    "holds the analyst's prior knowledge: suspicions, indicators seen "
    "elsewhere, accounts, hosts, a time window, facts about their own "
    "environment, and sometimes a pasted list or log excerpt in a code "
    "fence. Rewrite it so a parser reads it well, keeping every fact; a "
    "pasted list becomes one bullet per item that names a value, with the "
    "value kept exactly.\n\n"
    "- One bullet per fact. Keep every name, address, account, hash, path, "
    "time and every stated uncertainty (a spelling the analyst is unsure "
    "of stays marked as unsure). Add nothing the text does not say and "
    "drop nothing it says.\n"
    "- A sentence that asks for work to be done ('it needs to be "
    "investigated whether ...', 'find out what ...') is an investigation "
    "request, not knowledge: move each one to 'requests' as one imperative "
    "sentence that keeps its wording.\n"
    "- A Windows user name is written DOMAIN\\user when the text names the "
    "domain or the host; otherwise keep the bare name and append "
    "' (Windows account, domain not given)'.\n"
    "- A bullet about an account the analyst calls compromised begins "
    "'Compromised account: '.\n"
    "- Keep the analyst's language and wording; correct nothing but the "
    "shape.\n\n"
    "Reply with ONLY a JSON object: "
    '{"knowledge": ["<bullet>", ...], "requests": ["<request>", ...]}'
)

_BULLET_PREFIX_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")


def _label_for(rel_path: str) -> str:
    """evidence/HOST/x.vmdk -> HOST; evidence/x.csv -> x (bare stem)."""
    parts = Path(rel_path).parts
    if len(parts) >= 3:
        return parts[1]
    return Path(rel_path).stem


def build_proposal(case_dir: str | Path) -> dict[str, Any]:
    """Deterministic pass: confident rows vs. items needing judgement."""
    case_dir = str(case_dir)
    profile = build_evidence_profile(case_dir)
    current_md = read_case_md(case_dir)
    linked = parse_evidence_links(current_md, case_dir=case_dir)
    fence = unclosed_fence(current_md)
    linked_paths = {e.get("path") for e in linked["entries"] if e.get("path")}

    rows: list[dict[str, Any]] = []
    unsure: list[dict[str, Any]] = []
    for f in profile["files"]:
        path, cls = f["path"], f["class"]
        if path in linked_paths:
            continue
        kind = _CLASS_TO_KIND.get(cls)
        item = {"path": path, "label": _label_for(path),
                "kind": kind or "other", "notes": "", "class": cls,
                "size": f.get("size", 0)}
        (rows if kind else unsure).append(item)

    return {
        "case_id": profile["case_id"],
        "rows": rows,
        "unsure": unsure,
        # Requests an unclosed code block hides are still the analyst's: the
        # standard question is not added on top of them.
        "investigation_requests_empty": (not parse_case_requests(current_md)
                                         and not (fence or {}).get("hidden_requests")),
        "unclosed_fence": fence,
        # The analyst's prior knowledge as written (comments removed, a
        # pasted fenced block kept); "" when CASE.md has no such section
        # or it is empty.
        "prior_knowledge": section_text(current_md),
    }


def clean_bullets(items: Any) -> list[str]:
    out: list[str] = []
    for it in items if isinstance(items, list) else []:
        text = _BULLET_PREFIX_RE.sub("", str(it or "").strip()).strip()
        if text and text not in out:
            out.append(text)
    return out


def ask_llm_to_reformat_prior_knowledge(text: str, client: Any) -> dict[str, Any] | None:
    """One chat() call shaping the prior-knowledge section.

    Returns ``{"knowledge": [...], "requests": [...], "dropped": [...]}`` —
    the bullets to put under the section, the sentences that belong under
    Investigation Requests instead, and every indicator (address, account,
    hash, path ...) the original names that the rewrite no longer does.
    None when the section is empty or the reply is unusable: the operator
    then keeps the section as written rather than getting a guess.
    """
    text = (text or "").strip()
    if not text:
        return None
    resp = client.chat(
        [{"role": "system", "content": _PRIOR_KNOWLEDGE_SYSTEM_PROMPT},
         {"role": "user", "content": "What you already know:\n" + text}])
    reply = (resp.content or "").strip()
    m = re.search(r"\{.*\}", reply, re.DOTALL)
    try:
        parsed = json.loads(m.group(0) if m else reply)
    except (json.JSONDecodeError, AttributeError):
        return None
    if not isinstance(parsed, dict):
        return None
    knowledge = clean_bullets(parsed.get("knowledge"))
    requests = clean_bullets(parsed.get("requests"))
    if not knowledge and not requests:
        return None
    rewritten = "\n".join(knowledge + requests)
    dropped = sorted(extract(text) - extract(rewritten))
    return {"knowledge": knowledge, "requests": requests, "dropped": dropped}


def append_requests(text: str, requests: list[str]) -> str:
    """Append ``requests`` as bullets at the end of ``## Investigation
    Requests``, skipping any already there. A brief without the section
    gets it at the end of the file, so a request is never dropped for
    want of a heading."""
    have = {r.casefold() for r in parse_case_requests(text)}
    new = [f"- {r}" for r in clean_bullets(requests) if r.casefold() not in have]
    if not new:
        return text
    lines = text.splitlines()
    span = section_span(lines, _REQUEST_TITLES)
    if span is None:
        base = text.rstrip("\n")
        return ((base + "\n\n") if base else "") + "## Investigation Requests\n\n" \
            + "\n".join(new) + "\n"
    start, end = span
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    spliced = lines[:end] + new + [""] + lines[end:]
    return "\n".join(spliced).rstrip("\n") + "\n"


def splice_prior_knowledge(
    markdown: str, bullets: list[str], *, requests: list[str] | None = None,
) -> str:
    """Return CASE.md text whose *What you already know* section carries
    ``bullets`` — its comment blocks kept, everything else in it replaced —
    with ``requests`` appended under Investigation Requests. Pure text
    transform; raises ValueError when CASE.md has no such section.
    """
    lines = markdown.splitlines()
    span = section_span(lines, SECTION_TITLES)
    if span is None:
        raise ValueError("CASE.md has no '## What you already know' section")
    start, end = span
    body = comment_lines(lines[start + 1:end])
    new = [lines[start], ""] + body + ([""] if body else []) \
        + [f"- {b}" for b in clean_bullets(bullets)] + [""]
    text = "\n".join(lines[:start] + new + lines[end:])
    if not text.endswith("\n"):
        text += "\n"
    return append_requests(text, clean_bullets(requests or []))


def ask_llm_about_unsure(unsure: list[dict[str, Any]], client: Any) -> list[dict[str, Any]]:
    """One batched chat() call resolving (or asking about) unsure items.

    Order-aligned with `unsure`; a response the model omits or garbles falls
    back to the item's own class/label with an explicit question rather than
    being silently added — an autofill must never invent a row it can't back.
    """
    if not unsure:
        return []
    lines = [f"- {u['path']} ({u.get('size', '?')} bytes)" for u in unsure]
    resp = client.chat(
        [{"role": "system", "content": _AUTOFILL_SYSTEM_PROMPT},
         {"role": "user", "content": "Evidence files:\n" + "\n".join(lines)}])
    text = (resp.content or "").strip()
    m = re.search(r"\[.*\]", text, re.DOTALL)
    try:
        parsed = json.loads(m.group(0) if m else text)
    except (json.JSONDecodeError, AttributeError):
        parsed = []
    if not isinstance(parsed, list):
        parsed = []

    results: list[dict[str, Any]] = []
    for i, u in enumerate(unsure):
        entry = parsed[i] if i < len(parsed) and isinstance(parsed[i], dict) else {}
        question = str(entry.get("question") or "").strip()
        if not entry:
            question = question or "What is this file?"
        results.append({
            "path": u["path"],
            "label": str(entry.get("label") or u["label"]),
            "kind": _norm_kind(str(entry.get("kind") or "other")),
            "notes": str(entry.get("notes") or ""),
            "question": question,
        })
    return results


def _append_standard_request(text: str) -> str:
    if not re.search(r"## Investigation Requests\n", text):
        return text
    bullet = f"- {STANDARD_REQUEST}"
    return re.sub(
        r"(## Investigation Requests\n)",
        lambda m: m.group(1) + bullet + "\n", text, count=1)


def splice_case_md(
    markdown: str, rows: list[dict[str, Any]], *, add_standard_request: bool = False,
) -> str:
    """Return CASE.md text with `rows` appended to the Evidence Links table.

    Placeholder example rows (label like ``<HOST>``, straight from
    case-template) are dropped when real rows are being added; any existing
    real rows are kept as-is. Pure text transform — never touches disk.
    Raises ValueError if CASE.md has no ``## Evidence Links`` table to
    extend (case-template always ships one, so this is a hand-edited-away
    case, not the common path).
    """
    lines = markdown.splitlines()
    heading_idx: int | None = None
    header_idx: int | None = None
    end_idx: int | None = None
    in_section = False
    for i, line in enumerate(lines):
        hm = _HEADING_RE.match(line)
        if hm:
            title = hm.group(1).strip().casefold().rstrip(":").strip().strip("*_ ")
            if in_section:
                end_idx = i
                break
            if title in _SECTION_HEADINGS:
                heading_idx = i
                in_section = True
            continue
        if in_section and header_idx is None and line.strip().startswith("|"):
            header_idx = i
    if in_section and end_idx is None:
        end_idx = len(lines)

    if heading_idx is None or header_idx is None:
        raise ValueError("CASE.md has no '## Evidence Links' table to extend")

    kept: list[str] = []
    existing_paths: set[str] = set()
    for line in lines[header_idx + 2:end_idx]:
        cells = _split_row_cells(line)
        if not cells:
            if line.strip():
                kept.append(line)  # stray non-table content — preserve it
            continue
        if _is_separator_row(cells):
            continue
        while len(cells) < 4:
            cells.append("")
        if _PLACEHOLDER_RE.match(cells[0].strip()):
            continue  # drop case-template's <HOST>/<account> placeholder rows
        kept.append(line)
        if cells[2]:
            existing_paths.add(cells[2])

    new_rows: list[str] = []
    for r in rows:
        path = (r.get("path") or "").strip()
        if path and path in existing_paths:
            continue
        new_rows.append(
            f"| {r.get('label', '')} | {r.get('kind', 'other')} | {path} | "
            f"{r.get('notes', '')} |")
        if path:
            existing_paths.add(path)

    spliced = (lines[:header_idx] + lines[header_idx:header_idx + 2]
               + kept + new_rows + lines[end_idx:])
    text = "\n".join(spliced)
    if not text.endswith("\n"):
        text += "\n"
    if add_standard_request:
        text = _append_standard_request(text)
    return text
