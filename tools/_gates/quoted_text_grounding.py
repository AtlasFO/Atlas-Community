"""Gate: text a finding presents as a verbatim quotation must occur in a
forensic tool output.

A command line or log line written from memory after the original output
left the context reads as evidence in the report while differing from what
the source says. Only quotations that look like source material (a path,
an option, a key=value pair, a time) are checked; a quoted name or phrase
is left alone.
"""
from __future__ import annotations

import re
from typing import Optional

_QUOTE_RE = re.compile(
    r"(?:^|[\s(\[])[\"'\u201c\u2018`]([^\"'\u201c\u201d\u2018\u2019`\n]{16,300})"
    r"[\"'\u201d\u2019`](?=$|[\s.,;:)\]])")
_SOURCE_LIKE_RE = re.compile(r"[/\\=\[]|--|\s-[A-Za-z]|\d{1,2}:\d{2}")
_WS_RE = re.compile(r"\s+")


def _norm(text: str) -> str:
    text = text.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", " ")
    return _WS_RE.sub(" ", text).strip().casefold()


def quoted_source_text(description: str) -> list[str]:
    """The quotations in a description that read as copied source material."""
    out: list[str] = []
    for m in _QUOTE_RE.finditer(description or ""):
        q = m.group(1).strip()
        if _SOURCE_LIKE_RE.search(q):
            out.append(q)
    return out


def _forensic_text(ctx, *, include_files: bool) -> str:
    from core.forensic_citation import own_words_entry
    from tools.misc import _tool_entry_text_blobs
    wanted = {int(c) for c in (ctx.input_call_ids or []) if str(c).isdigit()}
    if ctx.linked_call_id:
        wanted.add(int(ctx.linked_call_id))
    blobs: list[str] = []
    entries = list(getattr(ctx.log, "_entries", []) or [])
    for e in reversed(entries[-400:]):
        if e.get("type") != "tool_call" or own_words_entry(e):
            continue
        cited = e.get("call_id") in wanted
        blobs.extend(_tool_entry_text_blobs(e, include_files=include_files and cited))
    return _norm("\n".join(blobs))


def check(ctx) -> Optional[dict]:
    quotes = quoted_source_text(ctx.description)
    if not quotes:
        return None
    hay = _forensic_text(ctx, include_files=False)
    missing = [q for q in quotes if _norm(q) not in hay]
    if missing:
        hay = _forensic_text(ctx, include_files=True)   # rows kept on disk
        missing = [q for q in missing if _norm(q) not in hay]
    if missing:
        # A dumper that wraps its output at a fixed width breaks a line
        # inside a token, so the tool output carries a space the source
        # never had and a quotation copied correctly from the source fails
        # the comparison above. The characters must still occur in order;
        # only the whitespace between them is forgiven.
        squashed = hay.replace(" ", "")
        missing = [q for q in missing if _norm(q).replace(" ", "") not in squashed]
    if not missing:
        return None
    shown = "; ".join(f"\u00ab{q[:80]}\u00bb" for q in missing[:3])
    return {
        "success": False,
        "error": (
            f"quoted_text_grounding: the quoted text {shown} does not occur in "
            "any tool output of this trace. Quote the line exactly as the tool "
            "result shows it (re-run the search if that output has left the "
            "context) or describe it without quotation marks."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "quoted_text_grounding",
    }
