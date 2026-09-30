"""Gate: refuse negative findings whose linked tool result is truncated.

A negative finding that rests on a truncated tool result is refused:
truncation can hide the match that would refute it. A result with
`truncated: true` is incomplete, so an UNCONFIRMED ("absent" / "no match")
finding needs a re-run with a narrower pattern, or another channel over the
same data, before it can be recorded.

This gate makes that a hard refusal. It fires only when:
  - tier is UNCONFIRMED (the finding is asserting absence)
  - linked_call_id points at a real tool_call entry
  - that entry has truncated: true

Higher-tier findings (CONFIRMED / LIKELY / SUSPECTED) that cite a truncated
result are tolerated — truncation can hide additional matches but rarely
invalidates a positive observation already present in the visible output.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.tier != "UNCONFIRMED":
        return None
    if ctx.linked_call_id == 0:
        return None
    entry = ctx.idx.by_call_id.get(ctx.linked_call_id)
    if entry is None:
        return None
    if not entry.get("truncated"):
        return None
    from core.forensic_citation import own_words_entry
    if own_words_entry(entry):
        return None  # the run's own state, not a scan that may hide a match
    cmd_excerpt = (entry.get("cmd") or entry.get("tool") or "<unknown>")[:120]
    return {
        "success": False,
        "error": (
            f"Refusing UNCONFIRMED finding: linked_call_id={ctx.linked_call_id} "
            f"({cmd_excerpt!s}) returned truncated output. "
            f"A negative result cannot rest on truncated output: re-run with a narrower pattern "
            f"(or use a parallel channel such as `grep -a` on the raw file) and "
            f"link this finding to a non-truncated call before recording the "
            f"negative result."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "negative_from_truncated",
    }
