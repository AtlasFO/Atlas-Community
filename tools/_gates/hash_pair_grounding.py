"""Gate: a CONFIRMED/LIKELY finding that binds a file to a hash must cite a
row that shows them together.

A hash shown in one row and a file name in another ground "file X has hash H"
for the entity test of the citation status, which looks for each value on its
own. Two files said to share a digest when only one of them has it, or a
hash moved to the wrong file, then read as cited. The pairs are lexical
(citation_support.hash_pairs); a pair an uncited call of the trace shows
passes and is recorded as located by Atlas (citation_status); one no call
shows is refused, with the SUSPECTED route.
"""
from __future__ import annotations

from typing import Optional


def _cited_entries(ctx) -> list[dict]:
    cids = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(ctx.linked_call_id)
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    return [by_id[c] for c in dict.fromkeys(cids) if isinstance(by_id.get(c), dict)]


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    from .citation_support import hash_pairs, pair_detail, pair_showing_calls, unshown_pairs
    if not hash_pairs(ctx.description):
        return None
    cited = _cited_entries(ctx)
    missing = unshown_pairs(ctx.description, cited)
    if not missing:
        return None
    tool_calls = [e for e in getattr(ctx.log, "_entries", []) or [] if e.get("type") == "tool_call"]
    showing = pair_showing_calls(missing, tool_calls, exclude=[e.get("call_id") for e in cited])
    if len(showing) == sum(len(names) for _d, names in missing):
        return None
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding binds a file to a hash that no row shows together ("
            + pair_detail(missing, showing)
            + "). A hash in one row and a file name in another do not say the file has that hash. "
            "Cite the call whose row prints the file with its hash (a hash of that file, a manifest "
            "row naming both), write each file with its own digest, like 'name.ext (MD5 ...)', or "
            "record the finding at SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "hash_pair_grounding",
    }
