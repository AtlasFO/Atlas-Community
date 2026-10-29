"""The attribution gates' pass test (ATLAS_ATTRIBUTION_IDENTITY_ROWS):
an account or a person credited with an act must stand in a printed row of
a call the finding cites, beside another checkable term of the same claim
(an entity of the act, a minute it names, a host it names, an identifier
word). Which record type binds a person to an act on a given platform is
the model's and the evaluator's judgement; this only checks that the
credited identity was read where the finding points, together with the act.
"""
from __future__ import annotations

import re
from typing import Any, Iterable


def _token_re(token: str) -> re.Pattern:
    """A whole label: 'jane' in 'CORP\\jane' or 'jane@example.com', not in
    'janet'."""
    return re.compile(rf"(?<![a-z0-9_]){re.escape(token.lower())}(?![a-z0-9_])")


def _evidence_call(entry: Any) -> bool:
    from core.forensic_citation import citation_class, own_words_entry
    return (isinstance(entry, dict) and entry.get("type") == "tool_call" and entry.get("success") is not False
            and not own_words_entry(entry) and citation_class(entry) == "evidence")


def binding_rows(ctx, identity: Iterable[str]) -> tuple[bool, list[int], list[int]]:
    """``(a cited call shows it, the cited call ids, the other calls of the
    trace that show it, newest first, at most five)``: a call shows the
    identity when one of its printed rows holds an identity token and
    another checkable term of the claim."""
    from core.forensic_citation import host_mentioned
    from .citation_support import _entity_in_row, _read_paths, _row_times, call_view, claim_terms
    tokens = sorted({t.lower() for t in identity if t and len(t) >= 3})
    if not tokens:
        return False, [], []
    rxs = [_token_re(t) for t in tokens]
    terms = claim_terms(ctx.description or "", host=getattr(ctx, "host", "") or "")
    strong = {e for e in terms["strong"] if not any(t in e.split(":", 1)[-1].lower() for t in tokens)}
    names = {n for n in terms["names"] if not any(t in n for t in tokens)}

    def row_binds(row: str) -> bool:
        low = (row or "").lower()
        if not any(rx.search(low) for rx in rxs):
            return False
        return (any(_entity_in_row(e, low) for e in strong)
                or bool(terms["times"] & _row_times(low))
                or any(host_mentioned(h, low) for h in terms["hosts"])
                or any(re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", low) for n in names))

    def shows(entry: dict) -> bool:
        if not _evidence_call(entry):
            return False
        _excluded, hosts = _read_paths(entry)
        if terms["hosts"] and hosts and not ({h.lower() for h in terms["hosts"]} & hosts):
            return False
        return any(row_binds(r) for r in call_view(entry)[0])

    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    cited = [int(c) for c in list(getattr(ctx, "input_call_ids", None) or []) + [ctx.linked_call_id]
             if isinstance(c, int) and c > 0]
    cited = list(dict.fromkeys(cited))
    if any(shows(by_id.get(c)) for c in cited):
        return True, cited, []
    calls = (getattr(ctx.idx, "by_type", {}) or {}).get("tool_call", [])
    others = []
    for e in reversed(calls):
        cid = e.get("call_id")
        if cid in cited or not isinstance(cid, int):
            continue
        if shows(e):
            others.append(cid)
            if len(others) >= 5:
                break
    return False, cited, others


def refusal(ctx, gate: str, who: str, what: str, cited: list[int], others: list[int],
            hint: str = "") -> dict[str, Any]:
    """The refusal of both attribution gates: the credited identity, the
    cited calls, the trace calls whose rows show it with the act; no record
    type and no parser named."""
    cited_txt = ", ".join(f"#{c}" for c in cited) or "none"
    head = (f"{ctx.tier} finding credits {who} with {what}, but no call it cites prints {who} in a row with "
            f"another term of the claim (cited: {cited_txt}). A person or account credited with an act must "
            "stand in a row of a call the finding cites, beside the act's object, host or time. ")
    if others:
        tail = (f"Calls in the trace whose rows show that: {', '.join(f'#{c}' for c in others)}. Cite the one "
                f"whose rows tie {who} to the act (input_call_ids), or record the finding as SUSPECTED.")
    else:
        tail = (f"No call in the trace prints {who} beside another term of the claim yet: read the records "
                "that tie it to the act and cite that call, or record the finding as SUSPECTED.")
    return {"success": False, "error": head + tail + (f" {hint}" if hint else ""),
            "description": ctx.description, "confidence": ctx.confidence, "gate": gate}
