"""When a finding's citation supports it - one answer for every reader.

The record-time advisory (tools.misc), the report gate (tools.reasoning)
and the duplicate guard that decides whether a re-record is a repair all
ask the same question of a finding and the calls it cites, so they ask it
here. Trace entries are immutable: the only way a recorded finding's
citations can change is a re-record, so every reader of a citation must
agree on what "supports" means or a finding is accepted by one and then
blocked by another with no way back.

A positive claim is supported when the cited evidence shows an identifier
the claim rests on (core.evidence_resolver anchors: a date, an address, an
account, a file, an event id). Only what a forensic tool produced counts as
the cited evidence: a call carrying the analyst's own words - the finding's
own record call, a reasoning step, a claim snapshot - restates the claim and
would let it support itself (core.forensic_citation.own_words_entry), and an
outside lookup echoes the value it was asked about, so it never shows that
the value was present (core.forensic_citation.citation_class).

An absence claim rests on the search that would have found what it says is
missing, and its identifiers are exactly what that search did not print.
Demanding them in the output refuses every well-founded negative by
construction. So an absence claim is supported when a cited evidence call
is that search: one the analyst saw whole (universal_from_truncated's
notion of a complete view) and over what the claim is about - the sources
its category requires when it falls in a gated category
(tools._gates._manifests), otherwise a call that shares the claim's scope:
an identifier it names (a date, an address, an event id, a host) or an
artifact it or its supporting evidence names. A claim that names nothing
checkable takes any cited complete evidence call. An absence claim whose
cited calls are all cut short, or carry no evidence output at all, is
unsupported: "we looked" has to point at a look that could have found it.
A claim of either kind whose cited searches left no recorded output cannot
be judged and is not flagged, as before.
"""
from __future__ import annotations

from typing import Optional

from ._manifests import absence_grounding, searches_of

# How much of a spilled output is read when judging a citation. Table rows
# beyond the trace excerpt live there; the report projection reads the same
# amount (core.evidence_resolver).
SPILL_READ_CHARS = 500_000


def call_output_text(entry: dict) -> str:
    """What a recorded tool call showed: its command line, the stored
    excerpt and the spilled output file, as the tool printed them."""
    from core.entities import scan_text
    parts = [str(entry.get("cmd") or ""),
             scan_text(str(entry.get("stdout_excerpt") or ""))]
    sf = entry.get("stdout_file")
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                parts.append(scan_text(fh.read(SPILL_READ_CHARS)))
        except OSError:
            pass
    return " ".join(parts)


def has_output(entry: dict) -> bool:
    return bool(entry.get("stdout_excerpt") or entry.get("stdout_file"))


def evidence_calls(entries) -> list[dict]:
    """The tool calls among ``entries`` whose output is evidence: neither
    the run's own words nor an outside lookup, whose output echoes the
    value it was asked about (core.forensic_citation.citation_class). A
    lookup grounds what a provider says, which the external-knowledge gate
    judges; that a value was present is shown only by evidence."""
    from core.forensic_citation import citation_class
    return [e for e in entries
            if isinstance(e, dict) and e.get("type") == "tool_call"
            and citation_class(e) == "evidence"]


def cited_ids(finding: dict) -> list[int]:
    """Every call a finding cites, lineage and linked call alike."""
    out: list[int] = []
    for c in list(finding.get("input_call_ids") or []) + [finding.get("linked_call_id")]:
        try:
            ci = int(c)
        except (TypeError, ValueError):
            continue
        if ci and ci not in out:
            out.append(ci)
    return out


def is_absence_claim(statement: str) -> bool:
    """A statement about all rows or about something being absent - the
    one grammar every gate on negatives reads (universal_from_truncated)."""
    from .universal_from_truncated import is_universal_or_negative
    return is_universal_or_negative(statement or "")


def complete_view(entry: dict) -> bool:
    """The analyst saw everything this call returned, and it ran."""
    from .universal_from_truncated import incomplete_reason
    return entry.get("success") is not False and not incomplete_reason(entry)


def absence_searches(statement: str, evidence: list[dict], *, tool_calls: list[dict],
                     supporting_evidence: str = "") -> list[dict]:
    """The calls among the cited ``evidence`` that ground ``statement`` as
    an absence claim: complete views that searched the sources its category
    requires, or - outside the gated categories - complete views that share
    the claim's scope (an identifier or an artifact the claim or its
    supporting evidence names; any complete view when it names none). Empty
    when the statement is not an absence claim."""
    if not is_absence_claim(statement):
        return []
    complete = [e for e in evidence if has_output(e) and complete_view(e)]
    grounding = absence_grounding(statement, supporting_evidence, tool_calls)
    if grounding:
        return searches_of(grounding, complete)
    from core.entities import artifact_tokens
    from core.evidence_resolver import _claim_anchors, _shares_anchor
    from .lineage_relevance import entry_text
    described = artifact_tokens(f"{statement or ''} {supporting_evidence or ''}")
    anchors = _claim_anchors({"statement": statement or "",
                              "reasoning": supporting_evidence or ""})
    if not described and not anchors:
        return complete
    return [e for e in complete
            if (described & artifact_tokens(entry_text(e)))
            or _shares_anchor(call_output_text(e), anchors)]


def citation_supports(statement: str, cited: list[dict], *, tool_calls: list[dict],
                      supporting_evidence: str = "") -> Optional[bool]:
    """Whether the cited calls support ``statement``.

    True when the cited evidence shows one of the statement's identifiers.
    For an absence claim, True when a cited evidence call is the complete
    search that grounds it (absence_searches); False when its cited calls
    are cut short, about something else, or not evidence at all; None when
    the searches it cites left no recorded output to judge against. For a
    positive claim, True when it names nothing a citation could be asked
    for, None when its cited calls left no output, False otherwise; a
    claim citing only outside lookups is False, their output being the
    value they were asked about.
    """
    from core.evidence_resolver import _claim_anchors, _shares_anchor
    evidence = evidence_calls(cited)
    shown = [e for e in evidence if has_output(e)]
    node = {"statement": statement or ""}
    if shown and _shares_anchor(" ".join(call_output_text(e) for e in shown),
                                _claim_anchors(node)):
        return True
    if is_absence_claim(statement):
        # An absence demands its search, whether or not the claim names
        # identifiers. One whose citations are all the run's own words rests
        # on itself; one whose cited searches left no recorded output, or
        # that cites nothing at all, cannot be judged here, as for any claim.
        if absence_searches(statement, shown, tool_calls=tool_calls,
                            supporting_evidence=supporting_evidence):
            return True
        if not cited:
            return None      # nothing cited: lineage_required's question, not this one
        if not evidence:
            return False     # only the run's own words cited: no search behind it
        return None if not shown else False
    if not shown:
        # Lookups printed output, all of it restating what they were asked:
        # the claim's identifiers are unshown, not unjudgeable.
        from core.forensic_citation import external_lookup_entry
        if (any(external_lookup_entry(e) and has_output(e) for e in cited)
                and _claim_anchors(node, demanding=True)):
            return False
        return None
    if not _claim_anchors(node, demanding=True):
        return True
    return False


def calls_showing(statement: str, tool_calls: list[dict], *, exclude=(),
                  complete_only: bool = False, limit: int = 3,
                  supporting_evidence: str = "") -> list[dict]:
    """The calls in the trace that would support ``statement`` if cited,
    each ``{"call_id", "why"}``: for an absence claim the searches of its
    sources first, then for any claim the calls whose output shows its
    identifiers, newest first within each group. With ``complete_only`` a
    call the analyst saw only part of is left out - a universal or negative
    statement cannot rest on it (universal_from_truncated), so suggesting
    it sends the analyst into that refusal.
    """
    from core.entities import artifact_tokens
    from core.evidence_resolver import _claim_anchors
    from .lineage_relevance import entry_text
    skip = {int(c) for c in exclude if c is not None}
    pool = [e for e in evidence_calls(tool_calls[-300:])
            if e.get("success") is not False and has_output(e)
            and int(e.get("call_id") or 0) not in skip
            and not (complete_only and not complete_view(e))]
    out: list[dict] = []
    seen: set[int] = set()

    def _add(e: dict, why: str) -> bool:
        cid = int(e.get("call_id") or 0)
        if cid in seen:
            return False
        seen.add(cid)
        out.append({"call_id": cid, "why": why})
        return len(out) >= limit

    if is_absence_claim(statement):
        grounding = absence_grounding(statement, supporting_evidence, tool_calls)
        if grounding:
            what = grounding["category"].lower().replace("_", "/")
            for e in reversed(searches_of(grounding, pool)):
                if _add(e, f"searched the {what} sources"):
                    return out
        described = artifact_tokens(f"{statement} {supporting_evidence or ''}")
        if described:
            for e in reversed(pool):
                shared = described & artifact_tokens(entry_text(e))
                if shared and _add(e, "read " + ", ".join(sorted(shared)[:3])):
                    return out
    anchors = _claim_anchors({"statement": statement or ""})
    if not anchors:
        return out
    for e in reversed(pool):
        low = call_output_text(e).lower()
        shared = sorted(a for a in anchors if a in low)
        if shared and _add(e, "shows " + ", ".join(shared[:5])):
            break
    return out
