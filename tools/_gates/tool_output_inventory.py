"""Gate: a statement that inventories a tool's output is not a finding.

"Amcache.hve parsed: 292 file entries, 97 shortcuts, 351 drive binaries"
and "Security.evtx parsed for the window: 7,137 total records, 1,622 in
window" say what a parser produced, not what happened in the case.
Recorded as findings they reach the claim graph, the report and any
grader as conclusions; the report audit says afterwards that such
statements are not findings, but only once they exist. The record-time
gates judged citations and tiers, never whether the statement was a
conclusion at all.

A finding says what happened, to whom or by whom, with which artifact,
when. The shape held here, and only the shape: a parse clause whose
object is a list of counts after a colon ("<artifact> parsed: N a, M b"),
within one sentence. A conclusion that quotes counts on its way to what
they show - "Security.evtx parsed for the window shows 95 failed logons
from 194.61.24.102" - has no such list and is not held, nor is a clause
whose subject did the processing ("the ransomware processed the share:
12,000 files encrypted and 3 ransom notes dropped"). Precision first: the rule reads
English and German parse verbs and a colon-separated list, and a tally
written any other way passes; a false refusal here would send a
conclusion to a note, which is the worse error. The refusal names the
tally and says where each part goes: the inventory to
misc.record_agent_message, the conclusion it supports to a finding of its
own.
"""
from __future__ import annotations

import re
from typing import Optional

GATE = "tool_output_inventory"

# A count: digits with thousands separators, not part of an address, a
# version, a path or a time (no letter, dot, colon, slash or dash on either
# side).
_NUM = r"(?<![\w.:/-])\d[\d,]*(?:\.\d+)?(?![\w.:/-])"
# A counted item: the count, at most two qualifying words, the category.
_ITEM = _NUM + r"\s+(?:[A-Za-z.$][\w.$-]*\s+){0,2}?[A-Za-z][\w-]*"
# A parse verb, then within the same sentence a colon and two or more
# items separated by commas, semicolons or "and" (a parenthesis such as an
# event id may follow an item).
_LIST_RE = re.compile(
    r"(?i)\b(?:parsed|parsing|processed|ingested|indexed|"
    r"geparst|ausgewertet|verarbeitet|eingelesen)\b"
    r"(?:[^.:;!?]|\.(?!\s)){0,120}:\s*"
    r"(" + _ITEM + r"(?:\s*(?:\([^)]*\))?\s*(?:,|;|and|und)\s*(?:of\s+which\s+)?"
    + _ITEM + r")+)")
# The items as the statement wrote them, for the refusal: the qualifiers
# taken greedily, since a comma or a conjunction ends an item anyway.
_ITEM_RE = re.compile(
    _NUM + r"\s+(?:(?!(?:and|und|of)\b)[A-Za-z.$][\w.$-]*\s+){0,2}"
    r"(?!(?:and|und|of)\b)[A-Za-z][\w-]*")
_SENTENCE_STOP_RE = re.compile(r"[.;!?](?:\s|$)")
# A clause whose subject did the processing ("the ransomware processed the
# share: 12,000 files encrypted") describes an act, not a parser's output.
# Only adversary words: "user", "account", "process" and a tool's ".exe"
# sit in ordinary inventory subjects ("NTUSER.DAT for user jdoe parsed:
# ...", "PECmd.exe processed the Prefetch folder: ...").
_ACTOR_RE = re.compile(
    r"(?i)\b(?:attacker|adversary|intruder|threat\s+actor|actor|malware|ransomware|"
    r"trojan|implant|beacon|suspect|operator)\b")


def tally(statement: str) -> list[str]:
    """The counted items of a statement that inventories a tool's output,
    in the statement's own words; empty when the statement is not such an
    inventory."""
    text = " ".join(str(statement or "").split())
    if not text:
        return []
    m = _LIST_RE.search(text)
    if not m:
        return []
    # The clause's subject: from the sentence start to the parse verb.
    starts = [x.end() for x in _SENTENCE_STOP_RE.finditer(text[:m.start()])]
    clause_start = starts[-1] if starts else 0
    if _ACTOR_RE.search(text[clause_start:m.start()]):
        return []
    # The items as the statement wrote them, to the end of the sentence.
    region = text[m.start(1):]
    stop = _SENTENCE_STOP_RE.search(region)
    if stop:
        region = region[:stop.start()]
    return _ITEM_RE.findall(region)


def check(ctx) -> Optional[dict]:
    counts = tally(ctx.description)
    if not counts:
        return None
    listed = ", ".join(counts[:4]) + (", ..." if len(counts) > 4 else "")
    return {
        "success": False,
        "error": (
            f"{GATE}: this statement inventories what a tool produced "
            f"({listed}) rather than stating what happened in the case. A "
            "finding says what happened, to whom or by whom, with which "
            "artifact, when; a count of parsed rows says none of that. Record "
            "the inventory as a note with misc.record_agent_message (it stays "
            "out of the findings and the report), then record as a finding only "
            "the conclusion the parse supports - which program ran, which "
            "account acted, what the counts show - citing the same calls."),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": GATE,
        "counts": counts[:8],
    }
