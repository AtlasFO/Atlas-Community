"""Gate: a value not found is never a verdict that a system is clean.

Principle (case-independent)
---------------------------
A search that did not find an indicator says what the searched outputs do
not hold. It says nothing about what was never searched, what the attacker
removed, or what never matched the value's form. A finding that turns the
miss into a verdict ("the IOC was not found, the host is clean") states
more than any search can show, at any tier. The search belongs in a
disposition note that names what was searched and where; the verdict stays
out of the record.

The check needs both halves in one finding: an absence (not found, no hits,
did not appear) and a system verdict (clean, not compromised, no evidence
of compromise). A negative about a hypothesis ("lateral movement via RDP
was ruled out") is the completeness gates' question, not this one.
"""
from __future__ import annotations

import re
from typing import Optional

_ABSENCE = re.compile(
    r"\b(?:not\s+(?:been\s+)?(?:found|present|observed|seen|detected|matched)"
    r"|no\s+(?:hits?|matches|match|occurrences?|sign|trace)\b"
    r"|did\s+not\s+(?:appear|match|occur|show)"
    r"|(?:is|was|were|are)\s+absent|zero\s+(?:hits?|matches))",
    re.IGNORECASE)
_VERDICT = re.compile(
    r"\b(?:(?:is|was|are|were|remains?|appears?|looks?)\s+(?:to\s+be\s+)?clean"
    r"|not\s+(?:been\s+)?compromised|no\s+compromise|uncompromised"
    r"|not\s+(?:been\s+)?infected|no\s+infection"
    r"|no\s+evidence\s+of\s+(?:a\s+)?(?:compromise|infection|intrusion))\b",
    re.IGNORECASE)


# A verdict the finding itself denies in the same clause ("this does not
# establish that the host is clean") is a caveat, not a verdict.
_DENIED = re.compile(r"(?i)\b(?:not|never|cannot|can't|nor|without|rather than|no basis)\b[^.;:]{0,60}$")


def _states_verdict(desc: str) -> bool:
    return any(not _DENIED.search(desc[max(0, m.start() - 80):m.start()])
               for m in _VERDICT.finditer(desc))


def check(ctx) -> Optional[dict]:
    desc = ctx.description or ""
    if not (_ABSENCE.search(desc) and _states_verdict(desc)):
        return None
    return {
        "gate": "indicator_absence",
        "success": False,
        "error": (
            "[indicator_absence] A value that was not found says what the searched outputs "
            "do not hold, never that the system is clean. Record the search as a disposition "
            "note (misc.record_agent_message with disposition=True) naming what was searched "
            "and where, and keep the verdict out of the finding; a finding states what the "
            "evidence shows."
        ),
        "detail_gate": "indicator_absence",
    }
