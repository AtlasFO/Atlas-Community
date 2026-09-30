"""Shared filters for tool banners / metadata that must not enter timelines.

Used by evidence resolution and Attack Timeline curation so version lines,
usage banners, and empty progress noise never become curated events.
"""
from __future__ import annotations

import re

# Tool version / usage / copyright banners that appear as L1 of dumps.
_TOOL_BANNER_RE = re.compile(
    r"(?i)^(?:"
    r"(?:EvtxECmd|Hayabusa|Chainsaw|PECmd|MFTECmd|LECmd|JLECmd|AmcacheParser|"
    r"AppCompatCacheParser|SBECmd|RECmd|WxTCmd|SumECmd|SrumECmd|"
    r"TimelineExplorer|ZimmermanTools)\s+version\b"
    r"|Usage:\s*"
    r"|Copyright\b"
    r"|Press\s+(?:CTRL|Ctrl)\+C\b"
    r"|\[\+\]\s+(?:Processing|Loading|Writing)\b"
    r"|Starting\s+(?:Hayabusa|Chainsaw|EvtxECmd)\b"
    r")"
)

# Lines that are clearly not forensic events (scout agent chatter without IOC).
_NON_EVENT_LINE_RE = re.compile(
    r"(?i)^(?:"
    r"File:\s*/"  # strings.stat / file path headers alone
    r"|git[0-9a-f]{6,}\b"  # bare git hashes from agent banners
    r"|waitRequestPerformed:\s*"
    r"|gai_suspend\s+rc="
    r"|The passed certificate is self-signed"
    r"|ReadApplications:\s*Loaded application"
    r"|uc::setting::ClientImpl::onSignal:"
    r")"
)


def is_tool_metadata_text(text: str) -> bool:
    """True if *text* is tool banner / metadata, not a forensic event."""
    if not text or not str(text).strip():
        return True
    first = ""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if not first:
        return True
    if _TOOL_BANNER_RE.search(first):
        return True
    # Entire blob is only a version/banner line
    if len(str(text).strip().splitlines()) <= 2 and _TOOL_BANNER_RE.search(
            str(text).strip()):
        return True
    return False


def is_weak_timeline_event_text(text: str) -> bool:
    """True if text should not appear as a curated Attack Timeline Event."""
    if is_tool_metadata_text(text):
        return True
    first = ""
    for line in str(text or "").splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if not first:
        return True
    if _NON_EVENT_LINE_RE.search(first):
        return True
    # Extremely short / non-descriptive fragments (e.g. "1,-1)", "E1E")
    compact = re.sub(r"\s+", "", first)
    if len(compact) < 8 and not re.search(r"\d{4}-\d{2}-\d{2}", first):
        return True
    return False


_GAP_STATEMENT_RE = re.compile(
    r"(?i)\b(?:"
    r"evidence\s+gap|absent\s+from\s+the\s+evidence|prevent(?:s|ing)?\s+"
    r"determination|missing\s+(?:categories|artifacts|hives?|logs?)|"
    r"not\s+available\s+in\s+(?:the\s+)?evidence|cannot\s+determine|"
    r"no\s+(?:disk\s+images?|registry\s+hives?|NTUSER|SAM\s+hive)"
    r")\b"
)

_EMPTY_GAPS_PROSE_RE = re.compile(
    r"(?i)(?:"
    r"no\s+formal\s+conclusions"
    r"|claims?\s+(?:list\s+)?(?:is|are)\s+empty"
    r"|absence\s+of\s+registered\s+findings"
    r"|no\s+findings\s+have\s+been\s+registered"
    r"|empty\s+finding\s+state"
    r"|no\s+attack\s+timeline\s+has\s+been\s+constructed"
    r"|no\s+user\s+accounts[^\n]{0,40}have\s+been\s+associated"
    r")"
)


def looks_like_evidence_gap_statement(statement: str) -> bool:
    return bool(_GAP_STATEMENT_RE.search(statement or ""))


# Process / hypothesis diary that must not dominate Key Findings.
_PROCESS_META_RE = re.compile(
    r"(?i)\b(?:"
    r"coverage[- ]ledger|hypothesis\s+h\d+|disposition(?:ed)?\s+h\d+|"
    r"not found in the available reasoning|"
    r"controller-of-record disposition|"
    r"unresolvable:\s*evidence/|"
    r"i will (?:either )?probe|document(?:ed)? as unconfirmed to disposition"
    r")\b"
)


def looks_like_process_or_hypothesis_note(statement: str) -> bool:
    """True for investigation-process / hypothesis diary, not evidence claims."""
    return bool(_PROCESS_META_RE.search(statement or ""))


def claim_report_role(statement: str) -> str:
    """``evidence`` | ``gap`` | ``process`` — report projection role."""
    text = statement or ""
    if looks_like_process_or_hypothesis_note(text):
        return "process"
    if looks_like_evidence_gap_statement(text):
        return "gap"
    return "evidence"


def is_contradictory_empty_gaps_prose(prose: str, *, finding_count: int) -> bool:
    """LLM Gaps prose that denies findings while findings exist."""
    if finding_count <= 0 or not (prose or "").strip():
        return False
    return bool(_EMPTY_GAPS_PROSE_RE.search(prose))
