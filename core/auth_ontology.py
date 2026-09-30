"""Platform → abstract authentication event ontology.

Platform event IDs (Windows 4624/4625, SSH Accepted/Failed) are *adapters*
that classify log text / tabular columns into abstract classes
``auth.success`` / ``auth.failure``. They are not case IOCs and must not
encode engagement facts (IPs, usernames, hostnames, product case names).

Executable layers (Claim Graph polarity, LOGON manifests, attribution gates,
reasoning logon inventory, DAIR principal cues, critical-scan detection)
import markers from here so Windows EID strings are not copy-pasted.
"""
from __future__ import annotations

import re
from typing import Pattern

EVENT_AUTH_SUCCESS = "auth.success"
EVENT_AUTH_FAILURE = "auth.failure"

# ── Windows platform adapter ─────────────────────────────────────────────────

WINDOWS_AUTH_SUCCESS_EIDS = ("4624", "4778")
WINDOWS_AUTH_FAILURE_EIDS = ("4625",)
# RDP reconnect / disconnect (interactive session presence).
WINDOWS_RDP_SESSION_EIDS = ("4778", "4779")
# Session / RDP reconnect presence (not success/failure classification alone).
WINDOWS_SESSION_EIDS = (
    WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS + ("4779",)
)
# Broader auth-related EIDs used by critical-scan / evidence component detection.
WINDOWS_AUTH_RELATED_EIDS = WINDOWS_SESSION_EIDS + ("4648", "4723", "4776")
# Kerberos pre-auth failures commonly used as spray/brute markers.
WINDOWS_AUTH_BRUTE_EIDS = ("4776",)

# The same events under the numbering Windows NT 4.0 through Server 2003
# (and XP) used, before the EVTX format renumbered them by adding 4096:
# 528 interactive and 540 network logon, 682 session reconnect; 529 to 537
# and 539 the logon failures. A legacy Security log is searched by these.
WINDOWS_LEGACY_AUTH_SUCCESS_EIDS = ("528", "540", "682")
WINDOWS_LEGACY_AUTH_FAILURE_EIDS = (
    "529", "530", "531", "532", "533", "534", "535", "536", "537", "539")
WINDOWS_LEGACY_SESSION_EIDS = ("682", "683")


def eid_alt(eids: tuple[str, ...]) -> str:
    return "|".join(re.escape(e) for e in eids)


def windows_auth_eids_prose(
    eids: tuple[str, ...] | None = None,
    *,
    sep: str = "/",
) -> str:
    """Human-facing EID list derived from ontology (no duplicated literals)."""
    return sep.join(eids or (WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS))


def windows_session_eids_prose(*, sep: str = "/") -> str:
    return sep.join(WINDOWS_SESSION_EIDS)


_AUTH_SUCCESS_STRONG = re.compile(
    r"(?:AUDIT_SUCCESS"
    r"|Accepted\s+(?:password|publickey|keyboard-interactive)"
    r"|authentication\s+success"
    r"|successful(?:ly)?\s+(?:remote\s+)?(?:logon|log[\s-]?on|authenticat)"
    r"|logon\s+success)",
    re.IGNORECASE,
)

_AUTH_SUCCESS_EID = re.compile(
    rf"\b(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS)})\b"
)

_AUTH_CTX = re.compile(
    r"(?:logon|log-?on|logoff|\beid\b|event\s?_?id|account|username"
    r"|target[\s_]?user|ntlm|kerberos|\bsecurity\b|credential|\bS-1-5"
    r"|logon\s?type|authentic)",
    re.IGNORECASE,
)

_AUTH_FAILURE = re.compile(
    rf"(?:\b(?:{eid_alt(WINDOWS_AUTH_FAILURE_EIDS)})\b|AUDIT_FAILURE|"
    r"Failed\s+password|authentication\s+failure"
    r"|logon\s+failure|0xC0000064|0xC000006A|0xC000006D|0xC0000234"
    r"|wrong\s+pw|invalid\s+(?:user|password))",
    re.IGNORECASE,
)

_CLAIM_AUTH_SUCCESS = re.compile(
    r"\b(?:\d+\s+)?successful\s+(?:network\s+)?logons?\b"
    r"|\b(?:successful|succeeded)\s+(?:network\s+)?(?:logon|login|authentication)\b"
    rf"|\bEID\s*(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS)})\b"
    rf"|\b\d+\s+successful\b.*\b(?:logons?|{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS)})\b",
    re.IGNORECASE | re.DOTALL,
)

_CLAIM_AUTH_NONE = re.compile(
    r"\bno\s+(?:evidence\s+of\s+)?(?:successful\s+)?(?:logon|login|authentication|auth)\b"
    r"|\b(?:no|without)\s+successful\s+(?:external\s+)?(?:authentication|logon|login)\b"
    r"|\bfailed\s+entirely\b.*\b(?:logon|auth)\b"
    r"|\bprobed\s+only\b.*\bno\s+(?:evidence\s+of\s+)?successful",
    re.IGNORECASE | re.DOTALL,
)

_SUCCESS_FRAMING = re.compile(
    r"\b(?:successful(?:ly)?|authenticated|valid(?:ated)?\s+(?:account|cred)"
    r"|logged\s+(?:on|in)|gain(?:ed|s)?\s+access|access\s+granted"
    r"|interactive\s+logon|established\s+(?:a\s+)?session|signed\s+in"
    r"|compromis|foothold|obtained\s+access)",
    re.IGNORECASE,
)

_NEG_WORD = re.compile(
    r"\b(?:no|not|never|without|failed|unsuccessful|denied|rejected|"
    r"attempted|unable)\b",
    re.IGNORECASE,
)

_SESSION_SEARCH_CMD = re.compile(
    rf"security\.evtx|security_logons|\b(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS)})\b",
    re.IGNORECASE,
)

# Evidence text that grounds account→person attribution (gates).
_SESSION_EVIDENCE = re.compile(
    rf"(?:\blogon\b|\blog-on\b|\b(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS)})\b"
    r"|\blogon type\s*\d+"
    r"|\btype\s*(?:3|10)\b|\binteractive session\b|\bremote session\b|\brdp\b"
    r"|\bsmb session\b|\bsshd\b|\bssh session\b|\bkerberos\b|\bntlm\b"
    r"|\bsource (?:network )?address\b|\bsource ip\b|\boriginating ip\b"
    r"|\bx-originating-ip\b|\binternetname\b|\bcert(?:ificate)? cn\b"
    r"|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
    re.IGNORECASE,
)

# chainsaw reads event logs, except when misc.mft_rule_hunt runs it over an
# $MFT: that command writes mft_rule_hunt_*.jsonl and reads no event log.
# Every classifier of executed command lines uses this, not the bare word.
CHAINSAW_EVTX = r"chainsaw(?!.*\bmft_rule_hunt_)"

# Tool cmds that count as logon/session inventory (reasoning pre_report).
_LOGON_INVENTORY_CMD = re.compile(
    rf"(?:evtxecmd|{CHAINSAW_EVTX}"
    rf"|\b(?:{eid_alt(WINDOWS_SESSION_EIDS)})\b"
    r"|\blast\b|wtmp|utmp|lastlog|\bwho\b)",
    re.IGNORECASE,
)

# Critical auth/session scan detection (timeout debt).
_CRITICAL_AUTH_SCAN = re.compile(
    rf"(?:\bevtxecmd\b|"
    r"chainsaw_hunt|ez\.evtxecmd|ez_evtxecmd|"
    r"(?:^|[\s\"'/])hayabusa(?:-[\w.]+)?(?:\s|$)|"
    rf"\b(?:{eid_alt(WINDOWS_AUTH_RELATED_EIDS)})\b)",
    re.IGNORECASE,
)

# Plan/discriminator phrase → ez.evtxecmd.
_AUTH_TOOL_HINT = re.compile(
    rf"logon type|logon source|\b(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS)})\b|"
    r"interactive logon|source address",
    re.IGNORECASE,
)

# DAIR principal-cue fragments (EID/session portion only).
_PRINCIPAL_INTERACTIVE_AUTH_CUE = re.compile(
    rf"(?:\b(?:{eid_alt(WINDOWS_RDP_SESSION_EIDS)})\b"
    r"|\brdp\b|\bremote desktop\b|\bterminal services\b"
    r"|\blogon type\s*(?:2|10)\b|\btype\s*(?:2|10)\b"
    r"|\binteractive logon\b|\brdp session from\b"
    r"|\blogged ?in\b|\bauthenticated\b|\bsigned ?in\b)",
    re.IGNORECASE,
)

_PRINCIPAL_APPEARANCE_CUE = re.compile(
    rf"(?:\b(?:{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS[:1] + WINDOWS_AUTH_FAILURE_EIDS)})\b"
    r"|\blogon type\s*3\b|\btype\s*3\b"
    r"|\bnew (?:correspondent|sender|recipient|account name)\b"
    r"|\bfirst (?:appears|seen|observed)\b"
    r"|\bpreviously[- ]unseen\b|\bunfamiliar (?:account|user|identity)\b)",
    re.IGNORECASE,
)

# CASE intent language that implies Windows session auth obligations.
_CASE_SESSION_AUTH_INTENT = re.compile(
    rf"(?i)\b(?:"
    r"logon|login|session|vpn|lateral|"
    r"controller|authenticat|rdp|smb|winevt|security\.evtx|"
    r"terminal\s*services|"
    rf"{eid_alt(WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS)}"
    r")\b"
)


def auth_success_strong_re() -> Pattern[str]:
    return _AUTH_SUCCESS_STRONG


def auth_success_eid_re() -> Pattern[str]:
    return _AUTH_SUCCESS_EID


def auth_context_re() -> Pattern[str]:
    return _AUTH_CTX


def auth_failure_re() -> Pattern[str]:
    return _AUTH_FAILURE


def claim_auth_success_regex() -> Pattern[str]:
    return _CLAIM_AUTH_SUCCESS


def claim_auth_none_regex() -> Pattern[str]:
    return _CLAIM_AUTH_NONE


def session_search_cmd_regex() -> Pattern[str]:
    """Regex matching tool cmds that touch Windows Security auth events."""
    return _SESSION_SEARCH_CMD


def session_evidence_regex() -> Pattern[str]:
    """Evidence markers that ground principal/session attribution."""
    return _SESSION_EVIDENCE


def logon_inventory_cmd_regex() -> Pattern[str]:
    """Trace cmds that count as a logon/session inventory."""
    return _LOGON_INVENTORY_CMD


def critical_auth_scan_regex() -> Pattern[str]:
    """Critical auth/session scan tool/cmd detection."""
    return _CRITICAL_AUTH_SCAN


def auth_tool_hint_regex() -> Pattern[str]:
    """Discriminator prose that should suggest ez.evtxecmd."""
    return _AUTH_TOOL_HINT


def principal_interactive_auth_cue_regex() -> Pattern[str]:
    return _PRINCIPAL_INTERACTIVE_AUTH_CUE


def principal_appearance_cue_regex() -> Pattern[str]:
    return _PRINCIPAL_APPEARANCE_CUE


def case_session_auth_intent_regex() -> Pattern[str]:
    return _CASE_SESSION_AUTH_INTENT


def classify_windows_eid(eid: str | int | None) -> str | None:
    """Map a Windows Event ID to auth.success / auth.failure, or None."""
    if eid is None:
        return None
    s = str(eid).strip()
    if s in WINDOWS_AUTH_SUCCESS_EIDS:
        return EVENT_AUTH_SUCCESS
    if s in WINDOWS_AUTH_FAILURE_EIDS:
        return EVENT_AUTH_FAILURE
    return None


def positively_frames_success(desc: str) -> bool:
    """True when prose asserts successful access without a nearby negation."""
    for m in _SUCCESS_FRAMING.finditer(desc or ""):
        pre = (desc or "")[max(0, m.start() - 24):m.start()]
        if not _NEG_WORD.search(pre):
            return True
    return False
