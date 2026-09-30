"""Extract structured auth events from tool output using auth_ontology.

Produces platform-agnostic AuthEvent records (auth.success / auth.failure)
with endpoints and dates taken from the evidence text — never from hardcoded
engagement IOCs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from core.auth_ontology import (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    auth_context_re,
    auth_failure_re,
    auth_success_eid_re,
    auth_success_strong_re,
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# No trailing \b — ISO timestamps have no boundary between day and "T".
_EVENT_DATE_RE = re.compile(r"(?<!\d)(\d{4})[-/](\d{2})[-/](\d{2})")
_LOGON_TYPE_RE = re.compile(
    r"logon[\s_]?type[\"'\s:=]{0,4}(\d{1,2})", re.IGNORECASE
)

_WINDOW = 160


@dataclass(frozen=True)
class AuthEvent:
    event_class: str
    source_endpoint: str
    when: str  # YYYY-MM-DD or ""
    auth_factor: str  # e.g. Windows logon type, or ""
    platform: str
    source_call_id: Optional[int]
    tool: str
    snippet: str

    def fingerprint(self) -> str:
        """Identity of the *observation*: class, endpoint, day, factor.

        The call that happened to see the event is provenance, not
        identity. With ``source_call_id`` in here, every re-parse of the
        same log would mint a fresh CONFIRMED observation, and dozens of
        near-identical "Successful authentication from <ip>" nodes would
        drown the real findings.
        """
        return "|".join((
            self.event_class,
            self.source_endpoint,
            self.when,
            self.auth_factor,
        ))


def is_ignorable_endpoint(endpoint: str) -> bool:
    if not endpoint:
        return True
    if endpoint.startswith("127."):
        return True
    return endpoint in {"0.0.0.0", "255.255.255.255"}


def _nearest(rx: re.Pattern, text: str, anchor: int) -> Optional[int]:
    best = None
    for m in rx.finditer(text):
        d = min(abs(m.start() - anchor), abs(m.end() - anchor))
        if best is None or d < best:
            best = d
    return best


def _classify_window(win: str, anchor: int) -> Optional[tuple[str, str]]:
    """Return (event_class, platform) for a proximity window, or None."""
    strong = auth_success_strong_re()
    eid = auth_success_eid_re()
    ctx = auth_context_re()
    fail = auth_failure_re()

    s = _nearest(strong, win, anchor)
    if s is None and ctx.search(win):
        s = _nearest(eid, win, anchor)
    f = _nearest(fail, win, anchor)

    if s is not None and (f is None or s <= f):
        platform = "linux_ssh" if re.search(
            r"(?i)Accepted\s+(?:password|publickey)", win
        ) else "windows"
        return EVENT_AUTH_SUCCESS, platform
    if f is not None and (s is None or f < s):
        platform = "linux_ssh" if re.search(r"(?i)Failed\s+password", win) else "windows"
        return EVENT_AUTH_FAILURE, platform
    return None


def extract_auth_events_from_text(
    text: str,
    *,
    call_id: Optional[int] = None,
    tool: str = "",
) -> list[AuthEvent]:
    """Extract distinct auth events from a blob of tool output."""
    if not (text or "").strip():
        return []
    out: dict[str, AuthEvent] = {}
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        if is_ignorable_endpoint(ip):
            continue
        idx = m.start()
        lo = max(0, idx - _WINDOW)
        win = text[lo:idx + _WINDOW]
        anchor = idx - lo
        classified = _classify_window(win, anchor)
        if not classified:
            continue
        event_class, platform = classified
        dm = _EVENT_DATE_RE.search(win)
        when = (
            f"{dm.group(1)}-{dm.group(2)}-{dm.group(3)}" if dm else ""
        )
        lt = _LOGON_TYPE_RE.search(win)
        factor = lt.group(1) if lt else ""
        ev = AuthEvent(
            event_class=event_class,
            source_endpoint=ip,
            when=when,
            auth_factor=factor,
            platform=platform,
            source_call_id=call_id,
            tool=tool,
            snippet=win.strip()[:200],
        )
        out[ev.fingerprint()] = ev
    return list(out.values())


def extract_auth_events_from_texts(
    texts: Iterable[tuple],
) -> list[AuthEvent]:
    """texts: iterable of (call_id, tool_label, text)."""
    merged: dict[str, AuthEvent] = {}
    for call_id, label, text in texts:
        for ev in extract_auth_events_from_text(
            text, call_id=call_id, tool=str(label or ""),
        ):
            merged[ev.fingerprint()] = ev
    return list(merged.values())
