"""Where a Windows installation keeps its event logs, per layout generation.

Windows Vista and later write EVTX channels under Windows/System32/winevt/Logs
and are read by EvtxECmd, Chainsaw or Hayabusa. Windows NT 4.0 through
Server 2003 and XP write three .Evt logs (Application, Security, System)
under WINDOWS/system32/config, in a format only a libevt-based exporter
reads; those systems have no TerminalServices channels, remote sessions are
Security events under the pre-Vista numbering.

Every place that demands "search the Windows event log", checks whether such
a search happened, or names where the log lives takes its words and its
pattern from this one table. The demand and its acceptance test therefore
cannot drift apart, and a requirement is only ever made of a layout the
evidence has shown to exist: a trace that lists the legacy logs is asked for
a legacy search, one that lists winevt/Logs for an EVTX search, and one
that has shown neither is asked for nothing that cannot be satisfied.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from core.auth_ontology import (
    CHAINSAW_EVTX,
    WINDOWS_AUTH_FAILURE_EIDS,
    WINDOWS_AUTH_SUCCESS_EIDS,
    WINDOWS_LEGACY_AUTH_FAILURE_EIDS,
    WINDOWS_LEGACY_AUTH_SUCCESS_EIDS,
    eid_alt,
)


@dataclass(frozen=True)
class EventLogLayout:
    name: str                  # short id used in trace notes
    windows: str               # which Windows generations use it
    log_dir: str               # where the logs live inside the system volume
    security_log: str          # the log that records logons
    session_logs: tuple[str, ...]   # further channels that record sessions
    parsers: tuple[str, ...]        # tool aliases that read this layout
    # Regex fragments. ``evidence`` matches text a successful call printed
    # (a directory listing, a resolved path) when the layout exists on the
    # media; ``search`` matches a command, argument or tool name when the
    # layout was searched or parsed.
    evidence: str
    search: str
    # A read of this layout's Security log in particular: the log's name or
    # the programs that parse it. Logon event ids are added when compiled.
    security_search: str
    logon_eids: tuple[str, ...]     # event ids a logon search of this layout names

    @property
    def location(self) -> str:
        return f"{self.log_dir}/{self.security_log}"

    def search_regex(self) -> re.Pattern[str]:
        return re.compile(self.search, re.IGNORECASE)

    def evidence_regex(self) -> re.Pattern[str]:
        return re.compile(self.evidence, re.IGNORECASE)

    def security_search_regex(self) -> re.Pattern[str]:
        """A command that read the Security log of this layout, or queried
        its logon events by id."""
        return re.compile(
            rf"{self.security_search}|security_logons|\b(?:{eid_alt(self.logon_eids)})\b",
            re.IGNORECASE,
        )

    def demand(self) -> str:
        """How to search this layout, for a refusal or a work order."""
        extra = (f" and the {', '.join(self.session_logs)} channels"
                 if self.session_logs else "")
        return (f"{self.location}{extra} with tsk.fls -> tsk.icat -> "
                f"{' / '.join(self.parsers)} ({self.windows})")


EVTX = EventLogLayout(
    name="evtx",
    windows="Windows Vista and later",
    log_dir="Windows/System32/winevt/Logs",
    security_log="Security.evtx",
    session_logs=("TerminalServices-LocalSessionManager",
                  "TerminalServices-RemoteConnectionManager"),
    parsers=("ez.evtxecmd", "misc.chainsaw_hunt", "hayabusa.triage"),
    # TerminalServices channels exist only in this layout, so a text that
    # names them presupposes it.
    evidence=r"winevt[\\/]+logs|\.evtx\b|terminalservices",
    # resolve_path is how the Logs directory is reached inside an image and
    # has always counted as an attempt; kept so older traces still qualify.
    search=(r"winevt|security\.evtx|terminalservices|ez_?evtxecmd|evtxecmd|"
            + CHAINSAW_EVTX + r"|hayabusa|resolve_path"),
    security_search=r"security\.evtx|evtxecmd|" + CHAINSAW_EVTX + r"|hayabusa",
    logon_eids=WINDOWS_AUTH_SUCCESS_EIDS + WINDOWS_AUTH_FAILURE_EIDS,
)

EVT = EventLogLayout(
    name="evt",
    windows="Windows NT 4.0 to Server 2003, including XP",
    log_dir="WINDOWS/system32/config",
    security_log="SecEvent.Evt",
    session_logs=(),
    parsers=("evt.evt_export",),
    evidence=r"(?:sec|sys|app)event\.evt\b|\.evt\b",
    search=r"(?:sec|sys|app)event\.evt\b|evt_?export|\.evt\b",
    security_search=r"secevent\.evt|evt_?export",
    logon_eids=WINDOWS_LEGACY_AUTH_SUCCESS_EIDS + WINDOWS_LEGACY_AUTH_FAILURE_EIDS,
)

LAYOUTS: tuple[EventLogLayout, ...] = (EVTX, EVT)

# Fields of a trace entry that hold what a call printed, and the fields that
# hold what it was asked to do. The evidence for a layout is in the former;
# a search of it is in the latter (a failed listing of a path proves the
# path was looked for, not that it exists).
_OUTPUT_KEYS = ("stdout_excerpt", "output", "result", "stdout", "out")
_REQUEST_KEYS = ("cmd", "mcp_tool", "tool", "args", "evidence_ref")


def _own_words(entry: dict) -> bool:
    """A record of the analyst's own words (a note, a disposition, a finding
    echoed back) proves nothing about the media, whatever paths it names."""
    try:
        from core.forensic_citation import own_words_entry
        return bool(own_words_entry(entry))
    except Exception:  # noqa: BLE001
        return False


def _text(entry, keys: tuple[str, ...]) -> str:
    if isinstance(entry, dict):
        return " ".join(str(entry.get(k) or "") for k in keys)
    return str(entry or "")


def layouts_in_evidence(entries: Iterable, *fallback_texts: str
                        ) -> tuple[EventLogLayout, ...]:
    """The layouts the evidence has shown to exist, in table order.

    A layout exists when a call that did not fail printed or was run
    against one of its paths or logs. A failed call is not evidence: a
    refused listing of winevt/Logs says the directory was looked for, not
    that it is there; nor is a record of the analyst's own words. When the
    trace shows no layout, the fallback texts (a claim's own words) decide,
    since a claim about a named log presupposes the layout that holds it.
    Empty when nothing establishes a layout.
    """
    shown: list[str] = []
    for e in entries or []:
        if isinstance(e, dict):
            if e.get("success") is False or e.get("failure_class"):
                continue
            if _own_words(e):
                continue
            # A call that ran against a log without failing consumed a path
            # that exists, so its request is evidence as much as its output.
            shown.append(_text(e, _OUTPUT_KEYS + _REQUEST_KEYS))
        else:
            shown.append(str(e or ""))
    printed = " ".join(shown)
    found = tuple(l for l in LAYOUTS if l.evidence_regex().search(printed))
    if found:
        return found
    spoken = " ".join(t or "" for t in fallback_texts)
    return tuple(l for l in LAYOUTS if l.evidence_regex().search(spoken))


def search_attempted(entries: Iterable,
                     layouts: Iterable[EventLogLayout] = LAYOUTS) -> bool:
    """True when any call in ``entries`` searched one of ``layouts``. A
    failed attempt counts: reaching for a log that turned out not to be
    there is how its absence is established."""
    rx = re.compile("|".join(f"(?:{l.search})" for l in layouts), re.IGNORECASE)
    return any(rx.search(_text(e, _REQUEST_KEYS)) for e in (entries or []))


def demand(layouts: Iterable[EventLogLayout] = LAYOUTS) -> str:
    """The search a refusal or work order asks for, one clause per layout."""
    return " or ".join(l.demand() for l in layouts) or EVTX.demand()


def locations(layouts: Iterable[EventLogLayout] = LAYOUTS) -> str:
    """Where the Security log lives, for prose that names the place."""
    return " or ".join(l.location for l in layouts)


def log_names_regex_fragment() -> str:
    """Alternation of every layout's log file names, for regexes that
    recognise a claim about event logs."""
    names = [l.security_log for l in LAYOUTS]
    names += ["System.evtx", "Application.evtx", "SysEvent.Evt", "AppEvent.Evt"]
    return "|".join(re.escape(n) for n in names)


def logon_where(entries: Iterable, claim_text: str = "") -> str:
    """Where a "no logon" negative has to look, phrased for the layouts the
    evidence shows (both when it shows neither), for the manifest refusal."""
    found = layouts_in_evidence(entries, claim_text) or LAYOUTS
    return (f"the Security event log on the mounted image: {demand(found)}; plus "
            "VSS / carved logs for windows that predate live-log coverage")


def logon_sources(entries: Iterable, claim_text: str = "") -> list[tuple]:
    """The sources a "no logon" negative must have searched, as
    ``(source_id, regex, hint)`` rows for the completeness manifest.

    Resolved per layout the evidence shows: the Security log of each, plus
    the session channels a layout has (only EVTX has TerminalServices).
    When no layout is established the Security log of either layout is
    required and satisfies, and no layout-specific channel is demanded.
    """
    found = layouts_in_evidence(entries, claim_text)
    if not found:
        rx = re.compile("|".join(l.security_search_regex().pattern for l in LAYOUTS),
                        re.IGNORECASE)
        return [("security_log", rx,
                 f"the Security event log ({locations()}) - logon success/"
                 "failure events by type and source address")]
    rows: list[tuple] = []
    for layout in found:
        rows.append((f"security_{layout.name}", layout.security_search_regex(),
                     f"{layout.location} - logon success/failure events by "
                     "type and source address"))
        if layout.session_logs:
            rows.append((f"sessions_{layout.name}",
                         re.compile("|".join(re.escape(s.lower()) for s in
                                             layout.session_logs)
                                    + r"|terminalservices|localsessionmanager|"
                                    r"remoteconnectionmanager",
                                    re.IGNORECASE),
                         f"{' / '.join(layout.session_logs)} channels under "
                         f"{layout.log_dir} - these record remote sessions with "
                         "user and source address"))
    return rows
