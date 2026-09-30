"""Per-category source manifests for the negative_completeness gate.

A negative/absence finding is only valid if the investigation searched the
COMPLETE set of sources where the thing could be. This encodes, as data, the
"complete source set" for each case-inverting claim category — the same lists
the playbook states as prose in hub/playbook/03_dfir_methodology.md (Exhaustive
Evidence Rule, Identity Exhaustion Gate, Authentication-Session Inventory,
Exfil-Channel Enumeration).

Each category has:
  trigger        — regex over a finding description that marks it as this kind
                   of absence claim (only matched UNCONFIRMED findings are gated)
  required       — [(source_id, cmd_regex, where_hint)] : every source must have
                   been touched by some tool_call (cmd substring match) OR proven
                   absent from evidence; or a callable (tool_calls, claim_text)
                   returning that list when the sources depend on the media
  alt_satisfies  — optional regex that waives `required` entirely (e.g. a Linux
                   host satisfies LOGON_AUTH via wtmp/last instead of the Windows
                   event channels)
  where          — human hint appended to the refusal: where the missing sources
                   live (so the agent is steered to them, not just blocked); a
                   callable (tool_calls, claim_text) when that depends on the media
"""
import re

from core.eventlog_layout import logon_sources as _logon_sources
from core.eventlog_layout import logon_where as _logon_where


def _rx(p: str) -> "re.Pattern":
    return re.compile(p, re.IGNORECASE)


MANIFESTS: dict = {
    # Order matters: classify() returns the FIRST matching category, so the
    # most specific / case-inverting (LOGON_AUTH) is listed first.
    "LOGON_AUTH": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:logon|log-on|rdp|remote[- ]?interactive|type ?10|"
            r"authenticat|session|sign[- ]?in|external network)"
            r"|local[- ]console only"
            r"|controller (?:unknown|unidentified|unestablished|cannot be|not established|"
            r"of[- ]record|unconfirmed)"
            r"|no (?:authentication|session|logon)[- ]?(?:artifact|event|source)"
            # Channel-absence claims: naming Security.evtx / TerminalServices as
            # missing without a search is still an absence claim.
            r"|(?:security\.evtx|terminal\s*services)[^.\n]{0,80}"
            r"(?:absent|not present|not (?:in|collected)|cannot be performed)"
            r"|(?:absent|not present|not (?:in|collected))[^.\n]{0,80}"
            r"(?:security\.evtx|terminal\s*services)"
        ),
        # Resolved per media: the Security log of the event-log layout the
        # evidence shows, plus the session channels only that layout has
        # (core.eventlog_layout.logon_sources).
        "required": _logon_sources,
        "alt_satisfies": _rx(r"\bwtmp\b|\butmp\b|lastlog|\blast\s+-|\bjournalctl\b|sshd|secure\.log"),
        "where": _logon_where,
    },
    # NOTE: DEVICE_INITIAL_ACCESS satisfaction is handled directly in
    # negative_completeness.check() against a COMPLETE structured device-install
    # inventory (misc.device_install_inventory + coverage span + flagged_count) —
    # not via the generic `required` cmd-substring loop. `required`/`where` below
    # are informational only and intentionally carry no device-specific signatures.
    "DEVICE_INITIAL_ACCESS": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:malicious (?:usb|device)|bad ?usb|hid (?:injection|attack|device)"
            r"|keystroke inject\w*|rogue device|physical (?:access|device))"
            r"|no initial[- ]access|not (?:a )?bad ?usb"
        ),
        "required": [
            ("device_inventory", _rx(r"device_install_inventory"),
             "a complete device-install inventory from setupapi.dev.log "
             "(misc.device_install_inventory) — enumerate every device, don't grep"),
        ],
        "alt_satisfies": None,
        "where": "the complete device-install inventory (misc.device_install_inventory) over "
                 "setupapi.dev.log — USBSTOR/mass-storage enumeration alone cannot reveal a "
                 "keystroke-injection device",
    },
    "IDENTITY": {
        "trigger": _rx(
            r"\b(?:identity|attribution|operator|owner|actor)\b[^.\n]*"
            r"(?:unknown|unidentified|cannot be|not (?:established|determined|known))"
            r"|no (?:match|identity)[^.\n]*(?:roster|suspect|directory)"
            r"|requires?[^.\n]*(?:subpoena|legal process)"
            r"|\bunattributed\b"
        ),
        "required": [
            ("sam", _rx(r"\bsam\b|sam hive|recmd[^\n]*sam"),
             "SAM hive — local accounts / last-login"),
            ("ntuser", _rx(r"ntuser"),
             "NTUSER.DAT per user profile — Office LiveId / owner identity"),
            ("browser", _rx(r"hindsight|webcache|places\.sqlite|\bhistory\b|cookies|chrome|firefox|edge"),
             "browser history/cookies across all profiles"),
            ("comms", _rx(r"readpst|pff_export|\.ost\b|\.pst\b|outlook|main\.db|skype|whatsapp|telegram"
                          r"|parse_msg_ole|parse_emlx|\.msg\b|\.emlx\b"),
             "mail/chat stores — full sender/recipient inventory"),
            # Roster/suspect-list xref is CASE workflow, not a universal source —
            # do not hard-require CTF roster tooling in the default gate.
        ],
        "alt_satisfies": None,
        "where": (
            "every identity-bearing artifact on the host (local accounts, per-user "
            "hives, browser, mail/chat) — cross-reference a case roster only when "
            "the CASE provides one"
        ),
    },
    "PERSISTENCE": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:persistence|persist|autostart|auto[- ]?run|run key|"
            r"scheduled task|service|wmi|startup|implant|foothold)"
        ),
        "required": [
            ("run_keys", _rx(r"\brun\b|runonce|recmd[^\n]*(software|ntuser)"),
             "all 4 Run/RunOnce hives (SOFTWARE + NTUSER, HKLM/HKCU)"),
            ("services", _rx(r"svcscan|svclist|\bservices?\b|recmd[^\n]*system"),
             "services (SYSTEM hive / vol.svcscan)"),
            ("scheduled_tasks", _rx(r"scheduled_task|schtask|\btasks?\b|parse_scheduled"),
             "scheduled tasks (\\Windows\\System32\\Tasks)"),
            ("startup_wmi_amcache", _rx(r"amcache|userassist|startup|\bwmi\b|autoruns|winlogon"),
             "Startup folder / WMI subscriptions / Winlogon / Amcache / UserAssist"),
        ],
        "alt_satisfies": None,
        "where": "all persistence locations (Run keys, services, scheduled tasks, WMI, Startup, Winlogon)",
    },
    "EXFIL": {
        "trigger": _rx(
            r"\bno\b[^.\n]*(?:exfil|exfiltrat|data (?:left|leav)|egress|"
            r"transfer(?:red)? (?:out|off|to)|dissemination|data (?:theft|removed))"
        ),
        "required": [
            ("removable", _rx(r"usbstor|mounteddevices|usbdevice|\blecmd\b|\blnk\b|removable|usn"),
             "removable-media trail (USBSTOR / MountedDevices / LNK / USN $J)"),
            ("cloud", _rx(r"\bcloud\b|filecache|sync\s*client|syncengine"),
             "cloud / sync-client artifacts (whichever clients the host actually has)"),
            ("mail_web", _rx(r"readpst|pff_export|attachment|\bhttp\b|ngrep|pcap|web upload"),
             "mail attachments / web-upload / HTTP sessions"),
            ("srum_ftp", _rx(r"srum|srudb|\bftp\b|transfer\.log|netflow"),
             "SRUM / FTP-transfer logs / netflow"),
        ],
        "alt_satisfies": None,
        "where": (
            "every candidate egress channel present on the host (removable, cloud/sync, "
            "mail, web, transfer logs / netflow), each checked for a transfer artifact"
        ),
    },
}


def classify(description: str):
    """Return the first category whose `trigger` matches `description`, else None.
    Only the four case-inverting categories are gated; everything else passes."""
    for cat, spec in MANIFESTS.items():
        if spec["trigger"].search(description or ""):
            return cat
    return None


def absence_grounding(description: str, supporting_evidence: str = "",
                      tool_calls: list | None = None) -> dict | None:
    """What grounds this statement as an absence claim, or None when it is
    not an absence claim of a gated category.

    The one notion every check of a negative shares: its ``category``, the
    ``required`` ``(source_id, regex, hint)`` rows a search must have touched
    (resolved for the media the trace shows when the manifest says so), the
    ``where`` hint naming those sources, and the ``alt_satisfies`` regex of a
    search that waives them. ``negative_completeness`` asks it of the whole
    trace at record time (was the search complete?); the citation checks ask
    it of a finding's cited calls (is the citation that search?).
    """
    category = classify(description)
    if not category:
        return None
    spec = MANIFESTS[category]
    calls = list(tool_calls or [])
    blob = f"{description or ''} {supporting_evidence or ''}"
    required = spec["required"]
    if callable(required):
        required = required(calls, blob)
    where = spec["where"]
    if callable(where):
        where = where(calls, blob)
    return {"category": category, "required": list(required), "where": where,
            "alt_satisfies": spec.get("alt_satisfies")}


def searches_of(grounding: dict, calls: list) -> list:
    """The calls among ``calls`` that searched one of the sources
    ``grounding`` requires (or one its alternative regex accepts): the calls
    that would have found what the claim says is absent. Judged on what the
    call was asked to read - its command line, evidence reference and
    arguments - and on the head of what it returned, because a typed tool's
    command line names only the tool and the result echoes the path it read.
    """
    from .lineage_relevance import entry_text
    rows = grounding.get("required") or []
    alt = grounding.get("alt_satisfies")
    out = []
    for e in calls:
        if not isinstance(e, dict):
            continue
        text = entry_text(e)
        if not text.strip():
            continue
        if any(rx.search(text) for _sid, rx, _hint in rows) or (alt and alt.search(text)):
            out.append(e)
    return out
