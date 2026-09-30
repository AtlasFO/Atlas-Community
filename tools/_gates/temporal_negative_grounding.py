"""Gate: temporal negative claims ("no activity after <date>", "system last
active on <date>", "dormant since …") need real grounding.

Failure this guards against: a run concludes "system last active on <date>,
no compromise" from the base flat extent of a snapshotted VMDK.
The base extent is FROZEN at snapshot creation; later activity (and any
compromise evidence) lives only in the snapshot delta chain. Two independent
failure modes are refused:

  1. the trace analyzed a base VMDK that is shadowed by snapshot deltas —
     any "nothing after <date>" read off that disk is an analysis artifact,
     not evidence;
  2. the claim rests on fewer than two independent artifact classes (event
     logs, filesystem metadata, registry, execution artifacts, unified
     timeline) — missing or timed-out tool output is an analysis problem,
     never proof of system inactivity.

Fires on EVERY tier: a temporal negative shapes the whole report, and a
CONFIRMED wrong one is strictly worse than an UNCONFIRMED wrong one.
"""
import os
import re
from typing import Optional

from core.auth_ontology import CHAINSAW_EVTX

# "no activity/events/logons ... after/since <ref>"
_NEG_AFTER_RE = re.compile(
    r"\b(?:no|zero|not\s+any|without|absence\s+of|lack\s+of)\s+"
    r"(?:\w+[\s-]+){0,3}?"
    r"(?:activity|events?|logs?|logons?|logins?|entries|sessions?|"
    r"artifacts?|evidence|writes?|usage)\s+"
    r"(?:after|since|beyond|past|later\s+than|following)\b",
    re.IGNORECASE)

# "last activity / last boot / most recent logon ..." — only a temporal
# negative when it ALSO pins a date (see _DATE_RE) AND carries an inactivity
# cue (see _INACTIVITY_CUE_RE). Without the cue, "the last logon on
# 2031-02-04 came from a Tor exit" is a POSITIVE attribution, not a claim of
# absence — gating it would block legitimate findings.
_LAST_ACTIVE_RE = re.compile(
    r"\b(?:last|latest|most\s+recent|final)\s+"
    r"(?:\w+[\s-]+){0,2}?"
    r"(?:activity|active|boot(?:ed)?|logon|login|log\s+entry|event|use[d]?|"
    r"write|modification|seen)\b",
    re.IGNORECASE)

# An inactivity/termination cue that turns a "last active on <date>" statement
# into a claim of absence-thereafter (vs. a positive last-observed fact).
_INACTIVITY_CUE_RE = re.compile(
    r"\b(?:no|nothing|none|never|ceased?|stopped|ended|halted|silent|"
    r"dormant|inactive|offline|idle|quiet|thereafter|afterwards?|"
    r"since\s+then|after\s+which|no\s+further|no\s+more|not\s+used|"
    r"decommissioned|abandoned)\b",
    re.IGNORECASE)

# "inactive/dormant/offline/powered off ... since/after"
_INACTIVE_SINCE_RE = re.compile(
    r"\b(?:inactive|dormant|offline|unused|decommissioned|"
    r"powered\s+(?:off|down)|shut\s*down)\s+(?:after|since|from)\b",
    re.IGNORECASE)

# ISO, slashed, dotted, and month-name dates.
_DATE_RE = re.compile(
    r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b"
    r"|\b\d{1,2}\.\d{1,2}\.\d{4}\b"
    r"|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+"
    r"\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b",
    re.IGNORECASE)

# The analyst deliberately reporting about the pre-snapshot state names the
# snapshot topology — that is a valid finding and must not be blocked.
_SNAPSHOT_AWARE_RE = re.compile(
    r"snapshot|delta\s+chain|frozen\s+(?:base|extent|state)|pre-snapshot",
    re.IGNORECASE)

# .vmdk paths in a command string. Two forms: a quoted path (may contain
# spaces — common on network shares like "//nas/My VM/disk.vmdk") and a bare
# unquoted token. Bare paths with an unescaped space can't be recovered
# unambiguously, but the executor-stamped warning (preferred above) is the
# real path anyway, so this fallback only needs the common cases.
_VMDK_QUOTED_RE = re.compile(r"""(['"])(.+?\.vmdk)\1""", re.IGNORECASE)
_VMDK_BARE_RE = re.compile(r"(?:^|[\s=])((?:[^\s'\"=]|\\ )+\.vmdk)\b",
                           re.IGNORECASE)


def _vmdk_paths(cmd: str) -> list[str]:
    if not isinstance(cmd, str):
        return []
    out = []
    for m in _VMDK_QUOTED_RE.finditer(cmd):
        out.append(m.group(2))
    for m in _VMDK_BARE_RE.finditer(cmd):
        out.append(m.group(1).replace("\\ ", " "))
    return out

# Independent artifact classes that can corroborate a temporal negative.
# Spans Windows AND Unix/Linux evidence — a Linux host would satisfy none of
# the Windows-only classes and be un-recordable otherwise. A chainsaw run
# that writes mft_rule_hunt_*.jsonl (misc.mft_rule_hunt) matched names in
# an $MFT: it read no event log and no timestamps worth corroborating, so
# it counts as neither class.
_ARTIFACT_CLASSES = [
    ("event logs", re.compile(
        r"evtxecmd|hayabusa|" + CHAINSAW_EVTX + r"|wevtutil|\.evtx\b",
        re.IGNORECASE)),
    ("filesystem metadata (MFT/USN/inode times)", re.compile(
        r"^(?!.*\bmft_rule_hunt_).*?(?:mftecmd|usnparser|usn_journal|\bfls\b"
        r"|mactime|\bistat\b|\$mft\b|\bstat\b|debugfs|\btimeliner\b)",
        re.IGNORECASE)),
    ("registry", re.compile(
        r"recmd|regripper|\brla\b|amcache|appcompat|shimcache"
        r"|ntuser\.dat|software\b.*hive|system\b.*hive",
        re.IGNORECASE)),
    ("execution artifacts (prefetch/SRUM)", re.compile(
        r"pecmd|prefetch|srum|userassist|jlecmd|\blecmd\b",
        re.IGNORECASE)),
    ("unified timeline (plaso)", re.compile(
        r"log2timeline|psort|plaso", re.IGNORECASE)),
    ("unix auth/session logs", re.compile(
        r"\bwtmp\b|\butmp\b|\bbtmp\b|\blast\b|lastlog|auth\.log|secure\b"
        r"|journalctl|\bjournald?\b|/var/log/",
        re.IGNORECASE)),
    ("unix shell/execution history", re.compile(
        r"bash_history|zsh_history|\.history\b|auditd|audit\.log|"
        r"cron(?:tab|\.log)?|systemd|dmesg",
        re.IGNORECASE)),
]


def _is_temporal_negative(text: str) -> bool:
    if _NEG_AFTER_RE.search(text) or _INACTIVE_SINCE_RE.search(text):
        return True
    return bool(_LAST_ACTIVE_RE.search(text) and _DATE_RE.search(text)
                and _INACTIVITY_CUE_RE.search(text))


def _tool_calls(ctx) -> list:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    return [e for e in by_type.get("tool_call", [])
            if isinstance(e.get("cmd"), str)]


def _entry_frozen_warning(e: dict) -> Optional[str]:
    """Frozen-base warning for a single tool_call entry, or None.

    Prefers the `vmdk_snapshot_warning` the executor already stamped
    (path realpath-resolved there, no cmd re-parsing); falls back to
    re-deriving it from any .vmdk path in the command — robust to quoted
    paths with spaces — for entries predating the stamped field.
    """
    stamped = e.get("vmdk_snapshot_warning")
    if stamped:
        return str(stamped)
    cmd = e.get("cmd")
    if not isinstance(cmd, str):
        return None
    try:
        from core.vmdk import snapshot_warning
    except Exception:
        return None
    for path in _vmdk_paths(cmd):
        try:
            if not os.path.exists(path):
                continue
            warning = snapshot_warning(path)
        except Exception:
            continue
        if warning:
            return warning
    return None


def _lineage_call_ids(ctx) -> set:
    """Trace call_ids THIS finding cites (linked_call_id + input_call_ids)."""
    ids = set()
    lid = getattr(ctx, "linked_call_id", 0)
    if lid:
        ids.add(lid)
    for c in (getattr(ctx, "input_call_ids", None) or []):
        if c:
            ids.add(c)
    return ids


def _frozen_in_lineage(ctx) -> Optional[str]:
    """Frozen-base warning from a tool_call THIS finding is derived from.

    Scoped to the finding's own cited call_ids so an UNRELATED orientation
    read of the flat base elsewhere in the trace does not refuse a correct
    finding derived from a properly flattened chain-top. Returns None when the finding cites
    no calls, so the caller can fall back to a trace-wide scan.
    """
    by_call_id = getattr(ctx.idx, "by_call_id", {}) or {}
    ids = _lineage_call_ids(ctx)
    if not ids:
        return None
    for cid in ids:
        entry = by_call_id.get(cid)
        if entry is None:
            entry = by_call_id.get(str(cid))
        if isinstance(entry, dict):
            warning = _entry_frozen_warning(entry)
            if warning:
                return warning
    return None


def _frozen_vmdk_in_trace(cmds: list) -> Optional[str]:
    """First snapshot-chain warning across ALL analyzed tool_calls.

    The conservative fallback used only when a finding cites no lineage at
    all — normally record_finding has already inferred input_call_ids, so
    _frozen_in_lineage is the precise path.
    """
    for e in cmds:
        warning = _entry_frozen_warning(e)
        if warning:
            return warning
    return None


def check(ctx) -> Optional[dict]:
    desc = ctx.description or ""
    blob = desc + " " + (getattr(ctx, "supporting_evidence", "") or "")
    if not _is_temporal_negative(blob):
        return None

    cmds = _tool_calls(ctx)

    # 1) Snapshot-frozen VMDK base: the disk itself cannot show anything
    #    after the snapshot date — the claim is an analysis artifact.
    #    Scoped to the finding's OWN lineage: a correct negative read off a
    #    flattened chain-top must not be refused just because an unrelated
    # orientation read touched the flat base earlier.
    #    Falls back to a trace-wide scan only for a finding with no lineage.
    if not _SNAPSHOT_AWARE_RE.search(blob):
        frozen = _frozen_in_lineage(ctx)
        if frozen is None and not _lineage_call_ids(ctx):
            frozen = _frozen_vmdk_in_trace(cmds)
        if frozen:
            return {
                "success": False,
                "error": (
                    "Refusing temporal-negative finding: the trace analyzed "
                    "a BASE VMDK that is shadowed by snapshot deltas, so the "
                    "disk state ends at the snapshot's creation — 'no "
                    "activity after <date>' read from it is an analysis "
                    "artifact, not evidence. " + frozen +
                    " Re-run the analysis against the chain-top descriptor "
                    "(img_vmdk_chain_info → img_vmdk_export_raw), or state "
                    "explicitly that the finding describes the pre-snapshot "
                    "state."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "temporal_negative_grounding",
            }

    # 2) Multi-artifact corroboration: >= 2 independent artifact classes
    #    successfully examined.
    satisfied = [name for name, rx in _ARTIFACT_CLASSES
                 if any(e.get("success") and rx.search(e["cmd"])
                        for e in cmds)]
    if len(satisfied) < 2:
        have = ", ".join(satisfied) or "none"
        missing = ", ".join(n for n, _ in _ARTIFACT_CLASSES
                            if n not in satisfied)
        return {
            "success": False,
            "error": (
                f"Refusing temporal-negative finding: 'no activity after "
                f"<date>' / 'last active on <date>' claims must be "
                f"corroborated by at least TWO independent artifact classes "
                f"— the trace shows successful examination of: {have}. "
                f"Missing or timed-out tool output is an analysis problem, "
                f"never proof of system inactivity. Examine at least one "
                f"more of: {missing}; then re-record."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "temporal_negative_grounding",
        }

    return None
