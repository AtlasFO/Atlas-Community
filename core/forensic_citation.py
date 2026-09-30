"""A citation an analyst can read, check, and go look up.

What was wrong
==============
Atlas had evidence but no *citation*. Supporting Evidence was raw tool
output pushed through a fixed field template by column position — with no
check that the value in a slot was of that kind. A line of ``fls`` output
became::

    Timestamp: d/d 1234-128-1:
    Machine: Documents and Settings
    User: ProgramData

None of those are a timestamp, a machine or a user. The renderer had simply
assigned column 0 → timestamp, column 1 → machine, column 2 → user. Beside
it, provenance read ``Source File: evidence_index call_id=21 / Line: 1`` —
an internal identifier that tells a reader nothing about where in the
evidence the fact lives, and 40 lines of hexdump pasted in as "description".

What a citation actually is
===========================
The reference an analyst would write by hand:

    HOST01 · Windows Event Log Security.evtx · Event 4624 ·
    2031-02-04 12:00:00 UTC

Five parts, each optional, each *earned*: which host, which artifact (named
by what it is, not by the path Atlas happened to write it to), which record
inside it, when, and the specific value being relied on.

The rule that keeps it honest — and the one whose absence produced the
nonsense above — is that **a field is only labelled when the value has been
validated as that kind of thing**. A timestamp must parse as a time. An
event id must be numeric. A host must look like a host name. Anything that
cannot be identified is not given a label at all: it is shown as a quoted
excerpt, which is honest and still useful. Atlas would rather say less than
say something false about its own evidence.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# ── artifact naming ──────────────────────────────────────────────────────
#
# An analyst cites "the Security event log", not
# "analysis/SRV-01_Security_evtx.csv". Map a produced path back to the
# artifact it represents, generically.
_ARTIFACT_KINDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)security\.evtx|_security_evtx"), "Windows Event Log"),
    (re.compile(r"(?i)\.evtx($|\.)|_evtx\.csv$|evtxecmd|"
                r"windows\s+\w*\s*event\s+log"), "Windows Event Log"),
    (re.compile(r"(?i)\$mft|_mft\.csv$|mftecmd"), "NTFS Master File Table"),
    (re.compile(r"(?i)\$usnjrnl|usnjrnl|_j\.bin$"), "NTFS USN Journal"),
    (re.compile(r"(?i)ntuser\.dat|usrclass\.dat"), "User Registry Hive"),
    (re.compile(r"(?i)(^|[\\/])(system|software|sam)$|\.hve$|regripper|recmd"),
     "Registry Hive"),
    (re.compile(r"(?i)amcache"), "Amcache"),
    (re.compile(r"(?i)prefetch|\.pf$"), "Prefetch"),
    # "fw" as its own path segment or name prefix — evidence/fw/2024-05-01.log
    # is a firewall log, and citing it as a generic "Log File" loses the one
    # thing that makes it answer an exfiltration question.
    (re.compile(r"(?i)firewall|(?:^|[\\/])fw(?:[-_./]|$)"),
     "Firewall Log"),
    (re.compile(r"(?i)\.pcap(ng)?$"), "Packet Capture"),
    (re.compile(r"(?i)srum|srudb"), "SRUM"),
    (re.compile(r"(?i)bodyfile|mactime|timeline"), "Filesystem Timeline"),
    (re.compile(r"(?i)\.log$"), "Log File"),
)

# Windows event ids worth naming in plain language. Not a lookup the
# investigation depends on — purely so a citation reads like a sentence.
_EVENT_MEANINGS: dict[str, str] = {
    "4624": "successful logon", "4625": "failed logon",
    "4634": "logoff", "4648": "explicit-credential logon",
    "4672": "special privileges assigned", "4688": "process created",
    "4697": "service installed", "4720": "user account created",
    "4726": "user account deleted", "4738": "user account changed",
    "4768": "Kerberos TGT requested", "4769": "Kerberos service ticket",
    "4776": "credential validation", "4778": "session reconnected",
    "4779": "session disconnected", "5140": "network share accessed",
    "5145": "share object checked", "7045": "service installed",
    "1102": "audit log cleared", "104": "event log cleared",
    "4104": "PowerShell script block", "4103": "PowerShell pipeline",
    "1116": "malware detected", "1117": "malware action taken",
}

_TS_PATTERNS = (
    re.compile(r"\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)"),
    re.compile(r"\b(\d{4}/\d{2}/\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)"),
)
_HOST_RE = re.compile(r"(?i)^[a-z][a-z0-9._-]{1,62}$")
# An EvtxECmd CSV row: RecordNumber,EventRecordId,TimeCreated,EventId,Level,
# Provider,Channel,… — the shape of the exporter, so the event id and the
# channel can be read from position without any phrasing in the text.
_EVTXECMD_ROW_RE = re.compile(
    r"^\d+,\d+,\d{4}-\d{2}-\d{2}[ T][\d:.]+,(\d{1,5}),[^,]*,[^,]*,([^,]+),")
_FILE_TOKEN_RE = re.compile(
    r"(?i)\b([\w$][\w$.-]*\.(?:evtx|evt|csv|tsv|hve|hive|dat|pf|lnk|log|txt|"
    r"json|jsonl|bin|raw|vmdk|e01|pcap|sqlite|db))\b")


def evtxecmd_fields(text: str) -> dict[str, str]:
    """Columns of an EvtxECmd CSV row, by the exporter's fixed order:
    RecordNumber, EventRecordId, TimeCreated, EventId, Level, Provider,
    Channel, ProcessId, ThreadId, Computer, ChunkNumber, UserId,
    MapDescription, UserName, RemoteHost, PayloadData1… Empty when the
    row is not one."""
    first = next((ln for ln in str(text or "").splitlines() if ln.strip()), "")
    first = first.lstrip("\ufeff").strip()
    if not _EVTXECMD_ROW_RE.match(first):
        return {}
    cols = first.split(",")
    def col(i: int) -> str:
        return cols[i].strip().strip('"') if len(cols) > i else ""
    # …Computer(9), ChunkNumber(10), UserId(11), MapDescription(12),
    # UserName(13), RemoteHost(14).
    user = re.sub(r"\s*\(S-1-5[^)]*\)\s*$", "", col(13))   # "name (SID)" → name
    if user in ("-", "-\\-", "\\-", "-\\", "N/A"):
        user = ""                                             # anonymous
    out = {
        "timestamp": col(2), "event_id": col(3), "channel": col(6),
        "computer": col(9), "description": col(12), "user": user,
        "remote_host": col(14),
    }
    # MapDescription is prose; when the exporter has no map the column is a
    # payload fragment, which is not a description.
    if out["description"] and (out["description"].startswith(("{", '""')) or
                               len(out["description"]) > 120):
        out["description"] = ""
    return out


def _artifact_from_text(text: str) -> str:
    """Name the artifact a record came from, from the record itself.

    A citation built from the analyst's own locator ("file01 Security.evtx
    EventID 4720 at …") or from a trace window has no file path to name —
    the source field says ``supporting_evidence`` or ``trace call_id=108``,
    and that was printed as the artifact.
    """
    body = str(text or "")
    m = _FILE_TOKEN_RE.search(body)
    if m:
        return m.group(1)
    m = _EVTXECMD_ROW_RE.match(body.lstrip())
    if m:
        return f"{m.group(2).strip()}.evtx"
    return ""
_EVENT_ID_RE = re.compile(r"(?i)\b(?:event\s*(?:id)?|eid)[\s:#]*(\d{1,5})\b")
_MFT_ENTRY_RE = re.compile(r"(?i)\b(?:mft\s*entry|entrynumber)[\s:#]*(\d{1,9})\b")

# Output that must never reach a report body as "evidence text".
_HEXDUMP_RE = re.compile(r"^\s*[0-9a-f]{8}(\s+[0-9a-f]{2}){4,}", re.I | re.M)
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=]{200,}$")

MAX_QUOTE_CHARS = 240


def artifact_kind(path_or_name: str) -> str:
    """What kind of forensic artifact this is, in an analyst's words."""
    text = str(path_or_name or "")
    for pattern, label in _ARTIFACT_KINDS:
        if pattern.search(text):
            return label
    return ""


def artifact_display_name(path_or_name: str) -> str:
    """The artifact's own name, not the working path Atlas wrote it to.

    ``analysis/SRV-01_Security_evtx.csv`` cites as ``Security.evtx``:
    the reader needs the artifact, not Atlas's intermediate file.
    """
    raw = str(path_or_name or "").replace("\\", "/").rstrip("/")
    if not raw:
        return ""
    base = raw.rsplit("/", 1)[-1]
    # Undo the "<host>_<Artifact>_evtx.csv" shape our own exporters produce.
    m = re.match(r"(?i)^(?:[a-z0-9.-]+_)?(.+?)_evtx\.csv$", base)
    if m:
        return f"{m.group(1)}.evtx"
    m = re.match(r"(?i)^(?:[a-z0-9.-]+_)?(.+?)\.(csv|json|txt)$", base)
    if m and artifact_kind(base):
        inner = m.group(1)
        if inner.lower().endswith((".evtx", ".dat", ".hve", ".log")):
            return inner
    return base


def normalize_timestamp(value: Any) -> str:
    """A timestamp only if it really is one — otherwise ``""``.

    This single check is what stops ``d/d 1234-128-1:`` being published
    under the label "Timestamp".
    """
    text = str(value or "").strip()
    if not text:
        return ""
    # A field value is short; a whole record is not. The old 64-character
    # cap meant no CSV row ever yielded a time — the attack timeline came
    # out empty and citations lost their timestamps. The regex, not the
    # length, is what keeps "d/d 1234-128-1" from being called a time;
    # the first match in a record is its own timestamp (EvtxECmd, MFTECmd
    # and timeline exports all lead with it).
    text = text[:4000]
    for pattern in _TS_PATTERNS:
        m = pattern.search(text)
        if m:
            date, clock = m.group(1).replace("/", "-"), m.group(2)
            if len(clock) == 5:
                clock += ":00"
            suffix = " UTC" if re.search(r"(?i)\bUTC\b|Z\b|\+00:?00", text) else ""
            return f"{date} {clock}{suffix}"
    return ""


def host_name_forms(label: str) -> list[str]:
    """The names a machine labelled ``label`` may call itself in a log.

    ``PROD-SQL-02`` appears as ``prod-sql-02``, ``sql-02``, ``prodsql02`` or
    ``sql02``; ``CORP-FILE01`` as ``file01``. Every dash-separated suffix,
    with and without its dashes, as long as it is still four characters —
    anything shorter matches half the words in a log.
    """
    lab = str(label or "").lower().split(".", 1)[0]
    parts = [p for p in lab.split("-") if p]
    forms: list[str] = []
    for i in range(len(parts)):
        for form in ("-".join(parts[i:]), "".join(parts[i:])):
            if len(form) >= 4 and form not in forms:
                forms.append(form)
    return forms


def host_mentioned(label: str, text: str) -> bool:
    """Does ``text`` refer to the case host ``label``?

    Logs write the machine as it calls itself — ``srv01.example.local``
    — while the evidence table calls it ``CORP-SRV01``. Matching the label
    verbatim missed every record, so citations lost their host.
    """
    low = str(text or "").lower()
    if not low:
        return False
    # "_" is a delimiter here, not a word character: extracts are named
    # node7_System.evtx, and the host is the part before the underscore.
    return any(re.search(rf"(?<![a-z0-9-]){re.escape(form)}(?![a-z0-9-])", low)
               for form in host_name_forms(label))


def looks_like_host(value: Any, known_hosts: Iterable[str] = ()) -> bool:
    """A host name, not merely a string sitting in the host column."""
    text = str(value or "").strip()
    if not text or " " in text or "/" in text or "\\" in text:
        return False
    known = {h.lower() for h in known_hosts if h}
    if known and text.lower() in known:
        return True
    if not _HOST_RE.match(text):
        return False
    # Reject things that are plainly filesystem nouns rather than machines.
    return not text.lower().endswith(
        (".exe", ".dll", ".txt", ".csv", ".log", ".evtx", ".dat"))


def is_binary_noise(text: str) -> bool:
    """Hexdumps and opaque blobs are not quotable evidence."""
    body = str(text or "")
    if not body.strip():
        return True
    if _HEXDUMP_RE.search(body):
        return True
    stripped = body.strip()
    if _BASE64ISH_RE.match(stripped):
        return True
    printable = sum(1 for c in stripped[:400]
                    if c.isprintable() or c in "\t\n\r")
    return bool(stripped) and printable / min(len(stripped), 400) < 0.85


def summarize_opaque(text: str, *, label: str = "binary content") -> str:
    """What to print instead of pasting a hexdump into a report."""
    body = str(text or "")
    n = len(body.encode("utf-8", "replace"))
    return f"[{label}, {n:,} bytes — not reproduced; see the source artifact]"


def quote_excerpt(text: str, *, limit: int = MAX_QUOTE_CHARS) -> str:
    """A short, single-line excerpt safe to place in a report."""
    body = " ".join(str(text or "").split())
    if not body:
        return ""
    if len(body) <= limit:
        return body
    return body[:limit].rstrip() + " …"


@dataclass
class Citation:
    """Where a statement's support actually lives."""

    host: str = ""
    artifact: str = ""
    kind: str = ""
    record: str = ""
    timestamp: str = ""
    excerpt: str = ""
    call_id: Optional[int] = None
    provenance: str = "direct"
    extra: dict[str, Any] = field(default_factory=dict)

    def render(self, *, with_excerpt: bool = True) -> str:
        """One line an analyst can act on.

        ``HOST01 · Windows Event Log Security.evtx · Event 4624
        (successful logon) · 2031-02-04 12:00:00 UTC``
        """
        parts: list[str] = []
        if self.host:
            parts.append(self.host)
        if self.artifact:
            parts.append(f"{self.kind} {self.artifact}".strip())
        elif self.kind:
            parts.append(self.kind)
        if self.record:
            parts.append(self.record)
        if self.timestamp:
            parts.append(self.timestamp)
        head = " · ".join(parts) if parts else "source not identified"
        if self.provenance and self.provenance != "direct":
            head += f" ({self.provenance})"
        if with_excerpt and self.excerpt:
            head += f' — "{self.excerpt}"'
        return head

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "artifact": self.artifact, "kind": self.kind,
            "record": self.record, "timestamp": self.timestamp,
            "excerpt": self.excerpt, "call_id": self.call_id,
            "provenance": self.provenance, "rendered": self.render(),
        }


def describe_record(text: str, *, source: str = "") -> str:
    """Name the specific record a citation points at, when it is knowable.

    Event ids, MFT entries and line numbers are the three that actually
    help someone re-find the fact. Everything else stays unlabelled rather
    than guessed.
    """
    body = str(text or "")
    m = _EVENT_ID_RE.search(body) or _EVTXECMD_ROW_RE.match(body.lstrip())
    if m:
        eid = m.group(1)
        meaning = _EVENT_MEANINGS.get(eid)
        return f"Event {eid}" + (f" ({meaning})" if meaning else "")
    m = _MFT_ENTRY_RE.search(body) or _MFT_ENTRY_RE.search(str(source or ""))
    if m:
        return f"MFT entry {m.group(1)}"
    return ""


def _record_from_ref(record_ref: str, kind: str) -> str:
    """Read the record identifier out of a ``path:line:id`` RecordRef.

    Only trusted for artifacts where the trailing number is genuinely a
    record id: on an event log it is the Event ID, which is what an analyst
    would cite. Elsewhere the line number is the honest answer. `kind` is
    passed in rather than re-derived so the label can never disagree with
    the artifact kind printed beside it.
    """
    ref = str(record_ref or "")
    parts = ref.split(":")
    if len(parts) < 3:
        return ""
    line_part, id_part = parts[-2].strip(), parts[-1].strip()
    if not id_part.isdigit():
        return ""
    if kind == "Windows Event Log":
        meaning = _EVENT_MEANINGS.get(id_part)
        return f"Event {id_part}" + (f" ({meaning})" if meaning else "")
    if line_part.isdigit():
        return f"record {id_part}"
    return ""


def citation_from_event(
    event: dict[str, Any],
    *,
    known_hosts: Iterable[str] = (),
) -> Citation:
    """Build a citation from a resolved evidence event, field by field.

    Every field is validated before it is accepted. An event whose fields
    cannot be identified still produces a usable citation — it just carries
    an excerpt instead of inventing structure.
    """
    ev = event if isinstance(event, dict) else {}
    text = str(ev.get("text") or "")
    source = str(ev.get("record_ref") or ev.get("source") or "")
    source_path = source.split(":")[0] if source else ""

    host = str(ev.get("host") or "").strip()
    if not looks_like_host(host, known_hosts):
        host = ""
        blob = (source + " " + text).lower()
        for candidate in known_hosts:
            if candidate and host_mentioned(candidate, blob):
                host = candidate
                break

    if not source_path or source_path in ("supporting_evidence",) or \
            source_path.startswith(("trace call_id", "evidence_index")):
        source_path = _artifact_from_text(text)
    artifact = artifact_display_name(source_path) if source_path else ""
    # The event's own description of where it came from ("Windows Security
    # Event Log") is often more informative than the working file Atlas
    # wrote, so it participates in identifying the kind.
    kind = (artifact_kind(source_path or artifact)
            or artifact_kind(str(ev.get("source_artifact") or ""))
            or artifact_kind(text))

    timestamp = normalize_timestamp(ev.get("timestamp"))
    if not timestamp:
        timestamp = normalize_timestamp(text)

    # A RecordRef is written "<artifact>:<line>:<record id>" — for an event
    # log that trailing id is the Event ID, which is far more useful to a
    # reader than the row offset it sits at.
    record = _record_from_ref(source, kind)
    if not record:
        record = describe_record(text, source=source)
    if not record:
        line = ev.get("line")
        if isinstance(line, int) and line > 0 and artifact:
            record = f"line {line}"

    if is_binary_noise(text):
        excerpt = summarize_opaque(text)
    else:
        excerpt = quote_excerpt(text)

    return Citation(
        host=host,
        artifact=artifact,
        kind=kind,
        record=record,
        timestamp=timestamp,
        excerpt=excerpt,
        call_id=ev.get("call_id") if isinstance(ev.get("call_id"), int) else None,
        provenance=str(ev.get("provenance") or "direct"),
    )


def render_citations(
    events: Iterable[dict[str, Any]],
    *,
    known_hosts: Iterable[str] = (),
    limit: int = 8,
) -> str:
    """A Supporting Evidence block a human can read.

    Deduplicated, capped, and rendered as a list of references rather than
    a transcript of tool output.
    """
    seen: set[str] = set()
    lines: list[str] = []
    total = 0
    for ev in events:
        total += 1
        cite = citation_from_event(ev, known_hosts=known_hosts)
        rendered = cite.render()
        key = rendered.lower()
        if key in seen:
            continue
        seen.add(key)
        if len(lines) < limit:
            suffix = (f"  \n  `call_id={cite.call_id}`"
                      if cite.call_id is not None else "")
            lines.append(f"- {rendered}{suffix}")
    if not lines:
        return ""
    if total > len(lines):
        lines.append(f"- …and {total - len(lines)} further record(s) in the "
                     "execution trace")
    return "\n".join(lines)


# A citation line the finding tool wrote itself, from a tool output that
# carried a value the analyst's evidence omitted. The finding keeps the
# mark, so the trace says which citations were machine-added; a report
# shows the citation without it.
MACHINE_CITATION_MARK = "[auto-cite from tool output]"
_MACHINE_CITATION_MARK_RE = re.compile(
    r"(?m)^[ \t]*" + re.escape(MACHINE_CITATION_MARK) + r"[ \t]*")


def strip_machine_citation_mark(text: str) -> str:
    """``text`` without the mark that opens a machine-added citation line."""
    return _MACHINE_CITATION_MARK_RE.sub("", text or "")


# Baseline entries of tools whose output is the run's own state rather than
# anything read from the evidence: a reasoning step, a recorded finding or
# note, the claim graph and its snapshots, coverage and accuracy over the
# trace, exports, the brain, job control, response actions, protocol
# bookkeeping. Whole namespaces where every tool is of that kind; for misc,
# which mixes parsers with bookkeeping, the bookkeeping verbs. The set is
# pinned tool by tool against the registered servers in the tests, so a new
# tool is classified when it is added. An unlisted tool counts as evidence:
# the gates then err towards refusing, never towards letting a claim rest on
# a partial view.
_OWN_WORDS_CMD_PREFIXES = (
    "<py>:reason_", "<py>:dair_", "<py>:claim_", "<py>:coverage_",
    "<py>:accuracy_", "<py>:export_", "<py>:brain_", "<py>:job_",
    "<py>:respond_", "<py>:atlas_", "<py>:correlate_",
    "<py>:misc_record_", "<py>:misc_start_", "<py>:misc_clear_",
    "<py>:misc_get_", "<py>:misc_current_", "<py>:misc_export_",
    "<py>:misc_write_", "<py>:misc_update_", "<py>:misc_supersede_",
    "<py>:misc_list_investigation_", "<py>:misc_launch_", "<py>:misc_serve_",
    "<py>:misc_symlink_", "<py>:misc_knowns_",
)
_OWN_WORDS_TYPES = frozenset((
    "reason_call", "dair_call", "finding", "self_correction",
    "investigation_narration", "curiosity_probe", "deferred_intent",
    "call_initiated",
))


def own_words_entry(entry: dict) -> bool:
    """True when a trace entry carries the analyst's own words rather than
    what a forensic tool produced. Quoting or citing such an entry as
    evidence would let a misremembered command line support itself."""
    if not isinstance(entry, dict):
        return True
    if entry.get("type") != "tool_call":
        return entry.get("type") in _OWN_WORDS_TYPES
    return str(entry.get("cmd") or "").startswith(_OWN_WORDS_CMD_PREFIXES)


# Tools whose output is knowledge about the values the call was given: a
# third party's reputation, registration or resolution, and the sweep of
# the operator's threat context, which lists the values it searched for.
# The output restates the values asked about, so it never shows a value was
# on the system; a lookup grounds what the provider says, and a sweep hit
# names the call a finding cites instead. Pinned tool by tool in the tests
# beside the other two classes.
_EXTERNAL_LOOKUP_CMD_PREFIXES = ("<py>:enrich_", "<py>:search_intel_sweep")


def external_lookup_entry(entry: dict) -> bool:
    """True when a trace entry is a lookup of a value at an outside source."""
    return (isinstance(entry, dict) and entry.get("type") == "tool_call"
            and str(entry.get("cmd") or "").startswith(_EXTERNAL_LOOKUP_CMD_PREFIXES))


def citation_class(entry: dict) -> str:
    """What a cited trace entry can show: ``own_words`` (the run restating
    itself), ``external_lookup`` (what a provider says about a value) or
    ``evidence`` (what a tool read). Only evidence shows that a value was
    present in the case."""
    if own_words_entry(entry):
        return "own_words"
    if external_lookup_entry(entry):
        return "external_lookup"
    return "evidence"


def known_case_hosts(case_dir: str | os.PathLike | None) -> list[str]:
    """Host names this case knows about, for validating host fields."""
    if not case_dir:
        return []
    hosts: list[str] = []
    try:
        import json
        from pathlib import Path
        p = Path(case_dir) / ".atlas" / "evidence_links.json"
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in (data.get("links") or data.get("entries") or []):
                if isinstance(item, dict):
                    label = str(item.get("label") or item.get("host") or "")
                    if label and label.lower() not in ("firewall", "other"):
                        hosts.append(label)
    except Exception:  # noqa: BLE001
        pass
    return hosts
