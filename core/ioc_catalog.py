"""Curated IOCs — what an analyst would hand to a threat-intel team.

The hard part of an IOC list is not extraction, it is refusal. A run that
watched ransomware touch a million files must not produce a million
indicators; it must produce one: ``*.locked``. So this module is built
around two rules, in order.

**1. Only recorded beliefs are candidates.** Never raw tool output. Atlas
records a belief only when ``record_finding`` passes its gates, so the
claim graph is already a curation boundary — the mass-encryption event
arrives as a single claim, not a million. Reading tool output directly
would reintroduce exactly the flood this exists to prevent.

**2. Being mentioned is not being implicated.** "Security.evtx shows a
logon for tempadmin on SRV01" mentions a file (the *evidence*), a host
(the *victim*) and an account. Only the account is a candidate indicator,
and only because of what the surrounding sentence says about it. Every
(indicator, belief) pair is therefore scored for a *role* from the language
around it, and anything that earns no role is dropped rather than listed
with a shrug.

Naming is deliberately split. Behaviour — "installed from a user's
Downloads directory, then executed" — is timeless and needs no
maintenance, so it is the primary signal. Tool *names* are the part that
goes stale, so the built-in list is a frozen bootstrap seed that is never
grown by hand; the living lexicon is the Brain, which learns adversary
tooling from finished runs (see ``adversary_tool_terms``). If the Brain is
empty or nobody reviews a candidate, behaviour-first still works and the
list degrades in quality rather than breaking.
"""
from __future__ import annotations

import functools
import os
import re
import datetime as _dt
from pathlib import Path
from dataclasses import dataclass, field
from collections.abc import Sequence
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

# Roles an indicator can earn. Anything that earns none is not an IOC.
ATTACKER_TOOL = "attacker_tool"
ATTACKER_FILE = "attacker_file"
ATTACKER_ACCOUNT = "attacker_account"
ATTACKER_INFRA = "attacker_infra"
ATTACKER_HOST = "attacker_host"
COMPROMISED_HOST = "compromised_host"
PATTERN = "pattern"
AFFECTED_ASSET = "affected_asset"
SUBJECT_IDENTIFIER = "subject_identifier"
THIRD_PARTY = "third_party"

_ROLE_ORDER = [ATTACKER_TOOL, ATTACKER_INFRA, ATTACKER_HOST, ATTACKER_ACCOUNT,
               ATTACKER_FILE, PATTERN, COMPROMISED_HOST, SUBJECT_IDENTIFIER,
               THIRD_PARTY, AFFECTED_ASSET]

_CONFIDENCE_RANK = {"CONFIRMED": 4, "LIKELY": 3, "SUSPECTED": 2,
                    "UNCONFIRMED": 1}

# ── language signals ─────────────────────────────────────────────────────
#
# What the belief says *about* the indicator. These decide the role; the
# tool names below only ever adjust confidence.
_ATTACK_ACTION_RE = re.compile(
    # "dropped" only with a file-like object: a firewall drops connections
    # ("500 dropped connections", "was dropped by a deny rule"), and that verb
    # made the firewall's own address attacker infrastructure.
    r"(?i)\b(install(?:ed|s)?|drop(?:ped|s)?\s+(?:(?:a|an|the|its|their)\s+)?"
    r"(?:files?|binar(?:y|ies)|payloads?|tools?|executables?|scripts?|dlls?|"
    r"webshells?|malware|ransomware|beacons?|implants?|"
    r"\S+\.(?:exe|dll|ps1|bat|vbs|js|sys|jar|py|sh|msi|scr|cmd)\b)|"
    r"deploy(?:ed|s)?|execut(?:ed|es|ion)|"
    r"ran|run|launch(?:ed|es)?|creat(?:ed|es)?|add(?:ed|s)?|stag(?:ed|ing)|"
    r"exfiltrat(?:ed|es|ion)|encrypt(?:ed|s|ion)|upload(?:ed|s)?|"
    r"download(?:ed|s)?|beacon(?:ed|s|ing)?|connect(?:ed|s)?\s+to|"
    r"persist(?:ence|ed)?|lateral\s+movement|privilege\s+escalation|"
    r"disabl(?:ed|es)|clear(?:ed|s)|delet(?:ed|es)|renam(?:ed|es)|"
    # Naming an attacker is describing attacker activity — see _MALICE_RE.
    r"attacker|adversary|threat\s+actor|intrusion|compromis(?:e|ed))\b"
)
# Characterisation of the *artifact*: this thing is bad.
#
# "attacker", "intrusion" and "compromised" used to live here, which made
# every sentence in an intrusion report read as malicious characterisation
# of everything it named — "tools executed by the attacker: taskmgr.exe"
# then promoted taskmgr.exe on the strength of the word "attacker". Framing
# the incident is true of the whole report and so corroborates nothing;
# it now counts as action, leaving every (action or malice) test unchanged
# while the stricter executable rule gets the real signal it asks for.
_MALICE_RE = re.compile(
    r"(?i)\b(malicious|suspicious|unauthori[sz]ed|"
    r"ransomware|backdoor|c2|command[- ]and[- ]control|"
    r"credential\s+(?:dump|theft|harvest)|"
    r"(?:dump|steal|harvest)(?:s|ed|ing)?\s+(?:the\s+|of\s+)?(?:credentials?|passwords?|hashes|lsass)|"
    r"byovd|vulnerable\s+driver|"
    r"anti[- ]forensic|payload|dropper|"
    r"remote\s+access\s+(?:tool|client)|rmm)\b"
)
# "we looked and it is not there" — nothing in such a sentence is an IOC.
_NEGATIVE_RE = re.compile(
    # \w+ could not span a filename, so "No mimikatz.exe was found" read as a
    # sighting. The subject is any run of non-space tokens up to the verb.
    r"(?i)(\bno\s+\S+(?:\s+\S+){0,4}?\s+(?:were|was|is|are)\s+"
    r"(?:found|present|observed|identified|detected)"
    r"|\b(?:were|was|is|are)\s+not\s+"
    r"(?:found|present|observed|identified|detected)"
    r"|\bnot\s+present\b|\bno\s+evidence\s+of\b"
    r"|\bcontains?\s+only\b|\bshows?\s+no\b|\bexcludes?\b"
    r"|\bno\s+indication\b|\bdid\s+not\s+contain\b"
    r"|\b(?:are|is|were|was)\s+absent\b|\babsent\s+from\b"
    # "we looked and it is nothing" — a value the belief itself dismisses.
    r"|\bnot\s+(?:an?\s+)?(?:attacker|malicious|adversary|threat)\b)"
)
# A dismissal: the belief looked at the value and calls it nothing. One the
# sentence negates ("does not appear benign", "cannot rule out") is the
# analyst's suspicion in the analyst's own words and reads as malice. A
# missed negator here would lose an indicator silently, so the negator is
# read widely: contractions, "cannot", "unable to", three words of gap,
# stopping at a conjunction ("was not blocked and is benign" dismisses).
_DISMISSAL_RE = re.compile(r"(?i)\bbenign\b|\bfalse\s+positives?\b|\brules?\s+out\b")
_DISMISSAL_NEGATOR = re.compile(
    r"(?i)(?:\b(?:not|no|never|nor|without|cannot)|n['’]t|\bunable\s+to)\s+(?!only\b)"
    r"(?:(?:a|an|the|any)\s+)?(?:(?!(?:and|but|or)\b)[\w/-]+\s+){0,3}$")
# An attack word the sentence negates ("not network exfiltration channels",
# "no C2 traffic") describes no attack: the analyst's clearing of a value
# used to attribute it on the strength of the very word being denied. Read
# narrowly, a negator within two words that stops at "and" and "but" ("was
# not blocked and exfiltrated data to X" asserts the exfiltration; "did not
# alert or exfiltrate" denies both): a missed negator on an attack word
# only adds a pivot, a negator read too widely would hide one.
_NEGATED = re.compile(
    r"(?i)\b(?:not|no|never|nor|without)\s+(?!only\b|doubt\b)"
    r"(?:(?:a|an|the|any)\s+)?(?:(?!(?:and|but)\b)[\w/-]+\s+){0,2}$")


def _negated_before(text: str, pos: int, negator: re.Pattern = _NEGATED) -> bool:
    return negator.search(text[max(0, pos - 60):pos]) is not None


def _asserted(rx: re.Pattern, text: str) -> bool:
    """Whether ``rx`` matches ``text`` somewhere the sentence does not negate."""
    return any(not _negated_before(text, m.start()) for m in rx.finditer(text))


def _dismissal(text: str) -> tuple[bool, bool]:
    """``(dismissed, suspicion)``: a dismissal the sentence asserts, and one
    it negates. Either may hold; an asserted dismissal wins."""
    dismissed = suspicion = False
    for m in _DISMISSAL_RE.finditer(text):
        if _negated_before(text, m.start(), _DISMISSAL_NEGATOR):
            suspicion = True
        else:
            dismissed = True
    return dismissed, suspicion
# Locations that make a binary interesting regardless of its name — this is
# the signal that generalises to tooling nobody has named yet.
_SUSPICIOUS_LOCATION_RE = re.compile(
    r"(?i)(\\users\\[^\\\s]+\\(?:downloads|desktop|documents)|"
    r"\\temp(?:\\|\b)|\\tmp(?:\\|\b)|\\appdata\\local\\temp|\\programdata\\|"
    r"\\inetcache|\\public\\|/tmp/|/dev/shm/|\\perflogs)"
)

# Frozen bootstrap seed. Its only job is cold start on a fresh install.
# It is NOT an encyclopedia and must not be grown by hand — new adversary
# tooling reaches Atlas through the Brain (adversary_tool_terms), learned
# from finished runs. A name here never makes something an IOC on its own;
# it only raises confidence in something behaviour already flagged.
_SEED_TOOL_TERMS = frozenset({
    "mimikatz", "mimidrv", "psexec", "procdump", "rclone", "cobaltstrike",
    "lazagne", "bloodhound", "sharphound", "adfind", "rubeus",
    "impacket", "winpeas", "seatbelt", "ngrok", "anydesk", "screenconnect",
    "teamviewer", "megacmd", "advanced_ip_scanner", "netcat", "plink",
})

# Software that is ordinary in isolation and only matters when behaviour
# says so (staging, exfiltration). Never promoted on the name alone, and
# never worth remembering as adversary tooling: knowing that an attacker
# used 7-Zip once teaches the next investigation nothing.
_DUAL_USE_TERMS = frozenset({
    "7-zip", "7zip", "7z", "winrar", "rsync", "curl", "wget", "certutil",
    "bitsadmin", "powershell", "cmd.exe", "wmic", "at.exe", "schtasks",
    "net.exe", "netsh", "reg.exe", "vssadmin", "wevtutil", "ftp",
})

_EXECUTABLE_RE = re.compile(
    r"(?i)\.(exe|dll|sys|ps1|bat|cmd|vbs|js|scr|jar|py|sh|elf|msi)$")
_ACCOUNT_PATH_RE = re.compile(r"(?i)[\\/]users[\\/]([^\\/\s]{2,64})[\\/]")
_HOME_PATH_RE = re.compile(r"(?i)[\\/]home[\\/]([^\\/\s]{2,64})[\\/]")
# "the tempadmin account", "user Jane.Doe" — but only when the token
# actually looks like a principal. The looser form of this rule harvested
# "user data" -> data and "account or" -> or.
# Only the token *after* the keyword. The mirrored form ("<word> account")
# harvested the preceding adjective — "encrypted user data" -> encrypted.
# The capture spans a backslash so "user EXAMPLE\jane.doe" is read
# whole; stopping at the separator harvested the *domain* as the principal.
_NAMED_USER_RE = re.compile(
    r"(?i)\b(?:account|user|username|principal)\s+"
    r"['\"]?([A-Za-z][\w.$\\-]{2,63})['\"]?")
# A principal is written like a name, not like ordinary prose. Quoted, or
# qualified (DOMAIN\user, first.last), or capitalised, or carrying a digit
# — anything else after "account"/"user" is the next English word, which is
# how "covert account creation" yielded `creation` and "Guest account via
# explorer.exe" yielded `via`. A bare lowercase token is accepted only when
# the statement writes it as a principal somewhere else (quoted, or
# qualified).
_PRINCIPAL_SHAPE_RE = re.compile(r"[A-Z0-9]|[.\\$_-]")


def written_as_principal(token: str, statement: str) -> bool:
    """True when `token` is written as a name rather than as ordinary prose.
    The one rule for every reader of principal names out of prose (this
    catalog, the DAIR candidate pivots, the report gate's account checks)."""
    if _PRINCIPAL_SHAPE_RE.search(token):
        return True
    esc = re.escape(token)
    return bool(re.search(r"(?i)['\"`]%s['\"`]|[\\/]%s\b" % (esc, esc), statement))

# Extensions that make a token genuinely a file. Without this check
# core.entities' filename shape (name.ext) claims "john.roe" and
# "example.com" as files. These are ordinary file types, not artifacts
# of any one incident — see ``_looks_like_file`` for encrypted names. One
# list, kept in core.entities.
from core.entities import FILE_EXTENSIONS as _KNOWN_FILE_EXT


def _looks_like_file(low: str) -> bool:
    """True when a ``name.ext`` token is really a filename.

    Ransomware renames keep the original extension and append their own:
    ``background.png.locked``, ``report.docx.WNCRY``. Judging by the
    extension *underneath* the appended one recognises every family without
    a list of family suffixes — such a list is stale by the next engagement
    and encodes one incident into the tool.
    """
    parts = low.split(".")
    if len(parts) < 2:
        return False
    if parts[-1] in _KNOWN_FILE_EXT:
        return True
    return len(parts) > 2 and parts[-2] in _KNOWN_FILE_EXT


@functools.lru_cache(maxsize=1)
def _tlds() -> frozenset[str]:
    """The delegated top-level domains from the vendored IANA list, plus
    the names the standards reserve beside it (the list's own trailing
    block); empty when the list is missing, which makes every dotted token
    a non-domain rather than every dotted token a domain."""
    path = Path(__file__).resolve().parents[1] / "share" / ".common" / "tlds.txt"
    try:
        entries = frozenset(
            line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#"))
    except OSError:
        entries = frozenset()
    if len(entries) < 1000:
        import sys
        print(f"atlas: the top-level domain list {path} is missing or short "
              f"({len(entries)} entries): domain and email indicators cannot be checked "
              "(restore share/.common/tlds.txt from the repository)", file=sys.stderr)
    return entries


def tld_list_missing() -> bool:
    return len(_tlds()) < 1000


# Usenet top-level hierarchies: a dotted token under one of them is a
# newsgroup when its last label is no top-level domain, or when a group cue
# governs the sentence and the hierarchy is not "news" (news.example.com is
# a news server). The cue words name groups, not servers.
_USENET_HIERARCHIES = frozenset({
    "alt", "comp", "rec", "sci", "soc", "talk", "news", "misc", "humanities",
    "free", "de", "uk", "fr", "it", "nl",
})
_NEWSGROUP_CUE_RE = re.compile(r"(?i)\b(?:newsgroups?|nachrichtengruppen?|group:)")
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)|\n")
# Special-use and private suffixes name the owner's own directory: an
# own-asset candidate, never attacker infrastructure, never an account.
_SPECIAL_USE_RE = re.compile(
    r"(?i)\.(?:local|localdomain|lan|internal|corp|home|home\.arpa|test|localhost)$")


def _url_host_ok(host: str) -> bool:
    """A URL's host is an address, or a name under a delegated or a
    special-use suffix; the file-name rules do not apply to it."""
    labels = host.split(".")
    return bool(host) and (_valid_ip(host) or _SPECIAL_USE_RE.search(host) is not None
                           or (len(labels) >= 2 and labels[-1] in _tlds()))


def _valid_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(value or "").strip("[]"))
        return True
    except ValueError:
        return False


def _cue_scopes(statement: str) -> list[tuple[int, int]]:
    """Spans a newsgroup cue governs: from the cue to the sentence end."""
    out = []
    for m in _NEWSGROUP_CUE_RE.finditer(statement):
        end = _SENTENCE_END_RE.search(statement, m.end())
        out.append((m.start(), end.start() if end else len(statement)))
    return out


def _dotted_kind(value: str, *, cued: bool = False) -> str:
    """What a dotted token is: ``file``, ``domain``, ``internal`` (a
    special-use name), ``newsgroup`` or ``""``. File-name rules run before
    the top-level-domain test because several extensions (md, py, zip, pf)
    are delegated domains too."""
    low = value.lower().strip(".")
    labels = low.split(".")
    if len(labels) < 2 or not labels[-1]:
        return ""
    if re.fullmatch(r"[\d.]+", low):
        return ""
    # A last label that is a file extension is a file, whatever the list
    # says about it. The extension underneath an appended one
    # ("report.docx.WNCRY") reads as a file only when the last label is no
    # delegated name: "node.js.org" is a host.
    if labels[-1] in _KNOWN_FILE_EXT:
        return "file"
    if len(labels) > 2 and labels[-2] in _KNOWN_FILE_EXT and labels[-1] not in _tlds():
        return "file"
    try:
        from core.artifact_value import artifact_score
        if artifact_score(value)[0] >= 55:
            return "file"
    except Exception:  # noqa: BLE001
        pass
    if _SPECIAL_USE_RE.search(low):
        return "internal"
    tld = labels[-1] in _tlds()
    hierarchy = labels[0] in _USENET_HIERARCHIES
    if (not tld and (cued or hierarchy)) or (tld and cued and hierarchy and labels[0] != "news"):
        return "newsgroup"
    return "domain" if tld else ""


def _host_of(value: str) -> str:
    """The host of a URL, an email address or a host:port form."""
    v = str(value or "").lower().strip()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/")[0].split("?")[0]
    v = v.rsplit("@", 1)[-1]
    if v.startswith("["):
        return v[1:].split("]")[0]
    return v.split(":")[0].rstrip(".")


def _has_term(term: str, low: str) -> bool:
    """A lexicon term matches whole tokens only: ``mimikatz`` is in
    ``mimikatz.exe`` and not in ``beaconing``."""
    return re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", low) is not None
# Ordinary English that follows "user"/"account" and is never a principal.
_NOT_A_PRINCIPAL = frozenset({
    "data", "share", "shares", "files", "file", "activity", "profile",
    "profiles", "accounts", "account", "interaction", "interactions",
    "directory", "directories", "folder", "folders", "name", "names",
    "context", "artifacts", "artifact", "and", "or", "on", "in", "the",
    "was", "were", "is", "are", "logon", "logons", "session", "sessions",
    # identifiers and attributes that follow "account" in an event summary:
    # "Account SID: S-1-5-…" yielded a principal called SID
    "sid", "rid", "guid", "uid", "gid", "pid", "id", "type", "status",
    "lockout", "password", "policy", "domain", "creation", "created",
    "deleted", "enabled", "disabled", "expires", "management", "control",
    # path segments that look like DOMAIN\user but are not, such as
    # "microsoft/user" from ProgramData\Microsoft\User Account Pictures
    "user", "users", "public", "default", "microsoft", "windows",
    "programdata", "system", "network", "local", "service",
})
# Path segments that are directories, not machines — they reach the host
# category only because a doubled backslash makes them look like UNC.
_NOT_A_HOST = frozenset({
    "users", "all", "windows", "shares", "share", "programdata", "temp",
    "downloads", "desktop", "documents", "public", "system32", "appdata",
    "program files", "winevt", "logs", "config",
})
# host:port as written in prose ("connects to relay.example.com:443").
_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,24})\b")
# Victim documents caught by ransomware are covered by the pattern IOC;
# listing them individually is the flood this module exists to prevent.
_VICTIM_DOC_RE = re.compile(
    r"(?i)\.(pdf|docx?|xlsx?|pptx?|odt|ods|jpe?g|png|gif|zip|rar|eml|msg)$")


def _normalize_statement(text: str) -> str:
    """Undo JSON-style escaping a model may leave in a statement.

    Doubled backslashes (``C:\\\\Users\\\\x``) hid a staging location from
    the role test; but collapsing them everywhere also turned a real UNC
    path (``\\\\srv01\\c$``) into a local one and lost the host. The
    same rule as core.entities.extract: collapse only when the text has no
    single backslash at all — then every pair is an escape.
    """
    text = str(text or "")
    if "\\\\" in text and not re.search(r"(?<!\\)\\(?!\\)", text):
        text = text.replace("\\\\", "\\")
    return text


_EXT_PATTERN_RE = re.compile(r"(?i)(?:^|[\s(])(\*?\.[a-z0-9]{2,8})\b")
_MASS_EFFECT_RE = re.compile(
    r"(?i)\b(multiple|mass|many|numerous|all\s+files|thousands|hundreds|"
    r"\d{3,}\s+files|bulk)\b")

_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)")

# Windows/vendor binaries that are expected on a healthy host. Present so a
# defensive agent's own driver is not reported as attacker tooling.
_KNOWN_DEFENSIVE_RE = re.compile(
    r"(?i)(crowdstrike|csagent|falcon|defender|msmpeng|sentinel|carbonblack|"
    r"cylance|sophos|mcafee|symantec|trendmicro|qualys|tanium|velociraptor)")

MAX_PER_CATEGORY = 60


@dataclass
class Ioc:
    category: str
    value: str
    role: str
    confidence: str = "SUSPECTED"
    explanation: str = ""
    why: list[str] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)
    call_ids: list[int] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    count: int = 1
    side: str = ""
    use: list[str] = field(default_factory=list)
    source: str = "prose"
    first_seen: str = ""
    last_seen: str = ""
    compromised: bool = False
    note: str = ""

    def key(self) -> tuple[str, str]:
        return (self.category, self.value.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category, "value": self.value, "role": self.role,
            "confidence": self.confidence, "explanation": self.explanation,
            "why": self.why[:4],
            "claim_ids": self.claim_ids, "call_ids": self.call_ids[:12],
            "hosts": self.hosts, "count": self.count,
            "side": self.side, "use": list(self.use), "source": self.source,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "compromised": self.compromised, "note": self.note,
        }


def _fold(target: Ioc, ioc: Ioc) -> None:
    """One more belief names the same indicator."""
    target.count += 1
    for cid in ioc.claim_ids:
        if cid not in target.claim_ids:
            target.claim_ids.append(cid)
    for cid in ioc.call_ids:
        if cid not in target.call_ids:
            target.call_ids.append(cid)
    for h in ioc.hosts:
        if h not in target.hosts:
            target.hosts.append(h)
    for w in ioc.why:
        if w not in target.why:
            target.why.append(w)
    if _CONFIDENCE_RANK.get(ioc.confidence, 0) > _CONFIDENCE_RANK.get(target.confidence, 0):
        target.confidence = ioc.confidence
    if _ROLE_ORDER.index(ioc.role) < _ROLE_ORDER.index(target.role):
        target.role = ioc.role
    if ioc.source == "typed" and target.source != "typed":
        target.source, target.side, target.use = ioc.source, ioc.side, list(ioc.use)
    target.first_seen = min(filter(None, (target.first_seen, ioc.first_seen)), default=target.first_seen)
    target.last_seen = max(filter(None, (target.last_seen, ioc.last_seen)), default=target.last_seen)
    target.compromised = target.compromised or ioc.compromised
    target.note = target.note or ioc.note


_EXEC_TYPES = frozenset({"file", "path", "hash"})


def _typed_role(side: str, kind: str, value: str, named: bool) -> str:
    """The catalog role of a typed row, from its side and type."""
    if side == "attacker":
        if kind in ("ip", "domain", "url", "email", "credential_id", "cloud_resource"):
            return ATTACKER_INFRA
        if kind == "account":
            return ATTACKER_ACCOUNT
        if kind == "host":
            return ATTACKER_HOST
        if kind == "pattern":
            return PATTERN
        if kind in _EXEC_TYPES and (named or _EXECUTABLE_RE.search(value)):
            return ATTACKER_TOOL
        return ATTACKER_FILE
    if side == "victim":
        return COMPROMISED_HOST if kind == "host" else AFFECTED_ASSET
    if side == "subject":
        return SUBJECT_IDENTIFIER
    return THIRD_PARTY


_USE_RANK = {u: i for i, u in enumerate(("block", "contain", "hunt", "request", "identify", "scope", "review"))}


def _typed_value_forms(rows: list[dict[str, Any]]) -> set[str]:
    """Every lower-cased form a typed row's value takes in prose: the value,
    a path's file name and profile name, a URL's or address's host, an
    ip:port's address. A prose candidate equal to one of them repeats the
    typed row instead of asking for a review of its own."""
    out: set[str] = set()
    for r in rows:
        v = str(r.get("value") or "").lower()
        if not v:
            continue
        out.add(v)
        kind = str(r.get("type") or "")
        if kind in ("path", "file"):
            norm = v.replace("\\", "/")
            parts = [x for x in norm.split("/") if x]
            if parts:
                out.add(parts[-1])
            m = re.search(r"/(?:users|home|documents and settings)/([^/]+)/", norm)
            if m:
                out.add(m.group(1))
        if kind in ("url", "email", "domain", "ip"):
            out.add(_host_of(v))
    return out


def _sort_key(i: Ioc) -> tuple:
    return (min((_USE_RANK.get(u, 9) for u in i.use), default=9),
            _ROLE_ORDER.index(i.role) if i.role in _ROLE_ORDER else 99,
            -_CONFIDENCE_RANK.get(i.confidence, 0), -i.count, i.value.lower())


# ── the living lexicon ───────────────────────────────────────────────────

def adversary_tool_terms(*, include_seed: bool = True) -> set[str]:
    """Known adversary tooling: the frozen seed plus whatever the Brain has
    learned from finished runs.

    The Brain half is what keeps this from rotting. A Brain that is empty,
    unreachable or never reviewed simply yields the seed, and behaviour-first
    detection carries the load.
    """
    terms = set(_SEED_TOOL_TERMS) if include_seed else set()
    try:
        from core.brain import store as _brain_store
        notes = getattr(_brain_store, "iter_notes", None)
        if callable(notes):
            for note in notes():
                meta = getattr(note, "meta", None) or {}
                if str(meta.get("type") or "") != "adversary_tool":
                    continue
                if str(meta.get("status") or "active") != "active":
                    continue
                for name in (meta.get("entities") or {}).get("tools") or []:
                    token = str(name or "").strip().lower()
                    if 2 < len(token) < 64:
                        terms.add(token)
    except Exception:  # noqa: BLE001 - the Brain must never break a catalog
        pass
    return terms


# ── context scoring ──────────────────────────────────────────────────────

def _window(text: str, needle: str, width: int = 140) -> str:
    low, target = text.lower(), needle.lower()
    i = low.find(target)
    if i < 0:
        return text[:width * 2]
    return text[max(0, i - width): i + len(target) + width]


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
_LEADING_NOISE_RE = re.compile(
    r"(?i)^(?:and|but|also|then|this|that|it|which|the|a|an|is|was|were|"
    r"are|has|have|had)\s+")

MAX_EXPLANATION = 72


# What the belief says happened, in the reader's words. Matched against the
# sentence around the indicator and rendered as a phrase.
_ACTION_PHRASES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\binstalled\b.*\b(?:service|driver)\b"), "installed as a service"),
    (re.compile(r"(?i)\bkernel driver\b"), "kernel driver loaded"),
    (re.compile(r"(?i)\binstalled\b"), "installed"),
    (re.compile(r"(?i)\bconnects?\s+to\b|\brelay\b|\bc2\b"), "contacted as remote endpoint"),
    (re.compile(r"(?i)\bexfiltrat"), "linked to exfiltration"),
    (re.compile(r"(?i)\bencrypt"), "used in file encryption"),
    (re.compile(r"(?i)\bstag(?:ed|ing)\b|\barchiv"), "possible staging for exfiltration"),
    (re.compile(r"(?i)\blateral\s+movement\b"), "lateral movement tooling"),
    (re.compile(r"(?i)\bcredential\s+(?:dump|theft|harvest)|mimikatz"), "credential dumping"),
    (re.compile(r"(?i)\bprivilege\s+escalation\b|\bbyovd\b|vulnerable driver"),
     "privilege escalation / BYOVD"),
    (re.compile(r"(?i)\bexecut(?:ed|ion)\b|\bran\b|userassist"), "executed on the host"),
    (re.compile(r"(?i)\bcreated\b"), "created during the incident"),
    (re.compile(r"(?i)\bdropped\b"), "dropped on the host"),
    (re.compile(r"(?i)\bdownloads?\b"), "found in a user download folder"),
)

# Which action phrases can truthfully be said about each kind of indicator.
# An account is not "installed"; a domain is not "a kernel driver".
_PHRASES_BY_ROLE: dict[str, set[str]] = {
    ATTACKER_ACCOUNT: {
        "created during the incident", "linked to exfiltration",
        "credential dumping",
    },
    ATTACKER_INFRA: {
        "contacted as remote endpoint", "linked to exfiltration",
    },
    PATTERN: {"used in file encryption", "linked to exfiltration"},
    COMPROMISED_HOST: {
        "executed on the host", "lateral movement tooling",
        "linked to exfiltration", "used in file encryption",
    },
}

_ROLE_FALLBACK = {
    ATTACKER_TOOL: "attacker tooling",
    ATTACKER_INFRA: "attacker-controlled endpoint",
    ATTACKER_ACCOUNT: "account involved in attacker activity",
    ATTACKER_FILE: "file linked to attacker activity",
    PATTERN: "signature of the attack",
    COMPROMISED_HOST: "host implicated in the activity",
}


# How far a verb can sit from an entity and still be about it.
_ATTRIBUTION_RADIUS = 110


def _spans(text: str, needle: str) -> list[tuple[int, int]]:
    low, target = text.lower(), needle.lower()
    out, i = [], low.find(target)
    while i >= 0:
        out.append((i, i + len(target)))
        i = low.find(target, i + 1)
    return out


def _gap(spans: list[tuple[int, int]], span: tuple[int, int]) -> Optional[int]:
    """Smallest character distance between any of `spans` and `span`."""
    best = None
    for a, b in spans:
        d = 0 if a < span[1] and b > span[0] else min(abs(a - span[1]),
                                                      abs(span[0] - b))
        if best is None or d < best:
            best = d
    return best


def _paren_spans(text: str) -> list[tuple[int, int]]:
    """Balanced ``(...)`` regions — asides that bind to what precedes them."""
    out, stack = [], []
    for i, ch in enumerate(text):
        if ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            out.append((stack.pop(), i + 1))
    return out


def _same_clause(text: str, a: tuple[int, int], b: tuple[int, int]) -> bool:
    """False when a parenthetical separates the two spans.

    "The 'tempadmin' account on HOST01 (created by user01) attempted
    logon ... targeting HOST01\\Guest account" — the verb lives inside an aside
    about tempadmin, so proximity alone made Guest read as "created during the
    incident". An aside binds to what it interrupts, never across itself.
    """
    for lo, hi in _paren_spans(text):
        inside_a = lo <= a[0] and a[1] <= hi
        inside_b = lo <= b[0] and b[1] <= hi
        if inside_a != inside_b:
            return False
    return True


def _owns_action(text: str, pattern: re.Pattern, value: str,
                 rivals: list[str]) -> bool:
    """True when `value` is the entity the verb is actually about.

    A belief names several entities and one action. Without this every entity
    in the sentence inherited the verb, so "New local account 'tempadmin' was
    created ... by domain user EXAMPLE\\user01" listed
    user01 as "created during the incident" as well — that account did the
    creating. The verb belongs to whichever named entity sits closest to it,
    which needs no grammar and holds for both active and passive phrasing.
    """
    own = _spans(text, value)
    if not own:
        return True     # value is derived, not quoted — position says nothing
    rival_spans = [(_spans(text, r)) for r in rivals]
    for m in pattern.finditer(text):
        mine = _gap(own, m.span())
        if mine is None or mine > _ATTRIBUTION_RADIUS:
            continue
        if not any(_same_clause(text, sp, m.span()) for sp in own):
            continue
        theirs = [_gap(rs, m.span()) for rs in rival_spans if rs]
        if all(t is None or mine <= t for t in theirs):
            return True
    return False


def _explain(value: str, statement: str, role: str, why: list[str],
             siblings: Sequence[str] = ()) -> str:
    """A short, always-grammatical reason this indicator is listed.

    Built from what the belief says *happened* plus the indicator's role.
    An earlier version sliced the sentence and removed the indicator from
    it, which produced fragments like "(imagePath)" and unbalanced
    parentheses — the value is already on the line, so the reader needs the
    meaning, not the leftovers.
    """
    text = _normalize_statement(statement)
    context = _window(text, value, width=_ATTRIBUTION_RADIUS)
    # Phrases describe an *action on a thing*; which actions can sensibly
    # apply depends on what the indicator is. Without this, the driver
    # sentence around an ImagePath made the account read
    # "tempadmin (installed as a service)".
    allowed = _PHRASES_BY_ROLE.get(role)
    # `psexec` / `psexec64.exe` and `driverx` / `driverx.sys` are one thing
    # written two ways, not competitors — their spans overlap, so letting them
    # rival each other robbed the fuller name of its own verb.
    low = value.lower()
    rivals = [v for v in siblings
              if v.lower() != low
              and v.lower() not in low and low not in v.lower()]
    phrases: list[str] = []
    for pattern, phrase in _ACTION_PHRASES:
        if allowed is not None and phrase not in allowed:
            continue
        if phrase in phrases or not pattern.search(context):
            continue
        # ...and the verb has to be about *this* entity, not a bystander.
        if not _owns_action(text, pattern, value, rivals):
            continue
        if any(phrase in q or q in phrase for q in phrases):
            continue          # "installed as a service, installed"
        phrases.append(phrase)
        if len(phrases) == 2:
            break
    if not phrases:
        phrases = [_ROLE_FALLBACK.get(role, "linked to attacker activity")]
    if "known adversary tooling" in why and role == ATTACKER_TOOL:
        phrases.append("known offensive tool")
    text = ", ".join(phrases[:2])
    return text[:MAX_EXPLANATION]


def _statement_is_usable(node: dict) -> bool:
    """Beliefs that describe the investigation rather than the incident are
    not indicator sources."""
    if str(node.get("status") or "") in ("superseded", "withdrawn"):
        return False
    if str(node.get("report_role") or "") in ("gap", "process"):
        return False
    statement = str(node.get("statement") or "")
    if not statement.strip():
        return False
    try:
        from core.answer_synthesis import GAP, classify_statement
        if classify_statement(statement) == GAP:
            return False
    except Exception:  # noqa: BLE001
        pass
    return True


def _role_for(value: str, category: str, context: str,
              tool_terms: set[str]) -> tuple[Optional[str], list[str]]:
    """Decide what this indicator *is*, from the sentence around it."""
    if _NEGATIVE_RE.search(context):
        return None, []          # asserted absence — nothing here is an IOC
    dismissed, suspicion = _dismissal(context)
    if dismissed:
        return None, []          # a value the belief itself dismisses
    why: list[str] = []
    action = _asserted(_ATTACK_ACTION_RE, context)
    malice = _asserted(_MALICE_RE, context) or suspicion
    location = bool(_SUSPICIOUS_LOCATION_RE.search(context))
    low = value.lower()
    named = any(_has_term(t, low) for t in tool_terms)

    if action:
        why.append("attacker action described")
    if malice:
        why.append("dismissal negated by the analyst" if suspicion
                   and not _asserted(_MALICE_RE, context) else "malicious characterisation")
    if location:
        why.append("non-standard location")
    if named:
        why.append("known adversary tooling")

    if category == "ip":
        if not (action or malice):
            return None, []
        why.append("internal address" if _PRIVATE_IP_RE.match(value)
                   else "external address")
        return ATTACKER_INFRA, why
    if category in ("domain", "url", "email"):
        if _SPECIAL_USE_RE.search(_host_of(low)):
            return None, []      # the owner's own directory name
        return (ATTACKER_INFRA, why) if (action or malice) else (None, [])
    if category == "account":
        return (ATTACKER_ACCOUNT, why) if (action or malice) else (None, [])
    if category == "host":
        return (COMPROMISED_HOST, why) if (action or malice) else (None, [])
    if category == "hash":
        return (ATTACKER_FILE, why) if (action or malice) else (None, [])
    if category == "pattern":
        return PATTERN, why or ["mass-effect signature"]
    if category == "file":
        if _KNOWN_DEFENSIVE_RE.search(value) or _KNOWN_DEFENSIVE_RE.search(context):
            return None, []      # the defender's own agent is not an IOC
        executable = bool(_EXECUTABLE_RE.search(value)) or named
        # Corroboration beyond the sentence's framing is required of every
        # executable, not just of a listed set of ordinary ones. A belief
        # that describes attacker activity makes *every* binary it names
        # look implicated: a UserAssist claim that lists the ordinary programs
        # a user ran (mstsc.exe, taskmgr.exe, ...) would promote the whole
        # Windows shell. The alternative — enumerating the binaries that ship
        # with the OS — is a list that is never complete and never current.
        # "The attacker ran X" is also not something a responder can
        # act on; malice or a staging location is. A lexicon name never
        # promotes on its own: it only makes a corroborated file a tool.
        if executable and (malice or location):
            return ATTACKER_TOOL, why
        if malice or (action and location):
            return ATTACKER_FILE, why
        return None, []
    return None, []


def _confidence_for(node_conf: Any) -> str:
    """Never exceed the belief's own confidence; a name match may not
    promote a SUSPECTED belief to CONFIRMED."""
    base = str(node_conf or "SUSPECTED").upper()
    return base if base in _CONFIDENCE_RANK else "SUSPECTED"


# ── candidate harvesting ─────────────────────────────────────────────────

def _candidates(statement: str, tool_terms: set[str]) -> list[tuple[str, str]]:
    """(category, value) pairs mentioned by one belief."""
    statement = _normalize_statement(statement)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    scopes = _cue_scopes(statement)
    low_statement = statement.lower()

    def cued(low: str) -> bool:
        i = low_statement.find(low)
        return i >= 0 and any(a <= i < b for a, b in scopes)

    def add(cat: str, val: str) -> None:
        val = (val or "").strip().strip(".,;:)('\"")
        if not val or len(val) > 200:
            return
        low = val.lower()
        if cat == "account" and _SPECIAL_USE_RE.search(low):
            cat = "domain"           # a directory name written like a principal
        if cat == "account" and (low in _NOT_A_PRINCIPAL or low in _NOT_A_HOST
                                 or len(low) < 3):
            return
        if cat == "host" and low in _NOT_A_HOST:
            return
        if cat == "file" and "." in low:
            # A name.ext shape is not enough: a dotted token is a file, a
            # domain, an internal name, a newsgroup or a person-style name.
            kind = _dotted_kind(low, cued=cued(low))
            if kind in ("domain", "internal"):
                cat = "domain"
            elif kind != "file":
                return
        elif cat == "domain":
            host_part = _host_of(low)
            if "://" in low:
                if not _url_host_ok(host_part):
                    return
            else:
                kind = _dotted_kind(host_part, cued=cued(host_part))
                if kind == "file" and host_part == low:
                    cat = "file"         # a renamed document the domain shape caught
                elif kind not in ("domain", "internal"):
                    return
        elif cat == "email":
            if _dotted_kind(low.rsplit("@", 1)[-1]) != "domain":
                return
        k = (cat, low)
        if k not in seen:
            seen.add(k)
            out.append((cat, val))

    try:
        from core.entities import extract
        for ent in extract(statement):
            kind, _, value = ent.partition(":")
            if not value:
                continue
            if kind == "ip":
                add("ip", value)
            elif kind == "host":
                add("host", value)
            elif kind == "account":
                # DOMAIN\user only when the left part could be a domain: a
                # directory name in that position is a path, not a principal.
                dom = value.split("/")[0].lower() if "/" in value else ""
                if dom and (dom in _NOT_A_HOST or dom in _NOT_A_PRINCIPAL):
                    continue
                add("account", value.split("/")[-1])
            elif kind == "email":
                add("email", value)
            elif kind == "url":
                add("domain", value)
            elif kind == "file":
                add("file", value)
            elif kind in ("md5", "sha1", "sha256"):
                add("hash", value)
    except Exception:  # noqa: BLE001
        pass

    # Accounts are usually implied by a path, not written as DOMAIN\user.
    for rx in (_ACCOUNT_PATH_RE, _HOME_PATH_RE):
        for m in rx.finditer(statement):
            add("account", m.group(1))
    for m in _NAMED_USER_RE.finditer(statement):
        token = (m.group(1) or "").rstrip("\\").split("\\")[-1]
        if token and written_as_principal(token, statement):
            add("account", token)

    # Domains written in prose, including host:port forms that are not URLs.
    for m in _DOMAIN_RE.finditer(statement):
        add("domain", m.group(1))

    # Tool names that appear as words rather than filenames ("Mimikatz
    # driver", "an Rclone upload").
    for term in tool_terms:
        if _has_term(term, low_statement):
            add("file", term)

    # A mass-effect statement contributes one pattern, never its members.
    if _MASS_EFFECT_RE.search(statement):
        for m in _EXT_PATTERN_RE.finditer(statement):
            ext = m.group(1)
            if not ext.lower().endswith((".exe", ".dll", ".sys")):
                add("pattern", ext if ext.startswith("*") else "*" + ext)
    return out


def _suppressed(category: str, value: str) -> bool:
    """Case-derived suppression: our own evidence and outputs."""
    low = value.lower()
    if category == "ip" and re.match(r"^(?:0\.|127\.|255\.|169\.254\.)", low):
        return True
    if category in ("file", "pattern"):
        try:
            from core.artifact_value import artifact_score
            # A forensic artifact we parsed is evidence, not an indicator;
            # an executable never is one (a deleted binary's Recycle Bin
            # record is named like a record and is still a binary).
            if artifact_score(value)[0] >= 55 and not _EXECUTABLE_RE.search(low):
                return True
        except Exception:  # noqa: BLE001
            pass
        if re.search(r"(?i)\.(csv|json|jsonl|md|txt|log|db)$", low):
            return True
        # A user document that ransomware encrypted is a victim, not an
        # indicator — the "*.locked" pattern already carries that fact, and
        # enumerating them is precisely the flood this module prevents.
        if _VICTIM_DOC_RE.search(low):
            return True
        # NTFS/OS structures named in a timeline are observations, not drops.
        if low.lstrip("$") in ("recycle.bin", "mft", "logfile", "extend",
                               "usnjrnl", "boot", "ntds.dit", "sam", "system",
                               "software", "security"):
            return True
    return False


# ── the catalog ──────────────────────────────────────────────────────────

def _not_exported(refused: list[dict[str, Any]], *buckets: dict[tuple[str, str], Ioc]) -> list[dict[str, Any]]:
    """The refused rows still owed to the reader, one per value with every
    finding that typed it. A value the catalog lists anyway (typed by another
    belief under any type, or read from a belief's wording) is left out, as
    is one whose suggested digest is listed and a hash within two edits of
    a listed one (the slip it was)."""
    from core.indicators import within_edits
    listed = {i.value.lower() for b in buckets for i in b.values()}
    hashes = [i.value.lower() for b in buckets for i in b.values() if i.category == "hash"]
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for r in refused:
        key = (r["category"], r["value"].lower())
        if (key[1] in listed or (r["suggested"] and r["suggested"].lower() in listed)
                or (r["category"] == "hash" and any(within_edits(key[1], h) is not None for h in hashes))):
            continue
        prev = rows.get(key)
        if prev is None:
            rows[key] = dict(r)
            continue
        prev["claim_ids"] += [c for c in r["claim_ids"] if c not in prev["claim_ids"]]
        prev["finding_call_ids"] += [c for c in r["finding_call_ids"]
                                     if c not in prev["finding_call_ids"]]
        prev["hosts"] += [h for h in r["hosts"] if h not in prev["hosts"]]
        if r["confidence"] in ("CONFIRMED", "LIKELY"):
            prev["confidence"] = r["confidence"]
    return list(rows.values())


def build_catalog(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Curated indicators for a case, derived purely from recorded beliefs.

    Deterministic, side-effect free and safe to call at any point in a run:
    a half-finished claim graph simply yields a smaller catalog. Typed rows
    (stated by the analyst at record time, checked against the cited
    output) are the actionable list; every value parsed from a belief's
    prose is a review row, never a block item; a value that is one of the
    case's own assets is an affected asset (incident frame) or a subject
    identifier (subject frame), whatever the prose says about it.
    """
    from core.indicators import frame_for, rows_of, use_for
    try:
        from core.claim_graph import load_graph
        nodes = list((load_graph(case_dir).get("nodes") or {}).values())
    except Exception:  # noqa: BLE001
        nodes = []
    try:
        from core.own_assets import lookup, own_assets
        assets = own_assets(case_dir)
    except Exception:  # noqa: BLE001
        assets, lookup = {"values": {}, "hosts": []}, (lambda *_a, **_k: None)
    frame = frame_for(case_dir)
    own_side = "subject" if frame == "subject" else "victim"
    tool_terms = adversary_tool_terms()

    actionable: dict[tuple[str, str], Ioc] = {}
    review: dict[tuple[str, str], Ioc] = {}
    affected: dict[tuple[str, str], Ioc] = {}
    refused: list[dict[str, Any]] = []

    def place(ioc: Ioc) -> None:
        bucket = (affected if ioc.side == own_side and ioc.role in (AFFECTED_ASSET, COMPROMISED_HOST, SUBJECT_IDENTIFIER) and frame != "subject"
                  else affected if (frame == "subject" and ioc.side == "subject" and ioc.source == "prose")
                  else review if ioc.source == "prose"
                  else actionable)
        prev = bucket.get(ioc.key())
        if prev is None:
            bucket[ioc.key()] = ioc
        else:
            _fold(prev, ioc)

    for node in nodes:
        if not isinstance(node, dict) or node.get("status") in ("superseded", "withdrawn"):
            continue
        if node.get("kind") == "observation":
            continue          # a reading (the system baseline) names no indicator
        prose_usable = _statement_is_usable(node)
        statement = _normalize_statement(str(node.get("statement") or ""))
        node_id = str(node.get("id") or "")
        host = str(node.get("host") or "")
        call_ids = [c for c in (node.get("input_call_ids") or []) if isinstance(c, int)]
        src = node.get("source_finding_call_id")
        if isinstance(src, int):
            call_ids = [src] + call_ids
        conf = _confidence_for(node.get("confidence"))

        typed = rows_of(node)
        typed_values = _typed_value_forms(typed)
        for r in typed:
            value, kind, side = str(r["value"]), str(r["type"]), str(r.get("side") or "")
            named = any(_has_term(t, value.lower()) for t in tool_terms)
            role = _typed_role(side, kind, value, named)
            why = ["stated by the analyst"] + (["known adversary tooling"] if named else [])
            if r.get("compromised"):
                why.append("used by the attacker")
            place(Ioc(category=kind, value=value, role=role, confidence=conf,
                      explanation=_explain(value, statement, role, why, [value]) if role in _ROLE_FALLBACK else str(r.get("note") or ""),
                      why=why, claim_ids=[node_id] if node_id else [], call_ids=call_ids[:12],
                      hosts=[host] if host else [], side=side,
                      use=use_for(frame, side, kind, value), source="typed",
                      first_seen=str(r.get("first_seen") or ""), last_seen=str(r.get("last_seen") or ""),
                      compromised=bool(r.get("compromised")), note=str(r.get("note") or "")))

        # Typed rows refused at record time: listed as not exported, never
        # as an indicator.
        for d in (node.get("indicators_dropped") or []) if node.get("kind") in ("claim", "conclusion") else []:
            if isinstance(d, dict) and d.get("value"):
                refused.append({"value": str(d["value"]), "category": str(d.get("type") or ""),
                                "reason": str(d.get("reason") or ""),
                                "refusal": str(d.get("refusal") or ""),
                                "suggested": str(d.get("suggested") or ""),
                                "claim_ids": [node_id] if node_id else [],
                                "finding_call_ids": [src] if isinstance(src, int) else [],
                                "hosts": [host] if host else [],
                                "confidence": str(node.get("confidence") or "").upper()})
        if not prose_usable:
            continue
        cands = [(c, v) for c, v in _candidates(statement, tool_terms)
                 if not _suppressed(c, v) and v.lower() not in typed_values
                 and _host_of(v) not in typed_values
                 and (frame != "subject" or c in ("email", "hash", "account", "ip", "domain"))]
        siblings = [v for _c, v in cands]
        for category, value in cands:
            probe = _host_of(value) if category in ("domain", "email") else value
            own = lookup(assets, probe, category if category in ("ip", "host", "account") else "")
            if own:
                role = COMPROMISED_HOST if category == "host" and frame != "subject" else (
                    SUBJECT_IDENTIFIER if frame == "subject" else AFFECTED_ASSET)
                place(Ioc(category=category, value=value, role=role, confidence=conf,
                          explanation="own asset named in the finding", why=["own asset"],
                          claim_ids=[node_id] if node_id else [], call_ids=call_ids[:12],
                          hosts=[own.get("host") or host] if (own.get("host") or host) else [],
                          side=own_side, use=["identify"] if frame == "subject" else ["scope"],
                          source="prose"))
                continue
            if frame == "subject":
                # no attacker side to read verbs for: an account on the device
                # is the subject's, anything else names a third party
                role = SUBJECT_IDENTIFIER if category == "account" else THIRD_PARTY
                place(Ioc(category=category, value=value, role=role, confidence=conf,
                          explanation="named in the finding", why=["named in the finding"],
                          claim_ids=[node_id] if node_id else [], call_ids=call_ids[:12],
                          hosts=[host] if host else [],
                          side="subject" if category == "account" else "third_party",
                          use=["review"], source="prose"))
                continue
            role, why = _role_for(value, category, _window(statement, value), tool_terms)
            if not role:
                continue
            place(Ioc(category=category, value=value, role=role, confidence=conf,
                      explanation=_explain(value, statement, role, why, siblings),
                      why=why, claim_ids=[node_id] if node_id else [], call_ids=call_ids[:12],
                      hosts=[host] if host else [], side="attacker",
                      use=["review"], source="prose"))

    # "Jane" and "Jane.Doe" are one principal seen two ways; the fuller
    # form wins and the fragment is folded into it.
    for bucket in (actionable, review, affected):
        for key in list(bucket):
            cat, low = key
            if cat != "account" or key not in bucket:
                continue
            fuller = next((k for k in bucket if k[0] == "account" and k[1] != low
                           and k[1].startswith((low + ".", low + "_", low + "-"))), None)
            if fuller:
                _fold(bucket[fuller], bucket[key])
                del bucket[key]

    # A value typed in one belief and written in another's prose is one
    # indicator: the prose sighting joins the typed row instead of asking
    # for a review of its own.
    for key in list(review):
        target = actionable.get(key) or affected.get(key)
        if target is not None:
            _fold(target, review.pop(key))
    not_exported = _not_exported(refused, actionable, affected, review)
    iocs = sorted(actionable.values(), key=_sort_key)
    review_rows = sorted(review.values(), key=_sort_key)
    affected_rows = sorted(affected.values(), key=_sort_key)
    by_role: dict[str, list[dict[str, Any]]] = {}
    for ioc in iocs:
        bucket = by_role.setdefault(ioc.role, [])
        if len(bucket) < MAX_PER_CATEGORY:
            bucket.append(ioc.to_dict())
    by_use: dict[str, int] = {}
    for ioc in iocs:
        for u in ioc.use:
            by_use[u] = by_use.get(u, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "frame": frame,
        "own_asset_basis": ("evidence links, graph hosts, brief tables, appositions"
                            + ("" if any("baseline" in e.get("sources", []) for e in assets["values"].values())
                               else "; P0 baseline pending")),
        "own_hosts": list(assets.get("hosts") or []),
        "counts": {r: len(v) for r, v in by_role.items()},
        "by_use": by_use,
        "total": len(iocs),
        "review_total": len(review_rows),
        "affected_total": len(affected_rows),
        "beliefs_considered": len(nodes),
        "by_role": by_role,
        "iocs": [i.to_dict() for i in iocs],
        "review": [i.to_dict() for i in review_rows],
        "not_exported": not_exported,
        "not_exported_total": len(not_exported),
        "affected_assets": [i.to_dict() for i in affected_rows],
        "tld_list_missing": tld_list_missing(),
    }


_ROLE_TITLES = {
    ATTACKER_TOOL: "Attacker tooling",
    ATTACKER_INFRA: "Attacker infrastructure",
    ATTACKER_HOST: "Attacker hostnames",
    ATTACKER_ACCOUNT: "Accounts used or created by the attacker",
    ATTACKER_FILE: "Malicious / dropped files",
    PATTERN: "Signatures and patterns",
    COMPROMISED_HOST: "Hosts implicated in attacker activity",
    AFFECTED_ASSET: "The owner's own assets named in the findings",
    SUBJECT_IDENTIFIER: "Identifiers of the person under investigation",
    THIRD_PARTY: "Third-party identifiers",
}

_USE_TITLES = {
    "block": "Block at the perimeter",
    "contain": "Contain: disable or isolate",
    "hunt": "Hunt across the estate",
    "request": "Request from the provider, through counsel or law enforcement: preservation, takedown or legal process",
    "identify": "Identify",
    "scope": "Scope: the owner's own assets the activity touched",
    "review": "Review before use",
}
_USE_ORDER = ("block", "contain", "hunt", "request", "identify", "scope")
_FRAME_LINES = {
    "incident": "Frame: incident on the owner's systems. Attacker rows are block and hunt items; the owner's own assets are listed under Scope, never as block items.",
    "subject": "Frame: examination of the device of the person under investigation. There is no attacker side to block; the rows are the case's key identifiers, and provider-held resources carry a preservation request.",
}

# The deliverable groups by what a responder searches on — a hostname is a
# hostname whether the machine was the attacker's or a victim's; the role
# and the explanation carry that distinction inside the line.
GROUP_ORDER: list[tuple[str, str]] = [
    ("tools", "Tools"),
    ("account", "Usernames"),
    ("host", "Hostnames"),
    ("domain", "Domains"),
    ("ip", "IP addresses"),
    ("file", "Files"),
    ("hash", "Hashes"),
    ("pattern", "Patterns"),
]


def group_for(ioc: dict[str, Any]) -> str:
    """Which heading an indicator belongs under."""
    if ioc.get("role") == ATTACKER_TOOL:
        return "tools"
    category = str(ioc.get("category") or "")
    if category in ("domain", "email", "url"):
        return "domain"
    return category if category in dict(GROUP_ORDER) else "file"


def grouped(catalog: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    """``[(heading, rows)]`` in deliverable order, empty groups dropped;
    the affected assets and the review rows follow as groups of their own."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for ioc in catalog.get("iocs") or []:
        buckets.setdefault(group_for(ioc), []).append(ioc)
    out = [(title, buckets[key]) for key, title in GROUP_ORDER if buckets.get(key)]
    if catalog.get("affected_assets"):
        out.append(("Subject and third-party identifiers" if catalog.get("frame") == "subject"
                    else "Affected assets", list(catalog["affected_assets"])))
    if catalog.get("review"):
        out.append(("Review before use", list(catalog["review"])))
    return out


def _table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> list[str]:
    lines = ["| " + " | ".join(h for h, _k in columns) + " |",
             "|" + "|".join("---" for _ in columns) + "|"]
    for r in rows:
        cells = []
        for _h, k in columns:
            v = r.get(k)
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            cells.append(str(v or "").replace("|", "\\|"))
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def _not_exported_lines(catalog: dict[str, Any]) -> list[str]:
    """The rows typed for a finding but refused when it was recorded: in no
    list above and never in the CSV, listed so the reader knows of them."""
    rows = catalog.get("not_exported") or []
    if not rows:
        return []
    return (["## Not exported", "",
             "Named by the analyst for a finding but refused when it was recorded (malformed, "
             "or not shown by the calls the finding cites): in no list above and never in the "
             "CSV.", ""]
            + _table(rows, [("Value", "value"), ("Type", "category"),
                            ("Why it was refused", "reason"), ("Finding", "claim_ids")]) + [""])


def render_markdown(catalog: dict[str, Any], *, case_id: str = "") -> str:
    """The deliverable: a list a responder can act on, with provenance."""
    frame = catalog.get("frame") or "incident"
    lines = [f"# Indicators — {case_id}".rstrip(), "",
             _FRAME_LINES.get(frame, _FRAME_LINES["incident"]),
             f"Own-asset basis: {catalog.get('own_asset_basis') or 'none'}.",
             "Verify ownership before deploying a block item.", ""]
    iocs = catalog.get("iocs") or []
    review = catalog.get("review") or []
    affected = catalog.get("affected_assets") or []
    if catalog.get("tld_list_missing"):
        lines += ["Warning: the top-level domain list is missing, so domain and email rows could not be "
                  "checked (restore share/.common/tlds.txt from the repository).", ""]
    if not (iocs or review or affected):
        lines += ["No indicators were attributed to attacker activity.", "",
                  "This is a statement about the recorded beliefs, not about "
                  "the evidence: indicators are derived only from findings "
                  "the investigation actually recorded.", ""]
        return "\n".join(lines + _not_exported_lines(catalog))
    lines += [f"{len(iocs)} typed indicator(s), {len(affected)} own asset(s) and "
              f"{len(review)} prose-derived candidate(s) from "
              f"{catalog.get('beliefs_considered', 0)} recorded belief(s). Every row cites the "
              "claim it came from; nothing here is inferred from raw tool output.", ""]
    cols = [("Value", "value"), ("Type", "category"), ("Side", "side"), ("Confidence", "confidence"),
            ("First seen", "first_seen"), ("Last seen", "last_seen"), ("Host", "hosts"),
            ("Finding", "claim_ids")]
    if frame == "subject":
        # the sides apart: the subject's own identifiers, the people the
        # material names, third parties; then what a provider holds
        for title, sides in (("Identifiers of the person under investigation", ("subject",)),
                             ("Victims and named targets", ("victim",)),
                             ("Third parties and other devices", ("third_party", "attacker"))):
            rows = [r for r in iocs if r.get("side") in sides]
            if rows:
                lines += [f"## {title}", ""] + _table(rows, cols) + [""]
        rows = [r for r in iocs if "request" in (r.get("use") or [])]
        if rows:
            lines += [f"## {_USE_TITLES['request']}", ""] + _table(rows, cols) + [""]
        rows = [r for r in iocs if "hunt" in (r.get("use") or [])]
        if rows:
            lines += [f"## {_USE_TITLES['hunt']}", ""] + _table(rows, cols) + [""]
    else:
        for use in _USE_ORDER:
            rows = [r for r in iocs if use in (r.get("use") or [])]
            if rows:
                lines += [f"## {_USE_TITLES[use]}", ""] + _table(rows, cols) + [""]
        third = [r for r in iocs if r.get("use") == ["review"] and r.get("source") == "typed"]
        if third:
            lines += ["## Third-party identifiers", "",
                      "Stated by the analyst for a party that is neither the attacker nor the owner.", ""]
            lines += _table(third, cols) + [""]
    if affected:
        lines += [f"## {'Subject and third-party identifiers' if frame == 'subject' else 'Affected assets'}", ""]
        lines += _table(affected, [("Value", "value"), ("Type", "category"), ("Host", "hosts"),
                                   ("Note", "explanation"), ("Finding", "claim_ids")]) + [""]
    if review:
        lines += [f"## {_USE_TITLES['review']}", "",
                  "Parsed from the wording of a belief, not stated by the analyst: confirm "
                  "each value against its finding before it enters a block list or a hunt.", ""]
        lines += _table(review, [("Value", "value"), ("Type", "category"), ("What the belief says", "explanation"),
                                 ("Finding", "claim_ids")]) + [""]
    return "\n".join(lines + _not_exported_lines(catalog))


def _csv_safe(value: str) -> str:
    """A cell that would open as a formula in a spreadsheet gets a leading
    quote, so an indicator such as a crafted pattern stays text."""
    from core.csv_safe import csv_safe
    return csv_safe(value)


def render_csv(catalog: dict[str, Any], case_dir: str | os.PathLike | None = None) -> str:
    """The same rows as a flat file for a SIEM or block-list import, the
    use column first so an import can filter on it."""
    import csv
    import io
    try:
        from core.finding_index import f_id_for
    except Exception:  # noqa: BLE001
        f_id_for = None
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["use", "side", "type", "value", "role", "confidence", "host", "first_seen",
                "last_seen", "source", "finding_ids", "claim_ids", "call_ids"])
    for rows in (catalog.get("iocs") or [], catalog.get("affected_assets") or [],
                 catalog.get("review") or []):
        for r in rows:
            fids = []
            if f_id_for and case_dir is not None:
                for cid in r.get("claim_ids") or []:
                    try:
                        fid = f_id_for(case_dir, cid)
                    except Exception:  # noqa: BLE001
                        fid = None
                    if fid:
                        fids.append(fid)
            w.writerow([" ".join(r.get("use") or ["review"]), r.get("side") or "", r.get("category") or "",
                        _csv_safe(r.get("value") or ""), r.get("role") or "", r.get("confidence") or "",
                        " ".join(r.get("hosts") or []), r.get("first_seen") or "", r.get("last_seen") or "",
                        r.get("source") or "", " ".join(fids), " ".join(r.get("claim_ids") or []),
                        " ".join(str(c) for c in (r.get("call_ids") or []))])
    return out.getvalue()


def write_indicator_files(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Write ``reports/<CASE_ID>_iocs.md`` and ``.csv``; return their paths
    and the counts. Never raises: a broken indicator list must not cost the
    case its report."""
    try:
        from core.paths import detect_case_id, assert_output_safe

        case_id = detect_case_id(case_dir) or "case"
        reports = Path(case_dir) / "reports"
        md_path, csv_path = reports / f"{case_id}_iocs.md", reports / f"{case_id}_iocs.csv"
        for path in (md_path, csv_path):
            assert_output_safe(str(path))
        reports.mkdir(parents=True, exist_ok=True)
        catalog = build_catalog(case_dir)
        md_path.write_text(render_markdown(catalog, case_id=case_id), encoding="utf-8")
        csv_path.write_text(render_csv(catalog, case_dir), encoding="utf-8")
        return {"markdown": str(md_path), "csv": str(csv_path), "total": catalog.get("total") or 0,
                "review_total": catalog.get("review_total") or 0,
                "affected_total": catalog.get("affected_total") or 0, "frame": catalog.get("frame"),
                "not_exported_total": catalog.get("not_exported_total") or 0,
                "by_use": catalog.get("by_use") or {}}
    except Exception:  # noqa: BLE001
        return {}


def write_ioc_report(case_dir: str | os.PathLike) -> str:
    """Write ``reports/<CASE_ID>_iocs.md`` and return its path ("" on failure).

    The IOC list is a deliverable of its own: a responder pastes it into a
    block list or a SIEM query, which is not something they should have to
    reconstruct from the narrative report by hand. Never raises — a broken
    indicator list must not be able to cost the case its report.
    """
    return str((write_indicator_files(case_dir) or {}).get("markdown") or "")


# ── keeping the lexicon alive ────────────────────────────────────────────

# What a run has to have shown before a name is worth remembering. A tool
# flagged *only* because it was already in the lexicon teaches nothing — it
# would just feed the lexicon its own output until it drifted.
_LEXICON_EVIDENCE = ("malicious characterisation", "non-standard location")


def capture_adversary_tools(case_dir: str | os.PathLike,
                            case_id: str = "") -> list[str]:
    """Write back tool names this run discovered *by behaviour*.

    This is the routine that keeps the lexicon from becoming an abandoned
    encyclopedia: it is deterministic, needs no LLM, no reviewer and no user
    interaction, and runs on every completed investigation. Nothing here is
    case-specific — only the name and the reason it is known adversary
    tooling cross the boundary into the Brain.

    Returns the note paths written. Never raises.
    """
    written: list[str] = []
    try:
        from core.brain import store as _store, frontmatter as _fm

        root = _store.brain_root()
        if not root.is_dir():
            return []
        known = adversary_tool_terms()
        catalog = build_catalog(case_dir)
        case_id = case_id or str(Path(case_dir).name)
        now = _dt.datetime.now(_dt.timezone.utc)
        stamp = now.strftime("%Y-%m-%d %H:%M UTC")

        for ioc in list(catalog.get("iocs") or []) + list(catalog.get("review") or []):
            if ioc.get("role") != ATTACKER_TOOL:
                continue
            name = str(ioc.get("value") or "").strip().lower()
            base = name.rsplit(".", 1)[0] if "." in name else name
            if not (2 < len(name) < 64):
                continue
            # Behaviour has to be the reason, on both paths below. A name
            # flagged only because the lexicon already knew it would just be
            # the lexicon citing itself.
            if not any(w in _LEXICON_EVIDENCE for w in ioc.get("why") or []):
                continue

            dest = root / "wiki" / "tools"
            dest.mkdir(parents=True, exist_ok=True)
            path = dest / f"adversary-tool-{_store.slugify(base)}.md"
            if not path.exists() and (
                    any(t in name for t in known) or base in _DUAL_USE_TERMS):
                continue     # ordinary software, or the seed already has it
            if path.exists():
                # Seen again in another case — corroboration is the whole
                # value of the record, so add the sighting and move on.
                meta, body, _w = _fm.parse(
                    path.read_text(encoding="utf-8", errors="replace"))
                cases = list((meta.get("entities") or {}).get("cases") or [])
                if case_id in cases:
                    continue
                cases.append(case_id)
                meta.setdefault("entities", {})["cases"] = cases
                meta["updated"] = stamp
                path.write_text(_fm.serialize(meta, body), encoding="utf-8")
                written.append(str(path))
                continue

            reasons = ", ".join(w for w in (ioc.get("why") or [])
                                if w in _LEXICON_EVIDENCE)
            meta = {
                "title": f"Adversary tooling: {base}",
                "type": "adversary_tool",
                "created": stamp,
                "updated": stamp,
                "status": "active",
                "source_classification": "internal",
                "confidence": "medium",
                "tags": ["adversary-tool", "ioc-lexicon"],
                "related": [],
                "source": {"type": "agent_run", "url": "",
                           "description": f"Behaviour-flagged during {case_id}"},
                "entities": {"cases": [case_id], "tools": [base],
                             "techniques": [], "actors": [], "cves": []},
            }
            body = (
                f"`{base}` was flagged as adversary tooling by behaviour "
                f"({reasons}) rather than by name, so the name is worth "
                f"remembering for future runs.\n\n"
                f"Recorded automatically at run close-out. A name here never "
                f"makes something an indicator on its own — it only raises "
                f"confidence in something behaviour has already flagged. "
                f"Set `status: retired` to drop it from the lexicon.\n"
            )
            path.write_text(_fm.serialize(meta, body), encoding="utf-8")
            written.append(str(path))
    except Exception:  # noqa: BLE001 - the Brain must never break a run
        return written
    return written
