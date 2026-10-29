"""Gate: a CONFIRMED/LIKELY finding that attributes the CORE ACT (exfiltration /
copy / theft / dissemination) to a NAMED HUMAN must be grounded in a logon /
session artifact.

Failure mode this closes: the sibling gate principal_attribution_grounding only
fires when the description binds an *account/identity* to a person via a copula
("account X is operated by Y"). A verdict phrased as a person acting directly —
"<Name> exfiltrated the data" — has no account token and no copula, so it would
otherwise ship with no session requirement, attributing a sole-actor verdict
without ruling out a second principal who operated the same host.
"""
import re
from typing import Optional

from core.execution_log import as_text

from core.auth_ontology import windows_auth_eids_prose, windows_session_eids_prose

from ._match import lineage_evidence_text
from .principal_attribution_grounding import _SESSION_RE, _ACCOUNT_RE, _ATTRIB_RE

# The core act a sole-actor verdict turns on.
_CORE_ACT_RE = re.compile(
    r"\b(?:exfiltrat\w+|copied|stole|stol\w+|disseminat\w+|uploaded|upload\b"
    r"|transferred|transmit\w+|leaked|sent\b|smuggled|removed|staged)\b",
    re.IGNORECASE,
)

# A capitalized given-name-like token.
_NAME_RE = re.compile(r"\b([A-Z][a-z]{2,20})\b")

# General-purpose denylist of capitalized tokens that are NOT human actors, so a
# capitalized non-name in subject position can't be mistaken for a person. This
# is ordinary English / DFIR / brand vocabulary, not tied to any case — it keeps
# "Classified data was exfiltrated", "Dropbox uploaded…", "Monday's copy" from
# firing. Broad on purpose; add common tokens freely, they only suppress noise.
_NAME_STOPS = frozenset({
    # Sentence openers / determiners / tier words.
    "The", "This", "That", "These", "Those", "Confirmed", "Likely",
    "Suspected", "Unconfirmed", "Subject", "User", "Account",
    # OS / forensic artifact category nouns.
    "Security", "Windows", "System", "Event", "Registry", "Prefetch",
    "Source", "Network", "Remote", "Local", "Host", "Server", "Workstation",
    "Run", "Runonce", "Startup", "Task", "Tasks", "Service", "Services",
    "Key", "Value", "Desktop", "Downloads", "Recycle", "Temp", "Drive",
    "Volume", "Disk", "Session", "Logon", "Console", "Interactive", "Type",
    "Rdp", "Smb", "Ssh", "Usb", "Hid",
    # Generic data / object nouns common in finding prose.
    "Data", "Research", "Classified", "Stolen", "Files", "File", "Archive",
    "Folder", "Document", "Documents", "Payload", "Image", "Backup",
    # Common application / vendor brand names (broad, not case-specific) — cloud
    # storage, comms, archive/crypto, browsers, transfer clients.
    "Dropbox", "Onedrive", "Googledrive", "Gdrive", "Sharepoint", "Box",
    "Icloud", "Mega", "Wetransfer", "Pcloud", "Sync",
    "Skype", "Whatsapp", "Telegram", "Signal", "Discord", "Slack", "Teams",
    "Zoom", "Messenger", "Wechat", "Viber",
    "Veracrypt", "Truecrypt", "Bitlocker", "Winrar", "Winzip", "Peazip",
    "Chrome", "Firefox", "Edge", "Safari", "Opera", "Brave", "Outlook",
    "Thunderbird", "Filezilla", "Winscp", "Putty", "Rclone",
    # Calendar words.
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
    "Sunday", "January", "February", "March", "April", "June", "July",
    "August", "September", "October", "November", "December",
})

# Sentence-position words that open or join clauses in finding prose. They
# are capitalised for grammar, not because they name anyone.
_NAME_STOPS = _NAME_STOPS | frozenset({
    "When", "Where", "While", "After", "Before", "During", "Then", "Also",
    "However", "Note", "Both", "Each", "Every", "All", "None", "Only", "First",
    "Last", "Second", "Next", "Since", "Until", "Between", "Within", "Without",
    "Via", "Per", "Using", "Because", "Although", "Once", "Later", "Earlier",
    "Zip", "Users", "Public", "Default", "Program", "Common", "Pictures",
})


def _name_shaped(token: str, desc: str) -> bool:
    """Is this capitalised token written like a person's name?

    Part of ``First.Last`` or ``adm-first.last``, a ``DOMAIN\\Name`` that is
    not a path segment, a ``First Last`` pair of non-stop words, or a
    possessive. A lone capitalised word in subject position is grammar, not
    an accusation.
    """
    t = re.escape(token)
    if re.search(rf"(?:\b|-){t}\.[A-Za-z]|[A-Za-z]\.{t}\b", desc):
        return True
    # DOMAIN\Name: a NetBIOS-shaped domain, one backslash, the name, and no
    # further segment. A path segment after a lower-case directory
    # ("Users\jane.doe\Google Drive") is a folder, not a person.
    if re.search(rf"(?<![\w\\/])[A-Z][A-Z0-9-]{{1,15}}\\{t}\b(?![\\/])", desc):
        return True
    for m in re.finditer(rf"\b([A-Z][a-z]{{2,20}})\s+{t}\b|\b{t}\s+([A-Z][a-z]{{2,20}})\b", desc):
        other = m.group(1) or m.group(2)
        if other and other not in _NAME_STOPS:
            return True
    return bool(re.search(rf"\b{t}'s\b", desc))


# "Subject <Name>" / "subject is <Name>": the cue is read in any case, the
# name must be capitalised. Reading the whole pattern case-insensitively
# made the word after "subject" a person whatever it was ("the subject
# placed", "subject activity").
_SUBJECT_RE = re.compile(r"(?i:\bsubject(?:\s+is)?\s*:?\s+)([A-Z][a-z]{2,20})\b")
_BY_ACTOR_RE = re.compile(r"\bby\s+([A-Z][a-z]{2,20})\b")

# A maximal run of capitalised words, read whole: a name pair inside a longer
# run ("... Control Manager") is the run's tail, not a person.
_CAP_RUN_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b")
# Where a run labels a log record instead of naming a person: in parentheses
# right after a source noun ("System log (Service Control Manager 7045)"), or
# followed by an event-id-shaped number that closes the parentheses (a number
# in running prose, a count or a year, labels nothing). The nouns are how a record's source
# is written in English and German prose, not knowledge of any case.
_LABEL_OPEN_RE = re.compile(r"(?i)\b(?:log|logs|channel|provider|source|event|events|record|records|"
                            r"protokoll|kanal|quelle|ereignis)\s*\(\s*$")
_LABEL_ID_RE = re.compile(r"^\s*\d{3,5}\s*\)")


def _label_words(text: str) -> set[str]:
    """The words of the capitalised runs ``text`` writes as a record's
    label (in parentheses after a source noun, or before an event id that
    closes the parentheses)."""
    out: set[str] = set()
    for m in _CAP_RUN_RE.finditer(text):
        if _LABEL_OPEN_RE.search(text[:m.start()]) or _LABEL_ID_RE.match(text[m.end():]):
            out.update(m.group(0).split())
    return out


def _case_subject_names(ctx) -> set[str]:
    """Learn the case subject's name from the trace (case_context is not plumbed
    into GateContext). Scan dair_call inputs.case_context / investigation_focus
    and agent_message content for 'Subject <Name>' / 'subject is <Name>'."""
    names: set[str] = set()
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    blobs: list[str] = []
    for e in by_type.get("dair_call", []):
        inp = e.get("inputs") or {}
        blobs.append(as_text(inp.get("case_context")))
        blobs.append(as_text(e.get("investigation_focus")))
    for e in by_type.get("investigation_narration", []):
        blobs.append(as_text(e.get("content")))
    for b in blobs:
        for m in _SUBJECT_RE.finditer(b):
            names.add(m.group(1))
    return names


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    named = actor_names(ctx)
    if not named:
        return None

    from core.attribution_identity import identity_rows_on
    if identity_rows_on():
        # The person (with the account spellings of each full name that
        # begins with the name) stands in a row of a cited call beside
        # another term of the claim.
        from core.attribution_identity import full_names, person_variants
        from ._identity_rows import binding_rows, refusal
        texts = [ctx.description or ""] + _finding_texts(ctx)
        ident: set[str] = set()
        bare = []
        for name in named:
            names = full_names(name, texts)
            if not names:
                bare.append(name)
            for n in names or [name]:
                ident |= set(person_variants(n))
        ok, cited, others = binding_rows(ctx, ident)
        if ok:
            return None
        hint = (f"No full name is written for {', '.join(sorted(bare))}: write the account the evidence "
                "prints for the person." if bare else "")
        return refusal(ctx, "named_actor_attribution_grounding", ", ".join(sorted(named)), "the act",
                       cited, others, hint)

    evidence = lineage_evidence_text(ctx)
    if _SESSION_RE.search(evidence):
        return None
    return _refusal(ctx, named)


def _finding_texts(ctx) -> list[str]:
    """The recorded findings' statements and the case context the trace
    holds: where a person's full name may be written."""
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    out = [as_text(e.get("description")) for e in by_type.get("finding", [])]
    for e in by_type.get("dair_call", []):
        out.append(as_text((e.get("inputs") or {}).get("case_context")))
    return [t for t in out if t]


def actor_names(ctx) -> set[str]:
    """The persons the finding names as the actor of its core act: the
    named-actor shape of an attribution verdict (empty when it has none)."""
    desc = ctx.description or ""
    m = _CORE_ACT_RE.search(desc)
    if not m:
        return set()

    # If the description is already an account+copula binding, the sibling gate
    # principal_attribution_grounding owns it — don't double-fire.
    if _ACCOUNT_RE.search(desc) and _ATTRIB_RE.search(desc):
        return set()

    # Candidate actors: capitalized names in subject position (before the verb)
    # or "by <Name>", minus noise; PLUS the case subject (always in scope even
    # if its name looks generic). Names AFTER the verb ("exfiltrated to China")
    # are destinations, not actors — excluded by the prefix slice.
    prefix = desc[:m.start()]
    candidates = ({t for t in _NAME_RE.findall(prefix) if _name_shaped(t, desc)}
                  | set(_BY_ACTOR_RE.findall(desc)))
    # The grammatical subject of the act — the capitalised word right before
    # the verb ("Alice exfiltrated …") — is an accusation even on its own.
    subj = re.search(r"\b([A-Z][a-z]{2,20})\s*$", prefix)
    if subj:
        candidates.add(subj.group(1))
    candidates -= _NAME_STOPS
    # A run written as a record's label names its source, not an actor.
    candidates -= _label_words(prefix)
    # Software the cited evidence names (an executable, a program directory)
    # is not an actor, however name-like the product reads.
    from ._match import labelled_quote_words, named_things_in_text, program_names_in_evidence
    candidates -= program_names_in_evidence(ctx)
    # Nor is a token the finding or its evidence spells as a thing: a file's
    # stem ('Planning.docx'), a domain's labels (docs.google.com), a path
    # segment, a quoted name a thing-noun introduces (the job "Nightly
    # Sync") - a service or a document is not the person who acted.
    things = (named_things_in_text(desc) | named_things_in_text(lineage_evidence_text(ctx))
              | labelled_quote_words(desc))
    candidates = {c for c in candidates if c.casefold() not in things}
    subjects = _case_subject_names(ctx)
    subject_in_desc = {s for s in subjects if re.search(rf"\b{re.escape(s)}\b", desc)}
    return candidates | subject_in_desc


def _refusal(ctx, named: set[str]) -> dict:
    who = ", ".join(sorted(named))
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding attributes the core act (exfiltration / copy / "
            f"transfer / dissemination) to a named person ({who}) but cites no "
            f"logon/RDP session artifact. Naming a person directly does not "
            f"establish that they — and not a second principal operating the "
            f"same host — performed the act. Pull the logon-session binding "
            f"(Security {windows_auth_eids_prose()} logon type + source address, "
            f"or RDP {windows_session_eids_prose()} "
            f"— ez.evtxecmd / misc.chainsaw_hunt) placing this person at the host "
            f"during the act and cite it (input_call_ids), or downgrade to "
            f"SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "named_actor_attribution_grounding",
    }
