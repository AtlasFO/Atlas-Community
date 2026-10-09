"""Shared description-matching helpers for finding gates.

Gates that must tie a reason_call (evaluate / confidence / cite) to the
*specific* finding being recorded match on a normalized prefix of the finding
description appearing in the reason_call's ``inputs.user_message``. Centralising
the matching semantics here keeps them identical across gates and is what stops
one finding's review verdict from satisfying or blocking a *different* finding
(cross-contamination) when several findings are reviewed in one batch.
"""
import re
from typing import Optional

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_desc(text: str) -> str:
    """Lowercase, collapse whitespace, first 60 chars — the stable key used to
    match a finding description against a reason_call's user_message."""
    return _WHITESPACE_RE.sub(" ", (text or "").lower()).strip()[:60]


def find_reason_call(window, tool_name: str, norm_desc: str,
                     after_call_id: int = 0) -> Optional[dict]:
    """Most-recent *usable* reason_call of ``tool_name`` whose user_message
    contains ``norm_desc`` and whose call_id > ``after_call_id``. None if no
    match. Empty / failed reason calls never satisfy a finding gate.
    """
    if not norm_desc:
        return None
    try:
        from core.reason_outcome import is_usable_reason_call
    except Exception:
        is_usable_reason_call = lambda e: bool(  # noqa: E731
            e and e.get("success") and (e.get("conclusion") or "").strip()
        )
    for entry in reversed(window):
        if entry.get("type") != "reason_call" or entry.get("tool") != tool_name:
            continue
        if int(entry.get("call_id") or 0) <= after_call_id:
            continue
        if not is_usable_reason_call(entry):
            continue
        user_msg = ((entry.get("inputs") or {}).get("user_message") or "").lower()
        if norm_desc in user_msg:
            return entry
    return None


def most_recent_reason_call(window, tool_name: str) -> Optional[dict]:
    """Most-recent *usable* reason_call of ``tool_name``."""
    try:
        from core.reason_outcome import is_usable_reason_call
    except Exception:
        is_usable_reason_call = lambda e: bool(  # noqa: E731
            e and e.get("success") and (e.get("conclusion") or "").strip()
        )
    for entry in reversed(window):
        if entry.get("type") != "reason_call" or entry.get("tool") != tool_name:
            continue
        if is_usable_reason_call(entry):
            return entry
    return None


def lineage_evidence_text(ctx) -> str:
    """Concatenated evidence text a grounding gate may inspect for a required
    marker: the agent-supplied ``supporting_evidence`` plus the ``cmd`` and
    ``stdout_excerpt`` of every entry referenced by ``linked_call_id`` and
    ``input_call_ids``. Used by grounding gates (principal_attribution_grounding,
    exfil_channel_grounding) that demand the *evidence* — not merely the
    description prose — carry a specific artifact marker."""
    parts: list[str] = [ctx.supporting_evidence or ""]
    cids = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(ctx.linked_call_id)
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    for cid in cids:
        entry = by_id.get(cid)
        if not entry:
            continue
        parts.append(entry.get("cmd") or "")
        parts.append(entry.get("stdout_excerpt") or "")
    return " \n ".join(p for p in parts if p)


# A negation earlier in the same sentence turns a claim word into its
# denial: "no data was exfiltrated over the stick", "not the exfiltration
# medium". A gate that keys on the word reads the sentence first.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|none|never|without|absent|absence|negative|ruled\s+out|"
    r"did\s+not|does\s+not|was\s+not|were\s+not|nothing|neither|nor)\b", re.IGNORECASE)
_SENTENCE_BREAK_RE = re.compile(r"[.;!?\n]")


def asserted_mention(text: str, pattern) -> Optional[re.Match]:
    """The first match of ``pattern`` in ``text`` with no negation before it
    in the same sentence, or None when every mention is denied."""
    text = text or ""
    for m in pattern.finditer(text):
        start = 0
        for end in _SENTENCE_BREAK_RE.finditer(text, 0, m.start()):
            start = end.end()
        if not _NEGATION_RE.search(text, start, m.start()):
            return m
    return None


# A capitalised token the cited evidence prints as a program: the stem of an
# executable-shaped file, or a directory under a program directory. Such a
# token in a finding names software, not a person, however name-like it
# reads ("Abel is Cain's companion tool"). A profile directory is not this:
# it is named after the very person an attribution gate asks about.
_PROGRAM_FILE_RE = re.compile(
    r"[\\/]([A-Z][\w@.-]{1,40}?)\.(?:exe|dll|sys|lnk|bat|cmd|ps1|vbs|js|jar|msi|"
    r"ocx|scr|com|pif|drv)\b", re.IGNORECASE)
_PROGRAM_DIR_RE = re.compile(
    r"program files(?: \(x86\))?[\\/]([A-Z][\w@ .-]{1,40}?)(?=[\\/]|\s*$|\s*[,;)])",
    re.IGNORECASE)


def program_names_in_evidence(ctx) -> set[str]:
    """Names the cited evidence prints as programs (executable stems, program
    directories), in their original casing and with each word of a spaced
    name, so a gate can tell "Cain" the tool from a person."""
    text = lineage_evidence_text(ctx)
    names: set[str] = set()
    for rx in (_PROGRAM_FILE_RE, _PROGRAM_DIR_RE):
        for m in rx.finditer(text):
            token = m.group(1).strip()
            names.add(token)
            names.update(w for w in re.split(r"[\s_.-]+", token) if len(w) >= 3)
    return names


# Tokens a text uses as the name of a thing: the labels of a domain name
# ("docs" and "google" in docs.google.com), the stem of a file name
# ("Planning" in 'Planning.docx') and the segments of a path - except the
# segment under a profile root, which is named after a person. Such a token
# is not a person however name-like it reads on its own.
_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]{1,63}\.)+[a-z]{2,24})\b", re.IGNORECASE)
_FILE_RE = re.compile(r"(?<![\w.])([A-Za-z][\w -]{0,60}?)\.(?:[a-z0-9]{1,5})\b(?=['\"\s,;:)\]]|$)")
# A path: at least two separator-led segments, preceded by the run of text
# that stands before the first separator (a root such as "Documents and
# Settings" carries spaces, so the run is read up to a colon or quote).
_PATH_RE = re.compile(r"([^\\/'\"<>|*?:\n]+)?((?:[\\/][^\\/\s'\"<>|*?]+){2,})")
_PROFILE_ROOTS = frozenset({"users", "documents and settings", "home", "user"})


# A noun that labels a thing, followed within a few words by the quotation
# that names it ('the sync job (id 4f2a) "Nightly Sync"', "a file titled
# 'Q3 Plan'"). Universal vocabulary, not case knowledge. Nouns for people are
# left out on purpose, and the words between the noun and the quotation may
# not hold one, nor an attribution cue ("by", "as"): a quoted name after them
# may be exactly whom a finding accuses ('the task owner "Jane Doe"', 'the job
# created by "Jane Doe"'). A single quote counts only as a quotation mark
# standing apart from words, since it is also an apostrophe.
_PEOPLE_NOUNS = (
    r"user|owner|account|person|people|member|employee|author|sender|recipient|"
    r"operator|admin|administrator|attacker|actor|suspect|subject|individual|"
    r"insider|analyst|examiner|investigator|colleague|manager|contractor|"
    r"customer|client|victim|witness")
_THING_LABEL_RE = re.compile(
    r"(?i)\b(?:job|task|title|document|file|folder|field|tag|label|window|service|"
    r"bucket|project|sheet|slide|volume|share|playlist|column|rule|schedule|"
    r"template|setting|entry|item)s?\b"
    r"(?:(?!\b(?:(?:" + _PEOPLE_NOUNS + r")s?|by|as)\b)[^.!?\"\u201c\u201d\n]){0,40}?"
    r"(?:[\"\u201c]([^\"\u201d\n]{1,80})[\"\u201d]"
    r"|(?<![\w'])'([^'\n]{1,80})'(?![\w']))")


def labelled_quote_words(text: str) -> set[str]:
    """Casefolded words of quotations a thing-noun introduces: the source's
    name for a job, a file or a field, not a person the finding names."""
    out: set[str] = set()
    for m in _THING_LABEL_RE.finditer(text or ""):
        quoted = m.group(1) or m.group(2)
        out.update(w.casefold() for w in re.findall(r"[A-Za-z][\w'-]*", quoted))
    return out


def named_things_in_text(text: str) -> set[str]:
    """Casefolded tokens the text spells as domain labels, file stems or
    path segments (a profile directory's own name excepted)."""
    text = text or ""
    out: set[str] = set()
    for m in _DOMAIN_RE.finditer(text):
        labels = m.group(1).casefold().split(".")
        out.update(label for label in labels if label)
    for m in _FILE_RE.finditer(text):
        stem = m.group(1).strip().casefold()
        out.add(stem)
        out.update(w for w in re.split(r"[\s_-]+", stem) if len(w) >= 3)
    for m in _PATH_RE.finditer(text):
        head = (m.group(1) or "").strip().casefold()
        parts = [p for p in re.split(r"[\\/]+", m.group(2)) if p]
        # The head is prose or a root: it decides whether the first segment
        # is a person's directory, and is never itself a thing.
        previous = head
        for part in parts:
            low = part.casefold()
            if previous in _PROFILE_ROOTS:
                previous = low
                continue                  # the person's own directory
            out.add(low)
            out.update(w for w in re.split(r"[\s_-]+", low) if len(w) >= 3)
            previous = low
    return out
