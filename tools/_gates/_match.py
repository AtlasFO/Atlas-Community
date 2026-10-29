"""Shared description-matching helpers for finding gates.

Gates that must tie a reason_call (evaluate / confidence / cite) to the
*specific* finding being recorded match the whole normalized description
against the FINDING section the review echoes in its ``inputs.user_message``:
a review counts only for the statement it reviewed, equal after
normalisation. Containment is no weakening: "No row shows that data was
exfiltrated" contains "data was exfiltrated", and a hedge or a negation
around a statement reverses it. A wording that adds, drops or reverses
anything is another finding and gets its own review; a statement quoted in
another review's evidence or context is not that review's finding. Centralising the matching
semantics here keeps them identical across gates and the report backstop.
"""
import re
import secrets
import unicodedata
from typing import Optional

_WHITESPACE_RE = re.compile(r"\s+")


# The line that opens the rows of the cited calls Atlas appends to an
# evaluation request (tools.reasoning.reason_evaluate_finding). The
# analyst's own text never holds it: "cited output" in the finding, its
# evidence or its context is rewritten before the request is built
# (neutral_request_text), so it can neither forge Atlas's rows nor cut the
# evidence a review read. The finding is rewritten too, and normalize_desc
# rewrites the same way, so a review is still tied to its finding by text.
CITED_OUTPUT_MARKER = "CITED OUTPUT (copied by Atlas from the run's record):"
_ANALYST_WORDS = "cited-output (analyst's words)"
# The phrase, in any case, spacing or joining; not the rewrite itself, so
# the rewrite is idempotent and a key made of it matches a key made twice.
_ANALYST_MARKER_RE = re.compile(r"(?i)cited[\s_-]*output(?! \(analyst's words\))")


def neutral_request_text(text: str) -> str:
    """The text with every "cited output" phrase made the analyst's own
    words, every other character kept as written. The phrase is looked for
    on a folded copy (NFKC per character, so a full-width or ligature letter
    is its plain letter, with the format characters between the letters
    left out), so it cannot hide behind another spelling; the rewrite
    replaces the span of the original text that folded to it. A look-alike
    domain or a direction override elsewhere in the text stays what it is.
    Applying it again changes nothing."""
    text = str(text or "")
    if text.isascii():
        return _ANALYST_MARKER_RE.sub(_ANALYST_WORDS, text)
    folded: list[str] = []
    back: list[int] = []        # the index in ``text`` each folded character came from
    for i, c in enumerate(text):
        if unicodedata.category(c) == "Cf":
            continue
        for fc in unicodedata.normalize("NFKC", c):
            folded.append(fc)
            back.append(i)
    out: list[str] = []
    pos = 0
    for m in _ANALYST_MARKER_RE.finditer("".join(folded)):
        start, end = back[m.start()], back[m.end() - 1] + 1
        out.append(text[pos:start])
        out.append(_ANALYST_WORDS)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def fence_nonce() -> str:
    """A token the analyst's text cannot hold: drawn when the request is
    built, after that text is fixed."""
    return secrets.token_hex(6)


def cited_output_fence(nonce: str) -> tuple[str, str]:
    """The lines that open and close Atlas's block of cited rows, both
    carrying ``nonce``: the evaluator takes as Atlas's only the block whose
    opening and closing lines carry the same token (the analyst's text is
    rewritten by neutral_request_text, so it holds no such heading at
    all)."""
    return f"{CITED_OUTPUT_MARKER} fence {nonce}", f"END OF CITED OUTPUT (fence {nonce})"


# The finding a review was asked about: reason_evaluate_finding,
# reason_confidence_score and reason_cite_check all open with it.
_FINDING_RE = re.compile(r"(?i)FINDING:\s*(.*?)(?:\n\s*SUPPORTING[ _]EVIDENCE:|\n\s*CASE[ _]CONTEXT:|\Z)", re.S)
_EVIDENCE_RE = re.compile(r"SUPPORTING[ _]EVIDENCE:\s*(.*?)(?:\n\s*\n\s*(?:CASE[ _]CONTEXT|AGENT_INTENDED_TIER):|"
                          r"\n\s*\n" + re.escape(CITED_OUTPUT_MARKER) + r"|\Z)", re.S)


def normalize_desc(text: str) -> str:
    """Lowercase, whitespace collapsed, "cited output" made the analyst's
    words (as the request writes it): the key that ties a finding
    description to the review of it, equal on both sides."""
    return _WHITESPACE_RE.sub(" ", neutral_request_text(text).lower()).strip()


def reviewed_finding(entry: dict) -> Optional[str]:
    """The normalized finding a reason_call reviewed, None when its input
    echoes none (traces older than the echo)."""
    m = _FINDING_RE.search(str((entry.get("inputs") or {}).get("user_message") or ""))
    return normalize_desc(m.group(1)) if m else None


def reviews(entry: dict, norm_desc: str) -> bool:
    """Whether the reason_call reviewed this finding: the normalized
    description equals its FINDING."""
    return bool(norm_desc) and reviewed_finding(entry) == norm_desc


def reviewed_evidence(entry: dict) -> str:
    """The SUPPORTING EVIDENCE a reason_call reviewed, '' when none."""
    m = _EVIDENCE_RE.search(str((entry.get("inputs") or {}).get("user_message") or ""))
    return m.group(1) if m else ""


def find_reason_call(window, tool_name: str, norm_desc: str,
                     after_call_id: int = 0) -> Optional[dict]:
    """Most-recent *usable* reason_call of ``tool_name`` that reviewed this
    finding (``reviews``) and whose call_id > ``after_call_id``. None if no
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
        if reviews(entry, norm_desc):
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
    """The evidence text a grounding gate inspects for a required marker:
    the rows every call referenced by ``linked_call_id`` and
    ``input_call_ids`` printed, echo-free (tools._gates.citation_support
    .call_rows), and the rows it printed past its excerpt (core.indicators
    .rows_text over its spill, a background job's start read as its
    outcome): a transfer line deep in a capture's output is evidence the
    excerpt never shows. Never the analyst's own words: not the
    ``supporting_evidence`` the analyst wrote, not a call's command line, not
    the request a search echoes back, so a marker the analyst typed is no
    marker. Used by grounding gates (principal_attribution_grounding,
    exfil_channel_grounding) that demand the *evidence* — not merely the
    description prose — carry a specific artifact marker. Worked out once
    per record (kept on the context)."""
    kept = getattr(ctx, "_lineage_text", None)
    if isinstance(kept, str):
        return kept
    from .citation_support import call_rows
    parts: list[str] = []
    cids = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(ctx.linked_call_id)
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    for cid in dict.fromkeys(cids):
        entry = by_id.get(cid)
        if not entry:
            continue
        try:
            parts.extend(call_rows(entry))
        except Exception:  # noqa: BLE001 - a call whose rows cannot be read shows nothing
            pass
        parts.append(_spilled_rows(entry))
    text = " \n ".join(p for p in parts if p)
    try:
        ctx._lineage_text = text
    except Exception:  # noqa: BLE001 - a context that takes no attribute is read again
        pass
    return text


def _spilled_rows(entry: dict) -> str:
    """The rows a cited call printed in its retained output, "" when it
    kept none or the read fails."""
    try:
        from core.coverage_ledger import resolved_entry
        from core.indicators import rows_text
        from core.paths import active_case_dir
        seen = resolved_entry(active_case_dir(), entry) or {}
        if not seen.get("stdout_file"):
            return ""
        # The whole retained output: a marker past the usual read size is
        # still a row the call printed.
        import os
        from core.indicators import SPILL_READ_CHARS
        size = os.path.getsize(str(seen["stdout_file"]))
        return rows_text(seen, limit=max(SPILL_READ_CHARS, size))
    except Exception:  # noqa: BLE001
        return ""


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
        # Prose before a file name is not part of it: a name with spaces
        # counts only where a quote opens it ("'Q3 plan.docx'"); otherwise
        # the stem is the word the extension is attached to.
        if " " in stem and not (m.start() > 0 and text[m.start() - 1] in "'\"`"):
            stem = stem.split()[-1]
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


def _call_args(entry: dict) -> dict:
    from core.indicators import _parsed_args
    args, _keys = _parsed_args(entry)
    return args if isinstance(args, dict) else {}


def analyst_authored_rule(entry: dict, run_start: Optional[float] = None) -> bool:
    """A scan whose rule the analyst may have written: an inline rule, or a
    rules file that is neither the rule set shipped with Atlas nor older
    than the run's first call (``run_start``, epoch seconds). The analyst
    can write a rule anywhere during the run (a shell or a script reaches
    /tmp as easily as the case tree), so only provenance outside the run
    grounds a match. Its match is otherwise the analyst's own word."""
    import glob
    import os
    cmd = str(entry.get("cmd") or "")
    if cmd.endswith("scan_strings"):
        return True
    args = _call_args(entry)
    if args.get("inline_rule"):
        return True
    rules = str(args.get("rules_path") or "")
    if not rules:
        return False                      # the scan used the shipped rule set
    try:
        from tools.yara_tools import bundled_rules_dir
        shipped = bundled_rules_dir()
        rp = os.path.realpath(rules)
        if shipped and os.path.commonpath([rp, os.path.realpath(shipped)]) == os.path.realpath(shipped):
            return False
        files = ([rp] if os.path.isfile(rp) else
                 glob.glob(os.path.join(rp, "**", "*.yar"), recursive=True)
                 + glob.glob(os.path.join(rp, "**", "*.yara"), recursive=True))
        if run_start is not None and files and all(
                max(os.stat(f).st_mtime, os.stat(f).st_ctime) < run_start for f in files):
            return False
    except (OSError, TypeError, ValueError):
        pass
    return True


def printed_name(entry: dict, name: str, run_start: Optional[float] = None) -> bool:
    """Whether a recorded tool call printed ``name``: its output only, never
    its command line or arguments. A rule scan grounds a name through a
    match whose rule, namespace, tags or meta carry it (no match grounds
    nothing) and never through a rule the analyst wrote; a lookup through
    the fields the provider returned; a parser or search through its rows."""
    import json
    from core.forensic_citation import own_words_entry
    from core.indicators import _output_text, printed_text
    needle = (name or "").strip().lower()
    if (not needle or not isinstance(entry, dict) or entry.get("type") != "tool_call"
            or own_words_entry(entry)):
        return False
    if str(entry.get("cmd") or "").startswith("<py>:yara_"):
        if analyst_authored_rule(entry, run_start):
            return False
        try:
            data = json.loads(_output_text(entry, 4_000_000))
        except ValueError:
            data = None
        if isinstance(data, dict) and ("matches" in data or "results" in data):
            # a directory scan nests its matches per file
            groups = [data] + [r for r in data.get("results") or [] if isinstance(r, dict)]
            fields = [json.dumps({k: m.get(k) for k in ("rule", "namespace", "tags", "meta")}, default=str)
                      for g in groups for m in g.get("matches") or [] if isinstance(m, dict)]
            return needle in " ".join(fields).lower()
    return needle in printed_text(entry).lower()
