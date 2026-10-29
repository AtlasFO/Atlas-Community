"""Deterministic citation check.

`reason.cite_check`'s own job description is a string match — "UNCITED: the
value appears in the finding but not in supporting_evidence". This implements
exactly that, deterministically, so a finding recorded WITH inline
supporting_evidence does not need a separate 8B-model round-trip.

Scope: only unambiguous artifact *values* are required to be cited — IPv4
addresses, hashes (32-64 hex), MITRE technique IDs, absolute file paths, and
registry keys. Prose, numbers, and ambiguous tokens are intentionally NOT
required (matching cite_check, which only flags concrete artifact claims).
"""
import re

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Absolute unix path with >= 2 segments (avoids matching a lone "/tmp").
_UNIX_PATH = re.compile(r"/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)+")
# Windows path or registry key.
# Do NOT allow whitespace inside the path match — otherwise
# ``D:\foo\bar.txt and D`` is extracted as one claim (a citation storm in
# one report). Paths with spaces remain citable when quoted in supporting_evidence
# via the full description substring check the agent supplies.
_WIN_PATH = re.compile(r"[A-Za-z]:\\[\\A-Za-z0-9._\-]+")
_REG_KEY = re.compile(r"\bHK(?:LM|CU|U|CR|CC)\\[\\A-Za-z0-9._\-]+", re.IGNORECASE)


def _trim_sentence_dots(value: str) -> str:
    """A path or key that ends a sentence takes the sentence's full stop, or
    an ellipsis, into the match, since "." is a segment character. A trailing
    dot is never part of a Windows file name and practically never of a Unix
    one; the cost is that a Unix path that really ends in ".." reads as its
    parent here."""
    return value.rstrip(".")


def extract_claims(finding: str) -> list[tuple[str, str]]:
    """Return [(kind, value), ...] of citable artifact values in the finding."""
    text = finding or ""
    claims: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, value: str):
        key = value.lower()
        if key and key not in seen:
            seen.add(key)
            claims.append((kind, value))

    for m in _IPV4.findall(text):
        add("ipv4", m)
    for m in _HASH.findall(text):
        add("hash", m)
    for m in _TID.findall(text):
        add("technique_id", m)
    for m in _REG_KEY.findall(text):
        add("registry_key", _trim_sentence_dots(m))
    for m in _WIN_PATH.findall(text):
        add("path", _trim_sentence_dots(m.strip()))
    for m in _UNIX_PATH.findall(text):
        add("path", _trim_sentence_dots(m))
    return claims


_CONTROL = re.compile(r"[\x00-\x1f]")


def value_forms(value: str) -> list[str]:
    """The forms a value takes in evidence text, lowered: as written; JSON-
    escaped (as json.dumps writes it, with and without ensure_ascii: a
    backslash doubled, a quote escaped, a non-ASCII letter as \\uXXXX); and,
    for a value the model copied in escaped form, unescaped, only when that
    gives no control character (a raw Windows path's \\t or \\n must not
    become a tab or a line break that meets a tab-separated text). Built from
    the value as written, lowered after. The other escape handling sits on
    the haystack side and is separate: quoted_text_grounding (decodes \\" \\\\
    \\n), the incident map's row mapping and frontier quote reading (\\\\
    only), core.indicators._unescaped (\\" and \\\\); the known-issues
    list names them."""
    import json
    forms = [value]
    for ascii_ in (False, True):
        escaped = json.dumps(value, ensure_ascii=ascii_)[1:-1]
        if escaped not in forms:
            forms.append(escaped)
    if "\\" in value:
        try:
            plain = json.loads('"' + value.replace('"', '\\"') + '"')
        except ValueError:
            plain = None
        if isinstance(plain, str) and plain not in forms and not _CONTROL.search(plain):
            forms.append(plain)
    return list(dict.fromkeys(f.lower() for f in forms))


def held_form(value: str, text_lower: str) -> str:
    """The form (value_forms) in which the value occurs in an already
    lowered text, "" when none does."""
    return next((f for f in value_forms(value) if f and f in text_lower), "")


def deterministic_cite_check(finding: str, supporting_evidence: str) -> dict:
    """Verify every citable artifact value in `finding` appears in
    `supporting_evidence`. Mirrors reason.cite_check's verdict vocabulary."""
    evidence = (supporting_evidence or "").lower()
    # A technique id is the analyst's classification of what the artifacts
    # show; no tool output ever contains "T1136.001", so requiring it there
    # would downgrade every finding that names its technique.
    # mitre_techniques= is where techniques are validated.
    claims = [(k, v) for k, v in extract_claims(finding) if k != "technique_id"]

    if not claims:
        # No concrete artifact claims to verify (prose-only finding).
        return {"verdict": "ALL_CITED", "cited_claims": [], "uncited_claims": []}

    if not evidence.strip():
        return {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "cited_claims": [],
            "uncited_claims": [v for _, v in claims],
        }

    cited, uncited = [], []
    for _kind, value in claims:
        if held_form(value, evidence):           # evidence is lowered above
            cited.append(value)
        else:
            uncited.append(value)

    verdict = "UNCITED_CLAIMS_PRESENT" if uncited else "ALL_CITED"
    return {"verdict": verdict, "cited_claims": cited, "uncited_claims": uncited}
