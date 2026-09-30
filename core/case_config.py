"""Per-case configuration (report language and related prefs).

Stored at ``<case>/.atlas/case_config.json``. Part of Current Investigation
State scaffolding — not a parallel SoT.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
SUPPORTED_LANGUAGES = frozenset({"en", "de"})
DEFAULT_LANGUAGE = "en"

# What kind of engagement the case is. A live incident earns first-hour
# precautions (isolate, preserve, block) as recommendations; a device or
# image examined after the fact cannot take them, so none are recorded.
# Stated in CASE.md, the analyst's own brief, as ``**Engagement:** ...``;
# absent, a case is treated as an incident, which is what Atlas did before
# the field existed.
ENGAGEMENTS = ("incident-response", "examination")
DEFAULT_ENGAGEMENT = "incident-response"
# The words a brief may use, in English and German. An examination word
# wins over an incident word ("live forensic examination" is an
# examination); a value with neither is reported, not guessed.
_EXAMINATION_WORDS = (
    "examination", "exam", "post-mortem", "postmortem", "historical", "dead-box",
    "deadbox", "after-the-fact", "untersuchung", "nachträglich", "nachträgliche",
    "nachtraeglich", "nachtraegliche",
)
_INCIDENT_WORDS = (
    "incident-response", "incident", "ir", "response", "live", "live-response",
    "vorfall", "vorfallsreaktion",
)
# The field on its own line: the template form ``**Engagement:** x``, a
# metadata-table row ``| **Engagement** | x |`` or a bare ``engagement: x``,
# with ``engagement type`` as a label too. A colon or a pipe must follow
# the label (a prose line that starts with the word is not the field), the
# value ends at the line, so an empty field never swallows the next line.
def _field_line_re(label: str) -> "re.Pattern[str]":
    """The regex for one brief field whose label matches ``label`` (a regex
    fragment), in the forms described above."""
    return re.compile(
        r"(?im)^[ \t]*\|?[ \t]*[*_]{0,2}(?:" + label + r")[*_]{0,2}[ \t]*(?::[*_]{0,2}|\|)"
        r"[ \t]*\|?[ \t]*(?P<value>[^\n|]*)")


_ENGAGEMENT_LINE_RE = _field_line_re(r"engagement(?:[ \t]+type)?")

# Whose system the evidence comes from, which is a different question from
# whether a first hour exists. A victim's systems (an organisation or a
# person whose systems were attacked or abused) owe remediation whether the
# evidence is live or an image examined later; the device of the person
# under investigation owes none, and gets investigative next steps and
# legal process instead. Stated in CASE.md as ``**System owner:** ...``
# (labels: system owner, device owner, Systeminhaber, Geräteeigentümer; a
# bare "Owner:" line names the case owner and is not read). The value's
# first word decides, a possessive included ("suspect's own laptop");
# free text may follow. Absent or unrecognised, the owner is unknown: the
# recommendations assume a victim and the report states that assumption.
SYSTEM_OWNERS = ("victim", "suspect", "unknown")
DEFAULT_SYSTEM_OWNER = "unknown"
_OWNER_WORDS = {
    "victim": ("victim", "victims", "opfer", "geschädigte", "geschädigter",
               "geschaedigte", "geschaedigter"),
    "suspect": ("suspect", "suspects", "beschuldigte", "beschuldigter",
                "verdächtige", "verdächtiger", "verdaechtige", "verdaechtiger",
                "tatverdächtige", "tatverdächtiger", "tatverdaechtige",
                "tatverdaechtiger"),
    "unknown": ("unknown", "unbekannt"),
}
_SYSTEM_OWNER_LINE_RE = _field_line_re(
    r"(?:system|device)[ \t]+owner|systeminhaber|ger(?:ä|ae)teeigent(?:ü|ue)mer")
_FIRST_WORD_RE = re.compile(r"[\s*_`'\"]*([^\W\d_]+)")

# Whom the examination is about. Stated in the case metadata table (the
# table under a metadata heading, or whose header reads Field | Value) as
# a Subject row, or in the template's own field line ``**Subject:** x``.
# A bare "Subject:" line elsewhere in a brief is a pasted mail header, and
# a table outside the metadata block may tabulate a lure: neither names a
# person and neither is read. The German labels are the accused or the
# suspect; "betroffene Person" is the data subject, the other side.
_SUBJECT_WORDS = (r"subject|person under investigation|suspect|beschuldigte[rn]?|"
                  r"verd(?:ä|ae)chtige[rn]?|tatverd(?:ä|ae)chtige[rn]?")
_SUBJECT_LABEL_RE = re.compile(r"(?i)^(?:" + _SUBJECT_WORDS + r")$")
# A metadata row that gives one of the subject's identifiers.
_SUBJECT_IDENT_LABEL_RE = re.compile(
    r"(?i)^(?:" + _SUBJECT_WORDS + r")(?:\s*'?s)?\s+(?:\w+\s+)?(?:user|username|account|login|logon|"
    r"mail|e-?mail|mailbox|alias|handle|name|id|benutzer|konto|adresse)\b")
_SUBJECT_TEMPLATE_RE = re.compile(
    r"(?im)^[ \t]*\*\*(?:" + _SUBJECT_WORDS + r")[ \t]*:\*\*[ \t]*(?P<value>[^\n]*)"
    r"|^[ \t]*\*\*(?:" + _SUBJECT_WORDS + r")\*\*[ \t]*:[ \t]*(?P<value2>[^\n]*)")
_META_HEADING_RE = re.compile(r"(?i)metadat|stammdaten|falldaten|case details")
_TABLE_HEADERS = ({"field", "value"}, {"feld", "wert"})
_SEPARATOR_CELL_RE = re.compile(r"^:?-{2,}:?$")


def _plain_cell(cell: str) -> str:
    return re.sub(r"[*_`]", "", cell).strip()


def _stripped(text: str) -> str:
    try:
        from core.investigation_tasks import _strip_noncontent_markdown
        return _strip_noncontent_markdown(text or "")
    except Exception:  # noqa: BLE001 - read the text as it is
        return text or ""


_CASE_FIELD_RE = re.compile(r"(?i)^(?:case[ \t]*id|fall[- ]?id|engagement(?:[ \t]+type)?|(?:system|device)[ \t]+owner|"
                            r"systeminhaber|ger(?:ä|ae)teeigent(?:ü|ue)mer|your[ \t]+role|rolle)$")


def _tables(text: str) -> list[tuple[bool, list[tuple[str, str]]]]:
    """Every table of the brief as ``(under a metadata heading, rows)``; a
    Field | Value header row is dropped, separator rows skipped."""
    out: list[tuple[bool, list[tuple[str, str]]]] = []
    under_heading = False
    current: list[tuple[str, str]] | None = None
    for line in _stripped(text).splitlines():
        s = line.strip()
        if s.startswith("#"):
            under_heading, current = bool(_META_HEADING_RE.search(s)), None
            continue
        if not s.startswith("|"):
            current = None
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if all(_SEPARATOR_CELL_RE.match(c) for c in cells if c):
            continue
        if current is None:
            current = []
            out.append((under_heading, current))
            if {_plain_cell(c).lower() for c in cells[:2]} in _TABLE_HEADERS:
                continue
        if len(cells) >= 2:
            current.append((_plain_cell(cells[0]), cells[1].strip()))
    return out


def metadata_rows(text: str) -> list[tuple[str, str]]:
    """``(label, value)`` for each row of the brief's case metadata table:
    the table under a metadata heading, or else the brief's first table
    when it carries a case field (Case ID, Engagement, System owner, Your
    role). One table only: a lure mail tabulated with a Field | Value
    header elsewhere in the brief is not case metadata."""
    tables = _tables(text)
    for under_heading, rows in tables:
        if under_heading and rows:
            return rows
    if tables and any(_CASE_FIELD_RE.match(label) for label, _v in tables[0][1]):
        return tables[0][1]
    return []


def subject_field(text: str) -> tuple[bool, str]:
    """``(present, value)`` for the subject the brief names."""
    for label, value in metadata_rows(text):
        if _SUBJECT_LABEL_RE.match(label) and value:
            return True, value
    m = _SUBJECT_TEMPLATE_RE.search(_stripped(text))
    if m:
        value = (m.group("value") or m.group("value2") or "").strip()
        if value:
            return True, value
    return False, ""


def names_subject(case_dir: str | os.PathLike | None) -> bool:
    """True when the brief names the person the examination is about."""
    try:
        return bool(case_dir) and subject_field(_brief(case_dir))[0]
    except Exception:  # noqa: BLE001
        return False


_MAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_QUOTED_NAME_RE = re.compile(r"[\"“„]([^\"”“„]{2,60})[\"”“]")


def _identifiers_in(value: str) -> set[str]:
    # A backticked artefact (a file, a path) beside the name is not an identifier.
    ticked = {v for v in re.findall(r"`([^`]+)`", value)
              if not re.search(r"\.[A-Za-z0-9]{1,5}$", v.strip()) and not re.search(r"[\\/]", v)}
    vals = ticked | set(_MAIL_RE.findall(value)) | set(_QUOTED_NAME_RE.findall(value))
    head = re.split(r"\s+[—–-]\s+|[(,;]", value, maxsplit=1)[0].strip(" \"'*_`“”„")
    if head and len(head) <= 80:
        vals.add(head)
    return {v.strip(" \"'*_`“”„") for v in vals if v.strip(" \"'*_`“”„")}


def subject_identifiers(text: str) -> set[str]:
    """The subject's stated identifiers, casefolded: the name and alias in
    the Subject row and the values of the metadata rows that give the
    subject's username, account, mailbox or alias."""
    out: set[str] = set()
    for label, value in metadata_rows(text):
        if _SUBJECT_LABEL_RE.match(label) or _SUBJECT_IDENT_LABEL_RE.match(label):
            out |= _identifiers_in(value)
    present, value = subject_field(text)
    if present:
        out |= _identifiers_in(value)
    return {v.casefold() for v in out if len(v) >= 2}


def get_subject_identifiers(case_dir: str | os.PathLike | None) -> set[str]:
    try:
        return subject_identifiers(_brief(case_dir)) if case_dir else set()
    except Exception:  # noqa: BLE001
        return set()


def _canonical_engagement(raw: str) -> str | None:
    words = re.findall(r"[a-zäöüß]+", (raw or "").lower())
    joined = "-" + "-".join(words) + "-"
    if any(f"-{w}-" in joined for w in _EXAMINATION_WORDS):
        return "examination"
    if any(f"-{w}-" in joined for w in _INCIDENT_WORDS):
        return "incident-response"
    return None


def engagement_field(text: str) -> tuple[bool, str, str | None]:
    """``(present, raw value, canonical)`` for the engagement field a case
    brief states; comments are not read, so a commented-out line does not
    count. ``canonical`` is None when the field is absent or its value is
    not a known engagement."""
    if not text:
        return False, "", None
    try:
        from core.investigation_tasks import _strip_noncontent_markdown
        text = _strip_noncontent_markdown(text)
    except Exception:  # noqa: BLE001 - read the text as it is
        pass
    m = _ENGAGEMENT_LINE_RE.search(text)
    if not m:
        return False, "", None
    raw = m.group("value").strip(" \t*_`")
    return True, raw, _canonical_engagement(raw)


def parse_engagement(text: str) -> str | None:
    """The engagement type a case brief states, or None."""
    return engagement_field(text)[2]


def _canonical_system_owner(raw: str) -> str | None:
    m = _FIRST_WORD_RE.match(raw or "")
    if not m:
        return None
    word = m.group(1).lower()
    for canonical, words in _OWNER_WORDS.items():
        if word in words:
            return canonical
    return None


def system_owner_field(text: str) -> tuple[bool, str, str | None]:
    """``(present, raw value, canonical)`` for the system-owner field a
    case brief states, read like the engagement field."""
    if not text:
        return False, "", None
    try:
        from core.investigation_tasks import _strip_noncontent_markdown
        text = _strip_noncontent_markdown(text)
    except Exception:  # noqa: BLE001 - read the text as it is
        pass
    m = _SYSTEM_OWNER_LINE_RE.search(text)
    if not m:
        return False, "", None
    raw = m.group("value").strip(" \t*_`")
    return True, raw, _canonical_system_owner(raw)


def parse_system_owner(text: str) -> str | None:
    """The system owner a case brief states, or None."""
    return system_owner_field(text)[2]


def _brief(case_dir: str | os.PathLike) -> str:
    from core.investigation_tasks import read_case_markdown
    return read_case_markdown(case_dir)


def get_engagement(case_dir: str | os.PathLike) -> str:
    """The case's engagement type: what CASE.md states, else an incident."""
    try:
        found = parse_engagement(_brief(case_dir))
    except Exception:  # noqa: BLE001 - an unreadable brief is an incident, as before
        found = None
    return found or DEFAULT_ENGAGEMENT


def is_examination(case_dir: str | os.PathLike | None) -> bool:
    """True when the case examines a device or image after the fact, so
    no first-hour response step can be taken on it."""
    return bool(case_dir) and get_engagement(case_dir) == "examination"


def get_system_owner(case_dir: str | os.PathLike) -> str:
    """Whose system the evidence comes from: what CASE.md states, else
    unknown."""
    try:
        found = parse_system_owner(_brief(case_dir))
    except Exception:  # noqa: BLE001 - an unreadable brief states nothing
        found = None
    return found or DEFAULT_SYSTEM_OWNER


def is_suspect_device(case_dir: str | os.PathLike | None) -> bool:
    """True when the evidence comes from the device of the person under
    investigation, so no remediation is recommended to its owner."""
    return bool(case_dir) and get_system_owner(case_dir) == "suspect"


def unrecognized_system_owner(case_dir: str | os.PathLike | None) -> str | None:
    """A warning when the brief states a system owner Atlas does not
    know, which it reads as unknown; None when absent or known."""
    if not case_dir:
        return None
    try:
        present, raw, canonical = system_owner_field(_brief(case_dir))
    except Exception:  # noqa: BLE001
        return None
    if not present or canonical:
        return None
    shown = raw or "(empty)"
    return (f"CASE.md states a system owner Atlas does not recognise: {shown!r} "
            f"(the first word must be one of: {', '.join(SYSTEM_OWNERS)}); the "
            "owner is treated as unknown and the recommendations assume a victim")


def unrecognized_engagement(case_dir: str | os.PathLike | None) -> str | None:
    """A warning when the brief states an engagement Atlas does not know,
    which it treats as an incident; None when the field is absent or
    known."""
    if not case_dir:
        return None
    try:
        present, raw, canonical = engagement_field(_brief(case_dir))
    except Exception:  # noqa: BLE001
        return None
    if not present or canonical:
        return None
    shown = raw or "(empty)"
    return (f"CASE.md states an engagement Atlas does not recognise: {shown!r} "
            f"(known: {', '.join(ENGAGEMENTS)}); the case is treated as an "
            "incident-response engagement")


def engagement_status(case_dir: str | os.PathLike) -> dict[str, Any]:
    """What the brief states about the engagement, for Plane A's result."""
    try:
        present, raw, canonical = engagement_field(_brief(case_dir))
    except Exception:  # noqa: BLE001
        present, raw, canonical = False, "", None
    try:
        o_present, o_raw, o_canonical = system_owner_field(_brief(case_dir))
    except Exception:  # noqa: BLE001
        o_present, o_raw, o_canonical = False, "", None
    return {"value": canonical or DEFAULT_ENGAGEMENT, "stated": present,
            "raw": raw, "unrecognized": bool(present and not canonical),
            "system_owner": {
                "value": o_canonical or DEFAULT_SYSTEM_OWNER, "stated": o_present,
                "raw": o_raw, "unrecognized": bool(o_present and not o_canonical)}}


def engagement_prompt_note(case_dir: str | os.PathLike | None) -> str:
    """The block the analyst's prompt carries when the engagement or the
    system owner changes what a recommendation may be: nothing on a plain
    incident on a victim's systems."""
    if not case_dir:
        return ""
    owner = get_system_owner(case_dir)
    after = is_examination(case_dir)
    if owner == "suspect":
        return (
            "# SYSTEM OWNER: THE PERSON UNDER INVESTIGATION\n"
            "The device or image belongs to the person under investigation. "
            "Record no containment, isolation, blocking, eradication, recovery "
            "or hardening step as a recommendation: there is no owner to "
            "remediate. A recommendation, where one is warranted, is an "
            "investigative next step, a preservation or legal-process request "
            "for a named account or provider, notification of an identified "
            "third party, or an escalation of ongoing harm."
            + ("" if after else
               " The device was seized running: preserving memory before "
               "power-off and isolating it from networks without powering it "
               "off are the first-hour steps that apply.")
            + "\n"
        )
    if not after:
        return ""
    return (
        "# ENGAGEMENT: EXAMINATION AFTER THE FACT\n"
        "This case examines a device or image after the event, but the "
        "owner's systems are still in service and the owner's duties remain. "
        "Record the containment, eradication, recovery and hardening steps "
        "the findings warrant for the owner's live estate (the named accounts "
        "to reset, the named persistence to remove, the named addresses to "
        "block), each applying only if the owner has not already taken it. A "
        "mitigation from the ATT&CK table is a lesson for the owner (phase "
        "harden, urgency later), not a first-hour step."
        + ("" if owner == "victim" else
           " The brief does not say whose system this is; assume the owner is "
           "the victim and say so where it matters.")
        + "\n"
    )


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def config_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "case_config.json"


def empty_config() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_language": DEFAULT_LANGUAGE,
        # Optional opt-in hypotheses, e.g. {"hid_injection": true}.
        # See core.case_intents — never infer these from evidence layout alone.
        "intents": {},
        "updated_at": "",
    }


def load_case_config(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = config_path(case_dir)
    if not path.is_file():
        return empty_config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_config()
    if not isinstance(data, dict):
        return empty_config()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("report_language", DEFAULT_LANGUAGE)
    return data


def save_case_config(
    case_dir: str | os.PathLike, config: dict[str, Any],
) -> Path:
    path = config_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = dict(config)
    cfg["schema_version"] = SCHEMA_VERSION
    cfg["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def get_report_language(case_dir: str | os.PathLike) -> str:
    lang = (load_case_config(case_dir).get("report_language") or DEFAULT_LANGUAGE)
    lang = str(lang).strip().lower()
    if lang in ("ger", "german", "deutsch"):
        lang = "de"
    if lang in ("eng", "english"):
        lang = "en"
    return lang if lang in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def set_report_language(
    case_dir: str | os.PathLike, language: str,
) -> dict[str, Any]:
    lang = (language or DEFAULT_LANGUAGE).strip().lower()
    if lang in ("ger", "german", "deutsch"):
        lang = "de"
    if lang in ("eng", "english"):
        lang = "en"
    if lang not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"unsupported report language: {language!r} "
            f"(supported: {', '.join(sorted(SUPPORTED_LANGUAGES))})"
        )
    cfg = load_case_config(case_dir)
    cfg["report_language"] = lang
    save_case_config(case_dir, cfg)
    return cfg
