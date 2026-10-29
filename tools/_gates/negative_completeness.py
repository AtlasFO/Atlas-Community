"""Gate: a negative/absence finding must search its claim's COMPLETE source set,
and the searched logs must cover the claim's time window.

Fires only on UNCONFIRMED findings (negatives are recorded UNCONFIRMED) whose
description matches a known case-inverting category (logon/auth, identity,
persistence, exfil — see _manifests.py). A manifest source is satisfied if the
trace shows a tool_call touched it OR an explicit "<source> absent from evidence"
note. STRICT: any unsatisfied source, or a claim window outside every searched
log's coverage, is a hard refusal.

Prose absence escapes are refused when access-gated disk media is still
planned/staged (never opened) — see core.evidence_access.
"""
from __future__ import annotations

import re
from typing import Optional

from ._device_install import claim_dates, flagged_count, inventory_for
from ._manifests import MANIFESTS, classify

# Names the device-install log / USB device class — used only to honour the
# explicit "<source> absent from evidence" escape for DEVICE_INITIAL_ACCESS.
_DEVLOG_NAME_RE = re.compile(
    r"setupapi(?:\.dev)?\.log|device[- ]install log|usb device[- ]class",
    re.IGNORECASE,
)

# A date in the claim description → the window the negative is asserted over.
_DATE_RE = re.compile(r"\b(\d{4})[-/](\d{1,2})[-/](\d{1,2})\b")

# Explicit "this source is genuinely absent from the evidence" escape.
_ABSENT_RE = re.compile(
    r"(?:absent from evidence|not (?:present|collected)|not in (?:the )?(?:evidence|image|collection)"
    r"|no (?:such )?(?:log|artifact|channel|store)\b)",
    re.IGNORECASE,
)


def _tool_cmds(ctx) -> list:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    return [e for e in by_type.get("tool_call", []) if isinstance(e.get("cmd"), str)]


def _claim_dates(text: str) -> list:
    out = []
    for y, m, d in _DATE_RE.findall(text or ""):
        try:
            out.append(f"{int(y):04d}-{int(m):02d}-{int(d):02d}")
        except ValueError:
            pass
    return out


def _case_dir(ctx) -> str | None:
    log = getattr(ctx, "log", None)
    if log is None:
        return None
    try:
        fn = getattr(log, "case_dir", None)
        if callable(fn):
            return fn() or None
        return getattr(log, "_case_dir", None) or None
    except Exception:
        return None


def _claim_scope_text(ctx) -> str:
    """What the claim is about, for scoping media checks: its words, its
    supporting evidence, and what the calls it cites were asked to read."""
    from .lineage_relevance import entry_text
    parts = [ctx.description or "", getattr(ctx, "supporting_evidence", "") or ""]
    by = getattr(getattr(ctx, "idx", None), "by_call_id", None) or {}
    cids = list(getattr(ctx, "input_call_ids", None) or [])
    linked = getattr(ctx, "linked_call_id", 0)
    if linked and linked not in cids:
        cids.append(linked)
    for cid in cids:
        e = by.get(cid)
        if isinstance(e, dict) and e.get("type") == "tool_call":
            parts.append(entry_text(e))
    return " ".join(parts)


def _access_blocks_absent_escape(ctx) -> Optional[dict]:
    """Block prose 'absent from evidence' when disk never opened or winevt unsearched."""
    case = _case_dir(ctx)
    if not case:
        return None
    try:
        from core.evidence_access import (
            absence_escape_blocked_by_access,
            absence_escape_blocked_for_winevt,
        )
        reason = absence_escape_blocked_by_access(case, about_text=_claim_scope_text(ctx))
        detail = "access_not_opened"
        if not reason:
            claim = f"{ctx.description or ''} {getattr(ctx, 'supporting_evidence', '') or ''}"
            reason = absence_escape_blocked_for_winevt(case, _tool_cmds(ctx), claim)
            detail = "eventlog_not_searched"
    except Exception:
        return None
    if not reason:
        return None
    return {
        "success": False,
        "error": (
            f"Refusing UNCONFIRMED absence claim: {reason} "
            "Inspected-absent requires opened media and a real search of the "
            "event log (or access_failed); never-opened / never-searched disk "
            "is not the same as 'source absent'."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "negative_completeness",
        "detail_gate": detail,
    }


# Artifact families that live *inside* a disk image rather than beside it.
# Absence of one of these says nothing until the container is opened.
# NB: NTFS metafile names start with "$", and \b never matches between a
# space and "$" (both non-word), so those alternatives sit outside the
# word-boundary group rather than inside it.
from core.eventlog_layout import log_names_regex_fragment as _log_names

_DISK_RESIDENT_RE = re.compile(
    r"(?i)(?:\b(?:evtx|event\s+log(?:s)?|" + _log_names() + r"|"
    r"winevt|registry|hive|ntuser|usrclass|amcache|"
    r"shimcache|prefetch|master\s+file\s+table|usn\s*journal|"
    r"srum|shellbag|jumplist|lnk\s+file|recycle\.bin)\b"
    r"|\$mft\b|\$j\b|\$usnjrnl\b|\$logfile\b)"
)

# Absence predicated of the artifact: "no Security.evtx", "the hives were
# not collected", "Prefetch is absent/missing/unavailable", "no EVTX is
# present". Any negation anywhere in a finding is not that: a positive
# finding about a registry value that says the machine is "NOT joined to a
# domain" mentions a hive and a negation and asserts nothing absent. The
# negation and the artifact name must be in the same sentence, with the
# negation shaped as one of existence or presence.
_ASSERTS_ABSENCE_RE = re.compile(
    r"(?i)(?:\b(?:no|without|lacks?|lacking)\s+(?:\w+\s+){0,3}?(?=ARTIFACT)"
    r"|(?:ARTIFACT)[^.;\n]{0,80}?\b(?:absent|absence|missing|unavailable|"
    r"not\s+(?:present|found|recovered|collected|available|there|exist\w*)|"
    r"(?:was|were|is|are)\s+not\s+(?:in|on|part\s+of)\b|"
    r"do(?:es)?\s+not\s+exist|never\s+(?:written|created|existed))"
    r"|\b(?:absent|absence\s+of|missing|unavailable|not\s+(?:present|found|"
    r"recovered|collected))\b[^.;\n]{0,60}?(?=ARTIFACT))"
    .replace("ARTIFACT", _DISK_RESIDENT_RE.pattern[4:])
)


def _absence_before_container_opened(ctx) -> Optional[dict]:
    """Refuse "artifact X is absent" while the image holding X was never opened.

    Narrow by construction — all three must hold:
      * the claim asserts an absence,
      * of an artifact family that lives inside a disk image, and
      * the case has disk media still unopened
        (``access_failed`` already excuses it — collection genuinely failed).

    Anything else is untouched, including every absence claim about evidence
    that sits beside the image (firewall logs, exports) and every claim made
    after the image is open.
    """
    text = (ctx.description or "") + " " + (ctx.supporting_evidence or "")
    if not _DISK_RESIDENT_RE.search(text):
        return None
    if not _ASSERTS_ABSENCE_RE.search(text):
        return None
    blocked = _access_blocks_absent_escape(ctx)
    if not blocked:
        return None
    # Reuse the existing refusal, but say plainly what the reader must do —
    # the finding is not wrong, it is unearned at this point in the run.
    blocked = dict(blocked)
    inner = str(blocked.get("error") or "")
    # The inner text is written for the UNCONFIRMED path; this check is
    # tier-independent, so do not mislabel a SUSPECTED claim.
    inner = inner.replace("Refusing UNCONFIRMED absence claim: ", "")
    from core.eventlog_layout import locations
    blocked["error"] = (
        f"Refusing this {ctx.tier or 'absence'} claim about disk-resident "
        f"artifacts: {inner}"
        + " Open the image and enumerate the artifact's own location "
        f"(e.g. tsk.fls over the directory holding {locations()}) before "
        "asserting it is missing. 'Not in the evidence folder' is not 'not "
        "on the disk' — the logs are inside the image."
    )
    return blocked


# The shape of an absence claim, whatever its subject. Kept broad on purpose:
# the check that uses it fires only when such a claim rests on a program that
# could not run, so a false positive here costs nothing.
_ABSENCE_SHAPE_RE = re.compile(
    r"(?i)\b(?:no|not|never|none|zero)\b[^.;]{0,80}?"
    r"\b(?:found|present|detected|observed|identified|located|recovered|"
    r"discovered|evidence|indication|traces?|hits?|matches?|results?)\b"
    r"|\babsen(?:t|ce)\b|\bnot found\b"
)

# How a call that could not run because its program is not installed looks
# in the trace: the executor's spawn failure, or a wrapper's refusal.
_PROGRAM_MISSING_RE = re.compile(
    r"(?i)(?:^|\W)tool not found\b|program_missing|is not installed\b"
)


def _program_of(entry: dict) -> str:
    cmd = str(entry.get("cmd") or "")
    if cmd.startswith("<py>:"):
        rest = cmd[5:].split()
        return rest[0] if rest else ""
    head = cmd.replace("sudo ", "", 1).split()
    return head[0].rsplit("/", 1)[-1] if head else ""


def _program_missing(entry: dict) -> bool:
    if entry.get("success"):
        return False
    blob = f"{entry.get('stderr') or ''} {entry.get('stdout_excerpt') or ''}"
    return bool(_PROGRAM_MISSING_RE.search(blob))


def _absence_on_unavailable_program(ctx) -> Optional[dict]:
    """An absence claim that rests on a search which never ran.

    A program that is not installed establishes nothing: "not found" after
    the extractor failed to start is a gap in capability, not a negative
    result. Two ways the claim can rest on such a call — it cites one, or a
    recent call to a program the claim itself names failed for that reason.
    Either way the honest record is a limitation, which the report carries
    in its own section; a finding is refused.
    """
    desc = ctx.description or ""
    if not _ABSENCE_SHAPE_RE.search(desc):
        return None
    by_call_id = getattr(getattr(ctx, "idx", None), "by_call_id", None) or {}
    cids = list(getattr(ctx, "input_call_ids", None) or [])
    linked = getattr(ctx, "linked_call_id", 0)
    if linked and linked not in cids:
        cids.append(linked)
    candidates: list[dict] = [by_call_id.get(c) or {} for c in cids]
    low = desc.lower()
    for entry in (getattr(ctx, "window", None) or []):
        if entry.get("type") != "tool_call" or entry in candidates:
            continue
        prog = _program_of(entry).lower()
        if prog and len(prog) >= 3 and prog in low:
            candidates.append(entry)
    missing = [e for e in candidates if e and _program_missing(e)]
    if not missing:
        return None
    named = sorted({_program_of(e) for e in missing if _program_of(e)})
    ids = [e.get("call_id") for e in missing]
    return {
        "success": False,
        "error": (
            f"Refusing this absence claim: it rests on {', '.join(named) or 'a program'} "
            f"which is not installed (call {ids[0]} failed to start). A search "
            "that could not run establishes nothing about what is absent. "
            "Record the gap as a limitation instead — state which program was "
            "unavailable and what it would have examined — or install it and "
            "re-run before concluding absence."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "negative_completeness",
        "detail_gate": "absence_on_unavailable_program",
        "unavailable_programs": named,
        "failed_call_ids": ids,
    }


# Grammar and absence words left out of an absence sentence's class words
# (English and German function words; no artefact or case vocabulary).
_CLASS_STOP = frozenset((
    "no", "not", "none", "never", "nothing", "any", "was", "were", "is", "are", "be", "been", "the", "a", "an",
    "of", "on", "in", "at", "for", "from", "to", "by", "with", "and", "or", "that", "this", "these", "those",
    "found", "present", "seen", "observed", "detected", "recorded", "exists", "exist", "existed", "absent",
    "missing", "there", "it", "its", "has", "have", "had", "evidence", "host", "system", "kein", "keine",
    "nicht", "nie", "auf", "im", "in", "der", "die", "das", "gefunden", "vorhanden", "beobachtet"))
_CLASS_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.$-]{2,}")
# A statement of what was read, not of the host: the gate's own remedy.
_READ_SCOPE_RE = re.compile(r"(?i)\b(?:exports?|rows|tables?|timeline)\s+searched\b|\bin the (?:rows|exports?) "
                            r"(?:read|searched)\b")


def _profile_gate_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_ABSENCE_GATE_V2")


def _args_text(entry: dict) -> str:
    args = entry.get("args")
    return args if isinstance(args, str) else ""


def _profile_shortfall(ctx, sid: str, rx, hits: list, blob: str) -> Optional[str]:
    """None when a hit is credited (a read of the log itself, an export whose
    profile carries the channel and the claim's event ids, or an export with
    no profile row, with an advisory); else the refusal sentence."""
    from core.envfile import env_flag
    if not env_flag("ATLAS_ABSENCE_GATE_V2") or not str(sid).startswith(("security", "sessions")):
        return None
    case = _case_dir(ctx)
    if not case:
        return None
    from core.export_profile import claim_event_ids, export_covers
    ids = claim_event_ids(blob)
    shortfalls = []
    for e in hits:
        ok, why = export_covers(case, e, rx, ids)
        if ok:
            return None
        if ok is None:
            notes = getattr(ctx, "notes", None)
            if isinstance(notes, dict):
                notes["export_profile_advisory"] = why
            return None
        shortfalls.append(why)
    from core.contents_index import handle_clause
    return ("The searches cited read " + "; ".join(shortfalls) + ". Read the log itself (" + handle_clause()
            + "), or state the absence as what was read ('not in the <export> rows searched'), not as absent "
              "from the host.")


def _index_absence(ctx) -> Optional[dict]:
    """An absence about a host is checked against the case's own index
    (the contents index): when the index lists files on that host that the
    sentence's class words name and that no call read, the claim is refused
    with the count, an example and a handle (ATLAS_ABSENCE_GATE_V2)."""
    from core.envfile import env_flag
    if not env_flag("ATLAS_ABSENCE_GATE_V2"):
        return None
    case = _case_dir(ctx)
    if not case:
        return None
    try:
        from core.contents_index import class_absence_candidates, index_on
        from core.forensic_citation import host_mentioned, known_case_hosts
    except Exception:  # noqa: BLE001
        return None
    if not index_on():
        return None
    desc = ctx.description or ""
    if _READ_SCOPE_RE.search(desc):
        return None
    hosts = list(dict.fromkeys(known_case_hosts(case)))
    from .universal_from_truncated import _P_ABSENCE_RE, analysts_words
    for written in re.split(r"(?<=[.;!?])\s+", " ".join(desc.split())):
        # The analyst's own claim, as the universal gate reads it: a quote, a
        # hedge, a condition or the run's own progress states no absence.
        sentence = analysts_words(written)
        if not _P_ABSENCE_RE.search(sentence):
            continue
        named = [h for h in hosts if host_mentioned(h, sentence)]
        if not named and getattr(ctx, "host", ""):
            named = [ctx.host]
        if not named:
            continue
        host_words = {w.casefold() for h in named for w in re.split(r"[^A-Za-z0-9]+", h) if w}
        words = [w.strip(".-").casefold() for w in _CLASS_WORD_RE.findall(sentence)]
        words = [w for w in dict.fromkeys(words) if w and w not in _CLASS_STOP and w not in host_words
                 and not any(host_mentioned(h, w) for h in named)]
        for host in named:
            cands = class_absence_candidates(case, host, words)
            if not cands:
                continue
            ex = cands[0]
            return {
                "success": False, "gate": "negative_completeness", "detail_gate": "index_absence",
                "description": ctx.description, "confidence": ctx.confidence, "objected_sentences": [written],
                "error": (f"The case's index lists {len(cands)} file(s) matching '{' '.join(words)}' on {host} "
                          f"(for example {ex['path']}), none read. Read one ({ex['handle'] or ex['path']}) or "
                          "state the absence as 'not in the exports searched'."),
            }
    return None


def check(ctx) -> Optional[dict]:
    """The refusal names the sentences it objects to: the finding's absence
    sentences, unless the check named its own (core.work_order keeps the
    rest of a refused finding on the table)."""
    out = _check(ctx)
    if out is not None and not out.get("objected_sentences"):
        from .universal_from_truncated import _P_ABSENCE_RE, analysts_words, split_sentences
        absent = [s for s in split_sentences(ctx.description or "") if _P_ABSENCE_RE.search(analysts_words(s))]
        if absent:
            out = {**out, "objected_sentences": absent}
    return out


def _check(ctx) -> Optional[dict]:
    # An absence asserted on the strength of a program that never ran is a
    # capability gap wearing a finding's clothes — any tier, any category.
    unavailable = _absence_on_unavailable_program(ctx)
    if unavailable:
        return unavailable

    # An absence on a host whose listed image holds unread files the
    # sentence names: the case's own index answers before any manifest.
    indexed = _index_absence(ctx)
    if indexed:
        return indexed

    # Tier- and category-independent: an artifact that lives *inside* a disk
    # image cannot be declared absent while that image has never been
    # opened. This runs before the tier test on purpose — the guard it uses
    # already existed and was correct, but only UNCONFIRMED findings in a
    # manifest category ever reached it, so a SUSPECTED "no Security.evtx /
    # no System.evtx / no Prefetch" would pass straight through and become
    # the premise of the rest of the run. Confidence does not repair an
    # unexamined container.
    unopened = _absence_before_container_opened(ctx)
    if unopened:
        return unopened

    if ctx.tier != "UNCONFIRMED":
        return None
    desc = ctx.description or ""
    category = classify(desc)
    if not category:
        return None

    spec = MANIFESTS[category]
    cmds = _tool_cmds(ctx)
    blob = desc + " " + (ctx.supporting_evidence or "")

    # OS / channel alternative that waives the required list (e.g. a Linux host
    # satisfies LOGON_AUTH via wtmp/last instead of the Windows event channels).
    alt = spec.get("alt_satisfies")
    if alt and any(alt.search(e["cmd"]) for e in cmds):
        return None

    # DEVICE_INITIAL_ACCESS: a "no BadUSB" negative must be grounded on a COMPLETE
    # structured device-install inventory (misc.device_install_inventory parses the
    # whole setupapi.dev.log), not a keyword grep over a truncated/windowed dump.
    # And the negative cannot stand if that inventory FLAGGED a device. An explicit
    # "<log> absent from evidence" note still escapes — unless disk access stage
    # says the image was never opened.
    if category == "DEVICE_INITIAL_ACCESS":
        if _ABSENT_RE.search(blob) and _DEVLOG_NAME_RE.search(blob):
            blocked = _access_blocks_absent_escape(ctx)
            if blocked:
                return blocked
            return None
        inv = inventory_for(ctx, claim_dates(blob))
        if inv is None:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: it asserts no BadUSB / "
                    f"HID-injection device, but no COMPLETE device-install inventory "
                    f"covering the window exists in the trace. USBSTOR / mass-storage "
                    f"enumeration and keyword greps over setupapi.dev.log can silently "
                    f"miss a device — run misc.device_install_inventory to enumerate "
                    f"every device, or record an explicit 'setupapi.dev.log absent from "
                    f"evidence' finding, before concluding absence."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }
        fc = flagged_count(inv)
        if fc > 0:
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: it asserts no BadUSB, "
                    f"but the structured device-install inventory FLAGGED {fc} "
                    f"keystroke-injection-capable device(s) in the window (a device "
                    f"exposing both HID/keyboard and mass-storage interfaces). "
                    f"A 'no BadUSB' negative cannot stand over an inventory that "
                    f"flagged a device — disposition the flagged device(s) explicitly "
                    f"(benign, with reasons) or record it as a positive finding."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }
        return None

    # 1) Manifest completeness — every required source touched or proven absent.
    # A category whose sources depend on what the media is (the Windows
    # event-log layout) resolves them from the trace and the claim.
    required = spec["required"]
    if callable(required):
        required = required(cmds, blob)
    where = spec["where"]
    if callable(where):
        where = where(cmds, blob)
    missing = []
    profile_refusals: list[str] = []
    for _sid, rx, hint in required:
        # What the call was asked to read: its command line and arguments
        # (a typed tool's command line names only the tool).
        hits = [e for e in cmds if rx.search(e["cmd"]) or (_profile_gate_on() and rx.search(_args_text(e)))]
        if hits:
            # A table read of an export counts for an event-log source only
            # for the channels and event ids the export's profile shows.
            why = _profile_shortfall(ctx, _sid, rx, hits, blob)
            if why is None:
                continue
            profile_refusals.append(why)
            continue
        if _ABSENT_RE.search(blob) and rx.search(blob):
            blocked = _access_blocks_absent_escape(ctx)
            if blocked:
                return blocked
            continue
        missing.append(hint)
    if profile_refusals and not missing:
        return {"success": False, "gate": "negative_completeness", "detail_gate": "export_profile",
                "description": ctx.description, "confidence": ctx.confidence,
                "error": " ".join(profile_refusals)}
    if missing:
        return {
            "success": False,
            "error": (
                f"Refusing UNCONFIRMED {category} finding: it asserts absence but the "
                f"trace never searched {len(missing)} required source(s) — "
                f"{'; '.join(missing)}. A negative is only valid over the COMPLETE "
                f"source set for the claim; absence from the subset you happened to "
                f"search is not evidence of absence. Search {where}, or record "
                f"an explicit '<source> absent from evidence' finding, before "
                f"concluding absence."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "negative_completeness",
        }

    # 2) Coverage window — if the claim names a date, at least one searched source
    #    carrying a coverage_window must span it. A silent (out-of-coverage) log
    #    cannot ground a negative.
    dates = _claim_dates(blob)
    covered = [e for e in cmds if isinstance(e.get("coverage_window"), dict)]
    if dates and covered:
        def _spans(cw: dict, day: str) -> bool:
            s = (cw.get("start") or "")[:10]
            e = (cw.get("end") or "")[:10]
            return bool(s and e and s <= day <= e)

        if not any(_spans(e["coverage_window"], day) for e in covered for day in dates):
            ranges = ", ".join(
                f"{(e['coverage_window'].get('start') or '?')[:10]}→"
                f"{(e['coverage_window'].get('end') or '?')[:10]}"
                for e in covered[:4]
            )
            claim = ", ".join(dates[:4])
            return {
                "success": False,
                "error": (
                    f"Refusing UNCONFIRMED {category} finding: the searched log(s) cover "
                    f"{ranges} but the claim window ({claim}) is OUTSIDE that coverage — a "
                    f"negative cannot be drawn from a log that is silent about the window. "
                    f"Search a source that covers it: TerminalServices logs, Volume Shadow "
                    f"Copies, or carved EVTX from unallocated/pagefile/hiberfil."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "negative_completeness",
            }

    return None
