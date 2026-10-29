"""Client-facing forensic report assembler.

Separates responsibilities:

* **LLM** (optional): Executive Summary narrative; per-finding Summary /
  Assessment; Gaps / Recommendations narrative prose stored in section bodies.
* **Deterministic code**: TOC, section order, F-IDs, Key Findings table,
  Supporting Evidence (via Evidence Resolver), Attack Timeline rows, Trace,
  Confidence, MITRE tags, Appendix artifact references.

``render_markdown`` / ``assemble_report`` call ``assemble_client_report`` so
future reports always follow the standard spine regardless of how section
prose was generated.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Any

from core.report_projection import (
    GENERATOR_VERSION,
    SECTION_ORDER,
    _load_section_body,
    load_manifest,
)

_FINDING_HDR_RE = re.compile(
    r"(?m)^#{2,4}\s*(F-\d+)\s*[—\-:\[]\s*(.*)$"
)
_SUMMARY_RE = re.compile(
    r"(?is)\*\*(?:Summary|Zusammenfassung)\*\*\s*\n+(.*?)(?=\n\*\*|\n#{2,4}\s|\Z)"
)
_ASSESSMENT_RE = re.compile(
    r"(?is)\*\*(?:Assessment|Bewertung)\*\*\s*\n+(.*?)(?=\n\*\*|\n#{2,4}\s|\Z)"
)


def _exec_next_steps(case_dir, language: str, *, scope: str = "case", host: str = "") -> list[str]:
    """The summary's next steps, by code from the recorded response plan:
    the open rows that rest on a finding (a prior-knowledge precaution
    rests on none and is not a next step of this case), in the lifecycle
    order of the engagement (core.recommendations.grouped: an examination
    investigates first and contains last, an incident the reverse), at most
    three with "+N more" for the rest; "no step recorded" when the plan
    holds none. The model writes none: a step it would add rests on nothing
    the plan records."""
    from core.report_i18n import t
    try:
        from core.recommendations import build_catalog, grouped
        catalog = build_catalog(case_dir)
        rows = [r for r in (catalog.get("recommendations") or [])
                if r.get("state") == "open" and not r.get("basis_lost")
                and r.get("source") != "prior_knowledge"]
        rows = [r for _phase, prow in grouped({**catalog, "recommendations": rows}) for r in prow]
    except Exception:  # noqa: BLE001 - no plan is no step
        rows = []
    if scope == "host" and host:
        h = host.strip().lower()
        rows = [r for r in rows if r.get("scope") == "host"
                and (not r.get("hosts") or h in (x.lower() for x in r["hosts"]))]
    out = ["", f"**{t('exec_next_steps', language)}**", ""]
    if not rows:
        out.append(f"- {t('exec_no_step', language)}")
        return out
    for r in rows[:3]:
        phase = t("response_phase_" + str(r.get("phase") or "investigate"), language)
        urgency = t("response_urgency_" + str(r.get("urgency") or "soon"), language)
        out.append(f"- {_md_inline(str(r.get('action') or ''))} ({phase}, {urgency}) — {r.get('id')}")
    if len(rows) > 3:
        out.append(f"- {t('exec_more_steps', language).format(n=len(rows) - 3)}")
    return out


def _part_lines(task: dict, fid_of: dict, language: str) -> list[str]:
    """One line per part of the request: the value found and the finding it
    came from, a limitation with its basis, or open. Values come from the
    part itself, never from a headline."""
    from core.report_i18n import t
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    # One part is itemised too when it was limited, or answered on the
    # analyst's link rather than a read value: the reader has to see that.
    if len(parts) < 2 and not any(p.get("status") == "limited" or p.get("bound_by") == "analyst"
                                  for p in parts):
        return []
    out = ["", f"*{t('answer_parts_heading', language)}:*", ""]
    for p in parts:
        st = p.get("status")
        text = _md_inline(str(p.get("text") or ""))
        if st == "answered":
            refs = [fid_of.get(c) or c for c in (p.get("claim_ids") or [])]
            val = f" {_md_inline(str(p.get('value')))}" if p.get("value") else ""
            state = t("answer_part_linked" if p.get("bound_by") == "analyst" else "answer_part_answered", language)
            out.append(f"- {text}: {state}{val}"
                       + (f" ({', '.join(str(r) for r in refs)})" if refs else ""))
        elif st == "limited":
            lim = p.get("limitation") or {}
            out.append(f"- {text}: {t('answer_part_limited', language)} — {lim.get('basis', '')}: "
                       f"{_md_inline(str(lim.get('reason') or ''))}")
        else:
            out.append(f"- {text}: {t('answer_part_open', language)}")
    out.append("")
    return out


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")


def _strip_outer_heading(prose: str) -> str:
    lines = (prose or "").splitlines()
    if lines and lines[0].lstrip().startswith("#"):
        return "\n".join(lines[1:]).lstrip()
    return (prose or "").strip()


# A tier written into the heading — "F-001 [SUSPECTED]: …", "F-001 (LIKELY) —",
# "F-001 · CONFIRMED: …", or trailing "[SUSPECTED]" — is not part of the title;
# the assembler prints the tier itself. Left in, the deterministic stub's
# headings came out as "SUSPECTED]: Firewall log …".
_TITLE_TIER_RE = re.compile(
    r"(?i)^[\s—\-:·]*[\[(]?\s*(?:CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED|REFUTED|"
    r"WITHDRAWN|POSSIBLE|PROBABLE)\s*[\])]?\s*[:—\-·]?\s*"
    r"|\s*[\[(]\s*(?:CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED|REFUTED|WITHDRAWN|"
    r"POSSIBLE|PROBABLE)\s*[\])]\s*$")


def parse_finding_narratives(prose: str) -> dict[str, dict[str, str]]:
    """Extract per-F-id Summary/Assessment from LLM detailed_findings prose."""
    text = _strip_outer_heading(prose or "")
    if not text.strip():
        return {}
    # Split on finding headers
    parts = re.split(r"(?m)(?=^#{2,4}\s*F-\d+)", text)
    out: dict[str, dict[str, str]] = {}
    for part in parts:
        m = re.match(r"(?m)^#{2,4}\s*(F-\d+)\b([^\n]*)\n?(.*)$", part, re.S)
        if not m:
            continue
        fid = m.group(1)
        title = _TITLE_TIER_RE.sub("", m.group(2) or "")
        title = re.sub(r"^[\s—\-:·\[]+", "", title).strip().rstrip("]").strip()
        body = m.group(3) or ""
        # Stop before dumped evidence appendix
        if "Supporting Evidence (deterministic)" in body:
            body = body.split("Supporting Evidence (deterministic)", 1)[0]
        sm = _SUMMARY_RE.search(body)
        am = _ASSESSMENT_RE.search(body)
        summary = (sm.group(1).strip() if sm else "")
        assessment = (am.group(1).strip() if am else "")
        if summary or assessment or title:
            out[fid] = {"summary": summary, "assessment": assessment,
                        "title": title}
    return out


def _narrative_section(case_dir: Path, section_id: str) -> str:
    body = _load_section_body(case_dir, section_id)
    return _strip_outer_heading(body.get("prose") or "")


def _hosts_from_nodes(nodes: list[dict]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for n in nodes:
        h = (n.get("host") or "").strip()
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _mitre_from_node(node: dict) -> list[str]:
    tactics = list(node.get("tactics") or [])
    stmt = (node.get("statement") or "") + " " + (node.get("reasoning") or "")
    techs = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", stmt)
    out: list[str] = []
    for x in tactics + techs:
        if x not in out:
            out.append(x)
    return out


def _trace_bits(node: dict) -> list[str]:
    bits: list[str] = []
    nid = node.get("id") or ""
    kind = node.get("kind") or ""
    if nid:
        if kind == "conclusion":
            bits.append(f"Conclusions: {nid}")
        else:
            bits.append(f"Claims: {nid}")
    for e in node.get("evidence") or []:
        if isinstance(e, dict) and e.get("call_id") is not None:
            bits.append(f"Calls: call_{e['call_id']}")
    # de-dupe preserving order
    return list(dict.fromkeys(bits))


def _valid_timestamp(value: Any) -> str:
    """A timestamp that parses as one, normalised — or ""."""
    try:
        from core.forensic_citation import normalize_timestamp
        return normalize_timestamp(value)
    except Exception:  # noqa: BLE001
        return ""


_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][\w ./()-]*$")
_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")


def _looks_like_header(text: str) -> bool:
    """A delimited row whose every field is a column *name*.

    Column names may contain digits (``SHA1``) and a row may start with a
    byte-order mark, so neither "has a digit" nor "starts with a letter"
    separates a header from a record. What does: a header has no field that
    is a number, a date, or empty, and at least four fields that read as
    identifiers.
    """
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    first = first.lstrip("\ufeff")
    for delim in (",", ";", "\t"):
        fields = [f.strip().strip('"') for f in first.rstrip(delim).split(delim)]
        if len(fields) < 4:
            continue
        if any(not f or _NUMERIC_RE.match(f) or _valid_timestamp(f) for f in fields):
            return False
        if all(_FIELD_NAME_RE.match(f) for f in fields):
            return True
    return False


def _short_event_label(ev: dict) -> str:
    text = (ev.get("text") or "").strip()
    # A record from a known exporter is named by what it is, not quoted.
    try:
        from core.forensic_citation import describe_record, evtxecmd_fields
        cols = evtxecmd_fields(text)
        if cols:
            label = describe_record(text) or f"Event {cols['event_id']}"
            if cols.get("description"):
                label += f" — {cols['description']}"
            elif cols.get("user"):
                label += f" — {cols['user']}"
            return label[:80]
    except Exception:  # noqa: BLE001
        pass
    # Prefer first non-header data line
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("timestamp") or line.lower().startswith("datetime"):
            continue
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 4 and parts[3].strip() and parts[3].strip().lower() != "event":
                return parts[3].strip()[:80]
            if len(parts) >= 6 and parts[5].strip():
                return parts[5].strip()[:80]
        one = re.sub(r"\s+", " ", line)[:80]
        if one.lower() not in ("timestamp", "machine", "user", "event"):
            return one
    return "event"


def _fields_from_event_text(text: str) -> dict[str, str]:
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        parts = line.split("\t")
        if parts[0].strip().lower() in ("timestamp", "datetime"):
            continue
        if len(parts) >= 4 and parts[3].strip().lower() == "event":
            continue
        host = parts[1].strip() if len(parts) > 1 else ""
        user = parts[2].strip() if len(parts) > 2 else ""
        event = parts[3].strip() if len(parts) > 3 else ""
        # Reject mis-parsed multi-line evidence_index blobs
        if len(host) > 48 or host.count(" ") > 3:
            continue
        if len(user) > 48 or user.count(" ") > 2:
            user = ""
        return {
            "timestamp": parts[0].strip() if parts else "",
            "host": host,
            "user": user,
            "event": event,
        }
    return {}


_WHEN_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2})(?::\d{2})?)?")


def _when_of(statement: str) -> str:
    """First date (and time, when written) a statement mentions."""
    m = _WHEN_RE.search(statement or "")
    if not m:
        return ""
    return f"{m.group(1)} {m.group(2)} UTC" if m.group(2) else m.group(1)


_MD_STRUCT_RE = re.compile(r"(?m)^(\s*)(#{1,6}\s|[-*+]\s|\d+\.\s|>\s|```)")


def _md_inline(text: str) -> str:
    """Belief text rendered *inside* the report, never *as* the report.

    A statement is whatever a model wrote: it can contain a newline and a
    "## heading", a table pipe, a code fence. Placed raw into Markdown that
    became a new section, a broken table, an unterminated fence. One line,
    structural prefixes neutralised, pipes made literal.
    """
    t = " ".join(str(text or "").split())
    t = t.replace("|", "\\|")
    if _MD_STRUCT_RE.match(t):
        t = "\u200b" + t              # a zero-width space defuses the prefix
    return t


def _short_title(f: dict[str, Any], narrative: dict[str, str], *,
                 with_host: bool = True) -> str:
    """The headline of a finding: what, where, when — never the statement.

    The report used the first 120 characters of the claim as the heading,
    which cut "…containing scanTime=1927972800 (Unix tim" mid-word
    and repeated the whole summary above itself. The model is asked for a
    short title; it is used when it wrote one, otherwise the statement is
    reduced to its headline.
    """
    stmt = _md_inline(f.get("statement") or "")
    title = _md_inline(narrative.get("title") or "")
    if not (8 <= len(title) <= 140) or stmt.lower().startswith(title.lower()[:40]) and len(title) > 100:
        try:
            from core.answer_synthesis import headline
            title = headline(stmt, limit=110)
        except Exception:  # noqa: BLE001
            title = stmt[:110]
    host = (f.get("host") or "").strip()
    if with_host and host and host.lower() not in title.lower():
        title += f" — {host}"
    return title


def _call_ids_of(f: dict[str, Any], *, limit: int = 8) -> list[int]:
    ids: list[int] = []
    for c in list(f.get("input_call_ids") or []) + [
            e.get("call_id") for e in (f.get("evidence") or [])
            if isinstance(e, dict)]:
        try:
            ci = int(c)
        except (TypeError, ValueError):
            continue
        if ci and ci not in ids:
            ids.append(ci)
    return sorted(ids)[:limit]


def _is_open_question_claim(f: dict[str, Any]) -> bool:
    """An UNCONFIRMED belief whose statement says the matter is undecided
    belongs under Evidence Gaps, not among the findings."""
    if (f.get("confidence") or "").upper() != "UNCONFIRMED":
        return False
    try:
        from core.answer_synthesis import GAP, classify_statement
        return classify_statement(f.get("statement") or "") == GAP
    except Exception:  # noqa: BLE001
        return False


def _demote_headings(prose: str, *, below: int = 2) -> str:
    """LLM prose may not out-rank the section it sits in."""
    out = []
    for line in (prose or "").splitlines():
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m and len(m.group(1)) <= below:
            line = "#" * (below + 1) + " " + m.group(2)
        out.append(line)
    return "\n".join(out)


def _evidence_source_lines(root: Path) -> list[str]:
    """One bullet per evidence class the case's inventory found, with an
    example path — what this case holds, not a fixed list of tool names."""
    lines: list[str] = []
    try:
        inv = json.loads((root / ".atlas" / "evidence_inventory.json").read_text(encoding="utf-8"))
        what = (inv.get("assessment") or {}).get("what_exists") or {}
        counts = what.get("counts") or {}
        samples = what.get("sample_paths") or {}
        for cls in sorted(counts, key=lambda c: (-int(counts[c] or 0), c)):
            n = int(counts[cls] or 0)
            ex = [str(p) for p in (samples.get(cls) or [])][:2]
            tail = f" (e.g. {', '.join(f'`{p}`' for p in ex)})" if ex else ""
            lines.append(f"- {cls}: {n} file{'s' if n != 1 else ''}{tail}")
    except Exception:  # noqa: BLE001
        lines = []
    if not lines:
        lines.append("- Files under `evidence/` and the tool outputs derived from them under `analysis/` and `exports/`")
    if (root / "analysis" / "master_timeline.tsv").is_file():
        lines.append("- Curated `analysis/master_timeline.tsv` (claim-relevant events)")
    return lines


def _integrity_lines(root: Path) -> list[str]:
    """One bullet per disk image with what the run established about its
    integrity: the digest the acquisition tool stored and whether the data
    still hashes to it, else the custody hash of the file as received. The
    first thing an examiner states, read from the mount plan's preflight."""
    try:
        plan = json.loads((root / ".atlas" / "mount_plan.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    lines: list[str] = []
    for img in plan.get("images") or []:
        pre = img.get("hash_preflight") or {}
        if not isinstance(pre, dict) or not pre.get("success"):
            continue
        base = img.get("basename") or Path(str(img.get("path") or "")).name
        acq = pre.get("acquisition_hashes") or {}
        if acq:
            algo, digest = next(iter(sorted(acq.items())))
            verdict = {True: "verified by ewfverify", False: "MISMATCH on ewfverify",
                       None: "stored digest, not re-verified"}[pre.get("acquisition_verified")]
            lines.append(f"- `{base}`: acquisition {algo.upper()} `{digest}` ({verdict})")
        elif pre.get("md5"):
            kind = ("custody hash of the file as received" if pre.get("full_hash")
                    else "sampled fingerprint, full hash deferred")
            lines.append(f"- `{base}`: {kind} `{pre['md5']}`")
    return lines


def _composed_part_lines(task: dict, fids: dict, language: str, unaddressed: list[str]) -> list[str]:
    """The part lines under a composed answer: status and citations, never
    the binder's value (it can be wrong; the composer read the belief), the
    part ids printed so the sentences' part citations resolve, and one
    deterministic line per part the written answer did not address."""
    from core.report_i18n import t
    parts = [p for p in (task.get("parts") or []) if isinstance(p, dict)]
    if len(parts) < 2 and not any(p.get("status") == "limited" or p.get("bound_by") == "analyst" for p in parts):
        parts = []
    out: list[str] = []
    if parts:
        out += ["", f"*{t('answer_parts_heading', language)}:*", ""]
    for p in parts:
        st = p.get("status")
        pid = str(p.get("id") or "")
        text = _md_inline(str(p.get("text") or ""))
        if st == "answered":
            refs = [fids.get(c) or c for c in (p.get("claim_ids") or [])]
            state = t("answer_part_linked" if p.get("bound_by") == "analyst" else "answer_part_answered", language)
            out.append(f"- {pid} {text}: {state}" + (f" ({', '.join(str(r) for r in refs)})" if refs else ""))
        elif st == "limited":
            lim = p.get("limitation") or {}
            out.append(f"- {pid} {text}: {t('answer_part_limited', language)} — {lim.get('basis', '')}: "
                       f"{_md_inline(str(lim.get('reason') or ''))}")
        else:
            out.append(f"- {pid} {text}: {t('answer_part_open', language)}")
    by_id = {str(p.get("id") or "").lower(): p for p in (task.get("parts") or []) if isinstance(p, dict)}
    omitted = [by_id[pid] for pid in unaddressed if pid in by_id]
    if omitted:
        if not parts:
            out += [""]
        for p in omitted:
            out.append(f"- {p.get('id')} {_md_inline(str(p.get('text') or ''))}: {t('answer_part_unaddressed', language)}")
    if out:
        out.append("")
    return out


def _composed_text_lines(composed: dict, fids: dict, language: str) -> str:
    """The composed sentences with their citation groups as the report prints
    them: belief ids become F-ids (the case-wide index; a claim folded under
    its conclusion prints the conclusion's id), part ids stay, a part-only
    group reads as the analyst's note, a none group as not established."""
    from core.report_i18n import t
    pieces = []
    for s in composed["sentences"]:
        body = str(s["text"]).rstrip()
        end = body[-1] if body and body[-1] in ".!?" else "."
        if body and body[-1] in ".!?":
            body = body[:-1].rstrip()
        if s["none"]:
            cite = f"[{t('answer_none_cite', language)}]"
        else:
            beliefs = [c for c in s["ids"] if not c.startswith(("p", "w", "v", "t"))]
            parts = [c for c in s["ids"] if c.startswith("p")]
            # A work order read prints as its item; a VALUES line as the
            # indicator list it comes from.
            others = [f"#{c[1:]}" for c in s["ids"] if c.startswith("w")]
            if any(c.startswith("v") for c in s["ids"]):
                others.append(t("answer_value_cite", language))
            if any(c.startswith("t") for c in s["ids"]):
                others.append(t("answer_window_cite", language))
            if beliefs:
                cite = "[" + ", ".join(parts + others + [str(fids.get(c) or c) for c in beliefs]) + "]"
            elif parts:
                cite = f"[{t('answer_part_cite', language)}, {', '.join(parts + others)}]"
            else:
                cite = "[" + ", ".join(others) + "]"
        body = _COMPOSE_ID_RE.sub(lambda m: str(fids.get(m.group(0)) or m.group(0)), body)
        pieces.append(f"{_md_inline(body)} {cite}{end}")
    return " ".join(pieces)


_COMPOSE_ID_RE = re.compile(r"\b[CNO]\d{4}\b")


def _case_fids(root: Path, findings: list[dict[str, Any]]) -> dict:
    """Claim id to F-id, case-wide (an answer is case-level, a per-host report
    numbers only its host's findings), with a folded claim aliased to the
    conclusion that absorbed it."""
    fids: dict = {}
    try:
        from core.finding_index import load_index
        fids.update((load_index(root) or {}).get("by_node_id") or {})
    except Exception:  # noqa: BLE001
        pass
    for f in findings:
        if f.get("id") and f.get("finding_id"):
            fids.setdefault(f["id"], f["finding_id"])
    alias_of = {}
    for f in findings:
        for twin in f.get("also_recorded_as") or []:
            alias_of[str(twin)] = f.get("finding_id")
    for nid, fid in list(fids.items()):
        if str(fid) in alias_of and alias_of[str(fid)]:
            fids[nid] = alias_of[str(fid)]
    return fids


def _answers_section(root: Path, findings: list[dict[str, Any]], language: str,
                     narratives: dict[str, dict[str, str]] | None = None, *,
                     compose: bool = True, answers_stats: dict | None = None) -> list[str]:
    """Answers to the investigation questions, from the beliefs linked to
    each — the same projection the dashboard's Questions tab shows. With
    ATLAS_ANSWER_COMPOSE on the text is the composed answer (core.answer_synthesis
    .compose_answer): the questions of one assembly are composed by a pool of
    workers sharing one breaker, taken in question order; a fallback prints
    the scaffold under a marker. ``compose=False`` makes no call: cached
    composed answers are used, else the scaffold (the prose pass is skipped
    on that path too)."""
    from core.report_i18n import t
    lines: list[str] = []
    try:
        from core.answer_synthesis import answer_for_task
        from core.claim_graph import load_graph
        from core.investigation_tasks import list_tasks, tasks_path
        if tasks_path(root).is_file():
            tasks = [x for x in list_tasks(root) if x.get("status") != "dropped"]
            for task in tasks:
                # A host-wide question carries its depth per host beside the
                # answer, read live (core.evidence_depth), never stored.
                try:
                    from core.evidence_depth import task_depth
                    task["_depth"] = task_depth(root, task)[1]
                except Exception:  # noqa: BLE001
                    task["_depth"] = ""
        else:
            # The store is written when a run starts; a report rendered
            # before that (or for a case that never ran) still owes the
            # reader the questions CASE.md asked.
            from core.investigation_tasks import parse_case_requests, read_case_markdown
            tasks = [{"id": f"task-{i:04d}", "text": q, "status": "open",
                      "related_claim_ids": []}
                     for i, q in enumerate(parse_case_requests(read_case_markdown(root)), 1)]
        graph = load_graph(root)
    except Exception:  # noqa: BLE001
        return [t("no_questions", language), ""]
    if not tasks:
        return [t("no_questions", language), ""]
    fid_of = {f.get("id"): f.get("finding_id") for f in findings}
    summaries = {nid: (narratives or {}).get(str(fid), {}).get("summary", "")
                 for nid, fid in fid_of.items() if fid}
    from core.answer_synthesis import competing_questions, compose_on
    questions = competing_questions(tasks)
    composing = compose_on()
    composed_by_task: dict[str, dict] = {}
    if composing:
        composed_by_task = _compose_all(root, tasks, graph, questions, language, allow_calls=compose)
        if answers_stats is not None:
            outcomes = [c.get("outcome") for c in composed_by_task.values()]
            answers_stats.update({
                "composed": outcomes.count("composed"), "cached": outcomes.count("cached"),
                "fallback": outcomes.count("fallback"),
                "fallback_reasons": sorted({str(c.get("reason") or "") for c in composed_by_task.values()
                                            if c.get("outcome") == "fallback"}),
            })
        case_fids = _case_fids(root, findings)
    for i, task in enumerate(tasks, start=1):
        text = (task.get("text") or "").strip()
        if text.lower().startswith("[derived]"):
            text = text[len("[derived]"):].strip()
        ans = answer_for_task(task, graph, summaries, language=language, questions=questions)
        composed = composed_by_task.get(str(task.get("id") or "")) if composing else None
        if composed and composed.get("outcome") in ("composed", "cached"):
            lines.extend(_composed_answer_lines(i, text, task, ans, composed, case_fids, language))
            continue
        if ans.get("has_answer") and compose and not composing:
            from core.answer_synthesis import synthesize_answer_text
            ans["text"] = synthesize_answer_text(
                root, task.get("id") or f"task-{i:04d}", text, ans, language=language)
        # A composition that fell back prints the scaffold text with one marker
        # line under it, the way the narrative sections mark their stubs.
        fallback = bool(composed and composed.get("outcome") == "fallback" and ans.get("has_answer"))
        conf = f" [{ans['confidence']}]" if ans.get("confidence") else ""
        lines.append(f"### Q{i} · {_md_inline(text)}{conf}")
        lines.append("")
        if ans["has_answer"]:
            lines.append(_md_inline(ans["text"]))
            if fallback:
                lines.append("")
                lines.append(f"*{t('answer_fallback', language)}*")
            lines.extend(_part_lines(task, fid_of, language))
            if ans.get("shape_gap"):
                lines.append("")
                lines.append(f"*{t('shape_' + ans['shape_gap'], language)}*")
            if ans.get("overview"):
                lines.append("")
                lines.append(f"*{t('overview_answer', language)}*")
            elif ans.get("by_relevance"):
                lines.append("")
                lines.append(f"*{t('relevance_answer', language)}*")
            fids = [fid_of.get(n.get("id")) or n.get("id")
                    for n in ans["supporting"]]
            fids = [x for x in dict.fromkeys(fids) if x]
            if fids:
                lines.append("")
                lines.append(f"{t('supported_by', language)} " + " · ".join(fids))
        else:
            lines.append(f"*{t('not_answered', language)}*")
        lines.append("")
    return lines


def _write_answers_stats(root: Path, stats: dict[str, Any]) -> None:
    """The assembly's answer counts (composed, cached, fallback with its
    reasons, and when) beside the report in the projection state, so the
    run status record, the dashboard and the audit see them without the
    trace and know which assembly they describe. Best effort."""
    if not stats:
        return
    try:
        import json as _json
        from datetime import datetime, timezone
        from core.report_projection import projection_dir
        path = projection_dir(root) / "answers.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {**stats, "assembled_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        path.write_text(_json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def compose_at_stop(case_dir: str | os.PathLike) -> dict[str, Any]:
    """The answers a stopped run owes, composed before its report: the
    composer for every question (one call each, as the close-out makes;
    a question with no current belief makes none), its results cached, so
    the report written next reads them. Returns the outcome counts and
    whether the composer could be reached at all."""
    root = Path(case_dir)
    from core.answer_synthesis import competing_questions, compose_on
    from core.claim_graph import load_graph
    from core.investigation_tasks import list_tasks, tasks_path
    if not compose_on() or not tasks_path(root).is_file():
        return {"questions": 0, "outcomes": {}, "reached": True}
    try:
        from core.case_config import get_report_language
        language = get_report_language(root)
    except Exception:  # noqa: BLE001
        language = "en"
    tasks = [x for x in list_tasks(root) if x.get("status") != "dropped"]
    composed = _compose_all(root, tasks, load_graph(root), competing_questions(tasks), language, allow_calls=True)
    outcomes: dict[str, int] = {}
    for res in composed.values():
        outcomes[str(res.get("outcome") or "none")] = outcomes.get(str(res.get("outcome") or "none"), 0) + 1
    # A fallback is an answer the composer did not give: it prints as a
    # projection. A question with no current belief ("none") needs no call.
    from core.report_projection import HURRY
    return {"questions": len(tasks), "outcomes": outcomes, "reached": not outcomes.get("fallback"),
            "hurried": HURRY.is_set()}


def _compose_all(root: Path, tasks: list[dict], graph: dict, questions: list[str], language: str, *,
                 allow_calls: bool) -> dict[str, dict]:
    """compose_answer for every question of one assembly: a pool of
    COMPOSE_WORKERS threads sharing one breaker when calls are allowed (one
    client per worker thread), the lexicon built once, results by task id.
    Without calls every question reads its cache or falls back, in order."""
    import time
    from concurrent.futures import ThreadPoolExecutor
    from core.answer_synthesis import (COMPOSE_WORKERS, ComposeBreaker, case_name_lexicon, compose_answer,
                                       trace_composed)
    lexicon = case_name_lexicon(graph) if allow_calls else frozenset()
    breaker = ComposeBreaker()

    def one(task: dict) -> tuple[str, dict]:
        t0 = time.monotonic()
        try:
            res = compose_answer(root, task, graph, questions, language=language, allow_calls=allow_calls,
                                 breaker=breaker, lexicon=lexicon)
        except Exception as exc:  # noqa: BLE001 - a question never costs the section
            res = {"outcome": "fallback", "reason": f"error: {type(exc).__name__}", "sheet": {}, "sentences": []}
        trace_composed(res, time.monotonic() - t0)
        return str(task.get("id") or ""), res

    if not allow_calls or len(tasks) <= 1:
        return dict(one(t) for t in tasks)
    with ThreadPoolExecutor(max_workers=COMPOSE_WORKERS, thread_name_prefix="atlas-compose") as pool:
        return dict(pool.map(one, tasks))


def _composed_answer_lines(i: int, text: str, task: dict, ans: dict, composed: dict, fids: dict,
                           language: str) -> list[str]:
    """One composed answer as the report prints it (3.9 of the design): the
    heading with the lowest tier among the lead's cited beliefs and the open
    state for a task never closed, the sentences with their citations, the
    part lines without values, the relevance or overview note, Supported-by
    with the cited beliefs first, then the analyst's other links, and the
    also-cited line for a closed task's unlinked citations."""
    from core.report_i18n import t
    sheet = composed.get("sheet") or {}
    tier = composed.get("lead_tier")
    closed = str(task.get("status") or "") in ("answered", "partial", "blocked_missing_evidence")
    pill = (tier or "").upper()
    if not closed and not sheet.get("overview"):
        pill = (pill + " · " if pill else "") + t("answer_open_state", language)
    lines = [f"### Q{i} · {_md_inline(text)}" + (f" [{pill}]" if pill else ""), ""]
    lines.append(_composed_text_lines(composed, fids, language))
    lines.extend(_composed_part_lines(task, fids, language, list(composed.get("parts_unaddressed") or [])))
    if task.get("_depth"):
        lines += ["", f"*{t('answer_depth', language)}: {_md_inline(str(task['_depth']))}*"]
    if not sheet.get("overview"):
        from core.answer_synthesis import answer_shape_gap
        gap = answer_shape_gap(text, [str(s.get("text") or "") for s in composed.get("sentences") or []
                                      if not s.get("none")], language)
        if gap:
            lines += ["", f"*{t('shape_' + gap, language)}*"]
    if sheet.get("overview"):
        lines += ["", f"*{t('overview_answer', language)}*"]
    elif not closed:
        lines += ["", f"*{t('relevance_answer', language)}*"]
    cited: list[str] = []
    for s in composed.get("sentences") or []:
        for c in s.get("ids") or []:
            # Parts, reads and value lines are sheet lines, not findings.
            if not c.startswith(("p", "w", "v", "t")) and c not in cited:
                cited.append(c)
    attached = {c for c, how in sheet.get("beliefs") or [] if str(how).startswith("linked")}
    attached |= set(sheet.get("linked_dropped") or [])
    if closed:
        attached |= {str(c) for c in (task.get("related_claim_ids") or [])}
        for p in task.get("parts") or []:
            if isinstance(p, dict) and p.get("closed_by") == "analyst":
                attached |= {str(c) for c in (p.get("claim_ids") or [])}
    supported = [str(fids.get(c) or c) for c in cited] + [
        str(fids.get(c) or c) for c in attached if c not in cited]
    supported = [x for x in dict.fromkeys(supported) if x]
    if supported:
        lines += ["", f"{t('supported_by', language)} " + " · ".join(supported)]
    if closed:
        also = [str(fids.get(c) or c) for c in cited if c not in attached]
        if also:
            lines.append(f"{t('answer_also_cited', language)} " + " · ".join(dict.fromkeys(also)))
    lines.append("")
    return lines


def _sighted_indicator_lines(cat: dict[str, Any], language: str, report_scope: str,
                             report_host: str) -> list[str]:
    """The report's Indicators section under the sighted catalogue: the
    block rows inline with where each was seen (a host report lists the rows
    seen on that host), then one line counting the hunt, scope, review,
    role-not-stated and context rows."""
    from core.ioc_catalog import _seen_cell
    from core.report_i18n import t
    seen = [r for r in cat.get("iocs") or [] if r.get("standing") in ("cited", "same_host", "elsewhere")]
    block = [r for r in seen if "block" in (r.get("use") or [])]
    if (report_scope or "") == "host" and report_host:
        block = [r for r in block if any(str(x.get("host") or "").lower() == report_host.lower()
                                         for x in r.get("sightings") or [])]
    out: list[str] = []
    if block:
        out += [t("ind_block_head", language), "",
                f"| {t('ind_col_value', language)} | {t('ind_col_type', language)} | "
                f"{t('ind_col_seen', language)} | {t('ind_col_finding', language)} |", "|---|---|---|---|"]
        for r in block:
            out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in (
                r.get("value"), r.get("category"), _seen_cell(r), ", ".join(r.get("claim_ids") or []))) + " |")
        out.append("")
    else:
        out.append(t("ind_block_none", language))
    review = [r for r in list(cat.get("iocs") or []) + list(cat.get("review") or [])
              if r.get("source") == "typed" and r.get("standing") in ("elsewhere", "unlocated")
              and "review" in (r.get("use") or [])]
    named = [r for r in cat.get("review") or [] if r.get("source") == "prose"
             and r.get("standing") not in ("unchecked", "")]
    context = cat.get("context") or []
    brief = sum(1 for r in context if "brief" in (r.get("named_by") or []))
    marked = sum(1 for r in seen if r.get("mark"))
    out.append(t("ind_sighted_counts", language).format(
        hunt=sum(1 for r in seen if "hunt" in (r.get("use") or [])),
        scope=sum(1 for r in seen if "scope" in (r.get("use") or [])),
        review=len(review), named=len(named), context=len(context),
        brief=t("ind_sighted_brief", language).format(n=brief) if brief else "", marked=marked))
    return out


def _fill_hosts(root: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Beliefs recorded without a host get it from their own statement."""
    try:
        from core.claim_graph import infer_host_from_text
    except Exception:  # noqa: BLE001
        return findings
    for f in findings:
        if not (f.get("host") or "").strip():
            host, mentioned = infer_host_from_text(root, f.get("statement") or "")
            if host:
                f["host"] = host
            elif len(mentioned) > 1:
                f["scope"] = "estate"
    return findings


def _fold_twins(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding, once — a graph written before anchor-merging existed
    can still hold the same event twice; the report shows the stronger
    and notes the other id."""
    try:
        from core.claim_graph import anchors_agree, statement_anchor_kinds
    except Exception:  # noqa: BLE001
        return findings
    rank = {"UNCONFIRMED": 0, "SUSPECTED": 1, "LIKELY": 2, "CONFIRMED": 3}
    kept: list[dict[str, Any]] = []
    for f in findings:
        mine = statement_anchor_kinds(f.get("statement") or "")
        twin = None
        if len(mine) >= 2:
            for k in kept:
                if f.get("refines") == k.get("id") or k.get("refines") == f.get("id"):
                    continue   # a linked refinement is reported beside its base
                same_host = not f.get("host") or not k.get("host") or \
                    f["host"].lower() == k["host"].lower()
                if same_host and anchors_agree(
                        mine, statement_anchor_kinds(k.get("statement") or "")):
                    twin = k
                    break
        if twin is None:
            kept.append(f)
            continue
        weaker, stronger = sorted(
            (twin, f), key=lambda x: rank.get(str(x.get("confidence")).upper(), 0))
        if stronger is f:
            kept[kept.index(twin)] = f
        stronger.setdefault("also_recorded_as", []).append(
            str(weaker.get("finding_id") or weaker.get("id")))
        # the weaker twin's lineage still belongs to the finding
        stronger["input_call_ids"] = list(dict.fromkeys(
            list(stronger.get("input_call_ids") or []) +
            list(weaker.get("input_call_ids") or [])))
    return kept


def _case_hosts(root) -> list[str]:
    """The case's known hosts, [] when they cannot be read."""
    try:
        from core.forensic_citation import known_case_hosts
        return list(known_case_hosts(root))
    except Exception:  # noqa: BLE001
        return []


def _build_attack_timeline_rows(
    findings: list[dict[str, Any]],
    packs: dict[str, dict[str, Any]],
    *,
    max_rows: int = 120,
    max_rows_per_finding: int = 12,
    known_hosts: Iterable[str] = (),
    case_dir: Any = None,
) -> list[dict[str, str]]:
    """Curated timeline rows from resolved evidence (not full master timeline).

    Keeps multiple artifact perspectives per finding (different sources /
    producers) instead of a single global type allow/deny list. Caps per
    finding so one noisy claim cannot crowd out the rest of the attack story.
    ``known_hosts``: the case's hosts beside the findings', so a record of a
    host no finding is about is still credited to that host.
    """
    from core.evidence_noise import (
        envelope_rows,
        is_tool_metadata_text,
        is_weak_timeline_event_text,
        looks_like_evidence_gap_statement,
    )

    rows: list[dict[str, str]] = []
    case_hosts = sorted({str(f.get("host") or "") for f in findings if f.get("host")}
                        | {str(h) for h in known_hosts if h})
    for f in findings:
        nid = f.get("id") or ""
        fid = f.get("finding_id") or nid
        stmt = (f.get("statement") or "") + " " + (f.get("description") or "")
        if looks_like_evidence_gap_statement(stmt) and (
                (f.get("confidence") or "").upper() == "UNCONFIRMED"):
            continue
        pack = packs.get(nid) or {}
        events = pack.get("events") or []
        mode = pack.get("selection_mode") or ""
        if mode == "correlated":
            continue
        claim_host = (f.get("host") or "").strip()
        per_finding: list[dict[str, str]] = []
        producer_counts: dict[str, int] = {}
        # The attack timeline is the story told to the exact minute: once a
        # finding has a record that shares an identifier or a timestamp with
        # it (relevance ≥ 3), rows that merely fall on the same day and
        # mention the same domain are not part of that story.
        best = max((int(ev.get("relevance") or 0)
                    for ev in events if isinstance(ev, dict)), default=0)
        floor = 3 if best >= 3 else (1 if best >= 1 else 0)
        for ev in events:
            if not isinstance(ev, dict):
                continue
            prov = ev.get("provenance") or "direct"
            if prov == "correlated":
                continue
            if int(ev.get("relevance") or 0) < floor:
                continue
            text = ev.get("text") or ""
            if is_tool_metadata_text(text) or is_weak_timeline_event_text(text):
                continue
            if envelope_rows(text) is not None:
                # Atlas's own result envelope is no event: its first date is
                # as often a tool's start time as a record's, and the
                # resolver already cites the rows inside it.
                continue
            parsed = _fields_from_event_text(text)
            # "++++ r/r 1234-128-4:" is not a time and a CSV header is not
            # an event; both reached the attack timeline as rows.
            ts = _valid_timestamp(ev.get("timestamp") or parsed.get("timestamp") or "") \
                or _valid_timestamp(text)
            # The record's host first (the rule the Evidence bullets use,
            # core.forensic_citation.record_host), then a host-shaped cell
            # of a timeline row, then the claim's: a record of one host
            # cited by a finding about another is that host's row.
            from core.forensic_citation import looks_like_host, record_host
            parsed_host = (parsed.get("host") or "").strip()
            host = (record_host(ev, case_hosts, case_dir)
                    or (parsed_host if looks_like_host(parsed_host, case_hosts) else "")
                    or claim_host).strip()
            user = (parsed.get("user") or "").strip()
            try:
                from core.forensic_citation import evtxecmd_fields, host_mentioned
                cols = evtxecmd_fields(text)
                if cols:
                    if cols.get("user") and not user:
                        user = cols["user"]
                    if cols.get("computer"):
                        named = next((h for h in case_hosts
                                      if host_mentioned(h, cols["computer"])), "")
                        if named:
                            host = named        # the record outranks the claim
            except Exception:  # noqa: BLE001
                pass
            if not ts or _looks_like_header(text):
                continue
            ref = (ev.get("record_ref") or "").strip()
            line = ev.get("line")
            src = (ev.get("source") or "").strip()
            source_file = ""
            if ref and ("/" in ref or "\\" in ref):
                source_file = ref.split(":")[0]
            elif src and ("/" in src or src.endswith(
                    (".csv", ".tsv", ".evtx", ".json", ".log", ".txt"))):
                source_file = src
            elif src and not src.startswith("evidence_index"):
                source_file = src
            provenance = ""
            if source_file or line is not None or ref:
                bits = []
                if source_file:
                    bits.append(
                        Path(source_file).name
                        if "/" in source_file or "\\" in source_file
                        else source_file)
                if line is not None:
                    bits.append(f"L{line}")
                if ref:
                    bits.append(ref[:80])
                provenance = " · ".join(bits)
            elif src.startswith("evidence_index") and line is not None:
                provenance = f"{src} · L{line}"
            # Producer diversity: keep up to 3 rows per distinct source file
            producer = (
                Path(source_file).name if source_file else ""
            ) or (src[:60] if src else "") or _short_event_label(ev)[:40]
            if producer_counts.get(producer, 0) >= 3:
                continue
            producer_counts[producer] = producer_counts.get(producer, 0) + 1
            per_finding.append({
                "timestamp": ts or "—",
                "host": host or "—",
                "user": user or "—",
                "event": _short_event_label(ev).replace("|", "/"),
                "finding": fid,
                "provenance": provenance.replace("|", "/"),
                "sort_key": ts or "",
                "direct": "1",
            })
            if len(per_finding) >= max_rows_per_finding:
                break
        rows.extend(per_finding)

    rows.sort(key=lambda r: (r["sort_key"], r["finding"]))
    merged: dict[str, dict[str, str]] = {}
    for r in rows:
        key = f"{r['timestamp']}|{r['host']}|{r['event'][:40]}"
        if key in merged:
            have = merged[key]["finding"].split(", ")
            if r["finding"] not in have:
                merged[key]["finding"] = ", ".join(have + [r["finding"]])
            continue
        merged[key] = dict(r)
        if len(merged) >= max_rows:
            break
    return list(merged.values())


def _confidence_label(f: dict[str, Any], language: str) -> str:
    """A finding's confidence as the report shows it; a finding Atlas has put
    under review says so, so it is not read as a settled one."""
    conf = str(f.get("confidence") or "UNCONFIRMED")
    if f.get("status") == "needs_review":
        from core.report_i18n import t
        conf += f", {t('under_review', language)}"
    return conf


def _is_gap_only_finding(f: dict[str, Any]) -> bool:
    from core.evidence_noise import looks_like_evidence_gap_statement
    stmt = (f.get("statement") or "") + " " + (f.get("description") or "")
    return looks_like_evidence_gap_statement(stmt)


def attack_timeline_readiness(
    case_dir: str | os.PathLike,
    *,
    report_scope: str = "case",
    report_host: str = "",
) -> dict[str, Any]:
    """Whether a curated Attack Timeline can be built from resolved evidence.

    Returns ``ok`` True when there is at least one direct curated timeline
    row, OR when every finding is an evidence-gap/absence finding (no attack
    events expected). Findings with attack content but no resolvable
    non-banner evidence cannot produce a report.
    """
    from core.evidence_resolver import resolve_nodes_evidence
    from core.finding_index import ensure_finding_ids, nodes_for_report
    from core.report_projection import bind_claims_to_sections

    root = Path(case_dir).resolve()
    scope = (report_scope or "case").lower()
    host = (report_host or "").strip()
    bind_kw: dict[str, str] = {}
    if scope == "host":
        bind_kw["scope"] = "host"
        if host:
            bind_kw["host"] = host
    bind_claims_to_sections(root, **bind_kw)
    ensure_finding_ids(root)
    findings = nodes_for_report(
        root,
        scope="host" if scope == "host" else "case",
        host=host,
    )
    packs = resolve_nodes_evidence(root, findings)
    rows = _build_attack_timeline_rows(findings, packs, known_hosts=_case_hosts(root), case_dir=root)
    findings_on_timeline = {r.get("finding") for r in rows}
    findings_without_direct = []
    findings_with_refs_but_no_rows = []
    findings_missing_timeline_row = []
    for f in findings:
        nid = f.get("id") or ""
        pack = packs.get(nid) or {}
        mode = pack.get("selection_mode") or ""
        events = pack.get("events") or []
        direct = [
            e for e in events
            if isinstance(e, dict) and (e.get("provenance") or "direct") != "correlated"
        ]
        fid = f.get("finding_id") or nid
        if _is_gap_only_finding(f):
            continue
        if mode == "correlated" or not direct:
            findings_without_direct.append(fid)
        elif fid not in findings_on_timeline:
            # Had resolved blobs but none survived timeline curation (banners
            # / weak text / missing timestamps).
            findings_with_refs_but_no_rows.append(fid)
            findings_missing_timeline_row.append(fid)
    attack_findings = [f for f in findings if not _is_gap_only_finding(f)]
    ok = bool(findings) and (bool(rows) or not attack_findings)
    error = ""
    if not findings:
        error = (
            "No current findings in Current Investigation State — "
            "promote claims/conclusions before writing a report."
        )
    elif not rows and attack_findings:
        if findings_without_direct and not findings_with_refs_but_no_rows:
            error = (
                "Attack Timeline is empty: attack findings lack resolvable "
                "evidence refs (record_ref / call_id / artifact+locator). "
                "Attach those on claims (not the record_finding call_id), "
                "then retry misc.write_projected_final_report. "
                f"Findings lacking direct evidence: "
                f"{', '.join(str(x) for x in findings_without_direct[:12])}."
            )
        else:
            error = (
                "Attack Timeline is empty: evidence refs resolved only to "
                "tool banners/metadata or non-event lines (e.g. a parser's "
                "version banner). Re-attach locators that quote the forensic row "
                "(EventID/line/quote), or point call_ids at the tool that "
                "emitted the real event — then retry. "
                f"Affected findings: "
                f"{', '.join(str(x) for x in (findings_with_refs_but_no_rows or findings_without_direct)[:12])}."
            )
    return {
        "ok": ok,
        "finding_count": len(findings),
        "timeline_row_count": len(rows),
        "findings_without_direct_evidence": findings_without_direct,
        "findings_resolved_but_not_timeline_shaped": findings_with_refs_but_no_rows,
        "findings_missing_timeline_row": findings_missing_timeline_row,
        "error": error,
    }


def assemble_client_report(
    case_dir: str | os.PathLike,
    *,
    report_scope: str = "case",
    report_host: str = "",
    compose: bool = True,
) -> str:
    """Build the full client Markdown report with deterministic structure.
    ``compose=False`` makes no model call for the answers (the no-model
    paths: the exit report, the deterministic fallback)."""
    from core.case_config import get_report_language
    from core.evidence_resolver import (
        format_evidence_markdown,
        resolve_nodes_evidence,
    )
    from core.finding_index import ensure_finding_ids, nodes_for_report
    from core.paths import detect_case_id
    from core.report_i18n import section_title, t
    from core.report_projection import bind_claims_to_sections

    root = Path(case_dir).resolve()
    from core.report_projection import prepare_report_inputs, report_inputs_at_render
    if report_inputs_at_render():
        # The next steps and the indicator files this report shows, prepared
        # here where every writer path assembles its report.
        prepare_report_inputs(root)
    language = get_report_language(root)
    case_id = detect_case_id(root) or root.name
    scope = (report_scope or "case").lower()
    host = (report_host or "").strip()

    # Ensure bindings + F-ids
    bind_kw: dict[str, str] = {}
    if scope == "host":
        bind_kw["scope"] = "host"
        if host:
            bind_kw["host"] = host
    bind_claims_to_sections(root, **bind_kw)
    ensure_finding_ids(root)
    findings = nodes_for_report(
        root,
        scope="host" if scope == "host" else "case",
        host=host,
    )
    # A belief that says "this cannot be determined" is an open question,
    # not a finding — it reads under Evidence Gaps, where a reader expects
    # it, instead of as a numbered finding that says it is unconfirmed.
    open_questions = [f for f in findings if _is_open_question_claim(f)]
    findings = [f for f in findings if not _is_open_question_claim(f)]
    findings = _fill_hosts(root, findings)
    findings = _fold_twins(findings)
    # Prefer conclusions ahead of claims already handled in nodes_for_report
    packs = resolve_nodes_evidence(root, findings)

    # Narratives from LLM section store (if any)
    detailed_prose = _narrative_section(root, "detailed_findings")
    narratives = parse_finding_narratives(detailed_prose)
    exec_prose = _narrative_section(root, "exec_summary")
    gaps_prose = _narrative_section(root, "gaps")
    scope_prose = _narrative_section(root, "scope_evidence")

    # Manifest titles (i18n)
    manifest = load_manifest(root)
    titles = {
        s["id"]: (manifest.get("sections") or {}).get(s["id"], {}).get("title")
        or section_title(s["id"], language)
        for s in SECTION_ORDER
    }

    # ---- TOC ----
    toc: list[str] = [f"## {t('toc', language)}", ""]
    answers_title = t("answers", language)
    for s in SECTION_ORDER:
        sid = s["id"]
        title = titles[sid]
        toc.append(f"- [{title}](#{_slug(title)})")
        if sid == "exec_summary":
            toc.append(f"- [{answers_title}](#{_slug(answers_title)})")
        if sid == "detailed_findings" and findings:
            # The per-finding index belongs to its section's entry, as an
            # indented sub-list. Emitted after the whole table with its own
            # "### 4. Detailed Findings" heading, it read as the section
            # itself: on a case with many findings the report opened with a
            # heading called Detailed Findings and pushed the Executive
            # Summary far down the page.
            for f in findings:
                fid = f.get("finding_id") or f.get("id")
                short = _short_title(f, narratives.get(str(fid)) or {})
                toc.append(f"  - [{fid} · {short}](#{_slug(str(fid))})")
    toc.append("")

    parts: list[str] = [
        f"# {t('report_title', language)}: {case_id}",
        "",
        f"*{t('projection_note', language)} "
        f"(generated {_utcnow()}, generator {GENERATOR_VERSION}).*",
        "",
        *toc,
    ]

    # ---- 1. Executive Summary (narrative) ----
    parts.append(f"## {titles['exec_summary']}")
    parts.append("")
    if exec_prose and not exec_prose.startswith("*No current"):
        # Prefer LLM narrative; drop trailing recommendation dumps if huge
        parts.append(_demote_headings(exec_prose).strip())
    else:
        # Deterministic narrative fallback — real paragraphs, not only bullets
        hosts = _hosts_from_nodes(findings)
        host_bit = (
            f" spanning {', '.join(hosts[:8])}"
            + ("…" if len(hosts) > 8 else "")
            if hosts else ""
        )
        parts.append(
            f"This investigation examined case `{case_id}`{host_bit}. "
            f"Current Investigation State currently holds {len(findings)} "
            f"active finding(s) (stable F-IDs). The following summarizes the "
            f"most material conclusions based on validated claims and evidence "
            f"references — Supporting Evidence for each finding appears only "
            f"in Detailed Findings."
        )
        parts.append("")
        for f in findings[:8]:
            fid = f.get("finding_id") or f.get("id")
            conf = f.get("confidence") or "UNCONFIRMED"
            stmt = _md_inline(f.get("statement") or "")
            parts.append(f"{fid} ({conf}): {stmt}")
            parts.append("")
        if len(findings) > 8:
            parts.append(
                f"Additional findings ({len(findings) - 8}) are listed in "
                f"Key Findings and Detailed Findings."
            )
            parts.append("")
    parts.extend(_exec_next_steps(root, language, scope=scope, host=host))
    parts.append("")

    # ---- Answers to the Investigation Questions ----
    parts.append(f"## {answers_title}")
    parts.append("")
    answers_stats: dict[str, Any] = {}
    parts.extend(_answers_section(root, findings, language, narratives, compose=compose,
                                  answers_stats=answers_stats))
    _write_answers_stats(root, answers_stats)

    # ---- 2. Scope and Evidence ----
    parts.append(f"## {titles['scope_evidence']}")
    parts.append("")
    hosts = _hosts_from_nodes(findings)
    if scope == "host" and host:
        parts.append(f"**Investigation scope:** host `{host}`.")
    else:
        parts.append("**Investigation scope:** estate / case-level synthesis.")
    parts.append("")
    if hosts:
        parts.append("**Analyzed hosts (from current beliefs):**")
        parts.append("")
        for h in hosts:
            parts.append(f"- `{h}`")
        parts.append("")
    parts.append("**Evidence sources (classes):**")
    parts.append("")
    parts.extend(_evidence_source_lines(root))
    try:
        from core.baseline import report_lines as _baseline_lines
        _bl = _baseline_lines(root, language)
        if _bl:
            parts.append("")
            parts.extend(_bl)
    except Exception:  # noqa: BLE001 - the report stands without the baseline
        pass
    try:
        from core.handling_stop import report_lines as _handling_lines
        _hl = _handling_lines(root, language)
        if _hl:
            parts.append("")
            parts.extend(_hl)
    except Exception:  # noqa: BLE001 - the report stands without the section
        pass
    parts.append(
        "- Claim Graph evidence references (`artifact` / `locator` / "
        "`call_id` / `record_ref`)"
    )
    parts.append("")
    integrity = _integrity_lines(root)
    if integrity:
        parts.append("**Image integrity:**")
        parts.append("")
        parts.extend(integrity)
        parts.append("")
    # Every delivered piece of evidence and whether the run read it.
    try:
        from core.evidence_items import report_lines as _item_lines
        _il = _item_lines(root, findings, language)
        if _il:
            parts.extend(_il)
            parts.append("")
    except Exception:  # noqa: BLE001 - the report stands without the table
        pass
    # The operator's threat context: sources, rows, the sweep and what it
    # could not see.
    try:
        from core.threat_context import report_lines as _intel_lines
        _tl = _intel_lines(root, findings, language)
        if _tl:
            parts.extend(_tl)
            parts.append("")
    except Exception:  # noqa: BLE001 - the report stands without the block
        pass
    # The analyst's prior knowledge: each statement with the findings
    # that name what it names.
    try:
        from core.analyst_context import report_lines as _context_lines
        _cl = _context_lines(root, findings, language)
        if _cl:
            parts.extend(_cl)
            parts.append("")
    except Exception:  # noqa: BLE001 - the report stands without the block
        pass
    parts.append(
        "**Timezone:** timestamps rendered as recorded in source artifacts "
        "(prefer UTC when ISO-8601 / exporter UTC)."
    )
    parts.append("")
    parts.append(
        "This report is a projection of Current Investigation State "
        "(`.atlas/`). It is not the source of truth."
    )
    parts.append("")
    # Optional LLM scope notes (if meaningful and not the empty-context fluff)
    if scope_prose and "keine finalisierten" not in scope_prose.lower() and len(scope_prose) < 2500:
        if "Host scope" not in scope_prose and "Estate" not in scope_prose[:80]:
            parts.append(scope_prose.strip())
            parts.append("")

    # ---- 3. Key Findings (table only) ----
    # Process/hypothesis diary claims stay out of Key Findings (report_role).
    try:
        from core.evidence_noise import claim_report_role
        key_findings = [
            f for f in findings
            if (f.get("report_role") or claim_report_role(
                f.get("statement") or f.get("description") or ""
            )) == "evidence"
        ]
    except Exception:
        key_findings = list(findings)
    parts.append(f"## {titles['key_findings']}")
    parts.append("")
    parts.append(
        "Concise overview only. Full analysis and Supporting Evidence are in "
        "Detailed Findings."
    )
    parts.append("")
    if not key_findings:
        parts.append("*No current evidence findings.*")
        parts.append("")
    else:
        parts.append(
            f"| ID | {t('statement', language)} | {t('host', language)} | "
            f"{t('when', language)} | {t('confidence', language)} |")
        parts.append("|----|---------|------|------|------------|")
        for f in key_findings:
            fid = f.get("finding_id") or f.get("id") or "?"
            title = _short_title(f, narratives.get(str(fid)) or {}, with_host=False)
            conf = _confidence_label(f, language)
            h = (f.get("host") or "—").replace("|", "/")
            when = _when_of(f.get("statement") or "") or "—"
            parts.append(
                f"| [{fid}](#{_slug(str(fid))}) | {title} | {h} | {when} | {conf} |"
            )
        parts.append("")

    # ---- 4. Detailed Findings ----
    parts.append(f"## {titles['detailed_findings']}")
    parts.append("")
    if not findings:
        parts.append(
            "*No bound beliefs for Detailed Findings in Current Investigation State.*"
        )
        parts.append("")
    try:
        from core.forensic_citation import known_case_hosts
        case_hosts = known_case_hosts(root)
    except Exception:  # noqa: BLE001
        case_hosts = []
    by_node = {str(x.get("id")): x for x in findings if x.get("id")}

    def _fid_tier(x: dict) -> str:
        return f"{x.get('finding_id') or x.get('id')} [{_confidence_label(x, language)}]"

    for f in findings:
        fid = str(f.get("finding_id") or f.get("id") or "?")
        nid = f.get("id") or ""
        conf = _confidence_label(f, language)
        stmt = (f.get("statement") or "").strip()
        nar = narratives.get(fid) or {}
        summary = _md_inline(nar.get("summary") or "") or _md_inline(stmt)
        assessment = _md_inline(nar.get("assessment") or "") or _md_inline(
            f.get("reasoning") or "")

        parts.append(f'<a id="{_slug(fid)}"></a>')
        for twin_id in f.get("also_recorded_as") or []:
            parts.append(f'<a id="{_slug(str(twin_id))}"></a>')
        parts.append("")
        parts.append(f"### {fid} · {_short_title(f, nar)} [{conf}]")
        parts.append("")
        parts.append(f"**{t('what_happened', language)}.** {summary}")
        parts.append("")
        if assessment:
            parts.append(f"**{t('why_it_matters', language)}.** {assessment}")
            parts.append("")
        parts.append(f"**{t('evidence', language)}.**")
        parts.append("")
        pack = packs.get(nid) if nid else None
        body = ""
        if pack:
            body = format_evidence_markdown(
                pack, compact=True, limit=3, known_hosts=case_hosts, case_dir=root,
            ).rstrip()
        parts.append(body or "*No record could be resolved for this "
                             "finding; the trace references below remain.*")
        parts.append("")
        footer: list[str] = []
        mitre = _mitre_from_node(f)
        if mitre:
            footer.append("MITRE " + ", ".join(mitre))
        if nid:
            footer.append(f"Claim {nid}")
        if f.get("also_recorded_as"):
            footer.append("also recorded as " + ", ".join(f["also_recorded_as"]))
        base = by_node.get(str(f.get("refines") or ""))
        if base is not None:
            footer.append(f"{t('refines_finding', language)} {_fid_tier(base)}")
        finer = [x for x in findings if nid and x.get("refines") == nid]
        if finer:
            footer.append(f"{t('refined_by_finding', language)} "
                          + ", ".join(_fid_tier(x) for x in finer))
        calls = _call_ids_of(f)
        if calls:
            footer.append("Trace calls " + ", ".join(str(c) for c in calls))
        if footer:
            parts.append("*" + " · ".join(footer) + "*")
            parts.append("")

    # ---- 5. Attack Timeline (deterministic curated table) ----
    parts.append(f"## {titles['timeline']}")
    parts.append("")
    parts.append(
        "Curated attack timeline derived from resolved evidence records "
        "linked to findings. Supporting claim-relevant detail is also in "
        "`master_timeline.tsv` (see Appendix) — that file is curated, not a "
        "raw EVTX/session dump."
    )
    parts.append("")
    tl_rows = _build_attack_timeline_rows(findings, packs, known_hosts=_case_hosts(root), case_dir=root)
    if not tl_rows:
        parts.append(
            "*No timestamped evidence events could be deterministically "
            "resolved for a curated Attack Timeline. See Detailed Findings "
            "Supporting Evidence and `master_timeline.tsv`.*"
        )
        parts.append("")
    else:
        parts.append(
            "| Timestamp | Host | User | Event | Finding | Evidence Ref |"
        )
        parts.append(
            "|-----------|------|------|-------|---------|--------------|"
        )
        for r in tl_rows:
            parts.append(
                f"| {r['timestamp']} | {r['host']} | {r['user']} | "
                f"{r['event']} | {r['finding']} | "
                f"{r['provenance'] or '—'} |"
            )
        parts.append("")

    # ---- 6. Gaps ----
    parts.append(f"## {titles['gaps']}")
    parts.append("")
    from core.evidence_noise import (
        is_contradictory_empty_gaps_prose,
        looks_like_evidence_gap_statement,
    )

    def _deterministic_gap_lines() -> list[str]:
        from core.dependency_index import COVERAGE_REVIEW_NOTE, coverage_corrected
        gap_lines: list[str] = []
        for f in findings:
            fid = f.get("finding_id") or f.get("id")
            if coverage_corrected(f):
                # The coverage it states is what the recount corrected: not
                # a standing gap.
                gap_lines.append(f"- **{fid}**: {COVERAGE_REVIEW_NOTE}")
                continue
            for g in f.get("gaps") or []:
                gap_lines.append(f"- **{fid}**: {_md_inline(g)}")
            if f.get("status") == "needs_review":
                gap_lines.append(
                    f"- **{fid}**: needs_review — re-validate against current evidence"
                )
            stmt = _md_inline(f.get("statement") or "")
            if looks_like_evidence_gap_statement(stmt):
                snippet = stmt[:240] + ("…" if len(stmt) > 240 else "")
                gap_lines.append(f"- **{fid}**: {snippet}")
            elif (f.get("confidence") or "").upper() == "UNCONFIRMED":
                gap_lines.append(
                    f"- **{fid}**: UNCONFIRMED — "
                    f"{stmt[:200]}{'…' if len(stmt) > 200 else ''}"
                )
        # de-dupe
        return list(dict.fromkeys(gap_lines))

    try:
        from core.evidence_items import gap_lines as _item_gap_lines
        item_gaps = _item_gap_lines(root, language)
    except Exception:  # noqa: BLE001
        item_gaps = []
    # High-value artifacts the case lists that nobody read, each with the
    # reason the run recorded, the read that failed, or that there is
    # neither (core.artifact_value.gap_lines).
    try:
        from core.artifact_value import gap_lines as _artifact_gap_lines
        item_gaps += _artifact_gap_lines(root, language, named="\n".join(item_gaps),
                                         host=host if scope == "host" else "")
    except Exception:  # noqa: BLE001
        pass
    # Indicators the findings name that were not searched for in every
    # relevant source (core.ioc_pivots.gap_lines).
    try:
        from core.ioc_pivots import gap_lines as _pivot_gap_lines
        item_gaps += _pivot_gap_lines(root, language, host=host if scope == "host" else "")
    except Exception:  # noqa: BLE001
        pass
    # What code states whatever a model wrote: the report gate's issues a
    # run ended with and the window's residual risk (hosts with attacker
    # activity and no stated start).
    try:
        from core.investigation_exit import open_limit_lines
        if scope != "host":
            item_gaps += [f"- {line}" for line in open_limit_lines(root)]
    except Exception:  # noqa: BLE001
        pass
    # The work order's planned reads not done: due, failed, moot and
    # proposals never adopted (core.work_order.report_lines).
    try:
        from core.deferred_intents import work_order_on
        if work_order_on():
            from core.execution_log import log as _wlog
            from core.work_order import report_lines as _order_lines
            item_gaps += _order_lines(_wlog, str(root))
    except Exception:  # noqa: BLE001
        pass
    # Findings a gate refused that were never recorded again, and those the
    # analyst withdrew with a reason (core.work_order.refused_report_lines).
    try:
        if scope != "host":
            from core.execution_log import log as _rlog
            from core.work_order import refused_report_lines
            item_gaps += refused_report_lines(_rlog, str(root))
    except Exception:  # noqa: BLE001
        pass
    # The extracted outputs with files no call read, each such class with
    # the count read, from the trace (core.coverage_ledger.extracted_outputs).
    try:
        if scope != "host":
            from core.coverage_ledger import extracted_lines, extracted_outputs
            item_gaps += [f"- Extracted output not wholly read: {ln}"
                          for ln in extracted_lines(extracted_outputs(root))]
    except Exception:  # noqa: BLE001
        pass
    # The pictures a vision model described (tools.images, the case switch on):
    # named here so the reader knows which descriptions came from a model.
    try:
        if scope != "host":
            item_gaps += described_picture_lines(root)
    except Exception:  # noqa: BLE001
        pass
    # The pictures no model could identify by their content, and why.
    try:
        if scope != "host":
            item_gaps += undescribed_picture_lines(root)
    except Exception:  # noqa: BLE001
        pass
    use_llm_gaps = (
        gaps_prose
        and "Supporting Evidence (deterministic)" not in gaps_prose
        and not is_contradictory_empty_gaps_prose(
            gaps_prose, finding_count=len(findings))
    )
    if use_llm_gaps:
        parts.append(_demote_headings(gaps_prose).strip())
        parts.append("")
        missing = [f for f in open_questions
                   if str(f.get("finding_id") or "") not in gaps_prose]
        if missing:
            parts.append("Open questions carried as beliefs:")
            parts.append("")
            for f in missing:
                parts.append(f"- **{f.get('finding_id') or f.get('id')}**: "
                             f"{_short_title(f, {})}")
            parts.append("")
        if item_gaps:
            parts.extend(item_gaps)
            parts.append("")
    else:
        gap_lines = _deterministic_gap_lines()
        for f in open_questions:
            gap_lines.append(f"- **{f.get('finding_id') or f.get('id')}**: "
                             f"{_short_title(f, {})}")
        gap_lines += item_gaps
        if gap_lines:
            parts.extend(gap_lines)
            parts.append("")
        else:
            parts.append(t("no_gaps", language))
            parts.append("")
    # Every handed-over item and class left or partly read, with its checked
    # reason (core.evidence_disposition), under the gaps.
    try:
        from core.evidence_disposition import disposition_on, report_lines as _ed_lines
        if disposition_on():
            parts.extend(_ed_lines(root, language, host=host if scope == "host" else ""))
    except Exception:  # noqa: BLE001
        pass

    # Observations the incident map keeps: facts with their basis that serve
    # no question and take no side. Their own section, never the answers.
    try:
        from core import incident_map as _im
        _m = _im.open(root)
        _obs = [o for o in (_m.observations() if _m is not None else [])
                if o["text"] and (scope != "host" or str(o["host"]).casefold() == host.casefold())]
    except Exception:  # noqa: BLE001
        _obs = []
    if _obs:
        parts.append(f"## {t('observations_title', language)}")
        parts.append("")
        for o in _obs:
            where = " ".join(x for x in (o["host"], o["time"]) if x)
            calls = f" (calls {', '.join(str(c) for c in o['call_ids'][:6])})" if o["call_ids"] else ""
            # The rows the observation rests on, beside the model's words:
            # an observation passes no finding gate, so its basis is shown.
            rows = "; ".join(f'"{_md_inline(q)}"' for q in o.get("quotes") or [])
            rows = f" ({t('observation_rows', language)}: {rows})" if rows else ""
            parts.append(f"- {where + ': ' if where else ''}{_md_inline(o['text'])}{calls}{rows}")
        parts.append("")

    # ---- 7. Recommendations ----
    parts.append(f"## {titles['recommendations']}")
    parts.append("")
    # The response plan the run recorded, read now: the section's stored body
    # is the same projection (core.report_projection keeps it mechanical) as
    # of its last regeneration, which a stopped or resumed run has outgrown.
    # Every line names its basis; nothing here is advice written for the
    # occasion.
    from core.recommendations import (build_catalog as _plan_catalog,
                                      hardening_references,
                                      render_markdown as _render_plan)
    parts.extend(_render_plan(_plan_catalog(root), language, host=host,
                              report_scope=scope))
    parts.extend(hardening_references(root, language))
    parts.append("")

    # ---- Indicators (a pointer: the list itself is its own deliverable) ----
    try:
        from core.ioc_catalog import build_catalog as _ioc_catalog
        _cat = _ioc_catalog(root)
        _cid = detect_case_id(root) or "case"
        parts.append(f"## {t('indicators', language)}")
        parts.append("")
        parts.append(t({"subject": "ind_frame_subject", "neutral": "ind_frame_neutral"}.get(
            str(_cat.get("frame") or ""), "ind_frame_incident"), language))
        _uses = ", ".join(f"{n} {t('use_' + u, language)}" for u, n in sorted((_cat.get("by_use") or {}).items()))
        if _cat.get("sighted"):
            parts.extend(_sighted_indicator_lines(_cat, language, report_scope, report_host))
        elif _cat.get("total"):
            parts.append(t("ind_counts", language).format(
                total=_cat["total"], uses=_uses, affected=_cat.get("affected_total") or 0,
                review=_cat.get("review_total") or 0))
        else:
            parts.append(t("ind_none", language).format(review=_cat.get("review_total") or 0))
        if (root / "reports" / f"{_cid}_iocs.md").is_file():
            parts.append(t("ind_see", language).format(
                md=f"reports/{_cid}_iocs.md", csv=f"reports/{_cid}_iocs.csv"))
        else:
            parts.append(t("ind_files_missing", language))
        parts.append("")
    except Exception:  # noqa: BLE001 - the report stands without the pointer
        pass

    # ---- 8. Appendix ----
    parts.append(f"## {titles['appendix']}")
    parts.append("")
    parts.append("### Master Timeline")
    parts.append("")
    mt_candidates = [
        root / "analysis" / "master_timeline.tsv",
        root / "reports" / "master_timeline.tsv",
        root / "reports" / "latest" / "master_timeline.tsv",
    ]
    mt_path = next((p for p in mt_candidates if p.is_file()), None)
    if mt_path:
        try:
            rel = mt_path.relative_to(root)
        except ValueError:
            rel = mt_path
        parts.append(
            f"- Curated investigation timeline: `{rel}` "
            f"(claim-relevant events only; raw capture stays under "
            f"`reports/.timeline_build/`)."
        )
    else:
        # Absent has two meanings and a reader deserves the difference: no
        # addon is switched on to produce one, or one is and it has not
        # written yet. Asked generically — core names no addon.
        try:
            from core.plugins import addons_for_event
            producers = addons_for_event("report_finalized")
        except Exception:  # noqa: BLE001 — an addon problem is not a report problem
            producers = []
        if not producers:
            why = "no addon installed produces one"
        elif not any(p.get("enabled") for p in producers):
            why = ("the addon that produces it is switched off: "
                   + ", ".join(p["addon"] for p in producers))
        else:
            why = "not written for this case yet"
        parts.append(
            f"- Curated investigation timeline: `master_timeline.tsv` ({why})."
        )
    parts.append("")
    parts.append("### Report generation metadata")
    parts.append("")
    parts.append(f"- Case ID: `{case_id}`")
    parts.append(f"- Report language: `{language}`")
    parts.append(f"- Generator: `{GENERATOR_VERSION}`")
    parts.append(f"- Scope: `{scope}`" + (f" host=`{host}`" if host else ""))
    parts.append(f"- Findings rendered: {len(findings)}")
    parts.append("")
    # Conflicts
    try:
        from core.claim_graph import load_graph, list_nodes
        graph = load_graph(root)
        conflicts = [
            n for n in list_nodes(graph, kind="conflict")
            if n.get("status") == "conflict"
        ]
        parts.append("### Conflicts")
        parts.append("")
        if not conflicts:
            parts.append(t("no_conflicts", language))
        else:
            for c in conflicts:
                parts.append(
                    f"- **{c.get('id')}**: {(c.get('statement') or '')[:200]}"
                )
        parts.append("")
    except Exception:
        pass

    # Section markers for tooling
    for s in SECTION_ORDER:
        sid = s["id"]
        sec = (manifest.get("sections") or {}).get(sid) or {}
        claim_s = ",".join(sec.get("claim_ids") or [])
        concl_s = ",".join(sec.get("conclusion_ids") or [])
        conf_s = ",".join(sec.get("conflict_ids") or [])
        parts.append(
            f"<!-- section:{sid} status:{sec.get('status') or 'assembled'} "
            f"claims:{claim_s} conclusions:{concl_s} conflicts:{conf_s} -->"
        )
    parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def undescribed_picture_lines(root) -> list[str]:
    """One line per extracted output's picture class (tools.images
    .PICTURE_TYPES) while no picture can be described (tools.images
    .unavailable): "- <n> pictures in <folder> (<class>) were not
    identified by their content: <reason>", n the class's files, read or
    not. [] when descriptions can run, and under a handling stop (no
    picture of such a case is ever sent; the stop's own line says so)."""
    from tools.images import PICTURE_TYPES, unavailable
    try:
        from core import handling_stop as hs
        if hs.state(root):
            return []
    except Exception:  # noqa: BLE001
        pass
    reason = unavailable(root)
    if not reason:
        return []
    from core.coverage_ledger import extracted_outputs, shown_name
    out = []
    for o in extracted_outputs(root):
        for label, (_read, total) in sorted((o.get("classes") or {}).items()):
            if str(label).lower().lstrip(".") in PICTURE_TYPES and total:
                out.append(f"- {total} picture{'s' if total != 1 else ''} in {shown_name(o['path'], quote=False)} "
                           f"({label}) {'were' if total != 1 else 'was'} not identified by their content: {reason}")
    return out


def described_picture_lines(root) -> list[str]:
    """One line per vision model that described pictures in this run, from
    the trace's successful images.describe calls: "- Pictures described by
    a vision model (<model>): <paths>", the paths through shown_name;
    [] when no call succeeded."""
    import json as _json
    from pathlib import Path as _Path
    from core.coverage_ledger import _trace_or_log, listed_tool_name, shown_name
    try:
        # The case's trace, as every other report line reads it: a report
        # assembled in a later process sees the same calls.
        entries = [e for e in _trace_or_log(None, _Path(root))
                   if e.get("type") == "tool_call" and e.get("success") is True
                   and listed_tool_name(str(e.get("mcp_tool") or e.get("cmd") or "")) == "images_describe"]
    except Exception:  # noqa: BLE001
        return []
    by_model: dict[str, list[str]] = {}
    for e in entries:
        try:
            args = e.get("args")
            args = _json.loads(args) if isinstance(args, str) else (args or {})
        except ValueError:
            args = {}
        paths = args.get("image_path") if isinstance(args, dict) else None
        paths = [paths] if isinstance(paths, str) else [str(p) for p in (paths or []) if p]
        m = re.search(r'"model":\s*"([^"\\]{1,120})"', str(e.get("stdout_excerpt") or ""))
        model = m.group(1) if m else "model not recorded"
        for p in paths:
            if p not in by_model.setdefault(model, []):
                by_model[model].append(p)
    return [f"- Pictures described by a vision model ({shown_name(model, quote=False)}): "
            + ", ".join(shown_name(p) for p in paths) for model, paths in sorted(by_model.items())]
