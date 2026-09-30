"""Client-facing forensic report assembler.

Separates responsibilities:

* **LLM** (optional): Executive Summary narrative; per-finding Summary /
  Assessment; Gaps / Recommendations narrative prose stored in section bodies.
* **Deterministic code**: TOC, section order, F-IDs, Key Findings table,
  Supporting Evidence (via Evidence Resolver), Attack Timeline rows, Trace,
  Confidence, MITRE tags, Appendix artifact references.

``render_markdown`` / ``assemble_report`` call ``assemble_client_report`` so
future reports always follow the standard spine regardless of how section
prose was previously generated.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def _answers_section(root: Path, findings: list[dict[str, Any]], language: str,
                     narratives: dict[str, dict[str, str]] | None = None) -> list[str]:
    """Answers to the investigation questions, from the beliefs linked to
    each — the same projection the dashboard's Questions tab shows."""
    from core.report_i18n import t
    lines: list[str] = []
    try:
        from core.answer_synthesis import answer_for_task
        from core.claim_graph import load_graph
        from core.investigation_tasks import list_tasks, tasks_path
        if tasks_path(root).is_file():
            tasks = [x for x in list_tasks(root) if x.get("status") != "dropped"]
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
    for i, task in enumerate(tasks, start=1):
        text = (task.get("text") or "").strip()
        if text.lower().startswith("[derived]"):
            text = text[len("[derived]"):].strip()
        ans = answer_for_task(task, graph, summaries, language=language)
        if ans.get("has_answer"):
            from core.answer_synthesis import synthesize_answer_text
            ans["text"] = synthesize_answer_text(
                root, task.get("id") or f"task-{i:04d}", text, ans, language=language)
        conf = f" [{ans['confidence']}]" if ans.get("confidence") else ""
        lines.append(f"### Q{i} · {_md_inline(text)}{conf}")
        lines.append("")
        if ans["has_answer"]:
            lines.append(_md_inline(ans["text"]))
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


def _build_attack_timeline_rows(
    findings: list[dict[str, Any]],
    packs: dict[str, dict[str, Any]],
    *,
    max_rows: int = 120,
    max_rows_per_finding: int = 12,
) -> list[dict[str, str]]:
    """Curated timeline rows from resolved evidence (not full master timeline).

    Keeps multiple artifact perspectives per finding (different sources /
    producers) instead of a single global type allow/deny list. Caps per
    finding so one noisy claim cannot crowd out the rest of the attack story.
    """
    from core.evidence_noise import (
        is_tool_metadata_text,
        is_weak_timeline_event_text,
        looks_like_evidence_gap_statement,
    )

    rows: list[dict[str, str]] = []
    case_hosts = sorted({str(f.get("host") or "") for f in findings if f.get("host")})
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
            parsed = _fields_from_event_text(text)
            # "++++ r/r 1234-128-4:" is not a time and a CSV header is not
            # an event; both reached the attack timeline as rows.
            ts = _valid_timestamp(ev.get("timestamp") or parsed.get("timestamp") or "") \
                or _valid_timestamp(text)
            host = (ev.get("host") or parsed.get("host") or claim_host or "").strip()
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
    rows = _build_attack_timeline_rows(findings, packs)
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
) -> str:
    """Build the full client Markdown report with deterministic structure."""
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
    recs_prose = _narrative_section(root, "recommendations")
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
    parts.append("")

    # ---- Answers to the Investigation Questions ----
    parts.append(f"## {answers_title}")
    parts.append("")
    parts.extend(_answers_section(root, findings, language, narratives))

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
    # Analyst context
    try:
        from core.analyst_context import list_context
        active = list_context(root, active_only=True)
        if active:
            parts.append("**Analyst-provided context (interpretation only):**")
            parts.append("")
            for e in active[:8]:
                parts.append(
                    f"- `{e.get('id')}`: {(e.get('text') or '')[:300]}"
                )
            parts.append("")
    except Exception:
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
            conf = f.get("confidence") or "UNCONFIRMED"
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
        return f"{x.get('finding_id') or x.get('id')} [{str(x.get('confidence') or 'UNCONFIRMED')}]"

    for f in findings:
        fid = str(f.get("finding_id") or f.get("id") or "?")
        nid = f.get("id") or ""
        conf = str(f.get("confidence") or "UNCONFIRMED")
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
                pack, compact=True, limit=3, known_hosts=case_hosts,
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
    tl_rows = _build_attack_timeline_rows(findings, packs)
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
        gap_lines: list[str] = []
        for f in findings:
            fid = f.get("finding_id") or f.get("id")
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

    # ---- 7. Recommendations ----
    parts.append(f"## {titles['recommendations']}")
    parts.append("")
    if recs_prose:
        parts.append(_demote_headings(recs_prose).strip())
        parts.append("")
    else:
        if scope == "host":
            parts.append(
                "1. Preserve forensic image and relevant volatile artifacts "
                "for this host."
            )
            parts.append(
                "2. See Estate Report for estate-wide recommendations."
            )
        else:
            parts.append(
                "1. Containment/isolation decisions must follow confirmed "
                "findings only — do not invent compromise evidence."
            )
            parts.append(
                "2. Credential hygiene and backup integrity verification as "
                "warranted by Detailed Findings."
            )
        parts.append("")
        parts.append("Finding-tied actions:")
        parts.append("")
        for f in findings[:10]:
            fid = f.get("finding_id") or f.get("id")
            parts.append(
                f"- **{fid}** ({f.get('confidence')}): "
                f"{_md_inline(f.get('statement') or '')[:160]}"
            )
        parts.append("")

    # ---- Indicators (a pointer: the list itself is its own deliverable) ----
    try:
        from core.ioc_catalog import build_catalog as _ioc_catalog
        _cat = _ioc_catalog(root)
        _cid = detect_case_id(root) or "case"
        parts.append(f"## {t('indicators', language)}")
        parts.append("")
        parts.append(t("ind_frame_subject" if _cat.get("frame") == "subject" else "ind_frame_incident", language))
        _uses = ", ".join(f"{n} {t('use_' + u, language)}" for u, n in sorted((_cat.get("by_use") or {}).items()))
        if _cat.get("total"):
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
