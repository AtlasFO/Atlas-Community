"""Report projection — format-agnostic sections from Current Investigation State.

The report is NEVER the source of truth. Markdown/HTML/JSON are assembled
projections of **Current Investigation State** (Claim Graph + investigation
memory + journal continuity — not the Claim Graph alone).

Investigation-driven flow::

    Current Investigation State
            ↓
    Relevant section context
            ↓
    LLM (per stale section)  — optional; --no-agent / Plane A only marks stale
            ↓
    Section store (.atlas/report_projection/sections/)
            ↓
    Renderer (markdown | html | json) → reports/*

Section identity is stable; deliverables are disposable output.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

GENERATOR_VERSION = "report-projection/2.1"
SCHEMA_VERSION = "1.0"

# Client-facing section spine (stable). MITRE tactics are tags only.
SECTION_ORDER: list[dict[str, Any]] = [
    {
        "id": "exec_summary",
        "title": "1. Executive Summary",
        "depends_on": ["detailed_findings", "gaps", "appendix"],
        "bind": "meta",
        "anti_dup": "exec_summary",
    },
    {
        "id": "scope_evidence",
        "title": "2. Scope and Evidence",
        "depends_on": [],
        "bind": "scope",
    },
    {
        "id": "key_findings",
        "title": "3. Key Findings",
        "depends_on": ["detailed_findings"],
        "bind": "meta",
        "anti_dup": "key_findings",
    },
    {
        "id": "detailed_findings",
        "title": "4. Detailed Findings",
        "depends_on": [],
        "bind": "primary",  # one authoritative block per finding
    },
    {
        "id": "timeline",
        "title": "5. Attack Timeline",
        "depends_on": ["detailed_findings"],
        "bind": "meta",
        "anti_dup": "timeline",
    },
    {
        "id": "gaps",
        "title": "6. Evidence Gaps and Open Questions",
        "depends_on": [],
        "bind": "gaps",
    },
    {
        "id": "recommendations",
        "title": "7. Recommendations",
        "depends_on": ["exec_summary", "detailed_findings", "gaps"],
        "bind": "meta",
        "anti_dup": "recommendations",
    },
    {
        "id": "appendix",
        "title": "8. Appendix",
        "depends_on": [],
        "bind": "appendix",  # conflicts + method notes
    },
]

# Internal MITRE / tactic tagging (not client H2 sections).
TACTIC_PATTERNS: list[tuple[str, list[str]]] = [
    ("initial_access", [
        r"\binitial\s+access\b", r"\bRDP\b", r"\blogon\b", r"\bT1078\b",
        r"\bT1021\.001\b", r"\bbrute.?force\b", r"\bT1110\b",
        r"\bauthentication\b", r"\bphishing\b",
    ]),
    ("execution", [
        r"\bexecut", r"\bPowerShell\b", r"\bcmd\.exe\b", r"\bT1059\b",
        r"\bprocess\s+creation\b", r"\bscript\b",
    ]),
    ("persistence", [
        r"\bpersistence\b", r"\bscheduled\s+task\b", r"\brun\s+key\b",
        r"\bT1547\b", r"\bT1053\b", r"\bautorun\b",
    ]),
    ("defense_evasion", [
        r"\bdefense\s+evasion\b", r"\bdisable\b.*\bdefender\b",
        r"\btimestomp\b", r"\blog\s+clear", r"\bT1070\b", r"\bT1562\b",
    ]),
    ("lateral_movement", [
        r"\blateral\b", r"\bSMB\b", r"\bT1021\b", r"\bpass.?the.?hash\b",
        r"\bnetwork\s+logon\b", r"\badmin\s+share\b",
    ]),
    ("impact", [
        r"\bransomware\b", r"\bencrypt", r"\bT1486\b", r"\bimpact\b",
        r"\bwiper\b", r"\bexfiltr",
    ]),
]

# Legacy MITRE section ids — accepted by explain/CLI, mapped to detailed_findings.
LEGACY_SECTION_ALIASES: dict[str, str] = {
    "initial_access": "detailed_findings",
    "execution": "detailed_findings",
    "persistence": "detailed_findings",
    "defense_evasion": "detailed_findings",
    "lateral_movement": "detailed_findings",
    "impact": "detailed_findings",
    "conflicts": "appendix",
}


# The model role the narrative sections run as. Named so the reasoning level
# can be set for it like any other role (ATLAS_EFFORT_REPORT), and so the trace
# attributes its calls to the report rather than to the analyst.
_REPORT_ROLE = "report"


def resolve_section_id(section_id: str) -> str:
    """Map legacy MITRE section ids onto the current spine."""
    sid = (section_id or "").strip()
    return LEGACY_SECTION_ALIASES.get(sid, sid)


def _tag_tactics(text: str) -> list[str]:
    tags: list[str] = []
    for tactic, pats in TACTIC_PATTERNS:
        if any(re.search(p, text, re.I) for p in pats):
            tags.append(tactic)
    return tags


SectionGenerator = Callable[[dict[str, Any], dict[str, Any]], str]


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def projection_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "report_projection"


def manifest_path(case_dir: str | os.PathLike) -> Path:
    return projection_dir(case_dir) / "manifest.json"


def sections_dir(case_dir: str | os.PathLike) -> Path:
    return projection_dir(case_dir) / "sections"


def empty_manifest(case_id: str = "", *, language: str = "en") -> dict[str, Any]:
    from core.report_i18n import section_title

    sections = {}
    for s in SECTION_ORDER:
        sid = s["id"]
        sections[sid] = {
            "id": sid,
            "title": section_title(sid, language),
            "status": "missing",  # missing | stale | current
            "depends_on": list(s.get("depends_on") or []),
            "claim_ids": [],
            "conclusion_ids": [],
            "conflict_ids": [],
            "evidence_ids": [],
            "finding_tactics": {},  # node_id -> [tactic, ...]
            "content_sha256": None,
            "generated_at": None,
            "generator_version": GENERATOR_VERSION,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "updated_at": _utcnow(),
        "generator_version": GENERATOR_VERSION,
        "report_language": language,
        "section_order": [s["id"] for s in SECTION_ORDER],
        "sections": sections,
        "note": (
            "Report projection only. Authoritative knowledge is Current "
            "Investigation State (.atlas/) — never edit assembled Markdown "
            "as source of truth."
        ),
    }


def load_manifest(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = manifest_path(case_dir)
    lang = "en"
    try:
        from core.case_config import get_report_language
        lang = get_report_language(case_dir)
    except Exception:
        lang = "en"
    if not path.is_file():
        return empty_manifest(language=lang)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_manifest(language=lang)
    # Ensure all known sections exist; drop legacy MITRE section keys from order
    base = empty_manifest(data.get("case_id", ""), language=lang)
    for sid, sec in base["sections"].items():
        data.setdefault("sections", {}).setdefault(sid, sec)
        # Refresh titles from glossary when language changes
        data["sections"][sid]["title"] = sec["title"]
        data["sections"][sid].setdefault("finding_tactics", {})
    data["section_order"] = list(base["section_order"])
    data["report_language"] = lang
    data.setdefault("generator_version", GENERATOR_VERSION)
    return data


def save_manifest(case_dir: str | os.PathLike, manifest: dict[str, Any]) -> Path:
    d = projection_dir(case_dir)
    d.mkdir(parents=True, exist_ok=True)
    sections_dir(case_dir).mkdir(parents=True, exist_ok=True)
    manifest = dict(manifest)
    manifest["updated_at"] = _utcnow()
    manifest["schema_version"] = SCHEMA_VERSION
    path = manifest_path(case_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)
    return path


def _load_section_body(case_dir: str | os.PathLike, section_id: str) -> dict[str, Any]:
    path = sections_dir(case_dir) / f"{section_id}.json"
    if not path.is_file():
        return {"id": section_id, "prose": "", "format": "dfir_notes"}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"id": section_id, "prose": "", "format": "dfir_notes"}


def _save_section_body(
    case_dir: str | os.PathLike,
    section_id: str,
    prose: str,
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "id": section_id,
        "prose": prose,
        "format": "dfir_notes",
        "generated_at": _utcnow(),
        "generator_version": GENERATOR_VERSION,
        "context_claim_ids": (context or {}).get("claim_ids") or [],
        "context_conclusion_ids": (context or {}).get("conclusion_ids") or [],
        "context_conflict_ids": (context or {}).get("conflict_ids") or [],
    }
    digest = hashlib.sha256(prose.encode("utf-8")).hexdigest()
    body["content_sha256"] = digest
    path = sections_dir(case_dir) / f"{section_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return body


def _node_evidence_ids(node: dict) -> list[str]:
    ids = []
    for item in node.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        # Prefer call_id as weak evidence ref; path fragments as artifact
        art = str(item.get("artifact") or "")
        if art:
            ids.append(art[:128])
        if item.get("call_id"):
            ids.append(f"call:{item['call_id']}")
    return ids


def bind_claims_to_sections(
    case_dir: str | os.PathLike,
    *,
    host: str = "",
    scope: str = "",
) -> dict[str, Any]:
    """Recompute which claims/conclusions/conflicts feed each section.

    Primary bind: every current belief lands once in ``detailed_findings``.
    Meta sections receive the same id lists for context, but assemblers /
    prompts forbid duplicating Evidence. MITRE tactics are stored as tags
    only (``finding_tactics``), not as separate H2 sections.

    Optional ``host`` / ``scope`` filters for per-host vs estate projections.
    Empty filters = all beliefs (case-level report).
    """
    from core.claim_graph import (
        CURRENT_BELIEF_STATUSES,
        load_graph,
        list_nodes,
        node_in_report_scope,
    )
    from core.finding_index import ensure_finding_ids
    from core.paths import detect_case_id

    graph = load_graph(case_dir)
    case_id = detect_case_id(case_dir)
    manifest = load_manifest(case_dir)
    manifest["case_id"] = case_id or manifest.get("case_id") or ""
    host_f = (host or "").strip()
    scope_f = "host" if (scope or "").strip().lower() == "host" or host_f else "case"

    # Ensure stable F-ids exist for report assembly
    try:
        ensure_finding_ids(case_dir)
    except Exception:
        pass

    def _include(n: dict) -> bool:
        return node_in_report_scope(n, scope_f, host_f)

    claims = [
        n for n in list_nodes(graph, kind="claim")
        if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}
        and _include(n)
    ]
    conclusions = [
        n for n in list_nodes(graph, kind="conclusion")
        if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}
        and _include(n)
    ]
    conflicts = [
        n for n in list_nodes(graph, kind="conflict")
        if n.get("status") == "conflict" and _include(n)
    ]

    # Reset bindings
    for sid, sec in manifest["sections"].items():
        if sid not in {s["id"] for s in SECTION_ORDER}:
            continue
        sec["claim_ids"] = []
        sec["conclusion_ids"] = []
        sec["conflict_ids"] = []
        sec["evidence_ids"] = []
        sec["finding_tactics"] = {}

    all_claim_ids = [n["id"] for n in claims]
    all_conclusion_ids = [n["id"] for n in conclusions]
    all_conflict_ids = [n["id"] for n in conflicts]
    all_evidence: list[str] = []
    finding_tactics: dict[str, list[str]] = {}

    for n in claims + conclusions:
        text = (n.get("statement") or "") + " " + (n.get("reasoning") or "")
        tags = _tag_tactics(text)
        if tags:
            finding_tactics[n["id"]] = tags
        all_evidence.extend(_node_evidence_ids(n))

    # Primary: detailed findings (once)
    dsec = manifest["sections"]["detailed_findings"]
    dsec["claim_ids"] = list(all_claim_ids)
    dsec["conclusion_ids"] = list(all_conclusion_ids)
    dsec["evidence_ids"] = list(dict.fromkeys(all_evidence))[:200]
    dsec["finding_tactics"] = finding_tactics

    # Gaps — bind ALL active claims so the LLM / deterministic generator
    # sees real findings. Prefer nodes with explicit gaps[] / needs_review /
    # UNCONFIRMED / evidence-gap language, but never leave the section empty
    # while Detailed Findings are full (contradictory empty-state prose).
    from core.evidence_noise import looks_like_evidence_gap_statement

    gsec = manifest["sections"]["gaps"]
    gap_claims = []
    priority_claims = []
    for n in claims + conclusions:
        nid = n["id"]
        stmt = (n.get("statement") or "") + " " + (n.get("reasoning") or "")
        is_priority = bool(
            n.get("gaps")
            or n.get("status") == "needs_review"
            or (n.get("confidence") or "").upper() == "UNCONFIRMED"
            or looks_like_evidence_gap_statement(stmt)
        )
        if is_priority:
            priority_claims.append(nid)
        gap_claims.append(nid)
        gsec["evidence_ids"].extend(_node_evidence_ids(n))
    # Bind the whole case, always. Binding only the gap-flagged claims lets a
    # case with one UNCONFIRMED claim among many be described as resting on
    # a single evidence category with nothing confirmed, in a report whose
    # previous section lists CONFIRMED findings. A section that writes about
    # a subset still has to
    # see the shape of the whole; priority_claim_ids says which subset it is
    # about.
    gsec["claim_ids"] = gap_claims
    gsec["priority_claim_ids"] = priority_claims
    gsec["conclusion_ids"] = [
        n["id"] for n in conclusions
        if n.get("gaps")
        or n.get("status") == "needs_review"
        or looks_like_evidence_gap_statement(
            (n.get("statement") or "") + " " + (n.get("reasoning") or ""))
    ] or [n["id"] for n in conclusions]

    # Appendix: conflicts + method notes
    asec = manifest["sections"]["appendix"]
    asec["conflict_ids"] = list(all_conflict_ids)
    for n in conflicts:
        asec["evidence_ids"].extend(_node_evidence_ids(n))

    # Scope: light — no claim dump; placeholders filled by generator
    ssec = manifest["sections"]["scope_evidence"]
    ssec["claim_ids"] = []
    ssec["conclusion_ids"] = []
    ssec["evidence_ids"] = list(dict.fromkeys(all_evidence))[:50]

    # Meta sections: same ids for context (anti-dup in prompts/assembler)
    for mid in ("exec_summary", "key_findings", "timeline", "recommendations"):
        sec = manifest["sections"][mid]
        sec["claim_ids"] = list(all_claim_ids)
        sec["conclusion_ids"] = list(all_conclusion_ids)
        sec["conflict_ids"] = list(all_conflict_ids)
        sec["evidence_ids"] = list(dict.fromkeys(all_evidence))[:100]
        sec["finding_tactics"] = finding_tactics

    # Dedup lists
    for sec in manifest["sections"].values():
        for key in ("claim_ids", "conclusion_ids", "conflict_ids", "evidence_ids"):
            sec[key] = list(dict.fromkeys(sec.get(key) or []))

    save_manifest(case_dir, manifest)
    return manifest


def _section_fingerprint(sec: dict) -> str:
    payload = json.dumps({
        "claim_ids": sec.get("claim_ids"),
        "conclusion_ids": sec.get("conclusion_ids"),
        "conflict_ids": sec.get("conflict_ids"),
        "evidence_ids": sec.get("evidence_ids"),
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def mark_stale_sections(
    case_dir: str | os.PathLike,
    *,
    dirty_node_ids: list[str] | None = None,
    force_all: bool = False,
    host: str = "",
    scope: str = "",
    report_scope: str = "",
    report_host: str = "",
) -> dict[str, Any]:
    """Mark sections stale when their contributing nodes changed or deps require it.

    Does not rewrite prose. Report remains a projection — this only updates
    projection metadata.

    ``report_scope``/``report_host`` name the deliverable being assembled;
    prose written for another one (a host report, now a case report) is
    stale even though its claims did not change: a summary written for a
    host must not survive a switch to the case scope.
    """
    bind_kw = {}
    if host:
        bind_kw["host"] = host
    if scope:
        bind_kw["scope"] = scope
    manifest = bind_claims_to_sections(case_dir, **bind_kw)
    dirty = set(dirty_node_ids or [])
    stale: list[str] = []

    # Direct: section contributes a dirty node
    for sid, sec in manifest["sections"].items():
        contrib = set(sec.get("claim_ids") or []) | set(
            sec.get("conclusion_ids") or []
        ) | set(sec.get("conflict_ids") or [])
        binding_fp = _section_fingerprint(sec)
        prev_fp = sec.get("binding_fingerprint")
        if force_all:
            sec["status"] = "stale"
            stale.append(sid)
        elif report_scope and sec.get("status") == "current" and (
            (sec.get("report_scope") or "") != report_scope.lower()
            or (sec.get("report_host") or "").lower() != (report_host or "").lower()
        ):
            sec["status"] = "stale"
            stale.append(sid)
        elif dirty and contrib & dirty:
            sec["status"] = "stale"
            stale.append(sid)
        elif prev_fp and prev_fp != binding_fp:
            sec["status"] = "stale"
            stale.append(sid)
        elif sec.get("status") == "missing":
            # Never generated — stale until first generation
            if contrib or sid in (
                "exec_summary", "scope_evidence", "key_findings",
                "detailed_findings", "gaps", "appendix",
                "recommendations", "timeline",
            ):
                sec["status"] = "stale"
                stale.append(sid)
        sec["binding_fingerprint"] = binding_fp

    # Propagate via depends_on
    changed = True
    while changed:
        changed = False
        stale_set = set(stale)
        for sdef in SECTION_ORDER:
            sid = sdef["id"]
            deps = sdef.get("depends_on") or []
            if sid in stale_set:
                continue
            if any(d in stale_set for d in deps):
                manifest["sections"][sid]["status"] = "stale"
                stale.append(sid)
                changed = True

    save_manifest(case_dir, manifest)
    return {
        "stale_sections": list(dict.fromkeys(stale)),
        "manifest_path": str(manifest_path(case_dir)),
    }


def section_context(
    case_dir: str | os.PathLike,
    section_id: str,
    *,
    report_scope: str = "case",
    report_host: str = "",
) -> dict[str, Any]:
    """Build LLM context for one section from Current Investigation State.

    The manifest binding says which beliefs feed the section; which of them
    belong in *this* deliverable is decided here, from ``report_scope`` and
    ``report_host``. The binding is rewritten by whoever bound last (Plane A
    rebinds the whole case after every scan), so a host report cannot rely
    on it having been made for that host.
    """
    from core.case_config import get_report_language
    from core.claim_graph import get_node, load_graph, node_in_report_scope
    from core.finding_index import f_id_for
    from core.report_i18n import language_instruction, section_title

    section_id = resolve_section_id(section_id)
    language = get_report_language(case_dir)
    manifest = load_manifest(case_dir)
    sec = manifest["sections"].get(section_id) or {}
    graph = load_graph(case_dir)
    tactics_map = sec.get("finding_tactics") or {}
    if not tactics_map:
        tactics_map = (
            (manifest.get("sections") or {})
            .get("detailed_findings", {})
            .get("finding_tactics")
            or {}
        )
    scope = (report_scope or "case").lower()
    host = (report_host or "").strip()

    def _nodes(ids: list[str]) -> list[dict]:
        out = []
        for i in ids:
            n = get_node(graph, i)
            if n and node_in_report_scope(n, scope, host):
                fid = None
                try:
                    fid = f_id_for(case_dir, i)
                except Exception:
                    fid = None
                out.append({
                    "id": n.get("id"),
                    "finding_id": fid,
                    "kind": n.get("kind"),
                    "status": n.get("status"),
                    "confidence": n.get("confidence"),
                    "statement": n.get("statement"),
                    "reasoning": n.get("reasoning"),
                    "gaps": n.get("gaps"),
                    "evidence": n.get("evidence"),
                    "temporal_qualifier": n.get("temporal_qualifier"),
                    "host": n.get("host"),
                    "scope": n.get("scope"),
                    "tactics": tactics_map.get(i) or [],
                })
        return out

    scope_style = ""
    if scope == "host":
        scope_style = (
            f" This is a HOST report"
            + (f" for host={host}." if host else ".")
            + " Recommendations must be host-scoped only; do not include "
            "estate-wide actions (krbtgt, domain-wide, containment of all "
            "hosts). Point to the Estate Report for estate items."
        )
    elif scope == "estate":
        scope_style = (
            " This is an ESTATE report. Include cross-host synthesis and "
            "estate-scoped recommendations when findings show multi-host "
            "impact."
        )

    anti = ""
    if section_id == "exec_summary":
        anti = (
            " Executive Summary: 1–2 sentences per F-id only; cite F-ids; "
            "NO Supporting Evidence blocks; NO full finding restatement."
        )
    elif section_id == "key_findings":
        anti = (
            " Key Findings: compact table rows only (F-id, confidence, host, "
            "one-line statement). No Evidence. Detail lives in Detailed Findings."
        )
    elif section_id == "detailed_findings":
        anti = (
            " Detailed Findings: write Summary and Assessment only for each "
            "F-id. Do NOT invent raw log lines — Supporting Evidence is "
            "injected deterministically after your prose."
        )
    elif section_id == "timeline":
        anti = (
            " Attack Timeline: compact chronological table with F-id refs; "
            "no raw timeline dumps; no Evidence blocks."
        )
    elif section_id == "recommendations":
        anti = (
            " Recommendations: tie each item to F-/G- ids; no Evidence blocks."
        )
    elif section_id == "gaps":
        flagged = [c for c in (sec.get("priority_claim_ids") or [])]
        anti = (
            " Evidence Gaps: write about what is MISSING or unresolved"
            + (f" — the gap-flagged findings are {', '.join(flagged[:12])}"
               if flagged else "")
            + ". You are shown every current finding so you can see the state "
            "of the case: do NOT characterise the investigation as a whole "
            "from the gaps (no 'nothing has been confirmed', no 'the case "
            "rests on one source', no 'no disk image has been referenced') "
            "unless the findings you were given actually say so."
        )

    claims = _nodes(sec.get("claim_ids") or [])
    conclusions = _nodes(sec.get("conclusion_ids") or [])
    conflicts = _nodes(sec.get("conflict_ids") or [])

    resolved_evidence: dict[str, Any] = {}
    if section_id == "detailed_findings":
        try:
            from core.evidence_resolver import resolve_nodes_evidence
            resolved_evidence = resolve_nodes_evidence(
                case_dir, list(claims) + list(conclusions),
            )
        except Exception:
            resolved_evidence = {}

    title = sec.get("title") or section_title(section_id, language)

    return {
        "section_id": section_id,
        "title": title,
        "case_dir": str(case_dir),
        "report_scope": scope,
        "report_host": host,
        "report_language": language,
        "claim_ids": [n["id"] for n in claims],
        "conclusion_ids": [n["id"] for n in conclusions],
        "conflict_ids": [n["id"] for n in conflicts],
        "evidence_ids": sec.get("evidence_ids") or [],
        "claims": claims,
        "conclusions": conclusions,
        "conflicts": conflicts,
        "resolved_evidence": resolved_evidence,
        "finding_tactics": tactics_map,
        "style": (
            "DFIR investigation notes. "
            + language_instruction(language)
            + " Do NOT invent, paraphrase, or reconstruct raw log lines. "
            "Never say 'was not compromised'; use available-evidence wording. "
            "Cite finding_id (F-NNN) and claim/conclusion ids when present."
            + anti
            + scope_style
        ),
    }


def deterministic_section_generator(
    context: dict[str, Any],
    manifest_section: dict[str, Any],
) -> str:
    """Fallback section writer from Current Investigation State (no LLM).

    Used when LLMHUB_API_KEY is unset or the LLM call fails — keeps
    investigation-driven reporting reliable. Prose is structured from
    beliefs; the LLM path remains preferred when available.
    """
    from core.report_i18n import t

    lang = context.get("report_language") or "en"
    title = context.get("title") or context.get("section_id") or "Section"
    sid = context.get("section_id") or ""
    lines = [f"## {title}", ""]
    conclusions = context.get("conclusions") or []
    claims = context.get("claims") or []
    conflicts = context.get("conflicts") or []
    resolved = context.get("resolved_evidence") or {}

    def _fid(n: dict) -> str:
        return n.get("finding_id") or n.get("id") or "?"

    if sid == "appendix":
        lines.append("### Conflicts")
        lines.append("")
        if not conflicts:
            lines.append(t("no_conflicts", lang))
            lines.append("")
        for c in conflicts:
            lines.append(
                f"- **{c.get('id')}** ({c.get('confidence') or 'n/a'}): "
                f"{(c.get('statement') or '').strip()}"
            )
            if c.get("reasoning"):
                lines.append(f"  - {t('assessment', lang)}: {c['reasoning'][:400]}")
            lines.append("")
        lines.append("### Method notes")
        lines.append("")
        lines.append(
            "Beliefs and evidence resolve from Current Investigation State "
            "(.atlas/). Supporting Evidence is provenance-first (record_ref → "
            "call_id → artifact+locator); correlated matches are labeled."
        )
        lines.append("")
    elif sid == "gaps":
        gaps: list[str] = []
        from core.evidence_noise import looks_like_evidence_gap_statement
        for n in conclusions + claims:
            fid = _fid(n)
            for g in n.get("gaps") or []:
                if g and g not in gaps:
                    gaps.append(f"{fid}: {g}")
            if n.get("status") == "needs_review":
                gaps.append(
                    f"{fid}: needs_review — re-validate against current evidence"
                )
            stmt = (n.get("statement") or "").strip()
            if looks_like_evidence_gap_statement(stmt):
                # Use the statement itself as a limitation bullet.
                snippet = stmt[:240] + ("…" if len(stmt) > 240 else "")
                entry = f"{fid}: {snippet}"
                if entry not in gaps:
                    gaps.append(entry)
            elif (n.get("confidence") or "").upper() == "UNCONFIRMED":
                entry = (
                    f"{fid}: UNCONFIRMED — "
                    f"{stmt[:200]}{'…' if len(stmt) > 200 else ''}"
                )
                if entry not in gaps:
                    gaps.append(entry)
        if not gaps:
            lines.append(t("no_gaps", lang))
            lines.append("")
        else:
            for g in gaps[:40]:
                lines.append(f"- {g}")
            lines.append("")
    elif sid == "scope_evidence":
        scope = (context.get("report_scope") or "case").lower()
        host = context.get("report_host") or ""
        if scope == "host" and host:
            lines.append(f"- Host scope: `{host}`")
        else:
            lines.append("- Scope: estate / case-level synthesis")
        lines.append(
            "- Evidence sources: tool outputs under analysis/, optional "
            "master_timeline.tsv, Claim Graph evidence references."
        )
        lines.append(
            "- Investigation SoT: `.atlas/` (claims, conclusions, conflicts, "
            "journal) — this report is a projection only."
        )
        lines.append("")
    elif sid == "key_findings":
        nodes = conclusions or claims
        if not nodes:
            lines.append("*No current findings.*")
            lines.append("")
        else:
            lines.append("| ID | Confidence | Host | Statement |")
            lines.append("|----|------------|------|-----------|")
            for n in nodes:
                stmt = (n.get("statement") or "").replace("|", "/").strip()
                if len(stmt) > 120:
                    stmt = stmt[:117] + "..."
                host = (n.get("host") or "—").replace("|", "/")
                conf = n.get("confidence") or "UNCONFIRMED"
                fid = _fid(n)
                anchor = fid.lower().replace(" ", "-")
                lines.append(
                    f"| [{fid}](#{anchor}) | {conf} | {host} | {stmt} |"
                )
            lines.append("")
    elif sid == "exec_summary":
        nodes = conclusions or claims
        if not nodes:
            lines.append("*No current findings to summarize.*")
            lines.append("")
        else:
            # Management reads this: a short plain paragraph, no identifiers.
            from core.answer_synthesis import _plain_headline, _hosts_in, _timespan
            rank = {"CONFIRMED": 4, "LIKELY": 3, "SUSPECTED": 2, "UNCONFIRMED": 1}
            top = sorted(nodes, key=lambda n: -rank.get(str(n.get("confidence") or "").upper(), 0))
            firm = [n for n in top if rank.get(str(n.get("confidence") or "").upper(), 0) >= 3]
            hosts = _hosts_in(nodes); span = _timespan(nodes)
            heads = [_plain_headline(n.get("statement") or "", limit=110) for n in (firm or top)[:3]]
            heads = [h for h in heads if h]
            lead = (f"The investigation covered {', '.join(hosts[:3])}" if hosts else "The investigation")
            lead += f" over {span}" if span else ""
            lead += (f" and established {len(firm)} well-supported finding(s) out of {len(nodes)}."
                     if firm else f" and recorded {len(nodes)} finding(s), none yet firmly established.")
            lines.append(lead)
            if heads:
                lines.append("What happened, in brief: " + "; ".join(heads) + ".")
            if conflicts:
                lines.append(f"{len(conflicts)} finding(s) are in open conflict and are being re-examined.")
            lines.append("The Key Findings and Detailed Findings sections carry the technical detail.")
            lines.append("")
    elif sid == "timeline":
        nodes = conclusions or claims
        lines.append("| Time / Qualifier | Finding | Statement |")
        lines.append("|-----------------|---------|-----------|")
        for n in nodes:
            tq = (n.get("temporal_qualifier") or "—").replace("|", "/")
            if len(tq) > 40:
                tq = tq[:37] + "..."
            stmt = (n.get("statement") or "").replace("|", "/").strip()
            if len(stmt) > 100:
                stmt = stmt[:97] + "..."
            lines.append(f"| {tq} | {_fid(n)} | {stmt} |")
        if not nodes:
            lines.append("| — | — | *No dated findings* |")
        lines.append("")
    elif sid == "recommendations":
        # The response plan the run recorded, ordered and with its basis on
        # every line — never advice written for the occasion.
        from core.recommendations import build_catalog, render_markdown
        case_dir = context.get("case_dir") or ""
        catalog = build_catalog(case_dir) if case_dir else {"recommendations": []}
        lines.extend(render_markdown(
            catalog, lang,
            host=str(context.get("report_host") or ""),
            report_scope=(context.get("report_scope") or "case").lower(),
        ))
        # Mitigations with nothing to act on are references, listed once.
        if case_dir:
            from core.recommendations import hardening_references
            lines.extend(hardening_references(case_dir, lang))
    else:
        # detailed_findings (and any unexpected section)
        nodes = conclusions or claims
        if not nodes and not conflicts:
            lines.append(
                "*No bound beliefs for this section in Current Investigation State.*"
            )
            lines.append("")
        for n in nodes:
            conf = n.get("confidence") or "UNCONFIRMED"
            nid = n.get("id") or ""
            fid = _fid(n)
            anchor = fid.lower().replace(" ", "-")
            lines.append(f'<a id="{anchor}"></a>')
            lines.append("")
            # A heading is a name, not the finding's full text. It used to
            # be the entire statement, truncated mid-word, and then repeated
            # verbatim under Summary two lines later.
            from core.answer_synthesis import headline as _headline
            _stmt = (n.get("statement") or "").strip()
            # Same shape the model is asked for ("### F-NNN — short title");
            # the assembler adds the tier.
            lines.append(f"### {fid} — {_headline(_stmt) or _stmt}")
            lines.append("")
            lines.append(f"**{t('summary', lang)}**")
            lines.append("")
            lines.append((n.get("statement") or "").strip() or "(none)")
            lines.append("")
            lines.append(f"**{t('assessment', lang)}**")
            lines.append("")
            if n.get("reasoning"):
                lines.append(str(n["reasoning"])[:800])
            else:
                lines.append(
                    "See claim graph reasoning; assessment not separately recorded."
                )
            lines.append("")
            lines.append(f"**{t('confidence', lang)}:** {conf}")
            lines.append("")
            tactics = n.get("tactics") or []
            if tactics:
                lines.append(f"**{t('mitre', lang)}:** {', '.join(tactics)}")
                lines.append("")
            if n.get("host"):
                lines.append(f"**{t('host', lang)}:** {n['host']}")
                lines.append("")
            lines.append(f"**{t('supporting_evidence', lang)}**")
            lines.append("")
            pack = resolved.get(nid) if isinstance(resolved, dict) else None
            if pack:
                from core.evidence_resolver import format_evidence_markdown
                lines.append(format_evidence_markdown(pack).rstrip())
            else:
                evid = n.get("evidence") or []
                if evid:
                    from core.forensic_citation import strip_machine_citation_mark
                    lines.append(
                        "*Deterministic evidence resolution unavailable; "
                        "retained references only:*"
                    )
                    for e in evid[:8]:
                        if isinstance(e, dict):
                            lines.append(
                                f"- `{e.get('artifact', '')}` "
                                f"{strip_machine_citation_mark(str(e.get('locator', '')))} "
                                f"call_id={e.get('call_id') or ''}".strip()
                            )
                else:
                    lines.append(
                        "*Supporting raw event(s) could not be deterministically "
                        "resolved; no evidence references on this node.*"
                    )
            lines.append("")
            trace_bits = [fid, nid]
            for e in (n.get("evidence") or []):
                if isinstance(e, dict) and e.get("call_id"):
                    trace_bits.append(f"call:{e['call_id']}")
            lines.append(
                f"**{t('trace', lang)}:** {', '.join(str(bit) for bit in trace_bits)}"
            )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# After a section generation fails, the provider is not tried again for this
# long; the remaining sections take the deterministic stub at once.
PROVIDER_COOLDOWN_SECONDS = 600.0
_PROVIDER_DOWN_UNTIL = [0.0]


# Set when a stopping run is told to stop again: narrative sections are
# skipped in favour of their deterministic stubs so the report still lands.
HURRY = threading.Event()


def _trace(method: str, *args: Any, **kwargs: Any) -> None:
    # Best effort: the CLI regenerates sections without a trace configured,
    # and a failed trace write must never cost a section its prose.
    try:
        from core.execution_log import log
        getattr(log, method)(*args, **kwargs)
    except Exception:  # noqa: BLE001
        pass


def resilient_section_generator(
    context: dict[str, Any],
    manifest_section: dict[str, Any],
) -> str:
    """Prefer LLM for narrative sections; structural sections stay deterministic.

    Structural (never LLM-authored as final truth): key_findings, timeline,
    scope_evidence, appendix — these are rebuilt at assemble time anyway, but
    we still store deterministic stubs for section status.
    """
    sid = context.get("section_id") or ""
    # Recommendations are a projection of recorded recommendation nodes,
    # not prose: each line names what it rests on.
    if sid in ("key_findings", "timeline", "scope_evidence", "appendix",
               "recommendations"):
        return deterministic_section_generator(context, manifest_section)
    import time as _time
    if HURRY.is_set():
        manifest_section["generator"] = "deterministic_fallback"
        manifest_section["generator_error"] = "stop requested during report writing"
        return deterministic_section_generator(context, manifest_section)
    if _time.monotonic() < _PROVIDER_DOWN_UNTIL[0]:
        # The provider failed a moment ago; eight sections each waiting out a
        # network timeout would hold a stopping run for a quarter of an hour.
        manifest_section["generator"] = "deterministic_fallback"
        manifest_section["generator_error"] = "provider unavailable (cooldown)"
        return deterministic_section_generator(context, manifest_section)
    try:
        prose = default_llm_section_generator(context, manifest_section)
    except TimeoutError as e:
        # A section that outran its budget says nothing about the provider:
        # the next section is smaller and may well be answered. Arming the
        # cooldown here would let one long section stub the whole report.
        import sys
        manifest_section["generator"] = "deterministic_fallback"
        manifest_section["generator_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        print(f"[Atlas WARN] report section {sid}: generation outran its "
              f"budget; deterministic fallback used", file=sys.stderr)
        return deterministic_section_generator(context, manifest_section)
    except Exception as e:  # noqa: BLE001
        _PROVIDER_DOWN_UNTIL[0] = _time.monotonic() + PROVIDER_COOLDOWN_SECONDS
        # Ship the deterministic stub, but say so: a bullet-list executive
        # summary must not pass as written prose without anyone knowing.
        import sys
        manifest_section["generator"] = "deterministic_fallback"
        manifest_section["generator_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        print(f"[Atlas WARN] report section {sid}: LLM generator failed "
              f"({type(e).__name__}: {str(e)[:120]}); deterministic fallback used",
              file=sys.stderr)
        return deterministic_section_generator(context, manifest_section)
    manifest_section["generator"] = "llm"
    manifest_section.pop("generator_error", None)
    return prose


_TECHNICAL_RE = re.compile(
    r"(?i)\b(?:EID|Event\s*ID)\s*\d{3,5}|\bS-1-5-21(?:-\d+){3,4}|\b[0-9a-f]{32,64}\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\bF-\d{3}\b|\$MFT|\bAmcache|\bPrefetch\b|LogonType|"
    r"\b\w+\.(?:exe|dll|ps1|evtx|csv|vmdk|raw|hve|dat)\b|\bRecordNumber\b|\binode\b")


def technical_depth(text: str) -> list[str]:
    """Fragments that do not belong in a management summary."""
    return [m.group(0) for m in _TECHNICAL_RE.finditer(text or "")]


def default_llm_section_generator(
    context: dict[str, Any],
    manifest_section: dict[str, Any],
) -> str:
    """AI-write narrative fields only (never raw evidence provenance)."""
    from core import providers
    from core.report_i18n import language_instruction

    lang = context.get("report_language") or "en"
    sid = context.get("section_id") or ""

    # Structural sections must not be LLM-authored
    if sid in ("key_findings", "timeline", "scope_evidence", "appendix"):
        return deterministic_section_generator(context, manifest_section)

    system = (
        "You are a DFIR investigator writing narrative sections of a forensic "
        "report from Current Investigation State only. "
        f"{language_instruction(lang)} "
        "NEVER invent events, timestamps, users, hosts, IPs, source files, "
        "line numbers, RecordRefs, Event IDs, commands, or processes. "
        "NEVER write Supporting Evidence blocks, raw log lines, or Attack "
        "Timeline tables — those are injected deterministically by code."
    )

    def _slim(nodes: list) -> list:
        out = []
        for n in nodes:
            out.append({
                k: n.get(k) for k in (
                    "id", "finding_id", "kind", "confidence", "statement",
                    "reasoning", "host", "scope", "temporal_qualifier",
                    "tactics", "gaps",
                )
            })
        return out

    claims = _slim(context.get("claims") or [])
    conclusions = _slim(context.get("conclusions") or [])

    if sid == "detailed_findings":
        user = (
            f"Section: Detailed Findings narratives only\n"
            f"Language: {lang}\n"
            f"Report scope: {context.get('report_scope')} "
            f"host={context.get('report_host') or '(n/a)'}\n\n"
            f"For EACH finding below, write Markdown of this exact shape:\n\n"
            f"### F-NNN — short title\n\n"
            f"**Summary**\n\n"
            f"<2-4 sentence narrative>\n\n"
            f"**Assessment**\n\n"
            f"<forensic analysis: what happened, why relevant, how evidence "
            f"supports the conclusion, relation to attack progression, "
            f"uncertainty>\n\n"
            f"**Confidence:** <tier>\n\n"
            f"Do NOT include Supporting Evidence, Trace, MITRE tables, or "
            f"raw events. Do NOT invent facts beyond the provided statements "
            f"and reasoning.\n\n"
            f"Conclusions:\n{json.dumps(conclusions, indent=2)}\n\n"
            f"Claims:\n{json.dumps(claims, indent=2)}\n"
        )
    elif sid == "exec_summary":
        user = (
            f"Write the Executive Summary for MANAGEMENT: a brief, plain-language "
            f"account of what happened, for readers who will not read the rest. "
            f"Take the room a clear account needs — a few short paragraphs, never "
            f"a forced summary: (1) what happened and "
            f"when, in one or two sentences; (2) what was affected and how badly "
            f"— systems by their role (the file server, the domain controller), "
            f"data, accounts, people; (3) what is still uncertain and the one or "
            f"two most important next steps. NO technical depth: no event ids, "
            f"log names, tool names, file paths, hashes, SIDs, IP addresses, "
            f"record numbers, extensions or F-id citations — all of that belongs "
            f"in Detailed Findings. State confidence in words (confirmed, likely, "
            f"unclear). Language: {lang}.\n\n"
            f"Conclusions:\n{json.dumps(conclusions, indent=2)}\n\n"
            f"Claims:\n{json.dumps(claims, indent=2)}\n\n"
            f"Conflicts:\n{json.dumps(context.get('conflicts'), indent=2)}\n"
        )
    elif sid == "gaps":
        user = (
            f"Write the Evidence Gaps and Open Questions section. Language: "
            f"{lang}.\n\n"
            f"CRITICAL: The Claims/Conclusions lists below ARE the registered "
            f"findings. NEVER write that there are no findings, no claims, no "
            f"timeline, or no identities if those lists are non-empty. Instead "
            f"synthesize real limitations from: (1) each claim's gaps[] field, "
            f"(2) UNCONFIRMED / evidence-gap statements, (3) missing artifact "
            f"categories named in the statements. Cite F-ids / claim ids. "
            f"Do not invent an empty investigation.\n\n"
            f"Style: {context.get('style')}\n\n"
            f"Conclusions:\n{json.dumps(conclusions, indent=2)}\n\n"
            f"Claims:\n{json.dumps(claims, indent=2)}\n\n"
            f"Conflicts:\n{json.dumps(context.get('conflicts'), indent=2)}\n"
        )
    else:
        user = (
            f"Section: {context.get('title')} ({sid})\n"
            f"Report scope: {context.get('report_scope')} "
            f"host={context.get('report_host') or '(n/a)'}\n"
            f"Language: {lang}\n\n"
            f"Style: {context.get('style')}\n\n"
            f"Conclusions:\n{json.dumps(conclusions, indent=2)}\n\n"
            f"Claims:\n{json.dumps(claims, indent=2)}\n\n"
            f"Conflicts:\n{json.dumps(context.get('conflicts'), indent=2)}\n\n"
            "Write narrative Markdown for this section only. No Supporting "
            "Evidence blocks and no invented raw events."
        )

    # Resolved through the registry so this path cannot drift onto a different
    # provider than the rest of the run.
    provider = providers.resolve(
        providers.role_name("ATLAS_REPORT_PROVIDER", "ATLAS_AGENT_PROVIDER"))
    if not provider.api_key:
        key_var = ("LLMHUB_API_KEY"
                   if provider.name == providers.DEFAULT_NAME
                   else providers.var(provider.name, "API_KEY"))
        raise RuntimeError(
            f"{key_var} not set — cannot AI-generate report section")
    if not provider.model:
        raise RuntimeError(
            f"no model configured for provider {provider.name!r}: set "
            f"{providers.var(provider.name, 'MODEL')}")

    def _ask(user_text: str) -> str:
        """One narrative section, over the same transport every other role uses."""
        from agent.llm import LLMHubClient
        client = LLMHubClient(
            base_url=getattr(provider, "base_url", ""),
            api_key=getattr(provider, "api_key", ""),
            model=getattr(provider, "model", ""),
            timeout=120, provider=getattr(provider, "name", ""))
        resp = client.chat(
            [{"role": "system", "content": system},
             {"role": "user", "content": user_text}],
            role=_REPORT_ROLE,
            # Prose about evidence: the lower the temperature, the less the
            # model embroiders. Dropped automatically for an endpoint that
            # refuses the field.
            temperature=0.2)
        text = resp.content.strip()
        if not text:
            # Empty after the ladder is a model that spent the budget
            # thinking. Raising hands the section to the caller's
            # deterministic fallback, which is a complete section.
            raise RuntimeError(resp.starved_reason())
        if resp.finish_reason == "length":
            raise RuntimeError(
                "section cut off at the completion limit; using the "
                "deterministic section instead of half a sentence")
        return text
    # The socket timeout above only bounds a silent connection; the same
    # watchdog that abandons a stalled reason call bounds the whole answer,
    # and records the abandon in the trace itself.
    import sys
    import time as _time
    from core.paths import REPORT_SECTION_TIMEOUT
    from core.timeout import with_tool_timeout

    label = f"report_section:{sid}"
    ask = with_tool_timeout(REPORT_SECTION_TIMEOUT, label=label)(_ask)

    def _call(user_text: str) -> str:
        _trace("record_call_initiated", label, provider.name,
               {"model": provider.model, "prompt_chars": len(user_text),
                "claims": len(claims), "conclusions": len(conclusions)})
        print(f"[Atlas] {label}: asking {provider.model} "
              f"({len(user_text)} chars, budget {REPORT_SECTION_TIMEOUT}s)",
              file=sys.stderr)
        t0 = _time.monotonic()
        try:
            out = ask(user_text)
        except Exception as e:  # noqa: BLE001 — traced, then handled by the caller
            _trace("record_call_abandoned", label,
                   f"{type(e).__name__}: {str(e)[:200]}")
            raise
        if isinstance(out, dict):
            raise TimeoutError(out.get("error") or f"{label} abandoned")
        elapsed = _time.monotonic() - t0
        _trace("record_tool_call", cmd=f"<py>:{label}", success=True,
               truncated=False, retries=0, exit_code=0,
               elapsed_seconds=round(elapsed, 1),
               stdout_excerpt=f"{len(out)} chars")
        print(f"[Atlas] {label}: {len(out)} chars in {elapsed:.0f}s",
              file=sys.stderr)
        return out

    prose = _call(user)
    if sid == "exec_summary":
        # A management summary that still quotes event ids or paths gets
        # one rewrite naming what to leave out; the second draft stands.
        tech = technical_depth(prose)
        if len(tech) > 2:
            prose = _call(user + "\n\nYour previous draft contained technical detail that must "
                         "not appear in a management summary: "
                         + ", ".join(sorted(set(tech))[:12])
                         + ". Rewrite it in plain language without any of these.")
    return prose


def regenerate_sections(
    case_dir: str | os.PathLike,
    *,
    section_ids: list[str] | None = None,
    generator: SectionGenerator | None = None,
    only_stale: bool = True,
    report_scope: str = "case",
    report_host: str = "",
) -> dict[str, Any]:
    """Regenerate section prose via AI (or injected/resilient generator)."""
    gen = generator or resilient_section_generator
    manifest = load_manifest(case_dir)
    raw_targets = section_ids or list(manifest.get("section_order") or [])
    targets = [resolve_section_id(s) for s in raw_targets]
    # Deduplicate while preserving order
    seen: set[str] = set()
    targets = [s for s in targets if not (s in seen or seen.add(s))]
    done: list[str] = []
    errors: list[dict] = []

    for sid in targets:
        sec = manifest["sections"].get(sid)
        if not sec:
            continue
        if only_stale and sec.get("status") == "current":
            continue
        ctx = section_context(
            case_dir, sid,
            report_scope=report_scope,
            report_host=report_host,
        )
        try:
            prose = gen(ctx, sec)
            if not prose.strip():
                raise RuntimeError("generator returned empty prose")
            body = _save_section_body(case_dir, sid, prose, context=ctx)
            sec["status"] = "current"
            sec["content_sha256"] = body["content_sha256"]
            sec["generated_at"] = body["generated_at"]
            sec["generator_version"] = GENERATOR_VERSION
            sec["report_scope"] = (report_scope or "case").lower()
            sec["report_host"] = report_host or ""
            sec["claim_ids"] = ctx["claim_ids"]
            sec["conclusion_ids"] = ctx["conclusion_ids"]
            sec["conflict_ids"] = ctx["conflict_ids"]
            sec["evidence_ids"] = ctx["evidence_ids"]
            sec["binding_fingerprint"] = _section_fingerprint(sec)
            done.append(sid)
        except Exception as e:
            errors.append({"section_id": sid, "error": str(e)[:300]})
            sec["status"] = "stale"

    save_manifest(case_dir, manifest)
    fallbacks = [
        {"section_id": sid, "error": manifest["sections"][sid].get("generator_error")}
        for sid in done
        if manifest["sections"][sid].get("generator") == "deterministic_fallback"
    ]
    return {
        "success": not errors or bool(done),
        "regenerated": done,
        "errors": errors,
        # Narrative sections the model did not write: the deterministic stub
        # stands in. Fix the provider and regenerate (force_regenerate_all).
        "fallbacks": fallbacks,
    }


def render_markdown(
    case_dir: str | os.PathLike,
    *,
    report_scope: str = "case",
    report_host: str = "",
) -> str:
    """Assemble the client deliverable Markdown.

    Always uses the deterministic client assembler (TOC, Key Findings table,
    per-finding Supporting Evidence, curated Attack Timeline). LLM section
    bodies contribute narrative fields only (exec summary, finding
    Summary/Assessment, gaps, recommendations).
    """
    from core.report_assemble import assemble_client_report

    return assemble_client_report(
        case_dir,
        report_scope=report_scope or "case",
        report_host=report_host or "",
    )


def default_report_output_path(
    case_dir: str | os.PathLike,
    *,
    scope: str = "case",
    host: str = "",
    fmt: str = "markdown",
) -> str:
    """Preferred deliverable path under ``reports/``.

    Modern names: ``estate_report.md``, ``host_<HOST>_report.md``.
    Case-level fallback: ``<CASE_ID>_report.md`` (compat).
    """
    from core.paths import detect_case_id

    reports = Path(case_dir) / "reports"
    ext = {"markdown": ".md", "md": ".md", "html": ".html", "json": ".json",
           "pdf": ".pdf"}.get(
        (fmt or "markdown").lower(), ".md",
    )
    scope_l = (scope or "case").lower()
    host_s = (host or "").strip()
    if scope_l == "estate":
        return str(reports / f"estate_report{ext}")
    if scope_l == "host" and host_s:
        safe = re.sub(r"[^\w.\-]+", "_", host_s)
        return str(reports / f"host_{safe}_report{ext}")
    case_id = detect_case_id(case_dir) or "case"
    if (fmt or "").lower() == "json":
        return str(reports / f"{case_id}_report_projection.json")
    return str(reports / f"{case_id}_report{ext}")


def assemble_report(
    case_dir: str | os.PathLike,
    *,
    output_path: str | None = None,
    fmt: str = "markdown",
    report_scope: str = "",
    report_host: str = "",
) -> dict[str, Any]:
    """Render projection to a deliverable file.

    Formats: ``markdown`` (default), ``html``, ``pdf``, ``json`` (manifest +
    section bodies). LaTeX is not offered.
    """
    fmt_n = (fmt or "markdown").lower().strip()
    if fmt_n in ("md", "markdown"):
        fmt_n = "markdown"
    elif fmt_n not in ("html", "json", "pdf"):
        return {
            "success": False,
            "error": (
                f"format {fmt!r} not implemented yet — "
                "supported: markdown, html, pdf, json"
            ),
        }

    from core.claim_graph import infer_report_scope
    from core.paths import detect_case_id, assert_output_safe

    case_id = detect_case_id(case_dir)
    reports = Path(case_dir) / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(case_dir)
    stale = [
        sid for sid, s in (manifest.get("sections") or {}).items()
        if s.get("status") == "stale"
    ]

    scope = (report_scope or "").strip().lower()
    host = (report_host or "").strip()
    if output_path and not scope:
        inferred = infer_report_scope(output_path, case_dir=case_dir)
        scope = inferred.get("scope") or "case"
        host = host or (inferred.get("host") or "")
    if not scope:
        scope = "case"

    if fmt_n == "json":
        sections_out: dict[str, Any] = {}
        for sid in (manifest.get("sections") or {}):
            body = _load_section_body(case_dir, sid)
            if body is not None:
                sections_out[sid] = body
        payload = {
            "schema": "atlas.report_projection.export",
            "case_id": case_id,
            "exported_at": _utcnow(),
            "manifest": manifest,
            "sections": sections_out,
        }
        text = json.dumps(payload, indent=2, default=str)
        if not output_path:
            output_path = default_report_output_path(
                case_dir, scope=scope, host=host, fmt="json",
            )
        assert_output_safe(output_path)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(text, encoding="utf-8")
        manifest["last_assembled_at"] = _utcnow()
        manifest["last_assembled_path"] = output_path
        manifest["last_assembled_format"] = fmt_n
        save_manifest(case_dir, manifest)
        return {
            "success": True,
            "output_path": output_path,
            "format": fmt_n,
            "bytes": len(text.encode("utf-8")),
            "stale_sections": stale,
        }

    # The next investigative steps rest on what is still open at report
    # time; they are recorded before the plan is rendered.
    try:
        from core.case_config import get_report_language
        from core.recommendations import derive_next_steps
        derive_next_steps(case_dir, get_report_language(case_dir))
    except Exception:  # noqa: BLE001 - the report is written whatever the plan does
        pass
    md_text = render_markdown(
        case_dir, report_scope=scope, report_host=host,
    )
    # The indicator files are a deliverable of their own; the report's
    # Indicators section (core.report_assemble) points at them.
    from core.ioc_catalog import write_indicator_files
    write_indicator_files(case_dir)
    if fmt_n == "markdown":
        if not output_path:
            output_path = default_report_output_path(
                case_dir, scope=scope, host=host, fmt="markdown",
            )
        assert_output_safe(output_path)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(md_text, encoding="utf-8")
        out_bytes = len(md_text.encode("utf-8"))
    elif fmt_n == "pdf":
        from core.report_pdf import render_pdf
        try:
            data = render_pdf(md_text, title=f"{case_id} report",
                              case_id=case_id)
        except RuntimeError as exc:
            # The renderer raises only for a missing package, and says how to
            # install it. A projection that already assembled must not lose
            # that message behind a traceback.
            return {"success": False, "error": str(exc)}
        if not output_path:
            output_path = default_report_output_path(
                case_dir, scope=scope, host=host, fmt="pdf",
            )
        assert_output_safe(output_path)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(data)
        out_bytes = len(data)
    else:  # html
        from agent.report import render_html
        html = render_html(md_text, title=f"{case_id} report")
        if not output_path:
            output_path = default_report_output_path(
                case_dir, scope=scope, host=host, fmt="html",
            )
        assert_output_safe(output_path)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(html, encoding="utf-8")
        out_bytes = len(html.encode("utf-8"))

    manifest = load_manifest(case_dir)
    manifest["last_assembled_at"] = _utcnow()
    manifest["last_assembled_path"] = output_path
    manifest["last_assembled_format"] = fmt_n
    save_manifest(case_dir, manifest)

    return {
        "success": True,
        "output_path": output_path,
        "format": fmt_n,
        "bytes": out_bytes,
        "stale_sections": [
            sid for sid, s in (manifest.get("sections") or {}).items()
            if s.get("status") == "stale"
        ],
    }


def sync_projection_after_plane_a(
    case_dir: str | os.PathLike,
    plane_a: dict[str, Any],
) -> dict[str, Any]:
    """Called from Plane A: rebind + mark stale. Does not call the LLM."""
    dirty = []
    for c in plane_a.get("affected_claims") or []:
        if c.get("id"):
            dirty.append(c["id"])
    for c in (plane_a.get("invalidation") or {}).get("marked") or []:
        dirty.append(c)
    result = mark_stale_sections(case_dir, dirty_node_ids=dirty)
    # First scan with empty graph: still create projection scaffold
    if plane_a.get("first_catalog_scan"):
        bind_claims_to_sections(case_dir)
        result = mark_stale_sections(case_dir, dirty_node_ids=dirty)
    return result
