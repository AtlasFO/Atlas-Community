"""Investigation journal + milestones.

Run history is more than an execution log: each rerun records *what* changed
and *why*. Milestones are a higher-level, non-gating chronology of how the
investigation evolved (first confirmed compromise, lateral movement, etc.).

Storage:
  ``<case>/.atlas/run_history/run-NNNN.json``  — per-rerun journal entries
  ``<case>/.atlas/milestones.json``           — cumulative milestones
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

# Why did something change? (investigation journal reason vocabulary)
JOURNAL_REASONS = frozenset({
    "bootstrap",
    "catalog_first_scan",
    "evidence_added",
    "evidence_modified",
    "evidence_removed",
    "evidence_touched",
    "parser_version_changed",
    "normalizer_version_changed",
    "claim_needs_review",
    "claim_updated",
    "claim_superseded",
    "claim_withdrawn",
    "conflict_created",
    "conflict_resolved",
    "contradiction_detected",
    "hypothesis_created",
    "hypothesis_promoted",
    "confidence_increased",
    "confidence_decreased",
    "conclusion_promoted",
    "report_section_regenerated",
    "report_full_regenerated",
    "milestone_recorded",
    "operator_note",
    "analyst_context_added",
    "analyst_context_withdrawn",
    "analyst_context_corrected",
})

# High-level milestones (advisory only — never gates investigation)
MILESTONE_KINDS = frozenset({
    "first_confirmed_compromise",
    "first_confirmed_lateral_movement",
    "persistence_confirmed",
    "persistence_disproved",
    "ransomware_execution_confirmed",
    "attribution_confidence_changed",
    "brute_force_confirmed",
    "investigation_completed",
    "custom",
})

_MILESTONE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("ransomware_execution_confirmed", re.compile(
        r"\bransomware\b|\bencrypt(?:ed|ion)\b|\bT1486\b", re.I),
     "CONFIRMED"),
    ("first_confirmed_lateral_movement", re.compile(
        r"\blateral\b|\bSMB\b.*\blogon\b|\bpass.?the.?hash\b|\bT1021\b", re.I),
     "CONFIRMED"),
    ("first_confirmed_compromise", re.compile(
        r"\bcompromis\b|\bmalware\b|\bbackdoor\b|\bbeacon\b|\bc2\b", re.I),
     "CONFIRMED"),
    ("persistence_confirmed", re.compile(
        r"\bpersistence\b|\bscheduled\s+task\b|\brun\s+key\b|\bT1547\b|\bT1053\b",
        re.I), "CONFIRMED"),
    ("persistence_disproved", re.compile(
        r"\bno\s+(?:evidence\s+of\s+)?persistence\b|\bpersistence\s+disproved\b",
        re.I), None),
    ("brute_force_confirmed", re.compile(
        r"\bbrute.?force\b|\bT1110\b|\bpassword\s+spray\b", re.I),
     "CONFIRMED"),
]


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_history_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "run_history"


def milestones_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "milestones.json"


def ensure_journal_dirs(case_dir: str | os.PathLike) -> None:
    run_history_dir(case_dir).mkdir(parents=True, exist_ok=True)
    mp = milestones_path(case_dir)
    if not mp.is_file():
        mp.write_text(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "updated_at": _utcnow(),
            "milestones": [],
        }, indent=2) + "\n", encoding="utf-8")


def next_run_id(case_dir: str | os.PathLike) -> str:
    d = run_history_dir(case_dir)
    d.mkdir(parents=True, exist_ok=True)
    existing = sorted(d.glob("run-*.json"))
    n = 1
    if existing:
        last = existing[-1].stem  # run-0003
        try:
            n = int(last.split("-")[1]) + 1
        except (IndexError, ValueError):
            n = len(existing) + 1
    return f"run-{n:04d}"


def journal_entry(
    *,
    reason: str,
    summary: str,
    details: dict[str, Any] | None = None,
    related_ids: list[str] | None = None,
) -> dict[str, Any]:
    if reason not in JOURNAL_REASONS:
        reason = "operator_note"
    return {
        "reason": reason,
        "summary": (summary or "")[:500],
        "details": details or {},
        "related_ids": related_ids or [],
        "ts": _utcnow(),
    }


def build_journal_from_plane_a(plane_a: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive journal entries (what + why) from a Plane A result."""
    entries: list[dict[str, Any]] = []
    boot = plane_a.get("bootstrap") or {}
    if boot.get("created"):
        entries.append(journal_entry(
            reason="bootstrap",
            summary="Lazy bootstrap created .atlas investigation state",
            details={"created": boot.get("created")},
        ))
    if plane_a.get("first_catalog_scan"):
        entries.append(journal_entry(
            reason="catalog_first_scan",
            summary="First evidence catalog scan — baseline fingerprints recorded",
            details={"counts": (plane_a.get("evidence_diff") or {}).get("counts")},
        ))

    diff = plane_a.get("evidence_diff") or {}
    for item in diff.get("added") or []:
        entries.append(journal_entry(
            reason="evidence_added",
            summary=f"New evidence introduced: {item.get('path')}",
            details=item,
            related_ids=[item["evidence_id"]] if item.get("evidence_id") else [],
        ))
    for item in diff.get("changed") or []:
        entries.append(journal_entry(
            reason="evidence_modified",
            summary=f"Evidence content changed: {item.get('path')}",
            details=item,
            related_ids=[x for x in [
                item.get("evidence_id"), item.get("previous_evidence_id")
            ] if x],
        ))
    for item in diff.get("removed") or []:
        entries.append(journal_entry(
            reason="evidence_removed",
            summary=f"Evidence removed from case tree: {item.get('path')}",
            details=item,
            related_ids=[item["evidence_id"]] if item.get("evidence_id") else [],
        ))
    for item in diff.get("touched") or []:
        entries.append(journal_entry(
            reason="evidence_touched",
            summary=(
                f"Evidence metadata changed (hash unchanged): {item.get('path')}"
            ),
            details=item,
        ))

    inv = plane_a.get("invalidation") or {}
    ctx_marked = set(inv.get("context_marked") or [])
    for nid in inv.get("marked") or []:
        if nid in ctx_marked:
            why = "analyst context changed interpretation"
        else:
            why = "dependent evidence added/changed/removed"
        entries.append(journal_entry(
            reason="claim_needs_review",
            summary=f"Claim/conclusion marked needs_review: {nid}",
            related_ids=[nid],
            details={"why": why},
        ))

    open_conflicts = plane_a.get("open_conflicts") or []
    if open_conflicts:
        entries.append(journal_entry(
            reason="contradiction_detected",
            summary=(
                f"{len(open_conflicts)} open conflict(s) present in claim graph"
            ),
            details={
                "ids": [c.get("id") for c in open_conflicts if c.get("id")],
            },
            related_ids=[c["id"] for c in open_conflicts if c.get("id")],
        ))

    if plane_a.get("rerun_brief_path"):
        entries.append(journal_entry(
            reason="operator_note",
            summary="Rerun Brief regenerated for investigator continuity",
            details={"path": plane_a.get("rerun_brief_path")},
        ))

    return entries


def detect_new_milestones(
    case_dir: str | os.PathLike,
    *,
    run_id: str,
) -> list[dict[str, Any]]:
    """Scan claim graph for high-level milestones not yet recorded.

    Advisory only — does not change claim statuses or gate the investigation.
    """
    from core.claim_graph import CURRENT_BELIEF_STATUSES, load_graph

    existing = load_milestones(case_dir)
    seen_kinds = {
        m.get("kind") for m in existing.get("milestones") or []
        if m.get("kind") != "custom"
    }
    # Allow attribution_confidence_changed multiple times; others once
    once_kinds = MILESTONE_KINDS - {"attribution_confidence_changed", "custom"}

    graph = load_graph(case_dir)
    new: list[dict[str, Any]] = []
    for node in (graph.get("nodes") or {}).values():
        if node.get("kind") not in ("claim", "conclusion"):
            continue
        if node.get("status") not in CURRENT_BELIEF_STATUSES:
            continue
        stmt = node.get("statement") or ""
        conf = (node.get("confidence") or "").upper()
        for kind, pattern, need_conf in _MILESTONE_PATTERNS:
            if kind in once_kinds and kind in seen_kinds:
                continue
            if need_conf and conf != need_conf:
                continue
            if not pattern.search(stmt):
                continue
            ms = {
                "id": f"ms_{kind}_{node.get('id', 'x')}",
                "kind": kind,
                "summary": stmt[:240],
                "confidence": conf,
                "related_node_id": node.get("id"),
                "run_id": run_id,
                "recorded_at": _utcnow(),
                "note": "Auto-detected from claim graph; advisory only",
            }
            new.append(ms)
            seen_kinds.add(kind)
            break  # one milestone kind per node
    return new


def load_milestones(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = milestones_path(case_dir)
    if not path.is_file():
        return {"schema_version": SCHEMA_VERSION, "milestones": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "milestones": []}


def append_milestones(
    case_dir: str | os.PathLike,
    milestones: list[dict[str, Any]],
) -> dict[str, Any]:
    ensure_journal_dirs(case_dir)
    data = load_milestones(case_dir)
    existing_ids = {m.get("id") for m in data.get("milestones") or []}
    added = []
    for m in milestones:
        if m.get("id") in existing_ids:
            continue
        data.setdefault("milestones", []).append(m)
        added.append(m)
        existing_ids.add(m.get("id"))
    data["updated_at"] = _utcnow()
    data["schema_version"] = SCHEMA_VERSION
    path = milestones_path(case_dir)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return {"added": added, "total": len(data.get("milestones") or [])}


def write_run_journal(
    case_dir: str | os.PathLike,
    *,
    plane_a: dict[str, Any],
    trigger: str = "cli",
    operator_note: str = "",
    extra_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Persist one investigation-journal run record + any new milestones."""
    ensure_journal_dirs(case_dir)
    run_id = next_run_id(case_dir)
    entries = build_journal_from_plane_a(plane_a)
    if operator_note:
        entries.append(journal_entry(
            reason="operator_note",
            summary=operator_note[:500],
        ))
    if extra_entries:
        entries.extend(extra_entries)

    new_ms = detect_new_milestones(case_dir, run_id=run_id)
    ms_result = append_milestones(case_dir, new_ms) if new_ms else {
        "added": [], "total": len(load_milestones(case_dir).get("milestones") or []),
    }
    for m in ms_result.get("added") or []:
        entries.append(journal_entry(
            reason="milestone_recorded",
            summary=f"Milestone: {m.get('kind')} — {m.get('summary')}",
            details={"milestone_id": m.get("id"), "kind": m.get("kind")},
            related_ids=[m["related_node_id"]] if m.get("related_node_id") else [],
        ))

    record = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": plane_a.get("started_at") or _utcnow(),
        "finished_at": _utcnow(),
        "trigger": trigger,
        "case_id": plane_a.get("case_id", ""),
        "mode": "no_agent" if plane_a.get("no_agent", True) else "agent",
        "evidence_diff": plane_a.get("evidence_diff"),
        "invalidation": plane_a.get("invalidation"),
        "affected_claims": plane_a.get("affected_claims"),
        "open_conflicts": plane_a.get("open_conflicts"),
        "affected_report_sections": plane_a.get("affected_report_sections") or [],
        "rerun_brief_path": plane_a.get("rerun_brief_path"),
        # What this pass handed the investigator, as the dashboard shows it.
        "work": plane_a.get("work"),
        "journal": entries,
        "milestones_recorded": [m.get("id") for m in (ms_result.get("added") or [])],
        "why_summary": _why_summary(entries),
    }
    path = run_history_dir(case_dir) / f"{run_id}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return {
        "success": True,
        "run_id": run_id,
        "path": str(path),
        "journal_entry_count": len(entries),
        "milestones_added": ms_result.get("added") or [],
        "why_summary": record["why_summary"],
    }


def _why_summary(entries: list[dict[str, Any]]) -> list[str]:
    """Short list of why-lines for CLI / brief."""
    lines = []
    for e in entries:
        if e.get("reason") in ("operator_note",) and "Rerun Brief" in (
            e.get("summary") or ""
        ):
            continue
        lines.append(f"{e.get('reason')}: {e.get('summary')}")
    return lines[:40]


def list_runs(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    d = run_history_dir(case_dir)
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.glob("run-*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({
            "run_id": data.get("run_id", p.stem),
            "finished_at": data.get("finished_at"),
            "journal_entry_count": len(data.get("journal") or []),
            "milestones_recorded": data.get("milestones_recorded") or [],
            "why_summary": data.get("why_summary") or [],
            "path": str(p),
        })
    return out


def load_run(case_dir: str | os.PathLike, run_id: str) -> Optional[dict[str, Any]]:
    path = run_history_dir(case_dir) / f"{run_id}.json"
    if not path.is_file():
        # allow run-1 vs run-0001
        matches = list(run_history_dir(case_dir).glob(f"{run_id}.json"))
        if not matches:
            return None
        path = matches[0]
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def diff_runs(
    case_dir: str | os.PathLike,
    run_a: str,
    run_b: str,
) -> dict[str, Any]:
    """Compare two journal runs — what/why changed between them."""
    a = load_run(case_dir, run_a)
    b = load_run(case_dir, run_b)
    if not a or not b:
        return {
            "success": False,
            "error": f"missing run(s): {run_a if not a else ''} {run_b if not b else ''}".strip(),
        }
    reasons_a = {e.get("reason") for e in (a.get("journal") or [])}
    reasons_b = {e.get("reason") for e in (b.get("journal") or [])}
    return {
        "success": True,
        "run_a": run_a,
        "run_b": run_b,
        "why_a": a.get("why_summary") or [],
        "why_b": b.get("why_summary") or [],
        "reasons_only_in_b": sorted(reasons_b - reasons_a),
        "reasons_only_in_a": sorted(reasons_a - reasons_b),
        "milestones_in_b": b.get("milestones_recorded") or [],
        "evidence_diff_b": (b.get("evidence_diff") or {}).get("counts"),
    }
