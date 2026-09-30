"""Current Investigation State — authoritative case knowledge.

Conceptual flow (investigation-driven reporting)::

    Evidence
        ↓
    AI Investigation
        ↓
    Current Investigation State   ← this module (authoritative)
        ↓
    AI Report Writer
        ↓
    Markdown Report               ← disposable projection (never SoT)

The Claim Graph is an important *part* of Current Investigation State, not
the investigation itself. Process audit remains ``analysis/*_trace.json``.

This module aggregates durable ``.atlas/`` artifacts into one snapshot for
report writers, explainers, and continuity tools — without restricting the
AI investigator.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atlas_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas"


def has_atlas_state(case_dir: str | os.PathLike) -> bool:
    return atlas_dir(case_dir).is_dir()


def _load_findings_summary(case_dir: Path) -> dict[str, Any]:
    """Lightweight findings.json summary (structured findings, not prose)."""
    for candidate in (
        case_dir / "analysis" / "findings.json",
        case_dir / "exports" / "findings.json",
    ):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        findings = data if isinstance(data, list) else data.get("findings") or []
        if not isinstance(findings, list):
            return {"path": str(candidate), "count": 0, "findings": []}
        compact = []
        for f in findings[:80]:
            if not isinstance(f, dict):
                continue
            compact.append({
                "id": f.get("id") or f.get("finding_id"),
                "title": (f.get("title") or f.get("summary") or "")[:160],
                "confidence": f.get("confidence"),
                "host": f.get("host"),
            })
        return {
            "path": str(candidate),
            "count": len(findings),
            "findings": compact,
        }
    return {"path": None, "count": 0, "findings": []}


def _projection_summary(case_dir: str | os.PathLike) -> dict[str, Any]:
    try:
        from core.report_projection import load_manifest
        manifest = load_manifest(case_dir)
    except Exception:
        return {"available": False}
    sections = manifest.get("sections") or {}
    by_status: dict[str, list[str]] = {
        "missing": [], "stale": [], "current": [],
    }
    for sid, sec in sections.items():
        st = sec.get("status") or "missing"
        by_status.setdefault(st, []).append(sid)
    return {
        "available": True,
        "last_assembled_at": manifest.get("last_assembled_at"),
        "last_assembled_path": manifest.get("last_assembled_path"),
        "last_deliverable_source": manifest.get("last_deliverable_source"),
        "counts": {k: len(v) for k, v in by_status.items()},
        "stale_sections": by_status.get("stale") or [],
        "missing_sections": by_status.get("missing") or [],
        "current_sections": by_status.get("current") or [],
    }


def _journal_summary(case_dir: str | os.PathLike) -> dict[str, Any]:
    try:
        from core.run_journal import list_runs, load_milestones
        runs = list_runs(case_dir)
        milestones = load_milestones(case_dir)
    except Exception:
        return {"runs": [], "milestones": []}
    last = runs[-1] if runs else None
    ms = milestones.get("milestones") if isinstance(milestones, dict) else []
    return {
        "run_count": len(runs),
        "last_run": last,
        "milestones": (ms or [])[:40],
    }


def build_current_investigation_state(
    case_dir: str | os.PathLike,
    *,
    compact: bool = True,
) -> dict[str, Any]:
    """Build the Current Investigation State snapshot for a case.

    Parameters
    ----------
    compact:
        When True, truncate long statement lists for LLM context budgets.
        When False, include fuller claim-graph node payloads.
    """
    from core.claim_graph import graph_snapshot_for_report, load_graph, list_nodes
    from core.paths import detect_case_id
    from core.rerun_brief import load_memory

    root = Path(case_dir).resolve()
    case_id = detect_case_id(root) or root.name
    graph = load_graph(root)
    claim_snap = graph_snapshot_for_report(root)
    memory = load_memory(root)
    needs_review = [
        {"id": n["id"], "kind": n.get("kind"),
         "statement": (n.get("statement") or "")[:200]}
        for n in (graph.get("nodes") or {}).values()
        if n.get("status") == "needs_review"
    ]
    if compact:
        for key in (
            "active_conclusions", "active_claims", "open_conflicts",
            "active_hypotheses", "superseded",
        ):
            nodes = claim_snap.get(key) or []
            claim_snap[key] = [
                {
                    "id": n.get("id"),
                    "kind": n.get("kind"),
                    "statement": (n.get("statement") or "")[:240],
                    "confidence": n.get("confidence"),
                    "status": n.get("status"),
                    "temporal_qualifier": n.get("temporal_qualifier"),
                }
                for n in nodes
            ]

    projection = _projection_summary(root)
    journal = _journal_summary(root)
    findings = _load_findings_summary(root)

    # Investigation tasks + plan (case-driven work queue)
    try:
        from core.investigation_tasks import load_tasks
        task_store = load_tasks(root)
        tasks = list(task_store.get("tasks") or [])
    except Exception:
        tasks = []
    try:
        from core.investigation_plan import load_plan
        inv_plan = load_plan(root)
    except Exception:
        inv_plan = {}

    task_counts: dict[str, int] = {}
    for t in tasks:
        st = t.get("status") or "unknown"
        task_counts[st] = task_counts.get(st, 0) + 1

    has_beliefs = bool(claim_snap.get("has_graph"))
    open_conflict_n = len(claim_snap.get("open_conflicts") or [])
    needs_n = len(needs_review)

    guidance = [
        "You are the investigator — explore freely; this snapshot grounds the report.",
        "The Markdown report is a projection of Current Investigation State, never source of truth.",
        "CASE.md is the investigator work inbox; investigation tasks live in "
        ".atlas/investigation_tasks.json — do not paste findings into CASE.md.",
        "Follow .atlas/investigation_plan.json as the pre-execution checklist.",
        "Required writer: misc.write_projected_final_report "
        "(RAW EVENT Supporting Evidence + curated Attack Timeline). "
        "misc.write_final_report is refused when beliefs exist. "
        "Custom analyst extracts (host/site splits, briefings) use "
        "misc.write_case_document — not batch_run/shell.",
        "Attach evidence refs on claims (record_ref / call_id / artifact+locator) "
        "so the Attack Timeline can be resolved — empty timeline blocks the report.",
    ]
    if open_conflict_n:
        guidance.append(
            f"Open Conflict Findings ({open_conflict_n}) must appear in the main report body."
        )
    if needs_n:
        guidance.append(
            f"{needs_n} node(s) are needs_review — re-validate (claim.revalidate, "
            "citing the calls that re-read the evidence) or supersede; what stays "
            "under review is reported as a limitation."
        )
    actionable_n = sum(
        task_counts.get(s, 0)
        for s in ("open", "in_progress", "partial", "reopened")
    )
    if actionable_n:
        guidance.append(
            f"{actionable_n} investigation task(s) still actionable — "
            "update status via misc.update_investigation_task as work completes."
        )
    if not has_beliefs:
        guidance.append(
            "No claim-graph beliefs yet — promote claims/conclusions with "
            "evidence references, then write via misc.write_projected_final_report."
        )

    return {
        "success": True,
        "schema_version": SCHEMA_VERSION,
        "label": "Current Investigation State",
        "case_id": case_id,
        "case_dir": str(root),
        "built_at": _utcnow(),
        "authoritative": True,
        "note": (
            "Authoritative knowledge representation for this investigation. "
            "Claim Graph ⊂ Current Investigation State. "
            "Investigation tasks = work queue (not beliefs). "
            "Execution trace = process audit. Report Markdown = projection only."
        ),
        "has_beliefs": has_beliefs,
        "claim_graph": claim_snap,
        "needs_review": needs_review,
        "investigation_tasks": {
            "tasks": [
                {
                    "id": t.get("id"),
                    "text": t.get("text"),
                    "status": t.get("status"),
                    "related_claim_ids": t.get("related_claim_ids") or [],
                    "updated_at": t.get("updated_at"),
                }
                for t in (tasks if not compact else tasks[:80])
            ],
            "counts": task_counts,
        },
        "investigation_plan": {
            "updated_at": inv_plan.get("updated_at"),
            "steps": (inv_plan.get("steps") or [])[:40],
            "actionable_task_ids": inv_plan.get("actionable_task_ids") or [],
            "blocked_task_ids": inv_plan.get("blocked_task_ids") or [],
            "focus_hosts": inv_plan.get("focus_hosts") or [],
            "revisit_claim_ids": inv_plan.get("revisit_claim_ids") or [],
        },
        "investigation_memory": {
            "validated_conclusions": memory.get("validated_conclusions") or [],
            "disproven_assumptions": memory.get("disproven_assumptions") or [],
            "unresolved_hypotheses": memory.get("unresolved_hypotheses") or [],
            "missing_evidence": memory.get("missing_evidence") or [],
            "open_investigation_goals": memory.get("open_investigation_goals") or [],
            "outstanding_questions": memory.get("outstanding_questions") or [],
            "updated_at": memory.get("updated_at"),
        },
        "journal": journal,
        "report_projection": projection,
        "findings_summary": findings,
        "counts": {
            "conclusions": len(claim_snap.get("active_conclusions") or []),
            "claims": len(claim_snap.get("active_claims") or []),
            "conflicts": open_conflict_n,
            "hypotheses": len(claim_snap.get("active_hypotheses") or []),
            "needs_review": needs_n,
            "findings": findings.get("count") or 0,
            "observation_nodes": len(list_nodes(graph, kind="observation")),
            "investigation_tasks_actionable": actionable_n,
        },
        "report_writer_guidance": guidance,
    }


def record_deliverable(
    case_dir: str | os.PathLike,
    output_path: str,
    *,
    source: str,
    content: str = "",
) -> dict[str, Any]:
    """Record that a client deliverable was written (projection metadata only).

    Does not treat Markdown as source of truth — only tracks path/hash/source
    on the report projection manifest for continuity.
    """
    from core.report_projection import load_manifest, save_manifest

    root = Path(case_dir).resolve()
    atlas_dir(root).mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(root)
    digest = (
        hashlib.sha256(content.encode("utf-8")).hexdigest()
        if content else None
    )
    manifest["last_assembled_at"] = _utcnow()
    manifest["last_assembled_path"] = str(output_path)
    manifest["last_assembled_format"] = "markdown"
    manifest["last_deliverable_source"] = source
    if digest:
        manifest["last_deliverable_sha256"] = digest
    save_manifest(root, manifest)
    return {
        "success": True,
        "output_path": str(output_path),
        "source": source,
        "content_sha256": digest,
    }


def project_report_from_state(
    case_dir: str | os.PathLike,
    *,
    regenerate_stale: bool = True,
    force_regenerate_all: bool = False,
    generator=None,
    output_path: str = "",
    report_scope: str = "",
    report_host: str = "",
) -> dict[str, Any]:
    """Build Markdown from Current Investigation State via report projection.

    Flow: state → bind sections → (optional AI/deterministic regen) → assemble.
    Does not write the gated final report file — caller passes text to
    ``write_final_report`` for gates + lint.

    ``output_path`` / ``report_scope`` / ``report_host`` select
    host vs estate projection filters.
    """
    from core.claim_graph import infer_report_scope
    from core.report_projection import (
        bind_claims_to_sections,
        mark_stale_sections,
        regenerate_sections,
        render_markdown,
    )

    state = build_current_investigation_state(case_dir, compact=True)
    if not state.get("has_beliefs"):
        return {
            "success": False,
            "error": (
                "Current Investigation State has no claim-graph beliefs yet. "
                "Promote claims/conclusions first, attach evidence references "
                "(record_ref / call_id / artifact+locator), then call "
                "misc.write_projected_final_report. Freeform "
                "misc.write_final_report is refused when beliefs exist and "
                "is not a substitute for a projected report."
            ),
            "investigation_state": state,
            "gate": "beliefs_required",
        }

    scope_info = infer_report_scope(output_path, case_dir=case_dir) if output_path else {
        "scope": report_scope or "case",
        "host": report_host or "",
    }
    scope = (report_scope or scope_info.get("scope") or "case").lower()
    host = (report_host or scope_info.get("host") or "").strip()

    bind_kwargs: dict[str, str] = {}
    if scope == "host":
        bind_kwargs["scope"] = "host"
        if host:
            bind_kwargs["host"] = host

    bind_claims_to_sections(case_dir, **bind_kwargs)
    mark_stale_sections(
        case_dir,
        force_all=force_regenerate_all,
        host=bind_kwargs.get("host", ""),
        scope=bind_kwargs.get("scope", ""),
        report_scope=scope,
        report_host=host,
    )

    regen: dict[str, Any] = {"skipped": True}
    if regenerate_stale or force_regenerate_all:
        try:
            regen = regenerate_sections(
                case_dir,
                generator=generator,
                only_stale=not force_regenerate_all,
                report_scope=scope,
                report_host=host,
            )
            regen["skipped"] = False
            regen["report_scope"] = scope
            regen["report_host"] = host
        except Exception as e:
            regen = {
                "skipped": False,
                "success": False,
                "errors": [{"section_id": "*", "error": str(e)[:300]}],
                "regenerated": [],
            }

    markdown = render_markdown(
        case_dir, report_scope=scope, report_host=host,
    )
    return {
        "success": True,
        "markdown": markdown,
        "regenerate": regen,
        "investigation_state_counts": state.get("counts"),
        "has_beliefs": True,
        "report_scope": scope,
        "report_host": host,
        "note": (
            "Markdown is a projection of Current Investigation State — "
            "not source of truth."
        ),
    }
