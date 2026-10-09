"""Incremental investigation engine — Plane A (deterministic).

Lazy bootstrap, evidence catalog scan/diff, dependency invalidation,
rerun brief, journal, and report-projection staleness.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.evidence_catalog import (
    catalog_path,
    diff_catalogs,
    load_catalog,
    atlas_dir,
    scan_evidence,
    update_catalog_from_scan,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_atlas_scaffold(case_dir: str | os.PathLike, *, case_id: str = "") -> dict[str, Any]:
    """Lazy bootstrap: create .atlas/ structures if missing. Never requires manual migration."""
    root = Path(case_dir).resolve()
    md = atlas_dir(root)
    md.mkdir(parents=True, exist_ok=True)
    created: list[str] = []

    # Claim graph
    from core.claim_graph import claim_graph_path, empty_graph, load_graph, save_graph
    cgp = claim_graph_path(root)
    if not cgp.is_file():
        save_graph(root, empty_graph(case_id or root.name))
        created.append("claim_graph.json")

    # Evidence catalog (empty until scan)
    if not catalog_path(root).is_file():
        from core.evidence_catalog import empty_catalog, save_catalog
        save_catalog(root, empty_catalog(case_id or root.name))
        created.append("evidence_catalog.json")

    # Investigation memory (lightweight; filled by rerun brief builders)
    mem_path = md / "investigation_memory.json"
    if not mem_path.is_file():
        mem_path.write_text(json.dumps({
            "schema_version": "1.0",
            "case_id": case_id or root.name,
            "updated_at": _utcnow(),
            "validated_conclusions": [],
            "disproven_assumptions": [],
            "unresolved_hypotheses": [],
            "missing_evidence": [],
            "open_investigation_goals": [],
            "outstanding_questions": [],
            "analyst_context": [],
        }, indent=2) + "\n", encoding="utf-8")
        created.append("investigation_memory.json")

    # Investigation tasks (CASE.md work queue materialization)
    from core.investigation_tasks import empty_tasks, tasks_path
    tp = tasks_path(root)
    if not tp.is_file():
        tp.write_text(
            json.dumps(empty_tasks(case_id or root.name), indent=2) + "\n",
            encoding="utf-8",
        )
        created.append("investigation_tasks.json")

    for name, stub in (
        ("dependency_index.json", {"schema_version": "1.0", "edges": [], "nodes": {}}),
        ("invalidation_queue.json", {
            "schema_version": "1.0",
            "updated_at": _utcnow(),
            "dirty_evidence": [],
            "stale_nodes": [],
            "note": (
                "Dirty set is the *starting point* for investigation, "
                "not a hard boundary."
            ),
        }),
        ("investigation_plan.json", {
            "schema_version": "1.0",
            "updated_at": _utcnow(),
            "steps": [],
            "actionable_task_ids": [],
            "blocked_task_ids": [],
            "revisit_claim_ids": [],
            "dirty_evidence_paths": [],
            "focus_hosts": [],
            "focus_evidence": [],
            "note": "Lightweight pre-execution investigation plan (Plane A).",
        }),
    ):
        p = md / name
        if not p.is_file():
            p.write_text(json.dumps(stub, indent=2) + "\n", encoding="utf-8")
            created.append(name)

    (md / "run_history").mkdir(exist_ok=True)
    from core.run_journal import ensure_journal_dirs
    ensure_journal_dirs(root)

    return {
        "atlas_dir": str(md),
        "created": created,
        "bootstrapped": bool(created),
    }


def resolve_case_id(case_dir: str | os.PathLike) -> str:
    try:
        from core.paths import detect_case_id
        return detect_case_id(case_dir)
    except Exception:
        return Path(case_dir).resolve().name


def _engagement_status(root) -> dict[str, Any]:
    try:
        from core.case_config import engagement_status
        return engagement_status(root)
    except Exception:  # noqa: BLE001 - the brief's field is advisory here
        return {"value": "incident-response", "stated": False, "raw": "", "unrecognized": False}


def plane_a_scan(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
    force_full_hash: bool = False,
    trigger: str = "cli",
    write_journal: bool = True,
    no_agent: bool = True,
    analyst_feedback: str | None = None,
    withdraw_context_id: str | None = None,
    correct_context_id: str | None = None,
    progress: Any = None,
) -> dict[str, Any]:
    """
    Plane A (6a–6d): bootstrap + fingerprint + diff + invalidate + brief + journal.

    Does not launch an AI agent. Dirty set is a starting point only.
    Optional analyst_feedback / withdraw / correct mutate investigation_memory
    (not evidence) and mark matching claims needs_review. ``progress`` hears
    the fingerprinting's progress (core.evidence_catalog.scan_evidence).
    """
    started_at = _utcnow()
    root = Path(case_dir).resolve()
    if not root.is_dir():
        return {"success": False, "error": f"case directory not found: {root}"}

    case_id = resolve_case_id(root)
    bootstrap = ensure_atlas_scaffold(root, case_id=case_id)
    previous = load_catalog(root)
    first_scan = not (previous.get("units"))

    current_units = scan_evidence(root, force_full_hash=force_full_hash, previous=previous,
                                  progress=progress)
    diff = diff_catalogs(previous, current_units)

    # Analyst context. The brief's "What you already know" bullets are its
    # source: a -q text is appended there first, an entry to withdraw or
    # correct loses its bullet, and the reconcile turns the section into
    # entries. Only the entries that changed in this pass re-open the
    # claims they name; the same brief seen again marks nothing.
    from core.analyst_context import find_matching_node_ids, list_context

    context_feedback: dict[str, Any] = {}
    knowledge: dict[str, Any] = {
        "added": [], "reactivated": [], "withdrawn": [], "matched": [],
    }
    new_entry: dict[str, Any] | None = None
    journal_hints: list[dict[str, Any]] = []
    feedback_text = (analyst_feedback or "").strip()
    if persist:
        from core import case_knowledge
        from core.analyst_context import (
            entry_by_id,
            link_supersedes,
            reconcile_case_knowledge,
            withdraw_context,
        )
        from core.investigation_tasks import fingerprint_text

        retired: dict[str, Any] | None = None
        try:
            if correct_context_id and not feedback_text:
                raise ValueError("--correct-context requires -q / --question "
                                 "with the replacement context text")
            retire_id = withdraw_context_id or correct_context_id
            if retire_id:
                retired = entry_by_id(root, retire_id)
                was_active = retired.get("status") == "active"
                if retired.get("origin") == case_knowledge.ORIGIN:
                    case_knowledge.remove_fact(root, retired.get("text") or "")
                retired = withdraw_context(root, retire_id)
                if not was_active:
                    retired = None
            if feedback_text:
                case_knowledge.append_facts(root, [feedback_text])
        except (ValueError, KeyError) as e:
            return {"success": False, "error": str(e)}
        knowledge = reconcile_case_knowledge(root, persist=True)
        if retired is not None and all(
                e.get("id") != retired.get("id") for e in knowledge["withdrawn"]):
            knowledge["withdrawn"].insert(0, retired)
        if feedback_text:
            fp = fingerprint_text(feedback_text)
            fresh = knowledge["added"] + knowledge["reactivated"]
            new_entry = next((e for e in fresh if e.get("fingerprint") == fp), None)
            if new_entry is None:  # the brief stated it already
                new_entry = next((e for e in list_context(root, active_only=True)
                                  if e.get("fingerprint") == fp), None)
            if new_entry is not None and correct_context_id:
                new_entry = link_supersedes(root, new_entry["id"], correct_context_id)
        for e in knowledge["added"] + knowledge["reactivated"]:
            journal_hints.append({
                "reason": "analyst_context_added",
                "summary": f"Analyst context added: {e['id']}",
                "related_ids": [e["id"]],
                "details": {"text": (e.get("text") or "")[:300],
                            "entities": e.get("entities")},
            })
        for e in knowledge["withdrawn"]:
            if correct_context_id and e.get("id") == correct_context_id and new_entry:
                journal_hints.append({
                    "reason": "analyst_context_corrected",
                    "summary": f"Analyst context corrected: {e['id']} → {new_entry['id']}",
                    "related_ids": [e["id"], new_entry["id"]],
                    "details": {"old_id": e["id"], "new_id": new_entry["id"],
                                "text": feedback_text[:300]},
                })
            else:
                journal_hints.append({
                    "reason": "analyst_context_withdrawn",
                    "summary": f"Analyst context withdrawn: {e['id']}",
                    "related_ids": [e["id"]],
                    "details": {"text": (e.get("text") or "")[:300]},
                })
    else:
        # A dry run previews: what the text would name, what the brief
        # would add. Nothing is written.
        if feedback_text or withdraw_context_id or correct_context_id:
            from core.analyst_context import apply_feedback
            try:
                context_feedback = apply_feedback(
                    root,
                    text=feedback_text or None,
                    withdraw_id=withdraw_context_id,
                    correct_id=correct_context_id,
                    dry_run=True,
                )
            except (ValueError, KeyError) as e:
                return {"success": False, "error": str(e)}
        from core.analyst_context import reconcile_case_knowledge
        knowledge = reconcile_case_knowledge(root, persist=False)

    changed_entries = (
        knowledge["added"] + knowledge["reactivated"] + knowledge["withdrawn"]
    )
    context_ids = list(context_feedback.get("matched_node_ids") or [])
    if changed_entries:
        for nid in find_matching_node_ids(
                root,
                entities=[x for e in changed_entries for x in (e.get("entities") or [])],
                texts=[e.get("text") or "" for e in changed_entries]):
            if nid not in context_ids:
                context_ids.append(nid)
    active_context = list_context(root, active_only=True)

    if persist:
        update_catalog_from_scan(
            root, current_units,
            case_id=case_id,
            bootstrap=bootstrap.get("bootstrapped") or first_scan,
        )
        # Keep evidence_profile in sync with the catalog. A stale profile
        # (refresh=False cache) falsely advertises absent classes and the
        # evidence-compat gate then blocks EVTX/disk tools after KAPE intake
        #. Refresh when the evidence tree changed
        # or on first catalog scan; cheap relative to a full agent turn.
        _diff_counts = (diff.get("counts") or {})
        _evidence_changed = bool(
            first_scan
            or _diff_counts.get("added")
            or _diff_counts.get("changed")
            or _diff_counts.get("removed")
        )
        if _evidence_changed:
            try:
                from core.evidence_profile import ensure_evidence_profile
                ensure_evidence_profile(root, refresh=True)
            except Exception:
                pass
            # Force a fresh agent inventory pass when the tree drifted —
            # stale latch would let parsers run against outdated layout.
            try:
                from core.evidence_inventory_gate import clear_inventory_stamp
                clear_inventory_stamp(root)
            except Exception:
                pass
        # 6b: rebuild deps + mark needs_review for dirty evidence dependents
        from core.dependency_index import (
            mark_needs_review,
            nodes_for_dirty_evidence,
            rebuild_from_claim_graph,
        )
        catalog_now = load_catalog(root)
        dep_index = rebuild_from_claim_graph(root, catalog=catalog_now)
        dirty_ids = (
            [x["evidence_id"] for x in diff["added"] if x.get("evidence_id")]
            + [x.get("previous_evidence_id") or x.get("evidence_id")
               for x in diff["changed"]]
            + [x["evidence_id"] for x in diff["removed"] if x.get("evidence_id")]
        )
        dirty_paths = (
            [x["path"] for x in diff["added"]]
            + [x["path"] for x in diff["changed"]]
            + [x["path"] for x in diff["removed"]]
        )
        # First catalog scan: do not mass-invalidate existing beliefs
        stale: list[str] = []
        mark_result: dict[str, Any] = {"marked": [], "skipped": []}
        if not first_scan and (dirty_ids or dirty_paths):
            stale = nodes_for_dirty_evidence(
                dep_index,
                dirty_evidence_ids=[x for x in dirty_ids if x],
                dirty_paths=dirty_paths,
            )
            if stale:
                from core.dependency_index import dirty_hits
                items = ([("added", x["path"], x.get("evidence_id")) for x in diff["added"]]
                         + [("changed", x["path"], x.get("previous_evidence_id") or x.get("evidence_id"))
                            for x in diff["changed"]]
                         + [("removed", x["path"], x.get("evidence_id")) for x in diff["removed"]])
                mark_result = mark_needs_review(
                    root, stale,
                    reason="upstream evidence added/changed/removed",
                    dirty={"added": [x["path"] for x in diff["added"]],
                           "changed": [x["path"] for x in diff["changed"]],
                           "removed": [x["path"] for x in diff["removed"]]},
                    hits=dirty_hits(dep_index, items),
                )

        # Analyst-context affected claims (union with evidence dirty set)
        ctx_ids = list(context_ids)
        ctx_mark: dict[str, Any] = {"marked": [], "skipped": []}
        if ctx_ids:
            ctx_mark = mark_needs_review(
                root, ctx_ids,
                reason="analyst context changed interpretation",
            )
            # Merge mark results
            marked = list(dict.fromkeys(
                (mark_result.get("marked") or []) + (ctx_mark.get("marked") or [])
            ))
            skipped = list(dict.fromkeys(
                (mark_result.get("skipped") or []) + (ctx_mark.get("skipped") or [])
            ))
            mark_result = {"marked": marked, "skipped": skipped,
                           "evidence_marked": mark_result.get("marked") or [],
                           "context_marked": ctx_mark.get("marked") or []}

        # CASE.md → investigation tasks (deterministic exact-match reconcile)
        from core.investigation_tasks import (
            reconcile_case_md,
            reopen_tasks_for_claims,
        )
        task_reconcile = reconcile_case_md(
            root, persist=True, case_id=case_id,
        )
        # Linked answered tasks → reopened when their claims need_review
        stale_for_tasks = list(mark_result.get("marked") or stale or [])
        reopen_result = reopen_tasks_for_claims(root, stale_for_tasks)
        task_reconcile["reopened_via_claims"] = reopen_result.get("reopened") or []

        # CASE.md Evidence Links → .atlas/evidence_links.json (host/path map)
        try:
            from core.evidence_links import sync_evidence_links
            elinks = sync_evidence_links(root, persist=True)
            task_reconcile["evidence_links"] = {
                "entries": len(elinks.get("entries") or []),
                "hosts": list(elinks.get("hosts") or []),
                "paths": list(elinks.get("paths") or [])[:20],
                "aliases": dict(elinks.get("aliases") or {}),
            }
        except Exception as e:
            task_reconcile["evidence_links_error"] = str(e)[:200]

        # Mount plan (safe E01 auto-mount); skip auto-mount in dry contexts
        try:
            from core.mount_plan import build_mount_plan
            # Auto-mount only when evidence tree changed or first scan —
            # avoid remount storms on every Plane A.
            do_auto = bool(_evidence_changed)
            mount_plan = build_mount_plan(
                root, persist=True, auto_mount=do_auto,
            )
            task_reconcile["mount_plan"] = {
                "images": len(mount_plan.get("images") or []),
                "auto_mounted": mount_plan.get("auto_mounted") or [],
                "errors": mount_plan.get("errors") or [],
                "soft_notes": mount_plan.get("soft_notes") or [],
                "auto_mount_policy": mount_plan.get("auto_mount_policy") or "",
            }
        except Exception as e:
            task_reconcile["mount_plan_error"] = str(e)[:200]

        # The system baseline: every Windows installation under a live
        # mount or a collected tree states its own facts once, as
        # observations, before the analyst's first turn. Installations
        # already profiled are skipped, so this costs nothing on a re-scan.
        try:
            from core.baseline import run_baseline
            baseline = run_baseline(root)
            if baseline.get("taken") or baseline.get("errors"):
                task_reconcile["baseline"] = {
                    "taken": [t.get("installation") for t in baseline.get("taken") or []],
                    "errors": baseline.get("errors") or [],
                }
        except Exception as e:  # noqa: BLE001 - a baseline must not stop Plane A
            task_reconcile["baseline_error"] = str(e)[:200]

        # Derived revisit tasks (after needs_review is known)
        try:
            from core.derived_revisit import derive_revisit_tasks
            # Build a minimal plane-shaped dict for derive
            derive_input = {
                "affected_claims": [
                    {"id": nid, "statement": "", "status": "needs_review"}
                    for nid in (mark_result.get("marked") or [])
                ],
            }
            # Enrich statements from graph when possible
            try:
                from core.claim_graph import load_graph
                gnodes = (load_graph(root).get("nodes") or {})
                for c in derive_input["affected_claims"]:
                    n = gnodes.get(c["id"]) or {}
                    c["statement"] = (n.get("statement") or "")[:160]
                    c["host"] = n.get("host") or ""
            except Exception:
                pass
            derived = derive_revisit_tasks(root, derive_input, persist=True)
            task_reconcile["derived_revisit"] = derived
        except Exception as e:
            task_reconcile["derived_revisit_error"] = str(e)[:200]

        qpath = atlas_dir(root) / "invalidation_queue.json"
        qpath.write_text(json.dumps({
            "schema_version": "1.0",
            "updated_at": _utcnow(),
            "dirty_evidence": [x for x in dirty_ids if x],
            "dirty_paths": dirty_paths,
            "stale_nodes": mark_result.get("marked") or stale,
            "context_matched_nodes": ctx_ids,
            "affected_report_sections": [],  # filled in 6e
            "note": (
                "Dirty set is the starting point of investigation, "
                "not a hard boundary. The AI may examine additional evidence."
            ),
            "diff_counts": diff["counts"],
        }, indent=2) + "\n", encoding="utf-8")
    else:
        mark_result = {"marked": [], "skipped": []}
        ctx_ids = list(context_ids)
        from core.investigation_tasks import reconcile_case_md
        task_reconcile = reconcile_case_md(
            root, persist=False, case_id=case_id,
        )
        try:
            from core.evidence_links import sync_evidence_links
            elinks = sync_evidence_links(root, persist=False)
            task_reconcile["evidence_links"] = {
                "entries": len(elinks.get("entries") or []),
                "hosts": list(elinks.get("hosts") or []),
                "paths": list(elinks.get("paths") or [])[:20],
                "aliases": dict(elinks.get("aliases") or {}),
            }
        except Exception as e:
            task_reconcile["evidence_links_error"] = str(e)[:200]

    # Claim / report placeholders for --no-agent report (6e enriches sections)
    from core.claim_graph import load_graph, list_nodes, CURRENT_BELIEF_STATUSES
    graph = load_graph(root)
    needs_review = [
        n for n in graph.get("nodes", {}).values()
        if n.get("status") == "needs_review"
    ]
    open_conflicts = [
        n for n in list_nodes(graph, kind="conflict")
        if n.get("status") == "conflict"
    ]

    ctx_affected = []
    ctx_id_set = set(ctx_ids)
    for n in graph.get("nodes", {}).values():
        if n.get("id") in ctx_id_set:
            ctx_affected.append({
                "id": n.get("id"),
                "kind": n.get("kind"),
                "status": n.get("status"),
                "statement": (n.get("statement") or "")[:160],
            })

    result = {
        "success": True,
        "case_dir": str(root),
        "case_id": case_id,
        "bootstrap": bootstrap,
        "first_catalog_scan": first_scan,
        "started_at": started_at,
        "no_agent": no_agent,
        "engagement": _engagement_status(root),
        "evidence_diff": {
            "added": diff["added"],
            "changed": diff["changed"],
            "removed": diff["removed"],
            "touched": diff["touched"],
            "counts": diff["counts"],
        },
        "affected_claims": [
            {"id": n.get("id"), "status": n.get("status"),
             "statement": (n.get("statement") or "")[:160],
             "reason": n.get("invalidation_reason", "")}
            for n in needs_review
        ],
        "invalidation": mark_result if persist else {"marked": [], "skipped": []},
        "open_conflicts": [
            {"id": n.get("id"), "statement": (n.get("statement") or "")[:160]}
            for n in open_conflicts
        ],
        "affected_report_sections": [],
        "current_belief_counts": {
            "claims": sum(
                1 for n in list_nodes(graph, kind="claim")
                if n.get("status") in CURRENT_BELIEF_STATUSES
            ),
            "conclusions": sum(
                1 for n in list_nodes(graph, kind="conclusion")
                if n.get("status") in CURRENT_BELIEF_STATUSES
            ),
        },
        "analyst_context_feedback": context_feedback or None,
        "new_analyst_context": new_entry,
        "active_analyst_context": active_context,
        "context_reconcile": knowledge,
        "context_affected_claims": ctx_affected,
        "task_reconcile": task_reconcile,
        "note": (
            "Plane A complete (--no-agent). Dirty evidence / analyst context "
            "is a starting point only (not a hard boundary). See "
            ".atlas/rerun_brief.md, .atlas/run_history/, and "
            ".atlas/report_projection/."
        ),
    }
    # Disk and memory images are counted by the calls that read them, as the
    # live run counts each call; ledger statuses that disagree with the
    # trace are recounted from it before the work list reads them.
    if persist:
        try:
            from core.coverage_ledger import rederive_container_coverage
            rederived = rederive_container_coverage(root)
        except Exception as e:  # noqa: BLE001 - the work list stands without it
            rederived = {}
            result["coverage_rederive_error"] = str(e)[:200]
        if rederived:
            result["coverage_rederived"] = rederived
            recounted = sorted({p for v in rederived.values() for p in v})
            journal_hints.append({
                "reason": "coverage_rederived",
                "summary": (f"Coverage recounted from the trace: "
                            f"{_count(len(recounted), 'image')} moved"),
                "related_ids": [],
                "details": rederived,
            })
    # The task store as it stands after the reconcile, the reopens and the
    # derived follow-ups above; a dry run only has the reconcile's own list.
    if persist:
        from core.investigation_tasks import load_tasks
        tasks_now = list(load_tasks(root).get("tasks") or [])
    else:
        tasks_now = list(task_reconcile.get("tasks") or [])
    result["work"] = summarize_work(
        result,
        open_tasks=[t for t in tasks_now if t.get("status") in _OPEN_TASK_STATUSES],
    )

    # Investigation Planning (orchestration only — before brief)
    if persist and result.get("success"):
        try:
            from core.investigation_plan import build_investigation_plan
            plan = build_investigation_plan(root, result, persist=True)
            result["investigation_plan"] = {
                "path": str(root / ".atlas" / "investigation_plan.json"),
                "steps": plan.get("steps") or [],
                "actionable_task_ids": plan.get("actionable_task_ids") or [],
                "blocked_task_ids": plan.get("blocked_task_ids") or [],
                "focus_hosts": plan.get("focus_hosts") or [],
            }
        except Exception as e:
            result["investigation_plan_error"] = str(e)[:200]
    elif not persist:
        try:
            from core.investigation_plan import build_investigation_plan
            plan = build_investigation_plan(root, result, persist=False)
            result["investigation_plan"] = {
                "steps": plan.get("steps") or [],
                "actionable_task_ids": plan.get("actionable_task_ids") or [],
                "dry_run": True,
            }
        except Exception as e:
            result["investigation_plan_error"] = str(e)[:200]

    # 6c: Rerun Brief
    if persist and result.get("success"):
        try:
            from core.rerun_brief import build_rerun_brief
            brief = build_rerun_brief(root, result)
            result["rerun_brief_path"] = brief.get("path")
            result["rerun_brief_text"] = brief.get("text")
        except Exception as e:
            result["rerun_brief_error"] = str(e)[:200]

    # 6e: Report projection — rebind + mark stale (no LLM in --no-agent)
    if persist and result.get("success"):
        try:
            from core.report_projection import sync_projection_after_plane_a
            proj = sync_projection_after_plane_a(root, result)
            result["affected_report_sections"] = proj.get("stale_sections") or []
            result["report_projection"] = proj
        except Exception as e:
            result["report_projection_error"] = str(e)[:200]

    # 6d: Investigation journal + milestones (after projection so sections appear)
    if persist and write_journal and result.get("success"):
        try:
            from core.run_journal import journal_entry, write_run_journal
            extra = []
            for hint in journal_hints:
                extra.append(journal_entry(
                    reason=hint.get("reason") or "operator_note",
                    summary=hint.get("summary") or "",
                    details=hint.get("details"),
                    related_ids=hint.get("related_ids"),
                ))
            journal = write_run_journal(
                root, plane_a=result, trigger=trigger,
                extra_entries=extra or None,
            )
            result["run_id"] = journal.get("run_id")
            result["journal_path"] = journal.get("path")
            result["why_summary"] = journal.get("why_summary") or []
            result["milestones_added"] = journal.get("milestones_added") or []
            # Back-fill created_run_id on the entries this pass created.
            fresh_ids = {e.get("id") for e in knowledge["added"] if e.get("id")}
            if fresh_ids and journal.get("run_id"):
                from core.analyst_context import save_context_entries
                entries = list_context(root)
                for e in entries:
                    if e.get("id") in fresh_ids and not e.get("created_run_id"):
                        e["created_run_id"] = journal["run_id"]
                save_context_entries(root, entries)
        except Exception as e:
            result["journal_error"] = str(e)[:200]

    return result


# Task statuses that leave a question for the investigator to work on.
_OPEN_TASK_STATUSES = frozenset({"open", "in_progress", "partial", "reopened"})


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def summarize_work(result: dict[str, Any], *, open_tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """What this pass hands the investigator: the evidence delta, findings
    under review, open conflicts, the questions still open (the analyst's,
    and the follow-ups Atlas derived) and the context that changed.
    ``pending`` is the one bit a rerun reads to decide whether to start the
    investigator at all; ``reasons`` is what the CLI, the brief and the
    dashboard show for it.

    A finding stays under review until the investigator supersedes or
    repairs it, so it counts as work on every pass until then.
    """
    from core.investigation_tasks import DERIVED_PREFIX

    counts = (result.get("evidence_diff") or {}).get("counts") or {}
    evidence = {k: int(counts.get(k) or 0) for k in ("added", "changed", "removed")}
    review = [c.get("id") for c in (result.get("affected_claims") or []) if c.get("id")]
    conflicts = [c.get("id") for c in (result.get("open_conflicts") or []) if c.get("id")]
    reconcile = result.get("task_reconcile") or {}
    new_questions = [str(t) for t in (reconcile.get("added") or [])]
    reopened = [str(t) for t in (reconcile.get("reopened_via_claims") or [])]
    open_questions: list[str] = []
    followups: list[str] = []
    for t in open_tasks or []:
        tid = str(t.get("id") or "")
        if not tid:
            continue
        derived = str(t.get("text") or "").lstrip().lower().startswith(DERIVED_PREFIX)
        (followups if derived else open_questions).append(tid)
    context = result.get("context_reconcile") or {}
    context_added = [e.get("id") for e in
                     (context.get("added") or []) + (context.get("reactivated") or [])
                     if e.get("id")]
    context_gone = [e.get("id") for e in (context.get("withdrawn") or []) if e.get("id")]
    first = bool(result.get("first_catalog_scan"))

    reasons: list[str] = []
    if first:
        if evidence["added"]:
            reasons.append(f"first look at {_count(evidence['added'], 'evidence file')}")
    else:
        for key in ("added", "changed", "removed"):
            if evidence[key]:
                reasons.append(f"{_count(evidence[key], 'evidence file')} {key}")
    if review:
        reasons.append(f"{_count(len(review), 'finding')} to re-validate")
    if conflicts:
        reasons.append(_count(len(conflicts), "open conflict"))
    if open_questions:
        detail = [f"{len(new_questions)} new"] if new_questions else []
        if reopened:
            detail.append(f"{len(reopened)} reopened")
        reasons.append(_count(len(open_questions), "open question")
                       + (f" ({', '.join(detail)})" if detail else ""))
    if followups:
        reasons.append(f"{_count(len(followups), 'follow-up')} Atlas raised")
    if context_added:
        reasons.append(f"{_count(len(context_added), 'new fact')} in the brief")
    if context_gone:
        reasons.append(f"{_count(len(context_gone), 'fact')} withdrawn from the brief")
    # Delivered evidence no call has read keeps a rerun pending; a blocked
    # item, or one handed over under a handling stop, is dispositioned.
    try:
        from core.evidence_items import unseen as _unseen_items
        not_read = _unseen_items(result.get("case_dir"), limit=1_000_000)
    except Exception:  # noqa: BLE001
        not_read = []
    if not_read:
        rederived = result.get("coverage_rederived") or {}
        recounted = set(rederived.get("demoted") or []) | set(rederived.get("unblocked") or [])
        reasons.append(f"{_count(len(not_read), 'delivered item')} not yet examined"
                       + (f" ({len(recounted)} recounted from the trace: no call had "
                          "read them)" if recounted else ""))
    pending = bool(any(evidence.values()) or review or conflicts or open_questions
                   or followups or context_added or context_gone or not_read)
    return {
        "pending": pending,
        "first_scan": first,
        "evidence": evidence,
        "claims_to_review": review,
        "open_conflicts": conflicts,
        "questions": {"open": open_questions, "new": new_questions,
                      "reopened": reopened, "followups": followups},
        "context": {"added": context_added, "withdrawn": context_gone},
        "unexamined_items": not_read[:40],
        "reasons": reasons,
    }


def format_plane_a_report(result: dict[str, Any]) -> str:
    """Human-readable summary for CLI."""
    if not result.get("success"):
        return f"atlas rerun failed: {result.get('error')}"
    lines = [
        f"Case: {result.get('case_id')} ({result.get('case_dir')})",
        "",
    ]
    boot = result.get("bootstrap") or {}
    if boot.get("created"):
        lines.append("Bootstrap created: " + ", ".join(boot["created"]))
        lines.append("")
    diff = result.get("evidence_diff") or {}
    counts = diff.get("counts") or {}
    lines.append("Evidence diff:")
    lines.append(f"  added:     {counts.get('added', 0)}")
    lines.append(f"  changed:   {counts.get('changed', 0)}")
    lines.append(f"  removed:   {counts.get('removed', 0)}")
    lines.append(f"  touched:   {counts.get('touched', 0)} (hash unchanged)")
    lines.append(f"  unchanged: {counts.get('unchanged', 0)}")
    lines.append("")

    def _list(title: str, items: list, key: str = "path") -> None:
        lines.append(f"{title}:")
        if not items:
            lines.append("  (none)")
        else:
            for it in items[:50]:
                lines.append(f"  - {it.get(key) or it.get('id') or it}")
            if len(items) > 50:
                lines.append(f"  … {len(items) - 50} more")
        lines.append("")

    _list("New evidence", diff.get("added") or [])
    _list("Modified evidence", diff.get("changed") or [])
    _list("Removed evidence", diff.get("removed") or [])
    _list("Claims requiring review", result.get("affected_claims") or [], key="id")
    _list("Open conflicts", result.get("open_conflicts") or [], key="id")
    tr = result.get("task_reconcile") or {}
    if tr:
        lines.append("Investigation tasks:")
        lines.append(f"  parsed:    {tr.get('requests_parsed', 0)}")
        lines.append(f"  added:     {len(tr.get('added') or [])}")
        lines.append(f"  matched:   {len(tr.get('matched') or [])}")
        lines.append(
            f"  dropped:   {len(tr.get('dropped') or tr.get('withdrawn') or [])}"
        )
        reopened = tr.get("reopened_via_claims") or []
        if reopened:
            lines.append(f"  reopened:  {', '.join(reopened)}")
        lines.append("")
    plan = result.get("investigation_plan") or {}
    steps = plan.get("steps") or []
    if steps:
        lines.append("Investigation plan:")
        for s in steps[:20]:
            lines.append(f"  - {s.get('id')}: {s.get('summary')}")
        if len(steps) > 20:
            lines.append(f"  … {len(steps) - 20} more")
        lines.append("")
    reconcile = result.get("context_reconcile") or {}
    fresh = list(reconcile.get("added") or []) + list(reconcile.get("reactivated") or [])
    if fresh:
        lines.append("New analyst context (from the brief):")
        for e in fresh:
            lines.append(f"  - {e.get('id')}: {e.get('text')}")
            ents = e.get("entities") or []
            if ents:
                lines.append(f"    entities: {', '.join(ents)}")
        lines.append("")
    gone = reconcile.get("withdrawn") or []
    if gone:
        lines.append("Analyst context withdrawn:")
        for e in gone:
            lines.append(f"  - {e.get('id')}: {e.get('text')}")
        lines.append("")
    _list(
        "Claims affected by analyst context",
        result.get("context_affected_claims") or [],
        key="id",
    )
    _list(
        "Affected report sections",
        [{"id": s} for s in (result.get("affected_report_sections") or [])],
        key="id",
    )
    rederived = result.get("coverage_rederived") or {}
    if rederived:
        lines.append("Coverage recounted from the trace:")
        for key, label in (("demoted", "counted as read, but no call read it"),
                           ("unblocked", "blocked, but no read of it failed"),
                           ("credited", "read, but counted as not examined")):
            paths = rederived.get(key) or []
            if paths:
                lines.append(f"  {label}: {len(paths)}")
                lines.extend(f"    - {p}" for p in paths[:10])
                if len(paths) > 10:
                    lines.append(f"    … {len(paths) - 10} more")
        lines.append("")
    work = result.get("work") or {}
    if work.get("pending"):
        lines.append("Work for the investigator:")
        for reason in work.get("reasons") or []:
            lines.append(f"  - {reason}")
    else:
        lines.append("Nothing new for the investigator since the previous run.")
    lines.append("")
    if result.get("run_id"):
        lines.append(f"Journal run: {result['run_id']}")
        if result.get("journal_path"):
            lines.append(f"  path: {result['journal_path']}")
    why = result.get("why_summary") or []
    if why:
        lines.append("")
        lines.append("Why (investigation journal):")
        for w in why[:20]:
            lines.append(f"  - {w}")
        if len(why) > 20:
            lines.append(f"  … {len(why) - 20} more")
    ms = result.get("milestones_added") or []
    if ms:
        lines.append("")
        lines.append("Milestones recorded:")
        for m in ms:
            lines.append(f"  - {m.get('kind')}: {m.get('summary', '')[:100]}")
    if result.get("rerun_brief_path"):
        lines.append(f"Rerun brief: {result['rerun_brief_path']}")
    if result.get("note"):
        lines.append(result["note"])
    return "\n".join(lines)
