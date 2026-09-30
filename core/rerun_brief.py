"""Rerun Brief + investigation memory.

The brief is the AI investigator's starting context. The dirty set is a
*starting point*, not a hard boundary — the brief says so explicitly.

Large evidence diffs are summarized (counts + folder buckets + samples)
so Plane B prompts stay within model context. The full catalog remains
authoritative; the brief is orientation, not an exhaustive file dump.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# List every path when the diff section is small enough for the LLM.
_EVIDENCE_LIST_FULL_MAX = 80
# When summarizing: path-prefix depth for folder buckets.
_EVIDENCE_BUCKET_DEPTH = 4
# Samples shown under each bucket in summary mode.
_EVIDENCE_BUCKET_SAMPLES = 3
# Cap how many buckets / sample lines appear in the brief.
_EVIDENCE_MAX_BUCKETS = 40
_EVIDENCE_MAX_SAMPLE_LINES = 120


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path_str(entry: dict[str, Any] | str) -> str:
    if isinstance(entry, str):
        return entry
    return str(entry.get("path") or "")


def _evidence_id_str(entry: dict[str, Any] | str) -> str:
    if isinstance(entry, str):
        return ""
    return str(entry.get("evidence_id") or "")


def _is_zone_identifier(path: str) -> bool:
    return ":Zone.Identifier" in path.replace("\\", "/")


def _bucket_key(path: str, depth: int = _EVIDENCE_BUCKET_DEPTH) -> str:
    """Folder prefix used to group large evidence diffs in the brief."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts:
        return "(unknown)"
    if len(parts) == 1:
        return parts[0]
    # Keep parent folders up to *depth*; file name is never a bucket alone.
    folder = parts[:-1]
    if len(folder) <= depth:
        return "/".join(folder)
    return "/".join(folder[:depth])


def format_evidence_diff_lines(
    entries: list[dict[str, Any] | str],
    *,
    full_max: int = _EVIDENCE_LIST_FULL_MAX,
    bucket_depth: int = _EVIDENCE_BUCKET_DEPTH,
    samples_per_bucket: int = _EVIDENCE_BUCKET_SAMPLES,
    max_buckets: int = _EVIDENCE_MAX_BUCKETS,
    max_sample_lines: int = _EVIDENCE_MAX_SAMPLE_LINES,
) -> list[str]:
    """Format added/changed/removed evidence for the Rerun Brief.

    Small sets: one bullet per path (legacy behaviour).
    Large sets: total count, per-folder bucket counts, and a few sample
    paths so Plane B knows where to look without dumping tens of thousands
    of paths into the LLM prompt. Full inventory stays in the evidence catalog.
    """
    if not entries:
        return ["(none)"]

    zone_n = 0
    usable: list[tuple[str, str]] = []
    for e in entries:
        path = _path_str(e)
        if not path:
            continue
        if _is_zone_identifier(path):
            zone_n += 1
            continue
        usable.append((path, _evidence_id_str(e)))

    total = len(entries)
    listed_n = len(usable)
    lines: list[str] = []

    if listed_n <= full_max:
        for path, eid in usable:
            if eid:
                lines.append(f"- `{path}` (`{eid}`)")
            else:
                lines.append(f"- `{path}`")
        if zone_n:
            lines.append(
                f"- _{zone_n} Zone.Identifier ADS omitted from listing "
                f"(not useful as evidence units)_"
            )
        if total and not usable and zone_n:
            # Only Zone noise — still say so explicitly.
            lines = [
                f"- _{zone_n} Zone.Identifier ADS only "
                f"(omitted from listing)_"
            ]
        return lines or ["(none)"]

    # --- Summary mode ---
    buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path, eid in usable:
        buckets[_bucket_key(path, bucket_depth)].append((path, eid))

    ranked = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    lines.append(
        f"**{listed_n} files** "
        f"(summarized for prompt size; full inventory is in "
        f"`.atlas/evidence_catalog.json` — use tools to inspect paths)."
    )
    if zone_n:
        lines.append(
            f"- _{zone_n} Zone.Identifier ADS omitted from listing_"
        )
    lines.append("")
    lines.append("### By folder")
    lines.append("")
    shown_buckets = ranked[:max_buckets]
    for key, items in shown_buckets:
        lines.append(f"- `{key}/` — **{len(items)}** file(s)")
    omitted_buckets = len(ranked) - len(shown_buckets)
    if omitted_buckets > 0:
        rest = sum(len(items) for _, items in ranked[max_buckets:])
        lines.append(
            f"- _… {omitted_buckets} further folder(s) "
            f"({rest} file(s)) not shown_"
        )

    lines.append("")
    lines.append("### Sample paths")
    lines.append("")
    sample_lines = 0
    for key, items in shown_buckets:
        if sample_lines >= max_sample_lines:
            break
        take = items[:samples_per_bucket]
        for path, eid in take:
            if sample_lines >= max_sample_lines:
                break
            if eid:
                lines.append(f"- `{path}` (`{eid}`)")
            else:
                lines.append(f"- `{path}`")
            sample_lines += 1
        remaining = len(items) - len(take)
        if remaining > 0 and sample_lines < max_sample_lines:
            lines.append(
                f"  - _… {remaining} more under `{key}/`_"
            )
            sample_lines += 1

    return lines

def memory_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "investigation_memory.json"


def brief_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "rerun_brief.md"


def load_memory(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = memory_path(case_dir)
    if not path.is_file():
        return {
            "schema_version": "1.0",
            "validated_conclusions": [],
            "disproven_assumptions": [],
            "unresolved_hypotheses": [],
            "missing_evidence": [],
            "open_investigation_goals": [],
            "outstanding_questions": [],
            "analyst_context": [],
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("analyst_context", [])
        return data
    except (OSError, json.JSONDecodeError):
        return {"schema_version": "1.0", "analyst_context": []}


def refresh_investigation_memory(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Derive lightweight investigation memory from claim graph (not chat)."""
    from core.claim_graph import (
        CURRENT_BELIEF_STATUSES,
        load_graph,
        list_nodes,
    )

    prior = load_memory(case_dir)
    graph = load_graph(case_dir)
    nodes = graph.get("nodes") or {}
    validated = [
        {"id": n["id"], "statement": (n.get("statement") or "")[:240],
         "confidence": n.get("confidence")}
        for n in list_nodes(graph, kind="conclusion")
        if n.get("status") in CURRENT_BELIEF_STATUSES
    ]
    unresolved_h = [
        {"id": n["id"], "statement": (n.get("statement") or "")[:240]}
        for n in list_nodes(graph, kind="hypothesis")
        if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}
    ]
    disproven = [
        {"id": n["id"], "statement": (n.get("statement") or "")[:240],
         "superseded_by": n.get("superseded_by"),
         "reason": n.get("supersede_reason", "")}
        for n in nodes.values()
        if n.get("status") == "superseded" and n.get("kind") in (
            "claim", "conclusion", "hypothesis"
        )
    ]
    missing: list[str] = []
    for n in nodes.values():
        for g in n.get("gaps") or []:
            if g and g not in missing:
                missing.append(str(g)[:300])
    needs = [
        n for n in nodes.values() if n.get("status") == "needs_review"
    ]
    goals = []
    if needs:
        goals.append("Re-validate claims marked needs_review against current evidence "
                     "and record the outcome (claim.revalidate or claim.supersede)")
    open_conflicts = [
        n for n in list_nodes(graph, kind="conflict")
        if n.get("status") == "conflict"
    ]
    if open_conflicts:
        goals.append("Reconcile open Conflict Findings before promoting conclusions")
    active_ctx = [
        e for e in (prior.get("analyst_context") or [])
        if e.get("status") == "active"
    ]
    if active_ctx:
        goals.append(
            "Apply active analyst context when interpreting claims "
            "(not as a blind allowlist)"
        )
    questions = list((prior.get("outstanding_questions") or []))
    for c in open_conflicts:
        q = f"Resolve conflict {c.get('id')}: {(c.get('statement') or '')[:120]}"
        if q not in questions:
            questions.append(q)

    mem = {
        "schema_version": "1.0",
        "updated_at": _utcnow(),
        "validated_conclusions": validated,
        "disproven_assumptions": disproven[:50],
        "unresolved_hypotheses": unresolved_h,
        "missing_evidence": missing[:50],
        # Continuity narrative only — NOT the CASE.md work queue.
        # Finish / pre-report gates read investigation_tasks.json.
        "open_investigation_goals": goals,
        "outstanding_questions": questions[:50],
        # Preserve analyst context across graph-derived refreshes
        "analyst_context": list(prior.get("analyst_context") or []),
    }
    path = memory_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mem, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return mem


def build_rerun_brief(
    case_dir: str | os.PathLike,
    plane_a_result: dict[str, Any],
) -> dict[str, Any]:
    """Build and persist the Rerun Brief from Plane A result + memory + graph."""
    from core.claim_graph import load_graph, list_nodes

    mem = refresh_investigation_memory(case_dir)
    graph = load_graph(case_dir)
    diff = plane_a_result.get("evidence_diff") or {}
    needs_review = plane_a_result.get("affected_claims") or []
    open_conflicts = plane_a_result.get("open_conflicts") or []

    superseded = [
        {"id": n.get("id"), "statement": (n.get("statement") or "")[:160],
         "superseded_by": n.get("superseded_by")}
        for n in (graph.get("nodes") or {}).values()
        if n.get("status") == "superseded"
        and n.get("kind") in ("conclusion", "claim")
    ][:30]

    unresolved_h = mem.get("unresolved_hypotheses") or []

    lines = [
        f"# Rerun Brief — {plane_a_result.get('case_id', '')}",
        "",
        f"Generated: {_utcnow()}",
        "",
        "## Investigation posture",
        "",
        "The **dirty set is the starting point** of this investigation, not a",
        "hard boundary. You MAY examine additional evidence, revisit assumptions,",
        "form competing hypotheses, and challenge conclusions whenever needed.",
        "You MUST NOT silently overwrite conclusions — use conflict / supersede.",
        "",
        "## Why this rerun",
        "",
    ]
    work = plane_a_result.get("work") or {}
    reasons = list(work.get("reasons") or [])
    if reasons:
        lines.extend(f"- {r}" for r in reasons)
    else:
        lines.append("(nothing changed since the previous run)")
    lines += ["", "## Evidence Links (from CASE.md)", ""]
    try:
        from core.evidence_links import (
            format_links_for_brief,
            load_evidence_links,
            sync_evidence_links,
        )
        elinks = load_evidence_links(case_dir)
        if not (elinks.get("entries") or []):
            elinks = sync_evidence_links(case_dir, persist=True)
        lines.extend(format_links_for_brief(elinks))
    except Exception:
        lines.append("(unavailable)")
    lines += ["", "## New Evidence", ""]
    added = diff.get("added") or []
    lines.extend(format_evidence_diff_lines(added))
    lines += ["", "## Modified Evidence", ""]
    changed = diff.get("changed") or []
    lines.extend(format_evidence_diff_lines(changed))
    lines += ["", "## Removed Evidence", ""]
    removed = diff.get("removed") or []
    lines.extend(format_evidence_diff_lines(removed))

    lines += ["", "## Claims requiring review", ""]
    if not needs_review:
        lines.append("(none)")
    else:
        for c in needs_review:
            lines.append(
                f"- **{c.get('id')}** [{c.get('status')}]: {c.get('statement')}"
            )
            if c.get("reason"):
                lines.append(f"  - reason: {c['reason']}")

    lines += ["", "## Existing open conflicts", ""]
    if not open_conflicts:
        lines.append("(none)")
    else:
        for c in open_conflicts:
            lines.append(f"- **{c.get('id')}**: {c.get('statement')}")

    lines += ["", "## Existing unresolved hypotheses", ""]
    if not unresolved_h:
        lines.append("(none)")
    else:
        for h in unresolved_h:
            lines.append(f"- **{h.get('id')}**: {h.get('statement')}")

    lines += ["", "## Previously superseded conclusions / claims", ""]
    if not superseded:
        lines.append("(none)")
    else:
        for s in superseded:
            lines.append(
                f"- **{s.get('id')}** → {s.get('superseded_by')}: {s.get('statement')}"
            )

    # Analyst context (interpretation layer — never modifies evidence)
    new_ctx = plane_a_result.get("new_analyst_context")
    active_ctx = plane_a_result.get("active_analyst_context")
    if active_ctx is None:
        active_ctx = [
            e for e in (mem.get("analyst_context") or [])
            if e.get("status") == "active"
        ]
    ctx_affected = plane_a_result.get("context_affected_claims") or []

    reconcile = plane_a_result.get("context_reconcile") or {}
    fresh = list(reconcile.get("added") or []) + list(reconcile.get("reactivated") or [])
    if new_ctx and all(e.get("id") != new_ctx.get("id") for e in fresh):
        fresh.insert(0, new_ctx)
    lines += ["", "## New Analyst Context (this run)", ""]
    if not fresh:
        lines.append("(none)")
    else:
        for e in fresh:
            lines.append(f"- **{e.get('id')}**: {e.get('text')}")
            ents = e.get("entities") or []
            if ents:
                lines.append(f"  - entities: {', '.join(ents)}")

    gone = list(reconcile.get("withdrawn") or [])
    lines += ["", "## Analyst Context withdrawn (this run)", ""]
    if not gone:
        lines.append("(none)")
    else:
        lines.append("No longer to be assumed; findings that leaned on it are "
                     "marked for review.")
        for e in gone:
            lines.append(f"- **{e.get('id')}**: {e.get('text')}")

    lines += ["", "## Active Analyst Context (persistent)", ""]
    if not active_ctx:
        lines.append("(none)")
    else:
        for e in active_ctx:
            lines.append(f"- **{e.get('id')}**: {e.get('text')}")
            ents = e.get("entities") or []
            if ents:
                lines.append(f"  - entities: {', '.join(ents)}")

    lines += [
        "",
        "## Analyst-context interpretation rule",
        "",
        "Analyst context improves interpretation of known infrastructure,",
        "accounts, and expected activity. It is **not** a blind allowlist:",
        "legitimate jump hosts / admin accounts can still host malicious",
        "activity (credential dumping, unusual auth, malware, out-of-scope use).",
        "Distinguish *identity of infrastructure* from *nature of observed activity*.",
        "",
        "## Claims / conclusions potentially affected by analyst context",
        "",
    ]
    if not ctx_affected:
        lines.append("(none)")
    else:
        for c in ctx_affected:
            lines.append(
                f"- **{c.get('id')}** [{c.get('kind', c.get('status', ''))}]: "
                f"{c.get('statement')}"
            )

    lines += ["", "## Outstanding investigation questions", ""]
    questions = mem.get("outstanding_questions") or []
    if not questions:
        lines.append("(none)")
    else:
        for q in questions:
            lines.append(f"- {q}")

    # Delivered evidence and high-value units no call has read yet: the
    # work a rerun has left even when nothing else changed.
    lines += ["", "## Evidence not yet examined", ""]
    try:
        from core.coverage_ledger import open_unit_paths
        from core.evidence_items import unseen as _unseen_items
        not_read = list(dict.fromkeys(_unseen_items(case_dir, limit=1_000_000)
                                      + open_unit_paths(case_dir, limit=1_000_000)))
    except Exception:  # noqa: BLE001
        not_read = []
    if not not_read:
        lines.append("(none: every delivered item and high-value unit was read, blocked or handed over)")
    else:
        lines.extend(f"- {p}" for p in not_read[:40])
        if len(not_read) > 40:
            lines.append(f"- ... and {len(not_read) - 40} more")
        lines.append("Read each with an applicable tool, or record a failed attempt with "
                     "coverage.mark_blocked.")
    # Folders and archives the calls reached only in part: for judgement,
    # not a reason to rerun (a collected tree is rarely read file by file).
    try:
        from core.evidence_items import rows as _item_rows
        partly = [r for r in _item_rows(case_dir) if r.get("status") == "examined"
                  and r.get("files") and r.get("named_files", 0) < r["files"]]
    except Exception:  # noqa: BLE001
        partly = []
    if partly:
        lines += ["", "Read in part (for judgement, not a reason to rerun):"]
        lines += [f"- {r['path']}: calls named {r.get('named_files', 0)} of {r['files']} files"
                  + (f" and {r['named_folders']} folders" if r.get("named_folders") else "")
                  for r in partly[:10]]

    # What the case already believes: a rerun that cannot see its own
    # findings re-derives and re-records them.
    try:
        from core.answer_synthesis import headline
        from core.claim_graph import load_graph
        held = [n for n in (load_graph(case_dir).get("nodes") or {}).values()
                if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion")
                and n.get("status") not in ("superseded", "withdrawn")]
    except Exception:
        held = []
    lines += ["", f"## Existing findings ({len(held)})", ""]
    if not held:
        lines.append("(none — this is the first pass over the evidence)")
    else:
        lines.append("Build on these: extend, strengthen or challenge them; "
                     "do not record them again.")
        for n in held[:60]:
            lines.append(f"- **{n.get('id')}** [{n.get('confidence')}]"
                         f"{' ' + str(n.get('host')) if n.get('host') else ''}: "
                         f"{headline(str(n.get('statement') or ''), limit=140, label_only=False)}")
        if len(held) > 60:
            lines.append(f"- … and {len(held) - 60} more (claim.snapshot lists all)")

    # Investigation tasks (CASE.md inbox materialization)
    try:
        from core.investigation_tasks import load_tasks
        task_store = load_tasks(case_dir)
        all_tasks = list(task_store.get("tasks") or [])
    except Exception:
        all_tasks = []
    lines += ["", "## Investigation Tasks", ""]
    if not all_tasks:
        lines.append("(none — add bullets under ## Investigation Requests in CASE.md)")
    else:
        for t in all_tasks:
            if t.get("status") in ("dropped", "withdrawn"):
                continue
            lines.append(
                f"- **{t.get('id')}** [{t.get('status')}]: {t.get('text')}"
            )

    # Investigation plan (Plane A orchestration)
    plan = plane_a_result.get("investigation_plan")
    if not plan:
        try:
            from core.investigation_plan import load_plan, format_plan_brief_section
            plan_full = load_plan(case_dir)
            lines.extend(format_plan_brief_section(plan_full))
        except Exception:
            lines += ["", "## Investigation Plan", "", "(unavailable)"]
    else:
        try:
            from core.investigation_plan import format_plan_brief_section, load_plan
            # Prefer full on-disk plan when available
            plan_full = load_plan(case_dir)
            if plan_full.get("steps"):
                lines.extend(format_plan_brief_section(plan_full))
            else:
                lines.extend(format_plan_brief_section({
                    "steps": plan.get("steps") or [],
                    "focus_hosts": plan.get("focus_hosts") or [],
                    "blocked_task_ids": plan.get("blocked_task_ids") or [],
                }))
        except Exception:
            lines += ["", "## Investigation Plan", "", "(unavailable)"]

    lines += ["", "## Investigation memory (summary)", ""]
    lines.append(
        f"- Validated conclusions: {len(mem.get('validated_conclusions') or [])}"
    )
    lines.append(
        f"- Active analyst context entries: {len(active_ctx)}"
    )
    lines.append(
        f"- Open investigation goals: {len(mem.get('open_investigation_goals') or [])}"
    )
    for g in (mem.get("open_investigation_goals") or []):
        lines.append(f"  - {g}")
    lines.append(
        f"- Missing evidence notes: {len(mem.get('missing_evidence') or [])}"
    )
    lines += [
        "",
        "## Next steps",
        "",
        "1. Follow the Investigation Plan checklist above.",
        "2. Call `claim.snapshot` and review needs_review / conflicts.",
        "3. Re-examine dirty evidence and analyst-context-affected claims first,",
        "   then expand as needed (dirty set is a start, not a boundary).",
        "4. Update investigation task status as work progresses",
        "   (`misc.update_investigation_task`).",
        "5. Record each reviewed claim's outcome: `claim.revalidate` (citing the",
        "   calls that re-read its evidence) when it still holds, `claim.supersede`",
        "   when it does not; promote with explicit reasoning; open conflicts on",
        "   disagreement.",
        "6. Rewrite only affected report sections when ready.",
        "",
    ]

    text = "\n".join(lines)
    path = brief_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return {
        "path": str(path),
        "text": text,
        "memory": mem,
    }
