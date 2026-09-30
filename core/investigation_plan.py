"""Investigation Plan — execution checklist built by the Orchestrator.

Plane A calls ``build_investigation_plan`` after evidence diff + task
reconcile. The plan does **not** analyse evidence or write claims; it is the
Lead-Investigator output of ``core.investigation_orchestrator`` (resources +
scored candidates). Middleware remains safety rails only.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.2"

_HOST_TOKEN_RE = re.compile(
    r"(?i)\b(?:host|workstation|server)\s+([A-Za-z0-9][A-Za-z0-9.\-_]{1,63})\b"
)
_BARE_HOST_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9\-_]{2,31}(?:\d{1,3})?)\b"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def plan_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "investigation_plan.json"


def empty_plan(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "steps": [],
        "actionable_task_ids": [],
        "blocked_task_ids": [],
        "revisit_claim_ids": [],
        "dirty_evidence_paths": [],
        "focus_hosts": [],
        "focus_evidence": [],
        "candidates": [],
        "context_budget": {},
        "coverage": {"mode": "not_needed", "chunks": []},
        "resources": {},
        "note": (
            "Investigation execution plan from the Resource Orchestrator. "
            "Optimises investigation value under context, tool, and cost "
            "constraints — not token usage alone. Disk-first; full coverage "
            "via table.* is last resort when still dark."
        ),
    }


def load_plan(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = plan_path(case_dir)
    if not path.is_file():
        return empty_plan(Path(case_dir).resolve().name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_plan()
    if not isinstance(data, dict):
        return empty_plan()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("steps", [])
    return data


def save_plan(case_dir: str | os.PathLike, plan: dict[str, Any]) -> Path:
    path = plan_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    plan = dict(plan)
    plan["schema_version"] = SCHEMA_VERSION
    plan["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def _detail_for(est_tokens: int, tool_room: int, policy: str) -> str:
    """Map estimated dump cost vs remaining tool budget to a detail level.

    Over-budget candidates stay **ready** as ``artifact_only`` (disk-first
    parse + LLM summary), not postpone — postpone is reserved for sources
    with no useful parse path yet.
    """
    if est_tokens <= 0:
        return "summary"
    if tool_room <= 0 or est_tokens > tool_room:
        return "artifact_only"
    if policy == "compact" and est_tokens > tool_room // 2:
        return "summary"
    if policy == "rich":
        return "full"
    return "filtered"


# Function words that legally follow "host"/"server" in prose but are never
# hostnames — "…on that host using the KAPE outputs…" would put focus_hosts=
# ["using"] into the plan and skew affinity scoring.
_HOST_STOPWORDS = frozenset({
    "using", "that", "this", "the", "with", "and", "for", "from", "was",
    "is", "are", "were", "has", "have", "name", "names", "in", "on", "of",
    "to", "or", "not", "it", "its", "a", "an", "as", "at", "by", "via",
    "where", "which", "whose", "will", "can", "may", "must", "should",
})


def _hosts_from_text(text: str) -> list[str]:
    found: list[str] = []
    for m in _HOST_TOKEN_RE.finditer(text or ""):
        tok = m.group(1)
        if tok.casefold() in _HOST_STOPWORDS:
            continue
        if tok not in found:
            found.append(tok)
    return found


def _order_tasks(tasks: list[dict[str, Any]], revisit_claim_ids: set[str]) -> list[dict[str, Any]]:
    """Order: reopened / needs_review-linked → open → partial → in_progress → blocked."""
    rank = {
        "reopened": 0,
        "open": 2,
        "partial": 3,
        "in_progress": 4,
        "blocked_missing_evidence": 5,
    }

    def key(t: dict[str, Any]) -> tuple:
        status = t.get("status") or "open"
        related = set(t.get("related_claim_ids") or [])
        linked = 0 if (related & revisit_claim_ids) else 1
        return (linked if status != "reopened" else 0,
                rank.get(status, 9),
                t.get("id") or "")

    return sorted(tasks, key=key)


def build_investigation_plan(
    case_dir: str | os.PathLike,
    plane_a_result: Optional[dict[str, Any]] = None,
    *,
    persist: bool = True,
    context_budget: Optional[dict[str, Any]] = None,
    messages: Optional[list] = None,
    model: str = "",
    provider: str = "",
) -> dict[str, Any]:
    """Build a deterministic execution plan from tasks + Plane A signals."""
    from core.investigation_tasks import load_tasks

    root = Path(case_dir).resolve()
    plane = plane_a_result or {}
    case_id = plane.get("case_id") or root.name
    store = load_tasks(root)
    tasks = list(store.get("tasks") or [])

    revisit_ids = [
        c.get("id") for c in (plane.get("affected_claims") or [])
        if c.get("id")
    ]
    revisit_set = set(revisit_ids)
    open_conflicts = [
        c.get("id") for c in (plane.get("open_conflicts") or [])
        if c.get("id")
    ]

    diff = plane.get("evidence_diff") or {}
    dirty_paths: list[str] = []
    for bucket in ("added", "changed", "removed"):
        for item in diff.get(bucket) or []:
            p = item.get("path") if isinstance(item, dict) else None
            if p and p not in dirty_paths:
                dirty_paths.append(p)

    actionable = [
        t for t in tasks
        if t.get("status") in {
            "open", "in_progress", "partial", "reopened",
        }
    ]
    blocked = [
        t for t in tasks
        if t.get("status") == "blocked_missing_evidence"
    ]
    ordered = _order_tasks(actionable, revisit_set)

    # CASE.md Evidence Links are authoritative for host/path focus seeds.
    link_hosts: list[str] = []
    link_paths: list[str] = []
    link_aliases: dict[str, str] = {}
    link_principals: list[str] = []
    try:
        from core.evidence_links import load_evidence_links, sync_evidence_links
        elinks = load_evidence_links(root)
        if not (elinks.get("entries") or []):
            elinks = sync_evidence_links(root, persist=True)
        link_hosts = list(elinks.get("hosts") or [])
        link_paths = list(elinks.get("paths") or [])
        link_aliases = dict(elinks.get("aliases") or {})
        link_principals = list(elinks.get("principals") or [])
        # Alias sources stay visible for affinity / the names logs use
        for src in link_aliases:
            if src not in link_hosts:
                link_hosts.append(src)
    except Exception:
        pass

    focus_hosts: list[str] = list(link_hosts)
    for t in ordered:
        for h in _hosts_from_text(t.get("text") or ""):
            if h.casefold() in _HOST_STOPWORDS:
                continue
            if h not in focus_hosts:
                focus_hosts.append(h)

    # Evidence focus: linked paths first, then dirty + basename tokens.
    # Require token-boundary match and min basename length so short names
    # like "all" do not match words such as "additionally" (orchestrator junk).
    focus_evidence = list(link_paths)
    for p in dirty_paths[:20]:
        if p and p not in focus_evidence:
            focus_evidence.append(p)
    try:
        import re as _re
        from core.coverage_ledger import is_noise_path
        from core.evidence_catalog import load_catalog
        units = (load_catalog(root).get("units") or {})
        basenames = {
            Path(u.get("path") or "").name.lower(): u.get("path")
            for u in units.values()
            if isinstance(u, dict) and not is_noise_path(
                str(u.get("path") or ""))
        }
        _SKIP_BN = frozenset({
            "all", "log", "data", "file", "tmp", "temp", "test", "bin",
            "lib", "src", "out", "csv", "txt", "json", "xml",
        })
        for t in ordered:
            text_l = (t.get("text") or "").casefold()
            for bn, path in basenames.items():
                if not bn or not path or path in focus_evidence:
                    continue
                stem = Path(bn).stem.casefold()
                if len(stem) < 5 or stem in _SKIP_BN or bn in _SKIP_BN:
                    continue
                if is_noise_path(str(path)):
                    continue
                # Token boundary — not substring of unrelated English words
                if _re.search(
                        rf"(?<![a-z0-9]){_re.escape(stem)}(?![a-z0-9])",
                        text_l):
                    focus_evidence.append(path)
    except Exception:
        pass

    # Mount plan hint (if present)
    mount_hint = ""
    try:
        mp = root / ".atlas" / "mount_plan.json"
        if mp.is_file():
            mdata = json.loads(mp.read_text(encoding="utf-8"))
            entries = mdata.get("images") or mdata.get("entries") or []
            auto = [e for e in entries if e.get("auto_mount") or e.get("status") == "mounted"]
            pending = [e for e in entries if e.get("action") == "plan_only" or e.get("recommended")]
            if auto or pending:
                mount_hint = (
                    f"{len(auto)} auto-mount candidate(s), "
                    f"{len(pending)} plan-only image(s) — see .atlas/mount_plan.json"
                )
    except Exception:
        pass

    steps: list[dict[str, Any]] = []
    step_n = 1

    # Always first: evidence assessment before any forensic / directing tool.
    steps.append({
        "id": f"step-{step_n:02d}",
        "action": "inventory_evidence",
        "summary": (
            "Call misc_inventory_evidence first — assess what exists, what "
            "is already parsed (consume those), what still needs processing, "
            "and what classes to skip. No mounts/parsers/DAIR/reason until then."
        ),
    })
    step_n += 1

    if revisit_ids:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "revisit_claims",
            "summary": (
                f"Revisit {len(revisit_ids)} claim(s) marked needs_review "
                "before promoting new conclusions; record each outcome with "
                "claim.revalidate (still holds, citing the re-read) or "
                "claim.supersede."
            ),
            "claim_ids": revisit_ids[:40],
        })
        step_n += 1

    if open_conflicts:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "reconcile_conflicts",
            "summary": f"Reconcile {len(open_conflicts)} open conflict(s).",
            "claim_ids": open_conflicts[:20],
        })
        step_n += 1

    if dirty_paths:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "examine_dirty_evidence",
            "summary": (
                f"Examine dirty evidence ({len(dirty_paths)} path(s)) "
                "as the starting point (not a hard boundary)."
            ),
            "paths": dirty_paths[:40],
        })
        step_n += 1

    for t in ordered:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "investigate_task",
            "summary": f"[{t.get('status')}] {t.get('text')}",
            "task_id": t.get("id"),
        })
        step_n += 1

    if blocked:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "note_blocked",
            "summary": (
                f"{len(blocked)} task(s) blocked on missing evidence — "
                "do not mark answered; request or wait for intake."
            ),
            "task_ids": [t.get("id") for t in blocked],
        })
        step_n += 1

    if mount_hint:
        steps.append({
            "id": f"step-{step_n:02d}",
            "action": "review_mount_plan",
            "summary": mount_hint,
        })

    if not steps:
        steps.append({
            "id": "step-01",
            "action": "await_work",
            "summary": (
                "No actionable investigation tasks. Append requests to CASE.md "
                "or add evidence under evidence/."
            ),
        })

    plan = empty_plan(case_id)
    plan.update({
        "steps": steps,
        "actionable_task_ids": [t.get("id") for t in ordered],
        "blocked_task_ids": [t.get("id") for t in blocked],
        "revisit_claim_ids": revisit_ids,
        "dirty_evidence_paths": dirty_paths,
        "focus_hosts": focus_hosts[:20],
        "focus_evidence": focus_evidence[:40],
        "open_conflict_ids": open_conflicts,
        "evidence_links": {
            "hosts": link_hosts[:20],
            "paths": link_paths[:40],
            "aliases": link_aliases,
            "principals": link_principals[:20],
        },
    })

    # Investigation Orchestrator: resources + ranked candidates
    # (value × tool fit × budget fit × inverse cost).
    try:
        from core.input_scale import (
            affinity_score,
            estimate_path_cost_tokens,
            rank_shards,
        )
        from core.investigation_orchestrator import (
            gather_resources,
            rank_actions,
            score_candidate,
        )

        resources = gather_resources(
            root,
            plane_a_result=plane,
            ordered_tasks=ordered,
            focus_hosts=focus_hosts,
            revisit_claim_ids=revisit_ids,
            context_budget=context_budget,
            messages=messages,
            model=model,
            provider=provider,
        )
        plan["resources"] = resources
        budget = resources.get("context_budget") or {}
        plan["context_budget"] = budget

        focus_blob = " ".join(
            (t.get("text") or "") for t in ordered
        ) + " " + " ".join(focus_hosts)
        tool_room = int(budget.get("available_for_tool_output_tokens") or 0)
        policy = budget.get("detail_policy") or "compact"
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        seed_paths = list(focus_evidence[:40])
        # Prefer coverage-ledger gaps over junk affinity seeds
        try:
            from core.coverage_ledger import open_unit_paths
            for gp in open_unit_paths(root, limit=20):
                if gp and gp not in seed_paths:
                    seed_paths.insert(0, gp)
        except Exception:
            pass
        for p in seed_paths:
            if not p or p in seen:
                continue
            seen.add(p)
            if os.path.isdir(p):
                from pathlib import Path as _P
                kids = [
                    c for c in _P(p).iterdir()
                    if c.is_file() and c.suffix.lower() == ".evtx"
                ][:200] if _P(p).is_dir() else []
                if kids:
                    for shard in rank_shards(kids, focus_text=focus_blob, cap=12):
                        sp = shard["path"]
                        if sp in seen:
                            continue
                        seen.add(sp)
                        est = int(shard.get("est_tokens") or 0)
                        aff = float(shard.get("affinity") or 0)
                        detail = _detail_for(est, tool_room, policy)
                        candidates.append(score_candidate(
                            path=sp,
                            affinity=aff,
                            est_tokens=est,
                            detail_level=detail,
                            tool_room=tool_room,
                            focus_text=focus_blob,
                            case_dir=root,
                        ))
                    continue
            est = estimate_path_cost_tokens(p)
            aff = affinity_score(p, focus_blob)
            detail = _detail_for(est, tool_room, policy)
            candidates.append(score_candidate(
                path=p,
                affinity=aff,
                est_tokens=est,
                detail_level=detail,
                tool_room=tool_room,
                focus_text=focus_blob,
                case_dir=root,
            ))
        candidates = rank_actions(candidates)[:40]
        plan["candidates"] = candidates
        if candidates:
            top = candidates[:5]
            steps.insert(1, {
                "id": "step-orchestrate",
                "action": "follow_investigation_plan",
                "summary": (
                    f"Orchestrator: policy={policy}; tool room≈{tool_room} tok. "
                    f"Prefer highest-score actions (value×tool×budget). "
                    f"Tabular spills → table.*; raw/disk exports → tsk.mmls "
                    f"(not table.*). Next: "
                    + ", ".join(
                        f"{c.get('path')} "
                        f"[{c.get('tool_hint')}|{c.get('detail_level')}"
                        f"|score={c.get('score')}]"
                        for c in top
                    )
                ),
            })
            plan["steps"] = steps

        # Full coverage last resort — only when bootstrap left the LLM dark
        # and analysis/*.csv already exists (prefer chunking artifacts, not
        # re-dumping raw sources into context).
        try:
            from core.coverage import (
                find_related_artifacts,
                plan_tabular_coverage,
                should_offer_full_coverage,
            )
            if should_offer_full_coverage(str(root)):
                coverage_chunks: list[dict[str, Any]] = []
                for csv_path in find_related_artifacts(str(root))[:3]:
                    coverage_chunks.extend(
                        plan_tabular_coverage(
                            csv_path,
                            available_tool_tokens=tool_room or 8000,
                        )[:8]
                    )
                plan["coverage"] = {
                    "mode": "full_coverage_last_resort",
                    "chunks": coverage_chunks[:24],
                    "note": (
                        "Only after affinity/table probes failed to answer "
                        "open tasks. Walk chunks via table.*; do not re-run "
                        "bulk parsers on the raw source for coverage."
                    ),
                }
                if coverage_chunks:
                    steps.append({
                        "id": "step-full-coverage",
                        "action": "full_coverage_table_windows",
                        "summary": (
                            f"LLM still dark after bootstrap: "
                            f"{len(coverage_chunks)} table.* windows planned "
                            f"across analysis CSVs. Run sequentially; stop "
                            f"early when a claim can be grounded."
                        ),
                    })
                    plan["steps"] = steps
            else:
                plan.setdefault("coverage", {"mode": "not_needed", "chunks": []})
        except Exception:
            plan.setdefault("coverage", {"mode": "unavailable", "chunks": []})
    except Exception:
        plan.setdefault("candidates", [])
        plan.setdefault("context_budget", {})
        plan.setdefault("resources", {})
        plan.setdefault("coverage", {"mode": "unavailable", "chunks": []})

    if persist:
        save_plan(root, plan)
    return plan


def format_plan_for_prompt(case_dir: str | os.PathLike) -> str:
    plan = load_plan(case_dir)
    steps = plan.get("steps") or []
    lines = ["# Investigation Plan", ""]
    if not steps:
        lines.append("(empty)")
        lines.append("")
        return "\n".join(lines)
    for s in steps:
        lines.append(f"- **{s.get('id')}** [{s.get('action')}]: {s.get('summary')}")
    hosts = plan.get("focus_hosts") or []
    if hosts:
        lines.append("")
        lines.append("Focus hosts: " + ", ".join(hosts))
    lines.append("")
    return "\n".join(lines)


def format_plan_brief_section(plan: dict[str, Any]) -> list[str]:
    """Markdown lines for inclusion in the Rerun Brief."""
    lines = [
        "",
        "## Investigation Plan",
        "",
        "Pre-execution orchestration (not forensic analysis). Follow these",
        "steps as the starting checklist for this iteration.",
        "",
    ]
    budget = plan.get("context_budget") or {}
    if budget:
        try:
            from core.context_budget import format_budget_for_brief
            lines.append(format_budget_for_brief(budget).rstrip())
            lines.append("")
        except Exception:
            lines.append(
                f"Context policy={budget.get('detail_policy')}; "
                f"tool room≈{budget.get('available_for_tool_output_tokens')} tok."
            )
            lines.append("")
    resources = plan.get("resources") or {}
    if resources:
        try:
            from core.investigation_orchestrator import format_resources_for_brief
            lines.append(format_resources_for_brief(resources).rstrip())
            lines.append("")
        except Exception:
            pass
    steps = plan.get("steps") or []
    if not steps:
        lines.append("(none)")
        return lines
    for s in steps:
        lines.append(
            f"- **{s.get('id')}** [{s.get('action')}]: {s.get('summary')}")
    hosts = plan.get("focus_hosts") or []
    if hosts:
        lines += ["", f"Suggested host focus: {', '.join(hosts)}"]
    blocked = plan.get("blocked_task_ids") or []
    if blocked:
        lines += ["", f"Blocked tasks: {', '.join(blocked)}"]
    cands = [
        c for c in (plan.get("candidates") or [])
        if c.get("status") == "ready"
    ][:8]
    if cands:
        lines += ["", "High-value candidate actions:"]
        for c in cands:
            lines.append(
                f"- `{c.get('path')}` tool={c.get('tool_hint')} "
                f"cap={c.get('capability_id')} "
                f"score={c.get('score')} detail={c.get('detail_level')} "
                f"value={c.get('investigation_value')} "
                f"est≈{c.get('est_tokens')} tok"
            )
    cov = plan.get("coverage") or {}
    if cov.get("mode") == "full_coverage_last_resort" and cov.get("chunks"):
        lines += [
            "",
            f"Full coverage (last resort): {len(cov['chunks'])} table.* "
            "windows — only after targeted probes failed.",
        ]
    return lines
