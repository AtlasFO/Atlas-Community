"""Derived revisit tasks from new findings / needs_review (V1, simple).

Creates new investigation tasks with ``[derived]`` text prefix. Exact-text
dedupe only — never fuzzy-merges with CASE.md inbox tasks.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional


def derive_revisit_tasks(
    case_dir: str | os.PathLike,
    plane_a_result: Optional[dict[str, Any]] = None,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Enqueue derived revisit tasks for the case's other hosts.

    A claim under review is re-checked against each host of the case that
    the claim does not already name:
    ``[derived] Re-check <other_host> for indicators related to: <claim>``

    The hosts are the ones the case actually knows — the labels on its
    evidence links — together with each claim's own ``host`` field. They
    are never read out of prose or off a file name: "the host name" in a
    question does not name a host called "name", and an evidence file
    called ``<something>.log`` does not make ``<something>`` a second
    machine. Guessing either way turned every basename into a host, so a
    handful of claims raised a follow-up per file.

    A case that knows fewer than two hosts has nothing to cross-check, and
    a claim with neither a statement nor a host says nothing to re-check
    for; both derive nothing.
    """
    from core.forensic_citation import host_mentioned, known_case_hosts
    from core.investigation_tasks import add_derived_task, load_tasks

    root = Path(case_dir).resolve()
    plane = plane_a_result or {}
    created: list[str] = []
    skipped: list[str] = []

    needs = plane.get("affected_claims") or []
    if not needs:
        return {"success": True, "created": [], "skipped": [], "note": "no needs_review"}

    known: list[str] = []
    seen: set[str] = set()
    for label in known_case_hosts(root):
        key = str(label or "").strip().casefold()
        if key and key not in seen:
            seen.add(key)
            known.append(str(label).strip())
    if len(known) < 2:
        return {
            "success": True,
            "created": [],
            "skipped": [],
            "note": "case knows fewer than two hosts",
        }

    for claim in needs[:20]:
        stmt = (claim.get("statement") or "").strip()[:120]
        own_host = str(claim.get("host") or "").strip()
        if not stmt and not own_host:
            continue
        cid = claim.get("id") or ""
        named = {own_host.casefold()} - {""}
        named |= {h.casefold() for h in known if host_mentioned(h, stmt)}
        targets = [h for h in known if h.casefold() not in named][:3]
        for host in targets:
            text = f"[derived] Re-check {host} for indicators related to: {stmt}"
            if not persist:
                skipped.append(text)
                continue
            result = add_derived_task(
                root, text,
                related_claim_ids=[cid] if cid else None,
            )
            if result.get("created"):
                created.append(result["task"]["id"])
            else:
                skipped.append(result.get("task", {}).get("id") or text)

    return {
        "success": True,
        "created": created,
        "skipped": skipped,
        "tasks_total": len(load_tasks(root).get("tasks") or []),
    }
