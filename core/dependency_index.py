"""Dependency index for incremental invalidation.

Maps evidence paths / evidence_ids → claim-graph node ids so Plane A can mark
``needs_review`` when inputs change. Semantic edges remain in claim_graph.json;
this index is the mechanical fan-out.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

_PATH_RE = re.compile(
    r"(?:evidence/|analysis/)[^\s\"'|,;]+\.[A-Za-z0-9]{1,12}",
    re.IGNORECASE,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dependency_index_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "dependency_index.json"


def empty_index() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": _utcnow(),
        "by_evidence_path": {},   # path -> [node_id, ...]
        "by_evidence_id": {},    # evidence_id -> [node_id, ...]
        "by_node": {},           # node_id -> {paths[], evidence_ids[]}
    }


def load_index(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = dependency_index_path(case_dir)
    if not path.is_file():
        return empty_index()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_index()
    if not isinstance(data, dict):
        return empty_index()
    data.setdefault("by_evidence_path", {})
    data.setdefault("by_evidence_id", {})
    data.setdefault("by_node", {})
    return data


def save_index(case_dir: str | os.PathLike, index: dict[str, Any]) -> Path:
    path = dependency_index_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    index = dict(index)
    index["updated_at"] = _utcnow()
    index["schema_version"] = SCHEMA_VERSION
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)
    return path


def _extract_paths_from_node(node: dict) -> list[str]:
    found: list[str] = []
    for item in node.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        for key in ("artifact", "locator"):
            val = str(item.get(key) or "")
            if not val:
                continue
            # Direct path-like artifact
            if "evidence/" in val or "analysis/" in val:
                for m in _PATH_RE.findall(val):
                    found.append(m.rstrip(".,;)"))
            elif "/" in val and not val.startswith("call_id"):
                # bare relative path
                found.append(val.split()[0].rstrip(".,;)"))
    # Statement may cite paths
    for m in _PATH_RE.findall(node.get("statement") or ""):
        found.append(m.rstrip(".,;)"))
    # Dedup preserve order
    out: list[str] = []
    seen: set[str] = set()
    for p in found:
        p = p.replace("\\", "/")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def rebuild_from_claim_graph(
    case_dir: str | os.PathLike,
    *,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rebuild dependency index from claim graph (+ optional catalog path map)."""
    from core.claim_graph import load_graph
    from core.evidence_catalog import load_catalog

    graph = load_graph(case_dir)
    cat = catalog if catalog is not None else load_catalog(case_dir)
    path_to_eid = {
        u.get("path"): u.get("evidence_id")
        for u in (cat.get("units") or {}).values()
        if u.get("path") and u.get("evidence_id")
    }

    index = empty_index()
    by_path: dict[str, list[str]] = {}
    by_eid: dict[str, list[str]] = {}
    by_node: dict[str, dict] = {}

    for nid, node in (graph.get("nodes") or {}).items():
        if not isinstance(node, dict):
            continue
        paths = _extract_paths_from_node(node)
        eids: list[str] = []
        for p in paths:
            # Normalize to evidence/-relative if possible
            norm = p
            if not norm.startswith("evidence/") and not norm.startswith("analysis/"):
                # try evidence/ prefix
                cand = f"evidence/{norm.lstrip('/')}"
                if cand in path_to_eid:
                    norm = cand
            by_path.setdefault(norm, []).append(nid)
            eid = path_to_eid.get(norm)
            if eid:
                eids.append(eid)
                by_eid.setdefault(eid, []).append(nid)
        by_node[nid] = {"paths": paths, "evidence_ids": eids, "kind": node.get("kind")}

    # Dedup lists
    index["by_evidence_path"] = {k: sorted(set(v)) for k, v in by_path.items()}
    index["by_evidence_id"] = {k: sorted(set(v)) for k, v in by_eid.items()}
    index["by_node"] = by_node
    save_index(case_dir, index)
    return index


def nodes_for_dirty_evidence(
    index: dict[str, Any],
    *,
    dirty_evidence_ids: list[str],
    dirty_paths: list[str],
) -> list[str]:
    """Return node ids that depend on dirty evidence (union)."""
    hit: set[str] = set()
    by_eid = index.get("by_evidence_id") or {}
    by_path = index.get("by_evidence_path") or {}
    for eid in dirty_evidence_ids:
        hit.update(by_eid.get(eid) or [])
    for path in dirty_paths:
        hit.update(by_path.get(path) or [])
        # Also try basename match
        base = path.split("/")[-1]
        for p, nids in by_path.items():
            if p.endswith("/" + base) or p == base:
                hit.update(nids)
    return sorted(hit)


_DIRTY_PATH_CAP = 20


def dirty_hits(
    index: dict[str, Any],
    items: list[tuple[str, str, str | None]],
) -> dict[str, dict[str, list[str]]]:
    """Which dirty evidence hit which node: ``{node id: {kind: [paths]}}``
    for ``items`` of ``(kind, path, evidence id)``, matched the way
    ``nodes_for_dirty_evidence`` matches (evidence id, full path, basename).
    A node stamped with the paths that hit it can be held to a read of
    exactly those, not of the whole scan's diff."""
    out: dict[str, dict[str, list[str]]] = {}
    by_eid = index.get("by_evidence_id") or {}
    by_path = index.get("by_evidence_path") or {}
    for kind, path, eid in items:
        nodes: set[str] = set(by_eid.get(eid) or []) if eid else set()
        nodes.update(by_path.get(path) or [])
        base = str(path).split("/")[-1]
        for p, nids in by_path.items():
            if p.endswith("/" + base) or p == base:
                nodes.update(nids)
        for nid in nodes:
            paths = out.setdefault(nid, {}).setdefault(kind, [])
            if path not in paths:
                paths.append(path)
    return out


def _merge_stamp(dst: dict[str, list[str]] | None, src: dict[str, list[str]] | None) -> dict[str, list[str]]:
    out = {k: list(v) for k, v in (dst or {}).items() if v}
    for k, v in (src or {}).items():
        merged = out.setdefault(k, [])
        for p in v:
            if p not in merged and len(merged) < _DIRTY_PATH_CAP:
                merged.append(p)
    return {k: v for k, v in out.items() if v}


def mark_needs_review(
    case_dir: str | os.PathLike,
    node_ids: list[str],
    *,
    reason: str = "upstream evidence changed",
    dirty: dict[str, list[str]] | None = None,
    hits: dict[str, dict[str, list[str]]] | None = None,
) -> dict[str, Any]:
    """Set status=needs_review on current beliefs (never silent supersede).

    ``hits`` (from ``dirty_hits``) names, per node, the added, changed and
    removed paths that hit it, stamped on the node as ``invalidated_by`` so
    a re-validation can be held to a read of what changed for it; ``dirty``
    (the whole scan's diff) is the stamp for a node ``hits`` does not name.
    A node already under review that is marked again merges the new paths
    and takes the new time. A node marked through a ``derived_from`` edge
    inherits its bases' paths and carries the
    parents it was marked for in ``invalidated_via``; a node marked
    directly carries none, and a direct mark drops the stamp, because the
    node is then questioned in its own right and not only through its
    bases (``core.claim_graph.revalidate`` returns only stamped nodes with
    their bases).
    """
    from core.claim_graph import (
        CURRENT_BELIEF_STATUSES,
        load_graph,
        save_graph,
    )

    graph = load_graph(case_dir)
    marked: list[str] = []
    skipped: list[str] = []
    remarked: list[str] = []
    touched = False
    now = _utcnow()
    by = {k: [str(p) for p in (dirty or {}).get(k) or []][:_DIRTY_PATH_CAP]
          for k in ("added", "changed", "removed")}
    by = {k: v for k, v in by.items() if v}

    def _stamp_for(nid: str) -> dict[str, list[str]]:
        own = (hits or {}).get(nid)
        if own:
            return _merge_stamp({}, own)
        return dict(by)

    def _mark(n: dict[str, Any], *, via: list[str] | None,
              stamp: dict[str, list[str]] | None) -> None:
        n["status"] = "needs_review"
        n["invalidation_reason"] = reason[:500]
        n["invalidated_at"] = now
        n["updated_at"] = now
        for stale in ("revalidated_at", "revalidation_call_ids", "invalidated_via", "invalidated_by"):
            n.pop(stale, None)
        if via:
            n["invalidated_via"] = list(via)
        if stamp:
            n["invalidated_by"] = dict(stamp)

    for nid in node_ids:
        node = (graph.get("nodes") or {}).get(nid)
        if not node:
            skipped.append(nid)
            continue
        st = node.get("status")
        # Do not disturb superseded/withdrawn/conflict nodes
        if st in ("superseded", "withdrawn", "conflict"):
            skipped.append(nid)
            continue
        if st in CURRENT_BELIEF_STATUSES or st == "needs_review":
            if st != "needs_review":
                _mark(node, via=None, stamp=_stamp_for(nid))
                marked.append(nid)
            else:
                # Questioned again, now in its own right: the new paths join
                # the stamp and the review's time moves, so a read made
                # between the two changes no longer passes.
                node.pop("invalidated_via", None)
                node["invalidated_by"] = _merge_stamp(node.get("invalidated_by"), _stamp_for(nid))
                if not node["invalidated_by"]:
                    node.pop("invalidated_by", None)
                node["invalidated_at"] = now
                node["updated_at"] = now
                touched = True
                remarked.append(nid)
                skipped.append(nid)
        else:
            skipped.append(nid)
        graph["nodes"][nid] = node

    # Also mark every node derived from a marked one (conclusions,
    # recommendations, claims resting on observations), stamping the bases
    # it was marked for.
    from core.claim_graph import list_nodes
    marked_set = set(marked)
    # A base marked again in a later scan carries its new paths and time to
    # what derives from it, so a derived node re-validated on its own is
    # held to the newer change too.
    sources = marked_set | set(remarked)
    for edge in graph.get("edges") or []:
        if edge.get("type") != "derived_from":
            continue
        if edge.get("from") in sources:
            tgt = edge.get("to")
            src = (graph.get("nodes") or {}).get(edge.get("from")) or {}
            n = (graph.get("nodes") or {}).get(tgt)
            if n and n.get("status") in CURRENT_BELIEF_STATUSES:
                _mark(n, via=[str(edge.get("from"))], stamp=src.get("invalidated_by"))
                graph["nodes"][tgt] = n
                if tgt not in marked_set:
                    marked.append(tgt)
                    marked_set.add(tgt)
            elif n and n.get("status") == "needs_review" and n.get("invalidated_via"):
                if str(edge.get("from")) not in n["invalidated_via"]:
                    n["invalidated_via"].append(str(edge.get("from")))
                merged = _merge_stamp(n.get("invalidated_by"), src.get("invalidated_by"))
                if merged:
                    n["invalidated_by"] = merged
                n["invalidated_at"] = now
                n["updated_at"] = now
                touched = True
                graph["nodes"][tgt] = n

    if marked or touched:
        save_graph(case_dir, graph)
    return {"marked": marked, "skipped": skipped}
