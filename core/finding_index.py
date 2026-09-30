"""Stable F-NNN finding IDs mapped to Claim Graph nodes.

Persisted at ``<case>/.atlas/finding_index.json``. IDs are assigned once and
never reshuffled when new claims appear (monotonic counter).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def index_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "finding_index.json"


def empty_index() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": "",
        "next_n": 1,
        "by_node_id": {},  # node_id -> F-NNN
        "by_f_id": {},     # F-NNN -> node_id
    }


def load_index(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = index_path(case_dir)
    if not path.is_file():
        return empty_index()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_index()
    if not isinstance(data, dict):
        return empty_index()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("next_n", 1)
    data.setdefault("by_node_id", {})
    data.setdefault("by_f_id", {})
    return data


def save_index(case_dir: str | os.PathLike, index: dict[str, Any]) -> Path:
    path = index_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    idx = dict(index)
    idx["schema_version"] = SCHEMA_VERSION
    idx["updated_at"] = _utcnow()
    payload = json.dumps(idx, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)
    return path


def ensure_finding_ids(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Assign F-NNN to current-belief claims and conclusions missing an id.

    Also drops index entries whose nodes no longer exist (heal drift).
    """
    from core.claim_graph import CURRENT_BELIEF_STATUSES, load_graph

    idx = load_index(case_dir)
    graph = load_graph(case_dir)
    nodes = graph.get("nodes") or {}
    changed = False

    # Drop stale mappings (node deleted / superseded out of index scope).
    stale = [nid for nid in list(idx.get("by_node_id") or {}) if nid not in nodes]
    for nid in stale:
        fid = idx["by_node_id"].pop(nid, None)
        if fid:
            idx.get("by_f_id", {}).pop(fid, None)
            changed = True

    for nid, node in nodes.items():
        kind = node.get("kind")
        if kind not in ("claim", "conclusion"):
            continue
        st = node.get("status")
        if st not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
            continue
        if nid in idx["by_node_id"]:
            continue
        n = int(idx.get("next_n") or 1)
        fid = f"F-{n:03d}"
        while fid in idx["by_f_id"]:
            n += 1
            fid = f"F-{n:03d}"
        idx["by_node_id"][nid] = fid
        idx["by_f_id"][fid] = nid
        idx["next_n"] = n + 1
        changed = True
    if changed or not index_path(case_dir).is_file():
        save_index(case_dir, idx)
    return idx


def sync_after_graph_write(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Transactional follow-up: claim_graph write ⇒ finding_index catch-up (X7)."""
    try:
        return ensure_finding_ids(case_dir)
    except Exception:
        return load_index(case_dir)


def f_id_for(case_dir: str | os.PathLike, node_id: str) -> str | None:
    idx = load_index(case_dir)
    return idx.get("by_node_id", {}).get(node_id)


def node_id_for(case_dir: str | os.PathLike, f_id: str) -> str | None:
    idx = load_index(case_dir)
    return idx.get("by_f_id", {}).get(f_id)


def nodes_for_report(
    case_dir: str | os.PathLike,
    *,
    scope: str = "case",
    host: str = "",
) -> list[dict[str, Any]]:
    """Return claim/conclusion nodes with stable F-ids for report assembly."""
    from core.claim_graph import (
        CURRENT_BELIEF_STATUSES, load_graph, node_in_report_scope,
    )

    idx = ensure_finding_ids(case_dir)
    graph = load_graph(case_dir)
    out: list[dict[str, Any]] = []
    for nid, node in (graph.get("nodes") or {}).items():
        kind = node.get("kind")
        if kind not in ("claim", "conclusion"):
            continue
        st = node.get("status")
        if st not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
            continue
        if not node_in_report_scope(node, scope, host):
            continue
        fid = idx["by_node_id"].get(nid)
        if not fid:
            continue
        item = dict(node)
        item["finding_id"] = fid
        out.append(item)

    # A conclusion promoted from a claim restates that claim at conclusion
    # rank; the report shows it once, under the conclusion, and keeps the
    # claim's id as an alias so references to it still resolve.
    by_id = {str(n.get("id")): n for n in out}
    folded: set[str] = set()
    for n in out:
        if n.get("kind") != "conclusion":
            continue
        src = str(n.get("promoted_from_claim_id") or "")
        if src and src != str(n.get("id")) and src in by_id:
            alias = by_id[src].get("finding_id")
            aliases = list(n.get("also_recorded_as") or [])
            if alias and alias not in aliases:
                aliases.append(alias)
            n["also_recorded_as"] = aliases
            folded.add(src)
    out = [n for n in out if str(n.get("id")) not in folded]

    def _sort_key(n: dict[str, Any]) -> tuple:
        fid = n.get("finding_id") or "F-9999"
        try:
            num = int(str(fid).split("-", 1)[1])
        except (IndexError, ValueError):
            num = 9999
        return (0 if n.get("kind") == "conclusion" else 1, num)

    out.sort(key=_sort_key)
    return out
