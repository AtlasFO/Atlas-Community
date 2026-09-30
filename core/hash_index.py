"""Which files in a case carry the same content.

A copy is a copy wherever it sits: a carved file that equals an evidence
file, an export that equals a mail attachment, two images that are one.
Every content hash a tool computes is recorded here under the
case-relative path, and a digest already recorded under another path is
handed back to the caller as those other paths. Evidence files need no
hashing by the model: the catalog's full fingerprints count as recorded.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Iterable

INDEX_REL = os.path.join(".atlas", "hash_index.json")
_LOCK = threading.Lock()


def rel_path(case_dir: str, path: str) -> str:
    """``path`` relative to the case root with forward slashes, or the
    absolute path when it lies outside the case."""
    root = os.path.realpath(case_dir)
    real = os.path.realpath(path)
    if real == root or real.startswith(root + os.sep):
        return os.path.relpath(real, root).replace(os.sep, "/")
    return real


def source_of(rel: str) -> str:
    """The case area a path belongs to: its first directory, "." for a file
    in the case root, "outside" for a path beyond it."""
    if os.path.isabs(rel):
        return "outside"
    return rel.split("/", 1)[0] if "/" in rel else "."


def _index_path(case_dir: str) -> str:
    return os.path.join(case_dir, INDEX_REL)


def _load(case_dir: str) -> dict[str, list[dict]]:
    try:
        with open(_index_path(case_dir), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(case_dir: str, index: dict) -> None:
    path = _index_path(case_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=1)
    os.replace(tmp, path)


def _catalog_paths_by_sha(case_dir: str) -> dict[str, list[str]]:
    """Evidence paths by content hash, from the catalog's full fingerprints
    only: a sampled fingerprint is not a content hash."""
    try:
        from core.evidence_catalog import load_catalog
        units = load_catalog(case_dir).get("units") or {}
    except Exception:  # noqa: BLE001 - the catalog is an aid, never a blocker
        return {}
    out: dict[str, list[str]] = {}
    for unit in units.values():
        if not isinstance(unit, dict) or unit.get("fingerprint_mode") != "full":
            continue
        sha, path = unit.get("content_sha256"), unit.get("path")
        if sha and path:
            out.setdefault(str(sha), []).append(str(path).replace(os.sep, "/"))
    return out


def _evidence_first(rows: Iterable[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r["source"] != "evidence", r["path"]))


def record(case_dir: str, entries: Iterable[tuple[str, str]]) -> dict[str, list[dict]]:
    """Record ``(path, sha256)`` pairs. Returns, for each recorded path that
    shares its content with other paths in the case, those other paths as
    ``{"path", "source"}`` rows, evidence first."""
    matches: dict[str, list[dict]] = {}
    with _LOCK:
        index = _load(case_dir)
        catalog = _catalog_paths_by_sha(case_dir)
        changed = False
        for path, sha in entries:
            if not sha:
                continue
            rel = rel_path(case_dir, path)
            rows = index.setdefault(sha, [])
            others = {r["path"]: r for r in rows
                      if isinstance(r, dict) and r.get("path") and r["path"] != rel}
            for p in catalog.get(sha, ()):
                if p != rel:
                    others.setdefault(p, {"path": p, "source": source_of(p)})
            if all(r.get("path") != rel for r in rows if isinstance(r, dict)):
                rows.append({"path": rel, "source": source_of(rel)})
                changed = True
            if others:
                matches[rel] = _evidence_first(others.values())
        if changed:
            _save(case_dir, index)
    return matches


def identical_groups(case_dir: str, limit: int = 10) -> list[dict]:
    """Contents present under more than one path, catalog and recorded
    hashes combined: ``{"sha256", "paths"}`` rows, the most copied first."""
    groups: dict[str, dict[str, dict]] = {}
    for sha, paths in _catalog_paths_by_sha(case_dir).items():
        for p in paths:
            groups.setdefault(sha, {})[p] = {"path": p, "source": source_of(p)}
    for sha, rows in _load(case_dir).items():
        for r in rows:
            if isinstance(r, dict) and r.get("path"):
                groups.setdefault(sha, {}).setdefault(r["path"], r)
    out = [{"sha256": sha, "paths": [r["path"] for r in _evidence_first(rows.values())]}
           for sha, rows in groups.items() if len(rows) > 1]
    out.sort(key=lambda g: (-len(g["paths"]), g["sha256"]))
    return out[:limit]
