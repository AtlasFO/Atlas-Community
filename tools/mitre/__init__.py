"""Cached access to the MITRE ATT&CK technique + group tables.

The tables are built once by `python -m tools.mitre.build_mitre_cache` from
the MITRE CTI public JSON. Loaders memoise the parsed dict and re-read only
when the file's mtime changes — call sites can hit `load_techniques()` /
`load_groups()` in tight loops without re-parsing.
"""
import functools
import json
import os
import sys
from typing import Optional

DEFAULT_TECHNIQUES_PATH = os.environ.get(
    "ATLAS_MITRE_TABLE",
    os.path.expanduser("~/cases/.common/mitre_techniques.json"),
)
DEFAULT_GROUPS_PATH = os.environ.get(
    "ATLAS_MITRE_GROUPS",
    os.path.expanduser("~/cases/.common/mitre_groups.json"),
)
DEFAULT_SOFTWARE_PATH = os.environ.get(
    "ATLAS_MITRE_SOFTWARE",
    os.path.expanduser("~/cases/.common/mitre_software.json"),
)
DEFAULT_MITIGATIONS_PATH = os.environ.get(
    "ATLAS_MITRE_MITIGATIONS",
    os.path.expanduser("~/cases/.common/mitre_mitigations.json"),
)


@functools.lru_cache(maxsize=4)
def _load_json(path: str, mtime_token: float) -> dict:
    """Internal: load + parse JSON, memoised by (path, mtime)."""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _read_with_mtime_key(path: str, empty: dict) -> dict:
    if not os.path.exists(path):
        return empty
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return empty
    return _load_json(path, mtime) or empty


def load_techniques(path: Optional[str] = None) -> dict:
    """Return the techniques table:
        {"_meta": {...}, "techniques": {tid: {name, tactic, description, keywords}}}.
    """
    p = path or DEFAULT_TECHNIQUES_PATH
    return _read_with_mtime_key(p, {"techniques": {}})


def load_groups(path: Optional[str] = None) -> dict:
    """Return the groups table:
        {"_meta": {...}, "groups": {gid: {name, aliases, description, technique_ids}}}.
    """
    p = path or DEFAULT_GROUPS_PATH
    return _read_with_mtime_key(p, {"groups": {}})


def load_software(path: Optional[str] = None) -> dict:
    """Return the software table:
        {"_meta": {...}, "software": {sid: {name, type, aliases, description, group_ids}}}.

    Missing file (cache built before software extraction, or never built)
    returns an empty table so callers degrade gracefully — attribution's
    malware_score simply contributes nothing.
    """
    p = path or DEFAULT_SOFTWARE_PATH
    return _read_with_mtime_key(p, {"software": {}})


def load_mitigations(path: Optional[str] = None) -> dict:
    """Return the mitigations table:
        {"_meta": {...}, "mitigations": {mid: {name, description, technique_ids}},
         "by_technique": {tid: [mid, ...]}}.

    A cache built before mitigations were extracted returns an empty table, so
    derived recommendations simply do not happen rather than failing.
    """
    p = path or DEFAULT_MITIGATIONS_PATH
    if not os.path.exists(p):
        # The cases root has no copy (a checkout without an installed
        # cases tree): the table the repository ships is the same one.
        shipped = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                               "share", ".common", "mitre_mitigations.json")
        if os.path.exists(shipped):
            p = shipped
    return _read_with_mtime_key(p, {"mitigations": {}, "by_technique": {}})


def mitigations_for(tids: list[str], path: Optional[str] = None) -> list[dict]:
    """Mitigations that apply to any of `tids`, most widely applicable first.

    Each entry: {id, name, description, technique_ids: the given tids it
    covers}. A sub-technique falls back to its parent's mitigations.
    """
    table = load_mitigations(path)
    by_tech = table.get("by_technique") or {}
    mits = table.get("mitigations") or {}
    hits: dict[str, set[str]] = {}
    for tid in tids:
        tid = (tid or "").strip().upper()
        mids = by_tech.get(tid) or by_tech.get(tid.split(".")[0]) or []
        for mid in mids:
            hits.setdefault(mid, set()).add(tid)
    out = [{"id": mid, "name": (mits.get(mid) or {}).get("name", ""),
            "description": (mits.get(mid) or {}).get("description", ""),
            "technique_ids": sorted(covered)}
           for mid, covered in hits.items()]
    out.sort(key=lambda m: (-len(m["technique_ids"]), m["id"]))
    return out


def validate(tid: str, path: Optional[str] = None) -> dict:
    """Return {exists, name, tactic, description} for a technique id.

    Revoked/deprecated IDs still exist (they are real, citable ATT&CK IDs);
    the result then carries `status` and, when ATT&CK renumbered the
    technique, `superseded_by` with the current ID.
    """
    table = load_techniques(path)
    info = table.get("techniques", {}).get(tid)
    if info:
        out = {
            "exists": True,
            "technique_id": tid,
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "description": info.get("description", ""),
        }
        if info.get("status"):
            out["status"] = info["status"]
            if info.get("superseded_by"):
                out["superseded_by"] = info["superseded_by"]
        return out
    return {
        "exists": False,
        "technique_id": tid,
        "available_count": len(table.get("techniques", {}) or {}),
    }


def groups_for_techniques(tids: list[str], path: Optional[str] = None) -> list[dict]:
    """Return groups whose technique_ids overlap the given tids.

    Sorted by overlap size descending. Each entry: {group_id, name, aliases,
    overlap_techniques, total_techniques}. Used by the attribution pipeline
    to surface candidate threat-actor matches.
    """
    table = load_groups(path)
    groups = table.get("groups", {}) or {}
    observed = set(tids or [])
    if not observed or not groups:
        return []
    candidates: list[dict] = []
    for gid, info in groups.items():
        gtids = set(info.get("technique_ids") or [])
        if not gtids:
            continue
        overlap = observed & gtids
        if not overlap:
            continue
        candidates.append({
            "group_id": gid,
            "name": info.get("name", ""),
            "aliases": info.get("aliases", []) or [],
            "overlap_techniques": sorted(overlap),
            "total_techniques": len(gtids),
        })
    candidates.sort(key=lambda c: (-len(c["overlap_techniques"]), c["group_id"]))
    return candidates


def cache_info() -> dict:
    """Diagnostic — returns lru_cache hits/misses for the loader."""
    return _load_json.cache_info()._asdict()
