"""The frontier's sweep: once per batch, every entity newly
labelled attacker is counted over the case's tables (the estate count's
native one-pass engine, through tools.tabular.count_values) and over the run's
saved tool outputs (the evidence index of call outputs), and every hit is
written to the incident map as a sighting. The count pass is traced as one
call, so each sighting has a basis. Sightings are signals, never labels;
the map's joins read the listings, so the sweep never does.
"""
from __future__ import annotations

import json
import os
from typing import Any

# Values shorter than this match too much text to be a sighting of one
# entity (a lexical floor, the same as the indicator search's).
_MIN_VALUE = 3


def _tables(case_dir: str) -> list[str]:
    """The case's tables: the estate count's sources."""
    try:
        from core.ioc_pivots import evidence_sources
        from tools.tabular import _kind
        return sorted(rel for rel in evidence_sources(str(case_dir)) if _kind(rel) in ("csv", "jsonl", "xlsx"))
    except Exception:  # noqa: BLE001
        return []


def _evidence_calls(log) -> list[int]:
    """The successful tool calls whose output is evidence (never the run's
    own words), the population of the saved-output search."""
    try:
        from core.forensic_citation import own_words_entry
    except Exception:  # noqa: BLE001
        return []
    return [int(e["call_id"]) for e in list(getattr(log, "_entries", []))
            if e.get("type") == "tool_call" and e.get("success") is not False and e.get("call_id")
            and not own_words_entry(e)]


def _call_host(log, call_id: int, case_dir: str) -> str:
    try:
        from core.provenance import call_provenance
        entry = (log.index().by_call_id or {}).get(int(call_id)) or {}
        hosts = list(call_provenance(entry, case_dir).get("hosts") or [])
        return hosts[0] if len(hosts) == 1 else ""
    except Exception:  # noqa: BLE001
        return ""


def prepare(case_dir: str | os.PathLike, log, entities: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The sweep's inputs, read on the caller's thread: the entities worth
    counting, the case's tables and the evidence calls. None when there is
    nothing to count."""
    ents = [e for e in entities if len(str(e.get("value") or "")) >= _MIN_VALUE]
    if not ents:
        return None
    case = str(case_dir)
    return {"case": case, "entities": len(ents),
            "by_value": {str(e["value"]): int(e["entity_id"]) for e in ents},
            "kinds": {str(e["value"]): str(e.get("kind") or "") for e in ents},
            "tables": _tables(case), "calls": _evidence_calls(log), "counts": {}, "hits_by_call": {}}


def count(job: dict[str, Any]) -> dict[str, Any]:
    """The reading part (any thread): the native count over the tables and
    the search of the saved outputs. Writes nothing but ``job``."""
    if job["tables"]:
        try:
            from tools.tabular import count_values
            job["counts"] = count_values(job["case"], sorted(job["by_value"]), job["tables"],
                                         job["kinds"]).get("counts") or {}
        except Exception:  # noqa: BLE001
            job["counts"] = {}
    if job["calls"]:
        try:
            from core.evidence_index import find_in_calls
            job["hits_by_call"] = {v: sorted({cid for cid, _w in find_in_calls(v, job["calls"])})
                                   for v in job["by_value"]}
        except Exception:  # noqa: BLE001
            job["hits_by_call"] = {}
    return job


def apply(log, job: dict[str, Any]) -> dict[str, Any]:
    """The writing part (the run's own thread): the pass as one traced call
    and every hit as a sighting with that call as its basis."""
    from core import incident_map
    m = incident_map.open(job["case"])
    if m is None:
        return {"entities": 0, "sightings": 0, "call_id": 0, "notes": []}
    case, by_value, counts, hits_by_call = job["case"], job["by_value"], job["counts"], job["hits_by_call"]
    summary = {"values": sorted(by_value), "tables": len(job["tables"]),
               "table_hits": {v: sorted(src for src, c in (per or {}).items()
                                        if (c or {}).get("full") or (c or {}).get("name"))
                              for v, per in counts.items()},
               "call_hits": hits_by_call}
    cid = log.record_tool_call("<py>:frontier_sweep", True, False, 0, 0,
                               stdout_excerpt=json.dumps(summary, default=str)[:20000])
    from core.evidence_links import host_of_path
    rows: list[dict[str, Any]] = []
    for value, per in counts.items():
        eid = by_value.get(value)
        for src, c in (per or {}).items():
            if not ((c or {}).get("full") or (c or {}).get("name")):
                continue
            host = host_of_path(case, src)
            if host and eid:
                rows.append({"entity_id": eid, "host": host, "source": src, "call_id": cid,
                             "time": (c or {}).get("first") or None})
    for value, call_ids in hits_by_call.items():
        eid = by_value.get(value)
        for call_id in call_ids:
            host = _call_host(log, call_id, case)
            if host and eid:
                rows.append({"entity_id": eid, "host": host, "source": f"call:{call_id}", "call_id": call_id})
    stored = m.add_sightings(rows) if rows else {"stored": 0, "notes": []}
    return {"entities": job["entities"], "sightings": int(stored.get("stored") or 0), "call_id": cid,
            "notes": list(stored.get("notes") or [])}


def sweep(case_dir: str | os.PathLike, log, entities: list[dict[str, Any]]) -> dict[str, Any]:
    """Count ``entities`` ([{entity_id, value, kind}]) over the tables and
    the saved outputs and write the hits as sightings, on this thread.
    Returns {entities, sightings, call_id, notes}."""
    from core import incident_map
    job = prepare(case_dir, log, entities) if incident_map.open(case_dir) is not None else None
    if job is None:
        return {"entities": 0, "sightings": 0, "call_id": 0, "notes": []}
    return apply(log, count(job))
