"""Ingest auth events into Claim Graph observations.

Structured tabular exports (EvtxECmd / auth CSVs) are preferred; unstructured
tool stdout/spills remain a fallback via ``auth_events``.
"""
from __future__ import annotations

import os
from typing import Any, Iterable, Optional

from core.auth_events import AuthEvent, extract_auth_events_from_texts
from core.auth_ontology import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS
from core.auth_tabular import (
    csv_paths_from_tool_entry,
    extract_auth_events_from_csv,
    looks_like_auth_tabular,
)

# Watchers report change notifications, not records; everything else that
# is not evidence is the run's own state (core.forensic_citation).
_WATCHER_PREFIXES = ("monitor_",)


def _not_evidence(e: dict) -> bool:
    from core.forensic_citation import own_words_entry
    tool = str(e.get("mcp_tool") or e.get("cmd") or "")
    return (own_words_entry(e)
            or own_words_entry({"type": "tool_call", "cmd": f"<py>:{tool}"})
            or tool.startswith(_WATCHER_PREFIXES))


def _read_spill(path: str, cap: int = 4_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(cap)
    except OSError:
        return ""


def evidence_texts_from_trace(entries: list[dict] | None = None) -> list[tuple]:
    """(call_id, label, text) for successful evidence-bearing tool_calls."""
    if entries is None:
        from core.execution_log import log
        entries = list(log._entries)
    out: list[tuple] = []
    for e in entries:
        if e.get("type") != "tool_call" or not e.get("success"):
            continue
        tool = str(e.get("mcp_tool") or "")
        if _not_evidence(e):
            continue
        text = str(e.get("stdout_excerpt") or "")
        spill = e.get("stdout_file")
        if spill:
            extra = _read_spill(str(spill))
            if extra:
                text = f"{text}\n{extra}" if text else extra
        if text.strip():
            out.append((
                e.get("call_id"),
                tool or str(e.get("cmd") or "?").split()[0],
                text,
            ))
    return out


def _statement_for(ev: AuthEvent) -> str:
    kind = "Successful" if ev.event_class == EVENT_AUTH_SUCCESS else "Failed"
    bits = [f"{kind} authentication from {ev.source_endpoint}"]
    if ev.when:
        bits.append(f"on {ev.when}")
    if ev.auth_factor:
        bits.append(f"(auth factor {ev.auth_factor})")
    return " ".join(bits)


def _existing_fingerprints(case_dir: str | os.PathLike) -> dict[str, str]:
    """``{fingerprint: node_id}`` for every auth observation already held."""
    from core.claim_graph import load_graph, list_nodes
    graph = load_graph(case_dir)
    out: dict[str, str] = {}
    for n in list_nodes(graph, kind="observation"):
        attrs = n.get("attrs") if isinstance(n.get("attrs"), dict) else {}
        fp = attrs.get("fingerprint")
        if fp:
            out[str(fp)] = str(n.get("id") or "")
    return out


def _host_for(ev: AuthEvent, known_hosts: list[str]) -> str:
    """The case host an auth event belongs to, if its snippet names one."""
    from core.forensic_citation import host_mentioned
    for label in known_hosts:
        if host_mentioned(label, ev.snippet or ""):
            return label
    return ""


def _record_sighting(case_dir: str | os.PathLike, node_id: str,
                     ev: AuthEvent) -> None:
    """A repeat sighting adds provenance to the existing observation."""
    from core.claim_graph import _LOCK, load_graph, save_graph
    with _LOCK:
        graph = load_graph(case_dir)
        node = (graph.get("nodes") or {}).get(node_id)
        if not isinstance(node, dict):
            return
        attrs = node.setdefault("attrs", {})
        seen = list(attrs.get("source_call_ids") or [])
        if ev.source_call_id is not None and ev.source_call_id not in seen:
            seen.append(ev.source_call_id)
            attrs["source_call_ids"] = seen
            ev_list = node.setdefault("evidence", [])
            if isinstance(ev_list, list):
                ev_list.append({"artifact": "auth_event",
                                "locator": ev.snippet[:120],
                                "call_id": ev.source_call_id})
        attrs["sightings"] = int(attrs.get("sightings") or 1) + 1
        save_graph(case_dir, graph)


def upsert_auth_events(
    case_dir: str | os.PathLike,
    events: Iterable[AuthEvent],
    *,
    source: str = "extract",
) -> dict[str, Any]:
    """Upsert AuthEvent records as Claim Graph observations (dedupe by fingerprint)."""
    from core.claim_graph import add_observation

    existing = _existing_fingerprints(case_dir)
    try:
        from core.forensic_citation import known_case_hosts
        hosts = known_case_hosts(case_dir)
    except Exception:  # noqa: BLE001
        hosts = []
    created: list[str] = []
    skipped = 0
    events_list = list(events)
    for ev in events_list:
        fp = ev.fingerprint()
        if fp in existing:
            # Same fact seen again — more provenance, not a second fact.
            try:
                _record_sighting(case_dir, existing[fp], ev)
            except Exception:  # noqa: BLE001
                pass
            skipped += 1
            continue
        attrs = {
            "event_class": ev.event_class,
            "source_endpoint": ev.source_endpoint,
            "when": ev.when,
            "auth_factor": ev.auth_factor,
            "platform": ev.platform,
            "source_call_id": ev.source_call_id,
            "source_call_ids": ([ev.source_call_id]
                                if ev.source_call_id is not None else []),
            "sightings": 1,
            "fingerprint": fp,
            "ingest_source": source,
        }
        evidence = None
        if ev.source_call_id is not None:
            evidence = [{
                "artifact": "auth_event",
                "locator": ev.snippet[:120],
                "call_id": ev.source_call_id,
            }]
        r = add_observation(
            case_dir,
            _statement_for(ev),
            confidence="CONFIRMED",
            evidence=evidence,
            host=_host_for(ev, hosts),
            reasoning=f"Auth observation via {source} ({ev.tool or 'unknown'})",
            attrs=attrs,
        )
        if r.get("success"):
            created.append(r["node_id"])
            existing[fp] = r["node_id"]
        else:
            skipped += 1
    return {
        "success": True,
        "events_seen": len(events_list),
        "created": created,
        "created_count": len(created),
        "skipped": skipped,
        "success_count": sum(
            1 for e in events_list if e.event_class == EVENT_AUTH_SUCCESS
        ),
        "failure_count": sum(
            1 for e in events_list if e.event_class == EVENT_AUTH_FAILURE
        ),
        "source": source,
    }


def ingest_auth_observations_from_csv(
    case_dir: str | os.PathLike,
    csv_path: str | os.PathLike,
    *,
    call_id: Optional[int] = None,
    tool: str = "",
) -> dict[str, Any]:
    """Structured ingest from one auth tabular export."""
    events = extract_auth_events_from_csv(
        csv_path, call_id=call_id, tool=tool or "tabular",
    )
    return upsert_auth_events(case_dir, events, source="structured_csv")


def _structured_events_from_trace(entries: list[dict]) -> list[AuthEvent]:
    merged: dict[str, AuthEvent] = {}
    for e in entries:
        if e.get("type") != "tool_call" or not e.get("success"):
            continue
        tool = str(e.get("mcp_tool") or e.get("cmd") or "")
        if _not_evidence(e):
            continue
        cid = e.get("call_id")
        for path in csv_paths_from_tool_entry(e):
            if not looks_like_auth_tabular(path):
                continue
            for ev in extract_auth_events_from_csv(
                path, call_id=cid, tool=tool or "tabular",
            ):
                merged[ev.fingerprint()] = ev
    return list(merged.values())


def ingest_auth_observations_from_trace(
    case_dir: str | os.PathLike,
    *,
    entries: list[dict] | None = None,
) -> dict[str, Any]:
    """Ingest auth observations: structured CSV first, text extract fallback."""
    if entries is None:
        from core.execution_log import log
        entries = list(log._entries)

    structured = _structured_events_from_trace(entries)
    structured_fps = {e.fingerprint() for e in structured}
    text_events = extract_auth_events_from_texts(evidence_texts_from_trace(entries))
    # Prefer structured fingerprints when both paths see the same event.
    fallback = [e for e in text_events if e.fingerprint() not in structured_fps]

    r_struct = upsert_auth_events(
        case_dir, structured, source="structured_csv",
    )
    r_text = upsert_auth_events(
        case_dir, fallback, source="text_extract",
    )
    return {
        "success": True,
        "events_seen": r_struct["events_seen"] + r_text["events_seen"],
        "created": list(r_struct["created"]) + list(r_text["created"]),
        "created_count": r_struct["created_count"] + r_text["created_count"],
        "skipped": r_struct["skipped"] + r_text["skipped"],
        "success_count": r_struct["success_count"] + r_text["success_count"],
        "failure_count": r_struct["failure_count"] + r_text["failure_count"],
        "structured_events": r_struct["events_seen"],
        "text_fallback_events": r_text["events_seen"],
    }
