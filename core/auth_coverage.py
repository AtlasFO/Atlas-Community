"""Auth success coverage gaps over Claim Graph observations.

An endpoint is *contested* when the graph has both auth.failure and
auth.success observations for it (structural coexistence — no hostile vocab).

A contested auth.success is a gap when no finding/claim positively frames
success for that endpoint on the same date (when known).
"""
from __future__ import annotations

import os
from typing import Any, Optional

from core.auth_ontology import (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    positively_frames_success,
)
from core.auth_events import is_ignorable_endpoint


def _trace_findings(case_dir: str | os.PathLike | None = None) -> list[dict]:
    """Trace findings the run still asserts; a withdrawn one covers nothing."""
    try:
        from core.claim_graph import asserted_finding_entries
        from core.execution_log import log
        return asserted_finding_entries(
            [e for e in log._entries if e.get("type") == "finding"], case_dir)
    except Exception:
        return []


def _auth_observations(case_dir: str | os.PathLike) -> list[dict]:
    from core.claim_graph import CURRENT_BELIEF_STATUSES, load_graph, list_nodes
    graph = load_graph(case_dir)
    out = []
    for n in list_nodes(graph, kind="observation"):
        if n.get("status") not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
            continue
        attrs = n.get("attrs") if isinstance(n.get("attrs"), dict) else {}
        ec = attrs.get("event_class")
        if ec not in (EVENT_AUTH_SUCCESS, EVENT_AUTH_FAILURE):
            continue
        endpoint = str(attrs.get("source_endpoint") or "")
        if is_ignorable_endpoint(endpoint):
            continue
        out.append(n)
    return out


def _claim_cover_texts(case_dir: str | os.PathLike) -> list[str]:
    """Statements from claims/conclusions plus finding descriptions."""
    texts: list[str] = []
    try:
        from core.claim_graph import (
            CURRENT_BELIEF_STATUSES, load_graph, list_nodes,
        )
        graph = load_graph(case_dir)
        for kind in ("claim", "conclusion"):
            for n in list_nodes(graph, kind=kind):
                if n.get("status") not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
                    continue
                texts.append(str(n.get("statement") or ""))
    except Exception:
        pass
    for f in _trace_findings(case_dir):
        texts.append(str(f.get("description") or ""))
    return texts


def _is_covered(endpoint: str, when: str, cover_texts: list[str]) -> bool:
    for desc in cover_texts:
        if endpoint not in desc:
            continue
        if not positively_frames_success(desc):
            continue
        if when and when not in desc:
            continue
        return True
    return False


def auth_success_coverage_gaps(
    case_dir: str | os.PathLike,
) -> dict[str, Any]:
    """Return unreported contested auth.success observations."""
    obs = _auth_observations(case_dir)
    by_endpoint: dict[str, dict[str, list]] = {}
    for n in obs:
        attrs = n["attrs"]
        ep = str(attrs.get("source_endpoint") or "")
        slot = by_endpoint.setdefault(
            ep, {"success": [], "failure": []}
        )
        if attrs.get("event_class") == EVENT_AUTH_SUCCESS:
            slot["success"].append(n)
        else:
            slot["failure"].append(n)

    contested = {
        ep: slot for ep, slot in by_endpoint.items()
        if slot["success"] and slot["failure"]
    }
    cover_texts = _claim_cover_texts(case_dir)

    unreported: list[dict] = []
    success_seen = 0
    for ep, slot in contested.items():
        for n in slot["success"]:
            success_seen += 1
            attrs = n["attrs"]
            when = str(attrs.get("when") or "")
            if _is_covered(ep, when, cover_texts):
                continue
            unreported.append({
                "ip": ep,
                "endpoint": ep,
                "date": when,
                "when": when,
                "logon_type": str(attrs.get("auth_factor") or ""),
                "auth_factor": str(attrs.get("auth_factor") or ""),
                "call_id": attrs.get("source_call_id"),
                "observation_id": n.get("id"),
                "snippet": (n.get("statement") or "")[:200],
                "tool": "",
            })

    unreported.sort(key=lambda e: (e["ip"], e["date"], e["logon_type"]))
    if not contested:
        return {
            "success": True,
            "hostile_ips": 0,
            "contested_endpoints": 0,
            "success_events_seen": 0,
            "unreported_count": 0,
            "unreported": [],
            "note": (
                "no contested endpoints (need both auth.failure and "
                "auth.success observations for the same source endpoint)"
            ),
        }
    return {
        "success": True,
        "hostile_ips": len(contested),
        "contested_endpoints": len(contested),
        "success_events_seen": success_seen,
        "unreported_count": len(unreported),
        "unreported": unreported,
        "hint": (
            "Each unreported entry is a SUCCESSFUL authentication for an "
            "endpoint that also has auth.failure observations in this case, "
            "but no finding/claim reports successful access for that "
            "endpoint/date. Record a finding or claim, or note why it is "
            "benign. A failure-only narrative does not cover a success, and "
            "a success on a different date does not cover this one."
        ),
    }


def resolve_case_dir_for_auth() -> Optional[str]:
    try:
        from core.claim_graph import resolve_case_dir
        return resolve_case_dir(None)
    except Exception:
        return None
