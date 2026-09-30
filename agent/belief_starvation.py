"""Belief-starvation latch — force finding formalisation after evidence hits.

Failure class: many successful table.* /
parser contacts (timeline filled) while ``misc.record_finding`` is never
called. Soft DAIR nudges alone are ignored; coverage probes look like
"progress" so stall soft/hard arrives too late.

This module is the hard twin of that nudge:
  * count **substantive evidence contacts** (successful content tools with
    non-empty hits, or successful single-file parsers)
  * if contacts ≥ threshold and still 0 findings → latch
  * while latched: refuse further exploratory evidence tools; require
    ``misc.record_finding`` (or task disposition) before more gathering

No case/IOC hardcoding — thresholds and tool-class patterns only.
"""
from __future__ import annotations

import json
import re
from typing import Any

# After this many substantive contacts with zero findings, latch engages.
MIN_SUBSTANTIVE_CONTACTS = 3

_FINDING_TOOL_RE = re.compile(r"record_finding", re.IGNORECASE)

# Tools that examine artifact *content* (not inventory/list/schema-only).
_CONTACT_TOOL_RE = re.compile(
    r"(?:table_query|table_pivot|table_grep|"
    r"table\.table_query|table\.table_pivot|table\.table_grep|"
    r"ez_evtxecmd|ez\.evtxecmd|"
    r"chainsaw_hunt|hayabusa|"
    r"ez_mftecmd|ez_amcacheparser|ez_prefetch|"
    r"tsk_fls|tsk\.fls|tsk_icat|tsk\.icat|"
    r"strings_grep|strings\.strings_grep|search_evidence|"
    r"vol_|vol\.|regripper)",
    re.IGNORECASE,
)

# While latched, only these tool families may run (formalise / disposition /
# schema bind / assess). Everything else is exploratory gathering.
_ALLOWED_WHILE_LATCHED_RE = re.compile(
    r"(?:record_finding|update_investigation_task|"
    r"record_agent_message|record_curiosity_probe|"
    r"reason_evaluate_finding|reason_confidence_score|reason_cite_check|"
    r"reason_hypothesize|"  # may refine, but must not replace record
    r"dair_assess|"
    r"table_schema|table\.table_schema|"
    r"ledger_status|mark_blocked|"
    r"current_investigation_state|"
    r"atlas_finish|"
    r"start_execution_log|inventory_evidence)",
    re.IGNORECASE,
)

_HIT_RE = re.compile(
    r'"(?:matched_rows|returned_rows|hit_count|rows_returned|event_count|'
    r'match_count|result_count|ascii_lines)"'
    r"\s*:\s*([1-9]\d*)",
)


def findings_recorded(entries: list[dict[str, Any]] | None) -> int:
    n = 0
    for e in entries or []:
        if e.get("type") == "finding":
            n += 1
            continue
        if e.get("type") != "tool_call":
            continue
        blob = " ".join(
            str(e.get(k) or "") for k in ("mcp_tool", "tool", "cmd")
        )
        if _FINDING_TOOL_RE.search(blob) and e.get("success") is True:
            n += 1
    return n


MIN_NOTE_CHARS = 200


def notes_recorded(entries: list[dict[str, Any]] | None) -> int:
    """Substantive evidence notes (misc.record_agent_message).

    The latch's own message tells the model that descriptions of the
    evidence — sizes, formats, column lists — are notes, not findings. A
    latch that refuses such a note pushes the model to record a description
    of the evidence (a count of dropped connections, say) as a SUSPECTED
    finding just to get past it. Writing down what was seen is formalisation.
    """
    return sum(
        1 for e in entries or []
        if e.get("type") == "investigation_narration"
        and len(str(e.get("content") or "")) >= MIN_NOTE_CHARS
    )


def _tool_blob(entry: dict[str, Any]) -> str:
    return " ".join(
        str(entry.get(k) or "") for k in ("mcp_tool", "tool", "cmd")
    )


def _result_blob(entry: dict[str, Any]) -> str:
    parts = [
        entry.get("output"),
        entry.get("result"),
        entry.get("stdout"),
        entry.get("error"),
        entry.get("stderr"),
    ]
    try:
        return json.dumps(parts, default=str)
    except Exception:
        return " ".join(str(p) for p in parts if p)


def is_substantive_contact(entry: dict[str, Any]) -> bool:
    """True for a successful content-tool call that produced usable hits.

    Schema-only / inventory / failed gates do not count. A successful
    single-file parser (EvtxECmd etc.) counts even when row counts are not
    in the payload — the artifact was examined.
    """
    if entry.get("type") != "tool_call":
        return False
    if entry.get("success") is False:
        return False
    tool = _tool_blob(entry)
    if not _CONTACT_TOOL_RE.search(tool):
        return False
    # Explicit gate failures sometimes still stamped success=False above;
    # also refuse known non-contact gates in the body.
    body = _result_blob(entry)
    if any(g in body for g in (
        '"gate": "unknown_columns"',
        '"gate":"unknown_columns"',
        '"gate": "schema_first_required"',
        '"gate": "schema_columns_absent"',
        '"gate":"schema_columns_absent"',
        '"gate": "wrong_input_kind"',
        '"gate": "empty_tabular"',
        '"gate": "belief_starvation"',
    )):
        return False
    # Search-style tools: require a positive hit count when present.
    if re.search(r"table_(?:query|pivot|grep)|table\.table_|strings_grep|"
                 r"search_evidence", tool, re.I):
        m = _HIT_RE.search(body)
        if m:
            return int(m.group(1)) > 0
        # Success without hit field — treat as contact only if not valid_zero
        if '"valid_zero": true' in body or '"valid_zero":true' in body:
            return False
        if '"matched_rows": 0' in body or '"matched_rows":0' in body:
            return False
        # Successful table_query after schema often omits fields in truncated
        # log slices — count success as contact (caller still needs ≥3).
        return entry.get("success") is True
    # Parsers / hunters: success is enough.
    return True


def substantive_contact_count(entries: list[dict[str, Any]] | None) -> int:
    return sum(1 for e in entries or [] if is_substantive_contact(e))


def active_claim_count(case_dir) -> int:
    """Claims the case already holds. The latch reads the trace of *this*
    process; after a restart the trace is empty while the claim graph is
    not, so a latch reading the trace alone fires on a case that already
    holds findings and spends the wrap-up window on findings that exist."""
    if not case_dir:
        return 0
    try:
        from core.claim_graph import load_graph
        nodes = (load_graph(case_dir).get("nodes") or {}).values()
    except Exception:  # noqa: BLE001
        return 0
    return sum(1 for n in nodes if isinstance(n, dict)
               and n.get("kind") in ("claim", "conclusion")
               and n.get("status") not in ("superseded", "withdrawn", "refuted"))


def starvation_latched(
    entries: list[dict[str, Any]] | None,
    *,
    min_contacts: int = MIN_SUBSTANTIVE_CONTACTS,
    case_dir=None,
) -> bool:
    """Latch when evidence was hit but nothing was formalised — neither as a
    finding nor as a substantive evidence note."""
    if findings_recorded(entries) > 0 or notes_recorded(entries) > 0:
        return False
    if case_dir and active_claim_count(case_dir) > 0:
        return False
    return substantive_contact_count(entries) >= min_contacts


def tool_allowed_while_latched(tool_name: str) -> bool:
    name = tool_name or ""
    if _ALLOWED_WHILE_LATCHED_RE.search(name):
        return True
    # dotted aliases
    dotted = name.replace("_", ".", 1)
    return bool(_ALLOWED_WHILE_LATCHED_RE.search(dotted))


def format_starvation_message(
    *,
    contacts: int,
    findings: int,
    dair_established: bool = True,
) -> str:
    # record_finding is refused until a DAIR phase exists; a model that learns
    # that only from the refusal spends turns on it. Say it first.
    lead = ("" if dair_established else
            "No DAIR phase is established yet — call dair.dair_assess FIRST "
            "(misc.record_finding is refused without it), then record.\n")
    return (
        "[belief-starvation latch] " + lead +
        f"{contacts} substantive evidence contact(s) with "
        f"{findings} recorded finding(s). Further exploratory table.*/disk/"
        "parser calls are REFUSED until you formalise observations.\n"
        "Required next steps (pick at least one):\n"
        "  1. misc.record_finding for each confirmed/likely fact from the "
        "recent table/parser hits (use linked_call_id / input_call_ids from "
        "those tool calls; SUSPECTED/LIKELY is fine — do not wait for a "
        "perfect evaluate ritual). A finding bears on the case questions: "
        "an actor, an action, an artifact's state, a time. Descriptions of "
        "the evidence itself — sizes, formats, column lists, partition "
        "layouts, which date a file holds — are notes for "
        "misc.record_agent_message, not findings; a substantive note "
        f"({MIN_NOTE_CHARS}+ characters) lifts this latch as well.\n"
        "  2. misc.update_investigation_task to answered/partial/"
        "blocked_missing_evidence when a CASE task is dispositioned.\n"
        "  3. If a hit was a true dead-end, say so in a finding "
        "(limitation/absence with evidence call ids) — do not keep probing.\n"
        "Allowed while latched: record_finding, record_agent_message, "
        "update_investigation_task, table.table_schema, dair_assess, coverage.ledger_status/"
        "mark_blocked, reason.evaluate_finding/cite_check/confidence_score.\n"
        "Blocked: new table_query/pivot/grep, TSK/img/EZ bulk parsers, "
        "strings/vol sweeps."
    )


def starvation_refusal(tool_name: str, *, contacts: int) -> str:
    """JSON refusal body for an exploratory tool while latched."""
    payload = {
        "success": False,
        "gate": "belief_starvation",
        "error": (
            f"{tool_name!r} refused: belief-starvation latch active after "
            f"{contacts} substantive evidence contact(s) with 0 findings. "
            "Call misc.record_finding for a fact that bears on the case, or "
            f"misc.record_agent_message ({MIN_NOTE_CHARS}+ characters) with "
            "what you saw when it does not, before more exploratory evidence work."
        ),
        "redirect_to": "misc.record_finding",
        "alternative": "misc.record_agent_message",
        "next_required_tool": "misc.record_finding",
        "hint": (
            "Formalise recent table/parser hits as findings with lineage; "
            "SUSPECTED/LIKELY allowed without a prior reason.evaluate."
        ),
        "substantive_contacts": contacts,
    }
    return json.dumps(payload, ensure_ascii=False)


def classify_result_as_contact(tool_name: str, result: str) -> bool:
    """Loop-side helper: did this tool result count as a substantive contact?"""
    entry = {
        "type": "tool_call",
        "mcp_tool": tool_name,
        "success": True,
        "output": result,
    }
    # Parse success from body
    low = (result or "").lower()
    if low.startswith(("tool error", "error", "tool info")):
        entry["success"] = False
    if '"success": false' in low or '"success":false' in low:
        entry["success"] = False
    return is_substantive_contact(entry)
