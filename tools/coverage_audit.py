"""Pre-report coverage audits: capability breadth, and work nothing rests on.

Two questions a reviewer asks that the investigation should have answered
first. Which investigative capabilities does this case's evidence call for
that were never exercised at all, and which successful, output-producing
calls did no finding ever rest on. Registered on the `coverage` namespace
beside coverage_report (the TTP view) and coverage_ledger_status (the
per-artifact view); this module is the capability and lineage view.

The capability question is answered from Atlas's own versioned tool manifest
(tools/tool_capabilities.py), which already states, per capability, the
evidence classes it applies to, the phases it belongs in and the tools that
exercise it. The evidence classes come from the case's own declared evidence
(core/evidence_links.py) and, failing that, from the coverage ledger's units.
Nothing here keeps a table of its own: a capability that gains a tool, or an
evidence class that gains a capability, is picked up because the manifest is
the single source and it is version-stamped in the answer.

The lineage question is answered from exact finding lineage — linked_call_id
and input_call_ids — because Atlas's trace records which calls a finding was
built from. A call whose output no finding rests on is not necessarily a
defect; it is work nobody accounted for, which is a different and weaker
claim than "uncovered", and the wording here says so.
"""
from __future__ import annotations

from collections import defaultdict

from core import output_safe
from tools.coverage import mcp  # register on the coverage namespace

# Calls that are investigation plumbing rather than evidence production.
# Nothing a finding would ever cite, so their absence from lineage says
# nothing: the run's own state (core.forensic_citation.own_words_entry)
# plus the index queries and watchers, which point at evidence rather than
# produce it.
_PLUMBING_EXTRA_PREFIXES = ("search_", "monitor_")


def _plumbing_call(e: dict) -> bool:
    from core.forensic_citation import own_words_entry
    tool = str(e.get("mcp_tool") or "")
    return (own_words_entry(e)
            or own_words_entry({"type": "tool_call", "cmd": f"<py>:{tool}"})
            or tool.startswith(_PLUMBING_EXTRA_PREFIXES))

# Atlas names an evidence class in two vocabularies: the case file's
# (core/evidence_links._VALID_KINDS) and the tool manifest's per-capability
# `evidence` field. They overlap but are not identical, so the translation is
# stated once, here, rather than assumed at each use.
_CLASS_TO_MANIFEST_EVIDENCE = {
    "disk": ("disk", "mounted_fs", "file"),
    "memory": ("memory",),
    "pcap": ("pcap",),
    "evtx": ("logs",),
    "tabular": ("logs", "siem_export"),
    "email": ("file",),
    "file": ("file",),
    "live": ("live",),
}


def _trace_entries() -> list[dict]:
    from core.execution_log import log
    return list(log._entries)


def _case_dir() -> str:
    from core.execution_log import log
    try:
        return log.case_dir() or ""
    except Exception:
        return ""


def _tool_was_invoked(dotted: str, invoked: set) -> bool:
    """Whether a `namespace.function` manifest tool matches an invoked name.

    Atlas mounts each tool under its namespace AND many tool functions
    already carry that namespace in their own name, so the registered name is
    double-prefixed: `tsk.fls` becomes `tsk_tsk_fls`, while
    `net.tcpdump_read` stays `net_tcpdump_read`. Matching only the single
    form reports false gaps for every double-prefixed tool. Accept any
    invoked name that starts with the namespace and ends with the function
    segment, which covers both shapes.
    """
    ns, _, func = dotted.partition(".")
    if not func:
        return dotted in invoked
    if invoked & {f"{ns}_{func}", f"{ns}_{ns}_{func}"}:
        return True
    suffix = f"_{func}"
    return any(t.startswith(f"{ns}_") and t.endswith(suffix) for t in invoked)


def _declared_evidence_classes() -> set[str]:
    """The evidence classes this case says it has.

    The case file is the first authority, because it is what a human wrote
    down. When it declares nothing, the coverage ledger's units are the
    fallback: those are real files the ledger found. An empty answer means
    neither knows, and the audit says so rather than guessing from filenames.
    """
    case_dir = _case_dir()
    if not case_dir:
        return set()
    classes: set[str] = set()
    try:
        from core.evidence_links import load_evidence_links
        for entry in load_evidence_links(case_dir).get("entries") or []:
            kind = str(entry.get("kind") or "").strip()
            if kind in _CLASS_TO_MANIFEST_EVIDENCE:
                classes.add(kind)
    except Exception:
        pass
    if classes:
        return classes
    try:
        from core.coverage_ledger import load_ledger
        for unit in (load_ledger(case_dir).get("units") or {}).values():
            kind = str(unit.get("kind") or "").strip()
            if kind in _CLASS_TO_MANIFEST_EVIDENCE:
                classes.add(kind)
    except Exception:
        pass
    return classes


def _manifest_evidence_for(classes: set[str]) -> set[str]:
    """The manifest's evidence vocabulary for a set of case classes."""
    out: set[str] = set()
    for cls in classes:
        out.update(_CLASS_TO_MANIFEST_EVIDENCE.get(cls, ()))
    return out


def tool_coverage() -> dict:
    """Capabilities this case's evidence calls for that were never exercised."""
    from tools.tool_capabilities import tool_capability_manifest

    manifest = tool_capability_manifest()
    classes = _declared_evidence_classes()
    if not classes:
        return {
            "success": True,
            "manifest_version": manifest.get("version", ""),
            "evidence_classes": [],
            "capabilities_applicable": 0,
            "unexercised_count": 0,
            "capabilities": [],
            "note": ("neither the case file nor the coverage ledger names an "
                     "evidence class, so there is nothing to judge breadth "
                     "against — record the evidence in CASE.md first"),
        }

    wanted = _manifest_evidence_for(classes)
    invoked = {
        str(e["mcp_tool"]) for e in _trace_entries()
        if e.get("type") == "tool_call" and e.get("mcp_tool")
    }

    rows = []
    unexercised = 0
    for cap in manifest.get("capabilities") or []:
        applies = set(cap.get("evidence") or ())
        # "all" is the manifest's own way of saying a capability is never
        # gated on the evidence present.
        if "all" not in applies and not (applies & wanted):
            continue
        tools = list(cap.get("tools") or ())
        used = [t for t in tools if _tool_was_invoked(t, invoked)]
        if not used:
            unexercised += 1
        rows.append({
            "capability": cap.get("id", ""),
            "purpose": cap.get("purpose", ""),
            "phases": list(cap.get("phases") or ()),
            "exercised": bool(used),
            "exercised_with": used[:6],
            "tools": tools if not used else [],
        })

    rows.sort(key=lambda r: (r["exercised"], r["capability"]))
    return {
        "success": True,
        "manifest_version": manifest.get("version", ""),
        "evidence_classes": sorted(classes),
        "capabilities_applicable": len(rows),
        "unexercised_count": unexercised,
        "capabilities": rows,
        "hint": ("An unexercised capability is a technique this evidence "
                 "admits that the investigation never tried. Either exercise "
                 "one of its tools or say in the report why the capability "
                 "does not apply here. Breadth is not a target in itself: a "
                 "capability deliberately skipped and explained is covered."),
    }


def evidence_coverage() -> dict:
    """Output-producing calls that no finding was built from."""
    entries = _trace_entries()

    rested_on: set[int] = set()
    for entry in entries:
        if entry.get("type") != "finding":
            continue
        candidates = list(entry.get("input_call_ids") or [])
        if entry.get("linked_call_id"):
            candidates.append(entry["linked_call_id"])
        for cid in candidates:
            try:
                rested_on.add(int(cid))
            except (TypeError, ValueError):
                continue

    produced = [
        e for e in entries
        if e.get("type") == "tool_call"
        and e.get("success")
        and (e.get("stdout_excerpt") or e.get("stdout_file"))
        and not _plumbing_call(e)
    ]
    unaccounted = [e for e in produced if e.get("call_id") not in rested_on]

    by_tool: dict[str, dict] = defaultdict(
        lambda: {"calls": 0, "call_ids": []})
    for entry in unaccounted:
        label = str(entry.get("mcp_tool")
                    or str(entry.get("cmd") or "?").split()[0])
        bucket = by_tool[label]
        bucket["calls"] += 1
        if len(bucket["call_ids"]) < 8:
            bucket["call_ids"].append(entry.get("call_id"))

    return {
        "success": True,
        "producing_calls": len(produced),
        "rested_on_count": len(produced) - len(unaccounted),
        "unaccounted_count": len(unaccounted),
        "unaccounted_by_tool": dict(by_tool),
        "hint": ("A call nothing rests on is work the report does not "
                 "account for, which is weaker than saying it was missed. "
                 "Read the listed call_ids with search.search_evidence or "
                 "the trace, then record a finding, fold the output into an "
                 "existing one, or note that it showed nothing. Not every "
                 "call earns a finding."),
    }


@mcp.tool()
@output_safe
def audit_tool_coverage() -> dict:
    """
    Which investigative capabilities this case's evidence admits were never
    exercised: reads the versioned tool manifest, keeps the capabilities whose
    evidence classes the case actually has, and reports which of those no tool
    call ever touched. Run it before the final report; an unexercised
    capability needs either a tool run or a stated reason it does not apply.
    """
    return tool_coverage()


@mcp.tool()
@output_safe
def audit_evidence_coverage() -> dict:
    """
    Which successful, output-producing calls no finding was ever built from
    (by linked_call_id / input_call_ids). Work nothing rests on is work the
    report does not account for. Run it before the final report and read the
    listed call_ids.
    """
    return evidence_coverage()


# ---------------------------------------------------------------------------
# Auth success coverage gaps (Claim Graph)
#
# Call-level evidence_coverage cannot see event grain: one finding citing an
# auth log marks the whole output covered. We ingest structured auth.success /
# auth.failure observations into the Claim Graph (via auth_ontology adapters),
# then flag contested successes that were never reported as findings/claims.
# Advisory only — never blocks Report.
# ---------------------------------------------------------------------------


def _positively_frames_success(desc: str) -> bool:
    """Compatibility helper for unit tests; delegates to auth_ontology."""
    from core.auth_ontology import positively_frames_success
    return positively_frames_success(desc)


def hostile_auth_reconciliation() -> dict:
    """Ingest auth observations from the trace; return contested success gaps.

    Name kept for MCP/test compatibility. Interest set is structural
    (auth.failure + auth.success for the same endpoint) — no hostile vocab.
    """
    from core.auth_coverage import (
        auth_success_coverage_gaps,
        resolve_case_dir_for_auth,
    )
    from core.auth_observations import ingest_auth_observations_from_trace
    from core.claim_graph import resolve_case_dir

    case_dir = resolve_case_dir_for_auth()
    if not case_dir:
        try:
            from core.execution_log import log
            case_dir = log.case_dir() or None
        except Exception:
            case_dir = None
    if not case_dir:
        # Last resort: allow resolve_case_dir with empty (same path).
        case_dir = resolve_case_dir(None)
    if not case_dir:
        return {
            "success": True,
            "hostile_ips": 0,
            "contested_endpoints": 0,
            "success_events_seen": 0,
            "unreported_count": 0,
            "unreported": [],
            "note": "no case directory resolved — cannot ingest auth observations",
        }
    ingest_auth_observations_from_trace(case_dir)
    return auth_success_coverage_gaps(case_dir)


@mcp.tool()
@output_safe
def audit_hostile_auth_coverage() -> dict:
    """
    Auth success coverage gaps: endpoints with both auth.failure and
    auth.success observations in the Claim Graph where the success was never
    surfaced as a finding/claim for that endpoint/date.

    Ingests structured auth observations from tool output (platform adapters in
    core.auth_ontology), then reports contested unreported successes. Advisory.
    """
    return hostile_auth_reconciliation()
