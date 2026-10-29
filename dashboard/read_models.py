"""Investigator-facing read models (projections) for the dashboard.

ARCHITECTURAL DECISION — derived answers, not a second source of truth
=======================================================================
An investigation question's "answer" shown in the dashboard is a pure
projection of the authoritative investigation state:

    Investigation task (CASE.md request, ``.atlas/investigation_tasks.json``)
            │ related_claim_ids
            ↓
    Claim graph nodes (``.atlas/claim_graph.json`` — conclusions/claims,
    confidence, evidence call ids, conflicts)
            ↓
    Human-readable answer summary (derived here, at read time)

There is deliberately **no** ``resolution``/answer field stored on tasks:
a second, manually maintained answer store could disagree with the claim
graph. Everything in this module is recomputed from the files on disk on
every request (with a small mtime-keyed cache for trace parsing). If the
projection is ever persisted for performance, it must be a cache keyed on
the source files' mtimes — never an independently editable record.

This module is read-only: it never writes into a case directory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

TRACE_RE = re.compile(r".*_trace\.json$", re.IGNORECASE)

# ── Investigator-facing status language ──────────────────────────────────────
#
# Internal task lifecycle enums stay in core.investigation_tasks; the UI shows
# these labels/glyphs instead. "bucket" groups statuses for progress bars:
#   answered / partial / open  (dropped tasks are excluded from progress).
STATUS_VIEW: dict[str, dict[str, str]] = {
    "answered": {"label": "Answered", "glyph": "\u25cf", "bucket": "answered"},
    "partial": {"label": "Partially answered", "glyph": "◐", "bucket": "partial"},
    "in_progress": {"label": "In progress", "glyph": "◐", "bucket": "partial"},
    "reopened": {"label": "Reopened", "glyph": "◐", "bucket": "partial"},
    "open": {"label": "Open", "glyph": "○", "bucket": "open"},
    "blocked_missing_evidence": {
        "label": "Blocked — missing evidence", "glyph": "○", "bucket": "open"},
    "dropped": {"label": "Dropped", "glyph": "—", "bucket": "dropped"},
    # Legacy task status (migrated on load; keep label path for stale JSON).
    "withdrawn": {"label": "Dropped", "glyph": "—", "bucket": "dropped"},
}

# The live-run check lives in core so the CLI and the MCP layer share it;
# the names it has always had here stay importable.
from core.run_state import (  # noqa: E402,F401
    LEGACY_ACTIVITY_PREFIX as _LEGACY_ACTIVITY_PREFIX,
    active_runs,
    agent_busy,
    pid_alive as _pid_alive,
    run_process_alive,
    run_status as _run_status,
    transcript_fresh as _transcript_fresh,
)

_CONFIDENCE_RANK = {"CONFIRMED": 4, "LIKELY": 3, "SUSPECTED": 2,
                    "UNCONFIRMED": 1}

# Claim-graph node statuses that represent a current belief (mirrors
# core.claim_graph.CURRENT_BELIEF_STATUSES without importing the heavier
# module on the dashboard read path).
_CURRENT_STATUSES = frozenset({"new", "unchanged", "updated", "needs_review",
                               "conflict"})
_GONE_STATUSES = frozenset({"superseded", "withdrawn"})


def _read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def load_claim_graph(case_dir: str) -> dict:
    data = _read_json(os.path.join(case_dir, ".atlas", "claim_graph.json"))
    return data if isinstance(data, dict) else {}


def load_task_store(case_dir: str) -> dict:
    # Reconcile CASE.md into the task store on read, but only when no run is
    # live for this case. This covers a case whose CASE.md was hand-edited
    # (or edited by a dashboard/CLI version that predates the write-side
    # sync) with nothing to otherwise trigger a sync — without it, such a
    # case shows "No investigation questions" forever. It must be skipped
    # while a run is active, though: a live run's own incremental engine
    # (core/incremental.py, which reconciles the same file on its own
    # writer path) and a viewer's background poll would both write
    # investigation_tasks.json at once. A live run already keeps the store
    # in sync itself, so a read-triggered reconcile has nothing to add there
    # and only adds a race.
    try:
        if not run_process_alive(case_dir):
            from core.investigation_tasks import reconcile_case_md
            reconcile_case_md(case_dir)
    except Exception:
        pass
    # Prefer the task SoT loader so legacy status "withdrawn" migrates to
    # "dropped" the same way Plane A / tools do.
    try:
        from core.investigation_tasks import load_tasks
        return load_tasks(case_dir)
    except Exception:
        data = _read_json(os.path.join(case_dir, ".atlas",
                                       "investigation_tasks.json"))
        return data if isinstance(data, dict) else {}


# ── Answer derivation ────────────────────────────────────────────────────────

def _node_brief(n: dict) -> dict:
    return {
        "id": n.get("id"),
        "kind": n.get("kind"),
        "statement": (n.get("statement") or "").strip(),
        "confidence": (n.get("confidence") or "").upper() or None,
        "status": n.get("status"),
        "host": n.get("host") or None,
        "evidence_call_ids": sorted({
            e.get("call_id") for e in (n.get("evidence") or [])
            if isinstance(e, dict) and e.get("call_id") is not None
        }),
        # The lineage-by-wiring fields the pre-report check writes on the node.
        "located_call_ids": [int(c) for c in (n.get("located_call_ids") or []) if c],
        "citation_status": n.get("citation_status") or None,
        # A conclusion's basis and the tier it asked for, and what bounded it.
        "basis_ids": [str(b) for b in (n.get("basis_ids") or [])],
        "requested_confidence": (n.get("requested_confidence") or "").upper() or None,
        "tier_bound": n.get("tier_bound") or None,
    }


def _narrative_summaries(case_dir) -> dict[str, str]:
    """``{node_id: summary}`` from the report's Detailed Findings prose."""
    if not case_dir:
        return {}
    try:
        from core.finding_index import load_index
        from core.report_assemble import _narrative_section, parse_finding_narratives
        by_fid = {v: k for k, v in (load_index(case_dir).get("by_node_id") or {}).items()}
        nar = parse_finding_narratives(_narrative_section(Path(case_dir), "detailed_findings"))
        return {by_fid[fid]: n.get("summary", "") for fid, n in nar.items()
                if fid in by_fid}
    except Exception:  # noqa: BLE001
        return {}


def derive_task_answer(task: dict, graph: dict, questions: list[str] | None = None) -> dict:
    """Project a human-readable answer for one task from the claim graph.

    Thin dashboard view over ``core.answer_synthesis.answer_for_task`` —
    the report's answers section reads the same function, with the same
    case questions (``questions``, core.answer_synthesis.competing_questions),
    so the analyst sees one answer everywhere. Never stored — see module
    docstring.
    """
    from core.answer_synthesis import answer_for_task, cached_answer_text, scaffold_fingerprint
    core = answer_for_task(task, graph, _narrative_summaries(graph.get("_case_dir")),
                           questions=questions)
    case_dir = graph.get("_case_dir")
    nodes = graph.get("nodes") or {}
    composed_fields: dict = {}
    if case_dir:
        # The composed answer when its sheet matches (a file read, never a
        # call and never a re-check); the scaffold otherwise, as today.
        try:
            from core.answer_synthesis import (answer_sheet, cached_composed, compose_on, composed_verdict,
                                               lead_tier, sheet_fingerprint)
            if compose_on():
                from core.case_config import get_report_language
                # The report's language: the fingerprint carries it.
                sheet = answer_sheet(task, graph, questions, language=get_report_language(case_dir),
                                     case_dir=case_dir)
                hit = cached_composed(case_dir, task.get("id") or "", sheet_fingerprint(sheet, graph)) \
                    if sheet["beliefs"] else None
                if hit:
                    cited = [c for s in hit["sentences"] for c in s.get("ids") or []
                             if not c.startswith(("p", "w", "v"))]
                    core["text"] = hit["text"]
                    core["has_answer"] = True
                    core["confidence"] = lead_tier(hit["sentences"], graph)
                    core["verdict"] = composed_verdict(hit["sentences"], sheet)
                    first = [nodes[c] for c in dict.fromkeys(cited) if c in nodes]
                    core["supporting"] = first + [n for n in core["supporting"] if n not in first]
                    composed_fields = {"composed": True,
                                       "citations": [{"sentence": s["text"], "ids": list(s["ids"])}
                                                     for s in hit["sentences"]]}
        except Exception:  # noqa: BLE001 - the scaffold stands
            composed_fields = {}
    if core.get("has_answer") and case_dir and not composed_fields:
        cached = cached_answer_text(case_dir, task.get("id") or "",
                                    scaffold_fingerprint(core))
        if cached:
            core["text"] = cached
    rel_ids = {n.get("id") for n in core["supporting"]}
    # Conflicts that touch any related claim (open conflicts only).
    conflicts = []
    for n in nodes.values():
        if n.get("kind") != "conflict":
            continue
        if n.get("status") in _GONE_STATUSES or n.get("status") == "resolved":
            continue
        if set(n.get("conflicting_claim_ids") or []) & rel_ids:
            conflicts.append(_node_brief(n))
    supporting = [_node_brief(n) for n in core["supporting"]]
    try:
        from core.finding_index import load_index
        by_node = (load_index(graph.get("_case_dir") or "") or {}).get("by_node_id", {}) \
            if graph.get("_case_dir") else {}
    except Exception:  # noqa: BLE001
        by_node = {}
    for b in supporting:
        if by_node.get(b["id"]):
            b["finding_id"] = by_node[b["id"]]
    return {
        "has_answer": core["has_answer"],
        "summary": core["text"] or None,
        # The position taken, separate from the prose — so the card can lead
        # with it and a reader sees the answer before the supporting detail.
        "verdict": core["verdict"],
        # Evidence that was never examined. Kept out of "summary" on
        # purpose: it qualifies an answer, it is not one.
        "gaps": core["gaps"],
        "confidence": core["confidence"],
        "supporting": supporting,
        "conflicts": conflicts,
        "missing_claim_ids": core["missing_claim_ids"],
        # A composed answer's flag and its per-sentence citations, for a
        # later card change (none on the scaffold).
        **composed_fields,
    }


def task_projection(task: dict, graph: dict, questions: list[str] | None = None) -> dict:
    """One investigator-facing question card."""
    status = task.get("status") or "open"
    view = STATUS_VIEW.get(status) or {
        "label": status.replace("_", " "), "glyph": "○", "bucket": "open"}
    text = (task.get("text") or "").strip()
    derived = text.lower().startswith("[derived]")
    if derived:
        text = text[len("[derived]"):].strip()
    return {
        "id": task.get("id"),
        "text": text,
        "derived": derived,
        "status": status,               # internal enum (behind "details")
        "status_label": view["label"],
        "glyph": view["glyph"],
        "bucket": view["bucket"],
        "updated_at": task.get("updated_at"),
        "created_at": task.get("created_at"),
        "answer": derive_task_answer(task, graph, questions),
    }


def questions_projection(case_dir: str) -> dict:
    """All questions for a case with derived answers + progress buckets."""
    store = load_task_store(case_dir)
    if not store.get("tasks"):
        # No store yet (the run has not started, or never did): the
        # questions still exist — CASE.md asked them.
        try:
            from core.investigation_tasks import parse_case_requests, read_case_markdown
            store["tasks"] = [
                {"id": f"task-{i:04d}", "text": q, "status": "open",
                 "related_claim_ids": []}
                for i, q in enumerate(parse_case_requests(read_case_markdown(case_dir)), 1)]
        except Exception:  # noqa: BLE001
            pass
    graph = load_claim_graph(case_dir)
    graph["_case_dir"] = case_dir           # lets answers name F-ids
    from core.answer_synthesis import competing_questions
    questions = competing_questions(store.get("tasks") or [])
    tasks = [task_projection(t, graph, questions)
             for t in (store.get("tasks") or [])]
    progress = {"answered": 0, "partial": 0, "open": 0, "dropped": 0}
    for t in tasks:
        progress[t["bucket"]] = progress.get(t["bucket"], 0) + 1
    visible = [t for t in tasks if t["bucket"] != "dropped"]
    dropped = [t for t in tasks if t["bucket"] == "dropped"]
    return {
        "case_id": store.get("case_id") or os.path.basename(case_dir),
        "updated_at": store.get("updated_at"),
        "questions": visible,
        "dropped": dropped,
        "withdrawn": dropped,  # deprecated alias
        "progress": progress,
        "total_visible": len(visible),
    }


# ── Claim graph summary ──────────────────────────────────────────────────────

def claims_summary(case_dir: str, *, conflict_limit: int = 5) -> dict:
    graph = load_claim_graph(case_dir)
    nodes = list((graph.get("nodes") or {}).values())
    by_kind: dict[str, int] = {}
    needs_review = 0
    open_conflicts = []
    conclusions = []
    for n in nodes:
        status = n.get("status")
        if status in _GONE_STATUSES:
            continue
        kind = n.get("kind") or "claim"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if status == "needs_review":
            needs_review += 1
        if kind == "conflict" and status == "conflict":
            open_conflicts.append(_node_brief(n))
        if kind == "conclusion":
            conclusions.append(_node_brief(n))
    return {
        "has_graph": bool(nodes),
        "active_by_kind": by_kind,
        "needs_review": needs_review,
        "open_conflicts": open_conflicts[:conflict_limit],
        "open_conflict_count": len(open_conflicts),
        "conclusions": conclusions,
        "updated_at": graph.get("updated_at"),
    }


# ── Activity + recent findings (trace projection, mtime-cached) ──────────────

_trace_cache: dict[str, tuple[float, dict]] = {}


def _newest_trace(case_dir: str) -> str | None:
    analysis = os.path.join(case_dir, "analysis")
    newest, newest_m = None, -1.0
    try:
        for fn in os.listdir(analysis):
            if not TRACE_RE.match(fn):
                continue
            p = os.path.join(analysis, fn)
            try:
                m = os.path.getmtime(p)
            except OSError:
                continue
            if m > newest_m:
                newest, newest_m = p, m
    except OSError:
        return None
    return newest


def _trace_digest(path: str) -> dict:
    """Findings + last activity from one trace file (cached by mtime)."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    cached = _trace_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    from core.execution_log import PROSE_NARRATION_KINDS
    data = _read_json(path)
    entries = (data or {}).get("entries") or []
    findings = []
    last_ts = None
    last_narration = None
    current_phase = None
    for e in entries:
        if not isinstance(e, dict):
            continue
        ts = e.get("ts")
        if ts:
            last_ts = ts
        if e.get("dair_phase"):
            current_phase = e["dair_phase"]
        t = e.get("type")
        if t == "finding":
            findings.append({
                "description": (e.get("description") or "").strip(),
                "confidence": (e.get("confidence") or "").upper() or None,
                "ts": e.get("ts"),
                "call_id": e.get("call_id"),
            })
        elif t == "investigation_narration" and (e.get("kind") or "") in PROSE_NARRATION_KINDS:
            content = (e.get("content") or "").strip()
            if content:
                last_narration = content
    digest = {
        "trace_name": os.path.basename(path),
        "trace_rel": None,  # filled by caller (needs case dir name)
        "entry_count": len(entries),
        "findings": findings,
        "last_ts": last_ts,
        "last_narration": last_narration,
        "current_phase": current_phase,
    }
    if len(_trace_cache) > 64:
        _trace_cache.clear()
    _trace_cache[path] = (mtime, digest)
    return digest


def seconds_since(value) -> float | None:
    """Seconds from a stored UTC stamp to now, never negative; None when the
    stamp cannot be read."""
    at = _ts_epoch(value)
    return None if at is None else max(0.0, datetime.now(timezone.utc).timestamp() - at)


def _ts_epoch(value) -> float | None:
    """Epoch seconds for a trace timestamp, or None if it cannot be read.
    Traces carry both ``...Z`` and ``+00:00`` forms; a stamp without a zone
    is read as UTC, which is what the writers emit."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _finding_stats(findings: list[dict], *, text_limit: int = 160) -> dict:
    """How the findings of a run are distributed — by confidence tier, and
    where each one falls across the run's own timespan.

    Every mark carries ``at``: its position between the first and the last
    finding, 0..1. Normalising here rather than in the page means a caller
    can draw the run without knowing when it happened or how long it took,
    and findings that all landed at once (or a single finding) sit in the
    middle rather than piling on an edge. A finding whose timestamp cannot
    be read still counts toward its tier; it simply cannot be placed.
    """
    by_confidence: dict[str, int] = {}
    stamped: list[tuple[float, dict]] = []
    for f in findings:
        tier = (f.get("confidence") or "UNCONFIRMED").upper()
        by_confidence[tier] = by_confidence.get(tier, 0) + 1
        stamp = _ts_epoch(f.get("ts"))
        if stamp is not None:
            stamped.append((stamp, f))
    stamped.sort(key=lambda pair: pair[0])
    timeline: dict = {"marks": [], "first_ts": None, "last_ts": None,
                      "span_seconds": 0}
    if stamped:
        low, high = stamped[0][0], stamped[-1][0]
        span = high - low
        timeline["first_ts"] = stamped[0][1].get("ts")
        timeline["last_ts"] = stamped[-1][1].get("ts")
        timeline["span_seconds"] = round(span)
        timeline["marks"] = [
            {"at": round((stamp - low) / span, 4) if span else 0.5,
             "confidence": (f.get("confidence") or "UNCONFIRMED").upper(),
             "ts": f.get("ts"),
             # The trace entry that recorded it, so a mark can open the
             # evidence trail at exactly this finding (?call=N in the
             # process view) rather than at the top of the trace.
             "call_id": f.get("call_id"),
             "text": (f.get("description") or "").strip()[:text_limit]}
            for stamp, f in stamped]
    return {"by_confidence": by_confidence, "timeline": timeline}


def activity_projection(case_dir: str, *, finding_limit: int = 5,
                        stale_window_seconds: int = 90) -> dict:
    trace = _newest_trace(case_dir)
    digest = _trace_digest(trace) if trace else {}
    findings = list(digest.get("findings") or [])
    stats = _finding_stats(findings)
    findings.reverse()  # newest first
    rel = None
    if trace:
        rel = "/{}/analysis/{}".format(
            os.path.basename(case_dir), os.path.basename(trace))
    busy = agent_busy(case_dir)
    # Always read, not just while busy: a run that stopped abnormally
    # (llm_error — the common real case is a token/context-limit rejection
    # from the LLM API — or an unexpected crash) needs its stopped_reason/
    # error surfaced *after* it stops too, not only while it's live. Before
    # this, run_process_alive() correctly reported not-busy once the
    # process actually exited, but nothing then told the operator *why* —
    # the card just silently reverted to "No active run".
    status = _run_status(case_dir)
    # A legacy prefixed tool name reads better in the UI as
    # "waiting on img_vmdk_export_raw" — strip the CLI-only prefix.
    current_tool = (status.get("activity") or "")\
        .removeprefix(_LEGACY_ACTIVITY_PREFIX).strip()
    tool_running_seconds = None
    started_at = status.get("tool_started_at")
    if busy and started_at:
        tool_running_seconds = seconds_since(started_at)
    # busy-but-nothing-in-the-transcript-recently: the case this whole
    # function exists for — a long tool call is genuinely running but has
    # nothing new to show, so last_narration below would otherwise be
    # whatever the run last said (often a stale run-start URL) rather than
    # a signal that logs simply haven't moved.
    logs_stale = busy and not _transcript_fresh(case_dir, stale_window_seconds)
    stopped_reason = str(status.get("stopped_reason") or "")
    last_stop = None
    # "running" (still going), "finished" (the model called atlas_finish)
    # and "closed_out" (the loop wrote the reports itself once the
    # pre-report gate had passed) are clean ends — already conveyed by the
    # Start/Stop pill's own "run finished" state — and don't get the
    # error-styled banner; every other reason is an abnormal stop the
    # operator needs to see explained.
    finish_status = str(status.get("finish_status") or "")
    try:
        from core.investigation_exit import FINISH_STATUSES, STOPPED_UNDECIDED
        undecided_end = finish_status == STOPPED_UNDECIDED or (
            bool(finish_status) and finish_status not in FINISH_STATUSES
            and finish_status not in ("error", "interrupted"))
    except Exception:  # noqa: BLE001
        undecided_end = False
    if not busy and (stopped_reason not in ("", "running", "finished", "closed_out") or undecided_end):
        detail = ""
        if undecided_end:
            # The run ended with content classes undecided: said as a stop,
            # with the count per host, whatever the loop's own stop word.
            und = (status.get("coverage_disclosure") or {}).get("evidence_disposition") or {}
            by_host = und.get("undecided_by_host") or {}
            detail = (f"{und.get('undecided_classes') or sum(by_host.values())} content class(es) with neither a "
                      "read nor a reason" + (": " + ", ".join(f"{h or 'no host'} {n}" for h, n in list(by_host.items())[:8])
                                              if by_host else "")
                      + ". Resume to continue, or decide them from the Coverage tab's list.")
        last_stop = {
            "reason": "undecided_evidence" if undecided_end and stopped_reason in ("", "finished", "closed_out",
                                                                                   "finish_deferred", "quiet")
            else stopped_reason,
            "finish_status": finish_status,
            "error": str(status.get("error") or "") or detail,
            "updated_at": status.get("updated_at"),
        }
    elif not busy and stopped_reason == "running" and status.get("pid"):
        # The process is gone but never wrote its exit: killed from outside
        # or by the kernel.
        last_stop = {
            "reason": "died",
            "finish_status": "error",
            "error": (f"the run process (pid {status.get('pid')}) ended without "
                      f"recording an exit at turn {status.get('turns')}; "
                      f"last activity {current_tool or 'unknown'}. Check memory "
                      "(dmesg) or whether it was killed; `atlas rerun` continues "
                      "from the recorded findings."),
            "updated_at": status.get("updated_at"),
        }
    return {
        "busy": busy,
        "current_tool": current_tool if busy else "",
        "tool_running_seconds": tool_running_seconds,
        "logs_stale": logs_stale,
        # Model calls have been failing longer than ATLAS_ESCAPE_ALERT_SECONDS;
        # the activity text says what the escape does next.
        "escape_alert": bool(busy and status.get("escape_alert")),
        "last_stop": last_stop,
        "trace": rel,
        "trace_entries": digest.get("entry_count") or 0,
        "last_ts": digest.get("last_ts"),
        "last_narration": digest.get("last_narration"),
        "current_phase": digest.get("current_phase"),
        "recent_findings": findings[:finding_limit],
        "finding_count": len(findings),
        "finding_by_confidence": stats["by_confidence"],
        "finding_timeline": stats["timeline"],
    }


# ── Evidence + report status ─────────────────────────────────────────────────

def evidence_summary(case_dir: str) -> dict:
    cat = _read_json(os.path.join(case_dir, ".atlas",
                                  "evidence_catalog.json")) or {}
    units = cat.get("units") or {}
    total = 0
    current = 0
    for u in units.values():
        if not isinstance(u, dict):
            continue
        if u.get("status") == "current":
            current += 1
        try:
            total += int(u.get("size") or 0)
        except (TypeError, ValueError):
            pass
    return {
        "cataloged": bool(units),
        "files": len(units),
        "current_files": current,
        "total_bytes": total,
    }


# ── Coverage: what was read, left with a reason, or is still open ─────────────

_coverage_cache: dict[str, tuple[tuple, dict]] = {}
# The extracted outputs are computed from the trace (extracted_outputs reads
# the whole document), so they are kept apart from the ledger part: read
# again at most once per interval while the trace or the ledger moves (a
# live run rewrites both at every flush), by one request at a time per case
# (the others wait for its result). The ledger part is cheap and follows
# every ledger write. The interval bounds a reader's cost; it never bounds
# the run.
_extracted_cache: dict[str, dict] = {}
_extracted_locks: dict[str, threading.Lock] = {}
_extracted_locks_guard = threading.Lock()
COVERAGE_EXTRACT_INTERVAL = 30.0   # seconds between two readings of a moving trace
_monotonic = time.monotonic

# The ledger's states in the four words the Coverage tab uses; the ledger's
# own words never reach the page.
_COVERAGE_STATE = {"read": "read", "partial": "partial", "walked": "partial", "swept": "partial",
                   "left": "left", "pending": "open", "relevant": "open", "parsed": "parsed"}
_COVERAGE_ZERO = {"read": 0, "partial": 0, "parsed": 0, "left": 0, "open": 0}


def _coverage_unit(u: dict) -> dict:
    """One ledger unit (an item or a content class) as the page shows it:
    the state, a note naming the next step (undecided, refused: a leave
    of it was refused) or how it was partly read (walked: the lists only;
    swept: a search for the known indicators), and a left unit's kind,
    reason and proof calls. The ledger's own prose stays here."""
    raw = str(u.get("state") or "pending")
    out = {"state": _COVERAGE_STATE.get(raw, "open"), "note": "", "reason_kind": "", "reason": "",
           "proof": [str(p) for p in (u.get("proof_call_ids") or []) if p][:6]}
    if out["state"] == "left":
        out["reason_kind"] = str(u.get("reason_kind") or "")
        out["reason"] = str(u.get("reason") or "")
    elif out["state"] == "open":
        # An undecided class (pending or relevant alike: no read credited,
        # no reason recorded), as the end label counts it; never shown as
        # left.
        out["note"] = "refused" if u.get("triage_refused") else "undecided"
    elif raw in ("walked", "swept"):
        out["note"] = raw
    elif raw == "parsed":
        # Open, with its next step: query the output that holds its rows.
        out["note"] = str((u.get("outputs") or [""])[0])
    return out


def _trace_document_mtime(case_dir: str) -> float:
    try:
        from core.execution_log import case_trace_document
        doc = case_trace_document(case_dir)
        return os.path.getmtime(doc) if doc else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def _extracted_cached(case_dir: str, key: tuple) -> tuple[list[dict], float]:
    """The extracted outputs under ``key`` (ledger mtime, trace mtime): the
    cached ones while the key stands or the interval has not passed since
    they were computed, else computed once for every request waiting on
    the case. Returns them with the moment they were computed."""
    def fresh(entry: dict | None) -> bool:
        return bool(entry) and (entry["key"] == key or _monotonic() - entry["at"] < COVERAGE_EXTRACT_INTERVAL)
    entry = _extracted_cache.get(case_dir)
    if fresh(entry):
        return entry["outputs"], entry["at"]
    with _extracted_locks_guard:
        lock = _extracted_locks.setdefault(case_dir, threading.Lock())
    with lock:
        entry = _extracted_cache.get(case_dir)
        if fresh(entry):
            return entry["outputs"], entry["at"]
        from core.coverage_ledger import extracted_outputs
        try:
            outputs = extracted_outputs(case_dir)
        except Exception:  # noqa: BLE001
            outputs = []
        at = _monotonic()
        if len(_extracted_cache) > 64:
            _extracted_cache.clear()
        _extracted_cache[case_dir] = {"key": key, "at": at, "outputs": outputs}
        return outputs, at


def coverage(case_dir: str) -> dict:
    """The Coverage tab: each evidence item with its content classes in
    four plain states (read, partly read, left with a reason, open), the
    extracted outputs' file classes the same way, and the counts behind the
    header. Read from the coverage ledger and the trace, never written.
    The ledger part is recomputed on every ledger write; the extracted
    outputs follow the trace at most once per COVERAGE_EXTRACT_INTERVAL
    (_extracted_cached).

    ``ledger`` False: the case has no ledger yet. ``disposition`` False: the
    ledger has no class level (a run from before it, or the switch off), so
    an item stands as the run left it: blocked is left, anything else open.
    """
    path = os.path.join(case_dir, ".atlas", "coverage_ledger.json")
    try:
        ledger_mtime = os.path.getmtime(path)
    except OSError:
        return {"ledger": False, "disposition": False, "items": [], "extracted": [],
                "summary": {**_COVERAGE_ZERO, "total": 0}}
    outputs, stamp = _extracted_cached(case_dir, (ledger_mtime, _trace_document_mtime(case_dir)))
    key = (ledger_mtime, stamp)
    cached = _coverage_cache.get(case_dir)
    if cached and cached[0] == key:
        return cached[1]
    from core.coverage_ledger import load_ledger
    ledger = load_ledger(case_dir)
    disposition = ledger.get("classes") is not None
    try:
        from core.evidence_depth import class_tiers
        tiers = class_tiers(case_dir, ledger) if disposition else {}
    except Exception:  # noqa: BLE001
        tiers = {}
    by_item: dict[str, list[dict]] = {}
    for c in (ledger.get("classes") or {}).values():
        if isinstance(c, dict):
            by_item.setdefault(str(c.get("item") or ""), []).append(c)
    summary = dict(_COVERAGE_ZERO)
    items: list[dict] = []
    for iid, it in (ledger.get("items") or {}).items():
        if not isinstance(it, dict):
            continue
        if disposition:
            unit = _coverage_unit(it)
        elif it.get("status") == "blocked":
            unit = {**_coverage_unit({"state": "left"}), "reason": str(it.get("blocked_reason") or "")}
        else:
            unit = {**_coverage_unit({"state": "pending"}), "note": ""}
        classes = [{"label": str(c.get("label") or ""), "files": int(c.get("files") or 0),
                    "tier": tiers.get(str(c.get("id")), ""), **_coverage_unit(c)}
                   for c in sorted(by_item.get(str(iid), []), key=lambda c: str(c.get("label") or ""))]
        counts = dict(_COVERAGE_ZERO)
        for c in classes or [unit]:
            counts[c["state"]] += 1
        for s in counts:
            summary[s] += counts[s]
        path = str(it.get("path") or iid)
        items.append({"id": str(iid), "path": path, "kind": str(it.get("kind") or ""),
                      "host": str(it.get("host") or ""),
                      # The lane the page shows the item under: its host, else
                      # the item's own file name, never "no host".
                      "lane": str(it.get("host") or "") or path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1],
                      # An item the ledger holds no class for stands in the
                      # depth count by itself as one cheap class.
                      "tier": "" if classes else "cheap",
                      **unit, "counts": counts, "classes": classes})
    items.sort(key=lambda i: (i["host"].casefold(), i["path"]))
    extracted: list[dict] = []
    for o in outputs:
        # ``left``: the classes a code fact leaves, when the ledger module gives them.
        left = o.get("left") or {}
        sample = o.get("sample") or {}
        blocked = str(o.get("blocked") or "")
        classes = []
        for label, (n, m) in sorted((o.get("classes") or {}).items(), key=lambda kv: (-kv[1][1], kv[0])):
            c = {"label": str(label), "read": int(n), "total": int(m), "state": "open", "note": "",
                 "detail": "", "reason_kind": "", "reason": "", "proof": []}
            if label in left:
                c.update(state="left", reason_kind=str((left[label] or {}).get("kind") or ""),
                         reason=str((left[label] or {}).get("basis") or ""))
            elif blocked and not n:
                c.update(state="left", reason_kind="blocked", reason=blocked)
            elif n >= m:
                c["state"] = "read"
            elif n:
                c["state"] = "partial"
            elif label in sample:
                c.update(note="file", detail=str(sample[label]))
            else:
                c["note"] = "failed"
            classes.append(c)
        counts = dict(_COVERAGE_ZERO)
        for c in classes:
            counts[c["state"]] += 1
        for s in counts:
            summary[s] += counts[s]
        extracted.append({"path": str(o.get("path") or ""), "made": str(o.get("made") or ""),
                          "counts": counts, "classes": classes})
    result = {"ledger": True, "disposition": disposition, "items": items, "extracted": extracted,
              "summary": {**summary, "total": sum(summary.values())}}
    if len(_coverage_cache) > 64:
        _coverage_cache.clear()
    _coverage_cache[case_dir] = (key, result)
    return result


def timeline_plugin_active() -> bool:
    """True when the timeline_builder plugin is enabled and importable.

    The Report tab's empty timeline-template download is gated on this so the
    option never appears when the plugin is disabled via ATLAS_PLUGINS=0 or
    ATLAS_PLUGINS_DISABLED=timeline_builder.
    """
    try:
        from core import plugins as plug
        if not plug.is_enabled("timeline_builder"):
            return False
        return any(
            m.rsplit(".", 1)[-1] == "timeline_builder"
            for m in plug.discover_plugin_modules()
        )
    except Exception:  # noqa: BLE001
        return False


def timeline_template_tsv() -> str | None:
    """Header-only master_timeline.tsv template, or None if plugin inactive."""
    if not timeline_plugin_active():
        return None
    try:
        from plugins.timeline_builder.export import TSV_COLUMNS
    except Exception:  # noqa: BLE001
        return None
    return "\t".join(TSV_COLUMNS) + "\n"


def list_report_files(case_dir: str) -> list[dict]:
    """Case-scoped report deliverables (core.report_snapshots.report_files),
    each with the URL the dashboard serves it under."""
    from core.report_snapshots import report_files
    case_name = os.path.basename(case_dir)
    out = []
    for f in report_files(case_dir):
        entry = {k: v for k, v in f.items() if k != "rel"}
        # A URL: a name holding "#" or "?" must not end the path.
        entry["path"] = quote(f"/{case_name}/reports/{f['rel']}")
        out.append(entry)
    return out


def _report_rank(f: dict, reports: str) -> tuple:
    """Order for the case's default report, best last (one rule with
    `atlas report`: core.report_snapshots.report_rank)."""
    from core.report_snapshots import report_rank
    return report_rank(f, reports)


def build_report_bundle_zip(case_dir: str) -> bytes | None:
    """Zip all report deliverables (reports + timeline). None if nothing."""
    import io
    import zipfile

    files = list_report_files(case_dir)
    if not files:
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            arc = f["name"]
            try:
                zf.write(f["abs_path"], arcname=arc)
            except OSError:
                continue
    data = buf.getvalue()
    return data or None


_STAGE_LABELS = {
    "deterministic": "Basis version — narrative pending",
    "upgrade_failed": "Narrative generation failed — basis version only",
    "complete": "",
}


def report_stage(case_dir: str) -> dict:
    """How far the report on disk got, for the reader looking at it.

    An analyst-written report is simply finished and carries no stage. For a
    report written on exit the manifest says which half of the work is in the
    file: ``upgrading`` left behind by a process that died during generation
    is the case nothing else can detect — it means "still upgrading" only for
    as long as the run is actually alive.
    """
    try:
        from core.report_exit import official_report_exists
        if official_report_exists(case_dir):
            return {"report_stage": None, "report_complete": True,
                    "report_label": ""}
        from core.report_projection import load_manifest
        stage = str((load_manifest(case_dir) or {}).get("report_stage") or "")
    except Exception:  # noqa: BLE001 - a missing stage is not a broken tab
        stage = ""
    if not stage:
        return {"report_stage": None, "report_complete": True,
                "report_label": ""}
    if stage == "upgrading":
        label = ("Report generation in progress" if run_process_alive(case_dir)
                 else "Report generation interrupted — basis version only")
    else:
        label = _STAGE_LABELS.get(stage, "")
    return {"report_stage": stage, "report_complete": stage == "complete",
            "report_label": label}


def report_status(case_dir: str) -> dict:
    """The case's report (see _report_rank) and its downloadable files.

    Also lists downloadable deliverables (markdown + timeline), how far the
    report got, and whether the timeline-plugin template download should be
    offered. The Overview card and the Report tab's first selection both
    show ``path``.
    """
    files = list_report_files(case_dir)
    public_files = [{k: v for k, v in f.items() if k != "abs_path"}
                    for f in files]
    plugin = timeline_plugin_active()

    md_files = [f for f in files if f["kind"] == "report"]
    reports = os.path.join(case_dir, "reports")
    best = max(md_files, key=lambda f: _report_rank(f, reports), default=None)

    if not best:
        return {
            "available": False,
            "files": public_files,
            "bundle_available": bool(public_files),
            "timeline_plugin_active": plugin,
            "timeline_template_available": plugin,
            **report_stage(case_dir),
        }
    return {
        "available": True,
        "path": best["path"],
        "name": best["name"],
        "mtime": best["mtime"],
        "files": public_files,
        "bundle_available": bool(public_files),
        "timeline_plugin_active": plugin,
        "timeline_template_available": plugin,
        **report_stage(case_dir),
    }


# ── Indicator summary (catalog is regex-heavy: cached on the graph mtime) ────

_ioc_cache: dict[str, tuple[float, dict]] = {}

_EMPTY_IOC_SUMMARY = {"total": 0, "beliefs_considered": 0, "groups": [], "others": [],
                      "review_total": 0, "affected_total": 0, "context_total": 0, "top": []}


def ioc_groups(catalog: dict) -> list[tuple[str, list, bool]]:
    """The catalog's groups in deliverable order, each marked whether its
    rows count as indicators. Only the typed rows do (the catalog's total,
    the number the report and the IOC export print); the case's own assets,
    the rows to review before use and the values named but not seen in this
    evidence are listed beside them and counted apart, so every page shows
    one indicator count."""
    from core.ioc_catalog import grouped
    typed = {title for title, _rows in grouped(
        {**catalog, "affected_assets": [], "review": [], "context": []})}
    return [(title, rows, title in typed) for title, rows in grouped(catalog)]


def ioc_summary(case_dir: str, *, top: int = 6) -> dict:
    """Indicator counts per group plus the strongest few, for the Overview.

    The catalog itself is a language pass over every recorded belief, while
    the Overview re-reads its projection every few seconds — so the result
    is cached on the claim graph's mtime, the only input that can change it.
    A case with no graph yet answers with zeroes rather than raising: the
    front door must render before the first finding lands.
    """
    path = os.path.join(case_dir, ".atlas", "claim_graph.json")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return dict(_EMPTY_IOC_SUMMARY)
    # the catalog also reads the brief (frame, own assets)
    try:
        mtime = (mtime, os.path.getmtime(os.path.join(case_dir, "CASE.md")))
    except OSError:
        mtime = (mtime, 0)
    cached = _ioc_cache.get(case_dir)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        from core.ioc_catalog import build_catalog
        catalog = build_catalog(case_dir)
    except Exception:  # noqa: BLE001
        return dict(_EMPTY_IOC_SUMMARY)
    groups = ioc_groups(catalog)
    summary = {
        "total": catalog.get("total") or 0,
        "beliefs_considered": catalog.get("beliefs_considered") or 0,
        # The groups that make up the total, and the ones listed beside it.
        "groups": [{"title": title, "count": len(rows)} for title, rows, counted in groups if counted],
        "others": [{"title": title, "count": len(rows)} for title, rows, counted in groups if not counted],
        "review_total": catalog.get("review_total") or 0,
        "affected_total": catalog.get("affected_total") or 0,
        "context_total": catalog.get("context_total") or 0,
        # The top rows: those a located sighting stands behind when the
        # catalogue is sighted (an unchecked row is not a headline).
        "top": [{"value": r.get("value"),
                 "explanation": r.get("explanation") or "",
                 "confidence": r.get("confidence"),
                 "hosts": r.get("hosts") or []}
                for r in [r for r in (catalog.get("iocs") or [])
                          if not catalog.get("sighted")
                          or r.get("standing") in ("cited", "same_host", "elsewhere")][:top]],
    }
    if len(_ioc_cache) > 64:
        _ioc_cache.clear()
    _ioc_cache[case_dir] = (mtime, summary)
    return summary


_response_cache: dict[str, tuple[float, dict]] = {}
_EMPTY_RESPONSE_SUMMARY = {"total": 0, "open": 0, "open_now": 0, "done": 0,
                           "evidence_backed": 0, "prior_only": False, "top": []}


def recommendation_summary(case_dir: str, *, top: int = 3) -> dict:
    """Open recommendations by urgency plus the few that matter most, for
    the Overview. Cached on the claim graph's mtime like the IOC summary:
    the plan changes only when a belief or a recommendation lands."""
    path = os.path.join(case_dir, ".atlas", "claim_graph.json")
    try:
        st = os.stat(path)
    except OSError:
        return dict(_EMPTY_RESPONSE_SUMMARY)
    # mtime alone misses two writes within one second (a run records a
    # finding and its recommendation back to back); size moves every time.
    stamp = (st.st_mtime, st.st_size)
    cached = _response_cache.get(case_dir)
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        from core.recommendations import build_catalog
        catalog = build_catalog(case_dir)
    except Exception:  # noqa: BLE001
        return dict(_EMPTY_RESPONSE_SUMMARY)
    rows = [r for r in catalog.get("recommendations") or [] if r.get("state") == "open"]
    summary = {
        "total": catalog.get("total") or 0,
        "open": catalog.get("open") or 0,
        "open_now": catalog.get("open_now") or 0,
        "done": catalog.get("done") or 0,
        "evidence_backed": catalog.get("evidence_backed") or 0,
        # Every open item rests on prior knowledge alone: worth saying on the
        # front door, because it means "precautions", not "findings".
        "prior_only": bool(rows) and all(r.get("source") == "prior_knowledge" for r in rows),
        "top": [{"id": r["id"], "action": r["action"], "phase": r["phase"],
                 "urgency": r["urgency"], "scope": r["scope"],
                 "basis_confidence": r["basis_confidence"],
                 "hosts": r.get("hosts") or []} for r in rows[:top]],
    }
    if len(_response_cache) > 64:
        _response_cache.clear()
    _response_cache[case_dir] = (stamp, summary)
    return summary


def recommendation_catalog(case_dir: str | os.PathLike) -> dict:
    """The response plan as the Response tab shows it: ordered rows with
    their basis in the beliefs' own words, and the phase groups. Never
    raises — an empty plan is fine, a broken tab is not."""
    from core.recommendations import build_catalog, do_now, grouped
    try:
        catalog = build_catalog(case_dir)
    except Exception:  # noqa: BLE001
        catalog = {"recommendations": [], "total": 0, "open": 0, "open_now": 0,
                   "done": 0, "dismissed": 0, "evidence_backed": 0}
    catalog["now"] = do_now(catalog)
    catalog["groups"] = [{"phase": phase, "recommendations": rows}
                         for phase, rows in grouped(catalog)]
    return catalog


# ── Case Findings (claim graph, arranged for reading) ──────────────────────

_board_cache: dict[str, tuple[float, dict]] = {}

_ATTENTION_STATUSES = frozenset({"needs_review", "conflict"})
_VERSIONED_KINDS = frozenset({"claim", "conclusion", "hypothesis", "recommendation"})
# Mirrors the recorder's default for folding a restated finding
# (ATLAS_FINDING_NEAR_DUPLICATE_MIN in tools/misc.py): the share of one
# statement's content words the other must carry. Display-side, so the
# recorder's own env switch is deliberately not read here.
_RESTATEMENT_MIN = 0.7


def _content_tokens(text: str) -> set[str]:
    """Content words of a statement, the recorder's tokeniser when present."""
    try:
        from tools.accuracy import _tokens
        return set(_tokens(text))
    except Exception:  # noqa: BLE001
        return {w for w in re.findall(r"[a-z0-9][a-z0-9_.:\\/-]{2,}", (text or "").lower())}


def _case_hosts(case_dir: str) -> list[str]:
    """The hosts this case declares (its brief's evidence table), via the
    same helper the claim writer and the report use."""
    try:
        from core.forensic_citation import known_case_hosts
        return list(known_case_hosts(case_dir))
    except Exception:  # noqa: BLE001
        return []


def _hosts_in_statement(statement: str, hosts: list[str]) -> list[str]:
    """Which of the case's hosts a statement names, in its own words —
    `infer_host_from_text`'s rule, with the host list resolved once for
    the whole graph instead of once per node."""
    if not statement or not hosts:
        return []
    try:
        from core.forensic_citation import host_mentioned
    except Exception:  # noqa: BLE001
        return []
    return [h for h in hosts if host_mentioned(h, statement)]


def _version_chains(nodes: dict[str, dict]) -> dict[str, dict]:
    """``{node_id: {chain, index, of, current, supersedes, superseded_by}}``
    for every node that is one version of a belief recorded more than once.

    A chain is the same statement recorded again (same normalised text — the
    identity ``find_claim_by_statement`` uses) or an explicit ``supersedes``
    reference. Ordered by creation; the newest is current. Display only:
    the graph itself is never rewritten here.
    """
    from core.claim_graph import _norm_text
    parent: dict[str, str] = {nid: nid for nid in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    by_text: dict[tuple[str, str], list[str]] = {}
    for nid, n in nodes.items():
        kind = n.get("kind") or "claim"
        # Only beliefs get revised. An observation recorded twice is the same
        # event seen twice, not a newer version of an opinion.
        if kind not in _VERSIONED_KINDS:
            continue
        key = (kind, _norm_text(n.get("statement") or ""))
        if key[1]:
            by_text.setdefault(key, []).append(nid)
    for ids in by_text.values():
        for other in ids[1:]:
            union(ids[0], other)
    for nid, n in nodes.items():
        prev = n.get("supersedes")
        if isinstance(prev, str) and prev in nodes:
            union(prev, nid)
    # Same belief in different words: judged the way the recorder judges a
    # restated finding — on content words, one statement carrying most of
    # the other's. Hard identifiers alone are not enough: two different
    # beliefs about one account share its SID and a timestamp, and chaining
    # them would hide a CONFIRMED belief behind an unrelated later one.
    # Note: O(n^2) over the versioned kinds; index tokens if a case
    # ever carries thousands of claims.
    tokens = _content_tokens
    worded = [(nid, tokens(n.get("statement") or ""))
              for nid, n in nodes.items()
              if (n.get("kind") or "claim") in _VERSIONED_KINDS]
    worded = [(nid, t) for nid, t in worded if len(t) >= 3]
    for i, (na, ta) in enumerate(worded):
        for nb, tb in worded[i + 1:]:
            if nodes[na].get("kind") != nodes[nb].get("kind"):
                continue
            shared = len(ta & tb)
            if shared < 3:
                continue
            if shared / len(ta) >= _RESTATEMENT_MIN or shared / len(tb) >= _RESTATEMENT_MIN:
                union(na, nb)
    groups: dict[str, list[str]] = {}
    for nid in nodes:
        groups.setdefault(find(nid), []).append(nid)
    out: dict[str, dict] = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda i: (nodes[i].get("created_at") or "", i))
        for idx, nid in enumerate(members):
            out[nid] = {
                "chain": members[0],
                "index": idx + 1,
                "of": len(members),
                "current": idx == len(members) - 1,
                "supersedes": members[idx - 1] if idx else None,
                "superseded_by": members[idx + 1] if idx + 1 < len(members) else None,
            }
    return out


def evidence_board(case_dir: str) -> dict:
    """The claim graph plus what Case Findings needs to arrange it:
    a host for every belief (its own field, else the hosts it names), the
    first moment its statement states (the Time layout's order), the
    version chains, an attention flag, and the counts for the band.

    Cached on the graph's mtime: hostname recognition runs the entity
    extractor over every statement, and the page polls every few seconds.
    """
    path = os.path.join(case_dir, ".atlas", "claim_graph.json")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {"graph": None, "mtime": None, "board": {}, "hosts": [],
                "counts": {}}
    cached = _board_cache.get(case_dir)
    if cached and cached[0] == mtime:
        return cached[1]
    from core.incident_window import leading_time
    graph = load_claim_graph(case_dir)
    nodes = {nid: n for nid, n in (graph.get("nodes") or {}).items()
             if isinstance(n, dict)}
    case_hosts = _case_hosts(case_dir)
    chains = _version_chains(nodes)
    board: dict[str, dict] = {}
    hosts: set[str] = set()
    counts = {"kind": {}, "confidence": {}, "conflicts": 0, "needs_review": 0,
              "evidence_refs": 0, "chains": len({c["chain"] for c in chains.values()}),
              "active": 0, "gone": 0}
    for nid, n in nodes.items():
        status = n.get("status") or "new"
        kind = n.get("kind") or "claim"
        chain = chains.get(nid)
        own = str(n.get("host") or "")
        named = _hosts_in_statement(n.get("statement") or "", case_hosts) if not own else []
        hlist = [own] if own else named
        for h in hlist:
            hosts.add(h)
        gone = status in _GONE_STATUSES or bool(chain and not chain["current"])
        attention = (kind == "conclusion"
                     or (kind == "conflict" and status == "conflict")
                     or status in _ATTENTION_STATUSES)
        board[nid] = {
            "host": hlist[0] if len(hlist) == 1 else "",
            "hosts": hlist,
            "t": leading_time(n.get("statement") or ""),
            "version": chain,
            "gone": gone,
            "attention": attention and not gone,
        }
        if gone:
            counts["gone"] += 1
            continue
        counts["active"] += 1
        counts["kind"][kind] = counts["kind"].get(kind, 0) + 1
        tier = (n.get("confidence") or "UNCONFIRMED").upper()
        per_kind = counts["confidence"].setdefault(kind, {})
        per_kind[tier] = per_kind.get(tier, 0) + 1
        if kind == "conflict" and status == "conflict":
            counts["conflicts"] += 1
        if status == "needs_review":
            counts["needs_review"] += 1
        counts["evidence_refs"] += len([e for e in (n.get("evidence") or [])
                                        if isinstance(e, dict)])
    result = {"graph": graph, "mtime": mtime, "board": board,
              "hosts": sorted(hosts, key=str.lower), "counts": counts}
    if len(_board_cache) > 64:
        _board_cache.clear()
    _board_cache[case_dir] = (mtime, result)
    return result


# ── The one aggregate the Overview page needs ────────────────────────────────

def latest_run_journal(case_dir: str) -> dict | None:
    """The newest pre-run record: when it ran and what it handed the
    investigator. The Overview shows it as the delta since the last run."""
    history = os.path.join(case_dir, ".atlas", "run_history")
    try:
        names = sorted(n for n in os.listdir(history)
                       if n.startswith("run-") and n.endswith(".json"))
    except OSError:
        return None
    for name in reversed(names):
        data = _read_json(os.path.join(history, name))
        if not isinstance(data, dict):
            continue
        work = data.get("work")
        return {
            "run_id": data.get("run_id") or name[:-len(".json")],
            "trigger": data.get("trigger") or "",
            "finished_at": data.get("finished_at"),
            "work": work if isinstance(work, dict) else None,
            "why_summary": list(data.get("why_summary") or [])[:6],
        }
    return None


def case_overview(case_dir: str) -> dict:
    """Everything the Case Overview front door shows, in one response.

    Strictly scoped to ``case_dir`` — never reads outside the case directory,
    so two cases can never mix.
    """
    questions = questions_projection(case_dir)
    return {
        "case_dir": os.path.basename(case_dir),
        "case_id": questions["case_id"],
        "questions": questions,
        "claims": claims_summary(case_dir),
        "activity": activity_projection(case_dir),
        "evidence": evidence_summary(case_dir),
        "report": report_status(case_dir),
        "iocs": ioc_summary(case_dir),
        "response": recommendation_summary(case_dir),
        "last_run": latest_run_journal(case_dir),
    }



def ioc_catalog_with_context(case_dir: str | os.PathLike) -> dict:
    """The IOC catalog plus what the IOC tab shows when an indicator is
    expanded: the beliefs it came from in their own words, and where it has
    and has not been searched for. Never raises: an empty context is fine,
    a broken tab is not."""
    from core.ioc_catalog import build_catalog
    catalog = build_catalog(case_dir)
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        nodes = {}
    try:
        from core.ioc_pivots import load_pivots
        pivots = load_pivots(case_dir).get("pivots") or {}
    except Exception:  # noqa: BLE001
        pivots = {}
    for row in (list(catalog.get("iocs") or []) + list(catalog.get("affected_assets") or [])
                + list(catalog.get("review") or []) + list(catalog.get("context") or [])):
        if row.get("sightings"):
            from core.ioc_catalog import _seen_cell
            row["seen"] = _seen_cell(row)
        claims = []
        for cid in (row.get("claim_ids") or [])[:6]:
            n = nodes.get(cid)
            if isinstance(n, dict):
                claims.append({"id": cid, "statement": str(n.get("statement") or "")[:600],
                               "confidence": n.get("confidence"), "host": n.get("host") or "",
                               "status": n.get("status") or ""})
        row["claims"] = claims
        val = str(row.get("value") or "").casefold()
        hit = next((v for k, v in pivots.items()
                    if val and k.split(":", 1)[-1].casefold().endswith(val)), None)
        targets = (hit or {}).get("targets") or {}
        row["searched"] = sorted(t for t, st in targets.items() if st == "searched")
        row["pending"] = sorted(t for t, st in targets.items() if st == "pending")
        # The estate count: rows per table, and the tables a call showed
        # them on (ATLAS_ESTATE_COUNT).
        row["counted"] = {src: int(c.get("full") or c.get("name") or 0)
                          for src, c in ((hit or {}).get("counts") or {}).items()}
        row["shown_on"] = sorted(((hit or {}).get("shown") or {}).keys())
    catalog["groups"] = [{"title": title, "iocs": rows, "counted": counted}
                         for title, rows, counted in ioc_groups(catalog)]
    return catalog
