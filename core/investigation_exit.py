"""Investigation exit control — shared policy for leaving a run cleanly.

This module is the single source of truth for the exit-safety concerns
that would otherwise be disconnected ad-hoc behaviours:

1. **Refuse latch** (Layer 2): repeated identical phase-wrong refuses
   (e.g. reason.synthesize outside Analyze) must force an Analyze transition
   rather than burning tokens in Collect. Latch *state* lives here; DAIR is
   the sole hard phase consumer (synthesize may read the latch as escape).

2. **Blocker-extension identity** (Layer 3): wrap-up must not keep granting
   turn extensions when the blocker fingerprint is unchanged and knowledge
   progress has not moved since the last grant.

3. **Degraded report** (Layer 4): a missing/empty Attack Timeline must not
   hard-block an otherwise writable report — write a partial report with an
   explicit "Timeline unavailable" limitation instead.

4. **Finish classification** (Done owner): ``classify_finish_status`` is the
   sole contract for complete / incomplete_coverage / degraded labels.
   READY_TO_REPORT is an input signal, not a second Done owner.

Production code (tools/dair, tools/reasoning, tools/misc, agent/loop) MUST
consult this module rather than re-deriving these policies. Devtools may
import it for probes.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from core.envfile import env_int

# ── tunables ──────────────────────────────────────────────────────────────

REFUSE_LATCH_MAX = env_int("ATLAS_REFUSE_LATCH_MAX", 3)

# Stable reason prefix for phase-gate refuses recorded via call_abandoned.
# Format: wrong_phase:<tool>:<required_phase>
WRONG_PHASE_PREFIX = "wrong_phase:"

_TIMELINE_UNAVAILABLE_SECTION = """## Attack Timeline

**Timeline unavailable.** A curated Attack Timeline could not be built from
deterministic evidence references for this case. Findings above still stand;
do not infer event order from this section.

"""

_LIMITATIONS_HEADER = "## Limitations\n\n"


def wrong_phase_reason(tool: str, required_phase: str,
                       current_phase: str = "") -> str:
    """Canonical abandon-reason string for a phase-gated tool refuse."""
    cur = current_phase or "unknown"
    return f"{WRONG_PHASE_PREFIX}{tool}:{required_phase}:current={cur}"


def record_wrong_phase_refuse(tool: str, required_phase: str,
                              current_phase: str = "") -> None:
    """Persist a phase refuse so the refuse-latch valve can see it.

    Early-return refuses that never hit `_ask` / middleware would otherwise
    leave no trace — exactly the synthesize-loop failure mode.
    """
    try:
        from core.execution_log import log
        log.record_call_abandoned(
            tool, wrong_phase_reason(tool, required_phase, current_phase),
        )
    except Exception as exc:  # noqa: BLE001
        import sys
        print(f"[Atlas WARN] refuse-latch record failed: {exc!r}", file=sys.stderr)


def consecutive_wrong_phase_refuses(
    tool: str = "reason_synthesize",
    *,
    required_phase: str = "Report",
) -> int:
    """Trailing count of identical wrong-phase abandons for `tool`.

    Stops at the first non-matching abandon or any dair_call that reached
    `required_phase` (latch resets when Report is actually entered).
    """
    needle = f"{WRONG_PHASE_PREFIX}{tool}:{required_phase}"
    count = 0
    try:
        from core.execution_log import log
        for e in reversed(log._entries):
            etype = e.get("type")
            if etype == "dair_call":
                if e.get("current_phase") == required_phase:
                    break
                continue
            if etype != "call_abandoned":
                continue
            reason = str(e.get("reason") or "")
            if e.get("tool") == tool and reason.startswith(needle):
                count += 1
            else:
                break
    except Exception:
        return 0
    return count


def refuse_latch_tripped(
    tool: str = "reason_synthesize",
    *,
    required_phase: str = "Report",
    threshold: int | None = None,
) -> bool:
    thr = REFUSE_LATCH_MAX if threshold is None else threshold
    return consecutive_wrong_phase_refuses(
        tool, required_phase=required_phase) >= thr


# The gate's verdict is BLOCKING_ISSUES, then WARNINGS, then documented
# limitations; only the first section is the blocker set.
_BLOCKING_SECTION_RE = re.compile(
    r"BLOCKING_ISSUES\s*\(\d+\)\s*:(.*?)(?=\n\s*(?:WARNINGS|DOCUMENTED_LIMITATIONS)\s*\(|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def blocker_fingerprint(conclusion: str = "") -> str:
    """Stable identity of the current READY_TO_REPORT:false blocker set.

    Uses the latest pre_report_check conclusion when `conclusion` is empty.
    Only the BLOCKING_ISSUES section is hashed: the warnings beside it
    change as findings are recorded (counts of excluded findings, unmapped
    techniques, indicators seen) while the blockers stand, and a fingerprint
    over the whole verdict never matched twice, so nothing keyed on "the same
    blockers again" could arm. Whitespace and case are normalised so a
    reformulation does not look like progress. A conclusion without the
    section (an older trace, a bare blocker line) is hashed whole, less the
    READY line.
    """
    text = conclusion
    if not text:
        try:
            from core.execution_log import log
            for e in reversed(log._entries):
                if (e.get("type") == "reason_call"
                        and e.get("tool") == "reason_pre_report_check"):
                    text = e.get("conclusion") or ""
                    break
        except Exception:
            text = ""
    m = _BLOCKING_SECTION_RE.search(text or "")
    if m:
        body = m.group(1)
    else:
        # Drop volatile READY line; keep blocker body.
        body = re.sub(
            r"READY_TO_REPORT:\s*(true|false)\s*", "", text or "",
            flags=re.IGNORECASE,
        )
    norm = " ".join(body.split()).lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def unchanged_blocker_verdicts(limit: int = 24) -> int:
    """How many of the newest consecutive report-gate verdicts say the same.

    Counts backwards over ``reason_pre_report_check`` conclusions while the
    blocker fingerprint matches the newest one, so a verdict that changed at
    all resets the count. Fingerprinting the gate's own output rather than
    the agent's prose is deliberate: the gate composes that text, so a run
    that reformats its blockers between passes — a section one time, inline
    items the next — cannot make a standing blocker look like a new one.

    Returns 0 when nothing has been asked yet.
    """
    try:
        from core.execution_log import log
        entries = list(log._entries)
    except Exception:
        return 0
    newest = ""
    seen = 0
    for e in reversed(entries):
        if e.get("type") != "reason_call":
            continue
        if e.get("tool") != "reason_pre_report_check":
            continue
        fp = blocker_fingerprint(e.get("conclusion") or "")
        if not newest:
            newest = fp
        elif fp != newest:
            break
        seen += 1
        if seen >= limit:
            break
    return seen


def knowledge_progressed_since_call_id(since_call_id: int) -> bool:
    """True if any dair_call after `since_call_id` recorded progress.changed."""
    if since_call_id <= 0:
        return True  # no prior extension → treat as fresh
    try:
        from core.execution_log import log
        for e in log._entries:
            if e.get("type") != "dair_call":
                continue
            if int(e.get("call_id") or 0) <= since_call_id:
                continue
            prog = e.get("progress")
            if isinstance(prog, dict) and prog.get("changed") is True:
                return True
    except Exception:
        return True  # fail open: allow extension rather than deadlocking
    return False


def should_grant_blocker_extension(
    *,
    last_fingerprint: str,
    last_extension_call_id: int,
    current_fingerprint: str | None = None,
) -> tuple[bool, str]:
    """Layer 3 policy: grant only when blockers changed or knowledge moved.

    Returns (allow, reason). `reason` is a short machine token for logging.
    """
    fp = current_fingerprint if current_fingerprint is not None else blocker_fingerprint()
    if not fp:
        return True, "no_fingerprint"
    if not last_fingerprint:
        return True, "first_extension"
    if fp != last_fingerprint:
        return True, "blocker_changed"
    if knowledge_progressed_since_call_id(last_extension_call_id):
        return True, "progress_since_extension"
    return False, "identical_blocker_no_progress"


def degraded_report_decision(readiness: dict[str, Any]) -> dict[str, Any]:
    """Layer 4: decide hard-refuse vs degraded write from timeline readiness.

    Returns:
      action: "write" | "degraded_write" | "refuse"
      limitations: list[str]
      gate: optional gate id when refusing
    """
    if readiness.get("ok"):
        return {"action": "write", "limitations": [], "gate": ""}

    finding_count = int(readiness.get("finding_count") or 0)
    error = str(readiness.get("error") or "Attack Timeline required")

    if finding_count > 0:
        return {
            "action": "degraded_write",
            "limitations": [
                "Attack Timeline unavailable — "
                + error.split(":")[0].strip()
                + ".",
                "Report written under degraded timeline policy "
                "(investigation exit Layer 4); event ordering in the "
                "Timeline section must not be treated as authoritative.",
            ],
            "gate": "",
            "timeline_section": _TIMELINE_UNAVAILABLE_SECTION,
        }

    # No findings at all — still produce a partial exit artifact rather than
    # leaving the run with no deliverable.
    return {
        "action": "degraded_write",
        "limitations": [
            "No findings were present in Current Investigation State at "
            "report time.",
            "Attack Timeline unavailable.",
            "This is a partial report documenting investigation limitations; "
            "conclusions must not be overstated.",
        ],
        "gate": "",
        "timeline_section": _TIMELINE_UNAVAILABLE_SECTION,
        "minimal_body": (
            "# Investigation Report (Partial)\n\n"
            "No findings were promoted into Current Investigation State "
            "before report generation.\n\n"
        ),
    }


# The labels classify_finish_status assigns itself. Any other value it
# returns is the raw stopped_reason echoed back — the run was cut off
# (turn cap, wall clock, deadlock, transport error) instead of reaching
# one of the loop's endings.
FINISH_STATUSES = frozenset({
    "complete",
    "incomplete_coverage",
    "exited_degraded_incomplete",
})
# The ending of a run that stopped with content classes undecided (no read
# credited, no reason recorded): outside FINISH_STATUSES by design, so no
# caller counts it as a finish; the disclosure carries the classes.
STOPPED_UNDECIDED = "stopped_undecided"


def ended_through_a_completion_path(finish_status: str) -> bool:
    """Did the run reach one of the loop's endings?

    ``stopped_reason`` names *how* the loop stopped, and several of its
    values — ``closed_out`` above all, the loop writing the reports itself
    once the gate passed — are endings as sound as ``finished``.
    classify_finish_status already treats them alike and lets the coverage
    verdict decide; a caller that re-reads ``stopped_reason`` to ask "did
    it finish" contradicts that and calls a clean run a failed one.
    Empty stays false, so an unset status is never mistaken for an ending.
    """
    return finish_status in FINISH_STATUSES


def classify_finish_status(
    stopped_reason: str,
    *,
    case_dir: str | os.PathLike | None,
    report_written: bool,
    synthesize_ok: bool,
    pre_report_ready: bool,
) -> str:
    """Sole Done-owner contract for run completion labels.

    ``complete`` requires beliefs + soft coverage/Access floor + official
    report + usable synthesize + READY_TO_REPORT:true + no actionable tasks.
    Never invent ``complete`` when any predicate fails or raises.
    """
    # "stall" is a quiet stop the loop could name precisely (forensic tools
    # still gated on dair_assess — agent/loop.py). It must classify exactly
    # like "quiet": the label says *why* the loop stopped, the coverage
    # verdict below says whether the investigation is actually complete.
    # "finish_deferred" is the same kind of label: the model called
    # atlas_finish, the loop held it back for a report or coverage, and
    # nothing followed. Why it stopped is not whether it is complete.
    # "report_stall" is the loop closing out a Report phase whose gate was
    # ready while the model never wrote the report: why it stopped, not
    # whether the investigation is complete.
    # "closed_out" is the loop writing the reports itself once the gate
    # passed; like "finished", whether the case is complete is the coverage
    # verdict below.
    if stopped_reason not in ("finished", "quiet", "stall", "finish_deferred",
                              "report_stall", "closed_out"):
        return stopped_reason
    # A content class with neither a read credited nor a reason at any of
    # these endings makes the run a stopped one, never a finished one
    # (the reason field takes no empty value). One place for the analyst
    # loop, the frontier, the close-out and the wall clock.
    try:
        from core.evidence_disposition import disposition_on, undecided_classes, undecided_items
        from core.coverage_ledger import load_ledger
        if case_dir and disposition_on():
            ledger = load_ledger(case_dir)
            if undecided_classes(ledger) or undecided_items(ledger):
                return STOPPED_UNDECIDED
    except Exception:  # noqa: BLE001 - a check that cannot run never says complete
        pass
    try:
        from core.coverage_ledger import (
            coverage_stats,
            load_ledger,
            ready_for_degraded_exit,
        )
        from core.investigation_state import build_current_investigation_state

        cis = build_current_investigation_state(case_dir) if case_dir else {}
        has_beliefs = bool(cis.get("has_beliefs"))
        ledger_ok = ready_for_degraded_exit(case_dir) if case_dir else True
        stats = coverage_stats(load_ledger(case_dir)) if case_dir else {}
        unseen = int(stats.get("unseen") or 0)
        counts = cis.get("counts") or {}
        open_tasks = int(
            counts.get("investigation_tasks_actionable")
            or cis.get("investigation_tasks_actionable")
            or 0
        )
        # Task soft floor may make ledger_ok true while HV units remain
        # unseen — that unlocks degraded paths only. ``complete`` still
        # requires zero unseen HV units plus critical CASE obligations
        # (e.g. winevt/Security search when disk + session/auth questions).
        from core.deferred_intents import work_order_on
        if work_order_on():
            # Under the work order `complete` is the order's: no due read and
            # no actionable question; the obligation list, the ledger floor
            # and the unseen units are disclosed beside the label
            # (completion_disclosure), not decisive.
            due = _due_reads(case_dir)
            # Evidence disposition: no pending item or class and every left
            # one's check holding under the final scope (no finish refusal:
            # pending units are due triage items, which the order closes).
            evidence_ok = True
            try:
                from core.evidence_disposition import disposition_complete, disposition_on
                if disposition_on() and case_dir:
                    evidence_ok = disposition_complete(case_dir)[0]
            except Exception:  # noqa: BLE001 - a check that cannot run never says complete
                evidence_ok = False
            if (has_beliefs and report_written and synthesize_ok and pre_report_ready
                    and open_tasks == 0 and due == 0 and evidence_ok):
                return "complete"
            if due == 0 and not has_beliefs:
                return "exited_degraded_incomplete"
            return "incomplete_coverage"
        try:
            from core.investigation_obligations import obligations_met_for_complete
            obligations_ok = (
                obligations_met_for_complete(case_dir) if case_dir else True
            )
        except Exception:
            obligations_ok = True
        if (has_beliefs and ledger_ok and report_written and synthesize_ok
                and pre_report_ready and open_tasks == 0
                and unseen == 0 and obligations_ok):
            return "complete"
        if not ledger_ok or unseen > 0 or not obligations_ok:
            return "incomplete_coverage"
        if not has_beliefs:
            return "exited_degraded_incomplete"
        return "incomplete_coverage"
    except Exception:
        if stopped_reason in ("finished", "quiet", "stall"):
            return "incomplete_coverage"
        return stopped_reason


def _due_reads(case_dir) -> int:
    """The work items still due in the case's trace."""
    if not case_dir:
        return 0
    from core.execution_log import trace_entries
    return sum(1 for e in trace_entries(case_dir) or []
               if e.get("type") == "work_item" and e.get("status") == "due")


def completion_disclosure(case_dir: str | os.PathLike | None) -> dict[str, Any]:
    """What no longer decides `complete` under the work order, stated beside
    the label: the coverage ledger's unseen units, whether its floor holds,
    the extracted outputs' file classes no call read, and the obligations
    not met."""
    if not case_dir:
        return {}
    out: dict[str, Any] = {}
    try:
        from core.coverage_ledger import coverage_stats, load_ledger, ready_for_degraded_exit
        out["unseen_units"] = int(coverage_stats(load_ledger(case_dir)).get("unseen") or 0)
        out["ledger_floor_met"] = bool(ready_for_degraded_exit(case_dir))
    except Exception:  # noqa: BLE001
        pass
    try:
        # The extracted outputs left the floor (their reads are the trace's
        # answer); what no call read in them is stated here, beside the label.
        from core.coverage_ledger import extracted_outputs
        outputs = extracted_outputs(case_dir)
        unread = sum(len(o["open"]) for o in outputs)
        if unread:
            out["extracted_classes_unread"] = unread
        # The classes a code fact left, apart: a reasoned class is not an
        # unreasoned one.
        left = sum(len(o.get("left") or {}) for o in outputs)
        if left:
            out["extracted_classes_left"] = left
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.investigation_obligations import unmet_obligation_summaries
        out["obligations_unmet"] = unmet_obligation_summaries(case_dir)
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.evidence_disposition import disposition_complete, disposition_on
        detail = disposition_complete(case_dir)[1] if disposition_on() else {}
        if detail:
            out["evidence_disposition"] = detail
    except Exception as e:  # noqa: BLE001 - said, never silent
        out["evidence_disposition"] = {"error": f"the evidence disposition could not be checked: {e}"[:300]}
    issues = report_gate_open(case_dir)
    if issues:
        out["report_gate_open"] = issues
    hosts = hosts_without_arrival(case_dir)
    if hosts:
        out["hosts_without_arrival"] = hosts
    return out


STOP_RECORD = "stop_record.json"


def record_stop(case_dir: str | os.PathLike, reason: str, composed: dict[str, Any] | None) -> dict[str, Any]:
    """What a stopped run leaves for its report: why it stopped, the items
    still due (count by origin, the first ones named) and whether its
    answers were composed at the stop or are projections from the
    findings. Written to .atlas/ (run-scoped). ``composed`` None records
    a stop whose composition has not run yet: the report written first
    says its answers are projections, and the record written after the
    composition replaces it."""
    import json
    from pathlib import Path
    due: dict[str, int] = {}
    named: list[str] = []
    try:
        from core.execution_log import log
        for i in log.work_items(statuses=("due",)):
            due[str(i.get("origin") or "")] = due.get(str(i.get("origin") or ""), 0) + 1
            if len(named) < 8:
                named.append(f"{i.get('origin')}: {str(i.get('why') or '')[:120]}")
    except Exception:  # noqa: BLE001
        pass
    rec = {"reason": str(reason or "stopped"), "due": due, "due_named": named,
           "composed": dict((composed or {}).get("outcomes") or {}),
           "projections": not bool((composed or {}).get("reached", False)),
           "pending": composed is None, "hurried": bool((composed or {}).get("hurried"))}
    p = Path(case_dir) / ".atlas" / STOP_RECORD
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rec, indent=1), encoding="utf-8")
    except OSError:
        pass
    return rec


def _stop_lines(case_dir: str | os.PathLike) -> list[str]:
    import json
    from pathlib import Path
    try:
        rec = json.loads((Path(case_dir) / ".atlas" / STOP_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    total = sum(int(v) for v in (rec.get("due") or {}).values())
    lines = [f"The run was stopped ({rec.get('reason')}) with {total} item(s) still due"
             + (": " + ", ".join(f"{k} {v}" for k, v in sorted((rec.get("due") or {}).items())) if total else "")]
    if rec.get("projections"):
        out = rec.get("composed") or {}
        projected = int(out.get("fallback") or 0)
        if rec.get("pending"):
            lines.append("Its answers are projections from the findings: the composer had not answered when "
                         "this report was written")
        elif rec.get("hurried") and projected:
            lines.append(f"{projected} answer(s) are projections from the findings: a second stop request "
                         "ended the composition")
        elif projected and (out.get("composed") or out.get("cached")):
            lines.append(f"{projected} answer(s) are projections from the findings: the composer did not "
                         "answer them at the stop")
        else:
            lines.append("Its answers are projections from the findings: the composer could not be reached "
                         "at the stop")
    return lines


def open_limit_lines(case_dir: str | os.PathLike | None) -> list[str]:
    """The limitations code states in every report, whatever a model wrote:
    a stop with the items still due (and whether its answers are only
    projections), the report gate's issues a run ended with, and the incident window's
    residual risk (every host with attacker activity and no stated start,
    which takes the estate start), in the WINDOW block's words."""
    if not case_dir:
        return []
    lines = _stop_lines(case_dir)
    try:
        from core.memory_batch import stop_lines
        lines += stop_lines(case_dir)
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.vol_cache import store_answer_lines
        lines += store_answer_lines(case_dir)
    except Exception:  # noqa: BLE001
        pass
    lines += [f"The report gate was not ready at the run's end: {i}" for i in report_gate_open(case_dir)]
    lines += helper_limit_lines()
    try:
        from core.coverage_ledger import load_ledger
        from core.evidence_disposition import walked_only
        walked = walked_only(load_ledger(case_dir))
        if walked:
            lines.append(f"Memory structures walked only, their scans not run (unlinked or freed objects not "
                         f"seen): {'; '.join(walked)}")
    except Exception:  # noqa: BLE001
        pass
    try:
        # Recurring values the run ruled out only in a disposition: kept out
        # of the findings and the report by design, so said here, every one.
        from core.execution_log import trace_entries
        from core.ioc_pivots import ruled_out_without_finding
        ruled = ruled_out_without_finding(trace_entries(case_dir) or [], case_dir)
        if ruled:
            lines.append(f"Recurring values ruled out without a finding ({len(ruled)}): " + "; ".join(
                f"{d['value']} ({d['kind']}) - disposition call {d['disposition']}: {d['reason']}" for d in ruled))
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.claim_graph import load_graph
        from core.incident_window import incident_window, window_in_frame
        from core.indicators import frame_for
        window = window_in_frame(incident_window(load_graph(case_dir), case_dir=case_dir), frame_for(case_dir))
        hosts = list(window.get("unanchored") or [])           # every host, never cut
        if hosts and window.get("estate"):
            lines.append(f"No start stated for {', '.join(hosts)}: they take the estate start "
                         f"{window['estate'][0]}; if that start is itself before the intrusion, their earlier "
                         "activity reads as inside the window")
        elif hosts:
            lines.append("Attacker labels and no anchor stated on: " + ", ".join(hosts))
    except Exception:  # noqa: BLE001
        pass
    return lines


def hosts_without_arrival(case_dir: str | os.PathLike | None) -> list[str]:
    """Hosts the incident map labels with attacker activity and no stated
    arrival of their own (the window's unanchored hosts, which take the
    estate start), as the case's frame states them (window_in_frame), []
    when the map is off or none."""
    if not case_dir:
        return []
    try:
        from core import incident_map
        from core.incident_window import window_in_frame
        from core.indicators import frame_for
        m = incident_map.open(case_dir)
        if m is None:
            return []
        return [str(h) for h in (window_in_frame(m.window(), frame_for(case_dir)).get("unanchored") or [])]
    except Exception:  # noqa: BLE001
        return []


def helper_limit_lines() -> list[str]:
    """The steps the latest report-gate verdict recorded as limitations
    because a helper model gave no usable answer (reason_pre_report_check,
    core.reason_outcome.helper_unavailable), [] when none."""
    try:
        from core.execution_log import log
        for e in reversed(log._entries):
            if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
                return [str(x) for x in e.get("helper_limitations") or []]
    except Exception:  # noqa: BLE001
        pass
    return []


def report_gate_open(case_dir: str | os.PathLike | None) -> list[str]:
    """The report gate's blocking issues a frontier run ended with (its
    state keeps the last verdict that was not ready), [] when none."""
    if not case_dir:
        return []
    try:
        from core.frontier_queue import load_state
        return [str(i) for i in load_state(case_dir).get("gate_open") or []]
    except Exception:  # noqa: BLE001
        return []


def inject_degraded_sections(markdown: str, decision: dict[str, Any]) -> str:
    """Append/replace timeline + limitations sections for a degraded write."""
    body = markdown or decision.get("minimal_body") or "# Investigation Report\n\n"
    limitations = list(decision.get("limitations") or [])
    timeline = decision.get("timeline_section") or _TIMELINE_UNAVAILABLE_SECTION

    # If an Attack Timeline heading already exists, leave it; otherwise append.
    if not re.search(r"^##\s+Attack Timeline\b", body, re.MULTILINE | re.IGNORECASE):
        body = body.rstrip() + "\n\n" + timeline
    else:
        # Replace empty-ish timeline sections with the unavailable notice.
        body = re.sub(
            r"(^##\s+Attack Timeline\b.*?)(?=^##\s|\Z)",
            timeline,
            body,
            count=1,
            flags=re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )

    lim_block = _LIMITATIONS_HEADER + "".join(f"- {x}\n" for x in limitations) + "\n"
    if re.search(r"^##\s+Limitations\b", body, re.MULTILINE | re.IGNORECASE):
        body = re.sub(
            r"(^##\s+Limitations\b.*?)(?=^##\s|\Z)",
            lim_block,
            body,
            count=1,
            flags=re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
    else:
        body = body.rstrip() + "\n\n" + lim_block
    return body
