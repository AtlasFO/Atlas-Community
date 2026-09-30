"""Run-level budget policy — stall loops, not hard turn aborts.

Philosophy
----------
A DFIR case with large evidence trees may legitimately need hundreds of
agent turns. A global turn cap that *stops* the run conflates two different
problems:

  * **Loop / deadlock** — belief + coverage + exploration are not moving.
    Soft/hard nudges break the loop.
  * **Long productive work** — new artifacts, coverage probes, findings.
    This MUST be allowed to continue.

``ATLAS_AGENT_MAX_TURNS`` default is **0 (unlimited)**. Absolute backstop
remains ``ATLAS_AGENT_MAX_WALL_SECONDS``.

Agent progress uses three signals:
  * belief — ``progress_signature.changed``
  * coverage — coverage ledger fingerprint
  * exploration — analysis artifacts + probed units

Force-report is allowed ONLY when the coverage ledger is ready for
degraded exit, or on wall-clock wrap-up. Belief-only stalls must not
unlock synthesize-escape / degraded finish.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

from core.envfile import env_int

# 0 = no hard turn abort (recommended). Positive = optional hard cap.
MAX_TURNS = env_int("ATLAS_AGENT_MAX_TURNS", 0)

# Advisory nudge once (does not stop) when the run grows long.
TURN_ADVISORY = env_int("ATLAS_AGENT_TURN_ADVISORY", 150)

# Consecutive turns without agent progress before soft / hard action.
# Raised vs an early false exit (soft 8 / hard 20).
STALL_SOFT_TURNS = env_int("ATLAS_AGENT_STALL_SOFT", 25)
STALL_HARD_TURNS = env_int("ATLAS_AGENT_STALL_HARD", 60)

# After hard stall, allow this many more no-progress turns before
# force-report — but only if coverage ledger permits (or wall_clock).
STALL_FORCE_REPORT_GRACE = env_int("ATLAS_AGENT_STALL_FORCE_REPORT_GRACE", 15)

_STALL_SOFT_MSG = (
    "[stall soft] Agent progress (belief/coverage/exploration) has not "
    "moved for {streak} turns. Do NOT repeat the same tool class or invent "
    "paths. Switch approach: probe coverage-ledger gaps with table.* on "
    "already_processed / case-root tabular, open canonical Security.evtx "
    "(single file), advance DAIR toward Collect/Analyze. Do NOT write a "
    "report yet.\n{ledger_nudge}"
)

_STALL_HARD_MSG = (
    "[stall hard] {streak} turns without agent progress. Change approach "
    "or DAIR phase (Triage→Collect→Analyze). Run coverage.ledger_status "
    "to see unseen high-value units, probe them, fix finding citation "
    "gates. Do NOT force a partial report while high-value evidence is "
    "still unseen.\n{ledger_nudge}"
)

_STALL_COVERAGE_REDIRECT_MSG = (
    "[stall coverage-redirect] Belief/exploration stalled and force-report "
    "grace elapsed, but the coverage ledger still has unseen high-value "
    "units — report close-out is blocked. Probe these next (table.* / "
    "single-file parse). If a real probe attempt failed (corrupt/empty/"
    "unparseable), document it with coverage.mark_blocked(path, reason) — "
    "never mark blocked without attempting. Then continue. "
    "Unseen examples: {gaps}"
)

_STALL_FORCE_REPORT_MSG = (
    "[stall force-report] Coverage floor met (or wall-clock) and still no "
    "belief progress after wrap-up. Force dair_assess next_phase=Report, "
    "call reason.synthesize, write a degraded/partial report with "
    "Limitations documenting uncovered/blocked units, then atlas_finish. "
    "Do not return to Triage/Collect loops on the same artifacts."
)

_TURN_ADVISORY_MSG = (
    "[turn advisory] This run has reached {turn} turns and is continuing "
    "(no hard turn abort). Prefer high-yield pivots and already_processed "
    "exports; avoid side-channel EVTX and memory tools when no memory "
    "image exists.\n{ledger_nudge}"
)

_BELIEF_STARVATION_HINT = (
    "[belief starvation] Actionable CASE tasks remain and no claim-graph "
    "beliefs exist — coverage/exploration probes alone do not clear the "
    "stall. Record findings (misc.record_finding) and update tasks "
    "(misc.update_investigation_task) before more disk-open work."
)


@dataclass
class StallState:
    no_progress_streak: int = 0
    soft_injected: bool = False
    hard_injected: bool = False
    force_report_injected: bool = False
    coverage_redirect_injected: bool = False
    # Streak value at the most recent coverage-redirect injection. The
    # redirect re-arms after another force-report grace window: the ledger
    # is re-checked (ready by then → force-report; still open → redirect
    # repeats with current gaps). Without this the first redirect
    # permanently disabled the force-report valve for the rest of the
    # streak — a silent dead end until wall clock.
    redirect_at_streak: int = 0
    advisory_injected: bool = False
    last_belief_snapshot: Any = None
    last_coverage_fp: Any = None
    last_exploration_fp: Any = None
    # Set when force-report message was actually emitted (ledger/wall ok).
    allow_synthesize_escape: bool = False
    # Coverage-only "busy" while CASE tasks lack beliefs.
    belief_starvation: bool = False


def belief_starvation_active(case_dir: str | os.PathLike | None) -> bool:
    """True when actionable investigation tasks exist but no beliefs yet.

    Coverage fingerprint churn must not fully reset the stall streak in
    this state — that is the "busy Triage, 0 findings" class.
    """
    if not case_dir:
        return False
    try:
        from core.investigation_state import build_current_investigation_state
        st = build_current_investigation_state(case_dir)
        actionable = int(
            (st.get("counts") or {}).get("investigation_tasks_actionable")
            or 0
        )
        has_beliefs = bool(st.get("has_beliefs"))
        return actionable > 0 and not has_beliefs
    except Exception:
        return False


def hard_turn_cap_enabled(max_turns: int | None = None) -> bool:
    """True when a positive hard turn cap is active."""
    n = MAX_TURNS if max_turns is None else int(max_turns)
    return n > 0


def initial_turn_limit(max_turns: int | None = None) -> int:
    """Effective turn_limit for the loop."""
    n = MAX_TURNS if max_turns is None else int(max_turns)
    if n > 0:
        return n
    return 10**9


def _ledger_nudge(case_dir: str | os.PathLike | None) -> str:
    try:
        from core.coverage_ledger import format_ledger_nudge
        return format_ledger_nudge(case_dir) or ""
    except Exception:
        return ""


def observe_progress(
    state: StallState,
    *,
    case_dir: str | os.PathLike | None,
) -> StallState:
    """Update stall streak from belief + coverage + exploration.

    Gate-repair loops (recent evidence_strength citation fails) do not
    increment the exit stall streak.
    """
    if not case_dir:
        return state
    try:
        from core import progress_signature as prog
        from core.coverage_ledger import (
            coverage_fingerprint,
            exploration_fingerprint,
            load_ledger,
            recent_gate_repair_active,
        )
        from core.execution_log import log as _elog

        belief_snap = prog.snapshot("cheap")
        try:
            cov_fp = coverage_fingerprint(load_ledger(case_dir))
        except Exception:
            cov_fp = ()
        try:
            exp_fp = exploration_fingerprint(case_dir)
        except Exception:
            exp_fp = ()

        if state.last_belief_snapshot is None:
            state.last_belief_snapshot = belief_snap
            state.last_coverage_fp = cov_fp
            state.last_exploration_fp = exp_fp
            state.no_progress_streak = 0
            return state

        belief_changed = bool(
            prog.diff(state.last_belief_snapshot, belief_snap).changed)
        coverage_changed = cov_fp != state.last_coverage_fp
        exploration_changed = exp_fp != state.last_exploration_fp
        starved = belief_starvation_active(case_dir)
        state.belief_starvation = starved

        #: under belief starvation, coverage/exploration alone is
        # not full agent progress — update fingerprints so we do not
        # re-fire on the same probe, but keep the stall streak alive so
        # soft/hard nudges push toward findings/tasks.
        if starved and not belief_changed and (
                coverage_changed or exploration_changed):
            state.last_coverage_fp = cov_fp
            state.last_exploration_fp = exp_fp
            state.no_progress_streak += 1
            return state

        agent_progressed = (
            belief_changed or coverage_changed or exploration_changed)

        if agent_progressed:
            state.last_belief_snapshot = belief_snap
            state.last_coverage_fp = cov_fp
            state.last_exploration_fp = exp_fp
            state.no_progress_streak = 0
            state.soft_injected = False
            state.hard_injected = False
            state.force_report_injected = False
            state.coverage_redirect_injected = False
            state.redirect_at_streak = 0
            state.allow_synthesize_escape = False
            return state

        # No agent progress — gate repair does not count toward exit stall.
        try:
            entries = list(_elog._entries)
        except Exception:
            entries = []
        if recent_gate_repair_active(entries):
            return state

        state.no_progress_streak += 1
    except Exception:
        pass
    return state


def messages_for_turn(
    state: StallState,
    *,
    turn: int,
    report_written: bool,
    case_dir: str | os.PathLike | None = None,
    wall_clock: bool = False,
) -> list[dict[str, str]]:
    """User-role injections for this turn (may be empty)."""
    out: list[dict[str, str]] = []
    nudge = _ledger_nudge(case_dir)
    if (TURN_ADVISORY > 0 and turn == TURN_ADVISORY
            and not state.advisory_injected):
        state.advisory_injected = True
        out.append({
            "role": "user",
            "content": _TURN_ADVISORY_MSG.format(
                turn=turn, ledger_nudge=nudge),
        })
    if report_written:
        return out
    streak = state.no_progress_streak
    starve_hint = ""
    if state.belief_starvation or belief_starvation_active(case_dir):
        state.belief_starvation = True
        starve_hint = "\n" + _BELIEF_STARVATION_HINT
    if (streak >= STALL_SOFT_TURNS and not state.soft_injected
            and streak < STALL_HARD_TURNS):
        state.soft_injected = True
        out.append({
            "role": "user",
            "content": _STALL_SOFT_MSG.format(
                streak=streak, ledger_nudge=nudge) + starve_hint,
        })
    if streak >= STALL_HARD_TURNS and not state.hard_injected:
        state.hard_injected = True
        out.append({
            "role": "user",
            "content": _STALL_HARD_MSG.format(
                streak=streak, ledger_nudge=nudge) + starve_hint,
        })
    redirect_rearmed = (
        not state.coverage_redirect_injected
        or streak >= state.redirect_at_streak + STALL_FORCE_REPORT_GRACE)
    if (state.hard_injected
            and streak >= STALL_HARD_TURNS + STALL_FORCE_REPORT_GRACE
            and not state.force_report_injected
            and redirect_rearmed):
        ledger_ok = False
        gaps: list[str] = []
        try:
            from core.coverage_ledger import (
                open_unit_paths, ready_for_degraded_exit,
            )
            ledger_ok = bool(ready_for_degraded_exit(case_dir))
            if not ledger_ok:
                gaps = open_unit_paths(case_dir, limit=6)
        except Exception:
            ledger_ok = False
        if wall_clock or ledger_ok:
            state.force_report_injected = True
            state.allow_synthesize_escape = True
            out.append({
                "role": "user",
                "content": _STALL_FORCE_REPORT_MSG,
            })
        else:
            state.coverage_redirect_injected = True
            state.redirect_at_streak = streak
            out.append({
                "role": "user",
                "content": _STALL_COVERAGE_REDIRECT_MSG.format(
                    gaps=", ".join(gaps) if gaps else "(rebuild ledger)"),
            })
    return out


def should_treat_as_wrapup(state: StallState) -> bool:
    """True once hard stall was injected (approach-change wrap marker).

    Synthesize-escape uses ``state.allow_synthesize_escape`` / force-report,
    not this alone.
    """
    return state.hard_injected or state.force_report_injected


def should_allow_synthesize_escape(state: StallState) -> bool:
    """Only force-report (ledger-ready or wall-clock) unlocks synthesize."""
    return bool(state.allow_synthesize_escape or state.force_report_injected)
