"""Independent post-run reviewer for `atlas train`.

After a full autonomous run, a Reviewer — a separate model surface with a
fresh context and no tools — reads the run's execution trace, final report,
and (when a ground-truth answer key exists) objective accuracy/coverage
metrics, then writes a review with actionable recommendations to
reports/<CASE_ID>_run_review.md.

Deliberately a single read-only LLM call rather than a second tool-calling
Agent: the execution-trace singleton (core.execution_log.log) is
process-global, so a second Agent in this process would append to the run
under review. The reviewer only ever consumes digests of it.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from agent.llm import LLMHubClient
from agent.tui import UI
from core.brain import answer_key

# The literal recommendations text the reviewer must use when the run met the
# bar — recommendations are suggested only when improvements are needed.
NO_RECOMMENDATIONS = "None — the run met the bar."

VERDICTS = ("STRONG", "ACCEPTABLE", "NEEDS WORK")


class CrossCaseTraceError(RuntimeError):
    """The process-global execution-log singleton is bound to a DIFFERENT
    case than the run being reviewed.

    The objective-metrics tools (accuracy_compare / coverage_report) read
    that singleton, so grading a run whose own trace names case X while the
    singleton names case Y would mix the two cases into one review. Raised
    instead of silently adopting the other case's trace, counts, and case_id."""

REVIEW_SYSTEM_PROMPT = f"""\
You are an INDEPENDENT DFIR run auditor. You did NOT run this investigation —
you are grading someone else's completed work from its execution trace,
final report, and run statistics. Be a fair, evidence-driven peer reviewer.

Judge the run on:
1. Case question — did the investigation actually answer it, with evidence?
2. Finding quality — is each finding evidence-backed with lineage
   (linked_call_id / input_call_ids)? CONFIRMED findings require a SUPPORTED
   adversarial evaluation and a citation; flag overclaimed tiers.
3. Completeness — missed leads, unexplored pivots, false negatives (when
   objective metrics are provided, treat them as ground truth).
4. Efficiency — wasted or error-heavy tool usage, repeated failures, stalls.
5. Process health — a run that stopped for reason `quiet` or `turn_cap`, or
   recorded zero findings, or never left Triage, is a failed run: diagnose why.

Output format (exactly this structure, GitHub Markdown). The VERDICT line is
MANDATORY and must be the very FIRST line of your response — before any title
or heading. A review without it is invalid. Do not prefix it with '#'.

VERDICT: <one of STRONG | ACCEPTABLE | NEEDS WORK>

## Assessment
<short paragraphs: what the run did well and, if anything, where it fell
short. Cite concrete finding descriptions, call counts, and metrics.>

## Recommendations
<numbered, actionable recommendations — each one concrete enough to apply on
the next run. ONLY include recommendations if the run genuinely needs them.
If the run met the bar, write exactly: {NO_RECOMMENDATIONS}
Do not invent nitpicks to fill the section.>
"""

# 60k, not 12k: at 12k the reviewer reads a clipped excerpt of an ordinary
# complete report and fabricates "report truncated / IoC table cuts off"
# weaknesses, which then stage a false-premise brain candidate.
# When a report genuinely exceeds the cap, _clip_report annotates the excerpt
# so the reviewer never grades the clipping as an analyst defect.
_MAX_REPORT_CHARS = 60000
_MAX_FINDINGS = 60
_MAX_DESC = 240


def _clip_report(text: str, limit: int = _MAX_REPORT_CHARS) -> str:
    """Clip report text for the reviewer prompt, marking any clipping as a
    review artifact rather than a property of the report itself."""
    if len(text) <= limit:
        return text
    return (text[:limit]
            + f"\n\n[NOTE TO REVIEWER: the report continues — this excerpt "
              f"was clipped at {limit} characters FOR REVIEW ONLY. The "
              f"report on disk is complete ({len(text)} characters). Do NOT "
              f"grade truncation or missing sections beyond this point as "
              f"weaknesses.]")


# Review artifacts the reviewer itself (or the meta-review) produces. Never
# candidates for "the run's final report": a live review that a concurrent
# process writes into reports/ would otherwise be graded as the final
# report, and the reviewer would conclude the report is for the wrong case.
_REVIEW_ARTIFACT_SUFFIXES = ("_run_review.md", "_live_review.md",
                             "_meta_review.md")


def find_latest_report(case_dir: Path) -> Path | None:
    """Newest *.md under reports/ or analysis/ (same logic the CLI uses)."""
    candidates = []
    for sub in ("reports", "analysis"):
        d = case_dir / sub
        if d.is_dir():
            candidates += [p for p in d.glob("*.md")
                           if p.is_file()
                           and not p.name.endswith(_REVIEW_ARTIFACT_SUFFIXES)]
    return max(candidates, key=lambda p: p.stat().st_mtime, default=None)


def ground_truth_path(case_dir: Path) -> Path | None:
    for candidate in (case_dir / "ground_truth.json",
                      case_dir / "analysis" / "ground_truth.json"):
        if candidate.is_file():
            return candidate
    return None


def reviewer_model(analyst_model: str = "") -> str:
    """Resolve the reviewer's model id — distinct from the analyst when
    configured: ATLAS_REVIEW_MODEL, then the reviewer's own provider, then
    REASON_MODEL, then the analyst's model. An unset reviewer provider is
    not the LLM hub.

    REASON_MODEL belongs to the reason role and is read only while the
    reviewer has no provider of its own (which is how the reviewer used to
    ride on the reason backend). Letting it outrank an explicit
    ATLAS_REVIEW_PROVIDER would mean that assignment is never followed.
    """
    from core import providers
    explicit = (os.environ.get("ATLAS_REVIEW_MODEL") or "").strip()
    if explicit:
        return explicit
    fallback = ((os.environ.get("REASON_MODEL") or "").strip()
                or (analyst_model or "").strip())
    name = reviewer_provider()
    if not name:
        return fallback
    try:
        return providers.resolve(name).model or fallback
    except providers.UnknownProvider:
        return fallback


def reviewer_provider() -> str:
    """Provider named by ATLAS_REVIEW_PROVIDER. Empty means not configured."""
    from core import providers
    return providers.role_name("ATLAS_REVIEW_PROVIDER")


def load_trace_from_disk(trace_path: Path) -> tuple[str, list[dict]]:
    """Read an execution trace JSON from disk without touching the live
    singleton. Returns (case_id, entries). Raises OSError/ValueError on a
    missing or malformed file."""
    import json
    data = json.loads(Path(trace_path).read_text(encoding="utf-8"))
    return data.get("case_id") or "", list(data.get("entries") or [])


def active_trace_path() -> Path | None:
    """The trace path of the currently-active Atlas session, if any
    (~/.cache/atlas/session.json → its `path`)."""
    import json
    session = Path.home() / ".cache" / "atlas" / "session.json"
    try:
        data = json.loads(session.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    p = data.get("path")
    return Path(p) if p else None


def newest_trace_fallback(case_dir: Path) -> Path | None:
    """Newest *_trace.json under case_dir/analysis/, else under
    cases/*/analysis/ relative to the cwd. Recovery path for review --live
    when the session beacon (~/.cache/atlas/session.json) is missing or was
    wiped while a run is still in flight."""
    candidates = list(Path(case_dir).glob("analysis/*_trace.json"))
    if not candidates:
        candidates = list(Path.cwd().glob("cases/*/analysis/*_trace.json"))
    return max(candidates, key=lambda p: p.stat().st_mtime, default=None)


# An in-flight run flushes its trace on every recorded call, so a trace
# untouched for this long is almost certainly a finished (or dead) run,
# not the one the operator wants a *live* review of.
TRACE_STALE_SECONDS = 600


def _trace_mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _age_minutes(p: Path) -> int:
    import time
    return int(max(0.0, time.time() - _trace_mtime(p)) // 60)


def resolve_review_trace(case_dir: Path, case_explicit: bool) -> tuple[Path | None, str]:
    """Pick the trace for `review` honoring an explicit --case.

    The session beacon is a single global slot that any concurrent Atlas
    process can rewrite (train runs, smoke tests, bridge shims) — or leave
    stale: a train run wipes it via clear_case_run and only re-claims it at
    start_execution_log, so between those points the beacon still names the
    *previous* case's finished trace. When the caller named a case, a beacon
    pointing outside that case must lose to the case's own newest on-disk
    trace — otherwise the review reads a foreign run and writes its report
    (named after the foreign case_id) into this case's reports/ dir. Without
    an explicit case, a beacon whose trace has not been touched for
    TRACE_STALE_SECONDS loses to a more recently modified on-disk trace
    (the actually-running session). Returns (trace_path_or_None, warning).
    """
    beacon = active_trace_path()
    if beacon is not None and not beacon.is_file():
        fallback = newest_trace_fallback(case_dir)
        warn = (f"session beacon points at a missing trace ({beacon}); "
                f"falling back to newest on-disk trace: {fallback}")
        return fallback, warn
    if beacon is not None and case_explicit:
        try:
            inside = Path(case_dir).resolve() in Path(beacon).resolve().parents
        except OSError:
            inside = False
        if not inside:
            fallback = newest_trace_fallback(case_dir)
            warn = (f"session beacon points outside --case ({beacon}); "
                    f"using the case's own trace instead: {fallback}")
            return fallback, warn
    if beacon is not None:
        age_min = _age_minutes(beacon)
        if age_min * 60 < TRACE_STALE_SECONDS:
            return beacon, ""
        newest = newest_trace_fallback(case_dir)
        if (newest is not None
                and newest.resolve() != beacon.resolve()
                and _trace_mtime(newest) > _trace_mtime(beacon)):
            warn = (f"session beacon trace is stale (untouched for "
                    f"{age_min} min): {beacon}; reviewing the most recently "
                    f"modified trace instead: {newest}")
            return newest, warn
        warn = (f"session beacon trace is stale (untouched for {age_min} "
                f"min) — the run it points at has likely finished or died: "
                f"{beacon}")
        return beacon, warn
    fallback = newest_trace_fallback(case_dir)
    warn = ""
    if fallback is not None:
        warn = (f"session beacon missing — falling back to newest on-disk "
                f"trace (last modified {_age_minutes(fallback)} min ago): "
                f"{fallback}")
    return fallback, warn


# ── deterministic stall detection (no LLM) ───────────────────────────────────

# Thresholds are conservative and overridable; every signal reports the
# observed value alongside the threshold so an operator can recalibrate.
STALL_MIN_TOOL_CALLS = 30        # below this a run is just young, not stalled
STALL_FAILURE_RATE = 0.20        # fraction of tool_calls that errored
STALL_FINDINGS_STARVED = 40      # tool_calls with zero findings recorded
STALL_LOOP_REPEATS = 8           # identical normalized command repeats
STALL_RAWBASH_SHARE = 0.60       # share of tool_calls that are bare shell
STALL_DAIR_IGNORED = 2           # DAIR recommended a transition, never taken
STALL_LOOP_WINDOW = 60           # trailing tool_calls scanned for command loops
STALL_PIPELINE_WINDOW = 25       # trailing entries scanned for finding-pipeline work

_RAWBASH_VERBS = {
    "openssl", "grep", "python3", "python", "cat", "xxd", "strings", "find",
    "ls", "head", "tail", "dd", "hexdump", "awk", "sed", "cut", "sort", "file",
    "echo", "printf", "base64", "cut", "tr", "wc",
}

# MCP tools that execute arbitrary shell the agent hands them. A shell verb run
# through these is a genuine bypass of typed forensic tools; the same verb as a
# typed tool's internal subprocess is not.
_GENERIC_EXECUTOR_TOOLS = {"misc_batch_run", "batch_run", "misc_misc_batch_run"}


def _cmd_text(entry: dict) -> str:
    cmd = entry.get("cmd")
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd)
    return str(cmd or "")


def _normalize_cmd(text: str) -> str:
    """Collapse a command to a loop signature: first two tokens, digits and
    quoted strings masked, so `openssl enc -aes-128-cbc... -k secret` and
    `openssl enc -aes-128-ecb ... -k key2` count as the same rabbit hole."""
    import re
    toks = text.strip().split()
    if not toks:
        return ""
    verb = toks[0].split("/")[-1]
    sub = toks[1] if len(toks) > 1 and not toks[1].startswith("-") else ""
    key = f"{verb} {sub}".strip()
    return re.sub(r"\d+", "#", key)


def detect_stall(entries: list[dict]) -> dict:
    """Score an execution trace for stall signatures. Pure function, no LLM.
    Returns per-signal dicts with observed vs threshold, an overall
    `stalled` bool, and a `severity` in {none, low, medium, high}."""
    tool_calls = [e for e in entries if e.get("type") == "tool_call"]
    n = len(tool_calls)
    findings = [e for e in entries if e.get("type") == "finding"]
    dair_calls = [e for e in entries if e.get("type") == "dair_call"]

    # Gate refusals are the protections working as designed, not tool failures;
    # counting them tripped high_failure_rate on a healthy run. expected_nonzero is a
    # comparison/search verb exiting 1 (differ / no-match) — a result, not a
    # failure. analyst_error
    # and tool_error still count. Older traces carry no failure_class and count
    # as before.
    _NON_FAILURES = {"gate_refusal", "expected_nonzero", "disk_floor"}
    failures = sum(1 for e in tool_calls
                   if not e.get("success", True)
                   and e.get("failure_class") not in _NON_FAILURES)
    failure_rate = (failures / n) if n else 0.0

    # DAIR recommended a phase transition (next_phase set and != current) that
    # never happened — the current_phase never became any recommended next.
    recommended, reached = set(), set()
    for e in dair_calls:
        cur, nxt = e.get("current_phase"), e.get("next_phase")
        if cur:
            reached.add(cur)
        if nxt and nxt != cur:
            recommended.add(nxt)
    dair_ignored = len([r for r in recommended if r not in reached])
    # count how many dair_calls recommended-but-unreached, for the observed value
    dair_ignored_calls = sum(
        1 for e in dair_calls
        if e.get("next_phase") and e["next_phase"] != e.get("current_phase")
        and e["next_phase"] not in reached)
    # A run that visited several phases, reached Report, or recorded real
    # findings is progressing — not stuck — even if a single recommended
    # transition was skipped or a tool was repeated. This distinguishes the
    # genuinely-stalled run (pinned in one phase, no findings) from a healthy
    # run that merely looks busy.
    finding_count = len(findings)
    progressed = len(reached) >= 3 or "Report" in reached
    productive = finding_count >= 3

    # Rabbit-hole loop: most-repeated normalized command in the TRAILING
    # window only. A loop the run already escaped must not keep flagging a
    # live run forever.
    # Loops are keyed by (routed mcp_tool, signature): a typed tool logs its
    # internal subprocess cmd, so a bare `strings` signature alone reads as
    # raw shell and made the live LLM reviewer prescribe "route through MCP"
    # to a run that already was routed.
    # Carrying the routed tool name lets the stall report say which tool is
    # looping — repetition problem, not a routing problem.
    loop_counts: dict[tuple[str | None, str], int] = {}
    for e in tool_calls[-STALL_LOOP_WINDOW:]:
        sig = _normalize_cmd(_cmd_text(e))
        if not sig:
            continue
        tool = e.get("mcp_tool")
        routed = tool if tool and tool not in _GENERIC_EXECUTOR_TOOLS else None
        loop_counts[(routed, sig)] = loop_counts.get((routed, sig), 0) + 1
    top_loop, top_loop_n, top_loop_tool = "", 0, None
    if loop_counts:
        (top_loop_tool, top_loop), top_loop_n = max(
            loop_counts.items(), key=lambda kv: kv[1])

    # Raw-bash dominance: tool_calls whose verb is a bare shell utility.
    # A "raw shell" call is a bare shell verb run through the GENERIC batch
    # executor (misc_batch_run) rather than a typed forensic tool. A verb-only
    # check misfires: typed wrappers log their internal subprocess cmd
    # (strings_strings_grep logs "strings -a …"), so on an all-typed run every
    # call matches _RAWBASH_VERBS.
    # The mcp_tool field (stamped by middleware) disambiguates: only count a
    # verb match when it came through the generic executor. Entries with no
    # mcp_tool (older traces) fall back to the verb-only heuristic so the
    # signal still works on historical data.
    def _is_rawbash(e: dict) -> bool:
        verb = _normalize_cmd(_cmd_text(e)).split(" ")[0]
        if verb not in _RAWBASH_VERBS:
            return False
        tool = e.get("mcp_tool")
        if tool is None:
            return True  # legacy trace without mcp_tool: verb-only fallback
        return tool in _GENERIC_EXECUTOR_TOOLS

    rawbash = sum(1 for e in tool_calls if _is_rawbash(e))
    rawbash_share = (rawbash / n) if n else 0.0

    young = n < STALL_MIN_TOOL_CALLS

    # Finding-pipeline damper: a live run with zero findings recorded is not
    # starved if its trailing entries show the finding pipeline actively
    # working.
    _PIPELINE_TOOLS = ("reason_hypothesize", "reason_evaluate_finding",
                       "reason_confidence_score", "reason_cite_check",
                       "reason_reason_hypothesize",
                       "reason_reason_evaluate_finding",
                       "reason_reason_confidence_score",
                       "reason_reason_cite_check")
    pipeline_active = any(
        e.get("type") == "reason_call" and e.get("tool") in _PIPELINE_TOOLS
        for e in entries[-STALL_PIPELINE_WINDOW:])

    signals = {
        "findings_starved": {
            "hit": (n >= STALL_FINDINGS_STARVED and len(findings) == 0
                    and not pipeline_active),
            "tool_calls": n, "findings": len(findings),
            "pipeline_active": pipeline_active,
            "threshold": STALL_FINDINGS_STARVED},
        "high_failure_rate": {
            "hit": (not young) and failure_rate >= STALL_FAILURE_RATE,
            "failures": failures, "rate": round(failure_rate, 3),
            "threshold": STALL_FAILURE_RATE},
        "dair_transition_ignored": {
            # only a real stall when the run is pinned in one phase — a run
            # that reached several phases obviously honored its transitions.
            "hit": (dair_ignored >= 1 and dair_ignored_calls >= STALL_DAIR_IGNORED
                    and len(reached) <= 1),
            "recommended_unreached": sorted(recommended - reached),
            "occurrences": dair_ignored_calls,
            "phases_reached": sorted(reached),
            "threshold": STALL_DAIR_IGNORED},
        "command_loop": {
            "hit": top_loop_n >= STALL_LOOP_REPEATS,
            "signature": top_loop, "repeats": top_loop_n,
            "routed_tool": top_loop_tool,
            "threshold": STALL_LOOP_REPEATS},
        "rawbash_dominance": {
            "hit": (not young) and rawbash_share >= STALL_RAWBASH_SHARE,
            "share": round(rawbash_share, 3), "raw": rawbash, "of": n,
            "threshold": STALL_RAWBASH_SHARE},
    }
    hits = [k for k, v in signals.items() if v["hit"]]
    # Findings-starvation or an ignored DAIR transition alone is enough to be a
    # stall; otherwise it takes two corroborating signals.
    hard = {"findings_starved", "dair_transition_ignored"}
    if progressed or productive:
        # The run is demonstrably making progress; any fired signals are
        # advisory (e.g. a repeated tool), not a stall.
        stalled = False
        severity = "low" if hits else "none"
    else:
        stalled = bool(hard & set(hits)) or len(hits) >= 2
        severity = ("high" if len(hits) >= 3
                    or (hard & set(hits) and len(hits) >= 2)
                    else "medium" if stalled
                    else "low" if hits else "none")
    return {"stalled": stalled, "severity": severity, "hits": hits,
            "signals": signals, "young": young, "tool_calls": n,
            "phases_reached": sorted(reached), "findings": finding_count,
            "progressed": progressed}


LIVE_REVIEW_SYSTEM_PROMPT = """\
You are an INDEPENDENT DFIR run supervisor observing an investigation that is
STILL RUNNING. You did not run it. A deterministic pre-check has flagged it as
possibly stalled. Your job is a short, decisive intervention memo that gets the
run un-stuck — not a grade.

You are given: the case, the execution-trace digest, and a STALL REPORT with
concrete signals (e.g. stuck in one DAIR phase despite a recommended
transition, high tool-failure rate, a repeated-command rabbit hole, raw-bash
dominance that can't be cited through the mcp_routing gate, zero findings).

Rules of this framework you can rely on when advising:
- DAIR prescribes the phase; the analyst must actually call dair_assess and
  honor the recommended next_phase — it does not advance on its own.
- Findings must be recorded via record_finding and need lineage; evidence
  gathered by raw bash cannot be cited — the same work must be re-run through
  the MCP-routed tool so it gets a call_id.
- Only advise "route through MCP" when the stall report itself flags RAW-BASH
  DOMINANCE. A COMMAND LOOP on an MCP-routed tool is a repetition problem —
  those calls are already citable; advise varying arguments, narrowing scope,
  or pivoting to a different tool, never re-routing work that is routed.
- A run drowning in permutations (e.g. brute-forcing crypto) should step back,
  record what is already known, and move to the next phase.

Output format (GitHub Markdown, be concise):

STATUS: <STALLED | AT RISK | HEALTHY>

## Diagnosis
<2-4 sentences naming the concrete stall signals and the likely root cause.>

## Unstick actions
<numbered, imperative, specific: the exact DAIR transition to take, which
rabbit hole to abandon, which MCP tool to route through instead of raw bash,
and which already-gathered facts to record as findings right now. If the run
is actually healthy, say so and keep this to a single line.>
"""


class Reviewer:
    """Grades a completed run and writes reports/<CASE_ID>_run_review.md."""

    def __init__(self, client: LLMHubClient, case_dir: Path,
                 ui: UI | None = None, gt_dir: Path | None = None):
        self.client = client
        self.case_dir = case_dir
        self.ui = ui or UI(quiet=True)
        # Where the answer key lives when it isn't in case_dir: mirror-case
        # runs (train --output-dir) keep ground_truth.json in the REAL case
        # so the analyst under review can't read it mid-run.
        self.gt_dir = gt_dir

    def _answer_key_secrets(self) -> list[str]:
        """Verbatim answer-key secrets for this case, read server-side only to
        scrub them out of the reviewer's prompt and its persisted output. The
        raw key must never survive into reports/<CASE_ID>_run_review.md — a
        durable, analyst-visible surface. Mirror-case runs keep the ground
        truth in gt_dir, so fall back to it."""
        secrets = answer_key.load_secrets(self.case_dir)
        if not secrets and self.gt_dir is not None:
            secrets = answer_key.load_secrets(self.gt_dir)
        return secrets

    # ── evidence gathering (all read-only) ───────────────────────────────

    def _summarize_trace(self, entries: list[dict] | None = None,
                         case_id: str | None = None) -> tuple[str, str]:
        """Compact digest of an execution trace. Defaults to the live
        singleton; pass `entries`/`case_id` to summarize a trace read from
        disk (an in-flight run in another process). Returns
        (case_id, digest_text)."""
        if entries is None:
            from core.execution_log import log
            entries = list(log._entries)
            case_id = case_id or log._case_id
        case_id = case_id or self.case_dir.name
        if not entries:
            return case_id, "(no execution trace entries — the run recorded nothing)"
        by_type: dict[str, int] = {}
        for e in entries:
            t = e.get("type") or "unknown"
            by_type[t] = by_type.get(t, 0) + 1
        lines = [f"entries: {len(entries)} — "
                 + ", ".join(f"{t}×{n}" for t, n in sorted(by_type.items()))]

        phases = []
        for e in entries:
            if e.get("type") == "dair_call":
                cur, nxt = e.get("current_phase"), e.get("next_phase")
                step = f"{cur}→{nxt}" if nxt and nxt != cur else str(cur)
                if not phases or phases[-1] != step:
                    phases.append(step)
        if phases:
            lines.append("DAIR phase path: " + " | ".join(phases[:30]))

        # Split genuine tool failures from gate refusals. A gate_refusal is a
        # protective gate working as designed (tier/lineage/DAIR-window
        # enforcement on record_finding, etc.) — NOT a tool defect. Lumping
        # them together made the reviewer repeatedly mis-frame "N failed
        # record_finding calls" as "diagnose a schema bug" and auto-stage a
        # wrong learning. The
        # failure_class field is already stamped on each tool_call.
        unsuccessful = [e for e in entries if e.get("type") == "tool_call"
                        and not e.get("success", True)]
        # expected_nonzero (cmp/diff/grep exit 1 = differ/no-match) is a result;
        # disk_floor is a disk-space fail-safe refusal — neither is a tool
        # failure, so drop both from the digest.
        tool_errors = [e for e in unsuccessful
                       if e.get("failure_class") not in
                       ("gate_refusal", "expected_nonzero", "disk_floor")]
        gate_refusals = [e for e in unsuccessful
                         if e.get("failure_class") == "gate_refusal"]

        def _verb(e: dict) -> str:
            cmd = e.get("cmd")
            if isinstance(cmd, list):
                return str(cmd[0]) if cmd else "?"
            if isinstance(cmd, str) and cmd:
                return cmd.split()[0]
            return str(e.get("tool") or "?")

        if tool_errors:
            worst: dict[str, int] = {}
            for e in tool_errors:
                worst[_verb(e)] = worst.get(_verb(e), 0) + 1
            lines.append(f"failed tool calls (genuine errors): {len(tool_errors)}"
                         " — top: " + ", ".join(f"{t}×{n}" for t, n in sorted(
                             worst.items(), key=lambda kv: -kv[1])[:5]))
        if gate_refusals:
            worst_g: dict[str, int] = {}
            for e in gate_refusals:
                worst_g[_verb(e)] = worst_g.get(_verb(e), 0) + 1
            lines.append(
                f"gate refusals (protections working, NOT tool failures): "
                f"{len(gate_refusals)} — top: "
                + ", ".join(f"{t}×{n}" for t, n in sorted(
                    worst_g.items(), key=lambda kv: -kv[1])[:5])
                + ". These are tier/lineage/DAIR-window enforcement; do not "
                  "recommend 'fix the schema' — the correct response is to run "
                  "the required reason.* chain before recording.")

        findings = [e for e in entries if e.get("type") == "finding"]
        ak_secrets = self._answer_key_secrets()
        lines.append(f"\nfindings recorded: {len(findings)}")
        for f in findings[:_MAX_FINDINGS]:
            lineage = f.get("input_call_ids") or (
                [f["linked_call_id"]] if f.get("linked_call_id") else [])
            desc, _ = answer_key.redact(
                (f.get('description') or '')[:_MAX_DESC], ak_secrets)
            lines.append(f"- [{f.get('confidence')}] {desc}"
                         f" (lineage: {lineage or 'NONE'})")
        if len(findings) > _MAX_FINDINGS:
            lines.append(f"- … {len(findings) - _MAX_FINDINGS} more")

        corrections = [e for e in entries if e.get("type") == "self_correction"]
        if corrections:
            lines.append(f"\nself-corrections: {len(corrections)}")
        reason_calls = [e for e in entries if e.get("type") == "reason_call"]
        if reason_calls:
            lines.append("\nadversarial-review calls: "
                         + ", ".join(sorted({str(e.get('tool'))
                                             for e in reason_calls})))
        return case_id, "\n".join(lines)

    def own_trace_path(self) -> Path | None:
        """Newest ``*_trace.json`` under THIS run's own ``analysis/`` dir.

        The reviewer must summarize the run it was handed (``self.case_dir``),
        not whatever case the process-global execution-log singleton was last
        pointed at. That singleton — and the ``~/.cache/atlas/session.json``
        beacon it persists — is a single slot any concurrent Atlas process can
        repoint (a harness subprocess, smoke script, live reviewer). Trusting
        it lets a review adopt another case's trace and case_id; binding to
        the case dir's own trace closes that."""
        analysis = self.case_dir / "analysis"
        if not analysis.is_dir():
            return None
        traces = list(analysis.glob("*_trace.json"))
        return max(traces, key=lambda p: p.stat().st_mtime, default=None)

    def _resolve_run_trace(self) -> tuple[list[dict] | None, str]:
        """Bind the review to the run's own trace + case_id.

        Returns ``(entries, case_id)``. ``entries`` is None only when no
        on-disk trace exists for this case — then the digest falls back to the
        live singleton (used by ad-hoc smoke scripts and unit fixtures that
        never wrote an ``analysis/`` trace).

        Raises CrossCaseTraceError when the live singleton has drifted to a
        DIFFERENT case than the run's own trace: the objective-metrics tools
        read that singleton, so proceeding would grade the wrong case.
        """
        from core.execution_log import log
        own = self.own_trace_path()
        if own is None:
            # No trace on disk for this case — fall back to the singleton for
            # both content and naming (preserves pre-bind behavior).
            return None, (log._case_id or self.case_dir.name)
        try:
            disk_case_id, entries = load_trace_from_disk(own)
        except (OSError, ValueError) as e:
            self.ui.warn(f"own trace unreadable ({own}): {e}; "
                         f"falling back to the live singleton")
            return None, (log._case_id or self.case_dir.name)
        disk_case_id = disk_case_id or self.case_dir.name
        live_id = log._case_id
        if live_id and live_id != disk_case_id:
            raise CrossCaseTraceError(
                f"cross-case bleed: this run's own trace ({own}) is for "
                f"case_id={disk_case_id!r}, but the process-global "
                f"execution-log singleton is bound to case_id={live_id!r} "
                f"(path={log._path!r}). The objective-metrics tools read that "
                f"singleton, so grading would mix cases. Refusing. Likely "
                f"cause: a concurrent Atlas process (a harness subprocess, "
                f"smoke script, or live reviewer) repointed "
                f"~/.cache/atlas/session.json. Re-run the review in a fresh "
                f"process bound only to this case.")
        return entries, disk_case_id

    def objective_metrics_data(self) -> dict:
        """Structured accuracy_compare + coverage_report results against the
        live trace, when a ground-truth answer key ships with the case.
        Best-effort: unavailable sections are None with the reason kept."""
        data: dict = {"ground_truth": None, "accuracy": None,
                      "accuracy_unscorable": None,
                      "false_negatives": [], "coverage": None,
                      "gt_exposure": None,
                      "errors": []}
        gt = ground_truth_path(self.case_dir)
        if gt is None and self.gt_dir is not None:
            gt = ground_truth_path(self.gt_dir)
        if gt is not None:
            data["ground_truth"] = gt.name
            try:
                from tools.accuracy import accuracy_compare
                r = accuracy_compare(str(gt))
                if r.get("unscorable"):
                    # A CTF flag/hash answer key, not finding-shaped GT — record
                    # it as unscorable so the reviewer does NOT read a false 0%.
                    data["accuracy_unscorable"] = r.get("reason", "unscorable")
                elif r.get("success", True) and "summary" in r and r["summary"]:
                    data["accuracy"] = r["summary"]
                    ak_secrets = self._answer_key_secrets()
                    # A miss whose fact a credited finding states in another
                    # sentence is on record; the reviewer must not read it
                    # as evidence the run never found it.
                    bundled_in = {b.get("ground_truth_id"): b.get("trace_call_id")
                                  for b in (r.get("bundled") or [])}
                    data["false_negatives"] = [
                        {"id": fn.get("id", ""),
                         "description": answer_key.redact(
                             fn.get("description", "")[:_MAX_DESC],
                             ak_secrets)[0],
                         **({"bundled_in_call_id": bundled_in[fn.get("id", "")]}
                            if fn.get("id", "") in bundled_in else {})}
                        for fn in (r.get("false_negatives") or [])[:20]]
            except Exception as e:  # metrics are best-effort context
                data["errors"].append(f"accuracy comparison unavailable: {e}")
            # Seen-vs-reported audit: splits every miss into a coverage gap
            # (never-surfaced) vs a reasoning gap (surfaced-not-reported).
            # Ids and classifications only — no ground-truth content.
            try:
                import json as _json
                from core.brain import gt_exposure as _gt_exposure
                entries, _ = self._resolve_run_trace()
                if entries:
                    exp = _gt_exposure.audit(
                        _json.loads(gt.read_text(encoding="utf-8")), entries)
                    data["gt_exposure"] = {
                        "summary": exp["summary"],
                        "not_reported": [
                            {"id": it["id"],
                             "classification": it["classification"],
                             "first_seen_call_id": it["first_seen_call_id"],
                             "first_seen_tool": it["first_seen_tool"]}
                            for it in exp["items"]
                            if it["classification"] in
                            ("surfaced-not-reported", "never-surfaced")][:20],
                    }
            except Exception as e:
                data["errors"].append(f"gt exposure audit unavailable: {e}")
        try:
            from tools.coverage import coverage_report
            r = coverage_report()
            if r.get("success", True) and r.get("summary"):
                data["coverage"] = {
                    "summary": r["summary"],
                    "gaps": sorted(r.get("gaps") or [])[:25]}
        except Exception as e:
            data["errors"].append(f"coverage report unavailable: {e}")
        return data

    def _objective_metrics(self, data: dict | None = None) -> str:
        """Render objective_metrics_data() as prose for the review prompt."""
        if data is None:
            data = self.objective_metrics_data()
        sections = []
        s = data.get("accuracy")
        if s:
            sections.append(
                "Accuracy vs ground truth "
                f"({data.get('ground_truth')}): precision={s.get('precision')}, "
                f"recall={s.get('recall')}, f1={s.get('f1')}, "
                f"TP={s.get('true_positive_count')}, "
                f"FP={s.get('false_positive_count')}, "
                f"FN={s.get('false_negative_count')}")
            fns = data.get("false_negatives") or []
            if fns:
                sections.append("Missed expected findings:\n" + "\n".join(
                    f"- {fn.get('id')}: {fn.get('description', '')}"
                    + (f" [stated inside finding call #{fn['bundled_in_call_id']}"
                       " that was credited to another item — recorded, not "
                       "missed; a granularity effect of 1:1 matching]"
                       if fn.get("bundled_in_call_id") is not None else "")
                    for fn in fns))
        exp = data.get("gt_exposure")
        if exp:
            counts = exp.get("summary") or {}
            sections.append(
                "Ground-truth exposure (seen vs reported): "
                + " · ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                + ". surfaced-not-reported = the run SAW the artifact in tool "
                  "output but never recorded it (attention/reasoning gap); "
                  "never-surfaced = no tool output contained it (coverage/"
                  "tooling gap). Weigh these differently.")
            nr = exp.get("not_reported") or []
            if nr:
                sections.append("Non-reported ground-truth items:\n" + "\n".join(
                    f"- {it['id']}: {it['classification']}"
                    + (f" (first seen call #{it['first_seen_call_id']} via "
                       f"{it['first_seen_tool'] or '?'})"
                       if it.get("first_seen_call_id") is not None else "")
                    for it in nr))
        cov = data.get("coverage")
        if cov:
            sections.append(f"TTP coverage: {cov['summary']}")
            if cov.get("gaps"):
                sections.append("Untouched TTP gaps: "
                                + ", ".join(cov["gaps"]))
        if data.get("accuracy_unscorable") and not s:
            sections.append(
                "Accuracy vs ground truth: UNSCORABLE — "
                f"{data['accuracy_unscorable']}. This is NOT 0% accuracy; "
                "no accuracy signal is available. Judge this run on process "
                "quality, evidence lineage, and internal consistency, exactly "
                "as you would a case with no ground truth.")
        sections += [f"({e})" for e in data.get("errors") or []]
        return "\n\n".join(sections) or "(no objective metrics available — " \
            "no ground_truth.json ships with this case; judge on process " \
            "quality and internal consistency)"

    def _build_context(self, run_stats: dict, question: str,
                       metrics: dict | None = None,
                       entries: list[dict] | None = None,
                       case_id: str | None = None) -> str:
        case_id, trace_digest = self._summarize_trace(entries=entries,
                                                      case_id=case_id)
        report = find_latest_report(self.case_dir)
        report_text = "(no final report was written)"
        if report is not None:
            try:
                report_text = _clip_report(report.read_text(encoding="utf-8"))
            except OSError as e:
                report_text = f"(final report unreadable: {e})"
        stats_lines = [
            f"stopped_reason: {run_stats.get('stopped_reason')}",
            f"turns: {run_stats.get('turns')}",
            f"duration_seconds: {run_stats.get('duration_seconds')}",
            f"findings_recorded: {run_stats.get('findings_recorded')}",
            f"tokens: {run_stats.get('input_tokens')} in / "
            f"{run_stats.get('output_tokens')} out",
        ]
        calls = run_stats.get("tool_calls") or []
        if calls:
            counts: dict[str, int] = {}
            for tc in calls:
                counts[tc["name"]] = counts.get(tc["name"], 0) + 1
            top = sorted(counts.items(), key=lambda kv: -kv[1])[:10]
            stats_lines.append(
                f"tool calls: {len(calls)} "
                f"({sum(1 for tc in calls if tc.get('error'))} errors) — top: "
                + ", ".join(f"{n}×{c}" for n, c in top))
        return (
            f"CASE: {case_id}\n"
            f"CASE QUESTION: {question or '(not provided)'}\n\n"
            f"## Run statistics\n" + "\n".join(stats_lines) + "\n\n"
            f"## Execution-trace digest\n{trace_digest}\n\n"
            f"## Objective metrics\n{self._objective_metrics(metrics)}\n\n"
            f"## Final report (as written by the run)\n{report_text}\n"
        )

    # ── the review ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_verdict(text: str) -> str:
        for line in text.splitlines():
            # Reviewers sometimes format the verdict as a markdown heading
            # ("## VERDICT: ACCEPTABLE") or bold ("**VERDICT:** …") — strip
            # leading markup before matching.
            norm = line.strip().lstrip("#*_>- ").upper()
            if norm.startswith("VERDICT"):
                # Match by position, not tuple order: "ACCEPTABLE (not
                # STRONG)" must return ACCEPTABLE, not STRONG.
                found = [(norm.find(v), v) for v in VERDICTS if v in norm]
                if found:
                    return min(found)[1]
        return None  # no verdict line present — caller decides how to handle

    def _verdict_or_repair(self, review_text: str) -> str:
        """Parse the verdict; if the reviewer omitted the VERDICT line, do one cheap
        re-ask for just the verdict rather than silently defaulting to the
        worst grade. Only a genuinely unparseable re-ask falls back to
        NEEDS WORK (a review with no verdict at all is itself a defect)."""
        v = self._parse_verdict(review_text)
        if v is not None:
            return v
        try:
            resp = self.client.chat(
                [{"role": "system", "content":
                  "You are grading a DFIR run review. Read it and reply with "
                  "EXACTLY one line and nothing else: "
                  "VERDICT: STRONG | ACCEPTABLE | NEEDS WORK"},
                 {"role": "user", "content": review_text[:_MAX_REPORT_CHARS]}])
            repaired = self._parse_verdict((resp.content or "").strip())
            if repaired is not None:
                self.ui.info(f"reviewer omitted VERDICT line; repaired to "
                             f"{repaired} via re-ask")
                return repaired
        except Exception as e:
            self.ui.warn(f"verdict repair re-ask failed: {e}")
        return "NEEDS WORK"

    def review(self, run_stats: dict, question: str = "") -> dict:
        """Grade the completed run; write and return the review.

        The trace digest, case_id, and output filename are bound to this
        run's own case dir (self.case_dir) — never the process-global
        session beacon. A case_id mismatch against the live singleton is a
        hard error (CrossCaseTraceError), because the objective-metrics tools
        read that singleton.
        """
        entries, case_id = self._resolve_run_trace()
        metrics = self.objective_metrics_data()
        context = self._build_context(run_stats, question, metrics=metrics,
                                      entries=entries, case_id=case_id)
        self.ui.info(f"reviewer model: {self.client.model} (independent pass)")
        resp = self.client.chat(
            [{"role": "system", "content": REVIEW_SYSTEM_PROMPT},
             {"role": "user", "content": context}])
        review_text = (resp.content or "").strip()
        # Final scrub: even with the prompt sanitized, the reviewer can echo a
        # recovered answer-key secret. This is the durable, analyst-visible
        # artifact — it must never carry the raw key.
        review_text, _ = answer_key.redact(review_text,
                                           self._answer_key_secrets())
        verdict = self._verdict_or_repair(review_text)

        # case_id is bound to the run's own trace (see _resolve_run_trace) —
        # never re-read from the process-global singleton here.
        out_dir = self.case_dir / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{case_id}_run_review.md"
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        header = (f"# Run Review — {case_id}\n\n"
                  f"_Independent review by `{self.client.model}` on {stamp}. "
                  f"Run: {run_stats.get('turns')} turns, "
                  f"{run_stats.get('findings_recorded')} findings, "
                  f"stopped: {run_stats.get('stopped_reason')}._\n\n")
        path.write_text(header + review_text + "\n", encoding="utf-8")

        return {
            "verdict": verdict,
            "needs_work": verdict == "NEEDS WORK",
            "review": review_text,
            "path": str(path),
            "reviewer_model": self.client.model,
            "metrics": metrics,
        }

    # ── in-flight / stuck-run review ─────────────────────────────────────

    @staticmethod
    def _stall_report_text(stall: dict) -> str:
        if not stall["hits"]:
            tail = "; run is still young)." if stall["young"] else ")."
            n = stall["tool_calls"]
            return f"No stall signals fired ({n} tool calls examined" + tail
        lines = [f"stalled={stall['stalled']} severity={stall['severity']} "
                 f"({stall['tool_calls']} tool calls examined)",
                 "Signals fired:"]
        s = stall["signals"]
        if "findings_starved" in stall["hits"]:
            lines.append(f"- FINDINGS-STARVED: {s['findings_starved']['tool_calls']} "
                         f"tool calls, {s['findings_starved']['findings']} findings "
                         "recorded — nothing is being captured.")
        if "dair_transition_ignored" in stall["hits"]:
            d = s["dair_transition_ignored"]
            lines.append(f"- DAIR TRANSITION IGNORED: DAIR recommended moving to "
                         f"{d['recommended_unreached']} but the run never left its "
                         f"current phase ({d['occurrences']} times).")
        if "command_loop" in stall["hits"]:
            c = s["command_loop"]
            if c.get("routed_tool"):
                # A typed tool's internal subprocess cmd looks like bare shell
                # ("strings -a …"); without the tool name the LLM reviewer
                # mislabels the loop as raw bash and prescribes re-routing
                #. Name the tool and rule that out.
                lines.append(
                    f"- COMMAND LOOP: MCP-routed tool `{c['routed_tool']}` "
                    f"called {c['repeats']} times with near-identical "
                    f"arguments (internal cmd `{c['signature']}`) — a rabbit "
                    "hole. These calls are already MCP-routed and citable; "
                    "the problem is repetition, NOT routing — do not advise "
                    "re-routing through MCP.")
            else:
                lines.append(f"- COMMAND LOOP: `{c['signature']}` repeated "
                             f"{c['repeats']} times — a rabbit hole.")
        if "high_failure_rate" in stall["hits"]:
            f = s["high_failure_rate"]
            lines.append(f"- HIGH FAILURE RATE: {f['failures']} failures "
                         f"({int(f['rate']*100)}% of tool calls).")
        if "rawbash_dominance" in stall["hits"]:
            r = s["rawbash_dominance"]
            lines.append(f"- RAW-BASH DOMINANCE: {r['raw']}/{r['of']} "
                         f"({int(r['share']*100)}%) are bare shell commands — "
                         "their evidence can't pass the mcp_routing gate.")
        return "\n".join(lines)

    def review_live(self, trace_path: Path | None = None,
                    question: str = "") -> dict:
        """Review an in-flight investigation from its on-disk trace (never the
        live singleton, so it is safe to run from a separate process while the
        investigation continues). Writes reports/<CASE_ID>_live_review.md."""
        if trace_path is None:
            trace_path = active_trace_path()
        if trace_path is None or not Path(trace_path).is_file():
            return {"error": f"no readable trace at {trace_path or '(none)'} — "
                             "pass --trace PATH or start an investigation first"}
        try:
            case_id, entries = load_trace_from_disk(Path(trace_path))
        except (OSError, ValueError) as e:
            return {"error": f"cannot read trace {trace_path}: {e}"}
        case_id = case_id or self.case_dir.name

        stall = detect_stall(entries)
        _, trace_digest = self._summarize_trace(entries=entries, case_id=case_id)
        stall_report = self._stall_report_text(stall)
        context = (
            f"CASE: {case_id}\n"
            f"CASE QUESTION: {question or '(not provided)'}\n\n"
            f"## Stall report (deterministic pre-check)\n{stall_report}\n\n"
            f"## Execution-trace digest\n{trace_digest}\n")

        self.ui.info(f"live reviewer model: {self.client.model} "
                     f"(stall severity: {stall['severity']})")
        resp = self.client.chat(
            [{"role": "system", "content": LIVE_REVIEW_SYSTEM_PROMPT},
             {"role": "user", "content": context}])
        review_text = (resp.content or "").strip()
        review_text, _ = answer_key.redact(review_text,
                                           self._answer_key_secrets())
        status = "STALLED"
        for line in review_text.splitlines():
            if line.strip().upper().startswith("STATUS"):
                up = line.upper()
                status = ("HEALTHY" if "HEALTHY" in up
                          else "AT RISK" if "AT RISK" in up else "STALLED")
                break

        out_dir = self.case_dir / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{case_id}_live_review.md"
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        header = (f"# Live Run Review — {case_id}\n\n"
                  f"_Independent mid-run review by `{self.client.model}` on "
                  f"{stamp}. Stall pre-check: {stall['severity']} "
                  f"({', '.join(stall['hits']) or 'no signals'})._\n\n")
        path.write_text(header + review_text + "\n", encoding="utf-8")

        return {
            "status": status,
            "stalled": stall["stalled"],
            "severity": stall["severity"],
            "hits": stall["hits"],
            "review": review_text,
            "path": str(path),
            "reviewer_model": self.client.model,
            "trace_path": str(trace_path),
        }
