"""Detect tool failures / incomplete scans that need investigate-then-retry.

Failed greps, timeouts, and truncated critical scans do not stop the agent
loop — but the model often ignores them and moves on. The loop uses this
module to latch an investigate nudge (and to refuse atlas_finish) until the
failure is diagnosed and retried or dispositioned via dair_assess.

Identical analyst-error / tool_error failures (e.g. ``event_ids="(4624, 4625)"``
or the same ``tsk.sigfind`` argv failing repeatedly) are fingerprinted: after
``IDENTICAL_FAIL_LIMIT`` repeats the latch stops blocking ``atlas_finish`` and
nudges reformulation so one bad command cannot burn the turn budget.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

# After this many identical failures (same tool+kind+summary), stop blocking
# atlas_finish — the agent must switch tools/args or dair_assess, not retry forever.
IDENTICAL_FAIL_LIMIT = 3

# Kinds that exhaust after IDENTICAL_FAIL_LIMIT identical fingerprints.
# incomplete_scan stays blocking (real truncation/timeout needs disposition).
_EXHAUSTIBLE_KINDS = frozenset({
    "bad_args",
    "truncated_critical",
    "tool_error",
    "bad_pattern",
    "tool_failure",
})

# Workflow/gate refusals are expected process — not "tool broke, investigate".
_WORKFLOW_GATES = frozenset({
    # Budget and phase gates are the loop steering the run, not tools that
    # failed; treating each refusal as a defect to diagnose costs a turn of
    # "investigation" after every one of them.
    "access_disk_budget", "access_work_order_pending",
    "wrapup_exploration_budget", "wrong_phase", "identical_call",
    "pre_report_check_required",
    "report_lint",
    "projection_required",
    "evidence_strength",
    "completeness",
    "lineage_required",
    "hypothesize_required",
    "mcp_routing",
    "negative_completeness",
    "negative_from_truncated",
    "principal_attribution_grounding",
    "named_actor_attribution_grounding",
    "external_knowledge_grounding",
    "exfil_channel_grounding",
    "hash_pair_grounding",
    "interactive_injection_grounding",
    "temporal_negative_grounding",
    "mitre_technique_validation",
    "linked_call_id_must_exist",
})

_CRITICAL_TOOL_RE = re.compile(
    r"(?:evtxecmd|chainsaw|hayabusa|"
    r"strings_grep|ngrep_search|batch_run)",
    re.IGNORECASE,
)

_PATTERN_FAIL_RE = re.compile(
    r"(?:invalid\s+(?:regex|pattern)|bad\s+pattern|re\.error|"
    r"nothing\s+to\s+repeat|unbalanced\s+parenthesis|"
    r"look-?behind|PCRE|regex\s+error)",
    re.IGNORECASE,
)

_BAD_ARGS_RE = re.compile(
    r"(?:no valid event_ids|bad_args|invalid argument|"
    r"pass digits and commas)",
    re.IGNORECASE,
)


def _parse_json_payload(result: str) -> dict[str, Any] | None:
    text = (result or "").strip()
    if not text:
        return None
    # Strip TOOL ERROR / namespace banners before the JSON object.
    if text.startswith("{"):
        blob = text
    else:
        idx = text.find("\n{")
        if idx < 0:
            idx = text.find("{")
        if idx < 0:
            return None
        blob = text[idx:]
    try:
        data = json.loads(blob)
    except Exception:
        # Truncated JSON in the chat view — try a looser scan.
        m = re.search(r"\{.*\}", blob, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except Exception:
            return None
    return data if isinstance(data, dict) else None


def issue_fingerprint(issue: dict[str, Any]) -> str:
    return "|".join([
        str(issue.get("tool") or ""),
        str(issue.get("kind") or ""),
        str(issue.get("summary") or "")[:120],
    ])


def _helper_role(name: str) -> bool:
    """The tool asks one of Atlas's own model roles (core.effort.ROLES: the
    director and the reasoning roles), not a tool that reads evidence. The
    registered name doubles its namespace in one form (reason_reason_plan)."""
    from core.effort import ROLES
    roles = {r.key for r in ROLES} - {"agent", "report"}
    ns, _, rest = name.partition("_")
    if rest.startswith(ns + "_"):
        name = rest
    return name in roles or ns in roles


def classify_tool_result(tool_name: str, result: str) -> dict[str, Any] | None:
    """Return an investigate issue dict, or None if the result is fine / workflow."""
    name = tool_name or ""
    text = result or ""
    if text.startswith("TOOL INFO"):
        return None

    if text.startswith(("TOOL ERROR", "ERROR")):
        return {
            "tool": name,
            "kind": "tool_error",
            "summary": text.splitlines()[0][:180],
            "blocking_finish": True,
        }

    data = _parse_json_payload(text)
    if not data:
        return None

    gate = str(data.get("gate") or "")
    if gate in _WORKFLOW_GATES:
        return None
    # Context-budget / artifact-first / discovery-first are protocol, not
    # investigate debt (do not invent path retries).
    if gate in (
        "artifact_ready", "input_scale", "context_budget", "discovery_first",
        "wrong_input_kind", "unknown_columns", "schema_first_required",
        "schema_columns_absent",
        "disk_open_policy",
        "unsupported_where_dialect", "non_numeric_compare",
        "task_status_contract",
        "evidence_available_required", "export_already_satisfied",
        "shell_pipeline_unsupported", "audit_delta_empty",
        "belief_starvation",
        # A lookup that answered "not there" answered; the absence is the
        # result, and nudging the model to fix the tool it just used right
        # cost turns after every absent directory.
        "path_not_found",
    ):
        return None
    # A helper role that timed out or answered empty did not fail on the
    # analyst's arguments: a narrower retry cannot help, and its debt must not
    # hold the finish. Non-blocking; a plain retry is what lets the report gate
    # see the helper as unavailable (core.reason_outcome.helper_unavailable)
    # and record the missing step as a limitation.
    if _helper_role(name) and data.get("success") is False and (
            gate in ("empty_reason_response", "reply_length_cut", "helper_unavailable", "scan_timeout")
            or data.get("timed_out") or data.get("incomplete")
            or "empty" in str(data.get("error") or "").lower()):
        return {
            "tool": name,
            "kind": "helper_unavailable",
            "summary": str(data.get("error") or "no usable answer from the helper model")[:180],
            "blocking_finish": False,
        }
    # empty_reason_response is NOT a silent workflow skip — the model burned
    # tokens and produced no usable conclusion. Surface as investigate debt.
    if gate == "empty_reason_response" or (
            data.get("success") is False
            and "empty" in str(data.get("error") or "").lower()
            and "reason" in name):
        return {
            "tool": name,
            "kind": "empty_reason",
            "summary": (
                str(data.get("error") or "empty reason response")[:180]
            ),
            "gate": "empty_reason_response",
            "blocking_finish": True,
        }

    from core.deferred_intents import incomplete_read_debt_on
    # A run cut by a time bound is an incomplete read whichever tool ran it:
    # the executor marks it timed_out.
    # A batch carries its calls' results: a sub-call cut by a time bound is
    # the batch's incomplete read too.
    subs = [r for r in data.get("results") or [] if isinstance(r, dict)]
    incomplete = bool(data.get("incomplete") or data.get("wall_clock_timed_out")
                      or (incomplete_read_debt_on()
                          and (data.get("timed_out") or any(r.get("timed_out") for r in subs))))
    truncated = bool(data.get("truncated"))
    success = data.get("success")
    err = str(data.get("error") or data.get("stderr") or "")
    hint = str(data.get("hint") or "")

    if gate == "scan_timeout" or incomplete:
        return {
            "tool": name,
            "kind": "incomplete_scan",
            "summary": (err or f"{name} incomplete/timed out")[:180],
            "gate": gate or "scan_timeout",
            "blocking_finish": True,
        }

    # Truncation with durable artifacts is success for the latch — the agent
    # must query the artifact, not re-run the bulk parser.
    if truncated and data.get("artifact_paths"):
        return None

    # A display cut of a named tool's output: no finish debt while incomplete
    # reads are debts (a claim resting on it is judged at record time by the
    # truncation gates).
    if truncated and _CRITICAL_TOOL_RE.search(name) and not incomplete_read_debt_on():
        return {
            "tool": name,
            "kind": "truncated_critical",
            "summary": (err or f"{name} truncated=true")[:180],
            "blocking_finish": True,
        }

    if success is False:
        fc = str(data.get("failure_class") or "")
        if gate == "wrong_input_kind" or fc == "wrong_input_kind":
            return None
        if (gate == "bad_args" or _BAD_ARGS_RE.search(err)
                or _BAD_ARGS_RE.search(text[:500])):
            issue = {
                "tool": name,
                "kind": "bad_args",
                "summary": (err or f"{name} bad arguments")[:180],
                "gate": "bad_args",
                "blocking_finish": True,
            }
            if hint:
                issue["hint"] = hint[:200]
            elif "event_ids" in err.lower():
                issue["hint"] = (
                    "Use event_ids='1000,1001' (digits and commas only; "
                    "no parentheses)."
                )
            return issue
        if _PATTERN_FAIL_RE.search(err) or _PATTERN_FAIL_RE.search(text[:500]):
            return {
                "tool": name,
                "kind": "bad_pattern",
                "summary": (err or f"{name} pattern/regex failure")[:180],
                "blocking_finish": True,
            }
        # Disk FS / critical tool failures (sigfind, icat, …) — fingerprint so
        # identical argv storms exhaust. Do not latch every soft
        # success:false (many are already handled as workflow gates above).
        _diskish = re.search(
            r"(?:tsk_|sleuth|sigfind|icat|fls|indxparse|mmls|mactime|ils)",
            name, re.IGNORECASE,
        )
        if (
            fc in ("tool_error", "analyst_error")
            or _CRITICAL_TOOL_RE.search(name)
            or _diskish
        ) and err:
            kind = "tool_failure" if _CRITICAL_TOOL_RE.search(name) else "tool_error"
            issue = {
                "tool": name,
                "kind": kind,
                "summary": err[:180],
                "gate": gate or None,
                "failure_class": fc or None,
                "blocking_finish": True,
            }
            if hint:
                issue["hint"] = hint[:200]
            return issue

    return None


def merge_investigate_debt(
    prev: list[dict[str, Any]] | None,
    batch: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge a new batch of issues into prior debt, tracking repeat counts.

    Identical exhaustible fingerprints that hit ``IDENTICAL_FAIL_LIMIT`` are
    marked exhausted and stop blocking ``atlas_finish``.
    """
    prev_by_fp = {
        issue_fingerprint(i): i for i in (prev or [])
    }
    out: list[dict[str, Any]] = []
    for raw in batch:
        issue = dict(raw)
        fp = issue_fingerprint(issue)
        prior = prev_by_fp.get(fp)
        count = int(prior.get("repeat_count", 1) if prior else 0) + 1
        issue["fingerprint"] = fp
        issue["repeat_count"] = count
        if issue.get("kind") in _EXHAUSTIBLE_KINDS and count >= IDENTICAL_FAIL_LIMIT:
            issue["exhausted"] = True
            issue["blocking_finish"] = False
            if not issue.get("hint"):
                if issue.get("kind") == "truncated_critical":
                    issue["hint"] = (
                        "Stdout was truncated for context; if a CSV/JSON was "
                        "written under analysis/, query it with table.* — do not "
                        "re-run the same bulk parser."
                    )
                else:
                    issue["hint"] = (
                        "Identical failure exhausted — change arguments or "
                        "switch tool family (e.g. disk FS → table.*/EVTX "
                        "parsers on already-exported artifacts). Do not resend "
                        "the same argv."
                    )
        else:
            issue["exhausted"] = bool(issue.get("exhausted"))
            issue.setdefault("blocking_finish", True)
        if prior and prior.get("hint") and not issue.get("hint"):
            issue["hint"] = prior["hint"]
        out.append(issue)
    return out


def input_paths(args: dict | None) -> list[str]:
    """The input files a call names (core.paths.INPUT_PATH_PARAM_NAMES)."""
    from core.paths import INPUT_PATH_PARAM_NAMES
    out: list[str] = []
    for k in INPUT_PATH_PARAM_NAMES:
        v = (args or {}).get(k)
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
    return out


def _same_file(a: str, b: str) -> bool:
    import os
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except (OSError, ValueError):
        return a == b


def _holds(folder: str, path: str) -> bool:
    """A folder a parser was run over holds the file (a parse of a folder
    reads every file of its kind in it)."""
    import os
    try:
        root = os.path.realpath(folder)
        return os.path.isdir(root) and os.path.realpath(path).startswith(root.rstrip(os.sep) + os.sep)
    except (OSError, ValueError):
        return False


def settle_investigate_debt(
    issues: list[dict[str, Any]] | None,
    succeeded: Iterable[str],
    reads: Iterable[tuple[str, list[str]]] = (),
) -> list[dict[str, Any]]:
    """Drop the issues whose tool has since run cleanly.

    The latch asks for a corrected retry; a clean run of the same tool is
    that retry. Without this the latch replayed the failure every turn after
    the retry had already succeeded, and a model that kept answering "already
    handled" without a call was counted as quiet until the run ended.

    With ATLAS_INPROCESS_DEADLINE a call cut at its deadline is also settled
    by a clean call of another tool that reads the same input's content
    (``reads``: tool name and input paths of each clean call;
    core.input_kind.reads_kind): the native parser of the same log. A hash
    or a listing of the file reads nothing of its content and settles
    nothing.
    """
    done = {name for name in succeeded if name}
    left = [i for i in (issues or []) if i.get("tool") not in done]
    from core.timeout import inprocess_deadline_on
    reads = list(reads or ())
    if not reads or not inprocess_deadline_on():
        return left
    from core.input_kind import reads_kind

    def settled(issue: dict[str, Any]) -> bool:
        if issue.get("kind") != "incomplete_scan":
            return False
        return any(reads_kind(tool, cut) is True and (_same_file(path, cut) or _holds(path, cut))
                   for cut in issue.get("inputs") or () for tool, paths in reads for path in paths)
    return [i for i in left if not settled(i)]


def finish_blocking_issues(
    issues: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Issues that still refuse atlas_finish."""
    return [i for i in (issues or []) if i.get("blocking_finish", True)]


def prune_exhausted_debt(
    issues: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Drop exhausted (non-blocking) issues so the latch stops nagging."""
    return [i for i in (issues or []) if i.get("blocking_finish", True)]


def format_investigate_message(issues: list[dict[str, Any]]) -> str:
    n = len(issues)
    lines = []
    for issue in issues[:5]:
        line = (
            f"- {issue.get('tool')}: [{issue.get('kind')}] "
            f"{issue.get('summary')}"
        )
        if issue.get("kind") == "helper_unavailable":
            line += ("\n  The helper model gave no usable answer (a timeout or an empty "
                     "reply, not your arguments: a narrower call does not help). This "
                     "does not block atlas_finish. If the step is still needed, call it "
                     f"again as it was; after {IDENTICAL_FAIL_LIMIT} failures in a row "
                     "reason.pre_report_check records a missing plan or synthesis as a "
                     "documented limitation instead of requiring it.")
            lines.append(line)
            continue
        if issue.get("hint"):
            line += f"\n  FIX: {issue['hint']}"
        rc = int(issue.get("repeat_count") or 1)
        if issue.get("exhausted"):
            line += (
                f"\n  EXHAUSTED after {rc} identical failures — stop retrying "
                "the same arguments. Reformulate args, switch tool family "
                "(disk FS ↔ table.*/EVTX), OR dair_assess to disposition. "
                "atlas_finish is no longer blocked by this failure alone."
            )
        elif rc >= 2 and issue.get("kind") in _EXHAUSTIBLE_KINDS:
            line += (
                f"\n  REPEAT {rc}/{IDENTICAL_FAIL_LIMIT}: do not resend the "
                "same failing arguments — change argv or tool."
            )
        lines.append(line)
    body = "\n".join(lines)
    if all(i.get("kind") == "helper_unavailable" for i in issues[:5]):
        return f"[tool-failure investigate] A helper call failed:\n{body}"
    return (
        "[tool-failure investigate] The last tool batch had "
        f"{n} failure(s)/incomplete scan(s) that must be handled BEFORE new "
        "unrelated evidence work or atlas_finish:\n"
        f"{body}\n"
        "Required next steps: (1) read the error/stderr, (2) diagnose "
        "(bad grep/regex? bad event_ids format? timeout on a huge EVTX? "
        "wrong path?), (3) retry with a corrected/narrower call OR switch to "
        "the structured extractor for that artifact (two strikes then switch "
        "for greps), OR call dair_assess with an honest tool_results_summary "
        "of the failure. Do not ignore the failure and move on."
    )


def format_finish_refusal(issues: list[dict[str, Any]],
                          critical_debt: list[dict[str, Any]]) -> str:
    parts = []
    blocking = finish_blocking_issues(issues)
    if blocking:
        parts.append(f"{len(blocking)} open tool-failure investigate item(s)")
    if critical_debt:
        parts.append(
            f"{len(critical_debt)} unresolved truncated critical auth/session "
            "scan(s)"
        )
    why = "; ".join(parts) or "open investigative debt"
    return (
        f"atlas_finish refused: {why}. Investigate and retry (or disposition "
        "via dair_assess) first, clear pre_report blockers, write the full "
        "report, then call atlas_finish."
    )
