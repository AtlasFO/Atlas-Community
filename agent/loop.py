"""The analyst agent loop.

A classic tool-calling loop with three Atlas-specific behaviors:
- every turn is appended to a JSONL transcript under the case's analysis/
  directory (separate from — and complementary to — the MCP execution trace);
- old tool outputs are trimmed once the conversation outgrows the context
  budget, since forensic tool output dominates token usage;
- the loop ends when the model calls `atlas_finish`, goes quiet, hits an
  optional hard turn cap (``ATLAS_AGENT_MAX_TURNS>0``), or exceeds the wall
  clock. Default turn budget is unlimited — stall nudges break deadlocks
  without aborting productive long cases (``core.run_budget``).

All terminal output goes through agent.tui.UI, which renders panels and
spinners on a TTY and plain lines everywhere else.
"""
from __future__ import annotations

import collections
import json
import os
import re
import contextlib
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent.llm import (_AGENT_ROLE, LLMHubClient, LLMError, LLMDeadlineError, LLMStatusError,
                       LLMTransportError, WAFBlockedError, ToolCall)
from agent.toolbox import Toolbox, is_call_shape_refusal, split_call_syntax
from agent.tui import UI

# Hard turn abort is OPT-IN. Default 0 = unlimited — stall/progress + wall
# clock govern the run (see core.run_budget). Positive ATLAS_AGENT_MAX_TURNS
# restores a lab/CI hard cap.
from core.envfile import env_int
from core.run_budget import (  # noqa: E402
    MAX_TURNS,
    TURN_ADVISORY,
    hard_turn_cap_enabled,
    initial_turn_limit,
    observe_progress,
    messages_for_turn as stall_messages_for_turn,
    should_allow_synthesize_escape,
    should_treat_as_wrapup,
    StallState,
)

# Dashboard / `atlas chat` tool-calling rounds per user message. 0 = unlimited
# (no hard stop). A positive value restores a cap; when the cap is hit the
# turn ends with an explicit error instead of a silent empty reply.
CHAT_MAX_TOOL_ROUNDS = env_int("ATLAS_CHAT_MAX_TOOL_ROUNDS", 0)

# Ceiling on how many times ONE chat turn will rescue a tool call written as
# text. Independent of CHAT_MAX_TOOL_ROUNDS (0 = unlimited rounds by
# default): without it, a model that keeps emitting recoverable pseudo-calls
# and never answers in prose loops until the operator kills it.
_CHAT_MAX_PSEUDO_RECOVERIES = env_int("ATLAS_CHAT_MAX_PSEUDO_RECOVERIES", 6)

# Some models emit tool calls as prose/XML in ``content`` instead of the
# structured ``tool_calls`` field. Taking that as a final answer would end
# the chat early — recover or nudge instead.
_PSEUDO_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*([A-Za-z_][\w.:]*)\s*(?:\((.*?)\))?\s*"
    r"(?:</arg_value>\s*)?</tool_call>",
    re.DOTALL | re.IGNORECASE,
)
# The same call with its closing tag missing. An endpoint can stop
# generation on `</tool_call>` and strip it, so the reply carries an opening
# tag and a whole call and nothing to close it — every call one model made
# arrived that way, and all of them were discarded. Still requires the literal
# tag and complete parentheses, so a tool named in a numbered plan stays prose.
_PSEUDO_TOOL_CUT_RE = re.compile(
    r"<tool_call>\s*([A-Za-z_][\w.:]*)\s*\((.*?)\)",
    re.DOTALL | re.IGNORECASE,
)
# The XML dialects some models use for the same thing: a block per call,
# arguments as key/value tags. Parsed before the prose forms above.
_PSEUDO_XML_BLOCK_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.DOTALL | re.IGNORECASE)
_PSEUDO_XML_FUNCTION_RE = re.compile(r"<function=([A-Za-z_][\w.:]*)>", re.IGNORECASE)
_PSEUDO_XML_KEYVAL_RE = re.compile(
    r"<arg_key>\s*(.*?)\s*</arg_key>\s*<arg_value>\s*(.*?)\s*</arg_value>",
    re.DOTALL | re.IGNORECASE)
_PSEUDO_XML_PARAM_RE = re.compile(
    r"<parameter=([\w.\-]+)>\s*(.*?)\s*</parameter>", re.DOTALL | re.IGNORECASE)


def _coerce_pseudo_value(raw: str):
    """A tag's text as the value the model meant: JSON where it parses
    (numbers, booleans, lists, objects), the string otherwise."""
    text = (raw or "").strip()
    if not text:
        return ""
    if text[0] in "[{" or text in ("true", "false", "null") or re.fullmatch(r"-?\d+(\.\d+)?", text):
        try:
            return json.loads(text)
        except ValueError:
            return text
    return text


# A call written as a JSON object instead of sent through the API: either
# {"tool": NAME, "arguments": {...}} or the wire shape
# {"function": {"name": NAME, "arguments": {...}}}. A model that loses its
# tool-call formatting mid-run often keeps emitting fully-specified calls in
# this form, and every one of them was discarded as prose. Only these keys
# count as a name — a bare "name" key appears in ordinary JSON a model quotes
# in prose, and recovering that would invent calls out of evidence.
_JSON_CALL_NAME_KEYS = ("tool", "tool_name", "function")
_JSON_CALL_ARG_KEYS = ("arguments", "args", "parameters", "params", "tool_input")
_JSON_CALL_NAME_RE = re.compile(r"^[A-Za-z_][\w.:]*$")


def _json_pseudo_call(obj):
    """(name, arguments) if a decoded JSON object names a tool, else None."""
    if not isinstance(obj, dict):
        return None
    name = None
    for key in _JSON_CALL_NAME_KEYS:
        value = obj.get(key)
        if isinstance(value, dict):  # {"function": {"name": ..., ...}}
            inner = value.get("name")
            if isinstance(inner, str) and _JSON_CALL_NAME_RE.match(inner):
                name, obj = inner, value
                break
        elif isinstance(value, str) and _JSON_CALL_NAME_RE.match(value):
            name = value
            break
    if name is None:
        return None
    for key in _JSON_CALL_ARG_KEYS:
        value = obj.get(key)
        if isinstance(value, str):  # arguments serialised twice
            try:
                value = json.loads(value)
            except ValueError:
                continue
        if isinstance(value, dict):
            return name, value
    return name, {}


_PSEUDO_TOOL_BARE_RE = re.compile(
    r"\b(atlas_load_namespaces|atlas_list_namespaces|atlas_finish|"
    r"atlas_ask_analyst)\s*\((.*?)\)",
    re.DOTALL,
)
_CHAT_PSEUDO_NUDGE = (
    "Your previous reply put a tool call in plain text "
    "(e.g. <tool_call>name(...)</tool_call>) instead of using the "
    "function-calling API. Call tools only via the structured tool "
    "interface — do not write tool XML or Python-style calls in the "
    "message body. Retry the same tool call(s) properly now."
)
# A chat reply with neither text nor a function call reached nobody: the
# endpoint dropped a call (a name outside the loaded tool list), or the
# model stopped after thinking. The run loop asks again in that case
# (_EMPTY_REPLY_MSG); the chat has no report phase to point at, so it asks
# for the call or the answer.
_CHAT_EMPTY_REPLY_MSG = (
    "[empty reply] Your last reply arrived with no text and no function "
    "call, so nothing ran and the analyst saw nothing. If you meant to call "
    "a tool, issue it now as a function call; a tool missing from your list "
    "is loaded with atlas_load_namespaces first. Otherwise answer the "
    "question in plain text now."
)

# Run-level wall clock. Off by default (0). Catching a wedged hub call that
# freezes a phase is not its job: the per-turn LLM deadline in agent.llm, the
# refusal-based deadlock breaker, the quiet valve and the status heartbeat
# catch a wedged run by its behaviour, and a clock cannot tell a wedged run
# from a large case — an estate with many images legitimately runs past any
# fixed number of hours and must not be cut short. Set
# ATLAS_AGENT_MAX_WALL_SECONDS for lab or CI
# runs that need a hard bound; the wrap-up path it triggers is unchanged.
MAX_WALL_SECONDS = float(
    os.environ.get("ATLAS_AGENT_MAX_WALL_SECONDS") or "0")
WALL_GRACE_SECONDS = float(
    os.environ.get("ATLAS_AGENT_WALL_GRACE") or "1800")

def _run_started_at() -> str:
    """When the run started, as whoever launched it stamped it (the CLI
    command, or the dashboard's Start) so the reported elapsed time takes in
    the evidence stage before this loop; the loop's own start when nothing
    was handed in, or the stamp cannot be read or lies in the future."""
    now = datetime.now(timezone.utc)
    given = (os.environ.get("ATLAS_RUN_STARTED_AT") or "").strip()
    try:
        at = datetime.strptime(given, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        at = None
    return given if at is not None and at <= now else now.strftime("%Y-%m-%dT%H:%M:%SZ")


# A model call whose transport failed on every attempt of one request (the
# provider dropped the connection, cut the reply off) is asked again after a
# pause that doubles from LOST_TURN_PAUSE up to LOST_TURN_PAUSE_MAX. After
# LOST_TURN_RETRIES consecutive losses of the same turn the run wraps up.
# A guard on repeated failure of one turn, not a limit on the run: a run
# that keeps getting answers is never cut short. A deadline is not retried
# here: it already spent a whole turn budget.
LOST_TURN_RETRIES = int(os.environ.get("ATLAS_AGENT_LOST_TURN_RETRIES") or "2")
LOST_TURN_PAUSE = float(os.environ.get("ATLAS_AGENT_LOST_TURN_PAUSE") or "60")
LOST_TURN_PAUSE_MAX = 300.0

# The escape's two messages (ATLAS_MODEL_CALL_ESCAPE): after a lost request
# the model is asked, without tools, for what the investigation has
# established and the one next step; then, with the tools back, for that
# step as one call.
_ESCAPE_ASK = (
    "[model call failed] Your last {n} replies for this step did not arrive: the provider ended them "
    "before they finished, so nothing ran. Tools are not available in this reply. In at most 8 short "
    "lines, write what the investigation has established so far, each line naming what showed it (the "
    "call, the file or the time), and the one next step you will take.")
_ESCAPE_FOLLOW_UP = "[next step] Now issue that next step as one function call, with short arguments."
# The stored text of a reply whose every tool call was left unanswered.
_PRUNED_REPLY_TEXT = "[this reply's tool calls did not run]"
# With the work order on and a read due, the follow-up names it; an item
# whose source named no tool is a read the model chooses the reader for.
_ESCAPE_FOLLOW_UP_READY = "[next step] Run this next, as one function call: {call}"
_ESCAPE_FOLLOW_UP_READ = "[next step] Read this next with one function call: {call}"
# How long an escape may run before the run log and the dashboard card show
# an alert: an operator setting for attention, not a limit; the escape keeps
# waiting either way. 0 turns the alert off.
def _escape_alert_seconds() -> float:
    """ATLAS_ESCAPE_ALERT_SECONDS, read at call time (default 1800)."""
    try:
        return float(os.environ.get("ATLAS_ESCAPE_ALERT_SECONDS") or "1800")
    except ValueError:
        return 1800.0

# Turns remaining at which the loop forces a wrap-up if no final report has
# been written yet. A run that dies "quiet" or at the turn cap without a
# Report is ungradeable. Wrap-up must clear pre_report blockers and write a *full*
# report — there is no partial-report escape hatch.
# The margin has to fit the full close-out chain when pre_report_check
# comes back READY_TO_REPORT: false — the analyst needs room to resolve
# blocking issues, re-check, and write.
WRAPUP_MARGIN = env_int("ATLAS_AGENT_WRAPUP_MARGIN", 25)

# Extra turns granted in chunks when the hard turn cap (or quiet death)
# would fire while pre_report_check is still READY_TO_REPORT: false.
# Chunks repeat until BLOCKER_EXTENSION_MAX total extra turns are granted
#.
BLOCKER_EXTENSION_TURNS = int(
    os.environ.get("ATLAS_AGENT_BLOCKER_EXTENSION") or "50")
BLOCKER_EXTENSION_MAX = int(
    os.environ.get("ATLAS_AGENT_BLOCKER_EXTENSION_MAX") or "150")

# Once the wrap-up has been injected, only this many further exploratory
# tool calls are allowed before the close-out tools are the only ones that
# run. The budget is refilled by every pre_report_check, whose blockers may
# legitimately need probes. Without it a model with a few turns left
# re-queries every source until the run hits its cap with no report.
WRAPUP_EXPLORE_CALLS = env_int("ATLAS_AGENT_WRAPUP_EXPLORE_CALLS", 12)
# An identical (tool, arguments) call that succeeded within this many turns
# is answered by a pointer to its earlier result instead of being re-run.
# How many turns back an identical read-only call is answered from memory.
# 0 means the whole run: evidence does not change while a run reads it, so
# the answer from turn 12 is still the answer at turn 200.
IDENTICAL_CALL_WINDOW = env_int("ATLAS_AGENT_IDENTICAL_CALL_WINDOW", 0)
HEARTBEAT_SECONDS = env_int("ATLAS_AGENT_STATUS_HEARTBEAT_SECONDS", 15)
# How many times in a row a reply that only *describes* a tool call is
# answered with a request for the call itself before it counts as quiet.
INTENT_RESCUES_MAX = env_int("ATLAS_AGENT_INTENT_RESCUES", 2)
_NO_CALL_MSG = (
    "[no tool call received] Your reply described what you would do next "
    "but contained no function call, so nothing ran. Issue the tool call "
    "now as a function call — not as prose. If the investigation is "
    "complete instead, proceed to reason.reason_pre_report_check."
)
# What a tool name can look like in the function channel: the listed form,
# or the dotted alias the playbook writes. Anything else is not a name.
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_MALFORMED_CALL_MSG = (
    "[malformed call] Your reply carried a function call that names no tool "
    "({names}), so nothing ran. Put the bare tool name in the call's name "
    "field and every argument in its arguments object, as JSON. Issue the "
    "call again now."
)
_EMPTY_REPLY_MSG = (
    "[empty reply] Your last reply arrived with no text and no function "
    "call, so nothing ran. Issue the next tool call now, as a function "
    "call. If the investigation is complete instead, proceed to "
    "reason.reason_pre_report_check."
)
_CUT_OFF_MSG = (
    "[reply cut off] Your reply reached the output length limit before any "
    "function call was issued, so nothing ran. Do not repeat the analysis: "
    "issue the tool calls now, as function calls, with at most a sentence "
    "of text."
)
_CUT_CALL_MSG = (
    "[reply cut off] The reply was cut before it finished, so the arguments "
    "of a call arrived incomplete and that tool did not run. Make the call "
    "again with far shorter arguments: a few sentences where a summary is "
    "asked for, and no long lists — a tool that takes a list of call ids "
    "derives it itself when the list is omitted."
)
# Consecutive cut-off replies answered with that message before the quiet
# path takes over; a real call resets the count.
CUT_OFF_NUDGES_MAX = env_int("ATLAS_AGENT_CUT_OFF_NUDGES", 4)
# The consecutive count above resets on a real call, which is right for a model
# cut off once that then recovers. It is wrong for one alternating between a
# runaway reply and a call: every call refills the budget, and the cut-off
# branch spends no quiet turn, so such a run converges on no exit at all and
# stays alive burning a whole output budget per dead turn. This is the run
# total and it does not reset. Reaching it does not end the run - it stops
# treating a cut-off as free, letting the ordinary quiet ladder (with its
# rescues, and the degraded exit that still writes a report) do its work. The
# total is generous on purpose: a model that answers inside its budget reaches
# the ceiling rarely, so only a model that keeps running away spends it.
CUT_OFF_TOTAL_MAX = env_int("ATLAS_AGENT_CUT_OFF_TOTAL", 12)
EMPTY_REPLY_NUDGES_MAX = env_int("ATLAS_AGENT_EMPTY_REPLY_NUDGES", 6)
# The provider declined a request (a safety classifier, a content filter).
# The next request carries this one line, never an empty-reply label; three
# declines in a row end the run, since the same context
# is likely to be declined again. A behaviour guard: any other reply resets
# the count.
_DECLINED_MSG = ("The provider declined the last request (category: {category}). "
                 "Continue the analysis with a different approach or other evidence.")
PROVIDER_DECLINES_MAX = 3
# Times the loop will ask again after going quiet with nothing recorded at
# all. This is not a budget for the run — it bounds only the case where the
# model is answering without ever issuing a call, which is a malfunction and
# not an investigation that has run its course.
NO_WORK_RESCUES_MAX = env_int("ATLAS_AGENT_NO_WORK_RESCUES", 10)
# When a turn shows the model tried to call a tool and no function call
# arrived, the tool list is cut to this share of its size and the turn is
# asked again; the size that answers is remembered for the model. Bounded
# per run so a model that never uses the function channel settles at the
# core namespaces instead of shrinking forever.
TOOL_BUDGET_SHRINK = 0.8
TOOL_BUDGET_SHRINKS_MAX = env_int("ATLAS_AGENT_TOOL_BUDGET_SHRINKS", 4)
# Replies in a row that tried to call and got no call through, at one list
# size, before that size is cut. One such reply is what a first turn often
# does with any list; two at the same size are a pattern.
TOOL_BUDGET_STRIKES = 2
# The most calls one reply may carry into execution. Not a run budget: the
# rest of a larger batch is handed back, and the model resends what it still
# needs after reading the results. A reply carrying hundreds of pivots, run
# one by one, holds a run for hours and teaches nothing the first few dozen
# would not.
CALLS_PER_TURN_MAX = env_int("ATLAS_AGENT_MAX_CALLS_PER_TURN", 24)
_BATCH_TRUNCATED_MSG = (
    "[batch bounded] Your reply carried {sent} tool calls; the first {ran} "
    "ran and the other {left} did not. Read these results, then resend "
    "only the calls you still need, most valuable first."
)
# A reply carrying this many times the cap is not a large batch but a
# runaway: the model spent a whole completion generating calls of which all
# but the first cap's worth were discarded unread. This detects the shape
# and names it to the model; it cuts nothing.
BATCH_RUNAWAY_FACTOR = 4
# More than this many calls in one reply repeating an earlier call of the
# same reply make it a runaway (the model emitted one call over and over).
REPLY_DUPLICATES_RUNAWAY = env_int("ATLAS_AGENT_REPLY_DUPLICATES_RUNAWAY", 5)
_BATCH_RUNAWAY_MSG = (
    " A reply of {sent} calls is far beyond what any reply can run: the "
    "{left} that did not run were discarded, not queued, and a call "
    "repeated with near-identical arguments is not progress. Keep the next "
    "reply to at most {ran} calls, each a distinct step."
)
_DROPPED_CALL_MSG = (
    "[call did not arrive] Your reply generated a function call that the "
    "endpoint dropped before it reached Atlas. That happens to a call whose "
    "name is not in the tool list, and a tool outside the loaded namespaces "
    "is not in the list. Loaded now: {loaded}. If the tool you meant lives "
    "in another namespace, load that one namespace with "
    "atlas_load_namespaces and make the call again, spelled exactly as the "
    "tool list spells it. Do not load namespaces you have no next call for: "
    "the list has room for a few at a time, and every extra one pushes out "
    "one you are using."
)
# The same note for a stable list (every namespace listed for the whole run):
# a dropped call then misspelled a listed name.
_DROPPED_CALL_STABLE_MSG = (
    "[call did not arrive] Your reply generated a function call that the "
    "endpoint dropped before it reached Atlas. That happens to a call whose "
    "name is not in the tool list. Every Atlas tool is in your list for this "
    "whole run: make the call again, spelled exactly as the tool list spells "
    "it."
)
# Leading tool token in a director prescription such as
# "table.table_pivot (column=service, scope=all day-files)".
_TOOL_TOKEN_RE = re.compile(r"^\s*([A-Za-z_][\w]*[.:_][A-Za-z_][\w.]*)")
# Replies that only load or list namespaces do no work. A model that keeps
# asking for more namespaces than the list holds can spend turn after turn
# on refusals and evictions; after this many in a row the loop loads what
# the director asked for and names the call to make.
META_ONLY_TURNS_MAX = env_int("ATLAS_AGENT_META_ONLY_TURNS", 3)
_NAMESPACE_META_TOOLS = frozenset({"atlas_load_namespaces", "atlas_list_namespaces"})
# Turns in a row whose only call was the director, each answered with an
# assessment that reports no change, before the loop names the action. The
# director assesses batches; asked again with no batch between, it can only
# say the same thing, and a model that keeps asking is not going to act on
# its own.
DIRECTOR_REASK_STREAK = env_int("ATLAS_AGENT_DIRECTOR_REASK_STREAK", 3)
# Times the loop names the work order, with no new claim between them,
# before it stops repeating itself and asks for the report instead. A nudge
# that changed nothing once will not change anything given again with the
# same words; from there the run is on the report-phase ladder, which wraps
# it up and closes it out.
DIRECTOR_REASK_FIRES = env_int("ATLAS_AGENT_DIRECTOR_REASK_FIRES", 2)
_DIRECTOR_REASK_MSG = (
    "[director re-asked] {streak} calls to dair_assess in a row with nothing "
    "between them, and its assessment has not changed: it will not change "
    "until you act. Its last work order named: {tools}. Make those calls now."
)
_META_ONLY_MSG = (
    "[namespaces only] {streak} replies in a row loaded or listed namespaces "
    "and called no tool. The list now holds: {loaded}. The director's last "
    "work order named: {tools}. Make one of those calls now. Ask for a "
    "namespace only when your next call needs it, one at a time: the list "
    "has room for a few, and every extra one pushes out one you are using."
)
_META_ONLY_STABLE_MSG = (
    "[namespaces only] {streak} replies in a row loaded or listed namespaces "
    "and called no tool. Every namespace is already in your tool list for "
    "this whole run, so loading changes nothing. The director's last work "
    "order named: {tools}. Make one of those calls now."
)


def _list_stable(toolbox) -> bool:
    """Whether the toolbox lists every tool for the rest of the run (a stand-in
    toolbox without the notion never does)."""
    fn = getattr(toolbox, "stable", None)
    try:
        return callable(fn) and fn() is True
    except Exception:  # noqa: BLE001 - a broken stand-in is no stable list
        return False


def _tool_list_mode(toolbox) -> str:
    """The toolbox's tool-list mode for the run_start record; "" for a
    stand-in toolbox without one."""
    fn = getattr(toolbox, "list_mode", None)
    try:
        mode = fn() if callable(fn) else ""
        return mode if isinstance(mode, str) else ""
    except Exception:  # noqa: BLE001 - a record field never breaks a run
        return ""
# An announced action is not always announced in the first person. A reply
# that says "Now verifying the hashes:" or "Continuing. Next step: ..." has
# named its next move as plainly as "Let me ...", and reading only the
# first-person openers counted both as a model with nothing left to do. That
# misreading is expensive rather than untidy: two in a row spend the run's
# single wrap-up round, and once it is spent a later quiet pair ends the run
# outright, with no report. Asking for the call costs one turn; a wrongly
# quiet death costs the investigation.
_INTENT_RE = re.compile(
    r"(?i)\b(?:let me|let's|i(?:'ll| will| need to| should| am going to| can now|"
    r" want to)|now (?:i|let|\w+ing)|next,? (?:i|let)|next step|continuing|"
    r"proceeding (?:to|with)|moving on|starting (?:with|the)|"
    r"lass mich|ich werde|ich muss|als n(?:ä|ae)chstes|weiter mit)\b")


def _no_call_loaded_msg(namespaces: list[str]) -> str:
    """The rescue for a narrated call whose tools were not in the list:
    the loop has brought them in, so the call can be issued at once."""
    return (
        "[no tool call received] Your reply named tools in "
        f"{', '.join(sorted(namespaces))}, which were not in your tool "
        "list; they are loaded now. Issue the call as a function call — "
        "not as prose."
    )


def _no_call_unloaded_msg(unloaded: list[tuple[str, str]]) -> str:
    """The rescue for a narrated call the model *cannot* issue.

    A model that unloaded a namespace earlier keeps naming its tools long
    after the schemas are gone; the generic "issue the call now" is advice
    it cannot act on, and the run ends quiet with the work in plain sight.
    Name the namespace and the exact call that brings it back.
    """
    tools = ", ".join(sorted({alias for alias, _ns in unloaded})[:4])
    spaces = sorted({ns for _alias, ns in unloaded})
    return (
        f"[no tool call received] Your reply named {tools}, but "
        f"{'that namespace is' if len(spaces) == 1 else 'those namespaces are'} "
        f"not loaded right now, so the schema is not in front of you and the "
        f"call cannot be issued. Call atlas_load_namespaces("
        f"{json.dumps(spaces)}) first — unload a namespace you no longer need "
        f"if the schema budget refuses — then issue the tool call itself as a "
        f"function call. If the investigation is complete instead, proceed to "
        f"reason.reason_pre_report_check."
    )

# Consecutive tool results that were all refusals or protocol notices
# before the loop declares a deadlock: first a warning naming the gates,
# then — after as many again — the close-out is forced.
DEADLOCK_REFUSALS = env_int("ATLAS_AGENT_DEADLOCK_REFUSALS", 12)

_DEADLOCK_MSG = (
    "[protocol deadlock] The last {n} tool results were all refusals "
    "({gates}). Nothing you are trying gets through, and repeating it will "
    "not. Either take the escape each refusal names (disposition the "
    "work order with coverage.mark_blocked, record at a lower tier, use "
    "tsk.resolve_path for a directory), or close out now: "
    "reason.reason_pre_report_check → misc.write_projected_final_report "
    "→ atlas_finish. After {n} more refusals the loop closes the run."
)
# Tools whose repeat is meaningful: they read or advance run state.
_STATEFUL_TOOL_RE = re.compile(
    r"(?:reason_|dair_|coverage_|claim_|record_|update_investigation_task|"
    r"write_[a-z_]*report|export_execution_log|atlas_|current_investigation_state|"
    r"pre_report_check|inventory_evidence|start_execution_log|misc_batch_run|"
    r"ledger_status|mark_blocked|search_index_status)", re.IGNORECASE)
_CLOSEOUT_TOOL_RE = re.compile(
    r"(?:record_finding|update_investigation_task|reason_|dair_|coverage_|"
    r"claim_|write_[a-z_]*report|write_case_document|export_execution_log|"
    r"atlas_|current_investigation_state|record_agent_message|"
    r"table_schema|inventory_evidence|start_execution_log|"
    r"mark_blocked|ledger_status|correlate_|ioc_|finding_|report_|"
    r"record_curiosity_probe|tsk_icat|resolve_path)",
    re.IGNORECASE)

_WRAPUP_EXPLORE_REFUSAL = (
    "[wrap-up] {tool!r} refused: the wrap-up exploration budget "
    "({budget} calls) is spent. The findings on record are the report's "
    "basis now. Continue the close-out: reason.reason_pre_report_check → "
    "fix its blocking_issues (evaluate_finding / dispositions) → "
    "misc.write_projected_final_report → export_execution_log → "
    "atlas_finish. A pre_report_check that still lists blockers refills "
    "this budget for the probes those blockers need."
)

_WRAPUP_MSG = (
    "[budget wrap-up] Only {left} turns remain in this run's budget. Close "
    "out properly. Prefer a full report when READY_TO_REPORT:true. A "
    "degraded/partial report with Limitations is allowed only when the "
    "coverage ledger floor is met or this is a wall-clock/turn hard stop — "
    "do NOT retry a refused write in a loop. 1) run coverage.coverage_report; "
    "2) probe any remaining coverage-ledger gaps or mark them blocked with "
    "evidence; 3) run reason.reason_pre_report_check; 4) if "
    "READY_TO_REPORT:false, finish every listed blocking_issue (return to "
    "Triage/Collect/Analyze, synthesize, evaluate_finding, record "
    "dispositions as required), then re-run reason.reason_pre_report_check "
    "— repeat until READY_TO_REPORT:true or ledger-ready degraded exit; "
    "5) call misc.current_investigation_state and "
    "misc.write_projected_final_report (or misc.write_final_report when "
    "has_beliefs is false); 6) export_execution_log; 7) atlas_finish. "
    "Blockers release by finishing their tasks, not by skipping them. "
    "The loop will grant more turns while blockers remain (up to the "
    "blocker-extension budget) — use them to clear the gates."
)

_BLOCKER_EXTENSION_MSG = (
    "[blocker extension] Still READY_TO_REPORT:false — granting {extra} "
    "more turns ({granted}/{max_extra} extension budget used). Finish the "
    "listed blocking_issues, re-run pre_report_check until "
    "READY_TO_REPORT:true, then write the full report and call atlas_finish. "
    "Do not write a partial report; do not retry a refused write."
)
# Rough char budget for the conversation (~4 chars/token). Beyond it, the
# LLM check compresses older turns / tool payloads; the full output remains
# in the execution trace. Read dynamically so a pre-run model-context probe
# can grow or shrink ATLAS_AGENT_CONTEXT_CHARS after this module is imported.
# Default matches the recommended 1_000_000-token GLM-5.2 window (75% × 4).
def context_char_budget() -> int:
    try:
        from core.llm_check import session_limits
        lim = session_limits()
        if lim is not None:
            return int(lim.context_chars)
    except Exception:
        pass
    return env_int("ATLAS_AGENT_CONTEXT_CHARS", 3_000_000)


# Module-level value of context_char_budget() for importers.
CONTEXT_CHAR_BUDGET = context_char_budget()
TRIMMED_STUB = "[output trimmed from context — full text is in the execution trace]"
WAF_STUB = ("[this tool output was removed from context: the provider's web "
            "application firewall rejected it. The full output is in the "
            "execution trace. Re-derive what you need with narrower queries "
            "(filters, counts, specific rows) instead of raw dumps.]")
INTERRUPT_STUB = "[tool execution interrupted by the user]"

_DEFERRED_BACKLOG_FORCE_MSG = (
    "DEFERRED INTENT BACKLOG LATCH is active ({open}/{cap} open). "
    "Your NEXT tool call MUST be dair_assess. For each deferred intent, "
    "dispose via deferred_intent_dispositions (promote into priority_tools, "
    "dismiss, or keep). Forensic tools are blocked until open ≤ {hyst}. "
    "Do not retry blocked greps/queries until dair_assess promotes them."
)

# Quiet + open deferred intents: the model narrated
# dair_assess instead of emitting a function call after the 20-entry DAIR
# window aged out. Below the backlog latch, the existing latch nudge never
# fires. Two recoveries, then the normal wrap-up / quiet path — never an
# unbounded loop, and never a change to genuine quiet (no open intents).
DAIR_REENGAGE_MAX = 2

# Consecutive turns in which EVERY tool result came back protocol-blocked
# before the blocked-streak ladder engages. Small on purpose: a blocked turn
# is pure waste (no evidence read, no belief recorded), and the model has
# already been told in the block message itself to call dair_assess. Two
# turns of grace absorbs a transient batch; three means it is not listening.
DAIR_BLOCKED_TURNS_MAX = env_int("ATLAS_AGENT_DAIR_BLOCKED_TURNS", 3)

# How often the open-IOC-pivot nudge is re-sent. Every turn would crowd out
# the investigation with a list it is already working through; the pivots
# themselves are re-derived every turn regardless, and they block `complete`
# via core.investigation_obligations either way.
IOC_PIVOT_NUDGE_EVERY = env_int("ATLAS_AGENT_IOC_PIVOT_NUDGE_EVERY", 4)
# Every this many turns (and after each compaction) the model is shown what
# the run has already established: the distinct calls it made, the open
# questions, the unsearched indicators. Re-asking was the largest single
# cost of long runs, and it followed directly from forgetting.
KNOWLEDGE_INDEX_EVERY = env_int("ATLAS_AGENT_KNOWLEDGE_INDEX_EVERY", 6)


def loop_mode() -> str:
    """ATLAS_LOOP: "conversation" (default) or "frontier" (the queue of
    short focused calls)."""
    from core.envfile import env_str
    v = str(env_str("ATLAS_LOOP", "conversation") or "conversation").strip().lower()
    return v if v in ("conversation", "frontier") else "conversation"


def _vol_store_entries(case_dir) -> int:
    """How many memory plugin answers the result store holds at the run's
    start (core.vol_cache): answers from it are not re-run, so a run's wall
    clock is read beside this count."""
    try:
        from core.vol_cache import store_dir
        return sum(1 for _p in store_dir(case_dir).glob("*.json")) if case_dir else 0
    except Exception:  # noqa: BLE001
        return 0


def _role_models_safe() -> dict:
    """The model behind every role, for the trace. A run must be readable
    with the models that served it; a resolution error must not stop one."""
    try:
        from core.providers import role_models
        return role_models()
    except Exception:  # noqa: BLE001
        return {}

# Marker every protocol-block carries (core.deferred_intents.PROTOCOL_MARKER).
# Imported defensively — a blocked-streak detector must never be the thing
# that breaks a run if that module moves.
try:
    from core.deferred_intents import PROTOCOL_MARKER as _PROTOCOL_MARKER
except Exception:  # noqa: BLE001
    _PROTOCOL_MARKER = "[ATLAS_PROTOCOL]"
_DEFERRED_RE = re.compile(r'"deferred":\s*true')

# Warn one batch before the DAIR window ages out. Every expiry costs two
# turns (refusals → deferred intents → bare dair_assess → the same batch
# again); a dair_assess at the head of the next batch costs none, because
# calls in a batch run in order and see it.
DAIR_NUDGE_MARGIN = env_int("ATLAS_AGENT_DAIR_NUDGE_MARGIN", 5)

_DAIR_WINDOW_MSG = (
    "[dair window] {used} of {window} actions used since the last "
    "dair_assess. Forensic tools in your next batch will be deferred once "
    "the window is full — put a dair.dair_assess call FIRST in the next "
    "turn (the tools it promotes can follow in the same turn)."
)

_DAIR_REENGAGE_MSG = (
    "[dair reengage] Forensic tools are blocked because the DAIR window "
    "aged out (open deferred intents). Your NEXT action MUST be a "
    "function call to dair_assess. Do not describe "
    "the call in prose. Do not write the report yet."
)

# The first empty-tool turn names the actual blocker instead of the generic
# "continue … then write the report" nudge: while forensic tools are gated
# the model cannot do the closing work that nudge points at, so the turn is
# spent and the run moves closer to the quiet valve. Distinct tag from
# _DAIR_REENGAGE_MSG on purpose — this one does not consume the (capped)
# re-engage budget.
_DAIR_CONTINUE_MSG = (
    "[blocked] You returned no tool call. Forensic tools are currently "
    "blocked because the DAIR window aged out — the only way forward is a "
    "function call to dair_assess, which re-opens them "
    "and lets you dispose the deferred intents. Emit that call now: do not "
    "describe it in prose, and do not write the report while evidence work "
    "is still gated."
)

# Prepended to _WRAPUP_MSG on the quiet path when the blocker is a cold DAIR
# window. Deliberately a prefix, not a replacement: the close-out steps stay
# reachable, so a run that truly cannot re-engage still produces a report
# instead of ending with nothing.
_WRAPUP_BLOCKER_PREFIX = (
    "[blocked] Forensic tools are still gated on a cold DAIR window (open "
    "deferred intents). Call dair_assess FIRST and "
    "dispose the deferred intents — that is what unblocks the remaining "
    "evidence work. Only if that call keeps failing, close out with what "
    "you already have:\n\n"
)

# A narrated call ("DAIR window expired again. Let me call dair_assess…")
# with tool_calls == [] is a stall signature: reasoning models
# describe the call instead of emitting it. Deliberately narrow — it must
# name a DAIR re-engage, so a model narrating anything else (or genuinely
# wrapping up) never trips it. A false positive would only cost one extra
# nudge; a false negative costs the run.
_DAIR_PROSE_RE = re.compile(
    r"\b(?:call|calling|invoke|invoking|run|running|use|using|issue|issuing|"
    r"re-?engage|re-?establish|refresh)\b[^.\n]{0,60}?"
    r"\bdair[_\s-]?(?:dair[_\s-]?)?assess",
    re.IGNORECASE,
)

_RAW_MESSAGE_LOG_CAP = 2000


# Turns the director may sit in Report without moving towards the report
# (Agent._report_moved) before the loop asks for the report itself.
# Behaviour-based: a Report phase that keeps collecting and gets no closer is
# finished in all but name.
REPORT_STALL_TURNS = env_int("ATLAS_AGENT_REPORT_STALL_TURNS", 12)
# Syntheses in Report before the loop asks for the report: each synthesis
# names new gaps, and chasing every one keeps a finished investigation open.
REPORT_STALL_SYNTHESES = env_int("ATLAS_AGENT_REPORT_STALL_SYNTHESES", 3)
# Report-phase pushes in a row with no move towards the report between them
# before the run wraps up. Each push is a whole stall's worth of turns; a run
# that collects through three of them without getting closer has stopped
# producing, and the report it can write now is the report it will write.
REPORT_STALL_WRAPUP_FIRES = env_int("ATLAS_AGENT_REPORT_STALL_WRAPUP_FIRES", 3)
_REPORT_STALL_WRAPUP_MSG = (
    "[report phase] Several requests for the report have passed with no "
    "evidence read for the first time and no blocking issue resolved. The run "
    "is wrapping up now. Do not collect further: run "
    "reason.reason_pre_report_check (open gaps become documented "
    "limitations), then write the report from the findings recorded. "
    "misc.current_investigation_state reads them back in full."
)
_REPORT_DONE_MSG = (
    "[report phase] The case's report is written and the director has "
    "nothing further to prescribe: asking it again changes nothing. Write "
    "any per-host report still owed with misc.write_projected_final_report, "
    "then call atlas_finish."
)
# The push with the work order on (ATLAS_WORK_ORDER): open reads are listed
# in the report as not read; nothing asks the model to declare them
# unresolvable.
_REPORT_STALL_MSG_WO = (
    "[report phase] The director has been in Report for a long stretch "
    "without getting closer to the report: several syntheses, or many turns in "
    "which no work item was read and the report gate's blocking issues did not "
    "go down (a further variant of a finding does not count). Reading a due "
    "item of the [work order] is work towards the report; beyond that, stop "
    "collecting. An item you cannot close: run the read that would close it and "
    "let it fail (the failed call closes the item), or leave it, and the report "
    "lists it as not read. Then run reason.pre_report_check and write the report "
    "from the findings you have. "
    "misc.current_investigation_state reads those findings back in full if "
    "the conversation above no longer shows them."
)

_REPORT_STALL_MSG = (
    "[report phase] The director has been in Report for a long stretch "
    "without getting closer to the report: several syntheses, or many turns in "
    "which no evidence was read for the first time and the report gate's "
    "blocking issues did not go down (a further variant of a finding does not "
    "count). Reading evidence the gate lists as unexamined is work towards the "
    "report; beyond that, stop collecting. "
    "Gaps no available tool can close are limitations, not blockers: state "
    "each as 'UNRESOLVABLE: <what> — <why it cannot be closed>' so "
    "reason.pre_report_check records it, then run reason.pre_report_check and "
    "write the report from the findings you have. "
    # Asking for a report from "the findings you have" assumes the run can
    # still see them. After a long stretch the conversation may not carry
    # them, and the answer is one call away rather than a reconstruction.
    "misc.current_investigation_state reads those findings back in full if "
    "the conversation above no longer shows them."
)


def _empty_reply(resp) -> bool:
    """A reply with no text and no tool call although output was generated."""
    return (not (getattr(resp, "content", "") or "").strip()
            and not getattr(resp, "tool_calls", None)
            and int(getattr(resp, "output_tokens", 0) or 0) > 0)


def _batch_grace_begin() -> bool:
    """Tell the DAIR gate a batch starts now (core.middleware.begin_batch)."""
    try:
        from core.middleware import begin_batch
        return begin_batch()
    except Exception:  # noqa: BLE001
        return False


def _batch_grace_end() -> None:
    try:
        from core.middleware import end_batch
        end_batch()
    except Exception:  # noqa: BLE001
        pass


def _capped_json(payload) -> str:
    """Serialize a provider message for the transcript, size-capped. Never
    raises: an unserializable payload must not break a run."""
    try:
        text = json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001
        text = str(payload)
    return text[:_RAW_MESSAGE_LOG_CAP]

# Successful dair_assess or a successful critical/grep retry clears the latch.
_CRITICAL_CLEAR_NAME_RE = re.compile(
    r"(?:evtxecmd|chainsaw|hayabusa|"
    r"strings_grep|ngrep_search)",
    re.IGNORECASE,
)



def _ledger_run_tokens(payload: dict) -> dict:
    """This run's tokens from the usage ledger, every role included (the
    reasoning and director calls, the report and the reviewer), as the run
    status's input/output/cached figures; the analyst client's own counts
    stay beside them as client_*. Nothing changes when the ledger has no
    run id or cannot be read."""
    try:
        from core import usage_ledger
        ctx = usage_ledger.current()
        run_id = str(ctx.get("run_id") or "")
        if not run_id:
            return {}
        t = usage_ledger.totals(str(ctx.get("case_id") or ""), run_id)
    except Exception:  # noqa: BLE001 - the status write must never fail on this
        return {}
    return {"run_id": run_id,
            "client_input_tokens": payload.get("input_tokens"),
            "client_output_tokens": payload.get("output_tokens"),
            "client_cached_tokens": payload.get("cached_tokens"),
            "input_tokens": t["input_tokens"], "output_tokens": t["output_tokens"],
            "cached_tokens": t["cached_tokens"]}

# The calls that check or write the report: a running estate count is
# applied before them.
_REPORT_ENTRY_TOOLS = ("pre_report_check", "write_final_report", "write_projected_final_report",
                       "export_execution_log")

class Agent:
    def __init__(self, client: LLMHubClient, toolbox: Toolbox,
                 case_dir: Path | None, quiet: bool = False,
                 ui: UI | None = None, command: str = "run",
                 interactive: bool = False, stamp: str = ""):
        self.client = client
        self.toolbox = toolbox
        self.case_dir = case_dir
        self.command = command  # label shown in the live status banner
        # When True, atlas_ask_analyst prompts the human; otherwise it returns a
        # "proceed autonomously" note so unattended runs never block.
        self.interactive = interactive
        self.ui = ui or UI(quiet=quiet)
        self.messages: list[dict] = []
        # ``stamp`` names the transcript after the run's usage-ledger id.
        self.transcript_path = self._transcript_path(stamp)
        # Per-run stats: filled by run()/_run_tool, consumed by --json and
        # the completion summary panel.
        self.stats: dict = {}
        self._tool_stats: list[dict] = []
        # Layer-3 blocker-extension identity (core.investigation_exit).
        self._blocker_ext_fingerprint: str = ""
        self._blocker_ext_at_call_id: int = 0

    def _transcript_path(self, stamp: str = "") -> Path | None:
        if not self.case_dir:
            return None
        out = self.case_dir / "analysis"
        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # A chat about the case is not a run of it. Its transcript carries a
        # name of its own, so what reads a run's transcript (the dashboard's
        # activity signal, the fresh-run check, the evidence catalogue's
        # exclusion) is never tripped by a chat.
        kind = "chat" if self.command == "chat" else "agent"
        return out / f"{kind}_transcript_{stamp}.jsonl"

    def _log(self, record: dict) -> None:
        if not self.transcript_path:
            return
        record["ts"] = datetime.now(timezone.utc).isoformat()
        with open(self.transcript_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def _persist_live_status(self) -> None:
        """Best-effort mid-run snapshot for the dashboard's run-status panel.

        Same file (.atlas/run_status.json) agent/cli.py's _persist_run_status
        writes once at completion — this just also writes it every turn while
        the run is in progress. dashboard/run_manager.py's RunSession.status()
        already reads and merges this file; the final _persist_run_status()
        call at the end of the run overwrites it with the completed-run
        record.
        Never raises: a status write must not be able to break a real
        investigation run.

        A chat session never writes it. The file is a run's record — its pid
        is what the dashboard's run indicators check — so a chat that wrote
        it would show as a run in progress for as long as its worker lived,
        and would overwrite the record of the finished run it is asking
        about.
        """
        if not self.case_dir or self.command == "chat":
            return
        try:
            # Two different things, reported as two: a tool that failed,
            # and a call the toolbox refused before running anything. Lumping
            # them together made a run that corrected its own tool calls look
            # like a run that was breaking.
            failed = [t.get("error_text") or "tool error"
                      for t in self._tool_stats
                      if t.get("error") and not t.get("refusal")]
            refused = [t.get("error_text") or "call refused"
                       for t in self._tool_stats if t.get("refusal")]
            infos = sum(1 for t in self._tool_stats if t.get("info"))
            payload = {
                "finish_status": "",
                "stopped_reason": "running",
                "turns": self.stats.get("turns"),
                "duration_seconds": self.stats.get("duration_seconds"),
                "input_tokens": getattr(self.client, "total_input_tokens", 0),
                "output_tokens": getattr(self.client, "total_output_tokens", 0),
                "cached_tokens": getattr(self.client, "total_cached_tokens", 0),
                "tool_calls": len(self._tool_stats),
                "error_count": len(failed),
                # Capped, not the full list — the file is rewritten every
                # turn, so an unbounded error list would grow the write cost
                # over a long run for no real benefit to the dashboard panel.
                "recent_errors": [str(e)[:200] for e in failed[-5:]],
                "refusal_count": len(refused),
                "recent_refusals": [str(e)[:200] for e in refused[-5:]],
                "info_count": infos,
                "activity": self.ui.run_state.get("activity") or "",
                # The model-call escape has run past ATLAS_ESCAPE_ALERT_SECONDS.
                "escape_alert": bool(self.ui.run_state.get("escape_alert")),
                # wall-clock start of the currently in-flight tool call, or
                # "" between calls — lets a reader (dashboard/read_models.py)
                # tell "waiting on a long tool" apart from "log just hasn't
                # updated in a while", and compute how long it's been running.
                "tool_started_at": self.ui.run_state.get("tool_started_at") or "",
                # Delivered pieces of evidence by status (core.evidence_items).
                "evidence_items": self._evidence_item_counts(),
                # What the images hold and how much of it was read (the
                # contents index's unit model, the same numbers the
                # evidence table shows), recomputed once per turn.
                "contents": self._contents_counts(),
                # This process's own PID — the one thing that stays valid
                # for a run's entire lifetime regardless of how often this
                # file itself gets rewritten. Lets a reader confirm the run
                # is still alive (os.kill(pid, 0)) even when nothing else
                # here has been updated recently, and regardless of whether
                # the run was started via the dashboard or the bare CLI.
                "pid": os.getpid(),
                "started_at": getattr(self, "_started_at", "") or "",
                "updated_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
            }
            payload.update(_ledger_run_tokens(payload))
            p = self.case_dir / ".atlas" / "run_status.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8")
            os.replace(tmp, p)
        except Exception:
            pass

    # ── context management ───────────────────────────────────────────────

    def _describes_a_tool_call(self, content: str) -> bool:
        """True when a reply with no function call reads as an announced
        action: it names a tool the run has, or opens with an intention."""
        text = content or ""
        if _INTENT_RE.search(text):
            return True
        low = text.lower()
        try:
            names = list(self.toolbox.tools.keys())
            aliases = [t.alias for t in self.toolbox.tools.values()]
        except Exception:  # noqa: BLE001
            names, aliases = [], []
        return any(n and n.lower() in low for n in names + aliases)

    def _named_tools_not_loaded(self, content: str) -> list[tuple[str, str]]:
        """``(alias, namespace)`` for tools the reply names that cannot run.

        The toolbox discovers every tool but only sends schemas for loaded
        namespaces, so a reply may name a real tool the model has no way to
        call. Reported so the rescue can say which namespace to bring back.
        """
        low = (content or "").lower()
        out: list[tuple[str, str]] = []
        try:
            loaded = self.toolbox.loaded
            infos = list(self.toolbox.tools.values())
        except Exception:  # noqa: BLE001
            return out
        control = getattr(self.toolbox, "control_names", frozenset())
        for info in infos:
            if info.namespace in loaded or getattr(info, "listed", "") in control:
                continue
            if any(token and token.lower() in low
                   for token in (info.alias, info.name)):
                out.append((info.alias, info.namespace))
        return out

    def _prefix_reuse(self) -> dict:
        """Compare this request's messages with the previous one: the count
        of leading messages that are byte-identical (the part a prefix
        cache can serve) over the total. Cheap — one hash per message."""
        import hashlib
        sigs = [hashlib.blake2b(
            json.dumps(m, sort_keys=True, default=str).encode("utf-8"),
            digest_size=12).digest() for m in self.messages]
        prev = getattr(self, "_last_sent_sigs", None) or []
        same = 0
        for a, b in zip(prev, sigs):
            if a != b:
                break
            same += 1
        self._last_sent_sigs = sigs
        return {"reused_messages": same, "messages": len(sigs)}

    def _nudge(self, kind: str, content: str) -> None:
        """Inject a steering message, superseding the last one of its kind.

        Nudges are re-derived every few turns from the same state; the
        earlier copies said the same thing with fewer items. Keeping all of
        them only made the conversation longer and the
        instruction less visible.
        """
        self._retire_nudge(kind)
        if getattr(self, "_nudge_index", None) is None:
            self._nudge_index = {}
        self.messages.append({"role": "user", "content": content})
        self._nudge_index[kind] = len(self.messages) - 1

    def _retire_nudge(self, kind: str) -> None:
        """Stub out the standing nudge of this kind, whose ask no longer
        holds or is said again below it."""
        i = (getattr(self, "_nudge_index", None) or {}).get(kind)
        if i is not None and i < len(self.messages) and \
                (self.messages[i].get("role") or "") == "user":
            from core.llm_check import _TURN_STUB
            self.messages[i]["content"] = _TURN_STUB

    def _nudge_stands(self, kind: str, content: str) -> bool:
        """Whether the last nudge of this kind is still in the conversation
        word for word - then saying it again adds nothing."""
        i = (getattr(self, "_nudge_index", None) or {}).get(kind)
        return (i is not None and i < len(self.messages)
                and (self.messages[i].get("content") or "") == content)

    def _trim_context(self) -> None:
        from core.llm_check import (
            ContextBudgetExceededError, compact_aged_messages, fit_messages,
        )
        tools = None
        try:
            tools = self.toolbox.openai_tools()
        except Exception:
            tools = None
        # Age first, budget second: the budget pass alone let a long run
        # resend every old tool payload on every turn.
        # The cadence is in turns unless the operator pinned the message
        # counts: the cacheable prefix then stays put for a fixed number of
        # turns however many calls the model makes in each.
        import os as _os
        pinned = any(_os.environ.get(k) for k in
                     ("ATLAS_AGENT_KEEP_TOOL_RESULTS", "ATLAS_AGENT_COMPACT_BATCH"))
        try:
            compacted = compact_aged_messages(
                self.messages,
                keep_tool_results=env_int("ATLAS_AGENT_KEEP_TOOL_RESULTS", 12),
                keep_turn_text=env_int("ATLAS_AGENT_KEEP_TURN_TEXT", 16),
                batch=env_int("ATLAS_AGENT_COMPACT_BATCH", 6),
                keep_tool_turns=None if pinned else env_int("ATLAS_AGENT_KEEP_TOOL_TURNS", 4),
                batch_turns=None if pinned else env_int("ATLAS_AGENT_COMPACT_BATCH_TURNS", 6))
            if compacted:
                self._log({"event": "context_compacted", "messages": compacted})
                self._compacted_since_index = True
        except Exception as _ce:  # noqa: BLE001
            self._log({"event": "context_compact_failed", "error": str(_ce)[:200]})
        try:
            fit_messages(self.messages, tools=tools)
        except ContextBudgetExceededError as e:
            # fit_messages refuses when the system frame alone exceeds the
            # send budget. That verdict comes from a chars/4 *estimate* and
            # from a window that may itself be a guess (a failed model-context
            # probe installs a fallback), so it must never be the thing that
            # kills a multi-hour investigation: say so loudly and let the
            # request go. If it really doesn't fit, the provider answers with
            # a 400/413 and the existing LLMError path reports the real
            # reason instead of an estimate's.
            self.ui.warn(f"context budget: {e}")
            self._log({"event": "context_budget_exceeded",
                       "error": str(e)[:300]})

    def _refresh_context_budget(self, turn: int = 0) -> None:
        """Stewardship: recompute budget + re-orchestrate the plan.

        Optionally LLM-refines candidate order when top scores are flat.
        Updates LIVE strip fields. Fail-open.
        """
        if not self.case_dir:
            return
        try:
            from core.investigation_orchestrator import refresh_orchestration
            model = getattr(self.client, "model", "") or ""
            provider = ""
            try:
                prov = getattr(self.client, "provider", None)
                provider = getattr(prov, "name", "") or ""
            except Exception:
                pass
            turn_n = int(turn or (self.ui.run_state or {}).get("turn") or 0)
            # The ranking gets a client only when ATLAS_ORCH_LLM_RANK asks for it.
            mode = (os.environ.get("ATLAS_ORCH_LLM_RANK") or "off").lower()
            client = None if mode in ("0", "off", "false", "no", "") else self.client
            result = refresh_orchestration(
                self.case_dir,
                messages=self.messages,
                model=str(model),
                provider=str(provider),
                llm_client=client,
                turn=turn_n,
                persist=True,
            )
            live = result.get("live") or {}
            self.ui.set_run_state(**{
                k: v for k, v in live.items() if v is not None and v != ""
            })
        except Exception:
            # Fall back to budget-only refresh
            try:
                from core import context_budget as _cb
                model = getattr(self.client, "model", "") or ""
                provider = ""
                try:
                    prov = getattr(self.client, "provider", None)
                    provider = getattr(prov, "name", "") or ""
                except Exception:
                    pass
                snap = _cb.compute(
                    self.case_dir,
                    model=str(model),
                    provider=str(provider),
                    messages=self.messages,
                    persist=True,
                )
                self.ui.set_run_state(
                    ctx_policy=snap.get("detail_policy"),
                    ctx_tool_tok=snap.get("available_for_tool_output_tokens"),
                )
            except Exception:
                pass

    def _chat_waf_tolerant(self):
        """One chat turn; on a WAF block, drop recent tool outputs from
        context (largest first) and retry — after a block a firewall may
        briefly ban the source, so wait before retrying."""
        for attempt in range(4):
            try:
                # The escape (_chat_turn_asked_again) may ask without the
                # tool list, with a shortened copy of the history, or with
                # a level, learn=False and a tool_choice of its own; all
                # unset outside an escape.
                escape_kw = dict(getattr(self, "_escape_kw", None) or {})
                no_tools = escape_kw.pop("_no_tools", False)
                tools = None if no_tools else self.toolbox.openai_tools()
                # getattr-guarded: test doubles and any other minimal
                # Toolbox-like object may not implement this — a schema-overflow warning is a nice-to-have
                # diagnostic, never worth an AttributeError on the hot path.
                pop_warning = getattr(
                    self.toolbox, "pop_schema_overflow_warning", None)
                overflow = pop_warning() if pop_warning else None
                if overflow:
                    self.ui.warn(overflow)
                    self._log({"event": "tool_schema_overflow",
                               "warning": overflow})
                # One request after a reply that narrated its call or named
                # no tool asks for the function channel outright. The same
                # request repeated gave the same prose; with tool_choice
                # "required" it answered with a call in a second. A standard
                # parameter, dropped by the 400-adaptation where an endpoint
                # rejects it.
                choice = getattr(self, "_tool_choice_next", None)
                self._tool_choice_next = None
                extra = {"tool_choice": choice} if (choice and tools) else {}
                # One ask one thinking level lower after a runaway reply of
                # repeated calls (_split_reply_duplicates); used once.
                once = getattr(self, "_next_level_once", None)
                if once:
                    extra.update({"level": once, "learn": False})
                    self._next_level_once = None
                extra.update(escape_kw)
                if not tools:
                    extra.pop("tool_choice", None)
                self._note_tool_choice_unavailable(extra.get("tool_choice"))
                messages = getattr(self, "_escape_messages", None) or self.messages
                resp = self.client.chat(messages, tools=tools, role=_AGENT_ROLE,
                                        **self._chat_kwargs_taken(extra))
                self._drop_malformed_calls(resp)
                return resp
            except WAFBlockedError as e:
                # The list the request carried: the escape's shortened copy
                # at rung 3, else the history.
                sent = getattr(self, "_escape_messages", None) or self.messages
                candidates = sorted(
                    (m for m in sent
                     if m.get("role") == "tool"
                     and len(m.get("content") or "") > 200
                     and m["content"] not in (TRIMMED_STUB, WAF_STUB)),
                    key=lambda m: len(m["content"]), reverse=True)
                if not candidates or attempt == 3:
                    raise
                candidates[0]["content"] = WAF_STUB
                self._log({"event": "waf_block", "error": str(e)})
                self.ui.warn("WAF block — removed a tool output from context, "
                             "retrying after cooldown")
                time.sleep(60)

    def _chat_kwargs_taken(self, extra: dict) -> dict:
        """``extra`` without the keywords this client's chat() does not take
        (a test double or a minimal client): the escape then skips what the
        client cannot do instead of raising."""
        if not extra:
            return extra
        import inspect
        try:
            params = inspect.signature(self.client.chat).parameters
        except (TypeError, ValueError):
            return extra
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return extra
        return {k: v for k, v in extra.items() if k in params}

    def _note_tool_choice_unavailable(self, choice) -> None:
        """Once per run, when a tool_choice value the endpoint refused for
        this model is asked for (the intent rescue's or the escape's
        "required"): the request goes as "auto" and only its text carries
        the ask (ATLAS_TOOL_CHOICE_VALUE_MEMORY)."""
        if not choice or getattr(self, "_tool_choice_unavailable_logged", False):
            return
        from agent.llm import tool_choice_value_memory_on
        profile = getattr(self.client, "profile", None)
        rejected = getattr(profile, "tool_choice_rejected", ())
        if isinstance(rejected, tuple) and choice in rejected and tool_choice_value_memory_on():
            self._tool_choice_unavailable_logged = True
            self._log({"event": "tool_choice_unavailable", "value": choice})

    # What the director last prescribed, as the tool references it wrote.
    _last_director_tools: list[str] = []
    # Whether the director's last reply reported no change since the one
    # before it (a standing assessment handed back).
    _last_dair_unchanged = False
    # The largest tool list a function call has arrived with in this run.
    _tools_ok_at = 0
    # A list sent past the learned ceiling as a test of it: its size, the
    # namespace that took it there and the ceiling it left, until the reply
    # decides; and the size at which a test failed, which none repeats.
    _tool_probe_at = 0
    _tool_probe_ns = ""
    _tool_probe_floor = 0
    _tool_probe_failed_at = 0

    def _note_dair_phase(self, result: str) -> None:
        """Remember the phase the director just set and what it prescribed,
        and bring the prescribed tools into the list before the next turn."""
        try:
            data = json.loads(result) if isinstance(result, str) else result
            phase = str((data or {}).get("current_phase") or "")
        except Exception:  # noqa: BLE001
            return
        if phase:
            self._dair_phase = phase
            if phase != "Report":
                self._report_pushed = False     # see _push_report_phase
        progress = data.get("progress") if isinstance(data, dict) else None
        self._last_dair_unchanged = (isinstance(progress, dict)
                                     and progress.get("changed") is False)
        tools = self._director_tools(data)
        if tools:
            self._last_director_tools = tools
            self._load_namespaces_for(tools)
        self._director_items(data)

    def _reaches_due_item(self, tool: str, args: dict | None) -> bool:
        """Whether a call would reach a due work item's target: the item is
        the reason the read exists, so the belief-starvation latch lets it
        run (ATLAS_WORK_ORDER)."""
        from core.deferred_intents import work_order_on
        if not (work_order_on() and getattr(self, "case_dir", None)):
            return False
        try:
            from core.execution_log import log
            from core.work_order import _call_view, _reaches
            view = _call_view({"type": "tool_call", "cmd": f"<py>:{tool}", "mcp_tool": tool}, dict(args or {}),
                              case_dir=str(self.case_dir))
            return any(_reaches(i, view, str(self.case_dir)) for i in log.work_items(statuses=("due",)))
        except Exception:  # noqa: BLE001
            return False

    def _director_items(self, data) -> None:
        """The director's prescribed reads as work items, by the
        vocabulary-free parse (ATLAS_WORK_ORDER); a parsed entry whose
        fingerprint equals a proposal's adopts it. An entry with no target
        a call can reach makes no item: it is recorded with the review's
        directives as refused, so the next review shows it, and counted on
        the director line."""
        from core.deferred_intents import work_order_on
        self._wo_not_tracked = 0
        if not (work_order_on() and getattr(self, "case_dir", None) and isinstance(data, dict)):
            return
        try:
            from core.execution_log import log
            from core.work_order import NOT_TRACKED, note_untracked_entries, parse_director_entries
            refused: list[str] = []
            for e in parse_director_entries(data, str(self.case_dir), refused):
                log.add_work_item("director", e["task_ids"], e["tool"], e["target"], e["why"],
                                  status=e["status"],
                                  source_ref={"kind": "dair_call", "call_id": data.get("_atlas_call_id")})
            if refused:
                # One refused line per reason names its tools, not one line
                # per entry: a long bare list would fill the next review, and
                # each line keeps the reason its entries were refused for.
                self._wo_not_tracked = len(refused)
                by_reason: dict[str, list[str]] = {}
                for t in refused:
                    tool, _sep, why = t.partition(": ")
                    by_reason.setdefault(why.strip() or NOT_TRACKED, []).append(tool)
                lines = []
                for why, named in list(by_reason.items())[:8]:
                    tools = list(dict.fromkeys(named))
                    names = ", ".join(tools[:20]) + (f" and {len(tools) - 20} more" if len(tools) > 20 else "")
                    lines.append(f"{names}: {why}")
                if len(by_reason) > 8:
                    rest = sum(len(v) for v in list(by_reason.values())[8:])
                    lines.append(f"and {rest} more entries refused for {len(by_reason) - 8} more reasons")
                note_untracked_entries(log, data.get("_atlas_call_id"), lines)
                self._log({"event": "director_entries_not_tracked", "call_id": data.get("_atlas_call_id"),
                           "count": len(refused), "entries": refused[:20]})
        except Exception as err:  # noqa: BLE001
            self._log({"event": "work_order_director_parse_failed", "error": str(err)[:200]})

    @staticmethod
    def _director_tools(data) -> list[str]:
        """Tool references in a director result, wherever it carries them."""
        if not isinstance(data, dict):
            return []
        refs: list[str] = []
        for holder in (data.get("directives") or {}, data):
            raw = holder.get("priority_tools") if isinstance(holder, dict) else None
            for item in raw or []:
                if isinstance(item, dict):
                    item = item.get("tool") or item.get("name") or ""
                if isinstance(item, str) and item.strip():
                    refs.append(item.strip())
            if refs:
                break
        return refs

    def _load_namespaces_for(self, tool_refs, *, turn: int | None = None) -> list[str]:
        """Load the namespaces of the tools in ``tool_refs`` that are not
        listed yet, so a call to any of them can arrive.

        A gateway drops a function call whose name is not in the list, and
        the loop cannot see what was dropped; what it can do is make sure the
        tools the director asked for are in the list before the model tries.
        Returns the namespaces newly loaded.
        """
        toolbox = self.toolbox
        resolve = getattr(toolbox, "resolve", None)
        infos = getattr(toolbox, "tools", None)
        load = getattr(toolbox, "load_with_budget", None)
        if resolve is None or not isinstance(infos, dict) or load is None:
            return []
        loaded = set(getattr(toolbox, "loaded", ()) or ())
        control = getattr(toolbox, "control_names", frozenset())
        # Every namespace the work order refers to stays or arrives; the
        # room for the ones arriving is never made from the ones it also
        # names, loaded already or not.
        referenced: list[str] = []
        for ref in tool_refs or []:
            m = _TOOL_TOKEN_RE.match(str(ref))
            if not m:
                continue
            real = resolve(m.group(1))
            info = infos.get(real) if real else None
            if info is None or getattr(info, "listed", "") in control:
                continue
            ns = getattr(info, "namespace", "")
            if ns and ns not in referenced:
                referenced.append(ns)
        wanted = [ns for ns in referenced if ns not in loaded]
        if not wanted:
            return []
        # A work order that does not fit under a learned ceiling is the
        # moment to test that ceiling: the load may go one namespace past
        # it, and the reply to the list says whether the size holds.
        toolbox.tool_probe_limit = self._tool_probe_limit()
        try:
            try:
                # Room may come from any cold namespace, never from one the
                # order names or one in recent use.
                from core.envfile import env_flag
                if env_flag("ATLAS_TOOL_ARRAY_STABLE", True):
                    # A preload for the director fills free room only: an
                    # eviction would change the schema array the provider
                    # renders before the whole conversation (its cache).
                    try:
                        outcome = load(wanted, keep=referenced, evict=False) or {}
                    except TypeError:        # a loader without the parameter
                        outcome = load(wanted, keep=referenced) or {}
                else:
                    outcome = load(wanted, keep=referenced) or {}
            except TypeError:
                outcome = load(wanted) or {}
        except Exception:  # noqa: BLE001 - loading is best effort
            return []
        finally:
            self._adopt_tool_probe(turn)
            toolbox.tool_probe_limit = self._tool_probe_limit()
        newly = list(outcome.get("newly_loaded") or [])
        self._log({"event": "namespaces_loaded_for_director", "turn": turn,
                   "wanted": wanted, "kept": referenced, "loaded": newly,
                   "refused": [r.get("namespace") for r in outcome.get("refused") or []],
                   "evicted": list(outcome.get("evicted") or [])})
        if newly:
            self.ui.info("loaded " + ", ".join(newly)
                         + " for the director's work order")
        return newly

    def _adopt_tool_probe(self, turn: int | None) -> None:
        """Read the probe the toolbox's last loads made, whoever asked for
        the load: the director's order, a call to an unloaded tool, or the
        model loading a namespace itself. The reply that follows tests it."""
        pop = getattr(self.toolbox, "pop_last_probe", None)
        probed = pop() if callable(pop) else None
        if not isinstance(probed, dict) or not probed.get("count"):
            return
        self._tool_probe_at = int(probed["count"])
        self._tool_probe_ns = str(probed.get("namespace") or "")
        self._tool_probe_floor = int(probed.get("floor") or 0)
        self._log({"event": "tool_budget_probe", "turn": turn,
                   "from": self._tool_probe_floor, "to": self._tool_probe_at,
                   "namespace": self._tool_probe_ns})
        self.ui.info(f"testing the tool list at {self._tool_probe_at} "
                     f"schemas (remembered ceiling {self._tool_probe_floor}): "
                     f"loaded {self._tool_probe_ns}")

    def _tool_probe_limit(self) -> int:
        """How far past the learned ceiling the next load may reach: not at
        all before a function call has arrived this run, not while a test
        awaits its reply, and never up to a size at which one failed."""
        if not self._tools_ok_at or self._tool_probe_at:
            return 0
        from agent.toolbox import hard_tool_cap
        limit = hard_tool_cap()
        if self._tool_probe_failed_at:
            limit = min(limit, self._tool_probe_failed_at - 1)
        return limit

    def _fail_tool_probe(self, turn: int) -> None:
        """The reply to a tested list tried to call and no call arrived:
        the namespace that took the list past the ceiling leaves, the
        ceiling returns to where it was, and no test reaches that size
        again this run."""
        from agent.toolbox import set_learned_tool_ceiling
        # The ceiling goes back first: a probe that completed the list made
        # it stable, and a stable list refuses the unload below.
        set_learned_tool_ceiling(self._tool_probe_floor or None)
        unload = getattr(self.toolbox, "unload", None)
        if unload is not None and self._tool_probe_ns:
            try:
                unload([self._tool_probe_ns])
            except Exception:  # noqa: BLE001 - the ceiling above still holds
                pass
        self._tool_probe_failed_at = self._tool_probe_at
        self._log({"event": "tool_budget_probe_failed", "turn": turn,
                   "at": self._tool_probe_at, "namespace": self._tool_probe_ns,
                   "back_to": self._tool_probe_floor})
        self.ui.warn(f"no function call arrived with {self._tool_probe_at} "
                     f"tool schemas — unloaded {self._tool_probe_ns}, back "
                     f"to {self._tool_probe_floor} and asked again")
        self._tool_probe_at = 0
        self._tool_probe_ns = ""

    def _dropped_call_message(self) -> str:
        if _list_stable(self.toolbox):
            return _DROPPED_CALL_STABLE_MSG
        loaded = sorted(set(getattr(self.toolbox, "loaded", ()) or ()))
        return _DROPPED_CALL_MSG.format(loaded=", ".join(loaded) or "none")

    def _last_tool_flags(self, name: str) -> dict:
        """How the call just executed was classified, for the transcript.

        `_run_tool` already separates a tool that broke from a call refused
        for its own shape — the tool never ran and nothing is damaged — and
        keeps both on the live counters. The transcript is what outlives the
        run, and carried neither, so a reader of a finished case could only
        tell them apart by re-implementing the classifier on the result text.
        Name-matched: a mismatch yields no flags rather than another call's.
        """
        stat = self._tool_stats[-1] if self._tool_stats else {}
        if not stat or stat.get("name") != name:
            return {}
        return {"error": bool(stat.get("error")),
                "refusal": bool(stat.get("refusal"))}

    def _claim_count(self) -> int:
        try:
            from core.claim_graph import load_graph
            nodes = load_graph(self.case_dir).get("nodes") or {}
            return len(nodes)
        except Exception:  # noqa: BLE001
            return -1

    @staticmethod
    def _last_call_id() -> int:
        """The highest call id the execution log holds."""
        try:
            from core.execution_log import log
            return max((int(e.get("call_id") or 0) for e in log._entries), default=0)
        except Exception:  # noqa: BLE001
            return 0

    def _report_blockers(self) -> int | None:
        """Blocking issues the newest report-gate verdict of this run named;
        None before its first. A rerun's log holds the previous run's
        verdicts (configure() resumes the trace), so the ones recorded before
        this run started (``_run_since``) are not its own."""
        try:
            from core.execution_log import log
            from core.progress_signature import report_gate_blockers
            return report_gate_blockers(log._entries,
                                        since_call_id=getattr(self, "_run_since", 0))
        except Exception:  # noqa: BLE001
            return None

    def _report_settled(self) -> int | None:
        """How many high-value artifacts the newest report-gate verdict of
        this run found read, failed or explained (tools/reasoning.py
        stores it on the check); None before its first."""
        try:
            from core.execution_log import log
            from core.progress_signature import newest_report_check
            e = newest_report_check(log._entries, since_call_id=getattr(self, "_run_since", 0))
            return None if e is None or e.get("hv_settled") is None else int(e["hv_settled"])
        except Exception:  # noqa: BLE001
            return None

    def _report_done(self) -> frozenset:
        """What the report gate's own sources count as discharged, by
        identity: coverage-ledger units and delivered evidence items no
        longer unseen, disk media no longer waiting for an open, requests no
        longer actionable (or blocked on missing evidence), request parts
        no longer open and findings no longer under the review Plane A raised
        on them. A first read, open, block, close or settled review adds a member; a
        re-read, a finding, a variant of one, a refused close, a reopened and
        re-closed part, or a unit registered unseen adds none, and a unit a
        ledger rebuild drops takes nothing away from what was already seen.

        Producing never-read artefacts out of the evidence (an extraction)
        and reading them adds members, so such a run is not stalled: reading
        what nobody has read is examination. No count can tell a thorough run
        from a wasteful one; repeated calls and refusals are the deadlock
        breaker's and the runaway guard's to end, not this ladder's."""
        done: set = set()
        try:
            from core.coverage_ledger import load_ledger
            ledger = load_ledger(self.case_dir)
            done.update(("unit", str(u.get("path"))) for u in (ledger.get("units") or {}).values()
                        if isinstance(u, dict) and str(u.get("status") or "unseen") != "unseen")
            done.update(("item", str(i.get("path"))) for i in (ledger.get("items") or {}).values()
                        if isinstance(i, dict) and i.get("status") in ("examined", "blocked"))
        except Exception:  # noqa: BLE001
            pass
        try:
            from core.evidence_access import media_entries, pending_media_open
            pending = {str(e.get("path")) for e in pending_media_open(self.case_dir)}
            done.update(("media", str(e.get("path"))) for e in media_entries(self.case_dir)
                        if str(e.get("path")) not in pending)
        except Exception:  # noqa: BLE001
            pass
        try:
            from core.investigation_tasks import ACTIONABLE_STATUSES, load_tasks
            for task in load_tasks(self.case_dir).get("tasks") or []:
                if not isinstance(task, dict):
                    continue
                tid, status = str(task.get("id") or ""), str(task.get("status") or "")
                if status not in ACTIONABLE_STATUSES or status == "blocked_missing_evidence":
                    done.add(("task", tid))
                done.update(("part", tid, str(part.get("id") or ""))
                            for part in task.get("parts") or []
                            if isinstance(part, dict) and part.get("status") != "open")
        except Exception:  # noqa: BLE001
            pass
        try:
            # A finding that left a review (re-validated: review_history;
            # superseded or withdrawn while under review: invalidated_at).
            # Only Plane A raises a review, so these grow only with what the
            # run was handed.
            from core.claim_graph import load_graph
            done.update(("review", str(nid))
                        for nid, n in (load_graph(self.case_dir).get("nodes") or {}).items()
                        if isinstance(n, dict) and n.get("status") != "needs_review"
                        and (n.get("review_history") or n.get("invalidated_at")))
        except Exception:  # noqa: BLE001
            pass
        try:
            # A work item closed (read, failed, dismissed) or made moot is a
            # move: a listing near it or a repeated step is not (ATLAS_WORK_ORDER).
            from core.deferred_intents import work_order_on
            if work_order_on():
                from core.execution_log import log as _wlog
                from core.work_order import closed_ids
                done.update(closed_ids(_wlog))
        except Exception:  # noqa: BLE001
            pass
        return frozenset(done)

    def _report_moved(self, attr: str, *, claims: bool) -> bool:
        """Has the run moved towards the report since the mark stored under
        ``attr``? Movement is a member of _report_done never seen before
        under this mark (something the gate counts as open read, opened,
        blocked or closed for the first time), a new low of the blocking
        issues of this run's newest gate verdict (its first verdict is one),
        a new high of the high-value artifacts that verdict found settled
        (_report_settled: one more read, failed or explained, which the
        gate's single issue for them does not show until the last one), or,
        before that verdict and when ``claims``, any change of the claim
        graph. A finding recorded while nothing new was discharged and the
        same blockers stand (a variant of a finding the gate objects to) is
        no movement, nor are blockers that rise and fall back. The mark keeps
        every member seen, the low and the high; a check without movement
        leaves it.

        The trade this accepts: after the gate's first verdict, a deep dive
        inside evidence already read that closes no request part and lowers
        no blocking issue wraps up after REPORT_STALL_WRAPUP_FIRES stalls
        (36 Report turns at the defaults): it is the collection the ladder
        exists to end."""
        blockers = self._report_blockers()
        settled = self._report_settled()
        done = self._report_done()
        count = self._claim_count() if claims and blockers is None else None
        last = getattr(self, attr, None)
        if last is None:
            setattr(self, attr, (blockers, count, done, settled))
            return True
        low, last_count, seen, high = last
        moved = (bool(done - seen)
                 or (blockers is not None and (low is None or blockers < low))
                 or (settled is not None and (high is None or settled > high))
                 or (count is not None and count != last_count))
        if moved:
            setattr(self, attr, (
                low if blockers is None else blockers if low is None else min(blockers, low),
                count, seen | done,
                high if settled is None else settled if high is None else max(settled, high)))
        return moved

    def _push_report_phase(self, turn: int, *, reason: str) -> bool:
        """Ask for the report with the gaps named. After
        REPORT_STALL_WRAPUP_FIRES pushes with no move towards the report
        between them the run wraps up: it has stopped producing, and asking
        again would only extend the collection it is asked to end. Returns
        True on wrap-up.

        From the first push until the director leaves Report the pivot nudge
        yields, and its standing copy goes: it sends the model back to
        searches that are no move towards the report, so the gate this
        message asks for is never run and the ladder wraps up without it."""
        self._nudge("report_phase_stall", self._report_stall_msg())
        self._report_pushed = True
        self._retire_nudge("ioc_pivot_nudge")
        self._log({"event": "report_phase_stall", "turn": turn,
                   "quiet_turns": REPORT_STALL_TURNS, "reason": reason})
        if not self._report_stall_exhausted(turn):
            return False
        self.messages.append({"role": "user", "content": _REPORT_STALL_WRAPUP_MSG})
        self._log({"event": "budget_wrapup", "turn": turn,
                   "trigger": "report_stall", "pushes": self._report_stall_fires})
        self._record_budget_wrapup_marker("report_stall", turn,
                                          allow_synthesize_escape=True)
        self.ui.warn(f"report phase pushed {self._report_stall_fires} times "
                     "without getting closer to the report — wrapping up")
        return True

    @staticmethod
    def _report_stall_msg() -> str:
        from core.deferred_intents import work_order_on
        return _REPORT_STALL_MSG_WO if work_order_on() else _REPORT_STALL_MSG

    # ── the work order (ATLAS_WORK_ORDER) ─────────────────────────────────

    def _escape_follow_up(self) -> str:
        """The escape's follow-up: the work order's shortest ready call when
        the order is on and a read is due (core.work_order), else the ask
        to issue the step the summary named."""
        try:
            from core.deferred_intents import work_order_on
            if work_order_on():
                from core import work_order as W
                from core.execution_log import log
                call, item_id = W.shortest_ready(log, self.case_dir, self._tool_params)
                if call:
                    # A showing like the per-turn block's, so the evidence
                    # gaps' "shown N times" counts it; the turn has not
                    # ended, so it is not counted as left unattended.
                    W.mark_presented(log, [item_id], {item_id})
                    if call.startswith("read "):
                        return _ESCAPE_FOLLOW_UP_READ.format(call=call[5:])
                    return _ESCAPE_FOLLOW_UP_READY.format(call=call)
        except Exception:  # noqa: BLE001 - the plain follow-up always stands
            pass
        return _ESCAPE_FOLLOW_UP

    def _tool_params(self, tool: str) -> list[str] | None:
        """The argument names of ``tool`` in the tool list, or None."""
        try:
            name = self.toolbox.resolve(tool)
            info = self.toolbox.tools.get(name) if name else None
            return list(((info.schema or {}).get("properties") or {}).keys()) if info else None
        except Exception:  # noqa: BLE001
            return None

    def work_order_settled(self) -> bool:
        """No counted due item, or the order neglected: the report ladder's
        force-report, finish and close-out may go ahead."""
        from core.deferred_intents import work_order_on
        if not work_order_on() or not self.case_dir:
            return True
        if getattr(self, "_wo_neglected", False):
            return True
        try:
            from core.execution_log import log
            from core.work_order import counted_due
            return not counted_due(log, self.case_dir)
        except Exception:  # noqa: BLE001
            return True

    def _work_order_turn(self, turn: int, wrapped_up: bool) -> None:
        """Once per turn: derive items from the run's state, track movement
        and the neglect streak, and show the due items as ready calls last
        in the conversation, superseding the standing copy. Fail-open."""
        from core.deferred_intents import work_order_on
        if not (work_order_on() and self.case_dir):
            return
        try:
            from core.execution_log import log
            from core import work_order as W
            self._derive_work_items(turn)
            W.moot_items(log, str(self.case_dir))
            # Movement is a change of an item's state, by whatever path it
            # came (a call closing it, a question closing and making it moot,
            # a director dismissal): the states now against last turn's.
            states = {i["call_id"]: i.get("status") for i in log.work_items()}
            before = getattr(self, "_wo_states", None) or {}
            moved = set(getattr(self, "_wo_moved", None) or ()) | {
                cid for cid, st in before.items() if st in ("due", "proposed") and states.get(cid) != st}
            self._wo_states = states
            self._wo_moved = set()
            # The streak lives on the loop and restarts at 0 in a resumed
            # session: at most REPORT_STALL_TURNS more turns before neglect,
            # while the items' own presented/unattended counts persist.
            shown_last = list(getattr(self, "_wo_shown", None) or [])
            if shown_last:
                if moved & set(shown_last):
                    self._wo_streak = 0
                    self._wo_neglected = False
                else:
                    self._wo_streak = getattr(self, "_wo_streak", 0) + 1
                W.mark_presented(log, shown_last, moved)
            if (not getattr(self, "_wo_neglected", False)
                    and getattr(self, "_wo_streak", 0) >= REPORT_STALL_TURNS):
                self._wo_neglected = True
                self._log({"event": "work_order_neglected", "turn": turn,
                           "streak": self._wo_streak, "shown": shown_last})
                self._director_event(turn, "neglected")
            headers = self._work_order_headers(turn)
            text, shown = W.work_order_block(log, self.case_dir, self._tool_params,
                                             header_lines=headers)
            had_due = bool(getattr(self, "_wo_had_due", False))
            self._wo_had_due = bool(shown)
            if had_due and not shown and getattr(self, "_wo_plan_done", False):
                self._director_event(turn, "due_set_empty")
            self._wo_shown = shown
            xo_text, xo_readers = self._extracted_open_block(turn)
            tools = ([i.get("priority_tool") or i.get("tool") for i in log.work_items(statuses=("due",))
                      if i.get("call_id") in shown] if text else []) + xo_readers
            if tools:
                # One load for the turn: the due items' tools and the readers
                # the class block names, so the one's room is never made from
                # the other's namespaces.
                self._load_namespaces_for([t for t in tools if t], turn=turn)
            if text:
                self._nudge("work_order", text)
            else:
                self._retire_nudge("work_order")
        except Exception as e:  # noqa: BLE001
            self._log({"event": "work_order_turn_failed", "turn": turn, "error": str(e)[:200]})
        self._extracted_open_turn(turn)

    def _extracted_open_block(self, turn: int) -> tuple[str, list[str]]:
        """(block, the readers it names) of the extracted file classes no call
        has read and a read is offered on (offered_open), from the first finish
        deferral on; ("", []) before it or when none is left. Computed from the
        trace each turn (extracted_outputs), never stored; recomputed only when
        the trace changed (its length or last call id), since a read or a new
        output is a call. A background job whose outcome lands without a new
        entry shows one turn late. Fail-open."""
        if not self._closing_stage():
            return "", []
        try:
            from core.execution_log import log
            from core import work_order as W
            classes = self._open_classes_cached()
            mark = (len(log._entries), log._entries[-1].get("call_id") if log._entries else None,
                    getattr(self, "_oc_cache", (None,))[0])
            cached = getattr(self, "_xo_cache", None)
            if cached is None or cached[0] != mark:
                from core.coverage_ledger import extracted_outputs, offered_open
                outs = offered_open(extracted_outputs(self.case_dir, readers=True)) \
                    if getattr(self, "_finish_named_at", None) is not None else []
                readers = list(dict.fromkeys(
                    str(name) for o in outs for pairs in (o.get("readers") or {}).values() for name, _m in pairs))
                if classes:
                    # The leave tool and the readers the class block names
                    # load together, so the call it asks for can arrive.
                    readers += ["coverage.set_evidence_disposition", "coverage.ledger_status"]
                    readers += [r for g in classes for r in g.get("readers") or []]
                cached = self._xo_cache = (mark, "\n".join(W.open_work_lines({"parts": [], "derived": outs,
                                                                               "due": [], "classes": classes})),
                                           list(dict.fromkeys(readers)))
            return cached[1], list(cached[2])
        except Exception as e:  # noqa: BLE001
            self._log({"event": "extracted_open_turn_failed", "turn": turn, "error": str(e)[:200]})
            return "", []

    def _extracted_open_turn(self, turn: int) -> None:
        """The class block (_extracted_open_block) shown each turn after the
        due items (the planned reads come first), superseding the standing
        copy; retired once none is left. A class named once at the deferral
        fades as the conversation grows, and only the last block of a turn
        reliably steers a small model."""
        text, _readers = self._extracted_open_block(turn)
        if text:
            self._nudge("extracted_open", text)
        elif self._closing_stage():
            self._retire_nudge("extracted_open")

    def _stall_work_order(self) -> tuple[bool, list[str]] | None:
        """(settled, due ready calls) for the stall ladder, None when the
        work order is off."""
        from core.deferred_intents import work_order_on
        if not work_order_on() or not self.case_dir:
            return None
        try:
            from core.execution_log import log
            from core.work_order import counted_due, ready_call
            due = counted_due(log, self.case_dir)
            return (self.work_order_settled(),
                    [ready_call(i, self._tool_params(i.get("tool") or "")) for i in due[:6]])
        except Exception:  # noqa: BLE001
            return None

    def _derive_work_items(self, turn: int) -> None:
        """Item sources read from the run's state each turn: the plan once
        the inventory gate holds (and a re-plan for a question whose items
        all closed without a claim), the sources behind a question's claims
        when its links change, absence contradictions, and every few turns
        the proposals (index artefacts, series read in part). A question
        leaving or re-entering the actionable set asks the director for a
        review. Each source fails open on its own."""
        from core.deferred_intents import work_order_plan_on
        from core.execution_log import log
        from core import question_plan as Q
        case = str(self.case_dir)
        try:
            from core.investigation_tasks import ACTIONABLE_STATUSES, load_tasks
            tasks = [t for t in load_tasks(case).get("tasks") or [] if isinstance(t, dict) and t.get("id")]
        except Exception:  # noqa: BLE001
            tasks = []
        status_sig = {str(t["id"]): str(t.get("status") or "") in ACTIONABLE_STATUSES for t in tasks}
        prev_sig = getattr(self, "_wo_task_sig", None)
        self._wo_task_sig = status_sig
        if prev_sig is not None and any(prev_sig.get(k) != v for k, v in status_sig.items() if k in prev_sig):
            self._director_event(turn, "question_closed_or_reopened")
        if work_order_plan_on():
            try:
                self._plan_questions(turn, case, tasks)
            except Exception as e:  # noqa: BLE001
                self._log({"event": "work_order_plan_failed", "turn": turn, "error": str(e)[:200]})
        self._triage_evidence(turn, case)
        self._claim_source_items(turn, case, tasks)
        try:
            # The incident map syncs once per turn; its signals (a specific
            # join) become items with the change kind as origin.
            from core.incident_map import feed_work_items
            self._map_cursor = feed_work_items(log, case, getattr(self, "_map_cursor", 0))
        except Exception as e:  # noqa: BLE001
            self._log({"event": "work_order_map_failed", "turn": turn, "error": str(e)[:200]})
        if turn % IOC_PIVOT_NUDGE_EVERY == 0:
            try:
                Q.proposal_items(log, case)
            except Exception as e:  # noqa: BLE001
                self._log({"event": "work_order_proposals_failed", "turn": turn, "error": str(e)[:200]})

    def _claim_source_items(self, turn: int, case: str, tasks: list[dict]) -> None:
        """The sources behind a question's claims when its links change, and
        the absence contradictions; each fails open. Both loops call it."""
        from core.deferred_intents import work_order_sources_on
        from core.execution_log import log
        from core import question_plan as Q
        if work_order_sources_on():
            try:
                links = {str(t["id"]): sorted(set(t.get("related_claim_ids") or [])
                                              | {c for p in t.get("parts") or [] if isinstance(p, dict)
                                                 for c in p.get("claim_ids") or []}) for t in tasks}
                seen = getattr(self, "_wo_links", {})
                for t in tasks:
                    if links[str(t["id"])] and links[str(t["id"])] != seen.get(str(t["id"])):
                        Q.source_items_for_question(log, case, t)
                self._wo_links = links
            except Exception as e:  # noqa: BLE001
                self._log({"event": "work_order_sources_failed", "turn": turn, "error": str(e)[:200]})
        try:
            Q.absence_items(log, case)
        except Exception as e:  # noqa: BLE001
            self._log({"event": "work_order_absence_failed", "turn": turn, "error": str(e)[:200]})

    def _plan_questions(self, turn: int, case: str, tasks: list[dict]) -> None:
        """The per-question plan, once the inventory gate first holds: one
        reason-role call per open question not planned in this trace (four
        at a time), outside the analyst's conversation; and a re-plan of a
        question whose items all closed while it has no linked claim. A
        re-plan that adds nothing marks the question exhausted."""
        from concurrent.futures import ThreadPoolExecutor
        from core.execution_log import log
        from core.investigation_tasks import ACTIONABLE_STATUSES
        from core import question_plan as Q
        if not getattr(self, "_wo_plan_done", False):
            from core.evidence_inventory_gate import inventory_satisfied
            if not inventory_satisfied(case):
                return
            done = Q.planned_task_ids(log)
            todo = [t for t in tasks if str(t.get("status") or "") in ACTIONABLE_STATUSES
                    and str(t["id"]) not in done]
            tools = Q.reading_tools()
            started = time.monotonic()
            from core.frontier_queue import beside_workers
            with ThreadPoolExecutor(max_workers=beside_workers()) as pool:
                results = list(pool.map(lambda t: (t, Q.plan_question(log, case, t, tools)), todo))
            for t, r in results:
                self._note_plan_result(turn, t, r)
                if r["empty"]:
                    self._log({"event": "work_order_plan_empty", "turn": turn, "task": t["id"],
                               "reads": r["reads"], "invalid": r["invalid"], "reason": r.get("reason", ""),
                               "refused": list(r.get("refused") or [])[:5]})
                    self.ui.warn(f"no read plan for {t['id']}: {r.get('reason') or 'no valid read'}")
            self._wo_plan_done = True
            self._log({"event": "work_order_planned", "turn": turn, "questions": len(todo),
                       "items": sum(len(r["items"]) for _t, r in results),
                       "seconds": round(time.monotonic() - started, 1)})
            return
        exhausted = getattr(self, "_wo_exhausted", None)
        if exhausted is None:
            exhausted = self._wo_exhausted = set()
        for t in tasks:
            tid = str(t["id"])
            if tid in exhausted or str(t.get("status") or "") not in ACTIONABLE_STATUSES:
                continue
            mine = [i for i in log.work_items(task_id=tid) if i.get("origin") == "plan"]
            linked = bool(t.get("related_claim_ids")) or any(
                p.get("claim_ids") for p in t.get("parts") or [] if isinstance(p, dict))
            if not mine or linked or any(i.get("status") in ("due", "proposed") for i in mine):
                continue
            before = {i["call_id"] for i in log.work_items()}
            closed = "\n".join(f"- {i.get('tool')} {i.get('args_summary')}: {i.get('status')}"
                               + (f" ({i.get('outcome')[:80]})" if i.get("outcome") else "") for i in mine)
            r = Q.plan_question(log, case, t, extra="READS ALREADY DONE OR FAILED (plan others):\n" + closed)
            self._note_plan_result(turn, t, r)
            # Only a new item still open after creation is a new read: a
            # re-planned read of a target already read is created closed.
            if not any(i["call_id"] not in before and i.get("status") in ("due", "proposed")
                       for i in r["items"]):
                exhausted.add(tid)
                self._log({"event": "work_order_plan_exhausted", "turn": turn, "task": tid})
                self._director_event(turn, "plan_exhausted")

    def _triage_evidence(self, turn: int, case: str) -> None:
        """Evidence disposition (ATLAS_EVIDENCE_DISPOSITION): once the
        inventory holds, every pending item not triaged in this trace gets
        its triage call; each turn the triage items and dispositions are
        brought together. Fail-open."""
        try:
            from core.evidence_disposition import disposition_on
            if not disposition_on():
                return
            from core.evidence_inventory_gate import inventory_satisfied
            if not inventory_satisfied(case):
                return
            from core.execution_log import log
            from core.evidence_triage import sync_triage, triage_pending
            def _started(n: int) -> None:
                # The calls run inside this turn, four at a time: say so.
                self.ui.info(f"triaging {n} evidence item(s): one short focused call each")
                self._log({"event": "evidence_triage_started", "turn": turn, "items": n})
            done = triage_pending(log, case, on_start=_started, agent=self)
            if done:
                self._log({"event": "evidence_triaged", "turn": turn, "items": len(done),
                           "left": sum(len(d["left"]) for d in done),
                           "refused": sum(len(d["refused"]) for d in done),
                           "work_items": sum(len(d["items"]) for d in done)})
            changed = sync_triage(log, case)
            if changed:
                self._log({"event": "evidence_triage_synced", "turn": turn, "items": changed})
            from core.evidence_leave import reopen_left
            reopened = reopen_left(log, case)           # one batch per turn
            if reopened:
                self._log({"event": "evidence_reopened", "turn": turn, "units": reopened})
        except Exception as e:  # noqa: BLE001
            self._log({"event": "evidence_triage_failed", "turn": turn, "error": str(e)[:200]})

    def _note_plan_result(self, turn: int, task: dict, r: dict) -> None:
        """What a plan call leaves behind: the LOCATE outcome in the log."""
        loc = r.get("locate") or {}
        if loc.get("empty"):
            self._log({"event": "work_order_locate_empty", "turn": turn, "task": task["id"],
                       "dropped": loc.get("dropped"), "error": loc.get("error", "")})

    def _work_order_headers(self, turn: int) -> list[str]:
        """Lines at the head of the work-order block: the director's last
        loop-made review, the progress line and the estate counts."""
        lines: list[str] = []
        note = getattr(self, "_wo_director_line", "")
        if note:
            lines.append(note)
            self._wo_director_line = ""
        from core.deferred_intents import dair_no_defer_on
        progress = self._progress_line(turn) if dair_no_defer_on() else ""
        if progress:
            lines.append(progress)
            self._at_progress_line(turn)
        counts = getattr(self, "_wo_count_lines", None)
        if counts:
            lines += counts
            self._wo_count_lines = []
        pending = self._estate_pending()
        if pending:
            lines.append(pending)
        if not self._closing_stage():
            try:
                from core import work_order as W
                count = W.class_count_line({"classes": self._open_classes_cached()}, str(self.case_dir))
            except Exception:  # noqa: BLE001
                count = ""
            if count:
                lines.append(count)
        return lines

    def _at_progress_line(self, turn: int) -> None:
        """What runs with each progress line: the sources behind every
        question's claims again, and the estate count of indicators found
        since the last line (filled in by the count)."""
        from core.deferred_intents import work_order_sources_on
        if work_order_sources_on():
            self._wo_links = {}          # re-derive every question's sources once
        self._count_new_indicators(turn)

    def _count_new_indicators(self, turn: int) -> None:
        """With each progress line: the indicators the findings attribute
        that no count has covered yet, over every table, in one pass."""
        from core.deferred_intents import estate_count_on
        if not (estate_count_on() and getattr(self, "_estate_intake_done", False)):
            return
        try:
            from core.ioc_pivots import _is_pivotable, indicators_from_beliefs
            counted = getattr(self, "_estate_counted", set())
            new = [i for i in indicators_from_beliefs(str(self.case_dir)) if _is_pivotable(i) and i not in counted]
            if new:
                self._estate_count(turn, new, self._estate_tables(), why="new indicators")
        except Exception as e:  # noqa: BLE001
            self._log({"event": "estate_count_failed", "turn": turn, "error": str(e)[:200]})

    def _estate_tables(self) -> list[str]:
        from core.ioc_pivots import evidence_sources
        from tools.tabular import _kind
        return sorted(rel for rel in evidence_sources(str(self.case_dir)) if _kind(rel) in ("csv", "jsonl", "xlsx"))

    def _estate_count_turn(self, turn: int) -> None:
        """The estate count (ATLAS_ESTATE_COUNT): once the inventory gate
        holds, the known indicators over every table; afterwards one pass
        per turn over the tables that appeared since the last, over the
        known indicators (a parser that writes one table per log leaves
        dozens at once: one pass, one thread, one trace entry for them, not
        one each, which filled the DAIR window and the progress line with
        counts). The lines open the next work-order block (or stand as
        their own message)."""
        from core.deferred_intents import estate_count_on
        if not (estate_count_on() and self.case_dir):
            return
        self._estate_collect(turn)
        try:
            from core.evidence_inventory_gate import inventory_satisfied
            from core.ioc_pivots import load_pivots
            case = str(self.case_dir)
            tables = self._estate_tables()
            known = list((load_pivots(case).get("pivots") or {}).keys())
            if not getattr(self, "_estate_intake_done", False):
                if not inventory_satisfied(case):
                    return
                self._estate_intake_done = True
                self._estate_tables_seen = set(tables)
                if known and tables:
                    self._estate_count(turn, known, tables, why="intake")
                return
            seen = getattr(self, "_estate_tables_seen", set())
            new = [t for t in tables if t not in seen]
            seen.update(new)
            self._estate_tables_seen = seen
            if known and new:
                self._estate_count(turn, known, new, why="new tables", new_tables=new)
        except Exception as e:  # noqa: BLE001
            self._log({"event": "estate_count_failed", "turn": turn, "error": str(e)[:200]})

    def _estate_count(self, turn: int, indicators: list[str], tables: list[str], *, why: str,
                      new_tables: list[str] | None = None) -> None:
        """One count pass. With ATLAS_ESTATE_COUNT_ASYNC the pass reads the
        tables in a thread of its own and the analyst's turns go on; the
        main loop applies the result once the pass ends (_estate_collect),
        so the ledger, the trace and the conversation are written by one
        thread only. Without it the pass runs here."""
        from core.deferred_intents import estate_count_async_on
        from tools.tabular import count_indicators
        case = str(self.case_dir)
        counted = getattr(self, "_estate_counted", set())
        counted.update(indicators)
        self._estate_counted = counted
        if not estate_count_async_on():
            self._estate_apply(turn, indicators, tables, why, new_tables, count_indicators(case, indicators, tables))
            return
        import threading
        job: dict = {"indicators": list(indicators), "tables": list(tables), "why": why, "new_tables": new_tables,
                     "res": None, "error": ""}

        def work() -> None:
            try:
                job["res"] = count_indicators(case, job["indicators"], job["tables"])
            except Exception as e:  # noqa: BLE001 - reported by _estate_collect
                job["error"] = f"{type(e).__name__}: {e}"[:200]
        job["thread"] = threading.Thread(target=work, name="atlas-estate-count", daemon=True)
        self._estate_jobs = [*getattr(self, "_estate_jobs", []), job]
        job["thread"].start()
        self._log({"event": "estate_count_started", "turn": turn, "why": why, "indicators": len(indicators),
                   "tables": len(tables)})
        from core.deferred_intents import work_order_on
        if not work_order_on():
            self._nudge("estate_counts", self._estate_pending())

    def _estate_pending(self) -> str:
        """The line that stands for passes still reading their tables."""
        running = [j for j in getattr(self, "_estate_jobs", []) if j["thread"].is_alive()]
        if not running:
            return ""
        tables = len({t for j in running for t in j["tables"]})
        iocs = len({i for j in running for i in j["indicators"]})
        return (f"[estate counts] counting {tables} tables for {iocs} indicators; "
                "the counts follow when the pass ends")

    def _estate_join(self, turn: int) -> None:
        """Wait for every count pass still reading and apply it: before the
        report is checked or written and when the run ends. The wait is
        bounded by the tables' size, as the pass is."""
        for job in list(getattr(self, "_estate_jobs", [])):
            job["thread"].join()
        self._estate_collect(turn)

    def _estate_collect(self, turn: int) -> None:
        """Apply every finished pass (main thread): its counts, trace entry
        and lines; a failed pass is logged and its indicators count again
        with the next pass."""
        jobs = getattr(self, "_estate_jobs", [])
        if not jobs:
            return
        keep = []
        for job in jobs:
            if job["thread"].is_alive():
                keep.append(job)
                continue
            if job["res"] is None:
                self._estate_counted = getattr(self, "_estate_counted", set()) - set(job["indicators"])
                self._log({"event": "estate_count_failed", "turn": turn, "error": job["error"]})
                try:
                    from core.execution_log import log
                    log.record_tool_call("<py>:coverage_count_indicators", False, False, 0, 1,
                                         stderr=f"estate count over {len(job['tables'])} tables failed: "
                                                + job["error"])
                except Exception:  # noqa: BLE001 - the loop log holds it
                    pass
                continue
            self._estate_apply(turn, job["indicators"], job["tables"], job["why"], job["new_tables"], job["res"])
        self._estate_jobs = keep

    def _estate_apply(self, turn: int, indicators: list[str], tables: list[str], why: str,
                      new_tables: list[str] | None, res: dict) -> None:
        """A finished pass: the counts go to the pivot ledger and into a
        trace entry marked ``kind: "count"`` (numbers, never rows: no
        sighting, cited like a listing), the lines to the next block."""
        from core.deferred_intents import work_order_on
        from core.execution_log import log
        from core.ioc_pivots import count_lines, record_counts
        case = str(self.case_dir)
        record_counts(case, res["counts"])
        summary = {i: {s: c.get("full") or c.get("name") for s, c in per.items()} for i, per in res["counts"].items()}
        cid = log.record_tool_call("<py>:coverage_count_indicators", True, False, 0, 0,
                                   stdout_excerpt=json.dumps({"why": why, "tables": len(tables),
                                                              "counts": summary}, default=str)[:4000])
        log.annotate_tool_call(cid, kind="count")
        lines = count_lines(case, res["counts"], sources=tables, new_tables=new_tables)
        self._log({"event": "estate_count", "turn": turn, "why": why, "indicators": len(indicators),
                   "tables": len(tables), "errors": len(res["errors"])})
        if not lines:
            if not work_order_on() and not self._estate_pending():
                self._retire_nudge("estate_counts")       # the "counting" line is stale
            return
        if work_order_on():
            self._wo_count_lines = (getattr(self, "_wo_count_lines", None) or []) + lines
        else:
            self._nudge("estate_counts", "\n".join(lines))

    def _progress_line(self, turn: int) -> str:
        """Every DAIR_WINDOW actions, on its own counter (the actions since
        the last line's mark): reads of new sources and how many failed, the
        findings, the other calls, and where the questions stand."""
        try:
            from core.execution_log import log
            from core.middleware import DAIR_WINDOW
            acts = [e for e in log._entries if e.get("type") in log.ACTION_TYPES]
            mark = int(getattr(self, "_progress_mark", 0) or 0)
            from core.execution_log import action_key
            window = [e for e in acts if int(e.get("call_id") or 0) > mark]
            if len({action_key(e) for e in window}) < DAIR_WINDOW:
                return ""
            self._progress_mark = int(window[-1].get("call_id") or 0)
            from core.coverage_ledger import _entry_tool, _failed_attempt, reads_content, resolved_entry
            earlier: set[str] = set()
            for e in acts:
                if int(e.get("call_id") or 0) <= mark and e.get("type") == "tool_call":
                    earlier.add(str(e.get("args") or e.get("cmd") or ""))
            # Each call as the read rule sees it: a background job's start by
            # the job's outcome (nothing while it runs), no analyst tool no read.
            jobs: dict = {}
            reads = [r for r in (resolved_entry(self.case_dir, e, jobs) for e in window
                                 if e.get("type") == "tool_call")
                     if r is not None and reads_content(_entry_tool(r))
                     and str(r.get("args") or r.get("cmd") or "") not in earlier]
            failed = sum(1 for e in reads if _failed_attempt(e))
            findings = [e for e in window if e.get("type") == "finding"]
            other = max(0, len({action_key(e) for e in window}) - len(reads) - len(findings))
            fids = ", ".join(str(e.get("call_id")) for e in findings[:6])
            qs = ""
            try:
                from collections import Counter
                from core.investigation_tasks import load_tasks
                st = Counter(str(t.get("status") or "open") for t in load_tasks(self.case_dir).get("tasks") or []
                             if isinstance(t, dict))
                if st:
                    answered = st.get("answered", 0) + st.get("done", 0)
                    partial = st.get("partial", 0)
                    qs = (f" Questions: {answered} answered, {partial} partial, "
                          f"{sum(st.values()) - answered - partial} other.")
            except Exception:  # noqa: BLE001
                qs = ""
            self._log({"event": "progress_line", "turn": turn, "actions": len(window)})
            n_actions = len({action_key(e) for e in window})
            return (f"[progress] last {n_actions} actions: {len(reads)} reads of new sources ({failed} failed), "
                    f"{len(findings)} findings" + (f" (calls {fids})" if fids else "")
                    + f", {other} other calls.{qs}")
        except Exception:  # noqa: BLE001
            return ""

    def _director_event(self, turn: int, event: str) -> None:
        """A review the loop asks the director for on an event of the order
        (the due set emptied, the order turned neglected, a re-plan came back
        exhausted, a question closed or reopened), in-process like the
        pre-report check. Its result goes through _note_dair_phase, so the
        phase follows the director and its reads become items; the analyst
        reads one line about it. A failed review is logged and skipped.
        The frontier has no director: its synthesis item covers the review."""
        if getattr(self, "_loop_mode", "conversation") == "frontier":
            return
        try:
            from tools.dair import dair_assess
            from core.execution_log import log
            from core import work_order as W
            due = len(W.counted_due(log, str(self.case_dir)))
            summary = (f"[loop review: {event.replace('_', ' ')}] The work order has {due} due reads; "
                       f"{len(log.work_items(statuses=('resolved',)))} read, "
                       f"{len(log.work_items(statuses=('failed',)))} failed, "
                       f"{len(log.work_items(statuses=('proposed',)))} proposed.")
            from core.deferred_intents import director_review_on
            if director_review_on():
                # The analyst's own stated next reads reach the review, so a
                # lead it named is not lost between turns.
                notes = [" ".join(str(m.get("content") or "").split())[:300]
                         for m in reversed(self.messages or []) if m.get("role") == "assistant"
                         and str(m.get("content") or "").strip()][:3]
                if notes:
                    summary += "\nANALYST'S LATEST NOTES (last three replies, trimmed):\n" + "\n".join(
                        f"- {n}" for n in reversed(notes))
            before_phase = getattr(self, "_dair_phase", "")
            before_ids = {i["call_id"] for i in log.work_items()}
            out = dair_assess(summary, phase_stack=None)
            result = json.dumps(out, default=str) if isinstance(out, dict) else str(out)
            self._note_dair_phase(result)
            added = [i for i in log.work_items() if i["call_id"] not in before_ids]
            phase = getattr(self, "_dair_phase", "")
            line = f"[director] phase {phase}" + (f" (was {before_phase})" if before_phase and before_phase != phase
                                                   else "")
            if added:
                qs = sorted({t for i in added for t in i.get("task_ids") or []})
                line += f"; added {len(added)} items" + (f" ({', '.join(qs[:6])})" if qs else "")
            proposed = len(log.work_items(statuses=("proposed",)))
            if proposed:
                line += f"; {proposed} proposed kept"
            untracked = int(getattr(self, "_wo_not_tracked", 0) or 0)
            if untracked:
                line += f"; {untracked} not tracked (no target)"
            self._wo_director_line = line
            self._log({"event": "work_order_director_review", "turn": turn, "trigger": event,
                       "phase": phase, "added": len(added)})
        except Exception as e:  # noqa: BLE001
            self._log({"event": "work_order_director_review_failed", "turn": turn, "trigger": event,
                       "error": str(e)[:200]})

    def _report_stall_exhausted(self, turn: int) -> bool:
        """Has the report-phase push fired REPORT_STALL_WRAPUP_FIRES times
        in a row with no move towards the report in between
        (:meth:`_report_moved`)? Called once per push."""
        if self._report_moved("_report_stall_mark", claims=True):
            self._report_stall_fires = 1
        else:
            self._report_stall_fires = getattr(self, "_report_stall_fires", 0) + 1
        return self._report_stall_fires >= REPORT_STALL_WRAPUP_FIRES

    def _director_reask_exhausted(self, turn: int) -> bool:
        """Has the director re-ask named the work order DIRECTOR_REASK_FIRES
        times in a row with no claim added in between? Called once per
        re-ask outside the Report phase."""
        count = self._claim_count()
        last = getattr(self, "_director_reask_claims", None)
        if last is None or count != last:
            self._director_reask_claims = count
            self._director_reask_fires = 1
        else:
            self._director_reask_fires = getattr(self, "_director_reask_fires", 0) + 1
        return self._director_reask_fires >= DIRECTOR_REASK_FIRES

    def _report_phase_stalled(self, turn: int) -> bool:
        """True once the director has sat in Report for REPORT_STALL_TURNS
        turns without moving towards the report; fires once per stall."""
        if getattr(self, "_dair_phase", "") != "Report" or not self.case_dir:
            return False
        if getattr(self, "_report_synth_calls", 0) >= REPORT_STALL_SYNTHESES:
            self._report_synth_calls = 0                 # re-arm
            return True
        # Progress in Report means moving towards a report: a first read of
        # evidence the gate counts as open, or fewer blocking issues once
        # this run has asked the gate (_report_moved). A belief alone never
        # buys time here: a run recording one now and then could otherwise
        # sit in Report for a whole phase without ever being asked to finish.
        last = getattr(self, "_report_progress_turn", None)
        if self._report_moved("_report_progress_mark", claims=False) or last is None:
            self._report_progress_turn = turn
            return False
        if turn - last < REPORT_STALL_TURNS:
            return False
        self._report_progress_turn = turn              # re-arm after firing
        return True

    def _note_repeated_refusal(self, tc, result: str, turn: int) -> str:
        """A gate refusal of a call the same gate already refused with the
        same arguments, marked as the repeat it is. The memo remembers a
        refusal as it remembers a success (core/call_memo.py); without that
        the identical call passed through each time and met the first
        refusal word for word. Any other result passes through unchanged."""
        memo = getattr(self, "_call_memo", None)
        if memo is None or not ('"success": false' in result[:300]
                                and '"gate"' in result[:600]):
            return result
        try:
            data = json.loads(result)
        except ValueError:
            return result
        gate = str(data.get("gate") or "") if isinstance(data, dict) else ""
        if not gate:
            return result
        seen = memo.refused(memo.key(tc.name or "", tc.arguments or {}),
                            gate, turn=turn)
        if seen.hits < 2:
            return result
        # Gate right after success: the refusal detection reads the head of
        # the result, and the note below lengthens the error text.
        data = {"success": data.get("success", False), "gate": gate, **data}
        data["error"] = (
            f"REPEATED REFUSAL (#{seen.hits}): {tc.name!r} with these exact "
            f"arguments was already refused by the {gate} gate at turn "
            f"{seen.turn}, for the reason below. Sent again unchanged it "
            "cannot pass. Do what the refusal names, then send a changed "
            "call, or drop this one. " + str(data.get("error") or ""))
        data["previous_turn"] = seen.turn
        data["identical_refusals"] = seen.hits
        self.ui.warn(f"{tc.name} refused again by {gate}, unchanged "
                     f"({seen.hits}x)")
        self._log({"event": "identical_refusal", "turn": turn, "tool": tc.name,
                   "gate": gate, "previous_turn": seen.turn, "times": seen.hits})
        return json.dumps(data, indent=2)

    def _result_still_in_context(self, tool_call_id: str) -> bool:
        """Is the tool result with this id still in the conversation with
        its content, or has compaction replaced it with a stub?"""
        from core.llm_check import _TOOL_STUB, _TURN_STUB
        for m in reversed(self.messages):
            if m.get("role") == "tool" and m.get("tool_call_id") == tool_call_id:
                body = m.get("content") or ""
                return bool(body) and body not in (_TOOL_STUB, _TURN_STUB)
        return False

    def _rest_of_result_hint(self, hit, spill: str) -> str:
        """Where the rest of a cut result is, for the replay and pointer
        texts: a table tool's result is narrowed (one term, a filter, a
        period), never searched through its spilled JSON; an executor tool's
        spill is searched; else the call is narrowed."""
        from tools._gates.universal_from_truncated import rest_of_result_hint
        entry = None
        if getattr(hit, "trace_call_id", ""):
            try:
                from core.execution_log import log
                entry = (log.index().by_call_id or {}).get(int(hit.trace_call_id))
            except Exception:  # noqa: BLE001
                entry = None
        cmd = str(entry.get("cmd") or "") if isinstance(entry, dict) else ""
        if not cmd:
            # No trace entry to read (the result carried no call id): the
            # memo's own tool name decides, so a capped table result still
            # names its narrower calls.
            from core.coverage_ledger import listed_tool_name
            name = listed_tool_name(str(getattr(hit, "tool", "") or ""))
            if name.startswith("table_"):
                entry = {"cmd": f"<py>:table_{name}"}
                cmd = entry["cmd"]
        if cmd.startswith("<py>:table_") or (cmd.startswith("<py>:") and "view_rows_shown" in entry):
            return rest_of_result_hint(entry, "", None)
        if spill:
            return (f"The complete output is on disk at {spill}: search it with "
                    "strings.strings_grep or search.search_evidence for what you need, "
                    "or narrow the call so the whole answer fits.")
        return ("Ask search.search_evidence for the detail you need, or narrow the call "
                "(a subdirectory or inode, no recursion, a pattern or a column) so the "
                "whole answer fits.")

    def _pointed_result_incomplete(self, hit) -> tuple[str, str]:
        """Why the result an identical call is pointed at was not a complete
        view, and where its complete output is; ``("", "")`` when the model
        saw all of it. Pointing at a cut view sends the model back to a part
        it has already read and found wanting - the repeat is how it asks
        for the rest - so the honest answer names the cut and the file.
        """
        from tools._gates.universal_from_truncated import incomplete_reason
        entry = None
        if getattr(hit, "trace_call_id", ""):
            try:
                from core.execution_log import log
                entry = (log.index().by_call_id or {}).get(int(hit.trace_call_id))
            except Exception:  # noqa: BLE001
                entry = None
        if not isinstance(entry, dict):
            # The memoised result carries the tool's own flags.
            try:
                data = json.loads(hit.result or "")
            except (TypeError, ValueError):
                data = None
            if not isinstance(data, dict):
                return "", ""
            entry = {"truncated": bool(data.get("truncated")),
                     "view_truncated": bool(data.get("view_truncated")),
                     "stdout": hit.result,
                     "stdout_file": str(data.get("stdout_file") or "")}
        why = incomplete_reason(entry)
        return (why, str(entry.get("stdout_file") or "")) if why else ("", "")

    @contextlib.contextmanager
    def _status_heartbeat(self):
        """Re-stamp the live status every few seconds while a call runs.

        A long tool (an image export runs a quarter of an hour) or a model
        request the endpoint holds open left run_status.json untouched for
        its whole duration, so the dashboard could not tell "still busy"
        from "hung". The stamp is the only sign of life a reader outside the
        process gets while the call is in flight.
        """
        stop = threading.Event()

        def _beat() -> None:
            while not stop.wait(HEARTBEAT_SECONDS):
                self._persist_live_status()
        worker = threading.Thread(target=_beat, name="atlas-status-heartbeat",
                                  daemon=True)
        worker.start()
        try:
            yield
        finally:
            stop.set()

    def _chat_turn_asked_again(self, turn: int):
        """``_chat_turn``, asked again when the provider's transport failed.

        With ATLAS_MODEL_CALL_ESCAPE on this is the escape (_escape_turn);
        off, the earlier rule: a pause and the same request, and after
        LOST_TURN_RETRIES losses the error goes to the run loop. A failed
        call appended nothing to the history and ran no tool."""
        from agent.llm import model_call_escape_on
        if model_call_escape_on():
            return self._escape_turn(turn)
        lost = 0
        while True:
            try:
                return self._chat_turn()
            except LLMTransportError as e:
                lost += 1
                if lost > LOST_TURN_RETRIES:
                    raise
                pause = min(LOST_TURN_PAUSE * (2 ** (lost - 1)), LOST_TURN_PAUSE_MAX)
                self._log({"event": "llm_turn_lost", "turn": turn, "attempt": lost,
                           "pause_seconds": pause, "error": str(e)[:500]})
                self.ui.warn(f"model call lost ({e}); asking again in {pause:.0f}s")
                time.sleep(pause)

    # ── the escape (ATLAS_MODEL_CALL_ESCAPE) ───────────────────────────────

    def _answered_in_run(self) -> bool:
        """The analyst has answered in this run: in this process, or (a
        resumed run) an earlier process's run transcript under analysis/
        holds an assistant event. The execution trace is not the record:
        intake writes tool calls there before the first reply. Read once."""
        if getattr(self, "_answered_in_process", False):
            return True
        cached = getattr(self, "_answered_before", None)
        if cached is not None:
            return cached
        found = False
        try:
            from core.run_state import TRANSCRIPT_PREFIX
            analysis = (self.case_dir / "analysis") if self.case_dir else None
            mine = getattr(self, "transcript_path", None)
            for path in sorted(analysis.glob(f"{TRANSCRIPT_PREFIX}*.jsonl")) if analysis else []:
                if mine is not None and path == mine:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    if any('"event": "assistant"' in line for line in fh):
                        found = True
                        break
        except Exception:  # noqa: BLE001 - no record reads as no answer
            found = False
        self._answered_before = found
        return found

    def _escape_turn(self, turn: int):
        """The analyst's escape from a lost model call.

        A reply the provider or the connection cut is a failed reply, never
        the model's words and never a reason to end the analysis once the
        model has answered in this run. Each loss moves to the next rung:
        0 the same request (only after a fast loss, once), 1 one thinking
        level lower, 2 a progress ask without the tool list, 3 the same ask
        over a shortened copy of the history (repeated). A pause doubling
        from LOST_TURN_PAUSE to LOST_TURN_PAUSE_MAX comes before each
        request after a loss; every request is learn=False. A summary reply
        after rung 2 or 3 is followed by one request with the tool list
        back asking for the next step as one call. The escape never gives up
        on its own; it raises only before the run's first answer (after two
        paused identical re-asks) and past the operator's wall clock."""
        choice0 = getattr(self, "_tool_choice_next", None)
        lost = 0
        rung = -1
        first_loss = None
        stepped = False
        level_now = None
        fallback_tried = False
        following = False
        alerted = False
        while True:
            try:
                resp = self._chat_turn()
            except LLMStatusError as e:
                tool_less = bool((getattr(self, "_escape_kw", None) or {}).get("_no_tools"))
                if rung >= 2 and tool_less and e.status == 400 and not fallback_tried:
                    # An endpoint that refuses a history with tool calls and
                    # no tool definitions: the same ask with the tool list
                    # and tool_choice "none".
                    fallback_tried = True
                    self._escape_kw = {**self._escape_request(rung, level_now, None), "tool_choice": "none"}
                    self._escape_kw.pop("_no_tools", None)
                    continue
                self._escape_clear()
                raise
            except (LLMTransportError, LLMDeadlineError) as e:
                lost += 1
                first_loss = first_loss or time.monotonic()
                deadline = isinstance(e, LLMDeadlineError)
                runaway = deadline or bool(getattr(e, "runaway", False))
                long = deadline or bool(getattr(e, "long", False))
                if not self._answered_in_run():
                    # A provider that never answered this run is a
                    # configuration problem: two paused identical re-asks
                    # (a blip after a long intake), then a clean stop.
                    if lost > LOST_TURN_RETRIES:
                        self._escape_clear()
                        raise
                    pause = min(LOST_TURN_PAUSE * (2 ** (lost - 1)), LOST_TURN_PAUSE_MAX)
                    self._log({"event": "llm_turn_lost", "turn": turn, "attempt": lost,
                               "kind": getattr(e, "kind", "deadline" if deadline else ""),
                               "pause_seconds": pause, "next": "unchanged", "error": str(e)[:500]})
                    self.ui.warn(f"model call lost before the first reply of this run ({e}); "
                                 f"asking again in {pause:.0f}s")
                    with self._status_heartbeat():
                        time.sleep(pause)
                    continue
                if getattr(self.client, "ladder_events", None) and any(
                        ev.get("cut") == "provider" for ev in self.client.ladder_events
                        if isinstance(ev, dict)):
                    stepped = True       # chat() already stepped down in this turn
                # The next rung.
                if rung < 0 and not long and not runaway:
                    rung = 0
                else:
                    lower = None
                    if rung < 1 and not stepped:
                        nxt = getattr(self.client, "next_lower_level", None)
                        try:
                            lower = nxt(_AGENT_ROLE, level_now) if callable(nxt) else None
                        except Exception:  # noqa: BLE001
                            lower = None
                    if lower:
                        rung, level_now, stepped = 1, lower, True
                    else:
                        rung = min(3, max(2, rung + 1))
                pause = min(LOST_TURN_PAUSE * (2 ** (lost - 1)), LOST_TURN_PAUSE_MAX)
                nxt_name = ("unchanged", "level", "progress_ask", "shortened")[rung]
                attempts = list(getattr(e, "attempts", None) or [])
                last = attempts[-1] if attempts else {}
                self._log({"event": "llm_turn_lost", "turn": turn, "attempt": lost,
                           "kind": getattr(e, "kind", "") or ("deadline" if deadline else ""),
                           "runaway": runaway, "long": long, "elapsed_s": last.get("seconds"),
                           "chars": last.get("chars"), "keepalives": last.get("keepalives"),
                           "provider_error": last.get("error") if last.get("kind") == "cut" else "",
                           "attempts": attempts, "ladder": list(getattr(self.client, "ladder_events", None) or []),
                           "pause_seconds": pause, "next": nxt_name, "level": level_now,
                           "error": str(e)[:500]})
                when = (datetime.now() + timedelta(seconds=pause)).strftime("%H:%M:%S")
                how = {"unchanged": "unchanged", "level": f"one thinking level lower ({level_now})",
                       "progress_ask": "asking for the progress so far",
                       "shortened": "asking for the progress over a shortened history"}[nxt_name]
                cause = (f"the provider ended the stream after {last.get('seconds')} s, "
                         f"{last.get('chars') or 0} characters arrived" if last.get("kind") == "cut"
                         else "the reply took the whole turn budget" if deadline else str(e)[:160])
                self.ui.warn(f"model call lost (turn {turn}, {lost}x): {cause}; asking again at {when}, {how}")
                activity = f"model call lost {lost}x, asking again at {when} {how}"
                escape_seconds = time.monotonic() - first_loss
                alert_after = _escape_alert_seconds()
                if alert_after > 0 and escape_seconds > alert_after:
                    activity = "ALERT " + activity
                    self.ui.set_run_state(escape_alert=True)
                    if not alerted:
                        alerted = True
                        self.ui.warn(f"model calls have been failing for {escape_seconds / 60:.0f} min "
                                     f"(ATLAS_ESCAPE_ALERT_SECONDS={alert_after:.0f})")
                self.ui.set_run_state(activity=activity)
                self._persist_live_status()
                run_start = getattr(self, "_run_start", None)
                if (MAX_WALL_SECONDS > 0 and run_start is not None
                        and time.monotonic() - run_start > MAX_WALL_SECONDS + WALL_GRACE_SECONDS):
                    self._escape_stop = "wall_clock"
                    self._escape_clear()
                    raise
                with self._status_heartbeat():
                    time.sleep(pause)
                self._escape_kw = self._escape_request(rung, level_now, choice0, losses=lost)
                following = False
                fallback_tried = False
                continue
            # A reply (a provider's decline is no progress summary).
            if (rung >= 2 and not following and not resp.tool_calls
                    and getattr(resp, "refusal", None) is None):
                # The progress summary: logged as the model's own words (an
                # empty one is not), then one request with the tool list back
                # for the next step as one call.
                if (resp.content or "").strip():
                    self._log({"event": "assistant", "turn": turn, "escape": "progress_summary",
                               "content": resp.content, "tool_calls": []})
                self._nudge("model_call_escape_next", self._escape_follow_up())
                self._escape_messages = None
                self._escape_kw = {"tool_choice": "required", "learn": False,
                                   **({"level": level_now} if level_now else {})}
                following = True
                continue
            self._last_reply_escape = "follow_up" if following else ""
            if lost:
                self._log({"event": "llm_turn_recovered", "turn": turn, "losses": lost,
                           "seconds": round(time.monotonic() - (first_loss or time.monotonic()), 1),
                           "answered_with": ("unchanged", "level", "progress_ask", "shortened")[max(rung, 0)]
                           + ("+follow_up" if following else "")})
                waited = time.monotonic() - (first_loss or time.monotonic())
                self.ui.warn(f"model call answered after {lost} lost request{'s' if lost != 1 else ''} "
                             f"(turn {turn}, {int(waited // 60)} min {int(waited % 60)} s)")
                self.ui.set_run_state(escape_alert=False)
            self._escape_clear()
            return resp

    def _escape_request(self, rung: int, level, choice0, *, losses: int = 0) -> dict:
        """What the escape's next request carries (the keywords
        _chat_waf_tolerant passes), and for rungs 2 and 3 the progress ask
        appended (rung 3 also the shortened copy of the history)."""
        kw: dict = {"learn": False}
        if level:
            kw["level"] = level
        self._escape_messages = None
        if rung == 0:
            if choice0:
                self._tool_choice_next = choice0     # the rescue's ask survives a resend
            return kw
        if rung == 1:
            return kw
        if losses:
            self._nudge("model_call_escape", _ESCAPE_ASK.format(n=losses))
        kw["_no_tools"] = True
        if rung >= 3:
            import copy
            from core.llm_check import compact_aged_messages
            shortened = copy.deepcopy(self.messages)
            compact_aged_messages(shortened, keep_tool_results=0, keep_turn_text=2, batch=1,
                                  keep_tool_turns=1, batch_turns=1)
            self._name_trimmed_sources(shortened)
            if shortened and shortened[-1].get("role") == "user":
                shortened[-1] = {**shortened[-1], "content": str(shortened[-1].get("content") or "")
                                 + " The conversation above was shortened for this request."}
            self._escape_messages = shortened
        return kw

    def _name_trimmed_sources(self, shortened: list[dict]) -> None:
        """Every tool result the shortened copy trimmed keeps one line of
        its source (the trace call id, the tool and its target), so the
        progress answer can cite what it read. Aligned with the history the
        copy was made from."""
        from core.call_memo import trace_call_id_of
        from core.deferred_intents import args_summary
        from core.llm_check import _TOOL_STUB
        calls: dict[str, tuple[str, dict]] = {}
        for m in self.messages:
            for tc in (m.get("tool_calls") or []) if m.get("role") == "assistant" else []:
                fn = tc.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except (TypeError, ValueError):
                    args = {}
                calls[tc.get("id")] = (str(fn.get("name") or ""), args if isinstance(args, dict) else {})
        for i, m in enumerate(shortened):
            if m.get("role") != "tool" or m.get("content") != _TOOL_STUB:
                continue
            original = str(self.messages[i].get("content") or "") if i < len(self.messages) else ""
            cid = trace_call_id_of(original) if original != _TOOL_STUB else ""
            name, args = calls.get(m.get("tool_call_id"), ("", {}))
            target = ", ".join(f"{k}={v}" for k, v in args_summary(args, limit=2, value_chars=80).items())
            m["content"] = (f"[trimmed: {name or 'a tool'}"
                            + (f"({target})" if target else "")
                            + (f", call {cid}" if cid else "") + "; full output in the execution trace]")

    def _escape_clear(self) -> None:
        """The escape's request shaping off, its two messages retired."""
        self._escape_kw = None
        self._escape_messages = None
        self._retire_nudge("model_call_escape")
        self._retire_nudge("model_call_escape_next")

    def _chat_turn(self):
        """One model call with spinner, appending the assistant message."""
        with self.ui.thinking(), self._status_heartbeat():
            resp = self._chat_waf_tolerant()
            refusal = getattr(resp, "refusal", None)
            if refusal is not None:
                # The provider declined (a safety classifier, a content
                # filter): the turn ends here, with no retry of the same
                # request; the trace and the token ledger say so. The caller
                # says what happened next; no assistant turn is kept, since
                # the provider dropped what the model wrote.
                self._log({"event": "model_refusal", "category": refusal.get("category"),
                           "explanation": refusal.get("explanation")})
                self.ui.warn("the model declined this turn"
                             + (f" ({refusal['category']})" if refusal.get("category") else "")
                             + (f": {refusal['explanation']}" if refusal.get("explanation") else ""))
            elif _empty_reply(resp):
                if (self._tried_to_call(resp)
                        and int(getattr(resp, "reasoning_tokens", 0) or 0) > 0):
                    # A counted thinking pass and tokens after it that reached
                    # nobody: a call the endpoint dropped. The same request
                    # gets the same drop, so the retry is left to the loop,
                    # which changes something first (the tool list) and asks
                    # for the call by name. A reply with no thinking count
                    # proves nothing about what was generated and still gets
                    # the one identical retry, for the provider that returns
                    # an empty body once.
                    self._log({"event": "empty_reply_swallowed",
                               "output_tokens": int(getattr(resp, "output_tokens", 0) or 0),
                               "reasoning_tokens": int(getattr(resp, "reasoning_tokens", 0) or 0)})
                else:
                    # A reasoning pass that produced no answer: one identical
                    # retry before the turn counts as quiet.
                    self._log({"event": "empty_reply_retry",
                               "output_tokens": int(getattr(resp, "output_tokens", 0) or 0)})
                    resp = self._chat_waf_tolerant()
        for ev in getattr(self.client, "ladder_events", None) or []:
            self._log({"event": "starvation_ladder", **ev})
        # The hidden retries of a call that was answered in the end.
        for ev in getattr(self.client, "transport_events", None) or []:
            if isinstance(ev, dict):
                self._log({"event": "model_attempt_failed", **ev})
        self._answered_in_process = True
        if getattr(resp, "refusal", None) is not None:
            return resp
        assistant_msg: dict = {"role": "assistant",
                               "content": resp.content or ""}
        # Thinking never enters the history, except the provider fields a
        # profile names because the endpoint wants them back on later turns.
        raw = getattr(resp, "raw_message", None) or {}
        for key in getattr(self.client, "echo_fields", ()) or ():
            if raw.get(key) is not None:
                assistant_msg[key] = raw[key]
        if resp.tool_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.name,
                              "arguments": json.dumps(tc.arguments)}}
                for tc in resp.tool_calls
            ]
        if getattr(resp, "responses_items", None):
            assistant_msg["_responses_items"] = list(resp.responses_items)
        self.messages.append(assistant_msg)
        return resp

    def _repair_pending_tool_calls(self) -> None:
        """After an interrupt, satisfy dangling tool_calls with stub results
        so the next request is still a valid OpenAI conversation."""
        if not self.messages:
            return
        last = self.messages[-1]
        if last.get("role") == "assistant" and last.get("tool_calls"):
            answered = {m.get("tool_call_id") for m in self.messages
                        if m.get("role") == "tool"}
            for tc in last["tool_calls"]:
                if tc["id"] not in answered:
                    self.messages.append({"role": "tool",
                                          "tool_call_id": tc["id"],
                                          "content": INTERRUPT_STUB})

    @staticmethod
    def _parse_pseudo_tool_args(name: str, raw: str) -> dict:
        """Best-effort parse of args from a prose/XML pseudo tool call."""
        import ast
        raw = (raw or "").strip()
        if not raw:
            return {}
        try:
            if raw.startswith("{"):
                val = json.loads(raw)
                return val if isinstance(val, dict) else {"value": val}
            if raw.startswith("["):
                val = ast.literal_eval(raw)
                if name == "atlas_load_namespaces":
                    return {"namespaces": list(val)}
                return {"value": list(val)}
            # kwargs, however many: parsed as a call expression so a second
            # argument does not make the remainder invalid Python. The
            # expression is parsed, never executed, and every value goes
            # through literal_eval, so nothing here can run code.
            if "=" in raw:
                try:
                    node = ast.parse("_f(%s)" % raw, mode="eval").body
                except (ValueError, SyntaxError):
                    node = None
                if (isinstance(node, ast.Call) and node.keywords
                        and not node.args
                        and all(kw.arg for kw in node.keywords)):
                    kwargs = {kw.arg: ast.literal_eval(kw.value)
                              for kw in node.keywords}
                    if (name == "atlas_load_namespaces"
                            and len(kwargs) == 1
                            and isinstance(next(iter(kwargs.values())),
                                           (list, tuple))):
                        return {"namespaces": list(next(iter(kwargs.values())))}
                    return kwargs
            val = ast.literal_eval(raw)
            if name == "atlas_load_namespaces" and isinstance(val, (list, tuple)):
                return {"namespaces": list(val)}
            if isinstance(val, dict):
                return val
        except (ValueError, SyntaxError, json.JSONDecodeError, TypeError):
            return {"_malformed_arguments": raw[:500]}
        return {"_malformed_arguments": raw[:500]}

    @staticmethod
    def _parse_xml_pseudo_calls(text: str) -> tuple[list[tuple[str, dict]], str]:
        """Tool calls written as XML (``<tool_call>name<arg_key>k</arg_key>
        <arg_value>v</arg_value>…</tool_call>`` or ``<tool_call><function=name>
        <parameter=k>v</parameter>…``). Returns the calls and the text with
        those blocks removed, so the prose parser does not see them again."""
        calls: list[tuple[str, dict]] = []
        remaining: list[str] = []
        last = 0
        for block in _PSEUDO_XML_BLOCK_RE.finditer(text or ""):
            body = block.group(1)
            fn = _PSEUDO_XML_FUNCTION_RE.search(body)
            if fn:
                name = fn.group(1)
            else:
                lead = re.match(r"\s*([A-Za-z_][\w.:]*)", body)
                name = lead.group(1) if lead else ""
            args: dict = {}
            for m in _PSEUDO_XML_KEYVAL_RE.finditer(body):
                args[m.group(1).strip()] = _coerce_pseudo_value(m.group(2))
            for m in _PSEUDO_XML_PARAM_RE.finditer(body):
                args[m.group(1).strip()] = _coerce_pseudo_value(m.group(2))
            if not name or not args:
                continue  # leave the block to the prose parser
            calls.append((name, args))
            remaining.append(text[last:block.start()])
            last = block.end()
        remaining.append((text or "")[last:])
        return calls, "".join(remaining)

    @staticmethod
    def _parse_json_pseudo_calls(text: str) -> tuple[list[tuple[str, dict]], str]:
        """Tool calls a model wrote as JSON objects, and the text without them.

        Scans for JSON objects rather than matching a regex so nested
        argument objects survive intact. Only objects that name a tool are
        consumed; anything else is left in the text for the prose forms.
        """
        decoder = json.JSONDecoder()
        source = text or ""
        calls: list[tuple[str, dict]] = []
        kept: list[str] = []
        last = 0
        start = source.find("{")
        while start != -1:
            try:
                obj, end = decoder.raw_decode(source, start)
            except ValueError:
                start = source.find("{", start + 1)
                continue
            call = _json_pseudo_call(obj)
            if call is None:
                start = source.find("{", start + 1)
                continue
            calls.append(call)
            kept.append(source[last:start])
            last = end
            start = source.find("{", end)
        kept.append(source[last:])
        return calls, "".join(kept)

    def _recover_tool_calls_from_content(self, content: str) -> list[ToolCall]:
        """Recover structured tool calls when the model wrote them as text."""
        xml_calls, text = self._parse_xml_pseudo_calls(content or "")
        out: list[ToolCall] = []
        for i, (name, args) in enumerate(xml_calls):
            out.append(ToolCall(id=f"pseudo_xml_{i}_{name}", name=name, arguments=args))
        json_calls, text = self._parse_json_pseudo_calls(text)
        for i, (name, args) in enumerate(json_calls):
            out.append(ToolCall(id=f"pseudo_json_{i}_{name}", name=name, arguments=args))
        found: list[tuple[str, str, bool]] = []
        for m in _PSEUDO_TOOL_CALL_RE.finditer(text):
            found.append((m.group(1), m.group(2) or "", True))
        if not found:
            # A call whose closing tag the endpoint consumed as a stop token.
            # Explicit call syntax either way, so it carries arguments like
            # the terminated form does.
            for m in _PSEUDO_TOOL_CUT_RE.finditer(text):
                found.append((m.group(1), m.group(2) or "", True))
        if not found:
            for m in _PSEUDO_TOOL_BARE_RE.finditer(text):
                found.append((m.group(1), m.group(2) or "", False))
        seen: set[tuple[str, str]] = set()
        for i, (name, raw_args, explicit) in enumerate(found):
            args = self._parse_pseudo_tool_args(name, raw_args)
            # A meta tool's name in a plan with a remark in brackets — "2.
            # atlas_load_namespaces (unload net; load hash, strings)" — is
            # prose, not a call: recovering it ran ten empty loads in one
            # turn and, counting as a call, kept the intent nudge from
            # asking for the real ones. Only explicit call syntax may carry
            # arguments the parser could not read.
            if not explicit and "_malformed_arguments" in args:
                continue
            key = (name, json.dumps(args, sort_keys=True, default=str))
            if key in seen:
                continue  # the same call named twice is one call
            seen.add(key)
            out.append(ToolCall(id=f"pseudo_{i}_{name}", name=name, arguments=args))
        for tc in out:
            tc.name = self._canonical_tool_name(tc.name)
        return out

    def _canonical_tool_name(self, name: str) -> str:
        """The name the tool list carries for ``name``, or ``name`` itself.

        A recovered call goes into the history under the name the model
        wrote. Written as the playbook's dotted alias, that name is not in
        the tool list, and a model that repeats it through the function-call
        channel is calling a function the endpoint does not know: a gateway
        drops such a call before the reply is built, and the loop sees an
        empty turn it cannot explain. Under the listed name the same call
        arrives intact.
        """
        toolbox = getattr(self, "toolbox", None)
        lookup = (getattr(toolbox, "listed_name", None)
                  or getattr(toolbox, "resolve", None))
        if lookup is None:
            return name
        try:
            return lookup(name) or name
        except Exception:  # noqa: BLE001 - a resolver fault must not lose the call
            return name

    def _drop_malformed_calls(self, resp) -> None:
        """Keep the calls a tool can be named from; lose the rest before
        the history sees them.

        A call the model wrote as call syntax into the name field is put
        back into shape: the listed name, and the arguments it carried in
        the name merged under those in the arguments field. A call whose
        name is empty or is no tool name at all is not a call. It must not
        be written back as the assistant's own function call, because a
        model repeats what the history shows it: one nameless call echoed
        that way was answered with nameless calls for the rest of a run.
        The reply then reads as empty, and the loop says what was wrong.
        """
        calls = list(getattr(resp, "tool_calls", None) or [])
        if not calls:
            return
        kept = []
        for tc in calls:
            raw = tc.name or ""
            listed = self._canonical_tool_name(raw) if raw else ""
            if listed and listed != raw:
                if "(" in raw:
                    _, written = split_call_syntax(raw)
                    tc.arguments = {**written, **(tc.arguments or {})}
                tc.name = listed
            if tc.name and _TOOL_NAME_RE.fullmatch(tc.name):
                kept.append(tc)
            else:
                getattr(resp, "malformed_calls", []).append(raw[:160])
        if len(kept) != len(calls):
            resp.tool_calls = kept
            self._log({"event": "malformed_calls_dropped",
                       "names": list(getattr(resp, "malformed_calls", []))})

    def _tried_to_call(self, resp) -> bool:
        """Did the reply try to call a tool although no function call arrived?

        Two shapes say so: the call written into the text, or an empty reply
        whose completion count exceeds its reasoning count, meaning tokens
        were generated after the thinking and reached nobody. A provider
        that reports thinking text without counting it cannot be read this
        way, so its empty replies do not count.
        """
        content = getattr(resp, "content", "") or ""
        if self._content_looks_like_pseudo_tool(content):
            return True
        if content.strip():
            return False
        out = int(getattr(resp, "output_tokens", 0) or 0)
        reasoning = int(getattr(resp, "reasoning_tokens", 0) or 0)
        if not reasoning and (getattr(resp, "reasoning", "") or "").strip():
            return False
        # Note: a bare stop is a token or two; a call is a name and its
        # arguments. Raise the margin if a provider bills more silently.
        return out > reasoning + 2

    def _tool_count(self) -> int:
        """How many tool schemas the toolbox sends right now, 0 if unknown."""
        count = getattr(self.toolbox, "schema_count", None)
        try:
            return int(count()) if count else 0
        except Exception:  # noqa: BLE001 - a double without a budget
            return 0

    def _shrink_tool_budget(self):
        """Cut the loaded tool list to TOOL_BUDGET_SHRINK of its size, coldest
        namespaces first, keeping the control plane; returns ``(sent, kept,
        evicted)`` or None when nothing could be cut. The cut holds for this
        run at once; it is remembered for the model only when a function
        call arrives at the cut size."""
        toolbox = self.toolbox
        shrink = getattr(toolbox, "shrink_to", None)
        if shrink is None:
            return None
        from agent.toolbox import set_learned_tool_ceiling
        sent = int(toolbox.schema_count())
        # With nothing loaded the count is the meta tools plus the control
        # plane, which is listed whatever the budget.
        floor = int(toolbox.schema_count(set()))
        target = max(floor, int(sent * TOOL_BUDGET_SHRINK))
        if target >= sent:
            return None
        evicted = list(shrink(target) or [])
        kept = int(toolbox.schema_count())
        if kept >= sent:
            return None
        set_learned_tool_ceiling(kept)
        return sent, kept, evicted

    @staticmethod
    def _content_looks_like_pseudo_tool(content: str) -> bool:
        text = content or ""
        if "<tool_call>" in text.lower():
            return True
        return bool(_PSEUDO_TOOL_BARE_RE.search(text))

    def _attach_tool_calls_to_last_assistant(self, tool_calls: list[ToolCall]) -> None:
        """Rewrite the just-appended assistant message to include tool_calls."""
        if not self.messages or not tool_calls:
            return
        last = self.messages[-1]
        if last.get("role") != "assistant":
            return
        last["tool_calls"] = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.name,
                          "arguments": json.dumps(tc.arguments)}}
            for tc in tool_calls
        ]
        # Keep a short content hint; the tools themselves carry the action.
        if "<tool_call>" in (last.get("content") or "").lower():
            last["content"] = (last.get("content") or "").split("<tool_call>")[0].rstrip()

    # ── meta-tool handling ───────────────────────────────────────────────

    def _handle_meta(self, name: str, args: dict) -> str | None:
        if name == "atlas_list_namespaces":
            return self.toolbox.namespace_summary()
        if name == "atlas_load_namespaces":
            wanted = args.get("namespaces") or []
            unload = args.get("unload") or []
            unloaded: list[str] = []
            if unload:
                unloaded = self.toolbox.unload(unload)
            result = self.toolbox.load_with_budget(wanted)
            newly = result.get("newly_loaded") or []
            loaded = result.get("loaded") or []
            refused = result.get("refused") or []
            unknown = result.get("unknown") or []
            parts = [
                f"Loaded namespaces: {', '.join(loaded) or '(none)'}"
                + (f" (newly: {', '.join(newly)})" if newly else "")
                + ".",
                f"Schema budget now "
                f"{result.get('schema_count')}/{result.get('max')}.",
            ]
            if unloaded:
                parts.insert(
                    0, f"Unloaded: {', '.join(unloaded)}.",
                )
            if result.get("evicted"):
                parts.insert(
                    0, "Unloaded to make room (least recently used): "
                       f"{', '.join(result['evicted'])}; load them again "
                       "when needed.")
            if refused:
                bits = []
                for item in refused:
                    bits.append(
                        f"{item['namespace']} "
                        f"(+{item['tools_in_namespace']} tools → "
                        f"{item['would_be_total']}/{item['max']}; "
                        f"currently {item['currently_loaded']})"
                    )
                # Which loaded namespace holds the room, and the unload
                # that frees it: the toolbox knows, and telling the model
                # is cheaper than a turn spent working it out.
                hint_of = getattr(self.toolbox, "_budget_holders_hint", None)
                first = refused[0]
                hint = ""
                if callable(hint_of):
                    try:
                        hint = hint_of(str(first.get("namespace") or ""),
                                       int(first.get("would_be_total") or 0),
                                       int(first.get("max") or 0))
                    except Exception:  # noqa: BLE001 - a hint never breaks a load
                        hint = ""
                parts.append(
                    "REFUSED (tool-budget): " + "; ".join(bits) + ". "
                    "Unload an unused namespace (atlas_load_namespaces "
                    "unload=[...]) then retry, or continue with loaded "
                    "namespaces. Do not retry the same oversized load "
                    "without freeing budget." + hint
                )
            if unknown:
                parts.append(f"Unknown: {', '.join(unknown)}.")
            return " ".join(parts)
        if name == "atlas_ask_analyst":
            return self._ask_analyst(args)
        return None

    def _ask_analyst(self, args: dict) -> str:
        question = str(args.get("question") or "").strip()
        context = str(args.get("context") or "").strip()
        options = args.get("options") or []
        if not self.interactive:
            return ("[interactive mode is off — no analyst is at the console. "
                    "Proceed autonomously with your best judgment and record "
                    "the assumption you made (misc_record_finding / an "
                    "agent_message) instead of asking.]")
        self.ui.set_run_state(activity="awaiting analyst guidance")
        answer = self.ui.ask_analyst(question, context, options)
        self._log({"event": "analyst_dialogue", "question": question,
                   "context": context, "options": options, "answer": answer})
        if not answer:
            return ("[the analyst did not respond — proceed autonomously and "
                    "note the assumption you made.]")
        return f"[analyst guidance] {answer}"

    def _run_tool(self, tc) -> str:
        if str(tc.name).endswith(_REPORT_ENTRY_TOOLS):
            self._estate_join(getattr(self, "_turn", 0))
        result = self._handle_meta(tc.name, tc.arguments)
        if result is not None:
            return result
        args_preview = json.dumps(tc.arguments, default=str)[:200]
        self.ui.tool_call(tc.name, args_preview)
        self.ui.note_tool(tc.name, args_preview)
        start = time.monotonic()
        # tool_started (monotonic) lets the CLI's own UI warn while a call
        # runs long; tool_started_at (wall-clock) is the same signal for the
        # dashboard, a different process that can't compare monotonic
        # clocks across processes. _persist_live_status() only otherwise
        # runs once per turn, at turn *start* (see the main loop below) — a
        # single long tool call (e.g. img_vmdk_export_raw's qemu-img
        # convert, which can run for hours) would leave run_status.json
        # showing the *previous* turn's activity for its entire duration
        # without this immediate write.
        tool_started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Bare tool name: a glyph prefix would leak from the CLI spinner into
        # run_status.json and from there into the dashboard.
        self.ui.set_run_state(activity=tc.name, tool_started=start,
                              tool_started_at=tool_started_at)
        self._persist_live_status()
        _trace_mark = self._trace_length()
        with self._status_heartbeat():
            if getattr(tc, "budget_free", False):
                result, auto_loaded = self.toolbox.call(tc.name, tc.arguments, budget_free=True)
            else:
                result, auto_loaded = self.toolbox.call(tc.name, tc.arguments)
        self._close_work_items(tc.name, tc.arguments, _trace_mark)
        if auto_loaded:
            result = "[namespace auto-loaded]\n" + result
        elapsed = time.monotonic() - start
        is_info = result.startswith("TOOL INFO")
        is_error = (result.startswith(("TOOL ERROR", "ERROR"))
                    and not is_info)
        # A refusal of the call's own shape is still an error to the model —
        # it has to correct the call — but the tool never ran and nothing
        # broke, so a reader reporting the run's health must not show it as
        # damage. See agent/toolbox.is_call_shape_refusal.
        is_refusal = is_error and is_call_shape_refusal(result)
        self._tool_stats.append({"name": tc.name,
                                 "seconds": round(elapsed, 2),
                                 "error": is_error,
                                 "refusal": is_refusal,
                                 # "host" when a report writer produced one
                                 # host's report; the case's own report is
                                 # what _report_written looks for.
                                 "deliverable_scope": self._deliverable_scope(
                                     tc.name, result, is_error),
                                 # Text preview for the dashboard's run log
                                 # (kept separate from the "error" bool above,
                                 # which existing count-based consumers rely
                                 # on staying a bool).
                                 "error_text": result[:200] if is_error else "",
                                 "info": is_info})
        # refresh the live counters per call, not per turn, so the dashboard
        # doesn't freeze during tool-heavy turns
        self.ui.set_run_state(
            tool_started=None,
            tool_started_at=None,
            tools=len(self._tool_stats),
            errors=sum(1 for t in self._tool_stats if t["error"]),
            infos=sum(1 for t in self._tool_stats if t.get("info")),
            findings=self._count_recorded_findings())
        self._persist_live_status()
        if tc.name.endswith("record_finding") and not is_error and not is_info:
            self.ui.pulse_event("finding")
        self.ui.tool_result(result, elapsed, is_error=is_error, is_info=is_info)
        return result

    def _call_once(self, name: str, args: dict | None, *, turn: int, tool_call_id: str = "",
                   before_run=None, in_context=None, budget_free: bool = False) -> dict:
        """One tool call through the run's per-call path, shared by the
        conversation loop and the frontier's items: the call memo (an
        identical call is replayed when its result has left the
        conversation, else pointed at), the caller's own gates
        (``before_run(name, args)`` returns a refusal text or None), the run
        (_run_tool: meta tools, the report-entry estate join, the status
        heartbeat, work-item closing, tool stats), the memo record, the
        result's issue class, the coverage ledger's observation, and the
        marking of a repeated identical refusal. ``in_context(tool_call_id)``
        says whether an earlier result is still in the caller's messages (an
        item starts fresh: nothing is). {"result", "kind": ran | replayed |
        pointer | refused, "issue", "ran_clean"} and, for a call that ran,
        "shown_rows" (the identities of the rows it showed the model, empty
        unless it ran clean); the caller appends the result to its
        messages."""
        from types import SimpleNamespace
        from core.call_memo import memoable
        tc = SimpleNamespace(name=name, arguments=args or {}, id=tool_call_id, budget_free=budget_free)
        memo = self._call_memo
        _key = memo.key(tc.name or "", tc.arguments or {})
        _hit = memo.get(_key)
        if (_hit is not None
                and (IDENTICAL_CALL_WINDOW <= 0
                     or turn - _hit.turn <= IDENTICAL_CALL_WINDOW)
                and not _STATEFUL_TOOL_RE.search(tc.name or "")
                and memoable(tc.name or "")):
            _hit.hits += 1
            if not (in_context or self._result_still_in_context)(_hit.tool_call_id):
                # The earlier result has been compacted out of
                # the conversation: hand it back rather than
                # refuse — the model is asking for data it no
                # longer has, and the answer costs nothing.
                memo.replays += 1
                _why, _spill = self._pointed_result_incomplete(_hit)
                _note = ""
                if _why:
                    # A replay of a cut view shows the same part
                    # again; a model that repeats the call is
                    # asking for the rest, so name where it is.
                    _note = (f" This view {_why}; repeating the call shows "
                             "the same part. "
                             + self._rest_of_result_hint(_hit, _spill))
                result = (f"[replayed from turn {_hit.turn}: identical call; "
                          "its result had been compacted out of the conversation."
                          f"{_note}]\n" + _hit.result)
                self._log({"event": "identical_call_replayed", "turn": turn,
                           "tool": tc.name, "previous_turn": _hit.turn,
                           "previous_call_id": _hit.trace_call_id})
                if str(_hit.trace_call_id or "").isdigit():
                    self._close_work_items(tc.name, tc.arguments, 0,
                                           replay_of=int(_hit.trace_call_id))
                return {"result": result, "kind": "replayed", "issue": None, "ran_clean": False}
            memo.pointers += 1
            _where = (f" (trace call id {_hit.trace_call_id})"
                      if _hit.trace_call_id else "")
            _why, _spill = self._pointed_result_incomplete(_hit)
            if _why:
                # The earlier view was cut: "read it there"
                # points at a part already read. Name the
                # cut, the complete output and the narrower
                # calls that fit whole.
                _error = (
                    f"{tc.name!r} with these arguments already ran at "
                    f"turn {_hit.turn}{_where} and {_why}. The "
                    "conversation holds only the part shown then, and "
                    "repeating the call returns that same part. "
                    + self._rest_of_result_hint(_hit, _spill))
            else:
                _error = (f"{tc.name!r} with these arguments already "
                          f"succeeded at turn {_hit.turn}{_where}; a path "
                          "written differently is the same argument. Its "
                          "result is still in the conversation: read it "
                          "there. Change the arguments (another path, "
                          "inode, pattern or column), or ask "
                          "search.search_evidence for a detail of it.")
            result = json.dumps({
                "success": False,
                "gate": "identical_call",
                "error": _error,
                "previous_turn": _hit.turn,
                "previous_call_id": _hit.trace_call_id,
                **({"incomplete": _why} if _why else {}),
            }, indent=2)
            self._log({"event": "tool_result", "turn": turn,
                       "tool": tc.name, "result": result[:4000],
                       "gate": "identical_call"})
            return {"result": result, "kind": "pointer", "issue": None, "ran_clean": False}
        if before_run is not None:
            refusal = before_run(tc.name, tc.arguments)
            if refusal is not None:
                return {"result": refusal, "kind": "refused", "issue": None, "ran_clean": False}
        from agent.toolbox import take_shown_rows, take_shown_source
        take_shown_rows()                       # nothing an earlier call on this thread left
        take_shown_source()
        result = self._run_tool(tc)
        _shown = take_shown_rows()
        _shown_source = take_shown_source()
        _ran_clean = (
            not result.startswith(("TOOL ERROR", "ERROR", "TOOL INFO"))
            and '"success": false' not in result[:200]
            and not (_PROTOCOL_MARKER and _PROTOCOL_MARKER in result[:300])
            # An answer deferred to the memory batch ran nothing: never
            # memoised, so the same call reaches the wrapper again and
            # gets the batch's answer (tools/volatility._in_batch).
            and not _DEFERRED_RE.search(result[:400]))
        if _ran_clean:
            if (not _STATEFUL_TOOL_RE.search(tc.name or "")
                    and memoable(tc.name or "")):
                memo.put(_key, turn=turn, tool_call_id=tc.id,
                         result=result, tool=tc.name or "",
                         args=tc.arguments or {})
        from agent.tool_investigate import classify_tool_result, input_paths
        issue = classify_tool_result(tc.name, result)
        if issue:
            issue["inputs"] = input_paths(tc.arguments)
        # Coverage ledger: successful probes move unseen→probed.
        # A middleware protocol refusal (the DAIR window, the
        # deferred backlog, input scale, context budget,
        # discovery-first, wrong input kind, disk-open policy)
        # ran no tool: it credits no probe, no search, no derived
        # output and no image open. A tool error or a failed
        # read still records its failure below.
        _blocked = (result.startswith("TOOL INFO")
                    or bool(_PROTOCOL_MARKER and _PROTOCOL_MARKER in result[:300]))
        if self.case_dir and issue is None and not _blocked:
            try:
                from core.coverage_ledger import (
                    observe_tool_paths,
                )
                _args_blob = ""
                try:
                    import json as _json
                    _args_blob = _json.dumps(
                        tc.arguments or {}, default=str,
                        ensure_ascii=False)
                except Exception:
                    _args_blob = str(tc.arguments or "")
                # Args only — paths that merely appear in the
                # RESULT text (listings, refusals, search
                # hits) are not probes; feeding output here
                # would forge the coverage floor.
                # Parse JSON success — sudo_auth / success:false
                # bodies must not count as probes or opens.
                try:
                    from core.evidence_access import (
                        parse_tool_result_success,
                    )
                    _ok, _err = parse_tool_result_success(
                        result)
                except Exception:
                    _ok = not result.startswith((
                        "TOOL ERROR", "ERROR",
                    ))
                    _err = "" if _ok else result[:300]
                observe_tool_paths(
                    self.case_dir,
                    tool_name=tc.name,
                    cmd_or_args=_args_blob,
                    success=_ok,
                    result_text=result,
                )
                if _ok:
                    try:
                        from core.coverage_ledger import (
                            register_derived_outputs,
                        )
                        _derived = register_derived_outputs(
                            self.case_dir, tool_name=tc.name,
                            arguments=tc.arguments or {},
                            result_text=result)
                        if _derived:
                            self._log({
                                "event": "derived_outputs_registered",
                                "turn": turn,
                                "paths": _derived[:8],
                            })
                    except Exception:  # noqa: BLE001
                        pass
                # Same observation, different ledger: a call
                # naming both an indicator and a source is
                # the pivot for that pair being carried out
                # (core/ioc_pivots.py).
                if _ok:
                    try:
                        from core.ioc_pivots import (
                            observe_search,
                        )
                        _closed = observe_search(
                            self.case_dir,
                            blob=f"{tc.name} {_args_blob}",
                            result=result)
                        if _closed:
                            self._log({
                                "event": "ioc_pivot_searched",
                                "turn": turn,
                                "closed": _closed[:8],
                            })
                    except Exception:
                        pass
                # Access stage: persist opened/access_failed
                # for TSK disk-open tools (mount_plan SoT).
                try:
                    from core.evidence_access import (
                        record_open_from_tool,
                    )
                    record_open_from_tool(
                        self.case_dir,
                        tool_name=tc.name,
                        cmd_or_args=_args_blob,
                        success=_ok,
                        error=_err or (
                            "" if _ok else result[:300]
                        ),
                    )
                except Exception as _acc_err:
                    self._log({
                        "event": "access_stage_write_failed",
                        "turn": turn,
                        "tool": tc.name,
                        "error": str(_acc_err)[:300],
                    })
            except Exception as _cov_err:
                # A ledger that silently stops moving is how
                # "coverage floor not met" ambushes the
                # analyst at close-out — log it.
                self._log({
                    "event": "coverage_observe_failed",
                    "turn": turn, "tool": tc.name,
                    "error": str(_cov_err)[:300]})
        result = self._note_repeated_refusal(tc, result, turn)
        # The rows the call showed the model (core.shown_rows), for an item's
        # progress; none for a call that did not run clean.
        return {"result": result, "kind": "ran", "issue": issue, "ran_clean": _ran_clean,
                "shown_rows": list(_shown or []) if _ran_clean else [],
                "shown_source": _shown_source if _ran_clean else ""}

    def _split_reply_duplicates(self, turn: int, calls: list, memo) -> tuple[list, list]:
        """A call identical to an earlier call of the same reply (same name,
        same canonical arguments) is not run (ATLAS_REPLY_DUPLICATES). More
        than REPLY_DUPLICATES_RUNAWAY of them make the reply a runaway: a
        warn line, and the next ask goes one thinking level lower. A
        behaviour guard, not a cap: every distinct call still runs."""
        from core.envfile import env_flag
        if not env_flag("ATLAS_REPLY_DUPLICATES") or len(calls) < 2:
            return calls, []
        first: dict = {}
        unique, dups = [], []
        for tc in calls:
            try:
                k = memo.key(tc.name or "", tc.arguments or {})
            except Exception:  # noqa: BLE001
                k = (tc.name, json.dumps(tc.arguments, sort_keys=True, default=str))
            if k in first:
                dups.append((tc, first[k]))
            else:
                first[k] = tc
                unique.append(tc)
        if not dups:
            return calls, []
        self._log({"event": "reply_duplicates", "turn": turn, "duplicates": len(dups),
                   "distinct": len(unique)})
        if len(dups) > REPLY_DUPLICATES_RUNAWAY:
            lower = None
            nxt = getattr(self.client, "next_lower_level", None)
            try:
                lower = nxt(_AGENT_ROLE, None) if callable(nxt) else None
            except Exception:  # noqa: BLE001
                lower = None
            if lower:
                self._next_level_once = lower
            self._log({"event": "reply_duplicates_runaway", "turn": turn, "duplicates": len(dups),
                       "runaway": True, "next_level": lower})
            self.ui.warn(f"runaway reply: {len(dups)} calls repeated a call of the same reply"
                         + (f"; next ask at thinking level {lower}" if lower else ""))
        return unique, dups

    def _answer_reply_duplicates(self, dups: list) -> None:
        """Each duplicate is answered with a short result naming the call it
        repeats (at most CALLS_PER_TURN_MAX answers; the rest share the
        batch note)."""
        if not dups:
            return
        from core.call_memo import trace_call_id_of
        results = {m.get("tool_call_id"): str(m.get("content") or "")
                   for m in self.messages if m.get("role") == "tool"}
        for tc, orig in dups[:CALLS_PER_TURN_MAX]:
            earlier = results.get(orig.id)
            ref = (trace_call_id_of(earlier) or orig.id) if earlier is not None else ""
            self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": (
                f"[duplicate of call {ref} in this reply, not run]" if ref else
                "[duplicate of an earlier call in this reply; neither ran]")})

    def _prune_unanswered_tool_calls(self) -> None:
        """Keep on the turn's assistant message only the tool calls a tool
        result answers. Calls of a reply that did not run (beyond the batch
        bound, duplicates beyond the answered ones) are said to the model in
        a note; a call id without its result makes a strict endpoint refuse
        the next request."""
        for i in range(len(self.messages) - 1, -1, -1):
            m = self.messages[i]
            if m.get("role") != "assistant":
                continue
            if not m.get("tool_calls"):
                return
            answered = {x.get("tool_call_id") for x in self.messages[i + 1:] if x.get("role") == "tool"}
            kept = [tc for tc in m["tool_calls"] if tc.get("id") in answered]
            if len(kept) != len(m["tool_calls"]):
                if kept:
                    m["tool_calls"] = kept
                else:
                    del m["tool_calls"]
                    if not str(m.get("content") or "").strip():
                        # An assistant message with neither text nor calls
                        # is refused by a strict endpoint; the placeholder
                        # also keeps the roles alternating.
                        m["content"] = _PRUNED_REPLY_TEXT
            return

    @staticmethod
    def _trace_length() -> int:
        try:
            from core.execution_log import log
            return len(log._entries)
        except Exception:  # noqa: BLE001
            return 0

    def _close_work_items(self, tool: str, args: dict | None, mark: int, *,
                          replay_of: int | None = None) -> None:
        """The closing rule (ATLAS_WORK_ORDER): the work items a call that
        ran reached close by its trace entry; a wrong-input-kind or
        evidence-compat refusal of an item's own ready call closes it as
        failed (read from the call_abandoned entry, before any protocol
        skip). A replayed call closes by the original call's entry. Every
        id closed is movement for the neglect streak. Fail-open."""
        try:
            from core.deferred_intents import work_order_on
            if not work_order_on():
                return
            from core.execution_log import log
            if replay_of is not None:
                entry = log.index().by_call_id.get(int(replay_of))
                calls, abandoned = ([entry] if isinstance(entry, dict) else []), []
            else:
                new = list(log._entries[mark:])
                calls = [e for e in new if e.get("type") == "tool_call"]
                abandoned = [e for e in new if e.get("type") == "call_abandoned"]
            if not calls and not abandoned:
                return
            closed = log.close_items_for_call(tool, args or {}, calls, abandoned,
                                              closing_call_id=replay_of)
            if closed:
                moved = getattr(self, "_wo_moved", None)
                if moved is None:
                    moved = self._wo_moved = set()
                moved.update(closed)
        except Exception as e:  # noqa: BLE001
            self._log({"event": "work_order_close_failed", "tool": tool, "error": str(e)[:200]})

    @staticmethod
    def _critical_scan_debt() -> list[dict]:
        from core.deferred_intents import incomplete_read_debt_on
        if incomplete_read_debt_on():
            return []        # a time-cut read is the investigate latch's debt
        try:
            from core.execution_log import log
            from tools._gates.critical_scan_timeout import (
                unresolved_critical_scan_timeouts,
            )
            return unresolved_critical_scan_timeouts(list(log._entries))
        except Exception:
            return []

    def _count_recorded_findings(self) -> int:
        """Findings that actually landed in the execution trace.

        Counting non-error record_finding *calls* overstated the number: gate refusals and
        duplicate short-circuits return cleanly without appending a finding
        entry. The MCP server runs in-process, so the trace is the truth.
        Falls back to the call count if the log is unavailable.
        """
        try:
            from core.execution_log import log
            return sum(1 for e in log._entries if e.get("type") == "finding")
        except Exception:
            return sum(1 for tc in self._tool_stats
                       if tc["name"].endswith("record_finding")
                       and not tc["error"])

    def _deliverable_scope(self, tool: str, result: str, is_error: bool) -> str:
        """"host" when a report-writer call wrote one host's report, "case"
        when it wrote the case's, "" when it wrote nothing. A refused write
        answers with a JSON body of its own (``success: false`` and no
        output path), not a tool error, and must not read as a report."""
        if is_error or not (tool.endswith("write_final_report")
                            or tool.endswith("write_projected_final_report")):
            return ""
        try:
            data = json.loads(result[result.index("{"):])
        except (ValueError, AttributeError):
            return ""
        if not isinstance(data, dict) or data.get("success") is False:
            return ""
        path = str(data.get("output_path") or "")
        if not path:
            return ""
        from core.report_exit import is_host_deliverable
        return "host" if is_host_deliverable(path, self.case_dir) else "case"

    def _report_written(self) -> bool:
        """Whether an official final report was produced this run.

        Only a write_final_report / write_projected_final_report call that
        wrote the case's report counts — not a refused write, not one host's
        report, not host scratch docs from write_case_document. File
        fallback accepts estate_report / final_report names or a projection
        deliverable recorded with those sources (not arbitrary reports/*.md).
        """
        # Only a write that produced the case's report counts: a refused
        # write is not an error string but a JSON refusal, and one host's
        # report is not the case's.
        if any(t.get("deliverable_scope") == "case" for t in self._tool_stats):
            return True
        if not self.case_dir:
            return False
        # Official deliverable names/sources only — not host_* scratch docs,
        # and not the report the exit path writes. One definition, shared
        # with the exit writer that must never collide with it.
        try:
            from core.report_exit import official_report_exists
            return official_report_exists(self.case_dir)
        except Exception:
            return False

    @staticmethod
    def _pre_report_blocking() -> bool:
        """True when the latest pre_report_check explicitly says not ready.

        Missing check → False (wrap-up still asks for the check). Grants
        turn extensions instead of dying mid-blocker work.
        """
        try:
            from core.execution_log import log
            for e in reversed(log._entries):
                if (e.get("type") == "reason_call"
                        and e.get("tool") == "reason_pre_report_check"):
                    conc = e.get("conclusion") or ""
                    m = re.search(
                        r"READY_TO_REPORT:\s*(true|false)",
                        conc, re.IGNORECASE)
                    return bool(m and m.group(1).lower() == "false")
        except Exception:
            pass
        return False

    @staticmethod
    def _dair_reengage_pending() -> bool:
        """True when forensic tools are waiting on a fresh dair_assess.

        Fail-closed to False: if the log is missing or unreadable, the
        quiet valve behaves exactly as it did before this recovery path.
        """
        try:
            from core.execution_log import log
            return bool(log.open_deferred_intents())
        except Exception:
            return False

    def _dair_stall_pending(self, content: str = "") -> bool:
        """True when an empty-tool turn is a protocol stall, not a model
        that has finished.

        Two independent signals, either sufficient:

        * a blocked forensic tool already recorded a deferred intent
          (authoritative — this is the state the DAIR gate is in), or
        * the model narrated the dair_assess call it failed to emit, which
          fires even before any intent exists.

        Fail-closed to False like _dair_reengage_pending: an unreadable log
        plus unremarkable prose leaves the pre-existing quiet path exactly
        as it was.
        """
        if self._dair_reengage_pending():
            return True
        return bool(_DAIR_PROSE_RE.search(content or ""))

    def _grant_blocker_extension(
            self, *, turn: int, turn_limit: int,
            granted_so_far: int) -> tuple[int, int, bool]:
        """Raise turn_limit by another chunk if blockers remain and budget left.

        Layer 3: identical READY_TO_REPORT:false blockers with no knowledge
        progress since the last grant do NOT get another extension — that is
        the wrap-up deadlock amplifier. Returns (new_turn_limit,
        new_granted_total, did_grant).
        """
        if self._report_written():
            return turn_limit, granted_so_far, False
        if BLOCKER_EXTENSION_TURNS <= 0 or BLOCKER_EXTENSION_MAX <= 0:
            return turn_limit, granted_so_far, False
        remaining = BLOCKER_EXTENSION_MAX - granted_so_far
        if remaining <= 0 or not self._pre_report_blocking():
            return turn_limit, granted_so_far, False

        from core.investigation_exit import (
            blocker_fingerprint, should_grant_blocker_extension,
        )
        fp = blocker_fingerprint()
        allow, deny_reason = should_grant_blocker_extension(
            last_fingerprint=self._blocker_ext_fingerprint,
            last_extension_call_id=self._blocker_ext_at_call_id,
            current_fingerprint=fp,
        )
        if not allow:
            self.messages.append({
                "role": "user",
                "content": (
                    "[blocker extension denied] The same READY_TO_REPORT:false "
                    "blockers remain and knowledge progress has not advanced "
                    f"since the last extension ({deny_reason}). Do NOT stay in "
                    "Collect. Force Report phase via dair_assess, write a "
                    "degraded/partial report with "
                    "misc.write_projected_final_report (timeline limitations "
                    "are acceptable), then call atlas_finish."
                ),
            })
            self._log({
                "event": "blocker_extension_denied",
                "turn": turn,
                "reason": deny_reason,
                "fingerprint": fp,
            })
            self.ui.info(
                f"blocker extension denied ({deny_reason}) — force degraded report")
            return turn_limit, granted_so_far, False

        extra = min(BLOCKER_EXTENSION_TURNS, remaining)
        new_limit = max(turn_limit, turn) + extra
        new_granted = granted_so_far + extra
        self.messages.append({
            "role": "user",
            "content": _BLOCKER_EXTENSION_MSG.format(
                extra=extra,
                granted=new_granted,
                max_extra=BLOCKER_EXTENSION_MAX),
        })
        # Stamp fingerprint + current max call_id so the next grant can detect
        # identical-blocker / no-progress.
        self._blocker_ext_fingerprint = fp
        try:
            from core.execution_log import log as _elog
            if _elog._entries:
                self._blocker_ext_at_call_id = int(
                    _elog._entries[-1].get("call_id") or 0)
        except Exception:
            pass
        self._log({
            "event": "blocker_extension",
            "turn": turn,
            "extra_turns": extra,
            "granted_total": new_granted,
            "max_extra": BLOCKER_EXTENSION_MAX,
            "new_turn_limit": new_limit,
            "fingerprint": fp,
            "grant_reason": deny_reason,
        })
        self.ui.info(
            f"blocker extension: +{extra} turns "
            f"({new_granted}/{BLOCKER_EXTENSION_MAX} used, "
            f"limit now {new_limit})")
        return new_limit, new_granted, True

    def _record_budget_wrapup_marker(
        self,
        trigger: str,
        turn: int,
        *,
        allow_synthesize_escape: "bool | None" = None,
    ) -> None:
        """Mirror the budget wrap-up into the shared in-process execution trace.

        The wrap-up steer is a conversation message plus a JSONL event; neither
        is visible to the report gate, which reads only the MCP execution trace
        (core.execution_log). Stamp a typed marker there so
        reason.pre_report_check can relax unresolved content-quality blockers to
        documented limitations rather than deadlock the report until the budget
        is spent with no deliverable. Best-effort — a failure here must never take down the run.

        ``allow_synthesize_escape`` is True only for wall-clock / hard-cap /
        ledger-ready force-report — not for exploration stalls with open
        coverage gaps.
        """
        try:
            from core.execution_log import log
            log.record_budget_wrapup(
                trigger, turn,
                allow_synthesize_escape=allow_synthesize_escape,
            )
        except Exception:
            pass

    def _contents_counts(self) -> dict:
        turn = self.stats.get("turns")
        cached = getattr(self, "_contents_cache", None)
        if cached is not None and cached[0] == turn:
            return cached[1]
        out: dict = {}
        try:
            from core.contents_index import index_status_on, inside_counts
            if index_status_on():
                out = {k: v for k, v in inside_counts(self.case_dir).items() if k != "per_image"}
        except Exception:  # noqa: BLE001
            out = {}
        self._contents_cache = (turn, out)
        return out

    def _evidence_item_counts(self) -> dict:
        try:
            from core.coverage_ledger import load_ledger
            from core.evidence_items import counts
            items = (load_ledger(self.case_dir).get("items") or {}).values()
            return counts([i for i in items if isinstance(i, dict)])
        except Exception:  # noqa: BLE001
            return {}

    def _finish_coverage_check(self, *, wall_expired: bool) -> str:
        """One-shot atlas_finish deferral while high-value evidence is open.

        Without it a run can finish with most ledger units unseen and every
        task still open. This check refuses the FIRST finish
        attempt with the concrete open units and task list so the agent gets
        one explicit chance to keep working (a run may take 1000 turns if
        the evidence warrants it). It never hard-blocks: the second attempt,
        wall-clock expiry, and ledger-ready degraded exits always pass, and
        classification stays truthful (incomplete_coverage) either way. With
        the work order on, the one list of open work decides instead
        (_finish_open_work_check).

        Returns the refusal message, or "" when the finish may proceed.
        """
        if wall_expired or not self.case_dir:
            return ""
        from core.deferred_intents import work_order_on
        if work_order_on():
            return self._finish_open_work_check()
        if getattr(self, "_finish_coverage_deferred", False):
            return ""
        try:
            from core.coverage_ledger import (
                open_unit_paths,
                ready_for_degraded_exit,
            )
            if ready_for_degraded_exit(self.case_dir):
                return ""
            gaps = open_unit_paths(self.case_dir, limit=8)
        except Exception:
            return ""
        if not gaps:
            return ""
        open_tasks: list[str] = []
        try:
            from core.investigation_tasks import (
                ACTIONABLE_STATUSES, list_tasks,
            )
            open_tasks = [
                f"{t.get('id')}: {(t.get('text') or '')[:90]}"
                for t in list_tasks(self.case_dir,
                                    statuses=ACTIONABLE_STATUSES)[:5]
            ]
        except Exception:
            open_tasks = []
        self._finish_coverage_deferred = True
        try:
            from core.coverage_ledger import open_units_read_hint
            how = open_units_read_hint(self.case_dir)
        except Exception:  # noqa: BLE001
            how = ""
        lines = [
            "atlas_finish deferred — this is NOT a hard stop, but high-value "
            "evidence is still unexamined. There is no turn limit: keep "
            "investigating as long as the evidence yields work.",
            "Unseen high-value units (read each" + (f" - {how}" if how else "")
            + "; coverage.mark_blocked records a read that failed):",
        ]
        lines += [f"  - {g}" for g in gaps]
        try:
            from core.evidence_items import unseen as _unseen_items
            _items = _unseen_items(self.case_dir, limit=8)
        except Exception:  # noqa: BLE001
            _items = []
        if _items:
            lines.append("Delivered evidence no call has read:")
            lines += [f"  - {p}" for p in _items]
        if open_tasks:
            lines.append("Open investigation tasks:")
            lines += [f"  - {t}" for t in open_tasks]
        try:
            from core.coverage_ledger import EXTRACTED_OPEN_HEAD, extracted_lines, extracted_outputs
            _extracted = extracted_lines([o for o in extracted_outputs(self.case_dir, readers=True) if o["open"]],
                                         only_open=True)
        except Exception:  # noqa: BLE001
            _extracted = []
        if _extracted:
            lines.append(EXTRACTED_OPEN_HEAD)
            lines += [f"  - {x}" for x in _extracted]
        lines.append(
            "If you have genuinely exhausted what the evidence supports, "
            "call atlas_finish again and it will proceed (the run is then "
            "classified as incomplete coverage)."
        )
        return "\n".join(lines)

    def _finish_open_work_check(self) -> str:
        """The finish is deferred while the run still owes work no deferral
        has named yet (core.work_order.open_work: open question parts,
        extracted file classes no call read, due reads). It passes when the
        list is empty, when everything on it was named before, and when the
        model made no call since the last deferral: atlas_finish called again
        right away always ends the run, and the report states what stays open
        (ATLAS_WORK_ORDER). Never a count: each further deferral needs model
        work and an item no deferral named. Before the list, each open refused
        finding defers the finish once on its own line
        (core.work_order.refused_deferral, recorded on the refusal's trace
        entry): a finding the run lost is acted on or let go one at a time,
        not read as one line among due reads. Then the parsed outputs no row
        of which was looked at defer it once together
        (core.work_order.parsed_deferral, once per set of outputs, recorded
        on the trace), so the outputs are not read as lines among due reads
        either."""
        try:
            from core.execution_log import log
            from core import work_order as W
            work = W.open_work(log, self.case_dir)
            keys = W.open_work_keys(work)
        except Exception:  # noqa: BLE001
            return ""
        try:
            alone = W.refused_deferral(log, work.get("refused") or [])
        except Exception:  # noqa: BLE001
            alone = ""
        if alone:
            return alone
        try:
            parsed = W.parsed_deferral(log, work.get("parsed") or [])
        except Exception:  # noqa: BLE001
            parsed = ""
        if parsed:
            return parsed
        classes = self._class_deferral(work)
        if classes:
            return classes
        named = getattr(self, "_finish_named", frozenset())
        calls = getattr(self, "_model_calls", 0)
        if not keys or keys <= named or calls == getattr(self, "_finish_named_at", None):
            return ""
        self._finish_named = named | keys
        self._finish_named_at = calls
        lines = ["atlas_finish deferred: work is still open. This is not a hard stop: atlas_finish called again "
                 "right away ends the run, and the report states what stays open.", *W.open_work_lines(work)]
        if work["due"]:
            try:
                text, _shown = W.work_order_block(log, self.case_dir, self._tool_params)
            except Exception:  # noqa: BLE001
                text = ""
            if text:
                lines.append(text)
        return "\n".join(lines)

    def _class_deferral(self, work: dict) -> str:
        """The class guard, its own step before the generic list: the
        content classes with neither a read nor a reason (open_class_keys)
        defer the finish while their set differs from the set the last
        class deferral named (a read or a leave changes it, a listing does
        not); the identical set lets the model out, and the ending then
        carries the stop label (core.investigation_exit: stopped_undecided),
        never a finished run. No count, no clock. The leave tool's
        namespace is loaded with the deferral, so the call it names can
        arrive."""
        from core import work_order as W
        ckeys = W.open_class_keys(work)
        if not ckeys:
            return ""
        named = getattr(self, "_finish_classes_named", frozenset())
        if ckeys == named:
            self._log({"event": "finish_undecided_classes", "classes": len(ckeys)})
            return ""
        self._finish_classes_named = ckeys
        try:
            self._load_namespaces_for(["coverage.set_evidence_disposition", "coverage.ledger_status"])
        except Exception:  # noqa: BLE001
            pass
        return "\n".join([
            "atlas_finish deferred: content classes with neither a read nor a reason stand open. Read one file "
            "of each, or leave its label with a checked reason (one call per label across hosts). The run cannot "
            "end as finished while one stands; atlas_finish called again with the same classes open ends the run "
            "as stopped, with them listed for a person to decide.", *W.class_lines(work)])

    def _closing_stage(self) -> bool:
        """Whether the run is closing: a finish was deferred, the class guard
        spoke, or the director is in Report. From here the class block is
        shown whole each turn; before it, one count line."""
        return (getattr(self, "_finish_named_at", None) is not None
                or bool(getattr(self, "_finish_classes_named", None))
                or getattr(self, "_dair_phase", "") == "Report")

    def _open_classes_cached(self) -> list:
        """The undecided classes (core.work_order.open_classes), read again
        only when the ledger file moved."""
        import os
        path = os.path.join(str(self.case_dir), ".atlas", "coverage_ledger.json")
        try:
            stamp = os.stat(path).st_mtime_ns
        except OSError:
            return []
        cached = getattr(self, "_oc_cache", None)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        try:
            from core import work_order as W
            classes = W.open_classes(str(self.case_dir))
        except Exception as e:  # noqa: BLE001
            self._log({"event": "open_classes_failed", "error": str(e)[:200]})
            classes = []
        self._oc_cache = (stamp, classes)
        return classes

    def _close_out_held(self, turn: int, *, wall_expired: bool) -> bool:
        """Whether the gate-ready close-out waits this turn. Under the work
        order the close-out first gives the model the finish's deferral
        (_finish_open_work_check: refused findings, parsed outputs, the open
        work no deferral named yet), as a model that never calls
        atlas_finish would otherwise never see it; then it waits while each
        turn's calls close named work (the open-work keys shrink, none
        appears; a listing reads no file and closes none). The first turn
        that closes nothing is closed out: progress decides, never a count.
        Each time it waits the model is shown the list as it stands, headed
        by the one next read (core.work_order.close_out_head). Without the
        work order, or once the clock ran out, the close-out never waits."""
        from core.deferred_intents import work_order_on
        if wall_expired or not self.case_dir or not work_order_on():
            return False
        try:
            from core import work_order as W
            from core.execution_log import log
            work = W.open_work(log, self.case_dir)
            keys = W.open_work_keys(work) | W.open_class_keys(work)
        except Exception:  # noqa: BLE001
            return False
        calls = getattr(self, "_model_calls", 0)
        last = getattr(self, "_close_hold", None)
        text = self._finish_open_work_check()
        if text:
            self._close_hold = (keys, calls)
            self._nudge("close_out_deferred", W.close_out_head(work) + "\n" + text)
            self._log({"event": "close_out_deferred", "turn": turn, "open": len(keys)})
            return True
        if last is not None and keys and calls != last[1] and keys < last[0]:
            self._close_hold = (keys, calls)
            self._nudge("close_out_deferred", "\n".join([W.close_out_head(work), *W.open_work_lines(work)]))
            self._log({"event": "close_out_held", "turn": turn, "open": len(keys)})
            return True
        return False

    def _finish_report_check(self, *, wall_expired: bool) -> str:
        """One-shot atlas_finish deferral when no official report exists.

        The near-cap wrap-up that forces a report is gated behind a hard
        turn cap (``hard_turn_cap_enabled``), and the default config has no
        turn cap — so an organic atlas_finish could end a run having written
        no report at all, which is ungradeable (the failure mode
        WRAPUP_MARGIN's comment describes, reached by a path that comment
        does not cover).

        Same contract as _finish_coverage_check: refuses the FIRST attempt
        only, never hard-blocks. A second atlas_finish always proceeds, so a
        model that genuinely cannot write one still ends the run — truthfully
        classified by classify_finish_status.

        Returns the deferral message, or "" when the finish may proceed.
        """
        # Same two escapes as _finish_coverage_check: a wall-clock stop must
        # never gain an extra hurdle, and with no case dir there is nowhere
        # to write a report and nothing to grade (chat and other harnesses).
        if wall_expired or not self.case_dir:
            return ""
        if getattr(self, "_finish_report_deferred", False):
            return ""
        if self._report_written():
            return ""
        self._finish_report_deferred = True
        return (
            "atlas_finish deferred — no official final report has been "
            "written this run, so there is nothing to grade. This is NOT a "
            "hard stop. Write the report now: call "
            "misc.current_investigation_state, then "
            "misc.write_projected_final_report (or misc.write_final_report "
            "when has_beliefs is false), then export_execution_log. "
            "If you genuinely cannot produce one, call atlas_finish again "
            "and it will proceed (the run is then classified incomplete)."
        )

    def _successful_synthesize_this_run(self) -> bool:
        """True when a usable reason.synthesize exists after the latest run open."""
        try:
            from core.execution_log import log
            from core.reason_outcome import is_usable_reason_call
            started = 0
            from core.execution_log import is_trace_opened
            for e in log._entries:
                if is_trace_opened(e):
                    started = int(e.get("call_id") or 0)
            for e in reversed(log._entries):
                if int(e.get("call_id") or 0) < started:
                    break
                if (e.get("type") == "reason_call"
                        and e.get("tool") == "reason_synthesize"
                        and is_usable_reason_call(e)):
                    return True
        except Exception:
            pass
        return False

    def _pre_report_verdict(self) -> str:
        """The latest usable reason.pre_report_check conclusion, "" if none."""
        try:
            from core.execution_log import log
            from core.reason_outcome import is_usable_reason_call
            for e in reversed(log._entries):
                if (e.get("type") != "reason_call"
                        or e.get("tool") != "reason_pre_report_check"):
                    continue
                if not is_usable_reason_call(e):
                    continue
                return str(e.get("conclusion") or "")
        except Exception:
            pass
        return ""

    def _pre_report_ready(self) -> bool:
        """True when the latest usable pre_report_check says READY_TO_REPORT:true."""
        m = re.search(r"READY_TO_REPORT:\s*(true|false)",
                      self._pre_report_verdict(), re.IGNORECASE)
        return bool(m and m.group(1).lower() == "true")

    def _pre_report_fresh_ready(self) -> bool:
        """READY_TO_REPORT: true from a check that no evidence-affecting
        call has aged out, by the report tools' own rule."""
        try:
            from tools.misc import _pre_report_ready_gate
            return _pre_report_ready_gate() is None
        except Exception:  # noqa: BLE001
            return self._pre_report_ready()

    def _run_pre_report_check(self) -> dict | None:
        """Consult the report gate on the model's behalf; the verdict goes
        into the trace like one the model asked for."""
        try:
            from tools.reasoning import reason_pre_report_check
            out = reason_pre_report_check()
            return out if isinstance(out, dict) else None
        except Exception as e:  # noqa: BLE001
            self._log({"event": "pre_report_check_failed", "error": str(e)[:200]})
            return None

    def _close_out_spine(self, turn: int, checked: dict, *, need_dair: bool = True) -> dict:
        """At the report-stall close-out, supply the synthesis the verdict
        names as missing: the reviewer's read is Atlas's reason role's work,
        and an analyst that never asked for it does not remove the need for
        it. Runs once, in-process, traced as a reason call with source
        "loop", then the check again. Without a dair_call (synthesize refuses
        without one), without a finding, or when the synthesis comes back
        unusable, the verdict stands and the reason is logged
        (ATLAS_CLOSE_OUT_SPINE; off: the verdict stands)."""
        from core.envfile import env_flag
        if not env_flag("ATLAS_CLOSE_OUT_SPINE") or checked.get("has_synthesize", True):
            return checked
        if getattr(self, "_spine_ran", False):
            return checked
        self._spine_ran = True

        def skipped(reason: str) -> dict:
            self._log({"event": "spine_skipped", "turn": turn, "reason": reason})
            return checked
        try:
            from core.execution_log import log
            entries = list(log._entries)
            # The frontier has no director, so no dair_call to wait for.
            if need_dair and not any(e.get("type") == "dair_call" for e in entries):
                return skipped("no dair_call in the trace")
            findings = [e for e in entries if e.get("type") == "finding"]
            replaced = {int(e["replaces_call_id"]) for e in findings if e.get("replaces_call_id")}
            standing = [e for e in findings if int(e.get("call_id") or 0) not in replaced]
            if not standing:
                return skipped("no finding to synthesise")
            text = "\n".join(
                f"[{e.get('call_id')}] {str(e.get('confidence') or '').upper()}: "
                f"{' '.join(str(e.get('description') or '').split())}" for e in standing)
            from tools.reasoning import reason_synthesize
            out = reason_synthesize(findings=text,
                                    investigation_summary=self._spine_summary(entries),
                                    input_call_ids=[int(e["call_id"]) for e in standing])
            cid = int((out or {}).get("_atlas_call_id") or 0)
            if cid:
                log.update_reason_call(cid, source="loop")
            if not (isinstance(out, dict) and out.get("success")):
                return skipped("synthesis unusable: " + str((out or {}).get("error") or "no result")[:160])
            self._log({"event": "close_out_spine", "turn": turn, "synthesize_call_id": cid})
            again = self._run_pre_report_check()
            return again if again else checked
        except Exception as e:  # noqa: BLE001 - the stall ends as without the spine
            return skipped(f"{type(e).__name__}: {e}"[:200])

    def _spine_summary(self, entries: list) -> str:
        """What was read, in counts: tool calls, the coverage ledger and the
        disk media's access stage."""
        bits = [f"{sum(1 for e in entries if e.get('type') == 'tool_call')} tool calls in the trace"]
        try:
            from core.coverage_ledger import coverage_stats, load_ledger
            stats = coverage_stats(load_ledger(self.case_dir)) if self.case_dir else {}
            if stats:
                bits.append("coverage ledger: " + ", ".join(f"{k} {v}" for k, v in stats.items()))
        except Exception:  # noqa: BLE001
            pass
        try:
            from core.evidence_access import media_entries
            media = media_entries(self.case_dir) if self.case_dir else []
            if media:
                opened = sum(1 for m in media if m.get("access_stage") == "opened")
                bits.append(f"disk media: {opened} of {len(media)} opened")
        except Exception:  # noqa: BLE001
            pass
        return "; ".join(bits)

    def _close_out(self, turn: int, *, reason: str) -> bool:
        """Write the case's reports now that the gate has passed, and say
        so. The projection of the recorded findings is the report whether
        the model or the loop asks for it; what the model kept not doing
        once the gate was ready is done here. True when a report was
        written."""
        if not self.case_dir:
            return False
        from core.report_exit import close_out_reports
        self.ui.info("report gate ready — writing the reports")
        self.ui.set_run_state(activity="writing the reports")
        self._persist_live_status()
        res = close_out_reports(self.case_dir, reason=reason,
                                verdict=self._pre_report_verdict())
        self._log({"event": "close_out", "turn": turn, "reason": reason,
                   "written": list(res.get("written") or []),
                   "errors": dict(res.get("errors") or {})})
        for path in res.get("written") or []:
            self.ui.info(f"wrote {path}")
        for path, err in (res.get("errors") or {}).items():
            self.ui.warn(f"could not write {path}: {err}")
        return bool(res.get("written"))

    def _finish_status(self, stopped_reason: str) -> str:
        """Classify exit via the single Done owner in investigation_exit."""
        from core.investigation_exit import classify_finish_status
        return classify_finish_status(
            stopped_reason,
            case_dir=self.case_dir,
            report_written=self._report_written(),
            synthesize_ok=self._successful_synthesize_this_run(),
            pre_report_ready=self._pre_report_ready(),
        )

    # ── main loop ────────────────────────────────────────────────────────

    def run(self, system_prompt: str, user_message: str) -> str:
        """The shared setup, then the loop the mode names (ATLAS_LOOP):
        the conversation loop (default) or the frontier queue."""
        mode = loop_mode()
        refusal = self._loop_mode_refusal(mode)
        if refusal:
            return self._refuse_loop_mode(mode, refusal)    # before any run state is written
        self._loop_mode = mode
        self._run_setup(system_prompt, user_message, mode)
        if mode == "frontier":
            from agent.frontier import FrontierRun
            return FrontierRun(self).run()
        return self._run_turns()

    def _loop_mode_refusal(self, mode: str) -> str:
        """Why this run cannot start in ``mode`` ("" when it can): the
        frontier needs the incident map's change feed, and a resumed trace
        keeps the mode it was run in (modes never mix in one trace)."""
        if mode == "frontier":
            from core.incident_map import map_on
            if not map_on():
                return "ATLAS_LOOP=frontier needs the incident map's change feed; ATLAS_INCIDENT_MAP is off"
        earlier = self._earlier_loop_mode()
        if earlier and earlier != mode:
            return (f"this case's trace was run in {earlier} mode; a resume in {mode} mode is refused "
                    "(a fresh start converts it)")
        return ""

    def _earlier_loop_mode(self) -> str:
        """The loop mode of the latest earlier run transcript under
        analysis/ (a resumed trace; a fresh start clears them), "" when
        none. A run_start without the field is the conversation loop."""
        if not self.case_dir:
            return ""
        try:
            from core.run_state import TRANSCRIPT_PREFIX
            mine = getattr(self, "transcript_path", None)
            found = ""
            for path in sorted((self.case_dir / "analysis").glob(f"{TRANSCRIPT_PREFIX}*.jsonl")):
                if mine is not None and path == mine:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if '"event": "run_start"' in line:
                            try:
                                found = str(json.loads(line).get("loop_mode") or "conversation")
                            except ValueError:
                                continue
            return found
        except Exception:  # noqa: BLE001 - an unreadable transcript never blocks a run
            return ""

    def _refuse_loop_mode(self, mode: str, msg: str) -> str:
        self.ui.warn(msg)
        self._log({"event": "loop_mode_refused", "mode": mode, "reason": msg})
        self.stats = {"stopped_reason": "loop_mode_refused", "finish_status": "loop_mode_refused",
                      "turns": 0, "duration_seconds": 0.0}
        return msg

    def _run_setup(self, system_prompt: str, user_message: str, mode: str = "conversation") -> None:
        """What every loop needs before its first call: the messages, the
        run_start record (roles and loop mode), the brain-injection manifest,
        the run clock, the stats, the call memo and the status fields."""
        from agent.llm import reset_run_memory
        reset_run_memory()
        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]
        from core.provider_profiles import HASH_ENV
        self._log({"event": "run_start", "model": self.client.model,
                   "roles": _role_models_safe(),
                   "base_url": self.client.base_url, "loop_mode": mode,
                   "vol_store_entries": _vol_store_entries(self.case_dir),
                   # The provider profiles this run started with.
                   "provider_profiles": os.environ.get(HASH_ENV, ""),
                   # Whether every tool is listed for the whole run, and why not.
                   "tool_list": _tool_list_mode(self.toolbox)})
        # Travel the brain-injection manifest with the run: _brain_context()
        # writes analysis/brain_injection.json at prompt-build time (a separate
        # process step), but it was never in the trace — so effectiveness stayed
        # un-analyzable. Copy it into the trace at run start so dfir-review can
        # cross-reference injected entries against run behaviour. Best-effort.
        if self.case_dir:
            try:
                import json as _json
                _mf = self.case_dir / "analysis" / "brain_injection.json"
                if _mf.exists():
                    self._log({"event": "brain_injection",
                               "manifest": _json.loads(_mf.read_text())})
            except Exception:
                pass
        self._run_start = time.monotonic()      # the escape compares the wall clock between pauses
        self._tool_stats = []
        # The report ladder reads this run's own gate verdicts only.
        self._run_since = self._last_call_id()
        # Every successful read-only call of the run, keyed on the tool and
        # its canonical arguments (paths in real form, tied to the inputs'
        # size and mtime). A repeat is answered from here instead of run
        # again: the result the model already had, at the cost of nothing.
        from core.call_memo import CallMemo
        self._call_memo = CallMemo(self.case_dir)
        # Keep a live snapshot so Ctrl+C can persist turns/duration
        # even when the normal run_end stats assignment never runs.
        self.stats = {
            "stopped_reason": "running",
            "finish_status": "",
            "turns": 0,
            "duration_seconds": 0.0,
        }
        # When this run began, for the run status the dashboard lists.
        self._started_at = _run_started_at()

    def _run_turns(self) -> str:
        """The conversation loop."""
        memo = self._call_memo
        run_start = self._run_start
        finish_summary = ""
        quiet_turns = 0
        dair_reengage_used = 0
        blocked_turns = 0
        stopped_reason = "finished"
        turn = 0
        wrapped_up = False
        report_wrapup_turn: int | None = None
        wrapup_explore_calls = 0
        intent_rescues = 0
        cut_offs = 0
        cut_offs_total = 0
        empty_replies = 0
        declines = 0
        no_work_rescues = 0
        tool_budget_shrinks = 0
        # The largest tool list a function call has arrived with in this
        # run. A failure at or under that size is not the list's fault, so
        # it never triggers a cut; the cut is for sizes never seen to work.
        tools_ok_at = 0
        # A cut size waiting for proof. It is remembered for the model only
        # once a function call arrives at it: a failure followed by a
        # success is the evidence, a failure alone is noise.
        tool_budget_pending = 0
        # Replies in a row that tried to call at the current size and got
        # no call through; a function call at any size clears it.
        tool_budget_strikes = 0
        # Consecutive replies that only loaded or listed namespaces.
        meta_only_streak = 0
        # Consecutive turns whose only call was the director, answered
        # each time with an unchanged assessment.
        director_reask_streak = 0
        # The model asked to finish and was deferred (report or
        # coverage still owed). If nothing follows, the run ended
        # because it considered itself done — not because it went
        # silent, and the operator is owed that distinction.
        finish_requested = False
        # Only a wrap-up caused by a hard budget (turn cap, wall clock, model
        # deadline) rations exploration. The quiet valve and the blocker
        # ladder inject the same message to *restart* a stalled model; a
        # ration after such a wrap-up would refuse the very probes that
        # answer the case.
        wrapup_rationed = False
        refusal_streak = 0
        deadlock_warned = False
        wall_expired = False
        turn_limit = initial_turn_limit(MAX_TURNS)
        blocker_extension_granted = 0
        investigate_debt: list[dict] = []
        stall_state = StallState()

        with self.ui.live_session():
            while True:
                # Optional hard turn cap (lab/CI). Default MAX_TURNS=0 skips
                # this — productive long runs must not die at a global quota.
                if hard_turn_cap_enabled(MAX_TURNS) and turn >= turn_limit:
                    turn_limit, blocker_extension_granted, granted = (
                        self._grant_blocker_extension(
                            turn=turn,
                            turn_limit=turn_limit,
                            granted_so_far=blocker_extension_granted))
                    if granted:
                        wrapped_up = True
                    else:
                        stopped_reason = "turn_cap"
                        self.ui.info(
                            f"agent stopped: turn cap {turn_limit} reached "
                            f"(ATLAS_AGENT_MAX_TURNS={MAX_TURNS})")
                        break
                # Deadlock: every recent tool result was a refusal.
                if DEADLOCK_REFUSALS > 0 and refusal_streak >= 2 * DEADLOCK_REFUSALS \
                        and not self._report_written():
                    stopped_reason = "gate_deadlock"
                    self.ui.warn(f"agent stopped: {refusal_streak} consecutive "
                                 "refused tool calls — protocol deadlock")
                    self._log({"event": "gate_deadlock", "turn": turn,
                               "refusals": refusal_streak})
                    break
                turn += 1
                self.stats = {
                    "stopped_reason": "running",
                    "finish_status": "",
                    "turns": turn,
                    "duration_seconds": round(time.monotonic() - run_start, 1),
                    "tool_calls": list(self._tool_stats or []),
                    "input_tokens": getattr(self.client, "total_input_tokens", 0),
                    "output_tokens": getattr(self.client, "total_output_tokens", 0),
                    "transcript": str(self.transcript_path or ""),
                    "distinct_tool_calls": len(memo),
                    "identical_calls_replayed": memo.replays,
                    "identical_calls_pointed": memo.pointers,
                }
                self._persist_live_status()
                self._trim_context()
                self._refresh_context_budget(turn=turn)
                stall_state = observe_progress(
                    stall_state, case_dir=self.case_dir)
                # wall_expired is set further down the turn and never reset,
                # so this sees the clock from the previous turn onward.
                for _msg in stall_messages_for_turn(
                        stall_state, turn=turn,
                        report_written=self._report_written(),
                        case_dir=self.case_dir,
                        wall_clock=wall_expired,
                        work_order=self._stall_work_order()):
                    self.messages.append(_msg)
                    self._log({
                        "event": "run_budget_nudge",
                        "turn": turn,
                        "kind": (_msg.get("content") or "")[:48],
                        "no_progress_streak": stall_state.no_progress_streak,
                    })
                    self.ui.info(
                        f"run-budget: {(_msg.get('content') or '')[:48]}…")
                # Force-report / synthesize-escape only when ledger (or
                # wall-clock path below) permits — not on soft/hard approach
                # nudges alone.
                if (should_allow_synthesize_escape(stall_state)
                        and not wrapped_up):
                    wrapped_up = True
                    self._record_budget_wrapup_marker(
                        "progress_stall", turn,
                        allow_synthesize_escape=True)
                elif should_treat_as_wrapup(stall_state):
                    # hard stall recorded for telemetry only
                    self._log({
                        "event": "run_budget_hard_stall",
                        "turn": turn,
                        "no_progress_streak": stall_state.no_progress_streak,
                    })
                if investigate_debt:
                    from agent.tool_investigate import format_investigate_message
                    self._nudge("tool_failure_investigate",
                                format_investigate_message(investigate_debt))
                    self._log({"event": "tool_failure_investigate",
                               "turn": turn,
                               "issues": investigate_debt[:8]})
                    self.ui.info(
                        f"tool-failure investigate latch "
                        f"({len(investigate_debt)} issue(s))")
                # Report phase that records nothing new for many turns while the
                # director keeps prescribing collection: ask for the report with
                # the gaps named, before the wrap-up guards have any reason to.
                try:
                    if ((not wrapped_up or report_wrapup_turn is None)
                            and not self._report_written()
                            and self._report_phase_stalled(turn)):
                        if not wrapped_up:
                            if self._push_report_phase(turn, reason="stalled"):
                                wrapped_up = True
                                wrapup_rationed = True
                                report_wrapup_turn = turn
                        else:
                            # Wrapped up by another trigger and stalled in
                            # Report all the same: start the close-out clock
                            # below, with no second wrap-up message.
                            self._nudge("report_phase_stall", self._report_stall_msg())
                            self._log({"event": "report_phase_stall", "turn": turn,
                                       "quiet_turns": REPORT_STALL_TURNS,
                                       "reason": "stalled_after_wrapup"})
                            report_wrapup_turn = turn
                    # After the report-stall wrap-up, still no report a
                    # stall's worth of turns later: the loop consults the
                    # gate itself. Ready, it writes the reports and ends
                    # the run; not ready, the run ends and the exit path
                    # writes what the findings support.
                    if (report_wrapup_turn is not None
                            and turn - report_wrapup_turn >= REPORT_STALL_TURNS
                            and not self._report_written()):
                        checked = self._run_pre_report_check()
                        if checked and not checked.get("ready_to_report"):
                            checked = self._close_out_spine(turn, checked)
                        ready = (bool(checked.get("ready_to_report")) if checked
                                 else self._pre_report_ready())
                        self._log({"event": "report_stall_close_out", "turn": turn,
                                   "since_wrapup": turn - report_wrapup_turn,
                                   "ready": ready})
                        if ready and self._close_out(turn, reason="report_stall"):
                            stopped_reason = "closed_out"
                        else:
                            stopped_reason = "report_stall"
                            self.ui.warn("no report written since the wrap-up "
                                         "and the gate is not ready — closing "
                                         "out; the exit path writes the report")
                        break
                except Exception as _e:  # noqa: BLE001
                    self._log({"event": "report_stall_check_failed", "turn": turn,
                               "error": str(_e)[:200]})
                # The gate has passed and no report exists: the loop writes
                # the reports and ends the run. What the model does after
                # READY_TO_REPORT: true is not something a run waits for.
                try:
                    if (self.case_dir
                            and getattr(self, "_dair_phase", "") == "Report"
                            and not self._report_written()
                            and self.work_order_settled()
                            and self._pre_report_fresh_ready()
                            and not self._close_out_held(turn, wall_expired=wall_expired)):
                        if self._close_out(turn, reason="gate_ready"):
                            stopped_reason = "closed_out"
                            break
                except Exception as _e:  # noqa: BLE001
                    self._log({"event": "close_out_failed", "turn": turn,
                               "error": str(_e)[:200]})
                # No deferral (ATLAS_DAIR_NO_DEFER): a resumed trace's open
                # protocol intents are retired once, and the window nudge
                # gives way to the progress line on its own counter.
                try:
                    from core.deferred_intents import dair_no_defer_on, work_order_on
                    if dair_no_defer_on():
                        if not getattr(self, "_intents_retired", False):
                            from core.execution_log import log as _rlog
                            _n = _rlog.retire_protocol_intents("deferral off")
                            self._intents_retired = True
                            if _n:
                                self._log({"event": "protocol_intents_retired", "turn": turn, "count": _n})
                        if not work_order_on():
                            _pl = self._progress_line(turn)
                            if _pl:
                                self._nudge("dair_progress", _pl)
                except Exception as _e:  # noqa: BLE001
                    self._log({"event": "no_defer_turn_failed", "turn": turn, "error": str(_e)[:200]})
                # DAIR window: say so a batch before it ages out, not after.
                try:
                    from core.deferred_intents import dair_no_defer_on as _ndo
                    if _ndo():
                        raise StopIteration          # nothing is deferred: no window to warn of
                    from core.middleware import dair_window_used
                    _used, _win = dair_window_used()
                    # A margin the size of the model's recent batches: a
                    # batch of six can take the window from 14 to 20 in one
                    # turn, past a fixed margin of five without a warning.
                    _margin = max(DAIR_NUDGE_MARGIN,
                                  max(getattr(self, "_recent_batch_sizes", None) or [0]))
                    if (_used and _win - _used <= _margin
                            and not wrapped_up
                            and not self._dair_reengage_pending()):
                        self._nudge("dair_window_nudge",
                                    _DAIR_WINDOW_MSG.format(used=_used, window=_win))
                        self._log({"event": "dair_window_nudge", "turn": turn,
                                   "used": _used, "window": _win})
                except StopIteration:
                    pass
                except Exception as _e:  # noqa: BLE001
                    self._log({"event": "dair_window_check_failed", "turn": turn,
                               "error": str(_e)[:200]})
                # IOC pivots: indicators recorded in beliefs must be carried
                # back across the evidence that could corroborate them —
                # including other hosts' material. Re-derived every turn so
                # an indicator found this turn is owed searches next turn,
                # and nudged only while work is actually outstanding
                # (core/ioc_pivots.py). Fail-open: a pivot ledger problem
                # must never stop an investigation.
                if self.case_dir:
                    try:
                        from core.ioc_pivots import (
                            format_pivot_nudge, open_pivots, refresh_pivots,
                        )
                        refresh_pivots(self.case_dir)
                        # Typed rows recorded before sightings existed are
                        # checked against the evidence a few per turn
                        # (core.indicators.refresh_sightings, fail-open).
                        from core.indicators import refresh_sightings
                        refresh_sightings(self.case_dir)
                        _pivots = open_pivots(self.case_dir)
                        self._estate_count_turn(turn)
                        # Not once the run is wrapping up, nor in Report
                        # once it has been asked for the report: the nudge
                        # sends the model back to grep, and the close-out
                        # never came (_push_report_phase).
                        if (_pivots and turn % IOC_PIVOT_NUDGE_EVERY == 0
                                and not wrapped_up
                                and not (getattr(self, "_report_pushed", False)
                                         and getattr(self, "_dair_phase", "") == "Report")):
                            self._nudge("ioc_pivot_nudge",
                                        format_pivot_nudge(_pivots, case_dir=self.case_dir))
                            self._log({"event": "ioc_pivot_nudge",
                                       "turn": turn,
                                       "open": len(_pivots),
                                       "iocs": [p["ioc"] for p in _pivots[:8]]})
                            self.ui.info(
                                f"{len(_pivots)} indicator(s) not yet "
                                "searched across relevant evidence")
                    except Exception as _pv_err:
                        self._log({"event": "ioc_pivot_check_failed",
                                   "turn": turn,
                                   "error": str(_pv_err)[:200]})
                    # What the run already established, shown every few
                    # turns and after each compaction (core/call_memo.py):
                    # the distinct calls made, the open questions, the
                    # unsearched indicators. Superseded in place, so it
                    # never grows the conversation. Fail-open.
                    try:
                        _compacted = getattr(self, "_compacted_since_index", False)
                        if (len(memo) and not wrapped_up
                                and (turn % KNOWLEDGE_INDEX_EVERY == 0 or _compacted)):
                            from core.call_memo import render_index
                            from core.investigation_tasks import list_tasks
                            _findings = None
                            try:
                                from core.execution_log import log as _klog
                                _findings = len(_klog.index().by_type.get("finding") or [])
                            except Exception:  # noqa: BLE001
                                _findings = None
                            try:
                                from core.hash_index import identical_groups
                                _identical = identical_groups(self.case_dir)
                            except Exception:  # noqa: BLE001
                                _identical = None
                            try:
                                from core.execution_log import log as _elog
                                from core.ioc_pivots import (
                                    unrecorded_demand,
                                    unrecorded_evidence_indicators,
                                )
                                _unrecorded, _bulk = unrecorded_demand(
                                    unrecorded_evidence_indicators(
                                        list(getattr(_elog, "_entries", []) or []),
                                        self.case_dir))
                            except Exception:  # noqa: BLE001
                                _unrecorded, _bulk = None, None
                            # The beliefs themselves, not their number: after a
                            # compaction the conversation no longer carries what
                            # the run concluded, and the model rebuilds it from
                            # prose instead of reading it back.
                            try:
                                from core.claim_graph import (
                                    active_conclusions_and_conflicts)
                                _snap = active_conclusions_and_conflicts(self.case_dir)
                                _claims = ((_snap.get("conclusions") or [])
                                           + (_snap.get("claims") or []))
                            except Exception:  # noqa: BLE001
                                _claims = None
                            self._nudge("knowledge_index", render_index(
                                memo, findings=_findings,
                                tasks=list_tasks(self.case_dir),
                                pivots_open=len(locals().get("_pivots") or []),
                                identical=_identical, unrecorded=_unrecorded,
                                unrecorded_bulk=_bulk, claims=_claims))
                            self._compacted_since_index = False
                            self._log({"event": "knowledge_index", "turn": turn,
                                       "distinct_calls": len(memo),
                                       "replays": memo.replays,
                                       "pointers": memo.pointers})
                    except Exception as _ki_err:  # noqa: BLE001
                        self._log({"event": "knowledge_index_failed", "turn": turn,
                                   "error": str(_ki_err)[:200]})
                    # Artifact value: read the evidence that can answer the
                    # most, and never let an absence claim stand over
                    # evidence the case itself has indexed
                    # (core/artifact_value.py). Same cadence as the pivot
                    # nudge, same fail-open contract.
                    try:
                        from core.artifact_value import (
                            contradicted_absence_claims, format_value_nudge,
                            unexamined_high_value,
                        )
                        from core.deferred_intents import work_order_on as _wo_on
                        _wo = _wo_on()
                        # With the work order on, clashes are items and the
                        # unread artefacts proposals (_derive_work_items).
                        _clashes = [] if _wo else [c for c in contradicted_absence_claims(self.case_dir)
                                                   if not c.get("hostless")]
                        _unread = (unexamined_high_value(self.case_dir)
                                   if turn % IOC_PIVOT_NUDGE_EVERY == 0 and not _wo else [])
                        # The contents index's rows reach the analyst as the
                        # first host lines of the host-first view, not as a
                        # rank over the estate (core.contents_index).
                        _view = ""
                        if _unread:
                            from core.contents_index import host_view, host_view_on
                            if host_view_on():
                                _view = host_view(self.case_dir, max_hosts=4, header=False)
                                _unread = [u for u in _unread
                                           if not str(u.get("source") or "").startswith("index:")]
                        if _clashes or _unread or _view:
                            _msg = format_value_nudge(_unread, _clashes, view=_view)
                            # Said once is said: the same list re-injected
                            # every few turns is noise the model learns to
                            # skip. It is repeated only when it changed or
                            # compaction took the standing copy away.
                            if _msg and not self._nudge_stands("artifact_value_nudge", _msg):
                                self._nudge("artifact_value_nudge", _msg)
                                self._log({
                                    "event": "artifact_value_nudge",
                                    "turn": turn,
                                    "contradictions": [
                                        c.get("claim_id") for c in _clashes[:6]],
                                    "unread": [a["name"] for a in _unread[:6]],
                                })
                                if _clashes:
                                    self.ui.warn(
                                        f"{len(_clashes)} absence claim(s) "
                                        "contradicted by the case's own index")
                    except Exception as _av_err:
                        self._log({"event": "artifact_value_check_failed",
                                   "turn": turn,
                                   "error": str(_av_err)[:200]})
                    # What the images hold, one line per host (C2 item 2b):
                    # said once after the inventory, said again only when
                    # compaction took the standing copy away.
                    try:
                        from core.contents_index import listing_digest, listing_shape_on
                        from core.evidence_inventory_gate import inventory_satisfied
                        if listing_shape_on() and inventory_satisfied(self.case_dir):
                            _dg = listing_digest(self.case_dir)
                            if _dg.get("lines"):
                                _dmsg = ("INSIDE THE IMAGES (the contents index built at intake: per host its "
                                         "file count, commonest extensions, and the largest directory trees "
                                         "few other hosts hold; tsk.index_find searches it):\n"
                                         + "\n".join(_dg["lines"]))
                                if not self._nudge_stands("listing_digest", _dmsg):
                                    self._nudge("listing_digest", _dmsg)
                                    self._log({"event": "listing_digest", "turn": turn,
                                               "hosts": _dg.get("hosts"), "shown": _dg.get("shown")})
                    except Exception as _ld_err:  # noqa: BLE001
                        self._log({"event": "listing_digest_failed", "turn": turn,
                                   "error": str(_ld_err)[:200]})
                    # Partial evidence sets: reading a few of many rotated
                    # logs and concluding about "the logs" is the failure that
                    # looks most like success (core/source_sets.py).
                    try:
                        from core.source_sets import (
                            format_series_nudge, partially_examined_series,
                        )
                        from core.deferred_intents import work_order_on as _wo_on2
                        # With the work order on, a partly read series is a
                        # proposal the director sees (_derive_work_items).
                        if turn % IOC_PIVOT_NUDGE_EVERY == 0 and not _wo_on2():
                            _partial = partially_examined_series(self.case_dir)
                            if _partial:
                                self._nudge("partial_evidence_set_nudge",
                                            format_series_nudge(_partial))
                                self._log({
                                    "event": "partial_evidence_set_nudge",
                                    "turn": turn,
                                    "series": [
                                        f"{s['directory']}/{s['pattern']}"
                                        for s in _partial[:6]],
                                })
                                self.ui.info(
                                    f"{len(_partial)} evidence series only "
                                    "partly examined")
                    except Exception as _ss_err:
                        self._log({"event": "source_set_check_failed",
                                   "turn": turn,
                                   "error": str(_ss_err)[:200]})
                    # The work order, last: the due reads as ready calls.
                    self._work_order_turn(turn, wrapped_up)
                # Belief-starvation latch: successful evidence contacts with
                # zero record_finding — hard-stop further gathering.
                belief_latched = False
                belief_contacts = 0
                try:
                    from agent.belief_starvation import (
                        findings_recorded as _bs_findings,
                        format_starvation_message,
                        starvation_latched,
                        substantive_contact_count,
                    )
                    from core.execution_log import log as _bs_elog
                    _bs_entries = list(_bs_elog._entries or [])
                    belief_contacts = substantive_contact_count(_bs_entries)
                    belief_latched = starvation_latched(
                        _bs_entries, case_dir=self.case_dir)
                    if belief_latched:
                        _bs_text = format_starvation_message(
                            contacts=belief_contacts,
                            findings=_bs_findings(_bs_entries),
                            dair_established=bool(
                                getattr(_bs_elog, "_last_dair_cid", 0)),
                        )
                        from core.envfile import env_flag
                        if env_flag("ATLAS_REFUSAL_ACCOUNTING"):
                            # One copy stands: each latched turn supersedes
                            # the last message (ATLAS_REFUSAL_ACCOUNTING).
                            self._nudge("belief_starvation_latch", _bs_text)
                        else:
                            self.messages.append({"role": "user", "content": _bs_text})
                        self._log({
                            "event": "belief_starvation_latch",
                            "turn": turn,
                            "contacts": belief_contacts,
                            "findings": _bs_findings(_bs_entries),
                        })
                        self.ui.warn(
                            f"belief-starvation latch "
                            f"({belief_contacts} contacts, 0 findings)")
                    # The recording nudge: the reads in context that showed
                    # rows and that no accepted finding cites; the latch,
                    # when on, says more and wins.
                    from agent.belief_starvation import RecordPace
                    if getattr(self, "_record_pace", None) is None:
                        self._record_pace = RecordPace()
                    _rp_text = self._record_pace.check(
                        _bs_entries, suppress=bool(
                            belief_latched or wrapped_up
                            or getattr(self, "_dair_phase", "") == "Report"))
                    if _rp_text:
                        self._nudge("record_nudge", _rp_text)
                        self._log({"event": "record_nudge", "turn": turn,
                                   "named": list(self._record_pace.named),
                                   "blanket_findings": self._record_pace.blanket})
                    elif _rp_text == "":
                        self._retire_nudge("record_nudge")
                except Exception as _bs_err:
                    self._log({
                        "event": "belief_starvation_check_failed",
                        "turn": turn,
                        "error": str(_bs_err)[:200],
                    })
                elapsed = time.monotonic() - run_start
                if MAX_WALL_SECONDS > 0 and elapsed > MAX_WALL_SECONDS:
                    if (wall_expired and
                            elapsed > MAX_WALL_SECONDS + WALL_GRACE_SECONDS):
                        stopped_reason = "wall_clock"
                        self.ui.info(
                            f"agent stopped: wall clock exceeded "
                            f"{MAX_WALL_SECONDS:.0f}s + grace")
                        break
                    if not wall_expired:
                        wall_expired = True
                        self._log({"event": "wall_clock_expired",
                                   "turn": turn,
                                   "elapsed_seconds": round(elapsed, 1)})
                        if not wrapped_up and not self._report_written():
                            wrapped_up = True
                            wrapup_rationed = True
                            self.messages.append({
                                "role": "user",
                                "content": _WRAPUP_MSG.format(
                                    left=min(WRAPUP_MARGIN,
                                             turn_limit - turn + 1))})
                            self._log({"event": "budget_wrapup",
                                       "turn": turn,
                                       "trigger": "wall_clock"})
                            self._record_budget_wrapup_marker(
                                "wall_clock", turn,
                                allow_synthesize_escape=True)
                            self.ui.info(
                                f"wall clock expired at turn {turn} — "
                                "wrap-up injected")
                            turn_limit, blocker_extension_granted, _ = (
                                self._grant_blocker_extension(
                                    turn=turn,
                                    turn_limit=turn_limit,
                                    granted_so_far=blocker_extension_granted))
                # Near-cap wrap-up only when an explicit hard turn cap is set.
                if (hard_turn_cap_enabled(MAX_TURNS)
                        and not wrapped_up
                        and turn > turn_limit - WRAPUP_MARGIN
                        and not self._report_written()):
                    wrapped_up = True
                    wrapup_rationed = True
                    self.messages.append({
                        "role": "user",
                        "content": _WRAPUP_MSG.format(
                            left=turn_limit - turn + 1)})
                    self._log({"event": "budget_wrapup", "turn": turn,
                               "trigger": "turn_budget"})
                    self._record_budget_wrapup_marker(
                        "turn_budget", turn,
                        allow_synthesize_escape=True)
                    self.ui.info(f"budget wrap-up injected at turn {turn}")
                    turn_limit, blocker_extension_granted, _ = (
                        self._grant_blocker_extension(
                            turn=turn,
                            turn_limit=turn_limit,
                            granted_so_far=blocker_extension_granted))
                self.ui.set_run_state(
                    command=self.command, turn=turn,
                    run_start=run_start,
                    elapsed=time.monotonic() - run_start,
                    tools=len(self._tool_stats),
                    errors=sum(1 for t in self._tool_stats if t["error"]),
                    infos=sum(1 for t in self._tool_stats if t.get("info")),
                    findings=self._count_recorded_findings(),
                    tokens=(self.client.total_input_tokens
                            + self.client.total_output_tokens),
                    activity="consulting model")
                # Deadlock prevention: if the deferred backlog latch is set,
                # force the analyst toward dair_assess. After enough ignored
                # nudges, auto-relieve so the run cannot wedge forever.
                try:
                    from core.deferred_intents import (
                        DEADLOCK_BLOCKS_WITHOUT_ASSESS,
                    )
                    from core.execution_log import log as _elog
                    _st = _elog.deferred_backlog_status()
                    if _st.get("latched"):
                        self.messages.append({
                            "role": "user",
                            "content": _DEFERRED_BACKLOG_FORCE_MSG.format(
                                open=_st.get("open", 0),
                                cap=_st.get("cap", 10),
                                hyst=_st.get("hysteresis", 7),
                            ),
                        })
                        self._log({"event": "deferred_backlog_nudge",
                                   "turn": turn, "status": _st})
                        self.ui.info(
                            f"deferred backlog latch "
                            f"({_st.get('open')}/{_st.get('cap')}) — "
                            f"forcing dair_assess")
                        if (int(_st.get("latch_blocks") or 0)
                                >= DEADLOCK_BLOCKS_WITHOUT_ASSESS
                                and int(_st.get("latch_assesses") or 0) == 0):
                            escaped = _elog.deadlock_escape_deferred_intents()
                            self._log({"event": "deferred_deadlock_escape",
                                       "turn": turn, "result": escaped})
                            self.ui.warn(
                                "deferred backlog deadlock escape: "
                                f"auto-dismissed {len(escaped.get('dismissed') or [])} "
                                "intent(s) so the run can continue")
                except Exception:
                    pass
                try:
                    _batch_grace_end()
                    resp = self._chat_turn_asked_again(turn)
                except (LLMDeadlineError, LLMTransportError) as e:
                    trigger = ("llm_deadline" if isinstance(e, LLMDeadlineError)
                               else "llm_transport")
                    from agent.llm import model_call_escape_on
                    if model_call_escape_on():
                        # The escape raises only before the run's first
                        # answer or past the operator's wall clock: the run
                        # stops with the error, no wrap-up, no marker, no
                        # relaxed gates.
                        stopped_reason = getattr(self, "_escape_stop", "") or trigger
                        self._log({"event": trigger, "turn": turn, "error": str(e),
                                   "stopped_reason": stopped_reason})
                        self.ui.warn(f"agent stopped ({stopped_reason}): {e}")
                        break
                    # A wedged model call, or a provider that stayed
                    # unreachable through the lost-turn retries, is a lost
                    # turn, not a lost run: steer into wrap-up so blockers can
                    # still be cleared and a full report written.
                    self._log({"event": trigger, "turn": turn,
                               "error": str(e)})
                    self.ui.warn(f"model call exceeded its time budget: {e}"
                                 if trigger == "llm_deadline"
                                 else f"model call lost after retries: {e}")
                    if not wrapped_up and not self._report_written():
                        wrapped_up = True
                        wrapup_rationed = True
                        self.messages.append({
                            "role": "user",
                            "content": _WRAPUP_MSG.format(
                                left=max(1, turn_limit - turn))})
                        self._log({"event": "budget_wrapup", "turn": turn,
                                   "trigger": trigger})
                        self._record_budget_wrapup_marker(
                            trigger, turn,
                            allow_synthesize_escape=True)
                        continue
                    stopped_reason = trigger
                    self.ui.info("agent stopped: model call lost again "
                                 "after wrap-up")
                    break
                except LLMError as e:
                    self._log({"event": "llm_error", "error": str(e)})
                    self.ui.error(f"LLM error: {e}")
                    raise
                _assistant_record = {
                    "event": "assistant", "turn": turn,
                    "content": resp.content,
                    "tool_calls": [(tc.name, tc.arguments)
                                   for tc in resp.tool_calls],
                    "finish_reason": resp.finish_reason,
                    "input_tokens": resp.input_tokens,
                    "output_tokens": resp.output_tokens,
                    "reasoning_tokens": getattr(resp, "reasoning_tokens", 0) or 0,
                    "cut_reason": getattr(resp, "cut_reason", "") or "",
                    "malformed_calls": list(getattr(resp, "malformed_calls", None) or []),
                    # Calls that came with no arguments, with what the wire
                    # carried for them and from which provider.
                    **({"empty_calls": [{**c, "provider": str(getattr(getattr(self.client, "provider", None),
                                                                      "name", "") or "")}
                                        for c in resp.empty_calls]}
                       if getattr(resp, "empty_calls", None) else {}),
                    # How much of this request the provider could serve from
                    # its prompt cache, and how much of the message list was
                    # byte-identical to the previous request's prefix — the
                    # two numbers that say whether caching is working.
                    "cached_tokens": getattr(resp, "cached_tokens", 0) or 0,
                    "prefix_reuse": self._prefix_reuse(),
                }
                if getattr(self, "_last_reply_escape", ""):
                    # The reply that followed the escape's progress summary.
                    _assistant_record["escape"] = self._last_reply_escape
                    self._last_reply_escape = ""
                if not resp.tool_calls:
                    # A turn that produced no tool call is the one turn whose
                    # raw provider message actually matters: it is the only
                    # way to tell "the model narrated the call in prose" from
                    # "the model emitted a call our parser dropped" (reasoning
                    # models put content in non-standard fields). Capped and
                    # only on this branch — the transcript gets a line every
                    # turn and must not balloon.
                    _assistant_record["raw_message"] = _capped_json(
                        resp.raw_message)
                    _assistant_record["reasoning"] = (
                        getattr(resp, "reasoning", "") or "")[:2000]
                self._log(_assistant_record)
                if resp.content:
                    self.ui.turn(turn)
                    self.ui.assistant(resp.content)

                refusal = getattr(resp, "refusal", None)
                if refusal is not None:
                    # Declined by the provider: its own branch, ahead of every
                    # empty-reply rule. Not a dropped call, a cut or silence,
                    # so no tool-list cut, no counter of theirs and no label
                    # of theirs; the next request says what happened, once.
                    declines += 1
                    if declines >= PROVIDER_DECLINES_MAX:
                        stopped_reason = "model_refusal"
                        self._log({"event": "model_refusal_stop", "turn": turn,
                                   "consecutive": declines})
                        self.ui.warn(f"agent stopped: the provider declined {declines} "
                                     "requests in a row")
                        break
                    self._nudge("provider_declined", _DECLINED_MSG.format(
                        category=refusal.get("category") or "not given"))
                    continue
                declines = 0

                # Some models write the call as text instead of using the
                # function-calling API. run_chat_turn has recovered that
                # shape since the pseudo-tool work landed; the investigation
                # loop never did, so the same model behaviour that chat
                # shrugs off killed a run as "quiet".
                # atlas_finish is deliberately NOT recoverable here: a model
                # *describing* the finish call must not end an investigation
                # — recovery is a rescue for work, not for stopping.
                turn_tool_calls = list(resp.tool_calls)
                if not turn_tool_calls and resp.content:
                    recovered = [
                        tc for tc in
                        self._recover_tool_calls_from_content(resp.content)
                        if tc.name != "atlas_finish"
                    ]
                    if recovered:
                        self._attach_tool_calls_to_last_assistant(recovered)
                        turn_tool_calls = recovered
                        self._log({"event": "pseudo_tool_recovered",
                                   "turn": turn,
                                   "tools": [tc.name for tc in recovered]})
                        self.ui.info(
                            "recovered "
                            f"{', '.join(tc.name for tc in recovered)} "
                            "from message text (model wrote the call as "
                            "prose instead of a function call)")

                # A reply that tried to call a tool and got no function call
                # through: the size of the tool list is the first suspect.
                # Function calling degrades as the schema block grows, and
                # where it degrades differs by model, so the working size is
                # learned here rather than pinned: cut the list, ask again,
                # remember what answered. A call recovered from the text
                # still runs; the cut only shapes the turns after it.
                if (not resp.tool_calls
                        and self._tool_count() > tools_ok_at
                        and self._tried_to_call(resp)):
                    shrunk = None
                    left_stable = False
                    if self._tool_probe_at:
                        # The list was past the ceiling on purpose: the
                        # test failed, and the answer is the ceiling it
                        # left, not a fresh cut.
                        self._fail_tool_probe(turn)
                        shrunk = ()
                    elif tool_budget_shrinks < TOOL_BUDGET_SHRINKS_MAX:
                        tool_budget_strikes += 1
                        if tool_budget_strikes >= TOOL_BUDGET_STRIKES:
                            left_stable = _list_stable(self.toolbox)
                            shrunk = self._shrink_tool_budget()
                            tool_budget_strikes = 0
                        if shrunk:
                            tool_budget_shrinks += 1
                            sent, kept, evicted = shrunk
                            tool_budget_pending = kept
                            self._log({"event": "tool_budget_shrunk", "turn": turn,
                                       "sent": sent, "kept": kept,
                                       "evicted": evicted,
                                       **({"left_stable_list": True} if left_stable else {})})
                            self.ui.warn(
                                f"no function call arrived with {sent} tool "
                                f"schemas — cut to {kept} (unloaded "
                                f"{', '.join(evicted) or 'nothing'}) and asked again"
                                + ("; the tool list leaves stable mode" if left_stable else ""))
                    if shrunk is not None and not turn_tool_calls:
                        self.messages.append({"role": "user",
                                              "content": _NO_CALL_MSG})
                        continue

                if (not turn_tool_calls and resp.finish_reason == "length"
                        and cut_offs < CUT_OFF_NUDGES_MAX
                        and cut_offs_total < CUT_OFF_TOTAL_MAX):
                    # The reply hit the output-length limit before any call
                    # was issued — a cut-off, not a stall (a reasoning model
                    # spent its whole budget analysing). Ask for the calls
                    # alone; this spends neither an intent rescue nor a
                    # quiet turn, and a real call resets the count.
                    cut_offs += 1
                    cut_offs_total += 1
                    self.messages.append({"role": "user", "content": _CUT_OFF_MSG})
                    self._log({"event": "reply_cut_off", "turn": turn,
                               "output_tokens": resp.output_tokens,
                               "consecutive": cut_offs,
                               "run_total": cut_offs_total})
                    self.ui.warn("reply hit the output length limit before "
                                 "any tool call — asked for the calls")
                    continue

                malformed = list(getattr(resp, "malformed_calls", None) or [])
                if (not turn_tool_calls
                        and not (resp.content or "").strip()
                        and malformed
                        and empty_replies < EMPTY_REPLY_NUDGES_MAX):
                    # The call arrived but named no tool. Not a dropped call
                    # (nothing to do with the list size) and not silence:
                    # say what was wrong with the call and ask again.
                    empty_replies += 1
                    self.messages.append({
                        "role": "user",
                        "content": _MALFORMED_CALL_MSG.format(
                            names=", ".join(repr(n) for n in malformed))})
                    self._tool_choice_next = "required"
                    self._log({"event": "malformed_call_nudge", "turn": turn,
                               "consecutive": empty_replies,
                               "names": malformed, "tool_choice": "required"})
                    self.ui.warn(
                        "the reply's function call named no tool — asked "
                        f"for it again ({empty_replies}/{EMPTY_REPLY_NUDGES_MAX})")
                    continue

                if (not turn_tool_calls
                        and not (resp.content or "").strip()
                        and empty_replies < EMPTY_REPLY_NUDGES_MAX
                        and self._claim_count() != 0):
                    # The provider billed output and returned neither text nor
                    # a call. A quiet turn means the model had nothing left to
                    # do; this is the provider answering with nothing, and the
                    # two must not share a budget. Two of these end a run, and
                    # every other rung of the quiet ladder is unavailable to a
                    # run that already holds findings: the wrap-up round is
                    # one-shot and usually spent, and the no-work rescue below
                    # covers only a run that has recorded nothing.
                    #
                    # Hence the claim guard. Before a run holds anything the
                    # rescue is the right instrument and must not be
                    # pre-empted — putting this ahead of it would leave a run
                    # at zero findings with its namespaces never loaded.
                    empty_replies += 1
                    if (self._tried_to_call(resp)
                            and self._tool_count() <= tools_ok_at):
                        # Tokens were generated after the thinking at a list
                        # size that has delivered calls before: not the size,
                        # a name the endpoint did not know. The likeliest
                        # such name is a tool outside the loaded namespaces;
                        # load what the director last asked for and say
                        # which namespaces are in the list.
                        loaded_now = self._load_namespaces_for(
                            self._last_director_tools, turn=turn)
                        self.messages.append({
                            "role": "user",
                            "content": self._dropped_call_message()})
                        self._log({"event": "dropped_call_nudge", "turn": turn,
                                   "consecutive": empty_replies,
                                   "output_tokens": resp.output_tokens,
                                   "namespaces_loaded": loaded_now})
                        self.ui.warn(
                            "a call was dropped before it arrived — named the "
                            f"loaded namespaces ({empty_replies}/"
                            f"{EMPTY_REPLY_NUDGES_MAX})")
                        continue
                    self.messages.append({"role": "user",
                                          "content": _EMPTY_REPLY_MSG})
                    self._log({"event": "empty_reply_nudge", "turn": turn,
                               "consecutive": empty_replies,
                               "output_tokens": resp.output_tokens})
                    self.ui.warn(
                        "empty reply — asked for the call "
                        f"({empty_replies}/{EMPTY_REPLY_NUDGES_MAX})")
                    continue

                if (not turn_tool_calls and resp.content
                        and intent_rescues < INTENT_RESCUES_MAX
                        and not self._dair_reengage_pending()
                        and self._describes_a_tool_call(resp.content)):
                    # The reply narrates the next step ("let me search the
                    # MFT CSVs…") and issues no call — a reasoning model's
                    # way of stalling; a run can end "quiet" after a few
                    # such turns while the work is in plain sight. Ask for the call itself before counting quiet.
                    intent_rescues += 1
                    unloaded = self._named_tools_not_loaded(resp.content)
                    # The reply named tools whose schemas are not in front
                    # of the model. They are brought in as for a work
                    # order before the call is asked for; only a namespace
                    # that could not be loaded is left for the model.
                    loaded_now = (self._load_namespaces_for(
                        [alias for alias, _ns in unloaded], turn=turn)
                        if unloaded else [])
                    still = [(a, ns) for a, ns in unloaded if ns not in loaded_now]
                    self.messages.append({
                        "role": "user",
                        "content": (_no_call_unloaded_msg(still) if still
                                    else _no_call_loaded_msg(loaded_now) if loaded_now
                                    else _NO_CALL_MSG),
                    })
                    self._tool_choice_next = "required"
                    self._log({"event": "intent_without_call", "turn": turn,
                               "rescue": intent_rescues,
                               "tool_choice": "required",
                               "unloaded_namespaces": sorted(
                                   {ns for _alias, ns in unloaded}),
                               "namespaces_loaded": loaded_now})
                    self.ui.warn(
                        "reply described a tool call but issued none — "
                        + ("loaded " + ", ".join(loaded_now) + " for it"
                           if loaded_now else "")
                        + (" — named tools whose namespace is not loaded: "
                           + ", ".join(sorted({ns for _a, ns in still}))
                           if still else "")
                        + ("" if unloaded else "asked for the call"))
                    continue
                if turn_tool_calls:
                    intent_rescues = 0
                    cut_offs = 0
                    empty_replies = 0
                    if resp.tool_calls:
                        count = self._tool_count()
                        tools_ok_at = max(tools_ok_at, count)
                        self._tools_ok_at = tools_ok_at
                        tool_budget_strikes = 0
                        remembered = 0
                        if self._tool_probe_at:
                            # The tested list delivered a call: its size is
                            # the ceiling from now on, for this model.
                            if count > self._tool_probe_floor:
                                remembered = count
                                self._log({"event": "tool_budget_raised", "turn": turn,
                                           "max_tools": count,
                                           "namespace": self._tool_probe_ns})
                            self._tool_probe_at = 0
                            self._tool_probe_ns = ""
                        elif tool_budget_pending:
                            remembered = tool_budget_pending
                            self._log({"event": "tool_budget_learned", "turn": turn,
                                       "max_tools": tool_budget_pending})
                            tool_budget_pending = 0
                        if remembered:
                            learn = getattr(self.client, "learn_max_tools", None)
                            if learn is not None:
                                try:
                                    learn(remembered)
                                except Exception:  # noqa: BLE001 - remembering is best effort
                                    pass
                if not turn_tool_calls:
                    quiet_turns += 1
                    # Evaluated once per empty turn and reused below: every
                    # branch of the quiet path needs to know whether this is
                    # a protocol stall (forensic tools gated on a cold DAIR
                    # window) or a genuinely finished model, and they must
                    # not disagree with each other.
                    stalled = self._dair_stall_pending(resp.content)
                    if quiet_turns >= 2:
                        if (dair_reengage_used < DAIR_REENGAGE_MAX
                                and stalled):
                            dair_reengage_used += 1
                            quiet_turns = 0
                            self.messages.append({
                                "role": "user",
                                "content": _DAIR_REENGAGE_MSG,
                            })
                            self._log({
                                "event": "dair_reengage_nudge",
                                "turn": turn,
                                "attempt": dair_reengage_used,
                            })
                            self.ui.info(
                                "quiet while DAIR window is cold — "
                                f"re-engage nudge "
                                f"{dair_reengage_used}/{DAIR_REENGAGE_MAX}")
                            continue
                        if not wrapped_up and not self._report_written():
                            # Going quiet without a report: force one wrap-up
                            # round before accepting the quiet death.
                            wrapped_up = True
                            quiet_turns = 0
                            # Name the real blocker when there is one. The
                            # close-out steps stay in the message either way,
                            # so this can never cost the run its report.
                            _wrap_body = _WRAPUP_MSG.format(
                                left=max(1, turn_limit - turn))
                            self.messages.append({
                                "role": "user",
                                "content": (_WRAPUP_BLOCKER_PREFIX + _wrap_body
                                            if stalled else _wrap_body)})
                            self._log({"event": "budget_wrapup",
                                       "turn": turn, "trigger": "quiet",
                                       "blocker": "dair" if stalled else ""})
                            _quiet_escape = False
                            try:
                                from core.coverage_ledger import (
                                    ready_for_degraded_exit,
                                )
                                _quiet_escape = bool(
                                    ready_for_degraded_exit(self.case_dir))
                            except Exception:
                                _quiet_escape = False
                            self._record_budget_wrapup_marker(
                                "quiet", turn,
                                allow_synthesize_escape=_quiet_escape)
                            self.ui.info("quiet without report — wrap-up "
                                         "injected")
                            turn_limit, blocker_extension_granted, _ = (
                                self._grant_blocker_extension(
                                    turn=turn,
                                    turn_limit=turn_limit,
                                    granted_so_far=blocker_extension_granted))
                            continue
                        # Still quiet after wrap-up: extend if blockers open
                        # instead of abandoning mid-close-out.
                        turn_limit, blocker_extension_granted, granted = (
                            self._grant_blocker_extension(
                                turn=turn,
                                turn_limit=turn_limit,
                                granted_so_far=blocker_extension_granted))
                        if granted:
                            quiet_turns = 0
                            continue
                        # A run that has recorded no belief has not finished;
                        # it has failed to start, and a model that answers
                        # "I need to issue the tool call now" without issuing
                        # one is malfunctioning rather than done. Stopping
                        # there files a completed investigation that never
                        # happened, and the evidence is untouched. Keep
                        # asking while there is nothing to show, bounded so a
                        # wedged model still ends instead of looping.
                        if (no_work_rescues < NO_WORK_RESCUES_MAX
                                and self._claim_count() == 0
                                and not self._report_written()):
                            no_work_rescues += 1
                            quiet_turns = 0
                            self.messages.append({
                                "role": "user", "content": _NO_CALL_MSG})
                            self._log({"event": "no_work_rescue",
                                       "turn": turn,
                                       "attempt": no_work_rescues})
                            self.ui.warn(
                                "quiet with nothing recorded — asked for the "
                                f"call ({no_work_rescues}/"
                                f"{NO_WORK_RESCUES_MAX})")
                            continue
                        # "quiet" reads as "the model had nothing left to
                        # do". When forensic work is still gated that is
                        # false and misleading to the operator — the run
                        # died on a protocol gate, not on completion.
                        # classify_finish_status treats both identically,
                        # so the coverage verdict is unchanged.
                        if finish_requested and not stalled:
                            stopped_reason = "finish_deferred"
                        else:
                            stopped_reason = "stall" if stalled else "quiet"
                        self.ui.info(
                            "agent stopped: forensic tools still gated on "
                            "dair_assess (protocol stall)" if stalled else
                            "agent stopped: no tool calls for two "
                            "consecutive turns")
                        break
                    self.messages.append({
                        "role": "user",
                        "content": _DAIR_CONTINUE_MSG if stalled else (
                            "Continue the investigation. If "
                            "reason.pre_report_check is not yet "
                            "READY_TO_REPORT:true, finish its "
                            "blocking_issues first; only then write "
                            "the final report and call atlas_finish."),
                    })
                    continue
                quiet_turns = 0
                # Provisional: cleared here because the turn produced a batch,
                # but restored below if every result came back protocol-
                # blocked. A turn that achieved nothing must not refill the
                # re-engage budget, or the blocked-streak ladder nudges
                # forever without ever escalating.
                reengage_used_before_batch = dair_reengage_used
                dair_reengage_used = 0

                done = False
                batch_issues: list[dict] = []
                batch_cleared = False
                # Tools that ran cleanly this turn: a corrected retry answers
                # the failure the investigate latch is holding for that tool.
                batch_succeeded: set[str] = set()
                batch_reads: list[tuple[str, list[str]]] = []
                # A turn whose every tool result came back protocol-blocked
                # achieved nothing, but it is not "quiet" either — see the
                # blocked-streak ladder after this loop.
                batch_blocked = 0
                batch_executed = 0
                _sizes = getattr(self, "_recent_batch_sizes", None)
                if _sizes is None:
                    _sizes = self._recent_batch_sizes = collections.deque(maxlen=3)
                _sizes.append(len(turn_tool_calls))
                turn_tool_calls, reply_dups = self._split_reply_duplicates(turn, turn_tool_calls, memo)
                batch_left = 0
                batch_runaway = False
                if len(turn_tool_calls) > CALLS_PER_TURN_MAX:
                    batch_left = len(turn_tool_calls) - CALLS_PER_TURN_MAX
                    self._log({"event": "batch_bounded", "turn": turn,
                               "sent": len(turn_tool_calls),
                               "ran": CALLS_PER_TURN_MAX, "left": batch_left})
                    self.ui.warn(
                        f"reply carried {len(turn_tool_calls)} tool calls — "
                        f"running the first {CALLS_PER_TURN_MAX}, handing "
                        f"{batch_left} back")
                    batch_runaway = (len(turn_tool_calls)
                                     >= BATCH_RUNAWAY_FACTOR * CALLS_PER_TURN_MAX)
                    if batch_runaway:
                        _names = sorted({tc.name for tc in turn_tool_calls})
                        self._log({"event": "batch_runaway", "turn": turn,
                                   "sent": len(turn_tool_calls),
                                   "cap": CALLS_PER_TURN_MAX,
                                   "distinct_tools": len(_names),
                                   "tools": _names[:8]})
                        self.ui.warn(
                            f"runaway reply: {len(turn_tool_calls)} tool calls "
                            f"across {len(_names)} tool(s), "
                            f"{BATCH_RUNAWAY_FACTOR}x the per-reply cap")
                    turn_tool_calls = turn_tool_calls[:CALLS_PER_TURN_MAX]
                _batch_grace_begin()
                # Any load during the batch (a call to an unloaded tool,
                # the model loading a namespace, the director's order) may
                # test the learned ceiling; the reply after the batch is
                # what the test reads.
                self.toolbox.tool_probe_limit = self._tool_probe_limit()
                for tc in turn_tool_calls:
                    if tc.name == "atlas_finish":
                        self._estate_join(turn)
                        critical_debt = self._critical_scan_debt()
                        from agent.tool_investigate import (
                            finish_blocking_issues,
                            format_finish_refusal,
                        )
                        blocking = finish_blocking_issues(investigate_debt)
                        coverage_refusal = ("" if (blocking or critical_debt)
                                            else self._finish_coverage_check(
                                                wall_expired=wall_expired))
                        report_refusal = (
                            "" if (blocking or critical_debt or coverage_refusal)
                            else self._finish_report_check(
                                wall_expired=wall_expired))
                        if blocking or critical_debt:
                            result = format_finish_refusal(
                                investigate_debt, critical_debt)
                            self.ui.warn("atlas_finish refused — investigate "
                                         "open failures first")
                            self._log({"event": "atlas_finish_refused",
                                       "turn": turn,
                                       "investigate": len(blocking),
                                       "critical_debt": len(critical_debt)})
                        elif coverage_refusal:
                            # One redirect back to concrete open evidence —
                            # never a hard stop: a second atlas_finish (or a
                            # wall-clock/wrap-up trigger) always goes through
                            # and is truthfully classified incomplete.
                            result = coverage_refusal
                            self.ui.warn("atlas_finish deferred — high-value "
                                         "evidence still unexamined")
                            finish_requested = True
                            self._log({
                                "event": "atlas_finish_coverage_deferred",
                                "turn": turn,
                            })
                        elif report_refusal:
                            # Same one-shot shape as the coverage deferral.
                            result = report_refusal
                            self.ui.warn("atlas_finish deferred — no official "
                                         "report written yet")
                            finish_requested = True
                            self._log({
                                "event": "atlas_finish_report_deferred",
                                "turn": turn,
                            })
                        else:
                            finish_summary = str(
                                tc.arguments.get("summary") or "")
                            result = "Run ended."
                            done = True
                    else:
                        def _gates(_name, _args, tc=tc):
                            """The conversation loop's own gates, between the
                            memo and the run: the wrap-up ration and the
                            belief-starvation latch."""
                            nonlocal wrapup_explore_calls
                            # Wrap-up: exploration is rationed so the close-out
                            # sequence is reachable before the cap.
                            if (wrapup_rationed and not self._report_written()
                                    and not _CLOSEOUT_TOOL_RE.search(tc.name or "")):
                                wrapup_explore_calls += 1
                                if wrapup_explore_calls > WRAPUP_EXPLORE_CALLS:
                                    result = json.dumps({
                                        "success": False,
                                        "gate": "wrapup_exploration_budget",
                                        "error": _WRAPUP_EXPLORE_REFUSAL.format(
                                            tool=tc.name, budget=WRAPUP_EXPLORE_CALLS),
                                    }, indent=2)
                                    self.ui.warn(f"refused {tc.name} — wrap-up "
                                                 "exploration budget spent")
                                    self._log({"event": "tool_result", "turn": turn,
                                               "tool": tc.name,
                                               "result": result[:4000],
                                               "gate": "wrapup_exploration_budget"})
                                    return result
                            # Refuse exploratory tools while belief-starvation
                            # latch is active (must formalise findings first).
                            if belief_latched:
                                try:
                                    from agent.belief_starvation import (
                                        starvation_refusal,
                                        tool_allowed_while_latched,
                                    )
                                    if (not tool_allowed_while_latched(tc.name)
                                            and not self._reaches_due_item(tc.name, tc.arguments)):
                                        result = starvation_refusal(
                                            tc.name,
                                            contacts=belief_contacts,
                                        )
                                        self.ui.warn(
                                            f"refused {tc.name} — "
                                            f"belief-starvation latch")
                                        self._log({
                                            "event": "tool_result",
                                            "turn": turn,
                                            "tool": tc.name,
                                            "result": result[:4000],
                                            "gate": "belief_starvation",
                                        })
                                        return result
                                except Exception as _bs_enforce_err:
                                    # Fail-open (the tool call proceeds below).
                                    # A silent failure would disable the
                                    # already-latched gate for the rest of the
                                    # run with no trace of why, so log it the
                                    # way the sibling latch-computation
                                    # try/except above does.
                                    self._log({
                                        "event": "belief_starvation_check_failed",
                                        "turn": turn,
                                        "tool": tc.name,
                                        "error": str(_bs_enforce_err)[:200],
                                    })
                            return None
                        # A model call, counted for the finish deferral (a
                        # finish with none since the last deferral ends the
                        # run); Atlas's own calls through _call_once are no
                        # model work.
                        self._model_calls = getattr(self, "_model_calls", 0) + 1
                        _out = self._call_once(tc.name, tc.arguments, turn=turn, tool_call_id=tc.id,
                                               before_run=_gates, in_context=self._result_still_in_context)
                        result = _out["result"]
                        if _out["kind"] != "ran":
                            self.messages.append({"role": "tool", "tool_call_id": tc.id,
                                                  "content": result})
                            continue
                        if tc.name.endswith("pre_report_check"):
                            wrapup_explore_calls = 0   # blockers may need probes
                        _ran_clean = _out["ran_clean"]
                        issue = _out["issue"]
                        from agent.tool_investigate import input_paths
                        if issue:
                            batch_issues.append(issue)
                        elif _ran_clean:
                            batch_succeeded.add(tc.name or "")
                            batch_reads.append((tc.name or "", input_paths(tc.arguments)))
                        if tc.name.endswith("dair_assess"):
                            batch_cleared = True
                            self._note_dair_phase(result)
                        if (tc.name.endswith("synthesize")
                                and getattr(self, "_dair_phase", "") == "Report"):
                            self._report_synth_calls = getattr(self, "_report_synth_calls", 0) + 1
                        elif (issue is None
                              and _CRITICAL_CLEAR_NAME_RE.search(tc.name)
                              and not result.startswith(
                                  ("TOOL ERROR", "ERROR", "TOOL INFO"))
                              and ('"success": true' in result.lower()
                                   or '"success":true' in result.lower())):
                            batch_cleared = True
                        # Mid-batch: record_finding in this turn must unlock
                        # later tools in the same batch (not only next turn).
                        if belief_latched and "record_finding" in (
                                tc.name or "").lower():
                            try:
                                from agent.belief_starvation import (
                                    starvation_latched as _bs_mid,
                                )
                                from core.execution_log import (
                                    log as _bs_elog_mid,
                                )
                                belief_latched = _bs_mid(
                                    list(_bs_elog_mid._entries or []),
                                    case_dir=self.case_dir)
                            except Exception:
                                pass
                    batch_executed += 1
                    if _PROTOCOL_MARKER and _PROTOCOL_MARKER in (result or ""):
                        batch_blocked += 1
                    self.messages.append({"role": "tool", "tool_call_id": tc.id,
                                          "content": result})
                    self._log({"event": "tool_result", "turn": turn,
                               "tool": tc.name, "result": result[:4000],
                               **self._last_tool_flags(tc.name)})
                    _refused = (result.startswith(("TOOL INFO", "TOOL ERROR", "ERROR"))
                                or bool(_PROTOCOL_MARKER and _PROTOCOL_MARKER in result[:300])
                                or ('"success": false' in result[:300]
                                    and '"gate"' in result[:600]))
                    refusal_streak = refusal_streak + 1 if _refused else 0
                    if (DEADLOCK_REFUSALS > 0 and refusal_streak >= DEADLOCK_REFUSALS
                            and not deadlock_warned):
                        deadlock_warned = True
                        import re as _re
                        _gates = sorted({m for m in _re.findall(
                            r'"gate":\s*"([^"]+)"',
                            " ".join(str(m.get("content") or "")
                                     for m in self.messages[-3 * DEADLOCK_REFUSALS:]
                                     if m.get("role") == "tool"))})
                        self._nudge("protocol_deadlock", _DEADLOCK_MSG.format(
                            n=DEADLOCK_REFUSALS, gates=", ".join(_gates) or "protocol gates"))
                        self._log({"event": "protocol_deadlock", "turn": turn,
                                   "refusals": refusal_streak, "gates": _gates})
                        self.ui.warn(f"{refusal_streak} consecutive refused tool calls")
                self.toolbox.tool_probe_limit = 0
                self._adopt_tool_probe(turn)
                self._answer_reply_duplicates(reply_dups)
                self._prune_unanswered_tool_calls()
                if batch_left:
                    _bounded = dict(sent=batch_left + CALLS_PER_TURN_MAX,
                                    ran=CALLS_PER_TURN_MAX, left=batch_left)
                    self.messages.append({
                        "role": "user",
                        "content": _BATCH_TRUNCATED_MSG.format(**_bounded) + (
                            _BATCH_RUNAWAY_MSG.format(**_bounded)
                            if batch_runaway else "")})
                if resp.finish_reason == "length" and any(
                        "_malformed_arguments" in (tc.arguments or {})
                        for tc in turn_tool_calls):
                    # The call's arguments were cut with the reply. Asked
                    # again as written it would be cut again; the note says
                    # what to shorten.
                    longest = [
                        f"{tc.arguments['_longest_argument']} on {tc.name}"
                        for tc in turn_tool_calls
                        if (tc.arguments or {}).get("_longest_argument")]
                    self.messages.append({"role": "user", "content": _CUT_CALL_MSG + (
                        f" Most of the reply went into {'; '.join(longest)}."
                        if longest else "")})
                    self._log({"event": "call_cut_off", "turn": turn,
                               "tools": [tc.name for tc in turn_tool_calls],
                               "longest_argument": longest})
                    self.ui.warn("a tool call's arguments were cut with the "
                                 "reply — asked for a shorter call")
                if turn_tool_calls and all(
                        tc.name in _NAMESPACE_META_TOOLS for tc in turn_tool_calls):
                    meta_only_streak += 1
                else:
                    meta_only_streak = 0
                if meta_only_streak >= META_ONLY_TURNS_MAX:
                    # Load what the director asked for, then name the call.
                    loaded_now = self._load_namespaces_for(
                        self._last_director_tools, turn=turn)
                    loaded_set = sorted(set(getattr(self.toolbox, "loaded", ()) or ()))
                    named = [str(t)[:60] for t in self._last_director_tools[:6]]
                    self.messages.append({
                        "role": "user",
                        "content": (_META_ONLY_STABLE_MSG if _list_stable(self.toolbox)
                                    else _META_ONLY_MSG).format(
                            streak=meta_only_streak,
                            loaded=", ".join(loaded_set) or "none",
                            tools=", ".join(named) or "no work order yet; call "
                                                       "dair_assess")})
                    self._log({"event": "meta_only_streak", "turn": turn,
                               "streak": meta_only_streak,
                               "namespaces_loaded": loaded_now})
                    self.ui.warn(
                        f"{meta_only_streak} replies loaded namespaces and called "
                        "no tool — named the director's work order")
                    meta_only_streak = 0
                if (len(turn_tool_calls) == 1
                        and (turn_tool_calls[0].name or "").endswith("dair_assess")
                        and self._last_dair_unchanged):
                    director_reask_streak += 1
                else:
                    director_reask_streak = 0
                if director_reask_streak >= DIRECTOR_REASK_STREAK:
                    # Asked again and again with no batch between: the
                    # answer is the one it already gave. Name the action.
                    if (getattr(self, "_dair_phase", "") == "Report"
                            or self._director_reask_exhausted(turn)):
                        # In Report the answer is the report, not the work
                        # order of an earlier phase: ask for it while it is
                        # owed, and for the close-out once it is written.
                        # Each such round is a report-phase push: three of
                        # them with nothing new recorded wrap the run up.
                        # Outside Report the work order is named first; once
                        # naming it has changed nothing, asking again with
                        # the same words would not either, and the run is
                        # put on the same ladder.
                        if self._report_written():
                            self._nudge("report_done", _REPORT_DONE_MSG)
                        elif wrapped_up:
                            # Wrapped up already: the close-out clock starts
                            # here if nothing started it, and no second
                            # wrap-up message is appended.
                            self._nudge("report_phase_stall", self._report_stall_msg())
                            if report_wrapup_turn is None:
                                report_wrapup_turn = turn
                        elif self._push_report_phase(turn, reason="director_reask"):
                            wrapped_up = True
                            wrapup_rationed = True
                            report_wrapup_turn = turn
                    else:
                        named = [str(t)[:60] for t in self._last_director_tools[:6]]
                        self.messages.append({
                            "role": "user",
                            "content": _DIRECTOR_REASK_MSG.format(
                                streak=director_reask_streak,
                                tools=", ".join(named) or "nothing yet: run the "
                                                          "next batch of evidence work")})
                    self._log({"event": "director_reask_streak", "turn": turn,
                               "streak": director_reask_streak,
                               "phase": getattr(self, "_dair_phase", ""),
                               "fires": getattr(self, "_director_reask_fires", 0)})
                    self.ui.warn(f"{director_reask_streak} director calls in a row "
                                 "with nothing between them — named the action")
                    director_reask_streak = 0
                if batch_succeeded:
                    # Settle before merging: a tool that failed again in the
                    # same batch after a clean run re-enters through the merge.
                    from agent.tool_investigate import settle_investigate_debt
                    investigate_debt = settle_investigate_debt(
                        investigate_debt, batch_succeeded, batch_reads)
                if batch_issues:
                    from agent.tool_investigate import merge_investigate_debt
                    investigate_debt = merge_investigate_debt(
                        investigate_debt, batch_issues)
                elif batch_cleared:
                    investigate_debt = []
                else:
                    # Drop exhausted bad_args so the latch stops nagging after
                    # IDENTICAL_FAIL_LIMIT identical analyst-error retries.
                    from agent.tool_investigate import prune_exhausted_debt
                    investigate_debt = prune_exhausted_debt(investigate_debt)
                # Re-evaluate latch after the batch (a successful
                # record_finding clears it for the next turn).
                try:
                    from agent.belief_starvation import starvation_latched
                    from core.execution_log import log as _bs_elog2
                    belief_latched = starvation_latched(
                        list(_bs_elog2._entries or []), case_dir=self.case_dir)
                except Exception:
                    pass

                # Blocked-streak ladder. The quiet valve above only fires on
                # turns with NO tool calls, but a model that keeps *calling*
                # DAIR-blocked forensic tools produces a full batch every
                # turn while achieving nothing — and each such turn resets
                # quiet_turns/dair_reengage_used, so the quiet valve can
                # never fire. Pseudo-tool recovery made that state easier to
                # reach (a call recovered from message text counts as a
                # batch too), so this ladder mirrors the quiet one exactly:
                # the same capped re-engage nudges, then the same
                # blocker-prefixed wrap-up, then the same "stall" label.
                # Deliberately keyed on every-result-blocked: one blocked
                # call alongside one that worked is still progress.
                if batch_executed and batch_blocked == batch_executed:
                    blocked_turns += 1
                    dair_reengage_used = reengage_used_before_batch
                else:
                    blocked_turns = 0
                if not done and blocked_turns >= DAIR_BLOCKED_TURNS_MAX:
                    if dair_reengage_used < DAIR_REENGAGE_MAX:
                        dair_reengage_used += 1
                        blocked_turns = 0
                        self.messages.append({"role": "user",
                                              "content": _DAIR_REENGAGE_MSG})
                        self._log({"event": "dair_reengage_nudge",
                                   "turn": turn,
                                   "attempt": dair_reengage_used,
                                   "trigger": "blocked_streak"})
                        self.ui.info(
                            "every tool call blocked on a cold DAIR window — "
                            f"re-engage nudge {dair_reengage_used}/"
                            f"{DAIR_REENGAGE_MAX}")
                    elif not wrapped_up and not self._report_written():
                        wrapped_up = True
                        blocked_turns = 0
                        self.messages.append({
                            "role": "user",
                            "content": _WRAPUP_BLOCKER_PREFIX + _WRAPUP_MSG.format(
                                left=max(1, turn_limit - turn))})
                        self._log({"event": "budget_wrapup", "turn": turn,
                                   "trigger": "blocked_streak",
                                   "blocker": "dair"})
                        self.ui.info("blocked-tool streak without report — "
                                     "wrap-up injected")
                    else:
                        stopped_reason = "stall"
                        self.ui.info(
                            "agent stopped: every tool call blocked on "
                            "dair_assess (protocol stall)")
                        break
                if done:
                    break

        return self._run_end(turn, stopped_reason, finish_summary)

    def _run_end(self, turn: int, stopped_reason: str, finish_summary: str) -> str:
        """The end every loop shares: the estate join, the unsupported
        answers reopened, the finish status and its disclosure, the stats
        and the run_end record."""
        memo = self._call_memo
        run_start = self._run_start
        # A count pass still reading its tables is waited for and applied:
        # its indicators were marked counted when it started.
        self._estate_join(turn)
        # The memory batch is never awaited: still running, it is stopped
        # here and what it did not run is disclosed (core.memory_batch).
        try:
            from core.memory_batch import stop as _stop_memory_batch
            if self.case_dir:
                _stop_memory_batch(self.case_dir)
        except Exception:  # noqa: BLE001
            pass
        # Before the run is classified: a task the model marked answered
        # over no current belief is not answered. Reopening it here keeps
        # the dashboard, the report and finish_status telling one story.
        try:
            from core.investigation_tasks import repair_unsupported_answers
            if self.case_dir:
                _reopened = repair_unsupported_answers(self.case_dir)
                if _reopened:
                    self._log({"event": "tasks_reopened_unsupported",
                               "task_ids": _reopened})
                    self.ui.info(
                        f"{len(_reopened)} question(s) were marked answered "
                        "without a supporting belief — reopened")
        except Exception:  # noqa: BLE001 - never block the close-out
            pass
        finish_status = self._finish_status(stopped_reason)
        coverage_disclosure: dict = {}
        try:
            from core.deferred_intents import work_order_on
            if work_order_on() and self.case_dir:
                from core.investigation_exit import completion_disclosure
                coverage_disclosure = completion_disclosure(self.case_dir)
        except Exception:  # noqa: BLE001 - a disclosure never blocks the close-out
            coverage_disclosure = {}
        self.stats = {
            "summary": finish_summary,
            "stopped_reason": stopped_reason,
            "finish_status": finish_status,
            "coverage_disclosure": coverage_disclosure,
            "turns": turn,
            "duration_seconds": round(time.monotonic() - run_start, 1),
            "tool_calls": self._tool_stats,
            "findings_recorded": self._count_recorded_findings(),
            "input_tokens": self.client.total_input_tokens,
            "output_tokens": self.client.total_output_tokens,
            "transcript": str(self.transcript_path or ""),
            "distinct_tool_calls": len(memo),
            "identical_calls_replayed": memo.replays,
            "identical_calls_pointed": memo.pointers,
            "roles": _role_models_safe(),
        }
        self._log({"event": "run_end", "summary": finish_summary,
                   "finish_status": finish_status,
                   "coverage_disclosure": coverage_disclosure,
                   "distinct_tool_calls": len(memo),
                   "identical_calls_replayed": memo.replays,
                   "identical_calls_pointed": memo.pointers,
                   "total_input_tokens": self.client.total_input_tokens,
                   "total_output_tokens": self.client.total_output_tokens})
        self.ui.finish(finish_summary, stats=self.stats)
        self.ui.tokens(self.client.total_input_tokens,
                       self.client.total_output_tokens)
        if self.transcript_path:
            self.ui.info(f"transcript: {self.transcript_path}")
        return finish_summary

    # ── interactive chat ─────────────────────────────────────────────────

    def _slash(self, line: str) -> bool:
        """Handle a slash command line (command plus optional arguments).
        Returns False when the REPL should exit."""
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ("/quit", "/exit"):
            return False
        if cmd == "/help":
            self.ui.help()
        elif cmd == "/case":
            self._slash_case(args[0] if args else None)
        elif cmd == "/report":
            self._slash_report()
        elif cmd == "/history":
            self._slash_history()
        elif cmd == "/save":
            self._slash_save(args[0] if args else None)
        elif cmd == "/resume":
            self._slash_resume(args[0] if args else "latest")
        elif cmd == "/tools":
            names = sorted(t.alias for t in self.toolbox.tools.values()
                           if t.namespace in self.toolbox.loaded)
            self.ui.info(f"loaded namespaces: "
                         f"{', '.join(sorted(self.toolbox.loaded))}")
            self.ui.info("\n".join(names))
        elif cmd == "/namespaces":
            self.ui.info(self.toolbox.namespace_summary())
        elif cmd == "/model":
            self.ui.info(f"model {self.client.model} @ {self.client.base_url}")
        elif cmd == "/tokens":
            self.ui.tokens(self.client.total_input_tokens,
                           self.client.total_output_tokens)
        elif cmd == "/clear":
            self.messages = self.messages[:1]  # keep the system prompt
            self.ui.info("conversation cleared")
        else:
            self.ui.warn(f"unknown command {cmd} — try /help")
        return True

    # ── slash-command helpers ────────────────────────────────────────────

    def _slash_case(self, new_dir: str | None) -> None:
        if new_dir is None:
            if not self.case_dir:
                self.ui.info("no case directory — /case DIR to set one")
                return
            self.ui.info(f"case: {self.case_dir}")
            for sub in ("evidence", "analysis", "exports", "reports"):
                mark = "✓" if (self.case_dir / sub).is_dir() else "✗"
                self.ui.info(f"  {mark} {sub}/")
            if self.transcript_path:
                self.ui.info(f"transcript: {self.transcript_path}")
            return
        case = Path(new_dir).expanduser().resolve()
        if not case.is_dir():
            self.ui.warn(f"not a directory: {case}")
            return
        os.chdir(case)  # tool modules resolve the case from the cwd
        self.case_dir = case
        self.transcript_path = self._transcript_path()
        # The usage ledger follows the switch: the new case, a run of its own.
        try:
            from core import usage_ledger
            from core.paths import detect_case_id
            usage_ledger.configure(
                case_id=detect_case_id(case) or case.name,
                run_id=self.transcript_path.stem.rsplit("_", 1)[-1]
                if self.transcript_path else "")
        except Exception:  # noqa: BLE001 - bookkeeping never stops a session
            pass
        self.ui.info(f"switched to case {case}")
        self.ui.warn("the system prompt still references the previous case — "
                     "/clear is recommended before continuing")

    def _find_latest_report(self) -> Path | None:
        if not self.case_dir:
            return None
        candidates = []
        for sub in ("reports", "analysis"):
            d = self.case_dir / sub
            if d.is_dir():
                candidates += [p for p in d.glob("*.md") if p.is_file()]
        return max(candidates, key=lambda p: p.stat().st_mtime,
                   default=None)

    def _slash_report(self) -> None:
        report = self._find_latest_report()
        if report is None:
            self.ui.warn("no report found under reports/ or analysis/")
            return
        self.ui.info(f"report: {report}")
        try:
            self.ui.markdown(report.read_text(encoding="utf-8"))
        except OSError as e:
            self.ui.error(f"cannot read report: {e}")

    def _slash_history(self) -> None:
        turns = [m for m in self.messages
                 if m.get("role") in ("user", "assistant")]
        for m in turns[-10:]:
            first_line = (str(m.get("content") or "").strip()
                          or "(tool calls)").splitlines()[0]
            self.ui.info(f"{m['role']:>9}: {first_line[:160]}")
        if self.transcript_path:
            self.ui.info(f"transcript: {self.transcript_path}")

    def _session_dir(self) -> Path | None:
        if not self.case_dir:
            self.ui.warn("no case directory — sessions are saved under "
                         "the case's analysis/")
            return None
        out = self.case_dir / "analysis"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def _slash_save(self, name: str | None) -> None:
        out = self._session_dir()
        if out is None:
            return
        stamp = name or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = out / f"agent_session_{stamp}.json"
        path.write_text(json.dumps(self.messages, ensure_ascii=False,
                                   default=str, indent=2), encoding="utf-8")
        self.ui.info(f"session saved: {path}")

    def _slash_resume(self, which: str) -> None:
        if which == "latest":
            out = self._session_dir()
            if out is None:
                return
            path = max(out.glob("agent_session_*.json"),
                       key=lambda p: p.stat().st_mtime, default=None)
            if path is None:
                self.ui.warn("no saved sessions in analysis/ — /save first")
                return
        else:
            path = Path(which).expanduser()
            if not path.is_file():
                self.ui.warn(f"no such session file: {path}")
                return
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            self.ui.error(f"cannot load session: {e}")
            return
        # Keep the current system prompt (prompts may have changed since the
        # save); restore everything after it.
        restored = [m for m in saved if m.get("role") != "system"]
        self.messages = self.messages[:1] + restored
        self._repair_pending_tool_calls()
        self.ui.info(f"restored {len(restored)} messages from {path.name}")

    def run_chat_turn(self, user: str, on_event=None) -> str:
        """Run one chat turn against the existing conversation: append the user
        message, run tool-calling rounds until the model answers in plain text,
        and return that answer.

        Round budget is ``ATLAS_CHAT_MAX_TOOL_ROUNDS`` (default 0 = unlimited).
        A positive value caps rounds; hitting the cap emits an explicit error
        via ``on_event`` instead of returning an empty string.

        Shared by the interactive CLI REPL (chat) and the dashboard chat
        worker. `on_event`, when given, is called with small dicts describing
        activity as it happens — {"type": "tool_call", ...} before each tool
        runs and {"type": "assistant", "text": ...} for the final answer — so a
        non-terminal frontend can stream progress. The UI is driven too, so CLI
        rendering is unchanged. Exceptions (KeyboardInterrupt, LLMError) are
        left for the caller to handle."""
        self.messages.append({"role": "user", "content": user})
        self._log({"event": "user", "content": user})
        answer = ""
        max_rounds = CHAT_MAX_TOOL_ROUNDS
        round_i = 0
        pseudo_nudges = 0
        pseudo_recovered = 0
        empty_replies = 0
        # Run tool calls until the model answers in plain text.
        while max_rounds <= 0 or round_i < max_rounds:
            round_i += 1
            self._trim_context()
            _batch_grace_end()
            resp = self._chat_turn()
            refusal = getattr(resp, "refusal", None)
            if refusal is not None:
                # Declined by the provider: said where the answer would have
                # appeared, never asked again.
                why = (refusal.get("explanation") or "").strip().rstrip(".")
                answer = (f"The provider declined this request (category: "
                          f"{refusal.get('category') or 'not given'})" + (f": {why}" if why else "") + ".")
                self._log({"event": "error", "content": answer})
                if on_event:
                    on_event({"type": "error", "message": answer})
                break
            tool_calls = list(resp.tool_calls)
            if not tool_calls and resp.content:
                # Recovery is capped even when max_rounds is unlimited (the
                # default): a model that keeps writing recoverable tool calls
                # as text, and never answers in plain prose, would otherwise
                # loop here forever burning tokens. Past the cap we stop
                # recovering, which drops through to the nudge and then to
                # the plain-answer break below.
                recovered = (
                    self._recover_tool_calls_from_content(resp.content)
                    if pseudo_recovered < _CHAT_MAX_PSEUDO_RECOVERIES else [])
                if recovered:
                    pseudo_recovered += 1
                    self._attach_tool_calls_to_last_assistant(recovered)
                    tool_calls = recovered
                    self._log({"event": "pseudo_tool_recovered",
                               "tools": [tc.name for tc in recovered],
                               "recovery": pseudo_recovered})
                elif (self._content_looks_like_pseudo_tool(resp.content)
                      and pseudo_nudges < 2):
                    pseudo_nudges += 1
                    self._log({"event": "pseudo_tool_nudge",
                               "nudge": pseudo_nudges})
                    if on_event:
                        on_event({"type": "assistant",
                                  "text": resp.content or ""})
                    self.messages.append({
                        "role": "user", "content": _CHAT_PSEUDO_NUDGE})
                    continue
            self._log({"event": "assistant", "content": resp.content,
                       "tool_calls": [(tc.name, tc.arguments)
                                      for tc in tool_calls]})
            if not tool_calls and not (resp.content or "").strip():
                # Nothing to show. Silence is not an answer: ask again,
                # bounded by consecutive empties as in the run loop, then
                # say so where the answer would have appeared.
                empty_replies += 1
                self._log({"event": "empty_reply_nudge",
                           "consecutive": empty_replies,
                           "output_tokens": int(
                               getattr(resp, "output_tokens", 0) or 0)})
                if empty_replies <= EMPTY_REPLY_NUDGES_MAX:
                    self.messages.append({"role": "user",
                                          "content": _CHAT_EMPTY_REPLY_MSG})
                    continue
                answer = (f"The model returned {empty_replies} empty replies "
                          "in a row (no text, no tool call). Ask again, or "
                          "rephrase the question.")
                self.ui.warn(answer)
                self._log({"event": "error", "content": answer})
                if on_event:
                    on_event({"type": "error", "message": answer})
                break
            empty_replies = 0
            if not tool_calls:
                self.ui.assistant(resp.content)
                answer = resp.content or ""
                if on_event:
                    on_event({"type": "assistant", "text": answer})
                break
            for tc in tool_calls:
                if tc.name == "atlas_finish":
                    result = "Noted."
                else:
                    if on_event:
                        on_event({"type": "tool_call", "name": tc.name,
                                  "args_preview": json.dumps(
                                      tc.arguments, default=str)[:200]})
                    result = self._run_tool(tc)
                self.messages.append({"role": "tool",
                                      "tool_call_id": tc.id,
                                      "content": result})
                self._log({"event": "tool_result", "tool": tc.name,
                           "result": result[:4000]})
        else:
            # Finite cap exhausted without a plain-text answer.
            answer = (
                f"Stopped after {max_rounds} tool rounds without a final "
                f"answer (ATLAS_CHAT_MAX_TOOL_ROUNDS). Ask again to continue, "
                f"or set ATLAS_CHAT_MAX_TOOL_ROUNDS=0 for unlimited rounds."
            )
            self.ui.warn(answer)
            self._log({"event": "error", "content": answer})
            if on_event:
                on_event({"type": "error", "message": answer})
        return answer

    def chat(self, system_prompt: str) -> None:
        self.messages = [{"role": "system", "content": system_prompt}]
        read_line = self.ui.make_prompt()
        self.ui.info("ask about the case — /help for commands, ctrl+d to exit")
        while True:
            try:
                user = read_line().strip()
            except KeyboardInterrupt:
                continue  # clear the line
            except EOFError:
                print()
                break
            if not user:
                continue
            if user.startswith("/"):
                if not self._slash(user):
                    break
                continue
            if user.lower() in ("exit", "quit"):
                break
            try:
                self.run_chat_turn(user)
            except KeyboardInterrupt:
                self._repair_pending_tool_calls()
                self.ui.warn("interrupted — conversation kept, ask away")
            except LLMError as e:
                self._repair_pending_tool_calls()
                self.ui.error(str(e))
