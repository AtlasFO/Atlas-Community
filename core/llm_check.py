"""Unified LLM Check — bind every send to the connected model's window.

Called at session start (after ``GET /models``) and before each chat request.

Why this exists
---------------
Overflow (request > window) is loud. Truncation is worse: the provider drops
the *head* of the prompt (system playbook, CASE.md, early findings) and the
run continues with forgotten gates. Atlas's previous char trim only *raised*
``ATLAS_AGENT_CONTEXT_CHARS`` for large windows and never shrank it, so a
16k model still received the 400k-char default.

This module:

1. **Probe result → session limits.** Default / recommended window is
   GLM-5.2's **1_000_000** tokens. Below **MIN_SENSIBLE_WINDOW** (32_000)
   Atlas still runs, but in compact / disk-first mode.
2. **Scale every budget from that window** — send chars, per-tool output
   cap, max tool schemas — both up (1M) and down (small local models).
3. **Fit the next request** before HTTP: estimate tokens of system +
   conversation + tool schemas; if over the send budget, compress the
   *body* of the conversation while keeping every ``role=system`` message
   intact (so playbook gates are never the thing that gets truncated).

Token counts are chars/4 (same estimate as ``context_budget``). Full tool
output remains in the execution trace when the in-chat copy is stubbed.

Callers (wired in this change):
- ``core/model_context.py`` ``apply_window`` / ``probe_and_apply``
- ``agent/loop.py`` ``_trim_context``
- ``core/context_budget.py`` ``resolve_window_tokens`` / ``compute``
- ``agent/toolbox.py`` tool-output / schema caps
- ``core/input_scale.py`` disk-first when below minimum
- tests under ``tests/core/test_llm_check.py``

No data files. Process-level ``_limits`` only.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

# GLM-5.2 (the LLM hub / OpenRouter z-ai/glm-5.2) — Atlas's recommended
# analyst window. Used when no live probe has run yet and the operator has
# not set ATLAS_MODEL_CONTEXT_TOKENS.
RECOMMENDED_WINDOW = 1_000_000
DEFAULT_WINDOW = RECOMMENDED_WINDOW

# Below this, Atlas can still run but must assume it cannot keep a full
# investigation in chat: compact policy, disk-first bulk parses, tighter
# tool-schema and per-tool output caps.
MIN_SENSIBLE_WINDOW = 32_000

# Headroom inside the window for completion + tool schemas (not history).
_SEND_FRACTION = 0.75

_TURN_STUB = (
    "[earlier turn omitted from context — full text is in the execution trace]"
)
_TOOL_STUB = (
    "[output trimmed from context — full text is in the execution trace]"
)

_limits: "SessionLimits | None" = None


def chars_to_tokens(n_chars: int) -> int:
    return max(0, (int(n_chars) + 3) // 4)


def tokens_to_chars(n_tokens: int) -> int:
    return max(0, int(n_tokens) * 4)


@dataclass(frozen=True)
class SessionLimits:
    window_tokens: int
    send_budget_tokens: int
    context_chars: int
    tool_output_chars: int
    max_openai_tools: int
    detail_policy: str
    disk_first: bool
    below_minimum: bool
    model: str = ""
    provider: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)


def session_limits() -> SessionLimits | None:
    return _limits


def reset_session() -> None:
    """Tests: drop process-level limits so one case cannot leak into the next."""
    global _limits
    _limits = None


def limits_for_window(
    window_tokens: int,
    *,
    model: str = "",
    provider: str = "",
) -> SessionLimits:
    """Derive every send-side budget from a context window."""
    window = max(4096, int(window_tokens or DEFAULT_WINDOW))
    below = window < MIN_SENSIBLE_WINDOW
    send = max(2048, int(window * _SEND_FRACTION))
    context_chars = tokens_to_chars(send)
    cap_raw = (os.environ.get("ATLAS_AGENT_CONTEXT_CHARS_MAX") or "").strip()
    cap = 4_000_000
    if cap_raw:
        try:
            cap = max(32_000, int(cap_raw))
        except ValueError:
            pass
    context_chars = min(context_chars, cap)

    if below:
        policy = "compact"
        disk_first = True
        max_tools = 24
        tool_out = 2_500
        notes = (
            f"window {window} < {MIN_SENSIBLE_WINDOW} (minimum for a full "
            f"investigation in chat). Compact / disk-first: bulk parses stay "
            f"on disk; only summaries enter the prompt.",
        )
    elif window < 128_000:
        policy = "standard"
        disk_first = False
        max_tools = 64
        tool_out = 8_000
        notes = ()
    else:
        policy = "rich"
        disk_first = False
        max_tools = 128
        tool_out = 12_000
        notes = ()

    # Operator overrides still win when set.
    env_tools = (os.environ.get("ATLAS_AGENT_MAX_OPENAI_TOOLS") or "").strip()
    if env_tools.isdigit():
        max_tools = max(8, int(env_tools))
    env_out = (os.environ.get("ATLAS_AGENT_TOOL_OUTPUT_LIMIT") or "").strip()
    if env_out.isdigit():
        tool_out = max(500, int(env_out))

    return SessionLimits(
        window_tokens=window,
        send_budget_tokens=send,
        context_chars=context_chars,
        tool_output_chars=tool_out,
        max_openai_tools=max_tools,
        detail_policy=policy,
        disk_first=disk_first,
        below_minimum=below,
        model=model or "",
        provider=provider or "",
        notes=notes,
    )


def apply_session_window(
    window_tokens: int,
    *,
    model: str = "",
    provider: str = "",
    adapt_chars: bool = True,
) -> SessionLimits:
    """Install session limits and write derived env so existing readers update.

    Char budget is moved *to* the derived value (grow or shrink) unless the
    operator locked it (``ATLAS_CONTEXT_CHARS_LOCK=1``) or disabled auto
    chars (``ATLAS_CONTEXT_AUTO_CHARS=0``).
    """
    global _limits
    limits = limits_for_window(window_tokens, model=model, provider=provider)
    if adapt_chars and _auto_chars_enabled() and not _chars_locked():
        os.environ["ATLAS_AGENT_CONTEXT_CHARS"] = str(limits.context_chars)
    _limits = limits
    return limits


def _auto_chars_enabled() -> bool:
    return (os.environ.get("ATLAS_CONTEXT_AUTO_CHARS") or "1").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _chars_locked() -> bool:
    return (os.environ.get("ATLAS_CONTEXT_CHARS_LOCK") or "0").strip().lower() in (
        "1", "true", "yes", "on",
    )


def estimate_messages_tokens(messages: list[dict] | None) -> int:
    if not messages:
        return 0
    n = 0
    for m in messages:
        n += len(str(m.get("content") or ""))
        for tc in m.get("tool_calls") or []:
            n += len(str(tc))
        extra = m.get("_responses_items")
        if extra:
            n += len(str(extra))
        n += 8
    return chars_to_tokens(n)


def estimate_tools_tokens(tools: list | dict | None) -> int:
    if not tools:
        return 0
    try:
        blob = json.dumps(tools, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        blob = str(tools)
    return chars_to_tokens(len(blob))


def estimate_request_tokens(
    messages: list[dict] | None,
    *,
    tools: list | dict | None = None,
) -> int:
    """Chars/4 estimate of the next Chat Completions request body."""
    return estimate_messages_tokens(messages) + estimate_tools_tokens(tools)


def _is_system(msg: dict) -> bool:
    return (msg.get("role") or "") == "system"


def _stub_tool_call(tc: dict) -> dict:
    """Shrink one tool_calls entry's arguments, keep id/name intact.

    A paired ``role=tool`` message elsewhere in the conversation references
    this call by id — dropping the whole entry (not just its arguments)
    would orphan that tool message and produce an invalid Chat Completions
    conversation shape.
    """
    if not isinstance(tc, dict):
        return tc
    out = dict(tc)
    fn = dict(out.get("function") or {})
    if fn.get("arguments"):
        fn["arguments"] = "{}"
    out["function"] = fn
    return out


def _shorten_turn(msg: dict) -> None:
    role = msg.get("role") or ""
    if role == "tool":
        msg["content"] = _TOOL_STUB
        return
    if role in ("user", "assistant"):
        raw = str(msg.get("content") or "").strip()
        if len(raw) > 80:
            msg["content"] = _TURN_STUB
        tool_calls = msg.get("tool_calls")
        if tool_calls:
            msg["tool_calls"] = [_stub_tool_call(tc) for tc in tool_calls]
        msg.pop("_responses_items", None)


def turn_index(messages: list[dict]) -> list[int]:
    """The conversation turn each message belongs to: an assistant message
    opens a turn, and the tool results and nudges that follow it are that
    turn's. Everything before the first assistant message is turn 0."""
    out: list[int] = []
    turn = 0
    for m in messages:
        if (m.get("role") or "") == "assistant":
            turn += 1
        out.append(turn)
    return out


def compact_aged_messages(
    messages: list[dict],
    *,
    keep_tool_results: int = 12,
    keep_turn_text: int = 16,
    batch: int = 6,
    keep_tool_turns: int | None = None,
    batch_turns: int | None = None,
) -> int:
    """Proactive compaction, by age rather than by budget.

    Age is measured in turns when ``keep_tool_turns`` or ``batch_turns`` is
    given: the tool results of the last ``keep_tool_turns`` turns stay, and
    the older ones are stubbed together once ``batch_turns`` turns' worth
    are due. Counting messages instead tied the cadence to how many calls
    the model makes per turn - at three calls a turn a twelve-result window
    was under four turns and a six-message batch came due every second
    turn, so the cacheable prefix never grew past the system frame. The
    older turns' prose is shortened in the same pass, so the prefix moves
    once per batch rather than twice.

    ``fit_messages`` only acts once a request is *over* budget, and against
    a million-token window that never happens — so every tool result and
    every nudge of a long run rides along in every request, and the tokens
    per turn grow several-fold, almost entirely from old tool payloads the
    model has already acted on. The facts
    those payloads carried live in the claim graph and the trace; the
    conversation needs the recent ones. Older tool results become the same
    stub ``fit_messages`` would use, older user/assistant prose is
    shortened, the system frame is untouched. Returns how many messages
    were compacted.
    """
    if not messages:
        return 0
    n = 0
    # Stubbing one message per turn moves the first changed message — and
    # with it the end of the provider's cacheable prefix — every turn.
    # Waiting until ``batch`` messages are due and stubbing them together
    # keeps the prefix identical for ``batch`` turns at a time; the
    # conversation carries a few more recent results in exchange for cache
    # reads that cost a fifth of a fresh token.
    tool_i = [i for i, m in enumerate(messages)
              if (m.get("role") or "") == "tool"
              and (m.get("content") or "") != _TOOL_STUB]
    by_turns = keep_tool_turns is not None or batch_turns is not None
    if by_turns:
        turns = turn_index(messages)
        last = turns[-1] if turns else 0
        keep_t = keep_tool_turns if keep_tool_turns is not None else max(1, keep_tool_results // 3)
        batch_t = batch_turns if batch_turns is not None else max(1, batch // 3)
        due = [i for i in tool_i if turns[i] <= last - max(0, keep_t)]
        fire = len({turns[i] for i in due}) >= max(1, batch_t)
    else:
        due = tool_i[:-keep_tool_results] if keep_tool_results else tool_i
        fire = len(due) >= max(1, batch)
    if fire:
        for i in due:
            _shorten_turn(messages[i]); n += 1
    turn_i = [i for i, m in enumerate(messages)
              if (m.get("role") or "") in ("user", "assistant")
              and not _is_system(m)
              and (m.get("content") or "") != _TURN_STUB]
    # The first user message is the case brief; it stays.
    due = turn_i[1:-keep_turn_text] if keep_turn_text else turn_i[1:]
    # In turn mode the prose is shortened only in the pass that stubs tool
    # results (one prefix move per batch); a conversation with no tool
    # results left to stub falls back to the message batch.
    if by_turns and tool_i:
        text_fire = fire
    else:
        text_fire = len(due) >= max(1, batch)
    if text_fire:
        for i in due:
            _shorten_turn(messages[i]); n += 1
    return n


class ContextBudgetExceededError(Exception):
    """Raised by fit_messages when the request still doesn't fit the send
    budget after every reduction step — see fit_messages' docstring."""


def fit_messages(
    messages: list[dict],
    *,
    tools: list | dict | None = None,
    window_tokens: int | None = None,
    tail: int = 4,
) -> list[dict]:
    """Compress ``messages`` so the next request fits the send budget.

    Order (inside → out, system frame preserved):

    1. Never mutate ``role=system`` (playbook / CASE seed).
    2. Keep the last ``tail`` non-system messages as the working set.
    3. In the body, shorten older user/assistant turns first.
    4. Then replace older tool payloads with stubs.
    5. If still over, stub tools in the tail (except the newest tool msg).
    6. If still over, shorten user/assistant in the tail except the last msg.
    7. If STILL over (the system frame alone exceeds the budget), raise
       ContextBudgetExceededError rather than send an over-budget request —
       every provider response to that is a guess (silent head truncation,
       a 413, or a 400), and none of them are distinguishable from a normal
       failure without this signal.

    Mutates message dicts in place (same contract as the old ``_trim_context``).
    """
    if not messages:
        return messages
    lim = _limits
    if window_tokens is not None:
        budget = max(2048, int(int(window_tokens) * _SEND_FRACTION))
    elif lim is not None:
        budget = lim.send_budget_tokens
    else:
        budget = max(2048, int(DEFAULT_WINDOW * _SEND_FRACTION))

    def over() -> bool:
        return estimate_request_tokens(messages, tools=tools) > budget

    if not over():
        return messages

    indices = list(range(len(messages)))
    system_i = [i for i in indices if _is_system(messages[i])]
    other_i = [i for i in indices if i not in system_i]
    tail_i = set(other_i[-tail:]) if tail else set()
    body_i = [i for i in other_i if i not in tail_i]

    for i in body_i:
        if not over():
            return messages
        if (messages[i].get("role") or "") in ("user", "assistant"):
            _shorten_turn(messages[i])

    for i in body_i:
        if not over():
            return messages
        if (messages[i].get("role") or "") == "tool":
            _shorten_turn(messages[i])

    tail_tool = [i for i in other_i[-tail:] if (messages[i].get("role") or "") == "tool"]
    for i in tail_tool[:-1]:
        if not over():
            return messages
        _shorten_turn(messages[i])

    for i in other_i[-tail:-1]:
        if not over():
            return messages
        if (messages[i].get("role") or "") in ("user", "assistant"):
            _shorten_turn(messages[i])

    if over() and tail_tool:
        _shorten_turn(messages[tail_tool[-1]])

    # A still-oversized *tail* (the newest tool result in particular, kept
    # verbatim by design in step 5 above — the freshest evidence a tool call
    # just produced) is an accepted, pre-existing tradeoff: send it anyway
    # rather than truncate the one thing the model most needs to see. What
    # is NOT acceptable is the system frame itself (step 1: "never mutate")
    # being too large for the window on its own — every later step is a
    # no-op in that case, and the request will overflow no matter what.
    # That case gets a loud, actionable failure instead of a silent
    # provider-side head-truncation or 413.
    system_tokens = estimate_request_tokens(
        [messages[i] for i in system_i], tools=None)
    if system_tokens > budget:
        raise ContextBudgetExceededError(
            f"system prompt/playbook alone is ~{system_tokens} tokens, "
            f"over the {budget}-token send budget — it is never shortened "
            "by design, so no amount of trimming the conversation can fix "
            "this. Use a model with a larger context window, or reduce "
            "the playbook/case-seed size."
        )

    return messages
