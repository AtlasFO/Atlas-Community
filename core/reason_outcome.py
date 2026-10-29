"""Usable reason-call outcomes — one predicate for agent / gates / finish.

Historical failure: HTTP 200 + finish_reason=length with
empty visible content was logged as a reason_call, then presence-only
checks treated hypothesize/plan/synthesize as "done." Transport now
fail-closes empty bodies; this module is the shared *consumer* contract
so gates and finish never regress to presence-only matching.
"""
from __future__ import annotations

from typing import Any, Optional


def is_usable_reason_call(entry: Optional[dict[str, Any]]) -> bool:
    """True when a reason_call produced a usable post-strip conclusion.

    Rejects: missing/failed calls, empty conclusions, empty_reason_response
    gate, and length-starved stubs (finish_reason=length with reasoning
    tokens and trivially short visible text).
    """
    if not isinstance(entry, dict):
        return False
    t = entry.get("type")
    if t is not None and t != "reason_call":
        return False
    if entry.get("success") is not True:
        return False
    if str(entry.get("gate") or "") == "empty_reason_response":
        return False
    conc = (entry.get("conclusion") or "").strip()
    if not conc:
        return False
    fr = str(entry.get("finish_reason") or "").lower()
    try:
        rt = int(entry.get("reasoning_tokens") or 0)
    except (TypeError, ValueError):
        rt = 0
    # Truncated visible stub after reasoning-token starvation is not usable
    # even if a few characters leaked into content.
    if fr == "length" and rt > 0 and len(conc) < 80:
        return False
    return True


def find_usable_reason_call(
    entries: list[dict[str, Any]] | None,
    tool: str,
    *,
    after_call_id: int = 0,
) -> Optional[dict[str, Any]]:
    """Most recent usable reason_call for ``tool`` (call_id > after_call_id)."""
    if not entries:
        return None
    for entry in reversed(entries):
        if entry.get("type") != "reason_call" or entry.get("tool") != tool:
            continue
        if int(entry.get("call_id") or 0) <= after_call_id:
            continue
        if is_usable_reason_call(entry):
            return entry
    return None


def any_usable_reason_call(
    entries: list[dict[str, Any]] | None,
    tool: str,
) -> bool:
    return find_usable_reason_call(entries, tool) is not None


def helper_unavailable(entries: list[dict[str, Any]] | None, tool: str) -> int:
    """The unusable outcomes of ``tool`` since its last usable one, when
    they reach the tool-failure latch's IDENTICAL_FAIL_LIMIT; else 0.

    Outcomes, not attempts: a call still running (or left running by the
    watchdog) has no reason_call yet and counts only once it returns, and a
    late usable reply clears the count. Every failure path of a helper call
    (timeout, empty or starved reply, transport error, missing backend)
    records an unusable reason_call, so a helper that cannot answer reaches
    the limit and the report gate records the missing step as a limitation
    instead of waiting for it. The latch's limit, so two failures in a row (a
    rate-limit or server-error pair) waive nothing."""
    from agent.tool_investigate import IDENTICAL_FAIL_LIMIT
    failed = len(failures_since_usable(entries, tool))
    return failed if failed >= IDENTICAL_FAIL_LIMIT else 0


def failures_since_usable(entries: list[dict[str, Any]] | None, tool: str) -> list[dict[str, Any]]:
    """The unusable reason_call outcomes of ``tool`` after its last usable
    one, in order. Those whose gate is "helper_unavailable" were answered
    from the run's memory of a cut request without reaching the model."""
    out: list[dict[str, Any]] = []
    for entry in entries or []:
        if entry.get("type") != "reason_call" or entry.get("tool") != tool:
            continue
        out = [] if is_usable_reason_call(entry) else out + [entry]
    return out
