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
