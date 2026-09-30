"""Context Budget Manager — first-class remaining room for LLM investigation.

Estimates how much of the active model's context is already committed
(system/seed/conversation) and how much remains for new evidence, tool
output, and reasoning. The Investigation Planner and Input Scale sensor
consume this; middleware enforces hard floors derived from it.

Tokens are approximate (chars/4) unless ATLAS_MODEL_CONTEXT_TOKENS is set.
Live window size preferably comes from ``core.model_context`` (GET /models).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.envfile import env_int
from core.llm_check import DEFAULT_WINDOW, MIN_SENSIBLE_WINDOW, session_limits

SCHEMA_VERSION = "1.0"

_DEFAULT_WINDOW = env_int("ATLAS_MODEL_CONTEXT_TOKENS", DEFAULT_WINDOW)
_DEFAULT_OUTPUT_RESERVE = env_int("ATLAS_CONTEXT_OUTPUT_RESERVE", 4096)
_DEFAULT_REASONING_RESERVE = env_int("ATLAS_CONTEXT_REASONING_RESERVE", 2048)
_MIN_TOOL_FLOOR = env_int("ATLAS_CONTEXT_MIN_TOOL_TOKENS", 1500)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def chars_to_tokens(n_chars: int) -> int:
    """Rough OpenAI-style estimate: ~4 chars per token."""
    return max(0, (int(n_chars) + 3) // 4)


def budget_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "context_budget.json"


def empty_budget() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": _utcnow(),
        "window_tokens": _DEFAULT_WINDOW,
        "reserved_output_tokens": _DEFAULT_OUTPUT_RESERVE,
        "reserved_reasoning_tokens": _DEFAULT_REASONING_RESERVE,
        "fixed_context_tokens": 0,
        "conversation_tokens": 0,
        "available_for_evidence_tokens": 0,
        "available_for_tool_output_tokens": 0,
        "available_for_reasoning_tokens": _DEFAULT_REASONING_RESERVE,
        "detail_policy": "compact",
        "disk_first": False,
        "conversation_included": False,
        "max_bulk_dir_files": 1,
        "model": "",
        "provider": "",
    }


def detail_policy_for(available_tool_tokens: int) -> str:
    if available_tool_tokens >= 24000:
        return "rich"
    if available_tool_tokens >= 8000:
        return "standard"
    return "compact"


def max_bulk_dir_files_for(policy: str, available_tool_tokens: int) -> int:
    if policy == "rich" and available_tool_tokens >= 40000:
        return 8
    if policy == "rich":
        return 4
    if policy == "standard":
        return 2
    return 1


def resolve_window_tokens(model: str = "", provider: str = "") -> int:
    """Resolve the active model context window (tokens).

    Priority:
      1. ``ATLAS_MODEL_CONTEXT_TOKENS`` (operator hard override)
      2. Live/cache probe from ``core.model_context`` (GET /models, no catalogue)
      3. Session limits from the unified LLM check
      4. ``ATLAS_AGENT_CONTEXT_CHARS`` converted via chars/4
      5. Recommended default (1_000_000, GLM-5.2)
    """
    explicit = os.environ.get("ATLAS_MODEL_CONTEXT_TOKENS")
    if explicit:
        try:
            return max(4096, int(explicit))
        except ValueError:
            pass
    try:
        from core.model_context import get_probed_window
        probed = get_probed_window()
        if probed is not None and probed >= 4096:
            return int(probed)
    except Exception:
        pass
    lim = session_limits()
    if lim is not None and lim.window_tokens >= 4096:
        return int(lim.window_tokens)
    chars = os.environ.get("ATLAS_AGENT_CONTEXT_CHARS")
    if chars:
        try:
            return max(
                4096,
                chars_to_tokens(int(chars)) + _DEFAULT_OUTPUT_RESERVE,
            )
        except ValueError:
            pass
    _ = (model, provider)
    return DEFAULT_WINDOW


def estimate_fixed_context_tokens(
    case_dir: str | os.PathLike | None = None,
    *,
    system_prompt: str = "",
    extra_text: str = "",
) -> int:
    total_chars = len(system_prompt or "") + len(extra_text or "")
    if case_dir:
        root = Path(case_dir).resolve()
        for rel in (
            "CASE.md",
            ".atlas/investigation_tasks.json",
            ".atlas/investigation_plan.json",
            ".atlas/rerun_brief.md",
            ".atlas/claim_graph.json",
        ):
            path = root / rel
            if not path.is_file():
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
                total_chars += min(len(raw), 120_000)
            except OSError:
                continue
    return chars_to_tokens(total_chars)


def estimate_conversation_tokens(messages: list[dict] | None) -> int:
    if not messages:
        return 0
    n = 0
    for m in messages:
        n += len(str(m.get("content") or ""))
        for tc in m.get("tool_calls") or []:
            n += len(str(tc))
    return chars_to_tokens(n)


def compute(
    case_dir: str | os.PathLike | None = None,
    *,
    model: str = "",
    provider: str = "",
    system_prompt: str = "",
    messages: list[dict] | None = None,
    persist: bool = False,
) -> dict[str, Any]:
    window = resolve_window_tokens(model=model, provider=provider)
    reserved_out = _DEFAULT_OUTPUT_RESERVE
    reserved_reason = _DEFAULT_REASONING_RESERVE
    fixed = estimate_fixed_context_tokens(
        case_dir, system_prompt=system_prompt)
    conv = estimate_conversation_tokens(messages)

    committed = fixed + conv + reserved_out + reserved_reason
    remaining = max(0, window - committed)
    tool_budget = max(_MIN_TOOL_FLOOR, int(remaining * 0.55))
    evidence_budget = max(0, int(remaining * 0.30))
    reason_budget = reserved_reason + max(
        0, remaining - tool_budget - evidence_budget)

    policy = detail_policy_for(tool_budget)
    lim = session_limits()
    below = window < MIN_SENSIBLE_WINDOW or (
        lim is not None and lim.below_minimum)
    disk_first = below or (lim.disk_first if lim is not None else False)
    if below:
        policy = "compact"
    elif lim is not None:
        order = {"compact": 0, "standard": 1, "rich": 2}
        if order.get(lim.detail_policy, 1) < order.get(policy, 1):
            policy = lim.detail_policy
    snap = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": _utcnow(),
        "window_tokens": window,
        "reserved_output_tokens": reserved_out,
        "reserved_reasoning_tokens": reserved_reason,
        "fixed_context_tokens": fixed,
        "conversation_tokens": conv,
        "conversation_included": messages is not None,
        "available_for_evidence_tokens": evidence_budget,
        "available_for_tool_output_tokens": tool_budget,
        "available_for_reasoning_tokens": reason_budget,
        "detail_policy": policy,
        "disk_first": disk_first,
        "max_bulk_dir_files": max_bulk_dir_files_for(policy, tool_budget),
        "model": model or "",
        "provider": provider or "",
    }
    if persist and case_dir:
        save_budget(case_dir, snap)
    return snap


def load_budget(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = budget_path(case_dir)
    if not path.is_file():
        return empty_budget()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_budget()
    if not isinstance(data, dict):
        return empty_budget()
    base = empty_budget()
    base.update(data)
    return base


def save_budget(case_dir: str | os.PathLike, budget: dict[str, Any]) -> Path:
    path = budget_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(budget)
    payload["schema_version"] = SCHEMA_VERSION
    payload["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def format_budget_for_brief(budget: dict[str, Any] | None) -> str:
    b = budget or empty_budget()
    return (
        "### Context budget\n"
        f"- window≈{b.get('window_tokens', 0)} tok · "
        f"tool output room≈{b.get('available_for_tool_output_tokens', 0)} tok · "
        f"policy={b.get('detail_policy', 'compact')}"
        f"{' · disk-first' if b.get('disk_first') else ''}\n"
        "- Prefer single-file / filtered parses; after CSV exists use "
        "`table.*` — do not re-dump bulk parsers into chat.\n"
    )
