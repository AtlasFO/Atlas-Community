"""Deferred forensic intents — recover probes blocked by the DAIR batch gate.

When middleware refuses a forensic tool because the DAIR window has aged out
(or the deferred backlog latch is set), the blocked call is recorded as a
``deferred_intent`` instead of vanishing. ``dair_assess`` surfaces open
intents; the DAIR director LLM promotes / dismisses / keeps them. Only
promoted tools are re-added to ``priority_tools`` for the next batch.

Protocol blocks are informational (not tool errors). A hard cap with
hysteresis forces disposition; a deadlock escape auto-relieves the queue if
the agent never recovers.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# Open-queue ceiling: at this many open intents the backlog latch engages
# and forensic tools stay blocked until dair_assess relieves the queue.
DEFERRED_BACKLOG_CAP = 10
# Latch clears only after open count falls to this (avoids flapping at 10).
DEFERRED_BACKLOG_HYSTERESIS = 7
# Consecutive protocol blocks while latched before agent-loop force-nudge
# escalates to deadlock escape (if still no dair_assess).
DEADLOCK_BLOCKS_WITHOUT_ASSESS = 5
# dair_assess calls under an active latch that fail to get under hysteresis
# before server-side auto-relieve runs.
DEADLOCK_ASSESS_WITHOUT_RELIEF = 2

# Argument keys worth fingerprinting / summarizing (stable identifying subset).
_FINGERPRINT_KEYS = (
    "path", "file", "filepath", "filename", "pattern", "query", "regex",
    "image", "cmd", "command", "host", "target", "hive", "key", "artifact",
    "offset", "pid", "plugin", "table", "expression", "strings_file",
)

PROTOCOL_MARKER = "[ATLAS_PROTOCOL]"


def mcp_tool_to_dotted(mcp_tool: str) -> str:
    """Map MCP registration name to Atlas dotted tool id used in priority_tools.

    ``strings_strings_grep`` → ``strings.grep``;
    ``vol_vol_psscan`` → ``vol.psscan``;
    ``misc_record_finding`` → ``misc.record_finding``.
    """
    parts = (mcp_tool or "").split("_")
    if len(parts) >= 2 and parts[0] == parts[1]:
        rest = "_".join(parts[2:])
        return f"{parts[0]}.{rest}" if rest else parts[0]
    if len(parts) >= 2:
        return parts[0] + "." + "_".join(parts[1:])
    return mcp_tool or ""


def args_fingerprint(tool: str, args: dict | None,
                     case_dir: str | None = None) -> str:
    """Stable short hash of tool + identifying args (not full payload).

    A path is hashed in its real form, so ``evidence/x.log`` and its
    absolute spelling are one fingerprint; ``case_dir`` resolves relative
    paths and defaults to the running trace's case.
    """
    if case_dir is None:
        try:
            from core.execution_log import log as _elog
            case_dir = _elog.case_dir()
        except Exception:  # noqa: BLE001
            case_dir = None
    subset: dict[str, Any] = {}
    for k in _FINGERPRINT_KEYS:
        if args and k in args and args[k] is not None and args[k] != "":
            subset[k] = args[k]
    # Fall back to a sorted shallow snapshot when no known keys present.
    if not subset and args:
        for k in sorted(args.keys()):
            if k.startswith("_"):
                continue
            v = args[k]
            if v is None or v == "":
                continue
            subset[k] = v
            if len(subset) >= 6:
                break
    from core.call_memo import canonical_args
    canon, _paths = canonical_args(subset, case_dir)
    blob = json.dumps({"tool": tool, "args": canon},
                      sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def args_summary(args: dict | None, limit: int = 6,
                 value_chars: int = 120) -> dict[str, str]:
    """Compact arg view for DAIR prompts and the trace."""
    if not args:
        return {}
    out: dict[str, str] = {}
    for k in _FINGERPRINT_KEYS:
        if k in args and args[k] is not None and args[k] != "":
            out[k] = str(args[k])[:value_chars]
            if len(out) >= limit:
                return out
    if not out:
        for k in sorted(args.keys()):
            if k.startswith("_"):
                continue
            out[k] = str(args[k])[:value_chars]
            if len(out) >= limit:
                break
    return out


def infer_kind(tool: str, args: dict | None = None) -> str:
    """Tag curiosity vs work-order-ish probes for pressure relief priority."""
    name = (tool or "").lower()
    # record_finding / reason are not curiosity; greps/strings often are.
    if "curiosity" in name:
        return "curiosity"
    if any(s in name for s in ("grep", "strings", "hexdump", "yara")):
        return "curiosity"
    return "work_order"


def format_open_intents_for_dair(intents: list[dict],
                                 latched: bool = False) -> str:
    """Human-readable block injected into the dair_assess user prompt."""
    if not intents and not latched:
        return ""
    lines = ["DEFERRED INTENTS (open):"]
    if latched:
        lines.append(
            f"BACKLOG LATCH ACTIVE — open queue at/above "
            f"{DEFERRED_BACKLOG_CAP}. Dispose intents (promote into "
            f"priority_tools, dismiss, or keep) before prescribing new "
            f"forensic work. Latch clears at ≤{DEFERRED_BACKLOG_HYSTERESIS} "
            f"open.")
    if not intents:
        lines.append("(none)")
        return "\n".join(lines)
    for e in intents:
        kind = e.get("kind") or "work_order"
        lines.append(
            f"- [#{e.get('call_id')}] {e.get('tool')}  "
            f"priority_hint={e.get('priority_tool')}  "
            f"kind={kind}  block_count={e.get('block_count', 1)}  "
            f"fingerprint={e.get('fingerprint')}")
        summary = e.get("args_summary") or {}
        if summary:
            lines.append(f"  args: {json.dumps(summary, ensure_ascii=False)}")
        if e.get("blocked_reason"):
            lines.append(f"  blocked: {e['blocked_reason']}")
    lines.append(
        "For each open intent emit deferred_intent_dispositions in "
        "DAIR_ASSESSMENT: "
        '{"call_id": N, "action": "promote"|"dismiss"|"keep", "note": "..."}. '
        "promote → include priority_hint (or equivalent) in "
        "directives.priority_tools. dismiss → drop. keep → leave open "
        "(does not clear backlog pressure). Do NOT tell the investigator to "
        "free-retry a blocked tool outside priority_tools.")
    return "\n".join(lines)


def is_protocol_block_message(text: str) -> bool:
    """True when a ToolError / rendered result is a protocol info block."""
    if not text:
        return False
    if PROTOCOL_MARKER in text:
        return True
    # Legacy / substring matches for older in-flight messages.
    needles = (
        "no active DAIR batch",
        "deferred backlog full",
        "Call dair_assess before forensic tools",
        '"gate": "input_scale"',
        '"gate": "context_budget"',
        '"gate": "discovery_first"',
        '"gate": "wrong_input_kind"',
        '"gate": "disk_open_policy"',
        '"gate": "unknown_columns"',
        '"gate":"input_scale"',
        '"gate":"context_budget"',
        '"gate":"discovery_first"',
        '"gate":"wrong_input_kind"',
        '"gate":"disk_open_policy"',
        '"gate":"unknown_columns"',
        "Authoritative discovery always overrides",
        "Wrong input kind",
        "wrong input kind",
        "never pass CSV",
        "Do not invent filenames",
        "discovery_next",
        "context budget allows at most",
        "Do not re-pass the whole directory",
        "do not re-pass the whole directory",
        "remaining tool-output budget",
        "already produced artifact",
    )
    return any(n in text for n in needles)
