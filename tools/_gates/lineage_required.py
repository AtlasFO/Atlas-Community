"""Gate: input_call_ids must be supplied (after genesis grace) and contain only
real, existing trace call_ids.

This turns the trace into a self-describing causal DAG. Every finding /
self_correction / reason call / dair_assess says explicitly which prior entries
informed it — the Process view (and any future audit consumer) gets real foreign
keys instead of substring heuristics.

Genesis grace: the very first ~5 trace entries are allowed to have empty
input_call_ids so the agent can bootstrap (pre-plan reads → reason.plan →
first dair_assess) without a chicken-and-egg loop.
"""
from typing import Optional

_GENESIS_GRACE_THRESHOLD = 5
# Unknown ids a refusal names. A list that ran away is not repeated whole.
_UNKNOWN_SHOWN = 10


def refuse_unknown(call_ids, known) -> Optional[dict]:
    """The refusal for ids in ``call_ids`` that ``known``, the ids the trace
    holds, does not; None when every id is real. It says how many ids the
    run has issued, so the list can be bounded against the run rather than
    guessed at."""
    unknown = [c for c in call_ids if c not in known]
    if not unknown:
        return None
    shown = ", ".join(str(c) for c in unknown[:_UNKNOWN_SHOWN])
    if len(unknown) > _UNKNOWN_SHOWN:
        shown += f" and {len(unknown) - _UNKNOWN_SHOWN} more"
    return {
        "success": False,
        "gate": "lineage_required",
        "error": (
            f"input_call_ids names {len(unknown)} call id(s) the run has not "
            f"issued: {shown}. The trace holds {len(known)} call ids"
            + (f", the highest is {max(known)}" if known else "")
            + ". Cite the _atlas_call_id values of results you have seen, "
            "or omit the list where the tool derives it itself."
        ),
        "unknown_cids": unknown[:_UNKNOWN_SHOWN],
    }


def check_ids(log, call_ids) -> Optional[dict]:
    """``refuse_unknown`` against the ids ``log`` holds, for a tool that
    records the list as given; None when there is no trace to check."""
    cids = list(call_ids or [])
    if not cids:
        return None
    try:
        known = {int(k) for k in log.index().by_call_id}
    except Exception:  # noqa: BLE001 - no index, nothing to check against
        return None
    return refuse_unknown(cids, known)


def check(ctx) -> Optional[dict]:
    cids = list(ctx.input_call_ids or [])
    # 1) Empty: only allowed in the genesis window.
    if not cids:
        if len(ctx.log._entries) < _GENESIS_GRACE_THRESHOLD:
            return None
        return {
            "success": False,
            "error": (
                "input_call_ids is required — list the _atlas_call_id values "
                "of the entries that informed this call. This turns the trace "
                "into an explicit causal DAG so the trace viewer and audit "
                "consumers can traverse real foreign keys instead of inferring "
                f"links from substrings. Genesis grace expires after the "
                f"{_GENESIS_GRACE_THRESHOLD}th entry; this trace already has "
                f"{len(ctx.log._entries)} entries."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "lineage_required",
        }
    # 2) Validate every cid actually exists in the trace.
    known = ctx.idx.by_call_id if hasattr(ctx.idx, "by_call_id") \
        else {e.get("call_id") for e in ctx.log._entries}
    try:
        known_set = set(known.keys()) if isinstance(known, dict) else set(known)
    except AttributeError:
        known_set = set()
    refusal = refuse_unknown(cids, known_set)
    if refusal is not None:
        return {**refusal, "description": ctx.description,
                "confidence": ctx.confidence}
    return None
