"""Gate: CONFIRMED tier requires a reason.evaluate_finding with SUPPORTED verdict
for THIS finding.

Matches the evaluate_finding whose user_message echoes this finding's
description (so a *different* finding's CHALLENGED verdict reviewed in the same
batch cannot block this one — the cross-contamination bug). That match is
made over the widened reason window: a review is tied to its finding by
content, so the tool calls the analyst batches between reviewing and
recording cannot age it out. Only when no description-matched evaluate
exists does it fall back to the most-recent evaluate_finding in the strict
window, and only when that entry does not record which finding it reviewed
(older traces that did not echo the description); a review of another
finding is never this finding's verdict. A CHALLENGED/UNCERTAIN verdict refuses and emits a
self_correction trace entry so the adversarial-review moment is auditable.

Non-CONFIRMED tiers are never gated here, but when a description-matched
evaluate_finding exists it is still stamped as gated_by_evaluate_call_id —
the finding→adversarial-review audit link must survive regardless of tier
(a LIKELY recorded after a CHALLENGED verdict is exactly the honest
downgrade the audit should show). Only exact description matches are
stamped on that path; the most-recent fallback stays CONFIRMED-only so a
lower-tier finding can't get falsely linked to someone else's review.
"""
import re
from typing import Optional

from ._match import normalize_desc, find_reason_call, most_recent_reason_call


def check(ctx) -> Optional[dict]:
    norm = normalize_desc(ctx.description)

    if ctx.tier != "CONFIRMED":
        matched = find_reason_call(ctx.reason_window, "reason_evaluate_finding", norm)
        if matched is not None and not ctx.gated_by_evaluate_call_id:
            ctx.gated_by_evaluate_call_id = int(matched.get("call_id") or 0)
        return None

    # Prefer the evaluate_finding that actually reviewed THIS finding. The
    # most-recent fallback stands only for a review whose recorded input does
    # not say which finding it reviewed (traces written before the input was
    # echoed): a review that names a different finding is that finding's
    # verdict, and taking it here would let one SUPPORTED carry every claim
    # recorded after it.
    matched = find_reason_call(ctx.reason_window, "reason_evaluate_finding", norm)
    eval_entry = matched
    if eval_entry is None:
        recent = most_recent_reason_call(ctx.window, "reason_evaluate_finding")
        if recent is not None and "finding:" not in str(
                (recent.get("inputs") or {}).get("user_message") or "").lower():
            eval_entry = recent

    if eval_entry is None:
        return {
            "success": False,
            "error": (
                "CONFIRMED tier requires a preceding reason.evaluate_finding "
                "call (none for this finding in the recent trace). Call "
                "reason.evaluate_finding(finding=..., supporting_evidence=...) "
                "first, then re-record this finding — or record it as "
                "SUSPECTED/LIKELY, which needs no evaluation."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confirmed_requires_supported_evaluate",
            "missing_check": "reason_evaluate_finding",
        }

    conclusion = eval_entry.get("conclusion", "") or ""
    # Keep in sync with reason_evaluate_finding's parse: tolerate markdown
    # decoration and separator variants ("**VERDICT: SUPPORTED**",
    # "Verdict — CHALLENGED") between the keyword and the value.
    verdict_match = re.search(
        r"VERDICT\W{0,12}(SUPPORTED|CHALLENGED|UNCERTAIN)",
        conclusion,
        re.IGNORECASE,
    )
    verdict = verdict_match.group(1).upper() if verdict_match else ""

    if verdict == "SUPPORTED":
        # Explicit SUPPORTED verdict — gate passes. Stamp the matched eval
        # call_id so record_finding carries it as an explicit foreign key.
        ctx.gated_by_evaluate_call_id = int(eval_entry.get("call_id") or 0)
        return None

    # CHALLENGED or UNCERTAIN both block CONFIRMED. CONFIRMED requires
    # an explicit SUPPORTED verdict; UNCERTAIN is insufficient — it means
    # the reviewer could not confirm the claim, which is not the same as
    # supporting it.
    trigger = "evaluate_challenged_gate_refused"
    if verdict == "UNCERTAIN":
        trigger = "evaluate_uncertain_gate_refused"

    ctx.log.record_self_correction(
        trigger=trigger,
        prior_belief=f"Attempted to record CONFIRMED: {ctx.description[:200]}",
        new_belief=(
            f"Refused — evaluate_finding returned VERDICT: {verdict or 'unparseable'}. "
            f"Awaiting re-evaluation with stronger evidence or tier downgrade."
        ),
        evidence=(eval_entry.get("conclusion", "") or "")[:300],
        linked_call_id=eval_entry.get("call_id", 0),
    )
    return {
        "success": False,
        "error": (
            f"CONFIRMED tier refused: the reason.evaluate_finding for this "
            f"finding returned VERDICT: {verdict or 'UNPARSEABLE'} — an explicit "
            f"SUPPORTED verdict is required. Re-evaluate with stronger "
            f"evidence or downgrade this finding to SUSPECTED/LIKELY."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_supported_evaluate",
        "evaluate_verdict": verdict or "UNPARSEABLE",
    }
