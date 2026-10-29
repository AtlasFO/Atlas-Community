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
self_correction trace entry so the adversarial-review moment is auditable; the
refusal carries the evaluator's reason (``evaluation``, marked ``reused``).
A review counts only for the statement it reviewed, equal after normalisation
(tools._gates._match.reviews): a narrowed, hedged or negated wording is judged on
its own.
When no review holds these words, the refusal says so and names the newest
SUPPORTED review of a longer or shorter form (one normalised statement inside
the other), so it does not read as if nothing were reviewed; a reworded
statement or a sibling finding's review is never named.
An evaluation record_finding ran itself (marked "auto") judged the evidence the
finding carried then: when the finding now carries rows that evaluation did not
see, it is judged again (the refusal names the missing evaluation, so
record_finding's auto-evaluation runs), never refused on the stale verdict. An
evaluation the analyst asked for stands.

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

from ._match import (_FINDING_RE, normalize_desc, find_reason_call, most_recent_reason_call,
                     reviewed_evidence, reviewed_finding)


def _unjudged_rows(entry: dict, evidence: str, cited=()) -> bool:
    """Whether the finding offers what the evaluation did not read: a line
    of evidence its SUPPORTING EVIDENCE lacked (whitespace and case aside,
    read as the request wrote it: normalize_desc rewrites "cited output" as
    the request did), or a cited call whose rows it was not given (its
    input_call_ids; the evaluation reads the cited calls' rows)."""
    seen = normalize_desc(reviewed_evidence(entry))
    if any(normalize_desc(line) not in seen
           for line in str(evidence or "").splitlines() if line.strip()):
        return True
    read = set()
    for c in entry.get("input_call_ids") or []:
        try:
            read.add(int(c))
        except (TypeError, ValueError):
            continue
    now = set()
    for c in cited or ():
        try:
            if int(c or 0) > 0:
                now.add(int(c))
        except (TypeError, ValueError):
            continue
    return bool(now - read)


def _auto_evaluate_on() -> bool:
    try:
        from tools.misc import _finding_auto_evaluate_enabled
        return _finding_auto_evaluate_enabled()
    except Exception:  # noqa: BLE001
        return False


_VERDICT_RE = re.compile(r"VERDICT\W{0,12}(SUPPORTED|CHALLENGED|UNCERTAIN)", re.IGNORECASE)

# The share of the longer statement's words the shorter one must make up for
# the two to count as one statement in a longer and a shorter form. At one
# half the shared statement is the larger part of the longer text: a sentence
# added to or dropped from a finding, not a short claim (a sibling finding's
# "CORP-WS01 is online") that happens to stand inside a long one.
_FORM_SHARE = 0.5
_EDGE = ".,;:!?()[]\"'"


def _other_form(a: str, b: str) -> bool:
    """Whether the normalised statements ``a`` and ``b`` differ and one holds
    the other as a run of whole words that is at least _FORM_SHARE of the
    longer one's words. A word's edge punctuation is not part of it, so a
    sentence that ends at "09:12." is a run inside "09:12, and ..."."""
    wa, wb = ([w for w in (t.strip(_EDGE) for t in x.split()) if w] for x in (a, b))
    short, long_ = (wa, wb) if len(wa) <= len(wb) else (wb, wa)
    if not short or short == long_ or len(short) < _FORM_SHARE * len(long_):
        return False
    n = len(short)
    return any(long_[i:i + n] == short for i in range(len(long_) - n + 1))


def _supported_containing(ctx, norm: str) -> Optional[dict]:
    """The newest SUPPORTED review of a statement that holds these words or
    that these words hold (the normalised statements, one inside the other:
    a statement and the same statement with a sentence added or dropped),
    None when there is none. A review counts only for the words it reviewed
    (_match.reviews); this one is named so the refusal does not read as if
    nothing were reviewed. A review of another wording (one rewritten, not
    extended) or of a sibling finding on the same host is never named, nor
    a short claim standing inside a long one (_FORM_SHARE)."""
    from core.reason_outcome import is_usable_reason_call
    for entry in reversed(ctx.reason_window or []):
        if entry.get("type") != "reason_call" or entry.get("tool") != "reason_evaluate_finding":
            continue
        reviewed = reviewed_finding(entry)
        if not reviewed or not _other_form(reviewed, norm):
            continue
        m = _VERDICT_RE.search(entry.get("conclusion", "") or "")
        if m and m.group(1).upper() == "SUPPORTED" and is_usable_reason_call(entry):
            return entry
    return None


def _missing(ctx, reviewed: Optional[dict] = None) -> dict:
    """The refusal for no review of these exact words; ``reviewed`` is the
    SUPPORTED review of a longer or shorter form, named after the cheap path,
    its words last: an also_refused_by entry is cut at a sentence end within
    400 characters in the joined error, so the named part drops whole there.
    The longer or shorter form may be the statement's negation ("No row shows
    that ..."): the text leaves it to the analyst whether the reviewed words
    are what was meant."""
    other = ""
    if reviewed is not None:
        from core.coverage_ledger import shown_name
        m = _FINDING_RE.search(str((reviewed.get("inputs") or {}).get("user_message") or ""))
        words = " ".join((m.group(1) if m else "").split())
        other = (f" Call {int(reviewed.get('call_id') or 0)} reviewed (SUPPORTED) a longer or shorter form of "
                 "these words; a review covers only the words it reviewed: evaluate these words, or record the "
                 f"reviewed words if that is what you mean. Reviewed words: {shown_name(words, limit=160)}")
    return {
        "success": False,
        "error": (
            "CONFIRMED tier requires a preceding reason.evaluate_finding "
            "call that reviewed these exact words (none did in the recent "
            "trace; a review counts only for the words it reviewed). Call "
            "reason.evaluate_finding(finding=..., supporting_evidence=...) "
            "first, then re-record this finding — or record it as "
            "SUSPECTED/LIKELY, which needs no evaluation." + other
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_supported_evaluate",
        "missing_check": "reason_evaluate_finding",
    }


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
        return _missing(ctx, _supported_containing(ctx, norm))

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

    if (eval_entry is matched and (eval_entry.get("inputs") or {}).get("auto")
            and _unjudged_rows(eval_entry, ctx.supporting_evidence,
                               [*(ctx.input_call_ids or []), ctx.linked_call_id])
            and _auto_evaluate_on()):
        # The statement's own auto-evaluation did not support it, on rows
        # short of the ones it cites now: judged again by the evaluation
        # record_finding runs for a missing one, never refused on the stale
        # verdict. The same rows find this entry again (no new call).
        return _missing(ctx)

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
        # The reason travels on reuse as on a fresh evaluation; an
        # auto-evaluation's own dict replaces this one (record_finding).
        "evaluation": {"verdict": verdict or "UNPARSEABLE", "text": _reason(conclusion, verdict),
                       "call_id": int(eval_entry.get("call_id") or 0), "reused": True},
    }


def _reason(conclusion: str, verdict: str) -> str:
    from tools.reasoning import challenge_reason
    return challenge_reason(conclusion, verdict)
