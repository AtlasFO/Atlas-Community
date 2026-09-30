"""Gate: CONFIRMED/LIKELY findings about specific behaviour kinds require a
recent reason.hypothesize call OR an explicit tested_hypothesis_id.

The behaviour vocabulary (process, service, persistence, C2, lateral, ...)
keys on the things the agent is most likely to claim without first
hypothesising. It is matched as words, and only where the finding asserts
the behaviour: a filesystem's orphaned directory entries are not an orphan
process, and "not the exfiltration medium" denies exfiltration rather than
claiming it. A spurious hit on a pure file-existence finding is satisfied
by a thin reason.hypothesize call describing the observation.
"""
import re
from typing import Optional

from ._match import asserted_mention

_BEHAVIOUR_RE = re.compile(
    r"\b(?:process(?:es)?|services?|scheduled\s+tasks?|persist\w*|c2|beacon\w*|"
    r"exfil\w*|lateral|ghost\w*|orphan(?:ed)?\s+(?:process|thread|service)\w*|"
    r"detached\s+(?:process|thread)\w*|null\s+cmdline|unsigned|credential\w*|"
    r"implants?|stagers?)\b", re.IGNORECASE)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    if (ctx.tested_hypothesis_id or "").strip():
        return None

    if asserted_mention(ctx.description or "", _BEHAVIOUR_RE) is None:
        return None

    # Usable hypothesize only — empty/length-starved calls do not satisfy.
    matched_hyp = None
    try:
        from core.reason_outcome import is_usable_reason_call
    except Exception:
        is_usable_reason_call = lambda e: bool(  # noqa: E731
            e and e.get("success") and (e.get("conclusion") or "").strip()
        )
    for e in reversed(ctx.window):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize":
            if is_usable_reason_call(e):
                matched_hyp = e
                break
    if matched_hyp is not None:
        ctx.gated_by_hypothesize_call_id = int(matched_hyp.get("call_id") or 0)
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding mentions process / service / persistence / "
            f"C2 / lateral-movement behaviour but no usable "
            f"reason.hypothesize result exists in the last 30 trace entries "
            f"(empty / failed hypothesize does not count). "
            f"Call reason.hypothesize(observation=..., evidence=..., context=...) "
            f"and capture the returned hypothesis_id, then pass it as "
            f"tested_hypothesis_id when recording this finding."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "hypothesize_required",
    }
