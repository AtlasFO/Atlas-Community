"""Gate: CONFIRMED/LIKELY tiers require recent confidence_score + cite_check whose
inputs reference this finding's text. Anti-reuse — each finding gets a fresh check.
"""
import re
from typing import Optional

_WHITESPACE_RE = re.compile(r"\s+")
_RANK = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0}


def _normalize(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", (text or "").lower()).strip()[:60]


def _find_matching(ctx, tool_name: str, norm_desc: str, prior_dup_call_id: int) -> Optional[dict]:
    # reason_window = window + recent reason_calls the 30-slice missed. Safe to
    # widen here: the match is content-gated (norm_desc must appear in the
    # reason_call's message) and anti-reuse-gated (prior_dup_call_id), so an
    # aged-out-but-valid score for THIS finding still counts, while a stale or
    # unrelated one cannot.
    for entry in reversed(ctx.reason_window or ctx.window):
        if entry.get("type") != "reason_call":
            continue
        if entry.get("tool") != tool_name:
            continue
        if int(entry.get("call_id") or 0) <= prior_dup_call_id:
            continue
        ins = entry.get("inputs") or {}
        user_msg = (ins.get("user_message") or "").lower()
        if norm_desc and norm_desc in user_msg:
            return entry
    return None


def _prior_dup_call_id(ctx, norm_desc: str) -> int:
    """call_id of the most recent already-recorded finding with the same
    normalized description. Anti-reuse floor: a matching reason_call must be
    NEWER than this to satisfy (or be stamped onto) the current finding."""
    prior = 0
    for e in ctx.idx.by_type.get("finding", []):
        if _normalize(e.get("description", "")) == norm_desc:
            prior = max(prior, int(e.get("call_id") or 0))
    return prior


def _stamp_matching_calls(ctx, norm_desc: str, prior_dup_call_id: int) -> None:
    """Best-effort audit linkage: stamp gated_by_confidence_call_id /
    gated_by_cite_check_call_id whenever a description-matched reason_call
    exists, even on paths where the gate itself doesn't require one (the
    deterministic fast path, SUSPECTED/UNCONFIRMED tiers). Never refuses —
    the FK is an audit trail, not a requirement, on these paths."""
    if not ctx.gated_by_confidence_call_id:
        cs = _find_matching(ctx, "reason_confidence_score", norm_desc, prior_dup_call_id)
        if cs is not None:
            ctx.gated_by_confidence_call_id = int(cs.get("call_id") or 0)
    if not ctx.gated_by_cite_check_call_id:
        cc = _find_matching(ctx, "reason_cite_check", norm_desc, prior_dup_call_id)
        if cc is not None:
            ctx.gated_by_cite_check_call_id = int(cc.get("call_id") or 0)


def check(ctx) -> Optional[dict]:
    norm_desc = _normalize(ctx.description)
    prior_dup_call_id = _prior_dup_call_id(ctx, norm_desc)

    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        # No gating for SUSPECTED/UNCONFIRMED, but still record the audit
        # linkage when the agent DID run the checks for this finding.
        _stamp_matching_calls(ctx, norm_desc, prior_dup_call_id)
        return None

    # ── R1 fast path ──────────────────────────────────────────────────────
    # If supporting_evidence was supplied inline, run a DETERMINISTIC citation
    # check instead of requiring two 8B-model round-trips (confidence_score +
    # cite_check). CONFIRMED's tier guard is confirmed_requires_supported_evaluate
    # (runs just before this gate); LIKELY trusts the agent tier + citation
    # check. This also sidesteps the description-substring matching of the
    # legacy path, so re-wording a finding no longer invalidates a prior check.
    if (ctx.supporting_evidence or "").strip():
        from ._citation import deterministic_cite_check
        cite = deterministic_cite_check(ctx.description, ctx.supporting_evidence)
        if cite["verdict"] != "ALL_CITED":
            return {
                "success": False,
                "error": (
                    "Inline citation check failed: these concrete claims appear "
                    "in the finding but not in supporting_evidence — "
                    f"{cite['uncited_claims']}. Add each value (with its tool/field "
                    "reference) to supporting_evidence, or remove the claim, then "
                    "re-record."
                    if cite["verdict"] == "UNCITED_CLAIMS_PRESENT"
                    else "supporting_evidence is empty or contains no artifact data."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "confidence_and_citation",
                "uncited_claims": cite["uncited_claims"],
            }
        ctx.citation_mode = "deterministic"
        # The fast path replaces the model round-trips, but if the agent ran
        # them anyway for this finding, keep the audit chain intact.
        _stamp_matching_calls(ctx, norm_desc, prior_dup_call_id)
        return None
    # ── legacy path (no inline supporting_evidence) ───────────────────────
    # Anti-reuse: the matching reason_call must come AFTER any prior finding
    # with the same normalized description (prior_dup_call_id above).
    # Otherwise one confidence_score call could satisfy the gate for
    # unbounded duplicate findings.

    cs_entry = _find_matching(ctx, "reason_confidence_score", norm_desc, prior_dup_call_id)
    if cs_entry is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} tier requires a preceding reason.confidence_score "
                f"call that referenced this finding's text. None found in the "
                f"recent trace window (last 30 entries plus recent reasoning "
                f"calls) that (a) matched the description and (b) was fresh "
                f"(not reused from an earlier identical finding). "
                f"PREFERRED: pass supporting_evidence= inline to this "
                f"record_finding call — the citation check then runs "
                f"deterministically on the evidence text, immune to any "
                f"wording drift between your reasoning call and the finding "
                f"(no separate confidence_score/cite_check needed for "
                f"{ctx.tier}). Otherwise call reason.confidence_score(finding=..., "
                f"supporting_evidence=..., intended_tier='{ctx.tier}') with the "
                f"finding text worded EXACTLY as you will record it, then re-record."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_confidence_score",
        }

    # Parse the tier the reviewer assigned; refuse if it's lower than requested.
    cs_conclusion = (cs_entry.get("conclusion") or "")
    cs_tier_match = re.search(
        r'"tier"\s*:\s*"(CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED)"',
        cs_conclusion,
        re.IGNORECASE,
    )
    if not cs_tier_match:
        cs_tier_match = re.search(
            r"\bTIER\s*[:=]\s*(CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED)\b",
            cs_conclusion,
            re.IGNORECASE,
        )
    if cs_tier_match:
        assigned = cs_tier_match.group(1).upper()
        if _RANK.get(assigned, 0) < _RANK.get(ctx.tier, 0):
            return {
                "success": False,
                "error": (
                    f"reason.confidence_score assigned tier {assigned!r} but "
                    f"this record_finding requested {ctx.tier!r}. Downgrade the "
                    f"finding to {assigned!r} (or lower) before recording."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "confidence_and_citation",
                "missing_check": "reason_confidence_score",
                "confidence_score_tier": assigned,
            }

    cc_entry = _find_matching(ctx, "reason_cite_check", norm_desc, prior_dup_call_id)
    if cc_entry is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} tier requires a preceding reason.cite_check call that "
                f"referenced this finding's text. None found in the recent trace "
                f"window (last 30 entries plus recent reasoning calls). "
                f"PREFERRED: pass supporting_evidence= inline to this "
                f"record_finding call — the citation check runs deterministically "
                f"and no separate cite_check is needed. Otherwise call "
                f"reason.cite_check(finding=..., supporting_evidence=...) with the "
                f"finding worded exactly as recorded, and resolve any uncited claims."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_cite_check",
        }

    cc_conclusion = (cc_entry.get("conclusion") or "").upper()
    if "UNCITED_CLAIMS_PRESENT" in cc_conclusion or "INSUFFICIENT_EVIDENCE" in cc_conclusion:
        return {
            "success": False,
            "error": (
                "reason.cite_check returned UNCITED_CLAIMS_PRESENT or "
                "INSUFFICIENT_EVIDENCE for this finding. Add citations for "
                "every concrete claim (paths, IPs, hashes, technique IDs) "
                "and re-run cite_check before recording."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_cite_check",
        }

    # Gate passed — stamp matched call_ids onto ctx so record_finding can
    # write them onto the finding entry as explicit foreign keys.
    ctx.gated_by_confidence_call_id = int(cs_entry.get("call_id") or 0)
    ctx.gated_by_cite_check_call_id = int(cc_entry.get("call_id") or 0)
    return None
