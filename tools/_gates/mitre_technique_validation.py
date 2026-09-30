"""Gate: any ATT&CK T-ID in the description must validate against the local table.

Auto-validates `T\\d{4}(\\.\\d{3})?` patterns via correlate.mitre_validate.
Unknown T-IDs are an automatic CHALLENGED trigger and refused here so a
fabricated technique can never reach the trace.
"""
import re
import sys
from typing import Optional

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def check(ctx) -> Optional[dict]:
    # T-IDs from the prose description AND from the structured mitre_techniques
    # channel. The latter lets the analyst attach techniques it mapped via
    # correlate.mitre_map without embedding them in the description (the reason
    # coverage_report saw 0 TTPs across four training runs).
    from_field = [str(t).strip().upper()
                  for t in (getattr(ctx, "mitre_techniques", None) or [])]
    technique_ids = sorted(set(_TID_RE.findall(ctx.description or ""))
                           | {t for t in from_field if _TID_RE.fullmatch(t)})
    bad_format = [t for t in from_field if not _TID_RE.fullmatch(t)]
    if bad_format:
        return {
            "success": False,
            "error": (
                f"Malformed technique ID(s) in mitre_techniques: "
                f"{', '.join(bad_format)}. Use ATT&CK form like 'T1059' or "
                "'T1059.005'."),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "mitre_technique_validation",
            "unknown_technique_ids": bad_format,
        }
    if not technique_ids:
        return None

    try:
        from tools.correlate import mitre_validate as _mitre_validate
    except Exception as e:
        print(f"[Atlas WARN] correlate.mitre_validate unavailable: {e}", file=sys.stderr)
        return None  # graceful-degrade: don't refuse if MITRE module is broken

    # Relevance oracle: candidates mitre_map's keyword scorer finds in the
    # finding's own description. A valid-but-irrelevant T-ID pasted onto a
    # finding passes existence validation, which lets minimum-compliance
    # mapping game the pre-report TTP gates. We never refuse on relevance
    # (the keyword table has recall limits — refusing would force
    # keyword-golfing); we annotate, and pre_report_check blocks only when
    # EVERY mapped technique on attack findings is unsupported.
    candidate_tids: set[str] | None = None
    try:
        from tools.correlate import mitre_map as _mitre_map
        mm = _mitre_map(ctx.description or "", top_n=10)
        candidate_tids = {
            str(c.get("technique_id") or "").upper()
            for c in (mm.get("candidates") or [])}
    except Exception as e:
        print(f"[Atlas WARN] mitre_map relevance check unavailable: {e}",
              file=sys.stderr)

    described_tids = {t.upper() for t in _TID_RE.findall(ctx.description or "")}

    unknown: list[str] = []
    for tid in technique_ids:
        v = _mitre_validate(tid)
        if v.get("exists"):
            entry = {
                "technique_id": tid,
                "name": v.get("name", ""),
                "tactic": v.get("tactic", ""),
            }
            # Historical (revoked/deprecated) IDs validate, but carry the
            # current replacement so reports can cite the up-to-date ID.
            if v.get("status"):
                entry["status"] = v["status"]
                if v.get("superseded_by"):
                    entry["superseded_by"] = v["superseded_by"]
            if candidate_tids is not None:
                parent = tid.split(".", 1)[0]
                supported = (tid in candidate_tids
                             or parent in candidate_tids
                             or any(c.startswith(parent + ".")
                                    for c in candidate_tids)
                             or tid in described_tids)
                if not supported:
                    entry["relevance"] = "unsupported"
            ctx.validated_techniques.append(entry)
        else:
            unknown.append(tid)

    if not unknown:
        return None
    return {
        "success": False,
        "error": (
            f"Unknown ATT&CK technique ID(s) in finding: {', '.join(unknown)}. "
            "Validate with correlate.mitre_map (to find candidates) and "
            "correlate.mitre_validate (to confirm existence) before citing. "
            "Unverified technique IDs are an automatic CHALLENGED trigger."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "mitre_technique_validation",
        "unknown_technique_ids": unknown,
    }
