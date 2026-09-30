"""Refuse UNCONFIRMED findings that only restate Access Stage limitations.

A run can spawn many near-identical "TSK blocked / EVTX absent / documented
limitation" findings when prose is the only writable surrogate for a
missing mount_plan transition. Once Access Stage is pending or terminal,
one structural note is enough — cite evidence_access / mount_plan instead.
"""
from __future__ import annotations

from typing import Optional


def check(ctx) -> Optional[dict]:
    if getattr(ctx, "tier", "") != "UNCONFIRMED":
        return None
    log = getattr(ctx, "log", None)
    case = None
    try:
        if log is not None and callable(getattr(log, "case_dir", None)):
            case = log.case_dir()
    except Exception:
        case = None
    if not case:
        return None

    prior: list[str] = []
    try:
        by_type = getattr(getattr(ctx, "idx", None), "by_type", None) or {}
        for e in by_type.get("finding", []) or []:
            if isinstance(e, dict) and e.get("description"):
                prior.append(str(e["description"]))
    except Exception:
        prior = []

    try:
        from core.evidence_access import refuse_duplicate_access_limitation
        reason = refuse_duplicate_access_limitation(
            case, ctx.description or "", existing_finding_texts=prior,
        )
    except Exception:
        return None
    if not reason:
        return None
    return {
        "success": False,
        "error": reason,
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "access_limitation_dedupe",
    }
