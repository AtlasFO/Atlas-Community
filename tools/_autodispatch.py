"""Transparent background dispatch for long-running forensic tools.

A full plaso pass or carve on a multi-GB image holds a synchronous MCP call
open for hours, serializing the whole investigation. The job.* namespace has
had non-blocking variants since day one — but the analyst has to REMEMBER to
use them, and across 13 train runs mostly didn't. This helper makes the sync
tools defer themselves: when the evidence is larger than a threshold, the
call starts the identical background job (same argv via tools/jobs.py
builders) and returns immediately with the job handle and polling protocol.

Fail-open by design: any dispatch problem (remote mode, no case context,
disk guard, import error) falls back to the synchronous path, which carries
its own guards. Disable with ATLAS_AUTODISPATCH=0; tune the threshold with
ATLAS_AUTODISPATCH_MB (default 256).
"""
from __future__ import annotations

import os

from core.envfile import env_int
from core.paths import _input_size_bytes

DEFAULT_THRESHOLD_MB = 256


def _disabled() -> bool:
    return (os.environ.get("ATLAS_AUTODISPATCH") or "1").strip().lower() in (
        "0", "false", "no", "off")


def maybe_defer(kind: str, evidence_path: str | None, params: dict) -> dict | None:
    """Start ``kind`` as a background job when the evidence is big enough.

    Returns the job-start payload (marked ``deferred``) to hand straight back
    to the caller, or None to run synchronously.
    """
    if _disabled() or not evidence_path:
        return None
    threshold_mb = env_int("ATLAS_AUTODISPATCH_MB", DEFAULT_THRESHOLD_MB)
    if threshold_mb <= 0:
        return None
    size = _input_size_bytes(evidence_path)
    if size < threshold_mb * 1_048_576:
        return None
    try:
        from core import remote as _remote
        if _remote.is_enabled():
            return None  # jobs are unsupported in remote-SIFT mode
        from tools import jobs
        result = jobs._start_job(kind, params)
    except Exception:
        return None  # fall back to the sync path and its own guards
    if not result.get("success"):
        return None
    size_mb = size // 1_048_576
    result["deferred"] = True
    result["auto_dispatched"] = True
    result["hint"] = (
        f"Evidence is {size_mb} MB (≥ {threshold_mb} MB auto-dispatch "
        f"threshold): started as background job {result['job_id']} instead "
        f"of blocking this session for its full runtime. Poll "
        f"job.job_status('{result['job_id']}'), then "
        f"job.job_collect('{result['job_id']}') when finished — keep "
        f"working other evidence meanwhile. ATLAS_AUTODISPATCH=0 forces "
        f"synchronous runs.")
    try:
        from core.execution_log import log
        log.record_agent_message(
            f"[auto-dispatch] {kind} on {evidence_path} ({size_mb} MB) "
            f"deferred to background job {result['job_id']}")
    except Exception:
        pass
    return result
