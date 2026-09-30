"""Disk-space fail-safe for case runs.

A single long carve or plaso timeline can grow output for hours and silently
fill the case volume — taking down not just the run but the whole VM/host
(logs stop, the DB corrupts, sudo tools half-write). This module is the
central guard so cases never run out of disk space.

Two layers use it:

* Preflight (``guard`` / ``check``) — refuse to *launch* disk-heavy work when
  free space is already below the floor. Wired into ``core.executor.run`` /
  ``run_with_progress`` and ``tools.jobs._start_job``.
* Runtime watchdog — ``tools.jobs_runner`` polls ``is_low`` while a detached
  job runs and kills it if free space crosses the floor mid-carve.

Stdlib-only (os, shutil) so the import-light detached supervisor can use it.
All thresholds are configurable via env and evaluated live on every call, so a
value changed between runs takes effect without a restart.
"""
from __future__ import annotations

import os
import shutil

# ── Configurable thresholds ──────────────────────────────────────────────────
# The floor is max(absolute MB, percent of the volume). Free space below the
# floor blocks new disk-heavy work and aborts a running job. Percent guards
# small volumes where a few GB is proportionally huge; the MB floor guards
# large volumes where 1% is still enormous. Read live so tests/ops can tune.

_DEFAULT_MIN_FREE_MB = 2048   # 2 GiB absolute floor
_DEFAULT_MIN_FREE_PCT = 2.0   # or 2% of the volume, whichever is larger


class DiskSpaceError(RuntimeError):
    """Raised by ``guard`` when free space is below the fail-safe floor."""


def _strip_inline_comment(raw: str) -> str:
    # python-dotenv doesn't strip a trailing '# comment' on an unquoted
    # value (its own documented behavior) — .env.example's house style is
    # 'KEY=2048   # explanation', so os.environ can hand back the comment
    # still attached. Duplicated here (not core.envfile.env_int/env_float)
    # deliberately: this module is stdlib-only so the import-light detached
    # supervisor can use it, per the module docstring.
    return raw.split("#", 1)[0].strip()


def _min_free_mb() -> int:
    try:
        return max(0, int(_strip_inline_comment(
            os.environ.get("ATLAS_MIN_FREE_DISK_MB") or str(_DEFAULT_MIN_FREE_MB))))
    except (TypeError, ValueError):
        return _DEFAULT_MIN_FREE_MB


def _min_free_pct() -> float:
    try:
        return max(0.0, float(_strip_inline_comment(
            os.environ.get("ATLAS_MIN_FREE_DISK_PCT") or str(_DEFAULT_MIN_FREE_PCT))))
    except (TypeError, ValueError):
        return _DEFAULT_MIN_FREE_PCT


def _probe_path(path: str | None) -> str:
    """Nearest existing ancestor of ``path`` to stat for free space.

    ``shutil.disk_usage`` needs an existing path; output dirs often do not
    exist yet at preflight time, so walk up to the first parent that does.
    Falls back to cwd, then root.
    """
    p = os.path.abspath(os.path.expanduser(path or os.getcwd()))
    while p and not os.path.exists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return p or "/"


def check(path: str | None = None) -> dict:
    """Free-space snapshot for the volume backing ``path``.

    Never raises — on any stat failure it reports ``ok=True`` (fail-open) so a
    guard can never wedge a run over an unstattable path. Returns a dict with
    ok, free/total/required bytes and MB, free_pct, and the probed path.
    """
    probe = _probe_path(path)
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return {"ok": True, "path": probe, "error": "disk_usage failed",
                "free_bytes": None, "total_bytes": None}

    min_mb = _min_free_mb()
    min_pct = _min_free_pct()
    required = max(min_mb * 1024 * 1024, int(usage.total * min_pct / 100.0))
    free_pct = (usage.free / usage.total * 100.0) if usage.total else 100.0
    return {
        "ok": usage.free >= required,
        "path": probe,
        "free_bytes": usage.free,
        "total_bytes": usage.total,
        "required_bytes": required,
        "free_mb": round(usage.free / 1024 / 1024, 1),
        "required_mb": round(required / 1024 / 1024, 1),
        "free_pct": round(free_pct, 2),
        "min_free_mb": min_mb,
        "min_free_pct": min_pct,
    }


def is_low(path: str | None = None) -> bool:
    """True if free space on ``path``'s volume is below the floor."""
    return not check(path)["ok"]


def message(status: dict, what: str = "operation") -> str:
    """Human/agent-readable explanation for a low-disk status dict."""
    if status.get("free_bytes") is None:
        return f"Disk space could not be verified for {status.get('path')}."
    return (
        f"Disk-space fail-safe: refusing to run {what} — only "
        f"{status['free_mb']} MB free ({status['free_pct']}%) on "
        f"{status['path']}, below the {status['required_mb']} MB floor "
        f"(ATLAS_MIN_FREE_DISK_MB={status['min_free_mb']}, "
        f"ATLAS_MIN_FREE_DISK_PCT={status['min_free_pct']}). Free space or "
        f"raise the floor before retrying."
    )


def guard(path: str | None = None, what: str = "operation") -> None:
    """Raise ``DiskSpaceError`` if free space on ``path``'s volume is low."""
    status = check(path)
    if not status["ok"]:
        raise DiskSpaceError(message(status, what))
