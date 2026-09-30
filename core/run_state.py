"""What a case remembers of its last process run.

A run leaves two marks: the ending it recorded in ``.atlas/run_status.json``
and the execution trace it wrote under ``analysis/``. Whether either is
present decides what the next start means, a fresh process over kept
findings or the first run of the case, and which action the dashboard
offers first. Read by the CLI's run isolation and by the dashboard's run
status, and defined once so the two cannot disagree.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path

# Which question a run was given, and where it came from: the analyst's
# -q ("question"), the case's open requests ("tasks"), the standard
# objective when neither named one ("default"), or the open questions of a
# rerun ("rerun"). Written by the CLI at the start of every investigating
# session and removed by clear_case_run with the other run-scoped state, so
# a record always describes the run whose trace it names; a chat, which
# writes none, reads the last run's record only while that trace is the
# one it has open.
OBJECTIVE_FILE = "run_objective.json"
OBJECTIVE_SOURCES = ("question", "tasks", "default", "rerun")

# The endings a run records for itself. "starting" is the marker the clear
# leaves behind for the run about to begin and is not an ending.
TERMINAL_STOP_REASONS = frozenset({
    "finished", "quiet", "stall", "keyboard_interrupt", "llm_error",
})


def prior_run_is_terminal(case_dir: str | os.PathLike) -> bool:
    """True when ``.atlas/run_status.json`` records a finished prior run."""
    try:
        p = Path(case_dir) / ".atlas" / "run_status.json"
        if not p.is_file():
            return False
        data = json.loads(p.read_text(encoding="utf-8"))
        stopped = str(data.get("stopped_reason") or "")
        status = str(data.get("finish_status") or "")
        if stopped == "starting" and not status:
            return False
        return stopped in TERMINAL_STOP_REASONS or bool(status)
    except Exception:  # noqa: BLE001 - an unreadable status is no ending
        return False


def prior_process_artifacts_present(case_dir: str | os.PathLike) -> bool:
    """True when a previous process left an execution trace, closed or not.

    A crash mid-run may never write a terminal status; without this the next
    run would silently append its phases onto the old trace.
    """
    analysis = Path(case_dir) / "analysis"
    if not analysis.is_dir():
        return False
    try:
        for p in analysis.iterdir():
            name = p.name.lower()
            if p.is_file() and (name.endswith(("_trace.json", "_trace.jsonl"))
                                or name.startswith("agent_transcript_")):
                return True
    except OSError:
        return False
    return False


def prior_run_exists(case_dir: str | os.PathLike) -> bool:
    """Whether the case has been run before, by either mark."""
    return prior_run_is_terminal(case_dir) or prior_process_artifacts_present(case_dir)


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except (OSError, ValueError):
        return False


def record_objective(case_dir: str | os.PathLike, *, text: str, source: str,
                     trace_path: str = "") -> Path | None:
    """Record the objective this run was given (see OBJECTIVE_FILE).

    Returns the file written, or None when the case has no ``.atlas/``
    directory. An unknown ``source`` is a programming error.
    """
    if source not in OBJECTIVE_SOURCES:
        raise ValueError(f"unknown objective source: {source!r}")
    atlas = Path(case_dir) / ".atlas"
    if not atlas.is_dir():
        return None
    data = {
        "text": str(text or ""),
        "source": source,
        "trace_path": os.path.realpath(trace_path) if trace_path else "",
        "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    }
    target = atlas / OBJECTIVE_FILE
    tmp = target.with_name(target.name + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, target)
    return target


def read_objective(case_dir: str | os.PathLike | None, *,
                   trace_path: str | None = None) -> dict | None:
    """The recorded objective, or None when there is none, it cannot be
    read, or ``trace_path`` is given and the record names another trace."""
    if not case_dir:
        return None
    try:
        data = json.loads((Path(case_dir) / ".atlas" / OBJECTIVE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("source") not in OBJECTIVE_SOURCES:
        return None
    if trace_path is not None:
        recorded = str(data.get("trace_path") or "")
        if not recorded or not _same_file(recorded, trace_path):
            return None
    return data
