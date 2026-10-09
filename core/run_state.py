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


# ── which runs are alive ──────────────────────────────────────────────────
# The dashboard's live-run check, here so the CLI and the MCP layer ask the
# same question it asks (dashboard/read_models.py re-exports these).

# Older run_status.json files carry a spinner prefix on "activity"
# (agent/loop.py no longer writes it). Kept as an escape so no
# pictograph appears in this source file.
LEGACY_ACTIVITY_PREFIX = "\u23f5 "


def pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (TypeError, ValueError):
        return False
    except OSError:
        # Exists but owned by another user (EPERM) or some other transient
        # signal error — something is there, so don't report the run dead.
        return True
    return True


def run_status(case_dir: str | os.PathLike) -> dict:
    """``.atlas/run_status.json`` of the case, ``{}`` when absent or unreadable."""
    try:
        data = json.loads((Path(case_dir) / ".atlas" / "run_status.json")
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def run_process_alive(case_dir: str | os.PathLike) -> bool:
    """True if the agent.cli run process for this case is still alive.

    Process liveness, not "did something write to disk recently" — a long
    tool call (img_vmdk_export_raw's qemu-img convert, which can run for
    hours) writes nothing to the transcript or the trace and only refreshes
    run_status.json at tool start/end, not while it's running. Checking the
    recorded pid instead means a run showing "in progress" here matches
    reality regardless of how long the current tool call has been running,
    and works the same whether the run was started via the dashboard or
    the bare CLI (dashboard/run_manager.py's own Popen-based liveness check
    only knows about runs it started itself)."""
    status = run_status(case_dir)
    if status.get("stopped_reason") != "running":
        return False
    return pid_alive(status.get("pid"))


def transcript_fresh(case_dir: str | os.PathLike, window_seconds: int) -> bool:
    """True if any agent_transcript_*.jsonl was written within window_seconds."""
    import time
    analysis = os.path.join(case_dir, "analysis")
    newest = None
    try:
        for name in os.listdir(analysis):
            if name.startswith("agent_transcript_") and name.endswith(".jsonl"):
                try:
                    m = os.path.getmtime(os.path.join(analysis, name))
                except OSError:
                    continue
                if newest is None or m > newest:
                    newest = m
    except OSError:
        return False
    return newest is not None and (time.time() - newest) < window_seconds


def agent_busy(case_dir: str | os.PathLike, *, window_seconds: int = 90) -> bool:
    """'Agent is working' signal: process liveness first, recent transcript
    growth as a fallback for a run_status.json written before the pid field
    existed, or one that's momentarily unreadable."""
    return run_process_alive(case_dir) or transcript_fresh(case_dir, window_seconds)


def active_runs(cases_root: str) -> list[dict]:
    """Every case under ``cases_root`` with a run in progress right now.

    The shell's "Atlas working" indicator used to ask the per-case questions
    projection for the *selected* case only, so a run started in another case
    -- or any run at all, before a case was picked -- left the header saying
    "idle". This is the case-wide answer, kept deliberately cheap because the
    shell polls it on a timer: per case it reads one small JSON and, only as
    the fallback path, lists one directory. It does not touch traces.
    """
    out: list[dict] = []
    try:
        entries = sorted(os.listdir(cases_root))
    except OSError:
        return out
    for name in entries:
        if name.startswith(".") or name == "_dashboard":
            continue
        case_dir = os.path.join(cases_root, name)
        if not os.path.isdir(case_dir):
            continue
        try:
            if not agent_busy(case_dir):
                continue
            status = run_status(case_dir)
            out.append({
                "case_dir": name,
                "case_id": status.get("case_id") or name,
                # Same de-prefixing as activity_projection: the legacy prefix reads
                # better in the UI as a plain tool name.
                "activity": (status.get("activity") or "")
                .removeprefix(LEGACY_ACTIVITY_PREFIX).strip(),
                "started_at": status.get("started_at") or "",
            })
        except Exception:  # noqa: BLE001 — one unreadable case must not
            # blank the indicator for every other case.
            continue
    return out


def live_runs() -> list[str]:
    """The case directories with a run alive on this host right now, for a
    caller that names no case (``atlas review`` without --case, an MCP
    server restarted outside a case, an enrichment lookup with no trace).

    Every case a run opened its trace in keeps a beacon in the execution
    log's beacon folder, whichever root it lies under (a chat saves none);
    a case counts while that beacon's process and the run's own record
    (run_process_alive) both say it is alive.
    """
    from core import execution_log

    out: list[str] = []
    folder = execution_log._BEACON_DIR       # read now: tests point it elsewhere
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                beacon = json.load(f)
            path = str(beacon.get("path") or "")
            pid = beacon.get("pid")
        except (OSError, ValueError, AttributeError):
            continue
        if not path or not pid_alive(pid):
            continue
        case = execution_log.case_dir_for_trace(path)
        if case not in out and run_process_alive(case):
            out.append(case)
    return out
