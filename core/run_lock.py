"""Cross-process exclusivity for "a run is happening in this case dir".

dashboard/run_manager.py's own concurrency guard is in-process only (a dict
of RunSession objects) and its check for an *externally* started run reads
``.atlas/run_status.json``'s pid — a file the run process first writes when
its evidence stage begins (agent/cli.py's ``_IntakeStatus``), then every turn
(agent/loop.py's ``_persist_live_status``) and at completion (agent/cli.py's
``_persist_run_status``); a ``--dry-run`` rerun writes none. Between
subprocess spawn and that first write there is a real window where a second
``atlas run``/``rerun`` (from the CLI, or a second dashboard request) could
start racing the same evidence/claim graph with nothing stopping it.

``atlas run``/``atlas rerun`` hold this OS-level lock (``fcntl.flock``) for
the run's entire lifetime, whichever way the run was started. flock ties
the lock to an open file descriptor, so it is released automatically if the
holding process dies for any reason (crash, SIGKILL, normal exit) — no
stale-lock cleanup is needed.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path


class RunLockedError(Exception):
    """Another process already holds the run lock for this case."""


# The cases this process holds, by real path. flock ties a lock to an open
# file description, so a probe from the holder itself also reads as locked;
# this set tells the holder's own lock from another process's.
_held: dict[str, int] = {}


def _key(case_dir: str | os.PathLike) -> str:
    return os.path.realpath(os.fspath(case_dir))


def _lock_path(case_dir: str | os.PathLike) -> Path:
    p = Path(case_dir) / ".atlas" / "run.lock"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def acquire(case_dir: str | os.PathLike) -> int:
    """Acquire the case's run lock, non-blocking. Returns an fd the caller
    must pass to release(). Raises RunLockedError if already held."""
    path = _lock_path(case_dir)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise RunLockedError(
            f"a run is already in progress for {os.fspath(case_dir)!r} "
            "(another atlas run/rerun holds .atlas/run.lock)"
        ) from None
    _held[_key(case_dir)] = fd
    return fd


def release(fd: int | None) -> None:
    """Best-effort release/close of a lock fd from acquire(). Safe to call
    with None (nothing was ever acquired)."""
    if fd is None:
        return
    for key, held in list(_held.items()):
        if held == fd:
            del _held[key]
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def held_here(case_dir: str | os.PathLike) -> bool:
    """True if this process holds the case's lock."""
    return _key(case_dir) in _held


def held_elsewhere(case_dir: str | os.PathLike) -> bool:
    """True if another process holds the case's lock: a run is live there
    and nothing may clear the case under it."""
    return not held_here(case_dir) and is_locked(case_dir)


def is_locked(case_dir: str | os.PathLike) -> bool:
    """Non-blocking probe: True if another process currently holds the
    lock for this case. Never raises."""
    try:
        fd = acquire(case_dir)
    except RunLockedError:
        return True
    except OSError:
        return False
    release(fd)
    return False
