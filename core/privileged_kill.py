"""SIGKILL as root to a process group Atlas started through sudo.

A tool run through sudo without a terminal stays in the group Atlas created
for it, running as root or as a user it drops to. The user may signal sudo,
not that command, so a command that ignores the SIGTERM sudo relays survives
a stop. The same NOPASSWD grant the tool ran under covers kill (any
arguments), which reaches it.

Stdlib only: the detached job supervisor imports this and must stay light.
"""
from __future__ import annotations

import os
import subprocess

# The one call that runs sudo; tests replace it (tests/conftest.py), since a
# host with the Atlas grant would carry the kill out as root.
_run = subprocess.run


def start_time(pid: int) -> str | None:
    """The kernel's start time of ``pid`` (field 22 of /proc/<pid>/stat), or
    None when no such process exists. A pid number handed to another
    process carries another start time."""
    try:
        with open(f"/proc/{int(pid)}/stat", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except (OSError, ValueError):
        return None
    fields = data.rsplit(")", 1)[-1].split()
    return fields[19] if len(fields) > 19 else None


def kill_group_as_root(pgid: int, leader_start: str | None = None) -> bool:
    """``sudo -n kill -KILL -- -<pgid>``; True when root's kill reached the
    group. Refused for pgid 1 or lower, our own group or session, and a
    group whose number now belongs to another process: while any member of
    our group lives the kernel keeps the number, so a live process with that
    pid and another start time than the leader Atlas spawned means the group
    is gone and the number was reused."""
    try:
        pgid = int(pgid)
    except (TypeError, ValueError):
        return False
    if pgid <= 1:
        return False
    try:
        if pgid in (os.getpgrp(), os.getsid(0)):
            return False
    except OSError:
        return False
    if leader_start is not None:
        now = start_time(pgid)
        if now is not None and now != leader_start:
            return False
    try:
        r = _run(["sudo", "-n", "kill", "-KILL", "--", f"-{pgid}"],
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0
