"""Mount-point detection and safe teardown for case directories.

A run can leave ewfmount/ntfs/loop mounts under the case dir (Atlas mounts
evidence at ``<case>/mnt/...``). Two things must never happen to such a tree:

  * ``rmtree`` recursing into a live mount — it would traverse mounted evidence
    instead of the on-disk directory, and on a writable mount could delete it.
  * removing the mountpoint out from under the kernel — that orphans the mount
    (a stale entry over a now-missing path) and can leave the whole case dir
    unreadable (ENOENT), with the trace and scaffold unrecoverable.

These helpers locate mounts at or under a path from ``/proc/mounts`` and unmount
them innermost-first, with a lazy-``umount -l`` fallback for busy mounts. They do
not touch evidence contents, so the read-only-evidence posture is preserved.
"""
import os

_PROC_MOUNTS = "/proc/mounts"


def _unescape_mountpoint(field: str) -> str:
    """Decode the octal escapes the kernel writes into /proc/mounts fields
    (\\040 space, \\011 tab, \\012 newline, \\134 backslash)."""
    if "\\" not in field:
        return field
    out: list[str] = []
    i = 0
    n = len(field)
    while i < n:
        c = field[i]
        if c == "\\" and i + 3 < n and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_mountpoints(proc_mounts: str | None = None):
    """Yield the (unescaped) mountpoint field of every /proc/mounts line."""
    proc_mounts = proc_mounts or _PROC_MOUNTS
    try:
        with open(proc_mounts, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return
    for line in data.splitlines():
        parts = line.split(" ")
        if len(parts) < 2:
            continue
        yield _unescape_mountpoint(parts[1])


def find_mounts_under(path: str, proc_mounts: str | None = None) -> list[str]:
    """Return mountpoints at or under ``path``, deepest (innermost) first.

    ``path`` is normalised with ``realpath`` so a case dir reached through a
    symlink still matches the kernel's canonical mountpoint paths. Nested mounts
    are ordered innermost-first so they can be unmounted without EBUSY.
    """
    target = os.path.realpath(path)
    prefix = target.rstrip("/") + "/"
    found = [
        mp for mp in _iter_mountpoints(proc_mounts)
        if mp == target or mp.startswith(prefix)
    ]
    found.sort(key=len, reverse=True)
    return found


def _umount_once(mp: str, lazy: bool, proc_mounts: str | None) -> tuple:
    """(ok, error) for one umount attempt.

    Tolerates the executor's trace-integrity raise: clear_case_run tears
    mounts down BEFORE any trace log is configured, and record_tool_call's
    _require_configured then raises out of run() — but the umount
    subprocess has already executed at that point, so /proc/mounts is
    re-checked as the ground truth instead of crashing the clear (a stale
    fuse mount with no recoverable session otherwise makes `atlas train`
    unlaunchable)."""
    from core.executor import run  # function-level: executor imports may cycle
    argv = ["umount", "-l", mp] if lazy else ["umount", mp]
    try:
        res = run(argv, needs_sudo=True)
        return bool(res.get("success")), (res.get("stderr") or "").strip()
    except RuntimeError as e:
        gone = mp not in find_mounts_under(mp, proc_mounts)
        return gone, f"umount ran unlogged (no trace configured): {e}"


def unmount_all_under(path: str, proc_mounts: str | None = None) -> dict:
    """Unmount every filesystem at or under ``path``, innermost-first.

    Tries a normal ``umount`` first, then ``umount -l`` (lazy) for busy mounts.
    Re-scans /proc/mounts afterwards so ``remaining`` reflects reality rather
    than the sum of per-call exit codes.

    Returns::

        {"unmounted": [mp, ...],
         "failed":    [{"mount": mp, "error": "..."}, ...],
         "remaining": [mp, ...]}
    """
    unmounted: list[str] = []
    failed: list[dict] = []
    for mp in find_mounts_under(path, proc_mounts):
        ok, err = _umount_once(mp, lazy=False, proc_mounts=proc_mounts)
        if not ok:
            ok, err = _umount_once(mp, lazy=True, proc_mounts=proc_mounts)
        if ok:
            unmounted.append(mp)
        else:
            failed.append({"mount": mp, "error": err})
    remaining = find_mounts_under(path, proc_mounts)
    return {"unmounted": unmounted, "failed": failed, "remaining": remaining}
