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


def _own_fuse_mounts(proc_mounts: str | None = None) -> set[str]:
    """Mountpoints of FUSE mounts this user serves (a raw view among them):
    their owner unmounts them with fusermount3, no root needed."""
    uid = f"user_id={os.getuid()}"
    out: set[str] = set()
    try:
        with open(proc_mounts or _PROC_MOUNTS, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split(" ")
                if len(parts) >= 4 and parts[2].startswith("fuse") and uid in parts[3].split(","):
                    out.add(_unescape_mountpoint(parts[1]))
    except OSError:
        pass
    return out


def unmount_all_under(path: str, proc_mounts: str | None = None,
                      spare: set[str] | frozenset[str] = frozenset()) -> dict:
    """Unmount every filesystem at or under ``path``, innermost-first.

    The daemons of the raw views under ``path`` are stopped first (each
    unmounts its view; one whose view was unmounted from outside still runs
    and holds its evidence open, so they are found by command line, not by
    the mount table). A FUSE mount of this user is unmounted with fusermount3,
    any other with ``umount``, then ``umount -l`` (lazy) for busy mounts.
    ``spare``: paths a running background job reads; the mount holding one
    stays. Re-scans /proc/mounts afterwards so ``remaining`` reflects reality
    rather than the sum of per-call exit codes.

    Returns::

        {"unmounted": [mp, ...],
         "failed":    [{"mount": mp, "error": "..."}, ...],
         "remaining": [mp, ...]}
    """
    unmounted: list[str] = []
    failed: list[dict] = []
    # The kernel's spelling, without a stat of the last part (a stale FUSE
    # file answers every stat with an error).
    kept = {os.path.join(os.path.realpath(os.path.dirname(os.path.abspath(str(s)))),
                         os.path.basename(str(s))) for s in spare}
    try:
        from core.raw_views import stop_under
        stop_under(path, spare=kept)
    except Exception:  # noqa: BLE001 - the mounts below are still taken down
        pass
    own_fuse = _own_fuse_mounts(proc_mounts)
    for mp in find_mounts_under(path, proc_mounts):
        if any(k == mp or k.startswith(mp.rstrip("/") + "/") for k in kept):
            continue
        if mp in own_fuse:
            from core.raw_views import fuse_unmount
            if fuse_unmount(mp) or mp not in find_mounts_under(mp, proc_mounts):
                unmounted.append(mp)
                continue
        ok, err = _umount_once(mp, lazy=False, proc_mounts=proc_mounts)
        if not ok:
            ok, err = _umount_once(mp, lazy=True, proc_mounts=proc_mounts)
        if ok:
            unmounted.append(mp)
        else:
            failed.append({"mount": mp, "error": err})
    remaining = find_mounts_under(path, proc_mounts)
    return {"unmounted": unmounted, "failed": failed, "remaining": remaining}
