"""Evidence is read, never written.

Two layers, both independent of any case's layout:

1. ``refuse_evidence_write`` — before a raw command runs, refuse it when its
   binary is one that changes files and any argument names a protected
   evidence path. The list is the coreutils that write; it is knowledge
   about the operating system, not about a case.
2. ``snapshot_evidence_refs`` / ``evidence_changes`` — around *every*
   subprocess the executor runs, stat the evidence paths the command
   referenced and compare afterwards. No list can foresee every tool that
   writes a sidecar or rewrites in place; the diff needs no foresight.

Without the diff, ``touch evidence/x`` and ``cp a evidence/b`` through
``misc.batch_run`` both succeed silently.
"""
from __future__ import annotations

import os
import re
from typing import Any

from core.paths import active_case_dir, is_evidence_path, is_inside, output_roots

# Binaries whose ordinary use modifies, moves or removes files. Interpreters
# and archivers are included because they write wherever they are pointed.
_WRITE_CAPABLE = frozenset({
    "rm", "rmdir", "mv", "cp", "install", "touch", "truncate", "shred",
    "dd", "tee", "ln", "mkdir", "chmod", "chown", "chgrp", "chattr",
    "sed", "perl", "python", "python3", "bash", "sh", "zsh", "dash",
    "tar", "unzip", "zip", "gzip", "gunzip", "bzip2", "xz", "7z", "7za",
    "rsync", "scp", "mkfs", "mount", "umount", "losetup", "fdisk", "sfdisk",
    "parted", "wipefs", "ntfsfix", "ntfsclone", "e2fsck", "fsck",
})
# A few of those only write when told to; refusing them outright would
# block their read-only forms (``sed -n`` prints, ``tar -t`` lists).
_WRITE_FLAGS = {
    "sed": ("-i", "--in-place"),
    "tar": ("-x", "--extract", "-c", "--create", "-r", "--append",
            "-u", "--update", "--delete"),
    "python": ("-c",), "python3": ("-c",), "perl": ("-e", "-i"),
    "bash": ("-c",), "sh": ("-c",), "zsh": ("-c",), "dash": ("-c",),
}
_MAX_SNAPSHOT_CHILDREN = 2000
# Mounting exposes evidence, it does not write it: a read-only mount changes
# the stat of the mount point (now the root of the exposed volume) and
# nothing else. So a read-only ``mount``, ``umount`` and the FUSE exposers
# are neither writers nor something to snapshot around. A mount that is not
# read-only stays a writer and is refused like any other.
_FUSE_EXPOSERS = frozenset({"ewfmount", "vshadowmount", "bdemount", "xmount",
                            "affuse"})


def _binary(cmd: list[str]) -> str:
    head = str(cmd[0]) if cmd else ""
    if head == "sudo" and len(cmd) > 1:
        head = str(cmd[1])
    return os.path.basename(head)


def _read_only_mount(cmd: list[str]) -> bool:
    """``mount`` asked for read-only: ``-r``, ``--read-only`` or ``ro`` in
    its ``-o`` list."""
    args = [str(a) for a in cmd[1:]]
    if "-r" in args or "--read-only" in args:
        return True
    opts = _flag_value(args, ("-o", "--options")) or ""
    return "ro" in opts.split(",")


def _exposes_only(cmd: list[str]) -> bool:
    """The command mounts or unmounts evidence read-only; it cannot alter it."""
    b = _binary(cmd)
    if b in _FUSE_EXPOSERS or b == "umount":
        return True
    return b == "mount" and _read_only_mount(cmd)


def _writes(cmd: list[str]) -> bool:
    b = _binary(cmd)
    if b not in _WRITE_CAPABLE or _exposes_only(cmd):
        return False
    flags = _WRITE_FLAGS.get(b)
    if flags is None:
        return True
    rest = [str(a) for a in cmd[1:]]
    if any(a == f or a.startswith(f) for a in rest for f in flags):
        return True
    # tar's bundled short form: "-xf", "xf", "-czf"
    if b == "tar" and rest:
        first = rest[0].lstrip("-")
        return any(ch in first for ch in "xcru") and not first.startswith("t")
    return False


_PATH_IN_TOKEN_RE = re.compile(r"(?:(?<![\w.])/|(?<![\w/])evidence/)[^\s'\"()<>|;,]+")


def _paths_in(token: str) -> list[str]:
    """Every path-shaped substring of one argument.

    An interpreter's ``-c`` script, ``of=/x``, ``--out=/x`` and a quoted
    path all carry their target *inside* the token; testing the token as
    a whole saw none of them (``python3 -c "open('…/evidence/side.txt',
    'w')"`` wrote its file unremarked on the first pen test).
    """
    token = str(token)
    out = [m.group(0).rstrip("/") or "/" for m in _PATH_IN_TOKEN_RE.finditer(token)]
    # "evidence/My Host/file.csv" as one argv element: the regex stops at
    # the space, so also take the whole token when it names something real.
    whole = token.strip("\"'").rstrip("/")
    if whole and whole not in out and any(ch.isspace() for ch in whole) \
            and os.path.lexists(whole):
        out.append(whole)
    return out


def _evidence_args(cmd: list[str]) -> list[str]:
    out = []
    for a in cmd[1:]:
        for piece in _paths_in(a):
            if is_evidence_path(piece) and piece not in out:
                out.append(piece)
    return out


# Where each tool puts its output is knowledge about the tool, not about
# any case: cp/mv-style tools write their last operand, dd its ``of=``,
# archivers the directory they extract into (or the archive they create),
# compressors a sibling of each operand. Anything else is assumed to write
# every operand. The old rule ("any evidence path named by a writing tool")
# refused ``tar -xf evidence/kape.zip -C analysis/`` — the ordinary way an
# export is unpacked — because the archive it *reads* lives in evidence.
_TARGET_IS_LAST = frozenset({"cp", "mv", "install", "rsync", "scp", "ln"})
_COMPRESSORS = frozenset({"gzip", "gunzip", "bzip2", "xz"})
_NO_WRITE_FLAGS = frozenset({"-t", "--list", "-l", "--test", "-c", "--stdout",
                             "--to-stdout", "-k"})


def _flag_value(args: list[str], flags: tuple[str, ...]) -> str | None:
    """Value of the first of ``flags`` present, in any of the spellings
    ``-C dir``, ``-Cdir``, ``--directory=dir``."""
    for i, a in enumerate(args):
        for f in flags:
            if a == f:
                return args[i + 1] if i + 1 < len(args) else None
            if a.startswith(f + "="):
                return a[len(f) + 1:]
            if len(f) == 2 and len(a) > 2 and a.startswith(f) and a[1] != "-":
                return a[2:]
    return None


def _targets(cmd: list[str], *, every_operand: bool = False) -> list[str]:
    """Every location a write-capable command could write to.

    For a tool whose target is known (cp, tar, dd …) that target alone.
    For any other writer, the path-shaped tokens it names — and, with
    ``every_operand``, each operand as well: a relative operand resolves
    inside the case, so listing them all costs nothing there, while a
    sed script or a date string mistaken for a path under a read-only
    case root would be a false evidence refusal.
    """
    b = _binary(cmd)
    args = [str(a) for a in cmd[1:]]
    operands = [a for a in args if not a.startswith("-")]
    out: list[str] = []
    if b in _TARGET_IS_LAST:
        into = _flag_value(args, ("-t", "--target-directory"))
        if into:
            out = [into]
        elif len(operands) >= 2:
            out = [operands[-1]]
    elif b == "dd":
        out = [a[3:] for a in args if a.startswith("of=")]
    elif b == "tar":
        first = args[0] if args else ""
        letters = first.lstrip("-") if not first.startswith("--") else ""
        longs = set(args)
        if "x" in letters or longs & {"--extract", "--get"}:
            out = [_flag_value(args, ("-C", "--directory")) or "."]
        elif any(ch in letters for ch in "cru") or longs & {
                "--create", "--append", "--update", "--delete"}:
            f = _flag_value(args, ("-f", "--file"))
            if f is None and "f" in letters and operands:
                f = operands[0]
            out = [f or "."]
    elif b == "unzip":
        out = [_flag_value(args, ("-d",)) or "."]
    elif b in ("7z", "7za"):
        verb = operands[0] if operands else ""
        if verb in ("x", "e"):
            out = [next((a[2:] for a in args if a.startswith("-o")), ".")]
        elif verb in ("a", "d", "u", "rn"):
            out = operands[1:2]
    elif b in _COMPRESSORS:
        if not any(a in _NO_WRITE_FLAGS for a in args):
            out = [os.path.dirname(o) or "." for o in operands]
    else:
        # Paths carried *inside* a token — an interpreter's -c script,
        # --out=/x — name real places whatever the tool is.
        out = list(operands) if every_operand else []
        for a in args:
            out.extend(_paths_in(a))
    seen: list[str] = []
    for t in out:
        if t and t not in seen:
            seen.append(t)
    return seen


def _write_targets(cmd: list[str]) -> list[str]:
    """The evidence paths this command could change."""
    return [p for p in _targets(list(cmd)) if is_evidence_path(p)]


def refuse_outside_case_write(cmd: list[str], *, case_dir: str | None = None,
                              cwd: str | None = None) -> dict[str, Any] | None:
    """A refusal dict when a writing command targets anything outside the
    active case (and the temp dir), else None. Nothing outside a run."""
    case_dir = case_dir or active_case_dir()
    if not case_dir or not cmd or not _writes(list(cmd)):
        return None
    base = cwd or os.getcwd()
    # A run works from inside its case (agent/cli.py chdir's there), so
    # the working directory is normally the case itself; listing it keeps
    # a relative write honest wherever the process was started.
    roots = output_roots(case_dir) + [base]
    for t in _targets(list(cmd), every_operand=True):
        full = t if os.path.isabs(t) else os.path.join(base, t)
        if not any(is_inside(full, r) for r in roots):
            return {
                "success": False,
                "gate": "outside_case_write_refused",
                "error": (
                    f"{_binary(cmd)!r} can modify files and the command "
                    f"targets {t!r}, which is outside the case directory. "
                    "Outputs belong under the case's analysis/, exports/ or "
                    "reports/."
                ),
                "rejected_cmd": " ".join(str(a) for a in cmd)[:200],
            }
    return None


def refuse_evidence_write(cmd: list[str]) -> dict[str, Any] | None:
    """A refusal dict when ``cmd`` would write into evidence, else None."""
    if not cmd or not _writes(list(cmd)):
        return None
    targets = _write_targets(list(cmd))
    if not targets:
        return None
    return {
        "success": False,
        "gate": "evidence_write_refused",
        "error": (
            f"{_binary(cmd)!r} can modify files and the command names a "
            f"protected evidence path ({targets[0]}). Evidence is read-only: "
            "write outputs under analysis/, exports/ or reports/ instead."
        ),
        "rejected_cmd": " ".join(str(a) for a in cmd)[:200],
    }


def _stat_key(path: str) -> tuple | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_mode)


def _referenced_paths(cmd: list[str]) -> list[str]:
    """Evidence paths the command names, plus the evidence directories any
    of its arguments point into — so a file written *beside* the one
    named (a sidecar, a new dump) is seen as well."""
    out: list[str] = []
    for a in cmd[1:]:
        for piece in _paths_in(a):
            for cand in (piece, os.path.dirname(piece)):
                if cand and is_evidence_path(cand) and cand not in out:
                    out.append(cand)
    return out


def snapshot_evidence_refs(cmd: list[str]) -> dict[str, tuple | None]:
    """``{path: stat-or-None}`` for every evidence path the command names
    and the immediate children of every evidence directory it touches."""
    snap: dict[str, tuple | None] = {}
    if _exposes_only(list(cmd)):
        return snap  # the mount point changes by design; the evidence cannot
    for p in _referenced_paths(list(cmd)):
        snap[p] = _stat_key(p)
        if os.path.isdir(p):
            try:
                for i, name in enumerate(os.listdir(p)):
                    if i >= _MAX_SNAPSHOT_CHILDREN:
                        break
                    child = os.path.join(p, name)
                    snap[child] = _stat_key(child)
            except OSError:
                pass
    return snap


def evidence_changes(before: dict[str, tuple | None],
                     cmd: list[str]) -> list[dict[str, str]]:
    """What changed among the snapshotted paths, as ``[{path, change}]``."""
    after = snapshot_evidence_refs(cmd)
    changes: list[dict[str, str]] = []
    for path in sorted(set(before) | set(after)):
        b, a = before.get(path), after.get(path)
        if b == a:
            continue
        change = ("created" if b is None else
                  "removed" if a is None else "modified")
        changes.append({"path": path, "change": change})
    return changes
