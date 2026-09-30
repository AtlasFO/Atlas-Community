"""Minimal in-place editor for the repo's `.env`.

`atlas provider use` has to change configuration that lives in `.env`, and hand
editing a file that also holds API keys is how a credential gets clobbered. This
module does the mechanical part and nothing else.

Three properties it exists to guarantee:

**Assignments are replaced, not appended.** python-dotenv keeps the *last*
assignment, so appending a second `REASON_BACKEND=` leaves a stale line above
that reads as if it were live. A commented-out assignment counts as the same key
and is replaced too, because that is what an operator means by "change it".

**The file keeps its identity.** Content is written back into the existing file
rather than a fresh one moved over it: a git worktree usually symlinks its `.env`
at the primary checkout, and replacing the file would break the link and silently
give the two checkouts different configuration. Inode, owner and mode survive.

**Values are never returned or logged.** read_values() exists for presence
checks; callers that want to show configuration must decide for themselves what
is safe to print. Nothing here writes to stdout.

**Writes to the same file are serialized here, not by the caller.** Every
dashboard config page (LLM, OSINT, mail, ...) edits this same `.env` from its
own request-handling thread. A lock that lives in each caller module doesn't
help — two different callers holding two different Lock objects don't block
each other, so a read-modify-write in one can be clobbered by another's
concurrent write. The lock therefore belongs to the resource being shared
(this module), not to whichever module happens to be writing to it: that way
no caller, present or future, can forget to acquire it. Use `lock()` when a
caller needs more than one write (e.g. set_values() followed by
save_secret_value()) to land as one atomic unit.
"""
from __future__ import annotations

import fcntl
import os
import re
import subprocess
import threading
from pathlib import Path

# KEY=value, optionally commented out, leading whitespace tolerated. Deliberately
# not a full dotenv parser — this only has to recognise the line it will replace.
_ASSIGN = re.compile(r"^[ \t]*(?P<commented>#[ \t]*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=")

# Reentrant so a caller holding lock() across several calls (set_values() then
# save_secret_value(), say) doesn't deadlock when those calls take the lock
# again internally.
_write_lock = threading.RLock()


def lock() -> threading.RLock:
    """The lock guarding every write to this repo's `.env`. Hold it with
    `with envfile.lock():` around a sequence of calls that must land as one
    atomic unit — set_values() and save_secret_value() already take it
    internally for a single call, so most callers don't need this directly."""
    return _write_lock


def resolve(repo_root: str | os.PathLike) -> Path:
    """The real `.env` for this checkout, symlinks followed."""
    return Path(os.path.realpath(Path(repo_root) / ".env"))


def read_values(path: str | os.PathLike) -> dict[str, str]:
    """Active (uncommented) assignments, last one winning as dotenv does."""
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = _ASSIGN.match(line)
        if match and not match.group("commented"):
            values[match.group("key")] = line.split("=", 1)[1]
    return values


def _strip_inline_comment(raw: str) -> str:
    """python-dotenv only strips a trailing '# comment' for quoted values or
    a full-line comment — an unquoted 'KEY=600     # explanation' value (the
    house style .env.example uses for every timeout/threshold default) is
    loaded into os.environ *with the comment still attached*, and int() on
    it raises ValueError in every module that parses it at import time —
    core.paths among them, which every dashboard handler imports
    transitively. Every env_int()/env_float() call goes through this so the
    whole class of bug is impossible at every call site."""
    return raw.split("#", 1)[0].strip()


def env_int(name: str, default: int) -> int:
    """int(os.environ[name]) tolerant of a trailing inline comment and of a
    missing/empty/malformed value — falls back to `default` instead of
    raising, because a bad config value must degrade a setting, not crash
    the whole process at import time for every caller downstream."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(_strip_inline_comment(raw))
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    """Same contract as env_int(), for float-valued settings."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(_strip_inline_comment(raw))
    except ValueError:
        return default


def env_str(name: str, default: str = "") -> str:
    """Same contract as env_int(), for string-valued settings: the value with
    any trailing inline comment removed, `default` when unset or empty."""
    raw = os.environ.get(name)
    if not raw:
        return default
    return _strip_inline_comment(raw) or default


def set_values(path: str | os.PathLike, updates: dict[str, str]) -> None:
    """Apply `updates` to the env file, replacing in place where the key exists.

    Keys not present are appended in the order given. Duplicate assignments of a
    replaced key are removed, so exactly one live line remains per key.
    """
    if not updates:
        return
    target = Path(path)
    with _write_lock:
        # threading.RLock above only serializes writers inside this one
        # process. The dashboard (threaded HTTP server) and a concurrent
        # `atlas provider use` (or another dashboard worker process) are
        # different processes entirely and don't share it — an flock on the
        # file itself is what actually makes the read-modify-write atomic
        # across them. Held for the read AND
        # the write via one fd, released on close.
        fd = os.open(str(target), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(fd, "r+", encoding="utf-8", newline="") as handle:
                fd = None  # ownership passed to `handle`; it closes it
                original = handle.read()
                # A file not ending in a newline would otherwise glue an
                # appended key onto the last line.
                ends_clean = original == "" or original.endswith("\n")
                lines = original.splitlines()

                written: set[str] = set()
                out: list[str] = []
                for line in lines:
                    match = _ASSIGN.match(line)
                    key = match.group("key") if match else None
                    if key is not None and key in updates:
                        if key not in written:
                            out.append(f"{key}={updates[key]}")
                            written.add(key)
                        continue  # later copies of the same key are dropped
                    out.append(line)

                for key, value in updates.items():
                    if key not in written:
                        out.append(f"{key}={value}")

                body = "\n".join(out)
                if ends_clean or body:
                    body += "\n"
                # Truncate-and-write in place, not replace: keeps the inode
                # so a worktree symlink pointing here still resolves to the
                # same file.
                handle.seek(0)
                handle.write(body)
                handle.truncate()
        finally:
            if fd is not None:
                os.close(fd)


def save_secret_value(repo_root: str | os.PathLike, env_path: str | os.PathLike,
                      key_var: str, value: str, store_in: str) -> dict:
    """Write an API-key-shaped value to the OS keyring (via bin/atlas-secret)
    or to .env, per `store_in` ("keyring"|"env") — falling back to .env if
    the keyring write fails. Shared by every dashboard config page that
    collects a secret (LLM provider keys, OSINT enrichment keys, ...) so the
    keyring-vs-.env decision and fallback behavior can't drift between them.

    Its own .env write (the "env" and keyring-fallback paths) goes through
    set_values(), which takes lock() internally — callers don't need to hold
    anything themselves unless this call is part of a larger multi-call
    atomic sequence (see lock()'s docstring).
    """
    if store_in == "keyring":
        secret_script = str(Path(repo_root) / "bin" / "atlas-secret")
        try:
            proc = subprocess.run(
                [secret_script, "set", key_var], input=value + "\n",
                text=True, capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            proc = None
            failure = str(exc)
        else:
            failure = proc.stderr.strip() if proc.returncode != 0 else ""
        if proc is not None and proc.returncode == 0:
            # core.secrets skips keyring probes entirely once a primary LLM
            # key is present in the environment (it avoids provoking a GUI
            # unlock prompt for optional credentials). Every working install
            # has such a key, so a secret stored here — an OSINT enrichment
            # key, say — would be written to the vault and then never read
            # back, leaving the tool reporting "not configured" forever.
            # Choosing keyring storage is an explicit opt-in to that vault,
            # so record the opt-in the loader looks for. Never unset: an
            # install that has stored one secret this way still has it.
            set_values(env_path, {"ATLAS_USE_KEYRING": "1"})
            os.environ["ATLAS_USE_KEYRING"] = "1"
            return {"stored": "keyring"}
        set_values(env_path, {key_var: value})
        os.environ[key_var] = value
        return {"stored": "env", "keyring_failed": failure or "no Secret Service"}
    set_values(env_path, {key_var: value})
    os.environ[key_var] = value
    return {"stored": "env"}
