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
import io
import os
import re
import unicodedata
import subprocess
import threading
from pathlib import Path

# KEY=value, optionally commented out, leading whitespace tolerated. Deliberately
# not a full dotenv parser — this only has to recognise the line it will replace.
_ASSIGN = re.compile(r"^[ \t]*(?P<commented>#[ \t]*)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=")
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def unsafe_value(value: str) -> str | None:
    """Why ``value`` cannot be one line of the env file, or None. A line is
    read with str.splitlines, here and by python-dotenv's reader, which
    breaks on more than CR and LF: every character of Unicode category Cc
    (C0, DEL, C1, U+0085 among them), Zl (U+2028) or Zp (U+2029). A value
    holding one would come back as a second assignment."""
    for ch in str(value):
        if unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            return f"it holds the control or line-break character U+{ord(ch):04X}"
    return None


def _check_updates(updates: dict[str, str | None]) -> None:
    for key, value in updates.items():
        if not _KEY.match(str(key)):
            raise ValueError(f"{key!r} is not a variable name; nothing was written")
        if value is None:
            continue                      # a removal writes nothing
        why = unsafe_value(value)
        if why:
            raise ValueError(f"{key}: {why}; nothing was written")

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
    """Active (uncommented) assignments as the env loader (python-dotenv)
    reads them at a start: quotes and their escapes undone, a trailing
    comment cut, the last assignment winning; no variable is expanded."""
    from dotenv import dotenv_values
    text = Path(path).read_text(encoding="utf-8")
    return {key: value for key, value in dotenv_values(stream=io.StringIO(text), interpolate=False).items()
            if value is not None}


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


def env_flag(name: str, default: bool = True) -> bool:
    """A behaviour switch read at call time: "0", "false", "no" and "off"
    (any case, inline comment allowed) turn it off, "1", "true", "yes" and
    "on" turn it on, anything else or an unset variable gives `default`.
    Read where the behaviour branches, never at import, so a test or an
    operator can flip it for one call."""
    raw = os.environ.get(name)
    if not raw:
        return default
    value = _strip_inline_comment(raw).strip().lower()
    if value in ("0", "false", "no", "off"):
        return False
    if value in ("1", "true", "yes", "on"):
        return True
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


def _line(key: str, value: str) -> str:
    """``key=value`` as every reader of the env file reads it back:
    python-dotenv (the CLI, and the dashboard at its start), systemd's
    EnvironmentFile and docker compose's env_file. A value the plain form
    would change goes in double quotes: whitespace at either end (stripped:
    an auth prefix "Token " would load as "Token"), a quote at the start
    (read as quoting), a '#' after whitespace (read as a comment). Inside,
    only backslash and double quote are escaped, the two escapes all three
    readers decode alike; the escaped backslash also keeps python-dotenv from
    decoding a backslash sequence of the value (n, t) as a control character.
    Not single quotes: systemd and compose read them literally, while
    python-dotenv decodes two escapes in them."""
    if value == value.strip() and value[:1] not in ("'", '"') and not re.search(r"\s#", value):
        return f"{key}={value}"
    return f'{key}="' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def set_values(path: str | os.PathLike, updates: dict[str, str | None]) -> None:
    """Apply `updates` to the env file, replacing in place where the key exists.

    Keys not present are appended in the order given. Duplicate assignments of a
    replaced key are removed, so exactly one live line remains per key. A value
    of None removes every assignment of its key (a commented one too, which
    may hold an old secret) and appends nothing.
    """
    if not updates:
        return
    # Every value is one line, refused before the file is opened.
    _check_updates(updates)
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
                        if updates[key] is not None and key not in written:
                            out.append(_line(key, updates[key]))
                            written.add(key)
                        continue  # later copies of the same key are dropped
                    out.append(line)

                for key, value in updates.items():
                    if key not in written and value is not None:
                        out.append(_line(key, value))

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

    Whitespace at either end of ``value`` is a paste's, never the key's: it
    is dropped, and a value of whitespace only stores nothing.
    """
    value = value.strip()
    if not value:
        return {"stored": "skip"}
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
