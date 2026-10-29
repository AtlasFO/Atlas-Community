"""One process-wide lock for the case's JSON stores: the claim graph, the
task store and the coverage ledger. Every load-modify-save of them holds it,
so the threads beside the item thread (triage, plans, coverage) never lose
another's update or read a store half written. One lock for the three
because their writers call each other (a supersession carries the task
links, a credit reads the graph), so no lock order can deadlock; it is
reentrant, so a writer may call another."""
from __future__ import annotations

import functools
import os
import threading
from pathlib import Path

STORE_LOCK = threading.RLock()


def locked(fn):
    """Run ``fn`` holding the store lock."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with STORE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


def write_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` whole or not at all: a reader sees the
    old file or the new one, never a truncated one."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
