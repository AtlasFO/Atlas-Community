"""Cross-process run lock (core/run_lock.py).

The interesting case is the one that looks re-entrant: `is_locked()` opens a
*second* file descriptor on a file this same process may already hold. Linux
flock treats separate open file descriptions independently, so the second
acquire is denied and `release()` is never reached — but that is subtle
enough to be worth pinning down, because if it ever behaved the other way
`is_locked()` would silently drop a live run's lock.
"""
from __future__ import annotations

import multiprocessing

import pytest

from core import run_lock


def test_acquire_then_release_round_trips(tmp_path):
    fd = run_lock.acquire(tmp_path)
    assert (tmp_path / ".atlas" / "run.lock").is_file()
    run_lock.release(fd)
    # Released — a fresh acquire must succeed.
    run_lock.release(run_lock.acquire(tmp_path))


def test_release_tolerates_none():
    run_lock.release(None)  # no exception


def test_is_locked_is_false_when_free(tmp_path):
    assert run_lock.is_locked(tmp_path) is False


def test_is_locked_from_the_holding_process_does_not_drop_the_lock(tmp_path):
    """is_locked() must be safe to call from the lock holder itself.

    It opens its own fd; if flock were re-entrant within a process that
    probe would succeed and its release() would unlock the real run.
    """
    fd = run_lock.acquire(tmp_path)
    try:
        assert run_lock.is_locked(tmp_path) is True
        # The original lock must still be held afterwards: a *different*
        # process must still be refused.
        assert _locked_from_child(tmp_path) is True
    finally:
        run_lock.release(fd)
    assert run_lock.is_locked(tmp_path) is False


def _child_probe(path, q):
    from core import run_lock as rl
    q.put(rl.is_locked(path))


def _locked_from_child(path) -> bool:
    ctx = multiprocessing.get_context("fork")
    q = ctx.Queue()
    p = ctx.Process(target=_child_probe, args=(str(path), q))
    p.start()
    p.join(10)
    return q.get(timeout=5)


def test_second_process_is_refused_while_held(tmp_path):
    fd = run_lock.acquire(tmp_path)
    try:
        assert _locked_from_child(tmp_path) is True
    finally:
        run_lock.release(fd)
    assert _locked_from_child(tmp_path) is False


def test_acquire_raises_runlockederror_for_a_second_holder(tmp_path):
    fd = run_lock.acquire(tmp_path)
    try:
        with pytest.raises(run_lock.RunLockedError):
            run_lock.acquire(tmp_path)
    finally:
        run_lock.release(fd)
