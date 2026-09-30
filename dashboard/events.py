"""Live change feed for the dashboard: which case just changed on disk.

One watcher (watchfiles, inotify-backed; polling on filesystems without
inotify, see WATCHFILES_FORCE_POLLING) on the cases root feeds every
connected browser tab through server-sent events. A tab learns *that* a
case changed and re-fetches the read models it shows; no case data travels
over this channel, so nothing beyond a session has to be authorised here.

Subscribers hold a set of pending case names and an asyncio.Event: a burst
of writes coalesces into one wake-up, and a slow client can never build a
backlog.
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import AsyncIterator, Iterable

from watchfiles import Change, DefaultFilter, awatch


class _Filter(DefaultFilter):
    """The default ignores (VCS dirs, swap files, ...) plus the temp files
    Atlas writes before an atomic rename, the cross-process lock files and
    the orchestrator's dirty marker — bookkeeping no page renders; the
    rename or the data file next to them is the change worth announcing."""

    ignore_entity_patterns = tuple(DefaultFilter.ignore_entity_patterns) + (
        r"\.tmp$", r"\.lock$", r"orchestrator\.dirty$")


class ChangeFeed:
    def __init__(self, cases_root: str, *, debounce_ms: int = 800):
        self.cases_root = os.path.abspath(cases_root)
        self._roots = {self.cases_root, os.path.realpath(self.cases_root)}
        self.debounce_ms = debounce_ms
        self._subscribers: set[Subscriber] = set()
        self._task: asyncio.Task | None = None
        self._stop: asyncio.Event | None = None

    async def start(self) -> None:
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        for sub in list(self._subscribers):
            sub.close()

    def cases_for(self, changes: Iterable[tuple[Change, str]]) -> set[str]:
        """Case dir names touched by a watcher batch: the first path
        component under the cases root. A file at the root itself (nothing a
        page re-reads), hidden entries and the dashboard's own folder are
        skipped."""
        out: set[str] = set()
        for _change, path in changes:
            for root in self._roots:
                rel = os.path.relpath(path, root)
                if not rel.startswith(".."):
                    break
            else:
                continue
            head, sep, _rest = rel.partition(os.sep)
            if not sep or head.startswith(".") or head == "_dashboard":
                continue
            out.add(head)
        return out

    def publish(self, cases: set[str]) -> None:
        for sub in list(self._subscribers):
            sub.pending.update(cases)
            sub.wake.set()

    def subscribe(self) -> "Subscriber":
        sub = Subscriber(self)
        self._subscribers.add(sub)
        return sub

    async def _run(self) -> None:
        try:
            async for changes in awatch(
                    self.cases_root, watch_filter=_Filter(),
                    debounce=self.debounce_ms, step=100,
                    stop_event=self._stop):
                cases = self.cases_for(changes)
                if cases:
                    self.publish(cases)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # Best effort: without the feed every tab still polls on its
            # timer, it just does not learn about changes the moment they
            # land.
            sys.stderr.write(f"[dashboard] change feed stopped: "
                             f"{exc.__class__.__name__}: {exc}\n")


class Subscriber:
    def __init__(self, feed: ChangeFeed):
        self._feed = feed
        self.pending: set[str] = set()
        self.wake = asyncio.Event()
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self._feed._subscribers.discard(self)
        self.wake.set()

    async def events(self) -> AsyncIterator[set[str]]:
        """Yields the set of cases that changed since the last yield; ends
        when the subscriber is closed (client gone or server stopping)."""
        try:
            while not self.closed:
                await self.wake.wait()
                self.wake.clear()
                if self.closed:
                    break
                cases, self.pending = self.pending, set()
                if cases:
                    yield cases
        finally:
            self.close()
