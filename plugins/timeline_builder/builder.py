"""Collect, persist, merge, sort, and dedupe normalized timeline events."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from plugins.timeline_builder.models import NormalizedTimelineEvent

_OUTPUT_DIR = "reports"
_BUILD_DIR = ".timeline_build"
_EVENTS_FILE = "events.jsonl"
_MASTER_TIMELINE = "master_timeline.tsv"
_LOCK = threading.Lock()
_INSTANCES: dict[str, "TimelineBuilder"] = {}


class TimelineBuilder:
    """One global investigation timeline per case directory."""

    def __init__(self, case_dir: Path) -> None:
        self.case_dir = Path(case_dir)
        self.output_dir = self.case_dir / _OUTPUT_DIR
        self.build_dir = self.output_dir / _BUILD_DIR
        self.events_path = self.build_dir / _EVENTS_FILE
        self.master_timeline_path = self.output_dir / _MASTER_TIMELINE
        self._events: list[NormalizedTimelineEvent] = []
        self._loaded = False

    @classmethod
    def for_case(cls, case_dir: str | Path | None) -> "TimelineBuilder | None":
        if not case_dir:
            return None
        key = os.path.abspath(str(case_dir))
        with _LOCK:
            if key not in _INSTANCES:
                _INSTANCES[key] = cls(Path(key))
            return _INSTANCES[key]

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.events_path.is_file():
            return
        try:
            for line in self.events_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                self._events.append(NormalizedTimelineEvent.from_json(json.loads(line)))
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    def append(self, event: NormalizedTimelineEvent) -> None:
        self._ensure_loaded()
        self._events.append(event)
        self._persist_one(event)

    def append_many(self, events: list[NormalizedTimelineEvent]) -> int:
        n = 0
        for ev in events:
            self.append(ev)
            n += 1
        return n

    def _persist_one(self, event: NormalizedTimelineEvent) -> None:
        self.build_dir.mkdir(parents=True, exist_ok=True)
        with open(self.events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_json(), ensure_ascii=False, default=str) + "\n")

    def all_events(self) -> list[NormalizedTimelineEvent]:
        self._ensure_loaded()
        return list(self._events)

    def merged_sorted_deduped(self) -> list[NormalizedTimelineEvent]:
        """Single chronology: sort, merge duplicates."""
        self._ensure_loaded()
        seen: set[tuple] = set()
        out: list[NormalizedTimelineEvent] = []
        for ev in sorted(self._events, key=lambda e: (e.timestamp, e.host, e.event_type)):
            key = ev.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            out.append(ev)
        return out

    def clear(self) -> None:
        with _LOCK:
            key = os.path.abspath(str(self.case_dir))
            _INSTANCES.pop(key, None)
        self._events.clear()
        try:
            if self.events_path.is_file():
                self.events_path.unlink()
        except OSError:
            pass
