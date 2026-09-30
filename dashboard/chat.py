"""Chat session manager for the dashboard chat window.

serve.py stays free of the heavy agent stack on its hot path; this module is
imported lazily only when a chat endpoint is hit. It owns one worker
subprocess per case (agent/chat_worker.py, run with cwd=case_dir), forwards
user messages to it, and buffers the worker's JSONL event stream so the
browser can poll it.

Isolation is the point: a wedged or OOM-killed forensic tool takes down only
its own worker, never the long-lived dashboard, and each worker gets the
single-case process model (`cwd`, in-process MCP toolbox, answer-key registry)
that `bin/atlas chat` assumes.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

from core.envfile import env_int

# How long a worker may sit idle (no new message) before it is reaped, and how
# often the reaper wakes. Overridable for the always-on dashboard.
IDLE_SECONDS = env_int("ATLAS_DASHBOARD_CHAT_IDLE", 1800)
MAX_SESSIONS = env_int("ATLAS_DASHBOARD_CHAT_MAX", 6)


class ChatSession:
    """One worker subprocess for one case, plus the buffered event stream.

    The worker speaks newline-delimited JSON on stdout; a reader thread drains
    it into `self.events` (each stamped with a monotonic `index`). `busy` is
    True from the moment a message is sent until the worker emits turn_done.
    """

    def __init__(self, case_dir: str, case_name: str, repo_root: str,
                 model: str = ""):
        self.case_dir = case_dir
        self.case_name = case_name
        self.events: list[dict] = []
        self.busy = False
        self.last_active = time.time()
        self._lock = threading.Lock()

        env = dict(os.environ)
        # The worker is `python -m agent.chat_worker`; the repo root must be on
        # PYTHONPATH for the `agent` package to import (the dashboard is started
        # from the repo root but subprocesses don't inherit sys.path).
        prior = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = repo_root + (os.pathsep + prior if prior else "")
        cmd = [sys.executable, "-m", "agent.chat_worker", "--case", case_dir]
        if model:
            cmd += ["--model", model]
        self.proc = subprocess.Popen(
            cmd, cwd=case_dir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        self._draining = threading.Thread(target=self._drain_stderr, daemon=True)
        self._draining.start()

    # ── worker I/O ───────────────────────────────────────────────────────
    def _read_stdout(self) -> None:
        # readline() (not iteration) so each flushed frame surfaces promptly.
        try:
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    break  # worker exited / closed stdout
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                kind = ev.get("type")
                if kind == "ready":
                    continue  # startup handshake, not a chat event
                if kind == "turn_done":
                    with self._lock:
                        self.busy = False
                        self.last_active = time.time()
                    continue
                # tool_call / assistant / error → surface to the browser
                with self._lock:
                    # Heartbeat while tools run so the idle reaper does not
                    # treat a long forensic turn as an abandoned session.
                    self.last_active = time.time()
                    self._append_locked(ev)
        finally:
            with self._lock:
                if self.busy:
                    # The stream closed mid-turn: the worker died (a tool
                    # that crashed or was OOM-killed takes it down with it).
                    # Say so where the answer would have appeared; the next
                    # message spawns a fresh worker without this conversation.
                    rc = self.proc.poll()
                    self._append_locked({
                        "type": "error",
                        "message": "chat worker exited during the turn"
                                   + (f" (exit code {rc})" if rc is not None else "")
                                   + "; the next message starts a new session "
                                     "without the conversation so far."})
                self.busy = False

    def _drain_stderr(self) -> None:
        """Drain the worker's stderr so its pipe never fills and blocks it.
        Mirror the lines to the dashboard's stderr (prefixed) for debugging."""
        try:
            for line in self.proc.stderr:
                sys.stderr.write(f"[chat {self.case_name}] {line.rstrip()}\n")
        except Exception:  # noqa: BLE001
            pass

    def _append_locked(self, ev: dict) -> int:
        ev = dict(ev)
        ev["index"] = len(self.events)
        self.events.append(ev)
        return ev["index"]

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def send(self, text: str, role: str = "", user: str = "") -> dict:
        """Forward one user message. Refuses if a turn is already running or the
        worker is dead — the browser serializes turns, this is the backstop."""
        with self._lock:
            if not self.alive:
                return {"ok": False, "error": "chat worker is not running"}
            if self.busy:
                return {"ok": False, "busy": True,
                        "error": "a turn is already in progress"}
            self._append_locked({"type": "user", "text": text})
            self.busy = True
            self.last_active = time.time()
            total = len(self.events)
        try:
            self.proc.stdin.write(
                json.dumps({"type": "user", "text": text, "role": role,
                            "user": user}) + "\n")
            self.proc.stdin.flush()
        except OSError as e:
            with self._lock:
                self.busy = False
                self._append_locked(
                    {"type": "error", "message": f"worker not reachable: {e}"})
            return {"ok": False, "error": str(e)}
        return {"ok": True, "total": total}

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            since = max(0, int(since))
            return {
                "events": self.events[since:],
                "total": len(self.events),
                "busy": self.busy,
                "alive": self.alive,
            }

    def close(self) -> None:
        try:
            if self.proc.poll() is None:
                try:
                    self.proc.stdin.write(json.dumps({"type": "shutdown"}) + "\n")
                    self.proc.stdin.flush()
                except OSError:
                    pass
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    try:
                        self.proc.kill()
                    except OSError:
                        pass
        finally:
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                try:
                    stream.close()
                except Exception:  # noqa: BLE001
                    pass


class ChatManager:
    """Per-case ChatSession registry with an LRU cap and an idle reaper."""

    def __init__(self, repo_root: str, max_sessions: int = MAX_SESSIONS,
                 idle_seconds: int = IDLE_SECONDS):
        self.repo_root = repo_root
        self.max_sessions = max(1, max_sessions)
        self.idle_seconds = idle_seconds
        self._sessions: dict[str, ChatSession] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    def _ensure_reaper(self) -> None:
        if self._reaper is None:
            self._reaper = threading.Thread(target=self._reaper_loop,
                                            daemon=True)
            self._reaper.start()

    def _reaper_loop(self) -> None:
        interval = max(30, min(self.idle_seconds, 300))
        while not self._stop.wait(interval):
            try:
                with self._lock:
                    self._reap_locked()
            except Exception:  # noqa: BLE001
                pass

    def _reap_locked(self) -> None:
        """Drop dead or truly-idle sessions.

        A session with ``busy=True`` is mid-turn (often multi-minute EVTX /
        strings work). Never reap those on the idle timer — that would kill
        a chat worker mid-turn while its tools are still running. Idle
        expiry applies only to abandoned idle sessions.
        """
        now = time.time()
        for name, sess in list(self._sessions.items()):
            if not sess.alive:
                sess.close()
                self._sessions.pop(name, None)
                continue
            if sess.busy:
                continue
            if (now - sess.last_active) > self.idle_seconds:
                sess.close()
                self._sessions.pop(name, None)

    def get_or_spawn(self, cases_root: str, case_name: str,
                     model: str = "") -> ChatSession:
        self._ensure_reaper()
        with self._lock:
            self._reap_locked()
            sess = self._sessions.get(case_name)
            if sess is not None and sess.alive:
                sess.last_active = time.time()
                return sess
            if sess is not None:  # dead — replace it
                sess.close()
                self._sessions.pop(case_name, None)
            # LRU-evict to stay under the cap before spawning a new worker.
            # Never evict an in-flight turn; allow a temporary over-cap instead.
            while len(self._sessions) >= self.max_sessions:
                idle = [s for s in self._sessions.values() if not s.busy]
                if not idle:
                    break
                oldest = min(idle, key=lambda s: s.last_active)
                oldest.close()
                self._sessions.pop(oldest.case_name, None)
            case_dir = os.path.join(cases_root, case_name)
            sess = ChatSession(case_dir, case_name, self.repo_root, model)
            self._sessions[case_name] = sess
            return sess

    def peek(self, case_name: str) -> ChatSession | None:
        with self._lock:
            sess = self._sessions.get(case_name)
            # Browser poll heartbeat — keeps last_active fresh while the UI
            # watches a long turn (complements the busy-skip in _reap_locked).
            if sess is not None and sess.alive:
                sess.last_active = time.time()
            return sess

    def close_all(self) -> None:
        self._stop.set()
        with self._lock:
            for sess in self._sessions.values():
                sess.close()
            self._sessions.clear()


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANAGER = ChatManager(repo_root=_REPO_ROOT)
