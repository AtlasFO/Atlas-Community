"""Idle reaper must not kill an in-flight chat turn; a worker that dies
mid-turn must say so instead of ending the turn in silence."""
from __future__ import annotations

import io
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from dashboard.chat import ChatManager, ChatSession
import dashboard.chat as chat_mod


def _session_at_eof(busy: bool, returncode) -> ChatSession:
    """A ChatSession whose worker stdout is already closed — no subprocess."""
    sess = ChatSession.__new__(ChatSession)
    sess.case_name = "Test"
    sess.events = []
    sess.busy = busy
    sess.last_active = time.time()
    sess._lock = threading.Lock()
    sess.proc = SimpleNamespace(stdout=io.StringIO(""), poll=lambda: returncode)
    return sess


def test_worker_exit_mid_turn_surfaces_an_error_event():
    sess = _session_at_eof(busy=True, returncode=-9)
    sess._read_stdout()
    assert sess.busy is False
    assert sess.events and sess.events[-1]["type"] == "error"
    assert "exited" in sess.events[-1]["message"]


def test_worker_exit_between_turns_is_quiet():
    sess = _session_at_eof(busy=False, returncode=0)
    sess._read_stdout()
    assert sess.events == []


def test_reaper_skips_busy_session_even_when_idle_expired():
    mgr = ChatManager(repo_root="/tmp", idle_seconds=60)
    busy = SimpleNamespace(
        busy=True,
        last_active=time.time() - 9999,
        case_name="Test",
        alive=True,
        close=MagicMock(),
    )
    idle = SimpleNamespace(
        busy=False,
        last_active=time.time() - 9999,
        case_name="Other",
        alive=True,
        close=MagicMock(),
    )
    mgr._sessions = {"Test": busy, "Other": idle}
    mgr._reap_locked()

    busy.close.assert_not_called()
    assert "Test" in mgr._sessions
    idle.close.assert_called_once()
    assert "Other" not in mgr._sessions


def test_reaper_removes_dead_busy_session():
    mgr = ChatManager(repo_root="/tmp", idle_seconds=60)
    dead = SimpleNamespace(
        busy=True,
        last_active=time.time(),
        case_name="Test",
        alive=False,
        close=MagicMock(),
    )
    mgr._sessions = {"Test": dead}
    mgr._reap_locked()
    dead.close.assert_called_once()
    assert "Test" not in mgr._sessions


def test_lru_evict_skips_busy_sessions():
    mgr = ChatManager(repo_root="/tmp", max_sessions=1, idle_seconds=3600)
    busy = SimpleNamespace(
        busy=True,
        last_active=time.time() - 100,
        case_name="BusyCase",
        alive=True,
        close=MagicMock(),
    )
    mgr._sessions = {"BusyCase": busy}

    fake_new = SimpleNamespace(
        case_name="NewCase",
        alive=True,
        last_active=time.time(),
        busy=False,
        close=MagicMock(),
    )
    with patch.object(chat_mod, "ChatSession", return_value=fake_new):
        sess = mgr.get_or_spawn("/tmp/cases", "NewCase")

    assert sess is fake_new
    busy.close.assert_not_called()
    assert "BusyCase" in mgr._sessions
    assert "NewCase" in mgr._sessions


def test_peek_refreshes_last_active():
    mgr = ChatManager(repo_root="/tmp", idle_seconds=60)
    sess = SimpleNamespace(
        busy=True,
        last_active=0.0,
        case_name="Test",
        alive=True,
        close=MagicMock(),
    )
    mgr._sessions = {"Test": sess}
    before = sess.last_active
    out = mgr.peek("Test")
    assert out is sess
    assert sess.last_active > before
