"""The tool registry is read once per process; its first read imports the
server, whose tools ask the trace log for its case. A caller that holds the
log's lock (the work order's matcher) gets the registry at once: the import
runs in the calling thread, never in a worker that would wait on that lock.
Invented fixture: a stand-in server module."""
from __future__ import annotations

import sys
import threading
import time

import core.execution_log as elog
import tools.tool_capabilities as tc

FAKE_SERVER = '''
from core.execution_log import log
log.case_dir()                       # what the real tools do at import


class _Tool:
    name = "misc_example_tool"
    parameters = {"properties": {}}
    description = "x"


class mcp:
    @staticmethod
    def list_tools():
        return [_Tool()]
'''


def test_a_lock_holder_gets_the_registry_promptly(tmp_path, monkeypatch):
    (tmp_path / "server.py").write_text(FAKE_SERVER, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "server", raising=False)
    monkeypatch.setattr(tc, "_REGISTERED", None)
    got: list = []

    def holder():
        with elog.log._lock:
            got.append(tc.registered_tool_schemas())
    t0 = time.monotonic()
    th = threading.Thread(target=holder, daemon=True)
    th.start()
    th.join(timeout=20)
    assert not th.is_alive() and time.monotonic() - t0 < 20
    assert [r[0] for r in got[0]] == ["misc_example_tool"]


def test_an_import_error_is_no_registry_and_no_block(tmp_path, monkeypatch):
    (tmp_path / "server.py").write_text("raise ImportError('no server here')\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "server", raising=False)
    monkeypatch.setattr(tc, "_REGISTERED", None)
    assert tc.registered_tool_schemas() == []
