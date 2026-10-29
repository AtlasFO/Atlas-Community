"""A timeout-wrapped tool body runs in the caller's context: a program it
runs logs its entry with the call's action id, and the middleware stamps
that entry with the call's arguments (with the names a tool's trace
withholds left out). Invented values."""
from __future__ import annotations

import pytest

from core import middleware
from core.execution_log import ExecutionLog, current_action_id
from core.timeout import with_tool_timeout


@pytest.fixture
def log(tmp_path, monkeypatch):
    lg = ExecutionLog()
    lg.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", lg)
    return lg


def _call(log, tool_name, args):
    @with_tool_timeout(30)
    def body(**_kw):
        cid = log.record_tool_call("file -b analysis/blob.bin", True, False, 0, 0)
        return {"success": True, "_atlas_call_id": cid}
    token = current_action_id.set(41)
    try:
        before = len(log._entries)
        result = body(**args)
        middleware._trace_success_baseline(tool_name, 0.1, before, result=result, args=args, action_id=41)
    finally:
        current_action_id.reset(token)
    return next(e for e in log._entries if e.get("call_id") == result["_atlas_call_id"])


def test_a_program_run_inside_the_watchdog_is_the_calls_own_entry(log):
    entry = _call(log, "strings_file_identify", {"file_path": "analysis/blob.bin"})
    assert entry.get("action_id") == 41
    assert '"file_path": "analysis/blob.bin"' in entry.get("args", "")


def test_the_trace_masking_applies_to_that_entry(log):
    entry = _call(log, "crypto_decrypt", {"file_path": "analysis/blob.bin", "key": "00112233445566778899aabbccddeeff"})
    assert entry.get("action_id") == 41 and "file_path" in entry.get("args", "")
    assert "00112233" not in entry.get("args", "")
