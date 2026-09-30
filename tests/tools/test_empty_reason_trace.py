"""Empty reasoning responses must be failures in the execution trace."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_empty_openai_compat_logs_failure_with_diagnostics(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    from tools import reasoning as R

    monkeypatch.setattr(R, "REASON_URL", "http://example.test/v1")
    monkeypatch.setattr(R, "REASON_API_KEY", "k")
    monkeypatch.setattr(R, "REASON_MODEL", "gpt-5-mini")
    monkeypatch.setattr(R, "REASON_BACKEND", "openai-compat")

    body = {
        "choices": [{
            "finish_reason": "length",
            "message": {"content": ""},
        }],
        "usage": {
            "prompt_tokens": 50,
            "completion_tokens": 4096,
            "completion_tokens_details": {"reasoning_tokens": 4096},
        },
    }

    class _Resp:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return body

    elog = ExecutionLog()
    elog.configure("EMPTY-REASON", str(tmp_path / "trace.json"),
                   save_session=False)

    with patch("httpx.post", return_value=_Resp()), \
         patch("core.execution_log.log", elog):
        result = R._ask_openai_compat(
            "system", "user question", "reason_hypothesize")

    assert result["success"] is False
    assert result.get("gate") == "empty_reason_response"
    assert result.get("finish_reason") == "length"
    assert int(result.get("reasoning_tokens") or 0) == 4096
    assert "error" in result and result["error"]

    reason_entries = [
        e for e in elog._entries
        if e.get("type") == "reason_call"
        and e.get("tool") == "reason_hypothesize"
    ]
    assert reason_entries
    last = reason_entries[-1]
    assert last.get("success") is False
    assert last.get("gate") == "empty_reason_response" or last.get("error")
    assert (last.get("conclusion") or "") == ""


def test_directives_only_response_is_not_success(tmp_path, monkeypatch):
    """DIRECTIVES-only prose must fail closed (empty post-strip conclusion)."""
    from core.execution_log import ExecutionLog
    from tools import reasoning as R

    monkeypatch.setattr(R, "REASON_URL", "http://example.test/v1")
    monkeypatch.setattr(R, "REASON_API_KEY", "k")
    monkeypatch.setattr(R, "REASON_MODEL", "gpt-5-mini")
    monkeypatch.setattr(R, "REASON_BACKEND", "openai-compat")

    body = {
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "content": (
                    "DIRECTIVES:\n"
                    '{"priority_tools": ["table.query"], '
                    '"required_actions": [], "open_questions": [], '
                    '"blocked_on": []}\n'
                ),
            },
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 40,
            "completion_tokens_details": {"reasoning_tokens": 0},
        },
    }

    class _Resp:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return body

    elog = ExecutionLog()
    elog.configure("DIR-ONLY", str(tmp_path / "trace.json"),
                   save_session=False)

    with patch("httpx.post", return_value=_Resp()), \
         patch("core.execution_log.log", elog):
        result = R._ask_openai_compat(
            "system", "user question", "reason_synthesize")

    assert result["success"] is False
    assert result.get("gate") == "empty_reason_response"
    assert (result.get("conclusion") or "") == ""


def test_pre_report_rejects_failed_empty_synthesize(tmp_path):
    from core.execution_log import ExecutionLog
    from tools.reasoning import reason_pre_report_check

    elog = ExecutionLog()
    elog.configure("PRE-EMPTY", str(tmp_path / "trace.json"),
                   save_session=False)
    elog.record_reason_call(
        "reason_plan", True, "Plan: inventory then table.query", {})
    elog.record_reason_call(
        "reason_synthesize", False, "", {},
        error="empty", finish_reason="length",
        reasoning_tokens=4096, gate="empty_reason_response")

    with patch("core.execution_log.log", elog):
        r = reason_pre_report_check()

    assert r["has_synthesize"] is False
    assert r["ready_to_report"] is False
    assert any("synthesize" in i.lower() for i in r["blocking_issues"])
