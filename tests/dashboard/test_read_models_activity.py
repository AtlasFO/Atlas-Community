"""Tests for dashboard/read_models.py's process-liveness-based activity
signal (agent_busy, run_process_alive, activity_projection).

Bug this fixes: agent_busy() used to check only "did agent_transcript_*.jsonl
grow in the last 90s". A long tool call (img_vmdk_export_raw's qemu-img
convert, which can run for hours) writes nothing to the transcript while it
runs, so the dashboard's "Current activity" card said "No active run" while
the agent process — and the tool — were both still very much alive. Fixed
by checking the pid agent/loop.py's _persist_live_status() now records in
run_status.json, with transcript growth kept only as a fallback."""
from __future__ import annotations

import json
import os

import pytest
import time
from datetime import datetime, timezone

from dashboard import read_models

_DEAD_PID = 2**31 - 1  # not a real PID on any Linux system this runs on


def _write_run_status(case_dir, **fields):
    atlas = case_dir / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    (atlas / "run_status.json").write_text(json.dumps(fields), encoding="utf-8")


class TestPidAlive:
    def test_own_pid_is_alive(self):
        assert read_models._pid_alive(os.getpid()) is True

    def test_improbable_pid_is_not_alive(self):
        assert read_models._pid_alive(_DEAD_PID) is False

    def test_none_or_zero_is_not_alive(self):
        assert read_models._pid_alive(None) is False
        assert read_models._pid_alive(0) is False


class TestRunProcessAlive:
    def test_no_run_status_file(self, tmp_path):
        assert read_models.run_process_alive(str(tmp_path)) is False

    def test_running_with_live_pid(self, tmp_path):
        _write_run_status(tmp_path, stopped_reason="running", pid=os.getpid())
        assert read_models.run_process_alive(str(tmp_path)) is True

    def test_running_with_dead_pid(self, tmp_path):
        _write_run_status(tmp_path, stopped_reason="running", pid=_DEAD_PID)
        assert read_models.run_process_alive(str(tmp_path)) is False

    def test_finished_with_live_pid_is_not_alive(self, tmp_path):
        # A finished run's stopped_reason changes away from "running" even
        # if its pid happens to still resolve to some (unrelated) process —
        # the status field, not just the pid, gates aliveness.
        _write_run_status(tmp_path, stopped_reason="finished", pid=os.getpid())
        assert read_models.run_process_alive(str(tmp_path)) is False


class TestAgentBusy:
    def test_busy_via_process_liveness_with_no_transcript_at_all(self, tmp_path):
        # A long tool call, nothing written to analysis/ in ages (or ever,
        # in this test), but the process is alive.
        _write_run_status(tmp_path, stopped_reason="running", pid=os.getpid())
        assert read_models.agent_busy(str(tmp_path)) is True

    def test_not_busy_when_nothing_present(self, tmp_path):
        assert read_models.agent_busy(str(tmp_path)) is False

    def test_busy_via_transcript_fallback(self, tmp_path):
        analysis = tmp_path / "analysis"
        analysis.mkdir()
        (analysis / "agent_transcript_1.jsonl").write_text("{}\n", encoding="utf-8")
        assert read_models.agent_busy(str(tmp_path)) is True

    def test_chat_transcript_is_not_a_run_signal(self, tmp_path):
        # A chat about the case writes its own transcript; only a run's
        # transcript may light the "Atlas working" indicator.
        analysis = tmp_path / "analysis"
        analysis.mkdir()
        (analysis / "chat_transcript_1.jsonl").write_text("{}\n", encoding="utf-8")
        assert read_models.agent_busy(str(tmp_path)) is False


class TestActivityProjection:
    def test_stale_logs_surfaces_current_tool_and_elapsed(self, tmp_path):
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_run_status(
            tmp_path, stopped_reason="running", pid=os.getpid(),
            activity="\u23f5 img_vmdk_export_raw", tool_started_at=started_at)
        result = read_models.activity_projection(str(tmp_path))
        assert result["busy"] is True
        assert result["current_tool"] == "img_vmdk_export_raw"
        assert result["logs_stale"] is True
        assert result["tool_running_seconds"] is not None
        assert result["tool_running_seconds"] < 5  # just wrote it

    def test_not_busy_reports_no_current_tool(self, tmp_path):
        result = read_models.activity_projection(str(tmp_path))
        assert result["busy"] is False
        assert result["current_tool"] == ""
        assert result["logs_stale"] is False

    def test_last_stop_surfaces_llm_error_after_process_exits(self, tmp_path):
        # A run that hits a token/context limit (LLMError in agent/cli.py)
        # exits, and the dashboard must still say why: stopped_reason/error
        # persist after the process is gone (pid is _DEAD_PID: no longer
        # alive).
        _write_run_status(
            tmp_path, stopped_reason="llm_error", pid=_DEAD_PID,
            finish_status="error", error="context length exceeded",
            updated_at="2031-02-04T12:00:00Z")
        result = read_models.activity_projection(str(tmp_path))
        assert result["busy"] is False
        assert result["last_stop"] == {
            "reason": "llm_error", "finish_status": "error",
            "error": "context length exceeded",
            "updated_at": "2031-02-04T12:00:00Z",
        }

    @pytest.mark.parametrize("reason", ["finished", "closed_out"])
    def test_last_stop_absent_for_a_clean_finish(self, tmp_path, reason):
        # "closed_out" is the loop writing the reports itself once the
        # gate passed: as clean an end as the model calling atlas_finish,
        # so it must not draw the abnormal-stop banner either.
        _write_run_status(tmp_path, stopped_reason=reason,
                          pid=_DEAD_PID, finish_status="complete")
        result = read_models.activity_projection(str(tmp_path))
        assert result["last_stop"] is None

    def test_last_stop_absent_while_still_running(self, tmp_path):
        _write_run_status(tmp_path, stopped_reason="running", pid=os.getpid())
        result = read_models.activity_projection(str(tmp_path))
        assert result["busy"] is True
        assert result["last_stop"] is None


class TestFindingStats:
    """The Overview's confidence bar and findings timeline: a histogram plus
    one mark per finding, positioned 0..1 across the run's own timespan so
    the page can draw it without knowing when the run happened."""

    def test_counts_every_tier_and_defaults_unconfirmed(self):
        stats = read_models._finding_stats([
            {"confidence": "CONFIRMED", "ts": "2026-01-01T00:00:00Z"},
            {"confidence": "likely", "ts": "2026-01-01T00:30:00Z"},
            {"confidence": None, "ts": "2026-01-01T01:00:00Z"},
        ])
        assert stats["by_confidence"] == {
            "CONFIRMED": 1, "LIKELY": 1, "UNCONFIRMED": 1}

    def test_marks_are_positioned_across_the_run(self):
        timeline = read_models._finding_stats([
            {"confidence": "LIKELY", "ts": "2026-01-01T00:00:00Z"},
            {"confidence": "LIKELY", "ts": "2026-01-01T00:30:00Z"},
            {"confidence": "LIKELY", "ts": "2026-01-01T01:00:00+00:00"},
        ])["timeline"]
        assert [m["at"] for m in timeline["marks"]] == [0.0, 0.5, 1.0]
        assert timeline["span_seconds"] == 3600
        assert timeline["first_ts"] == "2026-01-01T00:00:00Z"
        assert timeline["last_ts"] == "2026-01-01T01:00:00+00:00"

    def test_marks_are_ordered_however_the_trace_lists_them(self):
        marks = read_models._finding_stats([
            {"confidence": "LIKELY", "ts": "2026-01-01T02:00:00Z"},
            {"confidence": "LIKELY", "ts": "2026-01-01T00:00:00Z"},
        ])["timeline"]["marks"]
        assert [m["at"] for m in marks] == [0.0, 1.0]

    def test_findings_at_one_instant_sit_in_the_middle(self):
        # A single finding, or several written at once, has no span to
        # spread over — pinning them to an edge would read as a trend.
        marks = read_models._finding_stats(
            [{"confidence": "SUSPECTED", "ts": "2026-01-01T00:00:00Z"}]
        )["timeline"]["marks"]
        assert [m["at"] for m in marks] == [0.5]

    def test_unreadable_timestamps_still_count_by_tier(self):
        stats = read_models._finding_stats(
            [{"confidence": "SUSPECTED", "ts": "not a timestamp"}])
        assert stats["by_confidence"] == {"SUSPECTED": 1}
        assert stats["timeline"]["marks"] == []

    def test_no_findings_is_an_empty_timeline(self):
        stats = read_models._finding_stats([])
        assert stats["by_confidence"] == {}
        assert stats["timeline"] == {"marks": [], "first_ts": None,
                                     "last_ts": None, "span_seconds": 0}


class TestIocSummary:
    def test_no_claim_graph_yields_zeroes(self, tmp_path):
        assert read_models.ioc_summary(str(tmp_path))["total"] == 0

    def test_summarises_and_caches_on_the_graph_mtime(self, tmp_path, monkeypatch):
        atlas = tmp_path / ".atlas"
        atlas.mkdir()
        (atlas / "claim_graph.json").write_text(json.dumps({"nodes": {}}))
        calls = []

        def fake_catalog(case_dir):
            calls.append(case_dir)
            return {"total": 2, "beliefs_considered": 5,
                    "iocs": [{"value": "evil.example", "category": "domain",
                              "role": "attacker_infra", "confidence": "LIKELY",
                              "explanation": "contacted during the intrusion"}]}

        monkeypatch.setattr("core.ioc_catalog.build_catalog", fake_catalog)
        first = read_models.ioc_summary(str(tmp_path))
        assert first["total"] == 2
        assert first["groups"] == [{"title": "Domains", "count": 1}]
        assert first["top"][0]["value"] == "evil.example"
        # Second read of an unchanged graph must not rebuild the catalog:
        # the Overview asks for this every few seconds.
        read_models.ioc_summary(str(tmp_path))
        assert len(calls) == 1
