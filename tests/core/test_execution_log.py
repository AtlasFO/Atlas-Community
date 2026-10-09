"""Tests for core/execution_log.py."""
import json
import os
import pytest
from unittest.mock import patch
from core.execution_log import ExecutionLog


class TestExecutionLog:
    @pytest.fixture
    def log(self, tmp_path):
        l = ExecutionLog()
        l.configure("TEST-001", str(tmp_path / "trace.json"))
        return l

    def test_call_ids_since_the_last_assessment(self, log):
        """The lineage an omitted list means: the tool and reason calls
        after the newest director entry, or all of them before the first."""
        a = log.record_tool_call("ls", True, False, 0, 0)
        log.record_finding("f", "high")
        b = log.record_reason_call("reason.plan", "q", "a", 1, 1)
        assert log.call_ids_since_last("dair_call") == [a, b]
        log.record_dair_call(
            current_phase="Triage", phase_rationale="", transition_recommended=False,
            next_phase="", transition_rationale="", stack_action="stay",
            investigation_focus="", verification_satisfied=False,
            verification_challenges=[], recommended_actions=[], directives={},
            input_tokens=0, output_tokens=0)
        assert log.call_ids_since_last("dair_call") == []
        c = log.record_tool_call("cat", True, False, 0, 0)
        assert log.call_ids_since_last("dair_call") == [c]

    def test_configure_sets_case_id(self, log):
        assert log._case_id == "TEST-001"

    def test_configure_creates_file(self, tmp_path):
        l = ExecutionLog()
        p = str(tmp_path / "new.json")
        l.configure("X", p)
        with open(p) as f:
            data = json.load(f)
        assert data["case_id"] == "X"

    def test_configure_resets_entries_for_new_path(self, tmp_path):
        l = ExecutionLog()
        l.configure("A", str(tmp_path / "a.json"))
        l.record_finding("test", "high")
        # Different path → always fresh (no prior file for "B")
        l.configure("B", str(tmp_path / "b.json"))
        assert l._entries == []
        assert l._case_id == "B"

    def test_record_budget_wrapup_appends_typed_entry(self, log):
        # Written only by the agent loop; the report gate keys off the typed
        # entry to relax content-quality blockers (P4 report-gate deadlock).
        cid = log.record_budget_wrapup("turn_budget", 130)
        assert cid > 0
        entry = log._entries[-1]
        assert entry["type"] == "budget_wrapup"
        assert entry["trigger"] == "turn_budget"
        assert entry["turn"] == 130

    def test_configure_resets_seq(self, tmp_path):
        l = ExecutionLog()
        l.configure("A", str(tmp_path / "a.json"))
        l.record_finding("test", "high")
        l.configure("B", str(tmp_path / "b.json"))
        assert l._seq == 0

    # ── record_tool_call ───────────────────────────────────────────────────────

    def test_record_tool_call_type(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        assert log._entries[0]["type"] == "tool_call"

    def test_record_tool_call_fields(self, log):
        log.record_tool_call("vol psscan", True, True, 2, 0, "warn")
        e = log._entries[0]
        assert e["cmd"] == "vol psscan"
        assert e["success"] is True
        assert e["truncated"] is True
        assert e["retries"] == 2
        assert e["stderr"] == "warn"

    def test_record_tool_call_has_call_id(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        assert log._entries[0]["call_id"] == 1

    def test_record_tool_call_returns_call_id(self, log):
        cid = log.record_tool_call("vol psscan", True, False, 0, 0)
        assert cid == 1

    def test_record_tool_call_increments_call_id(self, log):
        cid1 = log.record_tool_call("vol psscan", True, False, 0, 0)
        cid2 = log.record_tool_call("vol netscan", True, False, 0, 0)
        assert cid2 == cid1 + 1

    def test_record_tool_call_stdout_file_stored(self, log):
        log.record_tool_call("strings img", True, True, 0, 0,
                             stdout_file="/tmp/case/analysis/tool-output/x.stdout")
        assert log._entries[0]["stdout_file"] == \
            "/tmp/case/analysis/tool-output/x.stdout"

    def test_record_tool_call_stdout_file_omitted_when_empty(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        assert "stdout_file" not in log._entries[0]

    def test_trace_dir_accessor(self, log, tmp_path):
        assert log.trace_dir() == str(tmp_path)

    def test_trace_dir_none_when_unconfigured(self):
        assert ExecutionLog().trace_dir() is None

    # ── record_reason_call ─────────────────────────────────────────────────────

    def test_record_reason_call_type(self, log):
        log.record_reason_call("reason_plan", True, "investigation plan", {})
        assert log._entries[0]["type"] == "reason_call"
        assert log._entries[0]["tool"] == "reason_plan"

    def test_record_reason_call_full_conclusion_stored(self, log):
        long_text = "x" * 1000
        log.record_reason_call("reason_plan", True, long_text, {})
        assert log._entries[0]["conclusion"] == long_text

    def test_record_reason_call_has_call_id(self, log):
        log.record_reason_call("reason_plan", True, "plan", {})
        assert log._entries[0]["call_id"] == 1

    def test_record_reason_call_stores_tokens(self, log):
        log.record_reason_call("reason_hypothesize", True, "hyp", {}, input_tokens=500, output_tokens=200)
        e = log._entries[0]
        assert e["input_tokens"] == 500
        assert e["output_tokens"] == 200

    def test_record_reason_call_default_tokens_zero(self, log):
        log.record_reason_call("reason_plan", True, "plan", {})
        e = log._entries[0]
        assert e["input_tokens"] == 0
        assert e["output_tokens"] == 0

    # ── record_finding ─────────────────────────────────────────────────────────

    def test_record_finding_type(self, log):
        log.record_finding("BlazingTools keylogger", "high", "Amcache")
        e = log._entries[0]
        assert e["type"] == "finding"
        assert e["confidence"] == "high"
        assert e["source"] == "Amcache"

    def test_record_finding_has_call_id(self, log):
        log.record_finding("keylogger", "high")
        assert log._entries[0]["call_id"] == 1

    def test_record_finding_linked_call_id(self, log):
        log.record_finding("exfil via BITS", "CONFIRMED", "ez.mftecmd", linked_call_id=7)
        assert log._entries[0]["linked_call_id"] == 7

    def test_record_finding_linked_call_id_default_zero(self, log):
        log.record_finding("test", "high")
        assert log._entries[0]["linked_call_id"] == 0

    def test_record_agent_message_disposition_is_narration_not_a_finding(self, log):
        from core.execution_log import is_disposition
        log.record_agent_message("searched the proxy log for the address: no match",
                                 kind="disposition")
        e = log._entries[0]
        assert e["type"] == "investigation_narration"
        assert e["kind"] == "disposition" and is_disposition(e)
        assert not [x for x in log._entries if x["type"] == "finding"]
        assert "**DISPOSITION**" in log.to_markdown()

    def test_record_agent_message_without_kind_carries_no_marker(self, log):
        from core.execution_log import is_disposition
        log.record_agent_message("plain analysis")
        assert "kind" not in log._entries[0]
        assert not is_disposition(log._entries[0])

    # ── call_id sequence across types ─────────────────────────────────────────

    def test_call_ids_sequence_across_types(self, log):
        log.record_tool_call("cmd", True, False, 0, 0)
        log.record_reason_call("reason_plan", True, "plan", {})
        log.record_finding("finding", "high")
        ids = [e["call_id"] for e in log._entries]
        assert ids == [1, 2, 3]

    # ── persistence ───────────────────────────────────────────────────────────

    def test_flush_writes_to_path(self, log, tmp_path):
        log.record_finding("test finding", "medium")
        with open(str(tmp_path / "trace.json")) as f:
            data = json.load(f)
        assert any(e["type"] == "finding" for e in data["entries"])

    # ── to_json ───────────────────────────────────────────────────────────────

    def test_to_json_structure(self, log):
        log.record_tool_call("cmd", True, False, 0, 0)
        j = log.to_json()
        assert j["case_id"] == "TEST-001"
        assert j["entry_count"] == 1
        assert len(j["entries"]) == 1

    def test_to_json_schema_version(self, log):
        j = log.to_json()
        assert j["schema_version"] == "2.0"

    # ── to_markdown ───────────────────────────────────────────────────────────

    def test_to_markdown_contains_tool_ok(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        md = log.to_markdown()
        assert "TOOL" in md
        assert "vol psscan" in md
        assert "OK" in md

    def test_to_markdown_contains_tool_fail_with_stderr(self, log):
        log.record_tool_call("vol malfind", False, False, 0, 1, "permission denied")
        md = log.to_markdown()
        assert "FAIL" in md
        assert "permission denied" in md

    def test_to_markdown_truncated_flag(self, log):
        log.record_tool_call("vol pstree", True, True, 0, 0)
        assert "[TRUNCATED]" in log.to_markdown()

    def test_to_markdown_retries_shown(self, log):
        log.record_tool_call("vol netscan", True, False, 2, 0)
        assert "2 retries" in log.to_markdown()

    def test_to_markdown_reason_with_directives(self, log):
        log.record_reason_call(
            "reason_plan", True, "run psscan first", {"priority_tools": ["vol.psscan"]}
        )
        md = log.to_markdown()
        assert "REASON" in md
        assert "priority_tools" in md

    def test_to_markdown_finding_uppercase_confidence(self, log):
        log.record_finding("exfil via BITS", "high")
        assert "[HIGH]" in log.to_markdown()

    def test_to_markdown_call_id_prefix(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        md = log.to_markdown()
        assert "[#1]" in md

    def test_to_markdown_token_counts(self, log):
        log.record_reason_call("reason_hypothesize", True, "hyp", {}, input_tokens=300, output_tokens=150)
        md = log.to_markdown()
        assert "in=300" in md
        assert "out=150" in md

    def test_to_markdown_finding_linked_call_id(self, log):
        log.record_finding("samplesvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=5)
        md = log.to_markdown()
        assert "← tool call #5" in md

    def test_to_markdown_finding_no_link_when_zero(self, log):
        log.record_finding("test", "high")
        md = log.to_markdown()
        assert "← tool call" not in md

    # ── call_initiated ────────────────────────────────────────────────────────

    def test_record_call_initiated_returns_call_id(self, log):
        cid = log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        assert cid > 0

    def test_record_call_initiated_entry_fields(self, log):
        log.record_call_initiated("reason_plan", "openai-compat", {"model": "fs-8b", "url": "http://localhost:8000"})
        entry = log._entries[-1]
        assert entry["type"] == "call_initiated"
        assert entry["tool"] == "reason_plan"
        assert entry["backend"] == "openai-compat"
        assert entry["inputs"]["model"] == "fs-8b"
        assert "ts" in entry

    def test_record_call_initiated_unconfigured_raises(self):
        """Unconfigured trace must raise — old behaviour silently dropped
        entries and returned 0, which made silent failures undetectable."""
        import core.execution_log as elog
        l = ExecutionLog()
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_call_initiated("dair_assess", "claude", {})

    def test_to_markdown_call_initiated_arrow(self, log):
        log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        md = log.to_markdown()
        assert "→ CALL" in md
        assert "dair_assess" in md
        assert "claude" in md

    def test_to_markdown_call_initiated_inputs_shown(self, log):
        log.record_call_initiated("reason_plan", "claude", {"model": "opus"})
        md = log.to_markdown()
        assert "opus" in md

    def test_call_initiated_before_response_in_entries(self, log):
        log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        log.record_dair_call(
            current_phase="Verification", phase_rationale="x",
            transition_recommended=False, next_phase="", transition_rationale="",
            stack_action="stay", investigation_focus="x",
            verification_challenges=[], recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        types = [e["type"] for e in log._entries]
        assert types.index("call_initiated") < types.index("dair_call")

    # ── export ────────────────────────────────────────────────────────────────

    def test_export_writes_json_and_md(self, log, tmp_path):
        log.record_finding("test", "low")
        out = str(tmp_path / "export")
        log.export(out)
        assert os.path.exists(out + ".json")
        assert os.path.exists(out + ".md")

    def test_export_json_parseable(self, log, tmp_path):
        log.record_tool_call("cmd", True, False, 0, 0)
        out = str(tmp_path / "export")
        log.export(out)
        with open(out + ".json") as f:
            data = json.load(f)
        assert data["case_id"] == "TEST-001"
        assert data["schema_version"] == "2.0"

    # ── edge cases ────────────────────────────────────────────────────────────

    def test_no_record_when_unconfigured(self):
        """Each record_* on an unconfigured log now raises RuntimeError so
        the caller (and ultimately the agent) sees a structured failure
        instead of a silent drop."""
        import core.execution_log as elog
        l = ExecutionLog()
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_tool_call("cmd", True, False, 0, 0)
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_finding("test", "high")
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_reason_call("r", True, "c", {})
        assert l._entries == []

    def test_bad_flush_path_raises(self):
        """Trace flush failures must bubble up so the operator sees lost
        entries — old behaviour swallowed the OSError and silently
        corrupted the audit log."""
        l = ExecutionLog()
        l._path = "/nonexistent/dir/trace.json"
        l._case_id = "X"
        l._entries = []
        with pytest.raises(OSError):
            l._flush()

    # ── configure auto-resume ─────────────────────────────────────────────────

    def test_configure_resumes_existing_trace(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("vol psscan", True, False, 0, 0)
        l1.record_finding("malware found", "CONFIRMED", "vol.malfind")

        l2 = ExecutionLog()  # simulates server restart
        recovered = l2.configure("CASE-1", p)
        assert recovered == 2
        assert l2._case_id == "CASE-1"
        assert len(l2._entries) == 2

    def test_configure_resumes_seq_counter(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("cmd", True, False, 0, 0)  # call_id=1
        l1.record_tool_call("cmd", True, False, 0, 0)  # call_id=2

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        cid = l2.record_finding("new finding", "CONFIRMED")
        assert cid == 3

    def test_configure_resume_does_not_overwrite_disk(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("cmd", True, False, 0, 0)

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        with open(p) as f:
            data = json.load(f)
        assert data["entry_count"] == 1

    def test_configure_resume_continues_appending(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("vol psscan", True, False, 0, 0)

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        l2.record_finding("new finding after restart", "CONFIRMED")

        with open(p) as f:
            data = json.load(f)
        assert data["entry_count"] == 2
        assert any(e.get("description") == "new finding after restart" for e in data["entries"])

    def test_configure_resets_on_different_case_id(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-OLD", p)
        l1.record_tool_call("cmd", True, False, 0, 0)

        l2 = ExecutionLog()
        recovered = l2.configure("CASE-NEW", p)
        assert recovered == 0
        assert l2._case_id == "CASE-NEW"
        assert l2._entries == []

    def test_configure_returns_zero_for_new_case(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l = ExecutionLog()
        recovered = l.configure("FRESH", p)
        assert recovered == 0

    def test_configure_missing_file_starts_fresh(self, tmp_path):
        p = str(tmp_path / "nonexistent.json")
        l = ExecutionLog()
        recovered = l.configure("CASE-X", p)
        assert recovered == 0
        assert l._case_id == "CASE-X"
        assert l._entries == []


class TestAtomicFlush:
    def test_flush_writes_valid_json(self, tmp_path):
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        with open(tmp_path / "trace.json") as f:
            data = json.load(f)
        assert data["case_id"] == "ATOMIC-001"
        assert len(data["entries"]) == 1

    def test_no_tmp_files_left_after_flush(self, tmp_path):
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_flush_warns_and_raises_on_bad_dir(self, tmp_path, capsys):
        """_flush still warns to stderr for visibility, but now also raises
        so the caller can surface a structured ToolError to the agent."""
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l._path = "/nonexistent/dir/trace.json"
        with pytest.raises(OSError):
            l._flush()
        assert "[Atlas WARN]" in capsys.readouterr().err


class TestThreadSafety:
    def test_concurrent_record_calls_no_duplicate_ids(self, tmp_path):
        import threading
        l = ExecutionLog()
        l.configure("THREAD-001", str(tmp_path / "trace.json"))
        ids = []
        errors = []

        def worker():
            try:
                cid = l.record_agent_message("concurrent message")
                ids.append(cid)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(ids) == 20
        assert len(set(ids)) == 20  # all unique

    def test_concurrent_flush_leaves_valid_json(self, tmp_path):
        import threading
        l = ExecutionLog()
        l.configure("THREAD-001", str(tmp_path / "trace.json"))

        def worker():
            for _ in range(10):
                l.record_tool_call("vol.pslist", True, False, 0, 0)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(tmp_path / "trace.json") as f:
            data = json.load(f)
        assert data["entry_count"] == 50
        assert len(data["entries"]) == 50


class TestUnconfiguredRecordRaises:
    """Unconfigured trace now raises RuntimeError on every record_*; the
    error message names the missing setup step so the agent can react."""

    def test_record_tool_call_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*tool_call"):
                l.record_tool_call("vol.pslist", True, False, 0, 0)

    def test_record_finding_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*finding"):
                l.record_finding("test finding", "CONFIRMED")

    def test_record_agent_message_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*agent_message"):
                l.record_agent_message("test message")

    def test_record_budget_wrapup_is_best_effort_when_unconfigured(self):
        # A wrap-up injected before start_execution_log must not raise (unlike
        # record_agent_message) — losing the marker is fine, crashing is not.
        l = ExecutionLog()
        assert l.record_budget_wrapup("turn_budget", 5) == 0
        assert l._entries == []

    def test_configure_warns_on_case_id_mismatch(self, tmp_path, capsys):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-OLD", p)
        l2 = ExecutionLog()
        l2.configure("CASE-NEW", p)
        captured = capsys.readouterr()
        assert "[Atlas WARN]" in captured.err
        assert "CASE-OLD" in captured.err

    def test_configure_warns_on_corrupted_json(self, tmp_path, capsys):
        p = str(tmp_path / "trace.json")
        with open(p, "w") as f:
            f.write("{invalid json{{")
        l = ExecutionLog()
        l.configure("CASE-X", p)
        captured = capsys.readouterr()
        assert "[Atlas WARN]" in captured.err
        assert "corrupted" in captured.err


class TestExportReturnValues:
    def test_export_reports_json_and_md_wrote(self, tmp_path):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        result = l.export(str(tmp_path / "reports" / "trace"))
        # reports/ dir doesn't exist — both writes fail
        assert result["json_wrote"] is False
        assert result["md_wrote"] is False
        assert "entry_count" in result

    def test_export_reports_success_when_dir_exists(self, tmp_path):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        reports = tmp_path / "reports"
        reports.mkdir()
        result = l.export(str(reports / "trace"))
        assert result["json_wrote"] is True
        assert result["md_wrote"] is True
        assert result["entry_count"] == 1

    def test_export_warns_on_write_failure(self, tmp_path, capsys):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        result = l.export(str(tmp_path / "no_such_dir" / "trace"))
        captured = capsys.readouterr()
        assert "[Atlas WARN]" in captured.err


class TestRenderUnknownType:
    def test_unknown_type_renders_fallback(self, tmp_path):
        l = ExecutionLog()
        l.configure("RENDER-001", str(tmp_path / "trace.json"))
        # Inject an unknown entry type directly
        with l._lock:
            l._entries.append({
                "call_id": 99,
                "type": "future_type",
                "ts": "2026-01-01T00:00:00+00:00",
                "data": "something",
            })
        md = l.to_markdown()
        assert "UNKNOWN TYPE" in md
        assert "future_type" in md


class TestTimeoutFlag:
    def test_timeout_renders_as_timeout_in_markdown(self, tmp_path):
        l = ExecutionLog()
        l.configure("TIMEOUT-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, -1,
                            stderr="timed out", timed_out=True)
        md = l.to_markdown()
        assert "TIMEOUT" in md

    def test_timeout_flag_stored_in_entry(self, tmp_path):
        l = ExecutionLog()
        l.configure("TIMEOUT-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, -1, timed_out=True)
        entry = l._entries[-1]
        assert entry.get("timed_out") is True

    def test_non_timeout_failure_renders_as_fail(self, tmp_path):
        l = ExecutionLog()
        l.configure("FAIL-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, 1, stderr="permission denied")
        md = l.to_markdown()
        assert "→ FAIL" in md
        assert "→ TIMEOUT" not in md


class TestCallAbandoned:
    def test_record_call_abandoned_written(self, tmp_path):
        l = ExecutionLog()
        l.configure("ABANDON-001", str(tmp_path / "trace.json"))
        cid = l.record_call_abandoned("reason_plan", "APITimeoutError: 300s exceeded")
        assert cid > 0
        entry = l._entries[-1]
        assert entry["type"] == "call_abandoned"
        assert entry["tool"] == "reason_plan"
        assert "300s" in entry["reason"]

    def test_call_abandoned_renders_in_markdown(self, tmp_path):
        l = ExecutionLog()
        l.configure("ABANDON-001", str(tmp_path / "trace.json"))
        l.record_call_abandoned("dair_assess", "connection reset")
        md = l.to_markdown()
        assert "ABANDONED" in md
        assert "dair_assess" in md
        assert "connection reset" in md


class TestVerificationSatisfiedRendering:
    def test_satisfied_renders_marker(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="Primary IOCs confirmed",
            transition_recommended=True,
            next_phase="Scope",
            transition_rationale="Core claims verified",
            stack_action="push",
            investigation_focus="Map lateral movement",
            verification_satisfied=True,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = l.to_markdown()
        assert "Verification Satisfied" in md

    def test_unsatisfied_does_not_render_marker(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="Still pending",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Keep verifying",
            verification_satisfied=False,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = l.to_markdown()
        assert "Verification Satisfied" not in md

    def test_satisfied_stored_in_entry(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="done",
            transition_recommended=True,
            next_phase="Scope",
            transition_rationale="satisfied",
            stack_action="push",
            investigation_focus="scope",
            verification_satisfied=True,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        assert l._entries[-1]["verification_satisfied"] is True


class TestProtocolViolationFlag:
    """tool_call entries are flagged when no recent dair_call exists."""

    def test_first_tool_call_not_flagged(self, tmp_path):
        # An empty log gets no flag — there's nothing before it to compare against.
        l = ExecutionLog()
        l.configure("PV-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        assert "protocol_violation" not in l._entries[0]

    def test_cold_start_tool_calls_not_flagged_before_any_dair(self, tmp_path):
        # R3b cold-start grace: the mandated pre-plan recon batch (hash verify,
        # image mount, hive reads) runs BEFORE the first dair_assess and must
        # NOT be flagged — flagging it was a self-contradiction. A missing-DAIR
        # violation only applies once DAIR has engaged at least once.
        l = ExecutionLog()
        l.configure("PV-002", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert "protocol_violation" not in l._entries[1]

    def test_tool_call_without_recent_dair_flagged_after_dair_aged_out(self, tmp_path):
        # Once DAIR has engaged, a later tool_call with no dair in the 20-entry
        # window IS flagged (the genuine "agent dropped DAIR mid-investigation").
        l = ExecutionLog()
        l.configure("PV-002b", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert l._entries[-1].get("protocol_violation") == "no_active_dair_batch"

    def test_tool_call_with_recent_dair_unflagged(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        tc = [e for e in l._entries if e["type"] == "tool_call"][0]
        assert "protocol_violation" not in tc

    def test_tool_call_beyond_20_entry_window_flagged(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # 20 reason_calls push the dair_call out of the lookback window.
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        tc = [e for e in l._entries if e["type"] == "tool_call"][-1]
        assert tc.get("protocol_violation") == "no_active_dair_batch"

    def test_markdown_renders_violation_marker(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-005", str(tmp_path / "trace.json"))
        # DAIR engaged once, then aged out of the 20-entry window → the next
        # tool_call is a real violation that the markdown must render. (Under
        # R3b a tool_call before any dair is cold-start grace, not a violation.)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        md = l.to_markdown()
        assert "PROTOCOL_VIOLATION" in md
        assert "no_active_dair_batch" in md

    def test_markdown_no_violation_when_dair_recent(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-006", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        md = l.to_markdown()
        assert "PROTOCOL_VIOLATION" not in md


class TestSelfCorrection:
    """Self-correction: record_self_correction creates first-class trace entries."""

    def test_self_correction_entry_type(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-001", str(tmp_path / "trace.json"))
        cid = l.record_self_correction(
            trigger="evaluate_challenged",
            prior_belief="toolx.exe is a C2 implant",
            new_belief="toolx.exe identity refuted by missing API hooks",
            evidence="vol.malfind shows no inject markers",
        )
        assert cid > 0
        entry = l._entries[-1]
        assert entry["type"] == "self_correction"
        assert entry["trigger"] == "evaluate_challenged"
        assert entry["prior_belief"].startswith("toolx.exe")
        assert "API hooks" in entry["new_belief"]

    def test_self_correction_stores_linked_call_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-002", str(tmp_path / "trace.json"))
        cid = l.record_self_correction("hypothesis_refuted", "old", "new",
                                       linked_call_id=42)
        assert l._entries[-1]["linked_call_id"] == 42

    def test_self_correction_markdown_marker(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-003", str(tmp_path / "trace.json"))
        l.record_self_correction("dair_max_pass_cap", "Verification looping",
                                 "Forced transition to Collect", "3 stays")
        md = l.to_markdown()
        assert "SELF-CORRECTION" in md
        assert "dair_max_pass_cap" in md
        assert "Verification looping" in md
        assert "Forced transition to Collect" in md

    def test_self_correction_mcp_wrapper(self, tmp_path):
        from tools.misc import record_self_correction
        l = ExecutionLog()
        l.configure("SC-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_self_correction(
                trigger="tool_failure_recovery",
                prior_belief="vol.netscan would resolve PIDs",
                new_belief="vol.netscan returned empty — fall back to memmap",
            )
        assert r["success"] is True
        assert r["trigger"] == "tool_failure_recovery"
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert len(sc) == 1


class TestHypothesisLineage:
    """Hypothesis lineage: reason_hypothesize gets a hypothesis_id; record_finding can link to it."""

    def test_reason_call_stores_hypothesis_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-001", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_hypothesize", True, "ok", {}, hypothesis_id="H0001")
        assert l._entries[-1]["hypothesis_id"] == "H0001"

    def test_reason_call_omits_hypothesis_id_when_unset(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-002", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "ok", {})
        assert "hypothesis_id" not in l._entries[-1]

    def test_finding_stores_tested_hypothesis_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-003", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan",
                         linked_call_id=0, tested_hypothesis_id="H0042")
        assert l._entries[-1]["tested_hypothesis_id"] == "H0042"

    def test_finding_omits_tested_hypothesis_id_when_unset(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-004", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan")
        assert "tested_hypothesis_id" not in l._entries[-1]

    def test_markdown_renders_hypothesis_lineage(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-005", str(tmp_path / "trace.json"))
        l.record_finding("rootkit confirmed", "LIKELY", "vol.malfind",
                         linked_call_id=0, tested_hypothesis_id="H0007")
        md = l.to_markdown()
        assert "tests hypothesis: H0007" in md


class TestMarkdownNavigability:
    """Markdown navigability: TOC, phase headers, and evidence chains."""

    def test_toc_lists_phases_encountered(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_tool_call("ez.mftecmd", True, False, 0, 0)
        md = l.to_markdown()
        assert "## Contents" in md
        assert "[Triage]" in md
        assert "[Collect]" in md

    def test_phase_anchor_emitted_at_first_dair_of_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-002", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        md = l.to_markdown()
        assert "<a id=\"phase-triage-1\"></a>" in md
        assert "## Phase: Triage" in md

    def test_phase_repeat_gets_distinct_anchor(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", False, "", "", "stay", "")  # pivot loop
        md = l.to_markdown()
        assert "phase-triage-1" in md
        assert "phase-triage-2" in md

    def test_evidence_chain_for_finding_with_tool_call_link(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call(
            "vol.psscan", True, False, 0, 0,
            stdout_excerpt="PID=5024 PPID=2748 Process=cmd.exe",
        )
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        l.record_finding("orphan cmd.exe", "CONFIRMED", "vol.psscan", linked_call_id=tid)
        md = l.to_markdown()
        assert "Evidence Chain" in md
        assert "vol.psscan" in md
        assert "PID=5024" in md

    def test_evidence_chain_absent_when_linked_call_id_zero(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-005", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan", linked_call_id=0)
        md = l.to_markdown()
        # No evidence chain block when there's no linked call.
        finding_line_idx = next(i for i, line in enumerate(md.split("\n")) if "FINDING" in line)
        # The very next line shouldn't be an Evidence Chain entry.
        following = md.split("\n")[finding_line_idx + 1:finding_line_idx + 3]
        assert not any("Evidence Chain" in line for line in following)


class TestAutoRecoverFromCwd:
    """The log singleton lazily binds to ./analysis/<X>_trace.json under CWD
    when no session.json is available — so an MCP-server restart inside a
    case directory doesn't lose writes if the agent skips start_execution_log."""

    def _make_case(self, root, case_name, *, with_claude_md=True):
        case = root / case_name
        (case / "analysis").mkdir(parents=True)
        trace = case / "analysis" / f"{case_name}_trace.json"
        trace.write_text(
            '{"schema_version":"2.0","case_id":"' + case_name +
            '","entry_count":0,"entries":[]}'
        )
        if with_claude_md:
            (case / "CASE.md").write_text(f"# {case_name}\n")
        return case, trace

    def test_cwd_recovery_when_no_session(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        case, trace_path = self._make_case(tmp_path, "FOO-CASE")
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path == str(trace_path)
        assert l._case_id == "FOO-CASE"

    def test_no_recovery_when_no_claude_md(self, tmp_path, monkeypatch):
        """Defensive: only real case dirs (with CASE.md) trigger recovery.
        Without recovery, record_* raises so silent drops are impossible."""
        import core.execution_log as elog
        case, _ = self._make_case(tmp_path, "BARE", with_claude_md=False)
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        with pytest.raises(RuntimeError, match="trace log not configured"):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path is None

    def test_cwd_case_wins_over_a_foreign_session_beacon(self, tmp_path, monkeypatch):
        # A run launched inside one case must not resume another case's
        # trace named by the per-user beacon (a leftover of the last run).
        import core.execution_log as elog
        cwd_case, _ = self._make_case(tmp_path, "CWD-CASE")
        monkeypatch.chdir(cwd_case)
        other_case, other_trace = self._make_case(tmp_path, "OTHER-CASE")
        sess = tmp_path / "session.json"
        sess.write_text(f'{{"case_id":"OTHER-CASE","path":"{other_trace}"}}')
        monkeypatch.setattr(elog, "_SESSION_FILE", str(sess))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._case_id == "CWD-CASE"

    def test_no_recovery_when_cwd_has_no_analysis_dir(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        bare = tmp_path / "bare"
        bare.mkdir()
        (bare / "CASE.md").write_text("# bare\n")
        monkeypatch.chdir(bare)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        with pytest.raises(RuntimeError, match="trace log not configured"):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path is None

    def test_cwd_recovery_picks_first_alphabetical_when_multiple(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        case = tmp_path / "MULTI"
        (case / "analysis").mkdir(parents=True)
        (case / "CASE.md").write_text("# multi\n")
        (case / "analysis" / "BBB_trace.json").write_text(
            '{"schema_version":"2.0","case_id":"BBB","entry_count":0,"entries":[]}'
        )
        (case / "analysis" / "AAA_trace.json").write_text(
            '{"schema_version":"2.0","case_id":"AAA","entry_count":0,"entries":[]}'
        )
        # Equally new documents: the first name wins, whatever order the
        # file system lists them in.
        for name in ("AAA_trace.json", "BBB_trace.json"):
            os.utime(case / "analysis" / name, (1_900_000_000, 1_900_000_000))
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._case_id == "AAA"

    def test_cwd_recovery_picks_the_newest_document(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        case = tmp_path / "MULTI"
        (case / "analysis").mkdir(parents=True)
        (case / "CASE.md").write_text("# multi\n")
        for cid, when in (("AAA", 1_900_000_000), ("BBB", 1_900_000_600)):
            doc = case / "analysis" / f"{cid}_trace.json"
            doc.write_text('{"schema_version":"2.0","case_id":"%s","entry_count":0,"entries":[]}' % cid)
            os.utime(doc, (when, when))
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._case_id == "BBB"


class TestReasonAndDairInputsField:
    """`inputs` round-trips on reason_call and dair_call entries."""

    def test_reason_call_with_inputs(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-001", str(tmp_path / "trace.json"))
        l.record_reason_call(
            "reason_plan", True, "plan", {},
            inputs={"user_message": "case desc",
                    "system_prompt_kind": "reason_plan",
                    "max_tokens": 2048},
        )
        e = l._entries[-1]
        assert "inputs" in e
        assert e["inputs"]["user_message"] == "case desc"
        assert e["inputs"]["system_prompt_kind"] == "reason_plan"

    def test_reason_call_without_inputs_omits_field(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-002", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "plan", {})
        assert "inputs" not in l._entries[-1]

    def test_dair_call_with_inputs(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-003", str(tmp_path / "trace.json"))
        l.record_dair_call(
            "Triage", "", False, "", "", "stay", "",
            inputs={"tool_results_summary": "summary",
                    "phase_stack": [],
                    "case_context": "ctx"},
        )
        e = l._entries[-1]
        assert "inputs" in e
        assert e["inputs"]["tool_results_summary"] == "summary"
        assert e["inputs"]["case_context"] == "ctx"

    def test_dair_call_without_inputs_omits_field(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert "inputs" not in l._entries[-1]


class TestDairPhaseStamping:
    """Per-entry dair_phase is auto-stamped from ExecutionLog state."""

    def test_first_dair_call_adopts_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._current_phase == "Triage"
        assert l._entries[-1].get("dair_phase") == "Triage"

    def test_subsequent_records_inherit_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-002", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "ok", {})
        l.record_agent_message("interpreting")
        for e in l._entries[1:]:
            assert e.get("dair_phase") == "Triage"
            assert e.get("dair_depth") == 1

    def test_push_advances_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Now declare a transition
        l.record_dair_call("Triage", "", True, "Collect", "verified",
                           "push", "begin collection")
        # The dair_call entry that DECLARED the transition is itself in Collect
        assert l._entries[-1].get("dair_phase") == "Collect"
        assert l._current_phase == "Collect"
        # Subsequent entries are in Collect
        l.record_tool_call("ez.mftecmd", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"
        assert l._entries[-1].get("dair_depth") == 2

    def test_pop_restores_parent_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l._current_phase == "Analyze"
        l.record_dair_call("Analyze", "", True, "Collect", "", "pop", "")
        assert l._current_phase == "Collect"
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"

    def test_verification_satisfied_auto_advances(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-005", str(tmp_path / "trace.json"))
        # verification_satisfied=True while still in Triage with stay action
        l.record_dair_call("Triage", "", False, "", "", "stay", "",
                           verification_satisfied=True)
        assert l._current_phase == "Collect"
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"

    def test_rehydrate_replays_history(self, tmp_path):
        trace_path = str(tmp_path / "rehydrate.json")
        # Set up a trace with two transitions, then close the log.
        l1 = ExecutionLog()
        l1.configure("PHASE-006", trace_path)
        l1.record_dair_call("Triage", "", False, "", "", "stay", "")
        l1.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l1.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l1._current_phase == "Analyze"

        # New log instance reloading the same trace should restore phase state.
        l2 = ExecutionLog()
        l2.configure("PHASE-006", trace_path)
        assert l2._current_phase == "Analyze"
        # Stack depth is 3 (Triage, Collect, Analyze)
        assert len(l2._phase_stack) == 3
        # New records inherit
        l2.record_tool_call("vol.malfind", True, False, 0, 0)
        assert l2._entries[-1].get("dair_phase") == "Analyze"

    def test_default_phase_before_first_dair_call_is_triage(self, tmp_path):
        """Per the DAIR spec — every investigation 'begins with a confirmed
        positive detection already in hand. Start at Triage unless the stack
        says otherwise.' So pre-DAIR entries get phase=Triage stamped, not
        an empty phase, so the Process view never shows 'no phase' orphans."""
        l = ExecutionLog()
        l.configure("PHASE-007", str(tmp_path / "trace.json"))
        l.record_tool_call("hash.verify", True, False, 0, 0)
        assert l._entries[-1]["dair_phase"] == "Triage"
        # depth = len(phase_stack); root Triage push yields depth 1 per the
        # existing convention in _apply_dair_transition.
        assert l._entries[-1]["dair_depth"] == 1

    def test_pop_with_next_phase_targets_the_named_phase(self, tmp_path):
        """pop → Report should land on Report even if Collect/Analyze are on top:
        an agent in Analyze that pops to Report skips the intervening phases."""
        l = ExecutionLog()
        l.configure("PHASE-008", str(tmp_path / "trace.json"))
        # Build the stack: Triage → Collect → Analyze → Scan → Report → Collect → Analyze
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        l.record_dair_call("Analyze", "", True, "Scan", "", "push", "")
        l.record_dair_call("Scan", "", True, "Report", "", "push", "")
        l.record_dair_call("Report", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l._current_phase == "Analyze"
        # Now pop → Report (skipping over the intervening Collect)
        l.record_dair_call("Analyze", "", True, "Report", "", "pop", "")
        assert l._current_phase == "Report"
        assert l._entries[-1].get("dair_phase") == "Report"

    def test_stay_does_not_overwrite_stack_phase(self, tmp_path):
        """Phase stack is sole authority on stay.

        A Collect↔Analyze oscillation: a valve pushes Analyze, then the
        next dair_assess declares Collect+stay; reconciling to the declared
        phase would demote the stack. Stay must keep the stack top.
        """
        l = ExecutionLog()
        l.configure("PHASE-009", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l._current_phase == "Analyze"
        # Stale agent declaration of Collect must NOT demote Analyze.
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        assert l._current_phase == "Analyze"
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Analyze"

    def test_stay_seeds_phase_only_on_cold_start(self, tmp_path):
        """With no phase yet, stay may adopt the declared current_phase."""
        l = ExecutionLog()
        l.configure("PHASE-009b", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._current_phase == "Triage"


class TestFlushPreservesHookEntries:
    """The MCP server's _flush() merges in hook-written entries (marked with
    `_source_tool_use_id` / `_source_uuid`) that aren't in self._entries.
    Without this, hook-written Bash tool_call entries would be overwritten
    by the next MCP server flush.

    Hook entries are identified by `_source_*` markers — NOT by call_id range.
    MCP server and hook share a single monotonic counter."""

    def _write_disk_with_hook_entry(self, path, mcp_entries, hook_entry):
        """Simulate the on-disk state after a hook write."""
        data = {
            "schema_version": "2.0",
            "case_id": "FLUSH-MERGE",
            "entry_count": len(mcp_entries) + 1,
            "entries": list(mcp_entries) + [hook_entry],
        }
        path.write_text(json.dumps(data, indent=2))

    def test_hook_entries_preserved_after_mcp_flush(self, tmp_path):
        trace_path = tmp_path / "trace.json"
        l = ExecutionLog()
        l.configure("FLUSH-MERGE", str(trace_path))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        # Snapshot the MCP entries; pretend the hook then wrote one too
        # (id picked from the shared counter — here we just claim id 999 as
        # "what the hook claimed before our next write"; the merge logic
        # keys off _source_tool_use_id, not the id range).
        mcp_entries_snap = list(l._entries)
        hook_entry = {
            "call_id": 999,
            "type": "tool_call",
            "ts": "2031-02-03T12:00:00+00:00",
            "cmd": "bash echo hook",
            "success": True,
            "truncated": False,
            "retries": 0,
            "exit_code": 0,
            "elapsed_seconds": 0,
            "stderr": "",
            "source": "claude_code_bash",
            "_source_tool_use_id": "tool-use-xyz",
        }
        self._write_disk_with_hook_entry(trace_path, mcp_entries_snap, hook_entry)
        # MCP server records another entry → triggers _flush
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        data = json.loads(trace_path.read_text())
        cmds = [e.get("cmd") for e in data["entries"] if e.get("type") == "tool_call"]
        assert "bash echo hook" in cmds, f"hook entry lost; cmds={cmds}"
        assert "vol.psscan" in cmds
        assert "vol.netscan" in cmds
        # The hook entry retains its own call_id; we don't renumber on merge
        hook_disk = [e for e in data["entries"] if e.get("_source_tool_use_id") == "tool-use-xyz"]
        assert hook_disk and hook_disk[0]["call_id"] == 999

    def test_no_hook_entries_clean_path(self, tmp_path):
        """Fast path: when no hook entries exist on disk, _flush behaves as
        before — fully overwrites with self._entries."""
        trace_path = tmp_path / "trace.json"
        l = ExecutionLog()
        l.configure("FLUSH-CLEAN", str(trace_path))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        data = json.loads(trace_path.read_text())
        assert data["entry_count"] == 2


class TestSharedCallIdCounter:
    """The writers of one trace share its counter file, so their ids are one
    dense sequence per trace; another trace's counter never moves it."""

    def test_a_fresh_trace_counts_from_one(self, tmp_path):
        from core.execution_log import _counter_file
        l = ExecutionLog()
        l.configure("COUNTER-RESET", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        cids = [e["call_id"] for e in l._entries]
        assert cids == [1, 2], f"expected dense ids starting at 1, got {cids}"
        with open(_counter_file(str(tmp_path / "trace.json"))) as f:
            assert json.load(f)["next"] == 3

    def test_a_fresh_trace_elsewhere_does_not_rewind_this_one(self, tmp_path, capsys):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        a = ExecutionLog()
        a.configure("CASE-A", str(tmp_path / "a" / "trace.json"))
        for _ in range(5):
            a.record_tool_call("vol.psscan", True, False, 0, 0)
        b = ExecutionLog()
        b.configure("CASE-B", str(tmp_path / "b" / "trace.json"))
        b.record_tool_call("vol.pslist", True, False, 0, 0)
        a.record_tool_call("vol.netscan", True, False, 0, 0)
        assert [e["call_id"] for e in a._entries] == [1, 2, 3, 4, 5, 6]
        assert [e["call_id"] for e in b._entries] == [1]
        assert "stale counter" not in capsys.readouterr().err

    def test_configure_resumes_counter_from_trace(self, tmp_path):
        """Reattaching to an existing trace picks up the counter past its
        highest id so we don't reuse an already-assigned id."""
        from core.execution_log import _CALL_ID_COUNTER_FILE
        trace_path = tmp_path / "trace.json"
        l1 = ExecutionLog()
        l1.configure("COUNTER-RESUME", str(trace_path))
        l1.record_dair_call("Triage", "", False, "", "", "stay", "")
        l1.record_tool_call("vol.psscan", True, False, 0, 0)
        l1.record_tool_call("vol.netscan", True, False, 0, 0)
        # Simulate process restart: new ExecutionLog, same path
        l2 = ExecutionLog()
        recovered = l2.configure("COUNTER-RESUME", str(trace_path))
        assert recovered == 3
        l2.record_tool_call("vol.cmdline", True, False, 0, 0)
        last = l2._entries[-1]
        assert last["call_id"] == 4, f"counter must continue past existing max; got {last['call_id']}"


class TestClearResurrectionGuard:
    """Regression coverage for a stale MCP server that resurrected a dead
    run's entries into a fresh run's trace because
    (1) clear_case_run left the in-process singleton's entries in memory and
    (2) configure() blindly resumed any on-disk trace with a matching case_id.
    The _CLEAR_MARKER_DIR / _BEACON_DIR module paths are redirected to a
    per-test tmp dir by the autouse isolate_session_file fixture in conftest."""

    def _case(self, tmp_path):
        """A case dir laid out like a real one: <case>/analysis/<CASE>_trace.json.
        Returns (case_dir, trace_path)."""
        case = tmp_path / "cases" / "ws01"
        (case / "analysis").mkdir(parents=True)
        return str(case), str(case / "analysis" / "WS01_trace.json")

    def test_clear_resets_in_process_singleton(self, tmp_path):
        case_dir, trace = self._case(tmp_path)
        l = ExecutionLog()
        l.configure("WS01", trace)
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_finding("dead-run finding", "CONFIRMED")
        assert len(l._entries) == 2

        info = l.reset_for_clear(case_dir)

        assert info["reset_in_process"] is True
        assert info["clear_marker"] and os.path.exists(info["clear_marker"])
        # In-memory dead-run state is gone — nothing left to re-flush.
        assert l._entries == []
        assert l._seq == 0
        assert l._path is None
        assert l._case_id is None

    def test_clear_then_record_does_not_resurrect_in_process(self, tmp_path):
        """After a clear the singleton is unconfigured; a record_* without a
        fresh configure must NOT silently re-flush the dead entries — it raises
        (the same _require_configured contract as a never-configured log)."""
        case_dir, trace = self._case(tmp_path)
        l = ExecutionLog()
        l.configure("WS01", trace)
        l.record_finding("dead-run finding", "CONFIRMED")
        l.reset_for_clear(case_dir)

        with patch("core.execution_log.ExecutionLog._auto_recover"):
            with pytest.raises(RuntimeError):
                l.record_finding("must not resurrect", "CONFIRMED")

    def test_configure_after_clear_starts_fresh_despite_stale_flush(self, tmp_path):
        """A stale server process re-flushes the dead run's entries to disk
        after clear_case_run. configure() must refuse to resume them — they
        predate the clear marker — and start fresh."""
        case_dir, trace = self._case(tmp_path)
        l1 = ExecutionLog()
        l1.configure("WS01", trace)
        l1.reset_for_clear(case_dir)  # writes the clear marker

        # Simulate the stale flush: dead-run entries (old ts) reappear on disk.
        stale = {
            "schema_version": "2.0",
            "case_id": "WS01",
            "entry_count": 2,
            "entries": [
                {"call_id": 201, "type": "tool_call", "ts": "2020-01-01T00:00:00+00:00", "cmd": "vol.psscan"},
                {"call_id": 202, "type": "reason_call", "ts": "2020-01-01T00:00:01+00:00", "tool": "reason_synthesize"},
            ],
        }
        with open(trace, "w") as f:
            json.dump(stale, f)

        l2 = ExecutionLog()
        recovered = l2.configure("WS01", trace)

        assert recovered == 0                 # dead entries refused
        assert l2._entries == []
        assert l2._seq == 0
        # And the fresh run's first id starts at 1, not 203.
        l2.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l2._entries[-1]["call_id"] == 1

    def test_configure_after_clear_keeps_post_clear_entries(self, tmp_path):
        """Entries written *after* the clear (a legit resumed run) are kept;
        only the pre-clear residue is dropped."""
        case_dir, trace = self._case(tmp_path)
        l1 = ExecutionLog()
        l1.configure("WS01", trace)
        l1.reset_for_clear(case_dir)

        mixed = {
            "schema_version": "2.0",
            "case_id": "WS01",
            "entry_count": 2,
            "entries": [
                {"call_id": 5, "type": "tool_call", "ts": "2020-01-01T00:00:00+00:00", "cmd": "dead"},
                {"call_id": 6, "type": "finding", "ts": "2099-01-01T00:00:00+00:00", "description": "fresh"},
            ],
        }
        with open(trace, "w") as f:
            json.dump(mixed, f)

        l2 = ExecutionLog()
        recovered = l2.configure("WS01", trace)

        assert recovered == 1
        assert [e["call_id"] for e in l2._entries] == [6]

    def test_reset_leaves_other_case_singleton_untouched(self, tmp_path):
        """reset_for_clear must not clobber a singleton bound to a different
        case — it only resets when the log's path is under the cleared dir."""
        case_dir, _ = self._case(tmp_path)
        other = tmp_path / "cases" / "other"
        (other / "analysis").mkdir(parents=True)
        l = ExecutionLog()
        l.configure("OTHER", str(other / "analysis" / "OTHER_trace.json"))
        l.record_finding("other-case finding", "CONFIRMED")

        info = l.reset_for_clear(case_dir)  # clearing a DIFFERENT case

        assert info["reset_in_process"] is False
        assert len(l._entries) == 1          # untouched
        assert l._case_id == "OTHER"
        assert info["clear_marker"]          # marker still written

    def test_split_brain_beacon_warns(self, tmp_path, capsys):
        """A second live process configuring the same case path trips a loud
        split-brain WARN via the beacon check."""
        import core.execution_log as elog
        case_dir, trace = self._case(tmp_path)
        # Pre-seed the beacon as if another live server holds this case.
        os.makedirs(elog._BEACON_DIR, exist_ok=True)
        beacon = os.path.join(elog._BEACON_DIR, elog._case_key(case_dir) + ".json")
        other_pid = os.getpid() + 1
        with open(beacon, "w") as f:
            json.dump({"pid": other_pid, "path": trace, "ts": "2031-02-03T00:00:00+00:00"}, f)

        l = ExecutionLog()
        with patch.object(elog, "_pid_alive", return_value=True):
            # save_session=True so the beacon check runs (investigator path).
            l.configure("WS01", trace, save_session=True)

        err = capsys.readouterr().err
        assert "split-brain" in err
        assert str(other_pid) in err

    def test_no_split_brain_warn_when_other_pid_dead(self, tmp_path, capsys):
        import core.execution_log as elog
        case_dir, trace = self._case(tmp_path)
        os.makedirs(elog._BEACON_DIR, exist_ok=True)
        beacon = os.path.join(elog._BEACON_DIR, elog._case_key(case_dir) + ".json")
        with open(beacon, "w") as f:
            json.dump({"pid": os.getpid() + 1, "path": trace, "ts": "2031-02-03T00:00:00+00:00"}, f)

        l = ExecutionLog()
        with patch.object(elog, "_pid_alive", return_value=False):
            l.configure("WS01", trace, save_session=True)

        assert "split-brain" not in capsys.readouterr().err




def test_prose_fields_are_stored_as_text_whatever_the_model_sent():
    """A list or a mapping handed to a prose field is stored as one string,
    so every reader of the trace can treat the field as text."""
    from core.execution_log import as_text
    assert as_text(["1. bound the claim", "2. move on"]) == "1. bound the claim 2. move on"
    assert as_text({"a": "x", "b": ["y", None, 3]}) == "x y 3"
    assert as_text(None) == ""
    assert as_text("plain") == "plain"


class TestChallengeAndAuditRendering:
    """The trace markdown names each challenge verdict and flags an audit
    row that leaves two or more fields unprovided, in plain words."""

    def test_challenge_result_words_per_verdict(self, tmp_path):
        log = ExecutionLog()
        log.configure("CH-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            "Verification", "", False, "", "", "stay", "",
            verification_challenges=[
                {"claim": "c1", "challenge_method": "m", "verified": True},
                {"claim": "c2", "challenge_method": "m", "verified": False, "notes": "no hit"},
                {"claim": "c3", "challenge_method": "m", "verified": None},
            ],
        )
        md = log.to_markdown()
        assert "| c1 | m | CONFIRMED |" in md
        assert "| c2 | m | REFUTED — no hit |" in md
        assert "| c3 | m | PENDING |" in md

    def test_audit_flag_needs_two_unprovided_fields(self, tmp_path):
        log = ExecutionLog()
        log.configure("AU-001", str(tmp_path / "trace.json"))
        log.record_reason_call(
            "reason_evaluate", True, "ok", {},
            evidence_audit=[
                {"claim": "one", "tool": "t", "a": "NOT PROVIDED", "b": "x"},
                {"claim": "two", "tool": "t", "a": "NOT PROVIDED", "b": "NOT PROVIDED"},
            ],
        )
        md = log.to_markdown()
        assert 'audit[0]: claim="one" tool=t\n' in md
        assert 'audit[1]: claim="two" tool=t WARNING: 2×NOT_PROVIDED' in md


class TestOneTraceDocumentPerCase:
    """Every reader that does not hold the live log takes the same document:
    the one the case id names, else the newest. A second document beside it
    (another case id, a copy) is never read as this case's trace."""

    def _case(self, tmp_path):
        import json as _json
        case = tmp_path / "CASE-A"
        (case / "analysis").mkdir(parents=True)
        (case / "CASE.md").write_text("# CASE-A\n\n**Case ID:** CASE-A\n", encoding="utf-8")
        own = case / "analysis" / "CASE-A_trace.json"
        own.write_text(_json.dumps({"case_id": "CASE-A", "entries": [
            {"type": "tool_call", "call_id": 1, "cmd": "fls evidence/CORP-WS01.dd"}]}),
            encoding="utf-8")
        other = case / "analysis" / "CORP-OTHER_trace.json"
        other.write_text(_json.dumps({"case_id": "CORP-OTHER", "entries": [
            {"type": "tool_call", "call_id": 9, "cmd": "fls evidence/CORP-WS09.dd"}]}),
            encoding="utf-8")
        os.utime(own, (1_000_000_000, 1_000_000_000))  # the copy is the newer file
        return case, own, other

    def test_the_case_ids_document_wins_and_nothing_is_merged(self, tmp_path):
        from core.execution_log import _trace_entries_on_disk, case_trace_document
        case, own, _ = self._case(tmp_path)
        assert case_trace_document(case) == str(own)
        assert [e["call_id"] for e in _trace_entries_on_disk(str(case))] == [1]

    def test_without_it_the_newest_document_answers_for_every_reader(self, tmp_path,
                                                                     monkeypatch):
        from agent.cli import _trace_case_id
        from core.execution_log import ExecutionLog, case_trace_document, log
        case, own, other = self._case(tmp_path)
        own.unlink()
        assert case_trace_document(case) == str(other)
        monkeypatch.setattr(log, "_case_id", "")
        assert _trace_case_id(case) == "CORP-OTHER"
        monkeypatch.chdir(case)
        restored = ExecutionLog()               # an MCP server started inside the case
        assert os.path.realpath(restored.case_dir()) == os.path.realpath(str(case))
        assert restored._case_id == "CORP-OTHER"

