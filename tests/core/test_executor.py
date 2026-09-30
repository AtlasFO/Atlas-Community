"""Tests for core/executor.py."""
import io
import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from core.executor import run, run_dotnet, _apply_line_cap, _classify_failure
from core.paths import OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES


class TestClassifyFailure:
    def test_success_is_unclassified(self):
        assert _classify_failure({"success": True, "exit_code": 0,
                                  "cmd": ["grep", "x", "f"]}) == ""

    @pytest.mark.parametrize("verb", ["cmp", "diff", "grep", "egrep", "zgrep"])
    def test_comparison_verb_exit1_is_expected_nonzero(self, verb):
        r = {"success": False, "exit_code": 1, "cmd": [verb, "a", "b"]}
        assert _classify_failure(r) == "expected_nonzero"

    def test_comparison_verb_exit2_is_a_real_error(self):
        # diff/grep exit >=2 is genuine trouble (bad flag, unreadable file).
        r = {"success": False, "exit_code": 2, "cmd": ["diff", "a", "b"]}
        assert _classify_failure(r) == "tool_error"

    def test_other_verb_exit1_is_tool_error(self):
        r = {"success": False, "exit_code": 1, "cmd": ["vol", "pslist"]}
        assert _classify_failure(r) == "tool_error"

    def test_disk_low_refusal_is_disk_floor_not_tool_error(self):
        # A fail-safe refusal of the disk-space guard is infra protection,
        # not a tool defect.
        r = {"success": False, "exit_code": -1, "cmd": ["vol", "pslist"],
             "disk_low": True}
        assert _classify_failure(r) == "disk_floor"

    def test_string_cmd_and_abs_path_verb(self):
        r = {"success": False, "exit_code": 1, "cmd": "/usr/bin/cmp a b"}
        assert _classify_failure(r) == "expected_nonzero"

    def test_preserves_explicit_sudo_auth_class(self):
        # Preflight sets failure_class=sudo_auth; classification must not
        # overwrite it to tool_error (an observability gap).
        r = {"success": False, "exit_code": 1, "cmd": ["mmls", "img"],
             "failure_class": "sudo_auth"}
        assert _classify_failure(r) == "sudo_auth"

# Note: the autouse `isolate_session_file` fixture in tests/conftest.py now
# also configures the global trace log to a tmp path, so run() can call
# _log_tool() without tripping the new _require_configured raise.


def make_popen(returncode=0, stdout=b"", stderr=b""):
    """Fake subprocess.Popen for the streaming executor: real BytesIO pipes
    so the reader threads drain them exactly like a live process."""
    m = MagicMock()
    m.stdout = io.BytesIO(stdout)
    m.stderr = io.BytesIO(stderr)
    m.returncode = returncode
    m.wait.return_value = returncode
    return m


class TestMemguardPreexec:
    def test_unset_returns_none(self, monkeypatch):
        from core.executor import _memguard_preexec
        monkeypatch.delenv("ATLAS_TOOL_MEM_CAP_MB", raising=False)
        assert _memguard_preexec() is None

    def test_zero_or_garbage_returns_none(self, monkeypatch):
        from core.executor import _memguard_preexec
        monkeypatch.setenv("ATLAS_TOOL_MEM_CAP_MB", "0")
        assert _memguard_preexec() is None
        monkeypatch.setenv("ATLAS_TOOL_MEM_CAP_MB", "notanumber")
        assert _memguard_preexec() is None

    def test_positive_returns_callable_that_sets_rlimit(self, monkeypatch):
        from core.executor import _memguard_preexec
        monkeypatch.setenv("ATLAS_TOOL_MEM_CAP_MB", "4096")
        fn = _memguard_preexec()
        assert callable(fn)
        import resource
        calls = []
        with patch("resource.setrlimit", lambda *a: calls.append(a)):
            fn()
        assert calls and calls[0][0] == resource.RLIMIT_AS
        assert calls[0][1][0] == 4096 * 1024 * 1024


@patch("core.executor._sudo_auth_preflight", return_value=None)
@patch("core.executor.subprocess.Popen")
class TestSudoOutputReclaim:
    def test_sudo_with_output_dir_reclaims_ownership(
            self, mock_sub, _sudo_ok, tmp_path):
        mock_sub.return_value = make_popen(0, b"carved", b"")
        out = tmp_path / "carve"
        out.mkdir()
        with patch("core.executor._reclaim_sudo_output") as reclaim:
            run(["tcpxtract", "-o", str(out)], needs_sudo=True,
                output_dir=str(out))
        reclaim.assert_called_once_with(str(out))

    def test_non_sudo_does_not_reclaim(self, mock_sub, _sudo_ok, tmp_path):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        out = tmp_path / "o"
        out.mkdir()
        with patch("core.executor._reclaim_sudo_output") as reclaim:
            run(["strings", "x"], output_dir=str(out))
        reclaim.assert_not_called()

    def test_sudo_without_output_dir_does_not_reclaim(
            self, mock_sub, _sudo_ok):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        with patch("core.executor._reclaim_sudo_output") as reclaim:
            run(["mmls", "img"], needs_sudo=True)
        reclaim.assert_not_called()


@patch("core.executor.subprocess.Popen")
class TestRun:
    def test_success_returns_success_true(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"hello", b"")
        r = run(["echo", "hello"])
        assert r["success"] is True
        assert r["exit_code"] == 0
        assert r["stdout"] == "hello"
        assert r["truncated"] is False
        assert r["retries"] == 0

    def test_failure_returns_success_false(self, mock_sub):
        mock_sub.return_value = make_popen(1, b"", b"fail")
        r = run(["false"])
        assert r["success"] is False
        assert r["exit_code"] == 1
        assert r["stderr"] == "fail"

    def test_needs_sudo_prepends_sudo(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        with patch("core.executor._sudo_auth_preflight", return_value=None):
            run(["ls", "/root"], needs_sudo=True)
        called = mock_sub.call_args[0][0]
        assert called[0] == "sudo"
        assert called[1] == "ls"

    def test_already_sudo_not_doubled(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        with patch("core.executor._sudo_auth_preflight", return_value=None):
            run(["sudo", "ls"], needs_sudo=True)
        called = mock_sub.call_args[0][0]
        assert called[:2] == ["sudo", "ls"]

    def test_sudo_auth_preflight_blocks_password_hang(self, mock_sub):
        blocked = {
            "success": False, "stdout": "",
            "stderr": "sudo: a password is required — non-interactive",
            "exit_code": 1, "elapsed_seconds": 0.0, "truncated": False,
            "cmd": "sudo losetup -f", "retries": 0, "progress_lines": [],
            "failure_class": "sudo_auth",
        }
        with patch("core.executor._sudo_auth_preflight",
                   return_value=blocked):
            r = run(["losetup", "-f"], needs_sudo=True)
        assert r["success"] is False
        assert r["failure_class"] == "sudo_auth"
        mock_sub.assert_not_called()

    def test_string_cmd_is_split(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run("ls -la /tmp")
        called = mock_sub.call_args[0][0]
        assert called == ["ls", "-la", "/tmp"]

    def test_output_cap_truncates(self, mock_sub):
        big = b"x" * (OUTPUT_CAP + 100)
        mock_sub.return_value = make_popen(0, big, b"")
        r = run(["cat", "bigfile"], line_cap=None)
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP

    def test_output_under_cap_not_truncated(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"small", b"")
        r = run(["echo", "small"])
        assert r["truncated"] is False

    def test_line_cap_truncates_at_150(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(200)) + "\n"
        mock_sub.return_value = make_popen(0, lines.encode(), b"")
        r = run(["vol", "psscan"])
        assert r["truncated"] is True
        assert "TRUNCATED" in r["stdout"]
        assert "50 lines omitted" in r["stdout"]

    def test_line_cap_not_triggered_under_150(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(100)) + "\n"
        mock_sub.return_value = make_popen(0, lines.encode(), b"")
        r = run(["vol", "pslist"])
        assert r["truncated"] is False
        assert "TRUNCATED" not in r["stdout"]

    def test_line_cap_none_disables_truncation(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(200)) + "\n"
        mock_sub.return_value = make_popen(0, lines.encode(), b"")
        r = run(["hashdeep", "-r", "/mnt"], line_cap=None)
        assert r["truncated"] is False
        assert "TRUNCATED" not in r["stdout"]

    def test_line_cap_footer_has_omitted_count(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(170)) + "\n"
        mock_sub.return_value = make_popen(0, lines.encode(), b"")
        r = run(["vol", "pstree"])
        assert "20 lines omitted" in r["stdout"]

    def test_stderr_capped_at_4096(self, mock_sub):
        big_err = b"e" * 10000
        mock_sub.return_value = make_popen(1, b"", big_err)
        r = run(["fail"])
        assert len(r["stderr"]) <= 4096

    def test_elapsed_seconds_present(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        r = run(["echo", "ok"])
        assert "elapsed_seconds" in r
        assert isinstance(r["elapsed_seconds"], float)

    def test_progress_lines_parsed_from_stderr(self, mock_sub):
        progress_stderr = b"Volatility 3 Framework 2.x\nProgress:   33.01\t\tscanning\nProgress:  100.00\t\tdone\n"
        mock_sub.return_value = make_popen(0, b"output", progress_stderr)
        r = run(["vol", "psscan"])
        assert r["progress_lines"]
        assert any("33.01" in line or "100.00" in line for line in r["progress_lines"])

    def test_progress_lines_stripped_from_stderr(self, mock_sub):
        mixed_stderr = b"Progress:   50.00\t\tscanning\nActual error: something failed\n"
        mock_sub.return_value = make_popen(1, b"", mixed_stderr)
        r = run(["vol", "bad"])
        assert "Actual error" in r["stderr"]
        assert "Progress:" not in r["stderr"]

    def test_timeout_returns_failure(self, mock_sub):
        proc = make_popen(0, b"", b"")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=1), -9]
        mock_sub.return_value = proc
        r = run(["sleep", "999"], timeout=1)
        assert r["success"] is False
        assert "timed out" in r["stderr"]
        assert r["timed_out"] is True
        # A stop request first; the fake exits within the grace, so no kill.
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()

    def test_timeout_does_not_retry(self, mock_sub):
        # Timeouts should fail immediately — retrying a timed-out command wastes time
        proc = make_popen(0, b"", b"")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=1), -9]
        mock_sub.return_value = proc
        r = run(["sleep", "999"], timeout=1)
        assert r["retries"] == 0
        assert mock_sub.call_count == 1

    def test_timeout_keeps_the_output_written_so_far(self, mock_sub):
        # A tool stopped at its budget still produced what it printed until
        # then; that is the result, and the message says where it is.
        proc = make_popen(0, b"one\ntwo\nthree\n", b"")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=1), -9]
        mock_sub.return_value = proc
        r = run(["scan", "target"], timeout=1)
        assert r["success"] is False and r["timed_out"] is True
        assert r["stdout"] == "one\ntwo\nthree\n"
        assert r["stderr"].startswith("Command timed out after 1s: scan target")
        assert "3 lines" in r["stderr"] and "stdout" in r["stderr"]

    def test_timeout_with_no_output_says_so(self, mock_sub):
        proc = make_popen(0, b"", b"")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=1), -9]
        mock_sub.return_value = proc
        r = run(["scan", "target"], timeout=1)
        assert r["stdout"] == ""
        assert r["stderr"].startswith("Command timed out after 1s")
        assert "no output" in r["stderr"]

    def test_timeout_output_is_capped_like_a_finished_run(self, mock_sub):
        # The same byte cap and spill as a run that ended: stdout holds the
        # retained prefix, the full copy is on disk, and the message names it.
        proc = make_popen(0, b"y" * 200000 + b"\n", b"")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="x", timeout=1), -9]
        mock_sub.return_value = proc
        r = run(["scan", "target"], timeout=1, line_cap=None)
        assert r["timed_out"] is True and r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP
        assert os.path.getsize(r["stdout_file"]) == 200001
        assert r["stdout_file"] in r["stderr"]

    def test_non_timeout_error_not_retried(self, mock_sub):
        mock_sub.side_effect = FileNotFoundError("no such file")
        r = run(["nonexistent_tool"])
        assert mock_sub.call_count == 1

    def test_tool_not_found_returns_failure(self, mock_sub):
        mock_sub.side_effect = FileNotFoundError("no such file")
        r = run(["nonexistent_tool"])
        assert r["success"] is False
        assert "not found" in r["stderr"]

    def test_cmd_string_in_result(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        r = run(["vol", "-f", "image.img"])
        assert "vol" in r["cmd"]

    def test_output_dir_evidence_path_raises(self, mock_sub, tmp_path):
        # exports/ is an output tree; the evidence tree is what must refuse
        with pytest.raises(ValueError, match="protected evidence"):
            run(["ls"], output_dir="/cases/example/evidence/out")

    def test_output_dir_safe_path_allowed(self, mock_sub, tmp_path):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        safe = str(tmp_path / "exports")
        r = run(["ls"], output_dir=safe)
        assert r["success"] is True

    def test_tilde_expanded_in_arg(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run(["vol", "-f", "~/cases/image.img"])
        called = mock_sub.call_args[0][0]
        home = os.path.expanduser("~")
        assert called[2] == home + "/cases/image.img"
        assert "~" not in called[2]

    def test_absolute_path_not_modified(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run(["vol", "-f", "/absolute/cases/image.img"])
        called = mock_sub.call_args[0][0]
        assert called[2] == "/absolute/cases/image.img"

    def test_tilde_expanded_in_string_cmd(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run("vol -f ~/cases/image.img")
        called = mock_sub.call_args[0][0]
        home = os.path.expanduser("~")
        assert called[2] == home + "/cases/image.img"


@patch("core.executor.subprocess.Popen")
class TestStdoutSpill:
    """Full stdout must survive truncation on disk (change: spill files)."""

    def test_byte_cap_overflow_spills_full_output(self, mock_sub):
        big = b"x" * (OUTPUT_CAP + 5000)
        mock_sub.return_value = make_popen(0, big, b"")
        r = run(["strings", "image.raw"], line_cap=None)
        assert r["truncated"] is True
        assert "stdout_file" in r
        assert os.path.isfile(r["stdout_file"])
        with open(r["stdout_file"], "rb") as f:
            assert f.read() == big

    def test_line_cap_only_truncation_spills_full_output(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(200)) + "\n"
        mock_sub.return_value = make_popen(0, lines.encode(), b"")
        r = run(["vol", "psscan"])
        assert r["truncated"] is True
        assert "stdout_file" in r
        with open(r["stdout_file"]) as f:
            assert f.read() == lines

    def test_under_cap_no_spill(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"small output", b"")
        r = run(["echo", "hi"])
        assert "stdout_file" not in r

    def test_spill_recorded_in_trace(self, mock_sub):
        from core.execution_log import log
        big = b"y" * (OUTPUT_CAP + 100)
        mock_sub.return_value = make_popen(0, big, b"")
        r = run(["strings", "img"], line_cap=None)
        entries = [e for e in log._entries if e.get("type") == "tool_call"]
        assert entries[-1].get("stdout_file") == r["stdout_file"]

    def test_no_trace_and_no_analysis_dir_skips_spill(self, mock_sub, tmp_path,
                                                      monkeypatch):
        monkeypatch.chdir(tmp_path)  # no ./analysis here
        with patch("core.executor._spill_target_dir", return_value=None):
            big = b"z" * (OUTPUT_CAP + 100)
            mock_sub.return_value = make_popen(0, big, b"")
            r = run(["strings", "img"], line_cap=None)
        assert r["truncated"] is True
        assert "stdout_file" not in r
        assert len(r["stdout"]) == OUTPUT_CAP

    def test_distinct_filenames_same_second(self, mock_sub):
        big = b"a" * (OUTPUT_CAP + 10)
        paths = []
        for _ in range(2):
            mock_sub.return_value = make_popen(0, big, b"")
            r = run(["strings", "img"], line_cap=None)
            paths.append(r["stdout_file"])
        assert paths[0] != paths[1]

    def test_footer_counts_discarded_tail_lines(self, mock_sub):
        # Lines short enough that >150 fit inside the byte cap, but enough
        # total output that the tail overflows the cap and is discarded from
        # memory; the footer count must include the discarded tail lines.
        line = b"q" * 300 + b"\n"  # 301-byte lines → ~170 fit in 50 KB
        n_lines = 400
        mock_sub.return_value = make_popen(0, line * n_lines, b"")
        r = run(["vol", "psscan"])
        assert r["truncated"] is True
        assert "TRUNCATED" in r["stdout"]
        import re
        m = re.search(r"(\d+) lines omitted", r["stdout"])
        # ±1 tolerance: the byte cap may split a line, which counts once in
        # the retained text and not in the discarded-newline tally.
        expected = n_lines - MAX_TOOL_OUTPUT_LINES
        assert m and abs(int(m.group(1)) - expected) <= 1


class TestStreamingIntegration:
    """Unmocked end-to-end: real subprocess, real pipes, real cap + spill."""

    def test_large_stdout_drained_and_capped(self):
        r = run(["python3", "-c", "print('x' * 200000)"], line_cap=None)
        assert r["success"] is True
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP
        assert "stdout_file" in r
        assert os.path.getsize(r["stdout_file"]) == 200001  # + newline

    def test_small_stdout_roundtrip(self):
        r = run(["python3", "-c", "print('hello')"])
        assert r["success"] is True
        assert r["stdout"].strip() == "hello"
        assert r["truncated"] is False

    @pytest.mark.asyncio
    async def test_run_with_progress_streams_and_caps(self):
        from core.executor import run_with_progress
        r = await run_with_progress(
            ["python3", "-c", "print('y' * 200000)"], None, line_cap=None)
        assert r["success"] is True
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP
        assert "stdout_file" in r
        assert os.path.getsize(r["stdout_file"]) == 200001

    @pytest.mark.asyncio
    async def test_run_with_progress_timeout_keeps_partial_output(self):
        from core.executor import run_with_progress
        r = await run_with_progress(
            ["python3", "-c",
             "import sys, time; sys.stdout.write('y' * 200000 + '\\n'); "
             "sys.stdout.flush(); time.sleep(60)"],
            None, line_cap=None, timeout=1)
        assert r["success"] is False and r["timed_out"] is True
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP
        assert os.path.getsize(r["stdout_file"]) == 200001
        assert r["stderr"].startswith("Command timed out after 1s")
        assert r["stdout_file"] in r["stderr"]

    @pytest.mark.asyncio
    async def test_run_with_progress_untracks_the_child_once_it_is_done(self):
        """A finished child leaves the active set, on the normal path and
        on the timeout path, so a later stop does not wait on a process
        that is already gone."""
        import core.executor as ex
        from core.executor import run_with_progress
        r = await run_with_progress(["python3", "-c", "print('z')"], None)
        assert r["success"] is True
        assert not ex._ACTIVE_CHILDREN
        r = await run_with_progress(
            ["python3", "-c", "import time; time.sleep(60)"], None, timeout=1)
        assert r["timed_out"] is True
        assert not ex._ACTIVE_CHILDREN


class TestApplyLineCap:
    def test_under_limit_unchanged(self):
        text = "\n".join(f"line{i}" for i in range(10))
        result, truncated = _apply_line_cap(text, 150)
        assert result == text
        assert truncated is False

    def test_over_limit_trimmed(self):
        text = "\n".join(f"line{i}" for i in range(200))
        result, truncated = _apply_line_cap(text, 150)
        assert truncated is True
        assert "TRUNCATED" in result
        assert "50 lines omitted" in result

    def test_exactly_at_limit_unchanged(self):
        text = "\n".join(f"line{i}" for i in range(150))
        result, truncated = _apply_line_cap(text, 150)
        assert truncated is False

    def test_footer_content_is_correct(self):
        text = "\n".join(f"x" for _ in range(160))
        result, _ = _apply_line_cap(text, 150)
        assert "focus_paths or focus_pids" in result

    def test_extra_omitted_added_to_footer(self):
        text = "\n".join(f"line{i}" for i in range(200))
        result, truncated = _apply_line_cap(text, 150, extra_omitted=30)
        assert truncated is True
        assert "80 lines omitted" in result


@patch("core.executor.subprocess.Popen")
class TestRunDotnet:
    def test_prepends_dotnet(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run_dotnet("/opt/tools/MFTECmd.dll", ["-f", "/mnt/mft"])
        called = mock_sub.call_args[0][0]
        assert called[:2] == ["dotnet", "/opt/tools/MFTECmd.dll"]

    def test_passes_args(self, mock_sub):
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run_dotnet("/opt/MFTECmd.dll", ["--csv", "/out"])
        called = mock_sub.call_args[0][0]
        assert "--csv" in called
        assert "/out" in called


@patch("core.executor.subprocess.Popen")
class TestFailureClass:
    """Nonzero-exit subprocess results must be classified tool_error in the
    trace: a failure without a failure_class blinds the stall detector's
    and analytics' taxonomy."""

    def test_nonzero_exit_tagged_tool_error(self, mock_sub):
        from core.execution_log import log
        mock_sub.return_value = make_popen(2, b"", b"boom")
        run(["failing-tool"])
        entry = log._entries[-1]
        assert entry["type"] == "tool_call"
        assert entry["success"] is False
        assert entry["failure_class"] == "tool_error"

    def test_success_carries_no_failure_class(self, mock_sub):
        from core.execution_log import log
        mock_sub.return_value = make_popen(0, b"ok", b"")
        run(["working-tool"])
        entry = log._entries[-1]
        assert entry["success"] is True
        assert not entry.get("failure_class")


class TestAToolThatWroteNothing:
    """A tool told where to write has said what success looks like. Some
    report a rejected argument by printing their usage and exiting zero,
    which from the exit code alone is indistinguishable from evidence that
    genuinely holds nothing — and the difference is a whole stage of work."""

    def _check(self, out, *, stderr, files=(), success=True):
        from core.executor import _flag_wrote_nothing
        out.mkdir(parents=True, exist_ok=True)
        for name in files:
            (out / name).write_text("x", encoding="utf-8")
        result = {"success": success, "stderr": stderr, "stdout": "",
                  "cmd": "carver -o out -t one,two"}
        _flag_wrote_nothing(result, str(out))
        return result

    def test_a_usage_banner_with_no_output_is_a_failure(self, tmp_path):
        r = self._check(tmp_path / "a",
                        stderr="carver 1.5.7\nUsage: carver [-v|-h]")
        assert r["success"] is False
        assert r["wrote_no_output"] is True
        assert r["failure_class"] == "analyst_error"
        assert "rejected the command line" in r["stderr"]

    def test_a_synopsis_without_the_word_usage_still_counts(self, tmp_path):
        """foremost's own banner announces a refused option list with a bare
        synopsis and no "usage" anywhere, then exits zero — so matching on
        the word alone would miss it."""
        banner = (
            "foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, "
            "and Nick Mikus.\n"
            "$ foremost [-v|-V|-h|-T|-Q|-q|-a|-w-d] [-t <type>] "
            "[-s <blocks>] [-k <size>]\n"
            "\t[-b <size>] [-c <file>] [-o <dir>] [-i <file]")
        r = self._check(tmp_path / "syn", stderr=banner)
        assert r["success"] is False
        assert r["wrote_no_output"] is True

    def test_a_refused_argument_with_no_output_is_a_failure(self, tmp_path):
        said = ["tool: no such scanner: jpeg",
                "unknown option -- 'q'",
                "invalid argument\nTry 'tool --help' for more information."]
        for i, text in enumerate(said):
            r = self._check(tmp_path / ("b%d" % i), stderr=text)
            assert r["success"] is False, text

    def test_finding_nothing_quietly_is_still_success(self, tmp_path):
        """The evidence really may hold nothing. A tool that says so by
        saying nothing must not be recast as a broken command line."""
        r = self._check(tmp_path / "c",
                        stderr="Processing: image.dd\nfoundat=none")
        assert r["success"] is True
        assert not r.get("wrote_no_output")

    def test_output_written_settles_it_whatever_was_printed(self, tmp_path):
        r = self._check(tmp_path / "d", stderr="Usage: carver [-v]",
                        files=("a.jpg",))
        assert r["success"] is True

    def test_a_run_with_no_output_directory_is_untouched(self):
        from core.executor import _flag_wrote_nothing
        result = {"success": True, "stderr": "Usage: x", "stdout": "", "cmd": "x"}
        _flag_wrote_nothing(result, None)
        assert result["success"] is True


class TestToolBanners:
    """What a tool prints about itself is not its output: read as output,
    the EZ Tools author line and project link turn into the most recurrent
    indicators of a run, present in every call and in no finding."""

    def test_the_ez_banner_is_not_output(self):
        from core.executor import strip_ez_banner
        text = ("EvtxECmd version 2026.5.0\r\n\r\nAuthor: Example Author "
                "(author@example.com)\r\nhttps://github.com/EricZimmerman/evtx\n\n"
                "Command line: -f x.evtx\n\nProcessed 3 files\n")
        out = strip_ez_banner(text)
        assert "Author:" not in out and "github.com" not in out
        assert out.startswith("EvtxECmd version 2026.5.0") and "Processed 3 files" in out

    def test_run_applies_the_filter_before_recording(self):
        from core.executor import strip_ez_banner
        with patch("core.executor._log_tool") as logged:
            result = run(["printf", "Author: someone\\nreal line\\n"],
                         stdout_filter=strip_ez_banner)
        assert result["stdout"] == "real line\n"
        assert logged.call_args[0][0]["stdout"] == "real line\n"


class TestToolGroupStop:
    """A stopped tool takes everything it started with it: tools run in a
    process group of their own, recorded at spawn, and only that group is
    ever signalled; a refusal is reported, never escalated."""

    @staticmethod
    def _gone(pid, within=5.0):
        import time as _t
        end = _t.monotonic() + within
        while _t.monotonic() < end:
            try:
                with open(f"/proc/{pid}/stat") as fh:
                    if fh.read().rsplit(")", 1)[1].split()[0] == "Z":
                        return True
            except OSError:
                return True
            _t.sleep(0.05)
        return False

    def test_the_guard_signals_only_the_recorded_leader_group(self):
        import signal as _sig
        from core.executor import _signal_created_group
        cases = [MagicMock(spec=["pid"], pid=4242),                         # nothing recorded
                 MagicMock(pid=1, _atlas_group=1),                          # group 1
                 MagicMock(pid=os.getpgrp(), _atlas_group=os.getpgrp()),    # our own group
                 MagicMock(pid=4242, _atlas_group=4343)]                    # not the leader
        with patch("core.executor.os.killpg") as kp:
            outcomes = [_signal_created_group(p, _sig.SIGTERM) for p in cases]
        assert all(o.startswith("refused") for o in outcomes), outcomes
        kp.assert_not_called()

    def test_a_timed_out_tool_takes_its_grandchild_with_it(self, tmp_path):
        pidfile = tmp_path / "child.pid"
        r = run(["bash", "-c", f"sleep 300 & echo $! > {pidfile}; wait"], timeout=1)
        assert r["timed_out"] is True
        assert self._gone(int(pidfile.read_text()))

    def test_the_async_runner_does_the_same(self, tmp_path):
        import asyncio
        from core.executor import run_with_progress
        pidfile = tmp_path / "child.pid"
        r = asyncio.run(run_with_progress(["bash", "-c", f"sleep 300 & echo $! > {pidfile}; wait"], None, timeout=1))
        assert r["timed_out"] is True
        assert self._gone(int(pidfile.read_text()))

    def test_a_stopped_run_ends_a_tool_and_its_grandchild(self, tmp_path):
        import threading
        import time as _t
        from core import executor
        pidfile = tmp_path / "child.pid"
        out = {}
        t = threading.Thread(target=lambda: out.update(run(
            ["bash", "-c", f"sleep 300 & echo $! > {pidfile}; wait"], timeout=120)))
        t.start()
        try:
            end = _t.monotonic() + 10
            while not pidfile.exists() and _t.monotonic() < end:
                _t.sleep(0.05)
            assert executor.terminate_active_children(grace=1) == 1
            t.join(timeout=20)
            assert out.get("interrupted") is True
            assert self._gone(int(pidfile.read_text()))
        finally:
            executor._STOP_EVENT.clear()

    @pytest.mark.parametrize("runner", ["run", "file", "async"])
    def test_a_stopped_run_discloses_a_sudo_command_that_outlived_it(self, tmp_path, runner):
        import asyncio
        import threading
        import time as _t
        from core import executor
        fake = tmp_path / "sudo"   # the runner classifies by the command's name
        fake.write_text("#!/bin/bash\ntrap '' TERM\necho up > \"$1\"\nwhile :; do sleep 0.1; done\n")
        fake.chmod(0o755)
        flag = tmp_path / "up"
        cmd = [str(fake), str(flag)]
        start = {"run": lambda: executor.run(cmd, timeout=120),
                 "file": lambda: executor.run_with_output_file(
                     cmd, output_path=str(tmp_path / "out.txt"), timeout=120),
                 "async": lambda: asyncio.run(executor.run_with_progress(cmd, None, timeout=120))}[runner]
        out = {}
        t = threading.Thread(target=lambda: out.update(start()))
        t.start()
        try:
            end = _t.monotonic() + 10
            while not flag.exists() and _t.monotonic() < end:
                _t.sleep(0.05)
            assert executor.terminate_active_children(grace=0.5) == 1
            t.join(timeout=20)
            assert out.get("interrupted") is True and out.get("stop_incomplete") is True, out
            assert "may still be running as root" in out["stderr"]
            from core.execution_log import log as _log
            entry = next(e for e in reversed(_log._entries) if e.get("type") == "tool_call")
            assert entry.get("interrupted") is True
        finally:
            executor._STOP_EVENT.clear()

    def test_the_memory_cap_and_the_new_session_work_together(self, monkeypatch):
        import asyncio
        from core.executor import run_with_progress
        monkeypatch.setenv("ATLAS_TOOL_MEM_CAP_MB", "512")
        assert run(["bash", "-c", "echo ok"], timeout=10)["success"] is True
        assert asyncio.run(run_with_progress(["bash", "-c", "echo ok"], None, timeout=10))["success"] is True

    def test_a_sudo_command_that_outlived_sigterm_is_killed_as_root(self, no_privileged_kill, monkeypatch):
        """The command sudo runs stays in the created group but out of the
        user's reach; the group is killed as root, and the stop is complete
        only when that kill went out."""
        import subprocess
        from core import privileged_kill as pk
        from core.executor import _stop_outcome
        proc = MagicMock(pid=4242, _atlas_group=4242, _atlas_group_start=None)
        with patch("core.executor.os.killpg", side_effect=ProcessLookupError):
            assert _stop_outcome(proc, False, True) is True      # sudo refused: disclosed
            assert no_privileged_kill == [["sudo", "-n", "kill", "-KILL", "--", "-4242"]]
            monkeypatch.setattr(pk, "_run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))
            assert _stop_outcome(proc, False, True) is False     # root's kill reached it

    def test_no_escalation_after_the_leader_is_gone_without_its_start_time(self, no_privileged_kill):
        from core.executor import _stop_outcome
        proc = MagicMock(pid=4242, _atlas_group=4242, _atlas_group_start=None)
        with patch("core.executor.os.killpg", side_effect=PermissionError):
            assert _stop_outcome(proc, True, True) is True      # disclosed, not escalated
        assert no_privileged_kill == []

    def test_a_tool_not_started_through_sudo_is_never_escalated(self, no_privileged_kill):
        from core.executor import _stop_outcome
        proc = MagicMock(pid=4242, _atlas_group=4242, _atlas_group_start=None)
        with patch("core.executor.os.killpg", side_effect=PermissionError):
            assert _stop_outcome(proc, True, False) is True
        assert no_privileged_kill == []

    def test_a_sudo_command_that_outlived_the_stop_request_is_reported(self):
        from core.executor import _stop_outcome
        proc = MagicMock(pid=4242, _atlas_group=4242)
        with patch("core.executor.os.killpg", side_effect=ProcessLookupError):
            assert _stop_outcome(proc, False, True) is True     # SIGKILL step ran on a sudo call
            assert _stop_outcome(proc, True, True) is False      # it ended on SIGTERM
        with patch("core.executor.os.killpg", side_effect=PermissionError):
            assert _stop_outcome(proc, True, False) is True      # members we may not signal remain
