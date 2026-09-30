"""Tests for the training solution-material blocklist.

Three layers: core.paths.is_solution_path (classifier),
NarrationMiddleware (MCP arg scan), core.executor.run (argv scan).
"""
import asyncio

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from core.paths import is_solution_path
from tests.core.test_middleware import _run_middleware


class TestIsSolutionPath:
    @pytest.mark.parametrize("path", [
        "cases/case-c/Solution/answers.json",
        "/home/x/cases/case-c/Solution/timeline.md",
        "Solution/answers.json",
        "./solutions/notes.txt",
        "answers.json",
        "cases/foo/ANSWER_KEY/key.txt",
        "cases/foo/answer-key/key.txt",
        "C:\\case\\Solution\\answers.json",
        "'cases/x/Solution/answers.json'",
        "ground_truth.json",
    ])
    def test_blocked(self, path):
        assert is_solution_path(path)

    @pytest.mark.parametrize("path", [
        "cases/case-c/evidence/memory.raw",
        "analysis/timeline.csv",
        "solution",                      # bare word, not path-shaped
        "find the solution to this",     # free text
        "/mnt/hx01/Users/bob/Documents/Solutions/report.docx",  # inside image
        "/media/e01/solution/x.txt",     # inside mounted evidence
        "",
        "cases/foo/resolutions/x.txt",   # segment only matches exactly
    ])
    def test_allowed(self, path):
        assert not is_solution_path(path)

    def test_non_string_values(self):
        assert not is_solution_path(None)  # type: ignore[arg-type]
        assert not is_solution_path(42)    # type: ignore[arg-type]


class TestMiddlewareSolutionGate:
    def _mw(self, tmp_path, case_id):
        from core.execution_log import ExecutionLog
        from core.evidence_inventory_gate import mark_inventory_complete
        from core.middleware import NarrationMiddleware
        (tmp_path / "analysis").mkdir(exist_ok=True)
        (tmp_path / "evidence").mkdir(exist_ok=True)
        mark_inventory_complete(tmp_path, summary={"test_fixture": True})
        l = ExecutionLog()
        l.configure(case_id, str(tmp_path / "analysis" / "trace.json"))
        return NarrationMiddleware(), l

    def test_solution_arg_is_blocked(self, tmp_path):
        from fastmcp.exceptions import ToolError
        mw, l = self._mw(tmp_path, "SOL-001")
        # A file that genuinely exists: the input-path gate runs before the
        # solution gate, so a made-up path would be refused as missing and this
        # test would pass for the wrong reason. Pointing at a real answer key
        # also makes the assertion stronger — the gate refuses a READABLE file.
        key = tmp_path / "cases" / "x" / "Solution" / "answers.json"
        key.parent.mkdir(parents=True)
        key.write_text('{"flag": "x"}', encoding="utf-8")
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="solution material"):
                asyncio.run(_run_middleware(
                    mw, "strings_strings_grep",
                    {"file_path": str(key), "pattern": "flag"}))

    def test_nested_solution_arg_is_blocked(self, tmp_path):
        from fastmcp.exceptions import ToolError
        mw, l = self._mw(tmp_path, "SOL-002")
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="solution material"):
                asyncio.run(_run_middleware(
                    mw, "misc_batch_run",
                    {"jobs": [{"path": "cases/x/Solution/notes.md"}]}))

    def test_block_is_traced_as_call_abandoned(self, tmp_path):
        from fastmcp.exceptions import ToolError
        mw, l = self._mw(tmp_path, "SOL-003")
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError):
                asyncio.run(_run_middleware(
                    mw, "strings_strings_grep",
                    {"file_path": "Solution/answers.json"}))
        kinds = [e.get("type") for e in l._entries]
        assert "call_abandoned" in kinds

    def test_clean_args_pass(self, tmp_path):
        mw, l = self._mw(tmp_path, "SOL-004")
        # Discovery-first requires the input path to exist.
        evidence = tmp_path / "evidence" / "disk.E01"
        evidence.write_bytes(b"EWF\x00")
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.run(_run_middleware(
                mw, "strings_strings_grep",
                {"file_path": str(evidence), "pattern": "solution"}))
        assert call_next.await_count == 1

    def test_accuracy_grader_is_exempt(self, tmp_path):
        mw, l = self._mw(tmp_path, "SOL-005")
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.run(_run_middleware(
                mw, "accuracy_accuracy_compare",
                {"ground_truth_path": "cases/x/Solution/answers.json"}))
        assert call_next.await_count == 1


class TestExecutorSolutionGate:
    def test_argv_with_solution_path_is_refused(self, tmp_path):
        from core.execution_log import ExecutionLog
        from core import executor
        l = ExecutionLog()
        l.configure("SOL-010", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            result = executor.run(["cat", "cases/x/Solution/answers.json"])
        assert result["success"] is False
        assert "solution material" in result["stderr"]
        assert result["exit_code"] == -1

    def test_clean_argv_runs(self):
        from core import executor
        result = executor.run(["echo", "hello"])
        assert result["success"] is True
        assert "hello" in result["stdout"]


class TestContainsSolutionReference:
    """Interpreter payloads defeat the path-shape check — a single argv token
    like `python3 -c "open('ground_truth.json')"` has no separator and its
    basename is the whole string. The substring check catches command text."""

    @pytest.mark.parametrize("payload", [
        "print(open('ground_truth.json').read())",
        'cat ground_truth.json | base64',
        "with open(\"cases/x/Solution/answers.json\") as f: print(f.read())",
        "for f in Solution/*.json: cat $f",
        "GROUND_TRUTH.JSON",  # case-insensitive
    ])
    def test_command_payloads_flagged(self, payload):
        from core.paths import contains_solution_reference
        assert contains_solution_reference(payload) is True

    @pytest.mark.parametrize("prose", [
        "the solution to this puzzle is lateral movement",
        "grounds for truth-telling in reports",
        "no solution material was accessed during this run",
        "answersheet.json",          # not a blocked basename
        "",
    ])
    def test_prose_and_near_misses_pass(self, prose):
        from core.paths import contains_solution_reference
        assert contains_solution_reference(prose) is False

    def test_mounted_solution_folder_exempt_but_key_basename_blocked(self):
        """A suspect's own Solution/ folder inside mounted evidence is
        legitimate (segment heuristic is mount-exempt), but a known
        answer-key BASENAME is blocked everywhere — a key shipped inside the
        image or a case dir bind-mounted under /media must not bypass."""
        from core.paths import contains_solution_reference, is_solution_path
        # folder segment under a mount → exempt
        assert contains_solution_reference(
            "/mnt/image_p1/Users/suspect/Solution/report.docx") is False
        assert is_solution_path(
            "/mnt/image_p1/Users/suspect/Solution/notes.md") is False
        # answer-key basename under a mount → still blocked
        assert is_solution_path("/mnt/hx01/ground_truth.json") is True
        assert is_solution_path(
            "/media/x/Solution/answers.json") is True
        assert contains_solution_reference(
            "cat /mnt/hx01/ground_truth.json") is True

    def test_executor_blocks_interpreter_payload(self, tmp_path):
        from core.execution_log import ExecutionLog
        from core import executor
        l = ExecutionLog()
        l.configure("SOL-020", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            result = executor.run(
                ["python3", "-c",
                 "print(open('ground_truth.json').read())"])
        assert result["success"] is False
        assert "solution material" in result["stderr"]

    def test_middleware_blocks_command_key_only(self, tmp_path):
        """cmd/script/query keys get the substring scan; prose keys (a
        finding description mentioning the file) must pass."""
        from core.middleware import _find_solution_arg
        assert _find_solution_arg(
            {"cmd": "bash -c 'cat ground_truth.json'"}) is not None
        assert _find_solution_arg(
            {"query": "select * from ground_truth.json"}) is not None
        assert _find_solution_arg(
            {"cmd": ["python3", "-c", "open('ground_truth.json')"]}) \
            is not None
        assert _find_solution_arg(
            {"description": "the gate blocked ground_truth.json access, "
                            "findings must come from evidence"}) is None
        assert _find_solution_arg(
            {"note": "Solution material stays isolated"}) is None


@pytest.fixture
def clean_gate():
    """Isolate the process-global answer-key registry per test."""
    from core import paths
    paths.clear_registered_answer_keys()
    yield
    paths.clear_registered_answer_keys()


def _make_case_with_gt(tmp_path, name="case-c"):
    case = tmp_path / name
    case.mkdir()
    gt = case / "ground_truth.json"
    gt.write_text('{"case_id": "X", "expected_findings": []}')
    return case, gt


class TestPositiveIdentifierGate:
    """A path that RESOLVES to a registered answer-key file is blocked no
    matter how it is spelled — closing the denylist's rename/symlink blind
    spot (limitation #2)."""

    def test_unregistered_is_noop(self, clean_gate, tmp_path):
        # With nothing registered the realpath layer never fires; a plain file
        # named gt.json (not a known basename) reads freely.
        _, gt = _make_case_with_gt(tmp_path)
        assert is_solution_path(str(gt.parent / "gt.json")) is False

    def test_registered_realpath_blocked(self, clean_gate, tmp_path):
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        added = paths.register_answer_keys(case)
        assert added == [str(gt.resolve())]
        assert is_solution_path(str(gt)) is True

    def test_renamed_symlink_to_key_blocked(self, clean_gate, tmp_path):
        """`ln -s ground_truth.json key.yaml; cat key.yaml` — the denylist
        never sees a blocked basename, but the realpath resolves to the key."""
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        paths.register_answer_keys(case)
        link = case / "key.yaml"
        link.symlink_to(gt)
        assert is_solution_path(str(link)) is True

    def test_relative_reference_blocked(self, clean_gate, tmp_path, monkeypatch):
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        (case / "analysis").mkdir()
        paths.register_answer_keys(case)
        monkeypatch.chdir(case / "analysis")
        assert is_solution_path("../ground_truth.json") is True

    def test_sibling_non_key_allowed(self, clean_gate, tmp_path):
        from core import paths
        case, _ = _make_case_with_gt(tmp_path)
        (case / "notes.json").write_text("{}")
        paths.register_answer_keys(case)
        assert is_solution_path(str(case / "notes.json")) is False

    def test_clear_disarms_gate(self, clean_gate, tmp_path):
        # Clearing disarms the REALPATH layer; the basename denylist is
        # independent, so test with a renamed reference the denylist ignores.
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        link = case / "key.yaml"
        link.symlink_to(gt)
        paths.register_answer_keys(case)
        assert is_solution_path(str(link)) is True
        paths.clear_registered_answer_keys()
        assert is_solution_path(str(link)) is False

    def test_register_is_idempotent(self, clean_gate, tmp_path):
        from core import paths
        case, _ = _make_case_with_gt(tmp_path)
        assert len(paths.register_answer_keys(case)) == 1
        assert paths.register_answer_keys(case) == []  # already known
        assert len(paths.registered_answer_keys()) == 1

    def test_oversized_arg_is_skipped(self, clean_gate, tmp_path):
        # A multi-KB interpreter payload must not trigger a realpath resolve.
        from core import paths
        case, _ = _make_case_with_gt(tmp_path)
        paths.register_answer_keys(case)
        assert is_solution_path("x" * 5000) is False

    def test_middleware_blocks_renamed_reference(self, clean_gate, tmp_path):
        from fastmcp.exceptions import ToolError
        from core import paths
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        case, gt = _make_case_with_gt(tmp_path)
        paths.register_answer_keys(case)
        link = case / "key.yaml"
        link.symlink_to(gt)
        l = ExecutionLog()
        l.configure("SOL-030", str(tmp_path / "trace.json"))
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="solution material"):
                asyncio.run(_run_middleware(
                    mw, "strings_strings_grep",
                    {"file_path": str(link), "pattern": "flag"}))

    def test_accuracy_grader_still_exempt(self, clean_gate, tmp_path):
        """The grader legitimately reads the registered key server-side."""
        from core import paths
        from core.execution_log import ExecutionLog
        from core.evidence_inventory_gate import mark_inventory_complete
        from core.middleware import NarrationMiddleware
        case, gt = _make_case_with_gt(tmp_path)
        paths.register_answer_keys(case)
        (tmp_path / "analysis").mkdir(exist_ok=True)
        mark_inventory_complete(tmp_path, summary={"test_fixture": True})
        l = ExecutionLog()
        l.configure("SOL-031", str(tmp_path / "analysis" / "trace.json"))
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            _result, call_next = asyncio.run(_run_middleware(
                mw, "accuracy_accuracy_compare",
                {"ground_truth_path": str(gt)}))
        assert call_next.await_count == 1

    def test_executor_blocks_renamed_reference(self, clean_gate, tmp_path):
        from core import paths
        from core import executor
        from core.execution_log import ExecutionLog
        case, gt = _make_case_with_gt(tmp_path)
        paths.register_answer_keys(case)
        link = case / "key.yaml"
        link.symlink_to(gt)
        l = ExecutionLog()
        l.configure("SOL-032", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            result = executor.run(["cat", str(link)])
        assert result["success"] is False
        assert "solution material" in result["stderr"]


class TestAnswerKeyStash:
    """The filesystem belt: the key is moved out of the analyst's tree for the
    analyst phase and restored afterward (limitation #1 for non-mirror runs)."""

    @pytest.fixture
    def stash_dir(self, tmp_path, monkeypatch):
        d = tmp_path / "stash"
        monkeypatch.setenv("ATLAS_ANSWER_KEY_STASH_DIR", str(d))
        return d

    def test_stash_then_restore_roundtrip(self, stash_dir, tmp_path):
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        original = gt.read_text()
        records = paths.stash_answer_keys(case)
        assert len(records) == 1
        assert not gt.exists()                      # gone from the analyst tree
        assert any(stash_dir.glob("*.key"))         # parked in the stash
        restored = paths.restore_answer_keys(records)
        assert restored == [str(gt.resolve())]
        assert gt.exists() and gt.read_text() == original
        assert not any(stash_dir.glob("*.key"))     # stash emptied

    def test_stash_no_ground_truth_is_empty(self, stash_dir, tmp_path):
        from core import paths
        case = tmp_path / "no-gt"
        case.mkdir()
        assert paths.stash_answer_keys(case) == []

    def test_recover_after_crash(self, stash_dir, tmp_path):
        """A stash that was never restored (crash/OOM) self-heals on the next
        run via the .orig sidecar."""
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        paths.stash_answer_keys(case)               # simulate: no restore
        assert not gt.exists()
        recovered = paths.recover_stashed_answer_keys(case)
        assert recovered == [str(gt.resolve())]
        assert gt.exists()
        assert not any(stash_dir.glob("*.orig"))

    def test_recover_scoped_to_case(self, stash_dir, tmp_path):
        from core import paths
        case_a, gt_a = _make_case_with_gt(tmp_path, "case-a")
        case_b, gt_b = _make_case_with_gt(tmp_path, "case-b")
        paths.stash_answer_keys(case_a)
        paths.stash_answer_keys(case_b)
        # Recovering case-a must not touch case-b's stash.
        assert paths.recover_stashed_answer_keys(case_a) == [str(gt_a.resolve())]
        assert gt_a.exists() and not gt_b.exists()
        assert paths.recover_stashed_answer_keys(case_b) == [str(gt_b.resolve())]
        assert gt_b.exists()

    def test_restore_does_not_clobber_reappeared_original(self, stash_dir,
                                                          tmp_path):
        from core import paths
        case, gt = _make_case_with_gt(tmp_path)
        records = paths.stash_answer_keys(case)
        # Original reappears (e.g. `git checkout`) with authoritative content.
        gt.write_text('{"restored": "by git"}')
        restored = paths.restore_answer_keys(records)
        assert restored == []                       # on-disk copy wins
        assert gt.read_text() == '{"restored": "by git"}'
        assert not any(stash_dir.glob("*.key"))     # stale stash dropped


class TestDetectCaseId:
    def test_claude_md_case_id(self, tmp_path):
        from core.paths import detect_case_id
        (tmp_path / "CASE.md").write_text("| **Case ID** | CASE-C |\n")
        assert detect_case_id(tmp_path) == "CASE-C"

    def test_case_md_fallback(self, tmp_path):
        from core.paths import detect_case_id
        (tmp_path / "CASE.md").write_text("case_id: WS01\n")
        assert detect_case_id(tmp_path) == "WS01"

    def test_bold_colon_inside_markers(self, tmp_path):
        from core.paths import detect_case_id
        (tmp_path / "CASE.md").write_text("**Case ID:** NITROBA-2008\n")
        assert detect_case_id(tmp_path) == "NITROBA-2008"

    def test_dir_basename_fallback(self, tmp_path):
        from core.paths import detect_case_id
        case = tmp_path / "cfreds-leak"
        case.mkdir()
        assert detect_case_id(case) == "cfreds-leak"

    def test_colon_inside_bold(self, tmp_path):
        # `**Case ID:** X` is what hand-written and model-written briefs use;
        # three committed demo briefs ship it. It used to miss both patterns and
        # degrade to the directory basename — silently, which is the expensive
        # part: the case dir is lowercase, so nothing looked broken.
        from core.paths import detect_case_id
        case = tmp_path / "nitroba"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID:** NITROBA-2008  \n")
        assert detect_case_id(case) == "NITROBA-2008"

    def test_colon_outside_bold(self, tmp_path):
        from core.paths import detect_case_id
        (tmp_path / "CASE.md").write_text("**Case ID**: WS01\n")
        assert detect_case_id(tmp_path) == "WS01"

    def test_colon_inside_bold_stops_at_trailing_prose(self, tmp_path):
        # A brief can carry `**Case ID:** CASE-C · **Host:** HOST01` on one
        # line: the capture must end at the id, not run into the next field.
        from core.paths import detect_case_id
        (tmp_path / "CASE.md").write_text(
            "**Case ID:** CASE-C · **Host:** HOST01\n")
        assert detect_case_id(tmp_path) == "CASE-C"
