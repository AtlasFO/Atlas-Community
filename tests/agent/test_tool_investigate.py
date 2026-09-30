"""Unit tests for tool-failure investigate classification."""
from agent.tool_investigate import (
    IDENTICAL_FAIL_LIMIT,
    classify_tool_result,
    finish_blocking_issues,
    format_finish_refusal,
    format_investigate_message,
    merge_investigate_debt,
    prune_exhausted_debt,
    settle_investigate_debt,
)


class TestSettleInvestigateDebt:
    """A clean run of the failed tool is the corrected retry the latch asked
    for, so it releases that tool's issue and nothing else."""

    def test_a_clean_run_of_the_failed_tool_releases_its_issue(self):
        debt = merge_investigate_debt([], [
            {"tool": "ns_tool_a", "kind": "tool_error", "summary": "TOOL ERROR:"},
            {"tool": "ns_tool_b", "kind": "tool_error", "summary": "TOOL ERROR:"},
        ])
        left = settle_investigate_debt(debt, {"ns_tool_a"})
        assert [i["tool"] for i in left] == ["ns_tool_b"]

    def test_other_tools_running_clean_release_nothing(self):
        debt = merge_investigate_debt([], [
            {"tool": "ns_tool_a", "kind": "tool_error", "summary": "TOOL ERROR:"},
        ])
        assert settle_investigate_debt(debt, {"ns_tool_c", ""}) == debt
        assert settle_investigate_debt(debt, set()) == debt


class TestClassifyToolResult:
    def test_tool_error_prefix(self):
        issue = classify_tool_result(
            "misc_batch_run", "TOOL ERROR: boom\nmore")
        assert issue is not None
        assert issue["kind"] == "tool_error"

    def test_tool_info_ignored(self):
        assert classify_tool_result(
            "strings_strings_grep",
            "TOOL INFO: deferred intent recorded",
        ) is None

    def test_scan_timeout(self):
        issue = classify_tool_result(
            "misc_evtx_filter",
            '{"success": false, "incomplete": true, "gate": "scan_timeout",'
            ' "error": "wall clock exceeded"}',
        )
        assert issue is not None
        assert issue["kind"] == "incomplete_scan"

    def test_bad_regex(self):
        issue = classify_tool_result(
            "strings_strings_grep",
            '{"success": false, "error": "re.error: nothing to repeat"}',
        )
        assert issue is not None
        assert issue["kind"] == "bad_pattern"

    def test_bad_event_ids_args(self):
        issue = classify_tool_result(
            "misc_evtx_filter",
            '{"success": false, "gate": "bad_args",'
            ' "error": "no valid event_ids parsed from \'(4624, 4625)\'. '
            'Pass digits and commas only — e.g. \'4624,4625\'.",'
            ' "hint": "Use event_ids=\'4624,4625\' (digits and commas only)."}',
        )
        assert issue is not None
        assert issue["kind"] == "bad_args"
        assert "4624,4625" in (issue.get("hint") or "")

    def test_workflow_gate_ignored(self):
        assert classify_tool_result(
            "misc_record_finding",
            '{"success": false, "gate": "evidence_strength",'
            ' "error": "need evaluate"}',
        ) is None

    def test_pre_report_gate_ignored(self):
        assert classify_tool_result(
            "misc_write_projected_final_report",
            '{"success": false, "gate": "pre_report_check_required",'
            ' "error": "READY_TO_REPORT: false"}',
        ) is None

    def test_success_ok(self):
        assert classify_tool_result(
            "misc_evtx_filter",
            '{"success": true, "matches": 12}',
        ) is None


class TestAnAbsentPathIsAnAnswer:
    def test_path_not_found_is_not_investigate_debt(self):
        import json
        from agent.tool_investigate import classify_tool_result
        result = json.dumps({"success": False, "gate": "path_not_found",
                             "missing": "sru", "resolved": "Windows/System32",
                             "error": "'sru' not found under Windows/System32"})
        assert classify_tool_result("tsk_resolve_path", result) is None


class TestMergeDebt:
    def _bad_args(self):
        return classify_tool_result(
            "misc_evtx_filter",
            '{"success": false, "gate": "bad_args",'
            ' "error": "no valid event_ids parsed from \'(4624, 4625)\'",'
            ' "hint": "Use event_ids=\'4624,4625\'."}',
        )

    def test_identical_bad_args_exhaust_after_limit(self):
        debt = []
        issue = self._bad_args()
        for _ in range(IDENTICAL_FAIL_LIMIT):
            debt = merge_investigate_debt(debt, [issue])
        assert debt[0]["repeat_count"] == IDENTICAL_FAIL_LIMIT
        assert debt[0]["exhausted"] is True
        assert debt[0]["blocking_finish"] is False
        assert finish_blocking_issues(debt) == []
        assert prune_exhausted_debt(debt) == []

    def test_identical_tool_error_exhausts(self):
        """B6: same disk FS tool_error argv must not retry forever."""
        issue = classify_tool_result(
            "tsk_sigfind",
            "TOOL ERROR: sigfind: invalid block size\n",
        )
        assert issue is not None and issue["kind"] == "tool_error"
        debt = []
        for _ in range(IDENTICAL_FAIL_LIMIT):
            debt = merge_investigate_debt(debt, [issue])
        assert debt[0]["exhausted"] is True
        assert debt[0]["blocking_finish"] is False
        assert finish_blocking_issues(debt) == []

    def test_json_disk_tool_error_classified(self):
        issue = classify_tool_result(
            "tsk_icat",
            '{"success": false, "failure_class": "tool_error",'
            ' "error": "Cannot open inode 0"}',
        )
        assert issue is not None
        assert issue["kind"] == "tool_error"

    def test_incomplete_scan_stays_blocking(self):
        issue = classify_tool_result(
            "misc_evtx_filter",
            '{"success": false, "incomplete": true, "gate": "scan_timeout",'
            ' "error": "timed out"}',
        )
        debt = []
        for _ in range(IDENTICAL_FAIL_LIMIT + 2):
            debt = merge_investigate_debt(debt, [issue])
        assert debt[0]["blocking_finish"] is True
        assert finish_blocking_issues(debt)


class TestMessages:
    def test_investigate_message_lists_issues(self):
        msg = format_investigate_message([{
            "tool": "strings_strings_grep",
            "kind": "bad_pattern",
            "summary": "re.error",
        }])
        assert "[tool-failure investigate]" in msg
        assert "bad_pattern" in msg
        assert "dair_assess" in msg

    def test_investigate_message_includes_hint(self):
        msg = format_investigate_message([{
            "tool": "misc_evtx_filter",
            "kind": "bad_args",
            "summary": "no valid event_ids",
            "hint": "Use event_ids='4624,4625'.",
            "repeat_count": 2,
        }])
        assert "FIX:" in msg
        assert "4624,4625" in msg
        assert "REPEAT" in msg

    def test_finish_refusal(self):
        msg = format_finish_refusal(
            [{"tool": "x", "kind": "tool_error", "summary": "e",
              "blocking_finish": True}],
            [{"call_id": 1}],
        )
        assert "atlas_finish refused" in msg
        assert "truncated critical" in msg

    def test_finish_refusal_with_only_exhausted_has_no_investigate_count(self):
        msg = format_finish_refusal(
            [{"tool": "misc_evtx_filter", "kind": "bad_args",
              "summary": "bad", "blocking_finish": False, "exhausted": True}],
            [],
        )
        assert "atlas_finish refused" in msg
        assert "open tool-failure investigate item" not in msg
