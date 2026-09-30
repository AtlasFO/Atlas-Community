"""Coverage audits (tools/coverage_audit.py).

Two questions, both read from the trace: which investigative capabilities the
case's evidence admits were never exercised, and which output-producing calls
no finding was ever built from.
"""
import pytest

from tools import coverage_audit as ca


@pytest.fixture
def clean_trace():
    from core.execution_log import log
    saved = list(log._entries)
    log._entries.clear()
    yield log
    log._entries.clear()
    log._entries.extend(saved)


def _tool_call(call_id, mcp_tool, success=True, stdout="some output"):
    return {"type": "tool_call", "call_id": call_id, "mcp_tool": mcp_tool,
            "cmd": mcp_tool.replace("_", " ", 1), "success": success,
            "stdout_excerpt": stdout}


def _row(out, capability):
    return next((r for r in out["capabilities"]
                 if r["capability"] == capability), None)


class TestCapabilityBreadth:
    def test_a_capability_with_a_tool_run_counts_as_exercised(
            self, clean_trace, monkeypatch):
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"pcap"})
        clean_trace._entries.append(_tool_call(1, "net_tcpdump_read"))
        out = ca.tool_coverage()
        row = _row(out, "network_pcap")
        assert row is not None and row["exercised"] is True
        assert "net.tcpdump_read" in row["exercised_with"]

    def test_an_untouched_capability_lists_what_would_exercise_it(
            self, clean_trace, monkeypatch):
        """An unexercised row carries its tools, so the answer says what to
        do rather than only that something is missing."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"pcap"})
        out = ca.tool_coverage()
        row = _row(out, "network_pcap")
        assert row["exercised"] is False and row["tools"]
        assert out["unexercised_count"] >= 1

    def test_only_capabilities_the_evidence_admits_are_judged(
            self, clean_trace, monkeypatch):
        """Memory capabilities are not a gap in a case with no memory."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"pcap"})
        out = ca.tool_coverage()
        assert _row(out, "network_pcap") is not None
        assert _row(out, "memory_process_network") is None

    def test_a_capability_for_any_evidence_is_always_judged(
            self, clean_trace, monkeypatch):
        """The manifest marks some capabilities as never gated on evidence."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"pcap"})
        assert _row(ca.tool_coverage(), "reasoning_control") is not None

    def test_no_declared_evidence_says_so_rather_than_guessing(
            self, clean_trace, monkeypatch):
        """Filename guessing is what this deliberately does not do: with
        nothing declared the honest answer is that there is nothing to judge
        breadth against."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: set())
        out = ca.tool_coverage()
        assert out["capabilities"] == [] and out["capabilities_applicable"] == 0
        assert "evidence class" in out["note"]

    def test_the_answer_names_the_manifest_it_judged_against(
            self, clean_trace, monkeypatch):
        """The manifest is versioned; an audit that does not say which
        version it used cannot be compared with a later one."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"disk"})
        assert ca.tool_coverage()["manifest_version"]

    def test_double_namespaced_tool_counts_as_exercised(self, clean_trace,
                                                        monkeypatch):
        """Atlas registers tsk.fls as "tsk_tsk_fls" because the function
        already carries its namespace. Matching only the single form reports
        a capability as untouched when its tools plainly ran."""
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"disk"})
        clean_trace._entries.extend([
            _tool_call(1, "tsk_tsk_fls"),
            _tool_call(2, "tsk_tsk_mmls"),
        ])
        row = _row(ca.tool_coverage(), "disk_filesystem_timeline")
        assert row["exercised"] is True

    def test_matcher_handles_both_prefix_shapes(self):
        invoked = {"tsk_tsk_fls", "net_tcpdump_read", "ez_ez_mftecmd"}
        assert ca._tool_was_invoked("tsk.fls", invoked)
        assert ca._tool_was_invoked("net.tcpdump_read", invoked)
        assert ca._tool_was_invoked("ez.mftecmd", invoked)
        assert not ca._tool_was_invoked("vol.pslist", invoked)


class TestEvidenceClassDerivation:
    def test_classes_come_from_the_case_file(self, clean_trace, monkeypatch,
                                             tmp_path):
        """The case file is what a human wrote down, so it is the first
        authority on what evidence exists."""
        monkeypatch.setattr(ca, "_case_dir", lambda: str(tmp_path))
        monkeypatch.setattr(
            "core.evidence_links.load_evidence_links",
            lambda _d: {"entries": [{"kind": "pcap"}, {"kind": "memory"},
                                    {"kind": "principal"}]})
        assert ca._declared_evidence_classes() == {"pcap", "memory"}

    def test_the_ledger_answers_when_the_case_file_does_not(
            self, clean_trace, monkeypatch, tmp_path):
        monkeypatch.setattr(ca, "_case_dir", lambda: str(tmp_path))
        monkeypatch.setattr("core.evidence_links.load_evidence_links",
                            lambda _d: {"entries": []})
        monkeypatch.setattr(
            "core.coverage_ledger.load_ledger",
            lambda _d: {"units": {"u1": {"kind": "disk"}}})
        assert ca._declared_evidence_classes() == {"disk"}

    def test_no_case_directory_yields_nothing(self, monkeypatch):
        monkeypatch.setattr(ca, "_case_dir", lambda: "")
        assert ca._declared_evidence_classes() == set()


class TestWorkNothingRestsOn:
    def test_a_call_no_finding_was_built_from_is_reported(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(1, "net_tcpdump_read"),
            _tool_call(2, "ez_mftecmd"),
            _tool_call(3, "vol_pslist"),
            {"type": "finding", "confidence": "CONFIRMED",
             "description": "f", "linked_call_id": 1,
             "input_call_ids": [2]},
        ])
        out = ca.evidence_coverage()
        assert out["producing_calls"] == 3
        assert out["rested_on_count"] == 2
        assert out["unaccounted_count"] == 1
        assert out["unaccounted_by_tool"]["vol_pslist"]["call_ids"] == [3]

    def test_failed_and_outputless_calls_are_not_work(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(1, "vol_pslist", success=False),
            _tool_call(2, "ez_mftecmd", stdout=""),
        ])
        assert ca.evidence_coverage()["producing_calls"] == 0

    def test_plumbing_is_not_work_a_finding_would_rest_on(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(1, "dair_dair_assess"),
            _tool_call(2, "misc_record_finding"),
            _tool_call(3, "search_search_evidence"),
        ])
        assert ca.evidence_coverage()["producing_calls"] == 0

    def test_an_empty_trace_has_nothing_unaccounted(self, clean_trace):
        out = ca.evidence_coverage()
        assert out["producing_calls"] == 0 and out["unaccounted_count"] == 0

    def test_a_malformed_lineage_id_does_not_break_the_audit(self,
                                                             clean_trace):
        """Lineage comes from a model-written record; a non-numeric id must
        cost that one link, not the whole answer."""
        clean_trace._entries.extend([
            _tool_call(1, "net_tcpdump_read"),
            {"type": "finding", "description": "f",
             "linked_call_id": "not-a-number", "input_call_ids": [None, 1]},
        ])
        assert ca.evidence_coverage()["rested_on_count"] == 1


class TestPreReportWiring:
    def test_both_audits_answer_on_a_busy_trace(self, clean_trace,
                                                monkeypatch):
        monkeypatch.setattr(ca, "_declared_evidence_classes", lambda: {"pcap"})
        clean_trace._entries.extend(
            [_tool_call(i, f"vol_plugin_{i}") for i in range(1, 11)])
        out = ca.tool_coverage()
        assert out["unexercised_count"] >= 1
        ec = ca.evidence_coverage()
        assert ec["producing_calls"] >= 8
        assert ec["unaccounted_count"] == ec["producing_calls"]
