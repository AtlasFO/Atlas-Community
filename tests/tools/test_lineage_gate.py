"""Tests for the lineage_required gate (G4).

Enforces that every agent-facing record_* MCP call carries input_call_ids
(after a 5-entry genesis grace period) and that each cid is real.
"""
import pytest
from unittest.mock import patch


def _seed_log_ready_for_confirmed(tmp_path, n_pad_entries=0):
    """Build a log primed for CONFIRMED-tier finding gates to pass everything
    EXCEPT lineage_required, so we can isolate it. Optionally pads with
    additional narration entries to exit the genesis grace window."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("LINEAGE", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
    l.record_reason_call("reason_hypothesize", True, "ok", {})
    l.record_reason_call(
        "reason_confidence_score",
        True,
        'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED", "score": 0.95}',
        {},
        inputs={"user_message": "a finding"},
    )
    l.record_reason_call(
        "reason_cite_check",
        True,
        'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
        {},
        inputs={"user_message": "a finding"},
    )
    l.record_reason_call(
        "reason_evaluate_finding", True,
        "VERDICT: SUPPORTED.",
        {},
    )
    # Pad with extra entries to escape the genesis grace if requested
    for i in range(n_pad_entries):
        l.record_agent_message(f"pad {i}", input_call_ids=[tid])
    return l, tid


class TestLineageGate:
    def test_auto_infers_empty_after_genesis(self, tmp_path):
        """R4: once past genesis, omitting input_call_ids no longer refuses — it
        is inferred from the recent tool/reason results and stamped
        lineage_inferred. record_finding fills it before the gate runs."""
        from tools.misc import record_finding
        # Helper adds 6 entries (dair + tool + 4 reasons) → past genesis grace
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        assert len(l._entries) >= 6  # past genesis grace
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid)  # NO input_call_ids → inferred
        assert r["success"] is True
        finding = [e for e in l._entries if e["type"] == "finding"][-1]
        assert finding.get("lineage_inferred") is True
        assert finding.get("input_call_ids")  # populated from recent results

    def test_gate_still_refuses_empty_directly(self, tmp_path):
        """The lineage_required gate in isolation still refuses an empty list —
        R4's inference happens in record_finding *before* the gate, not by
        loosening the gate itself."""
        from tools._gates import lineage_required, GateContext
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("LIN", str(tmp_path / "trace.json"))
        for _ in range(6):
            l.record_tool_call("vol.x", True, False, 0, 0)
        ctx = GateContext(
            description="x", confidence="SUSPECTED", tier="SUSPECTED", source="vol",
            linked_call_id=0, tested_hypothesis_id="", log=l, idx=l.index(),
            window=l.last_n_window(30), input_call_ids=[],
        )
        assert lineage_required.check(ctx) is not None

    def test_allows_empty_in_genesis_window(self, tmp_path):
        """With < 5 entries, empty input_call_ids is OK (bootstrap grace)."""
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("GENESIS", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # 2 entries — well within genesis grace
        assert len(l._entries) < 5
        with patch("core.execution_log.log", l):
            r = record_finding("first finding", "SUSPECTED", "vol.psscan",
                               linked_call_id=tid)  # NO input_call_ids
        # Other gates may or may not pass, but lineage_required should NOT fire
        assert r.get("gate") != "lineage_required"

    def test_repairs_unknown_cids_keeps_valid(self, tmp_path):
        """R5: mix of real + fabricated cids → drop unknown, keep real, record."""
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid,
                               input_call_ids=[tid, 99999])  # 99999 doesn't exist
        assert r["success"] is True
        finding = [e for e in l._entries if e["type"] == "finding"][-1]
        assert finding.get("lineage_repaired") is True
        assert 99999 in (finding.get("dropped_input_call_ids") or [])
        assert finding.get("input_call_ids") == [tid]

    def test_repairs_all_fabricated_cids_via_infer(self, tmp_path):
        """R5: entirely fabricated input_call_ids → infer real ones."""
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding(
                "a finding", "CONFIRMED", "vol.psscan",
                linked_call_id=901,  # also fabricated
                input_call_ids=[900, 901, 902],
            )
        assert r["success"] is True, r
        finding = [e for e in l._entries if e["type"] == "finding"][-1]
        assert finding.get("lineage_repaired") is True
        assert finding.get("lineage_inferred") is True
        assert finding.get("linked_call_id_repaired") is True
        assert finding.get("prior_linked_call_id") == 901
        assert finding.get("input_call_ids")
        assert all(cid in l.index().by_call_id for cid in finding["input_call_ids"])
        assert finding.get("linked_call_id") in l.index().by_call_id

    def test_passes_with_valid_cids(self, tmp_path):
        """input_call_ids containing only existing cids → finding records."""
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid,
                               input_call_ids=[tid])
        assert r["success"] is True
        # Finding entry carries the lineage we passed
        find_entry = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert find_entry["input_call_ids"] == [tid]
        assert not find_entry.get("lineage_repaired")

    def test_a_refusal_for_unknown_ids_says_how_many_exist_and_stays_short(self, tmp_path):
        """Ids the run has never issued are refused with the count of ids
        the trace holds and the highest one, so the list can be bounded
        against the run; a list that ran on past the range is not repeated
        whole, in the message or in the payload."""
        from tools._gates import lineage_required, GateContext
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("LIN", str(tmp_path / "trace.json"))
        for _ in range(6):
            l.record_tool_call("vol.x", True, False, 0, 0)
        top = max(l.index().by_call_id)
        invented = list(range(top + 1, top + 31))
        ctx = GateContext(
            description="x", confidence="SUSPECTED", tier="SUSPECTED", source="vol",
            linked_call_id=0, tested_hypothesis_id="", log=l, idx=l.index(),
            window=l.last_n_window(30), input_call_ids=[top] + invented,
        )
        r = lineage_required.check(ctx)
        assert r is not None and r["gate"] == "lineage_required"
        assert "30 call id(s) the run has not issued" in r["error"]
        assert f"holds 6 call ids, the highest is {top}" in r["error"]
        assert "and 20 more" in r["error"] and str(top + 30) not in r["error"]
        assert r["unknown_cids"] == invented[:10]
        assert r["description"] == "x" and r["confidence"] == "SUSPECTED"
        # The same check for a tool that records the list as given.
        assert lineage_required.check_ids(l, [top]) is None
        assert lineage_required.check_ids(l, None) is None
        assert lineage_required.check_ids(l, [top + 1])["gate"] == "lineage_required"

    def test_gate_runs_in_correct_order(self):
        """lineage_required follows dair_required in the GATES list (so
        DAIR-missing wins for a clearer message) and precedes the
        tier-specific gates that would otherwise confusingly run on a
        lineageless finding; the full order is pinned in
        test_gate_ordering.py."""
        from tools._gates import GATES
        names = [n for n, _ in GATES]
        assert names.index("dair_required") < names.index("lineage_required")
        assert names.index("lineage_required") < names.index("evidence_strength")


class TestLineageRelevance:
    """The cited call must be about the artifact the finding names, judged on
    everything the trace recorded about the call, not only the command."""

    @staticmethod
    def _ctx(description, entry):
        from types import SimpleNamespace
        from tools._gates import GateContext
        return GateContext(
            description=description, confidence="LIKELY", tier="LIKELY",
            source="net.tcpdump_read", linked_call_id=7, tested_hypothesis_id="",
            log=None, idx=SimpleNamespace(by_call_id={7: entry}),
            window=[], input_call_ids=[7],
        )

    def test_staged_alias_with_evidence_ref_is_about_the_file(self):
        from tools._gates import lineage_relevance
        entry = {"type": "tool_call",
                 "cmd": "sudo tcpdump -r /srv/cases/c1/analysis/pcap_staging/x2_ab12cd34.pcap port 21",
                 "evidence_ref": "/evidence/capture2.log"}
        assert lineage_relevance.check(
            self._ctx("capture2.log carries no FTP traffic", entry)) is None

    def test_typed_tool_named_by_its_arguments(self):
        from tools._gates import lineage_relevance
        entry = {"type": "tool_call", "cmd": "<py>:table_query",
                 "args": '{"path": "exports/tables/logons.csv", "where": "id=4624"}',
                 "stdout_excerpt": '{"returned_rows": 3}'}
        assert lineage_relevance.check(
            self._ctx("logons.csv lists three interactive logons", entry)) is None

    def test_a_typed_tools_arguments_do_not_excuse_an_unrelated_finding(self):
        """The twin of the case above: reading a call's arguments lets the
        citation be judged, and judging it means it can fail. Same entry, a
        finding about a different artifact, and the gate refuses."""
        from tools._gates import lineage_relevance
        entry = {"type": "tool_call", "cmd": "<py>:table_query",
                 "args": '{"path": "exports/tables/logons.csv", "where": "id=4624"}',
                 "stdout_excerpt": '{"returned_rows": 3}'}
        r = lineage_relevance.check(
            self._ctx("Security.evtx shows three interactive logons", entry))
        assert r is not None and r["gate"] == "lineage_relevance"

    def test_unrelated_call_still_refused(self):
        from tools._gates import lineage_relevance
        entry = {"type": "tool_call",
                 "cmd": "sudo tcpdump -r /srv/cases/c1/analysis/pcap_staging/x2_ab12cd34.pcap",
                 "evidence_ref": "/evidence/capture2.log"}
        r = lineage_relevance.check(
            self._ctx("report.docx was carved from the image", entry))
        assert r is not None and r["gate"] == "lineage_relevance"

    def test_inference_prefers_call_whose_evidence_ref_names_the_file(self):
        from tools.misc import _infer_input_call_ids
        window = [
            {"type": "tool_call", "call_id": 1,
             "cmd": "sudo tcpdump -r /x/pcap_staging/a_1.pcap",
             "evidence_ref": "/evidence/capture2.log"},
            {"type": "tool_call", "call_id": 2, "cmd": "strings /x/other.bin"},
        ]
        assert _infer_input_call_ids(
            window, description="capture2.log has no FTP") == [1]
