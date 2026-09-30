"""record_finding answers with every objection at once, runs the adversarial
evaluation a CONFIRMED claim needs itself when the evidence is on the table,
and repairs a citation that names the wrong evidence when the trace holds
the right one."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture(autouse=True)
def _no_side_helpers():
    """The wrappers around the gates that would reach for programs or the
    case directory are not what these tests are about."""
    with patch("tools.misc.tool_program",
               side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


def _log(tmp_path):
    l = ExecutionLog()
    l.configure("JOINT", str(tmp_path / "trace.json"), save_session=False)
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    return l


class TestEveryObjectionAtOnce:
    def test_the_refusal_lists_the_other_gates_objections(self, tmp_path, monkeypatch):
        """A CONFIRMED claim with no evaluation whose cited call is about a
        different artifact is refused for both reasons in one answer, and
        the tier is not lowered because a lower tier would not clear the
        citation objection."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        pcap = l.record_tool_call("tcpdump -r evidence/capture.pcap port 21", True, False, 0, 0,
                                  stdout_excerpt="3 packets")
        l.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                           evidence_ref="evidence/other/notes.txt",
                           stdout_excerpt="unrelated text")
        with patch("core.execution_log.log", l):
            r = record_finding("report.docx was carved from the disk image and holds "
                               "the customer list", "CONFIRMED", "carve",
                               linked_call_id=pcap, input_call_ids=[pcap])
        assert r["success"] is False
        assert r["gate"] == "lineage_relevance"
        others = {o["detail_gate"] for o in r["also_refused_by"]}
        assert "confirmed_requires_supported_evaluate" in others
        assert "ALSO REFUSED BY" in r["error"]
        assert "evaluate_finding" in r["error"]
        assert r.get("tier_auto_downgraded_from") is None

    def test_a_single_objection_carries_no_list(self, tmp_path, monkeypatch):
        """No DAIR batch is the one thing wrong with this SUSPECTED claim."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        from tools.misc import record_finding
        l = ExecutionLog()
        l.configure("SOLO", str(tmp_path / "trace.json"), save_session=False)
        tid = l.record_tool_call("<py>:misc_list_evidence_dir", True, False, 0, 0,
                                 stdout_excerpt="notes.txt")
        with patch("core.execution_log.log", l):
            r = record_finding("notes.txt is present in the export", "SUSPECTED",
                               "misc.list_evidence_dir",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False and r["gate"] == "dair_required"
        assert "also_refused_by" not in r and "ALSO REFUSED" not in r["error"]


def _evaluate_stub(verdict: str):
    """A reasoning backend that answers the adversarial review with one
    verdict, recorded on the trace the way the real tool records it."""
    def fake(finding, supporting_evidence, case_context="", input_call_ids=None):
        from core.execution_log import log
        cid = log.record_reason_call(
            "reason_evaluate_finding", True,
            f"VERDICT: {verdict}\n1. EVIDENCE SUPPORT - cited.", {},
            inputs={"user_message": f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n"
                                    f"{supporting_evidence}"},
            input_call_ids=input_call_ids)
        return {"success": True, "conclusion": f"VERDICT: {verdict}",
                "_atlas_call_id": cid}
    return fake


class TestTheReviewRunsInPlace:
    def test_confirmed_with_evidence_is_evaluated_and_recorded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0,
                                 stdout_excerpt="PID 5024 svchost.exe")
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", _evaluate_stub("SUPPORTED")):
            r = record_finding("Process 5024 is present in the memory image",
                               "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="vol.psscan: PID 5024 svchost.exe")
        assert r["success"] is True and r["confidence"] == "CONFIRMED"
        assert r["evaluation"]["auto"] is True
        assert r["evaluation"]["verdict"] == "SUPPORTED"
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert finding["gated_by_evaluate_call_id"] == r["evaluation"]["call_id"]

    def test_a_challenged_review_still_refuses_with_the_verdict(self, tmp_path, monkeypatch):
        """The bar is the verdict, not the ritual: the review Atlas ran is
        read exactly as one the analyst made."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0,
                                 stdout_excerpt="PID 5024 svchost.exe")
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", _evaluate_stub("CHALLENGED")):
            r = record_finding("Process 5024 is present in the memory image",
                               "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="vol.psscan: PID 5024 svchost.exe")
        assert r["success"] is False
        assert r["detail_gate"] == "confirmed_requires_supported_evaluate"
        assert r["evaluate_verdict"] == "CHALLENGED"
        assert r["evaluation"]["verdict"] == "CHALLENGED"

    def test_evidence_offered_to_a_sibling_reviewer_is_used(self, tmp_path, monkeypatch):
        """confidence_score and cite_check take the same finding and evidence
        the evaluation takes; what was assembled for them serves it."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0,
                                 stdout_excerpt="PID 5024 svchost.exe")
        desc = "Process 5024 is present in the memory image"
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call(
            "reason_confidence_score", True,
            'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED", "score": 0.9}', {},
            inputs={"user_message": f"FINDING:\n{desc}\n\nSUPPORTING_EVIDENCE:\n"
                                    "vol.psscan: PID 5024 svchost.exe\n\n"
                                    "AGENT_INTENDED_TIER: CONFIRMED"})
        l.record_reason_call(
            "reason_cite_check", True, 'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {},
            inputs={"user_message": f"FINDING:\n{desc}\n\nSUPPORTING_EVIDENCE:\n"
                                    "vol.psscan: PID 5024 svchost.exe"})
        seen = {}

        def fake(finding, supporting_evidence, case_context="", input_call_ids=None):
            seen["evidence"] = supporting_evidence
            return _evaluate_stub("SUPPORTED")(finding, supporting_evidence,
                                               case_context, input_call_ids)
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", fake):
            r = record_finding(desc, "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert seen["evidence"].startswith("vol.psscan: PID 5024")
        assert r["success"] is True and r["confidence"] == "CONFIRMED"

    def test_without_any_evidence_nothing_is_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        calls = []
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding",
                      lambda **kw: calls.append(kw)):
            r = record_finding("A process is present", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert calls == [] and r["success"] is False and "evaluation" not in r

    def test_the_switch_turns_it_off(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0,
                                 stdout_excerpt="PID 5024")
        calls = []
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding",
                      lambda **kw: calls.append(kw)):
            r = record_finding("Process 5024 is present", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="vol.psscan: PID 5024")
        assert calls == [] and r["success"] is False


class TestCitationRepair:
    def test_ids_about_other_artifacts_are_replaced_from_the_trace(self, tmp_path, monkeypatch):
        """The cited call read a capture; the finding is about a carved
        document the trace read forty calls earlier. The citation becomes
        that call, the finding records, and the repair is on the record."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        doc = l.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                                 evidence_ref="exports/carved/report.docx",
                                 stdout_excerpt="customer list ...")
        for i in range(40):
            l.record_tool_call(f"table_query analysis/t{i}.csv", True, False, 0, 0)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        pcap = l.record_tool_call("tcpdump -r evidence/capture.pcap port 21", True, False, 0, 0,
                                  stdout_excerpt="3 packets")
        with patch("core.execution_log.log", l):
            r = record_finding("report.docx was carved from the disk image and holds "
                               "the customer list", "SUSPECTED", "carve",
                               linked_call_id=pcap, input_call_ids=[pcap])
        assert r["success"] is True
        assert "lineage_note" in r and str(pcap) in r["lineage_note"]
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert finding["input_call_ids"] == [doc]
        assert finding["irrelevant_input_call_ids"] == [pcap]
        assert finding["linked_call_id"] == doc

    def test_nothing_in_the_trace_about_the_artifact_still_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        pcap = l.record_tool_call("tcpdump -r evidence/capture.pcap port 21", True, False, 0, 0,
                                  stdout_excerpt="3 packets")
        with patch("core.execution_log.log", l):
            r = record_finding("report.docx was carved from the disk image",
                               "SUSPECTED", "carve",
                               linked_call_id=pcap, input_call_ids=[pcap])
        assert r["success"] is False and r["gate"] == "lineage_relevance"

    def test_inference_reaches_past_the_recency_window(self, tmp_path):
        """An omitted citation is inferred from the call that read the
        artifact, wherever in the recent trace it is."""
        from tools.misc import _infer_input_call_ids
        entries = [{"type": "tool_call", "call_id": 1,
                    "cmd": "<py>:strings_read_text",
                    "evidence_ref": "exports/carved/report.docx"}]
        entries += [{"type": "tool_call", "call_id": i, "cmd": f"table_query t{i}.csv"}
                    for i in range(2, 60)]
        window = entries[-30:]
        assert _infer_input_call_ids(window, description="report.docx holds the list",
                                     entries=entries) == [1]
        assert 1 not in _infer_input_call_ids(window, description="report.docx holds the list")


class TestAnotherFindingsReviewIsNotThisOnes:
    def test_a_supported_review_of_another_claim_does_not_admit_confirmed(self, tmp_path, monkeypatch):
        """The review names the finding it reviewed; a later, different
        CONFIRMED claim is not carried by it and gets its own evaluation."""
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                                 evidence_ref="exports/tables/Amcache.csv",
                                 stdout_excerpt="sync.exe installed 2024-03-03")
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call(
            "reason_evaluate_finding", True, "VERDICT: SUPPORTED", {},
            inputs={"user_message": "FINDING:\nfive logons were recorded for the "
                                    "account\n\nSUPPORTING EVIDENCE:\n4624 rows"})
        seen = []

        def fake(finding, supporting_evidence, case_context="", input_call_ids=None):
            seen.append(finding)
            return _evaluate_stub("CHALLENGED")(finding, supporting_evidence,
                                                case_context, input_call_ids)
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", fake):
            r = record_finding("sync.exe was installed on 2024-03-03 by the account",
                               "CONFIRMED", "table.table_query",
                               linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="Amcache.csv: sync.exe installed 2024-03-03")
        assert seen == ["sync.exe was installed on 2024-03-03 by the account"]
        assert r["success"] is False and r["evaluate_verdict"] == "CHALLENGED"

    def test_a_review_that_does_not_say_what_it_reviewed_still_counts(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                                 stdout_excerpt="sync.exe installed 2024-03-03")
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("sync.exe was installed on 2024-03-03", "CONFIRMED",
                               "table.table_query", linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="table_query: sync.exe installed 2024-03-03")
        assert r["success"] is True and r["confidence"] == "CONFIRMED"
