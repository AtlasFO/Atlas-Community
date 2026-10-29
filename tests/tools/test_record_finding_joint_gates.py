"""record_finding answers with every objection at once, runs the adversarial
evaluation a CONFIRMED claim needs itself when the evidence is on the table,
and repairs a citation that names the wrong evidence when the trace holds
the right one."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture(autouse=True)
def _no_side_helpers():
    """The wrappers around the gates that would reach for programs or the
    case directory are not what these tests are about, nor is the presence
    check a CONFIRMED request passes before the gates (its own tests:
    test_confirmed_presence.py)."""
    with patch("tools.misc.tool_program",
               side_effect=lambda name, *rest: f"/usr/local/bin/{name}"), \
            patch("tools.misc._confirmed_presence", lambda *a, **k: None):
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

    @pytest.mark.usefixtures("todays_dair")
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
        # Lineage by wiring: the analyst's id stays as cited and nothing is
        # replaced. The relevance gate passes because the trace holds a call
        # about report.docx; that call read the file but its rows show none
        # of the finding's entities (the file it read does not count, so it
        # never locates the finding). The cited capture did not read the
        # file, so the read-file rule (not_checkable) does not apply: the
        # finding is disclosed as not shown.
        assert "lineage_note" not in r and "lineage" not in r
        assert "no call in the trace shows" in r["citation"]
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert finding["input_call_ids"] == [pcap] and finding["linked_call_id"] == pcap
        assert "located_call_ids" not in finding and finding["citation_status"] == "not_shown"
        assert "irrelevant_input_call_ids" not in finding

    def test_the_wiring_off_restores_the_replacement(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        monkeypatch.setenv("ATLAS_LINEAGE_WIRING", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        doc = l.record_tool_call("<py>:strings_read_text", True, False, 0, 0,
                                 evidence_ref="exports/carved/report.docx",
                                 stdout_excerpt="customer list ...")
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        pcap = l.record_tool_call("tcpdump -r evidence/capture.pcap port 21", True, False, 0, 0,
                                  stdout_excerpt="3 packets")
        with patch("core.execution_log.log", l):
            r = record_finding("report.docx was carved from the disk image and holds "
                               "the customer list", "SUSPECTED", "carve",
                               linked_call_id=pcap, input_call_ids=[pcap])
        assert r["success"] is True and "lineage_note" in r and str(pcap) in r["lineage_note"]
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert finding["input_call_ids"] == [doc] and finding["irrelevant_input_call_ids"] == [pcap]

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


def _evaluate_stub_text(verdict: str, more: str):
    def fake(finding, supporting_evidence, case_context="", input_call_ids=None):
        from core.execution_log import log
        # the reason where the prescribed format puts it (2. CONTRADICTING EVIDENCE)
        text = (f"VERDICT: {verdict}\n1. EVIDENCE SUPPORT - the logon row.\n"
                "2. CONTRADICTING EVIDENCE - a second principal is not excluded.\n"
                f"6. ADDITIONAL INVESTIGATION - {more}\n7. VERDICT: {verdict} - see above")
        cid = log.record_reason_call(
            "reason_evaluate_finding", True, text, {},
            inputs={"user_message": f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"},
            input_call_ids=input_call_ids)
        return {"success": True, "conclusion": text, "_atlas_call_id": cid}
    return fake


class TestLikelyAttributionIsEvaluated:
    """ATLAS_EXTERNAL_LOOKUP_FIRST: a LIKELY verdict binding an account to a
    person is evaluated adversarially; CHALLENGED lowers it to SUSPECTED and
    never refuses, SUPPORTED stands behind it."""

    DESC = "The account svc_backup was used by Alice during the remote session from 10.0.0.7"
    OUT = "EventID 4624 LogonType 10 TargetUserName svc_backup IpAddress 10.0.0.7"

    def _record(self, tmp_path, stub):
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("ez.evtxecmd", True, False, 0, 0, stdout_excerpt=self.OUT)
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", stub):
            r = record_finding(self.DESC, "LIKELY", "ez.evtxecmd", linked_call_id=tid,
                               input_call_ids=[tid], supporting_evidence=f"ez.evtxecmd: {self.OUT}")
        return l, r

    def test_challenged_lowers_to_suspected_with_the_evaluators_words(self, tmp_path):
        l, r = self._record(tmp_path, _evaluate_stub_text("CHALLENGED", "Read the session's other logons."))
        assert r["success"] is True and r["confidence"] == "SUSPECTED"
        assert r["tier_auto_downgrade_reason"] == "attribution_evaluation_challenged"
        assert r["evaluation"]["additional_investigation"] == "Read the session's other logons."
        assert "second principal is not excluded" in r["evaluation"]["text"]
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]           # the record keeps
        assert "second principal is not excluded" in json.dumps(finding)               # the evaluator's words

    def test_supported_stamps_the_evaluation(self, tmp_path):
        l, r = self._record(tmp_path, _evaluate_stub_text("SUPPORTED", "None."))
        assert r["success"] is True and r["confidence"] == "LIKELY"
        finding = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert finding["gated_by_evaluate_call_id"] == r["evaluation"]["call_id"]

    def test_switch_off_runs_no_evaluation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_EXTERNAL_LOOKUP_FIRST", "0")
        _l, r = self._record(tmp_path, lambda *a, **k: pytest.fail("evaluated with the switch off"))
        assert r["success"] is True and r["confidence"] == "LIKELY" and "evaluation" not in r

    def test_a_finding_that_names_no_person_is_not_evaluated(self, tmp_path):
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("ez.evtxecmd", True, False, 0, 0, stdout_excerpt=self.OUT)
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding",
                      lambda *a, **k: pytest.fail("evaluated a non-attribution")):
            r = record_finding("A remote session logon from 10.0.0.7 is recorded in the log", "LIKELY",
                               "ez.evtxecmd", linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence=f"ez.evtxecmd: {self.OUT}")
        assert r["success"] is True and "evaluation" not in r


def test_a_challenged_attribution_is_lowered_even_when_suspected_is_refused(tmp_path):
    """A SUSPECTED-only objection does not leave a challenged verdict at
    LIKELY unmarked: the finding is recorded lowered, the objection on the
    downgrade record."""
    import tools._gates as gates_mod
    real = gates_mod.run_all_gates

    def gates(ctx):
        out = real(ctx)
        if ctx.tier == "SUSPECTED":
            out = out + [{"success": False, "gate": "example_gate", "error": "an objection at SUSPECTED"}]
        return out
    t = TestLikelyAttributionIsEvaluated()
    with patch.object(gates_mod, "run_all_gates", gates):
        l, r = t._record(tmp_path, _evaluate_stub_text("CHALLENGED", "Read the other logons."))
    assert r["success"] is True and r["confidence"] == "SUSPECTED"
    assert "an objection at SUSPECTED" in r["tier_auto_downgrade_objection"]
    finding = [e for e in l._entries if e.get("type") == "finding"][-1]
    assert finding["confidence"] == "SUSPECTED"


def _evaluate_stub_reason(verdict: str):
    """A review that answers with a reason in the prescribed sections (and,
    for "", no VERDICT line): the supported part first, the reason after it."""
    def fake(finding, supporting_evidence, case_context="", input_call_ids=None):
        from core.execution_log import log
        text = ((f"VERDICT: {verdict}\n" if verdict else "")
                + "1. EVIDENCE SUPPORT - " + "the row shows process 5024 is present. " * 20
                + "\n2. CONTRADICTING EVIDENCE - the rows show the process, not who started it.")
        cid = log.record_reason_call(
            "reason_evaluate_finding", True, text, {},
            inputs={"user_message": f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"},
            input_call_ids=input_call_ids)
        return {"success": True, "conclusion": text, "_atlas_call_id": cid}
    return fake


def _erroring(finding, supporting_evidence, case_context="", input_call_ids=None):
    raise RuntimeError("the reasoning backend timed out")


class TestTheEvaluatorsReasonReachesTheModel:
    """The reason travels with a verdict that refuses, end to end: through
    record_finding, and through SubmitApplier._record into the item's reply."""

    def _record(self, tmp_path, stub):
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0, stdout_excerpt="PID 5024 svchost.exe")
        with patch("core.execution_log.log", l), patch("tools.reasoning.reason_evaluate_finding", stub):
            r = record_finding("Process 5024 is present in the memory image", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid],
                               supporting_evidence="vol.psscan: PID 5024 svchost.exe")
        return r

    def _item_reply(self, tmp_path, r):
        import json
        from agent.frontier import SubmitApplier

        class _A:
            def _call_once(self, name, args, **kw):
                return {"result": json.dumps(r), "kind": "ran"}
        ap = SubmitApplier(_A(), str(tmp_path), None, {"source_ref": {}, "call_id": 1}, "plan")
        f = {"statement": "Process 5024 is present in the memory image", "confidence": "confirmed"}
        gate, text, claim = ap._record(f, [{"call_id": 7, "row_ref": "7#L1", "quote": "PID 5024"}], ["PID 5024"], [])
        return gate, text, ap

    @pytest.mark.parametrize("verdict", ["CHALLENGED", "UNCERTAIN"])
    def test_a_refusing_verdict_carries_its_reason_into_the_item_reply(self, tmp_path, monkeypatch, verdict):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        r = self._record(tmp_path, _evaluate_stub_reason(verdict))
        assert r["success"] is False and r["evaluation"]["verdict"] == verdict
        assert "not who started it" in r["evaluation"]["text"]
        gate, text, ap = self._item_reply(tmp_path, r)
        assert f"an evaluator answered {verdict}" in text and "not who started it" in text
        assert any("not who started it" in v["text"] for v in ap.challenged.values())   # challenged-before keeps it

    def test_a_supported_verdict_carries_no_text(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        r = self._record(tmp_path, _evaluate_stub_reason("SUPPORTED"))
        assert r["success"] is True and "text" not in r["evaluation"]

    def test_an_evaluation_that_failed_is_said_as_that(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        r = self._record(tmp_path, _erroring)
        assert r["success"] is False and "timed out" in r["evaluation"]["error"]
        _gate, text, _ap = self._item_reply(tmp_path, r)
        assert "could not run" in text and "timed out" in text and "runs when the finding is recorded" not in text

    def test_an_answer_without_a_verdict_line_is_named_and_shows_its_words(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        r = self._record(tmp_path, _evaluate_stub_reason(""))
        assert r["success"] is False and "not who started it" in r["evaluation"]["text"]
        _gate, text, _ap = self._item_reply(tmp_path, r)
        assert "without a verdict line" in text and "not who started it" in text


# -- a review counts for the finding it reviewed ---------------------------------------------

_OPENING = "At 2031-03-10 14:03:15, a service named KitUpdate was installed on CORP-WS02"
_ROW_A = "[call 21] 2031-03-10 14:03:15 7045 KitUpdate C:\\Users\\Public\\svc_kit.exe -k"
_ROW_B = "[call 22] 2031-03-10 14:03:16 7036 KitUpdate entered the running state"


def _review(finding, evidence, verdict="SUPPORTED", text=""):
    return {"type": "reason_call", "tool": "reason_evaluate_finding", "success": True,
            "conclusion": f"VERDICT: {verdict}\n{text}",
            "inputs": {"user_message": f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{evidence}"}}


class TestTheReviewIsTheFindingsOwn:
    def test_a_review_counts_only_for_the_statement_it_reviewed(self):
        from tools._gates._match import normalize_desc, reviews
        e = _review(f"{_OPENING}.", _ROW_A)
        assert reviews(e, normalize_desc(f"{_OPENING}."))
        assert reviews(e, normalize_desc(f"  {_OPENING.upper()}.\n"))           # case and whitespace only
        assert not reviews(e, normalize_desc(_OPENING))                     # a narrowed wording
        assert not reviews(e, normalize_desc(f"{_OPENING}, establishing persistence."))   # adds an inference
        quoted = _review("svc_kit.exe connected to 203.0.113.7", f"earlier finding: {_OPENING}.")
        assert not reviews(quoted, normalize_desc(f"{_OPENING}."))       # named only in another's evidence
        assert not reviews({"inputs": {"user_message": f"{_OPENING}."}}, normalize_desc(f"{_OPENING}."))

    @pytest.mark.parametrize("reviewed, statement", [
        ("No row shows that data was exfiltrated to 198.51.100.20.", "data was exfiltrated to 198.51.100.20"),
        ("It is unlikely that svc_kit.exe established persistence on CORP-WS02.",
         "svc_kit.exe established persistence on CORP-WS02."),
        ("The attacker did not use jane.doe; the account jane.doe logged on from 203.0.113.7.",
         "The attacker did not use jane.doe"),
    ])
    def test_a_supported_negation_or_hedge_never_passes_the_claim_inside_it(self, tmp_path, monkeypatch,
                                                                             reviewed, statement):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools._gates._match import normalize_desc, reviews
        from tools.misc import record_finding
        e = _review(reviewed, _ROW_A)
        assert not reviews(e, normalize_desc(statement))
        l = _log(tmp_path)
        tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED - the rows hold it.", {},
                             inputs=e["inputs"])
        with patch("core.execution_log.log", l):
            r = record_finding(statement, "CONFIRMED", "table.table_grep", linked_call_id=tid,
                               input_call_ids=[tid], supporting_evidence=_ROW_A)
        assert r["success"] is False and "reason.evaluate_finding" in r["error"]

    def test_a_rewording_after_the_same_opening_is_reviewed_on_its_own(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {},
                             inputs={"user_message": f"FINDING:\n{_OPENING}.\n\nSUPPORTING EVIDENCE:\n{_ROW_A}"})
        asked = []

        def stub(finding, supporting_evidence, case_context="", input_call_ids=None):
            asked.append(finding)
            return _evaluate_stub("CHALLENGED")(finding, supporting_evidence, case_context, input_call_ids)
        reworded = f"{_OPENING} with image path C:\\Users\\Public\\svc_kit.exe -k, establishing persistence."
        with patch("core.execution_log.log", l), patch("tools.reasoning.reason_evaluate_finding", stub):
            r = record_finding(reworded, "CONFIRMED", "table.table_grep", linked_call_id=tid,
                               input_call_ids=[tid], supporting_evidence=_ROW_A)
        assert asked == [reworded] and r["success"] is False and r["evaluation"]["auto"] is True

    def test_a_reworded_legacy_record_without_evidence_is_told_to_evaluate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {},
                             inputs={"user_message": f"FINDING:\n{_OPENING}.\n\nSUPPORTING EVIDENCE:\n{_ROW_A}"})
        with patch("core.execution_log.log", l):
            r = record_finding(f"{_OPENING}, establishing persistence.", "CONFIRMED", "table.table_grep",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False and "reason.evaluate_finding" in r["error"]
        assert "evaluation" not in r

    def test_a_reused_challenged_review_carries_its_reason(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
        ev = l.record_reason_call(
            "reason_evaluate_finding", True,
            "VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT: the 7045 row.\n2. CONTRADICTING EVIDENCE: no row shows "
            "who installed it.\n7. VERDICT: CHALLENGED - the installer is not shown.", {},
            inputs={"user_message": f"FINDING:\n{_OPENING}.\n\nSUPPORTING EVIDENCE:\n{_ROW_A}"})
        asked = []
        with patch("core.execution_log.log", l), \
                patch("tools.reasoning.reason_evaluate_finding", lambda **kw: asked.append(kw)):
            r = record_finding(f"{_OPENING}.", "CONFIRMED", "table.table_grep", linked_call_id=tid,
                               input_call_ids=[tid], supporting_evidence=f"{_ROW_A}\n{_ROW_B}")
        assert asked == [] and r["success"] is False                    # an analyst's review stands
        assert r["evaluation"] == {"verdict": "CHALLENGED", "call_id": ev, "reused": True,
                                   "text": "the installer is not shown. | contradicting evidence: no row shows "
                                           "who installed it."}
        from agent.frontier import _item_refusal
        assert "the installer is not shown." in _item_refusal(r)


class TestAnAutoReviewIsRedoneOnRowsItDidNotJudge:
    def _first(self, tmp_path, monkeypatch, asked):
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
        from tools.misc import record_finding
        l = _log(tmp_path)
        tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=f"{_ROW_A}\n{_ROW_B}")

        def stub(finding, supporting_evidence, case_context="", input_call_ids=None):
            # recorded the way the real tool records (tools.reasoning._log_reason)
            import tools.reasoning as R
            asked.append(supporting_evidence)
            res = {"success": True, "conclusion": "VERDICT: CHALLENGED\n1. EVIDENCE SUPPORT - cited.",
                   "inputs": {"user_message": f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"}}
            R._log_reason("reason_evaluate_finding", res, input_call_ids=input_call_ids)
            return res

        def record(evidence):
            with patch("core.execution_log.log", l), patch("tools.reasoning.reason_evaluate_finding", stub):
                return record_finding(f"{_OPENING}.", "CONFIRMED", "table.table_grep", linked_call_id=tid,
                                      input_call_ids=[tid], supporting_evidence=evidence)
        r = record(_ROW_A)
        assert asked == [_ROW_A] and r["success"] is False
        return record, l

    def test_a_new_row_gets_a_new_evaluation(self, tmp_path, monkeypatch):
        asked: list = []
        record, l = self._first(tmp_path, monkeypatch, asked)
        r = record(f"{_ROW_A}\n{_ROW_B}")
        assert asked == [_ROW_A, f"{_ROW_A}\n{_ROW_B}"] and r["evaluation"]["auto"] is True
        marks = [(e.get("inputs") or {}).get("auto") for e in l._entries if e.get("type") == "reason_call"]
        assert marks == [True, True]


def test_an_auto_evaluation_is_marked_when_its_entry_is_created_and_only_it(tmp_path, monkeypatch):
    """The mark rides the exact request into the trace entry's creation (the
    call runs on the watchdog's thread); an analyst's call with the same
    finding and other evidence, or after the block, stays unmarked."""
    import tools.reasoning as R
    l = _log(tmp_path)
    seen = []

    def ask(system, user, _tool_name="", hypothesis_id="", input_call_ids=None):
        res = {"success": True, "conclusion": "VERDICT: CHALLENGED - not shown.", "inputs": {"user_message": user}}
        R._log_reason(_tool_name, res, input_call_ids=input_call_ids)
        seen.append(dict(l._entries[-1]["inputs"]))                  # as created, before anything else runs
        return res
    monkeypatch.setattr(R, "_ask", ask)
    with patch("core.execution_log.log", l):
        with R.auto_evaluation(f"{_OPENING}.", _ROW_A):
            R.reason_evaluate_finding(finding=f"{_OPENING}.", supporting_evidence=_ROW_A)
            R.reason_evaluate_finding(finding=f"{_OPENING}.", supporting_evidence=_ROW_B)
        R.reason_evaluate_finding(finding=f"{_OPENING}, by jane.doe.", supporting_evidence=_ROW_A)
    assert [i.get("auto") for i in seen] == [True, None, None] and not R._AUTO_REQUESTS

    def test_the_same_rows_give_the_stale_reason_without_a_call(self, tmp_path, monkeypatch):
        asked: list = []
        record, _l = self._first(tmp_path, monkeypatch, asked)
        r = record(_ROW_A)
        assert asked == [_ROW_A] and r["evaluate_verdict"] == "CHALLENGED" and r["evaluation"]["reused"] is True


def test_rewordings_re_evaluated_are_never_refused_as_reformulations(tmp_path, monkeypatch):
    """Three wordings of one opening, nothing read between them: each is a
    finding of its own, evaluated by the real tool (its backend stubbed)."""
    import tools.reasoning as R
    l = _log(tmp_path)

    def ask(system, user, _tool_name="", hypothesis_id="", input_call_ids=None):
        res = {"success": True, "conclusion": "VERDICT: CHALLENGED - not shown.",
               "inputs": {"user_message": user}}
        R._log_reason(_tool_name, res, input_call_ids=input_call_ids)
        return res
    monkeypatch.setattr(R, "_ask", ask)
    with patch("core.execution_log.log", l):
        out = [R.reason_evaluate_finding(finding=f"{_OPENING}{tail}", supporting_evidence=_ROW_A)
               for tail in (".", ", by jane.doe.", ", establishing persistence.")]
    assert all(o.get("gate") != "reformulation_depth_limit" and o["success"] for o in out)


def test_a_narrowed_statement_is_judged_on_its_own_and_never_as_a_reformulation(tmp_path, monkeypatch):
    """Two longer wordings were challenged with nothing read between; the
    statement narrowed to their common core is evaluated (the real tool,
    its backend stubbed), not refused on their verdict or as a repeat."""
    import tools.reasoning as R
    from tools.misc import record_finding
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    l = _log(tmp_path)
    tid = l.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
    asked = []

    def ask(system, user, _tool_name="", hypothesis_id="", input_call_ids=None):
        asked.append(user)
        verdict = "SUPPORTED" if f"{_OPENING}.\n" in user else "CHALLENGED"
        res = {"success": True, "conclusion": f"VERDICT: {verdict} - read.", "inputs": {"user_message": user}}
        R._log_reason(_tool_name, res, input_call_ids=input_call_ids)
        return res
    monkeypatch.setattr(R, "_ask", ask)
    with patch("core.execution_log.log", l):
        for tail in (", establishing persistence.", ", by jane.doe."):
            R.reason_evaluate_finding(finding=f"{_OPENING}{tail}", supporting_evidence=_ROW_A)
        r = record_finding(f"{_OPENING}.", "CONFIRMED", "table.table_grep", linked_call_id=tid,
                           input_call_ids=[tid], supporting_evidence=_ROW_A)
    assert len(asked) == 3 and r["success"] is True and r["confidence"] == "CONFIRMED"
    # the control: the same wording a third time with nothing read between is refused
    with patch("core.execution_log.log", l):
        again = [R.reason_evaluate_finding(finding=f"{_OPENING}, by jane.doe.", supporting_evidence=_ROW_A)
                 for _ in range(2)]
    assert again[-1].get("gate") == "reformulation_depth_limit"


def test_the_claim_keeps_the_recorded_wording_so_its_review_is_found_again(tmp_path, monkeypatch):
    """The incident map and the conclusion door look a claim's review up by
    the claim node's statement: it is the description record_finding took
    (host given separately, nothing appended), so the shared matcher finds
    the review that let it in."""
    from core.claim_graph import load_graph
    from core.conclusion_door import _evaluated
    from tests.core.test_incident_map import _case, _trace
    from tools._gates._match import find_reason_call, normalize_desc
    from tools.misc import record_finding
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    log.record_dair_call("Triage", "", False, "", "", "stay", "")
    tid = log.record_tool_call("table.table_grep", True, False, 0, 0, stdout_excerpt=_ROW_A)
    desc = f"{_OPENING}  with image path\nC:\\Users\\Public\\svc_kit.exe -k."
    with patch("tools.reasoning.reason_evaluate_finding", _evaluate_stub("SUPPORTED")):
        r = record_finding(desc, "CONFIRMED", "table.table_grep", host="CORP-WS02", linked_call_id=tid,
                           input_call_ids=[tid], supporting_evidence=_ROW_A)
    assert r["success"] is True and r["confidence"] == "CONFIRMED"
    (node,) = [n for n in load_graph(case)["nodes"].values() if n.get("statement")]
    assert normalize_desc(node["statement"]) == normalize_desc(desc)
    found = find_reason_call(log._entries, "reason_evaluate_finding", normalize_desc(node["statement"]))
    assert found is not None and found["call_id"] == r["evaluation"]["call_id"]
    assert _evaluated(node["statement"], log)
