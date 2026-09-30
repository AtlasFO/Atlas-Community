"""The report gate judges what the run still asserts, not everything the
append-only trace recorded. A finding retired on the claim graph stops
counting for every check; one the gate lowered is seen at its lowered tier;
one that is still asserted with an unsupported citation keeps blocking."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import load_graph, supersede
from core.execution_log import ExecutionLog


# The finding rests on an address that its cited call never printed while
# another call did: the record-time citation advisory and the report gate
# both read it as resting on evidence that does not show it.
MISCITED = ("Beacon traffic to 203.0.113.9 from the workstation was established "
            "over port 443 during the intrusion window")
SUPPORTED = "Process svc_update.exe on the workstation held an outbound connection"


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def log(case):
    l = ExecutionLog()
    l.configure("GATE", str(case / "trace.json"), save_session=False)
    l.record_tool_call("vol.psscan", True, False, 0, 0)
    l.record_tool_call("coverage.coverage_report", True, False, 0, 0)
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_hypothesize", True, "hyp", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    return l


def _record(log, case, description, confidence="LIKELY", cite=None):
    """A finding on the trace with its claim mirror on the graph, the way
    record_finding leaves them."""
    from core.claim_graph import upsert_claim_from_finding
    cid = log.record_finding(description, confidence, "vol.netscan",
                             linked_call_id=cite or 0,
                             input_call_ids=[cite] if cite else None)
    res = upsert_claim_from_finding(
        str(case), statement=description, confidence=confidence,
        source="vol.netscan", finding_call_id=cid, linked_call_id=cite or 0,
        input_call_ids=[cite] if cite else None)
    for e in log._entries:
        if e.get("call_id") == cid:
            e["claim_id"] = res["claim_id"]
    return cid, res["claim_id"]


def _check(log, case):
    from tools.reasoning import _pre_report_check
    with patch("core.execution_log.log", log), \
         patch.object(log, "case_dir", return_value=str(case)):
        return _pre_report_check()


def _citation_issues(verdict):
    return [i for i in verdict["blocking_issues"] if "identifiers they rest on" in i]


class TestWithdrawnClaimsStopCounting:
    def test_an_asserted_miscited_finding_blocks(self, log, case):
        """The genuine catch: the cited call shows none of the finding's
        identifiers, another call does, and nothing has been withdrawn."""
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                             stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        _record(log, case, MISCITED, cite=wrong)
        v = _check(log, case)
        assert v["ready_to_report"] is False
        assert _citation_issues(v)

    def test_a_superseded_finding_no_longer_blocks(self, log, case):
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        right = log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        _, old = _record(log, case, MISCITED, cite=wrong)
        assert _citation_issues(_check(log, case))
        _, new = _record(log, case, SUPPORTED, cite=right)
        assert supersede(str(case), old, new, reason="re-recorded against the call that shows it")["success"]
        v = _check(log, case)
        assert not _citation_issues(v)
        assert v["ready_to_report"] is True
        assert any("superseded or withdrawn" in w for w in v["warnings"])
        # The trace still holds both findings for audit.
        assert sum(1 for e in log._entries if e.get("type") == "finding") == 2

    def test_a_withdrawn_finding_with_no_replacement_no_longer_blocks(self, log, case):
        """A claim the evidence cannot support is withdrawn outright; the
        report then simply does not make it."""
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                             stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        _, old = _record(log, case, MISCITED, cite=wrong)
        assert _citation_issues(_check(log, case))
        r = supersede(str(case), old, reason="the address is in no output the finding cites; withdrawn")
        assert r["success"] and r["withdrawn"]
        v = _check(log, case)
        assert not _citation_issues(v)
        assert v["ready_to_report"] is True

    def test_withdrawal_reaches_every_check_not_one(self, log, case):
        """The case-question check reads the same view: the answer a run
        withdrew no longer answers the question."""
        right = log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        log.record_agent_message("CASE_QUESTION: Which external address did the beacon "
                                 "traffic reach during the intrusion?")
        _, cid = _record(log, case, MISCITED, cite=right)
        assert not any("Case question" in i for i in _check(log, case)["blocking_issues"])
        supersede(str(case), cid, reason="withdrawn: the beacon address could not be confirmed")
        assert any("Case question" in i for i in _check(log, case)["blocking_issues"])


class TestTheLoweredTierIsSeen:
    def test_a_claim_lowered_on_the_graph_is_a_limitation_not_a_blocker(self, log, case):
        """The gate's own remedy lowers a mis-cited claim to UNCONFIRMED on
        the graph; the next pass must see that tier or it re-blocks and the
        remedy oscillates."""
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                             stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        _, cid = _record(log, case, MISCITED, confidence="CONFIRMED", cite=wrong)
        assert _citation_issues(_check(log, case))
        g = load_graph(str(case))
        g["nodes"][cid]["confidence"] = "UNCONFIRMED"
        from core.claim_graph import save_graph
        save_graph(str(case), g)
        v = _check(log, case)
        assert not _citation_issues(v)
        assert any("Already at the floor tier" in w for w in v["warnings"])
        assert MISCITED[:80] in v["documented_limitations"]
        assert v["confirmed_findings"] == 0


class TestWhatCountsAsTheCitedEvidence:
    def test_the_findings_own_record_call_does_not_support_it(self, log, case):
        """Citing the call that recorded the finding restates it; the
        identifiers it carries are the analyst's, not a tool's."""
        own = log.record_tool_call("<py>:misc_record_finding", True, False, 0, 0,
                                   stdout_excerpt=json.dumps({"description": MISCITED}))
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                             stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443 ESTABLISHED")
        cid = log.record_finding(MISCITED, "LIKELY", "vol.netscan",
                                 linked_call_id=wrong, input_call_ids=[wrong, own])
        assert _citation_issues(_check(log, case))

    def test_a_cited_call_without_recorded_output_is_not_judged(self, log, case):
        silent = log.record_tool_call("<py>:vol_netscan", True, False, 0, 0)
        log.record_finding(MISCITED, "LIKELY", "vol.netscan",
                           linked_call_id=silent, input_call_ids=[silent])
        assert not _citation_issues(_check(log, case))

    def test_identifiers_printed_by_no_tool_still_block(self, log, case):
        """An identifier that appears in no evidence output at all is the
        case the gate exists for; it is not excused by being nowhere."""
        wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                     stdout_excerpt="svc_update.exe 4412 running")
        log.record_finding(MISCITED, "LIKELY", "vol.netscan",
                           linked_call_id=wrong, input_call_ids=[wrong])
        assert _citation_issues(_check(log, case))
