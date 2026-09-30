"""The report gate notices a run withdrawing claims between two checks while
its blockers persist, and says what keeps the finding instead. Withdrawal
itself stays allowed and unremarked when nothing blocks."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import supersede
from core.execution_log import ExecutionLog


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def log(case):
    l = ExecutionLog()
    l.configure("SHED", str(case / "trace.json"), save_session=False)
    l.record_tool_call("vol.psscan", True, False, 0, 0)
    l.record_tool_call("coverage.coverage_report", True, False, 0, 0)
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_hypothesize", True, "hyp", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    return l


def _record(log, case, description, cite):
    from core.claim_graph import upsert_claim_from_finding
    cid = log.record_finding(description, "LIKELY", "vol.netscan",
                             linked_call_id=cite, input_call_ids=[cite])
    res = upsert_claim_from_finding(str(case), statement=description, confidence="LIKELY",
                                    source="vol.netscan", finding_call_id=cid,
                                    linked_call_id=cite, input_call_ids=[cite])
    for e in log._entries:
        if e.get("call_id") == cid:
            e["claim_id"] = res["claim_id"]
    return res["claim_id"]


def _check(log, case):
    from tools.reasoning import _pre_report_check
    with patch("core.execution_log.log", log), \
         patch.object(log, "case_dir", return_value=str(case)):
        return _pre_report_check()


def _shed_warnings(verdict):
    return [w for w in verdict["warnings"] if "withdrawn since the previous report check" in w]


def test_withdrawals_while_blockers_persist_are_named(log, case):
    wrong = log.record_tool_call("<py>:vol_pslist", True, False, 0, 0,
                                 stdout_excerpt="svc_update.exe 4412 running")
    log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                         stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443")
    keep = _record(log, case, "Beacon traffic to 203.0.113.9 over port 443 from the workstation", wrong)
    shed_a = _record(log, case, "Process svc_update.exe on the workstation reached 198.51.100.7", wrong)
    shed_b = _record(log, case, "Account backup_svc on the workstation logged on from 198.51.100.8", wrong)
    first = _check(log, case)
    assert first["ready_to_report"] is False and _shed_warnings(first) == []
    for cid in (shed_a, shed_b):
        supersede(str(case), cid, reason="withdrawn to chase the citation gate, nothing replaces it")
    second = _check(log, case)
    assert second["ready_to_report"] is False
    warn = _shed_warnings(second)
    assert len(warn) == 1
    assert shed_a in warn[0] and shed_b in warn[0] and keep not in warn[0]
    assert "citation repair" in warn[0]


def test_a_withdrawal_with_no_blockers_left_is_not_remarked(log, case):
    right = log.record_tool_call("<py>:vol_netscan", True, False, 0, 0,
                                 stdout_excerpt="svc_update.exe 4412 TCPv4 10.0.0.5:49812 203.0.113.9:443")
    _record(log, case, "Beacon traffic to 203.0.113.9 over port 443 from the workstation", right)
    gone = _record(log, case, "Process svc_update.exe on the workstation reached 203.0.113.9", right)
    first = _check(log, case)
    supersede(str(case), gone, reason="withdrawn as a duplicate of the beacon finding; nothing lost")
    second = _check(log, case)
    assert _shed_warnings(second) == [] or first["blocking_issues"]
