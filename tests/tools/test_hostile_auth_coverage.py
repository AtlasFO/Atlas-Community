"""Auth success coverage gaps (Claim Graph) via coverage_audit.hostile_auth_reconciliation.

Contested endpoints have both auth.failure and auth.success observations.
A contested success with no covering finding/claim is reported as a gap.
No hostile-vocab / case-IOC interest set.
"""
import pytest

from tools import coverage_audit as ca


@pytest.fixture
def clean_trace(tmp_path):
    from core.execution_log import log
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text("Investigate authentication activity.\n")
    saved = list(log._entries)
    log._entries.clear()
    log.configure(
        "AUTHCOV", str(case / "analysis" / "trace.json"),
        save_session=False,
    )
    yield log
    log._entries.clear()
    log._entries.extend(saved)


def _finding(call_id, description, confidence="LIKELY"):
    return {"type": "finding", "call_id": call_id,
            "description": description, "confidence": confidence}


def _tool_call(call_id, stdout, mcp_tool="search_search_evidence",
               success=True, stdout_file=""):
    e = {"type": "tool_call", "call_id": call_id, "mcp_tool": mcp_tool,
         "cmd": mcp_tool.replace("_", " ", 1), "success": success}
    if stdout:
        e["stdout_excerpt"] = stdout
    if stdout_file:
        e["stdout_file"] = stdout_file
    return e


def _success_4624(ip, date, logon_type=3, computer="SRV01"):
    return (
        f'{{"timestamp":"{date}T12:05:00Z","level":"AUDIT_SUCCESS",'
        f'"win":{{"system":{{"eventID":"4624","computer":"{computer}"}},'
        f'"eventdata":{{"logonType":"{logon_type}","ipAddress":"{ip}",'
        f'"targetUserName":"Administrator","authenticationPackageName":"NTLM"}}}}}}'
    )


def _failure_4625(ip, date):
    return (
        f'{{"timestamp":"{date}T12:00:00Z","level":"AUDIT_FAILURE",'
        f'"win":{{"system":{{"eventID":"4625"}},'
        f'"eventdata":{{"logonType":"3","ipAddress":"{ip}",'
        f'"targetUserName":"Administrator","subStatus":"0xC000006A"}}}}}}'
    )


# RFC 5737 TEST-NET-3 — documentation range only.
IP = "203.0.113.66"


def _mixed_auth(ip, date, logon_type=3):
    """Failure + success for the same endpoint (structural contested set)."""
    return _failure_4625(ip, date) + "\n" + _success_4624(ip, date, logon_type)


class TestAuthSuccessCoverageGaps:
    def test_success_with_coexisting_failure_is_flagged(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(2, _mixed_auth(IP, "2031-02-04", logon_type=3)),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["contested_endpoints"] == 1
        assert out["unreported_count"] == 1
        ev = out["unreported"][0]
        assert ev["ip"] == IP
        assert ev["date"] == "2031-02-04"
        assert ev["logon_type"] == "3"
        assert ev["call_id"] == 2

    def test_success_finding_same_date_suppresses(self, clean_trace):
        clean_trace._entries.extend([
            _finding(2, f"Successful RDP logon from {IP} on 2031-02-06 as "
                        "Administrator (interactive).", confidence="LIKELY"),
            _tool_call(3, _mixed_auth(IP, "2031-02-06", logon_type=10)),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0

    def test_success_finding_different_date_does_not_cover(self, clean_trace):
        clean_trace._entries.extend([
            _finding(2, f"Successful RDP logon from {IP} on 2031-02-06 as "
                        "Administrator.", confidence="LIKELY"),
            _tool_call(3, _mixed_auth(IP, "2031-02-04", logon_type=3) + "\n"
                       + _success_4624(IP, "2031-02-06", logon_type=10)),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 1
        assert out["unreported"][0]["date"] == "2031-02-04"

    def test_failure_only_is_not_flagged(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(2, "\n".join(_failure_4625(IP, "2031-02-06")
                                    for _ in range(5))),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["success_events_seen"] == 0
        assert out["unreported_count"] == 0

    def test_success_only_not_contested(self, clean_trace):
        """Success without coexisting failure is not a contested gap."""
        clean_trace._entries.extend([
            _tool_call(2, _success_4624(IP, "2031-02-04")),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0
        assert out.get("contested_endpoints", 0) == 0

    def test_other_endpoint_success_not_flagged(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(2, _failure_4625(IP, "2031-02-04") + "\n"
                       + _success_4624("10.0.0.5", "2031-02-04")),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0

    def test_no_auth_events_is_calm(self, clean_trace):
        clean_trace._entries.append(
            _finding(1, "Normal admin logon from 10.0.0.5.", confidence="LIKELY"))
        out = ca.hostile_auth_reconciliation()
        assert out["contested_endpoints"] == 0
        assert out["unreported"] == []
        assert "no contested" in out["note"]

    def test_success_read_from_spill_file(self, clean_trace, tmp_path):
        spill = tmp_path / "evtx_dump.json"
        spill.write_text(
            ("padding line\n" * 50)
            + _failure_4625(IP, "2031-02-04") + "\n"
            + _success_4624(IP, "2031-02-04"),
            encoding="utf-8")
        clean_trace._entries.extend([
            _tool_call(2, "truncated excerpt with no auth line",
                       stdout_file=str(spill)),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 1
        assert out["unreported"][0]["date"] == "2031-02-04"

    def test_nearer_failure_wins_in_mashed_window(self, clean_trace):
        line = (f'{{"eventID":"4625","ipAddress":"{IP}","subStatus":'
                f'"0xC000006A"}} ... (200 chars) ...'
                + "x" * 200
                + '{"eventID":"4624","level":"AUDIT_SUCCESS",'
                  '"ipAddress":"198.51.100.9"}')
        clean_trace._entries.extend([
            _tool_call(2, line),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0

    def test_bare_eid_without_auth_context_not_flagged(self, clean_trace):
        dns = (f"12:10:00.000 IP {IP}.49743 > 10.0.0.1.53: 4624+ [1au] "
               "A? win8.ipv6.microsoft.com. (52)")
        clean_trace._entries.extend([
            _tool_call(2, _failure_4625(IP, "2031-02-04") + "\n" + dns,
                       mcp_tool="net_tcpdump_extract_dns"),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0

    def test_bare_eid_with_auth_context_is_flagged(self, clean_trace):
        line = (
            _failure_4625(IP, "2031-02-05") + "\n"
            + f"2031-02-05 12:00:00 EID=4624 svc.backup01 ip={IP} type=3 "
              "logon success"
        )
        clean_trace._entries.extend([
            _tool_call(2, line, mcp_tool="table_table_query"),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 1
        assert out["unreported"][0]["date"] == "2031-02-05"

    def test_plumbing_output_not_scanned(self, clean_trace):
        clean_trace._entries.extend([
            _tool_call(2, _mixed_auth(IP, "2031-02-04"),
                       mcp_tool="reason_reason_synthesize"),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 0

    def test_contradicted_negative_still_flags(self, clean_trace):
        clean_trace._entries.extend([
            _finding(1, f"Failed logons from {IP} on 2031-02-04; no successful "
                        "logon was observed.", confidence="SUSPECTED"),
            _tool_call(2, _mixed_auth(IP, "2031-02-04")),
        ])
        out = ca.hostile_auth_reconciliation()
        assert out["unreported_count"] == 1


class TestFramingHelper:
    def test_positive_success_framing(self):
        assert ca._positively_frames_success(
            "Administrator successfully authenticated from the host")

    def test_negated_success_not_framed(self):
        assert not ca._positively_frames_success(
            "no successful logon was observed for this account")
        assert not ca._positively_frames_success(
            "the attacker failed to gain access")

    def test_unsuccessful_word_not_matched(self):
        assert not ca._positively_frames_success(
            "all attempts were unsuccessful")


class TestPreReportIntegration:
    def test_pre_report_check_surfaces_warning(self, clean_trace):
        from tools import reasoning
        clean_trace._entries.extend([
            {"type": "reason_call", "call_id": 1, "tool": "reason_plan"},
            {"type": "reason_call", "call_id": 2, "tool": "reason_hypothesize"},
            {"type": "reason_call", "call_id": 3, "tool": "reason_synthesize",
             "conclusion": "BLOCKERS: none"},
            _tool_call(5, _mixed_auth(IP, "2031-02-04", logon_type=3)),
        ])
        out = reasoning.reason_pre_report_check()
        hits = [w for w in out["warnings"]
                if "unreported_auth_success" in w]
        assert len(hits) == 1
        assert IP in hits[0]
        assert "unreported_auth_success" not in " ".join(
            out["blocking_issues"])


class TestTheRunsOwnStateIsNotAnAuthSource:
    def test_a_claim_snapshot_yields_no_auth_events(self):
        """The snapshot restates claims that mention logons; an observation
        made from it would cite the analyst's own words as the record."""
        from core.auth_observations import evidence_texts_from_trace
        text = ("statement: 4 successful RDP logons (EID 4624 LogonType 10) "
                "from 198.51.100.7 to the domain controller")
        own = {"type": "tool_call", "call_id": 5, "success": True,
               "cmd": "<py>:claim_snapshot", "mcp_tool": "claim_snapshot",
               "stdout_excerpt": text}
        evidence = {"type": "tool_call", "call_id": 6, "success": True,
                    "cmd": "<py>:ez_evtxecmd", "mcp_tool": "ez_evtxecmd",
                    "stdout_excerpt": text}
        assert [cid for cid, _, _ in evidence_texts_from_trace([own, evidence])] == [6]
