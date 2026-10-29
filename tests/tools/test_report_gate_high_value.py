"""The report gate holds the report while the case lists high-value
artifacts that nobody read, tried to read or explained, and it can never
deadlock on them: a read, a failed read or a recorded reason settles each,
and a run that does none of these is wrapped up by the report-phase ladder,
whose wrap-up relaxes the issue like any content blocker. The report lists
every artifact it did not read with what stands for it."""
from __future__ import annotations

import json
import os
import re
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

LOGS = ".\\Windows\\System32\\winevt\\Logs"
PLACEHOLDER = "the collection holds a zero-filled placeholder for this channel"


pytestmark = pytest.mark.usefixtures("todays_report_check")


@pytest.fixture
def case(tmp_path):
    from core.coverage_ledger import save_ledger
    (tmp_path / ".atlas").mkdir()
    (tmp_path / "analysis").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps({
        "schema_version": "1.0", "entries": [{"label": "CORP-WS01"}, {"label": "CORP-WS02"}]}),
        encoding="utf-8")
    rows = ["_host,ParentPath,FileName,FileSize"]
    for host in ("CORP-WS01", "CORP-WS02"):
        rows += [f"{host},{LOGS},Security.evtx,20971520", f"{host},{LOGS},System.evtx,5242880"]
    (tmp_path / "analysis" / "listing.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    # The listing was read: the coverage floor is not what these tests are about.
    save_ledger(tmp_path, {"units": {"analysis/listing.csv": {
        "path": "analysis/listing.csv", "kind": "file", "status": "probed"}}})
    return tmp_path


@pytest.fixture
def log(case):
    l = ExecutionLog()
    l.configure("GATE", str(case / "analysis" / "GATE_trace.json"), save_session=False)
    l.record_tool_call("vol.psscan", True, False, 0, 0)
    l.record_tool_call("coverage.coverage_report", True, False, 0, 0)
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_hypothesize", True, "hyp", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    return l


def _in_case(log, case):
    return patch("core.execution_log.log", log), patch.object(log, "case_dir", return_value=str(case))


def _check(log, case):
    from tools.reasoning import _pre_report_check
    a, b = _in_case(log, case)
    with a, b:
        return _pre_report_check(apply_remedies=True)


def _hv(verdict):
    return [i for i in verdict["blocking_issues"] if i.startswith("High-value artifacts")]


def _read(log, cmd):
    return log.record_tool_call(cmd, True, False, 0, 0)


def _explain(log, text):
    log.record_reason_call("reason_synthesize", True, "BLOCKERS: None", {},
                           inputs={"user_message": f"FINDINGS:\n{text}"})


class TestTheHighValueBlocker:
    def test_unread_artifacts_are_one_issue_naming_them_and_the_ways_out(self, log, case):
        v = _check(log, case)
        assert v["blocking_issues"] == _hv(v) and len(_hv(v)) == 1
        issue = _hv(v)[0]
        assert ("Security.evtx at Windows/System32/winevt/Logs/Security.evtx on CORP-WS01, "
                "CORP-WS02") in issue
        assert "System.evtx at Windows/System32/winevt/Logs/System.evtx" in issue
        assert "'UNRESOLVABLE: <artifact> [<host>] — <why it is not read>'" in issue

    def test_a_read_a_failed_read_and_a_reason_settle_them(self, log, case):
        _read(log, "EvtxECmd -f exports/CORP-WS01/Security.evtx --csv analysis/ws01")
        _read(log, "EvtxECmd -f exports/CORP-WS02/Security.evtx --csv analysis/ws02")
        log.record_tool_call("EvtxECmd -f exports/CORP-WS01/System.evtx", False, False, 0, 1,
                             stderr="Invalid EVTX header signature")
        _explain(log, f"UNRESOLVABLE: System.evtx on CORP-WS02 — {PLACEHOLDER}")
        v = _check(log, case)
        assert v["ready_to_report"] and not _hv(v)
        assert any(d.startswith("2 high-value artifact(s) not opened, each with a recorded reason "
                                "or a failed read") for d in v["documented_limitations"])

    def test_work_between_checks_keeps_it(self, log, case):
        for n in range(6):
            assert _hv(_check(log, case)), n
            _read(log, f"strings_grep pattern=logon{n} file_path=analysis/notes.txt")

    def test_explaining_one_artifact_per_check_keeps_it_for_the_rest(self, log, case):
        for what in ("System.evtx on CORP-WS01", "System.evtx on CORP-WS02", "Security.evtx on CORP-WS01"):
            assert _hv(_check(log, case))
            _explain(log, f"UNRESOLVABLE: {what} — {PLACEHOLDER}")
        issue = _hv(_check(log, case))
        assert issue and "explained (1): Security.evtx" in issue[0] and "CORP-WS02" in issue[0]

    def test_a_reason_too_short_is_named_in_the_issue(self, log, case):
        _explain(log, "UNRESOLVABLE: System.evtx — not needed")
        issue = _hv(_check(log, case))[0]
        assert "give no reason of 40 characters or more" in issue and "System.evtx — not needed" in issue

    def test_asking_again_and_again_keeps_it(self, log, case):
        for n in range(6):
            assert _hv(_check(log, case)), n

    def test_the_check_records_its_counts_and_its_process(self, log, case):
        _read(log, "EvtxECmd -f exports/CORP-WS01/Security.evtx --csv analysis/ws01")
        _check(log, case)
        e = [x for x in log._entries if x.get("tool") == "reason_pre_report_check"][-1]
        assert (e["pid"], e["hv_settled"]) == (os.getpid(), 1)

    def test_the_report_phase_wrap_up_relaxes_it(self, log, case):
        log.record_budget_wrapup("report_stall", 40, allow_synthesize_escape=True)
        v = _check(log, case)
        assert v["ready_to_report"] and not _hv(v)
        assert any(d.startswith("High-value artifacts the case lists") for d in v["documented_limitations"])

    def test_an_accepted_limitations_note_lifts_it(self, log, case):
        (case / "analysis" / "REPORT_LIMITATIONS_ACCEPTED.md").write_text(
            "The analyst accepts that the remaining event logs are not parsed.", encoding="utf-8")
        assert not _hv(_check(log, case))

    def test_the_report_lists_what_was_not_read_and_why(self, log, case):
        from core.report_assemble import assemble_client_report
        log.record_tool_call("EvtxECmd -f exports/CORP-WS01/System.evtx", False, False, 0, 1,
                             stderr="Invalid EVTX header signature")
        _explain(log, f"UNRESOLVABLE: Security.evtx — {PLACEHOLDER}")
        a, b = _in_case(log, case)
        with a, b:
            report = assemble_client_report(case)
        gaps = re.search(r"\n## [^\n]*Evidence Gaps[^\n]*\n(.*?)(?=\n## |\Z)", report, re.DOTALL).group(1)
        assert (f"- Not opened: `Security.evtx` at `Windows/System32/winevt/Logs/Security.evtx` on "
                f"CORP-WS01, CORP-WS02: {PLACEHOLDER}") in gaps
        assert "on CORP-WS01: the read failed (call " in gaps and "Invalid EVTX header signature" in gaps
        assert "on CORP-WS02: no read was attempted and no reason was recorded." in gaps

    def test_a_to_do_list_in_the_synthesis_is_no_reason(self, log, case):
        log.record_reason_call(
            "reason_synthesize", True,
            "UNRESOLVABLE: none - every blocker is actionable: System.evtx on CORP-WS01 and "
            "CORP-WS02 must still be parsed with EvtxECmd\nBLOCKERS: None", {})
        issue = _hv(_check(log, case))
        assert issue and "explained (4)" in issue[0]

    def test_a_reason_that_names_no_listed_artifact_is_said_back(self, log, case):
        _explain(log, "UNRESOLVABLE: the second workstation's logs — the collection of that host "
                      "failed and holds none of its logs")
        issue = _hv(_check(log, case))[0]
        assert "name no artifact the case lists" in issue
        assert "the second workstation's logs" in issue


class TestNeverADeadlock:
    def test_a_run_that_never_opens_or_explains_anything_reaches_its_report(self, log, case):
        """The run only asks the gate, turn after turn. The report-phase
        ladder sees no progress, pushes, wraps up; the wrap-up relaxes the
        issue to a documented limitation, the gate lets the report through,
        and the report and the exit say what was left unread and that no
        reason was recorded."""
        from types import SimpleNamespace

        import agent.loop as lp
        from core.artifact_value import gap_lines
        from core.investigation_obligations import obligations_met_for_complete
        agent = lp.Agent.__new__(lp.Agent)
        agent.case_dir, agent.messages, agent._run_since = case, [], 0
        agent.ui = SimpleNamespace(warn=lambda *a, **k: None)
        agent._nudge = agent._log = lambda *a, **k: None
        agent._note_dair_phase(json.dumps({"current_phase": "Report"}))
        a, b = _in_case(log, case)
        with a, b:
            for turn in range(1, 1000):
                verdict = _check(log, case)
                if verdict["ready_to_report"]:
                    break
                if agent._report_phase_stalled(turn):
                    agent._push_report_phase(turn, reason="report gate blocked")
            assert verdict["ready_to_report"] and not _hv(verdict)
            # pushed REPORT_STALL_WRAPUP_FIRES times, REPORT_STALL_TURNS apart
            assert turn == lp.REPORT_STALL_WRAPUP_FIRES * lp.REPORT_STALL_TURNS + 2
            assert [e["trigger"] for e in log._entries if e.get("type") == "budget_wrapup"] == ["report_stall"]
            assert any(d.startswith("High-value artifacts the case lists")
                       for d in verdict["documented_limitations"])
            assert not obligations_met_for_complete(case)
            assert sum("no read was attempted and no reason was recorded" in line
                       for line in gap_lines(case)) == 2
