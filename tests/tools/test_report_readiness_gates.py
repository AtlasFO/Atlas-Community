"""The unrecorded-indicator report gate demands rulings only while the
demand is bounded: a sparse population blocks until each member is named;
a population the evidence shows in bulk is mentioned and never blocks."""
from unittest.mock import patch

from core.ioc_pivots import UNRECORDED_DEMAND_CAP


def _log(tmp_path, texts):
    from core.execution_log import ExecutionLog
    inst = ExecutionLog()
    inst.configure("GATE", str(tmp_path / "trace.json"))
    inst.record_dair_call("Triage", "", False, "", "", "stay", "")
    inst.record_reason_call("reason_plan", True, "ok", {})
    inst.record_reason_call("reason_hypothesize", True, "ok", {})
    inst.record_reason_call("reason_synthesize", True, "ok", {})
    for t in texts:
        inst.record_tool_call("tshark -r capture", True, False, 0, 0,
                              stdout_excerpt=t)
    return inst


def _check(inst, tmp_path):
    from tools.reasoning import reason_pre_report_check
    with patch("core.execution_log.log", inst), \
         patch.object(inst, "case_dir", return_value=str(tmp_path)), \
         patch("core.coverage_ledger.ready_for_degraded_exit",
               return_value=True):
        return reason_pre_report_check()


def _indicator_issues(r):
    return [i for i in r["blocking_issues"] if "Indicators recur" in i]


def test_bulk_population_warns_but_never_blocks(tmp_path):
    urls = " ".join(f"http://site{i}.example.test/p"
                    for i in range(UNRECORDED_DEMAND_CAP + 1))
    r = _check(_log(tmp_path, [urls] * 4), tmp_path)
    assert not _indicator_issues(r), r["blocking_issues"]
    assert any("in bulk" in w for w in r["warnings"]), r["warnings"]


def test_sparse_population_blocks_until_each_is_named(tmp_path):
    inst = _log(tmp_path, ["http://c2.example.test/beacon from CORP\\jdoe"] * 4)
    issues = _indicator_issues(_check(inst, tmp_path))
    assert issues and "c2.example.test" in issues[0] and "jdoe" in issues[0]
    inst.record_finding(
        "Beaconing to http://c2.example.test/beacon by CORP\\jdoe", "LIKELY")
    assert not _indicator_issues(_check(inst, tmp_path))
