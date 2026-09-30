"""Stats accounting in agent/loop.py.

findings_recorded must reflect the execution trace, not record_finding call
counts — gate refusals and duplicate short-circuits return cleanly without
appending a finding entry, so the call count overstates the findings.
"""
from unittest.mock import patch

from agent.loop import Agent


def _bare_agent(tool_stats):
    a = object.__new__(Agent)
    a._tool_stats = tool_stats
    return a


def test_counts_trace_findings_not_calls(tmp_path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("LOOP-001", str(tmp_path / "trace.json"))
    l.record_finding("toolx.exe dropped", "CONFIRMED", "ez.mftecmd")
    l.record_finding("Beacon to 198.51.100.2", "LIKELY", "vol.netscan")
    # Four non-error record_finding calls, but only two trace entries —
    # two were refused/duplicates.
    stats = [{"name": "misc_misc_record_finding", "seconds": 0.1, "error": False}
             for _ in range(4)]
    a = _bare_agent(stats)
    with patch("core.execution_log.log", l):
        assert a._count_recorded_findings() == 2


def test_falls_back_to_call_count_without_log():
    stats = [
        {"name": "misc_misc_record_finding", "seconds": 0.1, "error": False},
        {"name": "misc_misc_record_finding", "seconds": 0.1, "error": True},
        {"name": "vol_vol_pslist", "seconds": 0.1, "error": False},
    ]
    a = _bare_agent(stats)
    # Simulate an unavailable log by making the import raise.
    import sys
    with patch.dict(sys.modules, {"core.execution_log": None}):
        assert a._count_recorded_findings() == 1
