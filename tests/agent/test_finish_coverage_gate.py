"""atlas_finish coverage deferral + turn-budget semantics.

A run can end organically (atlas_finish) with most ledger units unseen and
every task open. There is deliberately NO
hard turn cap (ATLAS_AGENT_MAX_TURNS defaults to 0 = unlimited; turn 150 is a
one-shot advisory that explicitly says "continuing"). The corrective control
is a one-shot finish deferral that surfaces the concrete open units — never
a hard stop.
"""
from __future__ import annotations

from pathlib import Path


def _case_with_open_ledger(tmp_path: Path) -> Path:
    from core.coverage_ledger import build_coverage_ledger
    case = tmp_path / "case"
    evid = case / "evidence"
    evid.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "analysis").mkdir()
    (evid / "vpn_auth.csv").write_text("a,b\n1,2\n")
    (evid / "edr_events.csv").write_text("a,b\n1,2\n")
    build_coverage_ledger(case)
    return case


def _bare_agent(case_dir: str):
    from agent.loop import Agent
    a = Agent.__new__(Agent)
    a.case_dir = case_dir
    return a


class TestFinishCoverageCheck:
    def test_first_finish_deferred_with_gaps(self, tmp_path):
        case = _case_with_open_ledger(tmp_path)
        a = _bare_agent(str(case))
        msg = a._finish_coverage_check(wall_expired=False)
        assert "deferred" in msg
        assert "NOT a hard stop" in msg
        assert "vpn_auth.csv" in msg

    def test_second_finish_always_passes(self, tmp_path):
        """The deferral is one-shot — it can never deadlock the run."""
        case = _case_with_open_ledger(tmp_path)
        a = _bare_agent(str(case))
        assert a._finish_coverage_check(wall_expired=False) != ""
        assert a._finish_coverage_check(wall_expired=False) == ""

    def test_wall_clock_bypasses(self, tmp_path):
        case = _case_with_open_ledger(tmp_path)
        a = _bare_agent(str(case))
        assert a._finish_coverage_check(wall_expired=True) == ""

    def test_ledger_ready_passes_immediately(self, tmp_path):
        from core.coverage_ledger import load_ledger, mark_paths
        case = _case_with_open_ledger(tmp_path)
        led = load_ledger(case)
        mark_paths(case, [u["path"] for u in led["units"].values()],
                   status="probed")
        a = _bare_agent(str(case))
        assert a._finish_coverage_check(wall_expired=False) == ""

    def test_no_case_dir_passes(self):
        a = _bare_agent("")
        assert a._finish_coverage_check(wall_expired=False) == ""


class TestNoHardTurnCap:
    def test_default_turn_budget_is_unlimited(self, monkeypatch):
        """A run may take 1000+ turns; only an explicit env opt-in caps it."""
        from core.run_budget import hard_turn_cap_enabled, initial_turn_limit
        assert hard_turn_cap_enabled(0) is False
        assert initial_turn_limit(0) >= 1000
        assert hard_turn_cap_enabled(150) is True  # lab/CI opt-in only

    def test_turn_advisory_message_is_not_a_stop(self):
        from core.run_budget import _TURN_ADVISORY_MSG
        assert "no hard turn abort" in _TURN_ADVISORY_MSG
