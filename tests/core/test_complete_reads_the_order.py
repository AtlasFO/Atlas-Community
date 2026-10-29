"""Under the work order `complete` is the order's (no due
read, no actionable question, beliefs, report, synthesis, ready); the
obligation list, the ledger floor and the unseen units are disclosed beside
the label. Invented state only; the readers are stubbed."""
from __future__ import annotations

import pytest

import core.execution_log as elog
from core import investigation_exit as X


@pytest.fixture
def state(tmp_path, monkeypatch):
    (tmp_path / "analysis").mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    st = {"actionable": 0, "unseen": 4, "floor": False, "obligations": False}
    monkeypatch.setattr("core.investigation_state.build_current_investigation_state",
                        lambda _c: {"has_beliefs": True, "counts": {"investigation_tasks_actionable": st["actionable"]}})
    monkeypatch.setattr("core.coverage_ledger.ready_for_degraded_exit", lambda _c: st["floor"])
    monkeypatch.setattr("core.coverage_ledger.coverage_stats", lambda _l: {"unseen": st["unseen"]})
    monkeypatch.setattr("core.coverage_ledger.load_ledger", lambda _c: {})
    monkeypatch.setattr("core.investigation_obligations.obligations_met_for_complete", lambda _c: st["obligations"])
    monkeypatch.setattr("core.investigation_obligations.unmet_obligation_summaries",
                        lambda _c: [] if st["obligations"] else ["log_search: not searched"])
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    return tmp_path, st


def _label(case):
    return X.classify_finish_status("finished", case_dir=case, report_written=True, synthesize_ok=True,
                                    pre_report_ready=True)


def test_the_order_decides_and_the_floors_are_disclosed(state):
    case, st = state
    assert _label(case) == "complete"
    d = X.completion_disclosure(case)
    assert d == {"unseen_units": 4, "ledger_floor_met": False, "obligations_unmet": ["log_search: not searched"]}


def test_a_due_read_or_an_actionable_question_is_not_complete(state):
    case, st = state
    item = elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                                  {"path": "evidence/x.csv", "pattern": "y"}, "z")
    assert item["status"] == "due" and _label(case) == "incomplete_coverage"
    item["status"] = "resolved"
    st["actionable"] = 1
    assert _label(case) == "incomplete_coverage"


def test_off_the_order_the_floors_decide(state, monkeypatch):
    case, st = state
    monkeypatch.setenv("ATLAS_WORK_ORDER", "0")
    assert _label(case) == "incomplete_coverage"
    st.update(unseen=0, floor=True, obligations=True)
    assert _label(case) == "complete"
