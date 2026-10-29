"""A CONFIRMED finding a deterministic check refuses
costs no evaluator call. Invented fixtures only (CORP-WS01, 203.0.113.x,
svc_kit.exe)."""
from __future__ import annotations

from unittest.mock import patch


def _log(tmp_path):
    from core.execution_log import ExecutionLog
    (tmp_path / "analysis").mkdir()
    log = ExecutionLog()
    log.configure("T", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    log._entries.clear()
    log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    cid = log.record_tool_call("<py>:table_grep", True, False, 0, 0, evidence_ref="exports/corp-ws01-net.csv",
                               stdout_excerpt="2031-03-10 14:02:00,svc_kit.exe,203.0.113.7:443")
    return log, cid


def test_a_citation_failure_spends_no_evaluation(tmp_path, monkeypatch):
    from tools import misc
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    asked = []
    monkeypatch.setattr(misc, "_auto_evaluate", lambda *a, **k: asked.append(a) or {"verdict": "SUPPORTED"})
    log, cid = _log(tmp_path)
    with patch("core.execution_log.log", log):
        misc.record_finding(description="svc_kit.exe connected to 203.0.113.99 at 2031-03-10 14:02:00.",
                            confidence="CONFIRMED", source="table.table_grep", linked_call_id=cid,
                            input_call_ids=[cid], supporting_evidence="svc_kit.exe at 2031-03-10 14:02:00",
                            host="CORP-WS01")
    assert asked == []


def test_the_evaluation_still_runs_when_it_is_the_only_objection(tmp_path, monkeypatch):
    from tools import misc
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    asked = []
    monkeypatch.setattr(misc, "_auto_evaluate", lambda *a, **k: asked.append(a) or {"verdict": "CHALLENGED"})
    log, cid = _log(tmp_path)
    with patch("core.execution_log.log", log):
        misc.record_finding(description="svc_kit.exe connected to 203.0.113.7 at 2031-03-10 14:02:00.",
                            confidence="CONFIRMED", source="table.table_grep", linked_call_id=cid,
                            input_call_ids=[cid],
                            supporting_evidence="2031-03-10 14:02:00,svc_kit.exe,203.0.113.7:443",
                            host="CORP-WS01")
    assert len(asked) == 1
