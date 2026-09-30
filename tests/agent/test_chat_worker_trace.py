"""A dashboard chat records its tool calls in the case's trace from the
first call on, and never moves the host-wide session beacon."""
import io
import sys
from types import SimpleNamespace
from unittest.mock import patch


def test_the_worker_opens_the_case_trace_without_the_beacon(tmp_path, monkeypatch):
    import core.execution_log as elog
    from agent import chat_worker, cli

    case = tmp_path / "CASE-A"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID:** CASE-E\n", encoding="utf-8")
    beacon = tmp_path / "session.json"
    monkeypatch.setattr(elog, "_SESSION_FILE", str(beacon))
    monkeypatch.delenv("ATLAS_SESSION_BEACON", raising=False)
    fake_agent = SimpleNamespace(interactive=True, messages=[], client=SimpleNamespace(model="m"),
                                 toolbox=SimpleNamespace(deny=None))
    with patch.object(cli, "_bootstrap_env", lambda *a, **k: None), \
         patch.object(cli, "_make_agent", lambda *a, **k: fake_agent), \
         patch("agent.prompts.build_system_prompt", lambda *a, **k: "system"), \
         patch.object(sys, "stdin", io.StringIO("")), \
         patch.object(sys, "stdout", io.StringIO()):
        assert chat_worker.main(["--case", str(case)]) == 0
    assert elog.log._path == str(case / "analysis" / "CASE-E_trace.json")
    assert (case / "analysis" / "CASE-E_trace.json").is_file()
    assert not beacon.exists()
    import os
    assert os.environ.get("ATLAS_SESSION_BEACON") == "0"
    monkeypatch.delenv("ATLAS_SESSION_BEACON", raising=False)
