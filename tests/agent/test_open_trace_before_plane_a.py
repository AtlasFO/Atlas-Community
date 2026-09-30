"""The trace is opened before Plane A at the path the analyst is told to
use, so the pre-run auto-mount can record its tool calls; the analyst's
own start_execution_log then resumes the same file."""
import json

from agent.cli import _open_trace_before_plane_a
from core.execution_log import log


def _case(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("| **Case ID** | TRACE-1 |\n")
    return case


def test_trace_opened_at_the_prescribed_path(tmp_path):
    case = _case(tmp_path)
    path = _open_trace_before_plane_a(case, save_session=False)
    assert path == str(case / "analysis" / "TRACE-1_trace.json")
    assert log._case_id == "TRACE-1"
    log.record_system_error("plane_a_probe", "recorded before the analyst starts")
    assert json.load(open(path))["case_id"] == "TRACE-1"


def test_analyst_start_resumes_the_same_trace(tmp_path):
    case = _case(tmp_path)
    path = _open_trace_before_plane_a(case, save_session=False)
    log.record_system_error("plane_a_probe", "one entry from Plane A")
    recovered = log.configure("TRACE-1", path, save_session=False)
    assert recovered >= 1


def test_unopenable_trace_does_not_abort_the_run(tmp_path, capsys):
    case = _case(tmp_path)
    (case / "analysis").write_text("a file where the directory should be")
    assert _open_trace_before_plane_a(case, save_session=False) is None
    assert "could not open the trace before Plane A" in capsys.readouterr().err
