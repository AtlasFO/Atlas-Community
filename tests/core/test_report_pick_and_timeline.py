"""`atlas report` and the Report view pick the same file, the case's report,
never a review or note written after it; `atlas timeline --from-master` reads
the Timeline Builder's file where it writes it, by its header, and streams it."""
from __future__ import annotations

import os
import time
import tracemalloc
from pathlib import Path

import pytest

TSV_HEADER = "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\tLine\tRecordRef\n"


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "reports").mkdir()
    (case / "CASE.md").write_text("**Case ID:** CASE-A\n", encoding="utf-8")
    return case


def _write(path: Path, text: str, age: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    t = time.time() - age
    os.utime(path, (t, t))
    return path


# ── the case's report ────────────────────────────────────────────────────────

def test_atlas_report_renders_the_report_not_a_review_written_after_it(tmp_path, capsys):
    from agent import cli
    case = _case(tmp_path)
    _write(case / "reports" / "CASE-A_investigation_report.md", "# the report\n", 300)
    _write(case / "reports" / "CASE-A_run_review.md", "# the review\n", 200)
    _write(case / "reports" / "CASE-A_live_review.md", "# live review\n", 100)
    _write(case / "reports" / "analyst_notes.md", "# notes\n", 50)
    _write(case / "reports" / "host_CORP-WS01_report.md", "# one host\n", 10)
    cli.main(["report", "--case", str(case), "--format", "md"])
    assert capsys.readouterr().out == "# the report\n"


def test_an_official_report_name_is_the_report(tmp_path):
    from core.report_snapshots import default_report
    case = _case(tmp_path)
    _write(case / "reports" / "report.md", "# official\n", 300)
    _write(case / "reports" / "analyst_notes.md", "# notes\n", 10)
    assert default_report(case).name == "report.md"


def test_a_report_held_only_by_the_latest_snapshot(tmp_path):
    from core.report_snapshots import default_report
    case = _case(tmp_path)
    _write(case / "reports" / "rerun_0001" / "CASE-A_investigation_report.md", "# snap\n", 100)
    (case / "reports" / "latest").symlink_to("rerun_0001")
    _write(case / "reports" / "diff_report.md", "# changes\n", 10)
    assert default_report(case) == case / "reports" / "rerun_0001" / "CASE-A_investigation_report.md"


def test_a_case_from_before_reports_falls_back_to_analysis(tmp_path, capsys):
    from agent import cli
    case = _case(tmp_path)
    _write(case / "analysis" / "CASE-A_report.md", "# legacy\n", 100)
    _write(case / "analysis" / "scratch_notes.md", "# notes\n", 10)
    cli.main(["report", "--case", str(case), "--format", "md"])
    assert capsys.readouterr().out == "# legacy\n"


def test_the_report_view_and_atlas_report_pick_the_same_file(tmp_path):
    from core.report_snapshots import default_report
    from dashboard import read_models
    case = _case(tmp_path)
    _write(case / "reports" / "estate_report.md", "# estate\n", 300)
    _write(case / "reports" / "CASE-A_run_review.md", "# review\n", 10)
    status = read_models.report_status(str(case))
    assert status["name"] == default_report(case).name == "estate_report.md"


# ── the master timeline ──────────────────────────────────────────────────────

def _row(i: int) -> str:
    return (f"2031-03-01T04:{i // 60 % 60:02d}:{i % 60:02d}Z\tCORP-WS01\tjane.doe\tLogon\tSecurity\t"
            f"Logon {i} from 10.0.0.15\t{i}\tcall-{i}\n")


def test_the_builders_file_is_read_by_its_header(tmp_path):
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    _write(case / "reports" / "master_timeline.tsv", TSV_HEADER + _row(1) + _row(2), 0)
    r = build_timeline(case, source="master")
    assert r["success"] and r["count"] == 2 and r["shown"] == 2
    e = r["events"][0]
    assert e["ts"] == "2031-03-01T04:00:01Z" and e["summary"] == "Logon 1 from 10.0.0.15"
    assert e["host"] == "CORP-WS01" and e["user"] == "jane.doe"
    assert "call-1" not in str(r["events"])


def test_the_file_in_the_latest_snapshot_and_the_legacy_place_are_found(tmp_path):
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    _write(case / "reports" / "rerun_0001" / "master_timeline.tsv", TSV_HEADER + _row(3), 0)
    (case / "reports" / "latest").symlink_to("rerun_0001")
    assert build_timeline(case, source="master")["events"][0]["summary"] == "Logon 3 from 10.0.0.15"
    other = _case(tmp_path / "b")
    _write(other / "analysis" / "master_timeline.tsv",
           "datetime\tmessage\n2031-03-02T01:00:00Z\tservice installed\n", 0)
    assert build_timeline(other, source="master")["events"][0]["summary"] == "service installed"


def test_a_header_only_file_and_a_headerless_file(tmp_path):
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    _write(case / "reports" / "master_timeline.tsv", TSV_HEADER, 0)
    r = build_timeline(case, source="master")
    assert r["success"] and r["count"] == 0 and r["events"] == []
    _write(case / "reports" / "master_timeline.tsv",
           "2031-03-02T01:00:00Z\tCORP-WS01\tservice installed\n", 0)
    r = build_timeline(case, source="master")
    assert r["events"][0]["ts"] == "2031-03-02T01:00:00Z"
    assert r["events"][0]["summary"] == "service installed"


def test_a_large_file_is_streamed_and_says_how_much_it_shows(tmp_path, capsys):
    from agent import cli
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    path = case / "reports" / "master_timeline.tsv"
    with path.open("w", encoding="utf-8") as fh:
        fh.write(TSV_HEADER)
        for i in range(200_000):
            fh.write(_row(i))
    tracemalloc.start()
    r = build_timeline(case, source="master", limit=200)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r["count"] == 200_000 and r["shown"] == 200 and len(r["events"]) == 200
    assert peak < 8 * 1024 * 1024
    cli.main(["timeline", "--case", str(case), "--from-master"])
    assert "showing 200 of 200000" in capsys.readouterr().out


def test_limit_zero_reads_every_row(tmp_path):
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    _write(case / "reports" / "master_timeline.tsv", TSV_HEADER + "".join(_row(i) for i in range(300)), 0)
    r = build_timeline(case, source="master", limit=None)
    assert r["count"] == r["shown"] == 300


def test_no_master_timeline_names_where_it_was_looked_for(tmp_path):
    from core.investigation_cli import build_timeline
    r = build_timeline(_case(tmp_path), source="master")
    assert r["success"] is False and "reports" in r["error"] and "Timeline Builder" in r["error"]


def test_the_cli_reads_every_row_with_limit_zero(tmp_path, capsys):
    import json
    from agent import cli
    case = _case(tmp_path)
    _write(case / "reports" / "master_timeline.tsv", TSV_HEADER + "".join(_row(i) for i in range(300)), 0)
    cli.main(["timeline", "--case", str(case), "--from-master", "--limit", "0", "--json"])
    r = json.loads(capsys.readouterr().out)
    assert r["count"] == 300 and r["shown"] == 300


def test_quotes_in_a_row_are_text(tmp_path):
    """The builder writes tab-joined lines with no quoting; a Windows command
    line starts with a quote. Every line stays one row, its quotes kept."""
    from core.investigation_cli import build_timeline
    case = _case(tmp_path)
    rows = [
        '2031-03-01T04:00:01Z\tCORP-WS01\tjane.doe\tProcess\tSysmon\t"C:\\Windows\\System32\\cmd.exe" /c whoami\t1\tc-1\n',
        '2031-03-01T04:00:02Z\tCORP-WS01\tjane.doe\tProcess\tSysmon\t"unterminated argument\t2\tc-2\n',
        _row(3), _row(4), _row(5),
    ]
    _write(case / "reports" / "master_timeline.tsv", TSV_HEADER + "".join(rows), 0)
    r = build_timeline(case, source="master", limit=None)
    assert r["count"] == 5 and r["shown"] == 5
    assert r["events"][0]["summary"] == '"C:\\Windows\\System32\\cmd.exe" /c whoami'
    assert r["events"][1]["summary"] == '"unterminated argument'
    assert [e["summary"] for e in r["events"][2:]] == [f"Logon {i} from 10.0.0.15" for i in (3, 4, 5)]
