import datetime as dt
import json

from core.brain import report
from tests.brain.conftest import make_note


def test_report_without_prior_snapshot(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool", tags="volatility")
    text = report.generate(period="week")
    assert "Brain Report" in text
    assert "No prior snapshot" in text
    assert "## Accuracy Trend" in text


def test_report_diffs_against_prior_snapshot(brain):
    old_date = (dt.date.today() - dt.timedelta(days=10)).isoformat()
    prior = {"date": old_date,
             "totals": {"knowledge_objects": 1, "decisions": 0,
                        "research": 0, "run_summaries": 0, "open_loops": 0,
                        "candidates_pending": 0}}
    (brain / "analytics/snapshots" / f"{old_date}-brain-snapshot.json").write_text(
        json.dumps(prior))
    make_note(brain, "wiki/tools/a.md", "A", type="tool", tags="x")
    make_note(brain, "wiki/tools/b.md", "B", type="tool", tags="x")
    text = report.generate(period="week")
    assert "(+1)" in text  # 2 now vs 1 before


def test_recurring_recommendations_surface(brain):
    for i, name in enumerate(("a.md", "b.md")):
        (brain / "inbox/memory-candidates" / name).write_text(
            "---\ntitle: x\ntype: memory_candidate\n---\n"
            "## Proposed Entry\n\nRun coverage report before the Report phase.\n")
    text = report.generate(period="week")
    assert "(2×) run coverage report" in text.lower()


def test_report_cli_writes_file(brain, capsys):
    assert report.main(["--period", "week"]) == 0
    out = list((brain / "analytics/reports").glob("*-weekly-brain-report.md"))
    assert len(out) == 1
