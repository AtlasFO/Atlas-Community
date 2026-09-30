import json

from core.brain import stats
from tests.brain.conftest import make_note


def test_snapshot_counts_and_writes(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool", tags="volatility")
    make_note(brain, "logs/decisions/d1.md", "Use staged capture", type="decision", tags="memory")
    make_note(brain, "inbox/memory-candidates/c1.md", "Cand", type="memory_candidate")
    (brain / "memory/open-loops.md").write_text(
        "---\ntitle: Open Loops\ntype: note\n---\n- [ ] one\n- [x] two\n- [ ] three\n")
    data, path = stats.snapshot()
    assert data["totals"]["knowledge_objects"] >= 3
    assert data["totals"]["decisions"] == 1
    assert data["totals"]["open_loops"] == 2
    assert data["totals"]["closed_loops"] == 1
    assert data["totals"]["candidates_pending"] == 1
    assert ["volatility", 1] in [list(t) for t in
                                 json.loads(json.dumps(data["top_tags"]))]
    saved = json.loads((brain / "analytics/snapshots").glob("*-brain-snapshot.json").__next__().read_text())
    assert saved["date"] == data["date"]
    assert str(path).endswith("-brain-snapshot.json")


def test_accuracy_rollup_from_run_summaries(brain):
    run = make_note(brain, "logs/runs/r1.md", "run", type="run",
                    cases="nitroba", tags="agent-run")
    text = run.read_text().replace(
        'confidence: "medium"',
        'confidence: "medium"\naccuracy: {precision: 0.9, recall: 0.8, f1: 0.85}')
    run.write_text(text)
    data, _ = stats.snapshot()
    assert data["accuracy"]["nitroba"]["f1"] == 0.85


def test_confidential_counted_not_detailed(brain):
    make_note(brain, "wiki/tools/c.md", "Hush", type="tool",
              classification="confidential")
    data, path = stats.snapshot()
    assert data["security"]["confidential_skipped"] == 1
    snapshot_text = (brain / "analytics/snapshots").glob("*.json").__next__().read_text()
    assert "Hush" not in snapshot_text
