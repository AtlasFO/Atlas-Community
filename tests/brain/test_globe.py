import json

from core.brain import globe
from tests.brain.conftest import make_note


def _seed(brain):
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool",
              tags="memory", related='"[[timeline]]"', updated="2031-02-04")
    make_note(brain, "wiki/concepts/timeline.md", "Timeline", type="concept",
              tags="memory", updated="2026-01-01")
    make_note(brain, "wiki/cases/nitroba.md", "Nitroba", type="case",
              cases="nitroba", tags="network")
    make_note(brain, "wiki/tools/zeek.md", "Zeek", type="tool",
              cases="nitroba", tags="network")


def test_build_nodes_edges_clusters(brain):
    _seed(brain)
    data = globe.build()
    assert data["summary"]["nodes"] == 4
    ids = {n["id"] for n in data["nodes"]}
    assert {"vol", "timeline", "nitroba", "zeek"} <= ids
    edge_types = {e["type"] for e in data["edges"]}
    assert "related" in edge_types          # vol -> timeline
    assert "shared_tag" in edge_types or "shared_entity" in edge_types
    clusters = {n["cluster"] for n in data["nodes"]}
    assert {"tools", "concepts", "cases"} <= clusters
    # case/concept hubs are bigger than plain notes with equal degree
    vol = next(n for n in data["nodes"] if n["id"] == "vol")
    nitroba = next(n for n in data["nodes"] if n["id"] == "nitroba")
    assert nitroba["size"] >= vol["size"] - 2


def test_confidential_excluded(brain):
    _seed(brain)
    make_note(brain, "wiki/actors/secret.md", "Hidden actor", type="actor",
              classification="confidential")
    data = globe.build()
    assert "secret" not in {n["id"] for n in data["nodes"]}
    assert data["summary"]["confidential_skipped"] == 1
    assert "Hidden actor" not in json.dumps(data)


def test_case_and_topic_filters(brain):
    _seed(brain)
    data = globe.build(case="nitroba")
    ids = {n["id"] for n in data["nodes"]}
    assert "nitroba" in ids and "zeek" in ids
    assert "vol" not in ids
    data = globe.build(topic="memory")
    ids = {n["id"] for n in data["nodes"]}
    assert ids == {"vol", "timeline"}


def test_growth_mode_keeps_recent_only(brain):
    _seed(brain)
    data = globe.build(mode="growth")
    ids = {n["id"] for n in data["nodes"]}
    assert "timeline" not in ids  # stale (2026-01-01)


def test_recency_dims_stale_notes(brain):
    _seed(brain)
    data = globe.build()
    by_id = {n["id"]: n for n in data["nodes"]}
    assert by_id["vol"]["recency"] > by_id["timeline"]["recency"]


def test_open_loops_flagged(brain):
    _seed(brain)
    (brain / "memory/open-loops.md").write_text(
        "---\ntitle: Open Loops\ntype: note\n---\n- [ ] verify [[vol]] gotcha\n")
    data = globe.build()
    vol = next(n for n in data["nodes"] if n["id"] == "vol")
    assert vol["warning"] is True


def test_main_writes_json(brain, capsys):
    _seed(brain)
    assert globe.main([]) == 0
    out = brain / "analytics/globe/brain-globe.json"
    assert out.is_file()
    data = json.loads(out.read_text())
    assert data["nodes"] and data["edges"]
    assert "Brain Earth generated." in capsys.readouterr().out


def test_timeline_buckets_runs_timestamps_and_legacy_dates(brain):
    run = "2031-02-04-1015-case-c-train"
    # legacy day-only notes collapse into one date bucket
    make_note(brain, "wiki/tools/vol.md", "Volatility", type="tool",
              created="2031-02-03")
    make_note(brain, "wiki/tools/zeek.md", "Zeek", type="tool",
              created="2031-02-03")
    # two notes from the same agent run share one run bucket
    make_note(brain, "wiki/concepts/a.md", "Alpha", type="concept",
              created="2031-02-04 10:15 UTC", run_id=run,
              origin_case="case-c", command="train")
    make_note(brain, "wiki/concepts/b.md", "Beta", type="concept",
              created="2031-02-04 10:16 UTC", run_id=run,
              origin_case="case-c", command="train")
    # a manual timestamped note gets its own per-minute bucket
    make_note(brain, "wiki/concepts/manual.md", "Manual", type="concept",
              created="2031-02-04 12:30 UTC")
    make_note(brain, "wiki/concepts/undated.md", "Undated", type="concept",
              created="unknown")
    data = globe.build()
    by_id = {n["id"]: n for n in data["nodes"]}
    assert by_id["a"]["run_id"] == run
    assert by_id["a"]["bucket"] == f"run:{run}"
    assert by_id["vol"]["bucket"] == "date:2031-02-03"
    assert by_id["manual"]["bucket"] == "ts:2031-02-04 12:30"
    # unparseable created: no bucket, shown at every replay step
    assert by_id["undated"]["bucket"] == ""
    assert by_id["undated"]["created"] == "unknown"
    assert data["timeline"] == [
        {"id": "date:2031-02-03", "kind": "date", "label": "2031-02-03",
         "start": "2031-02-03 00:00", "added": 2, "total": 2},
        {"id": f"run:{run}", "kind": "run", "label": "case-c train run",
         "start": "2031-02-04 10:15", "added": 2, "total": 4},
        {"id": "ts:2031-02-04 12:30", "kind": "ts", "label": "Manual",
         "start": "2031-02-04 12:30", "added": 1, "total": 5},
    ]


def test_timeline_run_label_falls_back_to_run_id(brain):
    run = "2031-02-05-0900-mystery-train"
    make_note(brain, "wiki/concepts/x.md", "X", type="concept",
              created="2031-02-05 09:00 UTC", run_id=run)
    make_note(brain, "wiki/concepts/y.md", "Y", type="concept",
              created="2031-02-06")
    data = globe.build()
    run_bucket = next(t for t in data["timeline"] if t["kind"] == "run")
    assert run_bucket["label"] == f"{run} agent run"


def test_timeline_respects_filters(brain):
    _seed(brain)
    data = globe.build(topic="memory")
    assert sum(t["added"] for t in data["timeline"]) == len(data["nodes"])
