"""Tests for brain.consult contextual retrieval."""
from __future__ import annotations

from pathlib import Path


def _note(brain: Path, rel: str, title: str, body: str, ntype: str = "tool"):
    p = brain / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"""---
title: "{title}"
type: "{ntype}"
created: "2026-08-07 10:00 UTC"
updated: "2026-08-07 10:00 UTC"
status: "active"
source_classification: "internal"
confidence: "medium"
tags: [evtx, persistence]
related: []
source: {{type: "manual", url: "", description: ""}}
origin: {{case_id: "OTHER"}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# {title}

{body}
""")


def test_consult_returns_relevant_and_dedups(tmp_path, monkeypatch):
    brain = tmp_path / "brain"
    for d in ("wiki/tools", "wiki/techniques", "memory", "inbox/memory-candidates"):
        (brain / d).mkdir(parents=True)
    (brain / "AGENTS.md").write_text("# x\n")
    _note(brain, "wiki/tools/evtx.md", "EVTX parsing gotchas",
          "Prefer EvtxECmd over dumping with strings for Windows event logs.")
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)

    case = tmp_path / "CASEX"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text("# CASEX\n")

    from tools.brain_tools import consult_brain
    r1 = consult_brain("EVTX event log analysis", case_dir=case, limit=3)
    assert r1["ok"] is True
    assert r1.get("count", 0) >= 1
    assert any("EVTX" in n["title"] for n in r1["notes"])

    r2 = consult_brain("EVTX event log analysis", case_dir=case, limit=3)
    assert r2["count"] == 0  # deduped this run

    r3 = consult_brain("EVTX", case_dir=case, force=True, limit=3)
    assert r3["count"] >= 1


def test_consult_respects_no_brain(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_NO_BRAIN", "1")
    from tools.brain_tools import consult_brain
    r = consult_brain("anything")
    assert r["notes"] == []
    assert r.get("reason") == "ATLAS_NO_BRAIN"
