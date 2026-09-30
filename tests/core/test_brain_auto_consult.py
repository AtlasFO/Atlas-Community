"""Tests for proactive Brain auto-consult."""
from __future__ import annotations

from pathlib import Path


def test_topic_for_tool_maps_forensic_families():
    from core.brain.auto_consult import topic_for_tool
    assert topic_for_tool("ez_evtxecmd") is not None
    assert topic_for_tool("misc_chainsaw_hunt") is not None
    assert topic_for_tool("vol_vol_pslist") is not None
    assert topic_for_tool("brain_consult") is None
    assert topic_for_tool("reason_reason_plan") is None
    assert topic_for_tool("misc_record_finding") is None


def test_auto_consult_once_per_topic(tmp_path, monkeypatch):
    brain = tmp_path / "brain"
    for d in ("wiki/tools", "memory", "inbox/memory-candidates"):
        (brain / d).mkdir(parents=True)
    (brain / "AGENTS.md").write_text("# x\n")
    (brain / "wiki/tools/evtx.md").write_text("""---
title: "EVTX parsing gotchas"
type: "tool"
created: "2026-08-07 10:00 UTC"
updated: "2026-08-07 10:00 UTC"
status: "active"
source_classification: "internal"
confidence: "high"
tags: [evtx]
related: []
source: {type: "manual", url: "", description: ""}
origin: {case_id: "OTHER"}
entities: {cases: [], tools: [], techniques: [], actors: [], cves: []}
---

# EVTX parsing gotchas

Prefer EvtxECmd for Windows event logs; strings dumps miss structured fields.
""")
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)
    monkeypatch.delenv("ATLAS_NO_BRAIN_AUTO", raising=False)

    case = tmp_path / "CASEY"
    (case / "analysis").mkdir(parents=True)

    from core.brain.auto_consult import consult_for_tool, maybe_enrich_tool_result
    first = consult_for_tool("ez_evtxecmd", case_dir=case)
    assert first is not None
    assert first.get("block")
    assert "BRAIN WIKI" in first["block"]
    assert "EVTX" in first["block"]

    # Same topic — no second consult
    second = consult_for_tool("misc_chainsaw_hunt", case_dir=case)
    assert second is None

    # Enrichment path
    topics = case / "analysis" / "brain_auto_topics.json"
    topics.write_text('{"topics": []}\n')  # reset for enrich test
    # clear consulted note paths so search can return again
    consulted = case / "analysis" / "brain_consulted.json"
    if consulted.exists():
        consulted.unlink()
    enriched = maybe_enrich_tool_result(
        "ez_evtxecmd", {"success": True, "stdout": "ok"}, case_dir=case)
    assert isinstance(enriched, dict)
    assert "brain_wiki" in enriched or "BRAIN WIKI" in str(enriched.get("stdout", ""))


def test_auto_consult_accepts_str_case_dir(tmp_path, monkeypatch):
    """Middleware passes case_dir as str from execution_log.case_dir()."""
    brain = tmp_path / "brain"
    (brain / "wiki/tools").mkdir(parents=True)
    (brain / "memory").mkdir(parents=True)
    (brain / "inbox/memory-candidates").mkdir(parents=True)
    (brain / "AGENTS.md").write_text("# x\n")
    (brain / "wiki/tools/evtx.md").write_text("""---
title: "EVTX parsing gotchas"
type: "tool"
created: "2026-08-07 10:00 UTC"
updated: "2026-08-07 10:00 UTC"
status: "active"
source_classification: "internal"
confidence: "high"
tags: [evtx]
related: []
source: {type: "manual", url: "", description: ""}
origin: {case_id: "OTHER"}
entities: {cases: [], tools: [], techniques: [], actors: [], cves: []}
---

# EVTX

Prefer EvtxECmd.
""")
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)
    monkeypatch.delenv("ATLAS_NO_BRAIN_AUTO", raising=False)

    case = tmp_path / "CASEY"
    (case / "analysis").mkdir(parents=True)

    from core.brain.auto_consult import consult_for_tool
    # Intentionally pass str — must not TypeError on path join
    r = consult_for_tool("ez_ez_evtxecmd", case_dir=str(case))
    assert r is not None
    assert (case / "analysis" / "brain_auto_topics.json").is_file()


def test_auto_consult_disabled(monkeypatch):
    monkeypatch.setenv("ATLAS_NO_BRAIN_AUTO", "1")
    from core.brain.auto_consult import consult_for_tool
    assert consult_for_tool("ez_evtxecmd") is None
