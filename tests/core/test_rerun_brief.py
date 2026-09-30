"""Rerun Brief + investigation memory."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import add_claim, add_conflict, add_hypothesis
from core.incremental import plane_a_scan
from core.rerun_brief import (
    brief_path,
    build_rerun_brief,
    format_evidence_diff_lines,
    load_memory,
)


def test_rerun_brief_written(tmp_path: Path):
    case = tmp_path / "c"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** BriefTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"v1")
    r = plane_a_scan(case, persist=True)
    assert r.get("rerun_brief_path")
    text = Path(r["rerun_brief_path"]).read_text(encoding="utf-8")
    assert "Rerun Brief" in text
    assert "starting point" in text.lower()
    assert "New Evidence" in text
    assert "Outstanding investigation questions" in text


def test_brief_includes_conflicts_and_hypotheses(tmp_path: Path):
    case = tmp_path / "c"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "a.txt").write_bytes(b"x")
    plane_a_scan(case, persist=True)
    a = add_claim(case, "No successful logon", confidence="LIKELY")
    b = add_claim(case, "Successful logon confirmed", confidence="CONFIRMED")
    add_conflict(case, "Auth disagreement", claim_ids=[a["node_id"], b["node_id"]])
    add_hypothesis(case, "Maybe different EVTX windows", claim_ids=[a["node_id"]])
    r = plane_a_scan(case, persist=True)
    brief = build_rerun_brief(case, r)
    assert "Auth disagreement" in brief["text"] or "X0001" in brief["text"]
    assert "Maybe different EVTX windows" in brief["text"]
    mem = load_memory(case)
    assert mem.get("unresolved_hypotheses")
    assert brief_path(case).is_file()


def test_format_evidence_diff_lists_small_sets():
    entries = [
        {"path": "evidence/a.txt", "evidence_id": "ev_a"},
        {"path": "evidence/b.txt", "evidence_id": "ev_b"},
    ]
    lines = format_evidence_diff_lines(entries)
    assert lines == [
        "- `evidence/a.txt` (`ev_a`)",
        "- `evidence/b.txt` (`ev_b`)",
    ]


def test_format_evidence_diff_summarizes_large_sets():
    entries = []
    for i in range(50):
        entries.append({
            "path": f"evidence/pkg/KAPE/Remote Access/cache_{i}.bmp",
            "evidence_id": f"ev_ra_{i}",
        })
    for i in range(40):
        entries.append({
            "path": f"evidence/pkg/Windows/System32/log_{i}.evtx",
            "evidence_id": f"ev_win_{i}",
        })
    # Zone ADS must not explode the brief
    entries.append({
        "path": "evidence/pkg/foo.txt:Zone.Identifier",
        "evidence_id": "ev_zone",
    })
    lines = format_evidence_diff_lines(entries, full_max=80)
    text = "\n".join(lines)
    assert "90 files" in text or "**90 files**" in text
    assert "summarized for prompt size" in text
    assert "By folder" in text
    assert "Remote Access" in text
    assert "Windows/System32" in text
    assert "Zone.Identifier" in text
    # Must not list every path
    assert text.count("cache_") <= 10
    assert len(lines) < 80


def test_build_rerun_brief_summarizes_large_added(tmp_path: Path):
    case = tmp_path / "c"
    (case / "evidence").mkdir(parents=True)
    (case / ".atlas").mkdir(parents=True)
    added = [
        {
            "path": f"evidence/tree/mod{i // 20}/f{i}.dat",
            "evidence_id": f"ev_{i}",
        }
        for i in range(200)
    ]
    brief = build_rerun_brief(
        case,
        {
            "case_id": "BigDiff",
            "evidence_diff": {"added": added, "changed": [], "removed": []},
            "affected_claims": [],
            "open_conflicts": [],
        },
    )
    text = brief["text"]
    assert "summarized for prompt size" in text
    assert "200 files" in text
    assert len(text) < 50_000
    assert text.count("`evidence/tree/") < 80
