"""Investigation journal + milestones."""
from __future__ import annotations

import json
from pathlib import Path

from core.claim_graph import add_claim
from core.incremental import plane_a_scan
from core.run_journal import (
    diff_runs,
    list_runs,
    load_milestones,
    load_run,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** JournalTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"v1")
    return case


def test_journal_records_why(tmp_path: Path):
    case = _case(tmp_path)
    r1 = plane_a_scan(case, persist=True)
    assert r1.get("run_id") == "run-0001"
    assert r1.get("journal_path")
    assert any("bootstrap" in w or "catalog_first_scan" in w
               for w in (r1.get("why_summary") or []))
    rec = load_run(case, "run-0001")
    assert rec is not None
    reasons = {e["reason"] for e in rec["journal"]}
    assert "catalog_first_scan" in reasons or "bootstrap" in reasons
    assert "evidence_added" in reasons

    (case / "evidence" / "a.txt").write_bytes(b"v2-changed")
    r2 = plane_a_scan(case, persist=True)
    assert r2["run_id"] == "run-0002"
    rec2 = load_run(case, "run-0002")
    reasons2 = {e["reason"] for e in rec2["journal"]}
    assert "evidence_modified" in reasons2


def test_milestone_ransomware(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files on this host (T1486)",
        confidence="CONFIRMED",
    )
    r = plane_a_scan(case, persist=True)
    assert r.get("milestones_added")
    kinds = {m["kind"] for m in r["milestones_added"]}
    assert "ransomware_execution_confirmed" in kinds
    ms = load_milestones(case)
    assert any(m["kind"] == "ransomware_execution_confirmed"
               for m in ms["milestones"])


def test_diff_and_list_runs(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    (case / "evidence" / "b.txt").write_bytes(b"new")
    plane_a_scan(case, persist=True)
    runs = list_runs(case)
    assert len(runs) >= 2
    d = diff_runs(case, "run-0001", "run-0002")
    assert d["success"]
    assert "evidence_added" in (d.get("reasons_only_in_b") or []) or d.get("why_b")


def test_dry_run_skips_journal(tmp_path: Path):
    case = _case(tmp_path)
    r = plane_a_scan(case, persist=False)
    assert r["success"]
    assert not r.get("run_id")
    assert list_runs(case) == []
