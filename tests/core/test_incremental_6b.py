"""Dependency index + needs_review invalidation."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import add_claim, load_graph
from core.dependency_index import (
    mark_needs_review,
    nodes_for_dirty_evidence,
    rebuild_from_claim_graph,
)
from core.evidence_catalog import scan_evidence, update_catalog_from_scan
from core.incremental import plane_a_scan


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** DepTest\n", encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v1")
    return case


def test_rebuild_links_claim_to_evidence_path(tmp_path: Path):
    case = _case(tmp_path)
    units = scan_evidence(case)
    update_catalog_from_scan(case, units, case_id="DepTest")
    add_claim(
        case,
        "Brute-force in evidence/Security.evtx",
        confidence="LIKELY",
        evidence=[{
            "artifact": "evidence/Security.evtx",
            "locator": "EID 4625",
        }],
    )
    idx = rebuild_from_claim_graph(case)
    assert any("Security.evtx" in p for p in idx["by_evidence_path"])
    nids = []
    for p, ids in idx["by_evidence_path"].items():
        if "Security.evtx" in p:
            nids.extend(ids)
    assert nids


def test_changed_evidence_marks_needs_review(tmp_path: Path):
    case = _case(tmp_path)
    r0 = plane_a_scan(case, persist=True)
    assert r0["success"]
    add_claim(
        case,
        "Auth events from evidence/Security.evtx",
        confidence="CONFIRMED",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4624"}],
    )
    # Rebuild so claim is indexed, then change file and rerun
    rebuild_from_claim_graph(case)
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v2-CHANGED")
    r1 = plane_a_scan(case, persist=True)
    assert r1["evidence_diff"]["counts"]["changed"] == 1
    assert r1["invalidation"]["marked"]
    g = load_graph(case)
    statuses = {n["status"] for n in g["nodes"].values()}
    assert "needs_review" in statuses


def test_mark_skips_superseded(tmp_path: Path):
    case = _case(tmp_path)
    c = add_claim(case, "old", confidence="LIKELY")
    from core.claim_graph import load_graph, save_graph
    g = load_graph(case)
    g["nodes"][c["node_id"]]["status"] = "superseded"
    save_graph(case, g)
    r = mark_needs_review(case, [c["node_id"]])
    assert c["node_id"] in r["skipped"]
