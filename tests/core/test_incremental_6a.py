"""Evidence catalog + fingerprints + Plane A rerun."""
from __future__ import annotations

import json
from pathlib import Path

from core.evidence_catalog import (
    catalog_path,
    diff_catalogs,
    fingerprint_file,
    load_catalog,
    scan_evidence,
    update_catalog_from_scan,
)
from core.incremental import ensure_atlas_scaffold, format_plane_a_report, plane_a_scan


def _case_with_evidence(tmp_path: Path, files: dict[str, bytes]) -> Path:
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** TestRerun\n", encoding="utf-8")
    for rel, data in files.items():
        p = ev / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return case


def test_fingerprint_stable(tmp_path: Path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello-evidence")
    a = fingerprint_file(f)
    b = fingerprint_file(f)
    assert a["content_sha256"] == b["content_sha256"]
    assert a["fingerprint_mode"] == "full"
    assert a["size"] == 14


def test_scan_and_diff_added_changed_removed(tmp_path: Path):
    case = _case_with_evidence(tmp_path, {"a.txt": b"one", "b.txt": b"two"})
    units1 = scan_evidence(case)
    assert len(units1) == 2
    cat1 = update_catalog_from_scan(case, units1, case_id="TestRerun")
    assert catalog_path(case).is_file()

    # Change a.txt, remove b.txt, add c.txt
    (case / "evidence" / "a.txt").write_bytes(b"ONE-changed")
    (case / "evidence" / "b.txt").unlink()
    (case / "evidence" / "c.txt").write_bytes(b"three")
    units2 = scan_evidence(case)
    diff = diff_catalogs(cat1, units2)
    assert diff["counts"]["added"] == 1
    assert diff["counts"]["changed"] == 1
    assert diff["counts"]["removed"] == 1
    assert any(x["path"].endswith("c.txt") for x in diff["added"])
    assert any(x["path"].endswith("a.txt") for x in diff["changed"])
    assert any(x["path"].endswith("b.txt") for x in diff["removed"])


def test_lazy_bootstrap(tmp_path: Path):
    case = _case_with_evidence(tmp_path, {"x.evtx": b"fake"})
    r = ensure_atlas_scaffold(case, case_id="TestRerun")
    assert r["bootstrapped"]
    atlas = case / ".atlas"
    assert (atlas / "claim_graph.json").is_file()
    assert (atlas / "evidence_catalog.json").is_file()
    assert (atlas / "investigation_memory.json").is_file()
    assert (atlas / "run_history").is_dir()
    # Second call creates nothing new
    r2 = ensure_atlas_scaffold(case)
    assert r2["created"] == []


def test_plane_a_no_agent(tmp_path: Path):
    case = _case_with_evidence(tmp_path, {"sec.evtx": b"AAA"})
    r1 = plane_a_scan(case, persist=True)
    assert r1["success"]
    assert r1["first_catalog_scan"] is True
    assert r1["evidence_diff"]["counts"]["added"] == 1

    # Unchanged second scan
    r2 = plane_a_scan(case, persist=True)
    assert r2["evidence_diff"]["counts"]["added"] == 0
    assert r2["evidence_diff"]["counts"]["unchanged"] == 1

    text = format_plane_a_report(r2)
    assert "Evidence diff:" in text
    assert "New evidence:" in text


def test_dry_run_does_not_persist_units(tmp_path: Path):
    case = _case_with_evidence(tmp_path, {"a.txt": b"x"})
    ensure_atlas_scaffold(case)
    # empty catalog on disk
    from core.evidence_catalog import empty_catalog, save_catalog
    save_catalog(case, empty_catalog("T"))
    r = plane_a_scan(case, persist=False)
    assert r["success"]
    assert r["evidence_diff"]["counts"]["added"] == 1
    # catalog still empty
    assert load_catalog(case)["units"] == {}
