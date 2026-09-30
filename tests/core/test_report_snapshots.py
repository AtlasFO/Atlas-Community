"""Immutable report snapshots: migrate, promote, cumulative diff."""
from __future__ import annotations

from pathlib import Path

from core.analyst_context import add_context
from core.claim_graph import (
    add_claim,
    add_conflict,
    load_graph,
    save_graph,
    supersede,
)
from core.incremental import plane_a_scan
from core.report_snapshots import (
    diff_investigation_state,
    ensure_initial_report_layout,
    finalize_rerun_reports,
    investigation_fingerprint,
    list_rerun_dirs,
    material_change,
    prior_fingerprint,
    promote_rerun_snapshot,
    resolve_latest_report_dir,
    run_id_to_rerun_dirname,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** SnapTest\n", encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v1")
    return case


def _seed_flat_reports(case: Path) -> None:
    (case / "reports" / "SnapTest_report.md").write_text(
        "# Initial report\n", encoding="utf-8",
    )
    (case / "reports" / "SnapTest_estate_report.md").write_text(
        "# Estate\n", encoding="utf-8",
    )


def test_run_id_to_rerun_dirname():
    assert run_id_to_rerun_dirname("run-0001") == "rerun_0001"
    assert run_id_to_rerun_dirname("run-12") == "rerun_0012"


def test_migrate_flat_to_initial_report(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_flat_reports(case)
    fp = investigation_fingerprint(case)
    mig = ensure_initial_report_layout(case, fingerprint=fp)
    assert mig["migrated"] is True
    init = case / "reports" / "initial_report"
    assert init.is_dir()
    assert (init / "SnapTest_report.md").is_file()
    assert (init / "SnapTest_estate_report.md").is_file()
    assert (init / "investigation_fingerprint.json").is_file()
    assert (case / "reports" / "diff_report.md").is_file()
    assert not (case / "reports" / "SnapTest_report.md").exists()
    latest = case / "reports" / "latest"
    assert latest.is_symlink() or latest.is_dir()
    assert resolve_latest_report_dir(case).resolve() == init.resolve()
    mig2 = ensure_initial_report_layout(case)
    assert mig2["already_initialized"] is True
    assert (init / "SnapTest_report.md").read_text(encoding="utf-8") == (
        "# Initial report\n"
    )


def test_promote_rerun_0001_and_0002_immutable(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_flat_reports(case)
    fp0 = investigation_fingerprint(case)
    ensure_initial_report_layout(case, fingerprint=fp0)

    c1 = add_claim(
        case,
        "Suspicious auth from 10.1.1.1",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4624"}],
    )
    assert c1.get("success")
    (case / "reports" / "SnapTest_report.md").write_text(
        "# After rerun 1\n", encoding="utf-8",
    )
    r1 = promote_rerun_snapshot(
        case,
        run_id="run-0001",
        plane_a={"run_id": "run-0001", "why_summary": ["claim added"]},
        fp_before=fp0,
        trigger="test",
    )
    assert r1["snapshot_created"] is True
    d1 = case / "reports" / "rerun_0001"
    assert d1.is_dir()
    assert (d1 / "SnapTest_report.md").read_text(encoding="utf-8") == (
        "# After rerun 1\n"
    )
    assert not (case / "reports" / "SnapTest_report.md").exists()

    g = load_graph(case)
    g["nodes"][c1["node_id"]]["confidence"] = "CONFIRMED"
    save_graph(case, g)
    (case / "reports" / "SnapTest_report.md").write_text(
        "# After rerun 2\n", encoding="utf-8",
    )
    r2 = promote_rerun_snapshot(
        case,
        run_id="run-0002",
        plane_a={"run_id": "run-0002"},
        fp_before=prior_fingerprint(case),
        trigger="test",
    )
    assert r2["snapshot_created"] is True
    d2 = case / "reports" / "rerun_0002"
    assert d2.is_dir()
    assert (d1 / "SnapTest_report.md").read_text(encoding="utf-8") == (
        "# After rerun 1\n"
    )
    assert (d2 / "SnapTest_report.md").read_text(encoding="utf-8") == (
        "# After rerun 2\n"
    )
    assert list_rerun_dirs(case) == [d1, d2]
    assert resolve_latest_report_dir(case).resolve() == d2.resolve()

    root_names = {p.name for p in (case / "reports").iterdir()}
    assert "initial_report" in root_names
    assert "rerun_0001" in root_names
    assert "rerun_0002" in root_names
    assert "diff_report.md" in root_names
    assert "SnapTest_report.md" not in root_names


def test_cumulative_diff_report(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_flat_reports(case)
    fp0 = investigation_fingerprint(case)
    ensure_initial_report_layout(case, fingerprint=fp0)
    add_claim(
        case,
        "Finding alpha about host DC01",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "a"}],
    )
    (case / "reports" / "r.md").write_text("r1\n", encoding="utf-8")
    promote_rerun_snapshot(
        case, run_id="run-0001", plane_a={"run_id": "run-0001"}, fp_before=fp0,
    )
    add_claim(
        case,
        "Finding beta about host DC02",
        confidence="SUSPECTED",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "b"}],
    )
    (case / "reports" / "r.md").write_text("r2\n", encoding="utf-8")
    promote_rerun_snapshot(
        case, run_id="run-0002",
        plane_a={"run_id": "run-0002"},
        fp_before=prior_fingerprint(case),
    )
    text = (case / "reports" / "diff_report.md").read_text(encoding="utf-8")
    assert "## Rerun 0001" in text
    assert "## Rerun 0002" in text
    assert "New Findings" in text


def test_structured_diff_categories(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    before = investigation_fingerprint(case)

    c = add_claim(
        case,
        "Old claim about lateral movement",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "x"}],
    )
    assert c.get("success")
    mid = investigation_fingerprint(case)
    d_new = diff_investigation_state(before, mid)
    assert material_change(d_new)
    assert any(x["id"] == c["node_id"] for x in d_new["new_findings"])

    g = load_graph(case)
    g["nodes"][c["node_id"]]["confidence"] = "CONFIRMED"
    save_graph(case, g)
    after_conf = investigation_fingerprint(case)
    d_conf = diff_investigation_state(mid, after_conf)
    assert d_conf["confidence_changes"]
    assert d_conf["confidence_changes"][0]["from"] == "LIKELY"
    assert d_conf["confidence_changes"][0]["to"] == "CONFIRMED"

    c2 = add_claim(
        case,
        "Replacement claim about lateral movement",
        confidence="CONFIRMED",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "y"}],
    )
    supersede(case, c["node_id"], c2["node_id"], reason="corrected")
    after_sup = investigation_fingerprint(case)
    d_sup = diff_investigation_state(after_conf, after_sup)
    assert d_sup["withdrawn_or_superseded"] or d_sup["new_findings"]

    c3 = add_claim(
        case,
        "Competing claim for conflict test",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "z"}],
    )
    before_cf = investigation_fingerprint(case)
    add_conflict(
        case,
        "Conflict between interpretations of same event",
        claim_ids=[c2["node_id"], c3["node_id"]],
    )
    g = load_graph(case)
    conflict_ids = [
        nid for nid, n in g["nodes"].items()
        if n.get("kind") == "conflict" and n.get("status") == "conflict"
    ]
    mid_cf = investigation_fingerprint(case)
    d_cf = diff_investigation_state(before_cf, mid_cf)
    assert d_cf["new_conflicts"] or d_cf["new_findings"]

    if conflict_ids:
        g["nodes"][conflict_ids[0]]["status"] = "superseded"
        save_graph(case, g)
        after_res = investigation_fingerprint(case)
        d_res = diff_investigation_state(mid_cf, after_res)
        assert d_res["resolved_conflicts"] or d_res["withdrawn_or_superseded"]


def test_analyst_context_in_diff(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    before = investigation_fingerprint(case)
    add_context(case, "IP 10.10.10.5 is a legitimate admin IP")
    after = investigation_fingerprint(case)
    d = diff_investigation_state(before, after)
    assert d["analyst_context_added"]
    assert material_change(d)


def test_no_material_change_skips_snapshot(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_flat_reports(case)
    fp0 = investigation_fingerprint(case)
    ensure_initial_report_layout(case, fingerprint=fp0)
    (case / "reports" / "SnapTest_report.md").write_text(
        "# Reworded only\n", encoding="utf-8",
    )
    r = promote_rerun_snapshot(
        case,
        run_id="run-0001",
        plane_a={"run_id": "run-0001"},
        fp_before=fp0,
    )
    assert r["material"] is False
    assert r["snapshot_created"] is False
    assert not (case / "reports" / "rerun_0001").exists()
    text = (case / "reports" / "diff_report.md").read_text(encoding="utf-8")
    assert "No material investigation-state changes" in text
    assert (case / "reports" / "SnapTest_report.md").is_file()


def test_finalize_after_plane_a_no_agent(tmp_path: Path):
    case = _case(tmp_path)
    _seed_flat_reports(case)
    fp0 = investigation_fingerprint(case)
    ensure_initial_report_layout(case, fingerprint=fp0)
    add_claim(
        case,
        "Traffic from 192.0.2.1 looks malicious",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "z"}],
    )
    result2 = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="user admin-jd is legitimate domain admin",
    )
    snap = finalize_rerun_reports(
        case,
        plane_a=result2,
        trigger="no-agent",
        fp_before=fp0,
        migrate=False,
    )
    assert snap["success"]
    assert (case / "reports" / "diff_report.md").is_file()


def test_flat_layout_before_rerun(tmp_path: Path):
    case = _case(tmp_path)
    _seed_flat_reports(case)
    assert (case / "reports" / "SnapTest_report.md").is_file()
    assert not (case / "reports" / "initial_report").exists()
    assert resolve_latest_report_dir(case) == case / "reports"
