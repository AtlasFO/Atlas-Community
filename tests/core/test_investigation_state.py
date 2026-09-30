"""Current Investigation State + investigation-driven report projection."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import add_claim, add_conflict, promote_conclusion
from core.incremental import plane_a_scan
from core.investigation_state import (
    build_current_investigation_state,
    project_report_from_state,
    record_deliverable,
)
from core.report_projection import load_manifest


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** StateTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"x")
    return case


def test_build_state_empty_then_with_beliefs(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    empty = build_current_investigation_state(case)
    assert empty["success"]
    assert empty["label"] == "Current Investigation State"
    assert empty["has_beliefs"] is False
    assert empty["authoritative"] is True

    c = add_claim(
        case,
        "Interactive RDP session as Administrator from 203.0.113.10",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
    )
    promote_conclusion(case, c["node_id"])
    state = build_current_investigation_state(case)
    assert state["has_beliefs"] is True
    assert state["counts"]["conclusions"] >= 1
    assert state["claim_graph"]["has_graph"]
    assert any("projection" in g.lower() or "write_projected" in g
               for g in state["report_writer_guidance"])


def test_project_report_fallback_without_beliefs(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    r = project_report_from_state(case, regenerate_stale=False)
    assert r["success"] is False
    assert r.get("gate") == "beliefs_required"
    assert "write_projected" in (r.get("error") or "").lower() or "beliefs" in (r.get("error") or "").lower()
    assert "fallback" not in r or r.get("fallback") != "write_final_report"


def test_project_report_with_fake_generator(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Successful SMB lateral movement from HOST01 (T1021.002)",
        confidence="CONFIRMED",
    )
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files (T1486)",
        confidence="CONFIRMED",
    )

    def fake_gen(ctx, sec):
        return (
            f"## {ctx['title']}\n\n"
            f"Grounded on Current Investigation State "
            f"({len(ctx.get('claims') or [])} claims).\n"
        )

    r = project_report_from_state(
        case, regenerate_stale=True, generator=fake_gen,
    )
    assert r["success"]
    assert "Current Investigation State" in r["markdown"]
    # Findings project as per-finding blocks in the fixed 8-section structure
    # (which replaced the old kill-chain-phase section headings).
    assert "T1021.002" in r["markdown"] and "T1486" in r["markdown"]
    assert "lateral movement" in r["markdown"].lower()
    # The custom generator's prose flows into the section bodies.
    assert "Grounded on Current Investigation State" in r["markdown"]
    # Section titles come from the report_i18n glossary. Asserted in English on
    # purpose: "en" is the default language, and an assertion that passes in
    # either language stops pinning the structure. A German run deserves its own
    # test that sets the language explicitly.
    assert "Detailed Findings" in r["markdown"]
    assert r["regenerate"].get("regenerated")


def test_record_deliverable_updates_manifest(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    out = case / "reports" / "StateTest_investigation_report.md"
    out.write_text("# Report\n", encoding="utf-8")
    meta = record_deliverable(
        case, str(out), source="write_final_report", content="# Report\n",
    )
    assert meta["success"]
    m = load_manifest(case)
    assert m["last_assembled_path"] == str(out)
    assert m["last_deliverable_source"] == "write_final_report"
    assert m["last_deliverable_sha256"]


def test_state_includes_open_conflicts(tmp_path: Path):
    case = _case(tmp_path)
    a = add_claim(case, "No auth success", confidence="LIKELY")
    b = add_claim(case, "Auth success confirmed", confidence="CONFIRMED")
    add_conflict(case, "Auth disagreement", claim_ids=[a["node_id"], b["node_id"]])
    state = build_current_investigation_state(case)
    assert state["counts"]["conflicts"] == 1
    assert any("Conflict" in g for g in state["report_writer_guidance"])
