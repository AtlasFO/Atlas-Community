"""Tests for investigation CLI helpers + projection HTML/JSON assemble."""
from __future__ import annotations

import json
from pathlib import Path

from core.claim_graph import add_claim, add_conflict, load_graph
from core.incremental import plane_a_scan
from core.investigation_cli import (
    build_timeline,
    explain,
    format_explain,
    format_status,
    investigation_status,
)
from core.report_projection import assemble_report, bind_claims_to_sections


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** CliTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"hello")
    return case


def test_explain_claim(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    r = add_claim(
        case,
        "Successful SMB lateral movement from ws01 (T1021.002)",
        confidence="CONFIRMED",
        host="ws01",
    )
    assert r.get("success"), r
    cid = r["node_id"]
    result = explain(case, node_id=cid)
    assert result["success"]
    assert result["id"] == cid
    assert "lateral" in (result["statement"] or "").lower()
    text = format_explain(result)
    assert cid in text


def test_explain_section(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Successful SMB lateral movement from ws01 (T1021.002)",
        confidence="CONFIRMED",
    )
    bind_claims_to_sections(case)
    # New spine id
    result = explain(case, section_id="detailed_findings")
    assert result.get("success")
    assert result["kind"] == "section"
    # Legacy MITRE alias still resolves
    result2 = explain(case, section_id="lateral_movement")
    if result2.get("success"):
        assert result2["kind"] == "section"
    else:
        assert "known_sections" in result2


def test_timeline_from_claims(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "Brute force against RDP (T1110)", confidence="LIKELY")
    tl = build_timeline(case, source="claims")
    assert tl["success"]
    assert tl["count"] >= 1
    kinds = {e.get("kind") for e in tl["events"]}
    assert "claim" in kinds or "journal" in kinds or "milestone" in kinds


def test_timeline_from_master_missing(tmp_path: Path):
    case = _case(tmp_path)
    tl = build_timeline(case, source="master")
    assert not tl["success"]
    assert "master_timeline" in (tl.get("error") or "")


def test_timeline_from_master(tmp_path: Path):
    case = _case(tmp_path)
    tsv = case / "analysis" / "master_timeline.tsv"
    tsv.write_text(
        "datetime\tmessage\n"
        "2024-01-01T00:00:00Z\tInitial access\n"
        "2024-01-01T01:00:00Z\tLateral movement\n",
        encoding="utf-8",
    )
    tl = build_timeline(case, source="master")
    assert tl["success"]
    assert tl["count"] == 2


def test_status_counts(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    r1 = add_claim(case, "Persistence via Run key (T1547)", confidence="CONFIRMED")
    r2 = add_claim(
        case,
        "Successful RDP logon as Administrator on srv01 (T1021.001)",
        confidence="LIKELY",
    )
    assert r1.get("success") and r2.get("success"), (r1, r2)
    add_conflict(
        case,
        "Conflicting accounts of persistence",
        claim_ids=[r1["node_id"], r2["node_id"]],
    )
    st = investigation_status(case)
    assert st["success"]
    assert st["case_id"] == "CliTest"
    text = format_status(st)
    assert "Investigation status" in text


def test_assemble_json_and_html(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "C2 beacon to evil.example (T1071)", confidence="CONFIRMED")
    bind_claims_to_sections(case)

    js = assemble_report(case, fmt="json")
    assert js["success"]
    path = Path(js["output_path"])
    assert path.suffix == ".json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "manifest" in data
    assert "sections" in data

    html = assemble_report(case, fmt="html")
    assert html["success"]
    hpath = Path(html["output_path"])
    assert hpath.suffix == ".html"
    body = hpath.read_text(encoding="utf-8")
    assert "<html" in body.lower() or "<!doctype" in body.lower()


def test_cli_explain_wiring(tmp_path: Path):
    from agent.cli import build_parser, main

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    r = add_claim(case, "Test claim for CLI", confidence="SUSPECTED")
    assert r.get("success"), r
    cid = r["node_id"]
    parser = build_parser()
    args = parser.parse_args(["explain", cid, "--case", str(case), "--json"])
    assert args.func.__name__ == "cmd_explain"
    # smoke: does not raise
    main(["explain", cid, "--case", str(case), "--json"])


def test_cli_status_journal_timeline(tmp_path: Path, capsys):
    from agent.cli import main

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(case, "CLI status claim", confidence="LIKELY")
    main(["status", "--case", str(case)])
    out = capsys.readouterr().out
    assert "Investigation status" in out
    main(["journal", "--case", str(case)])
    main(["timeline", "--case", str(case), "--json"])
    # graph still loadable
    assert load_graph(case).get("nodes")
