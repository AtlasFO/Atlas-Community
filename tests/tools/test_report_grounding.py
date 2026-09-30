"""Report grounding against the claim graph."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import (
    add_claim,
    add_conflict,
    graph_snapshot_for_report,
    lint_report_against_graph,
    promote_conclusion,
)


def test_snapshot_for_report(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    assert graph_snapshot_for_report(case)["has_graph"] is False
    c = add_claim(case, "Successful SMB logon from srv01", confidence="CONFIRMED")
    promote_conclusion(case, c["node_id"])
    snap = graph_snapshot_for_report(case)
    assert snap["has_graph"]
    assert len(snap["active_conclusions"]) == 1
    assert snap["open_conflicts"] == []


def test_lint_open_conflict_must_appear(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    a = add_claim(case, "No auth success", confidence="LIKELY")
    b = add_claim(case, "Auth success confirmed", confidence="CONFIRMED")
    x = add_conflict(
        case,
        "VMDK vs KAPE disagree on SMB logon success",
        claim_ids=[a["node_id"], b["node_id"]],
    )
    report = "# Report\n\n## Findings\n\nHost was probed only.\n"
    warns = lint_report_against_graph(report, case)
    assert any("open_conflicts_unmentioned" in w for w in warns)

    report2 = (
        f"# Report\n\n## Conflicts\n\n{x['node_id']}: VMDK vs KAPE disagree.\n"
    )
    warns2 = lint_report_against_graph(report2, case)
    assert not any("open_conflicts_unmentioned" in w for w in warns2)


def test_lint_negative_compromise_wording(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    add_claim(case, "placeholder", confidence="LIKELY")  # ensure has_graph
    report = "The host was not compromised during the incident.\n"
    warns = lint_report_against_graph(report, case)
    assert any("negative_compromise_wording" in w for w in warns)

    ok = (
        "No evidence of compromise was identified within the available evidence.\n"
    )
    warns_ok = lint_report_against_graph(ok, case)
    assert not any("negative_compromise_wording" in w for w in warns_ok)


def test_lint_conclusion_grounding(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    c = add_claim(
        case,
        "Successful SMB network logon from srv01 as Administrator",
        confidence="CONFIRMED",
    )
    n = promote_conclusion(case, c["node_id"])
    bad = "# Report\n\nNothing to see here.\n"
    warns = lint_report_against_graph(bad, case)
    assert any("conclusion_grounding" in w for w in warns)

    good = (
        f"# Report\n\n## Findings\n\n"
        f"{n['node_id']}: Successful SMB network logon from srv01.\n"
    )
    asserts = lint_report_against_graph(good, case)
    assert not any("conclusion_grounding" in w for w in asserts)


def test_lint_claim_grounding_and_needs_review(tmp_path: Path):
    from core.claim_graph import add_claim, lint_report_against_graph, load_graph, save_graph

    case = tmp_path / "c"
    case.mkdir()
    c = add_claim(
        case,
        "Successful SMB network logon from srv01 as Administrator",
        confidence="CONFIRMED",
    )
    # Mark needs_review
    g = load_graph(case)
    g["nodes"][c["node_id"]]["status"] = "needs_review"
    save_graph(case, g)

    bad = "# Report\n\nNothing to see.\n"
    warns = lint_report_against_graph(bad, case)
    assert any("needs_review_unmentioned" in w for w in warns)

    # Fresh CONFIRMED claim (not needs_review)
    case2 = tmp_path / "c2"
    case2.mkdir()
    add_claim(
        case2,
        "ExampleLocker ransomware encrypted user files on the volume",
        confidence="CONFIRMED",
    )
    warns2 = lint_report_against_graph("# Report\n\nEmpty.\n", case2)
    assert any("claim_grounding" in w for w in warns2)


def test_infer_report_scope():
    from core.claim_graph import infer_report_scope

    assert infer_report_scope("reports/CASE_estate_report.md")["scope"] == "estate"
    assert infer_report_scope("reports/estate_report.md")["scope"] == "estate"
    host = infer_report_scope("reports/CASE_ws02_report.md")
    assert host["scope"] == "host"
    assert host["host"] == "ws02"
    modern = infer_report_scope("reports/host_ws02_report.md")
    assert modern["scope"] == "host"
    assert modern["host"] == "ws02"
    assert infer_report_scope("reports/CASE_investigation_report.md")["scope"] == "case"


def test_host_scope_skips_other_host_conclusions(tmp_path: Path):
    from core.claim_graph import add_claim, lint_report_against_graph, promote_conclusion

    case = tmp_path / "c"
    case.mkdir()
    a = add_claim(
        case,
        "RDP logon on ws02 as Administrator succeeded",
        confidence="CONFIRMED",
        host="ws02",
        temporal_qualifier="first interactive session",
    )
    pa = promote_conclusion(case, a["node_id"])
    b = add_claim(
        case,
        "Ransomware impact confirmed on ws01 workstation",
        confidence="CONFIRMED",
        host="ws01",
    )
    promote_conclusion(case, b["node_id"])

    # Host report for ws02 — ws01 conclusion not required
    report = (
        f"# Report\n\n## Findings\n\n"
        f"{pa['node_id']}: RDP logon on ws02 as Administrator succeeded.\n"
    )
    warns = lint_report_against_graph(
        report, case, output_path="reports/CASE_ws02_report.md",
    )
    assert not any("conclusion_grounding" in w for w in warns)


def test_lint_noop_without_graph(tmp_path: Path):
    case = tmp_path / "empty"
    case.mkdir()
    assert lint_report_against_graph("was not compromised", case) == []
    assert lint_report_against_graph("x", None) == []
