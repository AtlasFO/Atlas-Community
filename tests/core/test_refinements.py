"""A statement and its tier travel together when a finding meets its twin:
a stronger twin brings its own text, a weaker restatement is folded, a
weaker one that names more gets a claim of its own linked by ``refines``,
the asserted view never raises a finding through a merge, and the report
shows a linked pair as two findings with footers."""
from pathlib import Path

from core.claim_graph import asserted_finding_entries, load_graph, upsert_claim_from_finding

EVENT = ("Service PSEXESVC (SHA1 0098c79e1404b4399bf0e686d88dbf052269a302) was "
         "installed on WS-EXAMPLE at 2031-02-04 12:06:28 UTC")


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "C"
    for d in (".atlas", "evidence", "analysis", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** RFTest\n")
    return case


def _claim(case: Path, statement: str, confidence: str, call_id: int) -> str:
    r = upsert_claim_from_finding(case, statement=statement, confidence=confidence,
                                  host="WS-EXAMPLE", finding_call_id=call_id)
    assert r["success"], r
    return r["claim_id"]


def test_a_stronger_twin_brings_its_own_statement_and_tier(tmp_path):
    case = _case(tmp_path)
    a = _claim(case, EVENT + ", probably as part of lateral movement from a host not yet named.",
               "LIKELY", 1)
    b = _claim(case, EVENT + ".", "CONFIRMED", 2)
    node = load_graph(case)["nodes"][a]
    assert a == b and node["confidence"] == "CONFIRMED"
    assert node["statement"] == EVENT + "."


def test_a_weaker_restatement_is_folded_and_the_claim_keeps_its_text(tmp_path):
    case = _case(tmp_path)
    a = _claim(case, EVENT + ".", "CONFIRMED", 1)
    b = _claim(case, EVENT + ", a remote execution service.", "LIKELY", 2)
    node = load_graph(case)["nodes"][a]
    assert a == b and node["confidence"] == "CONFIRMED" and node["statement"] == EVENT + "."
    assert 2 in node["merged_finding_call_ids"]


def test_a_weaker_refinement_gets_its_own_claim_linked_to_the_stronger(tmp_path):
    case = _case(tmp_path)
    a = _claim(case, EVENT + ".", "CONFIRMED", 1)
    b = _claim(case, EVENT + ", pushed from 198.51.100.23 by CORP\\operator.", "SUSPECTED", 2)
    graph = load_graph(case)
    assert a != b
    assert graph["nodes"][b]["confidence"] == "SUSPECTED" and graph["nodes"][b]["refines"] == a
    assert {"from": b, "to": a, "type": "refines"}.items() <= next(
        e for e in graph["edges"] if e.get("type") == "refines").items()
    assert graph["nodes"][a]["confidence"] == "CONFIRMED"


def test_the_asserted_view_never_raises_a_finding_through_a_merge(tmp_path):
    case = _case(tmp_path)
    weaker = EVENT + ", probably as part of lateral movement from a host not yet named."
    _claim(case, weaker, "LIKELY", 1)
    _claim(case, EVENT + ".", "CONFIRMED", 2)
    trace = [{"type": "finding", "call_id": 1, "description": weaker, "confidence": "LIKELY"},
             {"type": "finding", "call_id": 2, "description": EVENT + ".", "confidence": "CONFIRMED"}]
    tiers = {f["call_id"]: f["confidence"] for f in asserted_finding_entries(trace, case)}
    assert tiers == {1: "LIKELY", 2: "CONFIRMED"}


def test_the_report_shows_a_refinement_beside_its_base(tmp_path):
    from core.report_assemble import _fold_twins, assemble_client_report
    case = _case(tmp_path)
    a = _claim(case, EVENT + ".", "CONFIRMED", 1)
    b = _claim(case, EVENT + ", pushed from 198.51.100.23 by CORP\\operator.", "SUSPECTED", 2)
    nodes = load_graph(case)["nodes"]
    kept = _fold_twins([dict(nodes[a], finding_id="F-001"), dict(nodes[b], finding_id="F-002")])
    assert len(kept) == 2
    md = assemble_client_report(case, report_scope="estate")
    assert "Refines F-001 [CONFIRMED]" in md
    assert "Refined by F-002 [SUSPECTED]" in md
