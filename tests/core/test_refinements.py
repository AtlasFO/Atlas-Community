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


def test_a_twin_of_two_claims_folds_the_second_into_the_first(tmp_path, monkeypatch):
    """Two records of one event that each lacked an identifier the other
    held become one claim when a later record shows both: the twin joins the
    first and the second is superseded by it, its citations carried."""
    case = _case(tmp_path)
    a = _claim(case, "jane.doe opened the share at 2031-02-04 12:06:28 and listed it at "
                     "2031-02-04 12:07:10.", "LIKELY", 1)
    b = _claim(case, "Share access by jane.doe from 2031-02-04 12:06:28; cookies from "
                     "2031-02-04 12:09:44.", "LIKELY", 2)
    assert a != b
    c = _claim(case, "jane.doe reached the share at 2031-02-04 12:06:28, listed it at "
                     "2031-02-04 12:07:10, cookies from 2031-02-04 12:09:44.", "LIKELY", 3)
    graph = load_graph(case)
    assert c == a
    assert graph["nodes"][b]["status"] == "superseded" and graph["nodes"][b]["superseded_by"] == a
    assert {2, 3} <= set(graph["nodes"][a]["merged_finding_call_ids"])
    # Off: the second record stays a claim of its own.
    monkeypatch.setenv("ATLAS_TWIN_FOLD", "0")
    case2 = _case(tmp_path / "off")
    a2 = _claim(case2, "jane.doe opened the share at 2031-02-04 12:06:28 and listed it at "
                       "2031-02-04 12:07:10.", "LIKELY", 1)
    b2 = _claim(case2, "Share access by jane.doe from 2031-02-04 12:06:28; cookies from "
                       "2031-02-04 12:09:44.", "LIKELY", 2)
    _claim(case2, "jane.doe reached the share at 2031-02-04 12:06:28, listed it at "
                  "2031-02-04 12:07:10, cookies from 2031-02-04 12:09:44.", "LIKELY", 3)
    assert load_graph(case2)["nodes"][b2]["status"] == "new" and a2 != b2


def test_a_stronger_twin_or_a_refinement_is_never_folded(tmp_path):
    case = _case(tmp_path)
    a = _claim(case, EVENT + ".", "LIKELY", 1)
    b = _claim(case, "PSEXESVC installed at 2031-02-04 12:06:28 UTC; started at "
                     "2031-02-04 12:06:30 UTC.", "CONFIRMED", 2)
    _claim(case, EVENT + ", started at 2031-02-04 12:06:30 UTC.", "LIKELY", 3)
    graph = load_graph(case)
    assert graph["nodes"][a]["status"] == "new" and graph["nodes"][b]["status"] == "new"


def test_two_findings_on_one_file_at_different_minutes_both_stay_current(tmp_path):
    """The fold rests on shared event identifiers (anchors_agree), never on a
    shared file: a twin merge into one finding leaves the other current."""
    case = _case(tmp_path)
    path = "C:\\Users\\jane.doe\\AppData\\Local\\Temp\\upd.exe"
    a = _claim(case, f"{path} ran at 2031-02-04 12:06:28 and wrote a file at 2031-02-04 12:07:10.", "LIKELY", 1)
    b = _claim(case, f"{path} ran again at 2031-02-04 13:15:02.", "LIKELY", 2)
    c = _claim(case, f"{path} ran at 2031-02-04 12:06:28 and wrote upd.dat at 2031-02-04 12:07:10.",
               "LIKELY", 3)
    graph = load_graph(case)
    assert c == a and b != a
    assert graph["nodes"][a]["status"] == "new" and graph["nodes"][b]["status"] == "new"
