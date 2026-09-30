"""What the pre-run pass hands the investigator as work: the evidence delta,
findings under review, open questions and changed context, with the one
bit a rerun reads and the lines people read."""
from __future__ import annotations

import json
from pathlib import Path

from core.claim_graph import add_claim, load_graph, save_graph
from core.incremental import plane_a_scan, summarize_work


def _case(tmp_path: Path, requests: str = "- What happened on WS01?\n") -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text(
        "**Case ID** WorkTest\n\n## Investigation Requests\n\n" + requests
        + "\n## What you already know\n\n", encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v1")
    return case


def _answer_all_tasks(case: Path) -> None:
    p = case / ".atlas" / "investigation_tasks.json"
    store = json.loads(p.read_text(encoding="utf-8"))
    for t in store["tasks"]:
        t["status"] = "answered"
        # A task's status follows its parts: answered means every part is.
        for part in t.get("parts") or []:
            part["status"] = "answered"
    p.write_text(json.dumps(store), encoding="utf-8")


def test_first_scan_is_work_and_says_so(tmp_path):
    r = plane_a_scan(_case(tmp_path), persist=True)
    work = r["work"]
    assert work["pending"] is True and work["first_scan"] is True
    assert work["questions"]["open"] and work["questions"]["new"]
    assert any("first look" in line for line in work["reasons"])
    assert any("open question" in line for line in work["reasons"])


def test_nothing_changed_and_everything_answered_is_no_work(tmp_path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _answer_all_tasks(case)
    r = plane_a_scan(case, persist=True)
    assert r["work"]["pending"] is False
    assert r["work"]["reasons"] == []


def test_new_evidence_is_work(tmp_path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _answer_all_tasks(case)
    (case / "evidence" / "System.evtx").write_bytes(b"EVTX-2")
    r = plane_a_scan(case, persist=True)
    assert r["work"]["pending"] is True
    assert r["work"]["evidence"] == {"added": 1, "changed": 0, "removed": 0}
    assert "1 evidence file added" in r["work"]["reasons"]


def test_a_new_question_in_the_brief_is_work(tmp_path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _answer_all_tasks(case)
    md = (case / "CASE.md").read_text(encoding="utf-8")
    md = md.replace("- What happened on WS01?\n", "- What happened on WS01?\n- Was data taken?\n")
    (case / "CASE.md").write_text(md, encoding="utf-8")
    r = plane_a_scan(case, persist=True)
    work = r["work"]
    assert work["pending"] is True
    assert len(work["questions"]["new"]) == 1 and len(work["questions"]["open"]) == 1
    assert "1 open question (1 new)" in work["reasons"]


def test_a_finding_under_review_is_work_until_it_is_settled(tmp_path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _answer_all_tasks(case)
    added = add_claim(case, "Brute force in evidence/Security.evtx", confidence="LIKELY",
                      evidence=[{"artifact": "evidence/Security.evtx", "locator": "4625"}])
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v2")
    r = plane_a_scan(case, persist=True)
    assert added["node_id"] in r["work"]["claims_to_review"]
    assert "1 finding to re-validate" in r["work"]["reasons"]
    # Still outstanding on the next pass with nothing else changed.
    r2 = plane_a_scan(case, persist=True)
    assert r2["work"]["pending"] is True
    assert added["node_id"] in r2["work"]["claims_to_review"]
    # Settled once the graph no longer holds it under review.
    g = load_graph(case)
    g["nodes"][added["node_id"]]["status"] = "updated"
    save_graph(case, g)
    r3 = plane_a_scan(case, persist=True)
    assert r3["work"]["pending"] is False


def test_a_new_fact_in_the_brief_is_work(tmp_path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _answer_all_tasks(case)
    r = plane_a_scan(case, persist=True,
                     analyst_feedback="The address 203.0.113.9 is the corporate proxy.")
    assert r["work"]["pending"] is True
    assert r["work"]["context"]["added"] == [r["new_analyst_context"]["id"]]
    assert "1 new fact in the brief" in r["work"]["reasons"]
    # The same brief on the next pass is not new work.
    r2 = plane_a_scan(case, persist=True)
    assert r2["work"]["pending"] is False


def test_summarize_work_is_plain_about_counts():
    work = summarize_work({
        "evidence_diff": {"counts": {"added": 2, "changed": 1, "removed": 0}},
        "affected_claims": [{"id": "C1"}, {"id": "C2"}],
        "open_conflicts": [{"id": "X1"}],
        "task_reconcile": {"added": ["T3"], "reopened_via_claims": ["T1"]},
        "context_reconcile": {"added": [{"id": "ac-0001"}], "withdrawn": [{"id": "ac-0002"}]},
    }, open_tasks=[{"id": "T1", "text": "Was data taken?"},
                   {"id": "T3", "text": "Who logged in?"},
                   {"id": "T9", "text": "[derived] Re-check WS02 for indicators related to: x"}])
    assert work["pending"] is True
    assert work["questions"]["open"] == ["T1", "T3"]
    assert work["questions"]["followups"] == ["T9"]
    assert work["reasons"] == [
        "2 evidence files added", "1 evidence file changed",
        "2 findings to re-validate", "1 open conflict",
        "2 open questions (1 new, 1 reopened)", "1 follow-up Atlas raised",
        "1 new fact in the brief", "1 fact withdrawn from the brief",
    ]


def test_reopened_and_derived_tasks_count_after_the_pass(tmp_path):
    """A task reopened because its finding went under review, and the
    follow-ups Atlas derives from that, are counted as they stand after the
    pass, not as the brief's reconcile left them."""
    case = _case(tmp_path, requests="- What happened on host WS01?\n")
    plane_a_scan(case, persist=True)
    added = add_claim(case, "Host WS01 was brute-forced via evidence/Security.evtx",
                      confidence="LIKELY",
                      evidence=[{"artifact": "evidence/Security.evtx", "locator": "4625"}])
    p = case / ".atlas" / "investigation_tasks.json"
    store = json.loads(p.read_text(encoding="utf-8"))
    for t in store["tasks"]:
        t["status"] = "answered"
        t["related_claim_ids"] = [added["node_id"]]
        for part in t.get("parts") or []:
            part["status"] = "answered"
            part["claim_ids"] = [added["node_id"]]
    p.write_text(json.dumps(store), encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v2")
    r = plane_a_scan(case, persist=True)
    work = r["work"]
    assert work["questions"]["reopened"] == [store["tasks"][0]["id"]]
    assert work["questions"]["open"] == [store["tasks"][0]["id"]]
    assert any(line.startswith("1 open question") and "1 reopened" in line
               for line in work["reasons"])
