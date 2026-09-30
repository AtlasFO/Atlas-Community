"""Tests for core/claim_graph.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.claim_graph import (
    SCHEMA_VERSION,
    active_conclusions_and_conflicts,
    claim_graph_path,
    empty_graph,
    find_claim_by_finding_call_id,
    load_graph,
    mirror_finding_fail_open,
    save_graph,
    upsert_claim_from_finding,
)


def test_empty_graph_shape():
    g = empty_graph("CASE1")
    assert g["schema_version"] == SCHEMA_VERSION
    assert g["case_id"] == "CASE1"
    assert g["nodes"] == {}
    assert g["edges"] == []
    assert g["meta"]["next_seq"] == 1


def test_save_load_roundtrip(tmp_path: Path):
    case = tmp_path / "mycase"
    case.mkdir()
    g = empty_graph("mycase")
    g["nodes"]["C0001"] = {
        "id": "C0001",
        "kind": "claim",
        "status": "unchanged",
        "statement": "test",
        "confidence": "LIKELY",
    }
    path = save_graph(case, g)
    assert path == claim_graph_path(case)
    assert path.is_file()
    loaded = load_graph(case)
    assert loaded["nodes"]["C0001"]["statement"] == "test"
    assert loaded["schema_version"] == SCHEMA_VERSION


def test_upsert_creates_and_updates(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    r1 = upsert_claim_from_finding(
        case,
        statement="Brute-force from 203.0.113.10",
        confidence="CONFIRMED",
        source="Security.evtx",
        host="SRV01",
        finding_call_id=42,
        linked_call_id=10,
        input_call_ids=[10, 11],
        supporting_evidence="EID 4625 count 10000",
        case_id="CASE-03",
    )
    assert r1["success"] and r1["created"]
    assert r1["claim_id"].startswith("C")
    g = load_graph(case)
    assert g["case_id"] == "CASE-03"
    node = g["nodes"][r1["claim_id"]]
    assert node["kind"] == "claim"
    assert node["source_finding_call_id"] == 42
    assert node["confidence"] == "CONFIRMED"
    assert any(e.get("artifact") == "Security.evtx" for e in node["evidence"])

    r2 = upsert_claim_from_finding(
        case,
        statement="Brute-force from 203.0.113.10 — updated",
        confidence="LIKELY",
        source="Security.evtx",
        host="SRV01",
        finding_call_id=42,
        case_id="CASE-03",
    )
    assert r2["updated"] and r2["claim_id"] == r1["claim_id"]
    g2 = load_graph(case)
    assert len(g2["nodes"]) == 1
    assert g2["nodes"][r1["claim_id"]]["confidence"] == "LIKELY"
    assert "updated" in g2["nodes"][r1["claim_id"]]["statement"]


def test_dedup_by_statement_host(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    a = upsert_claim_from_finding(
        case, statement="Same claim", confidence="LIKELY", host="h1"
    )
    b = upsert_claim_from_finding(
        case, statement="Same claim", confidence="CONFIRMED", host="h1"
    )
    assert a["claim_id"] == b["claim_id"]
    c = upsert_claim_from_finding(
        case, statement="Same claim", confidence="LIKELY", host="h2"
    )
    assert c["claim_id"] != a["claim_id"]
    assert len(load_graph(case)["nodes"]) == 2


def test_find_by_finding_call_id(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    upsert_claim_from_finding(
        case, statement="x", confidence="SUSPECTED", finding_call_id=99
    )
    g = load_graph(case)
    n = find_claim_by_finding_call_id(g, 99)
    assert n is not None and n["source_finding_call_id"] == 99


def test_mirror_fail_open_no_case_dir(monkeypatch):
    class _Log:
        def case_dir(self):
            return None

    monkeypatch.setattr("core.execution_log.log", _Log())
    assert mirror_finding_fail_open(
        statement="x", confidence="LIKELY", case_dir=None
    ) is None


def test_mirror_fail_open_with_case(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    r = mirror_finding_fail_open(
        statement="mirrored",
        confidence="LIKELY",
        case_dir=str(case),
        finding_call_id=7,
        case_id="T",
    )
    assert r and r["claim_id"]
    assert claim_graph_path(case).is_file()


def test_corrupt_file_loads_empty(tmp_path: Path):
    case = tmp_path / "c"
    atlas = case / ".atlas"
    atlas.mkdir(parents=True)
    (atlas / "claim_graph.json").write_text("{not json", encoding="utf-8")
    g = load_graph(case)
    assert g["nodes"] == {}


class TestWhichMachineAClaimIsAbout:
    """A host report is filtered by the host a belief was recorded against,
    so what counts as the same machine decides what a customer reads."""

    def test_two_addresses_on_one_network_are_two_machines(self):
        from core.claim_graph import node_in_report_scope, same_host
        assert not same_host("10.0.0.5", "10.0.0.7")
        assert same_host("10.0.0.5", "10.0.0.5")
        assert not node_in_report_scope(
            {"host": "10.0.0.5", "scope": "host"}, "host", "10.0.0.7")

    def test_a_log_abbreviation_is_the_same_machine(self):
        from core.claim_graph import same_host
        assert same_host("PROD-SQL-02", "sql-02")
        assert same_host("dc01.corp.example", "DC01")

    def test_a_fragment_too_short_to_identify_is_not(self):
        from core.claim_graph import same_host
        assert not same_host("dc", "prod-dc")
        assert not same_host("02", "PROD-SQL-02")


def test_active_snapshot(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    upsert_claim_from_finding(
        case, statement="a", confidence="LIKELY", finding_call_id=1
    )
    snap = active_conclusions_and_conflicts(case)
    assert len(snap["claims"]) == 1
    assert snap["conflicts"] == []
    assert snap["conclusions"] == []


# ── the trace as the run asserts it ─────────────────────────────────────────

def _finding(cid, desc, conf="LIKELY", claim_id=None):
    f = {"call_id": cid, "type": "finding", "description": desc, "confidence": conf}
    if claim_id:
        f["claim_id"] = claim_id
    return f


def _case_with(tmp_path, nodes):
    case = tmp_path / "case"
    case.mkdir()
    g = empty_graph("case")
    for n in nodes:
        g["nodes"][n["id"]] = {"kind": "claim", "status": "new", "confidence": "LIKELY", **n}
    save_graph(case, g)
    return case


def test_asserted_findings_drop_superseded_and_withdrawn_mirrors(tmp_path):
    from core.claim_graph import asserted_finding_entries
    case = _case_with(tmp_path, [
        {"id": "C0001", "statement": "old", "status": "superseded", "source_finding_call_id": 1},
        {"id": "C0002", "statement": "gone", "status": "withdrawn", "source_finding_call_id": 2},
        {"id": "C0003", "statement": "kept", "status": "updated", "source_finding_call_id": 3},
        {"id": "C0004", "statement": "twin", "status": "new", "source_finding_call_id": 4,
         "merged_finding_call_ids": [5]},
    ])
    findings = [_finding(1, "old", claim_id="C0001"), _finding(2, "gone"),
                _finding(3, "kept"), _finding(4, "twin"), _finding(5, "twin again"),
                _finding(6, "no mirror at all")]
    out = asserted_finding_entries(findings, case)
    assert [f["call_id"] for f in out] == [3, 4, 5, 6]
    # Unchanged entries are the trace's own dicts, so identity still works.
    assert out[0] is findings[2]


def test_asserted_findings_carry_the_claims_current_tier(tmp_path):
    from core.claim_graph import asserted_finding_entries
    case = _case_with(tmp_path, [
        {"id": "C0001", "statement": "x", "confidence": "UNCONFIRMED", "source_finding_call_id": 1},
    ])
    trace = _finding(1, "x", conf="CONFIRMED")
    (out,) = asserted_finding_entries([trace], case)
    assert out["confidence"] == "UNCONFIRMED" and out["trace_confidence"] == "CONFIRMED"
    assert trace["confidence"] == "CONFIRMED"     # the trace is not touched


def test_asserted_findings_without_a_graph_are_the_trace(tmp_path):
    from core.claim_graph import asserted_finding_entries
    findings = [_finding(1, "a"), _finding(2, "b", claim_id="C9")]
    assert asserted_finding_entries(findings, None) == findings
    assert asserted_finding_entries(findings, tmp_path / "nowhere") == findings
    assert asserted_finding_entries([], tmp_path) == []


def test_asserted_findings_match_legacy_traces_by_statement(tmp_path):
    """A trace written before findings carried claim ids: a superseded
    statement is matched on its opening text."""
    from core.claim_graph import asserted_finding_entries
    case = _case_with(tmp_path, [
        {"id": "C0001", "status": "superseded",
         "statement": "Scheduled task created for a renamed binary on WS01"},
    ])
    findings = [_finding(1, "Scheduled task created for a renamed binary on WS01"),
                _finding(2, "Run key modified on WS01")]
    assert [f["call_id"] for f in asserted_finding_entries(findings, case)] == [2]


# ── withdrawal ──────────────────────────────────────────────────────────────

def test_supersede_without_a_successor_withdraws_with_a_reason(tmp_path):
    from core.claim_graph import MIN_WITHDRAW_REASON, add_claim, supersede
    case = tmp_path / "c"
    case.mkdir()
    c = add_claim(case, "The beacon reached 203.0.113.9", confidence="LIKELY")["node_id"]
    short = supersede(case, c, reason="oops")
    assert short["success"] is False and str(MIN_WITHDRAW_REASON) in short["error"]
    r = supersede(case, c, reason="the address appears in no tool output the finding cites")
    assert r["success"] and r["withdrawn"]
    node = load_graph(case)["nodes"][c]
    assert node["status"] == "withdrawn" and node["withdraw_reason"].startswith("the address")
    assert not any(e["to"] == c for e in load_graph(case)["edges"])
    again = supersede(case, c, reason="withdrawing it a second time for the test")
    assert again["success"] is False and "withdrawn" in again["error"]
    assert c not in {n["id"] for n in active_conclusions_and_conflicts(case)["claims"]}


def test_superseding_a_node_with_itself_is_a_withdrawal(tmp_path):
    from core.claim_graph import add_claim, graph_snapshot_for_report, supersede
    case = tmp_path / "c"
    case.mkdir()
    c = add_claim(case, "An OCSP responder was the delivery host", confidence="SUSPECTED")["node_id"]
    r = supersede(case, c, c, reason="certificate validation traffic, not delivery")
    assert r["success"] and r["withdrawn"]
    snap = graph_snapshot_for_report(case)
    assert [n["id"] for n in snap["withdrawn"]] == [c]
    assert snap["superseded"] == [] and snap["active_claims"] == []


class TestRevalidate:
    """A belief under review that still holds returns to the current
    beliefs with the review kept as history; a conclusion that went under
    review with it returns once every basis is current again."""

    STATEMENT = ("The scheduled task Updater ran C:\\Windows\\Temp\\ps.exe as SYSTEM "
                 "at 2031-02-04 12:00:00")

    def _reviewed(self, tmp_path, *, promote=False):
        from core.claim_graph import add_claim, promote_conclusion
        from core.dependency_index import mark_needs_review
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        c = add_claim(case, statement=self.STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
        n = promote_conclusion(case, c, reasoning="stands")["node_id"] if promote else ""
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed")
        return case, c, n

    def test_a_re_checked_belief_returns_with_its_history(self, tmp_path):
        from core.claim_graph import get_node, load_graph, revalidate
        case, c, _ = self._reviewed(tmp_path)
        r = revalidate(case, c, call_ids=[91], note="task list re-read")
        assert r["success"] and r["status"] == "unchanged"
        node = get_node(load_graph(case), c)
        assert node["status"] == "unchanged"
        assert "invalidation_reason" not in node and "invalidated_at" not in node
        assert node["revalidation_call_ids"] == [91]
        assert node["review_history"][0]["invalidation_reason"] == "upstream evidence added/changed/removed"
        assert node["review_history"][0]["note"] == "task list re-read"

    def test_only_a_belief_under_review_and_only_with_calls(self, tmp_path):
        from core.claim_graph import revalidate
        case, c, _ = self._reviewed(tmp_path)
        r = revalidate(case, c, call_ids=[])
        assert not r["success"] and "call_ids required" in r["error"]
        assert revalidate(case, c, call_ids=[91])["success"]
        again = revalidate(case, c, call_ids=[92])
        assert not again["success"] and "is unchanged" in again["error"]
        assert not revalidate(case, "C9999", call_ids=[1])["success"]

    def test_a_conclusion_returns_with_its_only_basis(self, tmp_path):
        from core.claim_graph import get_node, load_graph, revalidate
        case, c, n = self._reviewed(tmp_path, promote=True)
        assert get_node(load_graph(case), n)["status"] == "needs_review"
        r = revalidate(case, c, call_ids=[91])
        assert r["also_revalidated"] == [n]
        conclusion = get_node(load_graph(case), n)
        assert conclusion["status"] == "unchanged"
        assert conclusion["review_history"][0]["via"] == c

    def test_a_recommendation_resting_on_the_belief_returns_with_it(self, tmp_path):
        from core.claim_graph import add_claim, add_recommendation, get_node, load_graph, revalidate
        from core.dependency_index import mark_needs_review
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        c = add_claim(case, statement=self.STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
        r = add_recommendation(case, action="Remove the Updater task on WS01", phase="eradicate",
                               scope="host", urgency="now", basis_ids=[c])["node_id"]
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed")
        assert get_node(load_graph(case), r)["status"] == "needs_review"
        assert get_node(load_graph(case), r)["invalidated_via"] == [c]
        out = revalidate(case, c, call_ids=[91])
        assert out["also_revalidated"] == [r]
        assert get_node(load_graph(case), r)["status"] == "unchanged"

    def test_a_node_questioned_in_its_own_right_stays_under_review(self, tmp_path):
        from core.claim_graph import get_node, load_graph, revalidate
        from core.dependency_index import mark_needs_review
        case, c, n = self._reviewed(tmp_path, promote=True)
        # the conclusion is then questioned directly (an analyst fact moved)
        mark_needs_review(case, [n], reason="analyst context changed interpretation")
        assert "invalidated_via" not in get_node(load_graph(case), n)
        assert revalidate(case, c, call_ids=[91])["also_revalidated"] == []
        assert get_node(load_graph(case), n)["status"] == "needs_review"

    def test_a_legacy_node_without_the_stamp_is_not_cascaded(self, tmp_path):
        from core.claim_graph import get_node, load_graph, revalidate, save_graph
        case, c, n = self._reviewed(tmp_path, promote=True)
        g = load_graph(case)
        g["nodes"][n].pop("invalidated_via", None)
        save_graph(case, g)
        assert revalidate(case, c, call_ids=[91])["also_revalidated"] == []
        assert get_node(load_graph(case), n)["status"] == "needs_review"

    def test_a_task_reopened_for_the_belief_is_answered_again(self, tmp_path):
        from core.claim_graph import revalidate
        from core.investigation_tasks import load_tasks, reopen_tasks_for_claims, save_tasks
        case, c, _ = self._reviewed(tmp_path)
        store = load_tasks(case)
        store["tasks"] = [{"id": "task-0001", "text": "Which task ran ps.exe?",
                           "status": "answered", "related_claim_ids": [c]}]
        save_tasks(case, store)
        assert reopen_tasks_for_claims(case, [c])["reopened"] == ["task-0001"]
        out = revalidate(case, c, call_ids=[91])
        assert out["restored_tasks"] == ["task-0001"]
        assert load_tasks(case)["tasks"][0]["status"] == "answered"

    def test_the_history_carries_the_trace_and_the_dirty_paths(self, tmp_path):
        from core.claim_graph import add_claim, get_node, load_graph, revalidate
        from core.dependency_index import mark_needs_review
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        c = add_claim(case, statement=self.STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed",
                          dirty={"changed": ["analysis/ws01_tasks.csv"]})
        assert get_node(load_graph(case), c)["invalidated_by"] == {"changed": ["analysis/ws01_tasks.csv"]}
        revalidate(case, c, call_ids=[91], trace="CASE_trace.json")
        node = get_node(load_graph(case), c)
        assert node["review_history"][0]["trace"] == "CASE_trace.json"
        assert node["review_history"][0]["invalidated_by"] == {"changed": ["analysis/ws01_tasks.csv"]}
        assert "invalidated_by" not in node

    def test_a_conclusion_with_another_basis_under_review_waits(self, tmp_path):
        from core.claim_graph import add_claim, add_node, get_node, load_graph, revalidate
        from core.dependency_index import mark_needs_review
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        c1 = add_claim(case, statement=self.STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
        c2 = add_claim(case, statement="ps.exe is a renamed PsExec (hash matches the vendor build)",
                       confidence="LIKELY", host="WS01")["node_id"]
        n = add_node(case, kind="conclusion", statement="PsExec ran from a scheduled task on WS01",
                     confidence="LIKELY", host="WS01", parent_ids=[c1, c2],
                     edge_type="derived_from")["node_id"]
        mark_needs_review(case, [c1, c2], reason="upstream evidence added/changed/removed")
        assert revalidate(case, c1, call_ids=[91])["also_revalidated"] == []
        assert get_node(load_graph(case), n)["status"] == "needs_review"
        assert revalidate(case, c2, call_ids=[92])["also_revalidated"] == [n]
        assert get_node(load_graph(case), n)["status"] == "unchanged"

    def test_a_node_is_stamped_with_the_paths_that_hit_it(self, tmp_path):
        from core.claim_graph import add_claim, get_node, load_graph
        from core.dependency_index import dirty_hits, mark_needs_review, rebuild_from_claim_graph
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        a = add_claim(case, statement="Auth events from evidence/h1/Security.evtx", confidence="LIKELY",
                      evidence=[{"artifact": "evidence/h1/Security.evtx", "locator": "4624"}])["node_id"]
        b = add_claim(case, statement="A task from evidence/h1/tasks.csv", confidence="LIKELY",
                      evidence=[{"artifact": "evidence/h1/tasks.csv", "locator": "Updater"}])["node_id"]
        index = rebuild_from_claim_graph(case)
        items = [("changed", "evidence/h1/Security.evtx", None), ("changed", "evidence/h1/tasks.csv", None)]
        hits = dirty_hits(index, items)
        assert hits[a] == {"changed": ["evidence/h1/Security.evtx"]}
        assert hits[b] == {"changed": ["evidence/h1/tasks.csv"]}
        mark_needs_review(case, [a, b], reason="upstream evidence added/changed/removed",
                          dirty={"changed": [p for _, p, _ in items]}, hits=hits)
        assert get_node(load_graph(case), a)["invalidated_by"] == {"changed": ["evidence/h1/Security.evtx"]}
        assert get_node(load_graph(case), b)["invalidated_by"] == {"changed": ["evidence/h1/tasks.csv"]}

    def test_a_second_change_moves_the_review_and_merges_its_paths(self, tmp_path):
        from core.claim_graph import get_node, load_graph, save_graph
        from core.dependency_index import mark_needs_review
        case, c, _ = self._reviewed(tmp_path)
        g = load_graph(case)
        g["nodes"][c]["invalidated_at"] = "2020-01-01T00:00:00Z"
        g["nodes"][c]["invalidated_by"] = {"changed": ["analysis/a.csv"]}
        save_graph(case, g)
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed",
                          dirty={"added": ["analysis/b.csv"]})
        node = get_node(load_graph(case), c)
        assert node["invalidated_at"] != "2020-01-01T00:00:00Z"
        assert node["invalidated_by"] == {"changed": ["analysis/a.csv"], "added": ["analysis/b.csv"]}

    def test_a_superseded_base_holds_nothing_under_review(self, tmp_path):
        from core.claim_graph import add_claim, add_node, get_node, load_graph, revalidate, supersede
        from core.dependency_index import mark_needs_review
        from core.investigation_tasks import load_tasks, reopen_tasks_for_claims, save_tasks
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        a1 = add_claim(case, statement=self.STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
        a2 = add_claim(case, statement=self.STATEMENT + " (re-recorded with the task export cited)",
                       confidence="LIKELY", host="WS01")["node_id"]
        n = add_node(case, kind="conclusion", statement="PsExec ran from a scheduled task on WS01",
                     confidence="LIKELY", host="WS01", parent_ids=[a1, a2], edge_type="derived_from")["node_id"]
        supersede(case, a1, a2, reason="citation repair")
        store = load_tasks(case)
        store["tasks"] = [{"id": "task-0001", "text": "Which task ran ps.exe?", "status": "answered",
                           "related_claim_ids": [a1, a2]}]
        save_tasks(case, store)
        mark_needs_review(case, [a2], reason="upstream evidence added/changed/removed")
        assert reopen_tasks_for_claims(case, [a2])["reopened"] == ["task-0001"]
        out = revalidate(case, a2, call_ids=[91])
        assert out["also_revalidated"] == [n]
        assert out["restored_tasks"] == ["task-0001"]
        assert get_node(load_graph(case), n)["status"] == "unchanged"

    def test_a_base_marked_again_moves_its_derived_nodes_review(self, tmp_path):
        from core.claim_graph import get_node, load_graph, save_graph
        from core.dependency_index import mark_needs_review
        case, c, n = self._reviewed(tmp_path, promote=True)
        g = load_graph(case)
        for nid in (c, n):
            g["nodes"][nid]["invalidated_at"] = "2020-01-01T00:00:00Z"
        save_graph(case, g)
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed",
                          dirty={"changed": ["analysis/later.csv"]})
        child = get_node(load_graph(case), n)
        assert child["invalidated_at"] != "2020-01-01T00:00:00Z"
        assert child["invalidated_by"] == {"changed": ["analysis/later.csv"]}
        assert child["invalidated_via"] == [c]

