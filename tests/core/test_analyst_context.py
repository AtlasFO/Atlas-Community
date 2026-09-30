"""Analyst-context persistence, matching, and Plane A wiring."""
from __future__ import annotations

from pathlib import Path

from core.analyst_context import (
    add_context,
    apply_feedback,
    correct_context,
    extract_entities,
    find_matching_node_ids,
    list_context,
    withdraw_context,
)
from core.claim_graph import add_claim, load_graph
from core.evidence_catalog import load_catalog
from core.incremental import plane_a_scan
from core.rerun_brief import load_memory, refresh_investigation_memory


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** AcCtx\n", encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX-v1")
    return case


def test_extract_entities_ip_user_host_quote():
    text = (
        'IP 10.0.1.5 is a legitimate admin jump host WS-ADMIN01; '
        'user jsmith and CORP\\svc.backup01; also "special token"'
    )
    ents = extract_entities(text)
    assert "10.0.1.5" in ents
    assert "WS-ADMIN01" in ents or any("WS-ADMIN01" in e for e in ents)
    assert any("jsmith" in e.lower() for e in ents) or "jsmith" in ents
    assert any("CORP\\svc.backup01" in e or "svc.backup01" in e for e in ents)
    assert "special token" in ents


def test_add_withdraw_correct_and_memory_preserve(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)  # bootstrap memory
    e1 = add_context(case, "IP 10.0.1.5 is a legitimate admin IP", run_id="run-0001")
    assert e1["id"] == "ac-0001"
    assert e1["status"] == "active"
    assert "10.0.1.5" in e1["entities"]

    refresh_investigation_memory(case)
    mem = load_memory(case)
    assert any(x["id"] == "ac-0001" for x in mem["analyst_context"])

    withdrawn = withdraw_context(case, "ac-0001", run_id="run-0002")
    assert withdrawn["status"] == "withdrawn"
    assert list_context(case, active_only=True) == []

    e2 = correct_context(
        case, "ac-0001", "IP 10.0.1.5 is corp jump host only", run_id="run-0003",
    )
    # correct_context withdraws then adds; ac-0001 already withdrawn
    assert e2["supersedes"] == "ac-0001"
    assert e2["status"] == "active"
    active = list_context(case, active_only=True)
    assert len(active) == 1
    assert active[0]["id"] == e2["id"]


def test_find_matching_multi_claim_ip(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    c1 = add_claim(
        case,
        "Suspicious RDP from 10.0.1.5 to DC01",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4624"}],
    )
    c2 = add_claim(
        case,
        "Admin logon from 10.0.1.5 looks malicious",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4672"}],
    )
    c3 = add_claim(
        case,
        "Unrelated phishing to user alice",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "mail"}],
    )
    assert c1.get("success") and c2.get("success") and c3.get("success")
    matched = find_matching_node_ids(case, entities=["10.0.1.5"])
    assert c1["node_id"] in matched
    assert c2["node_id"] in matched
    assert c3["node_id"] not in matched


def test_context_only_marks_needs_review_evidence_immutable(tmp_path: Path):
    case = _case(tmp_path)
    r0 = plane_a_scan(case, persist=True)
    assert r0["success"]
    cat0 = load_catalog(case)
    fp0 = {
        u.get("path"): (u.get("content_hash"), u.get("size"))
        for u in (cat0.get("units") or {}).values()
    }
    add_claim(
        case,
        "Lateral movement sourced from 10.0.1.5",
        confidence="CONFIRMED",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4648"}],
    )

    r1 = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="IP 10.0.1.5 is a legitimate administrator IP",
    )
    assert r1["success"]
    assert r1["evidence_diff"]["counts"]["changed"] == 0
    assert r1["evidence_diff"]["counts"]["added"] == 0
    assert r1["new_analyst_context"]
    assert r1["new_analyst_context"]["id"].startswith("ac-")
    assert r1["context_affected_claims"]
    assert r1["invalidation"].get("context_marked") or r1["invalidation"]["marked"]

    g = load_graph(case)
    statuses = {n["status"] for n in g["nodes"].values()}
    assert "needs_review" in statuses

    cat1 = load_catalog(case)
    fp1 = {
        u.get("path"): (u.get("content_hash"), u.get("size"))
        for u in (cat1.get("units") or {}).values()
    }
    assert fp0 == fp1

    brief = (case / ".atlas" / "rerun_brief.md").read_text(encoding="utf-8")
    assert "Analyst Context" in brief
    assert "blind allowlist" in brief.lower()
    assert "10.0.1.5" in brief

    why = " ".join(r1.get("why_summary") or [])
    assert "analyst" in why.lower() or r1.get("run_id")


def test_user_match_marks_claim(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Account CORP\\jsmith performed DCSync",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4662"}],
    )
    r = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="user CORP\\jsmith is a known domain admin account",
    )
    assert r["context_affected_claims"]
    g = load_graph(case)
    assert any(n.get("status") == "needs_review" for n in g["nodes"].values())


def test_withdraw_and_correct_via_plane_a(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Traffic from 192.168.1.50 looks C2",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "net"}],
    )
    r_add = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="IP 192.168.1.50 is the scanner VLAN gateway",
    )
    ac_id = r_add["new_analyst_context"]["id"]

    r_w = plane_a_scan(case, persist=True, withdraw_context_id=ac_id)
    assert r_w["success"]
    assert list_context(case, active_only=True) == []
    mem = load_memory(case)
    assert any(
        e["id"] == ac_id and e["status"] == "withdrawn"
        for e in mem["analyst_context"]
    )

    r_c = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="IP 192.168.1.50 is corp vuln-scan jump box",
        correct_context_id=ac_id,
    )
    assert r_c["success"]
    new = r_c["new_analyst_context"]
    assert new["supersedes"] == ac_id
    assert new["status"] == "active"


def test_dry_run_does_not_persist_context(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    added = add_claim(
        case,
        "Host 10.0.0.9 beaconed",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "dns"}],
    )
    assert added.get("success")
    r = plane_a_scan(
        case,
        persist=False,
        analyst_feedback="IP 10.0.0.9 is monitoring probe",
    )
    assert r["success"]
    assert list_context(case) == []
    matched = r.get("analyst_context_feedback", {}).get("matched_node_ids") or []
    assert added["node_id"] in matched


def test_apply_feedback_journal_hints(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    out = apply_feedback(case, text="IP 1.2.3.4 is internal DNS")
    assert out["journal_hints"][0]["reason"] == "analyst_context_added"
    ac = out["new_entry"]["id"]
    out2 = apply_feedback(case, withdraw_id=ac)
    assert out2["journal_hints"][0]["reason"] == "analyst_context_withdrawn"


def test_bare_plane_a_without_q_unchanged_shape(tmp_path: Path):
    """Bare rerun Plane A (no analyst ops) still succeeds and leaves memory empty."""
    case = _case(tmp_path)
    r = plane_a_scan(case, persist=True)
    assert r["success"]
    assert r.get("new_analyst_context") is None
    assert (r.get("context_affected_claims") or []) == []
    assert load_memory(case).get("analyst_context") == []


def test_cli_rerun_flags_present():
    from agent.cli import build_parser

    p = build_parser()
    # argparse stores dest without dashes
    ns = p.parse_args([
        "rerun", "--case", "/tmp/x", "-q", "IP 1.1.1.1 is CDN",
        "--no-agent",
    ])
    assert ns.question == "IP 1.1.1.1 is CDN"
    assert ns.no_agent is True

    ns2 = p.parse_args([
        "rerun", "--withdraw-context", "ac-0001", "--no-agent",
    ])
    assert ns2.withdraw_context == "ac-0001"

    ns3 = p.parse_args([
        "rerun", "--correct-context", "ac-0001", "-q", "new text", "--no-agent",
    ])
    assert ns3.correct_context == "ac-0001"
    assert ns3.question == "new text"


def test_projection_stale_after_context_mark(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    c = add_claim(
        case,
        "Malware download via 203.0.113.10",
        confidence="LIKELY",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "sysmon"}],
    )
    assert c.get("success")
    # Seed a projection section that contributes this claim
    from core.report_projection import load_manifest, save_manifest

    man = load_manifest(case)
    if not man.get("sections"):
        man["sections"] = {}
    man["sections"]["exec_summary"] = {
        "section_id": "exec_summary",
        "title": "Executive Summary",
        "status": "current",
        "contributing_claims": [c["node_id"]],
        "contributing_conclusions": [],
        "contributing_conflicts": [],
        "contributing_evidence": [],
        "body_hash": "abc",
        "generated_at": "2020-01-01T00:00:00Z",
    }
    save_manifest(case, man)

    r = plane_a_scan(
        case,
        persist=True,
        analyst_feedback="IP 203.0.113.10 is the corporate web proxy",
    )
    g = load_graph(case)
    assert g["nodes"][c["node_id"]]["status"] == "needs_review"
    stale = r.get("affected_report_sections") or []
    man2 = load_manifest(case)
    sec = (man2.get("sections") or {}).get("exec_summary") or {}
    # Rebind may rewrite contributing lists; prefer explicit stale when linked
    assert "exec_summary" in stale or sec.get("status") == "stale" or bool(stale)


# ── the brief's prior-knowledge section is the source of context ─────────

_BRIEF_TWO = (
    "**Case ID** AcCtx\n\n## What you already know\n\n"
    "- IP 10.0.0.5 is the print server.\n"
    "- The account svc.backup01 is a service account.\n"
)
_BRIEF_ONE = (
    "**Case ID** AcCtx\n\n## What you already know\n\n"
    "- IP 10.0.0.5 is the print server.\n"
)


def test_reconcile_turns_brief_facts_into_entries_and_back(tmp_path: Path):
    from core.analyst_context import reconcile_case_knowledge
    from core.case_knowledge import ORIGIN

    case = _case(tmp_path)
    (case / "CASE.md").write_text(_BRIEF_TWO, encoding="utf-8")
    first = reconcile_case_knowledge(case)
    assert [e["text"] for e in first["added"]] == [
        "IP 10.0.0.5 is the print server.",
        "The account svc.backup01 is a service account.",
    ]
    assert all(e["origin"] == ORIGIN and e["fingerprint"] for e in first["added"])
    assert "10.0.0.5" in first["added"][0]["entities"]

    # The same brief again changes nothing and writes nothing.
    stamp = load_memory(case)["updated_at"]
    again = reconcile_case_knowledge(case)
    assert again["changed"] is False
    assert again["matched"] == [e["id"] for e in first["added"]]
    assert load_memory(case)["updated_at"] == stamp

    # A bullet removed is withdrawn; written again, it comes back under its id.
    (case / "CASE.md").write_text(_BRIEF_ONE, encoding="utf-8")
    gone = reconcile_case_knowledge(case)
    assert [e["id"] for e in gone["withdrawn"]] == [first["added"][1]["id"]]
    assert [e["id"] for e in list_context(case, active_only=True)] == [first["added"][0]["id"]]
    (case / "CASE.md").write_text(_BRIEF_TWO, encoding="utf-8")
    back = reconcile_case_knowledge(case)
    assert [e["id"] for e in back["reactivated"]] == [first["added"][1]["id"]]
    assert len(list_context(case)) == 2
    assert len(list_context(case, active_only=True)) == 2


def test_reconcile_leaves_entries_added_the_old_way_alone(tmp_path: Path):
    from core.analyst_context import reconcile_case_knowledge

    case = _case(tmp_path)
    legacy = add_context(case, "IP 192.0.2.7 is the VPN concentrator")
    r = reconcile_case_knowledge(case)
    assert r["changed"] is False
    assert [e["id"] for e in list_context(case, active_only=True)] == [legacy["id"]]


def test_plane_a_context_goes_through_the_brief(tmp_path: Path):
    from core.case_knowledge import ORIGIN, facts

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    r = plane_a_scan(case, persist=True,
                     analyst_feedback="IP 10.0.1.5 is a legitimate administrator IP")
    assert facts(case) == ["IP 10.0.1.5 is a legitimate administrator IP"]
    assert r["new_analyst_context"]["origin"] == ORIGIN
    assert r["context_reconcile"]["added"][0]["id"] == r["new_analyst_context"]["id"]
    # Editing the brief by hand is the same channel.
    md = (case / "CASE.md").read_text(encoding="utf-8")
    (case / "CASE.md").write_text(
        md + "- The account CORP\\jsmith is a domain admin.\n", encoding="utf-8")
    r2 = plane_a_scan(case, persist=True)
    assert [e["text"] for e in r2["context_reconcile"]["added"]] == [
        "The account CORP\\jsmith is a domain admin."]
    assert r2["new_analyst_context"] is None
    assert len(list_context(case, active_only=True)) == 2


def test_only_context_that_changed_marks_claims(tmp_path: Path):
    from core.claim_graph import save_graph

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    c = add_claim(
        case, "Lateral movement sourced from 10.0.1.5", confidence="CONFIRMED",
        evidence=[{"artifact": "evidence/Security.evtx", "locator": "4648"}],
    )
    r = plane_a_scan(case, persist=True,
                     analyst_feedback="IP 10.0.1.5 is a legitimate administrator IP")
    assert c["node_id"] in r["invalidation"]["context_marked"]
    # Once the investigator has settled it, an unchanged brief leaves it be.
    g = load_graph(case)
    g["nodes"][c["node_id"]]["status"] = "updated"
    save_graph(case, g)
    r2 = plane_a_scan(case, persist=True)
    assert load_graph(case)["nodes"][c["node_id"]]["status"] == "updated"
    assert r2["context_affected_claims"] == []
    # Withdrawing the fact re-opens the claim it named.
    (case / "CASE.md").write_text("**Case ID** AcCtx\n\n## What you already know\n\n",
                                  encoding="utf-8")
    r3 = plane_a_scan(case, persist=True)
    assert [e["text"] for e in r3["context_reconcile"]["withdrawn"]] == [
        "IP 10.0.1.5 is a legitimate administrator IP"]
    assert load_graph(case)["nodes"][c["node_id"]]["status"] == "needs_review"
