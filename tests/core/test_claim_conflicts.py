"""Phases 4–5: contradiction detection and claim statement validation."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import (
    add_claim,
    detect_hard_contradictions,
    load_graph,
    validate_claim_statement,
)


def test_detect_auth_contradiction(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    add_claim(
        case,
        "No successful authentication from 10.0.0.12",
        confidence="LIKELY",
        host="SRV01",
    )
    add_claim(
        case,
        "5 successful network logons from 10.0.0.12",
        confidence="CONFIRMED",
        host="SRV01",
    )
    det = detect_hard_contradictions(case, auto_create=False)
    assert det["pair_count"] >= 1

    det2 = detect_hard_contradictions(case, auto_create=True)
    assert det2["conflicts_created"]
    g = load_graph(case)
    conflicts = [n for n in g["nodes"].values() if n["kind"] == "conflict"]
    assert len(conflicts) >= 1
    assert conflicts[0]["reconciliation_status"] == "open"


def test_add_claim_warns_on_contradiction(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    add_claim(case, "No successful logon from WS01", host="h1")
    r = add_claim(case, "Successful logon from WS01 confirmed", host="h1")
    assert r["success"]
    assert r.get("contradiction_warnings")


def test_validate_negative_compromise():
    errs = validate_claim_statement("Host was not compromised")
    assert any("negative_compromise" in e for e in errs)


def test_validate_temporal_requires_qualifier():
    errs = validate_claim_statement(
        "The first attacker activity on this host was RDP at 12:00"
    )
    assert any("temporal_qualifier" in e for e in errs)

    ok = validate_claim_statement(
        "The first interactive session was RDP at 12:00",
        temporal_qualifier="first interactive session",
    )
    assert ok == []


def test_validate_host_vs_estate():
    errs = validate_claim_statement(
        "Recommend domain-wide krbtgt reset",
        scope="host",
    )
    assert any("host_vs_estate" in e for e in errs)
    ok = validate_claim_statement(
        "Recommend domain-wide krbtgt reset",
        scope="estate",
    )
    assert ok == []


def test_add_claim_refuses_bad_temporal(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    r = add_claim(
        case,
        "First attacker access was the RDP session",
        confidence="LIKELY",
    )
    assert not r["success"]
    assert r.get("gate") == "claim_validation"
