"""Claim promotion: Observation → Claim → Hypothesis → Conflict → Conclusion."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import (
    add_claim,
    add_conflict,
    add_hypothesis,
    add_observation,
    load_graph,
    promote_conclusion,
    resolve_conflict,
    supersede,
)


def test_observation_claim_conclusion_chain(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    o = add_observation(
        case,
        "EID 4624 LogonType 3 from 10.0.0.12 as Administrator",
        evidence=[{
            "artifact": "Security.evtx",
            "locator": "RecordID 100001",
            "call_id": 12,
        }],
        host="SRV01",
    )
    assert o["success"]
    c = add_claim(
        case,
        "Successful SMB network logon from WS01",
        confidence="CONFIRMED",
        observation_ids=[o["node_id"]],
        host="SRV01",
        reasoning="LogonType 3 + NTLM V2 + ElevatedToken",
    )
    assert c["success"]
    n = promote_conclusion(case, c["node_id"], reasoning="Corroborated by Hayabusa")
    assert n["success"]
    g = load_graph(case)
    assert g["nodes"][n["node_id"]]["kind"] == "conclusion"
    assert any(
        e["type"] == "derived_from" and e["from"] == c["node_id"]
        for e in g["edges"]
    )


def test_conflict_and_resolve(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    a = add_claim(case, "No successful auth from WS01", confidence="LIKELY", host="SRV01")
    b = add_claim(
        case, "5 successful 4624 from WS01", confidence="CONFIRMED", host="SRV01"
    )
    x = add_conflict(
        case,
        "Disk and KAPE sources disagree on WS01→SRV01 auth success",
        claim_ids=[a["node_id"], b["node_id"]],
        possible_explanations=[
            "Security.evtx size-limit gap in the disk image",
            "KAPE collection had fuller EVTX coverage",
        ],
        evidence_still_required=["Reconcile Security.evtx coverage windows"],
    )
    assert x["success"]
    g = load_graph(case)
    assert g["nodes"][x["node_id"]]["reconciliation_status"] == "open"

    r = resolve_conflict(
        case, x["node_id"],
        winning_claim_id=b["node_id"],
        reason="KAPE EVTX contains the 4624 events",
    )
    assert r["success"]
    g2 = load_graph(case)
    assert g2["nodes"][x["node_id"]]["status"] == "superseded"
    assert g2["nodes"][a["node_id"]]["status"] == "superseded"
    assert g2["nodes"][b["node_id"]]["status"] in ("new", "unchanged", "updated")


def test_hypothesis_and_manual_supersede(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    c = add_claim(case, "Lateral movement used PtH", confidence="SUSPECTED")
    h = add_hypothesis(
        case,
        "NTLM auth may be cleartext credential reuse, not PtH",
        claim_ids=[c["node_id"]],
    )
    assert h["success"]
    c2 = add_claim(
        case, "NTLM V2 network logon — mechanism unknown", confidence="LIKELY"
    )
    s = supersede(case, c["node_id"], c2["node_id"], reason="Insufficient PtH artifacts")
    assert s["success"]
    g = load_graph(case)
    assert g["nodes"][c["node_id"]]["status"] == "superseded"


def test_conflict_requires_two_claims(tmp_path: Path):
    case = tmp_path / "c"
    case.mkdir()
    a = add_claim(case, "only one", confidence="LIKELY")
    r = add_conflict(case, "bad", claim_ids=[a["node_id"]])
    assert not r["success"]
