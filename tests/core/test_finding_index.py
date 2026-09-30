"""Tests for case_config report language and stable F-NNN finding IDs."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.case_config import (
    get_report_language,
    load_case_config,
    set_report_language,
)
from core.claim_graph import add_claim, promote_conclusion
from core.finding_index import (
    ensure_finding_ids,
    f_id_for,
    load_index,
    nodes_for_report,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** FindLang\n", encoding="utf-8")
    return case


def test_report_language_default_and_persist(tmp_path: Path):
    case = _case(tmp_path)
    assert get_report_language(case) == "en"
    set_report_language(case, "de")
    assert get_report_language(case) == "de"
    cfg = load_case_config(case)
    assert cfg["report_language"] == "de"
    assert (case / ".atlas" / "case_config.json").is_file()


def test_report_language_aliases_and_reject(tmp_path: Path):
    case = _case(tmp_path)
    set_report_language(case, "german")
    assert get_report_language(case) == "de"
    with pytest.raises(ValueError):
        set_report_language(case, "fr")


def test_finding_ids_stable_monotonic(tmp_path: Path):
    case = _case(tmp_path)
    a = add_claim(case, "RDP brute force T1110", confidence="CONFIRMED")
    b = add_claim(case, "ExampleLocker ransomware T1486", confidence="CONFIRMED")
    idx1 = ensure_finding_ids(case)
    fa = f_id_for(case, a["node_id"])
    fb = f_id_for(case, b["node_id"])
    assert fa == "F-001"
    assert fb == "F-002"
    # New claim gets next id; existing ids unchanged
    c = add_claim(case, "Lateral SMB movement", confidence="LIKELY")
    ensure_finding_ids(case)
    assert f_id_for(case, a["node_id"]) == "F-001"
    assert f_id_for(case, b["node_id"]) == "F-002"
    assert f_id_for(case, c["node_id"]) == "F-003"
    assert load_index(case)["next_n"] == 4


def test_upsert_finding_syncs_index_transactionally(tmp_path: Path):
    """X7: claim_graph write must not leave finding_index empty."""
    from core.claim_graph import upsert_claim_from_finding

    case = _case(tmp_path)
    r = upsert_claim_from_finding(
        case,
        statement="user01 lateral RDP to SRV02",
        confidence="LIKELY",
        host="SRV02",
        finding_call_id=42,
        supporting_evidence="table.query row host=SRV02 user=user01",
    )
    assert r["success"] is True
    assert r.get("finding_id", "").startswith("F-")
    assert (case / ".atlas" / "finding_index.json").is_file()
    assert f_id_for(case, r["claim_id"]) == r["finding_id"]
    idx = load_index(case)
    assert idx["by_node_id"].get(r["claim_id"]) == r["finding_id"]


def test_nodes_for_report_includes_f_ids(tmp_path: Path):
    case = _case(tmp_path)
    c = add_claim(case, "RDP on DC02", confidence="CONFIRMED", host="DC02")
    promote_conclusion(case, c["node_id"], statement="Estate-wide ransomware impact")
    nodes = nodes_for_report(case)
    assert nodes
    assert all(n.get("finding_id", "").startswith("F-") for n in nodes)
    host_nodes = nodes_for_report(case, scope="host", host="DC02")
    assert host_nodes
    assert any(
        "DC02" in (n.get("host") or "")
        or "dc02" in (n.get("statement") or "").lower()
        for n in host_nodes
    )


def test_nodes_for_report_host_scope_is_the_recorded_host_only(tmp_path: Path):
    """A host report carries the beliefs recorded against that host —
    not estate-wide ones, and not another host's because its statement
    happens to mention this one."""
    case = _case(tmp_path)
    add_claim(case, "RDP logon to DC02 as user01", confidence="CONFIRMED", host="DC02")
    add_claim(case, "Ransomware spread from DC02 across the estate",
              confidence="LIKELY", host="DC02", scope="estate")
    add_claim(case, "WS01 received a share from DC02", confidence="LIKELY", host="WS01")
    hosts = [(n.get("host"), n.get("scope"))
             for n in nodes_for_report(case, scope="host", host="dc02")]
    assert hosts == [("DC02", "host")]


def test_a_promoted_claim_is_shown_once_under_its_conclusion(tmp_path: Path):
    """A conclusion restates the claim it was promoted from; the report lists
    the conclusion, keeps the claim's id as an alias so references to it
    still resolve, and does not detail the claim a second time."""
    case = _case(tmp_path)
    c = add_claim(case, "Data left the host via the sync client", confidence="LIKELY", host="WS01")
    other = add_claim(case, "An archive was staged in the Downloads folder", confidence="LIKELY", host="WS01")
    n = promote_conclusion(case, c["node_id"], statement="The data left the host via the sync client")
    nodes = nodes_for_report(case)
    ids = [x.get("id") for x in nodes]
    assert n["node_id"] in ids and other["node_id"] in ids
    assert c["node_id"] not in ids
    conclusion = next(x for x in nodes if x.get("id") == n["node_id"])
    assert conclusion["also_recorded_as"] == [f_id_for(case, c["node_id"])]
    assert len(nodes) == 2
