"""B8 — task answered requires relevant HV disposition; soft floor no waiver."""
from __future__ import annotations

import json
from pathlib import Path

from core.coverage_ledger import (
    build_coverage_ledger,
    mark_paths,
    ready_for_degraded_exit,
    refuse_answered_unseen_coverage,
    relevant_ledger_units,
)
from core.investigation_tasks import reconcile_case_md, update_task


def _real_claim(case, text="Attacker activity was observed on the host."):
    from core.claim_graph import add_claim
    r = add_claim(case, text, confidence="LIKELY", enforce_validation=False)
    assert r.get("success"), r
    return r["node_id"]


def _inv(case: Path, paths: list[str]) -> None:
    (case / ".atlas").mkdir(parents=True, exist_ok=True)
    (case / "evidence").mkdir(parents=True, exist_ok=True)
    for p in paths:
        fp = case / p
        fp.parent.mkdir(parents=True, exist_ok=True)
        if not fp.exists():
            fp.write_text("a,b\n1,2\n", encoding="utf-8")
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({
            "complete": True,
            "summary": {"high_value_parsed": paths},
        }),
        encoding="utf-8",
    )


def test_catch_all_answered_refused_until_disposed(tmp_path: Path):
    case = tmp_path / "PR"
    paths = [
        "evidence/vpn.csv",
        "evidence/host/Windows/System32/winevt/logs/Security.evtx",
        "evidence/other.csv",
    ]
    _inv(case, paths)
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n"
        "- Identify any other attacker activity in the evidence.\n",
        encoding="utf-8",
    )
    build_coverage_ledger(case)
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    refuse = refuse_answered_unseen_coverage(
        case, "Identify any other attacker activity in the evidence.",
        task_id=tid,
    )
    assert refuse and "relevant_coverage_unseen" in refuse
    cid = _real_claim(case)
    upd = update_task(case, tid, status="answered", related_claim_ids=[cid])
    assert upd.get("success") is False
    assert upd.get("gate") == "task_coverage_disposition"

    mark_paths(case, paths, status="probed")
    assert refuse_answered_unseen_coverage(
        case, "Identify any other attacker activity in the evidence.",
        task_id=tid,
    ) is None
    upd2 = update_task(case, tid, status="answered", related_claim_ids=[cid])
    assert upd2.get("success") is True


def test_narrow_firewall_task_ignores_unrelated_evtx(tmp_path: Path):
    case = tmp_path / "Narrow"
    paths = [
        "evidence/vpn_logons.csv",
        "evidence/host/Windows/System32/winevt/logs/Security.evtx",
    ]
    _inv(case, paths)
    text = (
        "What suspicious activity can be identified on the firewall / "
        "VPN gateway logs, given that AD account svc.vpn is known?"
    )
    (case / "CASE.md").write_text(
        f"## Investigation Requests\n\n- {text}\n",
        encoding="utf-8",
    )
    build_coverage_ledger(case)
    mark_paths(case, ["evidence/vpn_logons.csv"], status="probed")
    # Security.evtx remains unseen — must not block a narrow VPN question.
    relevant = relevant_ledger_units(case, text)
    assert all("Security.evtx" not in str(u.get("path")) for u in relevant) or (
        refuse_answered_unseen_coverage(case, text) is None
    )
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    upd = update_task(case, tid, status="answered",
                      related_claim_ids=[_real_claim(case)])
    assert upd.get("success") is True
    assert not ready_for_degraded_exit(case)  # Security still unseen


def test_fileserver_host_stem_matches_image_tree(tmp_path: Path):
    case = tmp_path / "FS"
    paths = [
        "evidence/FILESRV02-flat.vmdk/Windows/System32/winevt/logs/Security.evtx",
        "evidence/EDR_filesrv01_filecreate.csv",
    ]
    _inv(case, paths)
    text = (
        "What happened on the fileserver FILESRV01 (10.0.0.20), and how "
        "did the files reach D:\\Share?"
    )
    build_coverage_ledger(case)
    refuse = refuse_answered_unseen_coverage(case, text)
    assert refuse and "Security.evtx" in refuse
    mark_paths(case, paths, status="probed")
    assert refuse_answered_unseen_coverage(case, text) is None
