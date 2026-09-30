"""Task status transitions must respect staged disk access."""
from __future__ import annotations

import json


def test_blocked_missing_evidence_refused_when_raw_exported(tmp_path):
    from core.investigation_tasks import update_task, save_tasks
    from core.mount_plan import register_exported_image

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    raw = case / "analysis" / "host.raw"
    raw.write_bytes(b"\x00" * 128)
    register_exported_image(case, raw, source=str(case / "evidence" / "d.vmdk"))
    save_tasks(case, {
        "schema_version": "1.0",
        "case_id": "case",
        "tasks": [{
            "id": "task-0002",
            "text": "Reconstruct activity on the fileserver using the VMDK disk image",
            "status": "in_progress",
            "related_claim_ids": [],
        }],
        "next_id": 3,
    })
    r = update_task(case, "task-0002", status="blocked_missing_evidence")
    assert r["success"] is False
    assert r.get("gate") == "task_status_contract"
    assert "tsk.mmls" in r["error"]


def test_blocked_missing_evidence_allowed_for_non_disk_task(tmp_path):
    from core.investigation_tasks import update_task, save_tasks

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    save_tasks(case, {
        "schema_version": "1.0",
        "case_id": "case",
        "tasks": [{
            "id": "task-0001",
            "text": "Review VPN gateway logs for svc.vpn",
            "status": "in_progress",
            "related_claim_ids": [],
        }],
        "next_id": 2,
    })
    r = update_task(case, "task-0001", status="blocked_missing_evidence")
    assert r["success"] is True
    assert r["task"]["status"] == "blocked_missing_evidence"
