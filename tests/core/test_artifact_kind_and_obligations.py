"""Artifact classer, finish honesty, winevt obligations."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from core.artifact_kind import (
    is_access_gated_disk_media,
    is_non_disk_container,
    media_role_for_path,
)
from core.evidence_access import (
    absence_escape_blocked_for_winevt,
    media_blocks_degraded_exit,
    media_entries,
    stage_for_path,
)
from core.evidence_noise import claim_report_role, looks_like_process_or_hypothesis_note
from core.investigation_exit import classify_finish_status
from core.investigation_obligations import (
    case_needs_windows_session_auth,
    obligations_met_for_complete,
)
from core.mount_plan import build_mount_plan, load_mount_plan, register_exported_image
from core.evidence_profile import classify_path


def test_non_disk_raw_classer_generic():
    assert is_non_disk_container("evidence/modules/SRUM/SRUDB.INTEG.RAW")
    assert is_non_disk_container("/case/evidence/foo/SRUDB.dat")
    assert is_non_disk_container("evidence/hiberfil.sys.raw")
    assert media_role_for_path("evidence/modules/SRUM/SRUDB.INTEG.RAW") == "database"
    assert not is_access_gated_disk_media(
        "evidence/modules/SRUM/SRUDB.INTEG.RAW"
    )
    # Real disk images stay gated
    assert is_access_gated_disk_media("evidence/host.vmdk")
    assert is_access_gated_disk_media("evidence/disk.e01")
    assert not is_non_disk_container("analysis/host.raw")


def test_classify_path_srum_not_disk(tmp_path: Path):
    p = tmp_path / "evidence" / "modules" / "SRUM" / "SRUDB.INTEG.RAW"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"x" * 20)
    assert classify_path(p) == "file"


def test_mount_plan_excludes_srum_raw(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence" / "modules" / "SRUM"
    ev.mkdir(parents=True)
    srum = ev / "SRUDB.INTEG.RAW"
    srum.write_bytes(b"rawdb" * 10)
    vmdk = case / "evidence" / "host.vmdk"
    vmdk.write_bytes(b"vmdk")
    (case / ".atlas").mkdir()
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "files": [
                {"path": str(srum), "class": "disk", "size": 40},
                {"path": str(vmdk), "class": "disk", "size": 4},
            ],
            "present_classes": ["disk"],
            "counts": {"disk": 2},
            "file_count": 2,
            "samples": {},
        }),
        encoding="utf-8",
    )
    # Poison prior mount_plan with SRUDB (legacy dual-run failure mode)
    (case / ".atlas" / "mount_plan.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "images": [{
                "path": str(srum),
                "status": "",
                "action": "plan_only",
                "recommended_tool": "tsk.mmls",
                "image_type": "raw_or_container",
            }],
        }),
        encoding="utf-8",
    )
    plan = build_mount_plan(case, persist=True, auto_mount=False)
    paths = [str(i.get("path")) for i in plan.get("images") or []]
    assert not any("SRUDB" in p for p in paths)
    assert any(p.endswith("host.vmdk") for p in paths)
    # Access Stage must ignore leftover SRUDB rows
    assert not any(
        "SRUDB" in str(e.get("path")) for e in media_entries(case)
    )
    assert stage_for_path(case, str(srum)) == "direct"


def test_srum_does_not_block_exit_when_real_disk_opened(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / ".atlas").mkdir()
    vmdk = ev / "host.vmdk"
    vmdk.write_bytes(b"vmdk")
    srum = ev / "modules" / "SRUM" / "SRUDB.INTEG.RAW"
    srum.parent.mkdir(parents=True)
    srum.write_bytes(b"db" * 20)
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [
                {"path": str(vmdk), "class": "disk", "size": 4},
                {"path": str(srum), "class": "file", "size": 40},
            ],
            "present_classes": ["disk"],
            "counts": {"disk": 1},
            "file_count": 2,
            "samples": {},
        }),
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8",
    )
    # Legacy poison row
    (case / ".atlas" / "mount_plan.json").write_text(
        json.dumps({
            "images": [
                {"path": str(srum), "action": "plan_only", "status": ""},
                {"path": str(vmdk), "action": "plan_only", "status": "opened"},
            ]
        }),
        encoding="utf-8",
    )
    assert media_blocks_degraded_exit(case) is False


def test_winevt_absent_escape_blocked_when_disk_opened(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / ".atlas").mkdir()
    vmdk = ev / "host.vmdk"
    vmdk.write_bytes(b"vmdk")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [{"path": str(vmdk), "class": "disk", "size": 4}],
            "present_classes": ["disk"],
            "counts": {"disk": 1},
            "file_count": 1,
            "samples": {},
        }),
        encoding="utf-8",
    )
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"x" * 50)
    register_exported_image(case, raw, source=str(vmdk))
    from core.mount_plan import mark_image_opened
    mark_image_opened(case, raw, tool="tsk.mmls")
    # An opened disk whose listings never showed an event-log layout has
    # nothing to demand: the escape stays open rather than asking for a
    # search of artifacts the media may not hold.
    assert absence_escape_blocked_for_winevt(case, cmds=[
        {"cmd": "fls -o 1 analysis/host.raw"},
    ]) is None
    # Once a listing has shown the layout, its log must have been searched.
    listing = {"cmd": "fls -o 1 analysis/host.raw 1234", "success": True,
               "stdout_excerpt": "d/d 5678: Windows/System32/winevt/Logs"}
    reason = absence_escape_blocked_for_winevt(case, cmds=[listing])
    assert reason and "eventlog_not_searched" in reason
    assert "Security.evtx" in reason
    ok = absence_escape_blocked_for_winevt(case, cmds=[
        listing, {"cmd": "ez_evtxecmd -f .../winevt/logs/Security.evtx"},
    ])
    assert ok is None


def test_complete_requires_unseen_zero_despite_soft_floor(tmp_path: Path):
    """A task soft floor must not yield complete while units stay unseen."""
    case = tmp_path / "case"
    case.mkdir()
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text(
        "Investigate logon sessions and VPN.\n", encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True}), encoding="utf-8",
    )
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [],
            "present_classes": ["tabular"],
            "counts": {"tabular": 1},
            "file_count": 1,
            "samples": {},
        }),
        encoding="utf-8",
    )
    (case / ".atlas" / "coverage_ledger.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "units": {
                "u1": {"path": "evidence/vpn_auth.csv", "status": "unseen"},
                "u2": {"path": "evidence/a.csv", "status": "answered"},
            },
            "meta": {"unit_count": 2},
        }),
        encoding="utf-8",
    )
    (case / ".atlas" / "investigation_tasks.json").write_text(
        json.dumps({
            "tasks": [{
                "id": "task-0001",
                "status": "answered",
                "text": "VPN review",
                "related_claim_ids": ["C0001"],
            }],
        }),
        encoding="utf-8",
    )
    (case / ".atlas" / "claim_graph.json").write_text(
        json.dumps({
            "nodes": {
                "C0001": {
                    "id": "C0001",
                    "kind": "claim",
                    "status": "new",
                    "statement": "VPN used",
                    "confidence": "LIKELY",
                }
            }
        }),
        encoding="utf-8",
    )

    with patch(
        "core.investigation_state.build_current_investigation_state",
        return_value={
            "has_beliefs": True,
            "counts": {"investigation_tasks_actionable": 0},
        },
    ):
        status = classify_finish_status(
            "finished",
            case_dir=case,
            report_written=True,
            synthesize_ok=True,
            pre_report_ready=True,
        )
    assert status == "incomplete_coverage"


def test_obligations_require_winevt_when_disk_auth_case(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text(
        "What happened on the host? Reconstruct VPN and logon sessions.\n",
        encoding="utf-8",
    )
    vmdk = ev / "host.vmdk"
    vmdk.write_bytes(b"vmdk")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [{"path": str(vmdk), "class": "disk", "size": 4}],
            "present_classes": ["disk"],
            "counts": {"disk": 1},
            "file_count": 1,
            "samples": {},
        }),
        encoding="utf-8",
    )
    assert case_needs_windows_session_auth(case)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"x" * 40)
    register_exported_image(case, raw, source=str(vmdk))
    from core.mount_plan import mark_image_opened
    mark_image_opened(case, raw, tool="tsk.mmls")
    assert obligations_met_for_complete(case) is False
    # Simulate winevt search in trace
    (analysis / "case_trace.jsonl").write_text(
        json.dumps({
            "entry": {
                "type": "tool_call",
                "cmd": "icat ... Windows/System32/winevt/logs/Security.evtx",
                "mcp_tool": "tsk_tsk_icat",
            }
        }) + "\n",
        encoding="utf-8",
    )
    assert obligations_met_for_complete(case) is True


def test_process_notes_report_role():
    assert looks_like_process_or_hypothesis_note(
        "Coverage-ledger: numerous high-value evidence units remain unexamined"
    )
    assert claim_report_role(
        "Hypothesis H0001 remains unresolved for controller attribution"
    ) == "process"
    assert claim_report_role(
        "User01 had multiple network logons (EventID 4624) from 10.0.0.101"
    ) == "evidence"


def test_export_work_order_mentions_winevt(tmp_path: Path):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / ".atlas").mkdir()
    vmdk = case / "evidence" / "host.vmdk"
    vmdk.write_bytes(b"v")
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw, source=str(vmdk))
    plan = load_mount_plan(case)
    exp = next(i for i in plan["images"] if i.get("origin") == "export_raw")
    assert "winevt" in (exp.get("reason") or "").lower()
    assert "Security.evtx" in " ".join(exp.get("next_work_order") or [])
