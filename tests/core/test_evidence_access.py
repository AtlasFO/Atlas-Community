"""Evidence Access Stage facade + mount_plan merge / invalidation contracts."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.evidence_access import (
    absence_escape_blocked_by_access,
    is_tsk_open_tool,
    media_blocks_degraded_exit,
    media_entries,
    normalize_media_status,
    parse_tool_result_success,
    pending_media_open,
    record_open_from_tool,
    refuse_blocked_missing_evidence,
    refuse_diskish_answered,
    refuse_duplicate_access_limitation,
    stage_for_path,
)
from core.mount_plan import (
    build_mount_plan,
    invalidate_missing_media,
    load_mount_plan,
    mark_image_access_failed,
    mark_image_opened,
    register_exported_image,
)
from core.coverage_ledger import ready_for_degraded_exit, mark_paths, build_coverage_ledger
from tools._gates import GateContext
from tools._gates import negative_completeness as nc


def _case_with_disk(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (case / ".atlas").mkdir()
    vmdk = ev / "host.vmdk"
    vmdk.write_bytes(b"vmdk-bytes")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "files": [
                {"path": str(vmdk), "class": "disk", "size": 10},
            ],
            "file_count": 1,
            "counts": {"disk": 1},
            "present_classes": ["disk"],
            "absent_classes": ["tabular", "memory"],
            "samples": {},
        }),
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}),
        encoding="utf-8",
    )
    return case


def test_normalize_media_status_matrix():
    assert normalize_media_status("exported", file_exists=True) == "staged"
    assert normalize_media_status("exported", file_exists=False) == "absent"
    assert normalize_media_status("opened", file_exists=True) == "opened"
    assert normalize_media_status("mounted", file_exists=True) == "opened"
    assert normalize_media_status("mount_failed", file_exists=True) == "access_failed"
    assert normalize_media_status("", file_exists=True) == "planned"


def test_export_register_and_stage(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 100)
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))
    entries = media_entries(case)
    assert any(e.get("access_stage") == "staged" for e in entries)
    assert stage_for_path(case, str(raw)) == "staged"
    assert media_blocks_degraded_exit(case) is True


def test_mark_opened_clears_exit_block(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 100)
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))
    assert media_blocks_degraded_exit(case) is True
    mark_image_opened(case, raw, tool="tsk.mmls")
    assert any(e.get("access_stage") == "opened" for e in media_entries(case))
    assert media_blocks_degraded_exit(case) is False


def test_build_mount_plan_merges_export(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 50)
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))
    # Rebuild from profile — must keep export_raw handoff
    plan = build_mount_plan(case, persist=True, auto_mount=False)
    assert any(
        i.get("origin") == "export_raw" and Path(i["path"]).is_file()
        for i in plan.get("images") or []
    )


def test_invalidate_missing_export_after_wipe(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 50)
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))
    raw.unlink()
    inv = invalidate_missing_media(case, persist=True)
    assert inv["changed"] >= 1
    plan = load_mount_plan(case)
    assert not any(i.get("origin") == "export_raw" for i in plan.get("images") or [])


def test_coverage_exit_blocked_while_disk_staged(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    # Add a tabular unit so ledger is non-empty
    csv = case / "evidence" / "edr_lateral.csv"
    csv.write_text("a,b\n1,2\n", encoding="utf-8")
    profile = json.loads(
        (case / ".atlas" / "evidence_profile.json").read_text(encoding="utf-8")
    )
    profile["files"].append(
        {"path": str(csv), "class": "tabular", "size": 10}
    )
    profile["present_classes"] = ["disk", "tabular"]
    profile["counts"] = {"disk": 1, "tabular": 1}
    profile["file_count"] = 2
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps(profile), encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({
            "complete": True,
            "summary": {"high_value_parsed": ["evidence/edr_lateral.csv"]},
        }),
        encoding="utf-8",
    )
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"x" * 20)
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))

    ledger = build_coverage_ledger(case)
    paths = [u["path"] for u in ledger["units"].values()]
    if paths:
        mark_paths(case, paths, status="probed")
    # Tabular probed but disk only staged → exit floor blocked
    assert ready_for_degraded_exit(case) is False
    mark_image_opened(case, raw, tool="tsk.mmls")
    assert ready_for_degraded_exit(case) is True


def test_task_refuse_and_repair(tmp_path: Path):
    from core.investigation_tasks import (
        update_task, load_tasks, save_tasks, empty_tasks,
        repair_tasks_against_access,
    )
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw, source=str(case / "evidence" / "host.vmdk"))

    store = empty_tasks(case.name)
    store["tasks"] = [{
        "id": "task-0001",
        "text": "Open the VMDK disk image and enumerate the filesystem",
        "status": "blocked_missing_evidence",
        "updated_at": "2026-01-01T00:00:00Z",
        "related_claim_ids": [],
    }]
    save_tasks(case, store)
    # Refuse new blocked write
    r = update_task(case, "task-0001", status="blocked_missing_evidence")
    assert r.get("success") is False
    assert r.get("gate") == "task_status_contract"
    # Repair persisted contradiction
    fix = repair_tasks_against_access(case, persist=True)
    assert "task-0001" in fix["repaired"]
    assert load_tasks(case)["tasks"][0]["status"] == "in_progress"


def test_record_open_from_tool(tmp_path: Path):
    """The image is opened when its filesystem opens; reading its partition
    table opens nothing."""
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw)
    record_open_from_tool(
        case,
        tool_name="tsk_mmls",
        cmd_or_args=json.dumps({"image": str(raw)}),
        success=True,
    )
    assert stage_for_path(case, str(raw)) != "opened"
    record_open_from_tool(
        case,
        tool_name="tsk_fsstat",
        cmd_or_args=json.dumps({"image": str(raw), "offset_sectors": 2048}),
        success=True,
    )
    assert stage_for_path(case, str(raw)) == "opened"


def test_mcp_double_prefix_tsk_name_and_json_failure(tmp_path: Path):
    """MCP exposes tsk_tsk_fsstat; JSON success:false must mark access_failed."""
    assert is_tsk_open_tool("tsk_tsk_fsstat")
    assert is_tsk_open_tool("tsk.fls")
    assert not is_tsk_open_tool("tsk_tsk_mmls")
    ok, err = parse_tool_result_success(
        json.dumps({
            "success": False,
            "failure_class": "sudo_auth",
            "stderr": "sudo: a password is required",
        })
    )
    assert ok is False
    assert "sudo" in err.lower() or "sudo_auth" in err

    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    vmdk = case / "evidence" / "host.vmdk"
    register_exported_image(case, raw, source=str(vmdk))
    # Source VMDK stays planned until export is terminal.
    build_mount_plan(case, persist=True, auto_mount=False)
    assert media_blocks_degraded_exit(case) is True

    record_open_from_tool(
        case,
        tool_name="tsk_tsk_fsstat",
        cmd_or_args=json.dumps({"image": str(raw)}),
        success=False,
        error="sudo_auth",
    )
    assert stage_for_path(case, str(raw)) == "access_failed"
    # access_failed on export satisfies source VMDK for pending-open.
    assert not any(
        e.get("path") and Path(e["path"]).name == "host.vmdk"
        for e in pending_media_open(case)
    )
    assert media_blocks_degraded_exit(case) is False


def test_refuse_diskish_answered_while_staged(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw)
    text = "Open the VMDK disk image and reconstruct the fileserver filesystem"
    assert refuse_diskish_answered(case, text)
    mark_image_access_failed(case, raw, error="sudo_auth", tool="tsk.mmls")
    assert refuse_diskish_answered(case, text) is None


def test_vmdk_flat_sibling_settled_when_export_opened(tmp_path: Path):
    """Descriptor + -flat.vmdk both leave pending when raw is opened."""
    case = _case_with_disk(tmp_path)
    # Replace single vmdk with descriptor + flat chain.
    ev = case / "evidence"
    desc = ev / "host.vmdk"
    flat = ev / "host-flat.vmdk"
    flat.write_bytes(b"flat-extent" * 20)
    desc.write_text("# Extent description file\n", encoding="utf-8")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "files": [
                {"path": str(desc), "class": "disk", "size": 10},
                {"path": str(flat), "class": "disk", "size": 200},
            ],
            "file_count": 2,
            "counts": {"disk": 2},
            "present_classes": ["disk"],
            "absent_classes": [],
            "samples": {},
        }),
        encoding="utf-8",
    )
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 100)
    register_exported_image(case, raw, source=str(desc))
    build_mount_plan(case, persist=True, auto_mount=False)
    mark_image_opened(case, raw, tool="tsk.mmls")
    pending = pending_media_open(case)
    assert not any(
        Path(p.get("path") or "").name.endswith((".vmdk",))
        for p in pending
    ), pending
    assert media_blocks_degraded_exit(case) is False


def test_refuse_duplicate_access_limitation(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw)
    mark_image_access_failed(case, raw, error="sudo_auth", tool="tsk.mmls")
    prior = [
        "Documented limitation: tsk.mmls blocked by non-interactive sudo",
    ]
    r = refuse_duplicate_access_limitation(
        case,
        "UNCONFIRMED: EVTX absent / TSK access_failed — investigation limitation",
        existing_finding_texts=prior,
    )
    assert r and "duplicate" in r.lower()


def test_absent_escape_blocked_when_disk_staged(tmp_path: Path):
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw)
    assert absence_escape_blocked_by_access(case)

    log = MagicMock()
    log.case_dir = MagicMock(return_value=str(case))
    tool_calls = [{"type": "tool_call", "cmd": "EvtxECmd -f Security.evtx"}]
    ctx = GateContext(
        description=(
            "No RDP logon for svc_x — TerminalServices logs not present in evidence"
        ),
        confidence="Unconfirmed",
        tier="UNCONFIRMED",
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=log,
        idx=SimpleNamespace(by_call_id={}, by_type={"tool_call": tool_calls}),
        window=[],
        supporting_evidence=(
            "TerminalServices RemoteConnectionManager channel absent from evidence"
        ),
    )
    out = nc.check(ctx)
    assert out is not None
    assert out.get("detail_gate") == "access_not_opened" or "access_not_opened" in (
        out.get("error") or ""
    )


def test_absent_escape_ok_without_disk(tmp_path: Path):
    """No disk media → prose escape still works (tabular-only case)."""
    case = tmp_path / "tab"
    (case / "evidence").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "present_classes": ["tabular"],
            "absent_classes": ["disk"],
            "files": [],
            "counts": {},
            "file_count": 0,
            "samples": {},
        }),
        encoding="utf-8",
    )
    assert absence_escape_blocked_by_access(case) is None
    assert refuse_blocked_missing_evidence(case, "parse CSV") is None


def test_absent_escape_blocked_when_disk_opened_but_winevt_unsearched(tmp_path: Path):
    """Opened disk + 'Security.evtx absent' without winevt search → refuse."""
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 20)
    register_exported_image(case, raw)
    mark_image_opened(case, raw, tool="tsk.mmls")

    log = MagicMock()
    log.case_dir = MagicMock(return_value=str(case))
    # Disk tools ran, but never winevt/Security.
    tool_calls = [
        {"type": "tool_call", "cmd": "mmls analysis/host.raw"},
        {"type": "tool_call", "cmd": "fls -r -o 2048 analysis/host.raw"},
    ]
    ctx = GateContext(
        description=(
            "Security.evtx and TerminalServices channels are not present in "
            "the case evidence bundle; EVTX session inventory cannot be performed."
        ),
        confidence="Unconfirmed",
        tier="UNCONFIRMED",
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=log,
        idx=SimpleNamespace(by_call_id={}, by_type={"tool_call": tool_calls}),
        window=[],
        supporting_evidence=(
            "Security.evtx absent from evidence; no TerminalServices channel"
        ),
    )
    out = nc.check(ctx)
    assert out is not None
    assert out.get("gate") == "negative_completeness"
    err = out.get("error") or ""
    assert "eventlog_not_searched" in err or out.get("detail_gate") == "eventlog_not_searched"
    # The claim names the EVTX layout, so that is the search demanded.
    assert "Security.evtx" in err and "ez.evtxecmd" in err


def test_clear_case_run_invalidates_export(tmp_path: Path):
    from tools.misc import clear_case_run
    case = _case_with_disk(tmp_path)
    analysis = case / "analysis"
    analysis.mkdir()
    raw = analysis / "host.raw"
    raw.write_bytes(b"raw" * 10)
    register_exported_image(case, raw)
    assert any(e.get("origin") == "export_raw" for e in media_entries(case))
    clear_case_run(str(case), clear_memory=False)
    assert not raw.exists()
    assert not any(e.get("origin") == "export_raw" for e in media_entries(case))
