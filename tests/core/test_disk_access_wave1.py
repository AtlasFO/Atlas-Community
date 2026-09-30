""": disk-open authority, export handoff, loop/FUSE demotion."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


def test_manifest_includes_tsk_mmls():
    from tools.tool_capabilities import allowed_tool_names, tool_capability_manifest

    names = allowed_tool_names()
    assert "tsk.mmls" in names
    disk = next(
        c for c in tool_capability_manifest()["capabilities"]
        if c["id"] == "disk_filesystem_timeline"
    )
    assert disk["tools"][2] == "tsk.mmls" or "tsk.mmls" in disk["tools"]
    # Orientation tool must appear before deep fls in the vocabulary list
    assert disk["tools"].index("tsk.mmls") < disk["tools"].index("tsk.fls")


def test_disk_open_tool_for_path():
    from core.runtime_capabilities import disk_open_tool_for_path

    assert disk_open_tool_for_path("evidence/x.vmdk") == "img.vmdk_chain_info"
    assert disk_open_tool_for_path("analysis/x.raw") == "tsk.mmls"
    assert disk_open_tool_for_path("evidence/x.E01") == "ewf.mount_full_image"


def test_register_exported_image_updates_mount_plan(tmp_path: Path):
    from core.mount_plan import register_exported_image, load_mount_plan

    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas").mkdir()
    raw = case / "analysis" / "host.raw"
    raw.write_bytes(b"\x00" * 16)

    plan = register_exported_image(
        case, raw, source=str(case / "evidence" / "host.vmdk"),
    )
    assert any(i.get("recommended_tool") == "tsk.mmls" for i in plan["images"])
    loaded = load_mount_plan(case)
    entry = next(i for i in loaded["images"] if str(i["path"]).endswith("host.raw"))
    assert entry["origin"] == "export_raw"
    assert entry["recommended_tool"] == "tsk.mmls"
    assert "losetup" not in (entry.get("reason") or "").lower() or "avoid" in (
        entry.get("reason") or ""
    ).lower()


def test_loop_fuse_demoted_in_triage():
    from core.runtime_capabilities import loop_fuse_demotion_refusal

    with patch("core.runtime_capabilities.current_dair_phase",
               return_value="Triage"), \
         patch("core.runtime_capabilities.tsk_disk_open_attempted",
               return_value=False):
        r = loop_fuse_demotion_refusal("img_losetup_create")
    assert r is not None
    assert r["gate"] == "disk_open_policy"
    assert r["recommended_tool"] == "tsk.mmls"


def test_loop_fuse_allowed_after_tsk_or_collect():
    from core.runtime_capabilities import loop_fuse_demotion_refusal

    with patch("core.runtime_capabilities.current_dair_phase",
               return_value="Triage"), \
         patch("core.runtime_capabilities.tsk_disk_open_attempted",
               return_value=True), \
         patch("core.runtime_capabilities._export_raw_registered",
               return_value=False):
        assert loop_fuse_demotion_refusal("img_losetup_create") is None

    # Collect without a pending export_raw → loop/FUSE allowed
    with patch("core.runtime_capabilities.current_dair_phase",
               return_value="Collect"), \
         patch("core.runtime_capabilities.tsk_disk_open_attempted",
               return_value=False), \
         patch("core.runtime_capabilities._export_raw_registered",
               return_value=False):
        assert loop_fuse_demotion_refusal("img_xmount_image") is None

    #: export registered but TSK not opened yet → still demoted
    with patch("core.runtime_capabilities.current_dair_phase",
               return_value="Collect"), \
         patch("core.runtime_capabilities.tsk_disk_open_attempted",
               return_value=False), \
         patch("core.runtime_capabilities._export_raw_registered",
               return_value=True):
        r = loop_fuse_demotion_refusal("img_losetup_create")
        assert r is not None
        assert r["gate"] == "disk_open_policy"


def test_dair_default_orders_prefer_tsk_not_mount():
    from tools.dair import _DEFAULT_WORK_ORDERS

    flat = {cue: order for cues, order in _DEFAULT_WORK_ORDERS for cue in cues}
    assert flat[".vmdk"][0] == "img.vmdk_chain_info"
    assert "tsk.mmls" in flat[".vmdk"]
    assert flat[".raw"][0] == "tsk.mmls"
    assert flat[".raw"][0] != "ewf.mount_full_image"
