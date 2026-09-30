"""An absence asserted of an opened image is not blocked because another
image in the case is still waiting to be opened. The media check reads what
the claim, its evidence and its cited calls name; a claim naming no medium
is judged against every pending one, as before."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core import evidence_access as ea
from tools._gates import GateContext
from tools._gates import negative_completeness as nc


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    for rel in ("evidence/PC/host_pc.E01", "evidence/RM3/host_rm#3_type1.iso"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"\0" * 16)
    (tmp_path / "mnt" / "host_pc" / "fs").mkdir(parents=True)
    plan = {"schema_version": "1.0", "case_id": "T", "images": [
        {"path": str(tmp_path / "evidence/PC/host_pc.E01"), "basename": "host_pc.E01",
         "stem": "host_pc", "access_gated": True, "media_role": "disk", "image_type": "ewf",
         "status": "mounted",
         "mount_result": {"success": True, "mount_point": str(tmp_path / "mnt/host_pc/fs")}},
        {"path": str(tmp_path / "evidence/RM3/host_rm#3_type1.iso"),
         "basename": "host_rm#3_type1.iso", "stem": "host_rm#3_type1", "access_gated": True,
         "media_role": "disk", "image_type": "iso", "action": "plan_only"},
    ]}
    (tmp_path / ".atlas" / "mount_plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / ".atlas" / "evidence_profile.json").write_text(json.dumps(
        {"schema_version": "1.0", "present_classes": ["disk"], "absent_classes": [],
         "files": [], "counts": {"disk": 2}}), encoding="utf-8")
    return tmp_path


def test_the_case_has_one_opened_and_one_pending_medium(case):
    stages = {e["basename"]: e["access_stage"] for e in ea.media_entries(case)}
    assert stages == {"host_pc.E01": "opened", "host_rm#3_type1.iso": "planned"}


def test_an_absence_about_the_opened_image_is_not_blocked(case):
    about = ("Prefetch on the PC records the shredder; no event-log clearing was "
             "found. PECmd.dll -d " + str(case / "mnt/host_pc/fs/Windows/Prefetch"))
    assert ea.absence_escape_blocked_by_access(case, about_text=about) is None


def test_an_absence_about_the_pending_image_is_blocked_and_names_it(case):
    reason = ea.absence_escape_blocked_by_access(
        case, about_text="no documents are present on the RM#3 disc")
    assert reason and "rm#3" in reason


def test_an_absence_naming_no_medium_is_judged_against_every_pending_one(case):
    reason = ea.absence_escape_blocked_by_access(case, about_text="no event log was cleared")
    assert reason and "access_not_opened" in reason
    assert ea.absence_escape_blocked_by_access(case) == reason


def test_media_labels_are_the_names_a_claim_would_use():
    entry = {"path": "/c/evidence/DC01/E01-DC01/20200918_0347_CDrive.E01",
             "mount_result": {"mount_point": "/c/mnt/20200918_0347_CDrive/fs"}}
    labels = ea.media_labels(entry)
    assert {"e01-dc01", "20200918_0347_cdrive", "20200918_0347_cdrive.e01"} <= labels
    assert "data" not in labels and "0347" not in labels
    assert ea.media_named_in(entry, "no backdoor account was created on DC01")
    assert not ea.media_named_in(entry, "no backdoor account was created on the desktop")


def _ctx(description, cited, case, tier="LIKELY"):
    log = MagicMock()
    log.case_dir.return_value = str(case)
    return GateContext(
        description=description, confidence=tier, tier=tier, source="test",
        linked_call_id=0, tested_hypothesis_id="", log=log,
        idx=SimpleNamespace(by_call_id=cited, by_type={}), window=[],
        input_call_ids=list(cited), supporting_evidence="")


def test_the_gate_reads_the_cited_calls_to_scope_the_claim(case):
    pecmd = {"type": "tool_call", "call_id": 30, "success": True,
             "cmd": "dotnet PECmd.dll -d " + str(case / "mnt/host_pc/fs/Windows/Prefetch"),
             "stdout_excerpt": "ERASER.EXE run 3 times"}
    ctx = _ctx("The Prefetch entries persist; no Security event-log clearing record is "
               "present after the tool ran", {30: pecmd}, case)
    assert nc._absence_before_container_opened(ctx) is None


def test_the_gate_still_blocks_an_absence_about_the_unopened_disc(case):
    strings = {"type": "tool_call", "call_id": 31, "success": True,
               "cmd": "strings -a " + str(case / "evidence/RM3/host_rm#3_type1.iso"),
               "stdout_excerpt": "ISO9660"}
    ctx = _ctx("No Prefetch or event log is present on the RM#3 disc image", {31: strings}, case)
    out = nc._absence_before_container_opened(ctx)
    assert out is not None and out["detail_gate"] == "access_not_opened"
