"""An artifact inside an unopened disk image cannot be declared absent.

A run can open with the inventory reporting no EVTX — true of the evidence
*folder*, false of the disks in it — and record "no Security.evtx, no
System.evtx, no Prefetch" as a SUSPECTED finding. The access guard must
refuse that at every tier, not only for UNCONFIRMED findings inside a
manifest category, or the claim becomes the premise for the rest of the run.
"""
from __future__ import annotations

import json

import pytest

from tools._gates import negative_completeness as nc


def _case(tmp_path, *, status="planned"):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    (case / "evidence" / "FILESRV01.vmdk").write_bytes(b"x" * 1024)
    (case / ".atlas" / "mount_plan.json").write_text(json.dumps({
        "images": [{"path": "evidence/FILESRV01.vmdk", "status": status,
                    "role": "disk"}]}), encoding="utf-8")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({"present_classes": ["disk"]}), encoding="utf-8")
    return case


def _ctx(case, description, tier="SUSPECTED", supporting=""):
    class _Log:
        def case_dir(self):
            return str(case)

    class _Ctx:
        pass

    c = _Ctx()
    c.description = description
    c.tier = tier
    c.confidence = tier
    c.supporting_evidence = supporting
    c.log = _Log()
    c.entries = []
    return c


ABSENCE_CLAIM = ("Standard Windows forensic artifacts are absent from FILESRV01: "
        "no Security.evtx, no System.evtx, no Application.evtx, no Prefetch "
        "directory, no Amcache.")


class TestRefusesUnearnedAbsence:
    @pytest.mark.parametrize("tier", ["SUSPECTED", "LIKELY", "UNCONFIRMED",
                                      "CONFIRMED"])
    def test_confidence_does_not_repair_an_unopened_container(
            self, tmp_path, tier):
        """Every tier — asserting it more confidently does not make the
        unexamined image any more examined."""
        out = nc._absence_before_container_opened(_ctx(_case(tmp_path), ABSENCE_CLAIM, tier))
        assert out is not None
        assert out["gate"] == "negative_completeness"

    def test_the_refusal_says_what_to_do(self, tmp_path):
        out = nc._absence_before_container_opened(_ctx(_case(tmp_path), ABSENCE_CLAIM))
        assert "inside the image" in out["error"]
        assert "tsk.fls" in out["error"]

    def test_the_full_gate_refuses_it_too(self, tmp_path):
        """Reached through check(), not just the helper."""
        out = nc.check(_ctx(_case(tmp_path), ABSENCE_CLAIM, "SUSPECTED"))
        assert out is not None and out["gate"] == "negative_completeness"

    @pytest.mark.parametrize("text", [
        "No EVTX evidence is present in this case.",
        "The registry hives were not collected from this host.",
        "No $MFT is available for CORP-DC01.",
        "Prefetch is missing on this system.",
    ])
    def test_other_disk_resident_families(self, tmp_path, text):
        assert nc._absence_before_container_opened(_ctx(_case(tmp_path), text))


class TestLeavesLegitimateClaimsAlone:
    """Over-blocking here would stop real findings being recorded."""

    def test_absence_in_evidence_beside_the_image_is_fine(self, tmp_path):
        """Firewall logs sit next to the disk, not inside it."""
        out = nc._absence_before_container_opened(_ctx(
            _case(tmp_path),
            "Firewall logs show only internal traffic; no external "
            "destination was observed."))
        assert out is None

    def test_a_positive_finding_is_untouched(self, tmp_path):
        out = nc._absence_before_container_opened(_ctx(
            _case(tmp_path),
            "Security.evtx shows event 4624 for jane.doe at 12:00 UTC.",
            "LIKELY"))
        assert out is None

    def test_once_the_image_is_opened_the_claim_is_allowed(self, tmp_path):
        """The whole point: examine it, then you may conclude absence."""
        out = nc._absence_before_container_opened(
            _ctx(_case(tmp_path, status="opened"), ABSENCE_CLAIM))
        assert out is None

    def test_access_failed_collection_still_excuses_it(self, tmp_path):
        """A genuinely unreadable image must not trap the run forever."""
        out = nc._absence_before_container_opened(
            _ctx(_case(tmp_path, status="access_failed"), ABSENCE_CLAIM))
        assert out is None

    def test_a_case_with_no_disk_media_is_untouched(self, tmp_path):
        case = tmp_path / "nodisk"
        (case / ".atlas").mkdir(parents=True)
        (case / "evidence").mkdir()
        assert nc._absence_before_container_opened(_ctx(case, ABSENCE_CLAIM)) is None
