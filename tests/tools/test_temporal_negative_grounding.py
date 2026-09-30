"""Tests for the temporal_negative_grounding gate.

Temporal negatives ("no activity after <date>", "last active on <date>")
must be corroborated by >= 2 independent artifact classes and are refused
outright when the trace analyzed a snapshot-frozen base VMDK, whose base
flat ends at an earlier snapshot than the host ran to.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools._gates import GateContext
from tools._gates import temporal_negative_grounding as tng


BASE_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=aabbccdd
parentCID=ffffffff
createType="vmfs"
RW 4096 VMFS "HOST-flat.vmdk"
"""

DELTA_DESCRIPTOR = """# Disk DescriptorFile
version=1
CID=11223344
parentCID=aabbccdd
createType="vmfsSparse"
parentFileNameHint="HOST.vmdk"
RW 4096 VMFSSPARSE "HOST-000001-delta.vmdk"
"""


def _ctx(description, cmds=None, *, tier="CONFIRMED",
         supporting_evidence="", stamped_warnings=None, lineage=None):
    """cmds: list of (cmd_str, success_bool) → tool_call entries.

    stamped_warnings: optional list parallel to cmds; a truthy entry stamps
    a vmdk_snapshot_warning on that tool_call (as the executor now does).
    lineage: 0-indexed positions into cmds that the finding CITES
    (input_call_ids). None (default) = the finding derives from ALL listed
    calls; [] = the finding cites nothing (exercises the trace-wide
    fallback). Each tool_call gets call_id = position+1.
    """
    stamped_warnings = stamped_warnings or []
    tool_calls = []
    by_call_id = {}
    for i, (cmd, ok) in enumerate(cmds or []):
        e = {"type": "tool_call", "cmd": cmd, "success": ok, "call_id": i + 1}
        if i < len(stamped_warnings) and stamped_warnings[i]:
            e["vmdk_snapshot_warning"] = stamped_warnings[i]
        tool_calls.append(e)
        by_call_id[i + 1] = e
    if lineage is None:
        input_call_ids = [i + 1 for i in range(len(tool_calls))]
    else:
        input_call_ids = [i + 1 for i in lineage]
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id,
                            by_type={"tool_call": tool_calls}),
        window=[],
        input_call_ids=input_call_ids,
        supporting_evidence=supporting_evidence,
    )


TWO_CLASSES = [
    ("dotnet EvtxECmd.dll -f Security.evtx", True),
    ("dotnet MFTECmd.dll -f $MFT", True),
]


class TestTrigger:
    def test_non_temporal_finding_passes(self):
        assert tng.check(_ctx("Mimikatz executed from C:\\tmp")) is None

    def test_no_activity_after_date_fires(self):
        out = tng.check(_ctx("No activity after 2031-02-04 on the host"))
        assert out is not None
        assert out["gate"] == "temporal_negative_grounding"

    def test_last_active_with_date_and_cue_fires(self):
        out = tng.check(_ctx(
            "System was last active on 04.02.2031, no events thereafter"))
        assert out is not None

    def test_last_active_with_date_no_cue_passes(self):
        # A positive last-observed fact, not a claim of absence-thereafter.
        assert tng.check(_ctx(
            "System was last active on 04.02.2031")) is None

    def test_positive_last_logon_attribution_passes(self):
        # A positive last-observed fact must NOT be gated as a temporal negative.
        assert tng.check(_ctx(
            "The most recent logon on 2031-02-04 was RDP from 10.0.0.5",
            TWO_CLASSES)) is None

    def test_last_logon_without_date_passes(self):
        # "last logon" without a pinned date is not a temporal negative.
        assert tng.check(_ctx("The last logon came from a Tor exit")) is None

    def test_dormant_since_fires(self):
        out = tng.check(_ctx("Host dormant since February 4, 2031"))
        assert out is not None

    def test_no_events_since_fires_via_supporting_evidence(self):
        out = tng.check(_ctx(
            "Host shows no signs of compromise",
            supporting_evidence="no events since 2031-02-04 in System.evtx"))
        assert out is not None


class TestMultiArtifactCorroboration:
    def test_single_artifact_class_refused(self):
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            [("dotnet EvtxECmd.dll -f Security.evtx", True)]))
        assert out is not None
        assert "TWO independent artifact classes" in out["error"]

    def test_failed_calls_do_not_count(self):
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            [("dotnet EvtxECmd.dll -f Security.evtx", True),
             ("dotnet MFTECmd.dll -f $MFT", False)]))
        assert out is not None

    def test_two_classes_pass(self):
        assert tng.check(_ctx("No activity after 2031-02-04",
                              TWO_CLASSES)) is None

    def test_linux_host_can_corroborate(self):
        # A Linux temporal-negative must be satisfiable with Unix artifacts
        # from two DISTINCT classes (auth/session + shell/execution history).
        out = tng.check(_ctx("No activity after 2031-02-04", [
            ("last -f /var/log/wtmp", True),
            ("cat /home/user01/.bash_history", True),
        ]))
        assert out is None

    def test_mft_rule_hunt_corroborates_no_class(self):
        # chainsaw matching names in an $MFT read no event log and no
        # timestamps worth corroborating: it counts as neither class.
        hunt = ("/usr/local/bin/chainsaw --no-banner hunt /case/evidence/$MFT -r "
                "/usr/local/share/chainsaw/rules/mft --load-unknown --skip-errors "
                "--jsonl --output /case/analysis/mft_rule_hunt_MFT_0a1b2c3d.jsonl", True)
        claim = "No activity after 2031-02-04"
        assert tng.check(_ctx(claim, [hunt, ("dotnet EvtxECmd.dll -f Security.evtx", True)])) is not None
        assert tng.check(_ctx(claim, [hunt, ("dotnet MFTECmd.dll -f $MFT", True)])) is not None
        sigma_hunt = ("/usr/local/bin/chainsaw hunt /case/evtx -s "
                      "/usr/local/share/chainsaw/sigma", True)
        assert tng.check(_ctx(claim, [sigma_hunt, ("dotnet MFTECmd.dll -f $MFT", True)])) is None

    def test_linux_single_class_still_refused(self):
        out = tng.check(_ctx("No activity after 2031-02-04", [
            ("last -f /var/log/wtmp", True)]))
        assert out is not None

    def test_fires_on_any_tier(self):
        out = tng.check(_ctx("No logons after 2031-02-04",
                             tier="CONFIRMED"))
        assert out is not None
        out = tng.check(_ctx("No logons after 2031-02-04",
                             tier="UNCONFIRMED"))
        assert out is not None


class TestFrozenVmdkBase:
    @pytest.fixture
    def snapshotted_vm(self, tmp_path):
        (tmp_path / "HOST.vmdk").write_text(BASE_DESCRIPTOR)
        (tmp_path / "HOST-flat.vmdk").write_bytes(b"\x00" * 512)
        (tmp_path / "HOST-000001.vmdk").write_text(DELTA_DESCRIPTOR)
        return tmp_path

    def test_frozen_base_refused_even_with_two_classes(self, snapshotted_vm):
        flat = str(snapshotted_vm / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            TWO_CLASSES + [(f"sudo fls -r {flat}", True)]))
        assert out is not None
        assert "snapshot" in out["error"].lower()
        assert "img_vmdk_chain_info" in out["error"]

    def test_snapshot_aware_wording_escapes(self, snapshotted_vm):
        flat = str(snapshotted_vm / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No activity after 2031-02-04 in the pre-snapshot state "
            "(frozen base; delta chain analyzed separately)",
            TWO_CLASSES + [(f"sudo fls -r {flat}", True)]))
        assert out is None

    def test_vmdk_without_deltas_passes(self, tmp_path):
        (tmp_path / "solo.vmdk").write_text(BASE_DESCRIPTOR)
        solo = str(tmp_path / "solo.vmdk")
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            TWO_CLASSES + [(f"sudo mmls {solo}", True)]))
        assert out is None

    def test_missing_vmdk_path_ignored(self):
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            TWO_CLASSES + [("sudo fls /gone/HOST-flat.vmdk", True)]))
        assert out is None

    def test_stamped_warning_detected_without_path_resolution(self):
        # The executor-stamped warning is authoritative: the gate must fire
        # even when the cmd path is unresolvable from its cwd (the review's
        # relative/unmounted/space-in-path cases).
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            TWO_CLASSES + [("sudo fls -r ./relative/HOST-flat.vmdk", True)],
            stamped_warnings=[None, None,
                              "VMDK SNAPSHOT CHAIN: HOST-flat.vmdk is FROZEN "
                              "... run img_vmdk_chain_info"]))
        assert out is not None
        assert "snapshot" in out["error"].lower()

    def test_quoted_path_with_space_resolved(self, tmp_path):
        share = tmp_path / "My VM"
        share.mkdir()
        (share / "HOST.vmdk").write_text(BASE_DESCRIPTOR)
        (share / "HOST-flat.vmdk").write_bytes(b"\x00" * 512)
        (share / "HOST-000001.vmdk").write_text(DELTA_DESCRIPTOR)
        flat = str(share / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No activity after 2031-02-04",
            TWO_CLASSES + [(f'sudo fls -r "{flat}"', True)]))
        assert out is not None
        assert "snapshot" in out["error"].lower()


class TestFrozenBaseLineageScoping:
    """Branch 1 must scope to the finding's OWN lineage,
    not scan the whole trace — an unrelated orientation read of the flat base
    must not refuse a correct negative derived from a flattened chain-top."""

    @pytest.fixture
    def snapshotted_vm(self, tmp_path):
        (tmp_path / "HOST.vmdk").write_text(BASE_DESCRIPTOR)
        (tmp_path / "HOST-flat.vmdk").write_bytes(b"\x00" * 512)
        (tmp_path / "HOST-000001.vmdk").write_text(DELTA_DESCRIPTOR)
        return tmp_path

    def test_orientation_read_not_in_lineage_passes(self, snapshotted_vm):
        # cmd 0: orientation mmls on the frozen flat (NOT cited by finding)
        # cmds 1,2: real analysis on host.raw (the finding's lineage)
        flat = str(snapshotted_vm / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No logons after 2031-02-04, derived from flattened host.raw",
            [(f"sudo mmls {flat}", True),
             ("dotnet EvtxECmd.dll -f host.raw/Security.evtx", True),
             ("dotnet MFTECmd.dll -f host.raw/$MFT", True)],
            lineage=[1, 2]))          # cites only the host.raw calls
        assert out is None

    def test_frozen_base_in_lineage_still_refused(self, snapshotted_vm):
        # The finding IS derived from the frozen flat → still refused.
        flat = str(snapshotted_vm / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No logons after 2031-02-04",
            [("dotnet EvtxECmd.dll -f Security.evtx", True),
             ("dotnet MFTECmd.dll -f $MFT", True),
             (f"sudo fls -r {flat}", True)],
            lineage=[0, 1, 2]))       # cites the frozen fls too
        assert out is not None
        assert "snapshot" in out["error"].lower()

    def test_no_lineage_falls_back_to_trace_scan(self, snapshotted_vm):
        # A finding citing nothing (rare — lineage_required usually populates
        # it) falls back to the conservative trace-wide scan.
        flat = str(snapshotted_vm / "HOST-flat.vmdk")
        out = tng.check(_ctx(
            "No logons after 2031-02-04",
            TWO_CLASSES + [(f"sudo fls -r {flat}", True)],
            lineage=[]))
        assert out is not None
        assert "snapshot" in out["error"].lower()

    def test_stamped_warning_only_via_lineage(self, snapshotted_vm):
        # Executor-stamped frozen call present but NOT cited → passes.
        out = tng.check(_ctx(
            "No logons after 2031-02-04, from host.raw",
            [("sudo mmls ./HOST-flat.vmdk", True),
             ("dotnet EvtxECmd.dll -f host.raw/Security.evtx", True),
             ("dotnet MFTECmd.dll -f host.raw/$MFT", True)],
            stamped_warnings=["VMDK SNAPSHOT CHAIN: ... img_vmdk_chain_info",
                              None, None],
            lineage=[1, 2]))
        assert out is None
