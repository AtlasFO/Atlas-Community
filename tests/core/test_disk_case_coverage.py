"""Coverage and the evidence profile on a disk-image case.

On a VMDK case Atlas can extract Security.evtx and the MFT, parse them to CSV,
and then neither see nor query its own output. Every check below is one of
the ways that happens — the whole failure is a single assumption (evidence
lives under ``evidence/``) written into five separate places.
"""
import json

import pytest

from core.coverage_ledger import (
    _norm_rel, build_coverage_ledger, coverage_stats, load_ledger,
    observe_tool_paths, open_unit_paths,
)
from core.evidence_profile import ensure_evidence_profile
from core.evidence_catalog import is_atlas_output


CSV = "RecordNumber,EventId,TimeCreated\n1,4624,2031-02-04T12:00:00Z\n"


@pytest.fixture
def disk_case(tmp_path):
    """A disk-image case: VMDKs in, extracts out."""
    case = tmp_path / "CASE-B"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    (case / "exports").mkdir()
    # Intake: raw containers only — nothing queryable.
    (case / "evidence" / "VM01.vmdk").write_bytes(b"\0" * 512)
    # What the run carved out of them.
    (case / "exports" / "vm01_Security.evtx").write_bytes(b"ElfFile\0" * 8)
    (case / "analysis" / "vm01_security_evtx.csv").write_text(CSV)
    (case / "analysis" / "vm01_mft.csv").write_text("Path,Size\nC:\\x,1\n")
    return case


# ── the reported bug ─────────────────────────────────────────────────────

def test_disk_case_seeds_units_from_run_extracts(disk_case):
    """The bug as reported: ledger stayed at units {} / unit_count 0."""
    ledger = build_coverage_ledger(disk_case)
    assert ledger["meta"]["unit_count"] > 0
    paths = {u["path"] for u in ledger["units"].values()}
    assert "analysis/vm01_security_evtx.csv" in paths
    assert "exports/vm01_Security.evtx" in paths


def test_a_rebuild_seeds_no_unit_from_what_the_run_wrote_since(disk_case):
    """The run's own outputs are covered by lineage, not by re-scanning:
    a query result it wrote out, or an archive it unpacked, must not come
    back from a rebuild as unseen sources the report has to wait for."""
    first = build_coverage_ledger(disk_case)
    (disk_case / "analysis" / "dc01_kerberos_filtered.csv").write_text(CSV)
    unpacked = disk_case / "analysis" / "installer_contents"
    unpacked.mkdir()
    (unpacked / "manifest.json").write_text("{}")
    (unpacked / "app.log").write_text("started\n")
    again = build_coverage_ledger(disk_case)
    assert set(again["units"]) == set(first["units"])
    assert "analysis/vm01_security_evtx.csv" in {u["path"] for u in again["units"].values()}


def test_every_unit_points_at_a_file_that_exists(disk_case):
    """Seeding units nobody can probe is worse than seeding none.

    ``_norm_rel`` forced every path under ``evidence/``, so a unit for an
    extract named a file that was never there — permanently unseen, and the
    coverage floor could never be met.
    """
    for unit in build_coverage_ledger(disk_case)["units"].values():
        assert (disk_case / unit["path"]).exists(), unit["path"]


@pytest.mark.parametrize("raw, expect", [
    ("analysis/x.csv", "analysis/x.csv"),
    ("exports/y.evtx", "exports/y.evtx"),
    ("./analysis/b.csv", "analysis/b.csv"),
    ("evidence/a.csv", "evidence/a.csv"),
    ("MFT.csv", "evidence/MFT.csv"),          # bare name: evidence by convention
    ("/srv/cases/C/analysis/z.csv", "analysis/z.csv"),
])
def test_norm_rel_can_name_every_case_directory(raw, expect):
    assert _norm_rel(raw) == expect


# ── the unit has to be markable ──────────────────────────────────────────

def test_probe_of_an_extract_marks_its_unit(disk_case):
    build_coverage_ledger(disk_case)
    before = coverage_stats(load_ledger(disk_case))["unseen"]
    observe_tool_paths(
        disk_case, tool_name="table_table_grep",
        cmd_or_args=json.dumps({"path": "analysis/vm01_security_evtx.csv",
                                "pattern": "4624"}),
        success=True,
        result_text=json.dumps({"success": True, "matched_rows": 200}))
    after = load_ledger(disk_case)
    assert coverage_stats(after)["unseen"] == before - 1
    unit = next(u for u in after["units"].values()
                if u["path"] == "analysis/vm01_security_evtx.csv")
    assert unit["status"] == "probed"


def test_forged_zero_row_probe_still_does_not_count(disk_case):
    """The anti-forgery guard has to survive the wider path matching."""
    build_coverage_ledger(disk_case)
    before = coverage_stats(load_ledger(disk_case))
    observe_tool_paths(
        disk_case, tool_name="table_table_grep",
        cmd_or_args=json.dumps({"path": "analysis/vm01_mft.csv"}),
        success=True,
        result_text=json.dumps({"success": True, "matched_rows": 0}))
    assert coverage_stats(load_ledger(disk_case)) == before


def test_open_units_give_the_agent_real_targets(disk_case):
    build_coverage_ledger(disk_case)
    targets = open_unit_paths(disk_case)
    assert targets
    for t in targets:
        assert (disk_case / t).exists()


# ── the profile has to see what the run produced ─────────────────────────

def test_extracts_make_their_classes_present(disk_case):
    """`tabular`/`windows_eventlog` were absent while the CSVs sat on disk."""
    profile = ensure_evidence_profile(str(disk_case), refresh=True)
    assert "tabular" in profile["present_classes"]
    assert "windows_eventlog" in profile["present_classes"]
    assert "disk" in profile["present_classes"]        # intake still counted
    for cls in ("tabular", "windows_eventlog"):
        assert cls not in profile["absent_classes"]


def test_intake_inventory_is_left_alone(disk_case):
    """file_count feeds the staleness check against the evidence catalog."""
    profile = ensure_evidence_profile(str(disk_case), refresh=True)
    assert profile["file_count"] == 1                  # the VMDK only
    assert all(f["path"].startswith("evidence/") for f in profile["files"])
    assert profile["derived_file_count"] == 3


def test_compat_gate_stops_refusing_tools_on_our_own_extracts(disk_case):
    """A gate that refuses table_table_grep on the run's own extracts leaves
    every derived CSV unqueryable."""
    from tools.evidence_compat import check_tool_against_profile
    profile = ensure_evidence_profile(str(disk_case), refresh=True)
    assert check_tool_against_profile("table_table_grep", profile) is None
    # ...and the gate still does its job for classes that really are absent.
    assert check_tool_against_profile("vol_pslist", profile) is not None


def test_profile_notices_new_extracts(disk_case):
    """Frozen-at-intake was the root cause; drift has to reopen it."""
    first = ensure_evidence_profile(str(disk_case), refresh=True)
    assert first["derived_file_count"] == 3
    import os
    import time
    time.sleep(0.02)
    (disk_case / "analysis" / "dc01_amcache.csv").write_text(CSV)
    os.utime(disk_case / "analysis", None)
    again = ensure_evidence_profile(str(disk_case))   # no refresh= flag
    assert again["derived_file_count"] == 4


# ── Atlas's own output is not evidence ───────────────────────────────────

@pytest.mark.parametrize("rel", [
    "analysis/CASE-B_trace.json",
    "analysis/agent_transcript_20310204T120000Z.jsonl",
    "analysis/chat_transcript_20310204T120000Z.jsonl",
    "analysis/brain_injection.json",
    "analysis/dashboard.url",
    ".atlas/coverage_ledger.json",
])
def test_run_bookkeeping_is_not_evidence(rel):
    assert is_atlas_output(rel)


@pytest.mark.parametrize("rel", [
    "analysis/vm01_security_evtx.csv",
    "exports/dc01_Security.evtx",
    "evidence/VM01.vmdk",
])
def test_real_artifacts_are_evidence(rel):
    assert not is_atlas_output(rel)


def test_transcript_alone_never_grants_a_class(tmp_path):
    """A case whose only 'tabular' file is Atlas's own transcript has none."""
    case = tmp_path / "C"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    (case / "evidence" / "img.vmdk").write_bytes(b"\0" * 16)
    (case / "analysis" / "agent_transcript_x.jsonl").write_text('{"a":1}\n')
    profile = ensure_evidence_profile(str(case), refresh=True)
    assert "tabular" not in profile["present_classes"]
    # The image is a unit — it is intake the run still has to open. Atlas's
    # own transcript is not, and never becomes one.
    paths = {u["path"] for u in build_coverage_ledger(case)["units"].values()}
    assert paths == {"evidence/img.vmdk"}


# ── the container itself is coverage ──────────────────────────────────────

def test_the_image_the_case_was_given_is_a_unit(disk_case):
    """A floor that cannot see the disk image reports a coverage it lacks.

    A ledger that holds only the queryable intake files answers "all probed,
    none unseen" while a large image was never opened — and the close-out
    takes that as a clean bill.
    """
    ledger = build_coverage_ledger(disk_case)
    units = {u["path"]: u for u in ledger["units"].values()}
    assert "evidence/VM01.vmdk" in units, "the image must be a unit"
    assert units["evidence/VM01.vmdk"]["kind"] == "container"
    assert units["evidence/VM01.vmdk"]["status"] == "unseen"
    assert "evidence/VM01.vmdk" in open_unit_paths(disk_case)


def test_working_on_the_raw_export_covers_the_image_it_came_from(disk_case):
    """After an export the run stops naming the image, so the mount plan is
    what ties the work back to the container."""
    build_coverage_ledger(disk_case)
    (disk_case / "exports" / "VM01.raw").write_bytes(b"\0" * 512)
    (disk_case / ".atlas" / "mount_plan.json").write_text(json.dumps({
        "images": [{
            "path": str(disk_case / "exports" / "VM01.raw"),
            "source": "evidence/VM01.vmdk",
            "origin": "export_raw",
        }],
    }), encoding="utf-8")

    observe_tool_paths(
        disk_case, tool_name="tsk_tsk_fls",
        cmd_or_args="fls -r -o 2048 exports/VM01.raw", success=True,
    )
    units = {u["path"]: u for u in load_ledger(disk_case)["units"].values()}
    assert units["evidence/VM01.vmdk"]["status"] == "probed"
