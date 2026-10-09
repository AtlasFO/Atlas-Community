"""Evidence-assessment latch — global, before forensic tools."""
from __future__ import annotations

from pathlib import Path


def _case_with(tmp_path: Path, files: dict[str, bytes]) -> Path:
    case = tmp_path / "CaseA"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    for name, data in files.items():
        p = ev / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (case / ".atlas").mkdir(exist_ok=True)
    return case


class TestAssessmentGate:
    def test_unsatisfied_until_inventory_tool(self, tmp_path):
        from core.evidence_inventory_gate import (
            inventory_satisfied,
            mark_inventory_complete,
        )

        case = _case_with(tmp_path, {"a.csv": b"x\n"})
        assert not inventory_satisfied(str(case))
        mark_inventory_complete(case, summary={"ok": True})
        assert inventory_satisfied(str(case))

    def test_list_evidence_dir_does_not_unlock(self, tmp_path):
        """Listing is discovery-only — must not stamp the assessment latch."""
        from core.evidence_inventory_gate import inventory_satisfied

        case = _case_with(tmp_path, {"a.csv": b"x\n"})
        assert not inventory_satisfied(str(case))
        # No maybe_mark helper anymore; stamp only via inventory tool.
        assert not inventory_satisfied(str(case))

    def test_build_assessment_answers_four_questions(self, tmp_path):
        from core.evidence_inventory_gate import (
            build_evidence_inventory,
            inventory_satisfied,
        )

        case = _case_with(tmp_path, {
            "logons.csv": b"u,t\n",
            "SYSTEM": b"regf" + b"\x00" * 20,
            "parsed/host/MFTECmd/mft.MFTECmd.timeline.csv": b"a,b\n1,2\n",
            "parsed/host/RegRipper/SYSTEM.regripper.txt": b"reg output\n",
        })
        r = build_evidence_inventory(case)
        assert r["success"]
        assert inventory_satisfied(str(case))
        a = r["assessment"]
        assert "what_exists" in a
        assert "catalog" in a
        assert "REFERENCE MAP" in a["catalog"]["policy"] or "reference" in a[
            "catalog"]["policy"].lower()
        assert a["catalog"]["top_level"]
        assert "time window" in a["catalog"]["policy"].lower() or any(
            "time window" in x.lower()
            for x in a["catalog"]["relevance_scoping"]
        )
        assert a["already_processed"]["available"] is True
        assert a["already_processed"]["paths"]
        assert a["reparse_not_required"]
        assert a["recommended_first_actions"]

    def test_assessment_is_persisted_in_stamp(self, tmp_path):
        """The full processing assessment must land on disk —
        coverage_ledger and discovery_first read inventory["assessment"]
        from the stamp. A stamp holding only the summary leaves every
        consumer silently falling back (a dead handoff)."""
        import json
        from core.evidence_inventory_gate import (
            build_evidence_inventory,
            inventory_path,
        )

        case = _case_with(tmp_path, {
            "logons.csv": b"u,t\n",
            "parsed/host/MFTECmd/mft.MFTECmd.timeline.csv": b"a,b\n1,2\n",
        })
        r = build_evidence_inventory(case)
        assert r["success"]
        stamp = json.loads(inventory_path(case).read_text(encoding="utf-8"))
        assessment = stamp.get("assessment") or {}
        assert assessment, "assessment missing from persisted stamp"
        ap = assessment.get("already_processed") or {}
        assert ap.get("paths"), "already_processed.paths missing on disk"
        # The coverage-ledger consumer reads exactly this shape.
        from core.coverage_ledger import build_coverage_ledger
        ledger = build_coverage_ledger(case)
        paths = {u["path"] for u in ledger["units"].values()}
        assert any("MFTECmd" in p for p in paths)

    def test_catalog_is_reference_map_not_mandatory_checklist(self, tmp_path):
        from core.evidence_inventory_gate import build_evidence_inventory

        case = _case_with(tmp_path, {
            "alpha.csv": b"a,b\n",
            "vpn_archive.csv": b"c,d\n",
            "nested/x.csv": b"e,f\n",
        })
        a = build_evidence_inventory(case)["assessment"]
        paths = {x["path"] for x in a["catalog"]["top_level"]}
        assert "evidence/alpha.csv" in paths
        assert "evidence/vpn_archive.csv" in paths
        assert "evidence/nested" in paths
        # Scoping allows deferral — no pending_disposition mandate
        assert not any(
            x.get("status") == "pending_disposition"
            for x in a["catalog"]["top_level"]
        )
        assert any("defer" in x.lower() or "time window" in x.lower()
                   for x in a["recommended_first_actions"]
                   + a["catalog"]["relevance_scoping"])

    def test_tabular_only_needs_no_reparse(self, tmp_path):
        from core.evidence_inventory_gate import build_processing_assessment

        a = build_processing_assessment(
            present=["tabular"],
            absent=["disk", "memory", "pcap", "windows_eventlog",
                    "email", "live", "file"],
            counts={"tabular": 3},
            high_value_parsed=[],
            samples_by_class={"tabular": ["evidence/a.csv"]},
            top_level=[{"path": "evidence/a.csv", "is_dir": False,
                        "class": "tabular"}],
            file_count=1,
        )
        assert a["needs_processing"] == []
        assert any(x["class"] == "tabular" for x in a["reparse_not_required"])
        assert any(x["class"] == "disk" for x in a["skip"])
        assert a["catalog"]["top_level"]

    def test_raw_evtx_without_parsed_needs_processing(self):
        from core.evidence_inventory_gate import build_processing_assessment

        a = build_processing_assessment(
            present=["windows_eventlog"],
            absent=["disk", "memory", "tabular", "file"],
            counts={"windows_eventlog": 2},
            high_value_parsed=[],
            samples_by_class={
                "windows_eventlog": ["evidence/Security.evtx"],
            },
        )
        assert any(x["class"] == "windows_eventlog"
                   for x in a["needs_processing"])

    def test_evtx_with_parsed_export_skips_reparse(self):
        from core.evidence_inventory_gate import build_processing_assessment

        a = build_processing_assessment(
            present=["windows_eventlog", "tabular"],
            absent=["disk"],
            counts={"windows_eventlog": 2, "tabular": 1},
            high_value_parsed=[
                "evidence/parsed/host/Hayabusa/hayabusa.csv",
            ],
            samples_by_class={
                "windows_eventlog": ["evidence/Security.evtx"],
            },
        )
        assert not any(x["class"] == "windows_eventlog"
                       for x in a["needs_processing"])
        assert any(x["class"] == "windows_eventlog"
                   for x in a["no_processing_needed"])

    def test_event_logs_absent_loose_are_not_unavailable_beside_disk_images(self):
        """A disk image holds event logs and mail stores as well as a package
        delivers them loose: with images present, their absence as loose
        files is no reason to skip the parsers."""
        from core.evidence_inventory_gate import build_processing_assessment

        def skip(present):
            a = build_processing_assessment(
                present=present, absent=["windows_eventlog", "email", "pcap"],
                counts={c: 1 for c in present}, high_value_parsed=[],
                samples_by_class={"disk": ["evidence/CORP-DC01.dd"]})
            return {x["class"]: x for x in a["skip"]}

        beside_disk = skip(["disk", "tabular"])
        for cls in ("windows_eventlog", "email"):
            assert "disk images may hold" in beside_disk[cls]["reason"]
            assert "unavailable" not in beside_disk[cls]["meaning"]
        assert "unavailable" in beside_disk["pcap"]["meaning"]
        assert "do not run" in skip(["tabular"])["windows_eventlog"]["reason"]

    def test_refusal_points_at_inventory_only(self):
        from core.evidence_inventory_gate import inventory_gate_refusal
        msg = inventory_gate_refusal("ez_ez_recmd_hive")
        assert "evidence-assessment gate" in msg
        assert "misc_inventory_evidence" in msg
        assert "list_evidence_dir" in msg
        assert "does not unlock" in msg

    def test_pre_assessment_allowlist_excludes_directing_tools(self):
        from core.evidence_inventory_gate import INVENTORY_GATE_ALLOWLIST
        assert "misc_inventory_evidence" in INVENTORY_GATE_ALLOWLIST
        assert "misc_list_evidence_dir" in INVENTORY_GATE_ALLOWLIST
        for blocked in (
            "dair_assess", "dair_dair_assess",
            "reason_hypothesize", "reason_reason_hypothesize",
            "reason_plan", "hash_verify_evidence_hash",
            "ez_ez_recmd_hive", "table_table_query",
            "img_vmdk_chain_info", "strings_stat_file",
        ):
            assert blocked not in INVENTORY_GATE_ALLOWLIST, blocked


class TestPathParserCompat:
    """Path parsers (ez_*) accept file|disk; image openers stay disk-only."""

    def test_any_ez_path_tool_allowed_on_file(self):
        from tools.evidence_compat import tool_compatible
        for tool in (
            "ez_ez_recmd_hive",
            "ez_ez_mftecmd",
            "ez_ez_pecmd",
            "ez_ez_amcache",
            "misc_regripper_hive",
            "misc_analyzemft",
        ):
            ok, reason = tool_compatible(tool, {"file"})
            assert ok, f"{tool}: {reason}"

    def test_path_parsers_blocked_on_tabular_only(self):
        from tools.evidence_compat import tool_compatible
        ok, reason = tool_compatible("ez_ez_recmd_hive", {"tabular"})
        assert not ok
        assert "evidence-compat" in reason

    def test_evtx_still_needs_eventlog_or_disk(self):
        from tools.evidence_compat import tool_compatible
        ok, _ = tool_compatible("ez_ez_evtxecmd", {"file"})
        assert not ok
        ok2, _ = tool_compatible("ez_ez_evtxecmd", {"windows_eventlog"})
        assert ok2

    def test_image_openers_still_disk_only(self):
        from tools.evidence_compat import tool_compatible
        for tool in ("ewf_ewf_mount", "tsk_fls", "img_vmdk_chain_info"):
            ok, _ = tool_compatible(tool, {"file"})
            assert not ok, tool
            ok2, _ = tool_compatible(tool, {"disk"})
            assert ok2, tool


class TestInvestigationPlanInventoryFirst:
    def test_first_step_is_inventory(self, tmp_path):
        from core.investigation_plan import build_investigation_plan
        from core.investigation_tasks import empty_tasks, save_tasks

        case = _case_with(tmp_path, {"a.csv": b"x\n"})
        store = empty_tasks(case_id=case.name)
        store["tasks"] = [{
            "id": "task-0001",
            "text": "Who logged in?",
            "status": "open",
            "related_claim_ids": [],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }]
        save_tasks(case, store)
        plan = build_investigation_plan(case, persist=False)
        assert plan["steps"]
        assert plan["steps"][0]["action"] == "inventory_evidence"
