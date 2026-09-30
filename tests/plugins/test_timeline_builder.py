"""Tests for Atlas plugin registry and Timeline Builder."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest


class TestPluginRegistry:
    def test_discover_timeline_builder(self):
        from core.plugins import discover_plugin_modules
        mods = discover_plugin_modules()
        assert "plugins.timeline_builder" in mods
        # hayabusa is a core tool (tools/hayabusa.py), not an addon.
        assert "plugins.hayabusa" not in mods

    def test_register_plugins_idempotent(self):
        from fastmcp import FastMCP
        from core.plugins import register_plugins
        mcp = FastMCP("test")
        names = register_plugins(mcp)
        assert "timeline_builder" in names
        # second call should not double-register middleware
        names2 = register_plugins(mcp)
        assert "timeline_builder" in names2

    def test_server_imports_plugins(self):
        import server
        assert server.mcp is not None


class TestTimelineMapper:
    @pytest.fixture
    def evtx_csv(self, tmp_path):
        p = tmp_path / "all-evtx.csv"
        with open(p, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "TimeCreated", "EventId", "Computer", "UserName",
                "Channel", "SourceFile", "ExecutableInfo",
            ])
            w.writeheader()
            w.writerow({
                "TimeCreated": "2031-02-04 12:00:00.000",
                "EventId": "4688",
                "Computer": "HOST01.example.com",
                "UserName": "EXAMPLE\\admin",
                "Channel": "Microsoft-Windows-Security-Auditing",
                "SourceFile": "Security.evtx",
                "ExecutableInfo": "C:\\Windows\\System32\\cmd.exe",
            })
            w.writerow({
                "TimeCreated": "2031-02-04 12:05:00.000",
                "EventId": "4625",
                "Computer": "HOST01.example.com",
                "UserName": "EXAMPLE\\user",
                "Channel": "Microsoft-Windows-Security-Auditing",
                "SourceFile": "Security.evtx",
                "ExecutableInfo": "",
            })
        return p

    def test_reader_and_mapper(self, evtx_csv):
        from plugins.timeline_builder.config import TimelineConfig
        from plugins.timeline_builder.mapper.forensic import MapContext, map_record
        from plugins.timeline_builder.mapper.readers import EvtxCsvReader

        cfg = TimelineConfig()
        ctx = MapContext(original_tool="table_table_query", evidence_reference="evidence/x")
        events = []
        for rec in EvtxCsvReader.read_rows(evtx_csv):
            ev = map_record(rec, ctx, cfg)
            if not ev:
                continue
            if isinstance(ev, list):
                events.extend(ev)
            else:
                events.append(ev)
        assert len(events) == 2
        assert events[0].title == "Process executed"
        assert "Windows Security Event Log (Event ID 4688)" in events[0].source_artifact
        assert "Hayabusa" not in events[0].source_artifact
        assert events[1].title == "Failed logon"

    def test_builder_dedupe(self, evtx_csv):
        from plugins.timeline_builder.builder import TimelineBuilder
        from plugins.timeline_builder.config import TimelineConfig
        from plugins.timeline_builder.mapper.dispatch import process_tool_result

        case = evtx_csv.parent
        (case / "analysis").mkdir()
        (case / "CASE.md").write_text("**Case ID**: TEST\n")

        from core.execution_log import log
        log.configure("TEST", str(case / "analysis" / "T_trace.json"),
                      save_session=False)
        payload = {"success": True, "path": str(evtx_csv), "rows": []}
        n = process_tool_result(
            "table_table_query",
            {"path": str(evtx_csv)},
            payload,
        )
        assert n == 2
        builder = TimelineBuilder.for_case(case)
        merged = builder.merged_sorted_deduped()
        assert len(merged) == 2

    def test_export_tsv(self, tmp_path):
        from plugins.timeline_builder.export import write_master_timeline
        from plugins.timeline_builder.models import NormalizedTimelineEvent

        ev = NormalizedTimelineEvent(
            timestamp="2031-02-04 12:00:00",
            host="HOST01",
            user="ADMIN",
            event_type="process_execution",
            title="Process executed",
            description="cmd.exe ran.",
            source_artifact="Windows Security Event Log (Event ID 4688)",
            source_identifier="EID-4688",
        )
        out = tmp_path / "master_timeline.tsv"
        summary = write_master_timeline([ev], out)
        assert summary["event_count"] == 1
        text = out.read_text(encoding="utf-8")
        assert "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\tLine\tRecordRef" in text
        assert "Process executed" in text
        assert "Hayabusa" not in text

        ev2 = NormalizedTimelineEvent(
            timestamp="2031-02-04 12:05:00",
            host="HOST01",
            user="ADMIN",
            event_type="logon",
            title="Logon",
            description="RDP logon",
            source_artifact="Security.evtx",
            source_identifier="EID-4624",
            record_ref="Security.evtx:42:4624",
            facts={"line": 42},
        )
        write_master_timeline([ev2], out)
        text2 = out.read_text(encoding="utf-8")
        assert "42" in text2
        assert "Security.evtx:42:4624" in text2

    def test_finalize_empty(self, tmp_path):
        from plugins.timeline_builder.finalize import finalize_timeline
        from plugins.timeline_builder.builder import TimelineBuilder
        case = tmp_path / "case"
        (case / "analysis").mkdir(parents=True)
        (case / "reports").mkdir(parents=True)
        from core.execution_log import log
        log.configure("X", str(case / "analysis" / "X_trace.json"),
                      save_session=False)
        # Drop any prior cached builder for this path
        TimelineBuilder.for_case(case).clear()
        r = finalize_timeline(case_dir=case)
        assert r.get("success") is True
        assert r.get("mandatory") is True
        assert r.get("event_count") == 0
        out = case / "reports" / "master_timeline.tsv"
        assert out.is_file()
        assert out.read_text(encoding="utf-8").startswith("Timestamp\t")

    def test_finalize_seeds_siem_csv_not_claim_graph(self, tmp_path):
        import json
        from plugins.timeline_builder.builder import TimelineBuilder
        from plugins.timeline_builder.finalize import finalize_timeline

        case = tmp_path / "case"
        (case / "analysis").mkdir(parents=True)
        (case / "reports").mkdir(parents=True)
        (case / ".atlas").mkdir(parents=True)
        (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
            "nodes": {
                "C0001": {
                    "id": "C0001",
                    "kind": "claim",
                    "status": "active",
                    "host": "HOST01",
                    "confidence": "CONFIRMED",
                    "statement": (
                        "Service installed on HOST01; RoeJohn logon 4624 observed "
                        "in SIEM at 2031-02-04 12:10 UTC."
                    ),
                    "temporal_qualifier": None,
                },
            },
            "edges": [],
        }), encoding="utf-8")
        # QRadar-style SIEM export
        siem = case / "analysis" / "logons.csv"
        with open(siem, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "startDateTime", "deviceEventId", "userName",
                "logSourceIdentifier", "eventDescription",
            ])
            w.writeheader()
            w.writerow({
                "startDateTime": "2031-02-03 12:00:00",
                "deviceEventId": "4624",
                "userName": "RoeJohn",
                "logSourceIdentifier": "DC01",
                "eventDescription": "Logon success",
            })
        TimelineBuilder.for_case(case).clear()
        r = finalize_timeline(case_dir=case)
        assert r["success"] is True
        assert r.get("seed", {}).get("claims_seeded", 0) == 0
        text = (case / "reports" / "master_timeline.tsv").read_text(encoding="utf-8")
        # Claim Graph is not a Source — findings must not appear as timeline rows
        assert "Finding C0001" not in text
        assert "Claim Graph" not in text
        assert "User logged on" in text or "4624" in text
        assert r["event_count"] >= 1

    def test_mft_mapper_source_artifact(self, tmp_path):
        from plugins.timeline_builder.config import TimelineConfig
        from plugins.timeline_builder.mapper.artifacts import map_mft_record
        from plugins.timeline_builder.mapper.forensic import MapContext
        from plugins.timeline_builder.models import EvidenceRecord

        rec = EvidenceRecord(
            timestamp="2031-02-04 12:00:00",
            host="",
            user="",
            event_id="",
            channel="",
            artifact_path=str(tmp_path / "host_mft.csv"),
            source_file="",
            fields={
                "ParentPath": "Windows\\System32",
                "FileName": "cmd.exe",
                "Extension": "exe",
                "IsDirectory": "False",
                "FileSize": "409600",
                "Created0x10": "2031-02-04 12:00:00.000",
                "LastModified0x10": "2031-02-04 12:05:00.000",
            },
            line_number=42,
            artifact_kind="mft",
        )
        events = map_mft_record(rec, MapContext(original_tool="ez.ez_mftecmd"), TimelineConfig())
        assert len(events) == 2
        assert events[0].source_artifact == "NTFS Master File Table"
        assert "MFTECmd" not in events[0].source_artifact
        assert "Hayabusa" not in events[0].source_artifact

    def test_registry_appcompat_mapper(self, tmp_path):
        from plugins.timeline_builder.config import TimelineConfig
        from plugins.timeline_builder.mapper.artifacts import map_registry_record
        from plugins.timeline_builder.mapper.forensic import MapContext
        from plugins.timeline_builder.models import EvidenceRecord

        rec = EvidenceRecord(
            timestamp="2031-02-04 12:00:00",
            host="",
            user="",
            event_id="",
            channel="",
            artifact_path=str(tmp_path / "system_registry_AppCompat.csv"),
            source_file="",
            fields={
                "BatchKeyPath": "ROOT\\ControlSet001\\Control\\Session Manager\\AppCompatCache",
                "ProgramName": "C:\\Program Files\\chrome.exe",
                "ModifiedTime": "2031-02-04 12:00:00.5000000",
            },
            line_number=1,
            artifact_kind="registry",
        )
        ev = map_registry_record(
            rec, MapContext(original_tool="ez.ez_recmd_hive"), TimelineConfig()
        )
        assert ev is not None
        assert ev.source_artifact == "Registry AppCompatCache"
        assert "RECmd" not in ev.source_artifact


class TestReportFinalizedHook:
    """The addon reaches the report through the event, not through an import
    in core — and the switch that turns it off actually turns it off."""

    def test_the_addon_declares_the_event(self):
        from core.addons import REPORT_FINALIZED, declares_event
        from plugins.timeline_builder.plugin import TimelineBuilderAddon
        assert declares_event(TimelineBuilderAddon, REPORT_FINALIZED)

    def test_the_hook_writes_the_timeline_for_a_case(self, tmp_path):
        from plugins.timeline_builder.plugin import TimelineBuilderAddon
        case = tmp_path / "case"
        (case / "reports").mkdir(parents=True)
        report = case / "reports" / "C_investigation_report.md"
        report.write_text("# report\n", encoding="utf-8")
        out = TimelineBuilderAddon().finalize(
            case_dir=str(case), report_path=str(report))
        assert out.get("success")
        assert Path(out["path"]).is_file()

    def test_switching_the_addon_off_stops_it(self, monkeypatch, tmp_path):
        from core.addons import REPORT_FINALIZED
        from core.plugins import dispatch_event
        monkeypatch.setenv("ATLAS_PLUGINS_DISABLED", "timeline_builder")
        case = tmp_path / "case"
        (case / "reports").mkdir(parents=True)
        out = [o for o in dispatch_event(REPORT_FINALIZED, case_dir=str(case),
                                         report_path="")
               if o["addon"] == "timeline_builder"]
        assert out and out[0]["status"] == "disabled"
        assert not (case / "reports" / "master_timeline.tsv").exists()

