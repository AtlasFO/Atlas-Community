"""Tests for core/cross_source_reconciliation.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.cross_source_reconciliation import (
    case_needs_reconciliation,
    discover_sources,
    extract_events,
    findings_trigger_reconciliation,
    run_reconciliation,
)


def _wazuh_bundle(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps({
        "description": "All alerts from attacker IPs ['198.51.100.253']",
        "records": records,
    }), encoding="utf-8")


def _evtx_csv(path: Path, rows: list[dict]) -> None:
    import csv
    fields = ["TimeCreated", "EventId", "Computer", "UserName", "IpAddress", "Logon Type"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def _timeline_tsv(path: Path, rows: list[str]) -> None:
    path.write_text(
        "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\n"
        + "\n".join(rows) + "\n",
        encoding="utf-8",
    )


@pytest.fixture
def mixed_case(tmp_path):
    """The SIEM holds a successful logon two days before the first one the
    disk and the timeline show."""
    evidence = tmp_path / "evidence"
    wazuh_dir = evidence / "wazuh" / "alerts"
    wazuh_dir.mkdir(parents=True)
    _wazuh_bundle(wazuh_dir / "attacker_ips.json", [
        {
            "timestamp": "2031-02-04T12:00:00.000+0000",
            "event_id": "4624",
            "src_ip": "198.51.100.253",
            "user": "Administrator",
            "rule_id": "92657",
            "full_log": json.dumps({
                "win": {
                    "system": {
                        "eventID": "4624",
                        "systemTime": "2031-02-04T12:00:00.000000000Z",
                        "computer": "HOST01.example.com",
                        "eventRecordID": "100001",
                    }
                }
            }) + " Logon Type:\t\t3 Authentication Package:\tNTLM",
        },
        {
            "timestamp": "2031-02-06T09:00:00.000+0000",
            "event_id": "4624",
            "src_ip": "198.51.100.253",
            "user": "Administrator",
            "full_log": "Logon Type:\t\t10",
        },
    ])
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    _evtx_csv(analysis / "security_evtx.csv", [
        {
            "TimeCreated": "2031-02-06 09:00:00",
            "EventId": "4624",
            "Computer": "HOST01.example.com",
            "UserName": "ADMIN",
            "IpAddress": "198.51.100.253",
            "Logon Type": "10",
        },
    ])
    _timeline_tsv(evidence / "investigation_timeline.tsv", [
        "2031-02-06 09:00:00\tHOST01\tADMIN\tRDP logon\tSecurity.evtx\t"
        "Source: 198.51.100.253 Logon Type 10",
    ])
    return tmp_path


class TestDiscovery:
    def test_discover_mixed_sources(self, mixed_case):
        sources = discover_sources(mixed_case)
        kinds = {s["kind"] for s in sources}
        assert "wazuh_json" in kinds
        assert "evtx_csv" in kinds
        assert "timeline_tsv" in kinds

    def test_case_needs_reconciliation(self, mixed_case):
        assert case_needs_reconciliation(mixed_case) is True

    def test_case_without_siem(self, tmp_path):
        analysis = tmp_path / "analysis"
        analysis.mkdir()
        _evtx_csv(analysis / "security_evtx.csv", [])
        assert case_needs_reconciliation(tmp_path) is False


class TestExtraction:
    def test_extract_successful_logons(self, mixed_case):
        sources = discover_sources(mixed_case)
        events = extract_events(
            sources, "successful_logon", [4624],
            focus_ips=["198.51.100.253"],
        )
        assert len(events) >= 3
        ips = {e.src_ip for e in events}
        assert "198.51.100.253" in ips
        ts = sorted(e.timestamp for e in events if e.src_ip == "198.51.100.253")
        assert ts[0].startswith("2031-02-04")


class TestReconciliation:
    def test_detects_earliest_mismatch(self, mixed_case):
        result = run_reconciliation(
            mixed_case, profiles=["successful_logon"], write_outputs=True,
        )
        assert result["success"] is True
        prof = result["profiles"]["successful_logon"]
        assert prof["event_count"] >= 3
        assert prof["earliest_by_src_ip"]["198.51.100.253"]["timestamp"].startswith(
            "2031-02-04"
        )
        assert result["blocking_issues"]
        assert (mixed_case / "analysis" / "cross_source_reconciliation.json").is_file()
        assert (mixed_case / "analysis" / "cross_source_reconciliation.md").is_file()

    def test_no_blocking_when_sources_agree(self, tmp_path):
        evidence = tmp_path / "evidence"
        wazuh_dir = evidence / "wazuh"
        wazuh_dir.mkdir(parents=True)
        ts = "2031-02-06 09:00:00"
        _wazuh_bundle(wazuh_dir / "alerts.json", [{
            "timestamp": "2031-02-06T09:00:00+0000",
            "event_id": "4624",
            "src_ip": "203.0.113.4",
            "user": "admin",
            "full_log": "Logon Type: 10",
        }])
        analysis = tmp_path / "analysis"
        analysis.mkdir()
        _evtx_csv(analysis / "security_evtx.csv", [{
            "TimeCreated": ts,
            "EventId": "4624",
            "Computer": "H",
            "UserName": "admin",
            "IpAddress": "203.0.113.4",
            "Logon Type": "10",
        }])
        _timeline_tsv(evidence / "timeline.tsv", [
            f"{ts}\tH\tadmin\tRDP\tSecurity.evtx\tSource: 203.0.113.4",
        ])
        result = run_reconciliation(
            tmp_path, profiles=["successful_logon"], focus_ips=["203.0.113.4"],
        )
        assert result["ready_for_report"] is True
        assert not result["blocking_issues"]


class TestFindingTriggers:
    def test_triggers_on_initial_access_claim(self):
        findings = [{
            "confidence": "LIKELY",
            "description": "Initial access via RDP from 203.0.113.4 at 2031-02-06",
        }]
        assert findings_trigger_reconciliation(findings) is True

    def test_no_trigger_on_unrelated_finding(self):
        findings = [{
            "confidence": "CONFIRMED",
            "description": "Ransomware note found on disk",
        }]
        assert findings_trigger_reconciliation(findings) is False
