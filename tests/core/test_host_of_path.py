"""ATLAS_HOST_OF_PATH: one path-to-host matcher (core.evidence_links
.host_of_path) for file names, the Evidence Links first, then a label
delimited by any non-alphanumeric character, the longest label winning.
Invented fixtures only (CORP-WS01, SRV-WS01, CORP-DC01)."""
from __future__ import annotations

import json

from core.evidence_links import host_of_path

HOSTS = ["CORP-WS01", "CORP-DC01", "WS01", "SRV-WS01"]


def test_hyphen_joined_names_map_and_the_longest_label_wins():
    assert host_of_path(None, "evidence/disks/corp-ws01-triage.raw", HOSTS) == "CORP-WS01"
    assert host_of_path(None, "evidence/memory/corp-dc01-memory.mem", HOSTS) == "CORP-DC01"
    assert host_of_path(None, "exports/srv-ws01_timeline.csv", HOSTS) == "SRV-WS01"
    assert host_of_path(None, "exports/ws01.csv", HOSTS) == "WS01"
    assert host_of_path(None, "exports/xws01y.csv", HOSTS) == ""
    assert host_of_path(None, "exports/corp-ws01-to-corp-dc01.csv", HOSTS) == ""   # two hosts


def test_the_evidence_links_come_first(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-DC01", "path": "evidence/disks/image7.E01"}]}))
    assert host_of_path(tmp_path, "evidence/disks/image7.E01", HOSTS) == "CORP-DC01"


def test_host_files_puts_hyphen_joined_case_files_under_their_host(tmp_path, monkeypatch):
    from core import question_plan as Q
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/disks/corp-ws01-triage.raw"},
        {"label": "CORP-DC01", "path": "evidence/disks/dc.raw"}]}))
    files = ["evidence/disks/corp-ws01-triage.raw", "evidence/memory/corp-ws01-memory.mem",
             "evidence/disks/dc.raw", "evidence/other/notes.txt"]
    monkeypatch.setattr("core.coverage_ledger.load_ledger",
                        lambda _c: {"units": {str(i): {"path": p} for i, p in enumerate(files)}})
    out = Q.host_files(str(tmp_path))
    assert out["CORP-WS01"] == ["evidence/disks/corp-ws01-triage.raw", "evidence/memory/corp-ws01-memory.mem"]
    assert out["CORP-DC01"] == ["evidence/disks/dc.raw"] and out[""] == ["evidence/other/notes.txt"]
    monkeypatch.setenv("ATLAS_HOST_OF_PATH", "0")
    assert "evidence/memory/corp-ws01-memory.mem" in Q.host_files(str(tmp_path))[""]
