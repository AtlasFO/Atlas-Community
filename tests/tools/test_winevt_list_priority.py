"""list_evidence_dir lists in name order and pages: no file is put first
and none hides behind the page bound."""
from __future__ import annotations

from pathlib import Path

from tools.misc import list_evidence_dir


def test_the_listing_is_in_name_order_and_pages(tmp_path: Path, monkeypatch):
    logs = tmp_path / "evidence" / "host" / "Windows" / "System32" / "winevt" / "logs"
    logs.mkdir(parents=True)
    names = ["Application.evtx", "Microsoft-Windows-Security-Mitigations%4KernelMode.evtx",
             "Security.evtx", "System.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx"]
    for name in names:
        (logs / name).write_bytes(b"ElfFile\x00")
    monkeypatch.chdir(tmp_path)
    out = list_evidence_dir(str(logs), limit=2)
    assert out["success"] and out["total"] == 5 and out["truncated"] is True
    assert [e["name"] for e in out["entries"]] == sorted(names)[:2]
    assert out["more"] == "+3 more entries: list_evidence_dir(path, glob, offset=2)"
    assert "priority_hint" not in out and "recommended_first" not in out
    last = list_evidence_dir(str(logs), limit=2, offset=4)
    assert [e["name"] for e in last["entries"]] == sorted(names)[4:] and "more" not in last


def test_list_evidence_dir_without_a_path_lists_the_open_cases_evidence(tmp_path, monkeypatch):
    """The path may be omitted: the open case's evidence directory is what
    a listing without one means."""
    from tools.misc import list_evidence_dir
    from core import execution_log
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "disk.E01").write_bytes(b"EVF")
    monkeypatch.setattr(execution_log.log, "case_dir", lambda: str(case))
    out = list_evidence_dir()
    assert out["success"] is True
    assert [e["name"] for e in out["entries"]] == ["disk.E01"]
