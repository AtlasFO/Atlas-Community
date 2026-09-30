"""Winevt listing prioritises Security.evtx over side channels."""
from __future__ import annotations

from pathlib import Path

from tools.misc import list_evidence_dir


def test_winevt_list_puts_security_first(tmp_path: Path, monkeypatch):
    logs = tmp_path / "evidence" / "host" / "Windows" / "System32" / "winevt" / "logs"
    logs.mkdir(parents=True)
    for name in (
        "Microsoft-Windows-Security-Mitigations%4KernelMode.evtx",
        "Microsoft-Windows-Security-Adminless%4Operational.evtx",
        "Security.evtx",
        "System.evtx",
        "Application.evtx",
    ):
        (logs / name).write_bytes(b"ElfFile\x00")

    monkeypatch.chdir(tmp_path)
    # No active case — path contains /evidence/ so list allows it
    out = list_evidence_dir(str(logs), limit=10)
    assert out["success"]
    names = [e["name"] for e in out["entries"]]
    assert names[0] == "Security.evtx"
    assert "recommended_first" in out
    assert "Security.evtx" in out["recommended_first"]
    assert "priority_hint" in out


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
