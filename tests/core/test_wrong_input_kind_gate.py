"""Wrong-input-kind gate — CSV must not storm EvtxECmd."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from core.input_kind import (
    GATE,
    check_tool_input_kind,
    refuse_preparsed_evtx,
    wrong_kind_count,
)
from core.deferred_intents import is_protocol_block_message
from agent.tool_investigate import classify_tool_result


def test_csv_refused_as_wrong_input_kind(tmp_path: Path):
    csv = tmp_path / "fw-a-vpn_logons.csv"
    csv.write_text("a,b\n1,2\n", encoding="utf-8")
    bad = refuse_preparsed_evtx(str(csv))
    assert bad and bad["gate"] == GATE
    assert "table" in (bad.get("use_instead") or "").lower()


def test_a_binary_without_the_evtx_signature_is_refused(tmp_path: Path):
    """A raw disk image handed to an event-log parser is refused before the
    parser walks it; a real EVTX header passes."""
    image = tmp_path / "host_raw.dd"
    image.write_bytes(b"\xeb\x52\x90NTFS    " + b"\x00" * 4096)
    bad = refuse_preparsed_evtx(str(image))
    assert bad and bad["gate"] == GATE and "ElfFile" in bad["error"]
    assert "icat" in (bad.get("use_instead") or "")
    log = tmp_path / "Security.evtx"
    log.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    assert refuse_preparsed_evtx(str(log)) is None
    with pytest.raises(ValueError):
        check_tool_input_kind("misc_evtx_filter", {"evtx_path": str(image)})


def test_middleware_protocol_and_quarantine(tmp_path: Path, monkeypatch):
    (tmp_path / ".atlas").mkdir()
    csv = tmp_path / "evidence" / "vpn_logons.csv"
    csv.parent.mkdir()
    csv.write_text("SourceUser,x\nadmin,1\n", encoding="utf-8")

    # Simulate case_dir for quarantine
    with pytest.raises(ValueError) as ei:
        check_tool_input_kind(
            "ez_ez_evtxecmd",
            {"evtx_path": str(csv)},
            case_dir=tmp_path,
        )
    body = json.loads(str(ei.value))
    assert body["gate"] == GATE
    assert wrong_kind_count(tmp_path, "ez_ez_evtxecmd", str(csv)) >= 1

    with pytest.raises(ValueError) as ei2:
        check_tool_input_kind(
            "ez_ez_evtxecmd",
            {"evtx_path": str(csv)},
            case_dir=tmp_path,
        )
    body2 = json.loads(str(ei2.value))
    assert "repeat" in body2["error"].lower()


def test_wrong_kind_is_tool_info_not_investigate():
    payload = json.dumps({
        "success": False,
        "gate": GATE,
        "failure_class": GATE,
        "error": "csv is not evtx",
    })
    assert classify_tool_result("ez_ez_evtxecmd", f"TOOL INFO:\n{payload}") is None
    assert classify_tool_result("ez_ez_evtxecmd", payload) is None
    assert is_protocol_block_message(f'ATLAS_PROTOCOL {payload}')


def test_inventory_forbids_evtx_on_tabular(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "fw-a-vpn_logons.csv").write_text("a,b\n1,2\n")
    winevt = evidence / "raw_extract" / "HOST" / "Windows" / "System32" / "winevt" / "logs"
    winevt.mkdir(parents=True)
    evtx = winevt / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 32)

    from core.evidence_inventory_gate import build_evidence_inventory
    out = build_evidence_inventory(tmp_path)
    assert out.get("success")
    assessment = out["assessment"]
    tabular = [x for x in assessment["reparse_not_required"]
               if x.get("class") == "tabular"]
    assert tabular
    assert "NEVER" in tabular[0]["reason"] or "forbidden_tools" in tabular[0]
    # Case-root CSV should be on already_processed / high_value
    paths = " ".join(assessment.get("already_processed", {}).get("paths") or [])
    assert "vpn_logons" in paths or "fw-a" in paths
