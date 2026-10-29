"""Tests for tool-banner / empty-gaps noise helpers."""
from core.evidence_noise import (
    is_contradictory_empty_gaps_prose,
    is_tool_metadata_text,
    is_weak_timeline_event_text,
    looks_like_evidence_gap_statement,
)


def test_evtxecmd_version_is_metadata():
    assert is_tool_metadata_text("EvtxECmd version 2026.5.0")
    assert is_weak_timeline_event_text("EvtxECmd version 2026.5.0")


def test_forensic_event_not_metadata():
    line = (
        "2031-02-04T12:00:00Z\tWS01\tuser01\tRDP session start\t"
        "session.log\tconnected"
    )
    assert not is_tool_metadata_text(line)
    assert not is_weak_timeline_event_text(line)


def test_gap_statement_detection():
    assert looks_like_evidence_gap_statement(
        "Evidence gap: SAM hive absent from the evidence package"
    )
    assert not looks_like_evidence_gap_statement(
        "Scheduled task created on WS01"
    )


def test_contradictory_empty_gaps_prose():
    prose = (
        "At the time of this report, no formal conclusions, claims, or "
        "conflicts have been registered."
    )
    assert is_contradictory_empty_gaps_prose(prose, finding_count=7)
    assert not is_contradictory_empty_gaps_prose(prose, finding_count=0)


def test_atlas_result_envelope_rows_are_read_and_the_envelope_is_no_event():
    """A Python tool's JSON result is Atlas's own writing: its rows inside are
    the records, the envelope itself never one."""
    from core.evidence_noise import envelope_rows
    env = ('{"success": true, "path": "exports/carve/audit.txt", "encoding": "utf-8", "lines": '
           '["Carver version 1.0", "", "Carver started at Wed Jun 04 09:00:00 2031", "0: 00001.jpg 31 KB"]}')
    assert envelope_rows(env) == ["Carver version 1.0", "Carver started at Wed Jun 04 09:00:00 2031",
                                  "0: 00001.jpg 31 KB"]
    assert envelope_rows('{"success": true, "matches": [{"line": 3, "text": "USER jane.doe"}]}') == ["3\tUSER jane.doe"]
    assert envelope_rows('{"success": false, "error": "no such file"}') == []
    assert envelope_rows('{"success": true, "path": "x", "lines": ["a", "b') == []     # cut short: still the envelope
    assert envelope_rows("2031-06-04 09:00:00 jane.doe logged on") is None
    assert envelope_rows('{"count": 3}') is None
