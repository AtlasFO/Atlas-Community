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
