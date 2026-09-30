"""Structured auth events from EvtxECmd / tabular exports (not text scrape)."""
from __future__ import annotations

from pathlib import Path

from core.auth_ontology import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS
from core.auth_tabular import (
    extract_auth_events_from_csv,
    looks_like_auth_tabular,
    row_to_auth_event,
)


def test_evtxecmd_row_shape():
    row = {
        "EventId": "4624",
        "TimeCreated": "2031-02-04 12:00:00.000",
        "RemoteHost": "- (203.0.113.66)",
        "PayloadData2": "LogonType 3",
        "MapDescription": "Successful logon",
    }
    ev = row_to_auth_event(row, call_id=9, tool="ez.evtxecmd")
    assert ev is not None
    assert ev.event_class == EVENT_AUTH_SUCCESS
    assert ev.source_endpoint == "203.0.113.66"
    assert ev.when == "2031-02-04"
    assert ev.auth_factor == "3"
    assert ev.platform == "windows"


def test_evtxecmd_failure_and_local_skipped():
    fail = row_to_auth_event({
        "EventId": "4625",
        "TimeCreated": "2031-02-04T12:05:00Z",
        "RemoteHost": "HOST (203.0.113.66)",
        "PayloadData2": "LogonType 3",
        "MapDescription": "Failed logon",
    })
    assert fail and fail.event_class == EVENT_AUTH_FAILURE
    local = row_to_auth_event({
        "EventId": "4624",
        "TimeCreated": "2031-02-04T12:05:00Z",
        "RemoteHost": "- (-)",
        "PayloadData2": "LogonType 5",
    })
    assert local is None
    loop = row_to_auth_event({
        "EventId": "4624",
        "TimeCreated": "2031-02-04T12:05:00Z",
        "RemoteHost": "x (127.0.0.1)",
        "PayloadData2": "LogonType 3",
    })
    assert loop is None


def test_chainsaw_and_edr_logon_shapes(tmp_path: Path):
    chainsaw = tmp_path / "chainsaw.csv"
    chainsaw.write_text(
        "timestamp,detections,Event ID,Logon Type,IP Address\n"
        "2031-02-05T12:00:00+00:00,Network Logon,4624,3,203.0.113.10\n"
        "2031-02-05T12:01:00+00:00,Failed Logon,4625,3,203.0.113.10\n",
        encoding="utf-8",
    )
    edr = tmp_path / "edr_logons.csv"
    # Quoted timestamps: EDR logon exports can carry commas in the datetime.
    edr.write_text(
        "Timestamp,ActionType,RemoteIP,LogonType\n"
        '"Feb 5, 2031 3:10:00 PM",LogonSuccess,203.0.113.20,3\n'
        '"Feb 5, 2031 3:11:00 PM",LogonFailure,203.0.113.20,3\n',
        encoding="utf-8",
    )
    assert looks_like_auth_tabular(chainsaw)
    assert looks_like_auth_tabular(edr)
    c_events = extract_auth_events_from_csv(chainsaw, call_id=1, tool="chainsaw")
    assert {e.event_class for e in c_events} == {
        EVENT_AUTH_SUCCESS, EVENT_AUTH_FAILURE,
    }
    assert any(e.source_endpoint == "203.0.113.10" for e in c_events)
    m_events = extract_auth_events_from_csv(edr, call_id=2, tool="edr")
    assert {e.event_class for e in m_events} == {
        EVENT_AUTH_SUCCESS, EVENT_AUTH_FAILURE,
    }
    assert any(e.when == "2031-02-05" for e in m_events)


def test_structured_ingest_prefers_csv_over_empty_excerpt(tmp_path: Path):
    from core.auth_observations import ingest_auth_observations_from_trace
    from core.auth_coverage import auth_success_coverage_gaps
    from core.execution_log import log

    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text("auth\n")
    csv_path = case / "analysis" / "auth.csv"
    csv_path.write_text(
        "EventId,TimeCreated,RemoteHost,PayloadData2,MapDescription\n"
        "4625,2031-02-04 00:00:00,- (203.0.113.66),LogonType 3,Failed logon\n"
        "4624,2031-02-04 10:00:00,- (203.0.113.66),LogonType 3,Successful logon\n",
        encoding="utf-8",
    )
    log.configure("TAB", str(case / "analysis" / "t.json"), save_session=False)
    log._entries.clear()
    log._entries.append({
        "type": "tool_call", "call_id": 3, "success": True,
        "mcp_tool": "ez_ez_evtxecmd",
        "stdout_excerpt": "Processed 1 files",  # no auth text
        "auth_csv": str(csv_path),
    })
    ing = ingest_auth_observations_from_trace(case)
    assert ing["structured_events"] >= 2
    assert ing["text_fallback_events"] == 0
    gaps = auth_success_coverage_gaps(case)
    assert gaps["unreported_count"] == 1
    assert gaps["unreported"][0]["ip"] == "203.0.113.66"
