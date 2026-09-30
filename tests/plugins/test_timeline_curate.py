"""Tests for narrative timeline curation + storm aggregation."""
from pathlib import Path

from plugins.timeline_builder.aggregate import aggregate_storms
from plugins.timeline_builder.curate import (
    curate_relevant_events,
    focus_tokens_from_claims,
)
from plugins.timeline_builder.models import NormalizedTimelineEvent
from plugins.timeline_builder.taxonomy import (
    EvidenceClass,
    classes_from_narrative,
    classify_event,
)


def _ev(**kw) -> NormalizedTimelineEvent:
    defaults = dict(
        timestamp="2031-02-04 12:00:00",
        host="",
        user="",
        event_type="process_execution",
        title="Process executed",
        description="noise",
        source_artifact="Security.evtx",
        source_identifier="EID-4688",
    )
    defaults.update(kw)
    return NormalizedTimelineEvent(**defaults)


def test_focus_tokens_from_claims(tmp_path: Path):
    atlas = tmp_path / ".atlas"
    atlas.mkdir()
    (atlas / "claim_graph.json").write_text(
        '''{"nodes": {
          "C0001": {
            "kind": "claim", "status": "new", "host": "WS01",
            "statement": "User jdoe1 connected via USB storage device serial 0A1B2C3D from 10.0.0.24",
            "evidence": [{"locator": "MAC 00:00:5e:00:53:01 on RoeJohn note"}]
          }
        }}''',
        encoding="utf-8",
    )
    toks = focus_tokens_from_claims(tmp_path)
    assert "ws01" in toks
    assert "jdoe1" in toks
    assert "10.0.0.24" in toks
    assert "0a1b2c3d" in toks
    assert "roejohn" in toks
    assert "00:00:5e:00:53:01" in toks
    assert "connected" not in toks


def test_taxonomy_classes_from_narrative():
    classes = classes_from_narrative([
        "USB storage device attached; user jdoe1 logon 4624; powershell ran."
    ])
    assert EvidenceClass.USB_DEVICE in classes
    assert EvidenceClass.AUTHENTICATION in classes
    assert EvidenceClass.COMMAND_EXECUTION in classes


def test_classify_prefetch_hint():
    cls, prod = classify_event(
        "process_execution",
        source_artifact="Prefetch/FOO.EXE-ABC.pf",
        title="Prefetch execution",
    )
    assert cls == EvidenceClass.EXECUTION
    assert prod == "prefetch"


def test_curate_keeps_findings_and_focus_drops_noise():
    focus = {"ws01", "jdoe1"}
    events = [
        _ev(
            event_type="investigation_finding",
            title="Finding C0001 (LIKELY)",
            description="USB storage device on WS01",
            host="WS01",
            facts={"claim_id": "C0001", "critical": True},
        ),
        _ev(
            event_type="session_activity",
            title="Session / tabular event",
            host="WS01",
            user="jdoe1",
            description="Remote session for jdoe1",
        ),
        _ev(
            event_type="process_execution",
            title="Process executed",
            host="WS01",
            user="SYSTEM",
            description="svchost.exe",
        ),
        _ev(
            event_type="process_execution",
            title="Process executed",
            host="OTHERHOST",
            user="random",
            description="firefox.exe",
        ),
        _ev(
            event_type="event_chain_summary",
            title="~100 more events in this eventchain",
            description="Collapsed sessions.csv Users sample: jdoe1, other",
        ),
        _ev(
            event_type="event_chain_summary",
            title="~5000 more events in this eventchain",
            description="Collapsed estate-wide connections.csv (4000 hosts)",
        ),
    ]
    out, stats = curate_relevant_events(
        events, focus_tokens=focus, aggregate=False)
    titles = [e.title for e in out]
    assert "Finding C0001 (LIKELY)" in titles
    assert any(e.user == "jdoe1" for e in out)
    assert any("~100 more" in t for t in titles)
    assert not any("~5000 more" in t for t in titles)
    assert not any(e.host == "OTHERHOST" for e in out)
    assert not any(
        e.event_type == "process_execution" and e.user == "SYSTEM" for e in out
    )
    assert stats["dropped"] >= 3
    assert stats["mode"] == "narrative_score"


def test_curate_without_focus_drops_bulk_noise():
    events = [
        _ev(event_type="process_execution", title="Process executed"),
        _ev(
            event_type="successful_logon",
            title="User logged on",
            description="4624",
        ),
    ]
    out, stats = curate_relevant_events(
        events, focus_tokens=set(), max_unmatched_noise=0, aggregate=False)
    assert any(e.title == "User logged on" for e in out)
    assert not any(e.event_type == "process_execution" for e in out)
    assert stats["dropped"] >= 1


def test_curate_auth_on_focus_host_kept():
    focus = {"ws01", "jdoe1"}
    events = [
        _ev(
            event_type="successful_logon",
            title="User logged on",
            host="WS01",
            user="jdoe1",
            description="4624 interactive",
        ),
        _ev(
            event_type="successful_logon",
            title="User logged on",
            host="WS01",
            user="SYSTEM",
            description="4624 service",
        ),
        _ev(
            event_type="successful_logon",
            title="User logged on",
            host="RANDOMBOX",
            user="other",
            description="4624 interactive",
        ),
    ]
    out, stats = curate_relevant_events(
        events, focus_tokens=focus, aggregate=False)
    assert len(out) == 1
    assert out[0].user == "jdoe1"
    assert stats["dropped"] == 2


def test_curate_keeps_usb_on_focus_host_when_class_asserted(tmp_path: Path):
    atlas = tmp_path / ".atlas"
    atlas.mkdir()
    (atlas / "claim_graph.json").write_text(
        '''{"nodes": {
          "C1": {
            "kind": "claim", "status": "new", "host": "WS01",
            "statement": "USB storage device attached to WS01"
          }
        }}''',
        encoding="utf-8",
    )
    events = [
        _ev(
            event_type="usb_activity",
            title="USB device",
            host="WS01",
            user="",
            description="USB Composite Device",
            source_artifact="setupapi.dev.log",
        ),
        _ev(
            event_type="process_execution",
            title="Process executed",
            host="WS01",
            user="SYSTEM",
            description="svchost",
        ),
    ]
    out, stats = curate_relevant_events(
        events, case_dir=tmp_path, aggregate=False)
    assert any(e.event_type == "usb_activity" for e in out)
    assert not any(e.event_type == "process_execution" for e in out)
    assert EvidenceClass.USB_DEVICE.value in stats["asserted_classes"]


def test_aggregate_failed_logon_storm():
    events = []
    users = [f"user{i}" for i in range(20)]
    for i, u in enumerate(users):
        events.append(_ev(
            timestamp=f"2031-02-04 12:{i:02d}:00",
            event_type="failed_logon",
            title="Failed logon",
            host="DC01",
            user=u,
            description=f"4625 from 10.0.0.5 user {u}",
            facts={"src_ip": "10.0.0.5"},
        ))
    out, stats = aggregate_storms(events, min_group_size=8, bucket_seconds=3600)
    assert stats["storms_aggregated"] >= 1
    assert len(out) < len(events)
    summaries = [e for e in out if (e.facts or {}).get("aggregated")]
    assert summaries
    assert "Users:" in summaries[0].description
    assert "user0" in summaries[0].description


def test_curate_aggregates_then_keeps_principal_storm():
    focus = {"dc01", "user1", "user2"}
    events = [
        _ev(
            timestamp=f"2031-02-04 12:00:{i:02d}",
            event_type="failed_logon",
            title="Failed logon",
            host="DC01",
            user=f"user{i % 3}",
            description="4625 spray",
            facts={"src_ip": "10.1.1.1"},
        )
        for i in range(30)
    ]
    out, stats = curate_relevant_events(
        events, focus_tokens=focus, aggregate=True,
        aggregate_min_group=8, aggregate_bucket_seconds=3600)
    assert any((e.facts or {}).get("aggregated") for e in out) or len(out) < 30
    assert stats["aggregate"]["enabled"] is True
