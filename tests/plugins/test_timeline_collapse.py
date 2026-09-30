"""Tests for curated event-chain collapse."""
from plugins.timeline_builder.collapse import collapse_event_chains, is_critical
from plugins.timeline_builder.models import NormalizedTimelineEvent


def _failed(i: int, ip: str = "10.0.0.5") -> NormalizedTimelineEvent:
    minute = i // 60
    second = i % 60
    return NormalizedTimelineEvent(
        timestamp=f"2031-02-04 11:{minute:02d}:{second:02d}",
        host="DC01",
        user="victim",
        event_type="failed_logon",
        title="Failed logon",
        description=f"Failed logon from {ip} attempt {i}",
        source_artifact="Windows Security Event Log (Event ID 4625)",
        source_identifier="EID-4625",
        record_ref=f"sec.evtx:{i}:4625",
        facts={"src_ip": ip, "line": i},
    )


def test_bruteforce_chain_keeps_first_interior_summary_last():
    chain = [_failed(i) for i in range(20)]
    out, stats = collapse_event_chains(chain, keep_interior=2, min_chain_size=7)
    assert stats["chains_collapsed"] == 1
    assert stats["events_omitted"] == 20 - 4  # first+2+last
    titles = [e.title for e in out]
    assert titles[0] == "Failed logon"
    assert any(t.startswith("~") and "more events in this eventchain" in t for t in titles)
    assert out[-1].title == "Failed logon"
    assert out[0].timestamp == "2031-02-04 11:00:00"
    assert out[-2].event_type == "event_chain_summary"


def test_critical_finding_never_collapsed_away():
    noise = [_failed(i) for i in range(30)]
    critical = NormalizedTimelineEvent(
        timestamp="2031-02-04 11:00:10",
        host="DC01",
        user="attacker",
        event_type="investigation_finding",
        title="Finding C0001 (CONFIRMED)",
        description="Successful password change during brute force window.",
        source_artifact="Security.evtx",
        source_identifier="C0001",
        facts={"claim_id": "C0001", "critical": True},
    )
    out, stats = collapse_event_chains(noise + [critical], keep_interior=2)
    assert is_critical(critical)
    assert any(e.source_identifier == "C0001" for e in out)
    assert stats["critical_kept"] >= 1


def test_small_chain_not_collapsed():
    chain = [_failed(i) for i in range(3)]
    out, stats = collapse_event_chains(chain, keep_interior=2, min_chain_size=7)
    assert stats["chains_collapsed"] == 0
    assert len(out) == 3


def test_separate_ips_are_separate_chains():
    a = []
    for i in range(10):
        ev = _failed(i, ip="10.0.0.1")
        a.append(NormalizedTimelineEvent(
            **{**ev.__dict__, "timestamp": f"2031-02-04 11:00:{i:02d}"},
        ))
    b = []
    for i in range(10):
        ev = _failed(i, ip="10.0.0.2")
        b.append(NormalizedTimelineEvent(
            **{**ev.__dict__, "timestamp": f"2031-02-04 11:10:{i:02d}"},
        ))
    out, stats = collapse_event_chains(a + b, keep_interior=2, min_chain_size=7)
    assert stats["chains_collapsed"] == 2
    summaries = [e for e in out if e.event_type == "event_chain_summary"]
    assert len(summaries) == 2


def test_bulk_session_rows_collapse_across_users():
    """Estate sessions.csv must not emit one row per user/host."""
    rows = []
    for i in range(40):
        rows.append(NormalizedTimelineEvent(
            timestamp=f"02/04/2031 10:{i:02d}:00",
            host=f"EXAMPLE\\WS{200 + i}",
            user=f"user{i:04d}",
            event_type="session_activity",
            title="Session / tabular event",
            description=f"SessionState=Active; ClientAddress=10.0.1.{i}",
            source_artifact="Tabular export (sessions.csv)",
            source_identifier=f"tabular:{i}",
            record_ref=f"sessions.csv:{i}",
        ))
    out, stats = collapse_event_chains(rows, bulk_keep_interior=1)
    assert stats["chains_collapsed"] >= 1
    assert stats["events_omitted"] >= 30
    assert len(out) < 15
    assert any(e.event_type == "event_chain_summary" for e in out)
    assert any(e.title == "Session / tabular event" for e in out)
