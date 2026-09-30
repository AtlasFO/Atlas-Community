"""Tests for provenance-first evidence resolver."""
from __future__ import annotations

import json
from pathlib import Path

from core.evidence_resolver import (
    format_evidence_markdown,
    resolve_claim_evidence,
)
from core.claim_graph import add_claim
from core.incremental import plane_a_scan


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    (case / "reports" / ".timeline_build").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** EvRes\n", encoding="utf-8")
    (case / "evidence" / "Security.evtx").write_bytes(b"EVTX")
    return case


def test_unresolved_without_provenance(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    c = add_claim(
        case,
        "Something happened on a host",
        confidence="SUSPECTED",
        evidence=[],
        enforce_validation=False,
    )
    # Direct node dict
    node = {
        "id": c.get("node_id") or "C0001",
        "statement": "Something happened on a host",
        "evidence": [],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.selection_mode == "empty"
    assert "could not be deterministically resolved" in pack.unresolved_note
    assert pack.events == []


def test_record_ref_exact_timeline(tmp_path: Path):
    case = _case(tmp_path)
    ref = "analysis/EvtxeCMD/host01.csv:120:4624"
    ev = {
        "timestamp": "2031-02-04T12:00:00Z",
        "host": "CORP-SRV01",
        "user": "Administrator",
        "event_type": "logon",
        "title": "Successful RDP Logon",
        "description": "LogonType 10 Source IP 203.0.113.71",
        "source_artifact": "Windows Security Event Log (Event ID 4624)",
        "source_identifier": ref,
        "record_ref": ref,
        "facts": {"line": 120, "call_id": 0},
    }
    jl = case / "reports" / ".timeline_build" / "events.jsonl"
    jl.write_text(json.dumps(ev) + "\n", encoding="utf-8")

    node = {
        "id": "C0001",
        "statement": "External RDP access to CORP-SRV01",
        "evidence": [{
            "artifact": "timeline",
            "locator": f"record_ref={ref}",
            "call_id": None,
        }],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].provenance == "direct"
    assert "203.0.113.71" in pack.events[0].text
    assert pack.events[0].line == 120
    md = format_evidence_markdown(pack)
    # Rendered as a citation a reader can follow back to the artifact,
    # not as a field-template dump of tool output.
    assert "Cited records" in md
    assert "203.0.113.71" in md
    assert "CORP-SRV01" in md
    assert "Event 4624 (successful logon)" in md


def test_call_id_from_evidence_index(tmp_path: Path):
    case = _case(tmp_path)
    import sqlite3
    db = case / "analysis" / "evidence_index.db"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
    CREATE TABLE sources (
        source_id INTEGER PRIMARY KEY, call_id INTEGER, tool TEXT,
        source_path TEXT, source_hash TEXT, line_count INTEGER,
        byte_count INTEGER, truncated INTEGER, ingested_at TEXT);
    CREATE TABLE windows (
        window_id INTEGER PRIMARY KEY, source_id INTEGER,
        line_start INTEGER, line_end INTEGER, event_time TEXT, raw_text TEXT);
    """)
    conn.execute(
        "INSERT INTO sources VALUES (1, 99, 'ez.evtxecmd', "
        "'analysis/out.csv', 'h', 10, 100, 0, 't')"
    )
    raw = (
        "2031-02-04T12:00:00Z,CORP-SRV01,Administrator,4624,"
        "LogonType 10,203.0.113.71"
    )
    conn.execute(
        "INSERT INTO windows VALUES (1, 1, 5, 5, '2031-02-04T12:00:00', ?)",
        (raw,),
    )
    conn.commit()
    conn.close()

    node = {
        "id": "C0002",
        "statement": "RDP logon observed",
        "evidence": [{"artifact": "ez.evtxecmd", "locator": "4624", "call_id": 99}],
        "input_call_ids": [99],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].provenance == "direct"
    assert pack.events[0].call_id == 99
    assert "203.0.113.71" in pack.events[0].text


def test_artifact_line_exact(tmp_path: Path):
    case = _case(tmp_path)
    csv_path = case / "analysis" / "sample.csv"
    csv_path.write_text(
        "hdr\n"
        "row1-alpha\n"
        "2031-02-04,SRV01,4624,RDP success from 203.0.113.4\n"
        "row3\n",
        encoding="utf-8",
    )
    node = {
        "id": "C0003",
        "statement": "RDP from 203.0.113.4",
        "evidence": [{
            "artifact": "analysis/sample.csv",
            "locator": "line=3",
            "call_id": None,
        }],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].line == 3
    assert "203.0.113.4" in pack.events[0].text
    assert pack.events[0].provenance == "direct"


def test_no_silent_nearby_guess(tmp_path: Path):
    case = _case(tmp_path)
    # Timeline has unrelated events; claim has no provenance
    ev = {
        "timestamp": "2031-02-04T01:00:00Z",
        "host": "OTHERHOST",
        "user": "x",
        "event_type": "logon",
        "title": "Unrelated",
        "description": "noise",
        "source_artifact": "Security",
        "source_identifier": "x",
        "record_ref": "other:1",
        "facts": {},
    }
    jl = case / "reports" / ".timeline_build" / "events.jsonl"
    jl.write_text(json.dumps(ev) + "\n", encoding="utf-8")
    node = {
        "id": "C0004",
        "statement": "Attacker did something vague",
        "evidence": [],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events == []
    assert pack.selection_mode == "empty"


def test_correlated_is_labeled(tmp_path: Path):
    case = _case(tmp_path)
    ev = {
        "timestamp": "2031-02-04T12:00:00Z",
        "host": "srv01",
        "user": "Administrator",
        "event_type": "logon",
        "title": "Successful RDP Logon",
        "description": "LogonType 10 Source IP 203.0.113.71 RDP",
        "source_artifact": "Security",
        "source_identifier": "a",
        "record_ref": "a:1",
        "facts": {"line": 9},
    }
    jl = case / "reports" / ".timeline_build" / "events.jsonl"
    jl.write_text(json.dumps(ev) + "\n", encoding="utf-8")
    node = {
        "id": "C0005",
        "statement": "External RDP compromise of SRV01 from 203.0.113.71",
        "host": "srv01",
        "evidence": [],  # no explicit refs → correlation path
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert all(e.provenance == "correlated" for e in pack.events)
    assert "correlated" in (pack.unresolved_note or "").lower()
    md = format_evidence_markdown(pack)
    assert "correlated" in md.lower()


def test_homogeneous_representative_selection(tmp_path: Path):
    case = _case(tmp_path)
    # Many direct events via artifact lines matching locator tokens
    rows = ["ts,host,eid,msg"]
    for i in range(30):
        rows.append(f"2031-02-03T00:{i:02d}:00,DC02,4776,wrong password spray svcadmin")
    csv_path = case / "analysis" / "spray.csv"
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    node = {
        "id": "C0006",
        "statement": "Password spray / brute-force against svcadmin (T1110)",
        "evidence": [{
            "artifact": "analysis/spray.csv",
            "locator": "svcadmin spray",
            "call_id": None,
        }],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.observed_count and pack.observed_count >= 12
    assert pack.selection_mode == "homogeneous"
    assert len(pack.events) < pack.observed_count
    assert len(pack.events) <= 6


def test_multi_component_selection(tmp_path: Path):
    case = _case(tmp_path)
    events = [
        {
            "timestamp": "2031-02-04T12:00:00Z",
            "host": "SRV01",
            "user": "Administrator",
            "event_type": "logon",
            "title": "Successful RDP Logon",
            "description": "RDP LogonType 10 from 203.0.113.4",
            "source_artifact": "Security",
            "source_identifier": "r1",
            "record_ref": "ref:rdp",
            "facts": {"line": 1},
        },
        {
            "timestamp": "2031-02-04T12:02:00Z",
            "host": "SRV01",
            "user": "SYSTEM",
            "event_type": "detection",
            "title": "Malware Detection",
            "description": "Windows Defender Ransom:Win32/ExampleLocker",
            "source_artifact": "Defender",
            "source_identifier": "r2",
            "record_ref": "ref:def",
            "facts": {"line": 2},
        },
        {
            "timestamp": "2031-02-04T12:02:30Z",
            "host": "SRV01",
            "user": "Administrator",
            "event_type": "file",
            "title": "Encrypted file created",
            "description": "Created ransom encrypted file .locked",
            "source_artifact": "MFT",
            "source_identifier": "r3",
            "record_ref": "ref:enc",
            "facts": {"line": 3},
        },
    ]
    jl = case / "reports" / ".timeline_build" / "events.jsonl"
    jl.write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8",
    )
    node = {
        "id": "C0007",
        "statement": (
            "External RDP access led to ExampleLocker ransomware execution and "
            "file encryption on SRV01"
        ),
        "evidence": [
            {"artifact": "t", "locator": "record_ref=ref:rdp"},
            {"artifact": "t", "locator": "record_ref=ref:def"},
            {"artifact": "t", "locator": "record_ref=ref:enc"},
        ],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.selection_mode in ("multi_component", "exact")
    comps = {e.component for e in pack.events}
    # Should cover multiple components when classified
    assert pack.events
    texts = " ".join(e.text for e in pack.events)
    assert "RDP" in texts or "Logon" in texts
    assert "ExampleLocker" in texts or "Defender" in texts or "encrypt" in texts.lower()


def test_timeline_tsv_record_ref_fallback(tmp_path: Path):
    """Resolver uses master_timeline.tsv Line/RecordRef when jsonl absent."""
    case = _case(tmp_path)
    tsv = case / "analysis" / "master_timeline.tsv"
    tsv.write_text(
        "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\tLine\tRecordRef\n"
        "2031-02-03T12:00:00\tDC02\tsvcadmin\tLogon\tSecurity.evtx\t"
        "4624 success\t17\tSecurity.evtx:17:4624\n",
        encoding="utf-8",
    )
    node = {
        "id": "C0099",
        "statement": "Successful RDP logon as svcadmin on DC02",
        "evidence": [{
            "artifact": "analysis/master_timeline.tsv",
            "locator": "record_ref=Security.evtx:17:4624",
            "call_id": None,
        }],
        "host": "DC02",
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].provenance == "direct"
    assert pack.events[0].record_ref == "Security.evtx:17:4624"
    assert pack.events[0].line == 17


def test_evidence_dir_basename_resolves_direct(tmp_path: Path):
    """I5: artifacts under evidence/ must resolve (not analysis-only rglob)."""
    case = _case(tmp_path)
    csv = case / "evidence" / "edr_lateral_20310205.csv"
    csv.write_text(
        "ts,host,user,ip\n"
        "2031-02-05T15:00:00Z,filesrv01,user01,10.0.0.101\n"
        "2031-02-05T15:00:30Z,filesrv01,user01,10.0.0.101\n",
        encoding="utf-8",
    )
    node = {
        "id": "C0100",
        "statement": "user01 authenticated from 10.0.0.101 to filesrv01",
        "host": "filesrv01",
        "evidence": [{
            "artifact": "edr_lateral_20310205.csv",
            "locator": "10.0.0.101 user01",
            "call_id": None,
        }],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].provenance == "direct"
    assert "10.0.0.101" in pack.events[0].text
    assert pack.selection_mode != "correlated"


def test_compound_artifact_plus_split(tmp_path: Path):
    """I5: ``A.csv + B.csv`` opens both evidence files."""
    case = _case(tmp_path)
    a = case / "evidence" / "vpn_auth.csv"
    b = case / "evidence" / "edr_lateral_20310205.csv"
    a.write_text(
        "ts,user,machine\n2031-02-05T12:00:00Z,admin,host02\n",
        encoding="utf-8",
    )
    b.write_text(
        "ts,host,user\n2031-02-05T15:00:00Z,filesrv01,user01\n",
        encoding="utf-8",
    )
    node = {
        "id": "C0101",
        "statement": "VPN admin on host02 then user01 lateral",
        "evidence": [{
            "artifact": "vpn_auth.csv + edr_lateral_20310205.csv",
            "locator": "host02 user01",
            "call_id": None,
        }],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.events
    assert pack.events[0].provenance == "direct"
    sources = {e.source for e in pack.events}
    assert any("vpn_auth" in s for s in sources) or any(
        "edr_lateral" in s for s in sources
    )


def test_supporting_evidence_prose_beats_correlated_flood(tmp_path: Path):
    """I5: failed call_id + prose citation must not dump correlated RAW EVENTs."""
    case = _case(tmp_path)
    # Timeline that would match host/IP correlation
    ev = {
        "timestamp": "2031-02-05T15:00:00Z",
        "host": "filesrv01",
        "user": "user01",
        "event_type": "logon",
        "title": "Network logon",
        "description": "NTLM from 10.0.0.101",
        "source_artifact": "EDR",
        "source_identifier": "x",
        "record_ref": "x:1",
        "facts": {},
    }
    jl = case / "reports" / ".timeline_build" / "events.jsonl"
    jl.write_text(json.dumps(ev) + "\n", encoding="utf-8")
    node = {
        "id": "C0102",
        "statement": "user01 from 10.0.0.101 on filesrv01 via SMB",
        "host": "filesrv01",
        "evidence": [
            {"artifact": "trace_call", "locator": "call_id=99999", "call_id": 99999},
            {
                "artifact": "supporting_evidence",
                "locator": (
                    "edr_filesrv01_filecreate shows user01 SMB FileCreate "
                    "report_01.txt from 10.0.0.101 at 15:00:30 UTC"
                ),
                "call_id": 99999,
            },
        ],
        "input_call_ids": [99999],
    }
    pack = resolve_claim_evidence(case, node)
    assert pack.selection_mode == "supporting_evidence_prose"
    assert pack.events
    assert all(e.provenance == "direct" for e in pack.events)
    assert pack.selection_mode != "correlated"
    md = format_evidence_markdown(pack)
    assert "correlated (not direct)" not in md.lower()


def test_claim_mirror_persists_evidence_paths(tmp_path: Path):
    """I5: upsert_claim_from_finding stores resolvable evidence/ paths."""
    from core.claim_graph import upsert_claim_from_finding, load_graph

    case = _case(tmp_path)
    (case / ".atlas").mkdir(exist_ok=True)
    r = upsert_claim_from_finding(
        case,
        statement="user01 lateral from 10.0.0.101",
        confidence="LIKELY",
        source="vpn_auth.csv + edr_lateral_20310205.csv",
        supporting_evidence=(
            "See evidence/edr_lateral_20310205.csv line=2 for SMB logon"
        ),
        finding_call_id=10,
        linked_call_id=9,
        input_call_ids=[9],
    )
    assert r.get("success")
    g = load_graph(case)
    node = next(iter((g.get("nodes") or {}).values()))
    arts = [e.get("artifact") for e in (node.get("evidence") or [])]
    assert "vpn_auth.csv" in arts
    assert "edr_lateral_20310205.csv" in arts
    assert "evidence/edr_lateral_20310205.csv" in arts
    assert "supporting_evidence" in arts


def test_a_machine_added_citation_is_rendered_without_its_mark(tmp_path: Path):
    """The finding tool marks a citation line it wrote itself. The finding
    keeps the mark; the events a report renders from that evidence carry
    the cited text without it."""
    from core.forensic_citation import MACHINE_CITATION_MARK
    case = _case(tmp_path)
    cited = ("10.0.0.101 :: 2031-02-05 15:00:00 IP 10.0.0.101.1655 > "
             "10.0.0.7.445 SMB session")
    node = {
        "id": "C0103",
        "statement": "user01 from 10.0.0.101 reached filesrv01 over SMB",
        "host": "filesrv01",
        "evidence": [{
            "artifact": "supporting_evidence",
            "locator": ("analyst notes the SMB session in the capture\n"
                        f"{MACHINE_CITATION_MARK} {cited}"),
            "call_id": 7,
        }],
        "input_call_ids": [7],
    }
    pack = resolve_claim_evidence(case, node)
    texts = [e.text for e in pack.events]
    assert cited in texts
    assert not any(MACHINE_CITATION_MARK in t for t in texts)
    assert MACHINE_CITATION_MARK not in format_evidence_markdown(pack)
