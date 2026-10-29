"""Client report assembler — spine, evidence, timeline separation."""
from __future__ import annotations

from pathlib import Path

from core.claim_graph import add_claim
from core.evidence_resolver import format_evidence_markdown
from core.incremental import plane_a_scan
from core.report_assemble import (
    assemble_client_report,
    parse_finding_narratives,
)
from core.report_projection import (
    assemble_report,
    deterministic_section_generator,
    mark_stale_sections,
    regenerate_sections,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** AsmTest\n**System owner:** victim\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"x")
    return case


def test_parse_finding_narratives():
    prose = """
## Detailed Findings

### F-001 — Lateral Movement to DC01

**Summary**

A concise narrative about DC01.

**Assessment**

Forensic analysis explaining relevance.

**Confidence:** LIKELY

### F-002 — Other

**Summary**

Second finding summary.

**Assessment**

Second assessment.
"""
    nar = parse_finding_narratives(prose)
    assert "F-001" in nar
    assert "DC01" in nar["F-001"]["summary"]
    assert "relevance" in nar["F-001"]["assessment"]
    assert "F-002" in nar


def test_assemble_has_spine_and_per_finding_evidence(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    # Seed timeline TSV for resolver
    (case / "analysis" / "master_timeline.tsv").write_text(
        "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\tLine\tRecordRef\n"
        "2031-02-05T12:05:00Z\tDC01\tAdministrator\tSuccessful Network Logon\t"
        "Security.evtx\tLogonType 3\t1200\tSecurity.evtx:1200:4624\n",
        encoding="utf-8",
    )
    add_claim(
        case,
        "Lateral Movement to DC01 via Administrator network logon T1021",
        confidence="LIKELY",
        host="DC01",
        evidence=[{
            "artifact": "analysis/master_timeline.tsv",
            "locator": "record_ref=Security.evtx:1200:4624",
        }],
        reasoning=(
            "Administrator authenticated to DC01 immediately after RDP "
            "compromise on the source host."
        ),
    )
    # Store LLM-like narratives without evidence dump
    from core.report_projection import _save_section_body
    _save_section_body(
        case,
        "detailed_findings",
        "## Detailed Findings\n\n"
        "### F-001 — Lateral Movement to DC01\n\n"
        "**Summary**\n\n"
        "Administrator moved laterally to DC01.\n\n"
        "**Assessment**\n\n"
        "Evidence supports lateral movement via network logon.\n\n",
    )
    text = assemble_client_report(case, report_scope="estate")
    assert "## Table of Contents" in text or "Inhaltsverzeichnis" in text
    assert "Executive Summary" in text or "Zusammenfassung" in text
    assert "Key Findings" in text or "Wesentliche" in text
    assert "Detailed Findings" in text or "Detaillierte" in text
    assert "Attack Timeline" in text or "Angriffszeitlinie" in text
    assert "Appendix" in text or "Anhang" in text
    assert "F-001" in text
    # The finding block reads top-down: headline, what happened, why it
    # matters, then at most three citations — no sub-heading ladder.
    assert "### F-001 · Lateral Movement to DC01" in text
    assert "**What happened.**" in text or "**Was geschehen ist.**" in text
    assert "**Why it matters.**" in text or "**Warum es relevant ist.**" in text
    assert "**Evidence.**" in text or "**Beweise.**" in text
    assert "#### Summary" not in text and "Observed Events" not in text
    assert "Answers to the Investigation Questions" in text
    # The citation names the artifact and the record inside it, so a reader
    # can go and re-check the fact.
    assert "Security.evtx" in text
    assert "Event 4624" in text or "1200" in text
    # Evidence under the finding, not a dump appendix
    assert "Supporting Evidence (deterministic)" not in text
    # Curated timeline table from evidence
    assert "| Timestamp | Host | User | Event | Finding |" in text
    assert "Successful Network Logon" in text
    tl = text.split("## 5. Attack Timeline", 1)[-1]
    assert "F-001" in tl
    assert "master_timeline.tsv" in text
    assert "curated" in text.lower()
    assert "complete export" not in text.lower()


def test_format_evidence_raw_event_block():
    md = format_evidence_markdown({
        "events": [{
            "text": (
                "2031-02-05T12:05:00Z\tDC01\tAdministrator\t"
                "Successful Network Logon\tSecurity Event Log\tLogonType 3"
            ),
            "source": "Security.evtx",
            "line": 1200,
            "record_ref": "Security.evtx:1200:4624",
            "provenance": "direct",
            "timestamp": "2031-02-05T12:05:00Z",
            "host": "DC01",
            "component": "lateral_movement",
        }],
        "observed_count": 1,
        "selection_mode": "exact",
        "retained_refs": [],
        "unresolved_note": "",
    })
    # One citation line carrying host, artifact, record and time — the
    # reference an analyst would write by hand.
    assert "Cited records" in md
    assert "DC01" in md
    assert "Windows Event Log Security.evtx" in md
    assert "Event 4624 (successful logon)" in md
    assert "2031-02-05 12:05:00 UTC" in md
    # ...and none of the old positional field labels.
    assert "Machine:" not in md
    assert "RecordRef:" not in md


def test_assemble_report_uses_client_assembler(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files T1486",
        confidence="CONFIRMED",
        host="HOST01",
    )
    mark_stale_sections(case, force_all=True)
    regenerate_sections(
        case, generator=deterministic_section_generator, only_stale=True,
    )
    asm = assemble_report(case, report_scope="estate")
    assert asm["success"]
    text = Path(asm["output_path"]).read_text(encoding="utf-8")
    assert Path(asm["output_path"]).name == "estate_report.md"
    assert "Table of Contents" in text or "Inhaltsverzeichnis" in text
    assert "F-001" in text
    assert "**Evidence.**" in text or "**Beweise.**" in text


def test_attack_timeline_drops_tool_banners(tmp_path: Path):
    from core.report_assemble import _build_attack_timeline_rows

    findings = [{
        "id": "C0001",
        "finding_id": "F-001",
        "statement": "User logged on via 4624",
        "host": "DC01",
        "confidence": "LIKELY",
    }]
    packs = {
        "C0001": {
            "selection_mode": "exact",
            "events": [
                {
                    "text": "EvtxECmd version 2026.5.0",
                    "timestamp": "2031-02-04T12:00:00",
                    "host": "",
                    "provenance": "direct",
                    "source": "evidence_index call_id=12",
                    "line": 1,
                },
                {
                    "text": (
                        "2031-02-04T12:05:00Z\tDC01\tjdoe\t"
                        "Password change attempt\tSecurity.evtx\t4723"
                    ),
                    "timestamp": "2031-02-04T12:05:00Z",
                    "host": "DC01",
                    "provenance": "direct",
                    "source": "Security.evtx",
                    "line": 42,
                    "record_ref": "Security.evtx:42:4723",
                },
            ],
        }
    }
    rows = _build_attack_timeline_rows(findings, packs)
    assert len(rows) == 1
    assert "4723" in rows[0]["event"] or "Password" in rows[0]["event"]
    assert "EvtxECmd" not in rows[0]["event"]


def test_attack_timeline_never_prints_atlas_own_result_envelope(tmp_path: Path):
    """A Python tool's JSON result cited for a finding is Atlas's writing:
    its first date is the carver's start time as readily as a record's, so
    the envelope is no timeline row, whatever time the index stamped it with."""
    from core.report_assemble import _build_attack_timeline_rows

    findings = [{"id": "C0001", "finding_id": "F-001", "statement": "A carved document holds a text note",
                 "host": "CORP-USB01", "confidence": "LIKELY"}]
    envelope = ('{"success": true, "path": "exports/carve/audit.txt", "encoding": "utf-8", "lines": '
                '["Carver started at Wed Jun 04 09:00:00 2031", "0: 00001.ole 31 KB"]}')
    packs = {"C0001": {"selection_mode": "exact", "events": [
        {"text": envelope, "timestamp": "2031-06-04T09:00:00", "host": "", "provenance": "direct",
         "source": "evidence_index call_id=65", "line": 1}]}}
    assert _build_attack_timeline_rows(findings, packs) == []


def test_gaps_section_rejects_contradictory_empty_prose(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    from core.claim_graph import upsert_claim_from_finding
    upsert_claim_from_finding(
        case,
        statement=(
            "Evidence gap: SAM hive absent from the evidence package "
            "and prevents determination of local accounts"
        ),
        confidence="UNCONFIRMED",
        host="WS02",
        finding_call_id=10,
        input_call_ids=[5],
    )
    from core.report_projection import _save_section_body
    _save_section_body(
        case,
        "gaps",
        "At the time of this report, no formal conclusions, claims, or "
        "conflicts have been registered against the estate-scoped "
        "investigation record. The absence of registered findings does "
        "not equate to an absence of incident activity.",
    )
    text = assemble_client_report(case, report_scope="estate")
    assert "no formal conclusions" not in text.lower()
    assert "Evidence gap" in text or "SAM hive" in text


def test_the_summarys_next_steps_come_from_the_recorded_plan_by_code(tmp_path: Path):
    """The executive summary's next steps are rendered by code from the
    response plan: open rows that rest on a finding, in the engagement's
    lifecycle order (an examination investigates first, contains last), at
    most three with "+N more"; a prior-knowledge precaution is no next step
    of the case; with no row recorded, "no step recorded"."""
    from core.claim_graph import add_claim, add_recommendation
    from core.report_assemble import _exec_next_steps
    case = _case(tmp_path)
    (case / "CASE.md").write_text("**Case ID** AsmTest\n**Engagement:** examination\n", encoding="utf-8")
    assert _exec_next_steps(case, "en") == ["", "**Next steps**", "", "- no step recorded"]
    cid = add_claim(case, "jane.doe's account stored files on CORP-WS01", confidence="LIKELY",
                    host="CORP-WS01")["node_id"]
    add_recommendation(case, action="Preserve volatile state before any remediation", phase="contain",
                       urgency="now", basis_ids=[], source="prior_knowledge")
    contain = add_recommendation(case, action="Reset jane.doe's password on CORP-WS01", phase="contain",
                                 scope="host", urgency="now", basis_ids=[cid])["node_id"]
    ask = add_recommendation(case, action="Ask the operator of CORP-WS01 to preserve the home directory",
                             phase="investigate", scope="host", urgency="soon", basis_ids=[cid])["node_id"]
    lines = _exec_next_steps(case, "en")
    assert lines[:3] == ["", "**Next steps**", ""] and len(lines) == 5
    assert "preserve the home directory" in lines[3] and ask in lines[3]       # investigate first
    assert "Reset jane.doe" in lines[4] and contain in lines[4]
    assert not any("volatile state" in ln for ln in lines)                     # prior knowledge: no step of the case
    for action in ("Hash the share export on CORP-WS01", "Compare the mailbox export on CORP-WS01 with the server copy",
                   "Request the provider's logs for jane.doe"):
        add_recommendation(case, action=action, phase="investigate", scope="host", urgency="later", basis_ids=[cid])
    lines = _exec_next_steps(case, "en")
    assert len(lines) == 7 and lines[-1] == "- +2 more in Recommendations"
    assert all("Next investigative steps" in ln for ln in lines[3:6])          # the examination's order: contain last


def test_next_steps_follow_the_frames_order_on_an_incident_case(tmp_path: Path):
    """A brief that states no engagement is an incident: the first hour
    leads, so a contain row comes before an investigate row."""
    from core.claim_graph import add_claim, add_recommendation
    from core.report_assemble import _exec_next_steps
    case = _case(tmp_path)
    cid = add_claim(case, "jane.doe's account stored files on CORP-WS01", confidence="LIKELY",
                    host="CORP-WS01")["node_id"]
    ask = add_recommendation(case, action="Ask the operator of CORP-WS01 to preserve the home directory",
                             phase="investigate", scope="host", urgency="soon", basis_ids=[cid])["node_id"]
    contain = add_recommendation(case, action="Reset jane.doe's password on CORP-WS01", phase="contain",
                                 scope="host", urgency="now", basis_ids=[cid])["node_id"]
    lines = _exec_next_steps(case, "en")
    assert contain in lines[3] and ask in lines[4]


def test_next_steps_follow_the_frames_order_on_a_subject_case(tmp_path: Path):
    """A device of the person under investigation is a subject frame: the
    examination of their conduct leads, so an investigate row comes before
    a contain row even on a live (incident-response) engagement."""
    from core.claim_graph import add_claim, add_recommendation
    from core.report_assemble import _exec_next_steps
    case = _case(tmp_path)
    (case / "CASE.md").write_text("**Case ID** AsmTest\n**System owner:** suspect\n", encoding="utf-8")
    cid = add_claim(case, "jane.doe's account stored files on CORP-WS01", confidence="LIKELY",
                    host="CORP-WS01")["node_id"]
    contain = add_recommendation(case, action="Reset jane.doe's password on CORP-WS01", phase="contain",
                                 scope="host", urgency="now", basis_ids=[cid])["node_id"]
    ask = add_recommendation(case, action="Ask the operator of CORP-WS01 to preserve the home directory",
                             phase="investigate", scope="host", urgency="soon", basis_ids=[cid])["node_id"]
    lines = _exec_next_steps(case, "en")
    assert ask in lines[3] and contain in lines[4]


def test_attack_timeline_rows_carry_the_records_host_not_the_claims(tmp_path: Path):
    """A finding about one host cites a record of another host: the row is
    the record's host (its source path names it), and a timeline cell that
    holds only digits is no host."""
    from core.report_assemble import _build_attack_timeline_rows
    findings = [{"id": "C0001", "finding_id": "F-001", "statement": "Credential abuse before encryption",
                 "host": "CORP-FS01", "confidence": "LIKELY"}]
    packs = {"C0001": {"selection_mode": "exact", "events": [
        {"text": '{"detections": 3, "hosts": {"ws07.example.test": 3}, "span": {"first": "2031-03-10T16:45:14Z"}}',
         "timestamp": "2031-03-10T16:45:14Z", "host": "", "provenance": "direct", "relevance": 3,
         "source": "analysis/extracted/CORP-WS07/summary.jsonl", "line": 1},
        {"text": "2031-03-10T17:00:00Z\t17\t1\tRecent/000.lnk opened\tlnk\t0",
         "timestamp": "2031-03-10T17:00:00Z", "host": "", "provenance": "direct", "relevance": 3,
         "source": "evidence_index call_id=12", "line": 1},
    ]}}
    rows = _build_attack_timeline_rows(findings, packs, known_hosts=["CORP-FS01", "CORP-WS07"])
    assert [r["host"] for r in rows] == ["CORP-WS07", "CORP-FS01"], rows
