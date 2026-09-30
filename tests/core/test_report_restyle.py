"""The report reads top-down and cites records a reader can re-find.

Each test pins one rule of the report's shape; the data here is invented so
the rules, not a case, are what is pinned."""
import json
from pathlib import Path

from core.forensic_citation import (
    citation_from_event, describe_record, evtxecmd_fields, normalize_timestamp,
)
from core.report_assemble import (
    _fold_twins, _looks_like_header, _short_event_label, _short_title,
    _build_attack_timeline_rows, assemble_client_report,
)

ROW = ("1000,1000,2031-02-04 12:00:00.0000000,4720,LogAlways,"
       "Microsoft-Windows-Security-Auditing,Security,600,700,"
       "sql02.corp.local,10,,A new account was created,"
       "CORP\\john.roe (S-1-5-21-1111111111-2222222222-3333333333-1105),-")


# ── citations name the record ────────────────────────────────────────────

def test_a_whole_record_still_yields_its_timestamp():
    """The 64-character cap meant no CSV row ever had a time."""
    assert normalize_timestamp(ROW) == "2031-02-04 12:00:00"
    assert normalize_timestamp("++++ r/r 1234-128-4:") == ""


def test_evtxecmd_row_is_read_by_column():
    cols = evtxecmd_fields(ROW)
    assert cols["event_id"] == "4720"
    assert cols["computer"] == "sql02.corp.local"
    assert cols["description"] == "A new account was created"
    assert cols["user"] == "CORP\\john.roe"                # SID suffix dropped
    assert describe_record(ROW) == "Event 4720 (user account created)"


def test_citation_from_a_trace_window_names_artifact_event_and_time():
    c = citation_from_event({"text": ROW, "source": "trace call_id=109"},
                            known_hosts=["PROD-SQL-02"])
    head = c.render(with_excerpt=False)
    assert head.startswith("PROD-SQL-02 · Windows Event Log Security.evtx · "
                           "Event 4720 (user account created) · 2031-02-04 12:00:00")


def test_analyst_locator_is_a_first_class_citation():
    loc = ("sql02 Security.evtx EventID 4720 at 2031-02-04 12:00:00: "
           "Subject=CORP\\john.roe, Target=SQL02\\tempadmin")
    c = citation_from_event({"text": loc, "source": "supporting_evidence"},
                            known_hosts=["PROD-SQL-02"])
    assert "supporting_evidence" not in c.render()
    assert "Security.evtx" in c.render() and "Event 4720" in c.render()
    assert "2031-02-04 12:00:00" in c.render()


# ── the timeline holds events, once each ─────────────────────────────────

def test_header_rows_are_not_events():
    assert _looks_like_header("ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,IsOsComponent,FullPath,")
    assert _looks_like_header("﻿RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider")
    assert not _looks_like_header(ROW)


def test_event_column_names_the_record_not_the_row():
    assert _short_event_label({"text": ROW}) == \
        "Event 4720 (user account created) — A new account was created"


def test_one_event_lists_every_finding_it_supports():
    packs = {"C1": {"events": [{"text": ROW, "provenance": "direct", "relevance": 3}]},
             "C2": {"events": [{"text": ROW, "provenance": "direct", "relevance": 3}]}}
    rows = _build_attack_timeline_rows(
        [{"id": "C1", "finding_id": "F-001", "statement": "x", "host": "PROD-SQL-02"},
         {"id": "C2", "finding_id": "F-002", "statement": "y", "host": "PROD-SQL-02"}],
        packs)
    assert len(rows) == 1
    assert rows[0]["finding"] == "F-001, F-002"
    assert rows[0]["user"] == "CORP\\john.roe"


def test_weakly_related_rows_yield_to_strongly_related_ones():
    weak = {"text": "9,9,2031-02-04 12:30:00.0,4624,L,P,Security,1,1,sql02.corp.local,1,,Successful logon,-\\-,-",
            "provenance": "direct", "relevance": 2}
    strong = {"text": ROW, "provenance": "direct", "relevance": 3}
    rows = _build_attack_timeline_rows(
        [{"id": "C1", "finding_id": "F-001", "statement": "x", "host": "PROD-SQL-02"}],
        {"C1": {"events": [weak, strong]}})
    assert [r["event"] for r in rows] == ["Event 4720 (user account created) — A new account was created"]


# ── findings: headline, once ─────────────────────────────────────────────

def test_short_title_uses_the_written_headline_or_reduces_the_statement():
    f = {"statement": "toolx_uploader_settings.ini found at root of PROD-SQL-02 "
                      "(inode 1234-128-1) containing lastScanTime=1927972800 "
                      "(Unix timestamp ≈ 2031-02-04 12:00:00 UTC).",
         "host": "PROD-SQL-02"}
    assert _short_title(f, {"title": "Tool Configuration at Filesystem Root"}) == \
        "Tool Configuration at Filesystem Root — PROD-SQL-02"
    fallback = _short_title(f, {})
    assert len(fallback) <= 140 and not fallback.endswith("(Unix tim")


def test_twins_fold_into_the_stronger_and_keep_the_other_id():
    base = ("Account 'tempadmin' (SID S-1-5-21-1111111111-2222222222-3333333333-1001) "
            "created on PROD-SQL-02 at 2031-02-04 12:00:00 UTC by CORP\\john.roe.")
    a = {"id": "C1", "finding_id": "F-003", "statement": base,
         "confidence": "LIKELY", "host": "PROD-SQL-02", "input_call_ids": [1]}
    b = {"id": "C9", "finding_id": "F-013", "statement": base + " Enabled (4722).",
         "confidence": "CONFIRMED", "host": "PROD-SQL-02", "input_call_ids": [2]}
    kept = _fold_twins([a, b])
    assert [k["finding_id"] for k in kept] == ["F-013"]
    assert kept[0]["also_recorded_as"] == ["F-003"]
    assert kept[0]["input_call_ids"] == [2, 1]


# ── the whole report ─────────────────────────────────────────────────────

def test_report_answers_the_questions_from_linked_beliefs(tmp_path):
    from core.claim_graph import add_claim
    case = tmp_path / "C"
    for d in (".atlas", "evidence", "analysis", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** RSTest\n")
    cid = add_claim(case, "Ransomware encrypted 800 files on PROD-SQL-02 on "
                          "2031-02-04 12:30:00 UTC (.locked extension).",
                    confidence="LIKELY", enforce_validation=False)["node_id"]
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": "RSTest", "next_id": 3, "tasks": [
            {"id": "task-0001", "text": "What type of attack happened?",
             "status": "answered", "related_claim_ids": [cid],
             "created_at": "x", "updated_at": "x"},
            {"id": "task-0002", "text": "Was data exfiltrated?",
             "status": "open", "related_claim_ids": [],
             "created_at": "x", "updated_at": "x"}]}))
    md = assemble_client_report(case, report_scope="estate")
    assert "## Answers to the Investigation Questions" in md
    assert "### Q1 · What type of attack happened? [LIKELY]" in md
    assert "Supported by F-001" in md
    assert "### Q2 · Was data exfiltrated?" in md
    assert "Not answered — no finding was linked to this question." in md
    # …and the finding block reads top-down with no heading ladder.
    assert "### F-001 · " in md and "[LIKELY]" in md
    assert "**What happened.**" in md and "**Evidence.**" in md
    assert "#### Summary" not in md and "Observed Events" not in md


def test_the_finding_index_belongs_to_its_toc_entry(tmp_path):
    """A findings index written under its own "### 4. Detailed Findings"
    heading makes the report look as though Detailed Findings came before
    the Executive Summary."""
    from core.claim_graph import add_claim
    from core.report_assemble import assemble_client_report

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "reports").mkdir()
    for i in range(3):
        add_claim(case, f"Remote logon {i} to WS-EXAMPLE from 198.51.100.{i}",
                  confidence="LIKELY", host="WS-EXAMPLE")

    md = assemble_client_report(case)
    lines = md.splitlines()
    heads = [ln for ln in lines if ln.startswith("#")]
    # The findings index must not introduce a heading of its own...
    assert not any(ln.startswith("### ") and "Detailed Findings" in ln
                   for ln in heads), "the index must not look like the section"
    # ...and the Executive Summary still comes first among the sections.
    section_heads = [ln for ln in heads if ln.startswith("## ")]
    assert "Table of Contents" in section_heads[0]
    assert "Executive Summary" in section_heads[1], section_heads[:3]
    # The per-finding links survive, nested under their section's entry.
    assert any(ln.startswith("  - [F-001") for ln in lines), \
        "each finding stays reachable from the table of contents"


def test_the_report_anchors_are_rendered_not_printed():
    """The dashboard escapes HTML, so the anchors the assembler writes for
    its own table of contents were shown to the reader as text."""
    import pathlib

    shell = pathlib.Path("dashboard/assets/shell.js").read_text(encoding="utf-8")
    assert 'raw.match(/^\\s*<a id="([a-z0-9._-]+)"><\\/a>\\s*$/i)' in shell, \
        "renderMarkdown must recognise the assembler's anchor lines"
    assert 'class="md-jump"' in shell, \
        "in-page links make a long report navigable"


def test_appendix_says_why_a_curated_timeline_is_absent(tmp_path, monkeypatch):
    """Absent has two meanings: nothing produces one, or the addon that does
    is switched off. A reader of the report gets the difference."""
    from core import plugins
    from core.report_assemble import assemble_client_report
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text(
        "# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n"
        "- What happened?\n", encoding="utf-8")
    from tests.core.test_audit_fixes import _graph_with_claims
    _graph_with_claims(case, 1)

    monkeypatch.setattr(plugins, "addons_for_event",
                        lambda event: [{"addon": "tl", "enabled": False}])
    assert "switched off" in assemble_client_report(case)

    monkeypatch.setattr(plugins, "addons_for_event", lambda event: [])
    assert "no addon installed produces one" in assemble_client_report(case)

