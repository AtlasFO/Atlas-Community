"""How the analyst's prior knowledge reaches the model: one block with every
statement and its id under one contract, a brief without the template's
comments, a pivot nudge that quotes the statement behind an indicator the
analyst named, and a report line per statement."""
from __future__ import annotations

import json

import pytest

from core import case_knowledge as ck
from core import ioc_pivots as ip

BRIEF = (
    "# Case: CASE-A\n\n**Case ID:** CASE-A\n\n"
    "## Investigation Requests\n\n"
    "<!-- Append one bullet per request, for example:\n"
    "- Determine whether the workstation was compromised.\n-->\n\n"
    "- What left CORP-WS01?\n\n"
    "## What you already know\n\n"
    "<!-- one bullet per item works well, for example:\n"
    "- We suspect a ransomware intrusion that began around <date>.\n-->\n\n"
    "- We suspect data theft that began around 2031-01-02.\n"
    "- 10.0.0.5 is our admin jump host; CORP\\jane.doe administers it.\n"
    "- The proxy logged uploads from CORP-WS01 to 203.0.113.7.\n\n"
    "## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
)


@pytest.fixture(autouse=True)
def _no_brain(monkeypatch):
    monkeypatch.setenv("ATLAS_NO_BRAIN", "1")


def _case(tmp_path, brief=BRIEF, *, graded=False, reconcile=True, claims=()):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "fw.log").write_text(
        "2031-01-02 10:00 ALLOW 10.0.0.5 -> 203.0.113.7:443\n", encoding="utf-8")
    (case / "CASE.md").write_text(brief, encoding="utf-8")
    if graded:
        (case / "ground_truth.json").write_text('{"expected_findings": []}', encoding="utf-8")
    if claims:
        (case / ".atlas").mkdir(exist_ok=True)
        nodes = {f"C{i:04d}": {"id": f"C{i:04d}", "kind": "claim", "status": "new",
                               "statement": text}
                 for i, text in enumerate(claims, start=1)}
        (case / ".atlas" / "claim_graph.json").write_text(
            json.dumps({"schema_version": "1.0", "nodes": nodes, "edges": []}),
            encoding="utf-8")
    if reconcile:
        from core.analyst_context import reconcile_case_knowledge
        reconcile_case_knowledge(case)
    return case


def _data(block: str) -> str:
    return block.split("<<<PRIOR KNOWLEDGE\n", 1)[1].split("\nPRIOR KNOWLEDGE>>>", 1)[0]


class TestBlock:
    def test_every_statement_stands_with_its_id_under_one_contract(self, tmp_path):
        block = ck.prompt_note(_case(tmp_path))
        data = _data(block)
        assert "- [ac-0001] We suspect data theft that began around 2031-01-02." in data
        assert "- [ac-0002] 10.0.0.5 is our admin jump host; CORP\\jane.doe administers it." in data
        assert ck.CONTRACT in block
        assert "not a blind allowlist" in block and "never exoneration" in block
        # The template's commented example is no statement of the analyst's.
        assert "ransomware" not in block
        assert "[ioc pivot] nudge" in block

    def test_chat_has_no_nudge_to_promise(self, tmp_path):
        block = ck.prompt_note(_case(tmp_path), chat=True)
        assert "10.0.0.5 is our admin jump host" in block
        assert "[ioc pivot]" not in block

    def test_a_graded_case_shows_the_statements_but_not_why_nothing_is_seeded(self, tmp_path):
        block = ck.prompt_note(_case(tmp_path, graded=True))
        assert "10.0.0.5 is our admin jump host" in block
        assert "answer key" not in block and "graded" not in block
        assert "seeded" not in block

    def test_entries_given_outside_the_brief_reach_a_fresh_run(self, tmp_path):
        from core.analyst_context import add_context
        case = _case(tmp_path)
        entry = add_context(case, "IP 10.0.1.9 is the backup server.")
        data = _data(ck.prompt_note(case))
        assert "Also standing, given outside CASE.md:" in data
        assert f"- [{entry['id']}] IP 10.0.1.9 is the backup server." in data

    def test_the_block_is_bounded_and_says_where_the_rest_stands(self, tmp_path):
        many = "".join(f"- Host CORP-SRV{i:03d} runs the nightly backup job.\n" for i in range(400))
        brief = "# Case: CASE-A\n\n## What you already know\n\n" + many
        block = ck.prompt_note(_case(tmp_path, brief, reconcile=False))
        assert len(_data(block)) <= ck._BLOCK_CHARS + 120
        assert "the rest stands in CASE.md" in block

    def test_nothing_to_show_means_no_block(self, tmp_path):
        brief = BRIEF.split("- We suspect data theft")[0] + "## Evidence Links\n"
        assert ck.prompt_note(_case(tmp_path, brief)) == ""

    def test_a_cut_inside_pasted_data_closes_its_fence(self, tmp_path):
        rows = "".join(f"2031-01-02 10:{i % 60:02d} ALLOW 10.0.0.{i % 250} -> 203.0.113.7\n"
                       for i in range(400))
        brief = "# Case: CASE-A\n\n## What you already know\n\n```\n" + rows + "```\n"
        data = _data(ck.prompt_note(_case(tmp_path, brief, reconcile=False)))
        assert data.count("```") % 2 == 0
        assert data.rstrip().endswith("under 'What you already know')")

    def test_the_seeded_count_is_what_the_ledger_can_hold(self, tmp_path):
        servers = "".join(f"- 198.51.100.{i} is one of our file servers.\n"
                          for i in range(1, ip.MAX_PIVOTS + 6))
        block = ck.prompt_note(_case(tmp_path, "# Case: CASE-C\n\n## What you already know\n\n"
                                     + servers, reconcile=False))
        assert f"{ip.MAX_PIVOTS} indicator(s) named here" in block

    def test_an_entry_given_outside_the_brief_and_written_there_too_shows_once(self, tmp_path):
        from core.analyst_context import add_context
        case = _case(tmp_path)
        add_context(case, "10.0.0.5 is our admin jump host; CORP\\jane.doe administers it.")
        data = _data(ck.prompt_note(case))
        assert data.count("10.0.0.5 is our admin jump host") == 1
        assert "Also standing" not in data


class TestCaseFile:
    def test_the_brief_carries_no_comments_and_points_at_the_block(self, tmp_path):
        from agent.prompts import build_system_prompt
        sp = build_system_prompt(_case(tmp_path))
        case_file = sp.split("# CASE FILE", 1)[1].split("# PRIOR KNOWLEDGE", 1)[0]
        assert "<!--" not in case_file and "for example" not in case_file
        assert "(shown below under PRIOR KNOWLEDGE" in case_file
        assert "- What left CORP-WS01?" in case_file
        assert sp.count("10.0.0.5 is our admin jump host") == 1

    def test_a_late_fact_on_a_long_brief_is_shown_and_the_cut_names_what_it_hides(self, tmp_path):
        from agent.prompts import build_system_prompt
        long = ("# Case: CASE-B\n\n## Investigation Requests\n\n- What happened on CORP-WS01?\n\n"
                "## Scenario\n\n" + "A narrative line about the estate. " * 300
                + "\n\n## Tool Notes\n\nNotes.\n")
        case = _case(tmp_path, long, reconcile=False)
        ck.append_facts(case, ["The account CORP\\svc.backup is a service account."])
        sp = build_system_prompt(case)
        assert "CORP\\svc.backup is a service account." in sp
        note = sp.split("…(CASE.md cut at", 1)[1].split(")", 1)[0]
        assert "## Tool Notes" in note
        assert "What you already know" not in note

    def test_a_brief_with_windows_line_ends_is_cut_and_named_like_any_other(self):
        # File reads already fold CRLF; the renderer must not depend on it.
        from agent.prompts import _case_file_text
        body = "".join(f"A narrative line {i:03d} about the estate.\n" for i in range(240))
        long = ("# Case: CASE-B\n\n## Investigation Requests\n\n- What happened on CORP-WS01?\n\n"
                "## Scenario\n\n" + body + "\n## Scope\n\nThe estate.\n")
        lf = _case_file_text(long, knowledge_shown=False)
        assert "not shown: ## Scope" in lf
        assert _case_file_text(long.replace("\n", "\r\n"), knowledge_shown=False) == lf


class TestPivots:
    def test_the_nudge_quotes_the_statement_behind_an_analyst_named_indicator(self, tmp_path):
        case = _case(tmp_path)
        ip.refresh_pivots(case)
        text = ip.format_pivot_nudge(ip.open_pivots(case), case_dir=case)
        assert ('statement ac-0002: "10.0.0.5 is our admin jump host; '
                'CORP\\jane.doe administers it."') in text
        assert "what a hit means depends on the statement" in text and "record it now" in text
        assert "corroborating hit is a finding" not in text
        assert "case_md" not in text

    def test_a_finding_named_indicator_keeps_its_corroboration_rule(self, tmp_path):
        case = _case(tmp_path, claims=("Beacon to 203.0.113.44 seen.",))
        ip.refresh_pivots(case)
        text = ip.format_pivot_nudge(ip.open_pivots(case), case_dir=case)
        assert "203.0.113.44 (from C0001)" in text
        assert "corroborating hit is a finding" in text

    def test_a_brief_describing_the_estate_does_not_crowd_out_the_runs_indicators(self, tmp_path):
        servers = "".join(f"- 198.51.100.{i} is one of our file servers.\n"
                          for i in range(1, ip.MAX_PIVOTS + 6))
        brief = "# Case: CASE-C\n\n## What you already know\n\n" + servers
        case = _case(tmp_path, brief, claims=("Beacon to 203.0.113.44 seen.",))
        pivots = ip.refresh_pivots(case)["pivots"]
        assert "ip:203.0.113.44" in pivots
        assert sum(1 for p in pivots.values() if p["origin"] == ck.ORIGIN) == ip.MAX_PIVOTS

    def test_only_a_shown_nudge_reads_the_brief_for_statements(self, tmp_path, monkeypatch):
        """open_pivots runs every turn and the obligation at every check;
        neither pays for parsing the brief. The nudge, every few turns, does."""
        from core.investigation_obligations import _ioc_pivot_obligations
        case = _case(tmp_path)
        ip.refresh_pivots(case)

        def _no_read(*_a, **_k):
            raise AssertionError("the brief was read for statements")
        monkeypatch.setattr(ck, "indicator_statements", _no_read)
        assert ip.open_pivots(case)
        assert _ioc_pivot_obligations(case)

    def test_the_obligation_counts_what_the_analyst_named(self, tmp_path):
        from core.investigation_obligations import _ioc_pivot_obligations
        case = _case(tmp_path)
        ip.refresh_pivots(case)
        detail = _ioc_pivot_obligations(case)[0]["detail"]
        assert "named by the analyst in CASE.md" in detail
        assert "recorded but" not in detail


class TestReport:
    def test_each_statement_names_the_findings_that_name_what_it_names(self, tmp_path):
        from core.analyst_context import report_lines
        case = _case(tmp_path, claims=("Uploads from CORP-WS01 to 203.0.113.7 on 2031-01-02.",))
        findings = [{"id": "C0001", "finding_id": "F-001"}]
        lines = report_lines(case, findings, "en")
        by_id = {line.split("`")[1]: line for line in lines if line.startswith("- `")}
        assert by_id["ac-0003"].endswith("named in F-001")
        assert by_id["ac-0002"].endswith("named in no finding")
        assert by_id["ac-0001"].endswith("names no address, account or host")
        assert any(line.endswith("genannt in F-001")
                   for line in report_lines(case, findings, "de"))
