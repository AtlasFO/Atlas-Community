"""The brief's prior-knowledge section as a list of facts: what counts as
one, how one is appended without repeating itself, how one is removed."""
from __future__ import annotations

from core import case_knowledge

TEMPLATE = (
    "# Case: Demo\n\n**Case ID:** Demo\n\n"
    "## Investigation Requests\n\n- What happened?\n\n"
    "## What you already know\n\n"
    "<!-- one bullet per item works well, for example:\n"
    "- The EDR alert carried the hash abc.\n-->\n\n"
    "- We suspect **ransomware** on host WS01.\n"
    "  - a nested note under it\n"
    "2. The firewall logged 203.0.113.9.\n"
    "Prose the analyst wrote without a bullet.\n\n"
    "## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
)


def test_facts_are_the_top_level_bullets_of_the_section():
    facts = case_knowledge.facts_in(TEMPLATE)
    assert facts == ["We suspect ransomware on host WS01.",
                     "The firewall logged 203.0.113.9."]


def test_no_section_means_no_facts():
    assert case_knowledge.facts_in("# Case\n\n## Investigation Requests\n- q\n") == []
    assert case_knowledge.facts_in("") == []


def test_append_adds_after_the_last_bullet_before_the_next_heading():
    out = case_knowledge.append_facts_text(TEMPLATE, ["The account j.doe is a service account."])
    facts = case_knowledge.facts_in(out)
    assert facts[-1] == "The account j.doe is a service account."
    body = out.split("## What you already know", 1)[1].split("## Evidence Links", 1)[0]
    assert body.rstrip().endswith("- The account j.doe is a service account.")
    # The requests section and the table are untouched.
    assert "- What happened?" in out and "| Label | Kind | Path | Notes |" in out


def test_append_skips_a_fact_already_there_however_it_is_spaced():
    out = case_knowledge.append_facts_text(
        TEMPLATE, ["  the FIREWALL logged   203.0.113.9. ", "- We suspect ransomware on host WS01."])
    assert out == TEMPLATE


def test_append_creates_the_section_when_the_brief_has_none():
    md = "# Case: Demo\n\n## Investigation Requests\n\n- What happened?\n"
    out = case_knowledge.append_facts_text(md, ["Backups were last verified in June."])
    assert out.endswith("## What you already know\n\n- Backups were last verified in June.\n")
    assert case_knowledge.facts_in(out) == ["Backups were last verified in June."]


def test_remove_drops_the_bullet_and_leaves_the_rest():
    out = case_knowledge.remove_fact_text(TEMPLATE, "the firewall logged 203.0.113.9.")
    assert case_knowledge.facts_in(out) == ["We suspect ransomware on host WS01."]
    assert "- The EDR alert carried the hash abc." in out  # the comment's example survives
    assert case_knowledge.remove_fact_text(TEMPLATE, "not in there") == TEMPLATE


def test_append_and_remove_write_the_case_file(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(TEMPLATE, encoding="utf-8")
    assert case_knowledge.append_facts(case, ["A new fact."]) == ["A new fact."]
    assert case_knowledge.append_facts(case, ["A new fact."]) == []
    assert "A new fact." in case_knowledge.facts(case)
    assert case_knowledge.remove_fact(case, "A new fact.") is True
    assert "A new fact." not in case_knowledge.facts(case)
    assert case_knowledge.remove_fact(case, "A new fact.") is False


# ── a fenced block is the analyst's pasted data ─────────────────────────

SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
FENCED = (
    "# Case: Demo\n\n## What you already know\n\n"
    "- We suspect data theft from CORP-WS01.\n\n"
    "```\n"
    "# pasted from the proxy export\n"
    "- 203.0.113.7 upload 2031-01-02\n"
    f"sha256 {SHA}\n"
    "```\n\n"
    "## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
)


def test_a_fenced_block_is_read_whole_but_not_split_into_facts():
    text = case_knowledge.section_text(FENCED)
    assert SHA in text
    # A shell comment inside the fence is no heading and ends nothing.
    assert "# pasted from the proxy export" in text
    assert case_knowledge.facts_in(FENCED) == ["We suspect data theft from CORP-WS01."]


def test_a_heading_like_line_in_a_fence_does_not_move_an_appended_fact():
    out = case_knowledge.append_facts_text(FENCED, ["Backups were verified in 2031."])
    body = out.split("## What you already know", 1)[1].split("## Evidence Links", 1)[0]
    assert body.rindex("```") < body.index("- Backups were verified in 2031.")


def test_remove_leaves_a_fenced_line_that_reads_like_the_fact():
    md = FENCED.replace("- We suspect data theft from CORP-WS01.\n",
                        "- 203.0.113.7 upload 2031-01-02\n")
    out = case_knowledge.remove_fact_text(md, "203.0.113.7 upload 2031-01-02")
    assert out.count("- 203.0.113.7 upload 2031-01-02") == 1
    assert case_knowledge.facts_in(out) == []


def test_a_section_holding_only_a_fence_is_present_and_seeds_it(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "CASE.md").write_text(
        f"# Case: Demo\n\n## What you already know\n\n```\nsha256 {SHA}\n```\n",
        encoding="utf-8")
    info = case_knowledge.read(tmp_path)
    assert info["present"] and f"sha256:{SHA}" in info["indicators"]


SEPARATED = (
    "# CASE-A\n\n"
    "## What you already know\n\n"
    "- We suspect data theft from CORP-WS01.\n\n"
    "* * *\n\n"
    "- jane.doe received a phishing mail on 2031-01-02.\n\n"
    "```\n"
    "---\n"
    "```\n\n"
    "{brk}\n\n"
    "## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
)


def test_the_break_before_the_next_heading_is_not_part_of_the_section():
    for brk in ("---", "***", "___", "- - -", " * * *"):
        text = case_knowledge.section_text(SEPARATED.format(brk=brk))
        assert text.endswith("```"), brk
        # An interior break and a break inside a fence are the analyst's text.
        assert "* * *" in text and "---" in text


def test_a_break_is_never_a_fact():
    assert case_knowledge.facts_in(SEPARATED.format(brk="---")) == [
        "We suspect data theft from CORP-WS01.",
        "jane.doe received a phishing mail on 2031-01-02."]


def test_the_prompt_block_ends_with_the_statements(tmp_path):
    (tmp_path / "CASE.md").write_text(
        "# CASE-A\n\n## What you already know\n\n- Backups of CORP-WS01 were verified.\n\n"
        "---\n\n## Investigation Requests\n\n- What happened?\n", encoding="utf-8")
    note = case_knowledge.prompt_note(tmp_path)
    block = note.split("<<<PRIOR KNOWLEDGE", 1)[1].split("PRIOR KNOWLEDGE>>>", 1)[0]
    assert block.strip().endswith("Backups of CORP-WS01 were verified.")
