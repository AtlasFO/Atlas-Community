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
