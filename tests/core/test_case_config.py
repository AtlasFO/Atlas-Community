"""The engagement type a case brief states: read from CASE.md in the
forms the template and a metadata table use, in English and German,
never from a comment, never across a line; absent, the case is an
incident, as every case was before the field existed; an unknown value
is reported, not guessed."""
from __future__ import annotations

import pytest

from core.case_config import (DEFAULT_ENGAGEMENT, engagement_field, engagement_status,
                              get_engagement, is_examination, parse_engagement,
                              unrecognized_engagement)


@pytest.mark.parametrize("text, expected", [
    ("**Engagement:** examination", "examination"),
    ("**Engagement:** incident-response", "incident-response"),
    ("| **Engagement** | examination |", "examination"),
    ("| **Engagement** | examination — seized devices examined after the fact |", "examination"),
    ("| Engagement | examination |", "examination"),
    ("engagement: post-mortem", "examination"),
    ("Engagement type: dead-box examination", "examination"),
    ("**Engagement:** *examination*", "examination"),
    ("**Engagement:** `incident-response`", "incident-response"),
    ("**Engagement:** live forensic examination", "examination"),
    ("**Engagement:** IR", "incident-response"),
    ("**Engagement:** live response", "incident-response"),
    ("**Engagement:** Untersuchung", "examination"),
    ("**Engagement:** nachträgliche Untersuchung", "examination"),
    ("**Engagement:** Vorfallsreaktion", "incident-response"),
    ("**Engagement:** examination of the seized laptop", "examination"),
])
def test_the_forms_and_words_a_brief_uses(text, expected):
    assert parse_engagement("# Case: X\n\n" + text + "\n\n## Investigation Requests\n") == expected


@pytest.mark.parametrize("text", [
    "Rules of engagement: examination only of the images provided.",
    "The engagement letter was signed on 2026-01-02.",
    "Engagement of external counsel was approved for the examination of the laptop.",
    "Engagement letter signed; the images arrived on 2026-01-02.",
    "",
])
def test_prose_about_engagements_is_not_the_field(text):
    assert not engagement_field(text)[0]


def test_a_prose_line_does_not_shadow_the_field():
    text = ("Engagement of external counsel was approved for the examination of the laptop.\n"
            "**Engagement:** incident-response\n")
    assert parse_engagement(text) == "incident-response"


def test_an_empty_field_does_not_swallow_the_next_line():
    present, raw, canonical = engagement_field(
        "**Engagement:**\nExamination requests are listed below.\n")
    assert present and raw == "" and canonical is None


def test_a_commented_out_line_is_not_read():
    text = "<!-- **Engagement:** examination -->\n**Engagement:** incident-response\n"
    assert parse_engagement(text) == "incident-response"


def test_an_unknown_value_is_reported_not_guessed(tmp_path):
    case = tmp_path / "CASE"
    case.mkdir()
    (case / "CASE.md").write_text("**Case ID:** CASE\n**Engagement:** examniation\n", encoding="utf-8")
    assert get_engagement(case) == DEFAULT_ENGAGEMENT
    warning = unrecognized_engagement(case)
    assert warning and "examniation" in warning and "incident-response" in warning
    status = engagement_status(case)
    assert status["stated"] and status["unrecognized"] and status["raw"] == "examniation"


def test_a_case_without_the_field_is_an_incident(tmp_path):
    case = tmp_path / "CASE"
    case.mkdir()
    assert get_engagement(case) == "incident-response" and not is_examination(case)
    (case / "CASE.md").write_text("**Case ID:** CASE\n", encoding="utf-8")
    assert get_engagement(case) == "incident-response"
    assert unrecognized_engagement(case) is None
    status = engagement_status(case)
    assert status["system_owner"]["value"] == "unknown"
    assert {k: v for k, v in status.items() if k != "system_owner"} == {
        "value": "incident-response", "stated": False, "raw": "", "unrecognized": False}


def test_claude_md_is_read_as_the_brief_too(tmp_path):
    case = tmp_path / "CASE"
    case.mkdir()
    (case / "CLAUDE.md").write_text("**Case ID:** CASE\n**Engagement:** examination\n", encoding="utf-8")
    assert is_examination(case)


class TestSystemOwner:
    """Whose system the evidence comes from is read from its own field: the
    first word decides, a possessive included; a bare "Owner:" line names
    the case owner and is not the field; absent or unrecognised, the owner
    is unknown and the report will state the assumption."""

    @pytest.mark.parametrize("text, expected", [
        ("**System owner:** victim", "victim"),
        ("**System owner:** victim organisation", "victim"),
        ("| **System owner** | suspect's own laptop |", "suspect"),
        ("| System owner | Suspect |", "suspect"),
        ("**Device owner:** suspect (seized)", "suspect"),
        ("**System owner:** unknown", "unknown"),
        ("**Systeminhaber:** Opfer (Unternehmen)", "victim"),
        ("**Geräteeigentümer:** Beschuldigter", "suspect"),
        ("**Geraeteeigentuemer:** Tatverdächtige", "suspect"),
        ("**System owner:** *victim*", "victim"),
        ("**System owner:** victims and suspects", "victim"),
    ])
    def test_the_forms_and_words_a_brief_uses(self, text, expected):
        from core.case_config import parse_system_owner
        assert parse_system_owner("# Case: X\n\n" + text + "\n") == expected

    def test_the_first_word_decides_when_both_classes_appear(self):
        from core.case_config import system_owner_field
        present, raw, canonical = system_owner_field(
            "**System owner:** the suspect's employer's laptop\n")
        assert present and canonical is None
        assert system_owner_field("**System owner:** suspect's employer's laptop\n")[2] == "suspect"

    def test_a_bare_owner_line_is_not_the_field(self):
        from core.case_config import system_owner_field
        assert not system_owner_field("**Owner:** suspect\n")[0]
        assert not system_owner_field("Owner: victim organisation\n")[0]

    def test_absent_or_unrecognised_is_unknown_and_reported(self, tmp_path):
        from core.case_config import (engagement_status, get_system_owner, is_suspect_device,
                                      unrecognized_system_owner)
        case = tmp_path / "CASE"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID:** CASE\n", encoding="utf-8")
        assert get_system_owner(case) == "unknown" and not is_suspect_device(case)
        assert unrecognized_system_owner(case) is None
        status = engagement_status(case)["system_owner"]
        assert status == {"value": "unknown", "stated": False, "raw": "", "unrecognized": False}
        (case / "CASE.md").write_text("**Case ID:** CASE\n**System owner:** the company\n",
                                      encoding="utf-8")
        assert get_system_owner(case) == "unknown"
        warning = unrecognized_system_owner(case)
        assert warning and "the company" in warning and "victim" in warning
        assert engagement_status(case)["system_owner"]["unrecognized"]
        (case / "CASE.md").write_text("**Case ID:** CASE\n**System owner:** suspect\n",
                                      encoding="utf-8")
        assert is_suspect_device(case) and unrecognized_system_owner(case) is None

    def test_the_prompt_note_follows_owner_and_engagement(self, tmp_path):
        from core.case_config import engagement_prompt_note
        case = tmp_path / "CASE"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID:** CASE\n**System owner:** victim\n",
                                      encoding="utf-8")
        assert engagement_prompt_note(case) == ""
        (case / "CASE.md").write_text(
            "**Case ID:** CASE\n**Engagement:** examination\n**System owner:** victim\n",
            encoding="utf-8")
        note = engagement_prompt_note(case)
        assert "owner's duties remain" in note and "assume" not in note
        (case / "CASE.md").write_text("**Case ID:** CASE\n**Engagement:** examination\n",
                                      encoding="utf-8")
        assert "assume the owner is the victim" in engagement_prompt_note(case)
        (case / "CASE.md").write_text(
            "**Case ID:** CASE\n**Engagement:** examination\n**System owner:** suspect\n",
            encoding="utf-8")
        note = engagement_prompt_note(case)
        assert "person under investigation" in note and "seized running" not in note
        (case / "CASE.md").write_text("**Case ID:** CASE\n**System owner:** suspect\n",
                                      encoding="utf-8")
        assert "seized running" in engagement_prompt_note(case)


class TestSubjectField:
    META = "# Case\n\n## Case Metadata\n\n| Field | Value |\n|---|---|\n| **Engagement** | examination |\n"

    def test_the_metadata_table_and_the_template_line_name_the_subject(self):
        from core.case_config import subject_field, subject_identifiers
        brief = (self.META + "| **Subject** | \"Jane Roe\" — analyst, Acme Ltd |\n"
                 "| **Subject username** | `jroe` (profile on the PC) |\n| **Subject mail** | jane.roe@mail.example.org |\n"
                 "| **Subject sophistication** | some knowledge of forensics |\n\n## Scenario\n\nSubject: Payment advice\n")
        assert subject_field(brief) == (True, "\"Jane Roe\" — analyst, Acme Ltd")
        ids = subject_identifiers(brief)
        assert {"jane roe", "jroe", "jane.roe@mail.example.org"} <= ids
        assert "some knowledge of forensics" not in ids
        assert subject_field("**Case ID:** X\n**Subject:** J. Doe\n") == (True, "J. Doe")
        assert subject_field("**Case ID:** X\n**Beschuldigter:** J. Doe\n") == (True, "J. Doe")

    def test_a_pasted_mail_header_or_a_tabulated_lure_is_not_the_subject(self):
        from core.case_config import subject_field
        assert subject_field("# Case\n\nThe lure read:\n\nSubject: Payment advice\nFrom: x@example.org\n")[0] is False
        assert subject_field("# Case\n\n## Lure\n\n| Header | Text |\n|---|---|\n| Subject | Invoice overdue |\n")[0] is False
        assert subject_field(self.META)[0] is False

    def test_a_lure_table_with_a_field_value_header_is_not_case_metadata(self):
        from core.case_config import subject_field, subject_identifiers
        lure = ("# Case\n\n## The lure\n\n| Field | Value |\n|---|---|\n| From | billing@example.org |\n"
                "| Subject | Invoice overdue |\n")
        assert subject_field(lure)[0] is False
        # the brief's first table counts when it carries a case field, and only that table
        first = ("# Case\n\n| Field | Value |\n|---|---|\n| Case ID | X |\n| Subject | J. Doe |\n\n"
                 "## The lure\n\n| Field | Value |\n|---|---|\n| Subject | Invoice overdue |\n")
        assert subject_field(first) == (True, "J. Doe")
        # a metadata heading wins over an earlier table without a case field
        headed = ("# Case\n\n| Field | Value |\n|---|---|\n| From | x@example.org |\n| Subject | Invoice overdue |\n\n"
                  "## Case Metadata\n\n| Field | Value |\n|---|---|\n| Subject | J. Doe |\n")
        assert subject_field(headed) == (True, "J. Doe")
        # a backticked artefact beside the name is not an identifier
        ids = subject_identifiers(self.META + "| **Subject** | J. Doe |\n| **Subject account** | `jdoe` (bound via `irun.ini`, `C:\\Users\\jdoe`) |\n")
        assert "jdoe" in ids and "irun.ini" not in ids and not any("users" in i for i in ids)

    def test_the_german_labels_leave_out_the_data_subject(self):
        from core.case_config import subject_field
        assert subject_field("## Metadaten\n\n| Feld | Wert |\n|---|---|\n| Tatverdächtiger | J. Doe |\n") == (True, "J. Doe")
        assert subject_field("## Metadaten\n\n| Feld | Wert |\n|---|---|\n| Betroffene Person | J. Doe |\n")[0] is False
