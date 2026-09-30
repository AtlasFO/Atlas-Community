"""CASE-derived investigation intents (opt-in, not silent curriculum)."""
from __future__ import annotations

import json
from pathlib import Path

from core.case_intents import considers_hid_injection


def test_default_no_hid_intent(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("Investigate ransomware on the file server.\n")
    assert considers_hid_injection(case) is False


def test_case_md_opt_in(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(
        "Was initial access via BadUSB / keystroke injection?\n"
    )
    assert considers_hid_injection(case) is True


def test_case_config_intents_flag(tmp_path: Path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "CASE.md").write_text("Timeline reconstruction only.\n")
    (case / ".atlas" / "case_config.json").write_text(json.dumps({
        "schema_version": "1.0",
        "report_language": "en",
        "intents": {"hid_injection": True},
    }))
    assert considers_hid_injection(case) is True


def test_finding_text_opt_in_without_case(tmp_path: Path):
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("Generic intrusion case.\n")
    assert considers_hid_injection(
        case, finding_text="Ruling out keystroke injection for the console session",
    ) is True
