"""Standard forensic report spine + i18n smoke tests."""
from __future__ import annotations

from pathlib import Path

from core.case_config import set_report_language
from core.claim_graph import add_claim
from core.finding_index import ensure_finding_ids
from core.incremental import plane_a_scan
from core.report_i18n import section_title, t
from core.report_projection import (
    assemble_report,
    default_report_output_path,
    deterministic_section_generator,
    mark_stale_sections,
    regenerate_sections,
    render_markdown,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** FmtTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"x")
    return case


def test_standard_spine_and_f_ids(tmp_path: Path):
    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Interactive RDP session as Administrator from 203.0.113.71",
        confidence="CONFIRMED",
        host="DC02",
    )
    ensure_finding_ids(case)
    mark_stale_sections(case, force_all=True)
    regenerate_sections(
        case, generator=deterministic_section_generator, only_stale=True,
    )
    text = render_markdown(case)
    for needle in (
        "Table of Contents",
        "Executive Summary",
        "Key Findings",
        "Detailed Findings",
        "Attack Timeline",
        "Recommendations",
        "Appendix",
        "F-001",
        "section:detailed_findings",
    ):
        assert needle in text, needle
    # Key Findings table
    assert "| ID | Statement | Host | When | Confidence |" in text


def test_german_headings_evidence_untouched(tmp_path: Path):
    case = _case(tmp_path)
    set_report_language(case, "de")
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "ExampleLocker ransomware encrypted files (T1486)",
        confidence="CONFIRMED",
        evidence=[{
            "artifact": "analysis/demo.csv",
            "locator": "ExampleLocker DETECTED",
        }],
    )
    (case / "analysis").mkdir(exist_ok=True)
    (case / "analysis" / "demo.csv").write_text(
        "ts,msg\n1,ExampleLocker DETECTED raw-line\n", encoding="utf-8",
    )
    mark_stale_sections(case, force_all=True)
    regenerate_sections(
        case, generator=deterministic_section_generator, only_stale=True,
    )
    text = render_markdown(case)
    assert "Inhaltsverzeichnis" in text
    assert "Wesentliche Erkenntnisse" in text or section_title("key_findings", "de") in text
    assert "Forensischer Untersuchungsbericht" in text
    # Evidence content not translated
    assert "ExampleLocker" in text


def test_default_paths_modern_names(tmp_path: Path):
    case = _case(tmp_path)
    assert default_report_output_path(case, scope="estate").endswith(
        "estate_report.md"
    )
    assert default_report_output_path(
        case, scope="host", host="DC02",
    ).endswith("host_DC02_report.md")
    plane_a_scan(case, persist=True)
    add_claim(case, "Brute-force T1110", confidence="LIKELY")
    mark_stale_sections(case, force_all=True)
    regenerate_sections(
        case, generator=deterministic_section_generator, only_stale=True,
    )
    asm = assemble_report(case, report_scope="estate")
    assert asm["success"]
    assert Path(asm["output_path"]).name == "estate_report.md"


def test_i18n_glossary_keys():
    assert t("supporting_evidence", "en") == "Supporting Evidence"
    assert t("supporting_evidence", "de") == "Unterstützende Beweise"
    assert section_title("timeline", "de").startswith("5.")
