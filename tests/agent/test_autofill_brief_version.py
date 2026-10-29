"""atlas autofill writes its proposal only onto the brief it was made from:
the rewrite of the prior-knowledge section replaces that section whole, so a
fact or question saved while the command waited for the model or the
operator would be dropped. The command refuses that write and says so; with
no change meanwhile it writes as before. Invented case only."""
from __future__ import annotations

import argparse

import pytest

from agent import cli
from core import case_autofill, case_knowledge
from core.investigation_tasks import case_markdown_version, read_case_markdown

ROW = {"path": "evidence/CORP-WS01.E01", "label": "CORP-WS01", "kind": "disk", "notes": ""}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "CASE-A"
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.md").write_text(
        "**Case ID:** CASE-A\n\n## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n\n"
        "## Investigation Requests\n- What ran on CORP-WS01?\n", encoding="utf-8")
    monkeypatch.setattr(cli, "_configure_usage", lambda *a, **k: "")
    monkeypatch.setattr(case_autofill, "build_proposal", lambda c: {
        "case_id": "CASE-A", "rows": [dict(ROW)], "unsure": [], "investigation_requests_empty": False,
        "unclosed_fence": None, "prior_knowledge": "",
        "version": case_markdown_version(read_case_markdown(c))})
    return d


def _run(case):
    cli.cmd_case_autofill(argparse.Namespace(case=str(case), yes=True))


def test_a_brief_saved_meanwhile_is_kept_and_nothing_is_written(case, monkeypatch):
    real = case_autofill.splice_case_md

    def splice_after_another_save(md, rows, **kw):
        case_knowledge.append_facts(case, ["10.0.0.5 is the print server."])
        return real(md, rows, **kw)
    monkeypatch.setattr(case_autofill, "splice_case_md", splice_after_another_save)
    with pytest.raises(SystemExit, match="changed while the rewrite was prepared"):
        _run(case)
    md = read_case_markdown(case)
    assert "10.0.0.5 is the print server." in md and "CORP-WS01.E01" not in md


def test_with_no_change_meanwhile_the_rows_are_written(case):
    _run(case)
    md = read_case_markdown(case)
    assert "evidence/CORP-WS01.E01" in md and "- What ran on CORP-WS01?" in md
    assert not [p.name for p in case.iterdir() if p.name.endswith(".tmp")]
