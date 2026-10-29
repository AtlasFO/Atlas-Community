"""The case in every item and triage call, a purpose
line per item, observations in their own report section. Invented
fixtures only (CASE-A, CORP-DC01, CORP-WS01, jane.doe, dates in 2031)."""
from __future__ import annotations

import json

from core import frontier_prompts as P
from tests.core.test_incident_map import _case, _trace

_BRIEF = """# CASE-A

## Question
How did the attacker reach CORP-DC01?

## Known facts
The first alert fired on 2031-03-10 at 14:02 on CORP-WS01.

## Context and false positives
The responders' collection agent ran on every host from 2031-03-11; jane.doe is the administrator.
"""


def _brief(case, text=_BRIEF):
    (case / "CASE.md").write_text(text, encoding="utf-8")
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "text": "How did the attacker reach CORP-DC01?", "status": "open",
         "parts": [{"id": "p1", "text": "the first access to CORP-DC01", "status": "open"}]}]}), encoding="utf-8")


def test_the_case_block_is_the_brief_as_written_and_a_long_one_is_fitted_by_sections(tmp_path):
    case = _case(tmp_path)
    _brief(case)
    block = P.case_block(case)
    assert block.startswith("THE CASE") and "responders' collection agent" in block and "Shortened" not in block
    long = _BRIEF.replace("is the administrator.", "is the administrator. " + "More context. " * 400)
    _brief(case, long)
    fitted = P.case_block(case, budget=1200)
    assert "## Question" in fitted and "## Known facts" in fitted and "[shortened]" in fitted
    assert "(Shortened to fit: Context and false positives)" in fitted and len(fitted) < 1600



def test_a_brief_is_cut_only_when_it_does_not_fit_beside_the_item_and_never_its_questions(tmp_path, monkeypatch):
    case = _case(tmp_path)
    long = _BRIEF.replace("is the administrator.", "is the administrator. " + "More context. " * 400)
    _brief(case, long)
    monkeypatch.setattr("agent.loop.context_char_budget", lambda: 100_000)
    assert "Shortened" not in P.case_block(case)                         # far above any share, still whole
    assert "Shortened" not in P.with_case(case, "x" * 20_000)
    tight = P.case_block(case, rest=47_000)
    assert "[shortened]" in tight and "How did the attacker reach CORP-DC01?" in tight
    asks = long.replace("How did the attacker reach CORP-DC01?", "- How did the attacker reach CORP-DC01? "
                        + "In detail. " * 200)
    _brief(case, asks)
    kept = P.case_block(case, budget=1200)
    assert "In detail. " * 200 in kept and "(Shortened to fit: Context and false positives)" in kept


def test_every_item_opens_with_the_case_and_its_purpose(tmp_path, monkeypatch):
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _brief(case)
    host = P.item_text(case, {"call_id": 1, "origin": "host_pass", "source_ref": {"host": "CORP-WS01"}}, None)
    assert host.startswith("THE CASE") and "PURPOSE: the attacker's activity on CORP-WS01" in host
    plan = P.item_text(case, {"call_id": 2, "origin": "plan", "task_ids": ["task-0001"], "target": {},
                              "source_ref": {"part_id": "p1"}}, None)
    assert "PURPOSE: question task-0001 part p1: the first access to CORP-DC01" in plan
    cover = P.item_text(case, {"call_id": 3, "origin": "plan", "_origin": "triage", "target": {}}, None)
    assert "PURPOSE: coverage of an evidence class" in cover


def test_the_triage_call_carries_the_case_block(tmp_path, monkeypatch):
    from core import evidence_triage as TR
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _brief(case)
    msg = TR.triage_message(case, {"classes": {}}, {"id": "x", "path": "evidence/x.raw"}, "s")
    assert msg.startswith("THE CASE") and "responders' collection agent" in msg


def test_observations_have_their_own_report_section_and_stay_out_of_the_answers(tmp_path, monkeypatch):
    from core import incident_map as IM
    from core.report_assemble import assemble_client_report
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _brief(case)
    IM.open(case).add_observation("A backup agent runs as a service on CORP-WS01.", "CORP-WS01",
                                  "2031-03-10 09:00:00", [])
    report = assemble_client_report(case, compose=False)
    head = "## Observations without a question or side"
    assert head in report and "A backup agent runs as a service" in report.split(head)[1]
    assert "A backup agent" not in report.split(head)[0]
