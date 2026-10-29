"""The composer's sheet, parser and check agree on what it names
(core.answer_synthesis): a part the sheet does not list is named nowhere on
it; a dated clock range is a range, never a clock with an offset; a word led
by a dot keeps its space; the sheet's own line ids in a sentence are ids;
a failed composition's reasons reach the trace; and a sentence the model
continued after its citation keeps its separator. Invented fixtures only
(CORP-WS01, jane.doe, 203.0.113.x, dates in 2031); no model is called."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from core import answer_synthesis as A
from core import incident_map
from core.entities import NamePool, name_tokens, unstated
from tests.core.test_answer_compose import GRAPH, LEX, _graph, _node, _task

ONE_PART = dict(_task(), parts=[{"id": "p1", "text": "who ran tool.exe and where it connected", "status": "answered",
                                 "closed_by": "analyst", "claim_ids": ["C0001"]}])
VIEW = {"task_id": "task-0001", "declared_by": "analyst", "part_id": "p1",
        "spec": {"over": "event:connection", "where": {"label": "attacker"}},
        "rows": [{"row_key": "-", "status": "open", "cells": {"time": {"value": "open", "claim": "", "open": True}}}]}


@pytest.fixture
def views(monkeypatch):
    monkeypatch.setattr(incident_map, "views_on", lambda: True)
    monkeypatch.setattr(incident_map, "open", lambda case_dir: SimpleNamespace(views=lambda: [VIEW]))


# one rule for every part the sheet names.

def test_a_part_the_sheet_does_not_list_is_named_nowhere_on_it(tmp_path, views):
    sheet = A.answer_sheet(ONE_PART, GRAPH, [], case_dir=tmp_path)
    assert sheet["shown_parts"] == [] and "PARTS:" not in sheet["text"]
    assert "part p1" not in sheet["text"] and ("C0001", "linked") in sheet["beliefs"]
    assert sheet["views"] and sheet["views"][0]["text"].startswith("rows over event:connection")


def test_a_listed_part_is_named_on_the_note_and_the_view(tmp_path, views):
    sheet = A.answer_sheet(_task(), GRAPH, [], case_dir=tmp_path)
    assert [p["id"] for p in sheet["shown_parts"]] == ["p1", "p2"]
    assert ("C0001", "linked, answers part p1") in sheet["beliefs"]
    assert sheet["views"][0]["text"].startswith("part p1, rows over event:connection")


# a dated clock range is a range.

@pytest.mark.parametrize("belief", ["opened at 2031-03-04 20:26-20:27 UTC", "ran 2031-03-04 09:00-10:00 UTC"])
def test_a_dated_clock_range_is_a_range_with_both_ends(belief):
    pool = NamePool.from_texts([f"Files were {belief}."])
    end = belief.split("-")[-1].split()[0]
    assert unstated(f"until {end} UTC", pool, frozenset()) == []
    assert unstated(belief.split(" ", 1)[1].split(" ", 1)[1], pool, frozenset()) == []
    assert unstated("at 2031-03-04 21:27 UTC", pool, frozenset()) == ["2031-03-04 21:27 utc"]


def test_an_offset_after_seconds_stays_one_zoned_value():
    assert "2031-03-04t09:12:00-04:00" in name_tokens("logon 2031-03-04T09:12:00-04:00")
    assert "2031-03-04 09:12+0530" in name_tokens("logon 2031-03-04 09:12+0530")
    assert not [t for t in name_tokens("logon 2031-03-04T09:12:00+15:00") if "+15" in t]   # past +14:00: no offset


# a word led by a dot keeps its space.

def test_a_dot_led_word_is_not_glued_to_the_word_before():
    graph = _graph(_node("C0001", "CORP-WS01 holds Microsoft .NET Runtime 9 and 40 .pf files."))
    sheet = {"beliefs": [("C0001", "linked")], "shown_parts": [], "question": "What is installed on CORP-WS01?"}
    sents = A.parse_composed("CORP-WS01 holds Microsoft .NET Runtime 9 and 40 .pf files [C0001].")
    assert "Microsoft .NET" in sents[0]["text"] and "40 .pf" in sents[0]["text"]
    assert A.check_composed(sents, sheet, graph, LEX)[0][0]["ok"]
    assert A.parse_composed("tool.exe ran , then stopped . [C0001]")[0]["text"] == "tool.exe ran, then stopped."


# the sheet's own line ids in a sentence are ids.

def test_a_line_id_written_in_the_sentence_is_no_name(tmp_path, views):
    sheet = A.answer_sheet(ONE_PART, GRAPH, [], case_dir=tmp_path)
    results, _ = A.check_composed(A.parse_composed("Row r1 is not established [r1]."), sheet, GRAPH, LEX)
    assert results[0]["ok"], results


# the reasons a composition failed reach the trace.

def _reply(content):
    return SimpleNamespace(content=content, finish_reason="stop", cut_reason="", input_tokens=1, output_tokens=10,
                           reasoning_tokens=0, length_cuts=0)


class _Client:
    def __init__(self, *replies):
        self.replies = list(replies)

    def chat(self, messages, **kw):
        return self.replies.pop(0)

    def next_lower_level(self, role, level=None):
        return None


def test_a_failed_composition_records_its_failing_sentences_per_round(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_ANSWER_COMPOSE", "1")
    (tmp_path / ".atlas").mkdir()
    bad = "\n".join(f"Sentence {n} " + "x" * 300 + f" [C009{n}]." for n in range(8))
    monkeypatch.setattr(A, "_compose_client", lambda: _Client(_reply(bad), _reply(bad)))
    res = A.compose_answer(tmp_path, _task(), GRAPH, [], lexicon=LEX)
    assert res["outcome"] == "fallback" and res["reason"] == "failed_after_repair"
    assert [r["round"] for r in res["failures"]] == [1, 2] and res["failures"][0]["failing"] == 8
    first = res["failures"][0]["sentences"]
    assert len(first) == A.COMPOSE_FAILURES_SHOWN and all(len(s["text"]) <= A.COMPOSE_FAILURE_CHARS for s in first)
    assert "not among the beliefs given" in first[0]["reasons"][0]
    seen = []
    monkeypatch.setattr("core.report_projection._trace", lambda *a, **k: seen.append(a[1]))
    A.trace_composed(res)
    assert '"failures": [{"round": 1, "failing": 8' in seen[0]


# a sentence the model continued after its citation keeps its separator.

@pytest.mark.parametrize("reply,printed", [
    ("tool.exe ran at 10:15 [C0001], and it connected to 203.0.113.7 [C0002].",
     "tool.exe ran at 10:15 [C0001], and it connected to 203.0.113.7 [C0002]."),
    ("tool.exe ran [C0001] and then it connected [C0002].", "tool.exe ran [C0001] and then it connected [C0002]."),
    ("Die Datei wurde ausgefuehrt [C0001] Danach baute sie eine Verbindung auf [C0002].",
     "Die Datei wurde ausgefuehrt [C0001]. Danach baute sie eine Verbindung auf [C0002]."),
    ("tool.exe ran [C0001]; it connected later [C0002].", "tool.exe ran [C0001]; it connected later [C0002]."),
])
def test_the_printed_answer_keeps_the_models_sentence_breaks(reply, printed):
    sents = A.parse_composed(reply)
    assert len(sents) == 2 and A.composed_text(sents) == printed


# The prompt: a sheet that lists no part gets rules with no part mechanics.

def test_a_sheet_without_parts_gets_rules_without_part_mechanics(tmp_path, views):
    sheet = A.answer_sheet(ONE_PART, GRAPH, [], case_dir=tmp_path)
    prompt = A.compose_prompt(dict(sheet, reads=[{"id": "w1", "text": "a read"}],
                                   values=[{"id": "v1", "text": "a value"}]))
    assert prompt.startswith(A.COMPOSE_PARTLESS_PROMPT.split(" The reader")[0])
    assert "part" not in prompt.lower().replace("party", "") and "[p1" not in prompt and "[p2" not in prompt
    assert "9. VIEW lines are rows the question ranges over" in prompt or "VIEW lines are rows the question" in prompt
    numbers = [int(x.split(".")[0]) for x in prompt.splitlines() if x[:1].isdigit()]
    assert numbers == list(range(1, len(numbers) + 1))


def test_a_sheet_with_parts_keeps_the_full_rules_byte_for_byte():
    import hashlib
    sheet = {"shown_parts": [{"id": "p1"}, {"id": "p2"}], "answering": {"p1": ["C0001"]},
             "reads": [1], "values": [1], "window": [1], "views": [1]}
    full = (A.COMPOSE_SYSTEM_PROMPT + A.COMPOSE_READS_RULE + A.COMPOSE_VALUES_RULE + A.COMPOSE_NOT_ANSWERING_RULE
            + A.COMPOSE_WINDOW_RULE + A.COMPOSE_VIEW_RULE)
    assert hashlib.sha256(full.encode()).hexdigest() == \
        "2e36b2ac27a8b42dac3b784b52c80cec61a35c7534678716e4846ba87e552e09"     # the c2-3 rules, unchanged
    with __import__("unittest.mock").mock.patch.object(A, "_structural_parts", lambda: True):
        assert A.compose_prompt(sheet) == full


def test_a_part_id_on_a_sheet_without_parts_is_told_to_cite_beliefs_only():
    sheet = {"beliefs": [("C0001", "linked")], "shown_parts": [], "question": "Who ran tool.exe on CORP-WS01?"}
    results, _ = A.check_composed(A.parse_composed("jane.doe ran tool.exe on CORP-WS01 [p1, C0001]."), sheet, GRAPH, LEX)
    assert results[0]["reasons"] == ["cites p1, but this question lists no parts: cite beliefs only"]
    listed = dict(sheet, shown_parts=[{"id": "p1", "text": "who ran it"}, {"id": "p2", "text": "when"}])
    results, _ = A.check_composed(A.parse_composed("jane.doe ran tool.exe on CORP-WS01 [p9, C0001]."), listed, GRAPH, LEX)
    assert results[0]["reasons"] == ["cites p9, not among the beliefs given"]
