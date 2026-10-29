"""ATLAS_ANSWER_READS_VALUES: the composer's sheet carries the work
order's reads for the question (READS) and the typed values of the shown
beliefs with their sighting state (VALUES); each line is citable like a part
and a sentence citing it is held to the line's text. Invented fixtures only
(CORP-WS01, jane.doe, 203.0.113.x, example.com); no model is called."""
from __future__ import annotations

import copy

import pytest

import core.execution_log as elog
from core import answer_synthesis as A
from tests.core.test_answer_compose import GRAPH, LEX, _task


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "case"
    (root / "analysis").mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    return root


def _graph_with_values():
    g = copy.deepcopy(GRAPH)
    g["nodes"]["C0002"]["indicators"] = [
        {"type": "ip", "value": "203.0.113.7", "side": "attacker",
         "sightings": [{"call": 4, "host": "CORP-WS01", "located": True},
                       {"call": 9, "host": "CORP-WS01", "located": True}]}]
    from core.indicators import DROP_REASON_NO_SIGHTING
    g["nodes"]["C0002"]["indicators_dropped"] = [
        {"type": "domain", "value": "portal.example.com", "side": "attacker",
         "reason": DROP_REASON_NO_SIGHTING, "refusal": "presence"}]
    return g


def test_each_value_line_says_what_was_checked(case):
    """A refused shape was never checked; a presence refusal seen by a later
    call names those calls; one checked against the cited calls only says
    so; a kept row without sightings is shown by its cited calls. Lines a
    reply must not state as seen come first."""
    import json
    from core.indicators import PROSE_SIGHTINGS_FILE, named_key
    g = _graph_with_values()
    g["nodes"]["C0002"]["indicators"].append({"type": "file", "value": "dropper.exe", "side": "attacker"})
    g["nodes"]["C0002"]["indicators_dropped"] += [
        {"type": "url", "value": "~jane", "reason": "'~jane' is not a URL (scheme://host...)", "refusal": "shape"},
        {"type": "ip", "value": "203.0.113.20", "reason": "no tool output of this case that read evidence shows it; "
         "a value only the brief, the threat context, a finding or a file this run wrote names is context until "
         "a call shows it", "refusal": "presence"},
        {"type": "ip", "value": "203.0.113.30", "reason": "not in the output of the cited calls [4]",
         "refusal": "presence"}]
    (case / ".atlas").mkdir(exist_ok=True)
    (case / PROSE_SIGHTINGS_FILE).write_text(json.dumps({"values": {
        named_key("ip", "203.0.113.20"): [{"call": 31, "host": "CORP-WS01"}, {"call": 12}],
        named_key("domain", "portal.example.com"): []}}), encoding="utf-8")
    vals = [v["text"] for v in A.answer_sheet(_task(), g, [], case_dir=case)["values"]]
    by = {t.split(" ", 1)[0]: t for t in vals}
    assert by["portal.example.com"].endswith("no sighting in any tool output; named by C0002")
    assert "not checked against tool output" in by["~jane"] and "no sighting" not in by["~jane"]
    assert "seen since by 2 call(s) (12, 31), none cited by C0002" in by["203.0.113.20"]
    assert "not shown by the calls C0002 cites; the rest of the run not checked" in by["203.0.113.30"]
    assert "shown by the calls C0002 cites; no sighting recorded" in by["dropper.exe"]
    unseen = {"portal.example.com", "~jane", "203.0.113.30"}
    firsts = [t.split(" ", 1)[0] for t in vals[:len(unseen)]]
    assert set(firsts) == unseen


def test_the_sheet_lists_the_reads_and_the_values(case):
    item = elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                                  {"path": "evidence/proxy.csv", "pattern": "203.0.113.7"}, "the proxy log")
    sheet = A.answer_sheet(_task(), _graph_with_values(), [], case_dir=case)
    w = f"w{item['call_id']}"
    assert sheet["reads"] == [{"id": w, "text": "table_grep evidence/proxy.csv: due"}]
    vals = {v["id"]: v["text"] for v in sheet["values"]}
    assert vals["v1"] == "203.0.113.7 (ip): attacker; seen by 2 call(s) on 1 host(s)"
    assert vals["v2"] == "portal.example.com (domain): attacker; no sighting in any tool output; named by C0002"
    text = sheet["text"]
    assert "READS (the work order's reads for this question):" in text and f"- {w} table_grep" in text
    assert "VALUES (typed values of the shown beliefs" in text
    assert "10. READS lines" in A.compose_prompt(sheet) and "11. When a VALUES line" in A.compose_prompt(sheet)
    assert "10. READS" not in A.compose_prompt({"reads": [], "values": []})


def test_a_sentence_citing_a_line_is_held_to_its_text(case):
    item = elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                                  {"path": "evidence/proxy.csv", "pattern": "203.0.113.7"}, "the proxy log")
    graph = _graph_with_values()
    sheet = A.answer_sheet(_task(), graph, [], case_dir=case)
    w = f"w{item['call_id']}"
    text = (f"jane.doe ran tool.exe [p1, C0001].\n"
            f"The proxy log evidence/proxy.csv was not read [p2, {w}].\n"
            f"No tool output shows portal.example.com [v2].\n"
            f"The proxy log evidence/other.csv was not read [{w}].")
    sents = A.parse_composed(text)
    assert sents[1]["ids"] == ["p2", w] and sents[2]["ids"] == ["v2"]
    results, unaddressed = A.check_composed(sents, sheet, graph, LEX)
    assert [r["ok"] for r in results] == [True, True, True, False]
    assert "other.csv" in results[3]["reasons"][0] and unaddressed == []


def test_the_report_prints_a_read_and_the_indicator_list():
    from core.report_assemble import _composed_text_lines
    composed = {"sentences": [{"text": "The proxy log was not read.", "ids": ["w812"], "none": False},
                              {"text": "No tool output shows portal.example.com.", "ids": ["C0002", "v2"],
                               "none": False}]}
    line = _composed_text_lines(composed, {"C0002": "F-002"}, "en")
    assert "The proxy log was not read [#812]." in line
    assert "portal.example.com [indicator list, F-002]." in line


def test_the_switch_off_leaves_the_sheet_as_before(case, monkeypatch):
    elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                           {"path": "evidence/proxy.csv", "pattern": "x"}, "y")
    monkeypatch.setenv("ATLAS_ANSWER_READS_VALUES", "0")
    sheet = A.answer_sheet(_task(), _graph_with_values(), [], case_dir=case)
    assert sheet["reads"] == [] and sheet["values"] == [] and "READS" not in sheet["text"]


def test_reads_and_value_lines_are_never_listed_as_support():
    from core.report_assemble import _composed_answer_lines
    composed = {"sheet": {"beliefs": [("C0002", "linked")]}, "lead_tier": "LIKELY",
                "sentences": [{"text": "The proxy log was not read.", "ids": ["w812"], "none": False},
                              {"text": "portal.example.com was named.", "ids": ["C0002", "v2"], "none": False}]}
    task = {"id": "task-0001", "status": "answered", "related_claim_ids": ["C0002"]}
    text = "\n".join(_composed_answer_lines(1, "Was the proxy log read?", task, {}, composed,
                                            {"C0002": "F-002"}, "en"))
    support = [ln for ln in text.splitlines() if ln.startswith(("Supported by", "Also cited"))]
    assert support and all("w812" not in ln and "v2" not in ln for ln in support)


def test_a_reads_line_carries_no_keep_note_and_unfinished_reads_come_first(case):
    from core import work_order as W
    done = elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                                  {"path": "evidence/a.csv", "pattern": "x"}, "a")
    done["status"] = "resolved"
    kept = elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                                  {"path": "evidence/b.csv", "pattern": "x"}, "b")
    W.dispose_work_item(elog.log, kept["call_id"], "keep", note="jane.doe ran tool.exe here")
    for n in range(14):
        elog.log.add_work_item("plan", ["task-0001"], "table_table_grep",
                               {"path": f"evidence/c{n}.csv", "pattern": "x"}, "c")["status"] = "resolved"
    sheet = A.answer_sheet(_task(), _graph_with_values(), [], case_dir=case)
    assert sheet["reads"][0]["id"] == f"w{kept['call_id']}" and "jane.doe" not in sheet["reads"][0]["text"]
    assert sheet["reads"][-1] == {"id": "", "text": "+4 more item(s)"} and "- +4 more item(s)" in sheet["text"]
