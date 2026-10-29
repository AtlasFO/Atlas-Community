"""C2 item 1: the plan sees what the images hold (ATLAS_PLAN_LISTING: the
digest, a LOCATE call naming places, the LISTING of what the index holds
there). Invented fixtures only (CORP-WS01, CORP-WS02, jane.doe, dates in
2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

from core import question_plan as Q
from core.execution_log import ExecutionLog
from tests.core.test_contents_index import _body, _build, _image, _links, _plan, case  # noqa: F401


def _indexed(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-WS02", "evidence/disk/corp-ws02.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "corp-ws02.raw")])
    many = [_body(f"C/inetpub/logs/LogFiles/W3SVC1/u_ex{i:05d}.log", f"{1000 + i}-128-1") for i in range(1200)]
    _build(case, monkeypatch, {"corp-ws01.raw": [_body("C/Windows/System32/winevt/Logs/Security.evtx", "200-128-1")],
                               "corp-ws02.raw": many})


def test_locate_reply_parsing_keeps_known_hosts_and_normalises_globs(case, monkeypatch):
    _indexed(case, monkeypatch)
    reply = ('Places:\n{"places": [{"host": "CORP-WS01", "glob": "C:\\\\Windows\\\\System32\\\\winevt\\\\Logs\\\\*.evtx",'
             ' "why": "logons"}, {"host": "*", "glob": "inetpub/logs/*", "why": "web"},'
             ' {"host": "CORP-NOPE", "glob": "x/*", "why": "?"}, {"host": "CORP-WS02", "glob": ""}]}\nThat is all.')
    places, dropped = Q.parse_locate(str(case), reply)
    assert places == [{"host": "CORP-WS01", "glob": "C/Windows/System32/winevt/Logs/*.evtx", "why": "logons"},
                      {"host": "", "glob": "inetpub/logs/*", "why": "web"}]
    assert dropped == ["CORP-NOPE: not a host of this case", "CORP-WS02: no glob"]


def test_the_listing_renders_many_files_of_one_directory_as_one_line(case, monkeypatch):
    _indexed(case, monkeypatch)
    block = Q.listing_block(str(case), [{"host": "", "glob": "inetpub/logs/*", "why": ""},
                                        {"host": "CORP-WS01", "glob": "Tools/*", "why": ""}])
    lines = block.splitlines()
    assert lines[1] == "- every host inetpub/logs/*: 1200 files in 1 directories"
    assert lines[2].startswith("  CORP-WS02 C/inetpub/logs/LogFiles/W3SVC1: 1200 files (log 1200)")
    assert "handle evidence/disk/corp-ws02.raw::C/inetpub/logs/LogFiles/W3SVC1" in lines[2]
    assert lines[3] == "- CORP-WS01 Tools/*: no listing entry matches"


def test_the_plan_sees_the_located_places_and_an_empty_locate_falls_back(case, monkeypatch):
    _indexed(case, monkeypatch)
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    seen = []
    locate = json.dumps({"places": [{"host": "*", "glob": "inetpub/logs/*", "why": "web"}]})
    plan = json.dumps({"reads": []})

    def ask(system, user, _tool_name=""):
        seen.append((_tool_name, user))
        return {"conclusion": locate if _tool_name == "reason_locate_question" else plan}
    task = {"id": "task-0001", "text": "Which web requests reached the server?"}
    with patch("tools.reasoning._ask", side_effect=ask):
        r = Q.plan_question(log, str(case), task, [("ez.evtxecmd", "event logs")])
    assert [n for n, _u in seen] == ["reason_locate_question", "reason_plan_question"]
    user = seen[1][1]
    assert "INSIDE THE IMAGES" in user and "LISTING" in user and "1200 files" in user
    assert r["locate"]["empty"] is False
    seen.clear()
    with patch("tools.reasoning._ask", side_effect=lambda s, u, _tool_name="": (
            seen.append(_tool_name), {"conclusion": "no idea"})[1]):
        r = Q.plan_question(log, str(case), task, [("ez.evtxecmd", "event logs")])
    assert seen == ["reason_locate_question", "reason_plan_question"] and r["locate"]["empty"] is True


def test_switches_off_the_plan_message_and_prompt_are_todays(case, monkeypatch):
    _indexed(case, monkeypatch)
    task = {"id": "task-0001", "text": "q"}
    monkeypatch.setenv("ATLAS_PLAN_LISTING", "0")
    monkeypatch.setenv("ATLAS_MAP_VIEWS", "0")
    off = Q.plan_message(str(case), task, [("t", "w")], listing="LISTING x")
    assert "INSIDE THE IMAGES" not in off and "LISTING" not in off
    assert Q.plan_system() == Q.PLAN_SYS


def test_the_new_plan_texts_name_no_artefact():
    for text in (Q.LOCATE_SYS, Q.PLAN_LISTING_RULE):
        assert not any(w in text.lower() for w in ("evtx", "winevt", "prefetch", "registry", "system32"))
    assert "not read until a read is planned" in Q.PLAN_LISTING_RULE
