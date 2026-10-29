"""The frontier's per-kind system texts, item texts and submit
schemas. Invented fixtures only (CORP-WS01, svc_kit.exe, jane.doe, dates in
2031)."""
from __future__ import annotations

import json
import re

import pytest

from core import frontier_prompts as P
from core import frontier_queue as Q
from tests.core.test_incident_map import _KIT, _case, _claim, _trace, _wide


def _descriptions(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "description":
                yield v
            yield from _descriptions(v)
    elif isinstance(node, list):
        for v in node:
            yield from _descriptions(v)


@pytest.mark.parametrize("kind", P.KINDS)
def test_each_submit_holds_only_its_kinds_fields(kind):
    s = P.submit_schema(kind)
    json.dumps(s)
    params = s["function"]["parameters"]
    assert s["function"]["name"] == f"submit_{kind}"
    assert tuple(params["properties"]) == P.SUBMIT_FIELDS[kind] + (() if kind == "synthesis" else ("partial",))
    assert params.get("required", []) == (["arrival"] if kind == "host_pass" else [])
    assert all(len(d) <= 1024 for d in _descriptions(s))


@pytest.mark.parametrize("kind", P.KINDS)
def test_system_texts_name_their_submit_and_no_artefact(kind):
    text = P.system_text(kind)
    assert P.submit_name(kind) in text and "basis" in text
    assert (P.USE_READERS in text) == (kind != "synthesis")
    # The method lives in the text; what to read is the model's (no
    # artefact, log family or event id).
    assert not re.search(r"evtx|event ?log|registry|prefetch|\b4\d{3}\b|sysmon|mft|\.exe", text, re.I)


def test_the_core_tools_are_registered_and_the_list_stays_at_ten():
    from core.work_order import is_reading_tool
    from tools.tool_capabilities import registered_tool_schemas
    names = {t[0] for t in registered_tool_schemas()}
    assert all(t.replace(".", "_") in names for t in P.READ_CORE)
    # the listing search is a lookup, every other core tool reads content
    assert [t for t in P.READ_CORE if not is_reading_tool(t)] == ["tsk.tsk_index_find"]
    assert len(P.READ_CORE) + P.MAX_READERS + 2 <= 10          # + the meta tool and the submit
    assert len(P.READ_CORE) + P.MAX_READER_TOOLS + 2 <= 13     # a memory pass with one framework's plugins
    assert P.core_tools("synthesis") == []


def test_pick_readers_keeps_known_readers_up_to_the_bound():
    menu = {"a.read_x", "b.read_y", "c.read_z", "d.read_w"}
    picked, reply = P.pick_readers(["a.read_x", "nope", "b.read_y", "c.read_z", "d.read_w", "a.read_x"], menu,
                                   folded=set())
    assert picked == ["a.read_x", "b.read_y", "c.read_z"]
    assert "nope" in reply and f"at most {P.MAX_READERS} readers" in reply
    assert P.pick_readers("a.read_x", menu)[0] == ["a.read_x"]


def test_a_host_pass_item_text_carries_the_host_its_values_the_map_and_the_readers(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    monkeypatch.setattr("core.frontier_sweep.sweep", lambda *a, **k: {"sightings": 0})
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    Q.generate(log, case)
    item = Q.next_item(log)
    from core import incident_map as IM
    m = IM.open(case)
    item["source_ref"]["entities"] = [e["entity_id"] for e in m.attacker_entities()]
    spec = P.item_spec(case, item, m, readers="READERS BY INPUT FORMAT:\n- x: a.read_x")
    assert spec.kind == "host_pass" and spec.submit_name == "submit_host_pass"
    assert spec.core_tools == P.READ_CORE and spec.menu and set(spec.menu) <= set(P.reader_names())
    assert P.item_spec(case, {**item, "origin": "synthesis"}, m, readers="").menu == []
    assert "HOST: CORP-WS01" in spec.user and "file svc_kit.exe" in spec.user
    assert "THE INCIDENT MAP NOW:" in spec.user and "a.read_x" in spec.user
    with pytest.raises(ValueError):
        P.item_spec(case, {**item, "origin": "triage"}, m, readers="")


def test_a_view_row_item_text_names_the_question_part_and_row(tmp_path, monkeypatch):
    case = _case(tmp_path)
    from core import incident_map as IM
    m = IM.open(case)
    monkeypatch.setattr(m, "views", lambda open_only=False: [
        {"view_id": 7, "task_id": "task-0001", "part_id": "p2", "spec": {"columns": ["host", "time"]},
         "rows": [{"row_key": "CORP-WS01", "cells": {"host": {"value": "CORP-WS01"}}}]}])
    monkeypatch.setattr(P, "_task_part", lambda _c, t, p: ("Which hosts were reached?", "when, per host")
                        if (t, p) == ("task-0001", "p2") else ("", ""))
    item = {"call_id": 9, "origin": "view_row_opened", "task_ids": ["task-0001"], "why": "row open",
            "source_ref": {"kind": "view_row", "view_id": 7, "row_key": "CORP-WS01"}}
    text = P.item_text(case, item, m)
    assert "QUESTION task-0001: Which hosts were reached?" in text and "PART p2: when, per host" in text
    assert "OPEN ROWS (1): CORP-WS01" in text and "ROW CORP-WS01, CELLS ALREADY FILLED: host = CORP-WS01" in text


def test_a_memory_item_menu_lists_the_memory_plugins_and_holds_more_than_three():
    from core.evidence_disposition import MEMORY_STRUCTURES
    from tools.tool_capabilities import MEMORY_FORMAT, readers_block, readers_by_format, registered_tool_schemas
    table = readers_by_format(registered_tool_schemas())
    mem = table.get(MEMORY_FORMAT) or []
    covered = {label for label, plugins in MEMORY_STRUCTURES.items()
               if any(p in name for name in mem for p in plugins)}
    assert covered == set(MEMORY_STRUCTURES)                    # every structure has a reader
    assert f"- {MEMORY_FORMAT}:" in readers_block() and set(mem) <= set(P.reader_names())
    picked, _reply = P.pick_readers(mem[:5] + ["a.read_x", "b.read_y", "c.read_z"], set(mem) | {"a.read_x",
                                                                                                "b.read_y",
                                                                                                "c.read_z"})
    assert picked == mem[:5] + ["a.read_x"]                      # the memory plugins are one place
    # any other namespace does not fold: a plain item keeps three readers
    plain = ["z.read_a", "z.read_b", "z.read_c", "z.read_d"]
    assert P.pick_readers(plain, set(plain))[0] == plain[:3]


def test_schema_descriptions_name_no_artefact():
    import re as _re
    for kind in P.KINDS:
        text = " ".join(_descriptions(P.submit_schema(kind)))
        assert not _re.search(r"evtx|event ?log|registry|prefetch|\b4\d{3}\b|sysmon|mft|\.exe", text, _re.I), kind
    assert not _re.search(r"evtx|registry|prefetch", " ".join(_descriptions(P.USE_READERS_SCHEMA)), _re.I)


def test_a_synthesis_lists_the_reading_tools_a_proposal_may_name(tmp_path, monkeypatch):
    from core import question_plan as Q
    from core.work_order import listed
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    tools = P.proposal_tools()
    reading = {listed(t) for t, _w in Q.reading_tools()}
    assert "table.table_grep" in tools and "tsk.tsk_index_find" not in tools
    assert all(listed(t) in reading for t in tools)              # every one passes the read check's tool test
    text = P.item_text(case, {"call_id": 5, "origin": "synthesis", "why": "s"}, None, readers="")
    assert "READING TOOLS (a proposal names one of these" in text and "table.table_grep" in text
    assert "READING TOOLS" in P.submit_schema("synthesis")["function"]["parameters"]["properties"]["proposals"][
        "items"]["properties"]["tool"]["description"]
    _ok, why = Q.check_read(str(case), {"tool": "search", "host": "CORP-WS01", "pattern": "x", "why": "w"},
                            {t for t, _w in Q.reading_tools()})
    assert _ok is None and "not a reading tool" in why


def test_the_plan_view_rule_keeps_views_for_list_parts():
    from core.question_plan import plan_view_rule
    rule = plan_view_rule()
    assert "only for a part whose answer lists several rows" in rule and "gets no view" in rule


def test_a_view_row_item_says_a_found_value_is_a_finding():
    text = P.system_text("view_row_opened")
    assert "submitted as a finding" in text and "only when you looked and the evidence holds nothing" in text


# -- a view-part item lists the sources of its rows' hosts ----------------------------------

def _sources(case, rows):
    from core.contents_index import _connect
    con = _connect(case, create=True)
    for i, (export, host) in enumerate(rows, 1):
        con.execute("INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (i, export, host, "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", None, 10,
                     "2031-03-10", "2031-03-11", "{}", "{}"))
    con.commit()
    con.close()


def test_a_view_item_lists_the_exports_of_its_rows_hosts_and_the_unattributed_ones(tmp_path):
    from core import incident_map as IM
    case = _case(tmp_path)
    m = IM.open(case)
    hosts = ["CORP-WS01", "CORP-WS02", "CORP-SRV01"]
    for h in hosts:
        m.upsert_entity("host", h)
    _sources(case, [("evidence/estate/estate-logons.csv", h) for h in hosts]
             + [("evidence/CORP-WS02/sysmon.csv", "CORP-WS02"), ("evidence/firewall/fw.csv", "")])
    v = m.declare_view("task-0001", "p1", {"over": "host", "columns": ["label"]})
    item = {"call_id": 9, "origin": "view_row_opened", "task_ids": ["task-0001"], "why": "rows open",
            "source_ref": {"kind": "view_row", "view_id": v["view_id"], "rows": hosts}}
    text = P.item_text(case, item, m)
    assert "SOURCES FOR THESE ROWS" in text
    assert "- evidence/estate/estate-logons.csv (3 of the 3 rows' hosts)" in text
    assert "- evidence/CORP-WS02/sysmon.csv (1 of the 3 rows' hosts)" in text
    assert text.index("estate-logons.csv (3") < text.index("sysmon.csv (1")          # the widest first
    assert "tables with no host attributed (estate-wide or unknown): evidence/firewall/fw.csv" in text
    assert "CELLS ALREADY FILLED: label = open" not in text                        # an open cell is not filled
    assert "a view narrowed by a label not yet written leaves no row to fill" in P.system_text("view_row_opened")


def test_the_rows_hosts_of_an_entity_view_and_an_event_view(tmp_path):
    from core import incident_map as IM
    case = _case(tmp_path)
    m = IM.open(case)
    acct = m.upsert_entity("account", "jane.doe")
    ev = m.add_event("CORP-WS02", "2031-03-10 13:58:02", "logon", actor=acct)
    va = m.declare_view("task-0001", "p1", {"over": "account", "columns": ["label"]})
    assert m.row_hosts(va["view_id"], ["jane.doe", "nobody"]) == {"jane.doe": ["CORP-WS02"], "nobody": []}
    ve = m.declare_view("task-0001", "p2", {"over": "event:logon", "columns": ["time"]})
    key = f"v:{ev['event_id']}"
    assert m.row_hosts(ve["view_id"], [key]) == {key: ["CORP-WS02"]}


def test_the_source_lines_are_bounded_with_the_count_left_out(tmp_path, monkeypatch):
    from core import incident_map as IM
    case = _case(tmp_path)
    m = IM.open(case)
    m.upsert_entity("host", "CORP-WS01")
    _sources(case, [(f"evidence/CORP-WS01/t{i:02d}.csv", "CORP-WS01") for i in range(45)])
    v = m.declare_view("task-0001", "p1", {"over": "host", "columns": ["label"]})
    lines = P._row_source_lines(str(case), m, next(x for x in m.views() if x["view_id"] == v["view_id"]),
                                ["CORP-WS01"])
    assert len([ln for ln in lines if ln.startswith("- evidence/")]) == P.VIEW_SOURCE_LINES
    assert "- and 5 more (table_query lists them)" in lines
