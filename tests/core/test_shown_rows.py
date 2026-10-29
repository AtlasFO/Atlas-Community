"""core.shown_rows: the records a call showed the model, named by where
they live (invented rows)."""
from __future__ import annotations

import json

from core.shown_rows import from_text, row_keys

_ROWS = [{"_sheet": "-", "_row": 10 + i, "TimeCreated": f"2031-03-10T0{i}:00:00Z", "UserName": "jane.doe",
          "RemoteHost": "10.0.0.5"} for i in range(5)]


def _data(rows):
    return {"success": True, "path": "evidence/CORP-WS02/sec.csv", "rows": rows}


def test_a_record_is_the_same_under_another_column_list_or_pattern():
    whole = row_keys("table_table_query", {"path": "evidence/CORP-WS02/sec.csv"}, _data(_ROWS))
    narrow = [{"_sheet": "-", "_row": r["_row"], "UserName": r["UserName"]} for r in _ROWS]
    clipped = [{**r, "_matched_columns": ["UserName"], "_n": k} for k, r in enumerate(narrow)]
    assert len(whole) == 5
    assert row_keys("table_table_query", {"path": "evidence/CORP-WS02/sec.csv", "columns": ["UserName"]},
                    _data(narrow)) == whole
    assert row_keys("table_table_grep", {"path": "evidence/CORP-WS02/sec.csv", "pattern": "jane"},
                    _data(clipped)) == whole


def test_aggregate_rows_name_no_record():
    groups = {"success": True, "path": "evidence/CORP-WS02/sec.csv", "rows": [{"UserName": "jane.doe", "count": 5}]}
    assert row_keys("table_table_pivot", {"path": "x", "group_by": ["UserName"]}, groups) == []
    assert row_keys("table_table_pivot", {"path": "x", "group_by": ["UserName"], "where": ["a=b"]}, groups) == []


def test_only_the_rows_a_view_showed_count():
    shown = row_keys("table_table_grep", {"path": "p"}, _data(_ROWS), shown_ids=[10, 12])
    assert shown == row_keys("table_table_grep", {"path": "p"}, _data([_ROWS[0], _ROWS[2]]))
    # a dict row without _row is selected by its 0-based place, a line by its 1-based place
    plain = [{"a": "x1"}, {"a": "x2"}]
    assert row_keys("t", {}, {"rows": plain}, shown_ids=[1]) == row_keys("t", {}, {"rows": plain[1:]})
    lines = {"matches": ["alpha one", "beta two", "gamma three"]}
    assert row_keys("strings_strings_grep", {"file_path": "m.bin"}, lines, shown_ids=[1, 3]) == \
        row_keys("strings_strings_grep", {"file_path": "m.bin"}, {"matches": ["alpha one", "gamma three"]})


def test_a_line_is_its_source_and_text_and_a_window_is_its_call_and_line():
    a = row_keys("strings_strings_grep", {"file_path": "m.bin", "pattern": "a"}, {"matches": ["alpha  one"]})
    b = row_keys("strings_strings_grep", {"file_path": "m.bin", "pattern": "al"}, {"matches": ["alpha one"]})
    other = row_keys("strings_strings_grep", {"file_path": "n.bin", "pattern": "a"}, {"matches": ["alpha one"]})
    assert a == b and a != other
    w1 = row_keys("search_search_evidence", {"query": "x"}, {"results": [{"call_id": 4, "line_start": 9, "snippet": "x"}]})
    w2 = row_keys("search_search_evidence", {"query": "y"}, {"results": [{"call_id": 4, "line_start": 9, "snippet": "y"}]})
    assert w1 == w2


def test_a_content_row_leaves_out_the_bookkeeping_and_the_echo():
    one = row_keys("vol_pslist", {"pid": "4412"}, {"rows": [{"PID": "4412", "Name": "svc_kit.exe", "_n": 1}]})
    two = row_keys("vol_pslist", {"pid": "4412"}, {"rows": [{"PID": "4412", "Name": "svc_kit.exe", "_n": 7}]})
    assert one == two and one


def test_a_text_result_names_rows_only_when_received_whole():
    whole = json.dumps(_data(_ROWS))
    assert len(from_text("table_table_query", {}, whole)) == 5
    assert from_text("table_table_query", {}, whole[:-40]) == []           # cut: no row named
    assert from_text("misc_tool", {}, "pid 4412 svc_kit.exe") == []        # plain text
    assert from_text("t", {}, json.dumps({"success": False, "rows": [{"a": 1}]})) == []


def test_the_view_selection_names_the_rows_the_real_view_printed():
    from core.tool_result_view import render_rows_view
    from tests.core.test_tool_result_view import _payload, _timeline_rows
    payload = _payload(_timeline_rows(n_routine=400))
    text, note = render_rows_view(payload, 3000, 7, [], tool="table_table_grep")
    keys = row_keys("table_table_grep", {"path": "t.csv"}, payload, note["view_row_ids"])
    # one identity per record: the fixture's burst row reuses a routine row's number
    assert 0 < len(keys) == len(set(note["view_row_ids"])) and note["view_rows_shown"] < len(payload["hits"])
    lines = {"matches": [f"line {i} svc_kit.exe" for i in range(400)], "pattern": "svc_kit"}
    text, note = render_rows_view(lines, 3000, 8, [], tool="strings_strings_grep")
    keys = row_keys("strings_strings_grep", {"file_path": "m.bin"}, lines, note["view_row_ids"])
    assert 0 < len(keys) == note["view_rows_shown"] < 400


def test_real_table_query_pages_sorts_and_projections_name_each_record_one_way(tmp_path):
    """Every table_query path carries the record's place, numbered as
    the survey path numbers it, so a page, a sort and a column list name one
    record one way (invented rows)."""
    import csv
    from tools import tabular as TB
    p = str(tmp_path / "logons.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["time", "host", "user", "src"])
        for i in range(200):
            w.writerow([f"2031-03-01 10:{i // 60:02d}:{i % 60:02d}", "CORP-WS01", f"user{i % 7}", f"10.0.0.{i % 50}"])

    def keys(args):
        d = TB.table_query(**args)
        assert d["success"] and all("_row" in r and "_sheet" in r for r in d["rows"])
        return set(row_keys("table_table_query", args, d))
    survey = keys({"path": p, "limit": 20})                                   # the counted survey path
    pages = set()
    for off in range(0, 200, 20):
        pages |= keys({"path": p, "limit": 20, "offset": off, "sort_by": "time"})
    assert len(pages) == 200 and survey <= pages                              # one identity per record
    page2 = keys({"path": p, "limit": 20, "offset": 20})
    assert page2 == keys({"path": p, "limit": 20, "offset": 20, "columns": ["time", "user"]}) \
        == keys({"path": p, "limit": 20, "offset": 20, "columns": ["time", "src"]})
    assert page2 <= pages
    assert keys({"path": p, "limit": 20, "offset": 20, "time_start": "2031-03-01", "time_end": "2031-03-01"}) <= pages


def test_one_file_named_relative_or_absolute_is_one_source(tmp_path, monkeypatch):
    (tmp_path / "sec.csv").write_text("a\n1\n")
    monkeypatch.chdir(tmp_path)
    rows = {"rows": [{"_sheet": "-", "_row": 1, "a": "1"}]}
    assert row_keys("table_table_query", {"path": "sec.csv"}, rows) == \
        row_keys("table_table_query", {"path": str(tmp_path / "sec.csv")}, rows)
