"""ATLAS_TABLE_TIME_ARGS: the table tools take one period
(time_start/time_end), page in time order (offset, order), write every row
to a file (output_csv), sort a time column by its parsed time, and
table_schema reports the time columns and their span. Invented fixtures only
(CORP-WS01, jane.doe, files.example.net, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import csv
import json

import pytest

from tests.tools.test_table_count_pass import _brute, _fn, _timeline
from tools.tabular import table_grep, table_query, table_schema

grep, query, schema = _fn(table_grep), _fn(table_query), _fn(table_schema)


@pytest.fixture
def tl(tmp_path):
    return _timeline(tmp_path / "tl.csv")


def test_a_window_counts_the_period_and_keeps_the_total(tl):
    r = grep(str(tl), r"jane\.doe", time_start="2031-01-02", time_end="2031-01-02")
    assert r["matched_rows_all"] == _brute(tl, r"jane\.doe")
    assert 0 < r["matched_rows"] < r["matched_rows_all"]
    assert all(h["date"] == "01/02/2031" for h in r["hits"])
    assert r["time_start"].startswith("2031-01-02") and r["time_end"].startswith("2031-01-02 23:59")


def test_pages_in_time_order_oldest_or_newest_first(tl):
    first = grep(str(tl), r"jane\.doe", max_hits=10, offset=0)
    second = grep(str(tl), r"jane\.doe", max_hits=10, offset=10)
    assert first["selection"] == "page" and [h["_n"] for h in first["hits"]] == list(range(1, 11))
    assert [h["_n"] for h in second["hits"]] == list(range(11, 21))
    newest = grep(str(tl), r"jane\.doe", max_hits=5, order="desc")
    n = newest["matched_rows"]
    assert [h["_n"] for h in newest["hits"]] == list(range(n, n - 5, -1)) and newest["order"] == "desc"


def test_output_csv_writes_every_matching_row(tl, tmp_path):
    out = tmp_path / "analysis" / "hits.csv"
    r = grep(str(tl), r"jane\.doe", max_hits=5, output_csv=str(out))
    assert r["output_csv"] == str(out)
    with open(out, newline="", encoding="utf-8") as fh:
        assert sum(1 for _ in csv.DictReader(fh)) == _brute(tl, r"jane\.doe")


def test_query_takes_a_period_and_sorts_a_time_column_by_its_moment(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("event_time,user\n01/02/2031 10:00:00,jane.doe\n12/31/2030 23:00:00,jane.doe\n"
                 "02/01/2031 08:00:00,jane.doe\n", encoding="utf-8")
    schema(str(p))
    r = query(str(p), sort_by="event_time", limit=3)
    assert [row["event_time"] for row in r["rows"]] == ["12/31/2030 23:00:00", "01/02/2031 10:00:00",
                                                  "02/01/2031 08:00:00"]
    w = query(str(p), time_start="2031-01-01", time_end="2031-01-31")
    assert w["matched_rows"] == 1 and w["matched_rows_all"] == 3 and w["rows"][0]["event_time"].startswith("01/02")


def test_a_capped_query_never_offers_a_file_of_every_row(tl):
    """The rest of a capped table_query is reached by a narrower filter, one
    period or a count by column: output_csv stays a parameter but no result
    text offers it, with or without a period."""
    plain = query(str(tl), where=[r"desc~jane\.doe"], limit=5)
    windowed = query(str(tl), where=[r"desc~jane\.doe"], limit=5, time_start="2031-01-01", time_end="2031-01-02")
    for r in (plain, windowed):
        assert r["success"] and r["matched_rows"] > r["returned_rows"]
        assert not [k for k, v in r.items() if isinstance(v, str) and "output_csv" in v]


def test_a_capped_query_says_how_many_rows_match_and_how_to_reach_the_rest(tl):
    """A table_query that returns fewer rows than match (one period, a sort, an
    offset) states the cut, and its view says N of M and names the narrower
    calls, never paging or a file of every row; one that returns every match
    reads as complete."""
    from core.tool_result_view import render_rows_view
    for extra in ({"time_start": "2031-01-01", "time_end": "2031-01-02"}, {"sort_by": "date"}, {"offset": 5}):
        r = query(str(tl), where=[r"desc~jane\.doe"], limit=5, **extra)
        m = r["matched_rows"]
        assert r["hit_cap_reached"] is True and m > r["returned_rows"] == 5, extra
        text, note = render_rows_view(r, 12000, 7, tool="table_table_query")
        view = json.loads(text)
        first = 1 + extra.get("offset", 0)
        assert view["shown"].startswith(f"5 of {m} matching rows (5 returned: rows {first} to {first + 4} of "
                                        f"the {m} in the call's order, not a sample of them)"), extra
        assert "all 5 matching rows" not in text and note["view_complete"] is False
        assert all(s in view["next"] for s in ("time_start=", "where=", "table.table_pivot group_by="))
        assert "offset=" not in view["next"] and "output_csv" not in view["next"]
    whole = query(str(tl), where=[r"desc~files\.example\.net"], limit=50, sort_by="date")
    assert whole["hit_cap_reached"] is False
    assert "next" not in json.loads(render_rows_view(whole, 12000, 8, tool="table_table_query")[0])
    # A table_grep page is the same kind of cut: a run of the counted matches in the call's order.
    page = grep(str(tl), r"jane\.doe", max_hits=10, offset=10)
    assert json.loads(render_rows_view(page, 12000, 9, tool="table_table_grep")[0])["shown"].startswith(
        f"10 of {page['matched_rows']} matching rows (10 returned: rows 11 to 20 of the")


def test_schema_reports_the_time_columns_and_their_span(tl):
    s = schema(str(tl))
    sheet = next(iter(s["sheets"].values()))
    assert sheet["time_columns"] == ["date", "time"]
    assert sheet["time_span"]["first"].startswith("2031-01-01 00:00") and sheet["time_span"]["last"] > \
        sheet["time_span"]["first"]


def test_the_switch_off_keeps_todays_result(tl, monkeypatch):
    monkeypatch.setenv("ATLAS_TABLE_TIME_ARGS", "0")
    r = grep(str(tl), r"jane\.doe", max_hits=5)
    assert "time_start" not in r and "offset" not in r and r["selection"] == "survey"
    assert "time_columns" not in next(iter(schema(str(tl))["sheets"].values()))


def test_a_window_is_complete_only_for_itself(tl):
    from core.middleware import _result_meta
    from tools._gates.universal_from_truncated import incomplete_reason
    r = grep(str(tl), r"jane\.doe", time_start="2031-01-02", time_end="2031-01-02", max_hits=1000)
    meta = _result_meta(r)
    assert meta["matched_rows_all"] == r["matched_rows_all"] and meta["time_start"].startswith("2031-01-02")
    why = incomplete_reason({"result_meta": meta, "view_complete": True})
    outside = r["matched_rows_all"] - r["matched_rows"]
    assert why.startswith("it searched only 2031-01-02") and f"{outside} of the file's" in why
    empty = {"matched_rows": 0, "returned_rows": 0, "matched_rows_all": 400}
    assert "400 of the file's 400" in incomplete_reason({"result_meta": empty, "view_complete": True})
    assert incomplete_reason({"result_meta": {**empty, "matched_rows_all": 0}, "view_complete": True}) == ""


def test_the_view_names_the_window_and_the_rows_outside(tl):
    from core.tool_result_view import render_rows_view
    r = grep(str(tl), r"jane\.doe", time_start="2031-01-02", time_end="2031-01-02", max_hits=1000)
    text, _note = render_rows_view(r, 200_000, 7, tool="table_table_grep")
    outside = r["matched_rows_all"] - r["matched_rows"]
    assert f"window: {r['time_start']} .. {r['time_end']} ({outside} matching rows outside it)" in text
    assert "window: none" not in text


def test_output_csv_keeps_long_cells_whole_and_sources_take_no_window(tmp_path):
    p = tmp_path / "t.csv"
    long_cmd = "powershell.exe -enc " + "A" * 3000
    p.write_text(f"event_time,cmd\n01/02/2031 10:00:00,{long_cmd}\n", encoding="utf-8")
    out = tmp_path / "analysis" / "o.csv"
    grep(str(p), "powershell", output_csv=str(out))
    with open(out, newline="", encoding="utf-8") as fh:
        assert next(csv.DictReader(fh))["cmd"] == long_cmd
    r = grep(str(p), "powershell", sources=[str(p)], time_start="2031-01-02")
    assert r["success"] is False and "takes no time window" in r["error"]
