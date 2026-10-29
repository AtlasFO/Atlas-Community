"""The count pass of table_grep and table_query (ATLAS_TABLE_SURVEY):
every match counted on every path (every matching line parsed, the streamed
pass above ATLAS_TABLE_FULL_PARSE_LINES, the row loop), the survey of the
match set, and the dict's key order. Invented fixtures only (CORP-WS01,
jane.doe, files.example.net, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import csv
import io
import json
import re

import pytest

import tools.tabular as tabular
from tools.tabular import _line_unsafe, table_grep, table_query


def _fn(tool):
    return getattr(tool, "fn", tool)


grep = _fn(table_grep)
query = _fn(table_query)

HEADER = ["date", "time", "timezone", "source", "sourcetype", "host", "desc", "filename"]


def _timeline(path, n=400, extra=(), *, ordered=True):
    """An l2tcsv-shaped timeline: one row a minute over several days, a few
    rows naming 203.0.113.9 and files.example.net."""
    rows = []
    for i in range(n):
        day, minute = 1 + (i // 120), i % 120
        src = ("EVT", "WinEVTX") if i % 3 else ("FILE", "NTFS $MFT")
        desc = "logon jane.doe" if i % 7 else "connect 203.0.113.9:443"
        if i % 50 == 0:
            desc = "dns query files.example.net"
        rows.append([f"01/{day:02d}/2031", f"{minute // 60:02d}:{minute % 60:02d}:00", "UTC", *src,
                     "CORP-WS01", desc, f"C:\\Users\\jane.doe\\f{i}.txt"])
    if not ordered:
        rows = rows[1::2] + rows[0::2]
    rows += [list(r) for r in extra]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(HEADER)
    w.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")
    return path


def _brute(path, pattern):
    rx = re.compile(pattern, re.IGNORECASE)
    with open(path, newline="", encoding="utf-8") as fh:
        r = csv.reader(fh)
        next(r)
        return sum(1 for row in r if any(c and rx.search(c) for c in row))


PATTERN = r"203\.0\.113\.9|files\.example\.net|absent\.example\.org"


@pytest.fixture
def paths(monkeypatch):
    """Run a search on the parsed path, the streamed path (bound 10) and the
    row loop (grep missing)."""
    def run(path, pattern, **kw):
        out = {}
        monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "20000")
        out["parsed"] = grep(str(path), pattern, **kw)
        monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "10")
        out["streamed"] = grep(str(path), pattern, **kw)
        monkeypatch.setattr(tabular.shutil, "which", lambda _n: None)
        out["rows"] = grep(str(path), pattern, **kw)
        monkeypatch.undo()
        return out
    return run


def test_exact_counts_on_every_path(tmp_path, paths):
    p = _timeline(tmp_path / "tl.csv")
    want = _brute(p, PATTERN)
    out = paths(p, PATTERN, max_hits=10)
    assert {k: r["count_path"] for k, r in out.items()} == {
        "parsed": "grep-parsed", "streamed": "grep-lines", "rows": "rows"}
    for r in out.values():
        assert r["matched_rows"] == want and r["returned_rows"] == 10 and r["selection"] == "survey"
        assert r["rows_scanned"] == 400 and r["hit_cap_reached"] is True
        assert [t["term"] for t in r["terms"]] == [r"203\.0\.113\.9", r"files\.example\.net"]
        assert r["terms_with_no_row"] == [r"absent\.example\.org"]
    s = out["streamed"]
    assert s["count_basis"] == "lines" and s["unparsed_lines"] == 0 and s["row_numbering"] == "lines"
    assert out["rows"]["row_numbering"] == "rows"
    for key in ("terms", "match_span", "sources"):
        assert s[key] == out["parsed"][key] == out["rows"][key], key
    assert s["distribution"]["basis"] == "all matching lines"
    same = [{k: v for k, v in r["distribution"].items() if k != "basis"} for r in out.values()]
    assert same[0] == same[1] == same[2]
    anchors = [(h["_n"], h.get("_tier")) for h in out["parsed"]["hits"]]
    assert anchors == [(h["_n"], h.get("_tier")) for h in s["hits"]]


def test_the_survey_anchors_each_term_and_source(tmp_path):
    p = _timeline(tmp_path / "tl.csv")
    r = grep(str(p), PATTERN, max_hits=8)
    tiers = [h["_tier"] for h in r["hits"]]
    assert 1 in tiers and 4 in tiers
    assert [h["_n"] for h in r["hits"]] == sorted(h["_n"] for h in r["hits"])
    assert {f"{h['source']}/{h['sourcetype']}" for h in r["hits"]} == set(r["sources"])
    for t in r["terms"]:
        first = [h for h in r["hits"] if h.get("_tier") == 1 and re.search(t["term"], h["desc"])]
        assert first and f"{first[0]['date'][6:]}-{first[0]['date'][:2]}-{first[0]['date'][3:5]}" == t["first"][:10]
    every = grep(str(p), r"files\.example\.net", max_hits=50)
    assert every["selection"] == "all" and every["hit_cap_reached"] is False
    assert [h["_n"] for h in every["hits"]] == list(range(1, every["matched_rows"] + 1))


def test_a_quoted_prefix_cell_is_read_by_the_csv_reader(tmp_path, monkeypatch):
    extra = [["01/09/2031", "10:00:00", "UTC", "EVT,quoted", "WinEVTX", "CORP-WS01",
              "connect 203.0.113.9:443", "x"]]
    p = _timeline(tmp_path / "tl.csv", extra=extra)
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "10")
    r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert r["count_path"] == "grep-lines" and r["unparsed_lines"] == 0
    assert "EVT,quoted/WinEVTX" in r["sources"]


def test_a_line_break_in_a_quoted_cell_sends_the_call_down_the_paths(tmp_path, monkeypatch):
    extra = [["01/09/2031", "10:00:00", "UTC", "EVT", "WinEVTX", "CORP-WS01",
              "connect 203.0.113.9:443\nsecond line", "x"]]
    p = _timeline(tmp_path / "tl.csv", extra=extra)
    want = _brute(p, r"203\.0\.113\.9")
    for bound in ("10", "20000"):
        monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", bound)
        r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
        assert r["count_path"] == "rows" and r["matched_rows"] == want


def test_a_match_across_two_cells_counts_only_by_line(tmp_path, monkeypatch):
    p = _timeline(tmp_path / "tl.csv")
    pattern = r"WinEVTX,CORP"
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "20000")
    parsed = grep(str(p), pattern, max_hits=5)
    assert parsed["count_path"] == "grep-parsed" and parsed["matched_rows"] == 0
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "0")
    streamed = grep(str(p), pattern, max_hits=5)
    assert streamed["count_basis"] == "lines" and streamed["matched_rows"] > 0


def test_a_record_holding_a_line_break_is_numbered_as_table_query_numbers_it(tmp_path, monkeypatch):
    """``_row`` is the record ordinal on every path (a table view's reader
    maps it back to the row's source): a file whose quoted cell holds a line
    break takes the row loop, since grep's line numbers would run one ahead
    of the records after it; a line-clean file keeps the grep paths, and
    the file rewritten is checked again."""
    clean = ("date,time,host,desc\n"
             "01/01/2031,00:00:00,CORP-WS01,one line\n"
             "01/01/2031,00:01:00,CORP-WS01,connect 203.0.113.9\n")
    p = tmp_path / "t.csv"
    p.write_text(clean, encoding="utf-8")
    r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert r["count_path"] == "grep-parsed" and r["hits"][0]["_row"] == 2
    p.write_text(clean.replace("one line", '"one\nline break"'), encoding="utf-8")
    want = query(str(p), where=["desc~203.0.113.9"])["rows"][0]["_row"]
    assert want == 2
    for bound in ("20000", "0"):
        monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", bound)
        r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
        assert r["count_path"] == "rows" and r["row_numbering"] == "rows" and r["hits"][0]["_row"] == want


def test_a_quote_less_continuation_line_is_caught_by_the_time_check(tmp_path, monkeypatch):
    text = ("date,time,host,desc\n"
            '01/01/2031,00:00:00,CORP-WS01,"first\nconnect 203.0.113.9, more"\n'
            "01/01/2031,00:01:00,CORP-WS01,connect 203.0.113.9\n")
    p = tmp_path / "t.csv"
    p.write_text(text, encoding="utf-8")
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "0")
    r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert r["count_path"] == "rows" and r["matched_rows"] == 2
    untimed = tmp_path / "u.csv"
    untimed.write_text("host,desc\n" + text.split("\n", 1)[1].replace("01/01/2031,00:00:00,", "")
                       .replace("01/01/2031,00:01:00,", ""), encoding="utf-8")
    u = grep(str(untimed), r"203\.0\.113\.9", max_hits=5)
    assert u["count_path"] == "rows" and u["matched_rows"] == 2
    clean = tmp_path / "c.csv"
    clean.write_text("host,desc\nCORP-WS01,connect 203.0.113.9\n", encoding="utf-8")
    c = grep(str(clean), r"203\.0\.113\.9", max_hits=5)
    assert c["count_path"] == "grep-lines" and "multiline_check" not in c


def test_an_unsorted_file_is_listed_in_file_order_on_the_streamed_path(tmp_path, monkeypatch):
    p = _timeline(tmp_path / "tl.csv", ordered=False)
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "0")
    streamed = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert streamed["order"] == "file"
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "20000")
    parsed = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert parsed["order"] == "asc"
    times = [h["date"][6:] + h["date"][:5] + h["time"] for h in parsed["hits"]]
    assert times == sorted(times)


def test_a_row_bound_marks_the_count_and_settles_no_absence(tmp_path, monkeypatch):
    p = _timeline(tmp_path / "tl.csv")
    monkeypatch.setattr(tabular, "MAX_SCAN_ROWS", 100)
    r = grep(str(p), PATTERN, max_hits=5)
    assert r["scan_capped"] is True and r["count_path"] == "rows"
    assert r["matched_rows"] == _brute_head(p, PATTERN, 100) and "terms_with_no_row" not in r


def _brute_head(path, pattern, n):
    rx = re.compile(pattern, re.IGNORECASE)
    with open(path, newline="", encoding="utf-8") as fh:
        r = csv.reader(fh)
        next(r)
        return sum(1 for k, row in enumerate(r) if k < n and any(c and rx.search(c) for c in row))


def test_the_key_order_keeps_the_counts_ahead_of_the_rows(tmp_path):
    terms = [f"term{k:02d}x" for k in range(12)]
    rows = [[f"01/{1 + k % 9:02d}/2031", "10:00:00", "UTC", "EVT", "WinEVTX", "CORP-WS01",
             f"{terms[k % 12]} seen", "x"] for k in range(240)]
    p = tmp_path / "t.csv"
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(HEADER)
    w.writerows(rows)
    p.write_text(buf.getvalue(), encoding="utf-8")
    r = grep(str(p), "|".join(terms), max_hits=20)
    keys = list(r)
    assert keys.index("terms") < keys.index("hits") < keys.index("sources") < keys.index("distribution")
    text = json.dumps(r)
    assert len(text[: text.index('"hits"')]) < 2000 and len(r["terms"]) == 12


def test_the_dot_peek_returns_its_rows_and_an_exact_count(tmp_path):
    p = _timeline(tmp_path / "tl.csv")
    r = grep(str(p), ".", max_hits=20)
    assert r["returned_rows"] == 20 and r["matched_rows"] == 400


def test_the_switch_off_keeps_the_search_that_stops_at_its_cap(tmp_path, monkeypatch):
    p = _timeline(tmp_path / "tl.csv")
    monkeypatch.setenv("ATLAS_TABLE_SURVEY", "0")
    r = grep(str(p), r"logon", max_hits=5)
    assert "matched_rows" not in r and r["rows_scanned"] < 400


def test_sources_count_the_pattern_in_every_listed_table(tmp_path):
    a = _timeline(tmp_path / "a.csv")
    b = _timeline(tmp_path / "b.csv", n=100)
    r = grep(str(a), PATTERN, sources=[str(b), str(tmp_path / "missing.csv")])
    assert "hits" not in r
    by_path = {c["path"]: c for c in r["counts"]}
    assert by_path[str(a)]["matched_rows"] == _brute(a, PATTERN)
    assert by_path[str(b)]["matched_rows"] == _brute(b, PATTERN)
    assert [t["rows"] for t in by_path[str(b)]["terms"]][2] == 0
    assert "error" in by_path[str(tmp_path / "missing.csv")]
    # Self-contained: the answer comes first, and nothing reads as a cut-off rows section.
    assert list(r)[:3] == ["success", "pattern", "counted"]
    assert r["counted"] == (f"counted in 3 tables: {a}: {_brute(a, PATTERN)}, {b}: {_brute(b, PATTERN)}, "
                            f"{tmp_path / 'missing.csv'}: error (file not found)")
    assert "no rows are returned" in r["note"]
    from core.tool_result_view import render_rows_view
    assert render_rows_view(r, 4000, 1, tool="table_table_grep") is None


def test_table_query_surveys_a_filter_that_matches_more_than_its_limit(tmp_path):
    from core.tool_result_view import render_rows_view
    p = _timeline(tmp_path / "tl.csv")
    r = query(str(p), where=["source=EVT"], limit=10)
    assert r["selection"] == "survey" and r["returned_rows"] == 10 and r["hit_cap_reached"] is True
    assert r["matched_rows"] == sum(1 for i in range(400) if i % 3)
    assert "distribution" in r and [x["_n"] for x in r["rows"]] == sorted(x["_n"] for x in r["rows"])
    paged = query(str(p), where=["source=EVT"], limit=10, offset=10)
    assert "selection" not in paged and paged["returned_rows"] == 10 and paged["hit_cap_reached"] is True
    # A view that shows every returned row of a survey still says how to reach the rest.
    view = json.loads(render_rows_view(r, 200_000, 3, tool="table_table_query")[0])
    assert view["shown"].startswith(f"10 of {r['matched_rows']} matching rows (10 returned)")
    assert "table.table_pivot" in view["next"]


def test_a_survey_cut_to_fit_the_output_says_so(tmp_path):
    """Rows dropped to fit the output are stated as payload_capped on the
    survey path too, not only on the other row builders."""
    p = tmp_path / "wide.csv"
    p.write_text("event_time,user,a,b,c\n" + "".join(
        f"01/02/2031 10:{i:02d}:00,jane.doe,{'x' * 500},{'y' * 500},{'z' * 500}\n" for i in range(60)),
        encoding="utf-8")
    r = query(str(p), where=["user=jane.doe"], limit=50)
    assert r["selection"] == "survey" and r["returned_rows"] < 50
    assert r["payload_capped"] is True and r["hit_cap_reached"] is True


@pytest.mark.parametrize("pattern,unsafe", [
    (r"C:\\Windows\\Temp", False), (r"\\Users\\Public", False), (r"203\.0\.113\.9", False),
    (r"run\.exe\s+-enc", True), (r"^4624$", True), (r"[^a]bc", True), (r"(?s)a.b", True),
    (r"[$]x", False)])
def test_the_guard_reads_the_pattern_token_by_token(pattern, unsafe):
    assert _line_unsafe(pattern) is unsafe


def test_the_guard_switch_off_keeps_the_regex_test(monkeypatch):
    monkeypatch.setenv("ATLAS_GREP_GUARD_TOKENS", "0")
    assert _line_unsafe(r"C:\\Windows\\Temp") is True


def test_the_view_states_the_count_of_every_match(tmp_path, monkeypatch):
    from core.tool_result_view import render_rows_view
    p = _timeline(tmp_path / "tl.csv")
    r = json.loads(json.dumps(grep(str(p), PATTERN, max_hits=10)))
    text, note = render_rows_view(r, 8000, 41, tool="table_table_grep")
    view = json.loads(text)
    assert view["shown"].startswith(f"10 of {r['matched_rows']} matching rows (10 returned): ")
    assert f"#n = place in the time order of the {r['matched_rows']}" in view["shown"]
    assert view["distribution"][0].endswith("(all matching rows)")
    assert view["terms"][0].startswith(r"203\.0\.113\.9: " + str(r["terms"][0]["rows"]) + " rows")
    assert view["terms_with_no_row"] == [r"absent\.example\.org"]
    assert "omitted_keys" not in view and note["view_complete"] is False
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "0")
    lines = json.loads(json.dumps(grep(str(p), PATTERN, max_hits=10)))
    assert "matching lines (counted by line)" in json.loads(
        render_rows_view(lines, 8000, 42, tool="table_table_grep")[0])["shown"]


def test_a_search_that_returned_every_match_is_a_complete_view():
    from tools._gates.universal_from_truncated import incomplete_reason
    full = {"type": "tool_call", "cmd": "<py>:table_table_grep",
            "result_meta": {"matched_rows": 50, "returned_rows": 50, "hit_count": 50, "max_hits": 50}}
    assert incomplete_reason(full) == ""
    part = {**full, "result_meta": {"matched_rows": 80, "returned_rows": 50, "hit_count": 50, "max_hits": 50}}
    assert incomplete_reason(part) == "it returned 50 of 80 matching rows"


def test_a_zero_match_grep_is_contact_and_a_zero_match_filter_is_not():
    from core.coverage_ledger import tabular_contact_ok
    zero = json.dumps({"success": True, "selection": "all", "matched_rows": 0, "hits": []})
    assert tabular_contact_ok("table_table_grep", zero) is True
    assert tabular_contact_ok("table_table_query", json.dumps(
        {"success": True, "selection": "all", "matched_rows": 0, "valid_zero": True, "rows": []})) is False
    assert tabular_contact_ok("table_table_grep", json.dumps({"success": False, "error": "x"})) is False


def test_a_fallback_keeps_the_count_of_lines_the_streamed_path_could_not_read(tmp_path, monkeypatch):
    p = _timeline(tmp_path / "tl.csv", extra=[["", "", "UTC", "EVT", "WinEVTX", "CORP-WS01",
                                               "connect 203.0.113.9:443", "x"]])
    monkeypatch.setenv("ATLAS_TABLE_FULL_PARSE_LINES", "0")
    r = grep(str(p), r"203\.0\.113\.9", max_hits=5)
    assert r["count_path"] == "grep-parsed" and r["unparsed_lines"] == 1
    assert r["matched_rows"] == _brute(p, r"203\.0\.113\.9") and r["untimed_rows"] == 1


def test_two_hosts_tables_of_one_name_are_counted_apart(tmp_path):
    """Per-host tables often share a file name: each is named by its path
    in the case, never by the base name alone."""
    from unittest.mock import patch
    case = tmp_path / "case"
    for host in ("corp-ws01", "corp-srv02"):
        (case / "evidence" / host).mkdir(parents=True)
    a = _timeline(case / "evidence" / "corp-ws01" / "timeline.csv")
    b = _timeline(case / "evidence" / "corp-srv02" / "timeline.csv", n=100)
    with patch("core.paths.active_case_dir", return_value=str(case)):
        r = grep(str(a), PATTERN, sources=[str(b)])
    assert r["counted"] == (f"counted in 2 tables: evidence/corp-ws01/timeline.csv: {_brute(a, PATTERN)}, "
                            f"evidence/corp-srv02/timeline.csv: {_brute(b, PATTERN)}")
