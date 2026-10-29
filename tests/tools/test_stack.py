"""C2 item 3 (ATLAS_STACK): table_pivot stacks a column across hosts and
reads the values few hosts hold, over tables, the contents index or a prior
call's output. Invented fixtures only (CORP-WS01..03, svc_kit.exe,
jane.doe)."""
from __future__ import annotations

import json
import shutil

import pytest

from core.stack import stack

PROCS = {
    "CORP-WS01": [("explorer.exe", "running"), ("svchost.exe", "running"), ("notepad.exe", "stopped")],
    "CORP-WS02": [("explorer.exe", "running"), ("svchost.exe", "running"), ("svc_kit.exe", "running")],
    "CORP-WS03": [("explorer.exe", "running"), ("svchost.exe", "running")],
}


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / "analysis").mkdir()
    links = []
    for host, rows in PROCS.items():
        name = f"analysis/{host.lower()}-pslist.csv"
        (tmp_path / name).write_text("Name,Status,StartTime\n" + "".join(
            f"{n},{st},2031-01-0{i + 1} 10:00:00\n" for i, (n, st) in enumerate(rows)))
        links.append({"label": host, "path": name})
    (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": links}))
    return tmp_path


def test_rare_order_lists_the_one_host_value_first(case):
    r = stack(str(case), "analysis/*-pslist.csv", ["Name"], ["Status=running"], "rare", None, 25, 0)
    first = r["groups"][0]
    assert first["Name"] == "svc_kit.exe" and first["units"] == 1 and first["unit_names"] == ["CORP-WS02"]
    assert r["tail_1"] == 1 and r["distinct_groups"] == 3 and first["first"] == "2031-01-03 10:00:00"
    common = stack(str(case), "analysis/*-pslist.csv", ["Name"], ["Status=running"], "common", None, 25, 0)
    assert [g["Name"] for g in common["groups"]][:2] == ["explorer.exe", "svchost.exe"]


def test_several_tables_without_gawk_need_a_literal_filter(case, monkeypatch):
    real = shutil.which
    monkeypatch.setattr("core.stack.shutil.which", lambda n: None if n == "gawk" else real(n))
    r = stack(str(case), "analysis/*-pslist.csv", ["Name"], None, "rare", None, 25, 0)
    assert r["success"] is False and r["gate"] == "stack_needs_native"
    ok = stack(str(case), "analysis/*-pslist.csv", ["Name"], ["Status=running"], "rare", None, 25, 0)
    assert ok["groups"][0]["Name"] == "svc_kit.exe" and {s["counted"] for s in ok["sources"]} == {"grep"}


@pytest.mark.skipif(not shutil.which("gawk"), reason="the native pass needs gawk")
def test_the_native_pass_counts_without_a_filter(case):
    r = stack(str(case), "analysis/*-pslist.csv", ["Name"], None, "rare", None, 25, 0)
    assert {s["counted"] for s in r["sources"]} == {"native"}
    assert [(g["Name"], g["units"]) for g in r["groups"][:2]] == [("notepad.exe", 1), ("svc_kit.exe", 1)]


def test_a_missing_table_is_reported_and_the_rest_counted(case):
    r = stack(str(case), ["analysis/corp-ws01-pslist.csv", "analysis/nope.csv"], ["Name"], ["Status=running"],
              "rare", None, 25, 0)
    assert r["errors"] == ["analysis/nope.csv: no such table in the case"] and r["distinct_groups"] == 2


def test_the_index_is_a_population(tmp_path, monkeypatch):
    from tests.core.test_contents_index import _body, _build, _image, _links, _plan
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (root / d).mkdir(parents=True)
    import core.execution_log as elog
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    std = [_body("Windows/System32/cmd.exe", "200-128-1"), _body("Windows/System32/kernel32.dll", "201-128-1")]
    _links(root, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-WS02", "evidence/disk/corp-ws02.raw")])
    _plan(root, [_image(root, "corp-ws01.raw"), _image(root, "corp-ws02.raw")])
    _build(root, monkeypatch, {"corp-ws01.raw": std,
                               "corp-ws02.raw": std + [_body("Users/jane.doe/kit.exe", "300-128-1"),
                                                       _body("Users/jane.doe/notes.txt", "301-128-1")]})
    r = stack(str(root), "index", ["name"], ["extension~^(exe|dll)$"], "rare", None, 25, 0)
    assert r["groups"][0]["name"] == "kit.exe" and r["groups"][0]["unit_names"] == ["CORP-WS02"]
    assert r["tail_1"] == 1 and r["distinct_groups"] == 3
    bad = stack(str(root), "index", ["owner"], None, "rare", None, 25, 0)
    assert bad["success"] is False and "owner" in bad["error"]


def test_a_prior_calls_tree_output_is_flattened(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    (tmp_path / "analysis").mkdir()
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    tree = [{"ImageFileName": "System", "__children": [
        {"ImageFileName": "smss.exe", "__children": [{"ImageFileName": "svc_kit.exe", "__children": []}]}]}]
    spill = tmp_path / "analysis" / "pstree.json"
    spill.write_text(json.dumps(tree))
    cid = log.record_tool_call(cmd="vol windows.pstree", success=True, truncated=True, retries=0, exit_code=0,
                               stderr="", stdout_excerpt="[", stdout_file=str(spill))
    r = stack(str(tmp_path), f"call:{cid}", ["ImageFileName"], None, "common", None, 25, 0)
    assert sorted(g["ImageFileName"] for g in r["groups"]) == ["System", "smss.exe", "svc_kit.exe"]
    assert r["source_call_ids"] == [cid]


def test_one_table_in_common_order_is_todays_pivot(case, monkeypatch):
    from tools.tabular import table_pivot
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    r = table_pivot(str(case / "analysis/corp-ws02-pslist.csv"), ["Status"])
    assert r["groups"] == [{"Status": "running", "count": 3}] and "units" not in r["groups"][0]


@pytest.mark.skipif(not shutil.which("gawk"), reason="the native pass needs gawk")
def test_the_native_pass_reads_crlf_and_takes_the_earliest_and_latest_time(tmp_path):
    (tmp_path / "analysis").mkdir()
    rows = [("explorer.exe", "2031-01-05 10:00:00"), ("kit.exe", "2031-01-09 10:00:00"),
            ("explorer.exe", "2031-01-01 10:00:00"), ("explorer.exe", "2031-01-03 10:00:00")]
    for host in ("a", "b"):
        (tmp_path / "analysis" / f"{host}.csv").write_bytes(
            ("Name,Time\r\n" + "".join(f"{n},{t}\r\n" for n, t in rows)).encode())
    r = stack(str(tmp_path), "analysis/*.csv", ["Name"], None, "common", None, 25, 0)
    first = r["groups"][0]
    assert first["Name"] == "explorer.exe" and first["rows"] == 6          # no "\r" kept on the last column
    assert (first["first"], first["last"]) == ("2031-01-01 10:00:00", "2031-01-05 10:00:00")


def test_too_many_distinct_values_refuse_the_call(case, monkeypatch):
    monkeypatch.setattr("core.stack.MAX_STACK_KEYS", 2)
    r = stack(str(case), "analysis/corp-ws01-pslist.csv", ["Name"], None, "rare", None, 25, 0)
    assert r["success"] is False and r["gate"] == "stack_too_many_values" and "Name" in r["error"]
    assert 'where=["<column>=<value>"]' in r["error"] and "path=<glob>" in r["error"]
    assert "time_start=<date>" in r["error"] and len(r["narrow_with"]) == 4


def test_a_month_first_time_column_is_labelled_file_order(tmp_path):
    (tmp_path / "analysis").mkdir()
    (tmp_path / "analysis" / "t.csv").write_text(
        "Name,Date\nkit.exe,03/01/2031 10:00:00\nkit.exe,01/15/2032 10:00:00\nkit.exe,12/31/2030 10:00:00\n")
    r = stack(str(tmp_path), "analysis/t.csv", ["Name"], None, "rare", None, 25, 0)
    g = r["groups"][0]
    assert r["time_order"].startswith("file order")
    assert (g["first"], g["last"]) == ("2031-03-01 10:00:00", "2030-12-31 10:00:00")
    iso = tmp_path / "analysis" / "i.csv"
    iso.write_text("Name,Date\nkit.exe,2031-03-01 10:00:00\nkit.exe,2030-12-31 10:00:00\n")
    r2 = stack(str(tmp_path), "analysis/i.csv", ["Name"], None, "rare", None, 25, 0)
    assert "time_order" not in r2 and r2["groups"][0]["first"] == "2030-12-31 10:00:00"


@pytest.mark.skipif(not shutil.which("gawk"), reason="the native pass needs gawk")
def test_the_native_pass_labels_a_month_first_column_file_order(tmp_path):
    (tmp_path / "analysis").mkdir()
    for name in ("a", "b"):
        (tmp_path / "analysis" / f"{name}.csv").write_text(
            "Name,Date\nkit.exe,03/01/2031 10:00:00\nkit.exe,12/31/2030 10:00:00\n")
    r = stack(str(tmp_path), "analysis/*.csv", ["Name"], None, "rare", None, 25, 0)
    assert r["time_order"].startswith("file order") and {s["counted"] for s in r["sources"]} == {"native"}
    assert (r["groups"][0]["first"], r["groups"][0]["last"]) == ("2031-03-01 10:00:00", "2030-12-31 10:00:00")


def test_time_order_is_decided_once_per_table(tmp_path):
    (tmp_path / "analysis").mkdir()
    (tmp_path / "analysis" / "t.csv").write_text(
        "Name,Date\nkit.exe,03/01/2031 10:00:00\nzz.exe,2031-05-01 10:00:00\nzz.exe,2031-04-01 10:00:00\n")
    r = stack(str(tmp_path), "analysis/t.csv", ["Name"], None, "common", None, 25, 0)
    zz = next(g for g in r["groups"] if g["Name"] == "zz.exe")
    assert r["time_order"].startswith("file order") and (zz["first"], zz["last"]) == (
        "2031-05-01 10:00:00", "2031-04-01 10:00:00")


def test_epoch_columns_of_mixed_lengths_are_file_order(tmp_path):
    (tmp_path / "analysis").mkdir()
    (tmp_path / "analysis" / "m.csv").write_text("Name,Timestamp\nkit.exe,999999999\nkit.exe,1000000000\n")
    (tmp_path / "analysis" / "s.csv").write_text("Name,Timestamp\nkit.exe,1900000000\nkit.exe,1000000000\n")
    assert "time_order" in stack(str(tmp_path), "analysis/m.csv", ["Name"], None, "common", None, 25, 0)
    assert "time_order" not in stack(str(tmp_path), "analysis/s.csv", ["Name"], None, "common", None, 25, 0)


def _timed(tmp_path, fmt=lambda d: f"2031-01-0{d} 10:00:00"):
    (tmp_path / "analysis").mkdir(exist_ok=True)
    for host in ("a", "b"):
        (tmp_path / "analysis" / f"{host}.csv").write_text(
            "Name,Time\n" + "".join(f"{n},{fmt(d)}\n" for n, d in (("x.exe", 1), ("y.exe", 5), ("z.exe", 9))))


def test_a_time_window_bounds_the_rows_a_stack_counts(tmp_path):
    _timed(tmp_path)
    r = stack(str(tmp_path), "analysis/a.csv", ["Name"], None, "common", None, 25, 0,
              time_start="2031-01-04", time_end="2031-01-06")
    assert [g["Name"] for g in r["groups"]] == ["y.exe"]


@pytest.mark.skipif(not shutil.which("gawk"), reason="the native pass needs gawk")
def test_the_native_pass_applies_the_window(tmp_path):
    _timed(tmp_path)
    r = stack(str(tmp_path), "analysis/*.csv", ["Name"], None, "common", None, 25, 0,
              time_start="2031-01-04", time_end="2031-01-09")
    assert {s["counted"] for s in r["sources"]} == {"native"}
    assert sorted(g["Name"] for g in r["groups"]) == ["y.exe", "z.exe"] and r["groups"][0]["rows"] == 2


def test_a_window_over_several_non_iso_tables_says_why(tmp_path):
    _timed(tmp_path, fmt=lambda d: f"01/0{d}/2031 10:00:00")
    r = stack(str(tmp_path), "analysis/*.csv", ["Name"], ["Name=y.exe"], "common", None, 25, 0,
              time_start="2031-01-04")
    assert all("not ISO-8601" in e for e in r["errors"])
    one = stack(str(tmp_path), "analysis/a.csv", ["Name"], None, "common", None, 25, 0, time_start="2031-01-04")
    assert sorted(g["Name"] for g in one["groups"]) == ["y.exe", "z.exe"]          # one table: the row loop
