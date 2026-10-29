"""A result whose call saved a JSON array of records (a plugin's JSON
rendering) is shown as the numbered row view, split once for the view and
the map. Invented memory-plugin-shaped records only (CORP-WS01, 2031 times)."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

from core import incident_map as IM
from core.indicators import _rows_of, flat_records, flat_rows_of
from core.tool_result_view import render_record_view


def _proc(pid, ppid, name, minute, kids=()):
    return {"CreateTime": f"2031-03-10T{8 + minute // 60:02d}:{minute % 60:02d}:05+00:00", "ExitTime": None,
            "File output": "Disabled", "Handles": None, "ImageFileName": name, "Offset(V)": 281474976710656 + pid * 64,
            "PID": pid, "PPID": ppid, "SessionId": 1, "Threads": 3 + pid % 7, "Wow64": False,
            "__children": list(kids)}


def _pslist(n=240):
    """A pslist of n invented processes, one created per minute."""
    return [_proc(1000 + 4 * i, 1000 + 4 * (i // 8), f"corp-app{i:03d}.exe", i) for i in range(n)]


def _pstree():
    """15 roots of 15 children each: 240 processes."""
    return [_proc(5000 + 100 * r, 4, f"corp-root{r:02d}.exe", r,
                  [_proc(5000 + 100 * r + c, 5000 + 100 * r, f"corp-child{r:02d}-{c:02d}.exe", r + c)
                   for c in range(1, 16)]) for r in range(15)]


def _entry(tmp_path, cid, records, **extra):
    path = tmp_path / f"{cid}_vol.stdout"
    path.write_text("\n" + json.dumps(records, indent=2), encoding="utf-8")
    return {"type": "tool_call", "call_id": cid, "cmd": "vol -f evidence/corp-ws01.mem -r json windows.pslist",
            "stdout_file": str(path), "stdout_excerpt": path.read_text()[:2000], "truncated": True, **extra}


def _result(cid, **extra):
    return {"success": True, "stdout": "[...]", "truncated": True, "exit_code": 0,
            "cmd": "vol -f evidence/corp-ws01.mem -r json windows.pslist", "_atlas_call_id": cid, **extra}


def test_a_240_process_list_is_a_numbered_view_with_its_header_and_a_real_route_to_the_rest(tmp_path):
    entry = _entry(tmp_path, 71, _pslist())
    text, note = render_record_view(_result(71, note="answered from the result store, not re-run"), entry,
                                    12000, 71)
    view = json.loads(text)
    assert note["rows_split"] == "flat" and note["view_rows_returned"] == 240
    assert 100 <= note["view_rows_shown"] < 240 and len(view["rows"]) <= note["view_rows_shown"]
    assert all(re.match(r"#\d+", r) for r in view["rows"])
    # the result's own scalars stay; the output text itself does not
    assert view["_atlas_call_id"] == 71 and view["note"].startswith("answered from the result store")
    # the stdout's cut flag is gone: the rows are the full saved output
    assert view["cmd"].endswith("windows.pslist") and "truncated" not in view and "stdout" not in view
    # a plugin takes no offset: the hint names a read that exists
    assert 'table.table_pivot path="call:71"' in view["next"]
    # the rows from the middle of the list are shown too
    mids = [int(r.split(" ", 1)[0][1:]) for r in view["rows"] if r.startswith("#")]
    assert any(100 <= m <= 140 for m in mids)


def test_the_split_keeps_value_types_and_a_trees_depth(tmp_path):
    rows = flat_records(_pstree())
    assert len(rows) == 240 and rows[0]["_depth"] == 0 and rows[1]["_depth"] == 1
    assert rows[1]["PPID"] == rows[0]["PID"] and isinstance(rows[1]["PID"], int) and rows[1]["Handles"] is None
    assert [r["_row"] for r in rows] == list(range(1, 241)) and "__children" not in rows[0]
    assert "_depth" not in flat_records(_pslist(3))[0]                      # a list that does not nest
    text, _note = render_record_view(_result(72), _entry(tmp_path, 72, _pstree()), 12000, 72)
    assert "_depth" in json.loads(text)["columns"]


def test_a_marker_of_the_view_names_one_process_and_an_older_entry_keeps_its_rows(tmp_path, monkeypatch):
    new = _entry(tmp_path, 73, _pstree())
    text, note = render_record_view(_result(73), new, 12000, 73)
    new.update(note)
    old = _entry(tmp_path, 74, _pstree())                                    # recorded before the flat view
    entries = {73: new, 74: old}
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid))))
    m = object.__new__(IM.IncidentMap)
    line = next(r for r in json.loads(text)["rows"] if re.search(r"corp-child\d\d-\d\d\.exe", r))
    name = re.search(r"corp-child\d\d-\d\d\.exe", line).group(0)
    n = re.match(r"#(\d+)", line).group(1)
    ref, exact = m.marker_rows(73)[n]
    assert exact and json.loads(m.row_text(ref))["ImageFileName"] == name
    # an entry without the flat view keeps the split: its R5 is still the fifth tree, whole
    fifth = json.loads(m.row_text("74#R5"))
    assert fifth["ImageFileName"] == "corp-root04.exe" and len(fifth["__children"]) == 15
    assert len(_rows_of(old, old["stdout_excerpt"])[0]) != 240 and len(_rows_of(new, "[")[0]) == 240


def test_a_basis_quote_of_the_view_resolves_by_its_marker(tmp_path, monkeypatch):
    from agent.frontier import SubmitApplier
    entry = _entry(tmp_path, 75, _pslist())
    text, note = render_record_view(_result(75), entry, 12000, 75)
    entry.update(note)
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entry if int(cid) == 75 else None))
    ap = object.__new__(SubmitApplier)
    ap.m, ap.named, ap.out, ap.item, ap.agent = object.__new__(IM.IncidentMap), set(), {"dropped": []}, {}, None
    line = json.loads(text)["rows"][5]
    name = re.search(r"corp-app\d{3}\.exe", line).group(0)
    kept, _q = ap._basis([{"call_id": 75, "quote": line.split(" | ")[0] + " | " + name}],
                         SimpleNamespace(calls=[75], seen={75: text}))
    assert len(kept) == 1 and json.loads(ap.m.row_text(kept[0]["row_ref"]))["ImageFileName"] == name


def test_a_deferred_partial_cut_or_non_record_result_keeps_todays_path(tmp_path, monkeypatch):
    entry = _entry(tmp_path, 76, _pslist(5))
    deferred = {"success": True, "deferred": True, "job_id": "job-1", "plugin": "windows.pslist",
                "_atlas_call_id": 76}
    assert render_record_view(deferred, entry, 12000, 76) is None
    assert render_record_view({**_result(76), "success": False}, entry, 12000, 76) is None
    monkeypatch.setattr("core.timeout.inprocess_deadline_on", lambda: True)
    assert render_record_view(_result(76, incomplete=True), entry, 12000, 76) is None
    cut = _entry(tmp_path, 77, _pslist(5))
    with open(cut["stdout_file"], "r+", encoding="utf-8") as fh:             # a cut JSON text
        fh.truncate(300)
    assert render_record_view(_result(77), cut, 12000, 77) is None
    text_out = _entry(tmp_path, 78, [])
    (tmp_path / "78_vol.stdout").write_text("PID\tPPID\tImageFileName\n4\t0\tSystem\n", encoding="utf-8")
    assert render_record_view(_result(78), text_out, 12000, 78) is None


def test_one_large_output_is_parsed_once_per_file_state(tmp_path):
    entry = _entry(tmp_path, 79, _pslist(50))
    first = flat_rows_of(entry)
    assert flat_rows_of(entry) is first                                     # cached
    with open(entry["stdout_file"], "a", encoding="utf-8") as fh:
        fh.write("\n")                                                       # the file changed: read again
    assert flat_rows_of(entry) is not first and len(flat_rows_of(entry)) == 50


def test_the_pivot_split_is_unchanged_text_cells_in_tree_order():
    from core.stack import _flatten
    rows = _flatten(_pstree()[:2])
    assert len(rows) == 32 and rows[0]["ImageFileName"] == "corp-root00.exe"
    assert rows[1]["ImageFileName"] == "corp-child00-01.exe" and rows[16]["ImageFileName"] == "corp-root01.exe"
    assert rows[0]["PID"] == "5000" and rows[0]["Handles"] == "" and "_row" not in rows[0] and "_depth" not in rows[0]


def test_the_toolbox_shows_a_saved_record_array_as_the_view_and_marks_the_split(tmp_path, monkeypatch):
    from agent import toolbox as TB
    entry = _entry(tmp_path, 80, _pslist(30))
    fake = SimpleNamespace(index=lambda: SimpleNamespace(by_call_id={80: entry}))
    monkeypatch.setattr("core.execution_log.log", fake)
    text, note, cid, rows = TB._record_view(_result(80), "{}", [])
    assert cid == 80 and note["rows_split"] == "flat" and len(rows) == 30 and json.loads(text)["rows"]
    assert TB._record_view({"success": True, "stdout": "x"}, "{}", []) is None              # no call id


def test_the_cache_holds_outputs_by_their_bytes_and_keeps_none_larger_than_its_bound(tmp_path, monkeypatch):
    from core import indicators as I
    monkeypatch.setattr(I, "_FLAT_CACHE", {})
    small = [_entry(tmp_path, 90 + i, _pslist(20)) for i in range(3)]
    size = (tmp_path / "90_vol.stdout").stat().st_size
    monkeypatch.setattr(I, "_FLAT_CACHE_BYTES", 2 * size + size // 2)          # room for two of them
    for e in small:
        assert len(flat_rows_of(e)) == 20
    assert len(I._FLAT_CACHE) == 2 and sum(k[1] for k in I._FLAT_CACHE) <= I._FLAT_CACHE_BYTES
    assert small[0]["stdout_file"] not in {k[0] for k in I._FLAT_CACHE}        # the oldest went first
    big = _entry(tmp_path, 99, _pslist(200))
    assert len(flat_rows_of(big)) == 200                                       # parsed for its call
    assert big["stdout_file"] not in {k[0] for k in I._FLAT_CACHE}             # and not kept


def test_readers_on_several_threads_never_fail_on_the_cache(tmp_path, monkeypatch):
    import threading
    from core import indicators as I
    monkeypatch.setattr(I, "_FLAT_CACHE", {})
    entries = [_entry(tmp_path, 100 + i, _pslist(5)) for i in range(6)]
    size = (tmp_path / "100_vol.stdout").stat().st_size
    monkeypatch.setattr(I, "_FLAT_CACHE_BYTES", 2 * size)                      # every read evicts
    errors = []

    def read():
        try:
            for _ in range(200):
                for e in entries:
                    assert len(flat_rows_of(e)) == 5
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    import sys
    switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)                       # switch threads often: the unlocked cache failed here
    try:
        threads = [threading.Thread(target=read) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(switch)
    assert errors == []


def test_two_plugins_on_one_image_each_credit_their_own_records(tmp_path, monkeypatch):
    from agent import toolbox as TB
    from core import shown_rows as S
    dll = [{"PID": 1000 + i, "Process": f"corp-app{i:03d}.exe", "Base": 140698833649664 + i * 4096,
            "Name": f"corp-lib{i:02d}.dll", "LoadTime": f"2031-03-10T09:{i:02d}:00+00:00", "__children": []}
           for i in range(20)]
    entries = {81: _entry(tmp_path, 81, _pslist(20)), 82: _entry(tmp_path, 82, dll),
               83: _entry(tmp_path, 83, _pslist(20))}
    fake = SimpleNamespace(index=lambda: SimpleNamespace(by_call_id=entries))
    monkeypatch.setattr("core.execution_log.log", fake)
    args = {"image": "evidence/corp-ws01.mem"}
    keys = {}
    for cid in entries:
        _t, _n, _c, rows = TB._record_view(_result(cid), "{}", [])
        assert rows and all("_row" not in r and "_depth" not in r for r in rows)
        keys[cid] = set(S.row_keys("vol_vol_pslist", args, {"rows": rows}))
    assert len(keys[81]) == 20 and len(keys[82]) == 20
    assert not keys[81] & keys[82]                     # a second plugin's records are new rows
    assert keys[83] == keys[81]                        # the same records read again are not


def test_the_shown_sentence_says_records_returned_and_never_a_match(tmp_path):
    text, _note = render_record_view(_result(84), _entry(tmp_path, 84, _pslist()), 12000, 84)
    shown = json.loads(text)["shown"]
    assert "of the 240 records this call returned (its whole output)" in shown and "match" not in shown
    assert "the rest are in call 84's saved output" in shown
    text, _note = render_record_view(_result(85), _entry(tmp_path, 85, _pslist(6)), 12000, 85)
    assert json.loads(text)["shown"].startswith("all 6 records this call returned (its whole output)")


def _handles(n=240):
    """A handle list of n invented records: no time in any of them."""
    return [{"PID": 1000 + 4 * (i // 12), "Process": f"corp-app{i // 12:03d}.exe", "Offset": 281474976710656 + i * 48,
             "HandleValue": 4 * (i + 1), "Type": ("File", "Key", "Event")[i % 3], "GrantedAccess": "0x1f0003",
             "Name": f"\\Device\\HarddiskVolume2\\corp\\data{i:03d}.bin", "__children": []} for i in range(n)]


def test_the_order_is_said_as_the_records_give_it_time_order_only_when_they_carry_times(tmp_path):
    timed = json.loads(render_record_view(_result(86), _entry(tmp_path, 86, _pslist()), 12000, 86)[0])["shown"]
    assert "listed oldest first" in timed and "#n = place in the time order of the 240" in timed
    text, _n = render_record_view(_result(87), _entry(tmp_path, 87, _handles()), 12000, 87)
    view = json.loads(text)
    assert "listed in the order the call returned them" in view["shown"] and "#n = place in that order" in view["shown"]
    assert "oldest" not in view["shown"] and "time order" not in view["shown"]
    marks = [int(r.split(" ", 1)[0][1:]) for r in view["rows"]]
    assert marks == sorted(marks) and f"data{marks[3] - 1:03d}.bin" in view["rows"][3]   # #n is the n-th record
    whole = json.loads(render_record_view(_result(88), _entry(tmp_path, 88, _handles(6)), 12000, 88)[0])["shown"]
    assert whole == "all 6 records this call returned (its whole output), listed in the order the call returned them"
    mixed = _pslist(4) + [{k: v for k, v in r.items() if k != "CreateTime"} for r in _pslist(4)]
    shown = json.loads(render_record_view(_result(89), _entry(tmp_path, 89, mixed), 12000, 89)[0])["shown"]
    assert "the 4 records with a time listed oldest first, the others after them" in shown


def test_two_readers_of_one_uncached_output_parse_it_once(tmp_path, monkeypatch):
    import threading
    import time
    from core import indicators as I
    monkeypatch.setattr(I, "_FLAT_CACHE", {})
    real, calls = I._flat_parse, []

    def slow(text):
        calls.append(1)
        time.sleep(0.2)
        return real(text)
    monkeypatch.setattr(I, "_flat_parse", slow)
    entry = _entry(tmp_path, 110, _pslist(30))
    got = []
    threads = [threading.Thread(target=lambda: got.append(flat_rows_of(entry))) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1 and len(got) == 3 and all(g is got[0] and len(g) == 30 for g in got)


def test_a_one_record_views_shared_cells_name_its_record_and_a_bare_marker_is_told_how(tmp_path, monkeypatch):
    """A plugin call for one process returns one record: the view puts its every cell into the shared line and the
    record's line is its marker alone. The marker-alone refusal says to quote a value with it; doing so names it."""
    from agent.frontier import SubmitApplier
    records = [{"PID": 4232, "Process": "corp-app.exe", "Args": "C:\\Users\\Public\\corp-app.exe -k --install",
                "__children": []}]
    entry = _entry(tmp_path, 120, records)
    text, note = render_record_view(_result(120), entry, 12000, 120)
    entry.update(note)
    view = json.loads(text)
    assert view["rows"] == ["#1 "] and view["same_in_every_returned_row"]["Process"] == "corp-app.exe"
    monkeypatch.setattr(IM.IncidentMap, "_entry", staticmethod(lambda cid: entry if int(cid) == 120 else None))
    ap = object.__new__(SubmitApplier)
    ap.m, ap.named, ap.out, ap.item, ap.agent = object.__new__(IM.IncidentMap), set(), {"dropped": []}, {}, None
    run = SimpleNamespace(calls=[120], seen={120: text})
    kept, _q = ap._basis([{"call_id": 120, "quote": "#1 "}], run)
    assert kept == [] and "quote a value of row #1 with it" in ap.out["dropped"][-1]
    for quote in ("#1 C:\\Users\\Public\\corp-app.exe -k --install", "#1 | Args: C:\\Users\\Public\\corp-app.exe",
                  "corp-app.exe | 4232"):
        kept, _q = ap._basis([{"call_id": 120, "quote": quote}], run)
        assert [k["row_ref"] for k in kept] == ["120#R1"], quote
    # the line and the shared cells a part of the quote is in ("corp-app.exe" is in two of them)
    assert kept[0]["quote"] == ("#1 | PID: 4232 | Process: corp-app.exe | Args: C:\\Users\\Public\\corp-app.exe -k "
                                "--install")
    kept, _q = ap._basis([{"call_id": 120, "quote": "#1 | PID | Process"}], run)
    assert kept == [] and "names no value" in ap.out["dropped"][-1]
