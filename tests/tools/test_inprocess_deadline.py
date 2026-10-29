"""ATLAS_INPROCESS_DEADLINE and ATLAS_REPEAT_KEY_PATHS: the
event-log record loops stop at a per-call deadline with a file-order resume,
a cut result is shown as written and keeps its work item open, and the bulk
repeat gate keys on what a call reads and writes. The python-evtx reader is
replaced by an invented in-memory log (chunks out of record-number order, a
damaged record); no case file is read."""
from __future__ import annotations

import itertools
import json

import pytest

import core.execution_log as elog


class _Rec:
    def __init__(self, n, renders, bad=False):
        self.n, self.renders, self.bad = n, renders, bad

    def xml(self):
        self.renders.append(self.n)
        if self.bad:
            raise ValueError("damaged record")
        return f"<Event><System><EventID>{1000 + self.n % 3}</EventID></System><Data>r{self.n}</Data></Event>"

    def timestamp(self):
        return None


class _Chunk:
    def __init__(self, first, last, renders, bad=()):
        self.first, self.last = first, last
        self._recs = [_Rec(n, renders, n in bad) for n in range(first, last + 1)]

    def log_first_record_number(self):
        return self.first

    def log_last_record_number(self):
        return self.last

    def records(self):
        return iter(self._recs)


def _fake_log(monkeypatch, renders, bad=()):
    # The numbering wraps: the file's first chunk holds the highest numbers.
    chunks = [(21, 30), (1, 10), (11, 20)]

    class _Evtx:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def chunks(self):
            return iter([_Chunk(a, b, renders, bad) for a, b in chunks])
    import Evtx.Evtx
    monkeypatch.setattr(Evtx.Evtx, "Evtx", _Evtx)


@pytest.fixture
def case(tmp_path, monkeypatch):
    for sub in ("analysis", "evidence"):
        (tmp_path / sub).mkdir()
    elog.log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"), save_session=False)
    log_path = tmp_path / "evidence" / "Application.evtx"
    log_path.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    return tmp_path, str(log_path)


def _clock(monkeypatch, step=1.0):
    import time
    ticks = itertools.count()
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks) * step)


def test_a_cut_dump_resumes_in_file_order_and_writes_every_record_once(case, monkeypatch):
    root, evtx = case
    renders: list[int] = []
    _fake_log(monkeypatch, renders)
    monkeypatch.setattr("core.timeout.evtx_deadline_seconds", lambda *a, **k: 12)
    _clock(monkeypatch)
    from tools.misc import evtx_dump
    out = str(root / "analysis" / "app.xml")
    first = evtx_dump(evtx, output_path=out)
    assert first["success"] is False and first["incomplete"] is True and first["gate"] == "call_deadline"
    assert first["records_total"] == 30 and "</Events>" not in open(out).read()
    assert "no absence follows" in first["note"] and "ez.evtxecmd" in first["note"]
    entry = next(e for e in elog.log._entries if e.get("call_id") == first["_atlas_call_id"]) \
        if first.get("_atlas_call_id") else elog.log._entries[-1]
    assert entry.get("incomplete") is True and entry.get("truncated") is True
    results, cursor = [first], first["resume"]["resume_from"]
    while cursor:
        before = len(renders)
        done = {int(x) for x in __import__("re").findall(r"<Data>r(\d+)</Data>", open(out).read())}
        nxt = evtx_dump(evtx, output_path=out, resume_from=cursor)
        # Nothing before the cursor is rendered again.
        assert not done & set(renders[before:])
        results.append(nxt)
        cursor = (nxt.get("resume") or {}).get("resume_from", "")
    text = open(out).read()
    order = [int(x) for x in __import__("re").findall(r"<Data>r(\d+)</Data>", text)]
    assert order == list(range(21, 31)) + list(range(1, 21)) and text.rstrip().endswith("</Events>")
    assert sum(x["records_written"] for x in results) == 30 and results[-1]["success"] is True


def test_a_damaged_record_is_counted_and_passed(case, monkeypatch):
    root, evtx = case
    _fake_log(monkeypatch, [], bad={5})
    from tools.misc import evtx_dump
    r = evtx_dump(evtx, output_path=str(root / "analysis" / "app.xml"))
    assert r["success"] is True and r["records_written"] == 29 and r["records_unreadable"] == 1


def test_the_filter_resumes_where_its_deadline_cut_it(case, monkeypatch):
    root, evtx = case
    _fake_log(monkeypatch, [])
    monkeypatch.setattr("core.timeout.evtx_deadline_seconds", lambda *a, **k: 8)
    _clock(monkeypatch)
    from tools.misc import evtx_filter
    r = evtx_filter(evtx, "1001")
    assert r["incomplete"] is True and r["resume"]["resume_from"]
    assert any("resume_from" in g for g in r["retry_guidance"])


def test_the_switch_off_dumps_as_before(case, monkeypatch):
    root, evtx = case
    _fake_log(monkeypatch, [])
    monkeypatch.setenv("ATLAS_INPROCESS_DEADLINE", "0")
    _clock(monkeypatch, step=10_000.0)
    from tools.misc import evtx_dump
    r = evtx_dump(evtx, output_path=str(root / "analysis" / "app.xml"))
    assert r["success"] is True and r["records_written"] == 30
    assert not {"incomplete", "resume", "records_total", "records_unreadable"} & set(r)


def test_a_cut_result_is_shown_as_written_and_keeps_its_item_open(case, monkeypatch):
    root, evtx = case
    from core.tool_result_view import compact_if_artifact_ready
    cut = {"success": False, "incomplete": True, "truncated": True, "artifact_paths": [str(root / "x.xml")],
           "resume": {"resume_from": "1:2"}}
    assert compact_if_artifact_ready(cut, force=True) is None
    from core import work_order as W
    item = elog.log.add_work_item("plan", ["task-0001"], "misc_evtx_dump", {"path": "evidence/Application.evtx"}, "x")
    cid = elog.log.record_tool_call("<py>:misc_evtx_dump", False, True, 0, 1, stderr="stopped at the deadline")
    elog.log.annotate_tool_call(cid, args=json.dumps({"evtx_path": "evidence/Application.evtx"}),
                                mcp_tool="misc_evtx_dump", incomplete=True)
    entry = next(e for e in elog.log._entries if e.get("call_id") == cid)
    assert W._outcome(entry) is None


def test_the_repeat_key_is_what_a_call_reads_and_writes():
    from core.input_scale import repeat_fingerprint as fp
    a = {"evtx_path": "/c/evidence/Security.evtx", "output_path": "/c/analysis/s.xml", "max_records": 1}
    b = {"evtx_path": "/c/evidence/Security.evtx", "output_path": "/c/analysis/s.xml"}
    assert fp("misc_evtx_dump", a, "/c") == fp("misc_evtx_dump", b, "/c")
    peek = {"evtx_path": "/c/evidence/Security.evtx", "max_records": 1}
    read = {"evtx_path": "/c/evidence/Security.evtx", "max_records": 500}
    assert fp("misc_evtx_dump", peek, "/c") != fp("misc_evtx_dump", read, "/c")
    f1 = {"evtx_path": "/c/e.evtx", "event_ids": "1000", "max_results": 200, "wall_clock_budget_s": 60}
    assert fp("misc_evtx_filter", f1, "/c") == fp("misc_evtx_filter", {**f1, "wall_clock_budget_s": 600}, "/c")
    assert fp("misc_evtx_filter", f1, "/c") != fp("misc_evtx_filter", {**f1, "max_results": 400}, "/c")
    assert fp("misc_evtx_filter", f1, "/c") != fp("misc_evtx_filter", {**f1, "event_ids": "1001"}, "/c")
    assert fp("misc_evtx_dump", {**b, "resume_from": "1:0"}, "/c") != fp("misc_evtx_dump",
                                                                        {**b, "resume_from": "2:0"}, "/c")


def test_a_read_of_the_same_log_settles_the_cut_call(tmp_path):
    from agent.tool_investigate import settle_investigate_debt
    log = tmp_path / "Security.evtx"
    other = tmp_path / "System.evtx"
    for p in (log, other):
        p.write_bytes(b"ElfFile\x00")
    issue = {"tool": "misc_evtx_dump", "kind": "incomplete_scan", "blocking_finish": True, "inputs": [str(log)]}
    assert settle_investigate_debt([issue], set(), [("hash_hash_file", [str(log)])]) == [issue]
    assert settle_investigate_debt([issue], set(), [("ez_ez_evtxecmd", [str(other)])]) == [issue]
    assert settle_investigate_debt([issue], set(), [("ez_ez_evtxecmd", [str(log)])]) == []


def test_an_identical_call_after_a_cut_gets_the_cursor_not_a_restart(case, monkeypatch):
    root, evtx = case
    renders: list[int] = []
    _fake_log(monkeypatch, renders)
    monkeypatch.setattr("core.timeout.evtx_deadline_seconds", lambda *a, **k: 12)
    _clock(monkeypatch)
    from tools.misc import evtx_dump
    out = str(root / "analysis" / "app.xml")
    first = evtx_dump(evtx, output_path=out)
    size, done = len(open(out).read()), len(renders)
    again = evtx_dump(evtx, output_path=out)
    assert again["repeated_cut_call"] is True and again["resume"] == first["resume"]
    assert len(renders) == done and len(open(out).read()) == size        # nothing read, nothing overwritten
    while (nxt := evtx_dump(evtx, output_path=out, resume_from=again["resume"]["resume_from"])).get("resume"):
        again = nxt
    assert "repeated_cut_call" not in evtx_dump(evtx, output_path=out)    # a finished log is read again


def test_the_filter_pages_past_max_results(case, monkeypatch):
    root, evtx = case
    _fake_log(monkeypatch, [])
    from tools.misc import evtx_filter
    page1 = evtx_filter(evtx, "1001", max_results=4)
    assert page1["cap_hit"] is True and page1["resume"]["resume_from"]
    page2 = evtx_filter(evtx, "1001", max_results=4, resume_from=page1["resume"]["resume_from"])
    assert not set(page1["events"]) & set(page2["events"]) and len(page2["events"]) == 4


def test_a_parse_of_the_folder_holding_the_log_settles_the_cut(tmp_path):
    from agent.tool_investigate import settle_investigate_debt
    logs = tmp_path / "Logs"
    logs.mkdir()
    cut = logs / "Security.evtx"
    cut.write_bytes(b"ElfFile\x00")
    issue = {"tool": "misc_evtx_dump", "kind": "incomplete_scan", "blocking_finish": True, "inputs": [str(cut)]}
    assert settle_investigate_debt([issue], set(), [("ez_ez_evtxecmd", [str(logs)])]) == []
    assert settle_investigate_debt([issue], set(), [("ez_ez_evtxecmd", [str(tmp_path / "Other")])]) == [issue]


def test_a_batch_whose_sub_call_timed_out_is_an_incomplete_read():
    from agent.tool_investigate import classify_tool_result
    batch = {"success": False, "results": [{"success": True}, {"success": False, "timed_out": True}]}
    assert classify_tool_result("misc_batch_run", json.dumps(batch))["kind"] == "incomplete_scan"


def test_a_bulk_tool_outside_the_named_set_keeps_the_full_argument_key():
    from core.deferred_intents import args_fingerprint
    from core.input_scale import repeat_fingerprint as fp
    a = {"csv_path": "/c/evidence/t.csv", "output_csv": "/c/analysis/o.csv", "max_hits": 1, "timeout": 60}
    b = {**a, "max_hits": 50, "timeout": 600}
    assert fp("ez_ez_evtxecmd", a, "/c") == args_fingerprint("ez_ez_evtxecmd", a, "/c")
    assert fp("ez_ez_evtxecmd", a, "/c") != fp("ez_ez_evtxecmd", b, "/c")
    for name in ("misc.evtx_dump", "misc_misc_evtx_dump"):          # either spelling is in the set
        assert fp(name, {"evtx_path": "/c/e.evtx", "timeout": 1}, "/c") == \
            fp(name, {"evtx_path": "/c/e.evtx", "timeout": 9}, "/c")


def test_the_filters_rows_are_kept_on_its_own_entry(case, monkeypatch):
    """The matching records are the call's output: its trace entry holds
    them (hashed, whole) and the result names that entry."""
    import hashlib
    root, evtx = case
    _fake_log(monkeypatch, [])
    from tools.misc import evtx_filter
    r = evtx_filter(evtx, "1001", max_results=4)
    entry = next(e for e in elog.log._entries if e.get("call_id") == r["_atlas_call_id"])
    kept = entry.get("stdout_excerpt") or open(entry["stdout_file"]).read()
    assert r["events"] and all(ev.split("<Data>")[1].split("</Data>")[0] in kept for ev in r["events"])
    assert entry.get("output_hash") != "blake2b:" + hashlib.blake2b(b"", digest_size=32).hexdigest()
