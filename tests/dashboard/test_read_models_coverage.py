"""The Coverage tab's read model: the ledger's items and content classes in
four plain states, the extracted outputs' file classes the same way, the
counts behind the header, and the cache that keeps a moving trace from
being read on every poll. Invented fixtures only (CORP-DC01, CORP-WS07,
dates in 2031)."""
from __future__ import annotations

import json
import os
import threading

import pytest

from dashboard import read_models


def _write(tmp_path, ledger):
    atlas = tmp_path / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    (atlas / "coverage_ledger.json").write_text(json.dumps(ledger))
    read_models._coverage_cache.clear()
    read_models._extracted_cache.clear()
    return str(tmp_path)


def _touch_trace(tmp_path, when: int):
    """A trace document with the given mtime (what a run's flush moves)."""
    doc = tmp_path / "analysis" / "CASE-A_trace.json"
    doc.parent.mkdir(exist_ok=True)
    if not doc.exists():
        doc.write_text("[]")
    os.utime(doc, (when, when))


def _unit(state, **extra):
    u = {"state": state, "reason_kind": "", "reason": "", "proof_call_ids": [], "scope_fingerprint": "",
         "acknowledged_entities": [], "reopened": 0}
    u.update(extra)
    return u


def _ledger():
    items = {
        "dc01": {"id": "dc01", "path": "evidence/CORP-DC01.E01", "kind": "image", "host": "CORP-DC01",
                 "level": "item", **_unit("relevant")},
        "ws07": {"id": "ws07", "path": "evidence/CORP-WS07.mem", "kind": "memory", "host": "CORP-WS07",
                 "level": "item", **_unit("relevant")},
        "notes": {"id": "notes", "path": "evidence/notes.zip", "kind": "archive", "host": "",
                  "level": "item", **_unit("relevant")},
    }
    classes = {
        "dc01:event logs": {"id": "dc01:event logs", "level": "class", "item": "dc01", "host": "CORP-DC01",
                            "label": "event logs", "files": 12, "empty": 0,
                            **_unit("read", proof_call_ids=[12, 14])},
        "dc01:registry hives": {"id": "dc01:registry hives", "level": "class", "item": "dc01", "host": "CORP-DC01",
                                "label": "registry hives", "files": 7, "empty": 0,
                                **_unit("partial", reason="3 of 7 files read", credited="3 of 7 files read")},
        "dc01:browser history": {"id": "dc01:browser history", "level": "class", "item": "dc01", "host": "CORP-DC01",
                                 "label": "browser history", "files": 2, "empty": 0,
                                 **_unit("left", reason_kind="outside_window",
                                         reason="its newest row is from 2031-01-20", proof_call_ids=[31])},
        "dc01:scheduled tasks": {"id": "dc01:scheduled tasks", "level": "class", "item": "dc01", "host": "CORP-DC01",
                                 "label": "scheduled tasks", "files": 9, "empty": 0, **_unit("relevant")},
        "dc01:prefetch": {"id": "dc01:prefetch", "level": "class", "item": "dc01", "host": "CORP-DC01",
                          "label": "prefetch", "files": 40, "empty": 0, **_unit("pending")},
        "ws07:processes": {"id": "ws07:processes", "level": "class", "item": "ws07", "host": "CORP-WS07",
                           "label": "processes", "files": 0, "empty": 0, **_unit("walked")},
        "ws07:network endpoints": {"id": "ws07:network endpoints", "level": "class", "item": "ws07",
                                   "host": "CORP-WS07", "label": "network endpoints", "files": 0, "empty": 0,
                                   **_unit("swept", reason="1 of 1 file(s) parsed and swept")},
        "ws07:file objects": {"id": "ws07:file objects", "level": "class", "item": "ws07", "host": "CORP-WS07",
                              "label": "file objects", "files": 0, "empty": 0,
                              **_unit("pending", triage_refused="the window has no stated start")},
    }
    return {"schema_version": 3, "case_id": "CASE-A", "units": {}, "items": items, "classes": classes}


def _outputs():
    return [
        {"path": "analysis/exports/dc01", "made": "tsk_icat", "blocked": "",
         "classes": {"evtx": [2, 2], "csv": [1, 3], "lnk": [0, 4], "dat": [0, 2]},
         "sample": {"lnk": "analysis/exports/dc01/desk.lnk"}, "open": ["lnk", "dat"]},
        {"path": "analysis/exports/ws07", "made": "7z", "blocked": "the reads failed",
         "classes": {"bin": [0, 1]}, "sample": {}, "open": []},
    ]


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr("core.coverage_ledger.extracted_outputs", lambda _cd: _outputs())
    return _write(tmp_path, _ledger())


def test_the_ledgers_states_become_four_plain_ones_and_its_prose_stays_behind(case):
    d = read_models.coverage(case)
    assert d["ledger"] and d["disposition"]
    dc01 = next(i for i in d["items"] if i["id"] == "dc01")
    by = {c["label"]: c for c in dc01["classes"]}
    assert by["event logs"]["state"] == "read" and by["event logs"]["proof"] == ["12", "14"]
    assert by["registry hives"]["state"] == "partial" and by["registry hives"]["note"] == ""
    assert by["browser history"]["state"] == "left"
    assert by["browser history"]["reason_kind"] == "outside_window"
    assert by["browser history"]["reason"] == "its newest row is from 2031-01-20"
    assert by["browser history"]["proof"] == ["31"]
    assert by["scheduled tasks"]["state"] == "open" and by["scheduled tasks"]["note"] == "undecided"
    assert by["prefetch"]["state"] == "open" and by["prefetch"]["note"] == "undecided"   # pending is undecided too
    assert by["prefetch"]["files"] == 40
    assert dc01["counts"] == {"read": 1, "partial": 1, "parsed": 0, "left": 1, "open": 2}
    ws07 = next(i for i in d["items"] if i["id"] == "ws07")
    by = {c["label"]: c for c in ws07["classes"]}
    assert by["processes"]["state"] == "partial" and by["processes"]["note"] == "walked"
    assert by["network endpoints"]["state"] == "partial" and by["network endpoints"]["note"] == "swept"
    assert by["file objects"]["state"] == "open" and by["file objects"]["note"] == "refused"
    # No ledger word and no ledger prose reaches the page: the states are
    # the four, the notes a closed set, and a unit's free text only where
    # it is a stated reason.
    units = [c for i in d["items"] for c in i["classes"]] + [c for o in d["extracted"] for c in o["classes"]]
    assert {c["state"] for c in units} <= {"read", "partial", "left", "open"}
    assert {c["note"] for c in units} <= {"", "undecided", "refused", "walked", "swept", "file", "failed"}
    assert not any("swept" in c.get("reason", "") or "did not hold" in c.get("reason", "") for c in units)
    assert not any("detail" in c for i in d["items"] for c in i["classes"])


def test_an_item_without_classes_counts_itself_once_and_hosts_order_the_items(case):
    d = read_models.coverage(case)
    notes = next(i for i in d["items"] if i["id"] == "notes")
    assert notes["classes"] == [] and notes["state"] == "open" and notes["note"] == "undecided"
    assert notes["counts"] == {"read": 0, "partial": 0, "parsed": 0, "left": 0, "open": 1}
    assert [i["host"] for i in d["items"]] == ["", "CORP-DC01", "CORP-WS07"]


def test_extracted_outputs_are_reshaped_with_the_next_read_and_a_block(case):
    d = read_models.coverage(case)
    dc01, ws07 = d["extracted"]
    assert dc01["path"] == "analysis/exports/dc01" and dc01["made"] == "tsk_icat"
    by = {c["label"]: c for c in dc01["classes"]}
    assert [c["label"] for c in dc01["classes"]] == ["lnk", "csv", "dat", "evtx"]   # largest first
    assert by["evtx"]["state"] == "read" and by["evtx"]["read"] == 2 and by["evtx"]["total"] == 2
    assert by["csv"]["state"] == "partial"
    assert by["lnk"]["state"] == "open" and by["lnk"]["note"] == "file"
    assert by["lnk"]["detail"] == "analysis/exports/dc01/desk.lnk"
    assert by["dat"]["state"] == "open" and by["dat"]["note"] == "failed"
    assert dc01["counts"] == {"read": 1, "partial": 1, "parsed": 0, "left": 0, "open": 2}
    # A blocked output's unread classes are left with the recorded block.
    bin_ = ws07["classes"][0]
    assert bin_["state"] == "left" and bin_["reason_kind"] == "blocked" and bin_["reason"] == "the reads failed"


def test_a_class_a_code_fact_leaves_is_left_when_the_outputs_say_so(tmp_path, monkeypatch):
    outs = _outputs()
    outs[0]["left"] = {"dat": {"kind": "unreadable", "basis": "every installed reader failed on two files"}}
    outs[0]["open"] = ["lnk"]
    monkeypatch.setattr("core.coverage_ledger.extracted_outputs", lambda _cd: outs)
    case = _write(tmp_path, _ledger())
    by = {c["label"]: c for c in read_models.coverage(case)["extracted"][0]["classes"]}
    assert by["dat"]["state"] == "left" and by["dat"]["reason_kind"] == "unreadable"
    assert by["dat"]["reason"] == "every installed reader failed on two files"
    assert by["lnk"]["state"] == "open"


def test_the_summary_counts_item_classes_items_without_classes_and_extracted_classes(case):
    s = read_models.coverage(case)["summary"]
    # dc01: 1 read, 1 partial, 1 left, 2 open; ws07: 2 partial, 1 open; notes: 1 open;
    # extracted: 1 read, 1 partial, 2 open, 1 left.
    assert s == {"read": 2, "partial": 4, "parsed": 0, "left": 2, "open": 6, "total": 14}


def test_a_bare_case_with_no_trace_and_no_questions_works(tmp_path):
    case = _write(tmp_path, _ledger())   # the real extracted_outputs: no derived units, no trace
    d = read_models.coverage(case)
    assert d["ledger"] and d["extracted"] == [] and len(d["items"]) == 3
    assert d["summary"]["total"] == 9


def test_no_ledger_is_said_plainly(tmp_path):
    read_models._coverage_cache.clear()
    d = read_models.coverage(str(tmp_path))
    assert d == {"ledger": False, "disposition": False, "items": [], "extracted": [],
                 "summary": {"read": 0, "partial": 0, "parsed": 0, "left": 0, "open": 0, "total": 0}}


def test_a_ledger_without_the_class_level_shows_items_as_the_run_left_them(tmp_path):
    case = _write(tmp_path, {"schema_version": 2, "case_id": "CASE-A", "units": {}, "items": {
        "a": {"id": "a", "path": "evidence/a.dd", "kind": "image", "status": "examined", "blocked_reason": ""},
        "b": {"id": "b", "path": "evidence/b.E01", "kind": "image", "status": "blocked",
              "blocked_reason": "the image header is damaged"},
    }})
    d = read_models.coverage(case)
    assert d["ledger"] and not d["disposition"]
    by = {i["id"]: i for i in d["items"]}
    assert by["a"]["state"] == "open" and by["a"]["note"] == ""
    assert by["b"]["state"] == "left" and by["b"]["reason"] == "the image header is damaged"
    assert d["summary"] == {"read": 0, "partial": 0, "parsed": 0, "left": 1, "open": 1, "total": 2}


def test_the_model_is_cached_on_the_ledger_and_never_writes(case, tmp_path):
    path = tmp_path / ".atlas" / "coverage_ledger.json"
    before = path.read_bytes()
    first = read_models.coverage(case)
    assert read_models.coverage(case) is first
    assert path.read_bytes() == before
    assert sorted(p.name for p in (tmp_path / ".atlas").iterdir()) == ["coverage_ledger.json"]


# ── The cache against a moving trace ─────────────────────────────────────────

@pytest.fixture
def counted(tmp_path, monkeypatch):
    """A case with a trace document, extracted_outputs counted per call, and
    a clock the test moves."""
    calls: list[int] = []
    monkeypatch.setattr("core.coverage_ledger.extracted_outputs", lambda _cd: calls.append(1) or _outputs())
    clock = [1000.0]
    monkeypatch.setattr(read_models, "_monotonic", lambda: clock[0])
    case = _write(tmp_path, _ledger())
    _touch_trace(tmp_path, 1_700_000_000)
    return case, calls, clock


def test_the_extracted_outputs_follow_a_moving_trace_once_per_interval_and_hold_when_nothing_moves(counted, tmp_path):
    case, calls, clock = counted
    first = read_models.coverage(case)
    assert len(calls) == 1
    assert read_models.coverage(case) is first and len(calls) == 1          # nothing moved: held
    _touch_trace(tmp_path, 1_700_000_001)                                    # only the trace moved (a flush)
    clock[0] += 5
    assert read_models.coverage(case) is first and len(calls) == 1          # within the interval: held
    clock[0] += read_models.COVERAGE_EXTRACT_INTERVAL
    again = read_models.coverage(case)
    assert again is not first and len(calls) == 2                            # after it: read again
    assert read_models.coverage(case) is again and len(calls) == 2          # and held again


def test_a_ledger_write_refreshes_the_items_at_once_and_reuses_the_extracted_outputs(counted, tmp_path):
    case, calls, clock = counted
    first = read_models.coverage(case)
    ledger = _ledger()
    ledger["classes"]["dc01:scheduled tasks"]["state"] = "read"
    path = tmp_path / ".atlas" / "coverage_ledger.json"
    path.write_text(json.dumps(ledger))
    os.utime(path, (1_700_000_010, 1_700_000_010))
    clock[0] += 1                                                            # within the interval
    again = read_models.coverage(case)
    assert again is not first and len(calls) == 1
    dc01 = next(i for i in again["items"] if i["id"] == "dc01")
    assert next(c for c in dc01["classes"] if c["label"] == "scheduled tasks")["state"] == "read"
    assert again["extracted"] == first["extracted"]


def test_one_request_reads_the_trace_for_every_request_waiting_on_the_case(tmp_path, monkeypatch):
    started, release, calls = threading.Event(), threading.Event(), []

    def slow(_cd):
        calls.append(1)
        started.set()
        release.wait(5)
        return _outputs()
    monkeypatch.setattr("core.coverage_ledger.extracted_outputs", slow)
    case = _write(tmp_path, _ledger())
    results: list[dict] = []
    threads = [threading.Thread(target=lambda: results.append(read_models.coverage(case))) for _ in range(3)]
    for th in threads:
        th.start()
    assert started.wait(5)
    release.set()
    for th in threads:
        th.join(5)
    assert len(results) == 3 and len(calls) == 1
    assert all(r["summary"] == results[0]["summary"] for r in results)
