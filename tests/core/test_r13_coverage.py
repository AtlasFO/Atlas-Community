"""The evidence decision per content class: the reason field has
no empty or placeholder value, a leave rests on an observation from a
read on the same host, code fills the mechanical kinds, the undecided
classes stand in the one open-work list, the finish and the Report push
wait on them by behaviour, a run that will not decide ends stopped, and
the report, the review and the Coverage tab say so. Invented fixtures
only (CORP-WS01..03, jane.doe, john.roe, svc_kit.exe, dates in 2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

import core.execution_log as elog
from core import evidence_leave as L
from core import evidence_depth as D
from core import work_order as W
from core.claim_graph import add_claim
from core.coverage_ledger import load_ledger, save_ledger
from core.evidence_disposition import disposition_complete, report_lines, undecided_classes
from tests.core.test_contents_index import _build, _image, _links, _plan, case  # noqa: F401
from tests.core.test_evidence_leave import T_NEW, T_OLD, _attacker, _b, _case, _item  # noqa: F401

# A leave's reason names the source it rests on (the read's file name)
# where it carries no checkable value of its own.
OBS = "no interactive logons on this host in the window per its Security.evtx"


def _class(led, image: str, word: str):
    item = next(i for i in led["items"].values() if i["path"].endswith(image))
    return next(c for c in led["classes"].values() if c["item"] == item["id"] and word in c["label"].lower())


def _read(case, host_image: str, text: str = "rows", ok: bool = True, tool: str = "misc_evtx_filter",
          cmd_extra: str = "") -> int:
    cid = elog.log.record_tool_call(f"<py>:{tool} evidence/disk/{host_image}::Windows/System32/winevt/Logs/Security.evtx"
                                    + (" " + cmd_extra if cmd_extra else ""),
                                    ok, False, 0, 0 if ok else 1, stdout_excerpt=text)
    elog.log.annotate_tool_call(cid, mcp_tool=tool)
    return cid


# ── the writer ───────────────────────────────────────────────────────────

def test_the_reason_field_takes_no_empty_or_placeholder_value(case, monkeypatch):
    led = _case(case, monkeypatch)
    ws03 = _item(led, "corp-ws03.raw")
    for reason in ("", "   ", "n/a", "not needed", "too short"):
        r = L.check_leave(case, led, ws03, "outside_window", reason)
        assert not r["ok"] and "reason" in r["error"], (reason, r)
    assert L.check_leave(case, led, ws03, "outside_window", "its data ends before the stated start of the case")["ok"]


def test_a_code_kind_is_refused_from_the_model(case, monkeypatch):
    led = _case(case, monkeypatch)
    for kind in L.CODE_KINDS:
        r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), kind, "every file of it appears empty to me")
        assert not r["ok"] and "code states" in r["error"]


def test_the_same_observation_text_on_two_hosts_is_accepted_when_each_has_its_read(case, monkeypatch):
    led = _case(case, monkeypatch)
    c1 = _read(case, "corp-ws01.raw", text="no interactive logons in the window")
    c2 = _read(case, "corp-ws02.raw", text="no interactive logons in the window")
    a = L.check_leave(case, led, _class(led, "corp-ws01.raw", "text")["id"], "unlikely_to_help", OBS, [c1])
    assert a["ok"], a
    L.set_disposition(case, _class(led, "corp-ws01.raw", "text")["id"], "left", "unlikely_to_help", OBS, [c1])
    led = load_ledger(case)
    b = L.check_leave(case, led, _class(led, "corp-ws02.raw", "text")["id"], "unlikely_to_help", OBS, [c2])
    assert b["ok"], b                                           # its own read on its own host
    c = L.check_leave(case, led, _class(led, "corp-ws03.raw", "text")["id"], "unlikely_to_help", OBS, [c1])
    assert not c["ok"] and "another host" in c["error"]


# ── unlikely_to_help ─────────────────────────────────────────────────────

def test_a_question_being_answered_is_never_the_reason(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw")
    for reason in ("not needed for task-0001, the security log answered it",
                   "the question is answered by the security log read on this host",
                   "s2 was answered by the security log, so this is already covered"):
        r = L.check_leave(case, led, cls["id"], "unlikely_to_help", reason, [cid])
        assert not r["ok"] and "question or a report" in r["error"], r
    # Observations that carry those words inside longer phrases pass the
    # ground check (they may fail the grounding, which names the values).
    for reason in ("Spooler report on this host lists no jobs in the window",
                   "The printer in question has no jobs on this server per the Print log",
                   "Insufficient quota: the Print log shows no job of type 10 after the start",
                   "No event reported by the AV log after 2031-03-10 on this host"):
        assert not L.FORBIDDEN_GROUND_RE.search(reason), reason


def test_an_observation_from_a_read_on_the_same_host_leaves_the_class(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624 logon events: 0 interactive logons for jane.doe in the window")
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, [cid])
    assert r["ok"], r
    listing = elog.log.record_tool_call("<py>:tsk_tsk_fls evidence/disk/corp-ws01.raw", True, False, 0, 0,
                                        stdout_excerpt="d/d 5: Users")
    elog.log.annotate_tool_call(listing, mcp_tool="tsk_tsk_fls")
    no = L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, [listing])
    assert not no["ok"] and "no successful content read" in no["error"] and f"call {cid}" in no["error"]
    other = _read(case, "corp-ws02.raw")
    no = L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, [other])
    assert not no["ok"] and "another host" in no["error"]


def test_a_value_the_reason_names_must_show_in_the_reads_rows(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624 logon events for jane.doe only, none for john.roe")
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help",
                      "the security log shows no logons for svc_backup in the window", [cid])
    assert not r["ok"] and "svc_backup" in r["error"] and "do not show" in r["error"]
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help",
                         "the security log shows logons for jane.doe only, none for john.roe", [cid])["ok"]


# ── the bulk leave by label handle ──────────────────────────────────────

def test_a_label_handle_leaves_the_class_on_every_host_whose_read_it_cites(case, monkeypatch):
    led = _case(case, monkeypatch)
    label = _class(led, "corp-ws01.raw", "text")["label"]
    assert L.label_handle("recent files and jump lists \u2014 what was opened") == "recent files and jump lists"
    assert L.label_handle("Recent files - and  more") == "recent files"      # an ASCII dash opens the gloss too
    assert L.label_handle("event log channel") == "event log channel"
    c1 = _read(case, "corp-ws01.raw", text="no interactive logons in the window")
    c2 = _read(case, "corp-ws02.raw", text="no interactive logons in the window")
    r = L.set_disposition(case, L.label_handle(label), "left", "unlikely_to_help", OBS, [c1, c2])
    assert r["success"] is True and sorted(r["hosts"]) == ["CORP-WS01", "CORP-WS02", "CORP-WS03"] or (
        r["success"] is False and set(r["refused"]) == {"CORP-WS03"} and sorted(r["hosts"]) == ["CORP-WS01", "CORP-WS02"]), r
    assert "CORP-WS03" in r.get("refused", {}) and "another host" in r["refused"]["CORP-WS03"]
    led = load_ledger(case)
    states = {c["host"]: c["state"] for c in led["classes"].values() if c["label"] == label}
    assert states["CORP-WS01"] == "left" and states["CORP-WS02"] == "left" and states["CORP-WS03"] != "left"


def test_a_handle_that_names_nothing_is_refused_with_the_candidates(case, monkeypatch):
    led = _case(case, monkeypatch)
    r = L.set_disposition(case, "textual", "left", "unlikely_to_help", OBS, [])
    assert r["success"] is False and "labels that match" in r["error"] and "textual log" in r["error"]
    one = L.set_disposition(case, "CORP-WS02: textual log", "relevant", reason="to be read on this host only")
    assert one["success"] and one["hosts"] == ["CORP-WS02"]


# ── the sweep, scoped to the class ──────────────────────────────────────

def test_the_sweep_refuses_the_class_whose_exports_hold_the_value_not_its_neighbour(case, monkeypatch):
    led = _case(case, monkeypatch)
    (case / "exports").mkdir(exist_ok=True)
    (case / "exports" / "corp-ws01-security.csv").write_text(
        "time,image\n2031-03-10 10:00:00,C:\\Users\\Public\\svc_kit.exe\n", encoding="utf-8")
    _attacker(case, "svc_kit.exe")
    monkeypatch.setattr(L, "_class_exports", lambda c, unit, item: ["exports/corp-ws01-security.csv"]
                        if "event" in unit["label"].lower() or "auth" in unit["label"].lower() else [])
    sec = _class(led, "corp-ws01.raw", "event") if any("event" in c["label"].lower() for c in led["classes"].values()) \
        else _class(led, "corp-ws01.raw", "auth")
    txt = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="rows of the log")
    why = "Security.evtx holds rows of the log only, nothing else"
    hit = L.check_leave(case, led, sec["id"], "unlikely_to_help", why, [cid])
    assert not hit["ok"] and "svc_kit.exe in exports/corp-ws01-security.csv" in hit["error"]
    assert L.check_leave(case, led, txt["id"], "unlikely_to_help", why, [cid])["ok"]


# ── readers by member names; unknown is never "no reader" ──────────────

def test_an_extensionless_class_is_not_leavable_as_unreadable_without_failed_reads(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _b("Windows/System32/config/SYSTEM", "200-128-1", T_NEW, 12_582_912),
        _b("$MFT", "0-128-1", T_NEW, 4_194_304),
        _b("$Extend/$UsnJrnl:$J", "5-128-1", T_NEW, 1_048_576)]})
    from core.coverage_ledger import build_coverage_ledger
    led = build_coverage_ledger(case)
    for word in ("registry", "timeline", "journal"):
        cls = next((c for c in led["classes"].values() if word in c["label"].lower()), None)
        if cls is None:
            continue
        r = L.check_leave(case, led, cls["id"], "unreadable", "no installed reader declares its format at all")
        assert not r["ok"] and ("two failed calls" in r["error"] or "not known" in r["error"]), (word, r)


# ── code leaves ─────────────────────────────────────────────────────────

def test_the_empty_code_leave_has_its_kind_and_is_never_left_not_holding(case, monkeypatch):
    led = _case(case, monkeypatch)
    from core.evidence_disposition import build_disposition
    real = __import__("core.evidence_disposition", fromlist=["_image_classes"])._image_classes
    monkeypatch.setattr("core.evidence_disposition._image_classes",
                        lambda root, item: {**real(root, item), "quiet log": {"files": 3, "empty": 3, "score": 10}})
    build_disposition(case, led, {}, [])
    save_ledger(case, led)
    empty = [c for c in led["classes"].values() if c["state"] == "left" and c["label"] == "quiet log"]
    assert empty and all(c["reason_kind"] == "empty" and c["reason"].startswith("by code") and c["scope_fingerprint"]
                         for c in empty)
    ok, detail = disposition_complete(case)
    assert detail["left_not_holding"] == []
    # The kind is checked against the index: a class whose files are not
    # empty there is refused, and a class the index does not list too.
    full = _class(led, "corp-ws01.raw", "text")
    r = L.check_leave(case, led, full["id"], "empty", "by code: all its files appear empty", by_code=True)
    assert not r["ok"] and "does not appear empty" in r["error"]
    r = L.check_leave(case, led, empty[0]["id"], "empty", "by code: all its files appear empty", by_code=True)
    assert not r["ok"] and "lists no live file" in r["error"]


def test_the_window_code_leave_runs_once_per_window_in_the_reopen_pass(case, monkeypatch):
    led = _case(case, monkeypatch)
    before = {c["id"]: c["state"] for c in led["classes"].values()}
    L.reopen_left(elog.log, case)
    led = load_ledger(case)
    old_host = [c for c in led["classes"].values() if c["host"] == "CORP-WS03"]
    assert old_host and all(c["state"] == "left" and c["reason_kind"] == "outside_window"
                            and c["reason"].startswith("by code") for c in old_host), old_host
    assert all(led["classes"][cid]["state"] == st for cid, st in before.items()
               if led["classes"][cid]["host"] != "CORP-WS03")
    assert led["meta"]["code_leave_window"]
    assert disposition_complete(case)[1]["left_not_holding"] == []


def test_the_code_no_reader_leave_reads_every_member_not_the_sample(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _b("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", T_NEW, 70000),
        _b("Users/jane.doe/mail/box.pst", "203-128-1", T_NEW, 4096)]})
    from core.coverage_ledger import build_coverage_ledger
    led = build_coverage_ledger(case)
    cls = next(c for c in led["classes"].values() if "email" in c["label"].lower())
    cls["names"] = ["box.zzz"]                                # a sample that says "no reader"
    sample, _k = L.unit_readers(case, "class", cls, led["items"][cls["item"]])
    whole, _k = L.unit_readers(case, "class", cls, led["items"][cls["item"]], whole=True)
    assert set(whole) >= set(sample)
    with patch.object(L, "readers_for", lambda fmt: ["mail.reader"] if fmt == "pst" else []):
        assert L.check_leave(case, led, cls["id"], "no_reader", "by code: no reader declares the format",
                             by_code=True)["ok"] is False


def test_no_reader_is_a_code_kind_only_for_a_known_format(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    with patch.object(L, "unit_readers", lambda *a, **k: ([], True)):
        assert L.check_leave(case, led, cls["id"], "no_reader", "by code: no reader declares the format", by_code=True)["ok"]
    with patch.object(L, "unit_readers", lambda *a, **k: ([], False)):
        assert not L.check_leave(case, led, cls["id"], "no_reader", "by code: no reader declares the format",
                                 by_code=True)["ok"]


# ── the undecided list, the tiers and the depth ────────────────────────

def test_undecided_classes_are_the_pending_and_relevant_ones(case, monkeypatch):
    led = _case(case, monkeypatch)
    for c in list(led["classes"].values())[:2]:
        c["state"] = "relevant"
    save_ledger(case, led)
    und = undecided_classes(load_ledger(case))
    assert {c["state"] for c in und} <= {"pending", "relevant"} and len(und) == len(led["classes"])
    detail = disposition_complete(case)[1]
    assert detail["undecided_classes"] == len(und) and set(detail["undecided_by_host"]) >= {"CORP-WS01"}


def test_tiers_come_from_cost_bands_and_depth_is_counted_per_host(case, monkeypatch):
    assert D.class_tier(1, ["ez.evtxecmd"], True, {"ez_evtxecmd": 5.0}) == "cheap"
    assert D.class_tier(100, ["ez.evtxecmd"], True, {"ez_evtxecmd": 5.0}) == "medium"
    assert D.class_tier(1000, ["ez.evtxecmd"], True, {"ez_evtxecmd": 5.0}) == "hard"
    # A reader that takes the folder reads 150 files in one call: cheap.
    assert D.class_tier(150, ["ez.evtxecmd"], True, {"ez_evtxecmd": 5.0}, many=True) == "cheap"
    # A reader that failed on it in this run, or none installed: hard.
    assert D.class_tier(6, ["ez.srumecmd"], True, {}, failed=True) == "hard"
    assert D.class_tier(1, [], False) == "hard" and D.class_tier(1, ["x.y"], False) == "hard"
    led = _case(case, monkeypatch)
    depth = D.depth_by_host(case, led)
    assert set(depth) >= {"CORP-WS01", "CORP-WS03"}
    line = D.depth_line(depth, ["CORP-WS01"])
    assert line.startswith("CORP-WS01: ") and "/" in line
    assert not D.depth_reached(depth, ["CORP-WS01"])
    for c in led["classes"].values():
        c["state"] = "read"
    assert D.depth_reached(D.depth_by_host(case, led), ["CORP-WS01", "CORP-WS03"])


def test_a_stored_band_is_never_lowered_and_a_failed_reader_moves_it_to_hard(case, monkeypatch):
    led = _case(case, monkeypatch)
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    cls = _class(led, "corp-ws01.raw", "text")
    cls["tier"] = "medium"
    save_ledger(case, led)
    tiers = D.class_tiers(case, load_ledger(case))
    assert tiers[cls["id"]] == "medium"                        # the stored band stands
    # Every installed reader of the class failed on this host's image: hard.
    for r in L.unit_readers(case, "class", cls, led["items"][cls["item"]])[0]:
        _read(case, "corp-ws01.raw", ok=False, tool=r.replace(".", "_"))
    assert D.class_tiers(case, load_ledger(case))[cls["id"]] == "hard"


def test_a_host_wide_question_is_known_by_structure_not_wording(case, monkeypatch):
    _case(case, monkeypatch)
    umbrella = {"id": "p1", "kind": "umbrella", "type": "narrative", "text": "Which hosts were touched?"}
    standard = [{"id": f"s{i}", "kind": "standard", "type": "yes_no", "text": "affected", "host": h}
                for i, h in enumerate(("CORP-WS01", "CORP-WS02"), start=1)]
    assert D.host_wide(case, {"parts": [umbrella, *standard]})
    assert D.host_wide(case, {"parts": [umbrella]})                     # scope: every evidence host
    valued = {"id": "p2", "kind": "value", "type": "ip", "text": "the beacon address"}
    assert not D.host_wide(case, {"parts": [umbrella, valued]})
    hosted = {"id": "p3", "kind": "value", "type": "narrative", "text": "on the server", "host": "CORP-WS02"}
    assert not D.host_wide(case, {"parts": [hosted]})
    reached, line = D.task_depth(case, {"parts": [umbrella, *standard]})
    assert not reached and "CORP-WS01" in line


def test_open_classes_are_grouped_by_label_in_yield_order_with_a_tier(case, monkeypatch):
    led = _case(case, monkeypatch)
    for c in led["classes"].values():
        c["state"] = "relevant"
    save_ledger(case, led)
    groups = W.open_classes(str(case))
    assert groups and all(g["handle"] and g["hosts"] and g["tier"] in D.TIERS for g in groups)
    labels = [g["label"] for g in groups]
    assert len(labels) == len(set(labels))
    assert all(len(h) == 4 for g in groups for h in g["hosts"])
    work = {"classes": groups}
    keys = W.open_class_keys(work)
    assert keys and all(k[0] == "class" for k in keys) and not (keys & W.open_work_keys({**work, "parts": [], "derived": [], "due": []}))
    lines = W.class_lines(work)
    assert lines[0] == W.CLASS_HEAD and "unlikely_to_help" in lines[0] and "set_evidence_disposition" in lines[0]
    assert any(groups[0]["handle"] in ln and groups[0]["tier"] in ln for ln in lines[1:])
    count = W.class_count_line(work, str(case))
    assert "neither a read nor a reason" in count and "Depth per host" in count


def test_a_triage_bundle_item_is_not_counted_while_its_classes_stand_in_the_ledger():
    bundle = {"status": "due", "origin": "triage", "task_ids": ["task-0001"],
              "source_ref": {"kind": "evidence", "item": "i1", "classes": ["i1#a", "i1#b"]}}
    assert not W.counted(bundle, {"task-0001": "open"})
    plain = {"status": "due", "origin": "plan", "task_ids": ["task-0001"]}
    assert W.counted(plain, {"task-0001": "open"})


# ── the finish guard and the stop label ─────────────────────────────────

def _work(groups):
    return {"parts": [], "derived": [], "due": [], "refused": [], "parsed": [], "classes": groups}


def test_the_finish_waits_on_the_undecided_set_and_the_same_set_lets_out(tmp_path, monkeypatch):
    from agent.loop import Agent
    a = Agent.__new__(Agent)
    a.case_dir = str(tmp_path)
    events = []
    a._log = events.append
    a._load_namespaces_for = lambda refs, turn=None: []
    g = [{"label": "event log channel", "handle": "event log channel", "score": 80, "readers": ["ez.evtxecmd"],
          "installed": True, "tier": "cheap", "hosts": [("CORP-WS01", 3, "i1#a", "cheap"), ("CORP-WS02", 2, "i2#a", "cheap")]}]
    msg = a._class_deferral(_work(g))
    assert "atlas_finish deferred" in msg and "event log channel" in msg and "cannot end as finished" in msg
    assert a._class_deferral(_work(g)) == ""                    # the same set: let out, the ending says stopped
    assert any(e.get("event") == "finish_undecided_classes" for e in events)
    g[0]["hosts"] = g[0]["hosts"][:1]                           # a leave shrank the set
    assert "atlas_finish deferred" in a._class_deferral(_work(g))
    assert a._class_deferral(_work([])) == ""


def test_a_run_with_undecided_classes_ends_stopped_never_finished(case, monkeypatch):
    from core.investigation_exit import FINISH_STATUSES, STOPPED_UNDECIDED, classify_finish_status, \
        ended_through_a_completion_path
    _case(case, monkeypatch)
    for reason in ("finished", "closed_out", "quiet", "finish_deferred"):
        assert classify_finish_status(reason, case_dir=case, report_written=True, synthesize_ok=True,
                                      pre_report_ready=True) == STOPPED_UNDECIDED
    assert STOPPED_UNDECIDED not in FINISH_STATUSES and not ended_through_a_completion_path(STOPPED_UNDECIDED)
    assert classify_finish_status("wall_clock", case_dir=case, report_written=True, synthesize_ok=True,
                                  pre_report_ready=True) == "wall_clock"


def test_the_report_push_waits_once_per_distinct_open_set(monkeypatch):
    import tools.dair as dair
    monkeypatch.setattr(dair, "_report_open_work_named", frozenset())
    monkeypatch.setattr(dair, "_case_root", lambda: "/case")
    g = [{"label": "event log channel", "handle": "event log channel", "score": 80, "readers": ["ez.evtxecmd"],
          "installed": True, "tier": "cheap", "hosts": [("CORP-WS01", 3, "i1#a", "cheap")]}]
    work = _work(g)
    monkeypatch.setattr(W, "open_work", lambda log, case: work)
    monkeypatch.setattr("core.evidence_depth.depth_by_host", lambda case: {"CORP-WS01": {"cheap": (0, 1), "medium": (0, 0), "hard": (0, 0)}})
    note, tools = dair._report_entry_open_work_gate()
    assert note.startswith("report_entry_open_work") and "event log channel" in note and "Depth per host" in note
    assert "cannot end as finished" in note and "will not pass" not in note   # the same set ends the run stopped
    assert "coverage.set_evidence_disposition" in tools
    assert dair._report_entry_open_work_gate() == ("", [])      # the same set passes
    # A parse that adds an extracted output between two pushes changes no
    # class key: the push still passes.
    work["derived"] = [{"path": "analysis/out", "open": ["csv"], "classes": {"csv": (0, 2)}, "sample": {}, "readers": {}}]
    assert dair._report_entry_open_work_gate() == ("", [])
    g[0]["hosts"] = []
    monkeypatch.setattr(W, "open_work", lambda log, case: _work([]))
    assert dair._report_entry_open_work_gate() == ("", [])


# ── the report and the staleness ────────────────────────────────────────

def test_the_report_names_the_undecided_classes_and_the_depth_never_a_no_reason_line(case, monkeypatch):
    led = _case(case, monkeypatch)
    for c in led["classes"].values():
        c["state"] = "relevant"
    save_ledger(case, led)
    lines = report_lines(case)
    joined = "\n".join(lines)
    assert "### Evidence not decided" in joined and "a person must decide" in joined
    assert "### Depth of analysis per host" in joined and "cheap" in joined
    assert "no reason was recorded" not in joined and "marked to be read" not in joined
    assert "neither a read credited" not in joined                # the lead is the undecided sentence alone
    de = "\n".join(report_lines(case, "de"))
    assert "Nicht entschiedene Beweismittel" in de and "Analysetiefe je Host" in de
    assert "Keine hat eine" not in de
    from core.artifact_value import gap_lines
    assert not any("no read was attempted and no reason was recorded" in ln for ln in gap_lines(case))


def test_a_leave_after_the_report_makes_its_evidence_section_stale(case, monkeypatch):
    from core.report_exit import class_state_digest
    led = _case(case, monkeypatch)
    before = class_state_digest(case)
    assert before
    assert L.set_disposition(case, _item(led, "corp-ws03.raw"), "left", "outside_window",
                             "its data ends before the stated start of the case")["success"]
    assert class_state_digest(case) != before


# ── the question and the tab ────────────────────────────────────────────

def test_a_host_wide_question_is_held_partial_live_and_answered_once_the_classes_are_decided(tmp_path, monkeypatch):
    from core import request_parts as rp
    from core.investigation_tasks import load_tasks, reconcile_case_md, save_tasks, update_task
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("## Investigation Requests\n\n- What happened on the hosts?\n", encoding="utf-8")
    reconcile_case_md(case, persist=True)
    store = load_tasks(case)
    t = store["tasks"][0]
    std = rp.standard_parts(t["text"], ["CORP-WS01", "CORP-WS02"])
    t["parts"] = [p for p in t.get("parts") or [] if p.get("kind") == "umbrella"] + std
    save_tasks(case, store)
    depth = {"line": "CORP-WS01: cheap 2/6, medium 0/3; CORP-WS02: cheap 1/5", "reached": False}
    monkeypatch.setattr("core.evidence_depth.task_depth", lambda c, task: (depth["reached"], depth["line"]))
    cid = add_claim(case, "No attacker activity was found on CORP-WS01: its event logs show no intrusion.",
                    confidence="LIKELY", host="CORP-WS01")["node_id"]
    cid2 = add_claim(case, "No attacker activity was found on CORP-WS02: its event logs show no intrusion.",
                     confidence="LIKELY", host="CORP-WS02")["node_id"]
    gates = {p["id"]: p for p in std if p.get("gate")}
    r = update_task(case, t["id"], parts={pid: {"claim_ids": [cid if p["host"] == "CORP-WS01" else cid2]}
                                         for pid, p in gates.items()})
    assert r.get("success"), r
    assert any("host-wide" in n for n in r.get("notes") or [])
    after = load_tasks(case)["tasks"][0]
    assert after["status"] == "partial" and "depth_note" not in after      # held live, nothing stored
    r = update_task(case, t["id"], status="answered", related_claim_ids=[cid, cid2])
    assert not r.get("success") and r.get("gate") == "task_depth_hold" and "cheap 2/6" in r["error"]
    assert "Decide the cheap and medium" in r["error"]
    depth["reached"] = True                                                # the classes were decided, no task call
    assert load_tasks(case)["tasks"][0]["status"] == "answered"


def test_the_tab_carries_the_tier_and_the_strip_shows_the_undecided_stop(case, monkeypatch):
    from dashboard import read_models
    _case(case, monkeypatch)
    read_models._coverage_cache.clear()
    read_models._extracted_cache.clear()
    data = read_models.coverage(str(case))
    classes = [c for it in data["items"] for c in it["classes"]]
    assert classes and all(c["tier"] in D.TIERS for c in classes)
    assert all(c["note"] in ("undecided", "refused", "") for c in classes if c["state"] == "open")
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "finished", "finish_status": "stopped_undecided", "pid": None,
        "coverage_disclosure": {"evidence_disposition": {"undecided_classes": 7, "undecided_by_host": {"CORP-WS01": 4, "CORP-WS02": 3}}}}),
        encoding="utf-8")
    act = read_models.activity(str(case)) if hasattr(read_models, "activity") else None
    if act is not None:
        stop = act.get("last_stop") or {}
        assert stop.get("reason") == "undecided_evidence" and "7 content class" in stop.get("error", "")



def test_a_model_cannot_leave_a_known_format_as_unreadable_without_failed_reads(case, monkeypatch):
    """The no-proof clause of unreadable belongs to code (no_reader): a
    model leave of a known format no reader declares is refused and told
    so; the code leave still takes it."""
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    with patch.object(L, "unit_readers", lambda *a, **k: ([], True)), patch.object(L, "readers_for", lambda fmt: []):
        r = L.check_leave(case, led, cls["id"], "unreadable", "no installed reader declares its format at all")
        assert not r["ok"] and "no_reader" in r["error"]
        assert L.check_leave(case, led, cls["id"], "no_reader", "by code: no reader declares the format", by_code=True)["ok"]


# ── readers by the declared names; unknown is never "no reader" ─────────

def _members(names: list[str], host: str = "CORP-WS01") -> tuple[dict, dict]:
    return ({"label": "x", "names": names},
            {"id": "i", "path": f"evidence/disk/{host.lower()}.raw", "kind": "image", "host": host})


def test_every_declared_input_name_resolves_its_reader_in_the_class_route():
    """Built from the declarations, not a hand list: a member named by each
    pattern a reader declares (meta input_names) resolves that reader,
    whatever class the member falls in."""
    from tools.tool_capabilities import input_name_declarations
    decl = input_name_declarations()
    assert len(decl) >= 20, decl
    for reader, patterns in decl:
        for pat in patterns:
            name = pat.replace("*", "x").replace("?", "a")
            readers, known = L.unit_readers("/nonexistent", "class", *_members([name]))
            assert reader in readers and known, (reader, pat, readers)


def test_the_class_route_resolves_by_name_before_extension_and_says_what_is_undeclared():
    def resolve(names):
        return L.unit_readers("/nonexistent", "class", *_members(names))
    assert resolve(["cmd.exe-0bd30981.pf"]) == (["ez.pecmd"], True)
    r, known = resolve(["ntuser.dat", "usrclass.dat"])
    assert known and {"ez.recmd_hive", "ez.sbecmd"} <= set(r)
    r, known = resolve(["system", "software", "sam", "security"])
    assert known and {"ez.recmd_hive", "ez.appcompatcacheparser"} <= set(r)
    r, known = resolve(["srudb.dat"])
    assert known and "ez.srumecmd" in r
    # A name a reader declares is resolved by that name alone: a Recycle
    # Bin record keeps its file's extension and is no Office document.
    assert resolve(["$iab12cd.docx"]) == (["ez.rbcmd"], True)
    # A declared head (db) whose readers declare other names: known, no reader.
    assert resolve(["thumbcache_256.db"]) == ([], True)
    # An extension no channel names, or an extensionless name no reader
    # declares: unknown, never "no reader".
    assert resolve(["report.xyz"]) == ([], False)
    assert resolve(["info2"]) == ([], False)
    assert resolve(["stickynotes.snt"]) == ([], False)
    r, known = resolve(["ntuser.dat", "box.mbox"])
    assert "ez.recmd_hive" in r and not known
    # Labels are keyed by their whole head: "evtx csv" and "mft csv" are
    # their own, not the readers of .evtx and $MFT.
    r, known = resolve(["security.evtx"])
    assert known and "ez.evtxecmd" in r and "misc.chainsaw_hunt" in r and "af.event_log_clear" not in r
    r, known = resolve(["$mft"])
    assert known and "ez.mftecmd" in r and "af.timestomp_drift" not in r


def test_prefetch_user_hives_and_amcache_are_neither_left_by_code_nor_tiered_hard(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _b("Windows/Prefetch/CMD.EXE-0BD30981.pf", "300-128-1", T_NEW, 20000),
        _b("Users/jane.doe/NTUSER.DAT", "301-128-1", T_NEW, 2_000_000),
        _b("Users/jane.doe/AppData/Local/Microsoft/Windows/UsrClass.dat", "302-128-1", T_NEW, 500_000),
        _b("Windows/AppCompat/Programs/Amcache.hve", "303-128-1", T_NEW, 3_000_000),
        _b("Windows/System32/config/SYSTEM", "304-128-1", T_NEW, 12_000_000),
        _b("Users/jane.doe/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db", "305-128-1", T_NEW, 90_000),
        _b("Users/jane.doe/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt", "306-128-1", T_NEW, 9_000)]})
    from core.coverage_ledger import build_coverage_ledger
    from core.evidence_disposition import _code_no_reader
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    led = build_coverage_ledger(case)
    by = {c["label"]: c for c in led["classes"].values()}
    pf = next(c for l, c in by.items() if "execution counts" in l)
    users = next(c for l, c in by.items() if "per-user" in l)
    amcache = next(c for l, c in by.items() if "program execution" in l)     # its own class, before the hives rule
    hives = next(c for l, c in by.items() if "registry hives" in l)
    thumbs = next(c for l, c in by.items() if "thumbnail" in l)
    notes = next(c for l, c in by.items() if "sticky" in l)
    assert hives["files"] == 1 and amcache["files"] == 1
    left = _code_no_reader(case, led)
    assert left == [thumbs["id"]], left                 # a known format no reader takes: code's fact
    assert all(c["state"] != "left" for c in (pf, users, amcache, hives, notes))
    tiers = D.class_tiers(case, led)
    assert all(tiers[c["id"]] == "cheap" for c in (pf, users, amcache, hives)), tiers
    assert tiers[notes["id"]] == "medium"               # undeclared: never hard for want of a reader
    work = W.open_classes(str(case))
    line = "\n".join(W.class_lines({"classes": work}))
    assert "sticky notes" in line and "reader: not declared" in line and "none installed" not in line


def test_only_installed_readers_decide_whether_a_class_is_read_in_one_call(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _b(f"Windows/System32/winevt/Logs/Channel{i:03d}.evtx", f"{400 + i}-128-1", T_NEW, 70000) for i in range(100)]})
    from core.coverage_ledger import build_coverage_ledger
    led = build_coverage_ledger(case)
    cls = next(c for c in led["classes"].values() if c["files"] == 100)
    folder = [r for r in L.unit_readers(case, "class", cls, led["items"][cls["item"]])[0]
              if D.reader_takes_many(r)]
    assert folder                                        # a reader takes the folder in one call
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    D._TIER_CACHE.clear()
    assert D.class_tiers(case, led)[cls["id"]] == "cheap"
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set(folder))
    D._TIER_CACHE.clear()
    assert D.class_tiers(case, led)[cls["id"]] == "medium"   # per file, by the readers that are here


# ── the proof read is the host's own and the reason names its source ────────────

def test_a_read_whose_paths_name_no_host_proves_no_hosts_leave(case, monkeypatch):
    led = _case(case, monkeypatch)
    cid = elog.log.record_tool_call("<py>:tabular_tabular_query evidence/firewall/2031-03-10.log", True, False, 0, 0,
                                    stdout_excerpt="rows: 0 denied connections from 203.0.113.7")
    elog.log.annotate_tool_call(cid, mcp_tool="tabular_tabular_query")
    for img in ("corp-ws01.raw", "corp-ws02.raw", "corp-ws03.raw"):
        r = L.check_leave(case, led, _class(led, img, "text")["id"], "unlikely_to_help",
                          "the firewall log 2031-03-10.log shows no denied connections from 203.0.113.7", [cid])
        assert not r["ok"] and "names no host" in r["error"], (img, r)
    own = _read(case, "corp-ws01.raw")
    r = L.check_leave(case, led, _class(led, "corp-ws01.raw", "text")["id"], "unlikely_to_help", OBS, [cid])
    assert f"call {own} (" in r["error"] and f"call {cid} (" not in r["error"]   # only the host's own reads are offered


def test_a_reason_with_no_checkable_value_must_name_the_reads_source(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624: none in the window")
    probe = "nothing seen on this machine suggests this kind of evidence matters at all here"
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", probe, [cid])
    assert not r["ok"] and "Security.evtx" in r["error"] and "source" in r["error"], r
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help", probe + ", per its Security.evtx", [cid])["ok"]


def test_an_observation_carrying_not_required_is_no_forbidden_ground(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="Print.evtx 1201: write cache not required for svc_backup")
    for reason in ("Print.evtx shows write cache not required for svc_backup only",
                   "Print.evtx: write cache not required, no other 1201 in the window"):
        ok = L.check_leave(case, led, cls["id"], "unlikely_to_help", reason, [cid])
        assert ok["ok"], ok
    for reason in ("these logs are not needed for the questions", "not required for the report on this host"):
        r = L.check_leave(case, led, cls["id"], "unlikely_to_help", reason, [cid])
        assert not r["ok"] and "question or a report" in r["error"], r


# ── tiers: stored bands first, failures per item ─────────────────────────

def test_stored_bands_are_read_without_resolving_readers_and_the_answer_is_cached(case, monkeypatch):
    led = _case(case, monkeypatch)
    for c in led["classes"].values():
        c["tier"] = "medium"
    save_ledger(case, led)
    calls: list = []
    monkeypatch.setattr("core.evidence_leave.unit_readers", lambda *a, **k: calls.append(a) or ([], True))
    D._TIER_CACHE.clear()
    led = load_ledger(case)
    assert set(D.class_tiers(case, led).values()) == {"medium"} and calls == []
    for c in led["classes"].values():
        c.pop("tier")
    save_ledger(case, led)
    led = load_ledger(case)
    D.class_tiers(case, led)
    n = len(calls)
    assert n >= 1
    D.class_tiers(case, led)
    assert len(calls) == n                              # the second answer is the cached one
    _read(case, "corp-ws01.raw")
    D.class_tiers(case, led)
    assert len(calls) > n                               # a trace that grew is read again


def test_a_failed_reader_on_one_host_moves_no_other_hosts_class(case, monkeypatch):
    led = _case(case, monkeypatch)
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    one, two = _class(led, "corp-ws01.raw", "auth"), _class(led, "corp-ws02.raw", "auth")
    one["tier"] = two["tier"] = "cheap"
    save_ledger(case, led)
    _read(case, "corp-ws01.raw", ok=False)               # misc_evtx_filter failed on CORP-WS01
    tiers = D.class_tiers(case, load_ledger(case))
    assert tiers[two["id"]] == "cheap" and tiers[one["id"]] == "cheap"   # one reader of several failed
    readers = L.unit_readers(case, "class", one, led["items"][one["item"]])[0]
    for r in readers:
        _read(case, "corp-ws01.raw", ok=False, tool=r.replace(".", "_"))
    tiers = D.class_tiers(case, load_ledger(case))
    assert tiers[one["id"]] == "hard" and tiers[two["id"]] == "cheap"


# ── the report's file-level gaps under ledger classes ────────────────────

def test_a_loose_files_open_line_is_not_printed_beside_the_ledgers_classes(case, monkeypatch):
    from core.artifact_value import gap_lines
    _case(case, monkeypatch)
    (case / "evidence" / "logs").mkdir(parents=True, exist_ok=True)
    (case / "evidence" / "logs" / "Application.evtx").write_bytes(b"ElfFile" + b"\0" * 80_000)
    for lang, phrase in (("en", "no reason was recorded"), ("de", "noch ein Grund ist festgehalten")):
        lines = gap_lines(case, lang)
        assert not any(phrase in ln for ln in lines), lines
        assert not any("Application.evtx" in ln for ln in lines), lines


# ── the grounding reads the case's own statements ─────────────────────────────

def test_an_absence_observation_grounded_in_the_brief_and_bare_numbers_leaves_the_class(case, monkeypatch):
    """A reason that restates the window's dates and a bare type code is
    grounded by the brief and the bare-number rule; a handle that rows,
    call and brief do not carry stays refused."""
    led = _case(case, monkeypatch)
    (case / "CASE.md").write_text("# Case: CASE-A\n\nIncident window: 2031-03-10 to 2031-03-12 on CORP-WS01 and "
                                  "CORP-WS02.\n\n## Investigation Requests\n\n- What happened on the hosts?\n",
                                  encoding="utf-8")
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624 logon events: svc_backup service logons only")   # no 10, no date
    probe = ("Security.evtx lists no logon of type 2 or 10 from 2031-03-10 to 2031-03-12; the rows hold service "
             "logons of svc_backup only, so interactive user traces are not expected in the text logs")
    # 2 and 10: type codes nothing need show
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", probe, [cid])
    assert r["ok"], r
    bulk = ("Security.evtx on this host shows no logon of type 10 between 2031-03-10 and 2031-03-12; only "
            "svc_backup service logons appear, so the textual logs cannot add user activity")
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help", bulk, [cid])["ok"]
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", "Security.evtx shows no logons for john.roe in the window", [cid])
    assert not r["ok"] and "john.roe" in r["error"] and "do not show" in r["error"], r
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", "Security.evtx shows no 4768 events in the window", [cid])
    assert not r["ok"] and "4768" in r["error"], r                 # four digits is a value, not a count


def test_the_brief_grounds_dates_and_hosts_never_an_indicator(case, monkeypatch):
    """"No sign of <the brief's indicator>" rests on a read that looked for
    it: the brief and the task texts ground dates and times only; a host
    name of the case stands by itself; an address the brief names is
    grounded by the proof read's rows, command or arguments alone."""
    led = _case(case, monkeypatch)
    (case / "CASE.md").write_text("# Case: CASE-A\n\nThe attacker's address is 203.0.113.9; the window is "
                                  "2031-03-10 to 2031-03-12.\n\n## Investigation Requests\n\n- What happened?\n",
                                  encoding="utf-8")
    cls = _class(led, "corp-ws01.raw", "text")
    plain = _read(case, "corp-ws01.raw", text="4624 logon events: svc_backup service logons only")
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help",
                      "No logons from 203.0.113.9 in the window per Security.evtx", [plain])
    assert not r["ok"] and "203.0.113.9" in r["error"] and "do not show" in r["error"], r
    searched = _read(case, "corp-ws01.raw", text="0 rows", cmd_extra="pattern=203.0.113.9")
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help",
                         "No logons from 203.0.113.9 in the window per Security.evtx", [searched])["ok"]
    # A host of the case (the Evidence Links) and a date the beliefs anchor
    # (the computed window, not the brief) are the case's own statements.
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help",
                         "Security.evtx shows no logon from CORP-WS02 or CORP-WS03 in the window", [plain])["ok"]
    (case / "CASE.md").write_text("# Case: CASE-A\n\n## Investigation Requests\n\n- What happened?\n", encoding="utf-8")
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help",
                         "Security.evtx shows no logons after 2031-03-10 on this host", [plain])["ok"]
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help",
                      "Security.evtx shows no logons after 2031-02-01 on this host", [plain])
    assert not r["ok"] and "2031-02-01" in r["error"], r         # a date nothing states


# ── the proof is read in the forms a model writes ──────────────────────────────

def test_a_proof_id_is_read_in_the_forms_a_model_writes(case, monkeypatch):
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624 logon events: svc_backup service logons only")
    assert L.proof_call_ids(["5", "call 5", "call-5", "call_5", "#5", "c5", "call id 5", 7, "Call ID 9", "call 5,"]) == \
        ([5, 5, 5, 5, 5, 5, 5, 7, 9, 5], [])
    assert L.proof_call_ids(["the security log read", "call", True, "5.0"]) == \
        ([], ["the security log read", "call", "True", "5.0"])
    for form in (f"call {cid}", f"call-{cid}", f"call_{cid}", f"#{cid}", f"c{cid}", f"call id {cid}", cid):
        assert L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, [form])["ok"], form
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, ["the security log read"])
    assert not r["ok"] and f"proof ids are call numbers, write {cid}" in r["error"] and f"call {cid} (" in r["error"], r
    # The ledger keeps the number the form parses to.
    assert L.set_disposition(case, cls["id"], "left", "unlikely_to_help", OBS, [f"call-{cid}"])["success"]
    assert load_ledger(case)["classes"][cls["id"]]["proof_call_ids"] == [cid]


# ── a unit with no host is named by its item ─────────────────────────────

def test_a_hostless_item_is_named_by_its_file_and_a_classless_item_counts_as_one_cheap_class(case, monkeypatch):
    """A FAT image the Evidence Links tie to no host: its classes stand under
    the image's file name in the depth lines, the block, the count line,
    the report and the Coverage tab; an image the class rules shape no
    class for counts by itself as one cheap class, decided with it."""
    _plan(case, [_image(case, "usb-a.dd"), _image(case, "usb-b.dd")])      # no Evidence Links: no host
    _build(case, monkeypatch, {"usb-a.dd": [_b("notes/todo.txt", "5-128-1", T_NEW, 900)],
                               "usb-b.dd": [_b("stuff/blob.xyz", "6-128-1", T_NEW, 900)]})
    from core.coverage_ledger import build_coverage_ledger
    from core.evidence_disposition import report_lines, undecided_by_host
    led = build_coverage_ledger(case)
    a = next(i for i in led["items"].values() if i["path"].endswith("usb-a.dd"))
    b = next(i for i in led["items"].values() if i["path"].endswith("usb-b.dd"))
    assert a["host"] == "" and b["host"] == ""
    assert [c["item"] for c in led["classes"].values()] == [a["id"]]    # the .xyz image yields no class
    for c in led["classes"].values():
        c["state"] = "relevant"
    save_ledger(case, led)
    depth = D.depth_by_host(case, load_ledger(case))
    assert set(depth) == {"usb-a.dd", "usb-b.dd"} and "" not in depth
    assert depth["usb-b.dd"]["cheap"] == (0, 1)                        # the item itself, one cheap class
    line = D.depth_line(depth)
    assert "usb-a.dd: " in line and "usb-b.dd: cheap 0/1" in line and "no host" not in line
    assert undecided_by_host(load_ledger(case)) == {"usb-a.dd": 1, "usb-b.dd": 1}   # the classless image counts
    work = W.open_classes(str(case))
    block = "\n".join(W.class_lines({"classes": work}))
    assert "usb-a.dd (1)" in block and "no host" not in block
    count = W.class_count_line({"classes": work}, str(case))
    assert "usb-a.dd: 1" in count and "no host" not in count
    report = "\n".join(report_lines(case))
    assert "- usb-a.dd: " in report and "- usb-b.dd: cheap 0/1" in report and "no host" not in report
    de = "\n".join(report_lines(case, "de"))
    assert "kein Host" not in de and "- usb-b.dd: " in de
    from dashboard import read_models
    read_models._coverage_cache.clear()
    read_models._extracted_cache.clear()
    data = read_models.coverage(str(case))
    lanes = {i["path"]: i for i in data["items"]}
    assert lanes[a["path"]]["lane"] == "usb-a.dd" and lanes[b["path"]]["lane"] == "usb-b.dd"
    assert lanes[b["path"]]["tier"] == "cheap" and lanes[a["path"]]["tier"] == ""
    # Read, the class-less item is decided.
    led = load_ledger(case)
    led["items"][b["id"]]["state"] = "read"
    save_ledger(case, led)
    assert D.depth_by_host(case, load_ledger(case))["usb-b.dd"]["cheap"] == (1, 1)


# ── the proof parser's forms, continued ───────────────────────────────────

def test_a_proof_id_takes_the_hint_form_and_several_ids_but_no_belief_id(case, monkeypatch):
    assert L.proof_call_ids(["call 5 (misc_evtx_filter)", "call 5, call 6", "5 and 7", "#8 (a read), 9",
                             "call 10 (misc_evtx_filter, rows)"]) == ([5, 5, 6, 5, 7, 8, 9, 10], [])
    assert L.proof_call_ids(["c5", "C12"]) == ([5, 12], [])
    assert L.proof_call_ids(["c05", "C0010", "c0"]) == ([], ["c05", "C0010", "c0"])   # the "c" form takes no leading zero
    led = _case(case, monkeypatch)
    cls = _class(led, "corp-ws01.raw", "text")
    cid = _read(case, "corp-ws01.raw", text="4624 logon events: svc_backup service logons only")
    assert L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, [f"call {cid} (misc_evtx_filter)"])["ok"]
    r = L.check_leave(case, led, cls["id"], "unlikely_to_help", OBS, ["C0010"])
    assert not r["ok"] and f"'C0010' is a belief id, not a call number (proof ids are call numbers, write {cid})" in r["error"], r


# ── an extracted file's class is an extension shape, never wire text ───────

def test_an_extracted_files_class_is_an_extension_shape_never_a_query_string():
    from core.coverage_ledger import _class_of
    assert _class_of("report.pdf") == "pdf" and _class_of("archive.tar.gz") == "gz" and _class_of("README") == "no extension"
    assert _class_of("Security.EVTX") == "evtx" and _class_of(".bashrc") == "no extension"
    for wire in ("banner.gif%3fid=111&ref=222", "logo.example%2f", "page.php?id=4&x=y", "a.b/c%20d"):
        assert _class_of(wire) == "other", wire


# ── a hostless class answers to its item's name; a classless item is undecided ───────────

def test_a_label_handle_finds_a_hostless_class_by_its_items_name(case, monkeypatch):
    _plan(case, [_image(case, "usb-a.dd")])
    _build(case, monkeypatch, {"usb-a.dd": [_b("notes/todo.txt", "5-128-1", T_NEW, 900)]})
    from core.coverage_ledger import build_coverage_ledger
    led = build_coverage_ledger(case)
    (cls,) = led["classes"].values()
    assert cls["host"] == ""
    assert [c["id"] for c in L.classes_by_handle(led, "textual log", ["usb-a.dd"])] == [cls["id"]]
    assert [c["id"] for c in L.classes_by_handle(led, "usb-a.dd: textual log")] == [cls["id"]]
    assert L.classes_by_handle(led, "textual log", ["CORP-WS09"]) == []
    cid = elog.log.record_tool_call("<py>:strings_strings_read_text evidence/disk/usb-a.dd::notes/todo.txt", True, False, 0, 0,
                                    stdout_excerpt="shopping list, nothing else")
    elog.log.annotate_tool_call(cid, mcp_tool="strings_strings_read_text")
    r = L.set_disposition(case, "textual log", "left", "unlikely_to_help",
                          "todo.txt holds a shopping list and nothing else", [cid], hosts=["usb-a.dd"])
    assert r["success"] is True and r["hosts"] == ["usb-a.dd"], r


def test_a_classless_item_still_to_be_read_keeps_the_run_from_finishing(case, monkeypatch):
    from core.coverage_ledger import build_coverage_ledger
    from core.evidence_disposition import disposition_complete, report_lines, undecided_items
    from core.investigation_exit import STOPPED_UNDECIDED, classify_finish_status
    _plan(case, [_image(case, "usb-a.dd"), _image(case, "usb-b.dd")])
    _build(case, monkeypatch, {"usb-a.dd": [_b("notes/todo.txt", "5-128-1", T_NEW, 900)],
                               "usb-b.dd": [_b("stuff/blob.xyz", "6-128-1", T_NEW, 900)]})
    led = build_coverage_ledger(case)
    b = next(i for i in led["items"].values() if i["path"].endswith("usb-b.dd"))
    for c in led["classes"].values():
        c["state"] = "read"                                   # every class read; the classless image still relevant
    b["state"] = "relevant"
    save_ledger(case, led)
    assert [i["id"] for i in undecided_items(load_ledger(case))] == [b["id"]]
    assert classify_finish_status("finished", case_dir=case, report_written=True, synthesize_ok=True,
                                  pre_report_ready=True) == STOPPED_UNDECIDED
    ok, detail = disposition_complete(case)
    assert not ok and detail["undecided_classes"] == 1 and detail["undecided_items"] == 1
    assert detail["undecided_by_host"] == {"usb-b.dd": 1} and b["id"] in detail["undecided_ids"]
    report = "\n".join(report_lines(case))
    assert "### Evidence not decided" in report and "- usb-b.dd: evidence/disk/usb-b.dd (no content classes known)" in report
    import tools.coverage as cov
    fn = getattr(cov.ledger_status, "fn", cov.ledger_status)
    st = fn()["classes_without_reason"]
    assert st["count"] == 1 and st["by_host"] == {"usb-b.dd": 1} and st["classes"] == ["usb-b.dd: evidence/disk/usb-b.dd (no content classes)"]
    # Read, it is decided and the run may finish (the other image's own
    # state follows its classes in the credit pass; set here as that would).
    led = load_ledger(case)
    led["items"][b["id"]]["state"] = "read"
    a = next(i for i in led["items"].values() if i["path"].endswith("usb-a.dd"))
    a["state"] = "read"
    save_ledger(case, led)
    assert undecided_items(load_ledger(case)) == [] and disposition_complete(case)[0]


def test_two_hostless_items_sharing_a_file_name_count_under_their_paths(case, monkeypatch):
    from core.coverage_ledger import build_coverage_ledger
    (case / "evidence" / "disk" / "b").mkdir(parents=True)
    _plan(case, [_image(case, "usb.dd"), _image(case, "b/usb.dd")])
    _build(case, monkeypatch, {"usb.dd": [_b("notes/todo.txt", "5-128-1", T_NEW, 900)]})
    led = build_coverage_ledger(case)
    labels = D.item_labels(led["items"])
    assert sorted(labels.values()) == ["evidence/disk/b/usb.dd", "evidence/disk/usb.dd"]
    depth = D.depth_by_host(case, led)
    assert set(depth) == {"evidence/disk/b/usb.dd", "evidence/disk/usb.dd"}
