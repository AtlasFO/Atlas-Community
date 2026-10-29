"""What each export covers
(channels, event ids, what it skipped per host), the hosts a call reached,
the run's inside counts, the intake listing as the image's open, and the
absence gate against the profile and the index. Invented fixtures only
(CORP-WS01, CORP-SRV02, jane.doe, dates in 2031)."""
from __future__ import annotations

import json
from types import SimpleNamespace

import core.execution_log as elog
from core import contents_index as ci
from core.export_profile import export_profile
from tests.core.test_contents_index import (SRV02, WS01, _body, _build, _image, _links, _plan,  # noqa: F401
                                            case)

L2T = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"


def _row(host, eid, src="OS:/Windows/System32/winevt/Logs/Security.evtx", t="08:00:00"):
    return f"01/02/2031,{t},UTC,M...,EVT,WinEVTX,t,-,{host},s,[{eid} / 0x1] e,2,{src},-,-,winevtx,-\n"


def _setup(case, monkeypatch, timeline_rows=None):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-SRV02", "evidence/disk/corp-srv02.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "corp-srv02.raw")])
    rows = timeline_rows if timeline_rows is not None else [_row("CORP-WS01", 4624), _row("CORP-WS01", 4625),
                                                            _row("CORP-SRV02", 4624)]
    (case / "evidence" / "timeline.csv").write_text(L2T + "".join(rows), encoding="utf-8")
    srv = SRV02 + [_body("Windows/System32/winevt/Logs/Security.evtx", "305-128-1", 1000)]
    _build(case, monkeypatch, {"corp-ws01.raw": WS01, "corp-srv02.raw": srv})
    return "evidence/timeline.csv"


def test_the_profile_carries_channels_ids_and_what_the_export_skipped(case, monkeypatch):
    rel = _setup(case, monkeypatch)
    p = export_profile(case, rel)
    assert p["rows"] == 3 and sorted(p["hosts"]) == ["CORP-SRV02", "CORP-WS01"]
    assert p["channels"] == {"Security": {"4624": 2, "4625": 1}} and p["sources"] == 2
    # CORP-SRV02's IIS log directory was listed in its image, never parsed.
    assert p["skipped"]["CORP-SRV02"][0]["dir"] == "inetpub/logs/LogFiles/W3SVC1"
    assert "skipped by the exports: inetpub/logs/LogFiles/W3SVC1 (1 files" in ci.host_view(case)
    from core.export_profile import inventory_lines
    assert inventory_lines(case)[0].startswith(f"{rel}: CORP-WS01, CORP-SRV02; 3 rows") or \
        inventory_lines(case)[0].startswith(f"{rel}: CORP-SRV02, CORP-WS01; 3 rows")


def test_the_hosts_a_call_reached(case, monkeypatch):
    rel = _setup(case, monkeypatch)
    rows = {"path": str(case / rel), "rows": [{"_row": 1, "filename": "OS:/Windows/System32/winevt/Logs/Security.evtx",
                                               "host": "CORP-WS01"}]}
    ci.observe_result(case, "table_table_query", rows, None, 41)
    assert ci.hosts_covered(case, 41, {"args": json.dumps({"path": rel, "where": ["host=CORP-WS01"]})}) == \
        ["CORP-SRV02", "CORP-WS01"]     # both hosts' sources share the Security log path
    assert ci.hosts_covered(case, 42, {"args": json.dumps({"path": rel})}) == ["CORP-SRV02", "CORP-WS01"]
    assert ci.hosts_covered(case, 43, {"args": json.dumps({"path": rel, "pattern": "4624"})}) == []


def test_inside_counts_and_the_evidence_table_note(case, monkeypatch):
    _setup(case, monkeypatch)
    c = ci.inside_counts(case)
    assert c["images"] == 2 and c["listed"] == 2 and c["high_value"] >= 4
    assert c["read"] == 0 and c["untouched"] + c["skipped"] + c["partial"] == c["high_value"]
    img = c["per_image"]["evidence/disk/corp-ws01.raw"]
    assert img["read"] == 0 and img["high_value"] >= 3


def test_the_intake_listing_opens_the_image(case, monkeypatch):
    _setup(case, monkeypatch)
    from core.mount_plan import build_mount_plan, load_mount_plan
    imgs = {img["basename"] if "basename" in img else img["path"].rsplit("/", 1)[-1]: img
            for img in load_mount_plan(case)["images"]}
    assert imgs["corp-ws01.raw"]["status"] == "opened" and imgs["corp-ws01.raw"]["opened_tool"] == "tsk.fls"
    build_mount_plan(case, persist=True, auto_mount=False)
    assert any(i.get("status") == "opened" for i in load_mount_plan(case)["images"])


def test_a_failed_listing_or_the_switch_off_opens_nothing(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws09.vhdx")])
    _build(case, monkeypatch, {})
    from core.mount_plan import load_mount_plan
    assert all(i.get("status") != "opened" for i in load_mount_plan(case)["images"])
    monkeypatch.setenv("ATLAS_INDEX_OPENS_MEDIA", "0")
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    assert all(i.get("status") != "opened" for i in load_mount_plan(case)["images"])


def test_the_intake_open_is_progress_already_made(case, monkeypatch):
    """The report ladder's done set starts with the images the intake opened:
    the model's own open adds no member, and a first turn is not read as a
    stall because of it."""
    _setup(case, monkeypatch)
    from agent.loop import Agent
    from tests.agent.test_loop_reliability import _ScriptedClient, _StubToolbox
    agent = Agent(_ScriptedClient([]), _StubToolbox(), case_dir=case, quiet=True)
    done = agent._report_done()
    assert any(m[0] == "media" and m[1].endswith("corp-ws01.raw") for m in done)


def _gate_ctx(case, description, calls=(), host=""):
    from tools._gates import GateContext
    log = elog.log
    for c in calls:
        cid = log.record_tool_call(f"<py>:{c['tool']}", True, False, 0, 0, stdout_excerpt="0 rows")
        log.annotate_tool_call(cid, args=json.dumps(c["args"]), mcp_tool=c["tool"])
    return GateContext(description=description, confidence="Unconfirmed", tier="UNCONFIRMED", source="t",
                       linked_call_id=0, tested_hypothesis_id="", log=log, idx=log.index(),
                       window=log.last_n_window(30), input_call_ids=[], host=host)


def test_an_export_counts_only_for_the_ids_its_profile_shows(case, monkeypatch):
    rel = _setup(case, monkeypatch)
    from tools._gates import negative_completeness as nc
    q = {"tool": "table_table_query", "args": {"path": rel, "where": ["filename~Security.evtx"]}}
    # The session channels read from the log itself; the Security log only through the export.
    ts = {"tool": "strings_strings_grep", "args": {"file_path": "evidence/Microsoft-Windows-TerminalServices-"
                                                             "LocalSessionManager%4Operational.evtx"}}
    ctx = _gate_ctx(case, "No logon of jane.doe with event ids 4648 and 4624 on CORP-WS01 was found", [q, ts])
    monkeypatch.setattr(nc, "_index_absence", lambda c: None)
    out = nc.check(ctx)
    assert out and out.get("detail_gate") == "export_profile"
    assert "only event ids 4624, 4625" in out["error"] and "4648" in out["error"]
    ctx = _gate_ctx(case, "No logon of jane.doe with event id 4624 on CORP-WS01 was found", [q, ts])
    out = nc.check(ctx)
    assert not out or out.get("detail_gate") != "export_profile"


def test_an_unprofiled_export_is_credited_with_an_advisory(case, monkeypatch):
    _setup(case, monkeypatch)
    (case / "evidence" / "other.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    from tools._gates import negative_completeness as nc
    q = {"tool": "table_table_query", "args": {"path": "evidence/other.csv", "where": ["x~Security.evtx"]}}
    ctx = _gate_ctx(case, "No logon of jane.doe with event id 4648 on CORP-WS01 was found", [q])
    monkeypatch.setattr(nc, "_index_absence", lambda c: None)
    out = nc.check(ctx)
    assert not out or out.get("detail_gate") != "export_profile"
    assert "not profiled" in ctx.notes.get("export_profile_advisory", "")


def test_an_absence_over_unread_files_the_index_lists_is_refused(case, monkeypatch):
    _setup(case, monkeypatch)
    from tools._gates import negative_completeness as nc
    ctx = _gate_ctx(case, "No W3SVC1 log files were found on CORP-SRV02.")
    out = nc._index_absence(ctx)
    assert out and out["detail_gate"] == "index_absence"
    assert "on CORP-SRV02" in out["error"] and "inetpub/logs/LogFiles/W3SVC1" in out["error"]
    assert "not in the exports searched" in out["error"]
    assert nc._index_absence(_gate_ctx(case, "No W3SVC1 log files in the exports searched on CORP-SRV02.")) is None
    assert nc._index_absence(_gate_ctx(case, "No W3SVC1 log files were found on CORP-WS01.")) is None


def test_the_row_grounding_drops_an_export_read_silent_about_the_ids(case, monkeypatch):
    import re
    rel = _setup(case, monkeypatch)
    from tools._gates._manifests import searches_of
    rx = re.compile(r"(?i)security\.evtx")
    grounding = {"required": [("security_evtx", rx, "the Security log")]}
    read = {"type": "tool_call", "call_id": 5, "cmd": "<py>:table_table_query", "mcp_tool": "table_table_query",
            "args": json.dumps({"path": rel, "where": ["filename~Security.evtx"]})}
    assert searches_of(grounding, [read], "no event id 4648 on CORP-WS01", case) == []
    assert searches_of(grounding, [read], "no event id 4625 on CORP-WS01", case) == [read]
    assert searches_of(grounding, [read]) == [read]


def _rec(case, monkeypatch, calls, description):
    from unittest.mock import patch
    log = elog.log
    log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    ids = []
    for tool, args in calls:
        cid = log.record_tool_call(f"<py>:{tool}", True, False, 0, 0, stdout_excerpt="0 rows")
        log.annotate_tool_call(cid, args=json.dumps(args), mcp_tool=tool)
        ids.append(cid)
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    from tools.misc import record_finding
    with patch.object(log, "case_dir", return_value=str(case)):
        return record_finding(description=description, confidence="UNCONFIRMED", source=calls[0][0],
                              linked_call_id=ids[0], input_call_ids=ids, host="CORP-WS01",
                              supporting_evidence="0 rows")


SESSIONS = ("strings_strings_grep", {"file_path": "evidence/Microsoft-Windows-TerminalServices-"
                                                  "LocalSessionManager%4Operational.evtx"})


def test_the_unprofiled_export_advisory_reaches_the_recorded_finding(case, monkeypatch):
    _setup(case, monkeypatch)
    (case / "evidence" / "other.csv").write_text("filename,host\nSecurity.evtx,CORP-WS01\n", encoding="utf-8")
    r = _rec(case, monkeypatch, [("table_table_query", {"path": "evidence/other.csv",
                                                         "where": ["filename~Security.evtx"]}), SESSIONS],
             "No logon of jane.doe with event id 4648 on CORP-WS01 was found")
    assert r["success"] is True and "evidence/other.csv is not profiled" in r["export_profile_advisory"]


def test_a_text_search_over_a_profiled_export_is_an_export_read(case, monkeypatch):
    rel = _setup(case, monkeypatch)
    r = _rec(case, monkeypatch, [("strings_strings_grep", {"file_path": rel, "pattern": "Security.evtx"}),
                                 SESSIONS], "No logon of jane.doe with event 4648 on CORP-WS01 was found")
    assert r["success"] is False and "timeline.csv carries from Security only event ids 4624, 4625" in r["error"]


def test_a_zero_row_search_over_an_export_covers_its_hosts(case, monkeypatch):
    rel = _setup(case, monkeypatch)
    entry = {"args": json.dumps({"path": rel, "pattern": "jane.doe"}),
             "result_meta": {"matched_rows": 0, "returned_rows": 0}}
    assert ci.hosts_covered(case, 51, entry) == ["CORP-SRV02", "CORP-WS01"]
    windowed = {**entry, "result_meta": {"matched_rows": 0, "matched_rows_all": 3}}
    assert ci.hosts_covered(case, 52, windowed) == []


def test_one_event_id_grammar():
    from core.export_profile import claim_event_ids
    assert claim_event_ids("no event 4663 on CORP-WS01") == ["4663"]
    assert claim_event_ids("event ids 4663 and 4656, EIDs 4624/4625") == ["4663", "4656", "4624", "4625"]


def test_a_condition_or_the_runs_progress_is_no_absence_for_the_index(case, monkeypatch):
    """The index check reads the analyst's own claim, as the universal gate
    does: a "no" inside a reported condition, or a statement of what the
    run has not read yet, names no absence on the host."""
    _setup(case, monkeypatch)
    from tools._gates import negative_completeness as nc
    rule = ("The memo on CORP-SRV02 says the W3SVC1 log files are purged after a week if no backup job "
            "runs, and names the operator.")
    assert nc._index_absence(_gate_ctx(case, rule)) is None
    assert nc._index_absence(_gate_ctx(case, "No W3SVC1 log file on CORP-SRV02 has been read yet.")) is None
    assert nc._index_absence(_gate_ctx(case, "No W3SVC1 log files were found on CORP-SRV02.")) is not None
