"""The contents index: the intake listing of every disk
image, its failures, the exports' sources joined to the files they came
from, the host-scoped absence lookups, the floor guard, the grouped evidence
gaps and the host-first view. Invented fixtures only (CORP-WS01, CORP-SRV02,
jane.doe, dates in 2031)."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

import core.execution_log as elog
from core import contents_index as ci

T = "1924992000"   # 2031-01-01T00:00:00Z


def _body(path: str, inode: str = "100-128-1", size: int = 4096, mode: str = "r/rrwxrwxrwx") -> str:
    return f"0|/{path}|{inode}|{mode}|0|0|{size}|{T}|{T}|{T}|{T}"


WS01 = [
    _body("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", 67_108_864),
    _body("Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx", "201-128-1", 31_457_280),
    _body("Windows/System32/config/SYSTEM", "202-128-1", 12_582_912),
    _body("Users/jane.doe/NTUSER.DAT", "203-128-1", 2_097_152),
    _body("Users/jane.doe/Documents/notes.txt", "204-128-1", 120),
    _body("Windows/System32", "30-144-1", 0, "d/drwxrwxrwx"),
]
SRV02 = [
    _body("Windows/System32/winevt/Logs/Security.evtx", "300-128-1", 33_554_432),
    _body("inetpub/logs/LogFiles/W3SVC1/u_ex310101.log", "301-128-1", 9_000),
]


@pytest.fixture
def case(tmp_path):
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (root / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    return root


def _image(root: Path, name: str, data: bytes = b"\0" * 512) -> str:
    p = root / "evidence" / "disk" / name
    p.write_bytes(data)
    return str(p)


def _plan(root: Path, images: list[str]) -> None:
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": p, "media_role": "disk", "action": "plan_only", "image_type": "raw_or_container"}
        for p in images]}), encoding="utf-8")


def _links(root: Path, pairs: list[tuple[str, str]]) -> None:
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": label, "path": path} for label, path in pairs]}), encoding="utf-8")


def _fake_run(listings: dict[str, object], mmls: dict[str, str] | None = None, calls: list | None = None):
    """A stand-in for the executor: ``listings`` maps an image basename to
    its bodyfile lines or a result dict; each call is recorded in the
    trace as the executor would."""
    def run(cmd, timeout):
        if calls is not None:
            calls.append(cmd)
        base = Path(cmd[-1]).name
        if cmd[0] == "mmls":
            out = (mmls or {}).get(base)
            res = ({"success": True, "stdout": out} if out is not None
                   else {"success": False, "stdout": "", "stderr": "Cannot determine partition type"})
        else:
            got = listings.get(base)
            if isinstance(got, dict):
                res = dict(got)
            elif got is None:
                res = {"success": False, "stdout": "", "stderr": "Cannot determine file system type",
                       "exit_code": 1}
            else:
                res = {"success": True, "stdout": "\n".join(got)}
        cid = elog.log.record_tool_call(cmd=" ".join(cmd), success=bool(res.get("success")), truncated=False,
                                        retries=0, exit_code=0 if res.get("success") else 1)
        res["_atlas_call_id"] = cid
        return res
    return run


def _build(root, monkeypatch, listings, mmls=None, calls=None):
    monkeypatch.setattr(ci, "_run", _fake_run(listings, mmls, calls))
    return ci.build(root)


# ── 1, 2, 12, 13a-c: the builder ──────────────────────────────────────────

def test_each_failure_is_recorded_per_image_and_the_others_are_built(case, monkeypatch):
    imgs = [_image(case, n) for n in ("corp-ws01.raw", "volume.dd", "slow.raw", "corp-ws09.vhdx", "corp-ws11.E01")]
    imgs.append(str(case / "evidence" / "disk" / "gone.raw"))
    _plan(case, imgs)
    monkeypatch.setattr("tools.sleuthkit.tsk_image_types", lambda: frozenset({"raw"}))
    out = _build(case, monkeypatch, {
        "corp-ws01.raw": WS01,
        "volume.dd": SRV02,                       # no partition table: listed at offset 0
        "slow.raw": {"success": False, "timed_out": True, "stdout": ""},
    }, mmls={"corp-ws01.raw": "     002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)"})
    assert sorted(out["listed"]) == ["evidence/disk/corp-ws01.raw", "evidence/disk/volume.dd"]
    reasons = dict(ci.failed_images(case))
    # A volume image's mmls finds no partition table; the listing at offset 0 says why it failed.
    assert reasons["evidence/disk/slow.raw"] == "mmls found no partition table; listing timed out"
    assert reasons["evidence/disk/corp-ws09.vhdx"].endswith("no filesystem The Sleuth Kit can open")
    assert reasons["evidence/disk/corp-ws11.E01"] == "EWF container not mounted"
    assert reasons["evidence/disk/gone.raw"] == "image file missing"
    rows = ci.find(case, pattern="security.evtx")["rows"]
    assert {r["image"] for r in rows} == {"evidence/disk/corp-ws01.raw", "evidence/disk/volume.dd"}
    assert {r["volume"] for r in rows} == {2048, 0}


def test_a_listing_that_timed_out_with_output_is_listed_but_incomplete(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": {"success": False, "timed_out": True,
                                                 "stdout": "\n".join(WS01[:2])}})
    img = ci.listed_images(case)[0]
    assert img["complete"] is False and img["entries"] == 2 and "timed out" in img["reason"]


def test_the_builder_reads_the_spill_file_not_the_capped_stdout(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    lines = [_body(f"Windows/Temp/f{n}.tmp", f"{1000 + n}-128-1") for n in range(151)]
    spill = case / "analysis" / "spill.txt"
    spill.write_text("\n".join(lines), encoding="utf-8")
    _build(case, monkeypatch, {"corp-ws01.raw": {"success": True, "stdout": "\n".join(lines[:150]),
                                                 "truncated": True, "stdout_file": str(spill)}})
    assert ci.find(case, under="Windows/Temp")["total"] == 151
    assert ci.listed_images(case)[0]["complete"] is True


def test_a_truncated_result_without_a_spill_file_is_incomplete(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": {"success": True, "stdout": "\n".join(WS01), "truncated": True}})
    img = ci.listed_images(case)[0]
    assert img["complete"] is False and img["reason"] == "spill failed"


def test_native_ewf_is_read_only_where_the_sleuth_kit_lists_it(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws11.E01")])
    from tools.sleuthkit import _tsk_readable
    with patch("core.paths.active_case_dir", return_value=str(case)):
        monkeypatch.setattr("tools.sleuthkit.tsk_image_types", lambda: frozenset({"raw"}))
        assert _tsk_readable(str(case / "evidence/disk/corp-ws11.E01"))[1] is not None
        _build(case, monkeypatch, {"corp-ws11.E01": WS01})
        assert ci.failed_images(case) == [("evidence/disk/corp-ws11.E01", "EWF container not mounted")]
        monkeypatch.setattr("tools.sleuthkit.tsk_image_types", lambda: frozenset({"raw", "ewf"}))
        assert _tsk_readable(str(case / "evidence/disk/corp-ws11.E01"))[1] is None
        _build(case, monkeypatch, {"corp-ws11.E01": WS01})
        assert ci.failed_images(case) == [] and ci.find(case, pattern="ntuser")["total"] == 1


def test_an_unchanged_image_is_kept_and_a_fresh_trace_relists_it(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    calls: list = []
    _build(case, monkeypatch, {"corp-ws01.raw": WS01}, calls=calls)
    n = len(calls)
    out = _build(case, monkeypatch, {"corp-ws01.raw": WS01}, calls=calls)
    assert out["kept"] == ["evidence/disk/corp-ws01.raw"] and len(calls) == n
    # A fresh start archives the trace: the listing call is no longer in it.
    elog.log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace2.json"), save_session=False)
    with patch("core.contents_index._trace_call_ids", return_value=set()):
        out = _build(case, monkeypatch, {"corp-ws01.raw": WS01}, calls=calls)
    assert out["listed"] == ["evidence/disk/corp-ws01.raw"] and len(calls) > n


def test_bodyfile_parsing_keeps_streams_and_marks_deletions():
    rows = ci.parse_bodyfile([
        _body("Users/jane.doe/a.txt ($FILE_NAME)"),
        _body("Users/jane.doe/b.txt (deleted)"),
        _body("Users/jane.doe/c.txt:Zone.Identifier"),
        "0|/odd|name.txt|7-128-1|r/rrwxrwxrwx|0|0|5|0|0|0|0",
        "not a bodyfile line",
    ])
    assert [r["path"] for r in rows] == ["Users/jane.doe/b.txt", "Users/jane.doe/c.txt:Zone.Identifier",
                                         "odd|name.txt"]
    assert rows[0]["deleted"] == 1 and rows[0]["mtime"] == "2031-01-01T00:00:00Z"
    assert rows[2]["mtime"] == ""


def test_a_mirror_folds_and_a_partial_overlap_does_not():
    live = [{"path": f"C/Windows/f{n}", "is_dir": 0, "volume": 0} for n in range(10)]
    mirror = [{"path": f"vs1/Windows/f{n}", "is_dir": 0, "volume": 0} for n in range(6)]
    other = [{"path": f"Data/Windows/f{n}", "is_dir": 0, "volume": 0} for n in range(4)]
    rows = live + mirror + other
    ci.fold_versions(rows)
    assert all(r.get("_live") == n for n, r in enumerate(rows[10:16]))
    assert {r["version_folder"] for r in rows[10:16]} == {"vs1"}
    assert not any("_live" in r for r in rows[16:]) and not any("_live" in r for r in rows[:10])


def test_versions_are_counted_on_the_live_entry_and_named_by_folder(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    lines = [_body(f"C/{p}", f"{400 + n}-128-1") for n, p in enumerate(
        ["Windows/System32/winevt/Logs/Security.evtx", "Windows/System32/config/SYSTEM"])]
    lines += [_body(f"vs{k}/Windows/System32/winevt/Logs/Security.evtx", f"{500 + k}-128-1") for k in (1, 2)]
    _build(case, monkeypatch, {"corp-ws01.raw": lines})
    rows = {r["path"]: r for r in ci.scored_rows(case, 70)}
    sec = rows["C/Windows/System32/winevt/Logs/Security.evtx"]
    assert sec["versions"] == 2 and sec["version_folders"] == ["vs1", "vs2"]
    assert not any(p.startswith("vs") for p in rows)
    found = ci.find(case, pattern="security.evtx")["rows"]
    folded = [r for r in found if r.get("version_of")]
    assert len(folded) == 2 and all(r["version_of"].endswith("::C/Windows/System32/winevt/Logs/Security.evtx")
                                    for r in folded)


def test_an_l2tcsv_timeline_joins_its_sources_by_path_suffix(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    tl = case / "evidence" / "timeline.csv"
    tl.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"
        "01/02/2031,08:00:00,UTC,M...,EVT,WinEVTX,t,-,CORP-WS01,s,[4624 / 0x1210] logon,2,"
        "OS:/mnt/x/Windows/System32/winevt/Logs/Security.evtx,-,-,winevtx,-\n"
        "01/04/2031,10:00:00,UTC,M...,EVT,WinEVTX,t,-,CORP-WS01,s,[4625 / 0x1211] fail,2,"
        "OS:/mnt/x/Windows/System32/winevt/Logs/Security.evtx,-,-,winevtx,-\n", encoding="utf-8")
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    row = ci.find(case, pattern="Security.evtx")["rows"][0]
    assert row["export"] == {"in": "evidence/timeline.csv", "rows": 2, "first": "2031-01-02T08:00:00Z",
                             "last": "2031-01-04T10:00:00Z"}
    assert row["state"] == "unread" and row["host"] == "CORP-WS01"
    sysmon = ci.find(case, pattern="sysmon")["rows"][0]
    assert sysmon["state"] == "skipped"


# ── 3: the intake's listings are no analyst's enumeration ─────────────────

def test_pre_run_listings_do_not_count_as_enumeration(case):
    from core.access_workflow import _count_fls_in_trace
    for n in range(30):
        elog.log.record_tool_call(cmd=f"fls -r -m / -o 0 /x/corp-ws{n:02d}.raw", success=True, truncated=False,
                                  retries=0, exit_code=0)
    assert _count_fls_in_trace(case) == 0
    token = elog.current_mcp_tool.set("tsk_tsk_fls")
    try:
        elog.log.record_tool_call(cmd="fls -r /x/corp-ws01.raw", success=True, truncated=False, retries=0,
                                  exit_code=0)
    finally:
        elog.current_mcp_tool.reset(token)
    assert _count_fls_in_trace(case) == 1


# ── 4: the index is never a floor ─────────────────────────────────────────

def _index_items(n: int) -> list[dict]:
    return [{"state": "open", "name": "Security.evtx", "host": f"CORP-WS{k:03d}", "source": "index:image",
             "lpath": "Windows/System32/winevt/Logs/Security.evtx", "score": 98,
             "why": "authentication, logon sessions, privilege use, object access"} for k in range(n)]


def test_two_thousand_open_index_rows_are_no_obligation_and_no_report_issue(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_BLOCKER_ITEMS", "0")
    items = _index_items(2000) + [{"state": "failed", "name": "SYSTEM", "host": "CORP-SRV02",
                                   "source": "index:image", "lpath": "Windows/System32/config/SYSTEM",
                                   "score": 82, "why": "registry hives", "call_id": 7, "reason": "icat failed"}]
    state = {"items": items, "read": 0, "short_waivers": [], "unmatched_waivers": [], "read_hosts": []}
    from core.investigation_obligations import _artifact_value_obligations
    with patch("core.artifact_value.high_value_state", return_value=state), \
            patch("core.artifact_value.contradicted_absence_claims", return_value=[]):
        obl = _artifact_value_obligations(tmp_path)
    assert not any(o["id"] == "high_value_artifacts_examined" and not o["met"] for o in obl)
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    (tmp_path / "analysis").mkdir()
    log.configure("CASE-A", str(tmp_path / "analysis" / "CASE-A_trace.json"))
    log.record_reason_call("reason_synthesize", True, "ok", {})
    from tools.reasoning import reason_pre_report_check
    with patch("core.execution_log.log", log), patch("core.artifact_value.high_value_state", return_value=state), \
            patch("tools.reasoning.reason_audit_findings",
                  return_value={"summary": {"candidate_count": 0}, "candidates": []}):
        r = reason_pre_report_check()
    assert not any("high-value" in i.lower() for i in r["blocking_issues"])
    assert any("SYSTEM" in d for d in r.get("documented_limitations") or [])
    from core.artifact_value import gap_lines
    with patch("core.artifact_value.high_value_state", return_value=state):
        lines = gap_lines(tmp_path)
    assert len(lines) == 2
    assert any("2000 file(s)" in l and "2000 host(s)" in l for l in lines)
    assert any("SYSTEM" in l and "call 7" in l for l in lines)


# ── 5: host-scoped absence lookups ────────────────────────────────────────

def _two_hosts(case, monkeypatch, ws01=WS01):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-SRV02", "evidence/disk/corp-srv02.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "corp-srv02.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": ws01, "corp-srv02.raw": SRV02})


def _limit(case, reason, **part):
    from core.investigation_tasks import _limitation_refusal
    return _limitation_refusal(case, part, "source_absent", reason, [])


def test_a_source_absent_limitation_is_judged_on_its_host(case, monkeypatch):
    _two_hosts(case, monkeypatch)
    # Only CORP-SRV02's image lists the IIS log.
    assert _limit(case, "the u_ex310101.log web log is not on this host", host="CORP-WS01") is None
    assert _limit(case, "the u_ex310101.log web log is not on this host", host="CORP-SRV02")
    assert _limit(case, "no u_ex310101.log was collected from CORP-WS01") is None
    assert _limit(case, "no u_ex310101.log was collected", hosts=["CORP-WS01"]) is None
    hostless = _limit(case, "no u_ex310101.log was collected anywhere")
    assert hostless and "CORP-SRV02" in hostless and "which host" in hostless


def test_one_host_cases_look_up_every_entry_as_today(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "usb.dd")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01, "usb.dd": SRV02})
    refused = _limit(case, "no u_ex310101.log was collected anywhere")
    assert refused and "is present in this case" in refused


def _claim(case, statement, **extra):
    from core.claim_graph import load_graph
    graph = load_graph(case)
    graph.setdefault("nodes", {})["C0001"] = {"id": "C0001", "kind": "claim", "status": "active",
                                               "statement": statement, **extra}
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")


def test_an_absence_claim_is_contradicted_only_by_its_own_host(case, monkeypatch):
    from core.artifact_value import contradicted_absence_claims
    _two_hosts(case, monkeypatch)
    _claim(case, "u_ex310101.log is not present on the host", host="CORP-WS01")
    assert contradicted_absence_claims(case) == []
    _claim(case, "u_ex310101.log is not present on the host", host="CORP-SRV02")
    assert [c["artifact"] for c in contradicted_absence_claims(case)] == ["u_ex310101.log"]
    _claim(case, "u_ex310101.log is not present", hosts=["CORP-WS01"])
    assert contradicted_absence_claims(case) == []
    _claim(case, "u_ex310101.log is not present on CORP-WS01")
    assert contradicted_absence_claims(case) == []
    _claim(case, "u_ex310101.log is not present on CORP-SRV02")
    assert len(contradicted_absence_claims(case)) == 1
    _claim(case, "u_ex310101.log is not present")
    (hit,) = contradicted_absence_claims(case)
    assert hit["hostless"] and hit["hosts"] == ["CORP-SRV02"] and hit["claim_host"] == ""


def test_a_case_without_links_looks_up_every_entry(case, monkeypatch):
    from core.artifact_value import contradicted_absence_claims
    _plan(case, [_image(case, n) for n in ("a.dd", "b.dd", "c.dd", "d.dd")])
    _build(case, monkeypatch, {"a.dd": WS01, "b.dd": SRV02, "c.dd": WS01, "d.dd": WS01})
    _claim(case, "u_ex310101.log is not present")
    (hit,) = contradicted_absence_claims(case)
    assert not hit.get("hostless")


# ── 6: copies fold into their entries ─────────────────────────────────────

def test_a_registered_copy_is_its_entry(case, monkeypatch):
    from core.artifact_value import high_value_state, known_artifacts
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    entry = ci.find(case, name="NTUSER.DAT")["rows"][0]
    copy = case / "analysis" / "extracted" / "corp-ws01" / "NTUSER.DAT"
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"regf" + b"\0" * 2000)
    ci.record_copy(case, str(copy), entry["id"], 9, copy.stat().st_size)
    assert ci.copy_source(case, str(copy))["host"] == "CORP-WS01"
    known = known_artifacts(case)
    assert not any(k.startswith("file:") or v["source"].startswith("file:") and v["name"] == "NTUSER.DAT"
                   for k, v in known.items())
    row = known["corp-ws01|users/jane.doe/ntuser.dat"]
    assert row["copy"] == ["analysis/extracted/corp-ws01/NTUSER.DAT"] and row["score_as"].endswith("NTUSER.DAT")
    before = [i["name"] for i in high_value_state(case)["items"]]
    assert "NTUSER.DAT" in before
    token = elog.current_mcp_tool.set("ez_ez_recmd_hive")
    try:
        elog.log.record_tool_call(cmd="RECmd -f analysis/extracted/corp-ws01/NTUSER.DAT", success=True,
                                  truncated=False, retries=0, exit_code=0)
    finally:
        elog.current_mcp_tool.reset(token)
    assert "NTUSER.DAT" not in [i["name"] for i in high_value_state(case)["items"]]


def test_a_copy_the_index_does_not_know_stays_a_file_entry(case, monkeypatch):
    from core.artifact_value import known_artifacts
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    out = case / "exports" / "recovered" / "SYSTEM"
    out.parent.mkdir(parents=True)
    out.write_bytes(b"regf" + b"\0" * 100)
    assert any(v["source"] == "file:exports" and v["name"] == "SYSTEM" for v in known_artifacts(case).values())


# ── 7: a fresh start keeps the listing, not the run's views ───────────────

def test_clear_empties_copies_and_partial_views(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    entry = ci.find(case, name="SYSTEM")["rows"][0]
    ci.record_copy(case, "analysis/extracted/SYSTEM", entry["id"], 3, 10)
    with ci._connect(case) as con:
        con.execute("INSERT INTO sources (export, host, source_path, entry_id, rows) VALUES ('x.csv','', 'a', ?, 1)",
                    (entry["id"],))
        con.execute("INSERT INTO partial VALUES (1, 4, 1)")
    assert ci.reset_run_scoped(case) == 2
    assert ci.find(case)["total"] == len(WS01)
    assert ci.copy_paths(case) == set() and not ci.scored_rows(case, 0)[0]["partial"]


# ── 8: the host-first view ────────────────────────────────────────────────

def _brief(case, text):
    (case / "CASE.md").write_text(text, encoding="utf-8")


def _many_hosts(case, monkeypatch, n=16):
    names = [f"CORP-WS{k:02d}" for k in range(1, n + 1)]
    _links(case, [(h, f"evidence/disk/{h.lower()}.raw") for h in names])
    _plan(case, [_image(case, f"{h.lower()}.raw") for h in names])
    _build(case, monkeypatch, {f"{h.lower()}.raw": WS01 for h in names})
    return names


def test_the_view_seeds_hosts_from_the_brief_narrative_not_its_inventory(case, monkeypatch):
    names = _many_hosts(case, monkeypatch)
    rows = "\n".join(f"| {h} | evidence/disk/{h.lower()}.raw |" for h in names)
    _brief(case, "# Case\n\n## Background\n\nThe intruder moved from CORP-WS07 to CORP-WS03 on 2031-01-04; "
                 "CORP-WS03 then reached the file server.\n\n## Evidence\n\n| Host | Image |\n|---|---|\n" + rows
                 + "\n\n## Investigation Requests\n\n1. What did the account do on CORP-WS12?\n")
    from core.investigation_tasks import reconcile_case_md
    reconcile_case_md(case, persist=True)
    view = ci.host_view(case)
    hosts = re.findall(r"^- (CORP-WS\d\d)", view, re.M)
    assert hosts[:3] == ["CORP-WS12", "CORP-WS03", "CORP-WS07"]
    assert "[question" in view.splitlines()[2] and "[brief]" in view.splitlines()[3]
    assert len(hosts) == 12 and "Other images: 4 host(s)" in view
    assert "Security.evtx 64 MB" in view and "Read one: pass its handle" in view
    assert "; ready: evidence/disk/corp-ws12.raw::Windows/System32/winevt/Logs/Security.evtx" in view
    monkeypatch.setenv("ATLAS_IMAGE_HANDLES", "0")
    view = ci.host_view(case)
    assert "Read one: tsk.index_find" in view and "ready:" not in view


def test_claim_named_hosts_take_the_reserved_slots(case, monkeypatch):
    names = _many_hosts(case, monkeypatch)
    _brief(case, "# Case\n\n## Background\n\n" + " ".join(f"{h} was seen." for h in names[:12]) + "\n")
    _claim(case, "jane.doe logged on interactively", host="CORP-WS15")
    view = ci.host_view(case)
    hosts = re.findall(r"^- (CORP-WS\d\d)", view, re.M)
    assert len(hosts) == 12 and hosts[-1] == "CORP-WS15" and "1 finding" in view
    assert "CORP-WS09" in hosts and "CORP-WS12" not in hosts


def test_a_host_with_nothing_unread_drops_and_failures_are_named(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "usb.dd"), _image(case, "corp-ws09.vhdx")])
    _build(case, monkeypatch, {"corp-ws01.raw": [WS01[4]], "usb.dd": WS01})
    view = ci.host_view(case)
    assert "CORP-WS01" not in view
    assert "- evidence/disk/usb.dd [no host in the links]:" in view
    assert re.search(r"not listed: evidence/disk/corp-ws09\.vhdx \([^)]*no filesystem The Sleuth Kit can open\)",
                     view)


def test_the_view_is_off_with_its_switch(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    monkeypatch.setenv("ATLAS_INDEX_HOST_VIEW", "0")
    from tools import dair
    with patch.object(dair, "_case_root", return_value=str(case)):
        block = dair._gaps_block()
    assert "CONTENTS OF THE IMAGES" not in block
    monkeypatch.setenv("ATLAS_INDEX_HOST_VIEW", "1")
    monkeypatch.setenv("ATLAS_WORK_ORDER", "0")
    with patch.object(dair, "_case_root", return_value=str(case)):
        block = dair._gaps_block()
    assert "CONTENTS OF THE IMAGES" in block and "UNREAD HIGH-VALUE" not in block


# ── 9: a handle is no inner path to the coverage ledger ───────────────────

def test_a_handle_credits_its_image_not_the_inner_path():
    from core.coverage_ledger import _paths_mentioned_in_blob
    found = _paths_mentioned_in_blob(
        '{"file": "evidence/disk/corp-ws01.raw::Windows/System32/winevt/Logs/Security.evtx"}')
    assert "evidence/disk/corp-ws01.raw" in found
    assert not any(p.startswith("windows/") for p in found)


# ── 11: partial views from the result dict ────────────────────────────────

def _timeline(case):
    tl = case / "evidence" / "timeline.csv"
    tl.write_text(
        "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"
        "01/02/2031,08:00:00,UTC,M...,EVT,WinEVTX,t,-,CORP-WS01,s,[4624 / 0x1] a,2,"
        "OS:/Windows/System32/winevt/Logs/Security.evtx,-,-,winevtx,-\n"
        "01/02/2031,08:00:01,UTC,M...,REG,Registry,t,-,CORP-WS01,s,key,2,"
        "OS:/Windows/System32/config/SYSTEM,-,-,winreg,-\n", encoding="utf-8")
    return "evidence/timeline.csv"


def test_only_the_shown_rows_mark_their_sources_partial(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    rel = _timeline(case)
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    result = {"path": str(case / rel), "rows": [
        {"_row": 1, "filename": "OS:/Windows/System32/winevt/Logs/Security.evtx"},
        {"_row": 2, "filename": "OS:/Windows/System32/config/SYSTEM"}]}
    assert ci.observe_result(case, "table_table_query", result, [1], 21) == 1
    state = {r["name"]: r["state"] for r in ci.find(case)["rows"]}
    assert state["Security.evtx"] == "partial" and state["SYSTEM"] == "unread"
    assert ci.observe_result(case, "table_table_query", result, None, 22) == 2
    assert {r["name"]: r["state"] for r in ci.find(case)["rows"]}["SYSTEM"] == "partial"
    from core.artifact_value import high_value_state
    assert "SYSTEM" in [i["name"] for i in high_value_state(case)["items"]]


# ── 13: no case identifiers in the module and the tool ────────────────────

def test_no_case_identifiers_are_baked_into_the_module():
    root = Path(__file__).resolve().parents[2]
    text = (root / "core" / "contents_index.py").read_text(encoding="utf-8")
    tool = (root / "tools" / "sleuthkit.py").read_text(encoding="utf-8")
    tool = tool[tool.index("def tsk_index_find"):tool.index("# Directory listings read while")]
    for blob in (text, tool):
        assert not re.search(r"\b[A-Z]{2,}-[A-Z]*\d+\b", blob)          # host labels
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob)      # addresses
        assert not re.search(r"\b(?:19|20)\d\d-\d\d-\d\d\b", blob)      # dates


def test_the_switch_off_builds_nothing(case, monkeypatch):
    monkeypatch.setenv("ATLAS_CONTENTS_INDEX", "0")
    _plan(case, [_image(case, "corp-ws01.raw")])
    assert _build(case, monkeypatch, {"corp-ws01.raw": WS01})["listed"] == []
    assert not ci.db_path(case).exists()


def test_a_relisted_image_keeps_its_export_coverage_without_a_rescan(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _timeline(case)
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    with patch("core.contents_index._trace_call_ids", return_value=set()), \
            patch("core.contents_index._scan_export", side_effect=AssertionError("rescanned")):
        out = _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    assert out["listed"] == ["evidence/disk/corp-ws01.raw"]
    row = ci.find(case, name="Security.evtx")["rows"][0]
    assert row["export"]["in"] == "evidence/timeline.csv" and row["origin"] == "image"
    assert ci.find(case, name="Security.evtx")["total"] == 1


def test_the_tool_answers_the_host_and_pattern_call(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    from tools.sleuthkit import tsk_index_find
    fn = getattr(tsk_index_find, "fn", tsk_index_find)
    with patch("core.paths.active_case_dir", return_value=str(case)):
        out = fn(host="CORP-WS01", pattern="sysmon")
        none = fn(host="CORP-SRV02", pattern="sysmon")
    assert out["success"] and out["total"] == 1
    row = out["rows"][0]
    assert row["handle"] == ("evidence/disk/corp-ws01.raw::Windows/System32/winevt/Logs/"
                             "Microsoft-Windows-Sysmon%4Operational.evtx")
    assert row["inode"] == "201-128-1" and row["modified"] == "2031-01-01T00:00:00Z" and row["state"] == "skipped"
    assert none["total"] == 0 and none["listed_images"] == 1


def test_under_the_work_order_the_view_is_the_map_in_proposed(case, monkeypatch):
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    from core.execution_log import ExecutionLog
    from core.work_order import work_order_for_director
    text = work_order_for_director(ExecutionLog(), str(case))
    assert text.startswith("PROPOSED") and "CONTENTS OF THE IMAGES" in text
    from tools import dair
    with patch.object(dair, "_case_root", return_value=str(case)):
        assert dair._gaps_block().count("CONTENTS OF THE IMAGES") == 1


def test_a_handle_in_the_search_arguments_is_refused_with_the_two_ways(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    from tools.sleuthkit import tsk_index_find
    fn = getattr(tsk_index_find, "fn", tsk_index_find)
    handle = "evidence/disk/corp-ws01.raw::Windows/System32/config/SYSTEM"
    with patch("core.paths.active_case_dir", return_value=str(case)):
        out = fn(host=handle)
        by_image = fn(image="evidence/disk/corp-ws01.raw", pattern="config/SYSTEM")
    assert not out["success"] and out["gate"] == "handle_in_search"
    assert "file argument of a parser" in out["error"] and 'image="evidence/disk/corp-ws01.raw"' in out["error"]
    assert by_image["success"] and by_image["total"] == 1


def test_the_format_routing_classes_every_input_form_of_one_entry(case, monkeypatch):
    """An image handle, an extracted copy's absolute and relative path and
    the inner path all reach the same entry's class."""
    import tools.tool_capabilities as T
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    entry = ci.find(case, name="NTUSER.DAT")["rows"][0]
    copy = case / "analysis" / "extracted" / "corp-ws01" / "NTUSER.DAT"
    copy.parent.mkdir(parents=True)
    copy.write_bytes(b"regf" + b"\0" * 2000)
    ci.record_copy(case, str(copy), entry["id"], 9, copy.stat().st_size)
    want = entry["class"]
    assert want
    for form in (f"evidence/disk/corp-ws01.raw::{entry['path']}", str(copy),
                 "analysis/extracted/corp-ws01/NTUSER.DAT", entry["path"]):
        assert T._index_class(form) == want, form


# ── 14: folder sizes, volume handles and the score index ─────────────────

_LIKE_COUNT = ("SELECT COUNT(*) FROM entries WHERE image = ? AND volume = ? AND is_dir = 0 "
               "AND path LIKE ? ESCAPE '\\'")
_LIKE_SUM = ("SELECT COALESCE(SUM(size), 0) FROM entries WHERE image = ? AND volume IS ? AND origin = 'image' "
             "AND version_of IS NULL AND is_dir = 0 AND path LIKE ? ESCAPE '\\'")
WS01_RAW = "evidence/disk/corp-ws01.raw"


def _index(root: Path, images: dict) -> None:
    """An index of ``images``, {(host, image): {volume: [(path, is_dir, deleted)]}}, 10 bytes a file, each
    image's meta naming its volumes as the build writes them."""
    con = ci._connect(root, create=True)
    for (host, image), vols in images.items():
        rows = [{"path": p, "name": p.rstrip("/").rsplit("/", 1)[-1], "is_dir": d, "deleted": x, "size": 10,
                 "volume": v} for v, items in vols.items() for p, d, x in items]
        ci._insert_entries(con, host, image, rows, "image")
        ci._meta_set(con, f"image:{image}", {"listed": 1, "complete": 1, "host": host, "volumes": list(vols)})
    con.commit()
    con.close()


def _spy(fn, *args):
    """fn(*args) with each index connection watched: the statements it ran
    with their arguments, and SQLite's VM steps in units of 100."""
    ran, steps, real = [], [0], sqlite3.connect

    class Con(sqlite3.Connection):
        def execute(self, sql, params=()):
            ran.append((sql, tuple(params)))
            return super().execute(sql, params)

    def connect(*a, **k):
        con = real(*a, factory=Con, **k)
        con.set_progress_handler(lambda: steps.__setitem__(0, steps[0] + 1), 100)
        return con

    with patch.object(ci.sqlite3, "connect", connect):
        out = fn(*args)
    return out, ran, steps[0]


_FOLDERS = [
    ("Windows/Prefetch", 1, 0), ("WINDOWS/PREFETCH/A.pf", 0, 0), ("windows/prefetch/sub", 1, 0),
    ("windows/prefetch/sub/B.pf", 0, 0), ("Windows/Prefetch/C.pf", 0, 1), ("Windows/Prefetch2/x.pf", 0, 0),
    ("Windows/Prefetch.old/x.pf", 0, 0), ("Windows/Prefetch-x/y.pf", 0, 0),
    ("Windows/Prefetch/~$report.docx", 0, 0), ("Windows/Prefetch/\u00c4pfel.pf", 0, 0),
    ("Users/jane.doe/50%_done", 1, 0), ("Users/jane.doe/50%_done/a.txt", 0, 0),
    ("Users/jane.doe/50X_done/b.txt", 0, 0), ("Users/jane.doe/50%_doneZ/c.txt", 0, 0),
    ("Data_1", 1, 0), ("Data_1/x.txt", 0, 0), ("DataX1/y.txt", 0, 0),
    ("Users/J\u00e4ne", 1, 0), ("Users/J\u00e4ne/f.txt", 0, 0), ("Users/J\u00c4NE/g.txt", 0, 0),
    ("Users/j\u00e4ne/h.txt", 0, 0), ("tail/", 1, 0), ("tail//x.txt", 0, 0), ("tail/y.txt", 0, 0),
]


def test_a_folder_is_sized_by_the_rows_the_like_count_found(case):
    """Both folder sizes (scored_rows' file count, entries_matching's byte
    sum) equal the per-folder LIKE query they replaced, kept here as the
    oracle: ASCII case folded, % and _ literal, siblings that share the
    prefix left out, names that sort above "~" (an Office lock file, a
    non-ASCII first letter) kept in, non-ASCII never folded, a trailing
    slash, deleted files counted, and the same folder on a second volume,
    on a second image of the host at the same offset, on another host and on
    an image with no host kept apart."""
    one = [("Windows/Prefetch", 1, 0), ("windows/PREFETCH/D.pf", 0, 0)]
    _index(case, {("CORP-WS01", WS01_RAW): {2048: _FOLDERS, 1026048: one},
                  ("CORP-WS01", "evidence/disk/corp-ws01-data.raw"): {2048: one + [("Windows/Prefetch/E.pf", 0, 0)]},
                  ("CORP-WS02", "evidence/disk/corp-ws02.raw"): {2048: one},
                  ("", "evidence/disk/usb.dd"): {0: one}})
    with closing(ci._connect(case)) as con:
        folders = con.execute("SELECT * FROM entries WHERE is_dir = 1").fetchall()
        like = {f["id"]: (con.execute(_LIKE_COUNT, (f["image"], f["volume"], ci._like_escape(f["path"]) + "/%")
                                      ).fetchone()[0],
                          con.execute(_LIKE_SUM, (f["image"], f["volume"], ci._like_escape(f["path"]) + "/%")
                                      ).fetchone()[0]) for f in folders}
    sized = {r["id"]: r["size"] for r in ci.scored_rows(case, 0) if r["is_dir"]}
    assert sized == {k: v[0] for k, v in like.items()}
    by = {(f["image"], f["volume"], f["path"]): sized[f["id"]] for f in folders}
    assert by[(WS01_RAW, 2048, "Windows/Prefetch")] == 5 and by[(WS01_RAW, 1026048, "Windows/Prefetch")] == 1
    assert by[(WS01_RAW, 2048, "Users/J\u00e4ne")] == 2 and by[(WS01_RAW, 2048, "tail/")] == 1
    assert by[("evidence/disk/corp-ws01-data.raw", 2048, "Windows/Prefetch")] == 2
    assert by[(WS01_RAW, 2048, "Users/jane.doe/50%_done")] == by[(WS01_RAW, 2048, "Data_1")] == 1
    assert by[("evidence/disk/usb.dd", 0, "Windows/Prefetch")] == 1
    for f in folders:
        if f["path"].endswith("/"):
            continue                      # a pattern's trailing "/" asks for a folder
        got = {r["entry_id"]: r["size"] for r in ci.entries_matching(case, f["image"], f["path"] + "/")}
        assert got[f["id"]] == like[f["id"]][1], f["path"]


def test_a_folder_path_past_the_like_pattern_limit_is_sized(case):
    """LIKE refuses a pattern over 50,000 bytes; a path within NTFS's 32,767
    UTF-16 units passes that in UTF-8 (three bytes a CJK character). The
    range has no such limit, in either folder size."""
    deep = "/".join(["\u6587" * 200] * 90)
    _index(case, {("CORP-WS01", WS01_RAW): {2048: [(deep, 1, 0), (deep + "/a.txt", 0, 0), (deep + "/b.txt", 0, 0)]}})
    assert [r["size"] for r in ci.scored_rows(case, 0) if r["is_dir"]] == [2]
    assert [r["size"] for r in ci.entries_matching(case, WS01_RAW, deep + "/")] == [20]


def test_the_folder_sizes_search_a_path_range_and_the_rows_their_score(case):
    """The folder count and the folder sum search entries_host_path by host
    and a path range, never every row of the image, also where LIKE is
    overloaded (an ICU build) and its prefix optimization is gone; the
    high-value rows come from entries_score, never a scan of the table."""
    from core.artifact_value import HIGH_VALUE_THRESHOLD
    _index(case, {("CORP-WS01", WS01_RAW): {2048: _FOLDERS}})
    _, ran, _ = _spy(ci.scored_rows, case, HIGH_VALUE_THRESHOLD)
    _, ran_matching, _ = _spy(ci.entries_matching, case, WS01_RAW, "Windows/Prefetch/")
    sizes = [s for s in ran + ran_matching if "COUNT(*)" in s[0] or "SUM(size)" in s[0]]
    assert any("COUNT(*)" in s[0] for s in sizes) and any("SUM(size)" in s[0] for s in sizes)
    (main,) = [s for s in ran if "deleted = 0" in s[0]]
    with closing(sqlite3.connect(str(ci.db_path(case)))) as con:
        def plan(sql, args):
            return " ".join(r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql, args))
        assert "entries_score (score>?)" in plan(*main)
        for overloaded in (False, True):
            if overloaded:
                con.create_function("like", 2, lambda *a: 0)
                con.create_function("like", 3, lambda *a: 0)
            for sql, args in sizes:
                assert "entries_host_path (host=? AND path>? AND path<?)" in plan(sql, args), (overloaded, sql)


def test_the_count_of_vm_steps_does_not_grow_with_unrelated_rows(tmp_path):
    """scored_rows on two indexes that differ only in N against 10 N files
    of an unrelated folder: SQLite's VM steps (no clock, no cap) stay within
    a factor of 2. A pass over every row of an image (a per-folder count, a
    grouping of its volumes, a scan for the score) multiplies them by
    about 10."""
    from core.artifact_value import HIGH_VALUE_THRESHOLD

    def steps(n: int) -> int:
        root = tmp_path / str(n)
        prefetch = [(f"Windows/Prefetch/TOOL{i:03d}.EXE-0A1B2C3D.pf", 0, 0) for i in range(200)]
        filler = [(f"Program Files/App/lib{i:05d}.dll", 0, 0) for i in range(n)]
        _index(root, {("CORP-WS01", WS01_RAW): {2048: [("Windows/Prefetch", 1, 0)] + prefetch + filler}})
        out, _, count = _spy(ci.scored_rows, root, HIGH_VALUE_THRESHOLD)
        assert [r["size"] for r in out if r["is_dir"]] == [200]
        return count

    small, large = steps(2_000), steps(20_000)
    assert large / max(small, 1) < 2, (small, large)


_MMLS_ONE = "     002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)"
_MMLS_TWO = _MMLS_ONE + "\n     003:  000:001   0001026048   0002050047   0001024000   NTFS / exFAT (0x07)"


def test_a_handle_names_its_volume_only_on_an_image_of_several(case, monkeypatch):
    """The images of several filesystems come from the image meta the build
    writes: their handles carry @<offset>, a one-volume image's carry none,
    and so does an image whose partition table names one start twice (the
    volume is listed twice and is still one). A meta value that does not
    parse is skipped."""
    _plan(case, [_image(case, n) for n in ("corp-ws01.raw", "corp-srv02.raw", "corp-ws03.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01, "corp-srv02.raw": SRV02, "corp-ws03.raw": WS01},
           mmls={"corp-ws01.raw": _MMLS_TWO, "corp-srv02.raw": _MMLS_ONE,
                 "corp-ws03.raw": _MMLS_ONE + "\n" + _MMLS_ONE.replace("002:", "003:")})
    with closing(ci._connect(case)) as con:
        con.execute("INSERT INTO meta VALUES ('image:evidence/disk/broken.raw', '{not json')")
        con.execute("INSERT INTO meta VALUES ('image:evidence/disk/odd.raw', '[2048, 4096]')")
        con.commit()
    images = {r["handle"].split("::")[0] for r in ci.find(case, name="Security.evtx")["rows"]}
    assert images == {"evidence/disk/corp-ws01.raw@2048", "evidence/disk/corp-ws01.raw@1026048",
                      "evidence/disk/corp-srv02.raw", "evidence/disk/corp-ws03.raw"}


def test_an_index_built_before_the_score_index_gains_it_on_the_next_connect(case):
    with closing(sqlite3.connect(str(ci.db_path(case)))) as con:
        con.executescript("\n".join(line for line in ci._SCHEMA.splitlines() if "entries_score" not in line))
    with closing(ci._connect(case)) as con:
        assert con.execute("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'entries_score'").fetchone()


# ── a folder copy's files, tied by the index the schema has ───────────────

def _folder_copy(case, monkeypatch):
    """The System32 folder of the WS01 listing extracted to a copy: two of
    its listed files (one in another letter case than the listing), one
    file the listing does not hold."""
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    folder = ci.find(case, name="System32")["rows"][0]
    root = case / "analysis" / "extracted" / "corp-ws01" / "Windows" / "System32"
    for rel in ("winevt/Logs/SECURITY.EVTX", "config/SYSTEM", "winevt/Logs/notlisted.evtx"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"x" * 16)
    return folder, root


def test_a_folder_copy_is_registered_with_one_connection_and_one_commit(case, monkeypatch):
    folder, root = _folder_copy(case, monkeypatch)
    opened = []
    real = ci._connect
    monkeypatch.setattr(ci, "_connect", lambda *a, **k: opened.append(1) or real(*a, **k))
    assert ci.record_folder_copy(case, str(root), folder["id"], 9) == 2
    assert len(opened) == 1
    src = ci.copy_source(case, str(root / "winevt" / "Logs" / "SECURITY.EVTX"))
    assert src["inner_path"] == "Windows/System32/winevt/Logs/Security.evtx" and src["host"] == "CORP-WS01"
    assert src["call_id"] == 9 and src["size"] == 16
    assert ci.copy_source(case, str(root))["entry_id"] == folder["id"]
    assert ci.copy_source(case, str(root / "winevt" / "Logs" / "notlisted.evtx")) is None
    assert len(ci.copy_paths(case)) == 3


def test_the_folder_is_tied_when_its_entry_is_gone(case, monkeypatch):
    _, root = _folder_copy(case, monkeypatch)
    assert ci.record_folder_copy(case, str(root), 999_999, 9) == 0
    assert ci._rel(case, str(root)) in ci.copy_paths(case)


def test_the_entry_lookup_is_served_by_the_host_path_index(case, monkeypatch):
    folder, _ = _folder_copy(case, monkeypatch)
    with closing(ci._connect(case)) as con:
        plan = " ".join(r[3] for r in con.execute("EXPLAIN QUERY PLAN " + ci._LIVE_ENTRY_SQL,
                                                   (folder["host"], "x", folder["image"], folder["volume"])))
        assert "entries_host_path" in plan and "entries_image_inode" not in plan
        # A row another writer left without a host is found the same way.
        con.execute("INSERT INTO entries (id, host, image, volume, path, name, inode, size, deleted, is_dir, "
                    "mtime, atime, ctime, crtime, origin, version_of, version_folder, score, class) VALUES "
                    "(900001, NULL, 'evidence/disk/other.raw', 0, 'Logs/app.log', 'app.log', '7-128-1', 1, 0, 0, "
                    "'', '', '', '', 'image', NULL, '', 0, '')")
        con.commit()
    assert ci.entry_id_of(case, "evidence/disk/other.raw", 0, "logs/APP.LOG") == 900001
    assert ci.entry_id_of(case, "evidence/disk/other.raw", 0, "logs/APP.LOG", host=None) == 900001
    sec = ci.find(case, name="Security.evtx")["rows"][0]
    assert ci.entry_id_of(case, sec["image"], sec["volume"], sec["path"].upper(), host="CORP-WS01") == sec["id"]
    assert ci.entry_id_of(case, sec["image"], sec["volume"], sec["path"]) == sec["id"]
    assert ci.entry_id_of(case, sec["image"], sec["volume"], sec["path"], host="CORP-WS09") is None


def test_a_parsers_csv_is_joined_to_the_index_at_result_time(case, monkeypatch):
    """register_exports joins the rows of the one table a parser wrote, so a
    table view can mark them partly seen (observe_result) during the run."""
    _build(case, monkeypatch, {"corp-ws01.raw": WS01})
    out = case / "analysis" / "evtx_csv"
    out.mkdir(parents=True)
    (out / "CORP-WS01.csv").write_text(
        "TimeCreated,EventId,Channel,Computer,SourceFile\n"
        "2031-01-01 00:00:01,4624,Security,CORP-WS01,C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\n",
        encoding="utf-8")
    assert ci.register_exports(case, [str(out / "CORP-WS01.csv")]) == ["analysis/evtx_csv/CORP-WS01.csv"]
    with closing(ci._connect(case)) as con:
        assert con.execute("SELECT COUNT(*) FROM sources WHERE export = ?",
                           ("analysis/evtx_csv/CORP-WS01.csv",)).fetchone()[0] == 1
    assert ci.register_exports(case, [str(out / "CORP-WS01.csv")]) == []      # unchanged: not scanned again
