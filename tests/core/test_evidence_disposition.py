"""Evidence disposition (ATLAS_EVIDENCE_DISPOSITION): the item,
class and artefact levels of the coverage ledger. Invented fixtures only
(CORP-WS01, CORP-WS02, jane.doe)."""
from __future__ import annotations

import json

from core.coverage_ledger import build_coverage_ledger, coverage_stats, load_ledger, save_ledger
from core.evidence_disposition import disposition_stats
from tests.core.test_contents_index import _body, _build, _image, _links, _plan, _two_hosts, case  # noqa: F401

WS = [_body("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", 67_108_864),
      _body("Windows/System32/config/SYSTEM", "201-128-1", 12_582_912),
      _body("Users/jane.doe/NTUSER.DAT", "202-128-1", 2_097_152),
      _body("Users/jane.doe/mail/box.pst", "203-128-1", 4_096)]


def _built(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS})
    tree = case / "evidence" / "corp-ws02-collection" / "C" / "Windows" / "System32" / "winevt" / "Logs"
    tree.mkdir(parents=True)
    (tree / "System.evtx").write_bytes(b"\0" * 70000)
    return build_coverage_ledger(case)


def test_items_and_their_classes_start_pending(case, monkeypatch):
    led = _built(case, monkeypatch)
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    assert image["level"] == "item" and image["state"] == "pending" and image["host"] == "CORP-WS01"
    labels = {c["label"] for c in led["classes"].values() if c["item"] == image["id"]}
    assert "email" in labels and any("registry" in x for x in labels) and len(labels) >= 4
    tree = next(i for i in led["items"].values() if i["kind"] in ("tree", "file"))
    assert any(c["item"] == tree["id"] for c in led["classes"].values())
    assert all(u["level"] == "artefact" for u in led["units"].values())
    stats = coverage_stats(led)
    assert stats["item_pending"] == len(led["items"]) and stats["class_pending"] == len(led["classes"])
    assert stats["item_read"] == 0                          # surveyed or not, pending is never touched


def test_a_disposition_survives_a_rebuild_and_blocked_migrates_to_pending(case, monkeypatch):
    led = _built(case, monkeypatch)
    cid = next(iter(led["classes"]))
    led["classes"][cid].update(state="left", reason_kind="duplicate_of", reason="same as the other copy")
    uid = next(iter(led["units"]))
    for k in ("state", "reason_kind", "reason", "proof_call_ids", "scope_fingerprint", "acknowledged_entities"):
        led["units"][uid].pop(k, None)                      # a ledger written before the disposition
    led["units"][uid].update(status="blocked", note="model said it cannot be read")
    save_ledger(case, led)
    again = build_coverage_ledger(case)
    assert again["classes"][cid]["state"] == "left"
    u = again["units"][uid]
    assert u["status"] == "unseen" and u["state"] == "pending" and u["migrated_from"] == "blocked"
    assert coverage_stats(again)["blocked"] == 0             # never counted settled before a read or a leave
    assert u["reason"] == "model said it cannot be read"


def test_switch_off_builds_no_disposition(case, monkeypatch):
    monkeypatch.setenv("ATLAS_EVIDENCE_DISPOSITION", "0")
    led = _built(case, monkeypatch)
    assert "classes" not in led and "item_pending" not in coverage_stats(led)
    assert disposition_stats({})["item"]["pending"] == 0


# ── the survey ───────────────────────────────────────────────────

def test_the_survey_shows_each_items_shape_and_is_cached(case, monkeypatch):
    import zipfile
    from core import evidence_survey as S
    (case / "evidence" / "app.log").write_text("2031-01-01 boot\n2031-01-02 start\n2031-01-09 stop\n")
    with zipfile.ZipFile(case / "evidence" / "kit.zip", "w") as z:
        z.writestr("Windows/Prefetch/A.EXE-1.pf", b"x" * 10)
        z.writestr("notes.txt", b"y")
    led = _built(case, monkeypatch)
    out = S.survey_all(case, led)
    by_path = {led["items"][i]["path"]: s["text"] for i, s in out.items()}
    image = by_path["evidence/disk/corp-ws01.raw"]
    assert image.startswith("ITEM evidence/disk/corp-ws01.raw (image, host CORP-WS01)")
    assert "CORP-WS01:" in image and "content classes:" in image and "- email: 1 files" in image
    log = by_path["evidence/app.log"]
    assert "text: 3 lines" in log and "first line: 2031-01-01 boot" in log and "last line: 2031-01-09 stop" in log
    assert "archive: 2 files" in by_path["evidence/kit.zip"]
    assert all(len(t) <= S.MAX_SURVEY_CHARS for t in by_path.values())
    calls = []
    monkeypatch.setattr(S, "_log_sample", lambda p: calls.append(p) or [])
    S.survey_all(case, led)
    assert calls == []                                      # unchanged items come from the cache


def test_a_memory_header_is_one_background_job_read_when_it_finishes(case, monkeypatch, tmp_path):
    monkeypatch.setenv("ATLAS_MEMORY_BATCH", "0")          # the switch-off path: one info job per image
    from core import evidence_survey as S
    from tools import jobs as J
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    started = []
    monkeypatch.setattr(J, "_start_job", lambda kind, params: started.append(kind) or {"job_id": "j1"})
    monkeypatch.setattr(J, "_load_job", lambda job: (job_dir, {}, None))
    state = {"s": "running"}
    monkeypatch.setattr(J, "_job_state", lambda d, m: state["s"])
    item = {"id": "m", "path": "evidence/mem/corp-ws01.mem", "kind": "memory", "host": "CORP-WS01"}
    cache: dict = {}
    first = S.survey_item(case, {}, item, cache)
    assert "pending (background job j1)" in first["text"] and started == ["memory_info"]
    state["s"] = "finished"
    (job_dir / "stdout.log").write_text('[{"Variable": "NtBuildLab", "Value": "19041.example"}]')
    done = S.survey_item(case, {}, item, cache)
    assert "- NtBuildLab: 19041.example" in done["text"] and started == ["memory_info"]



# ── credited, never stated ───────────────────────────────────────────────

def test_read_and_partial_come_from_the_evidence(case, monkeypatch):
    from core import contents_index as ci
    from core.evidence_disposition import credit_dispositions
    from core.evidence_leave import set_disposition
    led = _built(case, monkeypatch)
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    assert set_disposition(case, image["path"], "read")["success"] is False      # never stated
    labels = {c["label"]: c["id"] for c in led["classes"].values() if c["item"] == image["id"]}
    reg = next(lbl for lbl in labels if "registry" in lbl)
    monkeypatch.setattr(ci, "read_state_by_class", lambda c, imgs, files=None: {img: {
        reg: {"total": 2, "read": 2, "partial": 0}, "email": {"total": 4, "read": 1, "partial": 0}} for img in imgs})
    labels.setdefault("email", None)
    changed = credit_dispositions(case)
    after = load_ledger(case)
    assert after["classes"][labels[reg]]["state"] == "read"
    assert after["items"][image["id"]]["state"] == "partial" and image["id"] in changed


def test_an_image_class_moves_from_partial_to_read_with_its_reads(case, monkeypatch):
    from core import contents_index as ci
    from core.evidence_disposition import credit_dispositions
    led = _built(case, monkeypatch)
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    own = [c for c in led["classes"].values() if c["item"] == image["id"]]
    counts = {c["label"]: {"total": 2, "read": 1, "partial": 0} for c in own}
    monkeypatch.setattr(ci, "read_state_by_class", lambda c, imgs, files=None: {img: counts for img in imgs})
    credit_dispositions(case)
    after = load_ledger(case)
    assert {after["classes"][c["id"]]["state"] for c in own} == {"partial"}
    assert after["items"][image["id"]]["state"] == "partial"
    assert all(after["classes"][c["id"]]["credited"] == "1 of 2 files read" for c in own)
    for n in counts.values():
        n["read"] = 2
    credit_dispositions(case)
    after = load_ledger(case)
    assert {after["classes"][c["id"]]["state"] for c in own} == {"read"}
    assert after["items"][image["id"]]["state"] == "read"

def test_a_mail_store_counted_by_its_suffix_is_credited_by_its_read(case, monkeypatch):
    """A format class the disposition counts by name (a mail store the index
    gives no class) is counted by the read credit the same way."""
    import core.execution_log as elog
    from core import contents_index as ci
    from core.evidence_disposition import credit_dispositions
    led = _built(case, monkeypatch)
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    email = next(c for c in led["classes"].values() if c["item"] == image["id"] and c["label"] == "email")
    assert ci.read_state_by_class(case, [image["path"]])[image["path"]]["email"]["read"] == 0
    elog.log.record_tool_call("<py>:misc_pff_export", True, False, 0, 0)
    elog.log._entries[-1].update(mcp_tool="misc_pff_export", args=json.dumps(
        {"pst_path": f"{image['path']}::Users/jane.doe/mail/box.pst"}))
    counts = ci.read_state_by_class(case, [image["path"]])[image["path"]]["email"]
    assert counts["total"] == email["files"] == 1 and counts["read"] == 1
    credit_dispositions(case)
    assert load_ledger(case)["classes"][email["id"]]["state"] == "read"

def test_one_pass_reads_the_trace_once_and_the_index_through_its_indexes(case, monkeypatch):
    import sqlite3
    from contextlib import closing

    import core.execution_log as elog
    from core import artifact_value as AV
    from core import contents_index as ci
    from core.evidence_disposition import credit_dispositions
    _two_hosts(case, monkeypatch)
    with closing(sqlite3.connect(ci.db_path(case))) as con:          # an index from before the two indexes
        con.executescript("DROP INDEX sources_entry_id; DROP INDEX entries_version_of;")
    build_coverage_ledger(case)
    handle = "evidence/disk/corp-ws01.raw::Windows/System32/winevt/Logs/Security.evtx"
    token = elog.current_mcp_tool.set("ez_evtxecmd")
    try:
        elog.log.record_tool_call(cmd=f"EvtxECmd -f {handle}", success=True, truncated=False, retries=0,
                                  exit_code=0)
    finally:
        elog.current_mcp_tool.reset(token)
    parses = []
    real = AV._trace_calls
    monkeypatch.setattr(AV, "_trace_calls", lambda c: parses.append(c) or real(c))
    credit_dispositions(case)
    assert len(parses) == 1                                           # both images, one pass over the trace
    assert ci.read_state_by_class(case, []) == {} and len(parses) == 1          # no image, no pass
    label = str(ci.find(case, name="Security.evtx")["rows"][0]["class"]).removesuffix(" (appears empty)")
    after = load_ledger(case)
    state = {after["items"][c["item"]]["host"]: c["state"] for c in after["classes"].values()
             if c["label"] == label}
    assert state == {"CORP-WS01": "read", "CORP-SRV02": "pending"}         # the read is WS01's alone
    with closing(sqlite3.connect(ci.db_path(case))) as con:          # the connect migrated the index
        plans = [" ".join(r[-1] for r in con.execute("EXPLAIN QUERY PLAN " + q, (1,))) for q in (
            "SELECT * FROM sources WHERE entry_id IN (?)",
            "SELECT version_of, COUNT(*) FROM entries WHERE version_of IN (?) GROUP BY version_of",
            "SELECT id FROM entries WHERE version_of IS NULL AND score >= ?")]
    assert "sources_entry_id" in plans[0] and "entries_version_of" in plans[1]
    assert "entries_version_of" not in plans[2]                # partial: a live-entry filter keeps its scan


def test_a_memory_structure_is_walked_by_its_walk_and_read_by_its_scan(case, monkeypatch):
    monkeypatch.setenv("ATLAS_MEMORY_BATCH", "0")          # credit from the trace when the batch is off
    from core import evidence_disposition as D
    led = _built(case, monkeypatch)
    led["items"]["m"] = {"id": "m", "path": "evidence/mem/corp-ws01.mem", "kind": "memory", "host": "CORP-WS01",
                         "state": "pending"}
    from core.evidence_disposition import build_disposition
    build_disposition(case, led, led, [])
    save_ledger(case, led)
    mem = {c["label"] for c in led["classes"].values() if c["item"] == "m"}
    assert mem == set(D.MEMORY_STRUCTURES)
    monkeypatch.setattr(D, "_successful_calls", lambda c: ["vol -f evidence/mem/corp-ws01.mem windows.pslist"])
    D.credit_dispositions(case)
    after = load_ledger(case)
    states = {c["label"]: c["state"] for c in after["classes"].values() if c["item"] == "m"}
    assert states["processes"] == "walked" and states["network endpoints"] == "pending"
    monkeypatch.setattr(D, "_successful_calls", lambda c: ["vol -f evidence/mem/corp-ws01.mem windows.pslist",
                                                          "vol -f evidence/mem/corp-ws01.mem windows.psscan"])
    D.credit_dispositions(case)
    states = {c["label"]: c["state"] for c in load_ledger(case)["classes"].values() if c["item"] == "m"}
    assert states["processes"] == "read"


def test_a_class_whose_files_all_appear_empty_is_left_by_code(case, monkeypatch):
    led = _built(case, monkeypatch)
    from core.evidence_disposition import build_disposition
    image = next(i for i in led["items"].values() if i["kind"] == "image")
    monkeypatch.setattr("core.evidence_disposition._image_classes",
                        lambda root, item: {"quiet log": {"files": 3, "empty": 3}})
    build_disposition(case, led, {}, [])
    unit = next(c for c in led["classes"].values() if c["item"] == image["id"])
    assert unit["state"] == "left" and unit["reason_kind"] == "empty" and "appear empty" in unit["reason"]


def test_memory_headers_run_two_at_a_time_and_a_failure_is_retried_once(case, monkeypatch, tmp_path):
    monkeypatch.setenv("ATLAS_MEMORY_BATCH", "0")          # the switch-off path: one info job per image
    from core import evidence_survey as S
    from tools import jobs as J
    started = []
    states: dict = {}
    monkeypatch.setattr(J, "_start_job", lambda kind, params: started.append(params["image_path"]) or {
        "job_id": f"j{len(started)}"})
    monkeypatch.setattr(J, "_load_job", lambda job: (tmp_path, {"job": job}, None))
    monkeypatch.setattr(J, "_job_state", lambda d, m: states.get(m["job"], "running"))
    cache: dict = {}
    items = [{"id": f"m{i}", "path": f"evidence/mem/h{i}.mem", "kind": "memory", "host": ""} for i in range(3)]
    out = [S.survey_item(case, {}, it, cache) for it in items]
    assert len(started) == 2 and out[2]["state"] == "queued"
    states["j1"] = "failed"
    S.survey_item(case, {}, items[0], cache)             # the failed one is noted
    again = S.survey_item(case, {}, items[2], cache)      # a slot is free now
    assert again["state"] == "running" and len(started) == 3
    assert S.survey_item(case, {}, items[0], cache)["state"] == "queued"   # two still run
    states["j2"] = "finished"
    S.survey_item(case, {}, items[1], cache)
    retry = S.survey_item(case, {}, items[0], cache)
    assert retry["retries"] == 1 and len(started) == 4
    states["j4"] = "failed"
    S.survey_item(case, {}, items[0], cache)
    assert S.survey_item(case, {}, items[0], cache)["state"] == "failed" and len(started) == 4


def test_a_large_log_is_estimated_not_read_whole(case, monkeypatch, tmp_path):
    from core import evidence_survey as S
    monkeypatch.setattr(S, "_COUNT_BYTES", 1000)
    p = tmp_path / "big.log"
    p.write_text("".join(f"2031-01-01 line {i:05d}\n" for i in range(500)))
    lines = S._log_sample(p)
    assert lines[0].startswith("text: about ") and "estimated" in lines[0]


def test_reopen_clears_the_leave_kind_and_counts():
    from core.evidence_disposition import reopen
    unit = {"state": "left", "reason_kind": "out_of_scope", "reason": "kept", "reopened": 1}
    reopen(unit, "reopened: a new attacker value")
    assert unit == {"state": "pending", "reason_kind": "", "reason": "reopened: a new attacker value", "reopened": 2}


def test_a_read_item_with_no_classes_is_not_listed_as_not_analysed(tmp_path):
    """A capture has no class units. Read, it is analysed and the "not
    analysed" section says nothing about it; one still pending is named."""
    from core.coverage_ledger import empty_ledger, save_ledger
    from core.evidence_disposition import report_lines
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    data = empty_ledger("CASE-A")
    data["classes"] = {}
    data["items"] = {
        "evidence/corp-ws01.pcap": {"path": "evidence/corp-ws01.pcap", "host": "", "state": "read",
                                    "reason_kind": "", "reason": "a call read its content",
                                    "kind": "capture", "proof_call_ids": ["7"]},
        "evidence/corp-ws02.pcap": {"path": "evidence/corp-ws02.pcap", "host": "", "state": "pending",
                                    "reason_kind": "", "reason": "", "kind": "capture", "proof_call_ids": []},
    }
    save_ledger(case, data)
    lines = report_lines(case, "en")
    # The read capture is named only by the depth section (by itself, as
    # one cheap class decided), never as not analysed.
    assert all("cheap 1/1" in ln for ln in lines if "corp-ws01.pcap" in ln)
    assert any("corp-ws02.pcap" in ln and "no content classes known" in ln for ln in lines)
