"""Memory speed: walks before scans, a walked class is not read,
and a walk-only class is disclosed end to end (ledger, disposition, exit
limitations). Invented fixtures only (CORP-WS01, an invented memory image
path, dates in 2031)."""
from __future__ import annotations

from core import evidence_disposition as D
from core.coverage_ledger import load_ledger, save_ledger
from tests.core.test_incident_map import _case, _trace

_MEM = "evidence/mem/corp-ws01.mem"


def _ledger(case):
    classes = {f"m#{i}": {"id": f"m#{i}", "item": "m", "label": label, "state": "pending", "files": 1}
               for i, label in enumerate(D.MEMORY_STRUCTURES)}
    save_ledger(case, {"units": {}, "items": {"m": {"id": "m", "path": _MEM, "kind": "memory", "host": "CORP-WS01",
                                                    "state": "pending"}}, "classes": classes})
    return {c["label"]: cid for cid, c in classes.items()}


def test_every_structure_has_a_walk_listed_before_its_scan():
    for label, plugins in D.MEMORY_STRUCTURES.items():
        order = D.walk_first(plugins)
        assert D.memory_cost(order[0]) == "walk", label
        assert order.index(next(p for p in order if D.memory_cost(p) == "walk")) == 0
    assert D.memory_cost("windows.netscan.NetScan") == "scan" and D.memory_cost("vol.netstat") == "walk"


def _batch_ran(case, *plugins):
    import json
    from core import memory_batch as MB
    MB.batch_dir(case).mkdir(parents=True, exist_ok=True)
    (MB.batch_dir(case) / "status.json").write_text(json.dumps({"images": {str(case / _MEM): {
        "plugins": {p: "done" for p in plugins}}}}), encoding="utf-8")


def test_a_walk_leaves_the_class_walked_and_its_scan_reads_it(tmp_path, monkeypatch):
    from core.investigation_exit import open_limit_lines
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    ids = _ledger(case)
    _batch_ran(case, "windows.netstat")
    # a wrapper's own record of a call deferred to the batch ran nothing
    log.record_tool_call("<py>:vol_netscan corp-ws01.mem windows.netscan", True, False, 0, 0,
                         stdout_excerpt='{"success": true, "deferred": true}')
    D.credit_dispositions(case)
    led = load_ledger(case)
    net = led["classes"][ids["network endpoints"]]
    assert net["state"] == "walked" and led["items"]["m"]["state"] == "partial"
    ok, detail = D.disposition_complete(case)
    assert detail["walked_only"] == [f"{_MEM}: network endpoints"]
    assert any("network endpoints: walk only, scan not run" in x for x in D.report_lines(case))
    assert any(x.startswith("Memory structures walked only") and "network endpoints" in x
               for x in open_limit_lines(case))
    _batch_ran(case, "windows.netstat", "windows.netscan")
    D.credit_dispositions(case)
    assert load_ledger(case)["classes"][ids["network endpoints"]]["state"] == "read"
    assert not D.walked_only(load_ledger(case))


def test_a_scan_run_on_request_reads_the_class_and_a_batch_without_status_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MEMORY_BATCH_SCANS", "0")
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    ids = _ledger(case)
    _batch_ran(case, "windows.netstat")                      # pass 2 off: the batch walked only
    log.record_tool_call(f"vol -f {_MEM} -r json windows.psscan", True, False, 0, 0, stdout_excerpt="[]")
    D.credit_dispositions(case)
    led = load_ledger(case)
    assert led["classes"][ids["processes"]]["state"] == "read"
    assert led["classes"][ids["network endpoints"]]["state"] == "walked"
    import json
    from core import memory_batch as MB
    (MB.batch_dir(case) / "status.json").write_text(json.dumps({"images": {}}), encoding="utf-8")
    log.record_tool_call(f"vol -f {_MEM} -r json windows.cmdline", True, False, 0, 0, stdout_excerpt="[]")
    D.credit_dispositions(case)
    assert load_ledger(case)["classes"][ids["command lines"]]["state"] == "walked"


def test_the_triage_names_the_walk_and_offers_the_scan_as_deeper(tmp_path, monkeypatch):
    from core import evidence_triage as TR
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _ledger(case)
    led = load_ledger(case)
    msg = TR.triage_message(case, led, led["items"]["m"], "s")
    assert "network endpoints" in msg and "walk: netstat; deeper: netscan finds unlinked and freed objects" in msg
    assert D.walk_first(D.MEMORY_STRUCTURES["network endpoints"])[0] == "netstat"


def test_with_pass_two_off_every_memory_class_stays_walked_and_is_disclosed(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MEMORY_BATCH_SCANS", "0")
    from core import memory_batch as MB
    from core.investigation_exit import completion_disclosure, open_limit_lines
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _ledger(case)
    walks, _scans = MB.plan()
    _batch_ran(case, "windows.info", *walks)                # the batch's pass 1 only
    D.credit_dispositions(case)
    led = load_ledger(case)
    assert {c["state"] for c in led["classes"].values()} == {"walked"}
    assert len(completion_disclosure(case)["evidence_disposition"]["walked_only"]) == len(D.MEMORY_STRUCTURES)
    assert sum("walk only, scan not run" in x for x in D.report_lines(case)) == len(D.MEMORY_STRUCTURES)
    assert any(x.startswith("Memory structures walked only") for x in open_limit_lines(case))


def test_a_file_writer_is_never_the_walk_and_psxview_is_a_scan(tmp_path, monkeypatch):
    from core import evidence_triage as TR
    from core import memory_batch as MB
    files = D.MEMORY_STRUCTURES["file objects"]
    assert D.first_walk(files) == "handles" and D.walk_first(files)[-1] == "dumpfiles"
    walks, scans = MB.plan()
    assert "windows.handles" not in walks and "windows.filescan" in scans    # warm: its scan reads it
    monkeypatch.setenv("ATLAS_MEMORY_BATCH_SCANS", "0")
    walks, _scans = MB.plan()
    assert "windows.handles" in walks and not any("dumpfiles" in w for w in walks)
    assert D.memory_cost("windows.psxview.PsXView") == "scan"
    case = _case(tmp_path)
    _trace(case, monkeypatch)
    _ledger(case)
    led = load_ledger(case)
    assert "walk: handles; deeper: filescan" in TR.triage_message(case, led, led["items"]["m"], "s")
