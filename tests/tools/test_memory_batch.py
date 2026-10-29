"""Memory speed: the per-image memory batch: pass 1 (read, info,
walks), a failed walk moving its structure to its scan, answers kept in the
result store, front-moving on request, stop and disclosure at the run's
end, pauses while a foreground call runs. Invented fixtures only (an
invented image file, a fake Volatility binary, dates in 2031)."""
from __future__ import annotations

import json
import stat

import pytest

import tools.volatility as VV
from core import memory_batch as MB
from core import vol_cache as V


@pytest.fixture
def env(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence" / "mem").mkdir(parents=True)
    image = case / "evidence" / "mem" / "corp-ws01.mem"
    image.write_bytes(b"\x01" * (3 << 20))
    calls = tmp_path / "calls.txt"
    script = tmp_path / "vol.py"
    script.write_text(
        "import json, sys\n"
        "a = sys.argv[1:]\n"
        f"open({str(calls)!r}, 'a').write(' '.join(a) + '\\n')\n"
        "if a and a[0] == '--help':\n    print('Volatility 3 Framework 9.9.9'); sys.exit(0)\n"
        "plugin = a[-1]\n"
        "if plugin == 'windows.netstat':\n    sys.exit(1)\n"
        "if plugin == 'windows.info':\n"
        "    print(json.dumps([{'Variable': 'NtBuildLab', 'Value': '19041.invented'}])); sys.exit(0)\n"
        "print(json.dumps([{'Plugin': plugin, 'PID': 4242}]))\n")
    vol = tmp_path / "vol"
    vol.write_text(f"#!/bin/sh\nexec {__import__('sys').executable} {script} \"$@\"\n")
    vol.chmod(vol.stat().st_mode | stat.S_IEXEC)
    V.vol_version.cache_clear()
    monkeypatch.setattr(VV, "VOL", str(vol))
    monkeypatch.setattr(VV, "vol3_symbols", lambda: str(tmp_path / "symbols"))
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return case, str(image), calls, str(vol), str(tmp_path / "symbols")


def _manifest(case, image, vol, syms, pass2=False):
    walks, scans = MB.plan()
    d = MB.batch_dir(case)
    d.mkdir(parents=True, exist_ok=True)
    man = {"case": str(case), "images": [image], "vol": vol, "symbols": syms, "walks": walks, "scans": scans,
           "pass2": pass2, "timeouts": {image: 60}, "status": str(d / "status.json"),
           "front": str(d / "front.json"), "busy_dir": str(MB.busy_dir(case))}
    MB.manifest_path(case).write_text(json.dumps(man), encoding="utf-8")
    return man


def test_pass_one_reads_info_and_walks_and_a_failed_walk_moves_to_its_scan(env):
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    assert R.main(str(MB.manifest_path(case))) == 0
    plugins = MB.status(case)["images"][image]["plugins"]
    walks, scans = MB.plan()
    assert plugins["windows.info"] == "done" and all(plugins[w] in ("done", "failed") for w in walks)
    assert plugins["windows.netstat"] == "failed" and "windows.netscan" not in plugins   # pass 2 off: on request
    assert not any(s in plugins for s in scans)
    before = calls.read_text().count("windows.pslist")
    out = VV._vol(image, "windows.pslist")                                     # answered from the store
    assert out.get("cached_from") and calls.read_text().count("windows.pslist") == before


def test_a_queued_plugin_moves_its_image_to_the_front_and_answers_with_the_job(env, monkeypatch):
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    out = VV._vol(image, "windows.cmdline")
    assert out["deferred"] and out["job_id"] == "job-7"
    assert not calls.exists() or "windows.cmdline" not in calls.read_text()        # no second cold read
    assert json.loads((MB.batch_dir(case) / "front.json").read_text()) == [image]


def test_the_runs_end_stops_the_batch_and_discloses_what_it_did_not_run(env, monkeypatch):
    from core.investigation_exit import open_limit_lines
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    cancelled = []
    monkeypatch.setattr("tools.jobs.job_cancel", lambda job: cancelled.append(job) or {"success": True})
    MB.stop(case)
    assert cancelled == ["job-7"]
    (line,) = [x for x in open_limit_lines(case) if x.startswith("The memory batch was stopped")]
    assert "corp-ws01.mem: info" in line and "netstat" in line


def test_the_read_pauses_while_a_foreground_call_runs(env, monkeypatch):
    from tools import memory_batch_runner as R
    case, image, *_rest = env
    mark = MB.mark_busy(str(case))
    assert MB.foreground_busy(case)
    seen = []
    monkeypatch.setattr(R.time, "sleep", lambda s: (seen.append(s), MB.unmark_busy(mark)))
    assert R.warm(image, str(case)) > 0 and seen and not MB.foreground_busy(case)


def test_the_survey_header_comes_from_the_batch(env, monkeypatch):
    from core import evidence_survey as S
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    R.main(str(MB.manifest_path(case)))
    monkeypatch.setattr(MB, "ensure", lambda c, imgs: {"job_id": "job-7"})
    led = {"items": {"m": {"id": "m", "path": "evidence/mem/corp-ws01.mem", "kind": "memory"}}}
    lines, job, state = S._batch_header(case, led, led["items"]["m"])
    assert state == "finished" and job == "job-7" and "- NtBuildLab: 19041.invented" in lines


def test_with_scans_on_a_failed_walk_moves_to_its_scan_and_pass_two_scans_the_warm_image(env):
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms, pass2=True)
    assert R.main(str(MB.manifest_path(case))) == 0
    st = MB.status(case)["images"][image]
    walks, scans = MB.plan()
    assert st["plugins"]["windows.netstat"] == "failed" and st["plugins"]["windows.netscan"] == "done"
    assert all(st["plugins"][s] == "done" for s in scans) and "warm2_mb_s" in st
    assert "windows.handles" not in st["plugins"] and "windows.filescan" in scans


def test_a_repeated_deferred_call_waits_for_the_batch_and_gets_its_answer(env, monkeypatch):
    from agent.loop import _DEFERRED_RE
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    first = VV._vol(image, "windows.cmdline")
    assert first["deferred"] and _DEFERRED_RE.search(json.dumps(first)[:400])     # never memoised
    man = json.loads(MB.manifest_path(case).read_text())

    real_sleep, ran = __import__("time").sleep, []

    def batch_runs(s):                          # the batch runs the plugin while the call waits
        if ran:                                 # the plugin's own process wait sleeps too: really
            return real_sleep(s)
        ran.append(True)
        R.run_plugin(man, image, "windows.cmdline")
        MB._save_status(case, {"images": {image: {"plugins": {"windows.cmdline": "done"}}}})
    monkeypatch.setattr("time.sleep", batch_runs)
    again = VV._vol(image, "windows.cmdline")
    assert not again.get("deferred") and again.get("cached_from", {}).get("trace") == "memory batch"


def test_a_mark_of_a_dead_process_never_pauses_the_batch(env):
    import subprocess
    import sys
    case = env[0]
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    MB.busy_dir(case).mkdir(parents=True, exist_ok=True)
    (MB.busy_dir(case) / f"{p.pid}-1").touch()                  # left by a killed run
    assert not MB.foreground_busy(case)
    mark = MB.mark_busy(str(case))
    assert MB.foreground_busy(case)
    MB.unmark_busy(mark)


def test_a_scan_on_request_reads_the_image_first(env, monkeypatch):
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    warmed = []
    monkeypatch.setattr(R, "warm", lambda img, c, paced=True: warmed.append((img, paced)) or 1.0)
    VV._vol(image, "windows.psscan")
    VV._vol(image, "windows.pslist")
    assert warmed == [(image, False)]


def test_a_lanes_own_marks_pause_nothing_and_its_tools_run_niced(env, monkeypatch):
    import sys
    from core.execution_log import call_source
    from core.executor import run
    case = env[0]
    lane = MB.mark_busy(str(case), lane="coverage")
    assert not MB.foreground_busy(case)
    MB.unmark_busy(lane)
    token = call_source.set("coverage")
    try:
        out = run([sys.executable, "-c", "import os; print(os.nice(0))"], timeout=30)
    finally:
        call_source.reset(token)
    assert out["stdout"].strip() == "19"
    own = __import__("os").nice(0)
    assert run([sys.executable, "-c", "import os; print(os.nice(0))"], timeout=30)["stdout"].strip() == str(own)


def test_the_coverage_lane_waits_for_the_memory_batchs_first_pass_and_for_item_calls(env, monkeypatch):
    from core import coverage_path as CP
    case, image, calls, vol, syms = env
    _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    assert MB.pass1_running(case)
    assert CP.run_pass(None, case, []) == {"waiting": "the memory batch's first pass"}
    MB._save_status(case, {"images": {image: {"pass1": "done", "plugins": {}}}})
    assert not MB.pass1_running(case)
    mark = MB.mark_busy(str(case))                       # an item-thread call runs
    slept = []
    monkeypatch.setattr(CP.time, "sleep", lambda s: (slept.append(s), MB.unmark_busy(mark)))
    monkeypatch.setattr("core.evidence_leave.unit_format", lambda *a: "evtx")
    monkeypatch.setattr("core.evidence_leave.readers_for", lambda fmt: ["ez.evtxecmd"])
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    monkeypatch.setattr("tools.tool_capabilities.registered_tool_schemas", lambda: [
        ("ez_ez_evtxecmd", {"properties": {"evtx_path": {"type": "string"}}, "required": ["evtx_path"]}, "")])
    monkeypatch.setattr("core.contents_index.class_handles", lambda *a, **k: (["CORP-WS01::/a.evtx"], 1))
    seen = []

    class Box:
        def call(self, name, args, budget_free=False):
            seen.append((MB.foreground_busy(case), args))
            return '{"rows": [], "_atlas_call_id": 81}', False
    p = CP.parse_class(Box(), case, {"host": "CORP-WS01"}, {"label": "event logs", "files": 1})
    assert slept and seen == [(False, {"evtx_path": "CORP-WS01::/a.evtx"})] and p["parsed"] == 1 and "seconds" in p


def test_a_scan_on_requests_own_warm_read_marks_itself_busy(env, monkeypatch):
    from tools import memory_batch_runner as R
    case, image, calls, vol, syms = env
    busy = []
    monkeypatch.setattr(R, "warm", lambda img, c, paced=True: busy.append(MB.foreground_busy(c)) or 1.0)
    VV._vol(image, "windows.psscan")
    assert busy == [True] and not MB.foreground_busy(case)


def test_a_repeat_still_queued_after_its_wait_gets_new_facts_not_the_first_promise(env, monkeypatch):
    """The repeat says how long it waited, how many plugins of the image
    run first, which answers are ready, and what a repeat costs; the queued
    plugins are counted, never named; it stays deferred (never memoised) and
    names no row."""
    from agent.loop import _DEFERRED_RE
    from core.shown_rows import from_text
    case, image, calls, vol, syms = env
    man = _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    walks = man["walks"]
    MB._save_status(case, {"images": {image: {"plugins": {"windows.info": "done", walks[0]: "done"}}}})
    plugin = walks[-1]
    first = VV._vol(image, plugin)
    monkeypatch.setattr(VV, "_wait_batch", lambda *a, **k: False)              # the batch has not reached it
    again = VV._vol(image, plugin)
    assert again["deferred"] and again["still_queued"] and again["hint"] != first["hint"]
    assert _DEFERRED_RE.search(json.dumps(again)[:400])                         # never memoised
    assert f"{len(walks) - 2} plugin(s) of this image run before it" in again["hint"]
    assert again["ready"] == ["info", walks[0].split(".", 1)[-1]]
    # one wait per plugin; the reply never says a repeat waits again
    assert "It is not waited for again" in again["hint"] and "waits again" not in again["hint"]
    assert "Ready now on this image: info" in again["hint"]
    queued = [w.split(".", 1)[-1] for w in walks[1:-1]]
    assert not any(q in again["hint"] for q in queued if q not in again["ready"])   # queued plugins unnamed
    assert len(json.dumps(again)) < 700
    assert from_text("vol_pslist", {}, json.dumps(again)) == []                # no row credit



def test_a_position_is_stated_only_when_known_and_a_second_pass_scan_counts_every_first_pass(env, monkeypatch):
    """No manifest gives "not known", never a false 0; a second-pass scan
    waits for the first pass of every image."""
    case, image, calls, vol, syms = env
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    _walks, scans = MB.plan()
    assert "its place in the batch is not known" in VV._position({}, {}, image, "windows.pslist")
    other = image.replace("corp-ws01", "corp-ws09")
    man = {**_manifest(case, image, vol, syms, pass2=True), "images": [image, other]}
    states = {image: {"plugins": {"windows.info": "done"}}}
    text = VV._position(man, states, image, scans[0])
    first = 2 * (1 + len(man["walks"])) - 1                      # every first-pass plugin of both images but one
    assert f"the first pass of every image runs first ({first} plugin(s) of it left)" in text


def test_one_wait_per_plugin_then_answers_at_once_and_a_stored_answer_still_returns(env, monkeypatch):
    """The second repeat does not wait again; when the batch has run the
    plugin meanwhile, a later call gets the stored answer."""
    case, image, calls, vol, syms = env
    man = _manifest(case, image, vol, syms)
    monkeypatch.setattr(MB, "_running", lambda c: "job-7")
    VV._DEFERRED.clear()
    VV._WAITED.clear()
    waits = []
    monkeypatch.setattr(VV, "_wait_batch", lambda *a, **k: waits.append(1) or False)
    plugin = man["walks"][-1]
    VV._vol(image, plugin)                                        # deferred
    VV._vol(image, plugin)                                        # waited once: still queued
    third = VV._vol(image, plugin)                                # no second wait
    assert waits == [1] and third["still_queued"] and "waited for once already" in third["hint"]
    assert "waited_seconds" not in third                          # a reply that did not wait states no wait
    monkeypatch.setattr(VV, "_from_store", lambda *a, **k: {"success": True, "stdout": "stored answer"})
    assert VV._vol(image, plugin)["stdout"] == "stored answer" and waits == [1]
