"""Call ids never collide: `_next_shared_call_id` returns the maximum of
the trace's counter file, the trace's highest id plus one and the calling
log's in-memory sequence plus one, so a counter that is stale, reset or
hand-edited can never hand out an id the trace already holds. Each trace
has a counter file of its own; the counter of another trace never moves it.
"""
import json
import os
import threading
import pytest
from unittest.mock import patch


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Point all cache paths at a tmp dir so tests don't trample the real cache."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    counter = str(cache_dir / "call_id.counter")
    lock = str(cache_dir / "hook.lock")
    monkeypatch.setattr("core.execution_log._CALL_ID_COUNTER_FILE", counter)
    monkeypatch.setattr("core.execution_log._TRACE_LOCK_FILE", lock)
    return {"dir": cache_dir, "counter": counter, "lock": lock}


def test_stale_counter_does_not_produce_duplicates(isolated_cache, tmp_path):
    """Counter file says {"next": 5} but trace already has entries up to cid=100.
    Five calls to _next_shared_call_id must return 101..105 (not 5..9)."""
    from core.execution_log import _next_shared_call_id

    # Trace with cids up to 100
    trace = tmp_path / "trace.json"
    entries = [{"call_id": i, "type": "tool_call"} for i in range(1, 101)]
    trace.write_text(json.dumps({"case_id": "STALE", "entries": entries}))

    # Stale counter file
    from core.execution_log import _counter_file
    counter = _counter_file(str(trace))
    os.makedirs(os.path.dirname(counter), exist_ok=True)
    with open(counter, "w") as f:
        json.dump({"next": 5}, f)

    returned = [_next_shared_call_id(str(trace)) for _ in range(5)]
    assert returned == [101, 102, 103, 104, 105], (
        f"expected 101..105 (trace had max=100), got {returned}"
    )

    # Counter file ends pointing past the last allocation
    with open(counter) as f:
        assert int(json.load(f)["next"]) == 106


def test_in_memory_seq_protects_against_external_reset(isolated_cache, tmp_path):
    """An ExecutionLog has self._seq=50 (50 entries in memory). External
    process resets counter to {"next": 1}. Next allocation must return 51,
    not 1 — using the in_memory_seq fallback."""
    from core.execution_log import ExecutionLog
    from core import execution_log as elog_mod

    trace_path = str(tmp_path / "trace.json")
    log = ExecutionLog()
    log.configure("RESET-TEST", trace_path)
    # Hand-build 50 entries to push _seq up
    for i in range(50):
        log.record_tool_call(f"cmd-{i}", True, False, 0, 0)
    assert log._seq == 50

    # Simulate external reset of the counter — should not produce duplicates
    counter = elog_mod._counter_file(log._path)
    with open(counter, "w") as f:
        json.dump({"next": 1}, f)

    # In-memory seq protects against this
    cid = elog_mod._next_shared_call_id(log._path, in_memory_seq=log._seq)
    assert cid == 51, f"expected 51 (in_memory_seq=50), got {cid}"

    # Counter file now reflects the corrected allocation
    with open(counter) as f:
        assert int(json.load(f)["next"]) == 52


def test_concurrent_writers_no_duplicates(isolated_cache, tmp_path):
    """20 threads each call _next_shared_call_id simultaneously with the same
    trace_path (file has max cid = 100). All returned cids must be unique
    AND all ≥ 101."""
    from core.execution_log import _next_shared_call_id

    trace = tmp_path / "trace.json"
    entries = [{"call_id": i, "type": "tool_call"} for i in range(1, 101)]
    trace.write_text(json.dumps({"case_id": "CONCURRENT", "entries": entries}))

    # Stale counter
    from core.execution_log import _counter_file
    counter = _counter_file(str(trace))
    os.makedirs(os.path.dirname(counter), exist_ok=True)
    with open(counter, "w") as f:
        json.dump({"next": 5}, f)

    N = 20
    results: list[int] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(N)

    def worker():
        barrier.wait()
        cid = _next_shared_call_id(str(trace))
        with results_lock:
            results.append(cid)

    threads = [threading.Thread(target=worker) for _ in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(set(results)) == N, f"duplicates in concurrent allocation: {results}"
    assert all(c >= 101 for c in results), f"got cids below trace max+1: {[c for c in results if c < 101]}"


def test_atlas_reset_atomic(tmp_path, isolated_cache):
    """atlas_reset CLI clears all cache files and backs up the trace."""
    from tools.atlas_reset import reset

    # Set up a fake case dir
    case = tmp_path / "fake-case"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID**: FAKE-001")
    trace_path = case / "analysis" / "FAKE-001_trace.json"
    trace_path.write_text(json.dumps({"case_id": "FAKE-001", "entries": [
        {"call_id": 1, "type": "tool_call"}, {"call_id": 2, "type": "finding"},
    ]}))
    (case / "analysis" / "dashboard.url").write_text("http://localhost:8765/x")

    # Seed cache state
    with open(isolated_cache["counter"], "w") as f:
        json.dump({"next": 999}, f)
    # Patch the cache paths the reset CLI uses
    with patch("tools.atlas_reset._COUNTER_FILE", isolated_cache["counter"]), \
         patch("tools.atlas_reset._HOOK_STATE_FILE", str(isolated_cache["dir"] / "hook_state.json")), \
         patch("tools.atlas_reset._LOCK_FILE", isolated_cache["lock"]), \
         patch("tools.atlas_reset._CACHE_DIR", str(isolated_cache["dir"])):
        result = reset(str(case))

    assert result["success"] is True
    assert result["case_id"] == "FAKE-001"
    # Counter reset to 1
    with open(isolated_cache["counter"]) as f:
        assert int(json.load(f)["next"]) == 1
    # Trace gone from analysis/
    assert not trace_path.exists()
    # Dashboard URL gone
    assert not (case / "analysis" / "dashboard.url").exists()
    # Backup created
    assert result.get("backup_dir"), "expected a backup dir in result"
    assert os.path.exists(os.path.join(result["backup_dir"], "FAKE-001_trace.json"))


def test_atlas_reset_leaves_other_cases_counters_and_beacon(tmp_path, isolated_cache):
    """Resetting a case removes only its own trace's counter, and keeps a
    beacon that points at another case's live run."""
    import core.execution_log as elog
    from core.execution_log import _counter_file
    from tools.atlas_reset import reset

    cases = {}
    for name, cid in (("case-a", "CASE-A"), ("case-b", "CASE-B")):
        case = tmp_path / name
        (case / "analysis").mkdir(parents=True)
        (case / "CASE.md").write_text(f"**Case ID**: {cid}")
        trace = case / "analysis" / f"{cid}_trace.json"
        trace.write_text(json.dumps({"case_id": cid, "entries": []}))
        counter = _counter_file(str(trace))
        os.makedirs(os.path.dirname(counter), exist_ok=True)
        with open(counter, "w") as f:
            json.dump({"next": 40}, f)
        cases[name] = (case, trace, counter)
    with open(elog._SESSION_FILE, "w") as f:
        json.dump({"case_id": "CASE-B", "path": str(cases["case-b"][1])}, f)

    with patch("tools.atlas_reset._COUNTER_FILE", isolated_cache["counter"]), \
         patch("tools.atlas_reset._HOOK_STATE_FILE", str(isolated_cache["dir"] / "hook_state.json")), \
         patch("tools.atlas_reset._LOCK_FILE", isolated_cache["lock"]), \
         patch("tools.atlas_reset._CACHE_DIR", str(isolated_cache["dir"])):
        result = reset(str(cases["case-a"][0]))

    assert result["success"] is True
    assert not os.path.exists(cases["case-a"][2])
    assert os.path.exists(cases["case-b"][2])
    assert os.path.exists(elog._SESSION_FILE)

    # A beacon into the case being reset goes.
    with open(elog._SESSION_FILE, "w") as f:
        json.dump({"case_id": "CASE-B", "path": str(cases["case-b"][1])}, f)
    with patch("tools.atlas_reset._COUNTER_FILE", isolated_cache["counter"]), \
         patch("tools.atlas_reset._LOCK_FILE", isolated_cache["lock"]), \
         patch("tools.atlas_reset._CACHE_DIR", str(isolated_cache["dir"])):
        reset(str(cases["case-b"][0]))
    assert not os.path.exists(elog._SESSION_FILE)


def test_a_beacon_without_a_path_counts_as_unreadable(tmp_path):
    import core.execution_log as elog
    with open(elog._SESSION_FILE, "w") as f:
        json.dump({"case_id": "X"}, f)
    assert elog.drop_beacon_if_under(str(tmp_path / "some-case")) == (True, "")
    assert not os.path.exists(elog._SESSION_FILE)


def test_atlas_reset_refuses_when_mount_under_case(tmp_path):
    """reset() must not move/rmtree a case tree with a live mount under it —
    same hazard clear_case_run guards against."""
    from tools.atlas_reset import reset

    case = tmp_path / "fake-case"
    (case / "analysis").mkdir(parents=True)
    trace = case / "analysis" / "FAKE-001_trace.json"
    trace.write_text(json.dumps({"case_id": "FAKE-001", "entries": []}))
    base = os.path.realpath(str(case))

    proc = tmp_path / "proc_mounts"
    proc.write_text(f"/dev/loop0 {base}/mnt/dc01 ntfs ro 0 0\n", encoding="utf-8")

    # umount keeps failing → mount stays → reset must refuse and touch nothing
    with patch("core.mounts._PROC_MOUNTS", str(proc)), \
         patch("core.executor.run",
               return_value={"success": False, "stderr": "target is busy"}):
        result = reset(str(case))

    assert result["success"] is False
    assert f"{base}/mnt/dc01" in result["mounts_remaining"]
    assert trace.exists()          # tree untouched — nothing moved or deleted
