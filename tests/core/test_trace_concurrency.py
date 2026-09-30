"""Verify the trace flush is safe under concurrent record_* calls.

The audit flagged a hypothetical race in `_flush` (read trace JSON, merge with
in-memory, write back). In practice the read-merge-write critical section is
wrapped in an `fcntl.flock(_TRACE_LOCK_FILE, LOCK_EX)` + atomic temp-file
rename, so two callers serialise on the same lock file. This test exercises
that property: 20 concurrent record_tool_call calls all land in the trace
with unique, dense call_ids and no JSON corruption.
"""
import json
import os
import threading
import pytest

from core.execution_log import ExecutionLog


def test_concurrent_record_tool_call_no_corruption(tmp_path):
    """20 threads append simultaneously — every call_id unique, JSON intact."""
    p = str(tmp_path / "concurrent.json")
    log = ExecutionLog()
    log.configure("STRESS", p)

    N = 20
    barrier = threading.Barrier(N)
    errors: list[Exception] = []

    def worker(i: int):
        try:
            barrier.wait()  # release all threads at once
            log.record_tool_call(f"cmd-{i}", True, False, 0, 0)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"worker raised: {errors}"
    # All entries landed in memory
    assert len(log._entries) == N

    # All call_ids unique
    ids = [e["call_id"] for e in log._entries]
    assert len(set(ids)) == N, f"duplicate call_ids: {ids}"

    # Disk-state matches in-memory after final flush
    with open(p) as f:
        data = json.load(f)
    assert data["entry_count"] == N
    assert {e["call_id"] for e in data["entries"]} == set(ids)


def test_concurrent_findings_with_dair(tmp_path):
    """Mixed write workload — dair_calls + findings — still serialises correctly."""
    p = str(tmp_path / "mixed.json")
    log = ExecutionLog()
    log.configure("MIXED", p)
    # Prime a dair_call so dair_required gate is satisfiable if used elsewhere.
    log.record_dair_call(
        current_phase="Triage",
        phase_rationale="test",
        transition_recommended=False,
        next_phase="",
        transition_rationale="",
        stack_action="stay",
        investigation_focus="",
    )

    N = 10
    barrier = threading.Barrier(N)

    def worker(i: int):
        barrier.wait()
        log.record_finding(f"finding {i}", "SUSPECTED", source="test", linked_call_id=0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 1 dair_call + 10 findings
    assert len(log._entries) == 11
    finding_ids = [e["call_id"] for e in log._entries if e.get("type") == "finding"]
    assert len(set(finding_ids)) == 10


# ── Several writers of one trace ────────────────────────────────────────────
# A chat started on the case of a live run rehydrates the run's trace and
# writes it too; each writer holds only what it wrote or read.

def _two_writers(tmp_path, case_id="MULTI"):
    p = str(tmp_path / "analysis" / f"{case_id}_trace.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    a = ExecutionLog()
    a.configure(case_id, p)
    a.record_tool_call("run-0", True, False, 0, 0)
    b = ExecutionLog()
    b.configure(case_id, p)
    return p, a, b


def _disk_entries(p):
    with open(p) as f:
        return json.load(f)["entries"]


def test_writers_taking_turns_keep_each_others_entries(tmp_path):
    p, a, b = _two_writers(tmp_path)
    for i in range(3):
        a.record_tool_call(f"run-{i + 1}", True, False, 0, 0)
        b.record_tool_call(f"chat-{i}", True, False, 0, 0)
    cmds = [e.get("cmd") for e in _disk_entries(p) if e.get("type") == "tool_call"]
    assert cmds == ["run-0", "run-1", "chat-0", "run-2", "chat-1", "run-3", "chat-2"]
    ids = [e["call_id"] for e in _disk_entries(p)]
    assert len(ids) == len(set(ids))
    # Each writer's own list keeps only what it wrote or read at configure:
    # the middleware reads a tool's self-logging from that list's growth.
    assert [e.get("cmd") for e in a._entries if e.get("type") == "tool_call"] == [
        "run-0", "run-1", "run-2", "run-3"]
    assert [e.get("cmd") for e in b._entries if e.get("type") == "tool_call"] == [
        "run-0", "chat-0", "chat-1", "chat-2"]


def test_an_edit_by_one_writer_survives_the_others_flush(tmp_path):
    p = str(tmp_path / "analysis" / "EDIT_trace.json")
    os.makedirs(os.path.dirname(p))
    a = ExecutionLog()
    a.configure("EDIT", p)
    created = a.record_deferred_intent("tool_x", {"path": "/x"}, "blocked by a gate")
    b = ExecutionLog()
    b.configure("EDIT", p)                            # b reads the open intent
    assert b.resolve_deferred_intent("tool_x", {"path": "/x"}) == created["call_id"]
    b.record_tool_call("chat-1", True, False, 0, 0)   # the resolution reaches disk
    a.record_tool_call("run-1", True, False, 0, 0)    # a holds the open copy
    on_disk = [e for e in _disk_entries(p) if e.get("call_id") == created["call_id"]]
    assert on_disk[0]["status"] == "resolved"
    mine = [e for e in a._entries if e.get("call_id") == created["call_id"]]
    assert mine[0]["status"] == "resolved"
    assert a.open_deferred_intents() == []


def test_the_journal_chain_holds_across_writers(tmp_path):
    from core.execution_log import verify_trace_chain
    p, a, b = _two_writers(tmp_path)
    for i in range(3):
        a.record_tool_call(f"run-{i + 1}", True, False, 0, 0)
        b.record_tool_call(f"chat-{i}", True, False, 0, 0)
    result = verify_trace_chain(p[:-5] + ".jsonl")
    assert result["ok"] is True, result
    assert result["entries"] == len(_disk_entries(p))


def test_a_dead_runs_entries_are_not_written_back_after_a_clear(tmp_path):
    from core.execution_log import write_clear_marker
    p, _a, _b = _two_writers(tmp_path, case_id="CLEARED")
    residue = {"call_id": 900, "type": "tool_call", "ts": "2020-01-01T00:00:00+00:00",
               "cmd": "dead-run", "success": True}
    write_clear_marker(str(tmp_path))
    fresh = ExecutionLog()
    fresh.configure("CLEARED", p)
    # A stale process writes the dead run's entry back after the clear.
    with open(p) as f:
        data = json.load(f)
    data["entries"].append(residue)
    with open(p, "w") as f:
        json.dump(data, f)
    fresh.record_tool_call("new-run", True, False, 0, 0)
    cmds = [e.get("cmd") for e in _disk_entries(p)]
    assert "dead-run" not in cmds and "new-run" in cmds


def test_a_trace_of_another_case_at_the_path_is_replaced_not_merged(tmp_path):
    p = str(tmp_path / "analysis" / "x_trace.json")
    os.makedirs(os.path.dirname(p))
    with open(p, "w") as f:
        json.dump({"schema_version": "2.0", "case_id": "OTHER", "entry_count": 1,
                   "entries": [{"call_id": 5, "type": "tool_call", "cmd": "other-case",
                                "ts": "2099-01-01T00:00:00+00:00"}]}, f)
    log = ExecutionLog()
    log.configure("MINE", p)
    log.record_tool_call("mine", True, False, 0, 0)
    assert [e.get("cmd") for e in _disk_entries(p) if e.get("type") == "tool_call"] == ["mine"]


def test_a_writer_that_held_the_trace_before_a_clear_does_not_write_it_back(tmp_path):
    """Another process clears the case (clear marker, trace deleted) while
    this writer holds the trace; its next write carries only what came
    after the clear, although there is nothing on disk to merge."""
    from core.execution_log import write_clear_marker
    p = str(tmp_path / "analysis" / "STALE_trace.json")
    os.makedirs(os.path.dirname(p))
    held = ExecutionLog()
    held.configure("STALE", p)
    held.record_tool_call("dead-run", True, False, 0, 0)
    write_clear_marker(str(tmp_path))
    os.remove(p)
    held.record_tool_call("after-clear", True, False, 0, 0)
    cmds = [e.get("cmd") for e in _disk_entries(p) if e.get("type") == "tool_call"]
    assert cmds == ["after-clear"]


def test_a_run_configured_in_the_second_of_its_own_clear_keeps_its_entries(tmp_path):
    from core.execution_log import write_clear_marker
    write_clear_marker(str(tmp_path))
    p = str(tmp_path / "analysis" / "FRESH_trace.json")
    os.makedirs(os.path.dirname(p))
    run = ExecutionLog()
    run.configure("FRESH", p)
    run.record_tool_call("first", True, False, 0, 0)
    run.record_tool_call("second", True, False, 0, 0)
    cmds = [e.get("cmd") for e in _disk_entries(p) if e.get("type") == "tool_call"]
    assert cmds == ["first", "second"]
