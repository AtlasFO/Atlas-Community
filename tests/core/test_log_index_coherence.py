"""LogIndex must not go stale when _entries is mutated directly."""
from __future__ import annotations


def test_index_rebuilds_after_direct_entries_mutation(tmp_path):
    from core.execution_log import ExecutionLog

    log = ExecutionLog()
    log.configure("IDX", str(tmp_path / "t.json"), save_session=False)
    log._entries.append({"call_id": 99, "type": "dair_call", "current_phase": "Collect"})
    idx1 = log.index()
    assert 99 in idx1.by_call_id

    # Probe/test pattern: clear + reseed without _append_entry
    log._entries.clear()
    log._entries.append({"call_id": 1, "type": "dair_call", "current_phase": "Collect"})
    log._entries.append({"call_id": 2, "type": "tool_call", "success": True})
    idx2 = log.index()
    assert 1 in idx2.by_call_id
    assert 2 in idx2.by_call_id
    assert 99 not in idx2.by_call_id


def test_gate_success_path_reachable_after_refuse_scenarios():
    import tempfile
    import pytest
    probe_gates = pytest.importorskip(
        "devtools.validation.gate_probe",
        reason="devtools/ is a dev-only platform, not shipped in every distribution"
    ).probe_gates

    r = probe_gates(tempfile.mkdtemp())
    success = r.coverage["gates_fired"].get("success_path_minimal") or {}
    assert success.get("passed") is True, success
    assert not any(f.id == "GATE-SUCCESS-UNREACHABLE" for f in r.findings)
