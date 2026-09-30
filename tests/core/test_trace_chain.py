"""Tamper-evidence layer: output hashing + the hash-chained trace mirror.

trace.json is read-merge-rewritten per flush (past entries mutable); the
.jsonl mirror journals every entry once, chained to its predecessor, so a
reviewer can prove nothing journaled was altered afterwards.
"""
import json

import pytest

from core.execution_log import ExecutionLog, verify_trace_chain


@pytest.fixture
def trace(tmp_path):
    log = ExecutionLog()
    log.configure("CHAIN-001", str(tmp_path / "CHAIN-001_trace.json"),
                  save_session=False)
    return log, tmp_path


def _record_calls(log, n, prefix="tool"):
    for i in range(n):
        log.record_tool_call(cmd=f"{prefix} {i}", success=True,
                             truncated=False, retries=0, exit_code=0)


class TestMirror:
    def test_mirror_written_alongside_trace(self, trace):
        log, tmp = trace
        _record_calls(log, 3)
        mirror = tmp / "CHAIN-001_trace.jsonl"
        assert mirror.exists()
        lines = [json.loads(l) for l in mirror.read_text().splitlines()]
        assert len(lines) == 3
        assert lines[0]["prev_hash"] == ""
        assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
        assert lines[2]["prev_hash"] == lines[1]["entry_hash"]

    def test_verify_ok(self, trace):
        log, tmp = trace
        _record_calls(log, 5)
        log.record_finding("samplesvc.exe dropped", "CONFIRMED", "ez.mftecmd")
        result = verify_trace_chain(str(tmp / "CHAIN-001_trace.jsonl"))
        assert result["ok"] is True
        assert result["entries"] == 6

    def test_tampered_entry_detected(self, trace):
        log, tmp = trace
        _record_calls(log, 4)
        mirror = tmp / "CHAIN-001_trace.jsonl"
        lines = mirror.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["entry"]["cmd"] = "tool 1 --but-actually-something-else"
        lines[1] = json.dumps(rec)
        mirror.write_text("\n".join(lines) + "\n")
        result = verify_trace_chain(str(mirror))
        assert result["ok"] is False
        assert result["line"] == 2
        assert "altered" in result["error"]

    def test_deleted_entry_detected(self, trace):
        log, tmp = trace
        _record_calls(log, 4)
        mirror = tmp / "CHAIN-001_trace.jsonl"
        lines = mirror.read_text().splitlines()
        del lines[1]
        mirror.write_text("\n".join(lines) + "\n")
        result = verify_trace_chain(str(mirror))
        assert result["ok"] is False
        assert "chain broken" in result["error"]

    def test_entry_journaled_once_despite_reflushes(self, trace):
        # Every record_* reflushes the whole trace.json; the mirror must
        # not duplicate already-journaled entries.
        log, tmp = trace
        _record_calls(log, 2)
        _record_calls(log, 2, prefix="later")
        lines = (tmp / "CHAIN-001_trace.jsonl").read_text().splitlines()
        assert len(lines) == 4
        cmds = [json.loads(l)["entry"]["cmd"] for l in lines]
        assert len(set(cmds)) == 4

    def test_survives_process_restart(self, trace):
        # A new ExecutionLog resuming the same trace must continue the
        # chain, not fork it.
        log, tmp = trace
        _record_calls(log, 2)
        log2 = ExecutionLog()
        log2.configure("CHAIN-001", str(tmp / "CHAIN-001_trace.json"),
                       save_session=False)
        _record_calls(log2, 2, prefix="after-restart")
        result = verify_trace_chain(str(tmp / "CHAIN-001_trace.jsonl"))
        assert result["ok"] is True
        assert result["entries"] == 4

    def test_missing_file(self, tmp_path):
        result = verify_trace_chain(str(tmp_path / "nope.jsonl"))
        assert result["ok"] is False


class TestOutputHash:
    def test_hash_over_stdout(self):
        from core.executor import _output_hash
        h = _output_hash({"stdout": "some output"})
        assert h.startswith("blake2b:") and len(h) == len("blake2b:") + 64

    def test_hash_prefers_spill_file(self, tmp_path):
        from core.executor import _output_hash
        spill = tmp_path / "full.stdout"
        spill.write_bytes(b"the full output, much longer")
        h_spill = _output_hash({"stdout": "capped",
                                "stdout_file": str(spill)})
        h_capped = _output_hash({"stdout": "capped"})
        assert h_spill != h_capped

    def test_recorded_on_trace_entry(self, trace):
        log, tmp = trace
        log.record_tool_call(cmd="strings x", success=True, truncated=False,
                             retries=0, exit_code=0,
                             output_hash="blake2b:" + "0" * 64)
        entry = [e for e in log._entries if e["type"] == "tool_call"][-1]
        assert entry["output_hash"] == "blake2b:" + "0" * 64
