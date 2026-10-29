"""A marker or value a gate takes as evidence comes from the rows the cited
calls printed, never from the analyst's own text: not supporting_evidence,
not a call's command line, not the request a search echoes back
(tools._gates._match.lineage_evidence_text, the cite fast path of
tools._gates.confidence_and_citation). Each refusal names the SUSPECTED
route. Invented fixtures only (an FTP capture, 203.0.113.x, jane.doe, 2031)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.execution_log import ExecutionLog
from tools._gates import GateContext
from tools._gates import exfil_channel_grounding as ecg

DESC = "jane.doe exfiltrated report.zip over FTP to 203.0.113.5"


def _ctx(description, *, by_call_id=None, input_call_ids=None, supporting_evidence="", tier="LIKELY", log=None):
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier, source="test",
        linked_call_id=0, tested_hypothesis_id="", log=log or MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type={}), window=[],
        input_call_ids=input_call_ids or [], supporting_evidence=supporting_evidence)


def _grep(rows, pattern="STOR|226"):
    return {"type": "tool_call", "call_id": 9, "cmd": "<py>:table_table_grep", "success": True,
            "args": json.dumps({"path": "analysis/ftp.log", "pattern": pattern}),
            "stdout_excerpt": json.dumps({"success": True, "path": "analysis/ftp.log", "pattern": pattern,
                                          "hits": rows, "hit_count": len(rows)})}


def test_a_transfer_in_the_cited_rows_grounds_the_claim():
    entry = _grep([{"time": "2031-03-04 10:03:40", "line": "STOR report.zip"},
                   {"time": "2031-03-04 10:03:41", "line": "226 Transfer complete"}])
    assert ecg.check(_ctx(DESC, by_call_id={9: entry}, input_call_ids=[9])) is None


def test_a_transfer_typed_into_supporting_evidence_is_no_marker():
    entry = _grep([{"time": "2031-03-04 10:01:12", "line": "USER jane.doe 230 logged in"}])
    out = ecg.check(_ctx(DESC, by_call_id={9: entry}, input_call_ids=[9],
                         supporting_evidence="STOR report.zip 226 Transfer complete"))
    assert out is not None and out["gate"] == "exfil_channel_grounding"
    assert "SUSPECTED" in out["error"] and "supporting_evidence is not a row" in out["error"]


def test_the_searched_pattern_echoed_back_is_no_marker():
    """The command line and the echoed request name STOR; no row does."""
    entry = _grep([{"time": "2031-03-04 10:01:12", "line": "USER jane.doe 230 logged in"}])
    assert ecg.check(_ctx(DESC, by_call_id={9: entry}, input_call_ids=[9])) is not None


def test_a_marker_in_the_command_line_is_no_marker():
    """The analyst's own command names the transfer verbs; its output does not."""
    entry = {"type": "tool_call", "call_id": 9, "cmd": "grep -E 'STOR report.zip|226 Transfer' analysis/ftp.log",
             "success": True, "stdout_excerpt": "2031-03-04 10:01:12 USER jane.doe 230 logged in"}
    assert ecg.check(_ctx(DESC, by_call_id={9: entry}, input_call_ids=[9])) is not None


def test_a_marker_past_the_usual_read_size_is_found(tmp_path, monkeypatch):
    from core.indicators import SPILL_READ_CHARS
    spill = tmp_path / "out.txt"
    filler = "\n".join(f"2031-03-04 09:{i % 60:02d}:00 NOOP" for i in range(SPILL_READ_CHARS // 24 + 10))
    spill.write_text(filler + "\n2031-03-04 10:03:40 STOR report.zip\n2031-03-04 10:03:41 226 Transfer complete\n")
    assert spill.stat().st_size > SPILL_READ_CHARS
    entry = {"type": "tool_call", "call_id": 9, "cmd": "<py>:strings_read_text", "success": True,
             "stdout_excerpt": filler[:4000], "stdout_file": str(spill)}
    monkeypatch.setattr("core.coverage_ledger.resolved_entry", lambda case, e: e)
    assert ecg.check(_ctx(DESC, by_call_id={9: entry}, input_call_ids=[9])) is None


# ── the cite fast path: supporting_evidence names a value, a row shows it ──

@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    with patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def log(tmp_path):
    lg = ExecutionLog()
    lg.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    lg.record_dair_call("Analyze", "", False, "", "", "stay", "")
    return lg


def _record(log, desc, cids, se):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log):
        r = record_finding(desc, "LIKELY", "netstat", linked_call_id=cids[0], input_call_ids=cids,
                           supporting_evidence=se)
    entry = next((e for e in log._entries if e.get("call_id") == r.get("_atlas_call_id")), {})
    return {**r, "_entry_error": entry.get("tier_auto_downgrade_error", "")}


def _call(log, text):
    return log.record_tool_call("<py>:strings_read_text", True, False, 0, 0, stdout_excerpt=text)


def test_a_value_only_in_supporting_evidence_is_refused_with_the_suspected_route(log):
    cid = _call(log, "netstat: 198.51.100.4:443 ESTABLISHED")
    r = _record(log, "CORP-WS01 connected to 203.0.113.77:8443.", [cid], "netstat shows 203.0.113.77:8443")
    # Refused at LIKELY; the record lands one tier lower, saying why.
    assert r["success"] is True and r["confidence"] == "SUSPECTED"
    entry = next(e for e in log._entries if e.get("call_id") == r["_atlas_call_id"])
    assert entry["tier_auto_downgrade_reason"] == "confidence_and_citation"
    assert "no tool output of this run prints them" in entry["tier_auto_downgrade_error"]
    assert "record this finding at SUSPECTED" in entry["tier_auto_downgrade_error"]


def test_a_value_an_uncited_call_prints_is_not_refused_by_the_cite_check(log):
    shown = _call(log, "netstat: 203.0.113.77:8443 ESTABLISHED")
    other = _call(log, "netstat: 198.51.100.4:443 ESTABLISHED")
    r = _record(log, "CORP-WS01 connected to 203.0.113.77:8443.", [other], "netstat shows 203.0.113.77:8443")
    assert "no tool output of this run prints them" not in r["_entry_error"], (shown, r)


def test_a_value_the_cited_rows_print_passes(log):
    cid = _call(log, "netstat: 203.0.113.77:8443 ESTABLISHED")
    r = _record(log, "CORP-WS01 connected to 203.0.113.77:8443.", [cid], "netstat shows 203.0.113.77:8443")
    assert r["success"] is True


def test_an_escaped_windows_path_in_a_json_row_is_the_path(log):
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt=json.dumps(
        {"success": True, "hits": [{"Path": "C:\\Users\\Public\\agent.msi", "EventId": 7045}], "hit_count": 1}))
    r = _record(log, "A service was installed from C:\\Users\\Public\\agent.msi on CORP-WS01.", [cid],
                "7045 C:\\Users\\Public\\agent.msi")
    assert "no tool output of this run prints them" not in r["_entry_error"]


def test_a_decoded_value_counts_once_the_decode_call_prints_it(log):
    raw = _call(log, "powershell -enc QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABhAC4AbQBzAGkA")
    desc = "The encoded command names C:\\Users\\Public\\a.msi."
    before = _record(log, desc, [raw], "decoded: C:\\Users\\Public\\a.msi")
    assert "no tool output of this run prints them" in before["_entry_error"]
    dec = _call(log, "decoded: C:\\Users\\Public\\a.msi")
    after = _record(log, desc, [raw, dec], "decoded: C:\\Users\\Public\\a.msi")
    assert "no tool output of this run prints them" not in after["_entry_error"]
