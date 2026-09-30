"""A finding changes its tier or gains ATT&CK techniques by being recorded
again, since the trace cannot be edited. A re-record that names the finding
it replaces (supersedes=) replaces it: one standing finding, carrying the
new tier and techniques. Without the name a reworded re-record stands beside
the finding, and the advisories name the pair; a fold says what it dropped."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

FINDING = ("Keylogger.exe was executed 3 times from D:\\Tools\\Keylogger.exe on HOST-A. "
           "It is a commercial keylogger, and its execution is consistent with covert monitoring.")
REWORDED = ("Keylogger.exe was executed 3 times from D:\\Tools\\Keylogger.exe on HOST-A. It is a "
            "commercial keylogger; its presence and repeated execution constitute keylogging of the "
            "user's input on this workstation during the activity window.")
OUTPUT = "RunCount 3 Path D:\\Tools\\Keylogger.exe LastRun 2024-03-27 09:33:20"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch, tmp_path):
    # A minimal ATT&CK table, so the technique gate does not depend on the
    # machine-local cache (absent on CI runners).
    from tools.mitre import _load_json
    table = tmp_path / "mitre_techniques.json"
    table.write_text(json.dumps({"techniques": {"T1056.001": {
        "name": "Input Capture: Keylogging", "tactic": "collection"}}}), encoding="utf-8")
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    _load_json.cache_clear()
    with patch("tools.misc.tool_program",
               side_effect=lambda name, *rest: f"/usr/local/bin/{name}"), \
         patch("tools.correlate.DEFAULT_MITRE_PATH", str(table)):
        yield
    _load_json.cache_clear()


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def log(case):
    lg = ExecutionLog()
    lg.configure("SUPERSEDE", str(case / "trace.json"), save_session=False)
    lg.record_dair_call("Analyze", "", False, "", "", "stay", "")
    return lg


def _record(log, case, **kw):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log), \
         patch("core.claim_graph.resolve_case_dir", return_value=str(case)), \
         patch.object(log, "case_dir", return_value=str(case)):
        return record_finding(**kw)


def _call(log):
    return log.record_tool_call("ez.pecmd -d mnt/host/fs/Windows/Prefetch", True, False, 0, 0,
                                stdout_excerpt=OUTPUT)


def _standing(case, log):
    from core.claim_graph import asserted_finding_entries, load_graph
    entries = asserted_finding_entries([e for e in log._entries if e.get("type") == "finding"],
                                       str(case))
    nodes = load_graph(str(case)).get("nodes") or {}
    return entries, nodes


def _first(log, case, cid):
    r = _record(log, case, description=FINDING, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT)
    assert r.get("success") and not r.get("duplicate"), r
    return r


def test_a_re_record_naming_the_finding_replaces_it(log, case):
    cid = _call(log)
    first = _first(log, case, cid)
    r = _record(log, case, description=REWORDED, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT, mitre_techniques=["T1056.001"],
                supersedes=str(first["_atlas_call_id"]))
    assert r.get("success") and not r.get("duplicate"), r
    assert r["superseded_claim_id"] == first["claim_id"]
    entries, nodes = _standing(case, log)
    assert len(entries) == 1
    assert any(t.get("technique_id") == "T1056.001" for t in entries[0].get("validated_techniques") or [])
    assert nodes[first["claim_id"]]["status"] == "superseded"


def test_the_claim_id_names_the_finding_too(log, case):
    cid = _call(log)
    first = _first(log, case, cid)
    r = _record(log, case, description=FINDING, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT, mitre_techniques=["T1056.001"],
                supersedes=first["claim_id"].lower())
    assert r.get("success") and not r.get("duplicate"), r
    assert r["superseded_claim_id"] == first["claim_id"]
    assert len(_standing(case, log)[0]) == 1


def test_an_unknown_or_foreign_name_is_refused(log, case):
    cid = _call(log)
    first = _first(log, case, cid)
    r = _record(log, case, description=REWORDED, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT, supersedes="C9999")
    assert not r.get("success") and r.get("gate") == "supersedes_target"
    assert "standing findings" in r["error"]
    r = _record(log, case, description=REWORDED, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-B",
                supporting_evidence=OUTPUT, supersedes=first["claim_id"])
    assert not r.get("success") and "another host" in r["error"]


def test_a_fold_says_what_it_did_not_apply(log, case):
    cid = _call(log)
    _first(log, case, cid)
    r = _record(log, case, description=FINDING, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT, mitre_techniques=["T1056.001"])
    assert r.get("duplicate")
    assert "Not applied: the techniques T1056.001" in r["note"] and "supersedes=" in r["note"]


def test_a_longer_rewording_is_recorded_and_named(log, case):
    from tools.misc import standing_duplicate_pairs
    cid = _call(log)
    first = _first(log, case, cid)
    r = _record(log, case, description=REWORDED, confidence="SUSPECTED", source="ez.pecmd",
                linked_call_id=cid, input_call_ids=[cid], host="HOST-A",
                supporting_evidence=OUTPUT)
    assert r.get("success") and not r.get("duplicate")
    assert r.get("restates_call_id") and "supersedes=" in r["restatement"]
    pairs = standing_duplicate_pairs(_standing(case, log)[1])
    assert any(p["relation"] == "elaborates" and p["older"] == first["claim_id"] for p in pairs)


def test_elaboration_is_asked_for_only_by_the_advisories():
    from tools.misc import _relation, restated_belief
    assert _relation(REWORDED, FINDING) is None
    assert _relation(REWORDED, FINDING, elaborates=True)[0] == "elaborates"
    node = {"id": "C1", "kind": "claim", "status": "new", "statement": FINDING, "host": "HOST-A"}
    assert restated_belief({"C1": node}, REWORDED, "HOST-A") is None


def test_the_nudges_name_the_replacement():
    from tools.dair import _TTP_NUDGE
    from tools.hayabusa import _MITRE_HINT
    assert "supersedes=" in _TTP_NUDGE
    assert "mitre_techniques=" in _MITRE_HINT and "validated_techniques=" not in _MITRE_HINT
