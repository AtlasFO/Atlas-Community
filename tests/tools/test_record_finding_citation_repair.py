"""Re-recording a finding with citations that support it, where the
recorded finding's did not, is a citation repair: recorded rather than
folded as a duplicate, the earlier claim superseded by it, the hypothesis
it resolved carried over. Trace entries are immutable, so this is the only
way a finding's citations can change, and it is what the report gate asks
for. The same words with the same citations stay a duplicate."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import load_graph
from core.execution_log import ExecutionLog

ABSENCE = ("No second principal or backdoor account was identified on the "
           "controller: the Security 4720 account-creation events in the attack "
           "window show no new account; all activity traces to the attacker at "
           "203.0.113.9")
# The analyst quotes the value and cites the wrong call: the citation fill
# has nothing left to look for, so only a re-record can repair the lineage.
# (A value the analyst left uncited is found and cited at record time; see
# test_a_value_left_uncited_is_cited_to_the_call_that_holds_it.)
QUOTED = "Security log query of the window: RemoteHost 203.0.113.9"


@pytest.fixture(autouse=True)
def _no_side_helpers():
    with patch("tools.misc.tool_program",
               side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def case(tmp_path):
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    return tmp_path


@pytest.fixture
def log(case):
    l = ExecutionLog()
    l.configure("REPAIR", str(case / "trace.json"), save_session=False)
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    l.record_reason_call("reason_hypothesize", True, "H0003: a second principal", {},
                         inputs={"user_message": "is there a second principal"})
    return l


def _calls(log):
    wrong = log.record_tool_call(
        "vol -f evidence/host.mem windows.info", True, False, 0, 0,
        stdout_excerpt='[{"Variable": "Kernel Base", "Value": "0xf80162a14000"}]')
    right = log.record_tool_call(
        "<py>:table_table_query", True, False, 0, 0,
        stdout_excerpt=('{"success": true, "path": "analysis/dc_security_4720_4648_4663.csv", '
                        '"matched_rows": 11, "returned_rows": 11, "rows": [{"TimeCreated": '
                        '"2020-09-19 03:21:48", "EventId": "4648", "RemoteHost": "203.0.113.9"}]}'))
    return wrong, right


def _record(log, case, **kw):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log), \
         patch("core.claim_graph.resolve_case_dir", return_value=str(case)), \
         patch.object(log, "case_dir", return_value=str(case)):
        return record_finding(**kw)


def test_a_re_record_with_supporting_citations_is_a_repair(log, case, monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    first = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], supporting_evidence=QUOTED,
                    tested_hypothesis_id="H0003", host="DC01")
    assert first["success"] and "citation_advisory" in first
    assert first["cite_suggested_call_ids"] == [right]

    again = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=right, input_call_ids=[right], host="DC01")
    assert again["success"] is True
    assert again.get("duplicate") is not True
    assert again["repairs_call_id"] == first["_atlas_call_id"]
    assert again["tested_hypothesis_id"] == "H0003"
    assert again["superseded_claim_id"] == first["claim_id"]
    assert again["claim_id"] != first["claim_id"]
    assert "citation_advisory" not in again

    nodes = load_graph(str(case))["nodes"]
    assert nodes[first["claim_id"]]["status"] == "superseded"
    assert nodes[first["claim_id"]]["superseded_by"] == again["claim_id"]
    assert nodes[again["claim_id"]]["status"] == "new"
    entry = next(e for e in log._entries if e.get("call_id") == again["_atlas_call_id"])
    assert entry["tested_hypothesis_id"] == "H0003"
    stamped = entry.get("repairs_call_id") or (entry.get("gate_metadata") or {}).get("repairs_call_id")
    assert stamped == first["_atlas_call_id"]


def test_the_same_words_with_the_same_citations_stay_a_duplicate(log, case, monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    first = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], host="DC01")
    again = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], host="DC01")
    assert again["duplicate"] is True and again["existing_call_id"] == first["_atlas_call_id"]
    assert "citation repair" in again["note"]


def test_a_supported_finding_re_recorded_with_other_citations_is_still_a_duplicate(log, case, monkeypatch):
    """A repair replaces citations that do not support the claim. When the
    recorded ones already do, the re-record adds nothing and is folded."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    other = log.record_tool_call(
        "<py>:table_table_grep", True, False, 0, 0,
        stdout_excerpt='{"path": "analysis/dc_security_4624_4625.csv", "hits": [{"RemoteHost": "203.0.113.9", "EventId": "4624"}]}')
    _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
            linked_call_id=right, input_call_ids=[right], host="DC01")
    again = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=other, input_call_ids=[other], host="DC01")
    assert again["duplicate"] is True


def test_a_restatement_with_supporting_citations_is_a_repair_too(log, case, monkeypatch):
    """The near-duplicate guard folds the same conclusion in other words;
    when those other words come with the citations the recorded finding
    lacked, that is the repair as well."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    first = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], supporting_evidence=QUOTED,
                    host="DC01")
    reworded = ABSENCE.replace("all activity traces", "the observed activity traces")
    again = _record(log, case, description=reworded, confidence="LIKELY", source="evtx",
                    linked_call_id=right, input_call_ids=[right], host="DC01")
    assert again["success"] is True and again.get("duplicate") is not True
    assert again["repairs_call_id"] == first["_atlas_call_id"]
    assert again["superseded_claim_id"] == first["claim_id"]


def test_the_report_gate_clears_after_the_repair(log, case, monkeypatch):
    """The loop this closes: the gate blocks on the mis-cited finding, the
    re-record with the right call is recorded, and the gate stops seeing the
    earlier finding's citations."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    from tools.reasoning import _miscited_finding_entries, active_finding_entries
    wrong, right = _calls(log)
    _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
            linked_call_id=wrong, input_call_ids=[wrong], supporting_evidence=QUOTED, host="DC01")

    def _flagged():
        findings = active_finding_entries(
            [e for e in log._entries if e.get("type") == "finding"], str(case))
        return _miscited_finding_entries(findings, log._entries)

    assert len(_flagged()) == 1
    _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
            linked_call_id=right, input_call_ids=[right], host="DC01")
    assert _flagged() == []


def test_a_sharper_re_record_that_repairs_the_citation_supersedes_the_original(log, case, monkeypatch):
    """A re-record that adds an identifier is a refinement; when the finding
    it sharpens is mis-cited and the new citations support the claim, the
    original is superseded here instead of staying asserted with its wrong
    citations until the analyst supersedes it by hand."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    first = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], supporting_evidence=QUOTED,
                    tested_hypothesis_id="H0003", host="DC01")
    sharper = ABSENCE + " All 11 in-window records are explicit-credential logons (4648)."
    again = _record(log, case, description=sharper, confidence="LIKELY", source="evtx",
                    linked_call_id=right, input_call_ids=[right], host="DC01")
    assert again["success"] is True and again.get("duplicate") is not True
    assert again["refines_call_id"] == first["_atlas_call_id"]
    assert again["repairs_call_id"] == first["_atlas_call_id"]
    assert again["superseded_claim_id"] == first["claim_id"]
    assert again["tested_hypothesis_id"] == "H0003"
    assert load_graph(str(case))["nodes"][first["claim_id"]]["status"] == "superseded"


def test_a_value_left_uncited_is_cited_to_the_call_that_holds_it(log, case, monkeypatch):
    """The analyst cites the wrong call and quotes nothing: the citation
    fill finds the value in a recent call and cites that call, so the
    finding is supported at record time and no repair is owed."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    wrong, right = _calls(log)
    first = _record(log, case, description=ABSENCE, confidence="LIKELY", source="evtx",
                    linked_call_id=wrong, input_call_ids=[wrong], host="DC01")
    assert first["success"] and "citation_advisory" not in first
    entry = next(e for e in log._entries if e.get("call_id") == first["_atlas_call_id"])
    assert right in entry["input_call_ids"]
