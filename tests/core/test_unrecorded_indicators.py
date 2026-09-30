"""Indicators that recur across the run's tool output but are named by no
finding are surfaced (the seen-but-not-recorded gap), ranked by type, past a
recurrence floor, excluding the case's own files; the knowledge index shows
them; and the report gate re-checks that findings' citations support them."""
from core.call_memo import CallMemo, render_index
from core.ioc_pivots import unrecorded_evidence_indicators


def _tc(cid, text):
    return {"type": "tool_call", "call_id": cid, "success": True, "cmd": "", "stdout_excerpt": text}


def test_recurring_unrecorded_indicator_is_surfaced_recorded_one_is_not():
    entries = [
        _tc(1, "GET http://evilc2.example.test/api from host"),
        _tc(2, "beacon to http://evilc2.example.test/api again"),
        _tc(3, "http://evilc2.example.test/api a third time"),
        _tc(4, "logon from 203.0.113.9"),
        _tc(5, "203.0.113.9 seen again"),
        _tc(6, "203.0.113.9 once more"),
        _tc(7, "CORP\\attacker acted"),   # only two calls: below the floor
        _tc(8, "CORP\\attacker again"),
        {"type": "finding", "description": "malicious traffic from 203.0.113.9"},
    ]
    res = unrecorded_evidence_indicators(entries, None, min_calls=3)
    vals = [d["value"] for d in res]
    assert "http://evilc2.example.test/api" in vals   # recurring, unrecorded
    assert "203.0.113.9" not in vals                  # a finding already names it
    assert not any(v.endswith("attacker") for v in vals)  # below the call floor


def test_a_disposition_naming_the_value_rules_on_it_plain_narration_does_not():
    seen = [_tc(i, "beacon to http://evilc2.example.test/api") for i in range(1, 4)]
    plain = {"type": "investigation_narration",
             "content": "next: search the proxy log for http://evilc2.example.test/api"}
    ruled = dict(plain, kind="disposition",
                 content="http://evilc2.example.test/api searched in the proxy log: no match")
    assert [d["value"] for d in unrecorded_evidence_indicators(seen + [plain], None, min_calls=3)] \
        == ["http://evilc2.example.test/api"]
    assert unrecorded_evidence_indicators(seen + [ruled], None, min_calls=3) == []


def test_ranking_puts_network_indicators_before_internal_ips():
    entries = [_tc(i, "http://c2.example.test/x and 10.9.9.9") for i in range(1, 5)]
    res = unrecorded_evidence_indicators(entries, None, min_calls=3)
    assert res[0]["kind"] == "url" and res[0]["value"] == "http://c2.example.test/x"
    assert any(d["kind"] == "ip" for d in res)


def test_the_cases_own_files_are_not_flagged(monkeypatch):
    monkeypatch.setattr("core.ioc_pivots.case_file_names", lambda cd: {"srudb.dat"})
    entries = [_tc(i, "parsed srudb.dat and evil.exe") for i in range(1, 5)]
    res = unrecorded_evidence_indicators(entries, "/some/case", min_calls=3)
    vals = [d["value"].lower() for d in res]
    assert "evil.exe" in vals and "srudb.dat" not in vals


def test_indicators_only_in_the_retained_full_output_are_seen(tmp_path):
    # The excerpt the trace keeps is a few KB; the retained file is the
    # whole output. An address that only appears deep in the file counts.
    entries = []
    for i in range(1, 5):
        spill = tmp_path / f"call{i}.stdout"
        spill.write_text("noise\n" * 200 + "IP 10.0.0.5.51001 > 203.0.113.9.443\n")
        entries.append({"type": "tool_call", "call_id": i, "success": True, "cmd": "",
                        "stdout_excerpt": "noise", "stdout_file": str(spill)})
    res = unrecorded_evidence_indicators(entries, None, min_calls=3)
    assert "203.0.113.9" in [d["value"] for d in res]


def test_multicast_broadcast_and_link_local_are_not_indicators():
    entries = [_tc(i, "224.0.0.22 and 10.20.30.255 and 169.254.1.1 and 203.0.113.9")
               for i in range(1, 5)]
    vals = [d["value"] for d in unrecorded_evidence_indicators(entries, None, min_calls=3)]
    assert vals == ["203.0.113.9"]


def test_an_outside_address_ranks_above_a_private_one():
    entries = [_tc(i, "10.9.9.9 talks to 203.0.113.9") for i in range(1, 5)]
    res = unrecorded_evidence_indicators(entries, None, min_calls=3)
    assert [d["value"] for d in res][:2] == ["203.0.113.9", "10.9.9.9"]


def test_knowledge_index_lists_unrecorded_indicators():
    txt = render_index(CallMemo(), unrecorded=[
        {"value": "http://c2.test/a", "kind": "url", "calls": 5}])
    assert "http://c2.test/a" in txt and "named by no finding" in txt
    assert "http://c2.test/a" not in render_index(CallMemo())


def test_report_gate_flags_a_finding_whose_citation_lacks_its_identifier():
    from tools.reasoning import _findings_with_unsupported_citations
    entries = [
        {"type": "tool_call", "call_id": 10, "stdout_excerpt": "nothing relevant here"},
        {"type": "tool_call", "call_id": 11, "stdout_excerpt": "connection from 203.0.113.9"},
        {"type": "finding", "description": "traffic from 203.0.113.9 seen", "input_call_ids": [10]},
        {"type": "finding", "description": "traffic from 203.0.113.9 seen", "linked_call_id": 11},
    ]
    findings = [e for e in entries if e["type"] == "finding"]
    out = _findings_with_unsupported_citations(findings, entries)
    assert len(out) == 1 and "203.0.113.9" in out[0]


# ── what a gate may demand ──────────────────────────────────────────────
#
# A ruling can be demanded only while the demand can be met. A kind the
# evidence shows in bulk moves to a count; the sparse kinds are demanded in
# full, unless together they outrun the cap too.
import pytest

from core.ioc_pivots import UNRECORDED_DEMAND_CAP, unrecorded_demand


def _urls(n):
    return [f"http://site{i}.example.test/p" for i in range(n)]


def _demand(entries):
    return unrecorded_demand(unrecorded_evidence_indicators(entries, None))


def test_a_kind_shown_in_bulk_is_mentioned_while_sparse_kinds_are_demanded():
    text = " ".join(_urls(UNRECORDED_DEMAND_CAP + 1)) + " CORP\\jdoe 203.0.113.9"
    demand, bulk = _demand([_tc(i, text) for i in range(1, 5)])
    assert {d["kind"] for d in demand} == {"account", "ip"}
    assert {d["kind"] for d in bulk} == {"url"}
    assert len(bulk) == UNRECORDED_DEMAND_CAP + 1


def test_sparse_kinds_are_demanded_in_full():
    text = "http://a.example.test/1 http://b.example.test/2 CORP\\jdoe"
    demand, bulk = _demand([_tc(i, text) for i in range(1, 5)])
    assert len(demand) == 3 and not bulk


def test_sparse_kinds_that_together_outrun_the_cap_are_not_demanded():
    per_kind = UNRECORDED_DEMAND_CAP // 2 + 1
    text = " ".join(_urls(per_kind) + [f"user{i}@example.test" for i in range(per_kind)]
                    + [f"CORP\\acct{i}" for i in range(per_kind)])
    demand, bulk = _demand([_tc(i, text) for i in range(1, 5)])
    assert not demand and len(bulk) == 3 * per_kind


@pytest.mark.parametrize("per_kind", [1, 2, UNRECORDED_DEMAND_CAP // 2,
                                      UNRECORDED_DEMAND_CAP + 1,
                                      5 * UNRECORDED_DEMAND_CAP])
def test_no_population_can_extract_more_rulings_than_the_cap(per_kind):
    # An analyst that obeys every demand finishes, whatever the evidence
    # presents: the rulings extracted before the gate stops asking are
    # bounded by the cap, not by the size of the evidence.
    text = " ".join(_urls(per_kind)
                    + [f"user{i}@example.test" for i in range(per_kind)]
                    + [f"CORP\\acct{i}" for i in range(per_kind)]
                    + [f"203.0.{i // 250}.{i % 250 + 1}" for i in range(per_kind)]
                    + [f"tool{i}.exe" for i in range(per_kind)])
    entries = [_tc(i, text) for i in range(1, 5)]
    ruled = 0
    for _ in range(100):
        demand, _bulk = _demand(entries)
        if not demand:
            break
        entries.append({"type": "finding", "description":
                        "benign: " + " ".join(d["value"] for d in demand)})
        ruled += len(demand)
    assert not demand
    assert ruled <= UNRECORDED_DEMAND_CAP


def test_a_value_that_ends_a_sentence_counts_as_named():
    # The gate prints an account as domain/user; a finding that quotes it and
    # then stops must clear the demand, or the demand cannot be met by
    # writing exactly what was asked for.
    entries = [_tc(i, "CORP\\jdoe authenticated") for i in range(1, 5)]
    entries.append({"type": "finding", "description": "Benign: logged in as corp/jdoe."})
    assert unrecorded_evidence_indicators(entries, None, min_calls=3) == []


def test_a_crowded_kind_stays_uncountable_as_the_analyst_rules_on_it():
    # Recording the one that matters, which the bulk line invites, must not
    # turn the rest of that kind into a demand.
    text = " ".join(_urls(UNRECORDED_DEMAND_CAP + 1)) + " CORP\\jdoe"
    entries = [_tc(i, text) for i in range(1, 5)]
    entries.append({"type": "finding",
                    "description": "http://site0.example.test/p served the payload"})
    demand, bulk = _demand(entries)
    assert {d["kind"] for d in demand} == {"account"}
    assert len(bulk) == UNRECORDED_DEMAND_CAP  # one fewer, still not demanded


def test_knowledge_index_counts_bulk_indicators_without_asking_for_rulings():
    bulk = [{"value": f"http://s{i}.example.test/a", "kind": "url", "calls": 40 - i}
            for i in range(20)]
    txt = render_index(CallMemo(), unrecorded_bulk=bulk)
    assert "20 url" in txt and "http://s0.example.test/a" in txt
    assert "record each" not in txt


def test_the_runs_own_state_is_not_evidence_that_showed_an_indicator():
    """A claim snapshot or a recorded finding repeats what the analyst wrote;
    an address seen only there was not shown by the evidence."""
    own = [{"type": "tool_call", "call_id": i, "success": True, "cmd": "<py>:claim_snapshot",
            "stdout_excerpt": "statement: beacon to http://evilc2.example.test/api"}
           for i in range(1, 5)]
    assert unrecorded_evidence_indicators(own, None, min_calls=3) == []
    assert [d["value"] for d in unrecorded_evidence_indicators(
        own + [_tc(i, "GET http://evilc2.example.test/api") for i in range(10, 13)],
        None, min_calls=3)] == ["http://evilc2.example.test/api"]


def test_a_withdrawn_finding_no_longer_rules_on_its_indicator(tmp_path):
    from core.claim_graph import empty_graph, save_graph
    case = tmp_path / "case"
    case.mkdir()
    g = empty_graph("case")
    g["nodes"]["C0001"] = {"id": "C0001", "kind": "claim", "status": "withdrawn",
                           "statement": "malicious traffic from 203.0.113.9",
                           "source_finding_call_id": 9}
    save_graph(case, g)
    seen = [_tc(i, "logon from 203.0.113.9") for i in range(1, 4)]
    ruling = {"type": "finding", "call_id": 9, "description": "malicious traffic from 203.0.113.9"}
    assert unrecorded_evidence_indicators(seen + [ruling], None, min_calls=3) == []
    assert [d["value"] for d in unrecorded_evidence_indicators(seen + [ruling], case, min_calls=3)] \
        == ["203.0.113.9"]
