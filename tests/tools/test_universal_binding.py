"""An absence stays held to every truncated cited call the artifact-scope
rule binds: what it says is missing is not in the rows, so no term test can
free it. A universal that is no absence rests on a cut call only when the
call is about it: a specific term of the sentence (an entity, a file or
identifier name, a number) stands in the call's request or in the rows it
printed, or a plain word of it in the call's request; one that names no
such term rests on no one call. Never wider than the
artifact-scope rule: no new binding. The analyst's own progress (the means
tried) is no claim about the evidence; an absence from the rows read is. Invented fixtures only
(CORP-WS01, jane.doe, 2031)."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tools._gates import GateContext
from tools._gates import universal_from_truncated as g


def _ctx(description, entries, cited):
    return GateContext(
        description=description, confidence="LIKELY", tier="LIKELY", source="test", linked_call_id=0,
        tested_hypothesis_id="", log=None, idx=SimpleNamespace(by_call_id=entries), window=[],
        input_call_ids=cited, supporting_evidence="")


def _cut(cmd, args, excerpt):
    return {"type": "tool_call", "cmd": cmd, "args": json.dumps(args), "stdout_excerpt": excerpt,
            "view_truncated": True, "view_omitted_chars": 4000}


STRINGS_DOC = _cut("strings -a -n 6 analysis/carve/doc/00001.ole", {},
                   "the meeting moved to Friday\nplease bring the printed copies")
GREP_4724 = _cut("<py>:table_table_grep", {"path": "analysis/ws01/security.csv", "pattern": "4724|4723"},
                 '{"hits": [{"EventId": 4624, "TargetUserName": "jane.doe"}]}')
GREP_A = _cut("<py>:table_table_grep", {"path": "analysis/ws01/alpha.log", "pattern": "error"},
              '{"hits": [{"line": "alpha.log 2031-03-04 09:00 error disk"}]}')
PCAP = _cut("tcpdump -r analysis/pcap/one.pcap -nn", {}, "09:00:01 IP 203.0.113.5.21 > 203.0.113.9.4455")


def test_the_run_s_own_means_is_progress_not_an_absence():
    s = "Steganographic payloads were not recovered with the passphrases tried."
    assert g._progress(s)
    assert g.check(_ctx(s, {1: STRINGS_DOC}, [1])) is None


def test_an_absence_from_the_rows_read_is_still_held_to_the_cut_call():
    """"Not shown by these rows" of a cut call: an unseen row could show it."""
    s = "The delivery vector, phishing or other, is not shown by these rows."
    assert not g._progress(s)
    assert g.check(_ctx(s, {1: STRINGS_DOC}, [1])) is not None


def test_a_bare_passive_negation_is_still_a_claim_about_the_evidence():
    for s in ("The registry hive was not parsed.", "No file was opened.",
              "The archive was not recovered from the image."):
        assert not g._progress(s), s


UNFILTERED = _cut("<py>:table_table_query", {"path": "analysis/ws01/logons.csv"},
                  '{"rows": [{"EventId": 4624, "TargetUserName": "bob"}]}')


def test_a_universal_over_an_unfiltered_cut_query_stays_bound():
    """The query read the whole log; the sentence's terms would sit in its
    unseen rows, so their absence from the seen ones frees nothing."""
    r = g.check(_ctx("Every logon for jane.doe came from 203.0.113.5.", {1: UNFILTERED}, [1]))
    assert r is not None and r["incomplete_call_id"] == 1


def test_a_universal_over_a_cut_search_for_something_else_is_released():
    grep = _cut("<py>:table_table_grep", {"path": "analysis/ws01/logons.csv", "pattern": "4625"},
                '{"hits": [{"EventId": 4625, "TargetUserName": "bob"}]}')
    assert g.check(_ctx("Every logon for jane.doe came from 203.0.113.5.", {1: grep}, [1])) is None


def test_a_universal_about_another_subject_does_not_rest_on_the_cut_call():
    """"Only" over a share, cited beside a cut grep of a log: the grep's
    request and rows hold none of its terms."""
    s = "The share is reachable only from CORP-SRV02."
    assert g.check(_ctx(s, {1: GREP_A}, [1])) is None


def test_a_sentence_about_another_file_does_not_rest_on_the_cut_call():
    s = "No error was logged in beta.log."
    assert g.check(_ctx(s, {1: GREP_A}, [1])) is None
    assert g.check(_ctx("No disk error was logged in alpha.log after 09:00.", {1: GREP_A}, [1])) is not None


LOGONS = _cut("<py>:table_table_query", {"path": "analysis/ws01/logons.csv", "where": ["TargetUserName=jane.doe"]},
              '{"rows": [{"EventId": 4624, "TargetUserName": "jane.doe", "Host": "CORP-WS01"}]}')


@pytest.mark.parametrize("sentence", ["No 4625 events for jane.doe were found.",
                                      "No failed logons for jane.doe were found.",
                                      "jane.doe never logged on to the server."])
def test_an_absence_over_a_cut_query_is_refused_whatever_its_terms(sentence):
    """The over-claim the gate exists for: the term of an absence is not in
    the rows the cut query printed, which says nothing about the unseen
    middle."""
    r = g.check(_ctx(sentence, {1: LOGONS}, [1]))
    assert r is not None and r["incomplete_call_id"] == 1


def test_a_number_list_binds_to_the_search_for_it():
    r = g.check(_ctx("No 4724/4723 events for jane.doe were found.", {1: GREP_4724}, [1]))
    assert r is not None and r["incomplete_call_id"] == 1
    assert "names nothing call 1 read" not in r["error"]


def test_a_term_less_absence_stays_held_to_the_cut_call():
    r = g.check(_ctx("No earlier attacker activity has been found.", {1: STRINGS_DOC}, [1]))
    assert r is not None and "No earlier attacker activity" in r["error"]
    assert "cite that complete search (input_call_ids) in place of call 1" in r["error"]


def test_a_term_less_universal_over_items_is_not_held_to_one_cut_call():
    assert g.check(_ctx("All three captures carry file transfers.", {1: PCAP}, [1])) is None


def test_no_new_binding_beyond_the_artifact_scope():
    """The sentence names gamma.log and shares a time with the cut call's
    rows, but the call read alpha.log: the artifact scopes do not meet, so
    the shared time binds nothing."""
    s = "No disk error occurred in gamma.log at 2031-03-04 09:00."
    assert g.check(_ctx(s, {1: GREP_A}, [1])) is None
