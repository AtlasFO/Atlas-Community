"""The report gate's citation check on absence findings: a well-founded
negative citing the complete search that would have found what it says is
missing is not mis-cited; one resting on a truncated search, or on no
search, is."""
from __future__ import annotations

from tools.reasoning import _miscited_finding_entries


def _call(cid, cmd, excerpt="", **extra):
    e = {"type": "tool_call", "call_id": cid, "cmd": cmd, "success": True,
         "truncated": False, "stdout_excerpt": excerpt}
    e.update(extra)
    return e


def _finding(cid, description, cited, confidence="LIKELY"):
    return {"type": "finding", "call_id": cid, "description": description,
            "confidence": confidence, "input_call_ids": list(cited),
            "linked_call_id": cited[0] if cited else 0}


QUERY = _call(206, "<py>:table_table_query",
              '{"path": "analysis/dc_security_4624_4625.csv", "matched_rows": 11, '
              '"returned_rows": 11, "rows": [{"EventId": "4624", "TimeCreated": "2020-09-19 03:21:48"}]}')
CUT_GREP = _call(214, "sudo ngrep -q -I evidence/network/capture.pcap -i POST tcp",
                 "T 10.0.0.5:49694 -> 203.0.113.9:443 [AP] POST /x", truncated=True)
NOTE = {"type": "reason_call", "call_id": 300, "tool": "reason_synthesize",
        "conclusion": "no second principal"}

NEGATIVE = ("No second principal or backdoor account was identified: the Security "
            "4720 events in the attack window show no new account and no logon by "
            "any created account")


def test_a_negative_citing_its_complete_search_is_not_miscited():
    entries = [QUERY, CUT_GREP, _finding(400, NEGATIVE, [206])]
    assert _miscited_finding_entries([entries[-1]], entries) == []


def test_a_negative_resting_on_a_truncated_search_is_miscited():
    stmt = "No POST requests to any external address were observed in the capture"
    entries = [QUERY, CUT_GREP, _finding(401, stmt, [214])]
    assert _miscited_finding_entries([entries[-1]], entries) == [entries[-1]]


def test_a_negative_with_no_search_behind_it_is_miscited():
    entries = [QUERY, NOTE, _finding(402, NEGATIVE, [300])]
    assert _miscited_finding_entries([entries[-1]], entries) == [entries[-1]]


def test_a_negative_citing_a_search_of_the_wrong_sources_is_miscited():
    info = _call(77, "vol -f evidence/host.mem windows.info", '[{"Variable": "Kernel Base"}]')
    entries = [QUERY, info, _finding(403, NEGATIVE, [77])]
    assert _miscited_finding_entries([entries[-1]], entries) == [entries[-1]]


def test_the_blocker_names_the_search_that_would_ground_the_negative():
    from tools.reasoning import _citation_blocker
    info = _call(77, "vol -f evidence/host.mem windows.info", '[{"Variable": "Kernel Base"}]')
    entries = [QUERY, CUT_GREP, info, _finding(403, NEGATIVE, [77])]
    text = _citation_blocker([entries[-1]], entries)
    assert "identifiers they rest on" in text
    assert "asserts an absence" in text
    assert "206 (searched" in text and "214" not in text
    assert "citation repair" in text
