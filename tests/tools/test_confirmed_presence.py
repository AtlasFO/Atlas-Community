"""The presence check a CONFIRMED finding passes before its gates run
(tools._gates.citation_support.shown_values, tools.misc._confirmed_presence):
every checkable entity, minute time and quotation the statement states
stands in a row of the calls the analyst cited. It checks presence, never
meaning. Invented fixtures only."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog

ROW = {"TimeCreated": "2031-03-04 09:12:49", "Computer": "CORP-WS01", "EventId": 4688,
       "Message": "A new process has been created: C:\\Users\\Public\\dropper.exe"}
STATEMENT = "dropper.exe was started on CORP-WS01 at 2031-03-04 09:12 (event id 4688)"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
    monkeypatch.setenv("ATLAS_FINDING_AUTO_DOWNGRADE", "0")
    with patch("tools.misc.tool_program", side_effect=lambda name, *rest: f"/usr/local/bin/{name}"):
        yield


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / ".atlas" / "evidence_inventory.json").write_text(json.dumps({"complete": True, "summary": {}}))
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"}], "hosts": ["CORP-WS01"]}))
    return case


@pytest.fixture
def log(case):
    from core import provenance
    l = ExecutionLog()
    l.configure("CASE-A", str(case / "analysis" / "trace.json"), save_session=False)
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    provenance.reset_cache()
    return l


def _grep(log, rows, path="analysis/ws01/sec.csv", pattern="dropper"):
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "path": path, "pattern": pattern,
                                                          "hits": rows, "hit_count": len(rows), "max_hits": 50,
                                                          "hit_cap_reached": False}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"path": path, "pattern": pattern}))
    return cid


def _lines(log, lines, path="analysis/ws01/notes.bin"):
    cid = log.record_tool_call("<py>:strings_strings_grep", True, False, 0, 0,
                               stdout_excerpt=json.dumps({"success": True, "file": path, "pattern": "x",
                                                          "match_count": len(lines), "matches": lines}),
                               evidence_ref=path)
    log.annotate_tool_call(cid, args=json.dumps({"file_path": path, "pattern": "x"}))
    return cid


def _shown(log, case, statement, cids, **kw):
    from tools._gates.citation_support import shown_values
    by = log.index().by_call_id
    with patch("core.execution_log.log", log):
        return shown_values(statement, [by[c] for c in cids], hosts=["CORP-WS01"], case_dir=str(case),
                            tool_calls=[e for e in log._entries if e.get("type") == "tool_call"], **kw)


def _record(log, statement, cids, evidence="sec.csv: dropper.exe 2031-03-04 09:12:49 event id 4688",
            linked=None):
    from tools.misc import record_finding
    with patch("core.execution_log.log", log), \
            patch("tools._gates.contracts.failures", lambda name, ctx: []):
        return record_finding(statement, "CONFIRMED", "evtx", host="CORP-WS01",
                              linked_call_id=linked or cids[0],
                              input_call_ids=list(cids), supporting_evidence=evidence)


def _stub_ask(monkeypatch, verdict):
    """The evaluator answered with one verdict; the request it read is kept."""
    import tools.reasoning as R
    seen = []

    def ask(system, user, _tool_name="", hypothesis_id="", input_call_ids=None):
        seen.append(user)
        res = {"success": True, "conclusion": f"VERDICT: {verdict}\n1. CONTRADICTIONS - the rows show it.",
               "inputs": {"user_message": user}}
        R._log_reason(_tool_name, res, input_call_ids=input_call_ids)
        return res
    monkeypatch.setattr(R, "_ask", ask)
    return seen


CONNECTED = STATEMENT + "; it then connected to 203.0.113.7."
CONNECTED_EVIDENCE = "sec.csv: dropper.exe 2031-03-04 09:12:49 event id 4688; fw.csv: dropper.exe connected to 203.0.113.7"


# ── the check itself ──────────────────────────────────────────────────────

def test_every_value_in_a_cited_row_passes(case, log):
    cid = _grep(log, [ROW])
    out = _shown(log, case, STATEMENT, [cid])
    assert out["unshown"] == [] and out["unsupported"] == [] and out["shown"] >= 2


def test_a_value_no_cited_row_shows_is_named(case, log):
    cid = _grep(log, [ROW])
    out = _shown(log, case, STATEMENT + "; it then connected to 203.0.113.7.", [cid])
    assert out["unshown"] == ["ip:203.0.113.7"]


def test_a_time_counts_only_in_a_row_that_holds_the_findings_entity(case, log):
    other = {"TimeCreated": "2031-03-04 10:30:05", "Computer": "CORP-WS01", "EventId": 4624,
             "Message": "An account was successfully logged on"}
    cid = _grep(log, [ROW, other])
    out = _shown(log, case, "dropper.exe was started on CORP-WS01 at 2031-03-04 10:30", [cid])
    assert out["unshown"] == ["ts:2031-03-04 10:30"]


def test_a_negation_word_does_not_exempt_a_value(case, log):
    cid = _grep(log, [ROW])
    out = _shown(log, case, "Without authorization, 203.0.113.5 started dropper.exe on CORP-WS01.", [cid])
    assert "ip:203.0.113.5" in out["unshown"]


def test_an_absence_sentence_without_a_complete_cited_search_is_unsupported(case, log):
    cid = _grep(log, [ROW])
    out = _shown(log, case, STATEMENT + ". No persistence was found on CORP-WS01.", [cid])
    assert out["unshown"] == [] and len(out["unsupported"]) == 1


def test_a_long_quotation_split_across_rows_by_the_tool_is_shown(case, log):
    cid = _lines(log, ["The backup job copied the archive and then I", "m leaving the key at the front desk"])
    out = _shown(log, case, 'notes.bin holds "I\'m leaving the key at the front desk"', [cid])
    assert out["unshown"] == [] and out["quotes_shown"] == 1


def test_a_two_word_quotation_must_stand_in_one_row(case, log):
    cid = _lines(log, ["the job ended with status", "denied by the operator"])
    out = _shown(log, case, 'notes.bin shows "status denied"', [cid])
    assert out["unshown"] == ["quote:status denied"]


def test_a_quotation_in_another_script_is_a_value(case, log):
    cid = _lines(log, ["пароль изменён администратором"])
    assert _shown(log, case, 'notes.bin holds "пароль изменён"', [cid])["unshown"] == []
    assert _shown(log, case, 'notes.bin holds "доступ запрещён"', [cid])["unshown"] == ["quote:доступ запрещён"]
    assert _shown(log, case, 'notes.bin holds "パスワード変更"', [cid])["unshown"] == ["quote:パスワード変更"]


def test_a_one_word_ascii_quotation_is_a_label_not_a_value(case, log):
    """Known limit, the safe direction: a scare-quoted word is left to the evaluator."""
    from tools._gates.citation_support import quoted_values
    assert quoted_values('the "staging" folder held "two archives"') == ["two archives"]


def test_known_limit_presence_not_meaning_a_swapped_role_passes(case, log):
    """Known limit: the check sees that both addresses are printed, not which
    is the source. The evaluation the CONFIRMED gate requires judges roles."""
    row = {"TimeCreated": "2031-03-04 09:20:00", "Computer": "CORP-WS01", "EventId": 3,
           "Message": "Network connection: 203.0.113.9 -> 203.0.113.5 dropper.exe"}
    cid = _grep(log, [row])
    out = _shown(log, case, "dropper.exe on CORP-WS01 at 2031-03-04 09:20 connected from 203.0.113.5 "
                            "to 203.0.113.9", [cid])
    assert out["unshown"] == []


# ── record_finding: before the gates ─────────────────────────────────────

def test_a_confirmed_finding_whose_cited_rows_show_every_value_stays_confirmed(case, log):
    cid = _grep(log, [ROW])
    r = _record(log, STATEMENT, [cid])
    assert r["success"] is True and r["confidence"] == "CONFIRMED" and "tier_auto_downgrade_reason" not in r


def test_an_unshown_value_lowers_it_and_the_line_says_what_to_do(case, log):
    cid = _grep(log, [ROW])
    r = _record(log, STATEMENT + "; it then connected to 203.0.113.7.", [cid],
                evidence="sec.csv: dropper.exe 2031-03-04 09:12:49 event id 4688, 203.0.113.7")
    assert r["confidence"] == "LIKELY" and r["tier_auto_downgrade_reason"] == "citation_values_not_shown"
    assert r["citation"].startswith("Cite the call whose row shows each")
    assert "203.0.113.7: no tool output of this run shows it; leave it out" in r["citation"]


def test_a_value_shown_only_by_an_uncited_call_is_not_the_findings_citation(case, log):
    """The analyst's own ids decide; a call the auto-fill borrowed a value
    from is named as the one to cite, never counted as cited."""
    cid = _grep(log, [ROW])
    elsewhere = _grep(log, [{"TimeCreated": "2031-03-04 09:40:00", "Computer": "CORP-WS01", "EventId": 5156,
                             "Message": "dropper.exe connected to 203.0.113.7"}],
                      path="analysis/ws01/fw.csv", pattern="203.0.113")
    r = _record(log, STATEMENT + "; it then connected to 203.0.113.7.", [cid])
    assert r["confidence"] == "LIKELY"
    assert f"203.0.113.7: call {elsewhere} shows it" in r["citation"]


def test_a_status_borrowed_from_an_uncited_call_does_not_pass(case, log):
    """The analyst cites strings on dropper.exe, so the finding has no
    own-set value (the read file is its source). The registry key is a
    claim the auto-fill borrows from an uncited call whose row also holds
    the file name; computed over the analyst's ids plus that call the
    status would be "cited". The floor's status is computed over the own
    set alone: "located", and the line names the call to cite."""
    borrowed = _grep(log, [{"Key": "HKLM\\Software\\Run", "Name": "Updater",
                            "Value": "C:\\Users\\Public\\dropper.exe"}],
                     path="analysis/ws01/software.csv", pattern="Run")
    own = _lines(log, ["UPX0", "UPX1", "This program cannot be run in DOS mode"], path="analysis/ws01/dropper.exe")
    r = _record(log, "dropper.exe on CORP-WS01 is packed with UPX and sits under HKLM\\Software\\Run", [own],
                evidence="strings: UPX0 UPX1 section names")
    assert r["confidence"] == "LIKELY" and r["tier_auto_downgrade_reason"] == "citation_values_not_shown"
    assert f"the calls you cited show none of its values; call(s) {borrowed} show them" in r["citation"]


def test_a_quotation_shown_by_the_call_that_read_the_file_passes(case, log):
    """A statement whose only entity is the file its cited call read is not
    checkable by the row test; its quotation standing in that call's rows
    is what makes it CONFIRMED."""
    cid = _lines(log, ["The backup job copied the archive and then I", "m leaving the key at the front desk"])
    r = _record(log, 'notes.bin holds "I\'m leaving the key at the front desk"', [cid],
                evidence="notes.bin strings: I'm leaving the key at the front desk")
    assert r["success"] is True and r["confidence"] == "CONFIRMED" and "tier_auto_downgrade_reason" not in r


def _status(log, case, statement, cids, hosts=("CORP-WS01",)):
    from tools._gates.citation_support import citation_status
    by = log.index().by_call_id
    with patch("core.execution_log.log", log):
        return citation_status(statement, [by[c] for c in cids], [], "CORP-WS01",
                               [e for e in log._entries if e.get("type") == "tool_call"],
                               hosts=list(hosts), case_dir=str(case))[0]


def test_a_quotation_with_a_time_and_a_name_but_no_entity_is_cited_by_the_call_that_printed_it(case, log):
    """No strong entity, so the row test could only bind the name to the
    time through the host, which a chat line never prints; the quotation in
    the cited rows is the sighting."""
    cid = _lines(log, ["2031-03-04 09:30:02 jane.doe: as discussed I will upload it",
                       "tonight to the usual share and delete the", "local copy."], path="evidence/ws01/chat.log")
    statement = ('A chat line by jane.doe on CORP-WS01 (2031-03-04 09:30) reads "I will upload it tonight to the '
                 'usual share".')
    assert _status(log, case, statement, [cid]) == "cited"
    r = _record(log, statement, [cid], evidence="chat.log line 2: I will upload it tonight to the usual share")
    assert r["success"] is True and r["confidence"] == "CONFIRMED" and "tier_auto_downgrade_reason" not in r


def test_a_quotation_is_no_sighting_for_a_value_or_a_time_no_row_shows(case, log):
    """The stored status guards the report below CONFIRMED: an address no
    row of the trace holds, or a time outside the quotation's rows, keeps
    the statement not_shown however its quoted words are printed."""
    cid = _lines(log, ["2031-03-04 09:30:02 jane.doe: reset the password", "tonight to the usual share"],
                 path="evidence/ws01/chat.log")
    assert _status(log, case, 'CORP-WS01 sent "reset the password" to 203.0.113.99 at 2031-03-04 09:30',
                   [cid]) == "not_shown"
    assert _status(log, case, 'A chat line by jane.doe on CORP-WS01 (2031-03-04 09:45) reads "reset the password '
                              'tonight to the usual share"', [cid]) == "not_shown"
    assert _status(log, case, 'A chat line by jane.doe on CORP-WS01 (2031-03-04 09:30) reads "reset the password '
                              'tonight to the usual share"', [cid]) == "cited"


def test_a_quotation_does_not_outrank_a_located_status(case, log):
    """The superset of the located lowering: in a case of two hosts, a
    statement another call shows by its rows (its name, its time and its
    host in one row) stays "located" however its quotation, time included,
    is shown by the call it cites; cited together, it is cited by the rows.
    (In a case of one host the host label binds nothing: the next test.)"""
    shows = _grep(log, [{"TimeCreated": "2031-03-04 09:30:05", "Computer": "CORP-WS01", "EventId": 4624,
                         "Message": "An account was successfully logged on: jane.doe"}])
    own = _lines(log, ["2031-03-04 09:30:02 jane.doe: reset the password", "tonight to the usual share"],
                 path="evidence/ws01/chat.log")
    statement = ('A chat line by jane.doe on CORP-WS01 (2031-03-04 09:30) reads "reset the password tonight to '
                 'the usual share"')
    two = ("CORP-WS01", "CORP-WS02")
    assert _status(log, case, statement, [own], hosts=two) == "located"
    assert _status(log, case, statement, [own, shows], hosts=two) == "cited"


def test_in_a_case_of_one_host_a_row_with_the_name_and_the_time_cites_without_the_host_label(case, log):
    """The fallback's host label is vacuous when the case holds one host:
    tool rows of single-host evidence never print it. With two hosts it is
    still required (above)."""
    own = _lines(log, ["2031-03-04 09:30:02 jane.doe: reset the password", "tonight to the usual share"],
                 path="evidence/ws01/chat.log")
    statement = "A chat line by jane.doe on CORP-WS01 at 2031-03-04 09:30"
    assert _status(log, case, statement, [own]) == "cited"
    assert _status(log, case, statement, [own], hosts=("CORP-WS01", "CORP-WS02")) == "not_shown"


def test_an_absence_sentence_without_its_search_lowers_the_finding(case, log):
    cid = _grep(log, [ROW])
    r = _record(log, STATEMENT + ". No persistence was found on CORP-WS01.", [cid])
    assert r["confidence"] == "LIKELY" and r["tier_auto_downgrade_reason"] == "citation_values_not_shown"
    assert "cite the complete search that would have shown it" in r["citation"]


def test_a_check_that_raises_never_leaves_the_finding_confirmed(case, log):
    cid = _grep(log, [ROW])
    with patch("tools.misc._confirmed_presence", side_effect=RuntimeError("no index")):
        r = _record(log, STATEMENT, [cid])
    assert r["success"] is True and r["confidence"] == "LIKELY"
    assert r["tier_auto_downgrade_reason"] == "citation_presence_unchecked"
    entry = [e for e in log._entries if e.get("type") == "finding"][-1]
    assert "RuntimeError: no index" in json.dumps(entry)


def test_a_challenged_attribution_evaluation_records_the_tier_the_analyst_asked_for(case, log, monkeypatch):
    """Lowered to LIKELY by the presence check, then challenged by the
    attribution evaluation at LIKELY: recorded at SUSPECTED as lowered from
    CONFIRMED, the tier the analyst asked for."""
    monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
    monkeypatch.setenv("ATLAS_EXTERNAL_LOOKUP_FIRST", "1")
    seen = _stub_ask(monkeypatch, "CHALLENGED")
    sec = _grep(log, [ROW])
    with patch("tools.misc._is_attribution_verdict", return_value=True):
        r = _record(log, CONNECTED, [sec], evidence=CONNECTED_EVIDENCE)
    assert len(seen) == 1 and r["success"] is True and r["confidence"] == "SUSPECTED"
    assert r["tier_auto_downgraded_from"] == "CONFIRMED"
    assert r["tier_auto_downgrade_reason"] == "attribution_evaluation_challenged"
