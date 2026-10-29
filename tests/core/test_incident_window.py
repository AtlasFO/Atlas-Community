"""C2 item 4 (ATLAS_WINDOW_NOTES): the window the model states with
attacker_from on host and account rows; a note, never a refusal, for a
finding leading with an earlier time; the WINDOW block on the composer's
sheet. Invented fixtures only (CORP-WS01, CORP-WS02, jane.doe, svc_backup,
dates in 2031)."""
from __future__ import annotations

from unittest.mock import patch

from core import answer_synthesis as A
from core import indicators as I
from core.claim_graph import add_claim, load_graph, set_claim_indicators
from core.incident_window import incident_window, window_lines, window_note


def _case(tmp_path):
    for d in (".atlas", "analysis", "reports"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    return tmp_path


def _claim(case, text, rows, tier="LIKELY", host="CORP-WS01"):
    cid = add_claim(case, text, confidence=tier, host=host, enforce_validation=False)["node_id"]
    set_claim_indicators(case, cid, rows)
    return cid


def test_a_finding_leading_before_its_hosts_window_gets_a_note(tmp_path):
    case = _case(tmp_path)
    c1 = _claim(case, "The attacker logged on to CORP-WS01 at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    _claim(case, "A weaker view: CORP-WS01 reached at 2031-03-01 09:00:00.",
           [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-01 09:00:00"}],
           tier="SUSPECTED")
    note = window_note(case, "jane.doe opened a share on CORP-WS01 at 2031-03-02 09:00:00.", "CORP-WS01")
    assert "leads with 2031-03-02 09:00:00 on CORP-WS01" in note and c1 in note
    assert window_note(case, "Beacon traffic from CORP-WS01 at 2031-03-11 08:00:00.", "CORP-WS01") == ""
    assert window_note(case, "No time stated.", "CORP-WS01") == ""


def test_two_starts_for_one_host_the_earlier_wins_and_both_are_shown(tmp_path):
    case = _case(tmp_path)
    c1 = _claim(case, "Reached at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    c2 = _claim(case, "Reached earlier, at 2031-03-08 07:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-08 07:00:00"}])
    w = incident_window(load_graph(case))
    assert w["hosts"]["CORP-WS01"][0] == ("2031-03-08 07:00:00", c2) and w["estate"] == ("2031-03-08 07:00:00", c2)
    text = dict(window_lines(w))
    assert f"first attacker activity on CORP-WS01: 2031-03-08 07:00:00 ({c2}); also stated: " \
           f"2031-03-10 14:00:00 ({c1})" in text.values()


def test_account_sets_follow_the_typed_sides(tmp_path):
    case = _case(tmp_path)
    _claim(case, "jane.doe signed in at 2031-03-10 14:00:00.",
           [{"type": "account", "value": "jane.doe", "side": "victim"},
            {"type": "account", "value": "svc_backup", "side": "victim"}])
    _claim(case, "The attacker used svc_backup from 2031-03-10 15:00:00.",
           [{"type": "account", "value": "svc_backup", "side": "attacker", "attacker_from": "2031-03-10 15:00:00"}])
    w = incident_window(load_graph(case))
    assert w["own_accounts"] == ["jane.doe"] and w["compromised"] == {"svc_backup": "2031-03-10 15:00:00"}


def test_attacker_from_not_shown_by_the_cited_output_is_dropped(tmp_path):
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    (tmp_path / "analysis").mkdir()
    log.configure("CASE", str(tmp_path / "analysis" / "trace.json"))
    cid = log.record_tool_call("tool", True, False, 0, 0,
                               stdout_excerpt="4624 logon CORP-WS01 by jane.doe at 2031-03-10 14:00:00")
    with patch("core.execution_log.log", log):
        out = I.validate([
            {"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10T14:00:00Z"},
            {"type": "account", "value": "jane.doe", "side": "victim", "attacker_from": "2031-03-09 08:00:00"},
        ], call_ids=[cid], case_dir=None)
    kept = {r["value"]: r for r in out["kept"]}
    assert kept["CORP-WS01"]["attacker_from"].startswith("2031-03-10 14:00:00")
    assert "attacker_from" not in kept["jane.doe"] and "dropped" in kept["jane.doe"]["attacker_from_note"]


def test_the_composer_sheet_carries_the_window_and_the_flag(tmp_path):
    case = _case(tmp_path)
    c1 = _claim(case, "The attacker logged on to CORP-WS01 at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    early = _claim(case, "jane.doe opened the share on CORP-WS01 at 2031-03-02 09:00:00.", [])
    task = {"id": "task-0001", "text": "What did the attacker do on CORP-WS01?", "status": "answered",
            "related_claim_ids": [c1, early]}
    graph = load_graph(case)
    sheet = A.answer_sheet(task, graph, [])
    ids = [w["id"] for w in sheet["window"]]
    assert ids[:2] == ["t1", "t2"] and sheet["window_flags"][early].endswith("[t2]")
    assert "WINDOW (when the attacker first acted" in sheet["text"]
    assert "WINDOW lines say when the beliefs place" in A.compose_prompt(sheet)
    results, _ = A.check_composed(A.parse_composed(
        f"jane.doe opened the share before the attacker's first activity on CORP-WS01 [{early}, t2]."),
        sheet, graph, frozenset({"jane.doe", "corp-ws01"}))
    assert results[0]["ok"], results


def test_off_no_note_no_block(tmp_path, monkeypatch):
    case = _case(tmp_path)
    _claim(case, "Reached at 2031-03-10 14:00:00.",
           [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    monkeypatch.setenv("ATLAS_WINDOW_NOTES", "0")
    assert window_note(case, "x on CORP-WS01 at 2031-03-02 09:00:00.", "CORP-WS01") == ""
    sheet = A.answer_sheet({"id": "task-0001", "text": "q", "status": "open", "related_claim_ids": []},
                           load_graph(case), [])
    assert sheet["window"] == [] and "WINDOW lines say when" not in A.compose_prompt(sheet)
    assert I.normalize_row({"type": "host", "value": "CORP-WS01", "side": "victim",
                            "attacker_from": "2031-03-10 14:00:00"})[0].get("attacker_from") is None


def test_a_findings_own_early_row_never_silences_its_note_or_moves_the_window(tmp_path):
    from core.claim_graph import mark_window_noted
    case = _case(tmp_path)
    c1 = _claim(case, "The attacker logged on to CORP-WS01 at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    early_text = "Recon on CORP-WS01 at 2031-03-02 09:00:00."
    early = _claim(case, early_text,
                   [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-02 09:00:00"}])
    note = window_note(case, early_text, "CORP-WS01", claim_id=early)
    assert c1 in note                                       # judged without its own row
    mark_window_noted(case, early)
    w = incident_window(load_graph(case))
    assert w["hosts"]["CORP-WS01"][0] == ("2031-03-10 14:00:00", c1)   # the noted row moves nothing
    assert any("stated by a noted claim" in text for _i, text in window_lines(w))
    assert window_note(case, "Later read on CORP-WS01 at 2031-03-05 09:00:00.", "CORP-WS01") != ""
    with patch("core.incident_window._noted_stands", lambda n: True):     # evaluated SUPPORTED
        assert incident_window(load_graph(case))["hosts"]["CORP-WS01"][0][1] == early


def test_an_account_the_attacker_acted_with_is_compromised_whatever_its_side(tmp_path):
    case = _case(tmp_path)
    _claim(case, "jane.doe signed in at 2031-03-10 14:00:00 from the attacker's address.",
           [{"type": "account", "value": "jane.doe", "side": "victim", "attacker_from": "2031-03-10 14:00:00"},
            {"type": "account", "value": "john.roe", "side": "victim"}])
    w = incident_window(load_graph(case))
    assert w["own_accounts"] == ["john.roe"] and w["compromised"] == {"jane.doe": "2031-03-10 14:00:00"}
    assert window_lines(w)[0][1].startswith("no host window")


def _windowed(tmp_path):
    case = _case(tmp_path)
    c1 = _claim(case, "The attacker logged on to CORP-WS01 at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    return case, c1


def test_a_supersede_of_an_unrelated_claim_still_marks_a_noted_claim(tmp_path):
    from core.incident_window import note_after_record
    case, c1 = _windowed(tmp_path)
    other = _claim(case, "An unrelated finding.", [])
    text = "Recon on CORP-WS01 at 2031-03-02 09:00:00."
    new = _claim(case, text, [{"type": "host", "value": "CORP-WS01", "side": "victim",
                               "attacker_from": "2031-03-02 09:00:00"}])
    note = note_after_record(case, {"claim_id": new, "superseded_claim_id": other}, text, "CORP-WS01",
                             created=True)
    assert note and load_graph(case)["nodes"][new].get("window_noted") is True
    assert incident_window(load_graph(case))["hosts"]["CORP-WS01"][0] == ("2031-03-10 14:00:00", c1)
    # A re-record replacing the claim that drew the note answers it: no mark.
    again = _claim(case, text + " Argued: the logon came from the attacker's address.",
                   [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-02 09:00:00"}])
    note_after_record(case, {"claim_id": again, "superseded_claim_id": new}, text, "CORP-WS01", created=True)
    assert not load_graph(case)["nodes"][again].get("window_noted")


def test_a_twin_merged_into_a_counted_claim_does_not_hold_its_start(tmp_path):
    from core.incident_window import note_after_record
    case, c1 = _windowed(tmp_path)
    text = "The attacker logged on to CORP-WS01 at 2031-03-10 14:00:00, again."
    note = note_after_record(case, {"claim_id": c1, "indicators_kept": [
        {"type": "host", "value": "CORP-WS01", "attacker_from": "2031-03-10 14:00:00"}]}, text, "CORP-WS01",
        created=False)
    assert note == "" and not load_graph(case)["nodes"][c1].get("window_noted")
    assert incident_window(load_graph(case))["hosts"]["CORP-WS01"][0] == ("2031-03-10 14:00:00", c1)


def test_a_claim_new_to_the_graph_is_known_new_without_the_mirrors_word(tmp_path):
    from core.claim_graph import upsert_claim_from_finding
    from core.incident_window import claim_is_new
    case = _case(tmp_path)
    r = upsert_claim_from_finding(case, statement="A finding on CORP-WS01 at 2031-03-02 09:00:00.",
                                  confidence="LIKELY", host="CORP-WS01", finding_call_id=41)
    cid = r["claim_id"]
    assert claim_is_new(case, {"claim_id": cid}, r, 41) is True                   # the mirror says so
    assert claim_is_new(case, {"claim_id": cid}, None, 41) is True                # no mirror word
    assert claim_is_new(case, {"claim_id": cid}, {"skipped": True}, 42) is False  # another record's claim
    assert claim_is_new(case, {}, None, 41) is False


def test_a_start_and_a_lead_written_to_the_minute_count():
    from core.incident_window import _iso, leading_time
    assert _iso("2031-03-10 14:02") == "2031-03-10 14:02:00"
    assert leading_time("svc_kit.exe ran on CORP-WS01 at 2031-03-10T14:02Z.") == "2031-03-10 14:02:00"
    assert leading_time("Sessions on CORP-WS01 between 2031-03-10 09:00-10:30.") == "2031-03-10 09:00:00"
    assert leading_time("Logon at 2031-03-10 10:00:00-05:00.") == "2031-03-10 15:00:00"


def _held_case(tmp_path, monkeypatch, evaluate_first):
    from core.claim_graph import mark_window_noted
    from core.execution_log import ExecutionLog
    case = _case(tmp_path)
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    text = "The attacker reached CORP-WS01 at 2031-03-01 09:00:00."

    def evaluate():
        log._entries.append({"type": "reason_call", "tool": "reason_evaluate_finding", "call_id": log._next_id(),
                             "success": True, "conclusion": "VERDICT: SUPPORTED, the rows hold it.",
                             "inputs": {"user_message": f"Finding: {text}"}})
    if evaluate_first:
        evaluate()
    cid = _claim(case, text, [{"type": "host", "value": "CORP-WS01", "side": "victim",
                               "attacker_from": "2031-03-01 09:00:00"}])
    from core.incident_window import trace_mark
    mark_window_noted(case, cid, mark=trace_mark())
    return case, cid, evaluate


def test_an_evaluation_before_the_note_keeps_the_start_held(tmp_path, monkeypatch):
    case, cid, _evaluate = _held_case(tmp_path, monkeypatch, evaluate_first=True)
    w = incident_window(load_graph(case))
    assert w["hosts"] == {} and [n[3] for n in w["noted"]] == [cid]


def test_an_evaluation_after_the_note_lets_the_start_count(tmp_path, monkeypatch):
    case, cid, evaluate = _held_case(tmp_path, monkeypatch, evaluate_first=False)
    assert incident_window(load_graph(case))["hosts"] == {}
    evaluate()
    assert incident_window(load_graph(case))["hosts"]["CORP-WS01"][0][1] == cid
    assert incident_window(load_graph(case), case_dir=case)["hosts"]["CORP-WS01"][0][1] == cid
