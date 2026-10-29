"""The incident window in the words of the case's frame
(core.incident_window.window_in_frame, window_lines): the incident frame
keeps its lines; outside it no line presumes an attacker, an attacker
label with no stated time states no window, the victim's accounts are the
system owner's and the subject's the subject's, and a window with no
attacker data gives no WINDOW block; the composer's reader and rule 13
follow the frame. Invented fixtures only (CORP-WS01, jane.doe, john.roe,
dates in 2031)."""
from __future__ import annotations

from core import answer_synthesis as A
from core.claim_graph import add_claim, load_graph, set_claim_indicators
from core.incident_window import incident_window, window_in_frame, window_lines

INCIDENT = "# Case: A\n\n**Case ID:** A\n**System owner:** victim\n"
SUBJECT = "# Case: A\n\n**Case ID:** A\n**Engagement:** examination\n**System owner:** suspect\n"


def _case(tmp_path, brief=None):
    for d in (".atlas", "analysis", "reports"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    if brief:
        (tmp_path / "CASE.md").write_text(brief, encoding="utf-8")
    return tmp_path


def _claim(case, text, rows, tier="LIKELY", host="CORP-WS01"):
    cid = add_claim(case, text, confidence=tier, host=host, enforce_validation=False)["node_id"]
    set_claim_indicators(case, cid, rows)
    return cid


def _texts(window, frame):
    return [t for _i, t in window_lines(window_in_frame(window, frame))]


def test_the_incident_frame_keeps_todays_lines(tmp_path):
    case = _case(tmp_path)
    _claim(case, "jane.doe signed in at 2031-03-10 14:00:00.", [{"type": "account", "value": "jane.doe", "side": "victim"}])
    w = incident_window(load_graph(case))
    assert _texts(w, "incident") == ["no belief states when the attacker first acted (no window)",
                                     "accounts typed only as the organisation's: jane.doe"]
    assert [t for _i, t in window_lines(w)] == _texts(w, "incident")       # no frame given: the incident words


def test_a_subject_case_without_attacker_data_has_no_window_block(tmp_path):
    case = _case(tmp_path)
    _claim(case, "john.roe ran the wiper at 2031-03-10 14:00:00.", [{"type": "account", "value": "john.roe", "side": "subject"}])
    w = incident_window(load_graph(case))
    assert w["subject_accounts"] == ["john.roe"] and w["victim_accounts"] == [] and w["own_accounts"] == ["john.roe"]
    assert _texts(w, "subject") == [] and _texts(w, "neutral") == []
    assert "accounts typed as the subject's: john.roe" in _texts(w, "incident")


def test_a_neutral_case_without_attacker_data_has_no_window_block(tmp_path):
    case = _case(tmp_path)
    _claim(case, "jane.doe signed in at 2031-03-10 14:00:00.", [{"type": "account", "value": "jane.doe", "side": "victim"}])
    assert _texts(incident_window(load_graph(case)), "neutral") == []


def test_attacker_data_keeps_its_lines_in_any_frame_in_the_frames_words(tmp_path):
    case = _case(tmp_path)
    c1 = _claim(case, "The intruder reached CORP-WS01 at 2031-03-10 14:00:00.",
                [{"type": "host", "value": "CORP-WS01", "side": "victim", "attacker_from": "2031-03-10 14:00:00"}])
    _claim(case, "jane.doe and john.roe signed in.", [{"type": "account", "value": "jane.doe", "side": "victim"},
                                                     {"type": "account", "value": "john.roe", "side": "subject"}])
    texts = _texts(incident_window(load_graph(case)), "subject")
    assert f"first attacker activity on CORP-WS01: 2031-03-10 14:00:00 ({c1})" in texts
    assert "accounts typed as the system owner's: jane.doe" in texts
    assert "accounts typed as the subject's: john.roe" in texts
    assert not any("organisation" in t or "no window" in t or "no belief states" in t for t in texts)


def test_an_unanchored_label_states_no_window_outside_the_incident_frame():
    w = {"hosts": {}, "accounts": {}, "estate": None, "unanchored": ["CORP-WS01"], "noted": []}
    assert window_in_frame(w, "incident")["unanchored"] == ["CORP-WS01"]
    assert window_in_frame(w, "subject")["unanchored"] == [] and _texts(w, "subject") == []
    started = dict(w, estate=("2031-03-10 14:00:00", "C0001"))
    assert window_in_frame(started, "neutral")["unanchored"] == ["CORP-WS01"]


def test_the_composer_reads_the_frame_for_its_reader_and_its_window(tmp_path):
    case = _case(tmp_path, SUBJECT)
    c1 = _claim(case, "john.roe ran the wiper at 2031-03-10 14:00:00.",
                [{"type": "account", "value": "john.roe", "side": "subject"}])
    task = {"id": "task-0001", "text": "What did john.roe do on CORP-WS01?", "status": "answered",
            "related_claim_ids": [c1]}
    sheet = A.answer_sheet(task, load_graph(case), [], case_dir=case)
    prompt = A.compose_prompt(sheet)
    assert sheet["frame"] == "subject" and sheet["window"] == [] and "WINDOW" not in sheet["text"]
    assert "examiner who reports on it" in prompt and "incident-response lead" not in prompt
    assert "WINDOW lines say when" not in prompt
    assert "for the examiner" in A._answer_system_prompt(case)
    incident = _case(tmp_path / "b", INCIDENT)
    assert A._answer_system_prompt(incident) == A._ANSWER_SYSTEM_PROMPT
    assert A.compose_prompt(dict(sheet, frame="incident")).startswith(A.COMPOSE_PARTLESS_PROMPT)


def test_the_map_window_splits_the_owners_accounts_too(tmp_path, monkeypatch):
    from core import incident_map as IM
    from tests.core.test_incident_map import _case as map_case
    from tests.core.test_incident_map import _claim as map_claim
    case = map_case(tmp_path)
    map_claim(case, "jane.doe and john.roe signed in on CORP-WS01.",
              [{"type": "account", "value": "jane.doe", "side": "victim"},
               {"type": "account", "value": "john.roe", "side": "subject"}])
    w = IM.open(case).window()
    assert any("john.roe" in a for a in w["subject_accounts"]) and any("jane.doe" in a for a in w["victim_accounts"])
    assert sorted(w["own_accounts"]) == sorted(w["subject_accounts"] + w["victim_accounts"])


def test_the_frontier_states_hosts_without_an_arrival_by_the_frame(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from agent.frontier import FrontierRun
    from core import incident_map as IM
    from tests.core.test_incident_map import _case as map_case
    from tests.core.test_incident_map import _claim as map_claim
    from tests.core.test_incident_map import _trace
    for brief, expect in ((INCIDENT, ["CORP-WS02"]), (None, [])):
        case = map_case(tmp_path / ("i" if brief else "n"))
        if brief:
            (case / "CASE.md").write_text(brief, encoding="utf-8")
        _trace(case, monkeypatch)
        map_claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-09 09:00:00.",
                  [{"type": "file", "value": "svc_kit.exe", "side": "attacker"}], host="CORP-WS02")
        left = FrontierRun._left(SimpleNamespace(m=IM.open(case), case=case), {})
        assert left["hosts_without_arrival"] == expect


def test_attacker_typed_accounts_without_a_start_draw_no_absence_line_outside_the_incident_frame():
    w = {"hosts": {}, "accounts": {}, "estate": None, "attacker_accounts": ["x.intruder"], "noted": []}
    assert _texts(w, "subject") == ["accounts typed as the attacker's: x.intruder"]
    assert _texts(w, "incident")[0] == "no belief states when the attacker first acted (no window)"
