"""The map's window notes fold per host and kind, ride a host's pass
when the host has no start of its own, are re-checked before they run, and a
resumed queue raised one per entity folds once. Invented fixtures only
(CORP-WS01, CORP-WS02, CORP-SRV01, svc_kit.exe, dates in 2031)."""
from __future__ import annotations

from core import frontier_queue as Q
from core import incident_map as IM
from tests.core.test_incident_map import _anchor, _case, _sighted_kit, _trace


def _feed(monkeypatch, changes):
    monkeypatch.setattr(IM.IncidentMap, "changes_since", lambda self, cur=0: (
        [c for c in changes if c["seq"] > cur], max([cur] + [c["seq"] for c in changes])))


def _sbs(seq, host, eid, estate=True, t="2031-03-04 10:00:00"):
    return {"seq": seq, "kind": "seen_before_start", "ts": "",
            "fields": {"entity_id": eid, "host": host, "time": t, "anchor": "2031-03-05 00:00:00",
                       "anchor_claim": "C0001", "from_estate_start": estate}}


def _pass(log, host, status="due", **ref):
    item = log.add_work_item("host_pass", [], "", {"host": host}, f"pass {host}", status="due",
                             source_ref={"kind": "host_pass", "host": host, "entities": [], "closed_by": "executor",
                                         **ref}, extra_key=f"host_pass:{host}:0")
    if status != "due":
        from core.work_order import close_item
        close_item(log, item["call_id"], status, "passed")
    return item


def _followups(log):
    return [i for i in log.work_items() if i["origin"] == "followup" and i["status"] == "due"]


def test_a_sighting_on_a_host_without_a_start_rides_its_pass_unless_the_pass_has_begun(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    waiting = _pass(log, "CORP-WS01")
    running = _pass(log, "CORP-WS02", started=3)
    _feed(monkeypatch, [_sbs(1, "CORP-WS01", 501), _sbs(2, "CORP-WS02", 502)])
    Q.generate(log, case, {})
    assert [e["entity_id"] for e in waiting["source_ref"]["early"]] == [501]
    assert "early" not in running["source_ref"]                   # a pass in flight never reads it
    assert [(f["source_ref"]["subject"], len(f["source_ref"]["early"])) for f in _followups(log)] == \
        [("seen_before_start:CORP-WS02", 1)]


def test_a_host_passed_without_a_start_gets_a_pass_again_carrying_its_early_sightings(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _pass(log, "CORP-WS02", status="resolved", arrival_missing=True)
    _feed(monkeypatch, [_sbs(s, "CORP-WS02", 600 + s) for s in (1, 2, 3)])
    Q.generate(log, case, {})
    passes = [i for i in log.work_items() if i["origin"] == "host_pass" and i["status"] == "due"]
    assert len(passes) == 1 and passes[0]["fingerprint"] != "" and "again" in passes[0]["why"]
    assert [e["entity_id"] for e in passes[0]["source_ref"]["early"]] == [601, 602, 603]
    assert _followups(log) == []


def test_a_host_with_its_own_start_gets_one_followup_per_kind_extended_while_open(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _feed(monkeypatch, [_sbs(s, "CORP-WS01", 700 + s, estate=False) for s in (1, 2, 3)])
    Q.generate(log, case, {})
    (f,) = _followups(log)
    assert f["source_ref"]["subject"] == "seen_before_start:CORP-WS01" and len(f["source_ref"]["early"]) == 3
    assert f["why"].startswith("3 early sightings on CORP-WS01")


def test_a_window_check_raises_a_pair_at_most_twice_once_per_bound_source(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-SRV01", "2031-03-05 00:00:00")             # the estate start
    _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    m = IM.open(case)

    def raised():
        return [c["fields"]["from_estate_start"] for c in m.changes_since(0)[0]
                if c["kind"] == "seen_before_start" and c["fields"].get("host") == "CORP-WS02"]
    assert raised() == [True]
    _anchor(case, "CORP-WS02", "2031-03-11 09:00:00")               # the host's own start
    m = IM.open(case)
    assert raised() == [True, False]
    _anchor(case, "CORP-WS02", "2031-03-10 09:00:00")               # the own start moves: no third raise
    m = IM.open(case)
    assert raised() == [True, False]


def test_the_premise_keeps_a_merged_entity_and_closes_a_sighting_a_moved_start_explains(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _anchor(case, "CORP-SRV01", "2031-03-05 00:00:00")
    _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    m = IM.open(case)
    kit = next(e for e in m.attacker_entities() if e["value"].casefold().endswith("svc_kit.exe"))
    with m._read() as con:
        key = con.execute("SELECT kind, key FROM entities WHERE eid = ?", (kit["entity_id"],)).fetchone()
    merged = {"entity_id": 99999, "kind": key["kind"], "value": key["key"], "host": "CORP-WS02",
              "time": "2031-03-04 10:00:00", "anchor": "2031-03-05 00:00:00", "subject": "x:1"}
    assert m.early_holds(merged) == (True, "")                        # a new id for the same value: kept
    item = log.add_work_item("followup", [], "", {"host": "CORP-WS02"}, "note", status="due",
                             source_ref={"kind": "followup", "change": "seen_before_start",
                                         "subject": "seen_before_start:CORP-WS02",
                                         "early": [{**merged, "entity_id": kit["entity_id"]}]},
                             extra_key="followup:seen_before_start:CORP-WS02:0")
    _anchor(case, "CORP-WS02", "2031-03-03 09:00:00")               # the host's start moves before the sighting
    m = IM.open(case)
    assert Q.premise(log, m, item) is False
    assert item["status"] == "moot" and item["outcome"].startswith("premise gone: 2031-03-04 10:00:00 was before")
    assert "CORP-WS02's own start is 2031-03-03 09:00:00" in item["outcome"]


def test_a_resumed_queue_folds_once_into_one_item_per_host_and_kind(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _pass(log, "CORP-WS01")                                         # a pass not yet run: its host's sightings ride it
    old = []
    for i, (host, estate) in enumerate([("CORP-WS01", True), ("CORP-WS01", True), ("CORP-WS02", False),
                                        ("CORP-WS02", False), ("CORP-WS02", False)]):
        f = _sbs(i + 1, host, 800 + i, estate=estate)["fields"]
        old.append(log.add_work_item("followup", [], "", {"host": host}, f"note {i}", status="due",
                                     source_ref={"kind": "followup", "closed_by": "executor",
                                                 "change": "seen_before_start", "seq": i + 1,
                                                 "subject": f"seen_before_start:e{800 + i}:{host}", "fields": f},
                                     extra_key=f"followup:old:{i}"))
    for k in range(3):
        log.add_work_item("followup", [], "", {"host": "CORP-WS02"}, f"a finding refused twice by basis: s{k}",
                          status="due", source_ref={"kind": "refusal", "gate": "basis", "item": 64, "ask": "a"},
                          extra_key=f"refusal:basis:{k}")
    state = {"mode": "frontier", "cursor": 0}
    out = Q.fold_open(log, case, state)
    assert out["input"] == 8 and out["open"] + out["folded"] + out["gone"] == out["input"]
    assert out == {"input": 8, "open": 2, "folded": 6, "gone": 0}
    open_ = _followups(log)
    windows = [f for f in open_ if f["source_ref"].get("change") == "seen_before_start"]
    assert [f["source_ref"]["subject"] for f in windows] == ["seen_before_start:CORP-WS02"]   # each host once
    assert len(windows[0]["source_ref"]["early"]) == 3
    refusal = [f for f in open_ if f["source_ref"].get("kind") == "refusal"]
    assert len(refusal) == 1 and len(refusal[0]["source_ref"]["refused"]) == 3
    folded = [i for i in log.work_items() if i.get("folded_into")]
    assert all(i["status"] == "moot" and i["outcome"].startswith("folded into #") for i in folded)
    host_pass = next(i for i in log.work_items() if i["origin"] == "host_pass")
    assert len(host_pass["source_ref"]["early"]) == 2
    assert Q.fold_open(log, case, state) == {"input": 0, "open": 0, "folded": 0, "gone": 0}   # once per state


def test_a_host_gets_one_pass_again_and_after_it_ends_without_a_start_its_followup(tmp_path, monkeypatch):
    from core.work_order import close_item
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _pass(log, "CORP-WS02", status="resolved")
    changes = [_sbs(1, "CORP-WS02", 901)]
    _feed(monkeypatch, changes)
    Q.generate(log, case, {})
    (again,) = [i for i in log.work_items() if i["origin"] == "host_pass" and i["status"] == "due"]
    assert again["source_ref"]["repass"] is True
    close_item(log, again["call_id"], "resolved", "passed again, no arrival found")
    changes.append(_sbs(2, "CORP-WS02", 902))
    Q.generate(log, case, {"cursor": 1})
    assert not [i for i in log.work_items() if i["origin"] == "host_pass" and i["status"] == "due"]
    assert [f["source_ref"]["subject"] for f in _followups(log)] == ["seen_before_start:CORP-WS02"]


def test_a_pass_lists_its_early_sightings_as_leads_not_as_the_followups_question(tmp_path, monkeypatch):
    from core.frontier_prompts import item_text
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    waiting = _pass(log, "CORP-WS01")
    _feed(monkeypatch, [_sbs(1, "CORP-WS01", 501)])
    Q.generate(log, case, {})
    text = item_text(case, waiting, None)
    assert "EARLY SIGHTINGS (leads:" in text and "on CORP-WS01 at 2031-03-04 10:00:00, before 2031-03-05" in text
    assert "Say why" not in text
