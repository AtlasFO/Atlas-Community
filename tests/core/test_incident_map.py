"""ATLAS_INCIDENT_MAP: the incident map's store, keys, belief ingest,
label currency, sync with the claim graph, change feed and fingerprint.
Invented fixtures only (CORP-WS01, CORP-WS02, CORP-SRV01, jane.doe,
svc_kit.exe, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from core import claim_graph as CG
from core import incident_map as IM
from core.claim_graph import add_claim, set_claim_indicators, supersede

REPO = Path(__file__).resolve().parents[2]


def _case(tmp_path):
    for d in (".atlas", "analysis", "reports"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps({"links": [
        {"label": "CORP-WS01", "path": "evidence/corp-ws01.raw"},
        {"label": "CORP-WS02", "path": "evidence/corp-ws02.raw"},
        {"label": "CORP-SRV01", "path": "evidence/corp-srv01.raw"}]}), encoding="utf-8")
    return tmp_path


def _claim(case, text, rows, tier="LIKELY", host="CORP-WS01", calls=()):
    cid = add_claim(case, text, confidence=tier, host=host, enforce_validation=False)["node_id"]
    set_claim_indicators(case, cid, rows)
    if calls:
        g = CG.load_graph(case)
        g["nodes"][cid]["input_call_ids"] = list(calls)
        CG.save_graph(case, g)
    return cid


_KIT = [{"type": "file", "value": "svc_kit.exe", "side": "attacker"},
        {"type": "account", "value": "jane.doe", "side": "victim"}]


def _kinds(m, cursor=0):
    return [c["kind"] for c in m.changes_since(cursor)[0]]


def test_keys_fold_account_notations_and_keep_paths_per_host(tmp_path):
    m = IM.open(_case(tmp_path))
    a = m.upsert_entity("account", "CORP\\Jane.Doe")
    assert m.upsert_entity("account", "jane.doe@example.com") == a
    assert m.upsert_entity("account", "corp\\jane.doe") == a
    f1 = m.upsert_entity("file", "C:\\Users\\Public\\svc_kit.exe", host="CORP-WS01")
    f2 = m.upsert_entity("file", "C:\\Users\\Public\\svc_kit.exe", host="CORP-WS02")
    assert f1 != f2 and m.upsert_entity("file", "c:/users/public/SVC_KIT.exe", host="corp-ws01") == f1
    with m._read() as con:
        forms = json.loads(con.execute("SELECT attrs FROM entities WHERE eid = ?", (a,)).fetchone()[0])["forms"]
    assert len(forms) == 3


def test_a_belief_becomes_entities_labels_and_one_coarse_event(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00 under jane.doe.", _KIT)
    m = IM.open(case)
    att = m.attacker_entities()
    assert [(e["kind"], e["value"]) for e in att] == [("file", "svc_kit.exe")]
    with m._read() as con:
        assert con.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM labels WHERE claim_id = ?", (cid,)).fetchone()[0] == 3
        ev = m._attacker_events(con)
    assert [(e["host"], e["t"], e["verb"]) for e in ev] == [("CORP-WS01", "2031-03-10 14:02:00", "belief")]
    assert _kinds(m).count("host_attacker_event") == 1
    supersede(case, cid, reason="the evidence no longer supports this belief")
    assert m.attacker_entities() == []
    with m._read() as con:
        assert m._attacker_events(con) == []
    assert m.changes_since(0)[0][-1]["fields"]["label"] is None


def test_a_label_without_a_belief_is_a_proposal(tmp_path):
    case = _case(tmp_path)
    m = IM.open(case)
    eid = m.upsert_entity("endpoint", "203.0.113.7")
    res = m.label(f"e:{eid}", "attacker")
    assert res["ok"] and any("proposal" in n for n in res["notes"])
    ch = m.changes_since(0)[0]
    assert ch[-1]["kind"] == "entity_labeled" and ch[-1]["fields"]["proposal"] is True
    assert m.attacker_entities() == []


def test_a_label_citing_a_belief_follows_that_beliefs_currency(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "Beacon to 203.0.113.7 from CORP-WS02 at 2031-03-11 08:00:00.", [], host="CORP-WS02")
    m = IM.open(case)
    eid = m.upsert_entity("endpoint", "203.0.113.7")
    assert m.label(f"e:{eid}", "attacker", claim_id=cid)["notes"] == []
    assert [e["entity_id"] for e in m.attacker_entities()] == [eid]
    supersede(case, cid, reason="the evidence no longer supports this belief")
    assert m.attacker_entities() == []


def test_two_beliefs_that_disagree_raise_one_conflict(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    _claim(case, "svc_kit.exe is the owner's tool, seen 2031-03-12 10:00:00.",
           [{"type": "file", "value": "svc_kit.exe", "side": "victim"}])
    m = IM.open(case)
    assert _kinds(m).count("label_conflict") == 1
    m.upsert_entity("account", "jane.doe")
    assert _kinds(m).count("label_conflict") == 1
    # The conservative reading while beliefs disagree: still in the attacker set.
    assert [e["value"] for e in m.attacker_entities()] == ["svc_kit.exe"]


def test_sync_ingests_each_saved_belief_once(tmp_path):
    case = _case(tmp_path)
    m = IM.open(case)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    n = len(m.changes_since(0)[0])
    assert n > 0 and len(m.changes_since(0)[0]) == n
    with m._read() as con:
        assert con.execute("SELECT COUNT(*) FROM ingested").fetchone()[0] == 1


def test_a_reader_does_not_wait_for_the_claim_graph_lock(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    held, release, done = threading.Event(), threading.Event(), threading.Event()

    def recorder():
        with CG._LOCK:
            held.set()
            release.wait(10)

    t = threading.Thread(target=recorder)
    t.start()
    held.wait(5)
    out = []
    r = threading.Thread(target=lambda: (out.append(IM.open(case).attacker_entities()), done.set()))
    r.start()
    assert done.wait(10), "the map waited for the claim graph's lock"
    release.set()
    t.join()
    r.join()
    assert out[0]


def test_a_belief_written_by_another_process_is_ingested_on_the_next_access(tmp_path):
    case = _case(tmp_path)
    m = IM.open(case)
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from core.claim_graph import add_claim, set_claim_indicators\n"
            "cid = add_claim(%r, 'svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.', host='CORP-WS01',"
            " enforce_validation=False)['node_id']\n"
            "set_claim_indicators(%r, cid, [{'type': 'file', 'value': 'svc_kit.exe', 'side': 'attacker'}])\n"
            ) % (str(REPO), str(case), str(case))
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)
    assert [e["value"] for e in m.attacker_entities()] == ["svc_kit.exe"]


def test_the_fingerprint_follows_decisions_not_sightings(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    f0 = m.fingerprint()
    eid = m.attacker_entities()[0]["entity_id"]
    m.add_sighting(eid, "CORP-WS02", "sweep", 12, "2031-03-09 10:00:00")
    m.add_observation("A mailbox rule forwards to an outside address.", host="CORP-SRV01")
    assert m.fingerprint() == f0
    m.label(f"e:{eid}", "benign")
    f1 = m.fingerprint()
    assert f1 != f0
    from core.coverage_ledger import save_ledger
    save_ledger(case, {"units": {}, "items": {"item-1": {"path": "evidence/corp-ws02.raw", "host": "CORP-WS02",
                                                         "state": "pending"}}})
    assert m.fingerprint() != f1


def test_a_ledger_unit_entering_pending_raises_one_change(tmp_path):
    case = _case(tmp_path)
    from core.coverage_ledger import save_ledger
    item = {"path": "evidence/corp-ws02.raw", "host": "CORP-WS02", "state": "pending"}
    save_ledger(case, {"units": {}, "items": {"item-1": item}})
    m = IM.open(case)
    assert [c["fields"] for c in m.changes_since(0)[0]] == [
        {"item_id": "item-1", "level": "item", "host": "CORP-WS02"}]
    save_ledger(case, {"units": {}, "items": {"item-1": {**item, "state": "read"}}})
    assert _kinds(m) == ["evidence_item_pending"]
    save_ledger(case, {"units": {}, "items": {"item-1": item}})
    assert _kinds(m) == ["evidence_item_pending"] * 2
    with m._read() as con:
        attrs = json.loads(con.execute("SELECT attrs FROM entities WHERE kind = 'evidence_item'").fetchone()[0])
    assert "state" not in attrs


def test_the_feed_is_stable_and_a_rebuild_gives_the_same_map(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    _claim(case, "Beacon to 203.0.113.7 from CORP-WS02 at 2031-03-11 08:00:00.",
           [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS02")
    m = IM.open(case)
    first, cur = m.changes_since(0)
    assert m.changes_since(0) == (first, cur) and m.changes_since(cur) == ([], cur) and cur == m.head()

    def snapshot():
        with m._read() as con:
            ents = sorted(tuple(r)[1:5] for r in con.execute("SELECT * FROM entities"))
            labels = sorted((r["target"], r["label"], r["claim_id"], r["proposal"]) for r in con.execute(
                f"SELECT l.* FROM labels l WHERE {IM._CURRENT}"))
        return ents, labels, m.fingerprint()

    before = snapshot()
    sys.path.insert(0, str(REPO / "devtools"))
    from rebuild_incident_map import rebuild
    rebuild(str(case), force=True)
    assert snapshot() == before


def test_writes_return_notes_and_refuse_only_what_cannot_be_stored(tmp_path):
    m = IM.open(_case(tmp_path))
    acct = m.upsert_entity("account", "jane.doe")
    assert not m.add_event("CORP-XX99", "2031-03-10 14:00:00", "logon")["ok"]
    assert not m.add_event("CORP-WS01", "yesterday", "logon")["ok"]
    res = m.add_event("corp-ws01", "2031-03-10T14:00:00Z", "mailbox search", actor=acct, basis=[{"call_id": 9}])
    assert res["ok"] and res["event_id"]
    assert any("stored as other" in n for n in res["notes"]) and any("call 9" in n for n in res["notes"])
    with m._read() as con:
        ev = con.execute("SELECT * FROM events").fetchone()
    assert (ev["host"], ev["kind"], ev["verb"]) == ("CORP-WS01", "other", "mailbox search")


def test_row_ref_for_names_the_row_that_holds_a_quote(tmp_path):
    m = IM.open(_case(tmp_path))
    entries = {
        5: {"type": "tool_call", "stdout_excerpt": json.dumps(
            {"rows": [{"user": "corp\\jane.doe", "host": "CORP-WS01"},
                      {"user": "svc_kit", "path": "C:\\Users\\Public\\svc_kit.exe"}]})},
        6: {"type": "tool_call", "stdout_excerpt": "header\n2031-03-10 14:02:00  logon   jane.doe\n"},
    }
    with patch.object(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid)))):
        assert m.row_ref_for(5, "C:\\Users\\Public\\svc_kit.exe") == "5#R2"
        assert m.row_ref_for(6, "logon  jane.doe") == "6#L2"
        assert m.row_ref_for(6, "absent value") is None
        eid = m.upsert_entity("account", "jane.doe")
        notes = m.label(f"e:{eid}", "benign", basis=[{"call_id": 6, "row_ref": "6#L1"}])["notes"]
    assert any("row 6#L1 shows none of" in n for n in notes)


def test_the_map_is_off_with_its_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_INCIDENT_MAP", "0")
    case = _case(tmp_path)
    assert IM.open(case) is None and not IM.db_path(case).exists()


# ── the anchored window, its checks, joins, summary ─────────────

def _anchor(case, host, t, tier="LIKELY"):
    return _claim(case, f"The attacker reached {host}.", [
        {"type": "host", "value": host, "side": "victim", "attacker_from": t}], tier=tier, host=host)


def _sighted_kit(case, host, t):
    rows = [{"type": "file", "value": "svc_kit.exe", "side": "attacker",
             "sightings": [{"call": 4, "host": host, "first": t, "last": t, "rows": 1}]}]
    return _claim(case, "svc_kit.exe is the attacker's tool.", rows, host="CORP-WS01")


def _checks(m):
    return [(c["kind"], c["fields"]) for c in m.changes_since(0)[0]
            if c["kind"] in ("seen_before_start", "account_before_start")]


def test_a_value_seen_before_its_hosts_anchored_start_is_noted_once(tmp_path):
    case = _case(tmp_path)
    a = _anchor(case, "CORP-WS02", "2031-03-11 09:00:00")
    _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    m = IM.open(case)
    checks = _checks(m)
    assert len(checks) == 1 and checks[0][1]["host"] == "CORP-WS02" and checks[0][1]["anchor_claim"] == a
    assert not checks[0][1]["from_estate_start"]
    m.upsert_entity("account", "jane.doe")
    assert len(_checks(m)) == 1


def test_a_weak_anchor_and_a_coarse_event_never_set_a_start(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-WS02", "2031-03-11 09:00:00", tier="SUSPECTED")
    _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    _claim(case, "svc_kit.exe ran on CORP-WS02 at 2031-03-01 08:00:00.", _KIT[:1], host="CORP-WS02")
    m = IM.open(case)
    w = m.window()
    assert w["hosts"] == {} and w["estate"] is None and _checks(m) == []
    assert "CORP-WS02" in w["unanchored"]


def test_hosts_without_a_start_take_the_estate_start_until_they_state_one(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-WS01", "2031-03-10 00:00:00")
    _sighted_kit(case, "CORP-WS02", "2031-03-02 10:00:00")
    m = IM.open(case)
    (kind, f), = _checks(m)
    assert f["host"] == "CORP-WS02" and f["from_estate_start"] and f["anchor"] == "2031-03-10 00:00:00"
    assert m.window()["unanchored"] == ["CORP-WS02"]
    _anchor(case, "CORP-WS02", "2031-03-01 00:00:00")
    w = m.window()
    assert w["hosts"]["CORP-WS02"][0][0] == "2031-03-01 00:00:00" and "CORP-WS02" not in w["unanchored"]
    assert w["estate"][0] == "2031-03-01 00:00:00"


def test_fine_events_anchor_and_accounts_are_checked_against_their_own_start(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "jane.doe was the attacker's account from 2031-03-12 08:00:00.", [
        {"type": "account", "value": "jane.doe", "side": "attacker", "attacker_from": "2031-03-12 08:00:00"}])
    m = IM.open(case)
    acct = m.upsert_entity("account", "jane.doe")
    src = m.upsert_entity("host", "CORP-WS01")
    dst = m.upsert_entity("host", "CORP-SRV01")
    ev = m.add_event("CORP-SRV01", "2031-03-11 07:00:00", "logon", actor=acct, src=src, dst=dst)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    assert [k for k, _f in _checks(m)] == ["account_before_start"]
    # An event that drew a note anchors nothing; the inbound edge is seen.
    assert m.window()["hosts"] == {}
    with m._read() as con:
        assert m._inbound_hosts(con) == {"CORP-SRV01"}
    ev2 = m.add_event("CORP-SRV01", "2031-03-12 09:00:00", "logon", actor=acct, src=src, dst=dst)["event_id"]
    m.label(f"v:{ev2}", "attacker", claim_id=cid)
    w = m.window()
    assert w["hosts"]["CORP-SRV01"][0] == ("2031-03-12 09:00:00", cid) and w["via"]["CORP-SRV01"] == "inbound"


def test_incident_window_keeps_its_shape_with_the_map(tmp_path):
    from core.incident_window import incident_window
    case = _case(tmp_path)
    _anchor(case, "CORP-WS01", "2031-03-10 14:00:00")
    _claim(case, "svc_backup acted at 2031-03-10 15:00:00.", [
        {"type": "account", "value": "svc_backup", "side": "victim", "attacker_from": "2031-03-10 15:00:00"}])
    rows = incident_window(CG.load_graph(case))
    mapped = incident_window(CG.load_graph(case), case_dir=case)
    for key in ("hosts", "accounts", "estate", "attacker_accounts", "own_accounts", "compromised", "noted"):
        assert mapped[key] == rows[key], key


def test_the_rarity_rule_has_a_floor_of_one_host():
    from core.contents_index import is_specific
    assert is_specific(1, 1) and is_specific(1, 3) and is_specific(3, 30)
    assert not is_specific(2, 3) and not is_specific(29, 30)


def test_an_attacker_accounts_profile_folder_on_another_host_is_a_join(tmp_path):
    case = _case(tmp_path)
    _claim(case, "jane.doe acted for the attacker at 2031-03-10 14:00:00.",
           [{"type": "account", "value": "jane.doe", "side": "attacker"}])
    profiles = {"corp-ws01": {"jane.doe"}, "corp-ws02": {"jane.doe"}, "corp-srv01": {"admin"}}
    with patch.object(IM.IncidentMap, "_profile_cache", lambda self: profiles):
        m = IM.open(case)
    joins = [c["fields"] for c in m.changes_since(0)[0] if c["kind"] == "join_hit"]
    assert [(j["host"], j["via"], j["k"], j["n"]) for j in joins] == [("CORP-WS02", "account", 2, 3)]


def test_a_host_with_attacker_events_and_no_inbound_edge_is_raised_once(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    m.upsert_entity("account", "jane.doe")
    assert [c["fields"] for c in m.changes_since(0)[0] if c["kind"] == "host_without_inbound"] == [
        {"host": "CORP-WS01"}]


def test_the_summary_is_deterministic_and_within_budget(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-WS01", "2031-03-10 00:00:00")
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    s1 = m.summary({"host": "CORP-WS01"})
    assert s1 == IM.open(case).summary({"host": "CORP-WS01"})
    assert s1.startswith("estate start: 2031-03-10 00:00:00") and "attacker file" in s1 and "event v:" in s1
    short = m.summary(budget_chars=120)
    assert len(short) <= 120 and short.endswith("more lines)")


def test_a_record_gets_the_notes_its_belief_raised(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-WS02", "2031-03-11 09:00:00")
    IM.open(case)
    _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    notes = IM.record_notes(case)
    assert len(notes) == 1 and "svc_kit.exe" in notes[0] and "before the attacker's first activity" in notes[0]
    assert IM.record_notes(case) == []


# ── account folding, reopen, ids and held starts ────────────────────────────────────────────

def test_local_accounts_stay_apart_and_domain_forms_fold(tmp_path):
    m = IM.open(_case(tmp_path))
    a1 = m.upsert_entity("account", "CORP-WS01\\admin")
    a2 = m.upsert_entity("account", "CORP-WS02\\admin")
    a3 = m.upsert_entity("account", ".\\admin", host="CORP-WS01")
    assert a1 != a2 and a3 == a1 and m.upsert_entity("account", "admin") not in (a1, a2)
    j = m.upsert_entity("account", "CORP\\jane.doe")
    assert m.upsert_entity("account", "jane.doe@example.com") == j
    with m._read() as con:
        attrs = json.loads(con.execute("SELECT attrs FROM entities WHERE eid = ?", (j,)).fetchone()[0])
    assert attrs["qualified"] is True


def test_a_reopen_between_two_syncs_is_raised(tmp_path):
    from core.coverage_ledger import load_ledger, save_ledger
    from core.evidence_disposition import reopen
    case = _case(tmp_path)
    save_ledger(case, {"units": {}, "items": {"item-1": {"path": "evidence/corp-ws02.raw", "host": "CORP-WS02",
                                                         "state": "pending"}}})
    m = IM.open(case)
    ledger = load_ledger(case)
    ledger["items"]["item-1"]["state"] = "left"
    save_ledger(case, ledger)
    reopen(ledger["items"]["item-1"], "an attacker value reaches it")
    save_ledger(case, ledger)
    assert _kinds(m) == ["evidence_item_pending"] * 2


def test_a_deleted_events_id_is_never_reused(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    with m._read() as con:
        old = con.execute("SELECT MAX(vid) FROM events").fetchone()[0]
    g = CG.load_graph(case)
    g["nodes"][cid]["statement"] = "svc_kit.exe ran on CORP-WS01."
    CG.save_graph(case, g)
    m.sync()
    ev = m.add_event("CORP-WS01", "2031-03-10 15:00:00", "process")["event_id"]
    assert ev > old


def test_held_fine_event_starts_are_listed_as_noted(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "svc_kit.exe ran on CORP-SRV01 at 2031-03-01 08:00:00.", _KIT[:1], host="CORP-SRV01")
    g = CG.load_graph(case)
    g["nodes"][cid]["window_noted"] = True
    CG.save_graph(case, g)
    m = IM.open(case)
    ev = m.add_event("CORP-SRV01", "2031-03-01 08:00:00", "process")["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    w = m.window()
    assert w["hosts"] == {} and ("host", "CORP-SRV01", "2031-03-01 08:00:00", cid) in w["noted"]
    from core.evidence_leave import window_start
    assert window_start(case) == "2031-03-01 08:00:00"


def test_a_belief_about_another_host_does_not_anchor_an_event(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "Beacon to 203.0.113.7 from CORP-WS02 at 2031-03-11 08:00:00.",
                 [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS02")
    m = IM.open(case)
    ev = m.add_event("CORP-SRV01", "2031-03-01 08:00:00", "process")["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    assert m.window()["hosts"] == {}
    assert "not anchoring" in m.summary({"host": "CORP-SRV01"})
    ip = [e for e in m.attacker_entities() if e["kind"] == "endpoint"][0]["entity_id"]
    ev2 = m.add_event("CORP-SRV01", "2031-03-12 08:00:00", "connection", object=ip)["event_id"]
    m.label(f"v:{ev2}", "attacker", claim_id=cid)
    assert m.window()["hosts"]["CORP-SRV01"][0] == ("2031-03-12 08:00:00", cid)


def test_incremental_derives_miss_nothing_a_full_derive_finds(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-WS01", "2031-03-10 00:00:00")
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    kit = m.attacker_entities()[0]["entity_id"]
    res = m.add_sightings([{"entity_id": kit, "host": "CORP-WS02", "source": "sweep", "call_id": 7,
                            "time": "2031-03-02 10:00:00"},
                           {"entity_id": kit, "host": "CORP-XX99", "source": "sweep", "call_id": 8}])
    assert res["stored"] == 1 and len(res["notes"]) == 1
    m.upsert_entity("file", "D:\\Tools\\svc_kit.exe", host="CORP-SRV01")
    m.upsert_entity("file", "a" * 64, attrs={"sha256": "a" * 64})
    before = m.changes_since(0)[0]
    kinds = [c["kind"] for c in before]
    assert "seen_before_start" in kinds and kinds.count("join_hit") == 2
    with m._write() as con:
        con.execute("DELETE FROM meta WHERE key = 'attackers'")
    assert m.changes_since(0)[0][len(before):] == []


# ── signals into the work order ─────────────────────────────

def _wide(case, n=17):
    """The fixture's three hosts and ``n`` more, so a value two hosts hold is specific."""
    links = json.loads((case / ".atlas" / "evidence_links.json").read_text())
    links["links"] += [{"label": f"CORP-X{i:02d}", "path": f"evidence/corp-x{i:02d}.raw"} for i in range(n)]
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps(links), encoding="utf-8")
    return case


def _trace(case, monkeypatch):
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return log


def test_specific_joins_fold_into_one_item_per_host(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    _claim(case, "jane.doe acted for the attacker at 2031-03-10 14:00:00.",
           [{"type": "account", "value": "jane.doe", "side": "attacker"}])
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    profiles = {"corp-ws01": {"jane.doe"}, "corp-ws02": {"jane.doe"}, "corp-srv01": {"admin"}}
    profiles.update({f"corp-x{i:02d}": {"admin"} for i in range(17)})
    m = IM.open(case)
    with patch.object(IM.IncidentMap, "_profile_cache", lambda self: profiles):
        m.upsert_entity("account", "jane.doe")
        with m._write() as con:
            con.execute("DELETE FROM meta WHERE key IN ('attackers', 'listing_joined')")
        cur = IM.feed_work_items(log, case, 0)
    m.upsert_entity("file", "D:\\Kit\\svc_kit.exe", host="CORP-WS02")
    IM.feed_work_items(log, case, cur)
    IM.feed_work_items(log, case, 0)
    items = log.work_items()
    assert [(i["origin"], i["status"], i["target"]["host"], i["target"]["path"]) for i in items] == [
        ("join_hit", "due", "CORP-WS02", "evidence/corp-ws02.raw")]
    assert "account jane.doe by account (2 of 20 hosts)" in items[0]["why"]
    assert "file svc_kit.exe by name (2 of 20 hosts)" in items[0]["why"]
    from tests.core.test_work_order import _call
    read = _call(log, "strings_read_text", {"file": "evidence/corp-ws02.raw"})
    assert log.close_items_for_call("strings_read_text", {"file": "evidence/corp-ws02.raw"}, [read]) == [
        items[0]["call_id"]]


def test_a_join_to_a_host_with_attacker_events_is_a_proposal(tmp_path, monkeypatch):
    case = _wide(_case(tmp_path))
    log = _trace(case, monkeypatch)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    _claim(case, "Beacon from CORP-WS02 at 2031-03-11 08:00:00.",
           [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}], host="CORP-WS02")
    m = IM.open(case)
    m.upsert_entity("file", "D:\\Kit\\svc_kit.exe", host="CORP-WS02")
    IM.feed_work_items(log, case, 0)
    assert [(i["status"], i["target"]["host"]) for i in log.work_items()] == [("proposed", "CORP-WS02")]
    monkeypatch.setenv("ATLAS_MAP_SIGNALS_TO_WORK_ORDER", "0")
    m.upsert_entity("file", "E:\\svc_kit.exe", host="CORP-SRV01")
    IM.feed_work_items(log, case, 0)
    assert len(log.work_items()) == 1


def test_an_account_start_alone_rechecks_the_events_of_that_account(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "jane.doe logged on to CORP-SRV01 at 2031-03-11 07:00:00.", [
        {"type": "account", "value": "jane.doe", "side": "attacker"}], host="CORP-SRV01")
    m = IM.open(case)
    acct = m.upsert_entity("account", "jane.doe")
    ev = m.add_event("CORP-SRV01", "2031-03-11 07:00:00", "logon", actor=acct)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    assert [k for k, _f in _checks(m)] == []
    _claim(case, "jane.doe became the attacker's at 2031-03-12 08:00:00.", [
        {"type": "account", "value": "jane.doe", "side": "attacker", "attacker_from": "2031-03-12 08:00:00"}],
        host="CORP-SRV01")
    # The fine event and the first belief's coarse event both precede the stated start.
    noted = [f["event_id"] for k, f in _checks(m) if k == "account_before_start"]
    assert ev in noted and len(noted) == 2


def test_later_activity_never_notes_an_earlier_event(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "svc_backup logged on to CORP-WS02 and CORP-SRV01.", [
        {"type": "account", "value": "svc_backup", "side": "attacker"}], host="CORP-WS02")
    m = IM.open(case)
    acct = m.upsert_entity("account", "svc_backup")
    for host, t in (("CORP-WS02", "2031-03-11 08:10:00"), ("CORP-WS02", "2031-03-12 08:11:00")):
        ev = m.add_event(host, t, "logon", actor=acct)["event_id"]
        m.label(f"v:{ev}", "attacker", claim_id=cid)
    assert _checks(m) == []
    assert m.window()["hosts"]["CORP-WS02"][0] == ("2031-03-11 08:10:00", cid)


def test_disposition_reads_the_maps_attacker_set_with_proposals(tmp_path):
    from core.evidence_leave import attacker_entities
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT)
    m = IM.open(case)
    m.label(f"e:{m.upsert_entity('endpoint', '203.0.113.9')}", "attacker")
    assert attacker_entities(case) == ["203.0.113.9", "svc_kit.exe"]


# ── views ────────────────────────────────────────────────────────

def _tasks(case, parts=(("p1", "open"),)):
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "text": "Which hosts did the attacker reach, and from where?", "status": "open",
         "parts": [{"id": pid, "text": f"part {pid}", "status": st, "claim_ids": []} for pid, st in parts]}]}),
        encoding="utf-8")


def _three_hosts(case):
    out = {}
    for h, t in (("CORP-WS01", "2031-03-10 14:02:00"), ("CORP-WS02", "2031-03-11 09:00:00"),
                 ("CORP-SRV01", "2031-03-12 10:00:00")):
        out[h] = _claim(case, f"svc_kit.exe ran on {h} at {t}.", _KIT[:1], host=h)
    return out


_SPEC = {"over": "host", "where": {"label": "attacker"},
         "columns": ["first_attacker_event.time", "inbound.src", "inbound.verb"]}


def test_every_part_has_a_view_and_the_default_row_follows_the_part(tmp_path):
    case = _case(tmp_path)
    _tasks(case, (("p1", "open"), ("p2", "answered")))
    m = IM.open(case)
    rows = {v["part_id"]: (v["declared_by"], v["rows"][0]["status"]) for v in m.views()}
    assert rows == {"p1": ("default", "open"), "p2": ("default", "filled")}
    assert [v["part_id"] for v in m.views(open_only=True)] == ["p1"]


def test_a_view_over_hosts_fills_from_beliefs_and_keeps_open_cells_open(tmp_path):
    case = _case(tmp_path)
    _tasks(case)
    claims = _three_hosts(case)
    m = IM.open(case)
    res = m.declare_view("task-0001", "p1", _SPEC)
    assert res["ok"]
    ws01 = m.upsert_entity("host", "CORP-WS01")
    srv = m.upsert_entity("host", "CORP-SRV01")
    ev = m.add_event("CORP-SRV01", "2031-03-12 09:30:00", "logon", src=ws01, dst=srv)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=claims["CORP-SRV01"])
    view = [v for v in m.views() if v["view_id"] == res["view_id"]][0]
    rows = {r["row_key"]: r for r in view["rows"]}
    assert sorted(rows) == ["CORP-SRV01", "CORP-WS01", "CORP-WS02"]
    assert rows["CORP-SRV01"]["cells"]["inbound.src"]["value"] == "CORP-WS01"
    assert rows["CORP-SRV01"]["status"] == "filled" and claims["CORP-SRV01"] in rows["CORP-SRV01"]["basis_ids"]
    assert rows["CORP-WS02"]["cells"]["inbound.src"]["value"] == "open" and rows["CORP-WS02"]["status"] == "open"
    bad = m.declare_view("task-0001", "p1", {"over": "host", "columns": ["inbound.color"]})
    assert not bad["ok"] and "inbound.src" in bad["notes"][0]
    empty = m.declare_view("task-0001", "p1", {"over": "account", "where": {"label": "attacker"},
                                               "columns": ["label"]})
    cur = [v for v in m.views() if v["part_id"] == "p1"]
    assert [v["view_id"] for v in cur] == [empty["view_id"]] and cur[0]["rows"][0]["row_key"] == "-"
    with m._read() as con:
        assert con.execute("SELECT COUNT(*) FROM views WHERE part_id = 'p1'").fetchone()[0] == 3


def test_a_proposed_label_keeps_its_row_open(tmp_path):
    case = _case(tmp_path)
    _tasks(case)
    m = IM.open(case)
    m.label(f"e:{m.upsert_entity('endpoint', '203.0.113.7')}", "attacker")
    v = m.declare_view("task-0001", "p1", {"over": "endpoint", "where": {"label": "attacker"},
                                           "columns": ["label", "hosts"]})
    (row,) = [x for x in m.views() if x["view_id"] == v["view_id"]][0]["rows"]
    assert row["row_key"] == "203.0.113.7" and row["cells"]["label"]["value"] == "proposed"
    assert row["status"] == "open"


def test_an_open_row_of_a_declared_view_stays_in_the_view_and_makes_no_item(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    _tasks(case)
    _three_hosts(case)
    m = IM.open(case)
    m.declare_view("task-0001", "p1", _SPEC)
    IM.feed_work_items(log, case, 0)
    (v,) = [v for v in m.views() if v["part_id"] == "p1"]
    assert {r["status"] for r in v["rows"]} == {"open"} and len(v["rows"]) == 3
    assert [i for i in log.work_items() if i["origin"] == "view_row_opened"] == []


def test_a_resumed_traces_per_row_view_items_are_moot_and_say_why(tmp_path, monkeypatch):
    from core.work_order import report_lines
    case = _case(tmp_path)
    old = _trace(case, monkeypatch)
    row = old.add_work_item("view_row_opened", ["task-0001"], "", {"host": "CORP-WS02"},
                            "task-0001 part p1: row CORP-WS02 of its view is open", status="due",
                            source_ref={"kind": "view_row", "view_id": 2, "row_key": "CORP-WS02"})["call_id"]
    part = old.add_work_item("view_row_opened", ["task-0001"], "", None, "task-0001 part p1: 1 open row(s)",
                             status="due", source_ref={"kind": "view_part", "task_id": "task-0001",
                                                       "part_id": "p1", "view_id": 2, "rows": ["CORP-WS02"]},
                             extra_key="view_part:task-0001:p1:0")["call_id"]
    log = _trace(case, monkeypatch)                           # the trace loaded again, as on a resume
    IM.feed_work_items(log, case, 0)
    st = {i["call_id"]: (i["status"], i.get("outcome")) for i in log.work_items()}
    assert st[row] == ("moot", "its view no longer makes items") and st[part][0] == "due"
    assert f"- Planned reads not done: #{row} task-0001  CORP-WS02: not read: its view no longer makes items" \
        in report_lines(log, str(case))


def test_the_plan_reply_declares_views_and_the_composer_shows_and_accepts_rows(tmp_path):
    from core import answer_synthesis as A
    from core.question_plan import declare_plan_views, plan_system
    case = _case(tmp_path)
    _tasks(case)
    claims = _three_hosts(case)
    assert '"views":[' in plan_system()
    task = json.loads((case / ".atlas" / "investigation_tasks.json").read_text())["tasks"][0]
    reply = json.dumps({"reads": [], "views": [{"part": "p1", **_SPEC}, {"part": "p9", "over": "host"}]})
    out = declare_plan_views(str(case), task, reply)
    assert out["declared"] == 1 and "p9" in out["notes"][0]
    sheet = A.answer_sheet(task, CG.load_graph(case), case_dir=str(case))
    assert [r["id"] for r in sheet["views"]] == ["r1", "r2", "r3"] and "VIEW (" in sheet["text"]
    assert "VIEW lines are" in A.compose_prompt(sheet)        # the rule, numbered by the sheet
    open_row = next(r["id"] for r in sheet["views"] if "(open)" in r["text"])
    sentences = A.parse_composed(f"How the attacker reached that host is not established [{open_row.upper()}].")
    assert sentences[0]["ids"] == [open_row]
    checked, _missing = A.check_composed(sentences, sheet, CG.load_graph(case), frozenset())
    assert checked[0]["ok"], checked[0]["reasons"]


def test_views_are_off_with_their_switch(tmp_path, monkeypatch):
    from core.question_plan import plan_system
    monkeypatch.setenv("ATLAS_MAP_VIEWS", "0")
    case = _case(tmp_path)
    _tasks(case)
    assert IM.open(case).views() == [] and '"views"' not in plan_system()


def test_an_inbound_edge_bounds_the_events_of_its_host(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "The attacker logged on to CORP-WS02 from CORP-WS01.", [], host="CORP-WS02")
    early = _claim(case, "A cloud sync ran on CORP-WS02 at 2031-03-04 10:00:00.", _KIT[:1], host="CORP-WS02")
    m = IM.open(case)
    a, b = m.upsert_entity("host", "CORP-WS01"), m.upsert_entity("host", "CORP-WS02")
    ev = m.add_event("CORP-WS02", "2031-03-11 09:00:00", "logon", src=a, dst=b)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    noted = [f for k, f in _checks(m) if f.get("event_id")]
    assert [(f["host"], f["time"], f["anchor"]) for f in noted] == [
        ("CORP-WS02", "2031-03-04 10:00:00", "2031-03-11 09:00:00")]
    assert early


def test_an_inbound_edge_elsewhere_is_no_estate_start(tmp_path):
    case = _case(tmp_path)
    cid = _claim(case, "The attacker logged on to CORP-WS02 from CORP-WS01.", [], host="CORP-WS02")
    _sighted_kit(case, "CORP-WS01", "2031-03-02 10:00:00")
    m = IM.open(case)
    a, b = m.upsert_entity("host", "CORP-WS01"), m.upsert_entity("host", "CORP-WS02")
    ev = m.add_event("CORP-WS02", "2031-03-11 09:00:00", "logon", src=a, dst=b)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    assert _checks(m) == []


# ── review batch: stale hosts, conflicts, fixpoint, lapse, n_kind ───────

def test_a_retired_beliefs_sightings_and_event_leave_the_entity(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    other = _sighted_kit(case, "CORP-WS02", "2031-03-04 10:00:00")
    m = IM.open(case)
    assert m.attacker_entities()[0]["hosts"] == ["CORP-WS01", "CORP-WS02"]
    supersede(case, other, reason="the evidence no longer supports this belief")
    assert m.attacker_entities()[0]["hosts"] == ["CORP-WS01"]


def test_unknown_takes_no_position_in_a_conflict(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    _claim(case, "svc_kit.exe seen again at 2031-03-12 10:00:00.",
           [{"type": "file", "value": "svc_kit.exe", "side": "undetermined"}])
    assert "label_conflict" not in _kinds(IM.open(case))


def test_a_noted_event_stops_anchoring_in_the_same_write(tmp_path):
    case = _case(tmp_path)
    _anchor(case, "CORP-SRV01", "2031-03-01 00:00:00")
    cid = _claim(case, "jane.doe logged on to CORP-WS02 from CORP-SRV01.", [
        {"type": "account", "value": "jane.doe", "side": "attacker", "attacker_from": "2031-03-12 00:00:00"}],
        host="CORP-WS02")
    m = IM.open(case)
    a, b = m.upsert_entity("host", "CORP-SRV01"), m.upsert_entity("host", "CORP-WS02")
    acct = m.upsert_entity("account", "jane.doe")
    kit = m.upsert_entity("file", "svc_kit.exe", host="CORP-WS02")
    m.label(f"e:{kit}", "attacker", claim_id=cid)
    m.add_sighting(kit, "CORP-WS02", "sweep", 3, "2031-03-08 10:00:00")
    # The logon precedes its account's stated start: noted, so it bounds
    # nothing on CORP-WS02, and the earlier sighting there draws no note.
    ev = m.add_event("CORP-WS02", "2031-03-09 09:00:00", "logon", actor=acct, src=a, dst=b)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    checks = _checks(m)
    assert [(k, f.get("event_id")) for k, f in checks] == [("account_before_start", ev)]
    w = m.window()
    assert "CORP-WS02" not in w["hosts"] and ("host", "CORP-WS02", "2031-03-09 09:00:00", cid) in w["noted"]


def test_joins_say_what_their_denominator_counts(tmp_path):
    case = _case(tmp_path)
    _claim(case, "svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:02:00.", _KIT[:1])
    m = IM.open(case)
    m.upsert_entity("file", "D:\\Kit\\svc_kit.exe", host="CORP-WS02")
    (j,) = [c["fields"] for c in m.changes_since(0)[0] if c["kind"] == "join_hit"]
    assert j["n_kind"] == "case_hosts" and j["n"] == 3


def _evaluate(log, statement):
    cid = log._next_id()
    log._entries.append({"type": "reason_call", "tool": "reason_evaluate_finding", "call_id": cid,
                         "success": True, "conclusion": "VERDICT: SUPPORTED, the evidence holds it.",
                         "inputs": {"user_message": f"Finding: {statement}"}})
    return cid


def _noted_logon(case, log, before):
    statement = "jane.doe logged on to CORP-WS02 from CORP-SRV01."
    cid = _claim(case, statement, [
        {"type": "account", "value": "jane.doe", "side": "attacker", "attacker_from": "2031-03-12 00:00:00"}],
        host="CORP-WS02")
    if before:
        _evaluate(log, statement)
    m = IM.open(case)
    a, b = m.upsert_entity("host", "CORP-SRV01"), m.upsert_entity("host", "CORP-WS02")
    acct = m.upsert_entity("account", "jane.doe")
    ev = m.add_event("CORP-WS02", "2031-03-09 09:00:00", "logon", actor=acct, src=a, dst=b)["event_id"]
    m.label(f"v:{ev}", "attacker", claim_id=cid)
    return m, statement


def test_an_evaluation_before_the_note_does_not_answer_it(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m, _statement = _noted_logon(case, log, before=True)
    assert "CORP-WS02" not in m.window()["hosts"]


def test_an_evaluation_after_the_note_lets_the_event_anchor_again(tmp_path, monkeypatch):
    case = _case(tmp_path)
    log = _trace(case, monkeypatch)
    m, statement = _noted_logon(case, log, before=False)
    assert "CORP-WS02" not in m.window()["hosts"]
    _evaluate(log, statement)
    assert m.window()["hosts"]["CORP-WS02"][0][0] == "2031-03-09 09:00:00"


def test_the_same_event_written_twice_is_one_event_with_both_bases(tmp_path):
    m = IM.open(_case(tmp_path))
    acct = m.upsert_entity("account", "jane.doe", host="CORP-WS01")
    one = m.add_event("CORP-WS01", "2031-03-10T14:00:00Z", "logon", actor=acct, basis=[{"call_id": 7}])
    two = m.add_event("CORP-WS01", "2031-03-10 14:00:00", "logon", actor=acct, basis=[{"call_id": 8}])
    assert two["event_id"] == one["event_id"] and two.get("existing") and m.counts()["events"] == 1
    with m._read() as con:
        src = json.loads(con.execute("SELECT source FROM events").fetchone()[0])
    assert src["basis"] == [{"call_id": 7}, {"call_id": 8}]
    other = m.add_event("CORP-WS01", "2031-03-10 14:00:00", "logon", object=acct)      # another role
    assert other["event_id"] != one["event_id"] and m.counts()["events"] == 2


_SENTENCE = "the attacker staged the archive in a hidden folder"


def _grep_entry(pattern, out):
    return {"type": "tool_call", "cmd": "<py>:strings_grep", "success": True,
            "args": json.dumps({"path": "exports/corp-ws01-notes.txt", "pattern": pattern}), "stdout_excerpt": out}


def test_a_search_that_echoes_its_pattern_gives_no_basis_in_either_mode(tmp_path):
    from tools._gates.citation_support import call_output_text
    m = IM.open(_case(tmp_path))
    entries = {
        31: _grep_entry(_SENTENCE, json.dumps({"pattern": _SENTENCE, "matches": 0, "rows": []})),
        32: _grep_entry(_SENTENCE, f"searched exports/corp-ws01-notes.txt for '{_SENTENCE}'\n0 matches\n"),
    }
    with patch.object(IM.IncidentMap, "_entry", staticmethod(lambda cid: entries.get(int(cid)))):
        for cid in entries:
            assert m.row_ref_for(cid, _SENTENCE) is None
            assert m.row_ref_for_cells(cid, ["the attacker staged", "hidden folder"]) is None
    # the conversation mode's citation reader is the same echo-free one
    for e in entries.values():
        assert _SENTENCE not in call_output_text(e).lower()


def test_a_real_hit_quoting_the_searched_value_still_names_its_row(tmp_path):
    m = IM.open(_case(tmp_path))
    hit = _grep_entry("svc_kit.exe", json.dumps({"pattern": "svc_kit.exe", "rows": [
        {"User": "jane.doe", "Image": "C:\\Users\\Public\\svc_kit.exe"}]}))
    with patch.object(IM.IncidentMap, "_entry", staticmethod(lambda cid: hit)):
        assert m.row_ref_for(33, "svc_kit.exe") is None                   # the pattern alone shows nothing
        assert m.row_ref_for(33, "C:\\Users\\Public\\svc_kit.exe") == "33#R1"
        assert m.row_ref_for_cells(33, ["jane.doe", "svc_kit.exe"]) == "33#R1"


def test_data_lines_keep_the_searched_value_and_echo_lines_go():
    from core.indicators import _rows_of
    entry = _grep_entry("jane.doe", "")
    raw = ("Searching for \"jane.doe\" in exports/corp-ws01-notes.txt\n"
           "\"TargetUserName\": \"jane.doe\"\n"
           "2031-03-10 14:02:00,\"jane.doe\",\"CORP-WS01\"\n"
           "user=\"jane.doe\" host=CORP-WS01\n")
    rows = _rows_of(entry, raw)[0]
    assert rows == ["\"TargetUserName\": \"jane.doe\"", "2031-03-10 14:02:00,\"jane.doe\",\"CORP-WS01\"",
                    "user=\"jane.doe\" host=CORP-WS01"]


def test_digit_free_data_lines_keep_the_value_and_only_banner_echoes_go():
    from core.indicators import _rows_of
    entry = _grep_entry("jane.doe", "")
    kept = ["net user jane.doe /add", "User \"jane.doe\" logged on from WORKSTATION",
            "powershell -c \"jane.doe\"", "jane.doe", "Select-String -Pattern jane.doe",
            "Get-ADUser -Filter jane.doe"]
    raw = "\n".join(["Searching for \"jane.doe\" in exports/corp-ws01-notes.txt", *kept,
                     "looking for jane.doe"]) + "\n"
    assert _rows_of(entry, raw)[0] == kept
