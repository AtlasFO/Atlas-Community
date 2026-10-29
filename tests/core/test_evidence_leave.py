"""Evidence disposition: the leave checks. Invented fixtures only
(CORP-WS01..03, jane.doe, john.roe, svc_kit.exe, dates in 2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from core.claim_graph import add_claim, set_claim_indicators
from core.coverage_ledger import build_coverage_ledger, load_ledger
from core import evidence_leave as L
from tests.core.test_contents_index import _build, _image, _links, _plan, case  # noqa: F401

T_OLD = "1924560000"        # 2030-12-27 in the bodyfile's epoch seconds
T_NEW = "1931000000"        # 2031-03-12


def _b(path, inode, t, size=4096, mode="r/rrwxrwxrwx"):
    return f"0|/{path}|{inode}|{mode}|0|0|{size}|{t}|{t}|{t}|{t}"


def _case(case, monkeypatch, ws03=None):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-WS02", "evidence/disk/corp-ws02.raw"),
                  ("CORP-WS03", "evidence/disk/corp-ws03.raw")])
    _plan(case, [_image(case, n) for n in ("corp-ws01.raw", "corp-ws02.raw", "corp-ws03.raw")])
    std = [_b("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", T_NEW, 70000)]
    _build(case, monkeypatch, {
        "corp-ws01.raw": std + [_b("Users/jane.doe/a.txt", "210-128-1", T_NEW)],
        "corp-ws02.raw": std + [_b("Users/jane.doe/b.txt", "211-128-1", T_NEW),
                                _b("Users/Public/x.txt", "212-128-1", T_NEW)],
        "corp-ws03.raw": ws03 or [_b("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", T_OLD, 70000),
                                  _b("Users/john.roe/c.txt", "213-128-1", T_OLD)]})
    c = add_claim(case, "The attacker reached CORP-WS01 at 2031-03-10 14:00:00.", confidence="LIKELY",
                  host="CORP-WS01", enforce_validation=False)["node_id"]
    set_claim_indicators(case, c, [{"type": "host", "value": "CORP-WS01", "side": "victim",
                                    "attacker_from": "2031-03-10 14:00:00"}])
    return build_coverage_ledger(case)


def _item(led, name):
    return next(i["path"] for i in led["items"].values() if i["path"].endswith(name))


def test_outside_window_is_one_sided(case, monkeypatch):
    led = _case(case, monkeypatch)
    ok = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "outside_window", "its data ends before the stated start of the incident")
    assert ok["ok"], ok
    no = L.check_leave(case, led, _item(led, "corp-ws02.raw"), "outside_window", "a stated reason of enough length for the writer")
    assert not no["ok"] and "after the window" in no["error"]
    mem = {"id": "m", "path": "evidence/mem/corp-ws03.mem", "kind": "memory", "host": "CORP-WS03"}
    led["items"]["m"] = mem
    assert "never outside" in L.check_leave(case, led, "m", "outside_window", "a stated reason of enough length for the writer")["error"]


def test_other_scope_needs_an_unnamed_host_sharing_no_account(case, monkeypatch):
    led = _case(case, monkeypatch)
    assert L.check_leave(case, led, _item(led, "corp-ws03.raw"), "other_scope", "its host is not among the hosts in scope")["ok"]
    shared = L.check_leave(case, led, _item(led, "corp-ws02.raw"), "other_scope", "a stated reason of enough length for the writer")
    assert not shared["ok"] and "jane.doe" in shared["error"]
    named = L.check_leave(case, led, _item(led, "corp-ws01.raw"), "other_scope", "a stated reason of enough length for the writer")
    assert not named["ok"] and "named by a current finding" in named["error"]


def test_a_leave_is_refused_while_the_sweep_finds_an_attacker_entity(case, monkeypatch):
    led = _case(case, monkeypatch, ws03=[_b("Users/john.roe/svc_kit.exe", "300-128-1", T_OLD)])
    c = add_claim(case, "svc_kit.exe is the attacker's tool.", confidence="LIKELY", host="CORP-WS01",
                  enforce_validation=False)["node_id"]
    set_claim_indicators(case, c, [{"type": "file", "value": "svc_kit.exe", "side": "attacker"}])
    r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "outside_window", "its data is older than the stated start of the incident")
    assert not r["ok"] and "svc_kit.exe in evidence/disk/corp-ws03.raw::Users/john.roe/svc_kit.exe" in r["error"]


def test_unreadable_needs_reader_failures_or_no_reader(case, monkeypatch):
    led = _case(case, monkeypatch)
    with patch.object(L, "readers_for", lambda fmt: ["tsk.tsk_fls"]):
        r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "unreadable", "its filesystem does not open with any reader", ["1", "2"])
        assert not r["ok"] and "two failed calls" in r["error"]
    with patch.object(L, "readers_for", lambda fmt: []), patch.object(L, "unit_readers", lambda *a, **k: ([], True)):
        # An image is opened by Atlas's own readers: "no reader" never holds for it.
        no = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "unreadable", "no installed reader declares its format at all")
        assert not no["ok"] and "tools that open it" in no["error"]
        cid = next(c["id"] for c in led["classes"].values() if c["item"] == next(
            i["id"] for i in led["items"].values() if i["path"].endswith("corp-ws03.raw")))
        # A known format no reader declares is code's fact (no_reader): a
        # model's unreadable leave of it is refused and told so; the code
        # leave takes it.
        no_model = L.check_leave(case, led, cid, "unreadable", "no installed reader takes its format at all")
        assert not no_model["ok"] and "no_reader" in no_model["error"]
        assert L.check_leave(case, led, cid, "unreadable", "no installed reader takes its format at all",
                             by_code=True)["ok"]
        assert L.check_leave(case, led, _item(led, "corp-ws03.raw"), "unrelated_content", "no registered reader parses any of its classes")["ok"]
        led["items"]["m"] = {"id": "m", "path": "evidence/mem/x.mem", "kind": "memory", "host": "CORP-WS03"}
        assert "no content classes" in L.check_leave(case, led, "m", "unrelated_content", "a stated reason of enough length for the writer")["error"]
    with patch.object(L, "readers_for", lambda fmt: ["ez.evtxecmd"]):
        r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "unrelated_content", "a stated reason of enough length for the writer")
        assert not r["ok"] and "registered readers parse" in r["error"]


def test_closed_kinds_and_the_item_leaves_its_classes(case, monkeypatch):
    led = _case(case, monkeypatch)
    assert "one of outside_window" in L.check_leave(case, led, _item(led, "corp-ws03.raw"), "questions_answered",
                                                     "done")["error"]
    with patch.object(L, "_named_hosts", lambda c: set()):
        r = L.set_disposition(case, _item(led, "corp-ws03.raw"), "left", "outside_window", "its data ends before the stated start of the incident")
    assert r["success"], r
    after = load_ledger(case)
    item = next(i for i in after["items"].values() if i["path"].endswith("corp-ws03.raw"))
    assert item["state"] == "left" and item["reason_kind"] == "outside_window" and item["scope_fingerprint"]
    assert all(c["state"] == "left" for c in after["classes"].values() if c["item"] == item["id"])
    bad = L.set_disposition(case, _item(led, "corp-ws02.raw"), "left", "outside_window", "a stated reason of enough length for the writer")
    assert bad["success"] is False and bad["gate"] == "evidence_leave"


def test_duplicate_of_needs_equal_content(case, monkeypatch):
    led = _case(case, monkeypatch)
    r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "duplicate_of", "a byte-for-byte copy of the other image", [_item(led, "corp-ws02.raw")])
    assert not r["ok"] and "differ" in r["error"]
    from core.hash_index import _save
    _save(str(case), {"ab" * 32: [{"path": _item(led, "corp-ws03.raw"), "source": "evidence"},
                                  {"path": _item(led, "corp-ws02.raw"), "source": "evidence"}]})
    assert L.check_leave(case, led, _item(led, "corp-ws03.raw"), "duplicate_of", "a byte-for-byte copy of the other image",
                         [_item(led, "corp-ws02.raw")])["ok"]


# ── triage as work items ─────────────────────────────────────────

def test_a_triage_reply_is_recorded_as_work_items_and_dispositions(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    cls = [c for c in led["classes"].values() if c["item"] == ws01["id"] and c["state"] == "pending"]
    assert len(cls) >= 2
    first, rest = cls[0], cls[1:]
    reply = TR.parse_triage("Here:\n" + __import__("json").dumps({"decisions": [
        {"decision": "read_now", "classes": [first["label"]], "reason": "logons"},
        {"decision": "left", "classes": [c["label"].upper() for c in rest], "kind": "outside_window",
         "reason": "old"}]}))
    out = TR.apply_triage(elog.log, case, led, ws01, reply)
    items = [i for i in elog.log.work_items() if i["origin"] == "triage"]
    assert len(items) == 2 and all(i["status"] == "due" for i in items)   # one read item, one after the rest
    items.sort(key=lambda i: bool(i["source_ref"].get("after")))
    assert set(items[0]["source_ref"]["classes"]) == {first["id"]}
    # the classes whose leave did not hold are read last, never left untouched
    assert set(items[1]["source_ref"]["classes"]) == {c["id"] for c in rest}
    from core import frontier_queue as Q
    elog.log.add_work_item("coverage", [], "", {"host": "CORP-WS09"}, "w", status="due", source_ref={},
                           extra_key="coverage:t")
    assert Q.due_items(elog.log)[-1]["call_id"] == items[1]["call_id"]
    after = load_ledger(case)
    assert after["classes"][first["id"]]["state"] == "relevant"
    assert len(out["refused"]) == len(rest)
    # a leave that does not hold after the send-back keeps its class pending,
    # with the refusal as its triage record (disclosed as pending)
    assert all(after["classes"][c["id"]]["state"] == "pending" and after["classes"][c["id"]]["triage_refused"]
               for c in rest)
    assert ws01["id"] in TR.triaged_items(elog.log, after)
    from core.evidence_disposition import report_lines
    assert sum("its leave did not hold" in ln for ln in report_lines(case)) == len(rest)


def test_sync_closes_an_item_only_when_its_classes_are_settled(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    led = _case(case, monkeypatch)
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    TR.apply_triage(elog.log, case, led, ws03, {"item": {}, "decisions": []})
    assert TR.sync_triage(elog.log, case) == []                     # still to be read
    with patch.object(L, "_named_hosts", lambda c: set()):
        assert L.set_disposition(case, ws03["path"], "left", "other_scope", "its host is in no finding and shares no account with one")["success"]
    changed = TR.sync_triage(elog.log, case)
    assert changed and all(i["status"] == "dismissed" for i in elog.log.work_items() if i["origin"] == "triage")


def test_a_triage_item_never_merges_into_a_closed_read(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    led = _case(case, monkeypatch)
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    plan = elog.log.add_work_item("plan", ["task-0001"], "", {"host": "CORP-WS03", "path": ws03["path"]}, "p")
    plan["status"] = "failed"
    first = TR.reopen_item(elog.log, case, ws03, None, "triage: reopened")
    assert first["call_id"] != plan["call_id"] and first["status"] == "due" and plan["status"] == "failed"
    first["status"] = "dismissed"
    second = TR.reopen_item(elog.log, case, ws03, None, "triage: reopened again")
    assert second["call_id"] not in (first["call_id"], plan["call_id"]) and first["status"] == "dismissed"


def test_triage_pending_asks_once_per_pending_item(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    _case(case, monkeypatch)
    asked = []

    def ask(system, user, _tool_name=""):
        asked.append(user.split("\n", 1)[0])
        return {"conclusion": "{\"item\": {}, \"classes\": {}}"}
    done = TR.triage_pending(elog.log, case, ask=ask)
    led = load_ledger(case)
    assert len(asked) == len(led["items"]) == len(done) and all(a.startswith("ITEM ID ") for a in asked)
    assert "SURVEY:" in TR.triage_message(case, led, next(iter(led["items"].values())), "s")
    assert "Windows" not in TR.TRIAGE_SYS and "evtx" not in TR.TRIAGE_SYS.lower()


# ── reopen ───────────────────────────────────────────────────────

def _left_ws03(case, monkeypatch, ws03):
    import core.execution_log as elog
    from core import evidence_triage as TR
    led = _case(case, monkeypatch, ws03=ws03)
    ws03_item = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    TR.apply_triage(elog.log, case, led, ws03_item, {"item": {}, "decisions": []})
    assert L.set_disposition(case, ws03_item["path"], "left", "outside_window", "its data ends before the stated start of the incident")["success"]
    return elog.log, ws03_item


def _attacker(case, value):
    c = add_claim(case, f"{value} is the attacker's.", confidence="LIKELY", host="CORP-WS01",
                  enforce_validation=False)["node_id"]
    set_claim_indicators(case, c, [{"type": "file", "value": value, "side": "attacker"}])


def test_a_new_attacker_entity_in_a_rare_path_reopens_once(case, monkeypatch):
    log, item = _left_ws03(case, monkeypatch, [_b("Users/john.roe/svc_kit.exe", "300-128-1", T_OLD)])
    assert L.reopen_left(log, case) == []                          # the scope did not change
    _attacker(case, "svc_kit.exe")
    assert L.reopen_left(log, case) == [item["id"]]
    unit = load_ledger(case)["items"][item["id"]]
    assert unit["state"] == "pending" and "svc_kit.exe" in unit["reason"]
    assert any(e["status"] == "due" and e["origin"] == "triage" for e in log.work_items())
    assert L.set_disposition(case, item["path"], "left", "outside_window", "its data is still older than the stated start",
                             ) ["success"] is False             # the entity is in it: no leave


def test_an_entity_in_paths_most_hosts_share_does_not_reopen(case, monkeypatch):
    log, item = _left_ws03(case, monkeypatch, [_b("Windows/System32/winevt/Logs/Security.evtx", "200-128-1",
                                                  T_OLD, 70000)])
    _attacker(case, "Security.evtx")
    assert L.reopen_left(log, case) == []
    unit = load_ledger(case)["items"][item["id"]]
    assert unit["state"] == "left" and "Security.evtx" in unit["acknowledged_entities"]


# ── the finish label and the report ──────────────────────────────

def test_complete_needs_no_pending_unit_and_holding_leaves(case, monkeypatch):
    from core.evidence_disposition import disposition_complete, report_lines
    led = _case(case, monkeypatch)
    ok, detail = disposition_complete(case)
    assert not ok and detail["pending_items"] == len(led["items"])
    with patch.object(L, "_named_hosts", lambda c: set()):
        for i in led["items"].values():
            if i["path"].endswith("corp-ws03.raw"):
                assert L.set_disposition(case, i["path"], "left", "outside_window", "its data ends before the stated start of the incident")["success"]
    after = load_ledger(case)
    for unit in [*after["items"].values(), *after["classes"].values()]:
        if unit["state"] == "pending":
            unit["state"] = "read"
    from core.coverage_ledger import save_ledger
    save_ledger(case, after)
    assert disposition_complete(case)[0] is True
    lines = report_lines(case)
    assert lines[0] == "### Evidence not analysed"
    assert any("corp-ws03.raw (CORP-WS03): left, its data ends before the incident's earliest stated start: "
               "its data ends before the stated start of the incident" in x for x in lines)
    # A new start before the item's data makes the leave fail under the final scope.
    c = add_claim(case, "The attacker reached CORP-WS02 at 2030-12-01 08:00:00.", confidence="LIKELY",
                  host="CORP-WS02", enforce_validation=False)["node_id"]
    set_claim_indicators(case, c, [{"type": "host", "value": "CORP-WS02", "side": "victim",
                                    "attacker_from": "2030-12-01 08:00:00"}])
    ok, detail = disposition_complete(case)
    assert not ok and detail["left_not_holding"]


def test_switch_off_keeps_todays_label_inputs(case, monkeypatch):
    from core.evidence_disposition import disposition_complete
    monkeypatch.setenv("ATLAS_EVIDENCE_DISPOSITION", "0")
    _case(case, monkeypatch)
    assert disposition_complete(case) == (True, {})



def test_an_item_leaves_only_when_each_class_meets_the_reason(case, monkeypatch):
    led = _case(case, monkeypatch)
    item = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    own = [c for c in led["classes"].values() if c["item"] == item["id"]]
    assert len(own) >= 2
    real = L.check_leave

    def check(case_dir, ledger, ref, kind, reason, proof=None, ignore_entities=frozenset(), **kw):
        if ref == own[0]["id"]:
            return {"ok": False, "error": f"{ref} cannot be left as {kind}: a reader parses it"}
        return real(case_dir, ledger, ref, kind, reason, proof, ignore_entities, **kw)
    with patch.object(L, "check_leave", check), patch.object(L, "_named_hosts", lambda c: set()):
        r = L.set_disposition(case, item["path"], "left", "outside_window", "its data is older than the stated start of the incident")
    assert r["success"] is False and "cannot be left as a whole" in r["error"] and own[0]["label"] in r["error"]
    after = load_ledger(case)
    assert after["items"][item["id"]]["state"] == "pending"
    assert after["classes"][own[0]["id"]]["state"] == "pending" and after["classes"][own[1]["id"]]["state"] == "left"


def test_the_brief_and_questions_put_hosts_in_scope(case, monkeypatch):
    led = _case(case, monkeypatch)
    (case / "CASE.md").write_text("# Case\n\nCORP-WS03 was reached by the intruder.\n")
    r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "other_scope", "a stated reason of enough length for the writer")
    assert not r["ok"] and "named by a current finding" in r["error"]


def test_the_sweep_matches_an_entity_as_a_token(case, monkeypatch):
    led = _case(case, monkeypatch, ws03=[_b("Users/john.roe/administrator_notes.txt", "300-128-1", T_OLD)])
    item = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    assert L.sweep(case, "item", item, item, ["admin"]) == []
    assert L.sweep(case, "item", item, item, ["administrator_notes.txt"])



def test_the_triage_message_carries_the_facts_a_leave_needs(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    msg = TR.triage_message(case, led, ws01, "survey text")
    assert "EARLIEST STATED START: 2031-03-10 14:00:00" in msg and "HOSTS IN SCOPE: CORP-WS01" in msg
    assert "reader: " in msg and "#" not in msg.split("CLASSES:")[1]          # labels, never hash ids
    # An item whose triage left no record is triaged again.
    assert ws01["id"] not in TR.triaged_items(elog.log, led)
    TR.apply_triage(elog.log, case, led, ws01, {"item": {}, "decisions": []})
    assert ws01["id"] in TR.triaged_items(elog.log, load_ledger(case))


def test_a_reopen_pass_rejudges_only_the_part_a_kind_reads_and_shares_its_inputs(case, monkeypatch):
    import core.execution_log as elog
    led = _case(case, monkeypatch)
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    assert L.set_disposition(case, ws03["path"], "left", "outside_window", "its data ends before the stated start of the incident")["success"]
    L.reopen_left(elog.log, case)        # the first pass applies the code leaves of the window once
    calls = {"check": 0, "scan": 0}
    real_check, real_scan = L.check_leave, L._scan_profiles
    monkeypatch.setattr(L, "check_leave", lambda *a, **k: calls.__setitem__("check", calls["check"] + 1)
                        or real_check(*a, **k))
    monkeypatch.setattr(L, "_scan_profiles", lambda c: calls.__setitem__("scan", calls["scan"] + 1)
                        or real_scan(c))
    L._PROFILES_CACHE.clear()
    # A new finding names another host: the hosts in scope change, the window does not.
    add_claim(case, "CORP-WS02 was examined.", confidence="LIKELY", host="CORP-WS02", enforce_validation=False)
    assert L.reopen_left(elog.log, case) == [] and calls["check"] == 0
    for _ in range(2):
        L._profiles(case)
    assert calls["scan"] == 1                               # cached by the listing generation



def test_a_class_marked_to_be_read_and_never_read_keeps_the_run_incomplete(case, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    from core.coverage_ledger import save_ledger
    from core.evidence_disposition import disposition_complete, report_lines
    led = _case(case, monkeypatch)
    for unit in [*led["items"].values(), *led["classes"].values()]:
        unit["state"] = "read"
    one = next(iter(led["classes"].values()))
    one["state"] = "pending"
    save_ledger(case, led)
    item = led["items"][one["item"]]
    TR.apply_triage(elog.log, case, load_ledger(case), item, TR.parse_triage(__import__("json").dumps(
        {"decisions": [{"decision": "read_later", "classes": [one["label"]]}]})))
    ok, detail = disposition_complete(case)
    assert not ok and detail["relevant_not_read"] == 1
    lines = report_lines(case)
    assert any("Evidence not decided" in x for x in lines) and any("a person must decide" in x for x in lines)
    assert not any("no reason was recorded" in x or "marked to be read" in x for x in lines)
    de = report_lines(case, "de")
    assert de[0] == "### Nicht entschiedene Beweismittel"


def test_a_disposition_check_that_fails_never_says_complete(case, monkeypatch):
    from core import investigation_exit as X
    monkeypatch.setattr("core.evidence_disposition.disposition_complete",
                        lambda c: (_ for _ in ()).throw(RuntimeError("broken")))
    assert "could not be checked" in X.completion_disclosure(case)["evidence_disposition"]["error"]


def test_only_failures_of_tools_that_open_an_image_make_it_unreadable(case, monkeypatch):
    import core.execution_log as elog
    led = _case(case, monkeypatch)
    path = _item(led, "corp-ws03.raw")
    ids = [elog.log.record_tool_call(f"<py>:{t} {path}", False, False, 0, 1, stderr="failed")
           for t in ("strings_strings_grep", "ez_ez_evtxecmd")]
    with patch.object(L, "readers_for", lambda fmt: []):
        r = L.check_leave(case, led, path, "unreadable", "its filesystem does not open with any reader", [str(i) for i in ids])
        assert not r["ok"] and "tools that open it (tsk" in r["error"]
        ids2 = [elog.log.record_tool_call(f"<py>:tsk_tsk_fls {path}", False, False, 0, 1, stderr="no fs")
                for _ in range(2)]
        assert L.check_leave(case, led, path, "unreadable", "its filesystem does not open with any reader", [str(i) for i in ids2])["ok"]


# ── the export checks through the native count (tools.tabular.count_values) ──

def _exports(case, monkeypatch, per_host: dict):
    """Invented export tables per host, as the contents index's sources
    would name them; the count reads the files themselves."""
    (case / "exports").mkdir(exist_ok=True)
    for host, (name, text) in per_host.items():
        (case / "exports" / name).write_text(text, encoding="utf-8")
    monkeypatch.setattr(L, "_host_exports", lambda c, h: [f"exports/{per_host[k][0]}" for k in per_host
                                                          if k.casefold() == str(h).casefold()])


def test_an_attacker_value_in_the_hosts_exports_blocks_a_leave(case, monkeypatch):
    led = _case(case, monkeypatch)
    _exports(case, monkeypatch, {"CORP-WS03": ("corp-ws03-procs.csv",
                                               "time,image\n2030-12-27 10:00:00,C:\\Users\\Public\\svc_kit.exe\n")})
    _attacker(case, "svc_kit.exe")
    r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "outside_window", "its data is older than the stated start of the incident")
    assert not r["ok"] and "svc_kit.exe in exports/corp-ws03-procs.csv" in r["error"]


def test_an_account_in_the_exports_of_a_host_in_scope_blocks_other_scope(case, monkeypatch):
    led = _case(case, monkeypatch)
    _exports(case, monkeypatch, {"CORP-WS01": ("corp-ws01-logons.csv",
                                               "time,user\n2031-03-10 14:01:00,CORP\\john.roe\n")})
    r = L.check_leave(case, led, _item(led, "corp-ws03.raw"), "other_scope", "its host is not among the hosts in scope")
    assert not r["ok"] and "its account john.roe appears in the exports of a host in scope" in r["error"]


def test_a_reopen_pass_counts_the_accounts_over_the_exports_of_hosts_in_scope(case, monkeypatch):
    import core.execution_log as elog
    led = _case(case, monkeypatch)
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    _exports(case, monkeypatch, {"CORP-WS02": ("corp-ws02-logons.csv",
                                               "time,user\n2031-03-11 09:00:00,CORP\\john.roe\n")})
    assert L.set_disposition(case, ws03["path"], "left", "other_scope", "its host is not among the hosts in scope")["success"]
    # A finding names CORP-WS02: the hosts in scope change, and its exports
    # hold the left host's account.
    add_claim(case, "CORP-WS02 was reached at 2031-03-11 09:00:00.", confidence="LIKELY", host="CORP-WS02",
              enforce_validation=False)
    assert L.reopen_left(elog.log, case) == [ws03["id"]]
    unit = load_ledger(case)["items"][ws03["id"]]
    assert unit["state"] == "pending" and "john.roe" in unit["reason"]


def test_the_triage_message_states_the_scope_facts_the_checks_read(case, monkeypatch):
    from core import evidence_triage as TR
    led = _case(case, monkeypatch, ws03=[_b("Users/john.roe/svc_kit.exe", "300-128-1", T_OLD)])
    _exports(case, monkeypatch, {"CORP-WS01": ("corp-ws01-logons.csv", "time,user\n2031-03-10 14:01:00,john.roe\n")})
    _attacker(case, "svc_kit.exe")
    items = {i["path"].rsplit("/", 1)[-1]: i for i in led["items"].values()}
    ws02 = TR.triage_message(case, led, items["corp-ws02.raw"], "s")
    assert "- accounts its host shares with hosts in scope: 1 (jane.doe)" in ws02
    ws03 = TR.triage_message(case, led, items["corp-ws03.raw"], "s")
    assert "- its accounts in the exports of hosts in scope: 1 (john.roe)" in ws03
    assert "- current attacker values found in it: 1 (svc_kit.exe in" in ws03
    assert "- its host CORP-WS01 is in scope" in TR.triage_message(case, led, items["corp-ws01.raw"], "s")
    # the facts agree with the checks
    assert "john.roe" in L.check_leave(case, led, items["corp-ws03.raw"]["path"], "other_scope", "a stated reason of enough length for the writer")["error"]


def test_the_triage_is_one_call_without_tools_and_a_refusal_names_the_readers(case, monkeypatch):
    from core import evidence_triage as TR
    from core.evidence_leave import readers_for
    led = _case(case, monkeypatch)
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    spec = TR.triage_spec(case, led, ws02, "s")
    assert spec.core_tools == [] and spec.readers == [] and spec.menu == []
    assert "unreadable" not in TR.TRIAGE_ITEM_SYS.split("Unreadable is never")[0].split("Kinds:")[1]
    evtx = readers_for("evtx")
    cls = next(c for c in led["classes"].values() if c["item"] == ws02["id"]
               and any(r in evtx for r in readers_for(L.unit_format(case, "class", c, ws02))))
    r = L.set_disposition(case, cls["id"], "left", "outside_window", "its data is older than the stated start of the incident")
    assert not r["success"] and "; read it with " in r["error"] and any(x in r["error"] for x in evtx)

def test_a_text_class_has_readers_and_is_never_unreadable_without_two_failed_text_reads(case, monkeypatch):
    from core import evidence_triage as TR
    from core.frontier_prompts import reader_names
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    text = next(c for c in led["classes"].values() if c["item"] == ws01["id"]
                and L.unit_format(case, "class", c, ws01) == "txt")
    readers = L.readers_for("txt")
    assert readers and all("strings" in r for r in readers) and set(readers) <= set(reader_names())
    assert f"- {text['label']} ({text['files']} files; reader: yes)" in TR.triage_message(case, led, ws01, "s")
    r = L.check_leave(case, led, text["id"], "unreadable", "the readers that take its format cannot read it")
    assert not r["ok"] and "two failed calls" in r["error"]


def test_a_synthesis_proposal_may_name_a_hosts_content_class(case, monkeypatch):
    from types import SimpleNamespace
    import core.execution_log as elog
    from agent.frontier import SubmitApplier
    from core.evidence_leave import readers_for
    led = _case(case, monkeypatch)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    label = next(c["label"] for c in led["classes"].values() if c["item"] == ws02["id"]
                 and L.unit_format(case, "class", c, ws02) == "evtx")
    item = elog.log.add_work_item("synthesis", [], "", None, "s", source_ref={"kind": "synthesis"},
                                  extra_key="synthesis:t")
    from core import incident_map
    ap = SubmitApplier(SimpleNamespace(), case, incident_map.open(case), item, "synthesis")
    tool = readers_for("evtx")[0]
    ap({"proposals": [{"tool": tool, "host": "CORP-WS02", "source": label, "why": "how did the logons go"},
                      {"tool": tool, "host": "CORP-WS02", "source": "a log nobody has", "why": "nothing"}]},
       SimpleNamespace(calls=[]), False)
    plans = [i for i in elog.log.work_items() if i["origin"] == "plan"]
    from core.contents_index import class_handles
    assert len(plans) == 1 and "Security.evtx" in json.dumps(plans[0]["target"])
    (dropped,) = ap.out["proposals_dropped"]
    assert "is neither a file the listing of CORP-WS02 holds nor one of its content classes" in dropped
    assert label in dropped and "(class " in plans[0]["why"] and "file 1 of 1" in plans[0]["why"]


def test_the_next_synthesis_reads_what_the_last_one_lost(case, monkeypatch):
    from core import frontier_prompts as P
    _case(case, monkeypatch)
    item = {"call_id": 3, "origin": "synthesis", "why": "s",
            "source_ref": {"dropped": ["proposal 'x': 'a log nobody has' is neither a file of CORP-WS02's evidence"]}}
    text = P.item_text(case, item, None, readers="")
    assert "PROPOSALS OF THE LAST SYNTHESIS THAT WERE DROPPED" in text and "a log nobody has" in text
    assert "CONTENT CLASSES BY HOST" in text and "- CORP-WS02: " in text


def test_every_planned_read_checks_its_inner_path_against_the_listing(case, monkeypatch):
    import core.execution_log as elog
    from core import question_plan as Q
    from core.evidence_leave import readers_for
    led = _case(case, monkeypatch)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    tools = {t for t, _w in Q.reading_tools()}
    tool = readers_for("evtx")[0]
    bogus = {"tool": tool, "host": "CORP-WS02", "source": "a channel nobody wrote", "why": "w"}
    v, why = Q.check_read(str(case), bogus, tools)
    assert v is None and "neither a file the listing of CORP-WS02 holds" in why
    real = {**bogus, "source": "Windows/System32/winevt/Logs/Security.evtx"}
    assert Q.check_read(str(case), real, tools)[0]["target"]["inner_path"].endswith("Security.evtx")
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    label = next(c["label"] for c in led["classes"].values() if c["item"] == ws02["id"]
                 and L.unit_format(case, "class", c, ws02) == "evtx")
    reads, _w = Q.check_reads(str(case), {**bogus, "source": label}, tools)
    assert len(reads) == 1 and "file 1 of 1" in reads[0]["why"]
    # the director's reads go through the same check
    from tools import dair
    monkeypatch.setattr(dair, "_case_root", lambda: case)
    before = len(elog.log.work_items())
    dair._apply_director_review({"work_items": [bogus]}, {})
    assert len(elog.log.work_items()) == before


def test_the_directors_parsed_entries_keep_only_paths_the_listing_holds(case, monkeypatch):
    from core.work_order import parse_director_entries
    _case(case, monkeypatch)
    data = {"priority_tools": ["ez.evtxecmd CORP-WS02 Windows/System32/winevt/Logs/Security.evtx",
                               "ez.evtxecmd CORP-WS02 Windows/Invented/Channel.evtx"]}
    out = parse_director_entries(data, str(case))
    assert [e["target"]["inner_path"] for e in out] == ["Windows/System32/winevt/Logs/Security.evtx"]


def test_check_reads_takes_a_unit_id_and_refuses_a_tool_its_input_cannot_feed(case, monkeypatch):
    from core import question_plan as Q
    from core.evidence_leave import readers_for
    from core.input_kind import reads_kind
    led = _case(case, monkeypatch)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    tools = {t for t, _w in Q.reading_tools()}
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    unit = next(c["id"] for c in led["classes"].values() if c["item"] == ws02["id"]
                and L.unit_format(case, "class", c, ws02) == "evtx")
    reads, why = Q.check_reads(str(case), {"tool": readers_for("evtx")[0], "source": unit, "why": "w"}, tools)
    assert len(reads) == 1 and reads[0]["target"]["host"] == "CORP-WS02" and "file 1 of 1" in reads[0]["why"]
    mem_tool = readers_for("memory")[0]
    reads, why = Q.check_reads(str(case), {"tool": mem_tool, "host": "CORP-WS02", "source": ws02["path"],
                                           "why": "w"}, tools)
    assert reads == [] and f"{mem_tool} cannot read {ws02['path']}" in why
    assert reads_kind(mem_tool, "evidence/mem/corp-ws02.mem") is True
    assert reads_kind(mem_tool, "evidence/other/corp-ws02.raw") is None       # a name alone says nothing


def test_serves_gives_the_read_item_its_questions_and_a_refused_leave_goes_back_once(case, monkeypatch):
    import core.execution_log as elog
    from agent.llm import ChatResponse, ToolCall
    from core import evidence_triage as TR
    from tests.agent.test_item_executor import _Client
    led = _case(case, monkeypatch)
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({"tasks": [
        {"id": "task-0001", "text": "Who logged on to CORP-WS02?", "status": "open",
         "parts": [{"id": "p1", "text": "the accounts", "status": "open"}]}]}), encoding="utf-8")
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    cls = [c for c in led["classes"].values() if c["item"] == ws02["id"]]
    first, rest = cls[0], cls[1:]

    def submit(i, decisions):
        return ChatResponse(content="", tool_calls=[ToolCall(id=f"t{i}", name="submit_triage",
                                                             arguments={"decisions": decisions})])
    client = _Client([
        submit(1, [{"decision": "read_now", "classes": [first["label"]], "serves": ["task-0001/p1"]},
                   {"decision": "left", "classes": [c["label"] for c in rest], "kind": "outside_window",
                    "reason": "old"}]),
        submit(2, [{"decision": "left", "classes": [c["label"] for c in rest], "kind": "outside_window",
                    "reason": "still old"}])])
    agent = type("A", (), {"client": client, "toolbox": type("B", (), {"schemas_for": lambda self, n: []})(),
                           "_log": lambda self, e: None, "_turn": 0})()
    out = TR._triage_as_items(elog.log, case, led, [ws02], {}, agent)
    assert len(client.asks) == 2 and client.asks[0]["tools"] == ["submit_triage"]      # sent back once
    read = [i for i in elog.log.work_items() if i["origin"] == "triage"]
    assert read and read[0]["task_ids"] == ["task-0001"]
    after = load_ledger(case)
    assert all(after["classes"][c["id"]]["triage_refused"] for c in rest) and out[0]["refused"]
    assert "QUESTION PARTS (what serves names):" in TR.triage_message(case, after, ws02, "s")


def test_the_coverage_path_parses_sweeps_classifies_and_credits_swept(case, monkeypatch):
    import core.execution_log as elog
    from agent.llm import ChatResponse, ToolCall
    from core import coverage_path as CP
    from core import evidence_triage as TR
    from tests.agent.test_item_executor import _Client
    led = _case(case, monkeypatch)
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    classes = [c for c in led["classes"].values() if c["item"] == ws02["id"]]
    TR.apply_triage(elog.log, case, led, ws02, {"decisions": [
        {"decision": "read_now", "classes": [c["label"] for c in classes], "serves": ["coverage"]}]})
    coverage_item = next(i for i in elog.log.work_items() if i["origin"] == "triage")
    assert CP.held(elog.log, load_ledger(case)) == {coverage_item["call_id"]}       # not run as a read yet
    seen = []

    class _Box:
        def call(self, name, args, budget_free=False):
            seen.append((name, args))
            return json.dumps({"rows": [{"x": 1}, {"x": 2}], "_atlas_call_id": 70 + len(seen)}), False
    monkeypatch.setattr(CP, "sweep_calls", lambda values, calls: (["203.0.113.7"] if values and calls and
                        any(c == 71 for c in calls) else [], True))
    client = _Client([ChatResponse(content="", tool_calls=[ToolCall(id="c1", name="submit_coverage", arguments={
        "classes": [{"label": c["label"], "decision": "nothing"} for c in classes]})])])
    agent = type("A", (), {"client": client, "toolbox": _Box(), "_log": lambda self, e: None, "_turn": 0})()
    done = CP.run_pass(agent, case, ["203.0.113.7"])
    assert done["items"] == 1 and done["read"] == 1 and done["swept"] == len(classes) - 1
    after = load_ledger(case)
    hit = next(c for c in after["classes"].values() if c["item"] == ws02["id"]
               and 71 in ((c.get("coverage") or {}).get("calls") or []))
    assert hit["state"] == "relevant" and hit["coverage"]["hits"] == ["203.0.113.7"]
    swept = [c for c in after["classes"].values() if c["item"] == ws02["id"] and c["state"] == "swept"]
    assert swept and all("1 of 1 file(s) parsed and swept for the attacker values known at" in c["reason"]
                         for c in swept)
    assert coverage_item["status"] == "resolved"                                   # taken over
    reads = [i for i in elog.log.work_items() if i["origin"] == "triage" and i["status"] == "due"]
    assert len(reads) == 1 and "attacker values found: 203.0.113.7" in reads[0]["why"]
    from core.evidence_disposition import report_lines
    assert any("parsed and swept" in x for x in report_lines(case))
    # a later attacker value found in a swept class's outputs opens it again
    monkeypatch.setattr(CP, "sweep_calls", lambda values, calls: (["CORP\\\\jane.doe"] if values else [], True))
    opened = CP.reopen_swept(elog.log, case, ["203.0.113.7", "CORP\\\\jane.doe"])
    assert opened and load_ledger(case)["classes"][opened[0]]["state"] == "pending"



def test_two_threads_writing_the_ledger_keep_both_writes_and_a_reader_never_sees_it_empty(case, monkeypatch):
    import threading
    from core.coverage_ledger import update_ledger
    led = _case(case, monkeypatch)
    ids = [c for c in led["classes"]][:2]
    stop, empty = threading.Event(), []

    def writer(cid):
        for n in range(60):
            update_ledger(case, lambda d: d["classes"][cid].update(count=n + 1))

    def reader():
        while not stop.is_set():
            if not (load_ledger(case).get("classes") or {}):
                empty.append(1)
    r = threading.Thread(target=reader)
    r.start()
    ws = [threading.Thread(target=writer, args=(cid,)) for cid in ids]
    for w in ws:
        w.start()
    for w in ws:
        w.join()
    stop.set()
    r.join()
    after = load_ledger(case)
    assert [after["classes"][cid].get("count") for cid in ids] == [60, 60] and not empty


def test_the_beside_workers_are_one_named_setting(monkeypatch):
    from core import frontier_queue as Q
    assert Q.beside_workers() == Q.BESIDE_WORKERS
    monkeypatch.setenv("ATLAS_BESIDE_WORKERS", "2")
    assert Q.beside_workers() == 2



def test_a_class_with_nothing_parsed_or_not_searched_whole_is_never_swept(case, monkeypatch):
    import core.execution_log as elog
    from core import coverage_path as CP
    led = _case(case, monkeypatch)
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    a, b, *rest = [c for c in led["classes"].values() if c["item"] == ws02["id"]]
    parsed = {a["label"]: {"reader": "", "calls": [], "files": 0, "parsed": 0, "rows": 0, "hits": [], "whole": True,
                           "error": "no installed reader for x"},
              b["label"]: {"reader": "r", "calls": [7], "files": 2, "parsed": 2, "rows": 9, "hits": [], "whole": False}}
    out = CP.apply(elog.log, case, ws02, parsed, None, ["203.0.113.7"])
    after = load_ledger(case)
    assert out["swept"] == [] and set(out["unparsed"]) == {a["id"], b["id"]}
    assert after["classes"][a["id"]]["state"] == "pending" and after["classes"][b["id"]]["state"] == "pending"


def test_the_sweep_searches_each_full_output_and_says_when_one_was_not(tmp_path, monkeypatch):
    from core import coverage_path as CP
    big = tmp_path / "out.txt"
    with open(big, "w") as fh:
        fh.write("x" * ((1 << 20) - 4))                        # the value straddles a chunk border
        fh.write("Jane.Doe logged on\n")
        fh.write("y" * (9 << 20))                                # past any index cap
        fh.write("203.0.113.9\n")
    entries = {1: {"call_id": 1, "stdout_file": str(big), "truncated": True},
               2: {"call_id": 2, "stdout_excerpt": "nothing here", "truncated": False},
               3: {"call_id": 3, "stdout_excerpt": "cut", "truncated": True}}
    monkeypatch.setattr("core.execution_log.log.index", lambda: type("I", (), {"by_call_id": entries})())
    hits, whole = CP.sweep_calls(["jane.doe", "203.0.113.9", "corp-ws07"], [1, 2])
    assert hits == ["jane.doe", "203.0.113.9"] and whole
    assert CP.sweep_calls(["jane.doe"], [1, 3])[1] is False


def test_coverage_parses_are_stamped_and_earn_no_read_credit(case, monkeypatch):
    import core.execution_log as elog
    from core.artifact_value import _trace_calls
    from core.execution_log import call_source
    _case(case, monkeypatch)
    token = call_source.set("coverage")
    try:
        cid = elog.log.record_tool_call("<py>:ez_evtxecmd C:/Windows/System32/winevt/Logs/Security.evtx", True,
                                        False, 0, 0)
    finally:
        call_source.reset(token)
    plain = elog.log.record_tool_call("<py>:ez_evtxecmd C:/Windows/System32/winevt/Logs/System.evtx", True,
                                      False, 0, 0)
    entry = next(e for e in elog.log._entries if e.get("call_id") == cid)
    assert entry["source"] == "coverage"
    read = [c["call_id"] for c in _trace_calls(case)[0]]
    assert plain in read and cid not in read


def test_a_parse_whose_rows_are_in_its_csv_is_swept_in_the_csv_and_a_cut_excerpt_is_not_whole(tmp_path,
                                                                                               monkeypatch):
    from core import coverage_path as CP
    csv = tmp_path / "EvtxECmd.csv"
    csv.write_text("TimeCreated,UserName\n2031-03-10 14:02:00,jane.doe\n", encoding="utf-8")
    result = json.dumps({"success": True, "stdout": "parsed 1 file", "output_paths": [str(csv)]})
    entries = {1: {"call_id": 1, "stdout_excerpt": result, "truncated": False},
               2: {"call_id": 2, "stdout_excerpt": "x" * 4000, "truncated": False}}
    monkeypatch.setattr("core.execution_log.log.index", lambda: type("I", (), {"by_call_id": entries})())
    assert CP.sweep_calls(["jane.doe"], [1]) == (["jane.doe"], True)
    assert CP.sweep_calls(["jane.doe"], [2])[1] is False


def test_held_coverage_reads_run_when_nothing_else_is_due(tmp_path, monkeypatch):
    from agent.frontier import FrontierRun
    from core import coverage_path as CP
    from tests.agent.test_frontier_run import Agent, _Box, _Client
    from tests.core.test_incident_map import _case as _icase, _trace
    case = _icase(tmp_path)
    log = _trace(case, monkeypatch)
    held = log.add_work_item("triage", [], "", {"host": "CORP-WS01", "path": "evidence/disk/corp-ws01.raw"}, "t",
                             status="due", source_ref={"kind": "evidence"}, extra_key="triage:held")
    other = log.add_work_item("followup", [], "", {"host": "CORP-WS01"}, "f", status="due",
                              source_ref={"kind": "followup"}, extra_key="followup:x")
    monkeypatch.setattr(CP, "coverage_on", lambda: True)
    monkeypatch.setattr(CP, "held", lambda log, led: {held["call_id"]})
    fr = FrontierRun(Agent(_Client([]), _Box(), case_dir=case, quiet=True))
    assert fr._next_item()["call_id"] == other["call_id"]
    other["status"] = "resolved"
    assert fr._next_item()["call_id"] == held["call_id"]


def test_the_sweep_fails_closed_on_outputs_it_cannot_search(tmp_path, monkeypatch):
    from core import coverage_path as CP
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    inp = case / "evidence" / "Security.evtx"
    inp.write_text("jane.doe")                                   # the input itself is never swept as output
    out_dir = case / "analysis" / "parsed"
    out_dir.mkdir(parents=True)
    other = out_dir / "rows.tsv"
    other.write_text("203.0.113.9\n")
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    unknown_field = json.dumps({"success": True, "input": str(inp), "result_file": str(other)})
    folder_only = json.dumps({"success": True, "output_dir": str(case / "analysis")})
    broken = '{"success": true, "rows": ['
    entries = {1: {"call_id": 1, "stdout_excerpt": unknown_field}, 2: {"call_id": 2, "stdout_excerpt": folder_only},
               3: {"call_id": 3, "stdout_excerpt": broken}}
    monkeypatch.setattr("core.execution_log.log.index", lambda: type("I", (), {"by_call_id": entries})())
    assert CP.sweep_calls(["203.0.113.9", "jane.doe"], [1]) == (["203.0.113.9"], True)
    assert CP.sweep_calls(["203.0.113.9"], [2])[1] is False
    assert CP.sweep_calls(["203.0.113.9"], [3])[1] is False


def test_the_coverage_path_never_closes_the_item_the_frontier_runs(case, monkeypatch):
    import core.execution_log as elog
    from core import coverage_path as CP
    from core import frontier_queue as Q
    led = _case(case, monkeypatch)
    ws02 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws02.raw"))
    c = next(c for c in led["classes"].values() if c["item"] == ws02["id"])
    item = elog.log.add_work_item("triage", [], "", {"host": "CORP-WS02", "path": ws02["path"]}, "t", status="due",
                                  source_ref={"kind": "evidence", "item": ws02["id"], "classes": [c["id"]]},
                                  extra_key="triage:running")
    parsed = {c["label"]: {"reader": "r", "calls": [7], "files": 1, "parsed": 1, "rows": 1, "hits": [], "whole": True}}
    Q.RUNNING.add(item["call_id"])
    try:
        CP.apply(elog.log, case, ws02, parsed, None, [])
    finally:
        Q.RUNNING.discard(item["call_id"])
    assert item["status"] == "due"


# -- a class of a declared media type has readers, so it is never left for want of one --

def test_the_readers_of_an_extension_include_the_declared_readers_of_its_type():
    from core.evidence_leave import readers_for
    assert "misc.olevba_scan" in readers_for("doc") and "misc.olevba_scan" in readers_for("docx")
    assert readers_for("zip") == ["archive.zip_extract"]
    assert "steg.extract" in readers_for("jpg") and "strings.exiftool_metadata" in readers_for("jpg")
    assert "ez.evtxecmd" in readers_for("evtx")                      # the parameter route is untouched
    assert readers_for("txt") and all("strings" in r for r in readers_for("txt"))


def test_a_class_of_a_declared_media_type_needs_two_failed_reader_calls_and_is_never_unrelated(case, monkeypatch):
    """A ledger class is an artefact class; one whose member names are of a
    declared media type has readers (the class route resolves by member
    name), so the leaves that rest on "no reader" are refused for it as
    for an event log."""
    led = _case(case, monkeypatch)
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    cls = next(c for c in led["classes"].values() if c["item"] == ws03["id"])
    cls["names"] = ["photo1.jpg", "photo2.jpg"]
    r = L.check_leave(case, led, cls["id"], "unreadable", "the readers that take its format cannot read it")
    assert not r["ok"] and "two failed calls" in r["error"] and "steg.extract" in r["error"]
    r = L.check_leave(case, led, ws03["id"], "unrelated_content", "it holds only photographs no reader parses")
    assert not r["ok"] and "registered readers parse its classes" in r["error"]
    from core import evidence_triage as TR
    assert f"- {cls['label']} ({cls['files']} files; reader: yes)" in TR.triage_message(case, led, ws03, "s")


def test_refused_calls_and_host_faults_never_make_an_item_unreadable(case, monkeypatch):
    import core.execution_log as elog
    led = _case(case, monkeypatch)
    path = _item(led, "corp-ws03.raw")
    ids = []
    for fc in ("gate_refusal", "analyst_error", "expected_nonzero", "disk_floor", "sudo_auth"):
        cid = elog.log.record_tool_call(f"<py>:tsk_tsk_fls {path}", False, False, 0, 1, stderr="no fs")
        elog.log.annotate_tool_call(cid, failure_class=fc)
        ids.append(str(cid))
    ids.append(str(elog.log.record_tool_call(f"<py>:tsk_tsk_fls {path}", False, False, 0, 1, stderr="no fs",
                                             timed_out=True)))
    ids.append(str(elog.log.record_tool_call(f"<py>:tsk_tsk_fls {path}", False, False, 0, 1, stderr="stopped",
                                             interrupted=True)))
    with patch.object(L, "readers_for", lambda fmt: []):
        r = L.check_leave(case, led, path, "unreadable", "its filesystem does not open with any reader", ids)
        assert not r["ok"] and "the proof holds 0" in r["error"]
