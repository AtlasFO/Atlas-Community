"""The per-turn cost of the credit pass: the no_reader pass runs only
when its inputs changed, the sweep's scans are shared by the classes of an
image and a host, and the evidence profile is neither rebuilt nor reloaded
inside the loop while nothing it reads changed. Behaviour is unchanged:
the same leaves, the same reopen when the scope changes. Invented fixtures
only (CORP-WS01..03, jane.doe, dates in 2031)."""
from __future__ import annotations

import json
import os
import time

import core.execution_log as elog
from core import evidence_leave as L
from core import evidence_disposition as ED
from core import evidence_profile as EP
from core.coverage_ledger import load_ledger, save_ledger
from tests.core.test_contents_index import case  # noqa: F401
from tests.core.test_evidence_leave import _attacker, _case, _item  # noqa: F401


def _sources(case, host: str, image: str, exports: list[str]) -> None:
    """Register exports of a host in the index's sources (joined to its
    Security.evtx entry), with rows on disk."""
    from core.contents_index import _connect
    con = _connect(case)
    eid = con.execute("SELECT id FROM entries WHERE image = ? AND name = 'Security.evtx'",
                      (f"evidence/disk/{image}",)).fetchone()[0]
    (case / "exports").mkdir(exist_ok=True)
    for rel in exports:
        (case / rel).write_text("time,image\n2031-03-10 10:00:00,C:\\Windows\\notepad.exe\n", encoding="utf-8")
        con.execute("INSERT INTO sources (export, host, source_path, entry_id, rows, first, last, kinds, channels) "
                    "VALUES (?,?,?,?,?,?,?,?,?)", (rel, host, f"evidence/disk/{image}::Security.evtx", eid, 1,
                                                   "2031-03-10", "2031-03-10", "", "Security"))
    con.commit()
    con.close()


# ── the no_reader pass: once per key ─────────────────────────────────────

def test_the_no_reader_pass_runs_once_per_key_and_the_key_follows_its_inputs(case, monkeypatch):
    led = _case(case, monkeypatch)
    _sources(case, "CORP-WS01", "corp-ws01.raw", ["exports/corp-ws01-security.csv"])
    key = ED.code_no_reader_key(case, load_ledger(case))
    assert key and key == ED.code_no_reader_key(case, load_ledger(case))     # stable while nothing changed
    calls: list = []
    real = L.check_leave

    def counting(*a, **k):
        calls.append(a[2] if len(a) > 2 else k.get("ref"))
        return real(*a, **k)
    monkeypatch.setattr(L, "check_leave", counting)
    ED.credit_dispositions(case)
    first = len(calls)
    assert first > 0                                           # the pass ran once
    ED.credit_dispositions(case)
    assert len(calls) == first                                 # nothing changed: not repeated
    led = load_ledger(case)
    assert led["meta"]["code_no_reader_key"] == key and "code_no_reader_at" not in led["meta"]
    assert all(c.get("no_reader_key") == key for c in led["classes"].values()
               if c["state"] in ("pending", "relevant"))         # every open class carries the key
    # A class opened again (a reopen clears its leave) is checked again,
    # the others are not.
    cls = next(c for c in led["classes"].values() if c["state"] in ("pending", "relevant"))
    ED.reopen(cls, "the scope changed")                      # a reopen clears the key by itself
    assert "no_reader_key" not in cls
    save_ledger(case, led)
    ED.credit_dispositions(case)
    assert calls[first:] == [cls["id"]]
    n = len(calls)
    # A new attacker entity changes the key and every open class is checked again.
    L._ATTACKER_MEMO.clear()
    _attacker(case, "svc_kit.exe")
    key2 = ED.code_no_reader_key(case, load_ledger(case))
    assert key2 != key
    ED.credit_dispositions(case)
    assert len(calls) > n + 1
    n = len(calls)
    # A changed export (new rows) changes the key; an untouched one does not.
    ED.credit_dispositions(case)
    assert len(calls) == n
    p = case / "exports" / "corp-ws01-security.csv"
    p.write_text(p.read_text(encoding="utf-8") + "2031-03-11 11:00:00,C:\\Users\\Public\\svc_kit.exe\n", encoding="utf-8")
    os.utime(p, (time.time() + 5, time.time() + 5))
    assert ED.code_no_reader_key(case, load_ledger(case)) != key2
    # A credited read elsewhere changes no other class's verdict: the key stands.
    led = load_ledger(case)
    other = next(c for c in led["classes"].values() if c["state"] in ("pending", "relevant"))
    before = ED.code_no_reader_key(case, led)
    other["state"] = "read"
    assert ED.code_no_reader_key(case, led) == before


def test_the_key_never_skips_the_pass_when_it_cannot_be_computed(case, monkeypatch):
    led = _case(case, monkeypatch)
    monkeypatch.setattr("core.contents_index.listing_generation", lambda c: (_ for _ in ()).throw(RuntimeError("x")))
    assert ED.code_no_reader_key(case, led) == ""
    calls: list = []
    monkeypatch.setattr(L, "check_leave", lambda *a, **k: (calls.append(1), {"ok": False, "error": "x"})[1])
    ED._code_no_reader(case, led)
    ED._code_no_reader(case, led)
    assert len(calls) >= 2                                      # no key, no skip


def test_the_attacker_set_is_read_once_per_change_of_the_beliefs(case, monkeypatch):
    _case(case, monkeypatch)
    reads: list = []
    real = L._attacker_entities
    monkeypatch.setattr(L, "_attacker_entities", lambda c: (reads.append(1), real(c))[1])
    L._ATTACKER_MEMO.clear()
    a = L.attacker_entities(case)
    b = L.attacker_entities(case)
    assert a == b and reads == [1]                              # one read for the turn
    _attacker(case, "svc_kit.exe")                               # a new belief: read again
    assert "svc_kit.exe" in L.attacker_entities(case) and reads == [1, 1]


# ── the sweep: one scan per image and per host ──────────────────────────

def test_the_sweep_counts_a_hosts_exports_once_for_all_its_classes_and_hits_the_same(case, monkeypatch):
    led = _case(case, monkeypatch)
    _sources(case, "CORP-WS01", "corp-ws01.raw", ["exports/corp-ws01-security.csv", "exports/corp-ws01-system.csv"])
    (case / "exports" / "corp-ws01-security.csv").write_text(
        "time,image\n2031-03-10 10:00:00,C:\\Users\\Public\\svc_kit.exe\n", encoding="utf-8")
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    own = [c for c in led["classes"].values() if c["item"] == ws01["id"]]
    assert len(own) >= 2
    vals = ["svc_kit.exe", "203.0.113.9"]
    import tools.tabular as TB
    real = TB.count_values
    counted: list = []

    def counting(case_dir, values, sources, kinds=None):
        counted.append(tuple(sources))
        return real(case_dir, values, sources, kinds)
    monkeypatch.setattr(TB, "count_values", counting)
    L._SWEEP_MEMO.clear()
    hits = {c["label"]: L.sweep(case, "class", c, ws01, vals) for c in own}
    assert len(counted) == 1, counted                          # one count for the host's exports
    # The same hits as the unshared computation (each class its own exports).
    L._SWEEP_MEMO.clear()
    monkeypatch.setattr(TB, "count_values", real)
    for c in own:
        L._SWEEP_MEMO.clear()
        assert L.sweep(case, "class", c, ws01, vals) == hits[c["label"]], c["label"]
    sec = next(c for c in own if c["label"].startswith("authentication"))
    assert any("svc_kit.exe in exports/corp-ws01-security.csv" == h for h in hits[sec["label"]])
    # A changed export is read again; an untouched set is not.
    monkeypatch.setattr(TB, "count_values", counting)
    counted.clear()
    L.sweep(case, "class", sec, ws01, vals)
    L.sweep(case, "class", sec, ws01, vals)
    assert len(counted) == 1
    p = case / "exports" / "corp-ws01-system.csv"
    p.write_text(p.read_text(encoding="utf-8") + "2031-03-12 09:00:00,C:\\x.exe\n", encoding="utf-8")
    os.utime(p, (time.time() + 5, time.time() + 5))
    L.sweep(case, "class", sec, ws01, vals)
    assert len(counted) == 2


def test_the_sweep_scans_an_images_entries_once_per_value_set_for_all_its_classes(case, monkeypatch):
    from tests.core.test_evidence_leave import T_OLD, _b
    led = _case(case, monkeypatch, ws03=[_b("Windows/System32/winevt/Logs/Security.evtx", "200-128-1", T_OLD, 70000),
                                         _b("Users/john.roe/c.txt", "213-128-1", T_OLD),
                                         _b("Users/john.roe/svc_kit.exe", "300-128-1", T_OLD)])
    ws03 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws03.raw"))
    own = [c for c in led["classes"].values() if c["item"] == ws03["id"]]
    assert len(own) >= 2
    queries: list = []
    real = L._image_value_paths

    def counting(case_dir, item, vals):
        queries.append(tuple(vals))
        return real(case_dir, item, vals)
    monkeypatch.setattr(L, "_image_value_paths", counting)
    L._SWEEP_MEMO.clear()
    for c in own:
        L.sweep(case, "class", c, ws03, ["svc_kit.exe"])
    item_hits = L.sweep(case, "item", ws03, ws03, ["svc_kit.exe"])
    assert len(queries) == 1                                     # one scan of the image for every class and the item
    assert item_hits == ["svc_kit.exe in evidence/disk/corp-ws03.raw::Users/john.roe/svc_kit.exe"]
    # A class holds the hit only when the path is of its label.
    exe = [c for c in own if any("svc_kit" in h for h in L.sweep(case, "class", c, ws03, ["svc_kit.exe"]))]
    assert all("svc_kit" not in h for c in own if c not in exe for h in L.sweep(case, "class", c, ws03, ["svc_kit.exe"]))


# ── the evidence profile ────────────────────────────────────────────────

def test_the_profile_is_not_rebuilt_for_the_runs_own_writes_but_for_a_new_export(case, monkeypatch):
    (case / "evidence" / "notes.txt").write_text("a note\n", encoding="utf-8")
    builds: list = []
    real = EP.build_evidence_profile

    def counting(case_dir):
        builds.append(1)
        return real(case_dir)
    monkeypatch.setattr(EP, "build_evidence_profile", counting)
    EP._PROFILE_MEMO.clear()
    first = EP.ensure_evidence_profile(str(case))
    assert builds == [1] and first.get("derived_signature")
    # The trace document rewritten under analysis/ (what a run does every
    # turn): no rebuild, the same dict back.
    trace = case / "analysis" / "CASE-A_trace.json"
    trace.write_text(json.dumps({"entries": [1]}), encoding="utf-8")
    os.utime(case / "analysis", None)
    assert EP.ensure_evidence_profile(str(case)) is first and builds == [1]
    assert not EP._profile_is_stale(case, first)
    # A parser output under exports/ makes it stale and rebuilt once.
    (case / "exports").mkdir(exist_ok=True)
    (case / "exports" / "corp-ws01-security.csv").write_text("time,id\n2031-03-10 10:00:00,4624\n", encoding="utf-8")
    assert EP._profile_is_stale(case, first)
    second = EP.ensure_evidence_profile(str(case))
    assert builds == [1, 1] and second is not first
    assert EP.ensure_evidence_profile(str(case)) is second and builds == [1, 1]


def test_an_export_registered_mid_run_reaches_the_next_sweep_without_a_memo_clear(case, monkeypatch):
    """The class's own exports are keyed by the sources table's version: a
    new export whose rows hold the attacker value is found by the next
    sweep while the memo is warm (a listing generation alone would not
    change)."""
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    sec = next(c for c in led["classes"].values() if c["item"] == ws01["id"] and c["label"].startswith("authentication"))
    vals = ["svc_kit.exe"]
    L._SWEEP_MEMO.clear()
    assert L.sweep(case, "class", sec, ws01, vals) == []                   # the memo is warm now
    _sources(case, "CORP-WS01", "corp-ws01.raw", ["exports/corp-ws01-security.csv"])
    (case / "exports" / "corp-ws01-security.csv").write_text(
        "time,image\n2031-03-10 10:00:00,C:\\Users\\Public\\svc_kit.exe\n", encoding="utf-8")
    assert L.sweep(case, "class", sec, ws01, vals) == ["svc_kit.exe in exports/corp-ws01-security.csv"]


def test_a_two_part_extension_pattern_matches_whole():
    from tools.tool_capabilities import readers_by_input_name
    decl = [("x.tarball", ("*.tar.gz",)), ("x.gzip", ("*.gz",))]
    assert readers_by_input_name("backup.tar.gz", decl) == ["x.tarball", "x.gzip"]
    assert readers_by_input_name("backup.gz", decl) == ["x.gzip"]
