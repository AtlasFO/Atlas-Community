"""C2 item 2 (ATLAS_LISTING_SHAPE): a listing's shape reaches the model.
The per-host digest with its rare branches, the index search's directory
summary where rows would be cut, and a spilled fls listing returned as the
summary of the whole spill. Invented fixtures only (CORP-DC01, CORP-WS01,
CORP-WS02, jane.doe)."""
from __future__ import annotations

import core.contents_index as ci
from tests.core.test_contents_index import _body, _build, _image, _links, _plan, case  # noqa: F401

STD = [_body("Windows/System32/winevt/Logs/Security.evtx", "200-128-1"),
       _body("Windows/System32/config/SYSTEM", "201-128-1"),
       _body("Users/Public/desktop.ini", "202-128-1")]


def _three_hosts(case, monkeypatch, extra_ws02=()):
    names = {"CORP-DC01": "corp-dc01.raw", "CORP-WS01": "corp-ws01.raw", "CORP-WS02": "corp-ws02.raw"}
    _links(case, [(h, f"evidence/disk/{n}") for h, n in names.items()])
    _plan(case, [_image(case, n) for n in names.values()])
    kit = [_body(f"Tools/Kit/t{i}.exe", f"30{i}-128-1") for i in range(5)]
    _build(case, monkeypatch, {"corp-dc01.raw": STD, "corp-ws01.raw": STD + [_body("Users/jane.doe/a.txt", "210-128-1")],
                               "corp-ws02.raw": STD + kit + list(extra_ws02)})


def test_the_digest_names_a_tree_one_host_holds_and_no_shared_one(case, monkeypatch):
    _three_hosts(case, monkeypatch)
    d = ci.listing_digest(case)
    ws02 = next(line for line in d["lines"] if line.startswith("CORP-WS02"))
    assert "Tools (5 files)" in ws02 and "Windows" not in ws02.split("few:")[1]
    assert d["lines"][0].startswith("CORP-WS02")          # the most rare-branch files first
    dc = next(line for line in d["lines"] if line.startswith("CORP-DC01"))
    assert dc.endswith("few: none")
    one = ci.listing_digest(case, bound=1)
    assert len(one["lines"]) == 2 and "2 more hosts not shown" in one["lines"][1]


def test_index_find_returns_directories_when_rows_would_be_cut(case, monkeypatch):
    from tools.sleuthkit import tsk_index_find
    _three_hosts(case, monkeypatch, extra_ws02=[_body(f"Logs/app/l{i}.log", f"4{i:02d}-128-1") for i in range(60)])
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    r = tsk_index_find(pattern="*.log", host="CORP-WS02", limit=40)
    assert r["total"] == 60 and "rows" not in r
    assert r["summary"][0].startswith("CORP-WS02 Logs/app: 60 files (log 60)") and "handle" in r["summary"][0]
    rows = tsk_index_find(pattern="*.log", host="CORP-WS02", limit=40, summary=False)
    assert len(rows["rows"]) == 40 and rows["next_offset"] == 40
    small = tsk_index_find(pattern="*.exe", host="CORP-WS02")
    assert len(small["rows"]) == 5 and "summary" not in small
    monkeypatch.setenv("ATLAS_LISTING_SHAPE", "0")
    assert len(tsk_index_find(pattern="*.log", host="CORP-WS02")["rows"]) == 40


def test_a_spilled_listing_returns_the_summary_of_the_whole_spill(tmp_path):
    from tools.sleuthkit import _spill_as_summary
    lines = [_body(f"Users/jane.doe/Docs/d{i}.txt", f"{1000 + i}-128-1") for i in range(4000)]
    lines += [_body(f"Windows/Temp/t{i}.tmp", f"{6000 + i}-128-1") for i in range(1000)]
    spill = tmp_path / "spill.txt"
    spill.write_text("\n".join(lines) + "\n")
    res = {"success": True, "truncated": True, "stdout_file": str(spill), "stdout": lines[0]}
    out = _spill_as_summary(res, "evidence/disk/corp-ws01.raw", bodyfile=True)
    assert out["listing_summary"] and out["stdout"].startswith("5,000 files in 2 directories")
    assert "Users/jane.doe/Docs: 4000 files" in out["stdout"] and str(spill) in out["note"]
    assert _spill_as_summary({"success": True, "truncated": False, "stdout": "x"}, "i", True)["stdout"] == "x"


def test_a_later_page_is_rows_and_the_digest_follows_the_listing_generation(case, monkeypatch):
    from tools.sleuthkit import tsk_index_find
    _three_hosts(case, monkeypatch, extra_ws02=[_body(f"Logs/app/l{i}.log", f"4{i:02d}-128-1") for i in range(60)])
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    later = tsk_index_find(pattern="*.log", host="CORP-WS02", limit=40, offset=40)
    assert len(later["rows"]) == 20 and "summary" not in later
    gen = ci.listing_generation(case)
    assert gen >= 1
    calls = []
    real = ci._digest_per_host
    monkeypatch.setattr(ci, "_digest_per_host", lambda c: calls.append(1) or real(c))
    ci._DIGEST_CACHE.clear()
    ci.listing_digest(case)
    con = ci._connect(case)                                 # a read writing the index: no new digest
    con.execute("INSERT INTO partial (source_id, call_id, rows_shown) VALUES (1, 7, 3)")
    con.commit()
    con.close()
    ci.listing_digest(case)
    assert calls == [1]
    con = ci._connect(case)
    ci._meta_set(con, "listing_generation", {"n": gen + 1})
    con.commit()
    con.close()
    ci.listing_digest(case)
    assert calls == [1, 1]
