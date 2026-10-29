"""Design 12.3(3): the plan message names each source's form and cost, quick
sources first, and PLAN_SYS carries the one method line. Invented fixtures
only (CORP-WS01, CORP-WS02, an invented image, dates in 2031)."""
from __future__ import annotations

import json
import re

from core import question_plan as QP
from core.coverage_ledger import save_ledger
from tests.core.test_incident_map import _case

_METHOD = ("Start with sources that are already records or summaries and are quick to read; use them to find the "
           "first values and hosts, then go deeper where they point. Read a slow source when a quicker one cannot "
           "answer the question.")


def _fixture(tmp_path, tables: dict, files=("evidence/corp-ws01.raw",)):
    from core.contents_index import _connect
    case = _case(tmp_path)
    for f in list(files) + list(tables):
        p = case / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\0" * (4096 if f.endswith(".raw") else 64))
    paths = list(files) + list(tables)
    save_ledger(case, {"units": {f"u{i}": {"id": f"u{i}", "path": p, "kind": "file"} for i, p in enumerate(paths)},
                       "items": {"i0": {"id": "i0", "path": "evidence/corp-ws01.raw", "kind": "image"}},
                       "classes": {}})
    con = _connect(case, create=True)
    for path, (rows, first, last, hosts) in tables.items():
        con.execute("INSERT INTO exports VALUES (?,?,?,?,?,?,?)", (path, "csv", rows, first, last,
                                                                   json.dumps(hosts), "{}"))
    con.commit()
    con.close()
    return case


def test_each_source_shows_its_form_and_cost_and_quick_ones_come_first(tmp_path, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.window_start", lambda c: "2031-03-11T00:00:00")
    case = _fixture(tmp_path, {
        "evidence/timelines/corp-ws01-a.csv": (1200, "2031-03-10 08:00:00", "2031-03-12 17:00:00", ["CORP-WS01"]),
        "evidence/timelines/corp-ws01-b.csv": (40, "2031-03-01 08:00:00", "2031-03-02 09:00:00", ["CORP-WS01"]),
        "evidence/timelines/corp-ws01-c.csv": (0, "", "", ["CORP-WS01"]),
        "evidence/timelines/estate.csv": (900, "2031-03-10 00:00:00", "2031-03-12 00:00:00",
                                          ["CORP-WS01", "CORP-WS02"])})
    lines = QP.source_lines(str(case))
    ws01 = next(ln for ln in lines if ln.startswith("- CORP-WS01:"))
    assert ws01.index("corp-ws01-a.csv [parsed table, 1,200 rows, 2031-03-10 08:00:00 to 2031-03-12 17:00:00]") \
        < ws01.index("corp-ws01-c.csv [parsed table, empty]") < ws01.index("corp-ws01.raw [disk image, 4.0 KB]")
    assert "corp-ws01-b.csv [parsed table, 40 rows, 2031-03-01 08:00:00 to 2031-03-02 09:00:00, ends before the " \
           "earliest stated start]" in ws01
    assert "estate.csv" not in ws01 and lines[lines.index("SPANNING HOSTS (each named once):") + 1].startswith(
        "- evidence/timelines/estate.csv [parsed table, 900 rows") and "spans 2 hosts" in lines[-1]


def test_the_per_host_bound_says_what_it_leaves_out_and_never_hides_an_image(tmp_path, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.window_start", lambda c: "")
    tables = {f"evidence/timelines/corp-ws01-{n:02d}.csv": (10 + n, "2031-03-10 08:00:00", "2031-03-10 09:00:00",
                                                            ["CORP-WS01"]) for n in range(15)}
    case = _fixture(tmp_path, tables)
    ws01 = next(ln for ln in QP.source_lines(str(case)) if ln.startswith("- CORP-WS01:"))
    assert "corp-ws01.raw [disk image" in ws01 and ws01.count("[parsed table") == QP.SOURCES_PER_HOST - 1
    assert ws01.endswith("(4 more of this host not listed: 4 tables, 0 other)")


def test_the_new_texts_name_no_tool_format_or_artefact():
    assert _METHOD in QP.PLAN_SYS and _METHOD in QP.plan_system()
    fixed = " ".join([_METHOD, *QP._FORM_WORDS.values(), "EVIDENCE PER HOST (each source with its form, and rows "
                      "and time span or size):", "SPANNING HOSTS (each named once):", "ends before the earliest "
                      "stated start", "more of this host not listed"]).lower()
    names = ("evtx", "mft", "prefetch", "registry", "hive", "volatility", "csv", "sysmon", "security", "json",
             "timeline", "amcache", "shimcache", "lnk", "pcap", "zeek", "hayabusa", "chainsaw", "plaso", "log ")
    assert not [n for n in names if re.search(rf"\b{n}", fixed)]


def test_without_index_or_ledger_facts_the_sources_are_plain_files(tmp_path, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.window_start", lambda c: "")
    case = _case(tmp_path)
    assert QP.source_facts(str(case)) == {}
