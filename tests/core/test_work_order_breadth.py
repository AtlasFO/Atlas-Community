"""The parts beside the order: no deferral (ATLAS_DAIR_NO_DEFER),
coverage honesty (ATLAS_COVERAGE_HONESTY) and the estate count
(ATLAS_ESTATE_COUNT). Invented fixtures only (CORP-WS01, CORP-WS05,
jane.doe, 203.0.113.x, dates in 2031)."""
from __future__ import annotations

import csv
import io
import json

import pytest

import core.coverage_ledger as cl
from core.execution_log import ExecutionLog


@pytest.fixture
def log(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    lg = ExecutionLog()
    lg.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", lg)
    return root, lg


# ── no deferral ───────────────────────────────────────────────────────────

def test_no_forensic_call_is_deferred_and_old_intents_are_retired(log):
    root, lg = log
    lg.record_dair_call("Collect", "", False, "", "", "stay", "")
    for i in range(25):
        lg.record_tool_call(f"<py>:strings_strings_read_text_{i}", True, False, 0, 0)
    from core.middleware import _gate_decision
    assert _gate_decision() == (False, "no deferral")
    lg.record_deferred_intent("tsk_tsk_icat", {"image": "x"}, "window aged out")
    assert lg.open_deferred_intents() == []
    assert lg.retire_protocol_intents("deferral off") == 1
    assert [e["status"] for e in lg._entries if e.get("type") == "deferred_intent"] == ["retired"]


def test_with_the_switch_off_the_window_defers(log, monkeypatch):
    root, lg = log
    monkeypatch.setenv("ATLAS_DAIR_NO_DEFER", "0")
    lg.record_dair_call("Collect", "", False, "", "", "stay", "")
    for i in range(25):
        lg.record_tool_call(f"<py>:strings_strings_read_text_{i}", True, False, 0, 0)
    from core.middleware import _gate_decision
    assert _gate_decision()[0] is True


def test_the_two_gates_observe_and_never_refuse():
    from types import SimpleNamespace
    from tools._gates import dair_required, hypothesize_required
    ctx = SimpleNamespace(window=[], log=None, description="svchost.exe beacons to 203.0.113.9 every 60 s",
                          confidence="LIKELY", tier="LIKELY", tested_hypothesis_id="",
                          gated_by_hypothesize_call_id=0)
    assert dair_required.check(ctx) is None
    assert hypothesize_required.check(ctx) is None


def test_the_playbook_and_the_recipe_speak_of_the_work_order(monkeypatch):
    from agent.playbook import assemble_playbook
    from agent.prompts import initial_user_message
    text = assemble_playbook()
    assert "WORK-ORDER LOOP" in text and "Deferred intents (protocol recovery)" not in text
    assert "dair_assess after every tool batch" not in initial_user_message("q", "ns")
    monkeypatch.setenv("ATLAS_DAIR_NO_DEFER", "0")
    assert "Deferred intents (protocol recovery)" in assemble_playbook()


# ── coverage honesty ──────────────────────────────────────────────────────

@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    (d / "evidence").mkdir()
    (d / "evidence" / "disk.E01").write_bytes(b"x" * 16)
    (d / "evidence" / "auth.csv").write_text("a,b\n1,2\n")
    cl.build_coverage_ledger(d)
    return d


def _probe(case, tool, args, cid):
    cl.observe_tool_paths(case, tool_name=tool, cmd_or_args=json.dumps(args), success=True,
                          result_text=json.dumps({"success": True, "_atlas_call_id": cid}))


def test_a_listing_is_not_a_read_and_the_report_says_listed_only(case):
    from core.evidence_items import counts, gap_lines, report_lines, rows, unseen
    _probe(case, "tsk_fls", {"image": "evidence/disk.E01"}, 412)
    item = next(r for r in rows(case) if r["path"] == "evidence/disk.E01")
    assert item["listed_by"] == {"call_id": "412", "tool": "tsk_fls"} and not item.get("read_by")
    assert "evidence/disk.E01" in unseen(case)
    c = counts(rows(case))
    assert c["listed_only"] == 1 and c["read"] == 0
    gap = [g for g in gap_lines(case) if "disk.E01" in g][0]
    assert gap.startswith("- Listed only, content never read:") and "tsk_fls listed it (call 412)" in gap
    assert any("listed only: tsk_fls (call 412)" in line for line in report_lines(case))
    assert cl.states_unread(case, gap, ["evidence/disk.E01"])
    _probe(case, "tsk_icat", {"image": "evidence/disk.E01", "inode": "5"}, 420)
    item = next(r for r in rows(case) if r["path"] == "evidence/disk.E01")
    assert item["read_by"]["call_id"] == "420" and "evidence/disk.E01" not in unseen(case)


def test_ledger_status_splits_listed_and_read(case, monkeypatch):
    monkeypatch.setattr("tools.coverage._ledger_case_dir", lambda: str(case))
    _probe(case, "tsk_fls", {"image": "evidence/disk.E01"}, 412)
    _probe(case, "table_table_query", {"path": "evidence/auth.csv"}, 413)
    from tools.coverage import ledger_status
    out = getattr(ledger_status, "fn", ledger_status)()
    assert out["listed_only"] == ["evidence/disk.E01"] and "evidence/auth.csv" in out["read"]
    # The read inside an image is the handle (core.contents_index), or the two-step read without it.
    assert "<image>::<path>" in cl.read_hint(cl.CONTAINER_KIND) and "identify an image" in cl.read_hint(cl.CONTAINER_KIND)
    monkeypatch.setenv("ATLAS_IMAGE_HANDLES", "0")
    assert "tsk.icat" in cl.read_hint(cl.CONTAINER_KIND)
    monkeypatch.delenv("ATLAS_IMAGE_HANDLES")


def test_no_coverage_refusal_at_report_entry(monkeypatch):
    import tools.dair as D
    assert D._report_entry_coverage_gate() == ("", [])


# ── the estate count ──────────────────────────────────────────────────────

def _timeline(path, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["date", "time", "source", "sourcetype", "desc", "filename"])
    w.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def test_count_indicators_rows_spans_and_both_numbers_for_a_path(tmp_path):
    from tools.tabular import count_indicators
    _timeline(tmp_path / "corp-ws05.csv", [
        ["03/01/2031", "08:12:00", "EVT", "x", "ran TOOL.EXE", "C:\\Tasks\\upd\\tool.exe"],
        ["03/09/2031", "17:40:00", "EVT", "x", "connect 203.0.113.9", "-"],
        ["03/02/2031", "09:00:00", "FILE", "x", "prefetch TOOL.EXE-1A2B.pf", "-"]])
    _timeline(tmp_path / "corp-ws01.csv", [["03/03/2031", "10:00:00", "EVT", "x", "nothing", "-"]])
    (tmp_path / "corp-hub01.csv").write_bytes("date,time,desc\n03/04/2031,10:00:00,tool.exe é\n".encode("utf-16"))
    res = count_indicators(str(tmp_path), ["file:tool.exe", "path:C:/Tasks/upd/tool.exe", "ip:203.0.113.9",
                                            "account:corp/svc-backup"],
                           ["corp-ws05.csv", "corp-ws01.csv", "corp-hub01.csv"])
    c = res["counts"]
    assert c["file:tool.exe"]["corp-ws05.csv"]["full"] == 2
    assert c["file:tool.exe"]["corp-ws05.csv"]["first"].startswith("2031-03-01")
    assert c["file:tool.exe"]["corp-hub01.csv"]["full"] == 1          # the reader where grep cannot stand in
    p = c["path:C:/Tasks/upd/tool.exe"]["corp-ws05.csv"]
    assert p["full"] == 1 and p["name"] == 2
    assert c["ip:203.0.113.9"]["corp-ws05.csv"]["full"] == 1 and c["account:corp/svc-backup"] == {}


def test_count_lines_name_hosts_by_the_tables_path_and_zero_rows_share_a_line(log, monkeypatch):
    root, _lg = log
    from core.ioc_pivots import count_lines
    monkeypatch.setattr("core.forensic_citation.known_case_hosts", lambda _c: ["CORP-WS05", "CORP-WS01"])
    counts = {"file:tool.exe": {"analysis/corp-ws05.csv": {"full": 126, "name": 0, "first": "2031-03-01 08:12:00",
                                                           "last": "2031-03-09 17:40:00"}},
              "url:203.0.113.9/x": {}, "account:corp/svc-backup": {}}
    lines = count_lines(str(root), counts, sources=["analysis/corp-ws05.csv", "analysis/corp-ws01.csv"])
    assert lines[0].startswith("[estate counts]")
    assert "- file tool.exe: 126 rows CORP-WS05 (2031-03-01 08:12 .. 2031-03-09 17:40); 0 rows on 1 other tables" in lines
    assert any(line.startswith("- 0 rows anywhere: 2 indicators") for line in lines)
    new = count_lines(str(root), counts, sources=["analysis/corp-ws05.csv"], new_tables=["analysis/corp-ws05.csv"])
    assert any(line.startswith("- new table analysis/corp-ws05.csv: tool.exe 126 rows") for line in new)
    assert any(line.startswith("- 0 rows in the new table: 2 indicators") for line in new)


def test_a_pass_over_several_new_tables_names_each_indicators_tables_on_one_line(log, monkeypatch):
    """The tables that appeared since the last pass are counted in one
    pass (one thread, one trace entry); the block names, per indicator,
    the new tables with rows, most rows first, and the zero line says
    which tables it counted."""
    root, _lg = log
    from core.ioc_pivots import count_lines
    monkeypatch.setattr("core.forensic_citation.known_case_hosts", lambda _c: ["CORP-WS05", "CORP-WS01"])
    tables = ["analysis/corp-ws05.csv", "analysis/corp-ws01.csv", "analysis/corp-dc01.csv"]
    counts = {"file:tool.exe": {tables[0]: {"full": 3, "name": 0, "first": "2031-03-01 08:12:00", "last": ""},
                                tables[1]: {"full": 126, "name": 0, "first": "", "last": ""}},
              "ip:203.0.113.9": {}}
    lines = count_lines(str(root), counts, sources=tables, new_tables=tables)
    assert "- new tables: tool.exe 126 rows analysis/corp-ws01.csv; 3 rows analysis/corp-ws05.csv (2031-03-01 08:12)" in lines
    assert any(line.startswith("- 0 rows in the 3 new tables: 1 indicators (ip 203.0.113.9)") for line in lines)
    assert sum(line.startswith("- new table") for line in lines) == 1


def test_a_pass_over_thirty_new_tables_names_three_and_counts_the_rest(log, monkeypatch):
    """One line per indicator stays one line: the three tables with most
    rows are named, the rest are a count of tables and rows (the block
    already says where to read the rows)."""
    root, _lg = log
    from core.ioc_pivots import count_lines
    monkeypatch.setattr("core.forensic_citation.known_case_hosts", lambda _c: [])
    tables = [f"analysis/mail/folder-{i:02d}.csv" for i in range(30)]
    counts = {"ip:203.0.113.9": {t: {"full": i + 1, "name": 0, "first": "", "last": ""} for i, t in enumerate(tables)}}
    lines = count_lines(str(root), counts, sources=tables, new_tables=tables)
    assert ("- new tables: 203.0.113.9 30 rows analysis/mail/folder-29.csv; 29 rows analysis/mail/folder-28.csv; "
            "28 rows analysis/mail/folder-27.csv; and 27 more tables, 378 rows") in lines
    assert len([line for line in lines if line.startswith("- ")]) == 1


def test_the_ledger_keeps_counts_and_credits_shown_rows_only(log):
    root, _lg = log
    from core.ioc_pivots import gap_lines, load_pivots, observe_search, open_pivots, record_counts, refresh_pivots
    record_counts(root, {"ip:203.0.113.9": {"analysis/corp-ws05.csv": {"full": 4, "name": 0}}})
    refresh_pivots(root)
    assert open_pivots(root) == []
    assert gap_lines(root) == ["- Rows counted, never shown: `203.0.113.9` (4 rows on analysis/corp-ws05.csv)"]
    blob = json.dumps({"path": "analysis/corp-ws05.csv", "pattern": "203.0.113.9"})
    observe_search(root, blob=blob, result=json.dumps({"success": True, "hits": [{"desc": "x"}]}))
    assert "analysis/corp-ws05.csv" not in (load_pivots(root)["pivots"]["ip:203.0.113.9"].get("shown") or {})
    observe_search(root, blob=blob, result=json.dumps({"success": True,
                                                       "hits": [{"desc": "connect 203.0.113.9"}]}))
    assert "analysis/corp-ws05.csv" in load_pivots(root)["pivots"]["ip:203.0.113.9"]["shown"]
    assert gap_lines(root) == []


def test_the_recipe_swaps_are_exact(monkeypatch):
    from agent.prompts import _switch_texts
    before = ("Then drive the DAIR loop (dair_assess after every tool batch) until it directs Report. "
              "x drive the DAIR loop (dair_assess after every tool batch). "
              "y the [ioc pivot] nudge lists the searches still owed.")
    assert _switch_texts(before) == (
        "Then work through the [work order] shown each turn; call dair_assess when you need a new direction "
        "or a phase change, until it directs Report. x work through the [work order] shown each turn; call "
        "dair_assess when you need a new direction or a phase change. y the [estate counts] show where each "
        "indicator has rows; read them there.")
    monkeypatch.setenv("ATLAS_DAIR_NO_DEFER", "0")
    monkeypatch.setenv("ATLAS_ESTATE_COUNT", "0")
    assert _switch_texts(before) == before


def test_the_native_pass_counts_as_the_row_loop_does(tmp_path, monkeypatch):
    from tools.tabular import count_indicators
    _timeline(tmp_path / "corp-ws05.csv", [
        ["03/01/2031", "08:12:00", "EVT", "x", "ran TOOL.EXE from C:/Tasks/upd/tool.exe", "C:\\Tasks\\upd\\tool.exe"],
        ["03/09/2031", "17:40:00", "EVT", "x", "connect 203.0.113.9 and 203.0.113.90", "-"],
        ["03/02/2031", "09:00:00", "FILE", "x", "prefetch TOOL.EXE-1A2B.pf", "-"],
        ["02/27/2031", "23:59:59", "REG", "x", "C:\\\\Tasks\\\\upd\\\\tool.exe escaped", "-"]])
    iocs = ["file:tool.exe", "path:C:/Tasks/upd/tool.exe", "ip:203.0.113.9", "account:corp/svc-backup"]
    native = count_indicators(str(tmp_path), iocs, ["corp-ws05.csv"])
    monkeypatch.setenv("ATLAS_ESTATE_COUNT_NATIVE", "0")
    loop = count_indicators(str(tmp_path), iocs, ["corp-ws05.csv"])
    assert native == loop
    assert native["counts"]["path:C:/Tasks/upd/tool.exe"]["corp-ws05.csv"]["full"] == 2
    assert native["counts"]["file:tool.exe"]["corp-ws05.csv"]["first"].startswith("2031-02-27 23:59:59")


def test_a_non_ascii_term_on_a_cp1252_table_takes_the_row_loop(tmp_path):
    from tools.tabular import _count_native
    p = tmp_path / "corp-ws05.csv"
    p.write_bytes("date,time,desc\n03/01/2031,08:12:00,Datei übertragen\n".encode("cp1252"))
    import core.input_kind as ik
    assert ik.text_encoding(str(p)) == "cp1252"
    assert _count_native(str(p), [("file:übertragen", "full", ["übertragen"])]) is None


def test_count_values_gives_bare_values_their_form_and_keys_them_back(tmp_path):
    from tools.tabular import count_values
    (tmp_path / "corp-ws05.csv").write_text(
        "time,desc\n2031-03-01 08:00:00,ran C:\\Tasks\\tool.exe as CORP\\jane.doe\n"
        "2031-03-02 09:00:00,prefetch TOOL.EXE-1A2B.pf; get https://example.com/a/b\n")
    res = count_values(str(tmp_path), ["C:\\Tasks\\tool.exe", "CORP\\jane.doe", "https://example.com/a/b", "nothing"],
                       ["corp-ws05.csv"], {"CORP\\jane.doe": "account"})
    c = res["counts"]
    assert c["C:\\Tasks\\tool.exe"]["corp-ws05.csv"] == {"full": 1, "name": 2, "first": "2031-03-01 08:00:00",
                                                         "last": "2031-03-02 09:00:00"}
    assert c["CORP\\jane.doe"]["corp-ws05.csv"]["full"] == 1 and c["CORP\\jane.doe"]["corp-ws05.csv"]["name"] == 0
    assert c["https://example.com/a/b"]["corp-ws05.csv"]["full"] == 1 and c["nothing"] == {}
