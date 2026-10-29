"""What a call read (core/provenance.py): paths classed by resolved
containment, the attribution ledger around every call, lineage through
fixed tools only. Layouts and names are invented."""
from __future__ import annotations

import json
import os
import time

import pytest

from core import provenance as P


@pytest.fixture
def case(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    root = tmp_path / "mnt" / "cases" / "CASE-A"       # a case kept under a folder named mnt
    for sub in ("analysis", "evidence", "exports", "reports", ".atlas", "mnt"):
        (root / sub).mkdir(parents=True)
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    P.reset_cache()
    return root, log


def _entry(log, cmd, *, args=None, ref=""):
    cid = log.record_tool_call(cmd, True, False, 0, 0, stdout_excerpt="out", evidence_ref=ref)
    if args is not None:
        log.annotate_tool_call(cid, args=json.dumps(args, sort_keys=True))
    return log.index().by_call_id[cid]


def test_paths_are_classified_by_containment_not_segment_names(case):
    root, log = case
    (root / "evidence" / "img" / "analysis").mkdir(parents=True)
    (root / "evidence" / "img" / "reports").mkdir(parents=True)
    (root / "evidence" / "img" / "analysis" / "x.csv").write_text("x")
    (root / "evidence" / "img" / "reports" / "r.txt").write_text("x")
    # Folders named analysis and reports inside the evidence tree are evidence.
    e = _entry(log, "cat evidence/img/analysis/x.csv evidence/img/reports/r.txt")
    assert P.call_provenance(e, root)["class"] == "evidence"
    # The case's own analysis/ under a folder named mnt is the output tree, not evidence.
    (root / "analysis" / "own.txt").write_text("x")
    e = _entry(log, f"cat {root / 'analysis' / 'own.txt'}")
    assert P.call_provenance(e, root)["class"] == "own"
    # A link from the output tree into evidence is evidence by where it resolves.
    os.symlink(root / "evidence" / "img" / "analysis" / "x.csv", root / "analysis" / "link.csv")
    e = _entry(log, "cat analysis/link.csv")
    assert P.call_provenance(e, root)["class"] == "evidence"
    # Outside the case: own. No path: unplaced.
    e = _entry(log, "cat /etc/hostname")
    assert P.call_provenance(e, root)["class"] == "own"
    e = _entry(log, "<py>:table_table_query", args={"table_id": "t7", "sql": "select 1"})
    assert P.call_provenance(e, root)["class"] == "unplaced"
    # The run's own state, its spills and the brief are own.
    (root / "analysis" / "tool-output").mkdir()
    (root / "analysis" / "tool-output" / "s.json").write_text("x")
    for p in ("analysis/tool-output/s.json", ".atlas/claim_graph.json", "CASE.md"):
        assert P.call_provenance(_entry(log, f"cat {p}"), root)["class"] == "own", p


def test_a_case_root_below_a_parent_named_analysis(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    root = tmp_path / "analysis" / "CASE-B"
    (root / "evidence").mkdir(parents=True)
    (root / "analysis").mkdir()
    (root / "evidence" / "disk.E01").write_text("x")
    log = ExecutionLog()
    log.configure("CASE-B", str(root / "analysis" / "trace.json"))
    monkeypatch.setattr("core.execution_log.log", log)
    P.reset_cache()
    e = _entry(log, f"ewfinfo {root / 'evidence' / 'disk.E01'}")
    assert P.call_provenance(e, root)["class"] == "evidence"


def test_the_plans_mount_points_are_evidence_with_the_images_host(case):
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    mount = root / "mnt" / "ws01" / "fs" / "Windows"
    mount.mkdir(parents=True)
    (mount / "a.log").write_text("x")
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"schema_version": 1, "images": [
        {"path": "evidence/ws01.E01", "mount_result": {"mount_point": str(root / "mnt" / "ws01" / "fs")}}]}))
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01.E01", "kind": "image"}], "hosts": ["CORP-WS01"]}))
    e = _entry(log, "cat mnt/ws01/fs/Windows/a.log")
    prov = P.call_provenance(e, root)
    assert prov["class"] == "evidence" and prov["hosts"] == {"CORP-WS01"}


def test_attribution_ledger_records_changed_files_with_the_producing_call_and_class(case):
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    before = P.output_snapshot(root)
    fixed = _entry(log, "MFTECmd -f evidence/ws01.E01 --csv analysis/mft")
    (root / "analysis" / "mft").mkdir()
    (root / "analysis" / "mft" / "out.csv").write_text("EntryNumber,Created0x10\n1,2031-03-04 10:16:00\n")
    changed = P.record_outputs(root, fixed, before, P.output_snapshot(root))
    assert changed == ["analysis/mft/out.csv"]
    assert P.load_ledger(root)["analysis/mft/out.csv"] == {"call": fixed["call_id"], "class": "derived"}
    # A later table read over it is derived; a program's output is own.
    e = _entry(log, "<py>:table_table_grep", args={"path": "analysis/mft/out.csv", "pattern": "x"})
    assert P.call_provenance(e, root)["class"] == "derived"
    before = P.output_snapshot(root)
    prog = _entry(log, "python3 -c 'open(\"analysis/notes.txt\",\"w\").write(\"x\")'")
    (root / "analysis" / "notes.txt").write_text("x")
    P.record_outputs(root, prog, before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/notes.txt"]["class"] == "own"
    e = _entry(log, "cat analysis/notes.txt")
    assert P.call_provenance(e, root)["class"] == "own"
    # A fixed tool over own input writes own; a file two calls wrote is own when either is.
    before = P.output_snapshot(root)
    over_own = _entry(log, "sort analysis/notes.txt -o analysis/sorted.txt")
    (root / "analysis" / "sorted.txt").write_text("x")
    P.record_outputs(root, over_own, before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/sorted.txt"]["class"] == "own"
    # A rewrite the snapshot can see: the size changes (a same-size rewrite
    # inside one tick of the kernel's coarse file clock is invisible to a
    # stat diff, the ledger's stated ceiling).
    (root / "analysis" / "mft" / "out.csv").write_text("EntryNumber,Created0x10\n2,2031-03-05 10:16:00\n3,x\n")
    P.record_outputs(root, prog, before, P.output_snapshot(root))
    rec = P.load_ledger(root)["analysis/mft/out.csv"]
    assert rec["class"] == "own" and rec["call"] == fixed["call_id"]


def test_a_file_predating_the_first_call_is_derived_and_an_unattributed_one_is_own(case):
    root, log = case
    old = root / "analysis" / "intake.csv"
    old.write_text("TimeCreated,User\n2031-03-04 10:16:00,jane.doe\n")
    past = time.time() - 3600
    os.utime(old, (past, past))
    _entry(log, "fls -o 63 evidence/ws01.E01")          # the run's first call, after the file
    P.reset_cache()
    e = _entry(log, "<py>:table_table_grep", args={"path": "analysis/intake.csv", "pattern": "x"})
    assert P.call_provenance(e, root)["class"] == "derived"
    later = root / "analysis" / "later.csv"
    later.write_text("x")
    future = time.time() + 3600
    os.utime(later, (future, future))
    e = _entry(log, "<py>:table_table_grep", args={"path": "analysis/later.csv", "pattern": "x"})
    assert P.call_provenance(e, root)["class"] == "own"


def test_lineage_hands_a_programs_request_to_the_reader_of_its_derived_output(case):
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    before = P.output_snapshot(root)
    fixed = _entry(log, "<py>:table_table_query", args={"path": "evidence/ws01.E01", "needle": "203.0.113.7",
                                                        "output_csv": "analysis/q.csv"})
    (root / "analysis" / "q.csv").write_text("x")
    P.record_outputs(root, fixed, before, P.output_snapshot(root))
    reader = _entry(log, "<py>:table_table_grep", args={"path": "analysis/q.csv", "pattern": "4624"})
    prov = P.call_provenance(reader, root)
    assert prov["class"] == "derived" and "203.0.113.7" in prov["inherited"]
    assert P.call_provenance(fixed, root)["class"] == "evidence"   # its own output is not its input


def test_scripted_calls_are_recognised_by_the_interpreter_not_the_path():
    assert P.is_scripted({"cmd": "python3 -c 'print(1)'"})
    assert P.is_scripted({"cmd": "/usr/local/bin/python3.11 script.py"})
    assert P.is_scripted({"cmd": "<py>:misc_write_case_document"})
    assert not P.is_scripted({"cmd": "EvtxECmd.exe -f x.evtx"})
    assert not P.is_scripted({"cmd": "<py>:table_table_grep"})


@pytest.mark.parametrize("cmd", [
    "timeout 300 python3 x.py",
    "env A=1 python3 x.py",
    "/usr/bin/env bash -c ls",
    "A=1 python3 x.py",
    "cd /cases/CASE-A && python3 x.py",
    "cat analysis/x.csv | python3 -",
    "xargs -a list.txt python3 x.py",
    "sudo -u root /usr/bin/python3.11 x.py",
    "echo jane.doe >> analysis/n.txt; grep a evidence/ws01.E01",
    "printf '%s' x>analysis/a.txt",
])
def test_an_interpreter_behind_a_wrapper_or_an_operator_and_a_literal_write_are_scripted(cmd):
    assert P.is_scripted({"cmd": cmd})


@pytest.mark.parametrize("cmd", [
    "grep -i python analysis/x.csv",
    "grep 'a;b|python' evidence/ws01.E01",
    "echo done",
    "fls -o 63 evidence/ws01.E01 | grep -i jane.doe",
])
def test_a_fixed_tool_line_is_not_scripted(cmd):
    assert not P.is_scripted({"cmd": cmd})


def test_the_runs_state_files_are_never_attributed(case):
    """The trace, its mirror, the transcript, the index and the Brain's and
    a parser's state change in-process around calls; the snapshot skips them
    by the names their writers use, so a call over evidence never makes them
    derived and the ledger is not rewritten for them."""
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    names = ["CASE-A_trace.json", "CASE-A_trace.jsonl", "agent_transcript_20310304.jsonl",
             "evidence_index.db", "evidence_index.db-wal", "brain_injection.json",
             "brain_consulted.json", "brain_auto_topics.json", ".evtx_parse_registry.json"]
    before = P.output_snapshot(root)
    fixed = _entry(log, "MFTECmd -f evidence/ws01.E01 --csv analysis/mft")
    for name in names:
        (root / "analysis" / name).write_text("state")
    assert P.record_outputs(root, fixed, before, P.output_snapshot(root)) == []
    assert P.load_ledger(root) == {}
    assert not (root / P.LEDGER_FILE).exists()


def test_a_batch_window_is_own_when_any_entry_is_scripted(case):
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    before = P.output_snapshot(root)
    prog = _entry(log, "python3 make_notes.py")
    fixed = _entry(log, "grep x evidence/ws01.E01")
    (root / "analysis" / "notes.csv").write_text("x")
    P.record_outputs(root, [prog, fixed], before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/notes.csv"] == {"call": prog["call_id"], "class": "own"}
    # A window of fixed tools over evidence alone stays derived, under its last call.
    before = P.output_snapshot(root)
    first = _entry(log, "MFTECmd -f evidence/ws01.E01 --csv analysis/mft")
    last = _entry(log, "fls -o 63 evidence/ws01.E01")
    (root / "analysis" / "mft").mkdir()
    (root / "analysis" / "mft" / "out.csv").write_text("x")
    P.record_outputs(root, [first, last], before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/mft/out.csv"] == {"call": last["call_id"], "class": "derived"}


def test_a_file_a_second_call_rewrites_is_own(case):
    root, log = case
    (root / "evidence" / "ws01.E01").write_text("img")
    before = P.output_snapshot(root)
    one = _entry(log, "MFTECmd -f evidence/ws01.E01 --csv analysis/mft")
    (root / "analysis" / "mft").mkdir()
    (root / "analysis" / "mft" / "out.csv").write_text("a")
    P.record_outputs(root, one, before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/mft/out.csv"]["class"] == "derived"
    before = P.output_snapshot(root)
    two = _entry(log, "MFTECmd -f evidence/ws01.E01 --csv analysis/mft")
    (root / "analysis" / "mft" / "out.csv").write_text("ab")
    P.record_outputs(root, two, before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/mft/out.csv"] == {"call": one["call_id"], "class": "own",
                                                           "rewritten_by": two["call_id"]}
    # The mark keeps the record own: the first writer alone re-derives derived.
    reader = _entry(log, "<py>:table_table_grep", args={"path": "analysis/mft/out.csv", "pattern": "x"})
    assert P.call_provenance(reader, root)["class"] == "own"


def test_no_case_identifiers_are_baked_into_the_module():
    import pathlib
    import re
    src = pathlib.Path("core/provenance.py").read_text()
    code = re.sub(r'"""(?:.|\n)*?"""', "", src)
    code = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("#")).lower()
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code)
    assert not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", code)
    for token in ("corp-ws01", "corp-srv02", "ws01", "jane.doe", "case-a"):
        assert token not in code


def test_a_tools_program_and_resources_are_never_inputs(case, tmp_path):
    """The program a call runs, the assembly or jar a runtime is handed and
    a tool's own symbol or cache directory sit outside the case; they never
    make a call that read evidence the run's own. An outside file that is
    the call's only input does."""
    root, log = case
    (root / "evidence" / "mem.raw").write_text("x")
    (root / "evidence" / "jane.doe.lnk").write_text("x")
    cache = tmp_path / "home" / "cache" / "volatility3"
    cache.mkdir(parents=True)
    vol = _entry(log, f"/opt/atlas/.venv/bin/vol -s {cache} -f {root / 'evidence' / 'mem.raw'} windows.netscan")
    assert P.call_provenance(vol, root)["class"] == "evidence"
    lecmd = _entry(log, f"dotnet /opt/tools/LECmd/LECmd.dll -f {root / 'evidence' / 'jane.doe.lnk'} --json /tmp")
    assert P.call_provenance(lecmd, root)["class"] == "evidence"
    jar = _entry(log, f"timeout 300 java -jar /opt/tools/parser.jar {root / 'evidence' / 'mem.raw'}")
    assert P.call_provenance(jar, root)["class"] == "evidence"
    notes = _entry(log, "cat /tmp/notes.txt")
    assert P.call_provenance(notes, root)["class"] == "own"


def test_an_outside_file_keeps_a_scripted_call_own(case):
    root, log = case
    (root / "evidence" / "mem.raw").write_text("x")
    e = _entry(log, f"python3 /tmp/parse.py {root / 'evidence' / 'mem.raw'}")
    assert P.call_provenance(e, root)["class"] == "own"


def test_an_installed_module_run_by_its_interpreter_is_a_tool(case, tmp_path):
    root, log = case
    (root / "evidence" / "mem.raw").write_text("x")
    cache = tmp_path / "home" / "cache"
    cache.mkdir(parents=True)
    e = _entry(log, f"python3 -m volatility3 --cache-path {cache} -f {root / 'evidence' / 'mem.raw'} windows.pslist")
    assert P.call_provenance(e, root)["class"] == "evidence"


def test_resource_options_belong_to_volatility_only(case, tmp_path):
    """-s, -p and --cache-path name a resource directory for Volatility;
    for ls, du or unzip they are other options and the path stays an input."""
    root, log = case
    (root / "evidence" / "ws01").mkdir(parents=True)
    (root / "evidence" / "a.zip").write_text("x")
    for cmd in (f"ls -s {root / 'evidence' / 'ws01'}", f"du -s {root / 'evidence'}",
                f"unzip -p {root / 'evidence' / 'a.zip'} notes.txt"):
        assert P.call_provenance(_entry(log, cmd), root)["class"] == "evidence", cmd
    cache = tmp_path / "cache"
    cache.mkdir()
    (root / "evidence" / "mem.raw").write_text("x")
    py = _entry(log, f"python3 /opt/vol/vol.py -s {cache} -f {root / 'evidence' / 'mem.raw'} windows.pslist")
    assert P.call_provenance(py, root)["class"] == "own"      # a script run stays scripted


def test_an_installed_tool_script_is_a_fixed_tool_and_a_new_script_is_own(case, tmp_path):
    """An interpreter running a script installed before the run (outside the
    case, older than the trace's first entry) runs a tool; a script written
    during the run, and -c, stay scripted."""
    root, log = case
    (root / "evidence" / "doc.bin").write_text("x")
    tool = tmp_path / "opt" / "tool.py"
    tool.parent.mkdir()
    tool.write_text("print(1)")
    log.record_tool_call("<py>:misc_start_execution_log", True, False, 0, 0)
    log._entries[0]["ts"] = "2099-01-01T00:00:00+00:00"      # the run began after the tool was installed
    P.reset_cache()
    installed = _entry(log, f"python3 {tool} {root / 'evidence' / 'doc.bin'}")
    assert not P.is_scripted(installed, root)
    assert P.call_provenance(installed, root)["class"] == "evidence"
    log._entries[0]["ts"] = "2001-01-01T00:00:00+00:00"      # the script is newer than the run's start
    P.reset_cache()
    new = _entry(log, f"python3 {tool} {root / 'evidence' / 'doc.bin'}")
    assert P.is_scripted(new, root) and P.call_provenance(new, root)["class"] == "own"
    inline = _entry(log, f"python3 -c 'print(1)' {root / 'evidence' / 'doc.bin'}")
    assert P.is_scripted(inline, root)


# ── the contents index decides extracted copies and their folders ────────

_ENTRY_IDS = iter(range(1000, 100000))


def _copy(root, rel, host, call_id=7, data="x"):
    """An extracted copy the contents index registered: an entry of an
    invented image and the copy row tying the file to it."""
    from core import contents_index as ci
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data)
    eid = next(_ENTRY_IDS)
    con = ci._connect(root, create=True)
    con.execute("INSERT INTO entries (id, host, image, volume, path, name, deleted, is_dir, origin) "
                "VALUES (?,?,?,?,?,?,0,0,'image')", (eid, host, f"evidence/{host.lower()}.raw", 0,
                                                    "C/Windows/" + p.name, p.name))
    con.commit()
    con.close()
    ci.record_copy(root, str(p), eid, call_id, p.stat().st_size)
    return p


def _in_run(root, log, path):
    """``path`` written during the run: after the run's first call."""
    if not log._entries:
        _entry(log, "fls -o 63 evidence/ws01.E01")
    later = time.time() + 600
    os.utime(path, (later, later))


def _ledger(root, files):
    (root / ".atlas" / "output_provenance.json").write_text(json.dumps({"files": files}))
    P.reset_cache()


LOGS = "analysis/extracted/corp-ws01/Logs"


def _evtxecmd(log, folder, out="analysis/evtx"):
    e = _entry(log, f"dotnet /opt/tools/EvtxECmd.dll -d {folder} --csv {out}")
    log.annotate_tool_call(e["call_id"], mcp_tool="ez_ez_evtxecmd")
    return log.index().by_call_id[e["call_id"]]


def test_a_registered_copy_is_derived_with_its_host_whatever_an_old_record_says(case):
    root, log = case
    copy = _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, copy)
    job = _entry(log, "[background job] image_extract_runner.py manifest.json")
    _ledger(root, {f"{LOGS}/Security.evtx": {"call": job["call_id"], "class": "own"}})
    read = _entry(log, f"<py>:evtx_read {LOGS}/Security.evtx")
    prov = P.call_provenance(read, root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}


def test_without_copy_provenance_the_mtime_rule_stands(case, monkeypatch):
    root, log = case
    copy = _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, copy)
    monkeypatch.setenv("ATLAS_COPY_PROVENANCE", "0")
    read = _entry(log, f"<py>:evtx_read {LOGS}/Security.evtx")
    assert P.call_provenance(read, root)["class"] == "own"


def test_a_folder_of_copies_is_derived_beside_a_leftover_of_another_kind(case):
    root, log = case
    for name in ("Security.evtx", "System.evtx"):
        _copy(root, f"{LOGS}/{name}", "CORP-WS01")
    part = root / LOGS / "Security.evtx.part"
    part.write_text("partial")
    _in_run(root, log, root / LOGS)
    job = _entry(log, "[background job] image_extract_runner.py manifest.json")
    _ledger(root, {f"{LOGS}/Security.evtx.part": {"call": job["call_id"], "class": "own"}})
    parser = _evtxecmd(log, LOGS)
    prov = P.call_provenance(parser, root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}
    # Its table is derived and carries the host to every read of it.
    before = P.output_snapshot(root)
    (root / "analysis" / "evtx").mkdir()
    (root / "analysis" / "evtx" / "ws01.csv").write_text("TimeCreated,User\n2031-03-04 10:16:00,jane.doe\n")
    P.record_outputs(root, parser, before, P.output_snapshot(root))
    assert P.load_ledger(root)["analysis/evtx/ws01.csv"]["class"] == "derived"
    read = _entry(log, "<py>:table_table_query", args={"path": "analysis/evtx/ws01.csv", "where": ["User=x"]})
    prov = P.call_provenance(read, root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}


def test_a_same_kind_file_of_the_runs_own_in_the_folder_makes_it_own(case):
    root, log = case
    _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    planted = root / LOGS / "notes.evtx"
    planted.write_text("the analyst's words")
    _in_run(root, log, root / LOGS)
    prog = _entry(log, "python3 -c 'open(\"x\",\"w\")'")
    _ledger(root, {f"{LOGS}/notes.evtx": {"call": prog["call_id"], "class": "own"}})
    assert P.call_provenance(_evtxecmd(log, LOGS), root)["class"] == "own"
    # A tool the input-kind registry does not know reads every file: own.
    P.reset_cache()
    other = _entry(log, f"sometool --dir {LOGS}")
    assert P.call_provenance(other, root)["class"] == "own"


def test_a_folder_without_copies_keeps_the_mtime_rule(case):
    root, log = case
    folder = root / "analysis" / "made"
    folder.mkdir()
    (folder / "a.evtx").write_text("x")
    _in_run(root, log, folder)
    assert P.call_provenance(_evtxecmd(log, "analysis/made"), root)["class"] == "own"


def test_a_folder_spanning_two_hosts_keeps_both(case):
    root, log = case
    _copy(root, "analysis/extracted/both/a/Security.evtx", "CORP-WS01")
    _copy(root, "analysis/extracted/both/b/Security.evtx", "CORP-SRV02")
    _in_run(root, log, root / "analysis" / "extracted" / "both")
    prov = P.call_provenance(_evtxecmd(log, "analysis/extracted/both"), root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01", "CORP-SRV02"}
    # The host set reaches every read of the parser's table, so a finding
    # naming both hosts is still shown by it (host affinity reads this set).
    parser = log.index().by_call_id[max(log.index().by_call_id)]
    before = P.output_snapshot(root)
    (root / "analysis" / "evtx").mkdir()
    (root / "analysis" / "evtx" / "both.csv").write_text("x")
    P.record_outputs(root, parser, before, P.output_snapshot(root))
    read = _entry(log, "<py>:table_table_grep", args={"path": "analysis/evtx/both.csv", "pattern": "x"})
    assert P.call_provenance(read, root)["hosts"] == {"CORP-WS01", "CORP-SRV02"}


def test_a_path_naming_no_content_is_no_input_beside_a_derived_one(case):
    root, log = case
    store = _copy(root, "analysis/extracted/corp-ws01/Outlook/mail.ost", "CORP-WS01")
    target = root / "analysis" / "mail"
    target.mkdir()                                            # an empty folder made in the run
    _in_run(root, log, target)
    export = _entry(log, f"pffexport -m items -t {target} {store}")
    prov = P.call_provenance(export, root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}
    P.reset_cache()
    target.rmdir()                                            # or absent altogether
    assert P.call_provenance(export, root)["class"] == "derived"
    # Nothing derived behind it: a missing path stays own (fail closed).
    (root / "evidence" / "ws01.E01").write_text("img")
    assert P.call_provenance(_entry(log, "strings evidence/ws01.E01 analysis/nothere.txt"), root)["class"] == "own"
    assert P.call_provenance(_entry(log, "cat analysis/nothere.txt"), root)["class"] == "own"
    assert P.call_provenance(_entry(log, f"cat {root / 'nothere.csv'}"), root)["class"] == "own"
    # A parser told a file name it writes elsewhere (an output name given as
    # a path at the case root that never comes to exist) still read the copies.
    _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, root / LOGS)
    parser = _entry(log, f"dotnet /opt/tools/EvtxECmd.dll -d {LOGS} --csv analysis/evtx --csvf {root / 'ws01.csv'}")
    log.annotate_tool_call(parser["call_id"], mcp_tool="ez_ez_evtxecmd")
    assert P.call_provenance(log.index().by_call_id[parser["call_id"]], root)["class"] == "derived"


def test_a_stale_own_record_is_re_derived_from_its_producer(case):
    """A resumed run's ledger holds records written before the classing
    knew the copies: the record follows its producer's class now, unless
    the file changed after the producer, or a script wrote it."""
    root, log = case
    _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, root / LOGS)
    (root / "analysis" / "evtx").mkdir()
    table = root / "analysis" / "evtx" / "ws01.csv"
    table.write_text("x")
    os.utime(table, (time.time() - 5, time.time() - 5))
    parser = _evtxecmd(log, LOGS)
    _ledger(root, {"analysis/evtx/ws01.csv": {"call": parser["call_id"], "class": "own"}})
    read = _entry(log, "<py>:table_table_grep", args={"path": "analysis/evtx/ws01.csv", "pattern": "x"})
    prov = P.call_provenance(read, root)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}
    # Changed after its producer: the record stands.
    later = time.time() + 600
    os.utime(table, (later, later))
    P.reset_cache()
    assert P.call_provenance(read, root)["class"] == "own"
    # A scripted producer re-derives own.
    os.utime(table, (time.time() - 5, time.time() - 5))
    script = _entry(log, f"python3 parse.py {LOGS}")
    _ledger(root, {"analysis/evtx/ws01.csv": {"call": script["call_id"], "class": "own"}})
    assert P.call_provenance(read, root)["class"] == "own"


def test_a_parser_table_over_registered_copies_is_a_located_sighting(case, monkeypatch):
    """The read of a parser's table over a folder of copies shows a value
    with the copies' host (core.indicators.validate). Without the copy
    records the folder, made in the run, is own and shows nothing."""
    from core import indicators as I
    root, log = case
    monkeypatch.setattr("core.evidence_index.db_path", lambda: str(root / "analysis" / "evidence_index.db"))
    _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, root / LOGS)
    parser = _evtxecmd(log, LOGS)
    before = P.output_snapshot(root)
    (root / "analysis" / "evtx").mkdir()
    (root / "analysis" / "evtx" / "ws01.csv").write_text("TimeCreated,User\n2031-03-04 10:16:00,jane.doe\n")
    P.record_outputs(root, parser, before, P.output_snapshot(root))
    cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt=json.dumps(
        {"path": "analysis/evtx/ws01.csv", "rows": [["2031-03-04 10:16:00", "jane.doe"]]}))
    log.annotate_tool_call(cid, args=json.dumps({"path": "analysis/evtx/ws01.csv", "pattern": "4624"}))
    rows = [{"type": "account", "value": "jane.doe", "side": "attacker"}]
    s = I.validate(rows, call_ids=[cid], case_dir=str(root))["kept"][0]["sightings"][0]
    assert s["call"] == cid and s["located"] is True and s["host"] == "CORP-WS01"
    monkeypatch.setenv("ATLAS_COPY_PROVENANCE", "0")
    (root / ".atlas" / "output_provenance.json").unlink()
    P.reset_cache()
    assert I.validate(rows, call_ids=[cid], case_dir=str(root))["kept"] == []


def test_the_unchanged_window_is_two_seconds_after_the_producers_entry(case):
    """The producer's entry time is truncated to the second: a file its
    producer wrote may carry an mtime up to a second later and is as the
    producer left it; one changed three seconds later is not."""
    root, log = case
    _copy(root, f"{LOGS}/Security.evtx", "CORP-WS01")
    _in_run(root, log, root / LOGS)
    (root / "analysis" / "evtx").mkdir()
    table = root / "analysis" / "evtx" / "ws01.csv"
    table.write_text("x")
    parser = _evtxecmd(log, LOGS)
    _ledger(root, {"analysis/evtx/ws01.csv": {"call": parser["call_id"], "class": "own"}})
    read = _entry(log, "<py>:table_table_grep", args={"path": "analysis/evtx/ws01.csv", "pattern": "x"})
    end = P._entry_end(parser)
    for offset, want in ((1, "derived"), (3, "own")):
        os.utime(table, (end + offset, end + offset))
        P.reset_cache()
        assert P.call_provenance(read, root)["class"] == want, offset


def _carve(root, log, files):
    """A carver run over an evidence image during the run: its files in the
    attribution ledger as derived, the folder written after the first call."""
    (root / "evidence" / "usb01.dd").write_bytes(b"\0" * 512)
    carver = _entry(log, "foremost -i evidence/usb01.dd -o analysis/carved", ref="evidence/usb01.dd")
    records = {}
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\xff\xd8\xff" + rel.encode())
        records[rel] = {"call": carver["call_id"], "class": "derived"}
    _ledger(root, records)
    _in_run(root, log, root / "analysis" / "carved")
    return carver


CARVED = ["analysis/carved/jpg/00000101.jpg", "analysis/carved/jpg/00000202.jpg", "analysis/carved/ole/00000303.ole"]


def test_an_extractors_output_folder_is_derived_like_its_files(case):
    root, log = case
    _carve(root, log, CARVED)
    listing = _entry(log, "<py>:misc_list_evidence_dir", args={"path": "analysis/carved/ole"})
    hashing = _entry(log, "<py>:hash_hash_directory", args={"directory": "analysis/carved"})
    assert P.call_provenance(listing, root)["class"] == "derived"
    assert P.call_provenance(hashing, root)["class"] == "derived"


def test_an_unrecorded_file_below_an_extractors_folder_makes_it_own(case):
    """A file the run wrote there by a shell redirect has no record: the
    folder is own, also when the file sits in a nested folder and appears
    after the folder was classed once."""
    root, log = case
    _carve(root, log, CARVED)
    first = _entry(log, "<py>:hash_hash_directory", args={"directory": "analysis/carved"})
    assert P.call_provenance(first, root)["class"] == "derived"
    (root / "analysis" / "carved" / "jpg" / "notes.txt").write_text("the analyst's words")
    P._CACHE.clear()
    again = _entry(log, "<py>:hash_hash_directory", args={"directory": "analysis/carved"})
    assert P.call_provenance(again, root)["class"] == "own"


def test_an_unrecorded_file_of_another_kind_leaves_a_parsers_folder_derived(case):
    """A parser takes only its own kind: a stray file of another kind under
    the folder is not what it reads."""
    root, log = case
    carver = _carve(root, log, ["analysis/carved/evtx/Security.evtx"])
    (root / "analysis" / "carved" / "evtx" / "readme.txt").write_text("x")
    assert carver
    assert P.call_provenance(_evtxecmd(log, "analysis/carved/evtx"), root)["class"] == "derived"
    P.reset_cache()
    (root / "analysis" / "carved" / "evtx" / "planted.evtx").write_text("x")
    assert P.call_provenance(_evtxecmd(log, "analysis/carved/evtx"), root)["class"] == "own"


def test_a_record_rewritten_in_place_makes_the_folder_own(case):
    """A recorded tool rewriting a carved file in place changes no
    directory's mtime: the ledger's own change reclassifies the folder."""
    root, log = case
    _carve(root, log, CARVED)
    first = _entry(log, "<py>:hash_hash_directory", args={"directory": "analysis/carved"})
    assert P.call_provenance(first, root)["class"] == "derived"
    jpg = root / "analysis" / "carved" / "jpg"
    stamp = os.stat(jpg).st_mtime_ns
    before = P.output_snapshot(root)
    (root / CARVED[0]).write_bytes(b"\xff\xd8\xff rewritten by a second program")
    writer = _entry(log, "<py>:steg_extract", args={"path": CARVED[0], "output_path": CARVED[0]})
    P.record_outputs(root, writer, before, P.output_snapshot(root))
    assert os.stat(jpg).st_mtime_ns == stamp
    assert P.load_ledger(root)[CARVED[0]].get("rewritten_by") == writer["call_id"]
    again = _entry(log, "<py>:hash_hash_directory", args={"directory": "analysis/carved"})
    assert P.call_provenance(again, root)["class"] == "own"
