"""The Coverage tab's cost: a recorded call's read set is resolved
once and kept while the image listings stand (a copy registered or an
export indexed later resolves only calls not yet seen), the icat lookup
is served by the index, a folder's registered copies are remembered per
index version, and the read rule's program table loads without the
server's middleware. Invented fixtures only (CORP-WS01, jane.doe)."""
from __future__ import annotations

import json
import sys

import core.execution_log as elog
from core import contents_index as ci
from core import evidence_identity as EI
from core.coverage_ledger import _read_attempts
from tests.core.test_contents_index import _build, _image, _links, _plan, case  # noqa: F401
from tests.core.test_evidence_leave import T_NEW, _b


def _case(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw")])
    _plan(case, [_image(case, "corp-ws01.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": [
        _b("Windows/System32/winevt/Logs/Security.evtx", "5-128-1", T_NEW, 70000),
        _b("Windows/System32/winevt/Logs/System.evtx", "5-128-2", T_NEW, 70000),
        _b("Windows/System32/config/SYSTEM", "50-128-1", T_NEW, 12_000_000),
        _b("Users/jane.doe/a.txt", "7-128-1", T_NEW)]})
    (case / "analysis" / "corp-ws01").mkdir(parents=True, exist_ok=True)
    return case


def _read(cmd: str, tool: str = "misc_evtx_filter", ok: bool = True) -> int:
    cid = elog.log.record_tool_call(cmd, ok, False, 0, 0 if ok else 1, stdout_excerpt="rows")
    elog.log.annotate_tool_call(cid, mcp_tool=tool)
    return cid


def _entries(case):
    from core.execution_log import trace_tool_calls
    return trace_tool_calls(case) or list(elog.log._entries)


# ── a call's read set is kept while the listings stand ──────────────────

def test_a_recorded_calls_read_set_survives_a_new_copy_and_only_new_calls_are_resolved(case, monkeypatch):
    _case(case, monkeypatch)
    img = "evidence/disk/corp-ws01.raw"
    con = ci._connect(case)
    eid = con.execute("SELECT id FROM entries WHERE name = 'Security.evtx'").fetchone()[0]
    con.close()
    (case / "analysis" / "corp-ws01" / "Security.evtx").write_bytes(b"ElfFile")
    ci.record_copy(case, "analysis/corp-ws01/Security.evtx", int(eid), None, 7)
    c1 = _read("<py>:misc_evtx_filter analysis/corp-ws01/Security.evtx event_ids=[4624]")
    c2 = _read(f"<py>:misc_evtx_filter {img}::Windows/System32/winevt/Logs/System.evtx")
    resolved: list = []
    real = EI._call_reads
    monkeypatch.setattr(EI, "_call_reads", lambda r, e, a, n=None: (resolved.append(e.get("call_id")),
                                                                     real(r, e, a, n))[1])
    EI._READS.clear()
    first = {e["call_id"]: v for e, v in _read_attempts(case, list(elog.log._entries))}
    assert sorted(resolved) == [c1, c2] and ("entry", int(eid)) in first[c1]["content"]
    # Another copy is registered and an export indexed (the generation's
    # counters move): the two calls are not resolved again, their sets stand.
    resolved.clear()
    eid2 = ci._connect(case).execute("SELECT id FROM entries WHERE name = 'SYSTEM'").fetchone()[0]
    (case / "analysis" / "corp-ws01" / "SYSTEM").write_bytes(b"regf")
    ci.record_copy(case, "analysis/corp-ws01/SYSTEM", int(eid2), None, 4)
    c3 = _read("<py>:ez_recmd_hive analysis/corp-ws01/SYSTEM", tool="ez_recmd_hive")
    again = {e["call_id"]: v for e, v in _read_attempts(case, list(elog.log._entries))}
    assert resolved == [c3]                                      # only the call not yet seen
    assert again[c1] == first[c1] and again[c2] == first[c2]
    assert ("entry", int(eid2)) in again[c3]["content"]
    # A new listing of an image (the listings key) resolves them again.
    with EI.Resolver(case) as r:
        before = r.listings
    con = ci._connect(case)
    ci._meta_set(con, f"image:{img}", {**ci._meta_get(con, f"image:{img}"), "listed": 2, "entries": 5})
    con.commit(); con.close()
    with EI.Resolver(case) as r:
        assert r.listings != before
    resolved.clear()
    _read_attempts(case, list(elog.log._entries))
    assert sorted(resolved) == [c1, c2, c3]


def test_a_changed_record_of_a_call_is_resolved_again(case, monkeypatch):
    _case(case, monkeypatch)
    img = "evidence/disk/corp-ws01.raw"
    c1 = _read(f"<py>:misc_evtx_filter {img}::Windows/System32/winevt/Logs/Security.evtx")
    resolved: list = []
    real = EI._call_reads
    monkeypatch.setattr(EI, "_call_reads", lambda r, e, a, n=None: (resolved.append(e.get("call_id")),
                                                                     real(r, e, a, n))[1])
    EI._READS.clear()
    _read_attempts(case, list(elog.log._entries))
    elog.log.annotate_tool_call(c1, evidence_ref=f"{img}::Windows/System32/winevt/Logs/Security.evtx")
    _read_attempts(case, list(elog.log._entries))
    assert resolved == [c1, c1]                                  # the record changed: resolved once more


def test_a_copy_registered_after_a_read_is_credited_to_that_read(case, monkeypatch):
    # A background job's copies are registered when the job is collected;
    # the model can read its output folder before that.
    _case(case, monkeypatch)
    job = case / "analysis" / "corp-ws01" / "job"
    job.mkdir()
    (job / "Security.evtx").write_bytes(b"ElfFile")
    c1 = _read("<py>:misc_evtx_filter analysis/corp-ws01/job/Security.evtx event_ids=[4624]")
    c2 = _read("<py>:misc_evtx_filter analysis/corp-ws01/job")
    c3 = _read("<py>:misc_evtx_filter analysis/corp-ws01/other.evtx")
    resolved: list = []
    real = EI._call_reads
    monkeypatch.setattr(EI, "_call_reads", lambda r, e, a, n=None: (resolved.append(e.get("call_id")),
                                                                     real(r, e, a, n))[1])
    EI.reset_cache()
    first = {e["call_id"]: v for e, v in _read_attempts(case, list(elog.log._entries))}
    eid = ci._connect(case).execute("SELECT id FROM entries WHERE name = 'Security.evtx'").fetchone()[0]
    assert ("entry", int(eid)) not in first[c1]["content"] | first[c2]["folder"]
    resolved.clear()
    ci.record_copy(case, "analysis/corp-ws01/job/Security.evtx", int(eid), None, 7)
    again = {e["call_id"]: v for e, v in _read_attempts(case, list(elog.log._entries))}   # no memo cleared
    assert sorted(resolved) == [c1, c2]                          # the path never registered is not resolved again
    assert ("entry", int(eid)) in again[c1]["content"]
    assert ("entry", int(eid)) in again[c2]["folder"]
    resolved.clear()
    _read_attempts(case, list(elog.log._entries))
    assert resolved == []                                        # the new sets are kept


def test_a_set_resolved_from_names_older_than_the_counted_copies_is_not_kept(case, monkeypatch):
    # A resolver keys its cached names by the generation it read at its
    # start; a copy registered after that start is counted but missing
    # from those names, so the set resolved from them is not kept.
    _case(case, monkeypatch)
    job = case / "analysis" / "corp-ws01" / "job"
    job.mkdir()
    con = ci._connect(case)
    ids = {str(n): int(i) for i, n in con.execute("SELECT id, name FROM entries WHERE name LIKE '%.evtx'")}
    con.close()
    for name in ids:
        (job / name).write_bytes(b"ElfFile")
    ci.record_copy(case, "analysis/corp-ws01/job/Security.evtx", ids["Security.evtx"], None, 7)
    cid = _read("<py>:misc_evtx_filter analysis/corp-ws01/job")
    entry = next(e for e in elog.log._entries if e.get("call_id") == cid)
    EI.reset_cache()
    with EI.Resolver(case) as r:
        r.name("analysis/corp-ws01/job", "misc_evtx_filter")
        ci.record_copy(case, "analysis/corp-ws01/job/System.evtx", ids["System.evtx"], None, 7)
        stale = EI.call_reads(case, entry, resolver=r)["folder"]
    assert ("entry", ids["System.evtx"]) not in stale            # the resolver's names predate the copy
    assert ("entry", ids["System.evtx"]) in EI.call_reads(case, entry)["folder"]


def test_a_fresh_start_does_not_reuse_the_previous_runs_read_set(case, monkeypatch):
    # A fresh start numbers its calls from one again: the same call id and
    # command in the next run read what that run's folder holds.
    _case(case, monkeypatch)
    notes = case / "analysis" / "corp-ws01" / "notes"
    notes.mkdir()
    (notes / "a.txt").write_text("x")
    EI.reset_cache()
    call = {"type": "tool_call", "call_id": 1, "cmd": "<py>:strings_read_text analysis/corp-ws01/notes",
            "mcp_tool": "strings_read_text", "ts": "2031-03-01T08:00:00+00:00"}
    assert EI.call_reads(case, call)["folder"] == {("file", "analysis/corp-ws01/notes/a.txt")}
    (notes / "a.txt").unlink()
    (notes / "b.txt").write_text("y")
    later = {**call, "ts": "2031-03-02T08:00:00+00:00"}
    assert EI.call_reads(case, later)["folder"] == {("file", "analysis/corp-ws01/notes/b.txt")}


# ── the icat lookup is served by the index and gives the same rows ────────

def test_an_icat_inode_lookup_matches_the_dashed_forms_and_not_a_longer_number(case, monkeypatch):
    _case(case, monkeypatch)
    img = "evidence/disk/corp-ws01.raw"
    con = ci._connect(case)
    want = {int(r[0]) for r in con.execute("SELECT id FROM entries WHERE image = ? AND inode LIKE '5-%'", (img,))}
    longer = {int(r[0]) for r in con.execute("SELECT id FROM entries WHERE image = ? AND inode LIKE '50-%'", (img,))}
    con.close()
    assert len(want) == 2 and len(longer) == 1
    with EI.Resolver(case) as r:
        bare = r.name(f"icat -o 0 {img} 5", "tsk_tsk_icat")
        dashed = r.name(f"icat -o 0 {img} 5-128-2", "tsk_tsk_icat")
        fifty = r.name(f"icat -o 0 {img} 50", "tsk_tsk_icat")
    assert {i for k, i in bare.ids if k == "entry"} == want
    assert {i for k, i in dashed.ids if k == "entry"} < want and len(dashed.ids) == 1
    assert {i for k, i in fifty.ids if k == "entry"} == longer


# ── a folder's copies are remembered per index version ───────────────────

def test_copies_under_is_read_once_per_index_version(case, monkeypatch):
    _case(case, monkeypatch)
    con = ci._connect(case)
    eid = con.execute("SELECT id FROM entries WHERE name = 'SYSTEM'").fetchone()[0]
    con.close()
    (case / "analysis" / "corp-ws01" / "SYSTEM").write_bytes(b"regf" + b"\0" * 60)
    ci.record_copy(case, "analysis/corp-ws01/SYSTEM", int(eid), None, 64)
    probes: list = []
    import core.input_kind as IK
    real = IK.reads_kind
    monkeypatch.setattr(IK, "reads_kind", lambda tool, path, kind="": (probes.append(path), real(tool, path, kind))[1])
    ci._COPIES_UNDER.clear()
    a = ci.copies_under(case, "analysis/corp-ws01", "ez_recmd_hive")
    b = ci.copies_under(case, "analysis/corp-ws01", "ez_recmd_hive")
    assert a == b and [o["copy_path"] for o in a] == ["analysis/corp-ws01/SYSTEM"] and len(probes) == 1
    a[0]["copy_path"] = "changed"                                 # the caller's copy, not the memo's
    assert ci.copies_under(case, "analysis/corp-ws01", "ez_recmd_hive")[0]["copy_path"] == "analysis/corp-ws01/SYSTEM"
    (case / "analysis" / "corp-ws01" / "a.txt").write_bytes(b"x")
    eid2 = ci._connect(case).execute("SELECT id FROM entries WHERE name = 'a.txt'").fetchone()[0]
    ci.record_copy(case, "analysis/corp-ws01/a.txt", int(eid2), None, 1)
    c = ci.copies_under(case, "analysis/corp-ws01", "ez_recmd_hive")
    assert len(probes) == 3 and [o["copy_path"] for o in c] == ["analysis/corp-ws01/SYSTEM"]   # read again; the text file is no hive


# ── the program table loads without the server's middleware ──────────────

def test_the_wrapper_hints_load_without_the_middleware():
    import importlib
    for name in ("core.wrapper_hints", "core.middleware"):
        sys.modules.pop(name, None)
    had = {m for m in sys.modules if m == "fastmcp" or m.startswith("fastmcp.")}
    wh = importlib.import_module("core.wrapper_hints")
    assert isinstance(wh.MCP_WRAPPER_HINTS, dict) and wh.MCP_WRAPPER_HINTS
    assert not ({m for m in sys.modules if m == "fastmcp" or m.startswith("fastmcp.")} - had)
    assert "core.middleware" not in sys.modules
    from core.coverage_ledger import _own_program_tools
    _own_program_tools.cache_clear()
    assert _own_program_tools() and "core.middleware" not in sys.modules
    import core.middleware as mw                                  # the server still finds the table under its old name
    assert mw.MCP_WRAPPER_HINTS is wh.MCP_WRAPPER_HINTS
