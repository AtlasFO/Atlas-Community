"""A read of a whole disk image by a reader whose input is one file in the
image's filesystem, by a name the reader's registration declares
(meta "input_names"): the read names that file when the image's listing
holds it under one path, and is not made when the complete listing of every
volume holds no file of that name (core.question_plan.image_input, through
check_reads for the plan, the director's work items and the frontier, and
through the director's free-text entries). A read stands as named when the
tool declares nothing, when the listing is not complete, or when it did not
read the partition table. Invented fixtures only (CORP-WS01, jane.doe)."""
from __future__ import annotations

import inspect
import json

import pytest

from core import contents_index as ci
from core import question_plan as Q
from core import work_order as W
from core.execution_log import ExecutionLog

USB = "evidence/usb-a.dd"
DISK = "evidence/corp-ws01.raw"
FAT = ["notes1.txt", "notes2.txt", "$MBR", "$FAT1", "$FAT2", "$OrphanFiles"]
RECENT = "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent"
PROFILE = "Users/jane.doe/AppData"
NTFS = ["$MFT", "$Extend/$UsnJrnl:$J", "$Extend/$UsnJrnl:$Max", "Windows/Prefetch/CMD.EXE-0BD30981.pf",
        f"{RECENT}/a.lnk", f"{RECENT}/b.lnk",
        f"{RECENT}/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms",
        f"{RECENT}/CustomDestinations/28c8b86deab549a1.customDestinations-ms",
        # One file per declared input name of the readers (the pinned test
        # below), in the places the platform keeps them.
        "Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE", "Windows/System32/config/SAM",
        "Windows/System32/config/SECURITY", "Users/jane.doe/NTUSER.DAT",
        f"{PROFILE}/Local/Microsoft/Windows/UsrClass.dat", "Windows/AppCompat/Programs/Amcache.hve",
        "Windows/AppCompat/Programs/RecentFileCache.bcf", "Windows/System32/sru/SRUDB.dat",
        "$Recycle.Bin/S-1-5-21-1/$IAB12CD.docx", "$Recycle.Bin/S-1-5-21-1/$IAB12CE",
        f"{PROFILE}/Local/ConnectedDevicesPlatform/L.jane.doe/ActivitiesCache.db",
        f"{PROFILE}/Roaming/Mozilla/Firefox/Profiles/a1b2.default/places.sqlite",
        f"{PROFILE}/Roaming/Mozilla/Firefox/Profiles/a1b2.default/storage.sqlite3",
        f"{PROFILE}/Local/Google/Chrome/User Data/Default/History",
        f"{PROFILE}/Local/Google/Chrome/User Data/Default/Cookies",
        f"{PROFILE}/Local/Google/Chrome/User Data/Default/Login Data",
        f"{PROFILE}/Local/Google/Chrome/User Data/Default/Web Data",
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        f"{PROFILE}/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
        "Windows/INF/setupapi.dev.log", "Windows/setupapi.log", "Windows/System32/config/AppEvent.Evt",
        "Users/jane.doe/Documents/Outlook/mail.pst", f"{PROFILE}/Local/Microsoft/Outlook/mail.ost",
        "Users/jane.doe/Desktop/capture.pcap", "Users/jane.doe/Desktop/capture.pcapng",
        "Users/jane.doe/Desktop/capture.cap"]
TOOLS = {"ez.mftecmd", "ez.mftecmd_usn", "ez.lecmd", "ez.pecmd", "ez.sbecmd", "ez.sqlecmd", "strings.strings_grep",
         "tsk.tsk_istat", "tsk.indxparse"}


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    (root / "CASE.md").write_text("# Case: CASE-A\n", encoding="utf-8")
    for rel in (USB, DISK):
        (root / rel).write_bytes(b"\0")
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    return root


def _index(root, image, paths, *, volumes=(0,), complete=1, volumes_all=1, deleted=(), meta=True):
    con = ci._connect(root, create=True)
    rows = [{"path": p, "name": p.rsplit("/", 1)[-1], "size": 10, "volume": v, "deleted": int(p in deleted)}
            for v in volumes for p in paths]
    ci._insert_entries(con, "", image, rows, "image")
    if meta:
        ci._meta_set(con, f"image:{image}", {"listed": 1, "complete": complete, "volumes": list(volumes),
                                             "volumes_all": volumes_all, "entries": len(rows)})
    con.commit()
    con.close()


def _read(root, tool, image, **kw):
    return Q.check_reads(str(root), {"host": "", "source": image, "tool": tool, **kw}, TOOLS)


@pytest.mark.parametrize("tool, names", [("ez.mftecmd", "$MFT"), ("ez.mftecmd_usn", "$UsnJrnl:$J"),
                                         ("ez.lecmd", "*.lnk"), ("ez.sbecmd", "UsrClass.dat"),
                                         ("ez.sqlecmd", "*.sqlite, *.sqlite3, History, Cookies, Login Data, Web Data")])
def test_a_reader_whose_input_the_complete_listing_lacks_is_no_read(case, tool, names):
    _index(case, USB, FAT)
    reads, why = _read(case, tool, USB)
    assert reads == []
    which = "that name" if "," not in names else "these names"
    assert why == f"it reads {names}; no file of {which} is listed in the complete listing of {USB}"


@pytest.mark.parametrize("tool, kw", [("strings.strings_grep", {"pattern": "vpn"}), ("tsk.tsk_istat", {}),
                                      ("tsk.indxparse", {})])
def test_a_reader_of_the_image_itself_or_with_no_declaration_stands(case, tool, kw):
    _index(case, USB, FAT)
    reads, why = _read(case, tool, USB, **kw)
    assert why == "" and reads[0]["target"]["path"] == USB and not reads[0]["target"].get("inner_path")


@pytest.mark.parametrize("tool, inner", [("ez.mftecmd", "$MFT"), ("ez.mftecmd_usn", "$Extend/$UsnJrnl:$J"),
                                         ("ez.pecmd", "Windows/Prefetch/CMD.EXE-0BD30981.pf")])
def test_a_reader_of_one_file_the_listing_holds_reads_that_file(case, tool, inner):
    """One live file of that name on one volume: the read names it (a
    whole-image read of a format file names no file a call can be given)."""
    _index(case, DISK, NTFS, volumes=(2048,))
    reads, why = _read(case, tool, DISK)
    assert why == "" and [(r["target"]["path"], r["target"]["inner_path"]) for r in reads] == [(DISK, inner)]


def test_the_same_file_on_two_volumes_leaves_the_read_as_named(case):
    """$MFT on each of two volumes: a bare inner path would read one and
    close the item over the other, so the read stands, never refused."""
    _index(case, DISK, NTFS, volumes=(2048, 206848))
    reads, why = _read(case, "ez.mftecmd", DISK)
    assert why == "" and reads[0]["target"]["path"] == DISK and not reads[0]["target"].get("inner_path")


def test_a_reader_of_a_family_of_files_stands_as_named(case):
    _index(case, DISK, NTFS)
    reads, why = _read(case, "ez.lecmd", DISK)
    assert why == "" and not reads[0]["target"].get("inner_path")


def test_a_deleted_file_of_the_name_keeps_the_read(case):
    _index(case, USB, FAT + ["old/a.lnk"], deleted=("old/a.lnk",))
    reads, why = _read(case, "ez.lecmd", USB)
    assert why == "" and not reads[0]["target"].get("inner_path")


@pytest.mark.parametrize("kw", [{"complete": 0}, {"volumes_all": 0}, {"meta": False}])
def test_a_listing_that_cannot_show_absence_leaves_the_read_as_named(case, kw):
    """Not complete, or listed at a remembered offset alone (another volume
    may be unlisted), or an index written before the rule: as named."""
    _index(case, USB, FAT, **kw)
    reads, why = _read(case, "ez.mftecmd", USB)
    assert why == "" and reads[0]["target"]["path"] == USB


def test_no_index_cannot_show_absence(tmp_path):
    assert ci.input_entries(tmp_path, USB, ["$MFT"]) is None


def test_case_insensitive_and_ads_names_match(case):
    _index(case, DISK, ["$mft", "$Extend/$UsnJrnl:$J"])
    assert [p for _v, p, _d in ci.input_entries(case, DISK, ["$MFT"])] == ["$mft"]
    assert [p for _v, p, _d in ci.input_entries(case, DISK, ["$UsnJrnl:$J"])] == ["$Extend/$UsnJrnl:$J"]
    assert ci.input_entries(case, DISK, ["$UsnJrnl"]) == []


def test_a_director_entry_naming_the_whole_image_follows_the_same_rule(case):
    _index(case, USB, FAT)
    _index(case, DISK, NTFS)
    refused: list[str] = []
    data = {"directives": {"priority_tools": [f"ez.mftecmd {USB}", f"ez.mftecmd {DISK}"]}}
    out = W.parse_director_entries(data, str(case), refused)
    assert [(o["target"]["path"], o["target"]["inner_path"]) for o in out] == [(DISK, "$MFT")]
    assert refused == [f"ez.mftecmd: it reads $MFT; no file of that name is listed in the complete listing of {USB}"]


def test_the_directors_structured_work_item_is_refused_with_the_reason(case, monkeypatch):
    _index(case, USB, FAT)
    from tools import dair
    monkeypatch.setattr(dair, "_case_root", lambda: case)
    monkeypatch.setattr(Q, "reading_tools", lambda: [(t, "") for t in TOOLS])
    assessment, raw = {"work_items": [{"tool": "ez.mftecmd", "host": "", "source": USB}]}, {}
    dair._apply_director_review(assessment, raw)
    from core.execution_log import log
    assert [i for i in log.work_items() if i["tool"]] == []
    assert raw["work_items_refused"] == [
        f"ez.mftecmd  {USB} (it reads $MFT; no file of that name is listed in the complete listing of {USB})"]


def test_every_declared_input_name_matches_a_file_of_its_format():
    """A declaration that names no file of its format would refuse every
    read of that reader, and a name no file carries resolves nothing in
    the class route: every declared name matches a file of an NTFS-like
    listing (one fixture file per name)."""
    from tools.tool_capabilities import registered_tool_schemas
    declared = {e[0]: (e[3] or {}).get("input_names") for e in registered_tool_schemas()
                if len(e) > 3 and isinstance(e[3], dict) and e[3].get("input_names")}
    assert declared, "no reader declares input_names"
    import fnmatch
    for tool, names in declared.items():
        for n in names:
            assert any(fnmatch.fnmatch(p.rsplit("/", 1)[-1].casefold(), n.casefold()) for p in NTFS), (tool, n)


def test_the_rule_holds_no_file_name_of_its_own():
    """The names are the readers' declarations; the rule's code names none."""
    src = "".join(inspect.getsource(f) for f in (Q.image_input, ci.input_entries, W._whole_image_input))
    for token in ("$MFT", "$J", ".lnk", ".pf", "Prefetch", "NTFS", "FAT"):
        assert token not in src, token


def test_the_remembered_offset_alone_is_not_every_volume(tmp_path, monkeypatch):
    monkeypatch.setattr("core.mount_plan.volume_offset", lambda root, image: 2048)
    assert ci._volume_offsets(tmp_path, "x.raw", "x.raw", 5) == ([2048], "", False)
    monkeypatch.setattr("core.mount_plan.volume_offset", lambda root, image: None)
    monkeypatch.setattr(ci, "_run", lambda cmd, timeout: {"success": False, "exit_code": 1, "stdout": ""})
    assert ci._volume_offsets(tmp_path, "x.raw", "x.raw", 5) == ([0], "mmls found no partition table", True)


@pytest.mark.parametrize("res", [{"success": False, "exit_code": -1, "timed_out": True, "stdout": ""},
                                 {"success": False, "exit_code": 1, "stdout": "", "stderr": "Error reading image"},
                                 {"success": False, "exit_code": 2, "stdout": ""}])
def test_an_mmls_failure_other_than_no_partition_table_is_not_every_volume(tmp_path, monkeypatch, res):
    monkeypatch.setattr("core.mount_plan.volume_offset", lambda root, image: None)
    monkeypatch.setattr(ci, "_run", lambda cmd, timeout: res)
    assert ci._volume_offsets(tmp_path, "x.raw", "x.raw", 5)[2] is False


def test_the_directors_refused_lines_keep_their_reasons(tmp_path):
    from agent.loop import Agent as A
    refused = [f"ez.mftecmd: it reads $MFT; no file of that name is listed in the complete listing of {USB}",
               f"tsk.mactime: {W.NOT_TRACKED}", f"vol.pslist: {W.NOT_TRACKED}"]
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    cid = log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    import types
    from unittest.mock import patch
    agent = types.SimpleNamespace(case_dir=str(tmp_path), _log=lambda e: None)
    with patch("core.execution_log.log", log), patch("core.deferred_intents.work_order_on", lambda: True), \
            patch("core.work_order.parse_director_entries", lambda data, case, out: out.extend(refused) or []):
        A._director_items(agent, {"_atlas_call_id": cid})
    entry = next(e for e in log._entries if e.get("call_id") == cid)
    assert entry["directives"]["work_items_refused"] == [
        f"ez.mftecmd: it reads $MFT; no file of that name is listed in the complete listing of {USB}",
        f"tsk.mactime, vol.pslist: {W.NOT_TRACKED}"]


def test_the_directors_refused_lines_are_bounded(tmp_path):
    """Eight reasons are shown, the rest counted on one line: the next
    review stays short however many entries were refused."""
    from agent.loop import Agent as A
    refused = [f"ez.lecmd: 'Users/u{n}/a.lnk' is not in the complete listing of {USB}" for n in range(12)]
    log = ExecutionLog()
    log.configure("CASE-A", str(tmp_path / "trace.json"), save_session=False)
    cid = log.record_dair_call("Analyze", "", False, "", "", "stay", "")
    import types
    from unittest.mock import patch
    agent = types.SimpleNamespace(case_dir=str(tmp_path), _log=lambda e: None)
    with patch("core.execution_log.log", log), patch("core.deferred_intents.work_order_on", lambda: True), \
            patch("core.work_order.parse_director_entries", lambda data, case, out: out.extend(refused) or []):
        A._director_items(agent, {"_atlas_call_id": cid})
    lines = next(e for e in log._entries if e.get("call_id") == cid)["directives"]["work_items_refused"]
    assert len(lines) == 9 and lines[-1] == "and 4 more entries refused for 4 more reasons"


# ── a reader of another reader's output; a handle against the listing ───────

AF = TOOLS | {"af.af_timestomp_drift", "af.af_prefetch_deletion"}


def _plan(root):
    """The access plan names the disk image, as intake writes it."""
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / DISK), "media_role": "disk", "action": "plan_only",
         "image_type": "raw_or_container"}]}), encoding="utf-8")


def test_a_reader_of_another_readers_output_has_no_input_where_its_producer_has_none(case):
    """af_timestomp_drift reads ez_mftecmd's table: on an image whose
    complete listing holds no $MFT it has no input; where $MFT is listed it
    stands, its read never rewritten to the producer's input."""
    _index(case, USB, FAT)
    _index(case, DISK, NTFS)
    reads, why = Q.check_reads(str(case), {"host": "", "source": USB, "tool": "af.af_timestomp_drift"}, AF)
    assert reads == [] and why == (f"it reads the output of ez_mftecmd, whose input $MFT is not listed in the "
                                   f"complete listing of {USB}")
    reads, why = Q.check_reads(str(case), {"host": "", "source": DISK, "tool": "af.af_timestomp_drift"}, AF)
    assert why == "" and reads and not reads[0]["target"].get("inner_path")
    # a producer that declares no input leaves the reader as named
    reads, _why = Q.check_reads(str(case), {"host": "", "source": USB, "tool": "af.af_prefetch_deletion"}, AF)
    assert reads


@pytest.mark.parametrize("inner, stands", [
    ("Windows/Prefetch/CMD.EXE-0BD30981.pf", True),
    ("C/Windows/Prefetch/CMD.EXE-0BD30981.pf", True),        # a root folder the image lacks
    ("$Extend/$UsnJrnl:$J", True),                            # an alternate data stream
    ("Windows/Prefetch/GONE.EXE-11111111.pf", True),          # a deleted entry is still an entry
    ("Windows/System32/never.exe", False),
    ("network/pcap/<capture found by a listing>", False),     # a template, no path
    ("C:\\Windows\\Prefetch\\CMD.EXE-0BD30981.pf", True),     # the drive as a root folder, as the read takes it
])
def test_a_planned_handle_stands_where_a_read_of_it_would_run(case, inner, stands, monkeypatch):
    # The handle's existence is the question here, not the format routing
    # (a text grep over a journal whose parser is installed is refused).
    monkeypatch.setattr("tools.tool_capabilities.format_readers_on", lambda: False)
    _plan(case)
    _index(case, DISK, NTFS + ["Windows/Prefetch/GONE.EXE-11111111.pf"],
           deleted=("Windows/Prefetch/GONE.EXE-11111111.pf",))
    reads, why = Q.check_reads(str(case), {"host": "", "source": f"{DISK}::{inner}", "tool": "strings.strings_grep",
                                           "pattern": "jane"}, TOOLS)
    assert bool(reads) is stands, why
    assert ci.handle_missing(str(case), f"{DISK}::{inner}") is (not stands)


def test_a_handle_with_a_volume_and_one_the_image_roots_stand(case):
    _plan(case)
    _index(case, DISK, ["C/Users/jane.doe/notes.txt"], volumes=(0, 2048), volumes_all=2)
    assert not ci.handle_missing(str(case), f"{DISK}@2048::Users/jane.doe/notes.txt")
    assert ci.handle_missing(str(case), f"{DISK}@4096::Users/jane.doe/notes.txt")


def test_a_handle_stands_on_a_listing_that_is_not_complete(case):
    _plan(case)
    _index(case, DISK, NTFS, complete=0)
    reads, _why = Q.check_reads(str(case), {"host": "", "source": f"{DISK}::Windows/System32/never.exe",
                                            "tool": "strings.strings_grep", "pattern": "jane"}, TOOLS)
    assert reads
