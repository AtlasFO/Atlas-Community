"""A read through a filesystem the access plan mounted from an image names
the image's entries (core.evidence_identity readables, core.provenance
.plan_mounts): the mounted volume's live entries, every volume's (listed
only) when the plan has no offset. Invented fixtures only (CORP-WS01,
jane.doe, 2031)."""
from __future__ import annotations

import json

import pytest

import core.execution_log as elog
from core import contents_index as ci
from core.evidence_identity import identify, reset_cache

IMG = "evidence/disk/corp-ws01.E01"
MNT = "mnt/corp-ws01"
MMLS = ("DOS Partition Table\nOffset Sector: 0\nUnits are in 512-byte sectors\n\n"
        "      Slot      Start        End          Length       Description\n"
        "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
        "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
        "002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\n"
        "003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)\n")


def _case(tmp_path, volume_offset, *, rows=None, readable=f"{MNT}/ewf/ewf1"):
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", f"{MNT}/fs", f"{MNT}/ewf"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / IMG).write_bytes(b"\0" * 512)
    mr = {"success": True, "mount_point": str(root / MNT / "fs"), "ewf_device": str(root / MNT / "ewf" / "ewf1")}
    if volume_offset is not None:
        mr["volume_offset_sectors"] = volume_offset
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / IMG), "media_role": "disk", "action": "auto_mount", "status": "mounted",
         "mount_result": mr}]}), encoding="utf-8")
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    con = ci._connect(root, create=True)
    rows = rows or [
        {"path": "$MFT", "name": "$MFT", "inode": "0-128-1", "volume": 2048},
        {"path": "$MFT", "name": "$MFT", "inode": "0-128-1", "volume": 206848},
        {"path": "Users/jane.doe/NTUSER.DAT", "name": "NTUSER.DAT", "inode": "40-128-1", "volume": 206848},
        {"path": "Documents and Settings/jane.doe/NTUSER.DAT", "name": "NTUSER.DAT", "inode": "41-128-1",
         "volume": 206848}]
    ci._insert_entries(con, "CORP-WS01", IMG, rows, "image")
    ci._meta_set(con, f"image:{IMG}", {"listed": 1, "complete": 1, "host": "CORP-WS01",
                                       "volumes": sorted({r["volume"] for r in rows}), "readable": readable})
    con.commit()
    con.close()
    reset_cache()
    return root


def _entries(ids):
    """The index entries among a token's identities (a mount path also
    names itself as a case path: the tests at the end)."""
    return {x for x in ids if x[0] == "entry"}


def _id(root, vol, path, deleted=0):
    with ci._connect(root) as con:
        return con.execute("SELECT id FROM entries WHERE volume = ? AND path = ? AND deleted = ?",
                           (vol, path, deleted)).fetchone()[0]


def test_a_read_through_the_mount_names_the_mounted_volumes_entry(tmp_path):
    root = _case(tmp_path, 206848)
    assert _entries(identify(root, f"{MNT}/fs/$MFT")) == {("entry", _id(root, 206848, "$MFT"))}
    assert _entries(identify(root, str(root / MNT / "fs" / "Users/jane.doe/NTUSER.DAT"))) == {
        ("entry", _id(root, 206848, "Users/jane.doe/NTUSER.DAT"))}
    # a path with a space, written whole
    assert _entries(identify(root, f"{MNT}/fs/Documents and Settings/jane.doe/NTUSER.DAT")) == {
        ("entry", _id(root, 206848, "Documents and Settings/jane.doe/NTUSER.DAT"))}


def test_without_the_offset_a_path_on_several_volumes_is_listed_only(tmp_path):
    from core.evidence_identity import call_reads
    root = _case(tmp_path, None)
    entry = {"type": "tool_call", "call_id": 7, "mcp_tool": "ez_mftecmd", "cmd": "<py>:ez_ez_mftecmd",
             "success": True, "args": json.dumps({"mft_path": f"{MNT}/fs/$MFT"})}
    reads = call_reads(root, entry)
    assert not {x for x in reads["content"] if x[0] == "entry"}
    assert {x for x in reads["listed"] if x[0] == "entry"} == {("entry", _id(root, 2048, "$MFT")),
                                                               ("entry", _id(root, 206848, "$MFT"))}
    # a path on one volume only names that entry even without the offset
    assert _entries(identify(root, f"{MNT}/fs/Users/jane.doe/NTUSER.DAT")) == {
        ("entry", _id(root, 206848, "Users/jane.doe/NTUSER.DAT"))}


def test_a_mount_shows_live_files_only(tmp_path):
    rows = [{"path": "Users/jane.doe/report.docx", "name": "report.docx", "inode": "50-128-1", "volume": 0},
            {"path": "Users/jane.doe/report.docx", "name": "report.docx", "inode": "51-128-1", "volume": 0,
             "deleted": 1},
            {"path": "Users/jane.doe/gone.docx", "name": "gone.docx", "inode": "52-128-1", "volume": 0,
             "deleted": 1}]
    root = _case(tmp_path, 0, rows=rows)
    assert _entries(identify(root, f"{MNT}/fs/Users/jane.doe/report.docx")) == {
        ("entry", _id(root, 0, "Users/jane.doe/report.docx"))}
    assert _entries(identify(root, f"{MNT}/fs/Users/jane.doe/gone.docx")) == set()
    # a handle keeps naming the deleted twin too
    assert len(_entries(identify(root, f"{IMG}::Users/jane.doe/report.docx"))) == 2


def test_the_readable_device_alone_keeps_its_rule(tmp_path):
    root = _case(tmp_path, 206848, readable="")
    assert _entries(identify(root, f"{MNT}/fs/$MFT")) == {("entry", _id(root, 206848, "$MFT"))}


def test_a_plan_built_again_over_a_surviving_mount_keeps_its_volume(tmp_path, monkeypatch):
    from core import mount_plan as MP
    root = tmp_path / "case"
    (root / MNT / "fs").mkdir(parents=True)
    MP._record_mounted_volume(str(root / MNT / "fs"), 206848)
    assert MP.mounted_volume(str(root / MNT / "fs")) == 206848
    assert MP.mounted_volume(str(tmp_path / "elsewhere" / "fs")) is None
    # a mount that proved no volume removes the earlier record
    MP._record_mounted_volume(str(root / MNT / "fs"), None)
    assert MP.mounted_volume(str(root / MNT / "fs")) is None


def test_the_mount_and_the_index_number_a_volume_alike(monkeypatch):
    """The auto-mount's chosen volume (mmls start, sectors) is the index's
    volume number for it, also for a volume at sector 0."""
    from tools import ewf
    from core import contents_index
    mmls = MMLS
    start, _len, _size, fs = ewf._largest_mountable_volume(mmls, "/nonexistent/ewf1")
    monkeypatch.setattr(contents_index, "_run", lambda cmd, timeout: {"success": True, "stdout": mmls})
    monkeypatch.setattr("core.mount_plan.volume_offset", lambda root, image: None)
    offsets, _note, _all = contents_index._volume_offsets(None, "x", "/nonexistent/ewf1", 10)
    assert fs == "ntfs" and start == 206848 and start in offsets and 2048 in offsets
    # no partition table: the mount takes sector 0, as the index does
    monkeypatch.setattr(contents_index, "_run", lambda cmd, timeout: {"success": False, "exit_code": 1, "stdout": ""})
    offsets, _note, _all = contents_index._volume_offsets(None, "x", "/nonexistent/ewf1", 10)
    assert offsets == [0]



def test_the_mount_reports_the_volume_it_mounted(tmp_path, monkeypatch):
    from tools import ewf
    (tmp_path / "ewf").mkdir()
    (tmp_path / "fs").mkdir()
    (tmp_path / "ewf" / "ewf1").write_bytes(b"")
    monkeypatch.setattr(ewf, "ensure_mount_point", lambda mp: None)
    monkeypatch.setattr(ewf, "run", lambda cmd, **kw: {"success": True, "stdout": MMLS, "stderr": ""})
    # the chosen volume (mmls parsing: the test above), without a device to read
    monkeypatch.setattr(ewf, "_largest_mountable_volume", lambda out, dev: (206848, 41734144, 512, "ntfs"))
    monkeypatch.setattr(ewf, "mount_ntfs", lambda *a, **kw: {"success": True})
    r = ewf.mount_full_image("corp-ws01.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
    assert r["success"] and r["volume_offset_sectors"] == 206848


def test_the_plan_keeps_the_mounted_volume_on_a_mount_and_on_a_reuse(tmp_path, monkeypatch):
    from unittest.mock import patch
    from core import mount_plan as MP
    from core.evidence_profile import ensure_evidence_profile
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "force")
    root = tmp_path / "case"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence" / "corp-ws01.E01").write_bytes(b"fake-ewf")
    ensure_evidence_profile(root, refresh=True)
    monkeypatch.setattr("tools.ewf.mount_full_image",
                        lambda img, ewf_mp, fs_mp: {"success": True, "volume_offset_sectors": 206848})
    monkeypatch.setattr(MP, "_preflight_hash_before_mount", lambda path: {"success": True})
    with patch("core.mount_plan._path_is_mounted", return_value=False):
        plan = MP.build_mount_plan(root, persist=True, auto_mount=True)
    assert plan["images"][0]["mount_result"]["volume_offset_sectors"] == 206848
    # a plan built anew over the mount that survived (a rerun) reads it back
    MP.mount_plan_path(root).unlink()
    with patch("core.mount_plan._path_is_mounted", return_value=True):
        plan = MP.build_mount_plan(root, persist=True, auto_mount=True)
    mr = plan["images"][0]["mount_result"]
    assert mr["reused"] and mr["volume_offset_sectors"] == 206848


def test_a_stale_or_failed_mount_is_no_readable_form(tmp_path):
    from core.provenance import plan_mounts
    for name, mr in (("stale", {"success": False, "stale": True}), ("failed", {"success": False})):
        root = _case(tmp_path / name, 206848)
        plan = json.loads((root / ".atlas" / "mount_plan.json").read_text(encoding="utf-8"))
        plan["images"][0]["mount_result"].update(mr)
        (root / ".atlas" / "mount_plan.json").write_text(json.dumps(plan), encoding="utf-8")
        reset_cache()
        assert plan_mounts(str(root)) == []
        assert not {x for x in identify(root, f"{MNT}/fs/Users/jane.doe/NTUSER.DAT") if x[0] == "entry"}


def test_a_reused_mount_records_its_volume_only_when_the_offset_was_proved(tmp_path, monkeypatch):
    from tools import ewf
    (tmp_path / "ewf").mkdir()
    (tmp_path / "fs").mkdir()
    (tmp_path / "ewf" / "ewf1").write_bytes(b"")
    monkeypatch.setattr(ewf, "ensure_mount_point", lambda mp: None)
    monkeypatch.setattr(ewf, "run", lambda cmd, **kw: {"success": True, "stdout": MMLS, "stderr": ""})
    monkeypatch.setattr(ewf, "_largest_mountable_volume", lambda out, dev: (206848, 41734144, 512, "ntfs"))
    for res, want in (({"reused": True, "offset_verified": False}, None),
                      ({"reused": True, "offset_verified": True, "warning": "reused_foreign_mount_point"}, None),
                      ({"reused": True, "offset_verified": True}, 206848)):
        monkeypatch.setattr(ewf, "mount_ntfs", lambda *a, _r=res, **kw: {"success": True, **_r})
        r = ewf.mount_full_image("corp-ws01.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["volume_offset_sectors"] == want, res


def test_mount_ntfs_says_whether_a_reused_mounts_offset_was_checked(tmp_path, monkeypatch):
    from tools import ewf
    fs = str(tmp_path / "fs")
    for offset, want in ((None, False), (206848 * 512, True)):
        monkeypatch.setattr(ewf, "_existing_mount_of", lambda dev, _o=offset: (fs, "/dev/loop9", _o))
        r = ewf.mount_ntfs(str(tmp_path / "absent" / "ewf1"), fs, 206848 * 512)
        assert r["reused"] and r["offset_verified"] is want



# ── a volume listing's rows are tied within the volume it was parsed from ──

def _volume_rows(con):
    return {r["path"] for r in con.execute("SELECT path FROM entries WHERE origin = 'volume'")}


def test_a_volume_listing_ties_its_short_paths_to_its_own_volume(tmp_path):
    root = _case(tmp_path, 206848)
    rows = [{"host": "CORP-WS01", "path": p, "size": "4096", "is_dir": False}
            for p in ("$MFT", "Users/jane.doe/NTUSER.DAT", "BOOTLOG.TXT")]
    with ci._connect(root) as con:
        ci._store_volume_rows(con, "analysis/exports/mft.csv", rows, ci._SuffixJoin(con),
                              ("evidence/disk/corp-ws01.E01", 206848))
        kept = _volume_rows(con)
    # the volume's own $MFT and NTUSER.DAT are the image's files; BOOTLOG.TXT
    # is on the volume and not in the image: uncollected, kept
    assert "$MFT" not in kept and "Users/jane.doe/NTUSER.DAT" not in kept and "BOOTLOG.TXT" in kept


def test_without_a_source_or_on_another_volume_a_short_path_is_not_tied(tmp_path):
    root = _case(tmp_path, 206848)
    rows = [{"host": "CORP-WS01", "path": "$MFT", "size": "4096", "is_dir": False}]
    with ci._connect(root) as con:
        ci._store_volume_rows(con, "analysis/exports/a.csv", rows, ci._SuffixJoin(con), None)
        assert "$MFT" in _volume_rows(con)
    with ci._connect(root) as con:
        ci._store_volume_rows(con, "analysis/exports/b.csv", rows, ci._SuffixJoin(con),
                              ("evidence/disk/other-disk.E01", 0))
        assert "$MFT" in _volume_rows(con)


def test_the_export_volume_is_the_one_its_producing_call_read(tmp_path):
    from core.evidence_identity import Resolver
    root = _case(tmp_path, 206848)
    (root / ".atlas" / "output_provenance.json").write_text(json.dumps({"files": {
        "analysis/exports/mft.csv": {"call": 11, "class": "derived"}}}), encoding="utf-8")
    elog.log.record_tool_call("<py>:ez_ez_mftecmd", True, False, 0, 0)
    entry = elog.log._entries[-1]
    entry.update(call_id=11, mcp_tool="ez_mftecmd", args=json.dumps({"mft_path": f"{MNT}/fs/$MFT"}))
    with Resolver(root) as r:
        assert ci._export_volume(root, "analysis/exports/mft.csv", r) == ("evidence/disk/corp-ws01.E01", 206848)
        assert ci._export_volume(root, "analysis/exports/other.csv", r) is None


def test_a_short_path_of_another_volume_of_the_same_image_is_not_tied(tmp_path):
    root = _case(tmp_path, 206848, rows=[{"path": "$MFT", "name": "$MFT", "inode": "0-128-1", "volume": 206848}])
    rows = [{"host": "CORP-WS01", "path": "$MFT", "size": "4096", "is_dir": False}]
    with ci._connect(root) as con:
        ci._store_volume_rows(con, "analysis/exports/c.csv", rows, ci._SuffixJoin(con), (IMG, 2048))
        assert "$MFT" in _volume_rows(con)


def _producing_call(root, call_id, args):
    (root / ".atlas" / "output_provenance.json").write_text(json.dumps({"files": {
        "analysis/exports/mft.csv": {"call": call_id, "class": "derived"}}}), encoding="utf-8")
    elog.log.record_tool_call("<py>:ez_ez_mftecmd", True, False, 0, 0)
    elog.log._entries[-1].update(call_id=call_id, mcp_tool="ez_mftecmd", args=json.dumps(args))


def test_a_call_that_read_two_volumes_gives_no_source(tmp_path):
    from core.evidence_identity import Resolver
    root = _case(tmp_path, 206848)
    _producing_call(root, 12, {"mft_path": f"{IMG}@2048::$MFT", "second_path": f"{IMG}@206848::$MFT"})
    with Resolver(root) as r:
        assert ci._export_volume(root, "analysis/exports/mft.csv", r) is None


def test_an_indexed_listing_ties_its_short_paths_through_its_producing_call(tmp_path):
    root = _case(tmp_path, 206848)
    _producing_call(root, 11, {"mft_path": f"{MNT}/fs/$MFT"})
    (root / "analysis" / "exports").mkdir(parents=True)
    (root / "analysis" / "exports" / "mft.csv").write_text(
        "EntryNumber,ParentPath,FileName,FileSize,IsDirectory\n"
        "0,.,$MFT,4096,False\n"
        "70,.\\Windows,BOOTLOG.TXT,10,False\n", encoding="utf-8")
    with ci._connect(root) as con:
        ci._build_exports(con, root, False, {"exports": []}, only={"analysis/exports/mft.csv"})
        kept = _volume_rows(con)
    assert "$MFT" not in kept and "Windows/BOOTLOG.TXT" in kept


# ── a mount path is also the case path it is (per-path consumers) ──

NTUSER = f"{MNT}/fs/Users/jane.doe/NTUSER.DAT"


def _mount_read(root, call_id, tool, args, success=True):
    elog.log.record_tool_call(f"<py>:{tool}", success, False, 0, 0)
    elog.log._entries[-1].update(call_id=call_id, mcp_tool=tool, args=json.dumps(args))
    return elog.log._entries[-1]


def test_a_mount_read_names_the_entry_and_the_mount_path(tmp_path):
    from core.evidence_identity import call_reads
    root = _case(tmp_path, 206848)
    reads = call_reads(root, _mount_read(root, 21, "misc_regripper_hive", {"hive_path": NTUSER}))
    assert ("entry", _id(root, 206848, "Users/jane.doe/NTUSER.DAT")) in reads["content"]
    assert ("file", NTUSER) in reads["content"]
    assert identify(root, NTUSER) >= {("file", NTUSER), ("entry", _id(root, 206848, "Users/jane.doe/NTUSER.DAT"))}


def test_a_volume_file_known_by_its_mount_path_is_read_by_that_read(tmp_path):
    from core.artifact_value import _first_reads, _read_by, reading_calls
    root = _case(tmp_path, 206848)
    _mount_read(root, 21, "misc_regripper_hive", {"hive_path": NTUSER})
    reads = reading_calls(root, [])
    item = {"name": "NTUSER.DAT", "path": NTUSER, "kind": "file"}
    assert _read_by(item, reads, first=_first_reads(reads))["call_id"] == 21
    other = {"name": "NTUSER.DAT", "path": f"{MNT}/fs/Users/john.roe/NTUSER.DAT", "kind": "file"}
    assert _read_by(other, reads, first=_first_reads(reads)) is None


def test_without_the_offset_the_entries_are_listed_and_the_mount_path_is_read(tmp_path):
    from core.evidence_identity import call_reads
    root = _case(tmp_path, None)
    reads = call_reads(root, _mount_read(root, 22, "ez_mftecmd", {"mft_path": f"{MNT}/fs/$MFT"}))
    assert not {x for x in reads["content"] if x[0] == "entry"}
    assert ("file", f"{MNT}/fs/$MFT") in reads["content"]


def test_a_work_item_on_a_mount_path_is_reached_by_the_read_of_it(tmp_path):
    from core import work_order as W
    root = _case(tmp_path, 206848)
    tg = W._target({"call_id": 5, "target": {"path": NTUSER}}, str(root))
    assert ("file", NTUSER) in tg["ids"] and not tg["image"]
    # a file the index does not list, under the mount: that file, never the whole image
    unlisted = f"{MNT}/fs/Users/jane.doe/notes-2031.txt"
    tg = W._target({"call_id": 6, "target": {"path": unlisted}}, str(root))
    assert tg["ids"] == {("file", unlisted)} and not tg["image"]


def test_a_failed_read_of_the_folder_holding_a_file_is_a_failed_attempt_not_none():
    from core.artifact_value import _failed_over_folder
    profile = f"{MNT}/fs/Users/jane.doe/AppData/Local/Google/Chrome/User Data/Default"
    failed = [{"call_id": 30, "reads": {"content": frozenset({("file", profile)}), "listed": frozenset(),
                                         "folders": frozenset()}}]
    assert _failed_over_folder({"path": f"{profile}/History", "kind": "file"}, failed)["call_id"] == 30
    assert _failed_over_folder({"path": f"{profile}2/History", "kind": "file"}, failed) is None
    assert _failed_over_folder({"path": f"{profile}/History", "kind": "directory"}, failed) is None


def test_a_browser_history_whose_profile_folder_read_failed_stays_open_and_says_so(tmp_path, monkeypatch):
    import core.artifact_value as AV
    root = _case(tmp_path, 206848)
    profile = f"{MNT}/fs/Users/jane.doe/AppData/Local/Google/Chrome/User Data/Default"
    (root / profile).mkdir(parents=True)
    (root / profile / "History").write_bytes(b"SQLite format 3\0" + b"\1" * 40000)
    monkeypatch.setattr(AV, "_mounted_volumes", lambda c: [("corp-ws01", root / MNT / "fs", str(root / IMG))])
    elog.log.record_tool_call("<py>:misc_hindsight_chrome", False, False, 0, 1,
                              stderr="Traceback (most recent call last): parser crashed")
    elog.log._entries[-1].update(call_id=31, mcp_tool="misc_hindsight_chrome",
                                 args=json.dumps({"profile_path": profile}))
    item = next(i for i in AV.high_value_state_uncached(root)["items"] if i.get("path") == f"{profile}/History")
    # still open (its own read is still asked for), with what was tried
    assert item["state"] == "open" and item["failed_folder_call"]["call_id"] == 31
    line = next(ln for ln in AV.gap_lines(root) if f"{profile}/History" in ln)
    assert "its folder was given to misc_hindsight_chrome, which failed (call 31: Traceback" in line
