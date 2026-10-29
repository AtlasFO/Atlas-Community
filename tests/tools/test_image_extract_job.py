"""ATLAS_IMAGE_EXTRACT_JOB: one background job copies a path, a
glob or a folder out of several disk images, resolved through the contents
index; the worker copies each item with icat or tsk_recover and records its
size and hash; the collect ties every copy to its index entry. Invented
fixtures only (CORP-WS01, CORP-SRV02, jane.doe, dates in 2031)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core import contents_index as ci
from tests.core.test_contents_index import SRV02, WS01, _body, _build, _image, _links, _plan, case  # noqa: F401
from tools import image_extract_runner as runner
from tools import jobs

PREFETCH = [_body("Windows/Prefetch", "40-144-1", 0, "d/drwxrwxrwx"),
            _body("Windows/Prefetch/TOOL.EXE-0A1B2C3D.pf", "41-128-1", 1000),
            _body("Windows/Prefetch/EDIT.EXE-4E5F6071.pf", "42-128-1", 2000),
            _body("Users/jane.doe/notes[1].txt", "43-128-1", 10)]
SECURITY = "Windows/System32/winevt/Logs/Security.evtx"


@pytest.fixture
def images(case, monkeypatch):
    _links(case, [("CORP-WS01", "evidence/disk/corp-ws01.raw"), ("CORP-SRV02", "evidence/disk/corp-srv02.raw")])
    _plan(case, [_image(case, "corp-ws01.raw"), _image(case, "corp-srv02.raw")])
    _build(case, monkeypatch, {"corp-ws01.raw": WS01 + PREFETCH, "corp-srv02.raw": SRV02})
    return case


def _start(*args, **kw):
    popen = MagicMock()
    popen.pid = 4242
    with patch("tools.jobs.subprocess.Popen", return_value=popen):
        return jobs.job_start_image_extract(*args, **kw)


def _manifest(result: dict) -> dict:
    _dir, meta, _err = jobs._load_job(result["job_id"])
    return json.loads(Path(meta["argv"][-1]).read_text(encoding="utf-8"))


def test_every_image_and_path_resolves_through_the_index(images):
    r = _start("all", [SECURITY, "Users/*/NTUSER.DAT", "Windows/Prefetch/"])
    assert r["success"] is True and r["items"] == 4
    assert r["folder"].startswith("analysis/extracted/batch-")
    assert sorted(r["unmatched"]) == ["evidence/disk/corp-srv02.raw: Users/*/NTUSER.DAT: no entry of its listing matches",
                                      "evidence/disk/corp-srv02.raw: Windows/Prefetch/: no entry of its listing matches"]
    items = {(Path(i["image"]).stem, i["path"]): i for i in _manifest(r)["items"]}
    sec = items[("corp-ws01", SECURITY)]
    assert sec["inode"] == "200-128-1" and sec["is_dir"] is False
    assert sec["dest"] == str(images / r["folder"] / "corp-ws01" / SECURITY)
    assert ("corp-srv02", SECURITY) in items and ("corp-ws01", "Users/jane.doe/NTUSER.DAT") in items
    assert items[("corp-ws01", "Windows/Prefetch")]["is_dir"] is True
    assert items[("corp-ws01", "Windows/Prefetch")]["size"] == 3000
    # The same request writes the same manifest, so a running or finished job is found again.
    assert _start("all", [SECURITY, "Users/*/NTUSER.DAT", "Windows/Prefetch/"])["cmd"] == r["cmd"]


def test_a_host_label_names_its_image_and_an_unknown_name_is_reported(images):
    r = _start(["CORP-SRV02"], SECURITY)
    assert r["success"] is True and r["items"] == 1
    bad = _start(["CORP-WS77"], SECURITY)
    assert bad["success"] is False and "names no image of this case" in bad["unmatched"][0]


def _fake_tools(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "icat").write_text(
        "#!/usr/bin/env python3\nimport sys\ninode = sys.argv[-1]\n"
        "if inode.startswith('999'):\n    sys.stderr.write('Error reading inode'); sys.exit(1)\n"
        "sys.stdout.write('content of ' + inode)\n", encoding="utf-8")
    (bin_dir / "tsk_recover").write_text(
        "#!/usr/bin/env python3\nimport os, sys\nout = sys.argv[-1]\n"
        "for n in ('TOOL.EXE-0A1B2C3D.pf', 'EDIT.EXE-4E5F6071.pf'):\n"
        "    open(os.path.join(out, n), 'w').write(n)\n", encoding="utf-8")
    for f in bin_dir.iterdir():
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_the_worker_copies_files_and_folders_and_names_each_failure(tmp_path, monkeypatch, capsys):
    _fake_tools(tmp_path, monkeypatch)
    out = tmp_path / "out"
    items = [{"entry_id": 1, "image": "evidence/disk/corp-ws01.raw", "path": SECURITY, "device": "/dev/null",
              "offset": 2048, "inode": "200-128-1", "is_dir": False, "dest": str(out / "ws01" / SECURITY),
              "timeout": 60},
             {"entry_id": 2, "image": "evidence/disk/corp-ws01.raw", "path": "Users/jane.doe/NTUSER.DAT",
              "device": "/dev/null", "offset": 0, "inode": "999-128-1", "is_dir": False,
              "dest": str(out / "ws01" / "Users/jane.doe/NTUSER.DAT"), "timeout": 60},
             {"entry_id": 3, "image": "evidence/disk/corp-ws01.raw", "path": "Windows/Prefetch", "device": "/dev/null",
              "offset": 0, "inode": "40-144-1", "is_dir": True, "dest": str(out / "ws01" / "Windows/Prefetch"),
              "timeout": 60}]
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"items": items, "result": str(tmp_path / "m.result.json")}), encoding="utf-8")
    assert runner.main(str(m)) == 1
    done = {r["entry_id"]: r for r in json.loads((tmp_path / "m.result.json").read_text())["items"]}
    copy = Path(items[0]["dest"])
    assert copy.read_text() == "content of 200-128-1"
    assert done[1]["sha256"] == hashlib.sha256(copy.read_bytes()).hexdigest() and done[1]["size"] == copy.stat().st_size
    assert done[2]["ok"] is False and "Error reading inode" in done[2]["error"]
    assert not Path(items[1]["dest"]).exists() and not Path(items[1]["dest"] + ".part").exists()
    assert done[3]["ok"] is True and done[3]["files"] == 2
    printed = capsys.readouterr().out
    assert "failed: evidence/disk/corp-ws01.raw::Users/jane.doe/NTUSER.DAT" in printed
    assert "2 of 3 item(s) copied" in printed and str(copy) not in printed


def test_the_collect_ties_every_copy_to_its_entry(images, tmp_path, monkeypatch):
    _fake_tools(tmp_path, monkeypatch)
    r = _start(["CORP-WS01"], [SECURITY, "Windows/Prefetch/"])
    job_dir, meta, _ = jobs._load_job(r["job_id"])
    assert runner.main(meta["argv"][-1]) == 0
    meta["exit_code"] = 0
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (job_dir / "exit_code").write_text("0")
    out = jobs._collect_impl(r["job_id"])
    assert out["success"] is True and out["copied"] == 2 and out["failures"] == []
    assert out["folder"] == r["folder"] and out["image_folders"] == [r["folder"] + "/corp-ws01"]
    src = ci.copy_source(images, f"{r['folder']}/corp-ws01/{SECURITY}")
    assert src["inner_path"] == SECURITY and src["call_id"] == out["_atlas_call_id"] and len(src["sha256"]) == 64
    assert ci.copy_source(images, f"{r['folder']}/corp-ws01/Windows/Prefetch")["size"] is None
    assert jobs._collect_impl(r["job_id"])["already_collected"] is True


def test_the_switch_off_refuses_and_the_view_names_the_job_only_when_on(images, monkeypatch):
    assert "Read many: job.job_start_image_extract" in ci._read_line()
    monkeypatch.setenv("ATLAS_IMAGE_EXTRACT_JOB", "0")
    assert "Read many" not in ci._read_line()
    r = _start("all", [SECURITY])
    assert r["success"] is False and "off in this run" in r["error"]


def test_the_extract_is_no_read_and_is_refused_under_a_handling_stop():
    from core.coverage_ledger import is_probe_tool
    from core.handling_stop import tool_class
    assert is_probe_tool("job_job_start_image_extract") is False
    assert tool_class("job_job_start_image_extract") == "refused"


def _collected(images, tmp_path, monkeypatch, paths, dest=""):
    _fake_tools(tmp_path, monkeypatch)
    r = _start(["CORP-WS01"], paths, dest)
    job_dir, meta, _ = jobs._load_job(r["job_id"])
    assert runner.main(meta["argv"][-1]) == 0
    meta["exit_code"] = 0
    (job_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (job_dir / "exit_code").write_text("0")
    return r, jobs._collect_impl(r["job_id"])


def test_a_parse_over_the_folder_closes_its_planned_read_and_reads_no_copy_by_itself(images, tmp_path,
                                                                                      monkeypatch):
    """The work order closes the planned read the parse reached, as parsed with
    no report of what it processed (not resolved); no file of
    the folder counts as read from the command line alone: what a parser
    processed is its own report, and a processed file nobody looked at is
    parsed (core.contents_index.read_state_by_class)."""
    import core.execution_log as elog
    r, _out = _collected(images, tmp_path, monkeypatch, [SECURITY, "Users/*/NTUSER.DAT"])
    log = elog.log
    image = "evidence/disk/corp-ws01.raw"
    sec = log.add_work_item("plan", [], "ez_ez_evtxecmd", {"host": "CORP-WS01", "path": image,
                                                           "inner_path": SECURITY}, "the Security log")
    hive = log.add_work_item("plan", [], "ez_ez_recmd_hive", {"host": "CORP-WS01", "path": image,
                                                              "inner_path": "Users/jane.doe/NTUSER.DAT"}, "the hive")
    args = {"evtx_path": str(images / r["folder"])}
    cid = log.record_tool_call("<py>:ez_ez_evtxecmd", True, False, 0, 0, stdout_excerpt="1 file parsed")
    log.annotate_tool_call(cid, args=json.dumps(args), mcp_tool="ez_ez_evtxecmd")
    entry = next(e for e in log._entries if e.get("call_id") == cid)
    assert log.close_items_for_call("ez_ez_evtxecmd", args, [entry]) == [sec["call_id"]]
    # The parse ran on the item's file and reports nothing it processed: the
    # planned call is done, the file is not counted read.
    from core.work_order import PARSED_UNREPORTED
    assert sec["status"] == "parsed" and sec["outcome"] == PARSED_UNREPORTED and hive["status"] == "due"
    state = {row["path"]: row["state"] for row in ci.find(images, host="CORP-WS01")["rows"]}
    assert state[SECURITY] != "read" and state["Users/jane.doe/NTUSER.DAT"] != "read"


def test_each_file_of_a_folder_copy_is_tied_to_its_own_entry(images, tmp_path, monkeypatch):
    r, out = _collected(images, tmp_path, monkeypatch, ["Windows/Prefetch/"])
    src = ci.copy_source(images, f"{r['folder']}/corp-ws01/Windows/Prefetch/TOOL.EXE-0A1B2C3D.pf")
    assert src["inner_path"] == "Windows/Prefetch/TOOL.EXE-0A1B2C3D.pf" and src["call_id"] == out["_atlas_call_id"]


def test_a_second_job_copies_from_the_first_copy(images, tmp_path, monkeypatch):
    hive = "Users/jane.doe/NTUSER.DAT"
    first, _ = _collected(images, tmp_path, monkeypatch, [hive])
    copy = images / first["folder"] / "corp-ws01" / hive
    copy.write_bytes(b"r" * 2_097_152)                   # the size the index lists: a current copy
    monkeypatch.setenv("PATH", "/nonexistent")          # no icat: only the earlier copy can serve
    second = _start(["CORP-WS01"], [hive], "analysis/second")
    _dir, meta, _ = jobs._load_job(second["job_id"])
    item = _manifest(second)["items"][0]
    assert item["reuse"] == str(copy)
    assert runner.main(meta["argv"][-1]) == 0
    assert Path(item["dest"]).read_bytes() == copy.read_bytes()


def test_only_the_star_is_a_wildcard(images):
    rows = ci.entries_matching(images, "evidence/disk/corp-ws01.raw", "Users/*/notes[1].txt")
    assert [x["path"] for x in rows] == ["Users/jane.doe/notes[1].txt"]
    assert ci.entries_matching(images, "evidence/disk/corp-ws01.raw", "Users/jane.doe/notes?1].txt") == []


_TSK = all(shutil.which(t) for t in ("icat", "fls", "mkfs.vfat", "mcopy"))


@pytest.mark.skipif(not _TSK, reason="The Sleuth Kit and mtools are not installed here; the VM run covers it")
def test_the_worker_on_a_small_invented_image(tmp_path):
    """The runner with the real icat on a FAT image built here (skipped
    where The Sleuth Kit or mtools are missing)."""
    import subprocess
    img = tmp_path / "small.img"
    subprocess.run(["mkfs.vfat", "-C", str(img), "1024"], check=True, capture_output=True)
    (tmp_path / "note.txt").write_text("invented content for CORP-WS01", encoding="utf-8")
    subprocess.run(["mcopy", "-i", str(img), str(tmp_path / "note.txt"), "::NOTE.TXT"], check=True)
    listing = subprocess.run(["fls", "-p", str(img)], check=True, capture_output=True, text=True).stdout
    inode = next(ln.split()[-2].rstrip(":") for ln in listing.splitlines() if ln.rstrip().endswith("NOTE.TXT"))
    dest = tmp_path / "out" / "NOTE.TXT"
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"result": str(tmp_path / "r.json"), "items": [
        {"entry_id": 1, "image": "small.img", "path": "NOTE.TXT", "device": str(img), "offset": 0,
         "inode": inode, "is_dir": False, "dest": str(dest), "timeout": 60}]}), encoding="utf-8")
    assert runner.main(str(m)) == 0
    assert dest.read_text(encoding="utf-8") == "invented content for CORP-WS01"
