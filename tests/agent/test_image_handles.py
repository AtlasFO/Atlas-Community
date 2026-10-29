"""Image handles: one call reads a file inside a disk image.
The Toolbox resolves ``<image>::<path>`` in a file parameter through the
contents index, extracts the file by a traced call of its own and runs the
tool on the copy; the parse's trace entry names the extraction. Invented
fixtures only (CORP-WS01, CORP-SRV02, jane.doe, dates in 2031)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastmcp import FastMCP

import core.execution_log as elog
from core import contents_index as ci

T = "1924992000"


def _body(path, inode, size=4096, mode="r/rrwxrwxrwx"):
    return f"0|/{path}|{inode}|{mode}|0|0|{size}|{T}|{T}|{T}|{T}"


WS01 = [_body("C/Windows/System32/winevt/Logs/Security.evtx", "200-128-1", 12),
        _body("C/Users/jane.doe/NTUSER.DAT", "203-128-1", 8),
        _body("C/Windows/Prefetch", "40-144-1", 0, "d/drwxrwxrwx"),
        _body("C/Windows/Prefetch/TOOL.EXE-1A2B3C4D.pf", "41-128-1", 6)]


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis"):
        (root / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    imgs = []
    for name in ("corp-ws01.raw", "corp-srv02.raw", "corp-srv02.dd"):
        (root / "evidence" / "disk" / name).write_bytes(b"\0" * 512)
        imgs.append(str(root / "evidence" / "disk" / name))
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": p, "media_role": "disk", "action": "plan_only"} for p in imgs]}), encoding="utf-8")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/disk/corp-ws01.raw"},
        {"label": "CORP-SRV02", "path": "evidence/disk/corp-srv02.raw"},
        {"label": "CORP-SRV02", "path": "evidence/disk/corp-srv02.dd"}]}), encoding="utf-8")

    def run(cmd, timeout):
        lines = WS01 if Path(cmd[-1]).name == "corp-ws01.raw" else []
        cid = elog.log.record_tool_call(cmd=" ".join(cmd), success=True, truncated=False, retries=0, exit_code=0)
        return {"success": bool(lines), "stdout": "\n".join(lines), "_atlas_call_id": cid,
                "stderr": "" if lines else "Cannot determine file system type"}
    monkeypatch.setattr(ci, "_run", run)
    ci.build(root)
    monkeypatch.setenv("ATLAS_WORK_ORDER", "1")
    return root


@pytest.fixture
def tb(case, monkeypatch):
    calls: list[tuple[str, dict]] = []
    tsk = FastMCP("tsk")

    def _traced(cmd: str) -> int:
        return elog.log.record_tool_call(cmd=cmd, success=True, truncated=False, retries=0, exit_code=0)

    @tsk.tool
    def tsk_icat(image: str, inode: str, output_path: str, offset_sectors: int | None = None) -> dict:
        """Extract a file."""
        calls.append(("icat", {"image": image, "inode": inode, "output_path": output_path}))
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(b"x" * 12)
        return {"success": True, "_atlas_call_id": _traced(f"icat {image} {inode}")}

    @tsk.tool
    def tsk_recover(image: str, output_dir: str, dir_inode: int | None = None,
                    offset_sectors: int | None = None) -> dict:
        """Extract a folder."""
        calls.append(("recover", {"image": image, "dir_inode": dir_inode}))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return {"success": True, "_atlas_call_id": _traced(f"tsk_recover -d {dir_inode} {image} {output_dir}")}

    @tsk.tool
    def tsk_resolve_path(image: str, fs_path: str, offset_sectors: int | None = None) -> dict:
        """Walk a path."""
        calls.append(("walk", {"image": image, "fs_path": fs_path}))
        return {"success": True, "path": fs_path, "inode": "900-128-1", "type": "r/r"}

    ez = FastMCP("ez")

    @ez.tool
    def evtxecmd(file_path: str, pattern: str = "") -> dict:
        """Parse an event log."""
        calls.append(("parse", {"file_path": file_path, "pattern": pattern}))
        if file_path.endswith("NTUSER.DAT"):
            return {"success": False, "gate": "input_kind", "error": f"{file_path} is a registry hive"}
        return {"success": True, "file": file_path, "_atlas_call_id": _traced(f"EvtxECmd -f {file_path}")}

    @ez.tool
    def pecmd(directory: str) -> dict:
        """Parse Prefetch."""
        calls.append(("pecmd", {"directory": directory}))
        return {"success": True, "directory": directory}

    root = FastMCP("fixture")
    root.mount(tsk, namespace="tsk")
    root.mount(ez, namespace="ez")

    class FakeServer:
        mcp = root
    monkeypatch.setitem(sys.modules, "server", FakeServer)
    from agent.toolbox import Toolbox
    box = Toolbox(loaded=("tsk", "ez"))
    box.calls = calls
    return box


H = "evidence/disk/corp-ws01.raw::C/Windows/System32/winevt/Logs/Security.evtx"


def _entry(cid):
    return next(e for e in elog.log._entries if e.get("call_id") == cid)


# ── 14: one call, two client calls, the lineage in the trace ──────────────

def test_a_handle_is_extracted_and_the_tool_reads_the_copy(case, tb):
    out, _ = tb.call("ez.evtxecmd", {"file_path": H})
    assert [c[0] for c in tb.calls] == ["icat", "parse"]
    copy = str(case / "analysis" / "extracted" / "corp-ws01" / "C/Windows/System32/winevt/Logs/Security.evtx")
    assert tb.calls[0][1]["output_path"] == copy and tb.calls[0][1]["inode"] == "200-128-1"
    assert tb.calls[1][1]["file_path"] == copy
    note = json.loads(out)["read_from"]
    assert note["handle"] == H and note["reused"] is False
    assert note["copy"] == "analysis/extracted/corp-ws01/C/Windows/System32/winevt/Logs/Security.evtx"
    # The parse's entry names the extraction; the extraction names nothing of its own.
    parse = _entry(json.loads(out)["_atlas_call_id"])
    assert note["extracted_by_call"] in parse["input_call_ids"]
    assert note["extracted_by_call"] not in (_entry(note["extracted_by_call"]).get("input_call_ids") or [])
    assert ci.copy_source(case, copy)["inner_path"] == "C/Windows/System32/winevt/Logs/Security.evtx"
    # A second read of the same handle reuses the copy: one client call.
    tb.calls.clear()
    out2, _ = tb.call("ez.evtxecmd", {"file_path": H})
    assert [c[0] for c in tb.calls] == ["parse"] and json.loads(out2)["read_from"]["reused"] is True


def test_the_copy_is_credited_to_its_entry(case, tb):
    from core.artifact_value import high_value_state
    before = {i["name"] for i in high_value_state(case)["items"]}
    assert "Security.evtx" in before
    tb.call("ez.evtxecmd", {"file_path": H})
    assert "Security.evtx" not in {i["name"] for i in high_value_state(case)["items"]}


def test_a_folder_handle_is_recovered_as_a_tree(case, tb):
    tb.call("ez.pecmd", {"directory": "corp-ws01::C/Windows/Prefetch"})
    assert [c[0] for c in tb.calls] == ["recover", "pecmd"]
    assert tb.calls[0][1]["dir_inode"] == 40
    assert tb.calls[1][1]["directory"].endswith("analysis/extracted/corp-ws01/C/Windows/Prefetch")


# ── 14a: handles off ──────────────────────────────────────────────────────

@pytest.mark.parametrize("env", [{"ATLAS_IMAGE_HANDLES": "0"},
                                 {"ATLAS_DAIR_NO_DEFER": "0"}])
def test_with_handles_off_a_handle_is_refused_without_a_call(case, tb, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out, _ = tb.call("ez.evtxecmd", {"file_path": H})
    assert out == "ERROR: " + ci.HANDLES_OFF_REFUSAL and tb.calls == []


# ── 15: refusals name the images, the near names, the two images ──────────

def test_refusals_name_what_the_case_has(case, tb):
    out, _ = tb.call("ez.evtxecmd", {"file_path": "corp-ws9.raw::C/Windows/x.evtx"})
    assert "names no image of this case" in out and "evidence/disk/corp-ws01.raw (CORP-WS01)" in out
    out, _ = tb.call("ez.evtxecmd", {"file_path": "CORP-WS01::C/Windows/System32/winevt/Logs/Securty.evtx"})
    assert "is not in the contents of evidence/disk/corp-ws01.raw" in out and "Near:" in out
    out, _ = tb.call("ez.evtxecmd", {"file_path": "CORP-SRV02::Windows/System32/winevt/Logs/Security.evtx"})
    assert "host label 'CORP-SRV02' names 2 images" in out
    assert "evidence/disk/corp-srv02.raw" in out and "evidence/disk/corp-srv02.dd" in out
    assert tb.calls == []
    assert any(e.get("type") == "call_abandoned" for e in elog.log._entries)


def test_an_unlisted_image_is_walked(case, tb):
    tb.call("ez.evtxecmd", {"file_path": "evidence/disk/corp-srv02.raw::Windows/System32/winevt/Logs/System.evtx"})
    assert [c[0] for c in tb.calls] == ["walk", "icat", "parse"]


# ── 16: which parameters, the root folder, a mounted volume ───────────────

def test_a_handle_in_a_pattern_is_left_as_written(case, tb):
    out, _ = tb.call("ez.evtxecmd", {"file_path": H, "pattern": H})
    assert tb.calls[-1][1]["pattern"] == H
    assert "pattern was not resolved" in json.dumps(json.loads(out)["_arguments_adjusted"])


@pytest.mark.parametrize("inner", ["Windows/System32/winevt/Logs/Security.evtx",
                                   "/C/Windows/System32/winevt/Logs/Security.evtx",
                                   "C\\Windows\\System32\\winevt\\Logs\\security.EVTX"])
def test_the_collection_root_folder_may_be_left_out(case, inner):
    r = ci.resolve(case, f"corp-ws01.raw::{inner}")
    assert r["path"] == "C/Windows/System32/winevt/Logs/Security.evtx" and r["inode"] == "200-128-1"


def test_a_mounted_volume_is_read_in_place(case, tb, tmp_path):
    mnt = tmp_path / "mnt"
    (mnt / "C/Windows/System32/winevt/Logs").mkdir(parents=True)
    (mnt / "C/Windows/System32/winevt/Logs/Security.evtx").write_bytes(b"x")
    vol = [{"path": str(case / "evidence/disk/corp-ws01.raw"), "mount_point": str(mnt)}]
    with patch("core.mount_plan.mounted_volumes", return_value=vol):
        out, _ = tb.call("ez.evtxecmd", {"file_path": H})
    assert [c[0] for c in tb.calls] == ["parse"]
    assert json.loads(out)["read_from"]["mounted"].startswith(str(mnt))


# ── 18: a refusal of the copy is said in the handle's terms ───────────────

def test_a_wrong_input_kind_refusal_names_the_handle(case, tb):
    h = "corp-ws01.raw::C/Users/jane.doe/NTUSER.DAT"
    out, _ = tb.call("ez.evtxecmd", {"file_path": h})
    assert out.startswith(f"[{h} was read from its copy]") and "registry hive" in out


# ── the framing lines carry the handle clause ─────────────────────────────

def test_the_framing_lines_follow_the_handle_switch(case, monkeypatch):
    from core.evidence_framing import framing_lines
    assert ci.HANDLE_CLAUSE in framing_lines(handles=True)["policy_tail"]
    assert ci.HANDLE_CLAUSE_OFF in framing_lines(handles=False)["profile_rule"]
    from core.evidence_inventory_gate import build_processing_assessment
    a = build_processing_assessment(present={"windows_eventlog", "tabular"}, absent=[], counts={},
                                    high_value_parsed=["analysis/evtxecmd_out.csv"], samples_by_class={})
    assert ci.HANDLE_CLAUSE in a["catalog"]["policy"] and "the images are the authority" in a["rule"]
    assert a["recommended_first_actions"][0].startswith("The brief (CASE.md")
    monkeypatch.setenv("ATLAS_EVIDENCE_FRAMING", "0")
    a = build_processing_assessment(present={"windows_eventlog"}, absent=[], counts={},
                                    high_value_parsed=["analysis/evtxecmd_out.csv"], samples_by_class={})
    assert "Prefer already_processed over re-parse" in a["rule"] and "handle" not in a["catalog"]["policy"]
    from core.run_budget import _stall_soft_msg
    assert "already_processed / case-root tabular" in _stall_soft_msg()
    monkeypatch.setenv("ATLAS_EVIDENCE_FRAMING", "1")
    assert "read an unread source inside an image" in _stall_soft_msg()


def test_an_ewf_image_without_a_live_device_is_refused_naming_the_mount(case, tb, monkeypatch):
    # The index was built while a device was mounted; at read time it is gone.
    e01 = case / "evidence" / "disk" / "corp-ws01.E01"
    e01.write_bytes(b"\0" * 512)
    with ci._connect(case) as con:
        con.execute("UPDATE entries SET image = 'evidence/disk/corp-ws01.E01'")
        con.execute("UPDATE meta SET key = 'image:evidence/disk/corp-ws01.E01' "
                    "WHERE key = 'image:evidence/disk/corp-ws01.raw'")
    plan = json.loads((case / ".atlas" / "mount_plan.json").read_text())
    plan["images"][0]["path"] = str(e01)
    (case / ".atlas" / "mount_plan.json").write_text(json.dumps(plan))
    monkeypatch.setattr("tools.sleuthkit.tsk_image_types", lambda: frozenset({"raw"}))
    out, _ = tb.call("ez.evtxecmd", {"file_path": "corp-ws01.E01::C/Windows/System32/winevt/Logs/Security.evtx"})
    assert out.startswith("ERROR: evidence/disk/corp-ws01.E01 is an Expert Witness container")
    assert "mnt/" in out and "ewf/ewf1" in out and tb.calls == []
    monkeypatch.setattr("tools.sleuthkit.tsk_image_types", lambda: frozenset({"raw", "ewf"}))
    tb.call("ez.evtxecmd", {"file_path": "corp-ws01.E01::C/Windows/System32/winevt/Logs/Security.evtx"})
    assert [c[0] for c in tb.calls] == ["icat", "parse"]


# ── the work order closes what a handle read ──────────────────────────────

INNER = "C/Windows/System32/winevt/Logs/Security.evtx"


def _traced(tool, args):
    cid = elog.log.record_tool_call(f"<py>:{tool}", True, False, 0, 0, stdout_excerpt="out")
    elog.log.annotate_tool_call(cid, args=json.dumps(args, sort_keys=True), mcp_tool=tool)
    return elog.log.index().by_call_id[cid]


def test_an_item_read_through_a_handle_or_its_copy_closes(case, tb):
    from core import work_order as W
    tb.call("ez.evtxecmd", {"file_path": H})
    copy = str(case / "analysis" / "extracted" / "corp-ws01" / INNER)
    # By the handle the model wrote.
    on_image = elog.log.add_work_item("director", ["task-0001"], "ez_evtxecmd",
                                      {"path": "evidence/disk/corp-ws01.raw", "inner_path": INNER}, "read it")
    parse = _traced("ez_ez_evtxecmd", {"file_path": copy})
    assert on_image["call_id"] in elog.log.close_items_for_call("ez_ez_evtxecmd", {"file_path": H}, [parse])
    # By the copy alone: a call that names only the extracted file reaches
    # the host's file, so an item proposed after the read is born resolved.
    again = _traced("ez_ez_evtxecmd", {"file_path": copy})
    hinted_item = {"tool": "", "target": {"host": "CORP-WS01", "source_hint": INNER}}
    assert W._reaches(hinted_item, W._call_view(again), str(case))
    hinted = elog.log.add_work_item("index", [], "", {"host": "CORP-WS01", "source_hint": INNER},
                                    "the case index lists Security.evtx", status="proposed")
    assert hinted["status"] == "resolved"
    # The extraction's own entry reaches the item's target.
    icat = _traced("tsk_tsk_icat", {"image": str(case / "evidence/disk/corp-ws01.raw"), "inode": "200-128-1",
                                    "output_path": copy})
    item = {"tool": "", "target": {"host": "CORP-WS01", "source_hint": INNER}}
    assert W._reaches(item, W._call_view(icat), str(case))


def test_the_ready_call_names_the_handle(case):
    from core import work_order as W
    item = {"tool": "", "target": {"host": "CORP-WS01", "source_hint": INNER, "handle": H}}
    # The handle is evidence-derived (its inner path is the image's own), so the bare read
    # shows it JSON-quoted like the schema-placed form below (core.coverage_ledger.shown_name).
    assert W.ready_call(item) == f'read "{H}" (pass the handle as the file argument of a parser for its type)'
    item = {"tool": "ez_evtxecmd", "target": {"path": "evidence/disk/corp-ws01.raw", "inner_path": INNER}}
    assert W.ready_call(item, ["file_path"]) == f'ez_evtxecmd(file_path="evidence/disk/corp-ws01.raw::{INNER}")'


def test_a_mount_of_another_partition_is_not_read_in_place(case, tmp_path):
    with ci._connect(case) as con:
        con.execute("INSERT INTO entries (id, host, image, volume, path, name, inode, size, deleted, is_dir, "
                    "origin, score, class) VALUES (9999, 'CORP-WS01', 'evidence/disk/corp-ws01.raw', 206848, "
                    "'Data/x.txt', 'x.txt', '5-128-1', 1, 0, 0, 'image', 0, '')")
    mnt = tmp_path / "mnt"
    (mnt / "C/Windows/System32/winevt/Logs").mkdir(parents=True)
    (mnt / INNER).write_bytes(b"x")
    vol = [{"path": str(case / "evidence/disk/corp-ws01.raw"), "mount_point": str(mnt)}]
    plan = json.loads((case / ".atlas" / "mount_plan.json").read_text())
    plan["images"][0]["mount_result"] = {"ntfs_offset_sectors": 206848}
    (case / ".atlas" / "mount_plan.json").write_text(json.dumps(plan))
    with patch("core.mount_plan.mounted_volumes", return_value=vol):
        assert ci.resolve(case, f"corp-ws01.raw@0::{INNER}")["mounted_path"] == ""
        plan["images"][0]["mount_result"] = {"ntfs_offset_sectors": 0}
        (case / ".atlas" / "mount_plan.json").write_text(json.dumps(plan))
        assert ci.resolve(case, f"corp-ws01.raw@0::{INNER}")["mounted_path"].startswith(str(mnt))


def test_an_extraction_failure_is_recorded(case, tb, monkeypatch):
    from fastmcp import FastMCP  # noqa: F401
    from types import SimpleNamespace
    real = tb._tool_call

    def failing(name, args):
        if name.endswith("icat"):
            return SimpleNamespace(data={"success": False, "error": "icat: read error"}, is_error=False)
        return real(name, args)
    monkeypatch.setattr(tb, "_tool_call", failing)
    out, _ = tb.call("ez.evtxecmd", {"file_path": H})
    assert out.startswith(f"ERROR: extracting {H} failed") and "read error" in out
    assert any(e.get("type") == "call_abandoned" and "extracting" in e.get("reason", "")
               for e in elog.log._entries)


def test_no_case_identifiers_in_the_framing_module():
    import re
    text = (Path(__file__).resolve().parents[2] / "core" / "evidence_framing.py").read_text(encoding="utf-8")
    assert not re.search(r"\b[A-Z]{2,}-[A-Z]*\d+\b", text)
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert not re.search(r"\b(?:19|20)\d\d-\d\d-\d\d\b", text)


def test_every_dict_result_leads_with_its_own_call_id_whatever_call_id_its_content_holds(case, monkeypatch):
    """The toolbox stamps every dict result with the trace entry it stands for, first, so the item registers
    the call by it and a call_id of the content (a referenced call) never stands for the result."""
    from core.call_memo import trace_call_id_of
    rd = FastMCP("rd")
    ids = []

    @rd.tool
    def read_text(file_path: str) -> dict:
        """Read a text file."""
        ids.append(elog.log.record_tool_call(cmd="<py>:rd_read_text", success=True, truncated=False, retries=0,
                                             exit_code=0))
        return {"success": True, "call_id": 4, "path": file_path, "lines": ["@echo off", "exit /b 0"]}

    root = FastMCP("fixture")
    root.mount(rd, namespace="rd")

    class FakeServer:
        mcp = root
    monkeypatch.setitem(sys.modules, "server", FakeServer)
    from agent.toolbox import Toolbox
    out, _ = Toolbox(loaded=("rd",)).call("rd.read_text", {"file_path": "analysis/f.bat"})
    data = json.loads(out)
    assert ids and next(iter(data)) == "_atlas_call_id" and data["_atlas_call_id"] == ids[0]
    assert data["call_id"] == 4 and trace_call_id_of(out) == str(ids[0])


# ── an image path with a space; prose with "::" ───────────────────────────

def test_a_handle_whose_image_path_holds_a_space_is_a_handle(tmp_path, monkeypatch):
    root = tmp_path / "case"
    for d in ("evidence/notebook", ".atlas", "analysis"):
        (root / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    img = root / "evidence/notebook/corp laptop 03.raw"
    img.write_bytes(b"\0" * 512)
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(img), "media_role": "disk", "action": "plan_only"}]}), encoding="utf-8")

    def run(cmd, timeout):
        cid = elog.log.record_tool_call(cmd=" ".join(cmd), success=True, truncated=False, retries=0, exit_code=0)
        return {"success": True, "stdout": "\n".join(WS01), "_atlas_call_id": cid, "stderr": ""}
    monkeypatch.setattr(ci, "_run", run)
    ci.build(root)
    h = "evidence/notebook/corp laptop 03.raw::C/Windows/System32/winevt/Logs/Security.evtx"
    assert ci.looks_like_handle(h) and ci.names_case_image(root, h)
    r = ci.resolve(root, h)
    assert not r.get("error") and r.get("image") == "evidence/notebook/corp laptop 03.raw"
    assert ci.looks_like_handle("evidence/notebook/corp laptop 03.raw@2048::$MFT")
    assert not ci.looks_like_handle("C:\\Users\\jane.doe::stream")             # a drive is no image


def test_prose_with_a_double_colon_in_a_pattern_is_left_alone(case, tb):
    out, _ = tb.call("ez.evtxecmd", {"file_path": H, "pattern": "using namespace std::string here"})
    assert tb.calls[-1][1]["pattern"] == "using namespace std::string here"
    assert "pattern was not resolved" not in out


def test_prose_with_a_double_colon_in_a_path_parameter_is_refused_not_read(case, tb):
    out, _ = tb.call("ez.evtxecmd", {"file_path": "notes on std::string usage"})
    assert out.startswith("ERROR:") and "names no image of this case" in out
    assert tb.calls == []
