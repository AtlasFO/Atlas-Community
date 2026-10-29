"""A director entry's target is made true before it becomes work: a path
under the image's readable form is the image and the path inside it; the
image alone is refused for a tool whose schema needs an argument the entry
does not give, naming it (an object inside the image, or what a scan
searches for); a path a
complete listing lacks is refused with its reason, one an incomplete
listing lacks is kept. Invented fixtures (CORP-WS01, 2031)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

import core.execution_log as elog
from core import contents_index as ci
from core import work_order as W

IMG = "evidence/disk/corp-ws01.raw"
SEC = "Windows/System32/winevt/Logs/Security.evtx"
SCHEMAS = [("tsk_tsk_istat", {"required": ["image", "inode"]}), ("tsk_tsk_fls", {"required": ["image"]}),
           ("ez_ez_evtxecmd", {"required": ["evtx_path"]}), ("strings_strings_extract", {"required": ["file_path"]}),
           ("plaso_plaso_create_timeline", {"required": ["evidence_path", "storage_file"]}),
           ("carve_bulk_extractor_scan", {"required": ["image_path", "output_dir"]}),
           ("ewf_ewf_mount", {"required": ["image", "mount_point"]}),
           ("vol_vol_yarascan", {"required": ["image", "yara_rules"]}),
           ("tsk_tsk_sigfind", {"required": ["image", "signature_hex"]}),
           ("plaso_plaso_create_targeted", {"required": ["evidence_path", "storage_file", "artifact_filters"]})]


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_CONTENTS_INDEX", "1")
    root = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "mnt/CORP-WS01"):
        (root / d).mkdir(parents=True)
    (root / IMG).write_bytes(b"\0" * 512)
    (root / "mnt/CORP-WS01/disk").write_bytes(b"")
    (root / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": str(root / IMG), "media_role": "disk", "action": "plan_only",
         "image_type": "raw_or_container"}]}), encoding="utf-8")
    (root / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": IMG}]}), encoding="utf-8")
    elog.log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    from core.coverage_ledger import save_ledger
    save_ledger(root, {"units": {IMG: {"id": IMG, "path": IMG, "kind": "container", "status": "unseen"}}})
    con = ci._connect(root, create=True)
    ci._insert_entries(con, "CORP-WS01", IMG, [{"path": SEC, "name": "Security.evtx", "inode": "200-128-1"}],
                       "image")
    ci._meta_set(con, f"image:{IMG}", {"listed": 1, "complete": 1, "host": "CORP-WS01", "volumes": [0],
                                       "readable": "mnt/CORP-WS01/disk"})
    con.commit()
    con.close()
    return root


def _parse(root, *entries):
    refused: list[str] = []
    with patch("tools.tool_capabilities.registered_tool_schemas", return_value=SCHEMAS):
        out = W.parse_director_entries({"priority_tools": list(entries)}, str(root), refused)
    return out, refused


def test_a_path_under_the_readable_form_is_the_image_and_its_inner_path(case):
    (o,), refused = _parse(case, f"ez.evtxecmd CORP-WS01 mnt/CORP-WS01/disk/{SEC}")
    assert o["target"]["path"] == IMG and o["target"]["inner_path"] == SEC and not refused


def test_the_image_alone_is_refused_for_a_tool_that_needs_an_object_in_it(case):
    out, refused = _parse(case, "tsk.istat CORP-WS01 mnt/CORP-WS01/disk",
                          "strings.strings_extract CORP-WS01 mnt/CORP-WS01/disk")
    assert len(out) == 1 and "strings_extract" in out[0]["tool"] and out[0]["target"]["path"] == IMG
    assert out[0]["target"].get("inner_path") is None
    assert refused == [f"tsk.istat: needs inode, which {IMG} alone does not give; name it in the entry"]


def test_a_path_a_complete_listing_lacks_is_refused_an_incomplete_one_kept(case):
    out, refused = _parse(case, "ez.evtxecmd CORP-WS01 Windows/System32/winevt/Logs/Nothing.evtx")
    assert out == [] and refused == [f"ez.evtxecmd: 'Windows/System32/winevt/Logs/Nothing.evtx' is not in the "
                                     f"complete listing of {IMG}"]
    con = ci._connect(case)
    ci._meta_set(con, f"image:{IMG}", {"listed": 1, "complete": 0, "host": "CORP-WS01", "volumes": [0]})
    con.commit()
    con.close()
    (o,), refused = _parse(case, "ez.evtxecmd CORP-WS01 Windows/System32/winevt/Logs/Nothing.evtx")
    assert o["target"]["inner_path"] == "Windows/System32/winevt/Logs/Nothing.evtx" and not refused


def test_a_whole_image_tool_that_only_needs_where_to_write_is_not_refused(case):
    """Where a tool writes (an output, an output name, a mount point) is no
    object inside the image: plaso, bulk_extractor and a mount take the image
    whole; tsk_istat (image and inode) still needs the inode."""
    out, refused = _parse(case, "plaso.plaso_create_timeline CORP-WS01 mnt/CORP-WS01/disk",
                          "carve.bulk_extractor_scan CORP-WS01 mnt/CORP-WS01/disk",
                          "tsk.istat CORP-WS01 mnt/CORP-WS01/disk")
    assert len(out) == 2 and all(o["target"]["path"] == IMG for o in out)
    assert refused == [f"tsk.istat: needs inode, which {IMG} alone does not give; name it in the entry"]


def test_a_scan_is_refused_only_for_the_argument_it_lacks_and_kept_with_it(case):
    """A whole-image scan needs what it searches for, not a path inside the
    image: refused naming its rules or filters when the entry gives none,
    kept when it gives them (as name=value or as a key of an object); an
    inner-object tool given its object is kept on the image."""
    out, refused = _parse(case, "vol.yarascan CORP-WS01 mnt/CORP-WS01/disk",
                          "tsk.sigfind CORP-WS01 mnt/CORP-WS01/disk",
                          "plaso.plaso_create_targeted CORP-WS01 mnt/CORP-WS01/disk")
    assert out == [] and refused == [
        f"vol.yarascan: needs yara_rules, which {IMG} alone does not give; name it in the entry",
        f"tsk.sigfind: needs signature_hex, which {IMG} alone does not give; name it in the entry",
        f"plaso.plaso_create_targeted: needs artifact_filters, which {IMG} alone does not give; name it in the entry"]
    out, refused = _parse(case, "vol.yarascan CORP-WS01 mnt/CORP-WS01/disk yara_rules=rule a { condition: true }",
                          {"tool": "plaso.plaso_create_targeted", "host": "CORP-WS01", "path": "mnt/CORP-WS01/disk",
                           "artifact_filters": "WindowsEventLogs"},
                          "tsk.istat CORP-WS01 mnt/CORP-WS01/disk inode=200-128-1")
    assert not refused and len(out) == 3 and all(o["target"]["path"] == IMG for o in out)


def test_the_image_named_by_its_case_path_alone_is_held_to_the_same_arguments(case):
    out, refused = _parse(case, f"tsk.istat CORP-WS01 {IMG}", f"strings.strings_extract CORP-WS01 {IMG}")
    assert len(out) == 1 and "strings_extract" in out[0]["tool"] and out[0]["target"]["path"] == IMG
    assert refused == [f"tsk.istat: needs inode, which {IMG} alone does not give; name it in the entry"]


def test_the_image_fills_the_argument_a_ready_call_puts_a_path_in():
    """Which required argument the image fills is the work order's own
    rule (_FILE_PARAMS order, as ready_call places a target's path), not the
    schema's first: a rule scan of a file needs its rule, not its file."""
    schemas = SCHEMAS + [("yara_yara_scan_strings", {"required": ["inline_rule", "file_path"]})]
    with patch("tools.tool_capabilities.registered_tool_schemas", return_value=schemas):
        assert W._missing_arguments("yara_scan_strings", "", set()) == ["inline_rule"]
        assert W._missing_arguments("tsk_istat", "", set()) == ["inode"]
        assert W._missing_arguments("plaso_create_timeline", "", set()) == []
