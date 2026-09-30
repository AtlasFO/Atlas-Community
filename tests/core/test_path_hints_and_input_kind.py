"""Path hints, prefer-parsed input gates, profile drift."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from core.middleware import _refuse_missing_input_paths
from core.path_hints import format_missing_path_hint, enrich_missing_paths_message
from core.input_kind import refuse_preparsed_hive, refuse_preparsed_evtx, FAILURE_CLASS
from core.evidence_profile import (
    classify_path,
    ensure_evidence_profile,
    save_profile,
    build_evidence_profile,
)


def test_sibling_hint_on_missing_mft(tmp_path: Path):
    parent = tmp_path / "MFTECmd"
    parent.mkdir()
    real = parent / "mft.MFTECmd.timeline.csv"
    real.write_text("a,b\n", encoding="utf-8")
    guessed = parent / "MFT.csv"
    hint = format_missing_path_hint(str(guessed))
    assert "mft.MFTECmd.timeline.csv" in hint
    assert "list_evidence_dir" in hint


def test_refuse_missing_includes_sibling_recovery(tmp_path: Path):
    parent = tmp_path / "FileSystem"
    parent.mkdir()
    (parent / "USNJRNL.fullPaths.csv").write_text("x", encoding="utf-8")
    missing = parent / "USNJRNL.csv"
    # Unique fuzzy sibling → auto-resolve (no raise)
    rewritten = _refuse_missing_input_paths(
        "table_table_query",
        {"path": str(missing)},
    )
    assert rewritten["path"].endswith("USNJRNL.fullPaths.csv")


def test_layout_hint_parser_folder_inside_raw_extract(tmp_path: Path):
    # A parser output folder guessed inside a raw filesystem extract gets a
    # redirect even when its parent does not exist.
    path = tmp_path / "evidence" / "raw_extract" / "host" / "Windows" / "MFTECmd" / "MFT.csv"
    msg = enrich_missing_paths_message([f"path={str(path)!r}"])
    assert "Parser output folders do not sit inside a raw filesystem extract" in msg


def test_refuse_regripper_txt(tmp_path: Path):
    p = tmp_path / "SYSTEM.regripper.txt"
    p.write_text("RegRipper output…\n", encoding="utf-8")
    bad = refuse_preparsed_hive(str(p))
    assert bad and bad["success"] is False
    assert bad["failure_class"] == FAILURE_CLASS
    assert "table" in bad["error"].lower()


def test_refuse_hive_without_regf(tmp_path: Path):
    p = tmp_path / "SYSTEM"
    p.write_text("not a hive", encoding="utf-8")
    bad = refuse_preparsed_hive(str(p))
    assert bad and bad["failure_class"] == FAILURE_CLASS


def test_accept_regf_hive(tmp_path: Path):
    p = tmp_path / "SYSTEM"
    p.write_bytes(b"regf" + b"\x00" * 32)
    assert refuse_preparsed_hive(str(p)) is None


def test_missing_hive_path_refuses_not_fail_open(tmp_path):
    missing = tmp_path / "no_such_Amcache.hve"
    bad = refuse_preparsed_hive(str(missing))
    assert bad is not None
    assert bad.get("success") is False
    assert bad.get("failure_class") in (FAILURE_CLASS, "missing_input")


def test_refuse_evtx_csv(tmp_path: Path):
    p = tmp_path / "all-evtx.csv"
    p.write_text("RecordNumber,TimeCreated\n", encoding="utf-8")
    bad = refuse_preparsed_evtx(str(p))
    assert bad and bad["failure_class"] == FAILURE_CLASS
    assert "table" in bad["error"].lower()


def test_defender_bin_not_disk(tmp_path: Path):
    p = tmp_path / "evidence" / "Windows Defender" / "Support" / "foo.bin"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"x")
    assert classify_path(p) == "file"


def test_top_level_raw_is_disk(tmp_path: Path):
    p = tmp_path / "evidence" / "disk.raw"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"x")
    assert classify_path(p) == "disk"


def test_profile_refresh_on_catalog_newer(tmp_path: Path):
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    (ev / "a.csv").write_text("x,y\n", encoding="utf-8")
    p1 = ensure_evidence_profile(case, refresh=True)
    assert "tabular" in (p1.get("present_classes") or [])
    # Simulate stale profile + newer catalog
    atlas = case / ".atlas"
    atlas.mkdir(exist_ok=True)
    cat = atlas / "evidence_catalog.json"
    cat.write_text('{"units": {"u1": {}}, "schema_version": "1.0"}\n', encoding="utf-8")
    # Make catalog newer than profile
    time.sleep(0.05)
    cat.write_text(
        '{"units": {"u1": {}, "u2": {}}, "schema_version": "1.0"}\n',
        encoding="utf-8",
    )
    (ev / "b.evtx").write_bytes(b"ElfFile" + b"\x00" * 8)
    # Without explicit refresh, drift should rebuild
    p2 = ensure_evidence_profile(case, refresh=False)
    assert p2.get("file_count", 0) >= 2


@pytest.mark.parametrize("path", [
    "/mnt/c/Users/me/cases/CASE-A/analysis/table_out.csv",
    "/Users/me/cases/CASE-A/analysis/x.csv",
])
def test_no_layout_hint_outside_the_evidence_tree(path):
    assert "raw filesystem extract" not in format_missing_path_hint(path)


def test_parser_folder_names_count_as_tokens_not_inside_words():
    from core.path_hints import PARSER_DIR_RE
    assert PARSER_DIR_RE.search("evidence/p/WS01/MFTECmd_Output/x.csv")
    assert PARSER_DIR_RE.search("evidence/p/2031-02_MFTECmd/x.csv")
    assert not PARSER_DIR_RE.search("evidence/overlays/x.csv")
