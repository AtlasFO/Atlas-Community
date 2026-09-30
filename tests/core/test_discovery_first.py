"""Discovery-first path resolution — global architecture tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from core.middleware import _refuse_missing_input_paths
from core.discovery_first import (
    check_and_resolve_input_paths,
    failed_guess_count,
    knowledge_path,
    quarantine_guessed_paths,
    remember_failed_guess,
    try_resolve_missing_path,
)


def test_auto_resolve_unique_sibling(tmp_path: Path):
    parent = tmp_path / "MFTECmd"
    parent.mkdir()
    real = parent / "mft.MFTECmd.timeline.csv"
    real.write_text("a,b\n1,2\n")
    guessed = parent / "MFT.csv"
    info = try_resolve_missing_path(str(guessed), case_dir=tmp_path)
    assert info["resolved"] == str(real)
    assert info["method"] == "sibling_unique"


def test_check_rewrites_unique_sibling(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    parent = tmp_path / "out"
    parent.mkdir()
    real = parent / "USNJRNL.fullPaths.csv"
    real.write_text("x\n")
    args, res = check_and_resolve_input_paths(
        "table_table_query",
        {"path": str(parent / "USNJRNL.csv")},
        case_dir=tmp_path,
    )
    assert args["path"] == str(real)
    assert res and res[0]["method"] == "sibling_unique"


def test_tabular_guess_does_not_resolve_to_raw_mft(tmp_path: Path):
    """A tabular guess (MFT.csv) beside the raw $MFT must not rewrite to $MFT."""
    (tmp_path / ".atlas").mkdir()
    export = tmp_path / "evidence" / "raw_extract" / "HOST-flat.vmdk"
    export.mkdir(parents=True)
    (export / "$MFT").write_bytes(b"\x00" * 64)
    (export / "Windows").mkdir()
    tools = tmp_path / "evidence" / "parsed" / "HOST-flat.vmdk" / "MFTECmd"
    tools.mkdir(parents=True)
    real = tools / "mft.MFTECmd.timeline.csv"
    real.write_text("FileName\nx\n")
    guessed = export / "MFT.csv"
    info = try_resolve_missing_path(str(guessed), case_dir=tmp_path)
    assert info["resolved"] == str(real)
    assert info["method"] in ("parallel_tools", "inventory")
    assert not str(info["resolved"]).endswith("$MFT")


def test_usn_guess_resolves_via_the_sibling_tree(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    export = tmp_path / "evidence" / "raw_extract" / "HOST-flat.vmdk"
    export.mkdir(parents=True)
    (export / "$MFT").write_bytes(b"\x00")
    tools = tmp_path / "evidence" / "parsed" / "HOST-flat.vmdk" / "MFTECmd"
    tools.mkdir(parents=True)
    real = tools / "USN_journal.csv"
    real.write_text("FileName\ny\n")
    guessed = export / "USN_journal.csv"
    info = try_resolve_missing_path(str(guessed), case_dir=tmp_path)
    assert info["resolved"] == str(real)


def test_poisoned_known_mft_csv_to_dollar_mft_ignored(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    export = tmp_path / "evidence" / "raw_extract" / "HOST-flat.vmdk"
    export.mkdir(parents=True)
    raw = export / "$MFT"
    raw.write_bytes(b"\x00")
    tools = tmp_path / "evidence" / "parsed" / "HOST-flat.vmdk" / "MFTECmd"
    tools.mkdir(parents=True)
    real = tools / "mft.MFTECmd.timeline.csv"
    real.write_text("a\n")
    guessed = str(export / "MFT.csv")
    # Simulate prior bug writing incompatible knowledge directly to disk
    kp = knowledge_path(tmp_path)
    kp.write_text(json.dumps({
        "schema_version": "1.0",
        "known_paths": {
            guessed: {"resolved": str(raw), "source": "bug", "at": 0},
        },
        "failed_guesses": {},
        "discovered_dirs": {},
    }) + "\n", encoding="utf-8")
    info = try_resolve_missing_path(guessed, case_dir=tmp_path)
    assert info["resolved"] == str(real)
    assert not str(info["resolved"]).endswith("$MFT")


def test_repeat_guess_blocked(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    parent = tmp_path / "x"
    parent.mkdir()
    # Ambiguous: two similar names → no auto-resolve
    (parent / "a_mft_one.csv").write_text("1\n")
    (parent / "b_mft_two.csv").write_text("2\n")
    missing = str(parent / "MFT.csv")
    with pytest.raises(ValueError) as ei:
        check_and_resolve_input_paths(
            "table_table_query",
            {"path": missing},
            case_dir=tmp_path,
        )
    body = json.loads(str(ei.value))
    assert body["gate"] == "discovery_first"
    assert failed_guess_count(tmp_path, missing) >= 1

    with pytest.raises(ValueError) as ei2:
        check_and_resolve_input_paths(
            "table_table_query",
            {"path": missing},
            case_dir=tmp_path,
        )
    body2 = json.loads(str(ei2.value))
    assert "repeat" in body2["error"].lower() or body2.get("missing")


def test_middleware_protocol_marker(tmp_path: Path):
    parent = tmp_path / "d"
    parent.mkdir()
    (parent / "real_export.csv").write_text("a\n")
    # Ambiguous won't auto-resolve if names don't fuzzy-match MFT
    missing = parent / "TotallyInventedName.csv"
    with pytest.raises(ToolError, match="ATLAS_PROTOCOL|discovery_first|list_evidence"):
        _refuse_missing_input_paths(
            "table_table_query",
            {"path": str(missing)},
        )


def test_quarantine_failed_guesses(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    good = tmp_path / "ok.csv"
    good.write_text("x\n")
    bad = tmp_path / "nope.csv"
    remember_failed_guess(tmp_path, str(bad), hint="invented")
    cleaned = quarantine_guessed_paths(
        [str(good), str(bad), str(tmp_path / "also_missing.csv")],
        tmp_path,
    )
    assert cleaned == [str(good)]


def test_layout_hint_names_a_raw_extract(tmp_path: Path):
    from core.path_hints import format_missing_path_hint
    raw = tmp_path / "evidence" / "raw_extract" / "HOST-flat.vmdk"
    (raw / "Windows").mkdir(parents=True)
    (raw / "Users").mkdir()
    (raw / "$MFT").write_bytes(b"\x00")
    hint = format_missing_path_hint(str(raw / "MFT.csv"))
    assert "raw filesystem extract" in hint and "sibling tree" in hint


def _layout(root: Path, dirs, files=()):
    for d in dirs:
        (root / d).mkdir(parents=True, exist_ok=True)
    for rel, text in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_host_first_layout_never_crosses_to_another_host(tmp_path: Path):
    from core.discovery_first import _parallel_parsed_dirs
    for host in ("WS01", "WS02"):
        _layout(tmp_path, [f"evidence/{host}/Windows/Prefetch", f"evidence/{host}/Users"],
                [(f"evidence/{host}/Windows/Prefetch/CMD.EXE-{host}.pf", "pf")])
    guess = tmp_path / "evidence/WS01/Windows/Prefetch/CMD.EXE-0A1B2C3D.pf"
    assert _parallel_parsed_dirs(str(guess), tmp_path) == []
    assert "WS02" not in str(try_resolve_missing_path(str(guess), case_dir=tmp_path)["resolved"] or "")


def test_the_same_host_name_at_two_sites_never_crosses(tmp_path: Path):
    _layout(tmp_path, ["evidence/SiteA/DC01/logs"],
            [("evidence/SiteB/DC01/logs/Security_logons.csv", "a\n")])
    guess = tmp_path / "evidence/SiteA/DC01/logs/Security_logons.csv"
    assert try_resolve_missing_path(str(guess), case_dir=tmp_path)["resolved"] is None


def test_a_host_without_digits_and_a_drive_folder_resolves(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    _layout(tmp_path, ["evidence/raw/FILESRV/C/Windows", "evidence/raw/FILESRV/C/Users"],
            [("evidence/parsed/FILESRV/MFTECmd/FILESRV_mft.csv", "a\n")])
    info = try_resolve_missing_path(str(tmp_path / "evidence/raw/FILESRV/MFT.csv"), case_dir=tmp_path)
    assert (info["resolved"] or "").endswith("parsed/FILESRV/MFTECmd/FILESRV_mft.csv")


def test_a_symlinked_case_resolves_in_both_path_forms(tmp_path: Path):
    real = tmp_path / "real" / "CASE-A"
    (real / ".atlas").mkdir(parents=True)
    _layout(real, ["evidence/raw_extract/WS01/Windows", "evidence/raw_extract/WS01/Users"],
            [("evidence/raw_extract/WS01/$MFT", "x"),
             ("evidence/parsed/WS01/MFTECmd/WS01_mft.csv", "a\n")])
    (tmp_path / "cases").symlink_to(tmp_path / "real")
    lexical = tmp_path / "cases" / "CASE-A"
    for guess in (lexical / "evidence/raw_extract/WS01/MFT.csv",
                  real / "evidence/raw_extract/WS01/MFT.csv"):
        info = try_resolve_missing_path(str(guess), case_dir=str(lexical))
        assert (info["resolved"] or "").endswith("parsed/WS01/MFTECmd/WS01_mft.csv"), guess


def test_the_parser_tree_comes_first_of_several(tmp_path: Path):
    from core.discovery_first import _parallel_parsed_dirs
    _layout(tmp_path, ["evidence/Raw/WS01/Windows", "evidence/Raw/WS01/Users",
                       "evidence/Memory/WS01", "evidence/Parsed/WS01/MFTECmd"])
    dirs = _parallel_parsed_dirs(str(tmp_path / "evidence/Raw/WS01/Timeline.csv"), tmp_path)
    assert dirs[0].endswith("Parsed/WS01")


def test_no_silent_rewrite_outside_a_parser_folder(tmp_path: Path):
    (tmp_path / ".atlas").mkdir()
    _layout(tmp_path, ["evidence/raw/WS01/Windows", "evidence/raw/WS01/Users"],
            [("evidence/notes/WS01/MFT.csv", "a\n")])
    info = try_resolve_missing_path(str(tmp_path / "evidence/raw/WS01/MFT.csv"), case_dir=tmp_path)
    assert info["resolved"] is None
    assert any(c.endswith("notes/WS01/MFT.csv") for c in info["candidates"])


def test_a_host_shaped_case_id_does_not_favour_every_host():
    from core.discovery_first import _rank_candidate
    guess = "/cases/CASE-2031-001/evidence/raw/WS01/MFT.csv"
    same = "/cases/CASE-2031-001/evidence/parsed/WS01/MFTECmd/WS01_mft.csv"
    other = "/cases/CASE-2031-001/evidence/parsed/WS02/MFTECmd/WS02_mft.csv"
    assert _rank_candidate(guess, same) > _rank_candidate(guess, other)
