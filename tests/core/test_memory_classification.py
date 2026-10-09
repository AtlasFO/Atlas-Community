"""A raw image is judged by its first sectors and by the kind the analyst
declared, not by its name: a memory format is memory wherever it lies, a
user-mode minidump is a file, a partition table or a boot block is a disk,
and a shallow raw image with no signature at all may be either, so both tool
families stay open on it."""
import json
import os
import time

import pytest

from core.artifact_kind import head_signature
from core.evidence_profile import (
    _profile_is_stale, build_evidence_profile, classify_path, ensure_evidence_profile,
    path_classes,
)


def _mbr() -> bytes:
    head = bytearray(4096)
    head[446] = 0x80          # bootable
    head[446 + 4] = 0x07      # NTFS / exFAT partition type
    head[510:512] = b"\x55\xaa"
    return bytes(head)


def _with(prefix: bytes, size: int = 4096) -> bytes:
    return prefix + b"\x00" * (size - len(prefix))


def _elf(e_type: int) -> bytes:
    head = bytearray(64)
    head[:4] = b"\x7fELF"
    head[4], head[5] = 2, 1   # 64-bit, little-endian
    head[16:18] = e_type.to_bytes(2, "little")
    return _with(bytes(head))


def _ext(block_exponent: int) -> bytes:
    head = bytearray(4096)
    head[1048:1052] = block_exponent.to_bytes(4, "little")
    head[1080:1082] = b"\x53\xef"
    return bytes(head)


@pytest.mark.parametrize("data, expect", [
    (_mbr(), "disk"),
    (_with(b"PAGEDU64"), "memory"),
    (_with(b"PAGEDUMP"), "memory"),
    (_with(b"EMiL"), "memory"),
    (_with(b"hibr"), "memory"),
    (_elf(4), "memory"),
    (_elf(2), ""),
    (_with(b"MDMP"), "minidump"),
    (_ext(2), "disk"),
    (_ext(40), ""),
    (_with(b"vhdxfile"), "disk"),
    (b"\x00" * 4096, ""),
])
def test_the_head_of_a_file_says_what_it_holds(tmp_path, data, expect):
    p = tmp_path / "CORP-WS01.raw"
    p.write_bytes(data)
    assert head_signature(p) == expect


def test_a_fixed_vhd_is_known_by_its_footer(tmp_path):
    p = tmp_path / "CORP-DC01.img"
    p.write_bytes(b"\x00" * 8192 + b"conectix" + b"\x00" * 504)
    assert head_signature(p) == "disk"


def _case(tmp_path, files: dict[str, bytes], links: str = ""):
    case = tmp_path / "CASE-A"
    for rel, data in files.items():
        p = case / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (case / ".atlas").mkdir(parents=True, exist_ok=True)
    if links:
        (case / "CASE.md").write_text("# CASE-A\n\n## Evidence Links\n\n"
                                      "| Label | Kind | Path | Notes |\n"
                                      "|-------|------|------|-------|\n" + links,
                                      encoding="utf-8")
    return case


def test_a_raw_image_with_no_signature_opens_both_tool_families(tmp_path):
    from core.evidence_inventory_gate import build_processing_assessment
    from tools.evidence_compat import check_tool_against_profile
    case = _case(tmp_path, {"evidence/CORP-WS01-memory.img": b"\x00" * 8192})
    p = case / "evidence" / "CORP-WS01-memory.img"
    assert path_classes(p) == ("disk", "memory") and classify_path(p) == "disk"
    profile = build_evidence_profile(case)
    assert {"disk", "memory"} <= set(profile["present_classes"])
    assert profile["ambiguous"] == ["evidence/CORP-WS01-memory.img"]
    assert check_tool_against_profile("vol_windows_pslist", profile) is None
    assert check_tool_against_profile("tsk_fls", profile) is None
    a = build_processing_assessment(
        present=profile["present_classes"], absent=profile["absent_classes"],
        counts=profile["counts"], high_value_parsed=[], samples_by_class=profile["samples"],
        ambiguous=profile["ambiguous"])
    assert not any(x["class"] == "memory" for x in a["skip"])
    memory = next(x for x in a["needs_processing"] if x["class"] == "memory")
    assert "no recognised disk or memory signature" in memory["reason"]
    assert "CORP-WS01-memory.img" in memory["reason"]


def test_signatures_settle_disk_memory_and_minidump(tmp_path):
    case = _case(tmp_path, {
        "evidence/CORP-DC01.img": _mbr(),
        "evidence/CORP-WS02/memory/ram.raw": _with(b"PAGEDU64"),
        "evidence/CORP-WS03/C/Windows/MEMORY.DMP": _with(b"PAGEDU64"),
        "evidence/CORP-WS04/C/Windows/MEMORY.DMP": b"x" * 64,
        "evidence/CORP-WS05/C/hiberfil.sys": _with(b"hibr"),
        "evidence/CORP-WS06/C/ProgramData/Microsoft/Windows/WER/app.dmp": _with(b"MDMP"),
        "evidence/CORP-WS07/C/ProgramData/Microsoft/Windows Defender/Support/a.bin": _with(b"PAGEDU64"),
    })
    ev = case / "evidence"
    assert path_classes(ev / "CORP-DC01.img") == ("disk",)
    assert classify_path(ev / "CORP-WS02/memory/ram.raw") == "memory"
    assert classify_path(ev / "CORP-WS03/C/Windows/MEMORY.DMP") == "memory"
    assert classify_path(ev / "CORP-WS04/C/Windows/MEMORY.DMP") == "file"
    assert classify_path(ev / "CORP-WS05/C/hiberfil.sys") == "memory"
    assert classify_path(ev / "CORP-WS06/C/ProgramData/Microsoft/Windows/WER/app.dmp") == "file"
    # Program data in a collected tree is never read as an image.
    assert classify_path(ev / "CORP-WS07/C/ProgramData/Microsoft/Windows Defender/Support/a.bin") == "file"


def test_a_declared_kind_wins_and_a_folder_row_declares_nothing(tmp_path):
    case = _case(tmp_path, {"evidence/CORP-WS01.img": _mbr(),
                            "evidence/CORP-WS02.img": _mbr()},
                 links="| CORP-WS01 | memory | evidence/CORP-WS01.img | RAM capture |\n"
                       "| exports | tabular | evidence/ | case-root exports |\n")
    profile = build_evidence_profile(case)
    classes = {f["path"]: f["class"] for f in profile["files"]}
    assert classes == {"evidence/CORP-WS01.img": "memory", "evidence/CORP-WS02.img": "disk"}


def test_an_edit_of_the_brief_makes_the_profile_stale(tmp_path):
    case = _case(tmp_path, {"evidence/CORP-WS01.img": _mbr()},
                 links="| CORP-WS01 | disk | evidence/CORP-WS01.img | |\n")
    profile = ensure_evidence_profile(case, refresh=True)
    assert not _profile_is_stale(case, profile)
    later = time.time() + 5
    os.utime(case / "CASE.md", (later, later))
    assert _profile_is_stale(case, profile)
    old = dict(profile, schema_version="1.0")
    os.utime(case / "CASE.md", (0, 0))
    assert _profile_is_stale(case, old)


def test_a_memory_image_stays_out_of_the_disk_access_plan(tmp_path):
    from core.mount_plan import build_mount_plan
    case = _case(tmp_path, {"evidence/CORP-WS01.raw": _with(b"PAGEDU64")})
    ensure_evidence_profile(case, refresh=True)
    assert build_mount_plan(case, persist=True, auto_mount=False)["images"] == []
    unread = _case(tmp_path / "other", {"evidence/CORP-WS02.raw": b"\x00" * 4096})
    ensure_evidence_profile(unread, refresh=True)
    plan = build_mount_plan(unread, persist=True, auto_mount=False)
    assert [i["basename"] for i in plan["images"]] == ["CORP-WS02.raw"]
    assert json.loads(json.dumps(plan))  # the plan stays serialisable
