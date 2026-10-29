"""tools.media_types: the pinned extension table (no host mime database),
the content route through libmagic (any of a family's spellings, never one
assumed), the matcher and the fail-open. Invented fixtures only."""
from __future__ import annotations

import inspect
import struct
import sys

from tools import media_types as MT


def test_the_name_route_is_pinned_and_reads_no_host_database():
    assert "mimetypes" not in inspect.getsource(MT)
    assert MT.name_type("exports/carve/00001.jpg") == "image/jpeg"
    assert MT.name_type("C/Users/jane.doe/report.DOCX") == MT.OFFICE[7]
    assert MT.name_type("svc_kit.exe") == MT.PE[0] and MT.name_type("tool.7z") == MT.SEVEN_ZIP[0]
    assert MT.name_type("a.rar") == MT.RAR[0] and MT.name_type("a.tgz") == MT.GZIP[0]
    assert MT.name_type("payload.dat") == "" and MT.name_type(".bashrc") == "" and MT.name_type("") == ""


def _file(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_the_content_route_types_real_headers_within_their_family(tmp_path):
    jpeg = _file(tmp_path, "00001.dat", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 64)
    assert MT.content_type(jpeg) == "image/jpeg" and MT.candidates(jpeg) == ["image/jpeg"]
    pdf = _file(tmp_path, "00002.bin", b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + b"\0" * 64)
    assert MT.matches(MT.PDF, MT.candidates(pdf))
    zipped = _file(tmp_path, "00003", b"PK\x03\x04" + b"\0" * 64)
    assert MT.matches(MT.ZIP, MT.candidates(zipped))
    ole = _file(tmp_path, "00004.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 512)
    assert MT.matches(MT.OFFICE, [MT.content_type(ole)])             # a generic container spelling
    assert MT.candidates(ole)[-1] == "application/msword"             # and the name beside it
    pe = _file(tmp_path, "00005.bin", b"MZ" + b"\0" * 58 + struct.pack("<I", 64) + b"PE\0\0\x4c\x01" + b"\0" * 64)
    assert MT.matches(MT.PE, MT.candidates(pe))
    # Not on disk: the name alone.
    assert MT.candidates("img::C/Users/jane.doe/a.jpg") == ["image/jpeg"]
    assert MT.candidates("img::C/Windows/x.bin") == []


def test_the_matcher_takes_exact_types_and_top_level_wildcards():
    assert MT.matches(["image/jpeg"], ["image/jpeg"]) and not MT.matches(["image/jpeg"], ["image/png"])
    assert MT.matches(["image/*"], ["image/png"]) and not MT.matches(["image/*"], ["application/pdf"])
    assert MT.matches(MT.RAR, ["application/x-rar"]) and MT.matches(MT.GZIP, ["application/x-gzip"])
    assert not MT.matches([], ["image/jpeg"]) and not MT.matches(["image/jpeg"], [])


def test_every_family_spelling_shows_as_its_first_member():
    for fam in (MT.JPEG, MT.BMP, MT.PE, MT.RAR, MT.GZIP, MT.JAVASCRIPT, MT.OLE_GENERIC):
        assert {MT.CANONICAL[s] for s in fam} == {fam[0]}
    assert "application/x-ole-storage" not in MT.CANONICAL or MT.CANONICAL["application/CDFV2"] == MT.OLE_GENERIC[0]
    assert MT.CANONICAL.get("application/pdf", "application/pdf") == "application/pdf"


def test_without_libmagic_the_name_route_stands_and_the_warning_is_said_once(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "magic", None)             # import magic raises ImportError
    monkeypatch.setattr(MT, "_MAGIC_WARNED", False)
    jpeg = _file(tmp_path, "a.jpg", b"\xff\xd8\xff\xe0" + b"\0" * 64)
    assert MT.content_type(jpeg) == "" and MT.candidates(jpeg) == ["image/jpeg"]
    assert MT.content_type(jpeg) == ""
    assert capsys.readouterr().err.count("libmagic is not available") == 1
