"""The coverage path parses a class with a reader that takes the file alone,
found by its listed name whatever spelling the readers table gave it; a
reader that also requires an output folder is skipped. Invented fixtures
only (CASE-A, CORP-WS01)."""
from __future__ import annotations

import pytest

from core import coverage_path as CP


def _schema(*required, extra=()):
    props = {p: {"type": "string"} for p in (*required, *extra)}
    return {"properties": props, "required": list(required)}


REGISTRY = [
    ("steg_steg_extract", _schema("image_path", "output_dir", extra=("passphrase",)), "Extract hidden data.",
     {"reads": ["image/jpeg"]}),
    ("archive_archive_extract_7z", _schema("archive_path", "output_dir"), "Extract a 7z archive.",
     {"reads": ["application/x-7z-compressed"]}),
    ("strings_strings_exiftool_metadata", _schema("file_path"), "Extract metadata.",
     {"reads": ["image/*"], "depth": "metadata"}),
    ("ez_ez_evtxecmd", _schema("evtx_path", extra=("output_dir",)), "Parse event logs."),
]


def test_the_single_input_reader_is_found_by_listed_name_and_a_folder_taking_one_is_skipped():
    assert CP.single_input_reader(["steg.extract", "strings.exiftool_metadata"], REGISTRY) == (
        "strings.exiftool_metadata", "file_path")
    assert CP.single_input_reader(["archive.extract_7z", "ez.evtxecmd"], REGISTRY) == ("ez.evtxecmd", "evtx_path")
    assert CP.single_input_reader(["steg_steg_extract", "archive.archive_extract_7z"], REGISTRY) == ("", "")
    assert CP.single_input_reader([], REGISTRY) == ("", "")


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas"):
        (root / sub).mkdir(parents=True)
    monkeypatch.setattr("core.evidence_leave.unit_format", lambda *a: "jpg")
    monkeypatch.setattr("tools.tool_capabilities._not_installed", lambda: set())
    monkeypatch.setattr("tools.tool_capabilities.registered_tool_schemas", lambda: REGISTRY)
    monkeypatch.setattr("core.contents_index.class_handles", lambda *a, **k: (["CORP-WS01::/a.jpg"], 1))
    monkeypatch.setattr("core.memory_batch.foreground_busy", lambda c: False)
    return root


def test_the_parse_carries_the_readers_own_file_parameter(case, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.readers_for", lambda fmt: ["steg.extract", "strings.exiftool_metadata"])
    calls = []

    class Box:
        def call(self, name, args, budget_free=False):
            calls.append((name, args))
            return '{"rows": [], "_atlas_call_id": 81}', False
    p = CP.parse_class(Box(), case, {"host": "CORP-WS01"}, {"label": "images", "files": 1})
    assert p["reader"] == "strings.exiftool_metadata" and p["parsed"] == 1
    assert calls == [("strings.exiftool_metadata", {"file_path": "CORP-WS01::/a.jpg"})]


def test_a_class_whose_readers_all_need_more_than_the_file_is_reported_not_called(case, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.readers_for", lambda fmt: ["steg.extract", "archive.extract_7z"])
    calls = []

    class Box:
        def call(self, name, args, budget_free=False):
            calls.append((name, args))
            return '{"rows": []}', False
    p = CP.parse_class(Box(), case, {"host": "CORP-WS01"}, {"label": "images", "files": 1})
    assert p["reader"] == "" and "no single-input reader" in p["error"] and "steg.extract" in p["error"]
    assert calls == []


def test_an_uninstalled_reader_is_skipped_by_its_listed_name(case, monkeypatch):
    monkeypatch.setattr("core.evidence_leave.readers_for", lambda fmt: ["strings.exiftool_metadata"])
    monkeypatch.setattr("tools.tool_capabilities._not_installed",
                        lambda: {"strings.strings_exiftool_metadata"})      # the mark's own spelling

    class Box:
        def call(self, name, args, budget_free=False):
            raise AssertionError("no call for an uninstalled reader")
    p = CP.parse_class(Box(), case, {"host": "CORP-WS01"}, {"label": "images", "files": 1})
    assert p["reader"] == "" and "no installed reader" in p["error"]
