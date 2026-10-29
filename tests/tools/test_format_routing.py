"""ATLAS_FORMAT_READER_ROUTING: a generic text tool over an input whose
format has an installed reader is refused with the readers named, for a
director's or planner's read (check_read) and an analyst's call alike.
Invented fixtures only (CORP-WS04, jane.doe)."""
from __future__ import annotations

import json

import pytest

import tools.tool_capabilities as T

TOOLS = [
    ("ez_ez_recmd_hive", {"properties": {"hive_path": {"type": "string",
                                                       "description": "path to SYSTEM, SOFTWARE, NTUSER.DAT, etc."}},
                          "required": ["hive_path"]}, "Parse a registry hive."),
    ("ez_ez_pecmd", {"properties": {"prefetch_path": {"type": "string"}}, "required": ["prefetch_path"]},
     "Parse Prefetch files."),
]


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    monkeypatch.setattr(T, "_index_class", lambda p: "an artefact")
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: TOOLS)
    monkeypatch.setattr(T, "_not_installed", lambda: set())


def test_a_text_tool_over_a_parsed_format_is_refused_with_its_readers():
    why = T.generic_text_refusal("strings.strings_grep", "C/Windows/System32/config/SYSTEM")
    assert "ez.recmd_hive" in why and "raw text" in why
    assert "ez.pecmd" in T.generic_text_refusal("strings_strings_extract", "C/Windows/Prefetch")
    assert T.generic_text_refusal("strings.strings_grep", "C/Users/jane.doe/notes.txt") == ""
    assert T.generic_text_refusal("strings.hexdump", "C/Windows/System32/config/SYSTEM") == ""


def test_an_uninstalled_reader_routes_nothing(monkeypatch):
    monkeypatch.setattr(T, "_not_installed", lambda: {"ez.recmd_hive", "ez.pecmd"})
    assert T.generic_text_refusal("strings.strings_grep", "C/Windows/System32/config/SYSTEM") == ""


def test_the_analysts_call_meets_the_same_rule(tmp_path):
    from core.input_kind import check_tool_input_kind
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf" + b"\0" * 100)
    with pytest.raises(ValueError) as e:
        check_tool_input_kind("strings_strings_grep", {"file_path": str(hive), "pattern": "x"})
    body = json.loads(str(e.value))
    assert body["gate"] == "wrong_input_kind" and "ez.recmd_hive" in body["use_instead"]


def test_off_nothing_is_routed(monkeypatch):
    monkeypatch.setenv("ATLAS_FORMAT_READER_ROUTING", "0")
    assert T.generic_text_refusal("strings.strings_grep", "C/Windows/System32/config/SYSTEM") == ""


def test_a_proposed_read_is_refused_at_check_read(tmp_path):
    from core.question_plan import check_read
    v, why = check_read(str(tmp_path), {"tool": "strings.strings_grep", "host": "CORP-WS04", "pattern": "x",
                                        "source": "C/Windows/Prefetch"}, {"strings.strings_grep"})
    assert v is None and "ez.pecmd" in why


def test_every_format_reader_is_a_reading_tool_for_the_plan(monkeypatch):
    from core import question_plan as Q
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: TOOLS + [
        ("misc_parse_scheduled_tasks", {"properties": {"tasks_dir": {"type": "string"}},
                                        "required": ["tasks_dir"]}, "Parse scheduled task files.")])
    monkeypatch.setattr("tools.tool_capabilities.tool_capability_manifest", lambda: {"capabilities": []})
    names = {t for t, _p in Q.reading_tools()}
    assert "misc.parse_scheduled_tasks" in names and "ez.pecmd" in names
    v, why = Q.check_read("/nonexistent", {"tool": "misc.parse_scheduled_tasks", "host": "", "source": "x"},
                          names)
    assert "not a reading tool" not in why


def test_a_literal_grep_is_allowed_once_a_reader_ran_on_the_same_input(monkeypatch):
    monkeypatch.setattr(T, "_index_class", lambda p: "registry hives")
    path = "C/Windows/System32/config/SYSTEM"
    monkeypatch.setattr(T, "_reader_ran_on", lambda p, readers: False)
    assert "parse it first" in T.generic_text_refusal("strings.strings_grep", path, pattern="jane.doe")
    monkeypatch.setattr(T, "_reader_ran_on", lambda p, readers: True)
    assert T.generic_text_refusal("strings.strings_grep", path, pattern="jdoe") == ""
    assert T.generic_text_refusal("strings.strings_grep", path, pattern="j.*doe") != ""     # a pattern
    assert T.generic_text_refusal("strings.strings_extract", path) != ""                    # never a strings pass
    assert T.generic_text_refusal("strings.read_text", path, is_text=False) != ""


def test_a_name_routes_only_when_the_index_classes_it_an_artefact(monkeypatch):
    monkeypatch.setattr(T, "_index_class", lambda p: "")
    assert T.readers_for_input("C/Users/jane.doe/Documents/system") == ("", [])
    monkeypatch.setattr(T, "_index_class", lambda p: "registry hives")
    assert T.readers_for_input("C/Windows/System32/config/SYSTEM")[1]


def test_the_image_openers_are_registered_namespaces():
    from agent.toolbox import Toolbox
    from core.evidence_leave import _OPENING_NAMESPACES
    namespaces = {i.namespace for i in Toolbox().tools.values()}
    assert all(ns in namespaces for kinds in _OPENING_NAMESPACES.values() for ns in kinds)
    assert "af" not in _OPENING_NAMESPACES["image"]


def test_any_jsonl_is_plain_text_and_hayabusas_own_output_keeps_its_reader(monkeypatch):
    from core.evidence_leave import readers_for
    from tools.tool_capabilities import readers_by_format
    monkeypatch.undo()                                      # the registry as it is
    table = readers_by_format(T.registered_tool_schemas())
    assert table.get("hayabusa jsonl") == ["hayabusa.summary"] and "jsonl" not in table
    assert T.readers_for_input("exports/corp-ws04-alerts.jsonl") == ("", [])
    assert T.generic_text_refusal("strings.strings_grep", "exports/corp-ws04-alerts.jsonl", pattern="jane") == ""
    assert readers_for("jsonl") and all("strings" in r for r in readers_for("jsonl"))


# -- a declared media type: a strings pass stays a read, a text read of a binary is refused --

MEDIA = TOOLS + [
    ("steg_steg_extract", {"properties": {"image_path": {"type": "string"}, "output_dir": {"type": "string"}},
                           "required": ["image_path", "output_dir"]}, "Extract hidden data.",
     {"reads": ["image/jpeg"]}),
    ("misc_pdfid_scan", {"properties": {"pdf_path": {"type": "string"}}, "required": ["pdf_path"]},
     "Quick triage of a PDF file using pdfid.", {"reads": ["application/pdf"]}),
]


def test_a_text_read_of_a_binary_of_a_declared_type_is_refused_a_strings_pass_is_not(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: MEDIA)
    jpeg = tmp_path / "notes.txt"                                   # a JPEG named as text
    jpeg.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 64)
    why = T.generic_text_refusal("strings.read_text", str(jpeg), is_text=False)
    assert "steg.extract" in why and "strings_extract and strings_grep stay allowed" in why
    assert T.generic_text_refusal("strings.strings_extract", str(jpeg)) == ""
    assert T.generic_text_refusal("strings.strings_grep", str(jpeg), pattern="jane.doe") == ""
    text = tmp_path / "notes.jpg"                                   # text named as an image
    text.write_text("jane.doe logged on\n", encoding="utf-8")
    assert T.generic_text_refusal("strings.read_text", str(text), is_text=True) == ""


def test_a_handle_or_a_planned_read_is_never_refused_by_the_type_rule(monkeypatch):
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: MEDIA)
    handle = "evidence/disk/corp-ws04.raw::C/Users/jane.doe/a.jpg"
    assert T.readers_for_input(handle)[1] == ["steg.extract"]        # the readers are named
    assert T.generic_text_refusal("strings.read_text", handle, is_text=None) == ""
    assert T.generic_text_refusal("strings.read_text", handle, is_text=False) == ""     # not a file here
    from core.input_kind import check_tool_input_kind
    check_tool_input_kind("strings_read_text", {"file_path": handle})                  # no raise


def test_the_parameter_route_decides_before_the_type_route(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "registered_tool_schemas", lambda: MEDIA)
    named = tmp_path / "report.pdf"
    named.write_bytes(b"%PDF-1.4\n" + b"\0" * 64)
    assert "parse it first" in T.generic_text_refusal("strings.strings_extract", str(named))   # pdf: its parser
    renamed = tmp_path / "00007.dat"
    renamed.write_bytes(b"%PDF-1.4\n" + b"\0" * 64)
    assert T.readers_for_input(str(renamed))[0] == "application/pdf"
    assert T.generic_text_refusal("strings.strings_extract", str(renamed)) == ""              # the type: a read
    assert T.generic_text_refusal("strings.read_text", str(renamed), is_text=False) != ""
