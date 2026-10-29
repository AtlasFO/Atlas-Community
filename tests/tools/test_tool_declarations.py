"""Item C: a tool declares the media types it reads in its own registration
(``@mcp.tool(meta={"reads": [...]})``), and the readers table is built from
those declarations beside the parameter-declared formats. The availability
marks and the table spell a tool the same way once brought to the listed
name. Invented fixtures only."""
from __future__ import annotations

import re

import pytest

import tools.tool_capabilities as T
from core.coverage_ledger import listed_tool_name


def _schema(*required, extra=()):
    props = {p: {"type": "string"} for p in (*required, *extra)}
    return {"properties": props, "required": list(required)}


STEG = ("steg_steg_extract", _schema("image_path", "output_dir"), "Extract data hidden in a carrier image.",
        {"reads": ["image/jpeg", "image/bmp"]})
EXIF = ("strings_strings_exiftool_metadata", _schema("file_path"), "Extract EXIF and metadata.",
        {"reads": ["image/*", "application/pdf"], "depth": "metadata"})
PDFID = ("misc_pdfid_scan", _schema("pdf_path"), "Quick triage of a PDF file using pdfid.", {"reads": ["application/pdf"]})
HIVE = ("ez_ez_recmd_hive", _schema("hive_path"), "Parse a registry hive.")
GREP = ("strings_strings_grep", _schema("file_path", "pattern"), "Grep a file.")
TOOLS = [STEG, EXIF, PDFID, HIVE, GREP]


@pytest.fixture(autouse=True)
def _installed(monkeypatch):
    monkeypatch.setattr(T, "_not_installed", lambda: set())


def test_a_declared_type_is_a_format_of_the_table_and_a_generic_parameter_alone_is_none():
    table = T.readers_by_format(TOOLS)
    assert table["image/jpeg"] == ["steg.extract"] and table["image/bmp"] == ["steg.extract"]
    assert table["image/*"] == ["strings.exiftool_metadata"]
    assert table["application/pdf"] == ["strings.exiftool_metadata", "misc.pdfid_scan"]    # registration order
    assert next(v for k, v in table.items() if k.startswith("hive")) == ["ez.recmd_hive"]
    assert table["pdf (PDF file)"] == ["misc.pdfid_scan"]
    assert "strings.grep" not in str(table)                        # a generic parameter, no declaration: no format
    assert T.readers_by_format([("steg_steg_extract", _schema("image_path"))]) == {}     # a 2-tuple still works
    assert T.metadata_only(TOOLS) == {"strings.exiftool_metadata"}


def test_an_input_is_routed_by_its_name_and_by_its_content_in_registration_order(tmp_path):
    # By name: a handle inside an image, an export not on disk.
    assert T.readers_for_input("img::C/Users/jane.doe/a.jpg", TOOLS) == ("image/jpeg",
                                                                          ["steg.extract", "strings.exiftool_metadata"])
    assert T.readers_for_input("exports/carve/00002.bmp", TOOLS)[1] == ["steg.extract", "strings.exiftool_metadata"]
    # By content: a JPEG the carver named by number.
    carved = tmp_path / "00001.dat"
    carved.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\0" * 64)
    assert T.readers_for_input(str(carved), TOOLS) == ("image/jpeg", ["steg.extract", "strings.exiftool_metadata"])
    assert T.class_readers(str(carved), TOOLS) == [("steg_extract", False), ("strings_exiftool_metadata", True)]
    # The parameter route decides first: a .pdf goes to the pdf format's parser, the type comes second.
    assert T.readers_for_input("exports/carve/a.pdf", TOOLS)[0] == "pdf (PDF file)"
    renamed = tmp_path / "a.bin"
    renamed.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + b"\0" * 64)
    assert T.readers_for_input(str(renamed), TOOLS) == ("application/pdf", ["strings.exiftool_metadata",
                                                                           "misc.pdfid_scan"])
    assert T.readers_for_input("exports/carve/notes.txt", TOOLS) == ("", [])


def test_the_readers_of_an_extension_come_from_the_type_it_names():
    assert T.declared_readers_for_extension("jpg", TOOLS) == ["steg.extract", "strings.exiftool_metadata"]
    assert T.declared_readers_for_extension("pdf", TOOLS) == ["strings.exiftool_metadata", "misc.pdfid_scan"]
    assert T.declared_readers_for_extension("txt", TOOLS) == [] and T.declared_readers_for_extension("", TOOLS) == []


def test_the_block_keeps_the_format_section_and_adds_one_line_per_reader_set():
    block = T.readers_block(TOOLS)
    head, _, types = block.partition("READERS BY CONTENT TYPE")
    assert head.startswith("READERS BY INPUT FORMAT") and "- hive (registry hive): ez.recmd_hive" in head
    assert "image/" not in head                                   # declared types are not formats
    lines = [ln for ln in types.split("\n") if ln.startswith("- ")]
    assert "- image/bmp, image/jpeg: steg.extract" in lines
    assert "- image/*: strings.exiftool_metadata (metadata only)" in lines
    assert "- application/pdf: strings.exiftool_metadata (metadata only), misc.pdfid_scan" in lines
    assert "a strings pass over such a file is a read of its own" in types


def test_an_availability_mark_is_matched_by_the_listed_name_whatever_its_spelling(monkeypatch):
    # The marks spell a tool ns.<server name>; the table spells it ns.<name>.
    monkeypatch.setattr(T, "_not_installed", lambda: {"steg.steg_extract", "archive.archive_extract_rar"})
    assert not T.is_installed("steg.extract") and not T.is_installed("steg_steg_extract")
    assert T.is_installed("strings.exiftool_metadata")
    assert T.is_installed("ez.pecmd", {"ns:vol"}) and not T.is_installed("vol.pslist", {"ns:vol"})
    assert "steg.extract (not installed)" in T.readers_block(TOOLS)
    assert T.readers_for_input("img::C/a.jpg", TOOLS) == ("image/jpeg", ["strings.exiftool_metadata"])


def test_every_availability_key_names_a_registered_tool_or_namespace():
    """The registry test the marks rest on: a key no listed name resolves
    would mark nothing, and the tool would pass as installed."""
    reg = T.registered_tool_schemas()
    assert reg and len(reg[0]) == 4
    listed = {listed_tool_name(n) for n, *_ in reg}
    namespaces = {n.split("_", 1)[0] for n, *_ in reg}
    keys = [*T.EXTERNAL_BINARIES, *T.EXTERNAL_MODULES, *T.AVAILABILITY_PROBES, *T._manifest_names()]
    unresolved = [k for k in keys if ("." in k and listed_tool_name(k) not in listed)
                  or ("." not in k and k not in namespaces)]
    assert unresolved == []


_TYPE_RE = re.compile(r"^(?:application|text|image|audio|video)/[A-Za-z0-9][\w.+-]*$")


def test_declarations_are_capability_vocabulary_only():
    """Every declared type is a media type (never an extension, a file name
    or a case token), never a generic one, and only image, audio and video
    take a wildcard; a declaring tool takes a file as its first parameter."""
    reg = T.registered_tool_schemas()
    declared = [(n, s, m) for n, s, _d, m in reg if m.get("reads")]
    assert len(declared) >= 15
    for name, schema, meta in declared:
        for t in meta["reads"]:
            assert _TYPE_RE.match(t) or t in ("image/*", "audio/*", "video/*"), (name, t)
            assert t not in ("application/octet-stream", "*/*", "application/*", "text/*", "text/plain"), (name, t)
        assert meta.get("depth") in (None, "metadata"), name
        props = list((schema.get("properties") or {}))
        assert props and re.search(r"(?:^|_)(?:path|file)$", props[0]), (name, props)
        from core.work_order import is_reading_tool
        assert is_reading_tool(name), name


def test_a_spreadsheet_has_its_sheet_readers_and_csv_stays_undeclared():
    assert {"table.schema", "table.query"} <= set(T.declared_readers_for_extension("xlsx"))
    assert {"table.schema", "table.query"} <= set(T.declared_readers_for_extension("xlsm"))
    assert "table.schema" not in T.declared_readers_for_extension("xls")         # openpyxl reads OOXML only
    assert T.declared_readers_for_extension("csv") == [] and T.readers_for_input("exports/x/a.csv") == ("", [])


OFFICE_TOOLS = [
    ("strings_strings_exiftool_metadata", _schema("file_path"), "Metadata.", {"reads": ["image/*", "application/msword"],
                                                                             "depth": "metadata"}),
    ("misc_olevba_scan", _schema("office_path"), "Macros.", {"reads": ["application/msword"]}),
    ("misc_mraptor_scan", _schema("office_path"), "Macro triage.", {"reads": ["application/msword"]}),
    ("table_table_schema", _schema("path"), "Sheet structure.", {"reads": ["application/msword"]}),
    ("table_table_query", _schema("path"), "Sheet rows.", {"reads": ["application/msword"]}),
]


def test_the_class_line_names_one_reader_per_namespace_in_registration_order():
    """A namespace is one toolkit: its second tool is the same way in, so the
    line reaches the third toolkit instead of repeating the second."""
    assert T.class_readers("img::C/Users/jane.doe/a.doc", OFFICE_TOOLS) == [
        ("strings_exiftool_metadata", True), ("misc_olevba_scan", False), ("table_schema", False)]
    assert T.class_readers("img::C/Users/jane.doe/a.doc", OFFICE_TOOLS, limit=2) == [
        ("strings_exiftool_metadata", True), ("misc_olevba_scan", False)]
    assert T.readers_for_input("img::C/Users/jane.doe/a.doc", OFFICE_TOOLS)[1] == [
        "strings.exiftool_metadata", "misc.olevba_scan", "misc.mraptor_scan", "table.schema", "table.query"]


def test_a_reader_set_of_many_types_shows_a_few_and_a_count():
    many = [("misc_olevba_scan", _schema("file_path"), "Macros.",
             {"reads": ["application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                        "application/vnd.ms-word.document.macroEnabled.12"]})]
    (line,) = [ln for ln in T.readers_block(many).split("\n") if ln.startswith("- ")]
    assert line.count("application/") == 4 and " and 2 more types: misc.olevba_scan" in line


FILL_TOOLS = [
    ("archive_tar_extract", _schema("archive_path", "output_dir"), "Extract a tar.", {"reads": ["application/gzip"]}),
    ("archive_gzip_extract", _schema("archive_path", "output_path"), "Decompress gzip.", {"reads": ["application/gzip"]}),
    ("strings_strings_extract_x", _schema("file_path"), "Strings.", {"reads": ["application/gzip"]}),
    ("misc_misc_gz_peek", _schema("file_path"), "Peek.", {"reads": ["application/gzip"]}),
]


def test_the_line_fills_with_the_remaining_readers_in_registration_order_after_one_per_namespace():
    assert T.class_readers("exports/x/a.gz", FILL_TOOLS) == [
        ("archive_tar_extract", False), ("strings_extract_x", False), ("misc_gz_peek", False)]     # one per namespace
    assert T.class_readers("exports/x/a.gz", FILL_TOOLS[:2]) == [
        ("archive_tar_extract", False), ("archive_gzip_extract", False)]                            # then the rest
    assert T.class_readers("exports/x/a.gz", FILL_TOOLS, limit=4)[3] == ("archive_gzip_extract", False)


def test_a_plain_gz_names_both_archive_readers_from_the_registry(monkeypatch):
    names = [n for n, _m in T.class_readers("exports/carve/00001.gz")]
    assert names[:2] == ["archive_tar_extract", "archive_gzip_extract"]


def test_the_vision_reader_declares_every_image_type_and_its_case_switch():
    """images.describe declares image/* (so a gif or a png gains a content
    reader) and the case switch the reader table applies."""
    tools = T.registered_tool_schemas()
    entry = next(e for e in tools if listed_tool_name(e[0]) == "images_describe")
    assert entry[3].get("reads") == ["image/*"] and entry[3].get("case_switch") == "model_vision"
    table = T.readers_by_format(tools)
    assert "images.describe" in table["image/*"]
    assert "images.describe" in T.readers_of_type("image/png", tools, table=table, installed=False)
    assert "images.describe" in T.readers_of_type("image/gif", tools, table=table, installed=False)
