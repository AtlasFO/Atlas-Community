"""An unpacked Office Open XML package's own wiring (ECMA-376 Part 2, Open
Packaging Conventions: the content-types stream and relationships parts with
no external target) is no class to read (core.coverage_ledger
._package_structure, the package_structure leave). The stream only names
candidates; each is checked to be what it claims. Invented package parts
written from the public format only (CORP-WS01, jane.doe, example.com)."""
from __future__ import annotations

import json

import pytest

from core import coverage_ledger as cl
from core.execution_log import ExecutionLog

UNIT = "exports/report_docx"
REL_TYPE = "application/vnd.openxmlformats-package.relationships+xml"
TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _types(*overrides, dtd=""):
    over = "".join(f'<Override PartName="{p}" ContentType="{t}"/>' for p, t in overrides)
    return (f'<?xml version="1.0" encoding="UTF-8"?>{dtd}<Types xmlns="{TYPES_NS}">'
            f'<Default Extension="rels" ContentType="{REL_TYPE}"/><Default Extension="xml" ContentType="application/xml"/>'
            f'<Default Extension="png" ContentType="image/png"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            f'{over}</Types>')


def _rels(*targets):
    body = "".join(f'<Relationship Id="rId{i}" Type="{DOC_REL}/{kind}" Target="{t}"'
                   + (' TargetMode="External"' if ext else "") + "/>"
                   for i, (kind, t, ext) in enumerate(targets, 1))
    return f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{RELS_NS}">{body}</Relationships>'


PARTS = {
    "[Content_Types].xml": _types(),
    "_rels/.rels": _rels(("officeDocument", "word/document.xml", False)),
    "word/document.xml": "<w:document xmlns:w='urn:example'><w:body>jane.doe notes</w:body></w:document>",
    "word/_rels/document.xml.rels": _rels(("image", "media/image1.png", False)),
    "word/media/image1.png": "\x89PNG-invented",
}


@pytest.fixture
def unit(tmp_path, monkeypatch):
    root = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", ".atlas", UNIT):
        (root / sub).mkdir(parents=True)
    (root / "evidence" / "report.docx").write_bytes(b"PK")
    log = ExecutionLog()
    log.configure("CASE-A", str(root / "analysis" / "CASE-A_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    from core.provenance import reset_cache
    reset_cache()

    def write(parts):
        for rel, text in parts.items():
            p = root / UNIT / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(text, bytes):
                p.write_bytes(text)
            else:
                p.write_text(text, encoding="utf-8")
        made = log.record_tool_call(f"7z x -o{root}/{UNIT} evidence/report.docx", True, False, 0, 0)
        log.annotate_tool_call(made, mcp_tool="archive_zip_extract")
        (root / ".atlas" / "output_provenance.json").write_text(json.dumps({"files": {
            f"{UNIT}/{n}": {"call": made, "class": "derived"} for n in parts}}), encoding="utf-8")
        assert cl.register_derived_outputs(root, tool_name="archive_zip_extract",
                                           arguments={"archive_path": "evidence/report.docx", "output_dir": UNIT},
                                           result_text='{"success": true}') == [UNIT]
        (out,) = cl.extracted_outputs(root)
        return out
    return root, log, write


def _read(log, rel):
    cid = log.record_tool_call("<py>:strings_read_text", True, False, 0, 0, stdout_excerpt="x")
    log.annotate_tool_call(cid, args=json.dumps({"file_path": f"{UNIT}/{rel}"}), mcp_tool="strings_read_text")


def test_the_wiring_is_left_and_the_content_stays_with_the_stream_never_offered(unit):
    _root, _log, write = unit
    out = write(PARTS)
    assert {k: v["kind"] for k, v in out["left"].items()} == {"rels": "package_structure",
                                                              "no extension": "package_structure"}
    assert out["open"] == ["xml", "png"]
    assert out["sample"]["xml"] == f"{UNIT}/word/document.xml"           # never the content-types stream


def test_a_read_of_the_stream_reads_no_content_of_its_class(unit):
    _root, log, write = unit
    write(PARTS)
    _read(log, "[Content_Types].xml")
    (out,) = cl.extracted_outputs(unit[0])
    assert "xml" in out["open"] and out["classes"]["xml"] == [1, 2]


def test_an_external_relationship_stays_content_and_is_the_offered_file(unit):
    _root, log, write = unit
    parts = {**PARTS, "word/_rels/settings.xml.rels": _rels(
        ("attachedTemplate", "https://templates.example.com/corp-ws01.dotm", True))}
    out = write(parts)
    assert "rels" in out["open"] and "rels" not in out["left"]
    assert out["sample"]["rels"] == f"{UNIT}/word/_rels/settings.xml.rels"
    assert out["left"]["no extension"]["kind"] == "package_structure"
    # a read of an internal-only part does not read the external one
    _read(log, "word/_rels/document.xml.rels")
    (out,) = cl.extracted_outputs(unit[0])
    assert "rels" in out["open"] and out["sample"]["rels"].endswith("settings.xml.rels")
    _read(log, "word/_rels/settings.xml.rels")
    (out,) = cl.extracted_outputs(unit[0])
    assert "rels" not in out["open"]


def test_a_part_declared_as_relationships_that_is_none_is_left_open(unit):
    _root, _log, write = unit
    parts = {**PARTS, "[Content_Types].xml": _types(("/word/vbaProject.bin", REL_TYPE), ("/word/props.cfg", REL_TYPE)),
             "word/vbaProject.bin": "\xd0\xcf\x11\xe0 invented blob",
             "word/props.cfg": '<Props xmlns="urn:example"/>'}                # well-formed, another root
    out = write(parts)
    assert {"bin", "cfg"} <= set(out["open"]) and not {"bin", "cfg"} & set(out["left"])


def test_a_rels_part_that_is_no_relationships_document_is_left_open(unit):
    _root, _log, write = unit
    out = write({**PARTS, "word/_rels/document.xml.rels": "<Relationships><Relationship Target='media/image1.png'/>"
                                                         "</Relationships>"})
    assert "rels" in out["open"]


def test_a_dtd_in_the_stream_or_a_part_leaves_nothing(unit):
    _root, _log, write = unit
    dtd = '<!DOCTYPE Types [<!ENTITY a "x">]>'
    out = write({**PARTS, "[Content_Types].xml": _types(dtd=dtd)})
    assert out["left"] == {} and {"rels", "no extension"} <= set(out["open"])



def test_a_wide_encoded_stream_is_refused_also_with_a_declaration_the_byte_search_cannot_see(unit):
    _root, _log, write = unit
    stream = _types(dtd='<!DOCTYPE Types [<!ENTITY a "x">]>').replace('encoding="UTF-8"', 'encoding="UTF-16"')
    out = write({**PARTS, "[Content_Types].xml": stream.encode("utf-16")})
    assert out["left"] == {} and {"rels", "no extension"} <= set(out["open"])


def test_a_part_with_a_nul_or_a_wide_byte_order_mark_is_no_package_part(tmp_path):
    good = _rels(("image", "media/image1.png", False))
    wide = good.replace("UTF-8", "UTF-16")
    for name, data in (("utf8.rels", good.encode()), ("utf16.rels", wide.encode("utf-16")),
                       ("utf16-no-mark.rels", wide.encode("utf-16-le")), ("utf32.rels", wide.encode("utf-32")),
                       ("nul.rels", good.encode().replace(b"<Relationship ", b"<Relationship \x00", 1))):
        (tmp_path / name).write_bytes(data)
        got = cl._opc_part(str(tmp_path / name), "Relationships", RELS_NS, cl._opc_internal_only)
        assert bool(got) is (name == "utf8.rels"), name

def test_a_dtd_in_a_relationships_part_keeps_it_open(unit):
    _root, _log, write = unit
    bad = _rels(("image", "media/image1.png", False)).replace("<Relationships", '<!DOCTYPE r [<!ENTITY a "x">]><Relationships', 1)
    out = write({**PARTS, "word/_rels/document.xml.rels": bad})
    assert "rels" in out["open"]


def test_an_oversized_part_is_not_read_as_wiring(unit):
    _root, _log, write = unit
    big = _rels(*[("image", f"media/image{i}.png", False) for i in range(1, 900)])
    assert len(big) > cl._OPC_MAX_BYTES
    out = write({**PARTS, "word/_rels/document.xml.rels": big})
    assert "rels" in out["open"]


def test_without_a_stream_nothing_is_left(unit):
    _root, _log, write = unit
    loose = {k: v for k, v in PARTS.items() if k != "[Content_Types].xml"}
    out = write(loose)
    assert out["left"] == {} and "rels" in out["open"]


def test_a_package_nested_below_the_unit(unit):
    _root, _log, write = unit
    out = write({f"inner/report/{k}": v for k, v in PARTS.items()} | {"inner/notes.rels": _rels()})
    # the package's own parts are left; a .rels beside it, outside any package, is not
    assert out["left"]["no extension"]["kind"] == "package_structure"
    assert "rels" in out["open"] and out["sample"]["rels"] == f"{UNIT}/inner/notes.rels"


def test_an_attacker_entity_in_a_parts_name_still_blocks_the_leave(unit, monkeypatch):
    _root, _log, write = unit
    from core import evidence_leave
    monkeypatch.setattr(evidence_leave, "attacker_entities", lambda c: ["document.xml.rels"])
    out = write(PARTS)
    assert "rels" in out["open"] and out["left"]["no extension"]["kind"] == "package_structure"
