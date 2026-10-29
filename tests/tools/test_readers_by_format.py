"""ATLAS_READERS_BY_FORMAT: which tool parses which input format is
read from the tools' declared input parameters, not from a list; a tool
registered with a new input parameter changes the block by itself."""
from __future__ import annotations

from tools.tool_capabilities import input_format_param, readers_block, readers_by_format


def _schema(*required, extra=()):
    props = {p: {"type": "string"} for p in (*required, *extra)}
    return {"properties": props, "required": list(required)}


def test_the_format_is_the_declared_input_parameter():
    assert input_format_param(_schema("hive_path", extra=("output_dir",))) == "hive_path"
    assert input_format_param(_schema("file_path", extra=("rules_path",))) == ""      # any file
    assert input_format_param(_schema("hives_dir")) == "hives_dir"
    table = readers_by_format([("ez_ez_recmd_hive", _schema("hive_path")),
                               ("ez_ez_recmd_dir", _schema("hives_dir")),
                               ("strings_strings_grep", _schema("file_path", "pattern"))])
    assert table == {"hive": ["ez.recmd_hive"], "hives (folder)": ["ez.recmd_dir"]}


def test_a_new_input_kind_changes_the_block():
    base = [("ez_ez_pecmd", _schema("prefetch_path"))]
    assert "- widget log:" not in readers_block(base)
    grown = readers_block(base + [("misc_parse_widget_log", _schema("widget_log_path"))])
    assert "- widget log: misc.parse_widget_log" in grown and "- prefetch: ez.pecmd" in grown


def test_the_registry_block_names_formats_not_events(monkeypatch):
    import re
    block = readers_block()
    assert "- hive" in block and "- prefetch:" in block and "strings.grep" not in block
    assert "accuracy." not in block
    assert not re.search(r"\b4\d{3}\b", block)
    monkeypatch.setenv("ATLAS_READERS_BY_FORMAT", "0")
    assert readers_block() == ""


def test_the_grader_rule_writers_and_own_tables_are_no_readers(monkeypatch):
    tools = [("accuracy_accuracy_compare", _schema("ground_truth_path")),
             ("yara_yara_compile_check", _schema("rules_path")),
             ("hash_hashdeep_audit", _schema("manifest_path")),
             ("correlate_mitre_map", _schema("table_path")),
             ("misc_write_final_report", _schema("evidence_csv_path")),
             ("ez_ez_pecmd", _schema("prefetch_path"))]
    assert list(readers_by_format(tools)) == ["prefetch"]


def test_a_reader_whose_program_is_missing_is_marked(monkeypatch):
    import tools.tool_capabilities as T
    monkeypatch.setattr(T, "_not_installed", lambda: {"ez.pecmd"})
    assert "- prefetch: ez.pecmd (not installed)" in readers_block([("ez_ez_pecmd", _schema("prefetch_path"))])


def test_a_short_label_is_glossed_from_its_parameter():
    schema = {"properties": {"j_path": {"type": "string"}}, "required": ["j_path"]}
    table = readers_by_format([("ez_ez_mftecmd_usn", schema,
                                "Parse the journal.\n\nj_path: the NTFS change journal, extracted.")])
    assert list(table) == ["j (NTFS change journal)"]


def test_a_gloss_ends_at_a_phrase_never_mid_phrase():
    def gloss(param, text):
        schema = {"properties": {param: {"type": "string"}}, "required": [param]}
        return list(readers_by_format([("ez_ez_example_reader", schema, f"Parse it.\n\n{param}: {text}")]))[0]

    assert gloss("evt_path", "path to a .evt file or a directory of .evt files") == "evt (.evt file)"
    assert gloss("db_path", "database file to read rows from") == "db (database file)"
    assert gloss("pf_path", "SYSTEM, SOFTWARE, SAM, etc.") == "pf (SYSTEM, SOFTWARE, SAM, etc)"
    assert gloss("ix_path", "the directory index stream, extracted") == "ix (directory index stream)"
    # A leading phrase longer than a gloss gives the label alone, never a cut phrase.
    assert gloss("qz_path", "one very long noun phrase naming seven eight nine items") == "qz"
