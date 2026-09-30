"""LLM tool-arg coercion against JSON schemas."""
from __future__ import annotations

from core.tool_arg_coerce import coerce_tool_arguments, coerce_value


def test_phase_stack_list_to_json_string():
    prop = {"type": "string", "description": "JSON list"}
    out = coerce_value(
        [{"phase": "Triage", "entry_reason": "start", "depth": 0}],
        prop,
    )
    assert isinstance(out, str)
    assert '"phase": "Triage"' in out or '"phase":"Triage"' in out.replace(" ", "")


def test_columns_string_to_array():
    prop = {"type": "array", "items": {"type": "string"}}
    out = coerce_value('["Timestamp", "DeviceName"]', prop)
    assert out == ["Timestamp", "DeviceName"]


def test_input_call_ids_string_to_int_array():
    prop = {"type": "array", "items": {"type": "integer"}}
    out = coerce_value("[1, 2, 5]", prop)
    assert out == [1, 2, 5]


def test_coerce_tool_arguments_dair_schema():
    schema = {
        "type": "object",
        "properties": {
            "tool_results_summary": {"type": "string"},
            "phase_stack": {"type": "string"},
            "input_call_ids": {
                "type": "array",
                "items": {"type": "integer"},
            },
        },
    }
    args, notes = coerce_tool_arguments(
        {
            "tool_results_summary": "ok",
            "phase_stack": [{"phase": "Triage", "depth": 0}],
            "input_call_ids": "[3]",
        },
        schema,
    )
    assert isinstance(args["phase_stack"], str)
    assert args["input_call_ids"] == [3]
    assert any("phase_stack" in n for n in notes)


def test_a_lone_unknown_keyword_becomes_the_lone_missing_required_one():
    """A guessed parameter name for the one required argument is a renamed
    call, not a different one; the rename is reported so the real name is
    learned. Two unknowns, or two missing, or a type that does not fit, are
    left for the pre-flight to refuse."""
    from core.tool_arg_coerce import coerce_tool_arguments
    schema = {"type": "object",
              "properties": {"evidence_path": {"type": "string"},
                             "force_full": {"type": "boolean"}},
              "required": ["evidence_path"]}
    args, notes = coerce_tool_arguments({"file_path": "evidence/a.vmdk"}, schema)
    assert args == {"evidence_path": "evidence/a.vmdk"}
    assert notes and "file_path renamed to evidence_path" in notes[0]
    args, notes = coerce_tool_arguments({"file_path": 7}, schema)
    assert "file_path" in args and "evidence_path" not in args and not notes
    args, _ = coerce_tool_arguments({"file_path": "x", "other": "y"}, schema)
    assert "evidence_path" not in args
    args, _ = coerce_tool_arguments({"evidence_path": "x", "extra": "y"}, schema)
    assert args == {"evidence_path": "x", "extra": "y"}


def test_a_guess_that_shares_no_word_with_the_parameter_is_not_renamed():
    """``dir`` for a tool whose one required parameter is ``image`` names a
    different thing: renaming it would hand the tool a directory as an
    image and the model an error about a missing image. The call is left
    for the pre-flight refusal, which lists the real parameters. Names
    that share a word (``image`` for ``image_path``, ``paths`` for
    ``path``) are still renamed."""
    from core.tool_arg_coerce import coerce_tool_arguments
    schema = {"type": "object",
              "properties": {"image": {"type": "string"},
                             "recursive": {"type": "boolean"}},
              "required": ["image"]}
    args, notes = coerce_tool_arguments({"dir": "mnt/host/fs/Windows"}, schema)
    assert args == {"dir": "mnt/host/fs/Windows"} and notes == []
    schema = {"type": "object",
              "properties": {"image_path": {"type": "string"}},
              "required": ["image_path"]}
    args, notes = coerce_tool_arguments({"image": "carrier.jpg"}, schema)
    assert args == {"image_path": "carrier.jpg"} and "renamed" in notes[0]
    schema = {"type": "object", "properties": {"path": {"type": "string"}},
              "required": ["path"]}
    args, notes = coerce_tool_arguments({"paths": "a.csv"}, schema)
    assert args == {"path": "a.csv"}


def test_an_underscored_keyword_is_an_annotation_and_is_dropped():
    """A call that carries a note under an underscored name is the call
    without the note; the note's removal is reported, and the remaining
    guessed name still finds the one required parameter."""
    from core.tool_arg_coerce import coerce_tool_arguments
    schema = {"type": "object",
              "properties": {"descriptor_path": {"type": "string"}},
              "required": ["descriptor_path"]}
    args, notes = coerce_tool_arguments(
        {"_note": "chain top", "path": "evidence/a.vmdk"}, schema)
    assert args == {"descriptor_path": "evidence/a.vmdk"}
    assert any("_note dropped" in n for n in notes)
    assert any("path renamed to descriptor_path" in n for n in notes)
    # Atlas's own marker for unparseable arguments is not a note.
    args, notes = coerce_tool_arguments(
        {"_malformed_arguments": "{", "descriptor_path": "x"}, schema)
    assert "_malformed_arguments" in args and notes == []


def test_leave_correct_types_alone():
    schema = {
        "properties": {
            "phase_stack": {"type": "string"},
            "input_call_ids": {"type": "array", "items": {"type": "integer"}},
        }
    }
    args, notes = coerce_tool_arguments(
        {"phase_stack": "[]", "input_call_ids": [1, 2]},
        schema,
    )
    assert args["phase_stack"] == "[]"
    assert args["input_call_ids"] == [1, 2]
    assert notes == []
