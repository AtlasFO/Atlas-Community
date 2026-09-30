"""Input-path existence gate (middleware) — TOOL-BADARGS class."""
from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from core.middleware import _refuse_missing_input_paths


def test_refuse_missing_directory():
    with pytest.raises(ToolError, match="do not exist"):
        _refuse_missing_input_paths(
            "hash_hash_directory",
            {"directory": "/nonexistent/validation/probe/path"},
        )


def test_accept_existing_directory(tmp_path):
    _refuse_missing_input_paths(
        "hash_hash_directory",
        {"directory": str(tmp_path)},
    )


def test_missing_path_mentions_siblings(tmp_path):
    parent = tmp_path / "dir"
    parent.mkdir()
    (parent / "real_timeline.csv").write_text("a\n", encoding="utf-8")
    with pytest.raises(ToolError) as ei:
        _refuse_missing_input_paths(
            "table_table_query",
            {"path": str(parent / "MFT.csv")},
        )
    assert "real_timeline.csv" in str(ei.value)
    assert "list_evidence_dir" in str(ei.value)


def test_ignore_non_path_content_fields():
    # finding_text / command_line are content, not INPUT_PATH_PARAM_NAMES
    _refuse_missing_input_paths(
        "correlate_mitre_map",
        {"finding_text": "/nonexistent/validation/probe/path"},
    )


def test_hash_directory_refused_via_toolbox(tmp_path):
    """End-to-end: middleware must refuse before empty-success body runs."""
    from agent.toolbox import Toolbox
    import json
    tb = Toolbox()
    tb.load(["hash"], force=True)
    text, _ = tb.call(
        "hash.hash_directory",
        {"directory": "/nonexistent/validation/probe/path"},
    )
    assert "refused" in text.lower() or "do not exist" in text.lower() or text.startswith("ERROR")
    # Must NOT be a success=True empty dict
    if text.strip().startswith("{"):
        out = json.loads(text.strip().split("\n", 1)[-1] if text.startswith("[") else text)
        assert out.get("success") is not True
