"""C2 (ATLAS_TOOL_PARAM_DESCRIPTIONS): a docstring's parameter lines move
into the parameter descriptions, and the tool description stays under the
provider bound, cut at a paragraph or sentence when it must be cut."""
from __future__ import annotations

import re

import pytest

from agent.toolbox import DESCRIPTION_CHARS, model_description


@pytest.fixture(scope="module")
def tools():
    from agent.toolbox import Toolbox
    tb = Toolbox()
    tb.loaded = set(tb.namespaces)
    return tb


def test_every_description_fits_the_bound(tools):
    for info in tools.tools.values():
        body, _schema = model_description(info.description, info.schema)
        assert len(body) <= DESCRIPTION_CHARS, info.listed


def test_the_table_grep_paging_text_reaches_its_parameters(tools):
    info = next(i for i in tools.tools.values() if i.listed == "table_grep")
    body, schema = model_description(info.description, info.schema)
    props = schema["properties"]
    assert "offset=0" in props["offset"]["description"] and "order=\"desc\"" in props["order"]["description"]
    assert "every matching row" in props["output_csv"]["description"]
    assert "one period" in props["time_start"]["description"] and "offset" not in body.split("\n")[0]


def test_output_csv_says_what_it_writes_not_when_to_use_it(tools):
    for name in ("table_query", "table_grep"):
        info = next(i for i in tools.tools.values() if i.listed == name)
        desc = model_description(info.description, info.schema)[1]["properties"]["output_csv"]["description"]
        assert "every matching row" in desc and not re.search(r"\b(use it|when|for a read|exceeds?|beyond)\b", desc, re.I), desc


def test_a_cut_ends_at_a_sentence_and_the_switch_off_cuts_as_before(monkeypatch):
    text = "Intro sentence one. " * 80
    body, _ = model_description(text, {"properties": {}})
    assert len(body) <= DESCRIPTION_CHARS and body.endswith(".")
    monkeypatch.setenv("ATLAS_TOOL_PARAM_DESCRIPTIONS", "0")
    body, schema = model_description("x: y\n" + text, {"properties": {"x": {"type": "string"}}})
    assert len(body) == DESCRIPTION_CHARS and "description" not in schema["properties"]["x"]
