"""ATLAS_TOOL_ARRAY_STABLE: a provider renders the tool schemas before the
conversation, so the schema array is part of the cached prefix. Namespaces
are listed in the order they were loaded (a new one appended), two requests
with no load between them send the same array, and a preload for the
director never evicts."""
from __future__ import annotations

import json

import pytest


@pytest.fixture(scope="module")
def toolbox():
    from agent.toolbox import Toolbox
    return Toolbox()


def _names(tb):
    return [t["function"]["name"] for t in tb.openai_tools()]


def _ns_order(tb):
    seen = []
    by_name = {(i.listed or i.name): i.namespace for i in tb.tools.values()}
    for n in _names(tb):
        ns = by_name.get(n)
        if ns in tb.loaded and ns not in seen:
            seen.append(ns)
    return seen


def test_a_namespace_loaded_later_is_appended(toolbox, monkeypatch):
    monkeypatch.setattr("agent.toolbox.max_openai_tools", lambda: 10_000)
    tb = toolbox
    tb.loaded.clear()
    tb.load_with_budget(["vol"])
    tb.load_with_budget(["ez"])
    assert _ns_order(tb)[-2:] == ["vol", "ez"]
    first = json.dumps(tb.openai_tools())
    assert json.dumps(tb.openai_tools()) == first        # no load between: the same bytes
    tb.unload(["vol"])
    tb.load_with_budget(["table"])
    assert _ns_order(tb)[-2:] == ["ez", "table"]


def test_a_director_preload_never_evicts(toolbox, monkeypatch):
    tb = toolbox
    tb.loaded.clear()
    cap = max(tb.schema_count({"ez"}), tb.schema_count({"vol"}))
    assert tb.schema_count({"ez", "vol"}) > cap
    monkeypatch.setattr("agent.toolbox.max_openai_tools", lambda: cap)
    tb.load_with_budget(["ez"])
    monkeypatch.setattr(tb, "_use_clock", 100)          # ez is cold: a candidate to make room
    out = tb.load_with_budget(["vol"], evict=False)
    assert tb.loaded == {"ez"} and out["evicted"] == [] and out["refused"]
    out = tb.load_with_budget(["vol"])                    # the model's own load may make room
    assert "vol" in tb.loaded and out["evicted"] == ["ez"]


def test_a_director_preload_never_probes_past_the_ceiling(toolbox, monkeypatch):
    tb = toolbox
    tb.loaded.clear()
    tb._last_probe = None
    cap = tb.schema_count({"ez"})
    monkeypatch.setattr("agent.toolbox.max_openai_tools", lambda: cap)
    tb.load_with_budget(["ez"])
    monkeypatch.setattr(tb, "tool_probe_limit", 10_000)
    out = tb.load_with_budget(["vol"], evict=False)
    assert out["probed"] is None and out["refused"] and tb.loaded == {"ez"}
