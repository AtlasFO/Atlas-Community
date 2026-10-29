"""A recorded step that would block or contain a value on published shared
infrastructure is refused once with the mark named; repeated as it is, it is
kept with that value moved to a hunt note (ATLAS_REC_MARKED_VALUES).
Invented fixtures only (CORP-WS01, 198.51.100.x, example.com)."""
from __future__ import annotations

import json

import pytest

from core import shared_infrastructure as S
from core.claim_graph import add_node, add_recommendation, load_graph


@pytest.fixture
def case(tmp_path, monkeypatch):
    # The marked-value check alone (the sighting check is in tests/core/test_ioc_roles_slice2.py).
    monkeypatch.setenv("ATLAS_REC_VALUE_SIGHTING", "0")
    path = tmp_path / "si.json"
    path.write_text(json.dumps({"built": "2031-02-01T00:00:00Z",
                                "edges": [{"label": "Example CDN", "networks": ["198.51.100.0/24"]}],
                                "vendors": {}, "popular": {}}))
    monkeypatch.setattr(S, "PATH", path)
    S._load.cache_clear()
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    c = add_node(d, kind="claim", statement="beacon to 198.51.100.20 and 203.0.113.9", confidence="LIKELY",
                 host="CORP-WS01")
    yield d, c["node_id"]
    S._load.cache_clear()


def _step(d, cid):
    return add_recommendation(d, action="Block 198.51.100.20, 203.0.113.9 at the perimeter", phase="contain",
                              basis_ids=[cid], indicators=["198.51.100.20", "203.0.113.9"])


def test_refused_once_then_kept_with_the_value_moved_to_a_hunt_note(case):
    d, cid = case
    first = _step(d, cid)
    assert first["success"] is False and "198.51.100.20 (shared edge (Example CDN))" in first["error"]
    assert "hunt, never block" in first["error"]
    second = _step(d, cid)
    assert second["success"] is True and second["removed_values"] == ["198.51.100.20"]
    node = load_graph(d)["nodes"][second["node_id"]]
    assert "198.51.100.20" not in node["statement"] and node["indicators"] == ["203.0.113.9"]
    assert "Hunt, never block: 198.51.100.20" in node["reasoning"]


def test_an_investigate_step_and_the_switch_off_are_untouched(case, monkeypatch):
    d, cid = case
    hunt = add_recommendation(d, action="Search the proxy logs for 198.51.100.20", phase="investigate",
                              basis_ids=[cid])
    assert hunt["success"] is True
    monkeypatch.setenv("ATLAS_REC_MARKED_VALUES", "0")
    assert _step(d, cid)["success"] is True


def test_a_value_is_removed_only_as_a_whole_token():
    from core.claim_graph import _without_values
    assert _without_values("Block 198.51.100.20, 198.51.100.2 at the edge.", ["198.51.100.2"]) \
        == "Block 198.51.100.20, at the edge."
    assert _without_values("Block 198.51.100.2.", ["198.51.100.2"]) == "Block."
    assert _without_values("Block cdn.example.com and example.com", ["example.com"]) == "Block cdn.example.com and"
