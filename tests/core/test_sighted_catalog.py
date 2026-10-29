"""The sighted indicator catalogue (ATLAS_IOC_SIGHTED_CATALOG) with
the shared-infrastructure mark: a value stands in the lists where a
tool output that read evidence shows it; what is only named is context.
Invented fixtures only (CORP-WS01, CORP-WS05, jane.doe, 198.51.100.x,
203.0.113.x, dates in 2031)."""
from __future__ import annotations

import csv
import io
import json

import pytest

from core import shared_infrastructure as S
from core.ioc_catalog import build_catalog, render_csv, render_markdown, standing_of


@pytest.fixture(autouse=True)
def _lists(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_IOC_SIGHTED_CATALOG", "1")
    path = tmp_path / "si.json"
    path.write_text(json.dumps({"built": "2031-02-01T00:00:00Z",
                                "edges": [{"label": "Example CDN", "networks": ["198.51.100.0/24"]}],
                                "vendors": {"Example 365 service": ["login.example-vendor.com"]},
                                "popular": {}}))
    monkeypatch.setattr(S, "PATH", path)
    S._load.cache_clear()
    yield
    S._load.cache_clear()


def _sight(call, host="CORP-WS05", cited=True, located=True, first="2031-03-01 08:12:00",
           last="2031-03-09 17:40:00", rows=3, tool="table_table_grep"):
    return {"call": call, "tool": tool, "host": host, "cited": cited, "located": located,
            "first": first, "last": last, "rows": rows}


def _case(tmp_path, nodes, named=None):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True, exist_ok=True)
    (d / "CASE.md").write_text("# Case: CASE-A\n\n**Case ID:** CASE-A\n**System owner:** victim\n", encoding="utf-8")
    graph = {"nodes": {}, "edges": []}
    for i, n in enumerate(nodes, start=1):
        nid = n.pop("id", f"C{i:04d}")
        graph["nodes"][nid] = {"id": nid, "kind": "claim", "status": "new", "confidence": "LIKELY",
                               "host": "CORP-WS05", "input_call_ids": [i], **n}
    (d / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    if named is not None:
        (d / ".atlas" / "prose_sightings.json").write_text(json.dumps({"index_sources": 1, "values": named}))
    return d


def _row(value, kind="domain", side="attacker", sightings=None):
    r = {"type": kind, "value": value, "side": side}
    if sightings is not None:
        r["sightings"] = sightings
    return r


def _by_value(rows):
    return {r["value"]: r for r in rows}


def test_standing_by_the_sightings():
    assert standing_of(None, []) == "unchecked"
    assert standing_of([], []) == "none"
    assert standing_of([_sight(1, located=False)], ["CORP-WS05"]) == "unlocated"
    assert standing_of([_sight(1, cited=True)], []) == "cited"
    assert standing_of([_sight(1, cited=False)], ["CORP-WS05"]) == "same_host"
    assert standing_of([_sight(1, cited=False, host="CORP-WS01")], ["CORP-WS05"]) == "elsewhere"


def test_a_cited_sighting_is_a_block_row_and_its_seen_line_prints(tmp_path):
    d = _case(tmp_path, [{"statement": "The implant beaconed to update-check.example.com",
                          "indicators": [_row("update-check.example.com", sightings=[_sight(412)])]}])
    cat = build_catalog(d)
    row = _by_value(cat["iocs"])["update-check.example.com"]
    assert row["use"] == ["block"] and row["standing"] == "cited"
    md = render_markdown(cat, case_id="CASE-A")
    assert "## Block at the perimeter and resolver" in md
    assert "CORP-WS05 2031-03-01 08:12 to 2031-03-09 17:40 (call 412, 3 rows)" in md


def test_uncited_only_sighting_is_typed_but_not_block(tmp_path):
    d = _case(tmp_path, [{"statement": "Logons came from 203.0.113.44",
                          "indicators": [_row("203.0.113.44", "ip", sightings=[_sight(518, host="CORP-WS01",
                                                                                      cited=False)]),
                                         _row("jane.doe", "account", sightings=[_sight(519, host="CORP-WS01",
                                                                                       cited=False)])]}])
    cat = build_catalog(d)
    rows = _by_value(cat["iocs"])
    assert rows["203.0.113.44"]["standing"] == "elsewhere" and rows["203.0.113.44"]["use"] == ["review"]
    assert rows["jane.doe"]["use"] == ["review", "hunt"]       # contain to review, hunt kept
    md = render_markdown(cat, case_id="CASE-A")
    assert "## Seen elsewhere in this evidence or location unresolved" in md
    assert "(call 518, 3 rows; not cited)" in md


def test_unlocated_sighting_is_typed_but_not_block_or_hunt(tmp_path):
    d = _case(tmp_path, [{"statement": "x", "indicators": [
        _row("evil.example.org", sightings=[_sight(9, host="", located=False)])]}])
    cat = build_catalog(d)
    row = _by_value(cat["review"])["evil.example.org"]
    assert row["use"] == ["review"] and row["role_label"] == "seen, location unresolved"
    assert "evil.example.org" not in render_csv(cat, d)


def test_legacy_rows_without_sightings_stay_listed_as_unchecked(tmp_path):
    d = _case(tmp_path, [{"statement": "x", "indicators": [_row("legacy.example.org")]}])
    cat = build_catalog(d)
    row = _by_value(cat["iocs"])["legacy.example.org"]
    assert row["standing"] == "unchecked" and row["role_label"] == "sighting unchecked"
    md = render_markdown(cat, case_id="CASE-A")
    assert "## Sighting unchecked" in md
    assert "legacy.example.org" not in render_csv(cat, d)


def test_prose_value_without_sighting_goes_to_context_and_a_sighted_one_carries_no_role(tmp_path):
    d = _case(tmp_path, [{"statement": "The attacker downloaded payload from stage.example.org and "
                                       "contacted c2.example.net"}],
              named={"domain|stage.example.org": [_sight(7, cited=False)], "domain|c2.example.net": []})
    cat = build_catalog(d)
    review = _by_value(cat["review"])
    assert review["stage.example.org"]["role_label"] == "not stated" and review["stage.example.org"]["side"] == ""
    assert review["stage.example.org"]["prose_role"]           # the wording's role kept, internal
    assert "c2.example.net" in _by_value(cat["context"])
    assert "c2.example.net" not in render_csv(cat, d)


def test_an_unchecked_prose_value_waits_in_review(tmp_path):
    d = _case(tmp_path, [{"statement": "The attacker contacted c2.example.net"}], named={})
    row = _by_value(build_catalog(d)["review"])["c2.example.net"]
    assert row["standing"] == "unchecked"


def test_recommendation_statements_give_values_never_roles(tmp_path):
    d = _case(tmp_path, [{"id": "R0001", "kind": "recommendation",
                          "statement": "Block stage.example.org and evil.example.net at the proxy"}],
              named={"domain|stage.example.org": [_sight(3)], "domain|evil.example.net": []})
    cat = build_catalog(d)
    row = _by_value(cat["review"])["stage.example.org"]
    assert row["role_label"] == "named, role not stated" and row["side"] == "" and row["role"] != "attacker_infra"
    assert "evil.example.net" in _by_value(cat["context"])


def test_a_presence_refused_row_is_context_with_its_search_status(tmp_path):
    d = _case(tmp_path, [{"statement": "x", "indicators_dropped": [
        {"type": "ip", "value": "203.0.113.9", "reason": "no tool output shows it", "refusal": "presence"},
        {"type": "hash", "value": "abc", "reason": "65 hex characters", "refusal": "shape"}]}])
    (d / ".atlas" / "ioc_pivots.json").write_text(json.dumps(
        {"pivots": {"ip:203.0.113.9": {"origin": "C0001", "targets": {"a.csv": "searched", "b.csv": "pending"}}}}))
    cat = build_catalog(d)
    ctx = _by_value(cat["context"])["203.0.113.9"]
    assert ctx["search_status"] == "1 sources searched, 1 pending"
    assert [r["value"] for r in cat["not_exported"]] == ["abc"]
    assert cat["refused_presence"][0]["value"] == "203.0.113.9"


def test_marked_rows_are_hunt_and_say_the_role_as_stated(tmp_path):
    d = _case(tmp_path, [{"statement": "x", "indicators": [
        _row("198.51.100.20", "ip", sightings=[_sight(377)]),
        _row("login.example-vendor.com", sightings=[_sight(378)])]}])
    cat = build_catalog(d)
    rows = _by_value(cat["iocs"])
    assert rows["198.51.100.20"]["use"] == ["hunt"] and rows["198.51.100.20"]["mark_kind"] == "shared_edge"
    md = render_markdown(cat, case_id="CASE-A")
    assert ("shared edge (Example CDN), role as stated: attacker infrastructure; "
            "block the name, not the address") in md
    assert "vendor service (Example 365 service)" in md
    out = list(csv.DictReader(io.StringIO(render_csv(cat, d))))
    assert {r["value"]: r["mark"] for r in out}["198.51.100.20"] == "shared edge (Example CDN)"


def test_the_fold_merges_sightings(tmp_path):
    d = _case(tmp_path, [
        {"statement": "x", "indicators": [_row("update-check.example.com", sightings=[_sight(412)])]},
        {"statement": "y", "host": "CORP-WS01",
         "indicators": [_row("update-check.example.com", sightings=[_sight(518, host="CORP-WS01")])]}])
    row = _by_value(build_catalog(d)["iocs"])["update-check.example.com"]
    assert [s["call"] for s in row["sightings"]] == [412, 518]
    assert set(row["hosts"]) >= {"CORP-WS05", "CORP-WS01"}


def test_the_csv_carries_only_located_sighted_rows_with_the_new_columns(tmp_path):
    d = _case(tmp_path, [{"statement": "x", "indicators": [
        _row("update-check.example.com", sightings=[_sight(412)]), _row("legacy.example.org")]}])
    rows = list(csv.DictReader(io.StringIO(render_csv(build_catalog(d), d))))
    assert [r["value"] for r in rows] == ["update-check.example.com"]
    assert rows[0]["standing"] == "cited" and rows[0]["sightings"] == "412"
    assert list(rows[0].keys())[:4] == ["use", "side", "type", "value"]


def test_the_report_section_lists_the_block_rows_inline(tmp_path):
    from core.report_assemble import _sighted_indicator_lines
    d = _case(tmp_path, [{"statement": "x", "indicators": [
        _row("update-check.example.com", sightings=[_sight(412)]),
        _row("198.51.100.20", "ip", sightings=[_sight(377)])]}],
        named={})
    lines = _sighted_indicator_lines(build_catalog(d), "en", "case", "")
    text = "\n".join(lines)
    assert "| update-check.example.com | domain |" in text and "198.51.100.20 |" not in text
    assert "1 in published shared infrastructure" in text
    host = "\n".join(_sighted_indicator_lines(build_catalog(d), "en", "host", "CORP-WS09"))
    assert "update-check.example.com" not in host


def test_pivot_seeds_keep_context_and_unchecked_rows(tmp_path, monkeypatch):
    """The sighted lists move rows between lists; the pivot seeds do not
    shrink."""
    from core.ioc_pivots import indicators_from_beliefs
    d = _case(tmp_path, [{"statement": "The attacker contacted c2.example.net and legacy.example.org",
                          "indicators": [_row("legacy.example.org")]}],
              named={"domain|c2.example.net": []})
    seeds_on = indicators_from_beliefs(str(d))
    monkeypatch.setenv("ATLAS_IOC_SIGHTED_CATALOG", "0")
    seeds_off = indicators_from_beliefs(str(d))
    assert seeds_on == seeds_off and any("c2.example.net" in k for k in seeds_on)
    assert any("legacy.example.org" in k for k in seeds_on)


def test_build_catalog_never_writes_the_cache(tmp_path):
    d = _case(tmp_path, [{"statement": "The attacker contacted c2.example.net"}], named={})
    path = d / ".atlas" / "prose_sightings.json"
    before = path.stat().st_mtime_ns
    build_catalog(d)
    assert path.stat().st_mtime_ns == before


def test_refresh_backfills_legacy_rows_and_writes_the_prose_cache(tmp_path, monkeypatch):
    from core import indicators as I
    d = _case(tmp_path, [{"statement": "The attacker contacted c2.example.net",
                          "indicators": [_row("legacy.example.org")]}])
    seen = {"legacy.example.org": [_sight(5)], "c2.example.net": []}
    monkeypatch.setattr(I, "sightings", lambda kind, value, cited, **kw: list(seen.get(value, [])))
    monkeypatch.setattr("core.evidence_index.stats", lambda: {"sources": 3})
    I.refresh_sightings(d, per_turn=None)
    cache = json.loads((d / ".atlas" / "prose_sightings.json").read_text())
    assert cache["values"]["domain|c2.example.net"] == [] and cache["index_sources"] == 3
    node = json.loads((d / ".atlas" / "claim_graph.json").read_text())["nodes"]["C0001"]
    assert node["indicators"][0]["sightings"][0]["call"] == 5
    # A context value is checked again once the index gained sources.
    seen["c2.example.net"] = [_sight(9, cited=False)]
    I.refresh_sightings(d, per_turn=None)
    assert json.loads((d / ".atlas" / "prose_sightings.json").read_text())["values"]["domain|c2.example.net"] == []
    monkeypatch.setattr("core.evidence_index.stats", lambda: {"sources": 4})
    I.refresh_sightings(d, per_turn=None)
    assert json.loads((d / ".atlas" / "prose_sightings.json").read_text())["values"]["domain|c2.example.net"][0]["call"] == 9


def test_a_presence_refused_row_a_later_call_shows_is_review(tmp_path):
    """refresh_sightings re-checks a typed row refused at record time; once a
    call shows it, it is review, seen but refused, its stated role kept as
    prose_role only and never block; the advisory no longer names it."""
    d = _case(tmp_path, [{"statement": "x", "indicators_dropped": [
        {"type": "ip", "value": "203.0.113.9", "reason": "no tool output shows it", "refusal": "presence",
         "side": "attacker"},
        {"type": "ip", "value": "203.0.113.10", "reason": "no tool output shows it", "refusal": "presence"}]}],
        named={"ip|203.0.113.9": [_sight(41, cited=False)], "ip|203.0.113.10": []})
    cat = build_catalog(d)
    row = _by_value(cat["review"])["203.0.113.9"]
    assert row["role_label"] == "seen, refused at record time" and row["use"] == ["review"]
    assert row["prose_role"] == "attacker_infra" and row["role"] != "attacker_infra"
    assert "203.0.113.9" not in _by_value(cat["iocs"]) and "203.0.113.9" not in _by_value(cat["context"])
    assert "203.0.113.10" in _by_value(cat["context"])
    assert [r["value"] for r in cat["refused_presence"]] == ["203.0.113.10"]


def test_named_values_include_presence_refused_rows(tmp_path):
    from core.indicators import named_values
    graph = {"nodes": {"C0001": {"id": "C0001", "kind": "claim", "status": "new", "statement": "x",
                                 "indicators_dropped": [
                                     {"type": "ip", "value": "203.0.113.9", "refusal": "presence"},
                                     {"type": "hash", "value": "abc", "refusal": "shape"}]}}}
    keys = named_values(tmp_path, graph)
    assert "ip|203.0.113.9" in keys and "hash|abc" not in keys


def test_under_the_estate_count_the_status_states_the_tables_counted_only(tmp_path):
    """The estate count fills counts per table and no targets: the column
    says how many tables were counted and how many had rows, never that the
    value was searched for or that no output shows it."""
    d = _case(tmp_path, [{"statement": "x", "indicators_dropped": [
        {"type": "ip", "value": "203.0.113.9", "reason": "no tool output shows it", "refusal": "presence"},
        {"type": "domain", "value": "stage.example.org", "reason": "no tool output shows it",
         "refusal": "presence"},
        {"type": "service", "value": "updsvc", "reason": "no tool output shows it", "refusal": "presence"}]}],
        named={"domain|stage.example.org": []})
    (d / ".atlas" / "ioc_pivots.json").write_text(json.dumps({"pivots": {
        "ip:203.0.113.9": {"origin": "C0001", "targets": {}, "counts": {
            "analysis/evtx/ws05.csv": {"full": 3, "name": 0, "first": "2031-03-01", "last": "2031-03-02"},
            "analysis/evtx/srv02.csv": {"full": 0, "name": 0, "first": "", "last": ""}}},
        "domain:stage.example.org": {"origin": "C0001", "targets": {}, "counts": {
            "analysis/evtx/ws05.csv": {"full": 0, "name": 0, "first": "", "last": ""}}}}}))
    ctx = _by_value(build_catalog(d)["context"])
    assert ctx["203.0.113.9"]["search_status"] == "counted on 2 tables, 1 with rows"
    zero = ctx["stage.example.org"]["search_status"]
    assert zero == "counted on 1 table, 0 with rows"
    assert "searched" not in zero and "no row" not in zero
    assert ctx["updsvc"]["search_status"] == "not counted"
    # A raw-text read shows the value although no counted table has a row:
    # it is seen (review), and the count claims nothing against that.
    (d / ".atlas" / "prose_sightings.json").write_text(json.dumps(
        {"index_sources": 1, "values": {"domain|stage.example.org": [_sight(41, tool="strings_read_text")]}}))
    cat = build_catalog(d)
    assert "stage.example.org" in _by_value(cat["review"])
    assert "stage.example.org" not in _by_value(cat["context"])
