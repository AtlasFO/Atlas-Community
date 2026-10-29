"""One reader of what a call read (core.evidence_identity), pinned.

Sites that decide "was this evidence read" from a call's text each grow
their own path grammar (a handle regex here, a copy lookup there, a
prefix test elsewhere), and they disagree. Each site asks
core.evidence_identity (call_reads / identify / the Resolver). This pin
fails when a function on a site's path takes up a path grammar of its own
again, or stops reaching the identity module. A backstop beside the
behaviour tests: a helper reached through a function outside the table
passes it, so the table names every function on each site's path that
touches a call's tokens, callers included."""
from __future__ import annotations

import importlib
import inspect

# The helpers a site could parse a call's text with. A site function
# that names one has a grammar of its own again.
BANNED = (
    "_blob_paths", "_PATH_IN_TEXT", "_CASE_REL_TOKEN", "_paths_mentioned_in_blob", "handle_parts", "copy_map",
    "copies_under", "copy_source", "HANDLE_RE", "_source_images_for", "_any_path_match", "_parsed_args",
    "_reached_inside_images", "_folder_copies_text",
)
# The text rule that stays for an artifact the case cannot name by identity
# (a listing row known by name and inner path, a case file by name; a volume
# file's copy no registration ties to it): reached only through these.
TEXT_RULE_CALLERS = {"_item_read", "_named_in", "_unregistered_copy", "_examined_in_trace"}
# A function reaches the identity module by calling it, by holding its
# resolver, or by reading what call_reads answered (a call's "reads").
REACH = ("evidence_identity", "call_reads", "Resolver", "identify(", "resolver.", '["reads"]', "reads[",
         "view.get(", "reads.get(")

# site -> the functions on its path ("module:function").
SITES: dict[str, list[str]] = {
    "f contents_index sources": [
        "core.contents_index:_build_exports", "core.contents_index:_join_sources",
        "core.contents_index:_named_source", "core.contents_index:_rejoin", "core.contents_index:resolve_source",
        "core.contents_index:register_exports",
    ],
    "a artifact_value reads": [
        "core.artifact_value:_trace_calls", "core.artifact_value:_where", "core.artifact_value:_read_by",
        "core.artifact_value:_first_reads",
        "core.artifact_value:high_value_state_uncached", "core.artifact_value:examined_items",
        "core.artifact_value:reading_calls", "core.artifact_value:_failed_over_folder",
        "core.contents_index:_annotate",
        "core.contents_index:read_state_by_class", "core.contents_index:inside_counts",
    ],
    "e coverage_ledger extracted outputs": [
        "core.coverage_ledger:extracted_outputs",
    ],
    "c coverage_ledger units": [
        "core.coverage_ledger:_entry_view", "core.coverage_ledger:_view_reaches",
        "core.coverage_ledger:_read_attempts", "core.coverage_ledger:_calls_reaching",
        "core.coverage_ledger:_entry_reaches", "core.coverage_ledger:images_read",
        "core.coverage_ledger:_reads_and_failures", "core.coverage_ledger:image_reads",
        "core.coverage_ledger:_block_item", "core.coverage_ledger:rederive_container_coverage",
        "core.coverage_ledger:_misses_at_sector_zero",
        "core.coverage_ledger:observe_tool_paths", "core.coverage_ledger:_live_reads",
        "core.coverage_ledger:mark_paths",
    ],
    "d evidence_items": [
        "core.evidence_items:observe",
    ],
    "b work_order": [
        "core.work_order:_call_view", "core.work_order:_target", "core.work_order:_reach",
        "core.work_order:_hint_reach", "core.work_order:_reaches",
        "core.work_order:_close_by", "core.work_order:close_items_for_call", "core.work_order:reads_of",
        "core.work_order:later_reads", "core.work_order:counted_due", "core.work_order:report_lines",
        "core.work_order:_refused_ready_call", "core.work_order:dispose_work_item",
        "core.work_order:add_work_item", "core.work_order:_cached_view", "agent.loop:Agent._reaches_due_item",
    ],
}
SIX = ("f ", "a ", "e ", "c ", "d ", "b ")
# Where a text in the analyst's own words names paths (a finding, a belief,
# the unit a blocking call names): it names, nothing is read, so the text
# tokenizer stays, outside the table.
PROSE = {"core.coverage_ledger:_prose_view", "core.coverage_ledger:_prose_units",
         "core.coverage_ledger:_mark_named", "core.coverage_ledger:_prose_reaches",
         "core.coverage_ledger:mark_unit_blocked"}


def _fn(ref: str):
    mod, name = ref.split(":")
    obj = importlib.import_module(mod)
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj


def _source(ref: str) -> str:
    src = inspect.getsource(_fn(ref))
    # The docstring may name a helper while explaining what replaced it.
    doc = inspect.getdoc(_fn(ref)) or ""
    return src.replace(doc, "") if doc else src


def test_no_site_function_parses_a_calls_text_itself():
    bad = [(ref, b) for refs in SITES.values() for ref in refs for b in BANNED if b in _source(ref)]
    assert bad == []


def test_every_site_function_reaches_the_identity_module():
    refs = [r for refs in SITES.values() for r in refs]
    reach = {r for r in refs if any(t in _source(r) for t in REACH)}
    grew = True
    while grew:                            # through the table's own functions
        grew = False
        for r in refs:
            if r not in reach and any(o.split(":")[1].split(".")[-1] + "(" in _source(r) for o in reach):
                reach.add(r)
                grew = True
    assert sorted(set(refs) - reach) == []


def test_the_text_rule_is_reached_only_for_what_identity_cannot_name():
    import ast
    import core.artifact_value as av
    tree = ast.parse(inspect.getsource(av))
    callers = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
               for n in ast.walk(f) if isinstance(n, ast.Call) and getattr(n.func, "id", "") in
               ("_examined_in_trace", "_extracted")}
    assert callers <= TEXT_RULE_CALLERS
    src = _source("core.artifact_value:high_value_state_uncached") + _source("core.artifact_value:examined_items")
    assert src.count("_identified(item)") >= 3          # every text use behind the identity test


def test_all_six_reading_sites_are_pinned():
    assert sorted(k[:2] for k in SITES) == sorted(SIX)
    assert all(SITES[k] for k in SITES)
