"""The set of tools whose output is the run's own state rather than
evidence is declared once (core.forensic_citation.own_words_entry) and read
by every gate that treats tool output as evidence. This pins the
declaration to the registered servers, so a tool added to a control-plane
namespace is covered and a misc tool is classified when it is written."""
from __future__ import annotations

import asyncio
import importlib

import pytest

from core.forensic_citation import citation_class, external_lookup_entry, own_words_entry


def _tool_names(module: str) -> list[str]:
    mcp = importlib.import_module(module).mcp
    return sorted(t.name for t in asyncio.run(mcp.list_tools()))


def _entry(namespace: str, tool: str) -> dict:
    # The middleware records a call as ``<py>:<mounted name>``, the mounted
    # name being the server's namespace prefix and the function name.
    return {"type": "tool_call", "cmd": f"<py>:{namespace}_{tool}"}


# Servers whose every tool reads the trace, the claim graph or the ledgers.
CONTROL_PLANE = {
    "tools.claim_tools": "claim",
    "tools.reasoning": "reason",
    "tools.dair": "dair",
    "tools.coverage": "coverage",
    "tools.accuracy": "accuracy",
    "tools.export_tools": "export",
    "tools.brain_tools": "brain",
    "tools.jobs": "job",
    "tools.correlate": "correlate",
    "tools.respond": "respond",
}

# Servers whose every tool reads evidence.
EVIDENCE = {
    "tools.volatility": "vol",
    "tools.sleuthkit": "tsk",
    "tools.tabular": "table",
    "tools.network": "net",
    "tools.strings_tools": "strings",
    "tools.search_tools": "search",
    "tools.hashing": "hash",
    "tools.evt": "evt",
    "tools.eztools": "ez",
}

# Servers whose every tool asks an outside source about a value.
EXTERNAL_LOOKUP = {
    "tools.enrichment": "enrich",
}
# Single tools of an evidence server whose output lists the values they
# were asked about (the threat-context sweep): cited for nothing.
LOOKUP_TOOLS = {("tools.search_tools", "intel_sweep")}

# misc mixes parsers with bookkeeping: every tool is named on one side.
MISC_OWN_WORDS = {
    "start_execution_log", "record_curiosity_probe", "record_finding",
    "record_self_correction", "export_execution_log",
    "current_investigation_state", "update_investigation_task",
    "supersede_investigation_task", "list_investigation_tasks",
    "write_projected_final_report", "write_final_report", "write_case_document",
    "record_agent_message", "clear_case_run", "launch_dashboard",
    "serve_dashboard", "symlink_evidence", "knowns_pattern_generate",
}
MISC_EVIDENCE = {
    "evtx_dump", "evtx_filter", "analyzemft_parse", "mft_rule_hunt",
    "regripper_hive", "regripper_list_plugins", "usnparser_parse",
    "hindsight_chrome", "clamscan_file", "clamscan_directory",
    "device_install_inventory", "parse_scheduled_tasks", "pdfid_scan",
    "pdf_parser_analyze", "pe_scanner", "pe_carver", "pff_export",
    "readpst_extract", "parse_email", "parse_msg_ole", "parse_emlx",
    "densityscout_scan", "chainsaw_hunt", "capa_analyze", "olevba_scan",
    "mraptor_scan", "list_evidence_dir", "inventory_evidence", "batch_run",
    "onedrive_odl",
}


@pytest.mark.parametrize("module,namespace", sorted(CONTROL_PLANE.items()))
def test_every_control_plane_tool_is_the_runs_own_words(module, namespace):
    names = _tool_names(module)
    assert names, module
    missed = [n for n in names if not own_words_entry(_entry(namespace, n))]
    assert missed == []


@pytest.mark.parametrize("module,namespace", sorted(EVIDENCE.items()))
def test_no_evidence_tool_is_mistaken_for_the_runs_own_words(module, namespace):
    names = _tool_names(module)
    assert names, module
    wrong = [n for n in names if own_words_entry(_entry(namespace, n))]
    assert wrong == []


def test_every_misc_tool_is_classified():
    names = set(_tool_names("tools.misc"))
    unclassified = names - MISC_OWN_WORDS - MISC_EVIDENCE
    assert unclassified == set(), (
        "classify each new misc tool here and, if it is bookkeeping, in "
        "core.forensic_citation._OWN_WORDS_CMD_PREFIXES")
    assert [n for n in sorted(MISC_OWN_WORDS & names)
            if not own_words_entry(_entry("misc", n))] == []
    assert [n for n in sorted(MISC_EVIDENCE & names)
            if own_words_entry(_entry("misc", n))] == []


def test_the_analysts_own_entries_and_shell_commands_are_classified():
    assert own_words_entry({"type": "reason_call"})
    assert own_words_entry({"type": "finding"})
    assert not own_words_entry({"type": "tool_call", "cmd": "strings -a evidence/x.bin"})
    assert not own_words_entry({"type": "tool_call", "cmd": "<py>:unknown_new_tool"})


@pytest.mark.parametrize("module,namespace", sorted(EXTERNAL_LOOKUP.items()))
def test_every_outside_lookup_is_classed_as_one(module, namespace):
    names = _tool_names(module)
    assert names, module
    assert [n for n in names if citation_class(_entry(namespace, n)) != "external_lookup"] == []


def test_every_registered_tool_sits_in_exactly_one_class():
    servers = {**CONTROL_PLANE, **EVIDENCE, **EXTERNAL_LOOKUP, "tools.misc": "misc"}
    want = {**{m: "own_words" for m in CONTROL_PLANE}, **{m: "evidence" for m in EVIDENCE},
            **{m: "external_lookup" for m in EXTERNAL_LOOKUP}}
    for module, namespace in servers.items():
        for n in _tool_names(module):
            e = _entry(namespace, n)
            classes = [own_words_entry(e), external_lookup_entry(e),
                       not own_words_entry(e) and not external_lookup_entry(e)]
            assert sum(classes) == 1, (module, n)
            if (module, n) in LOOKUP_TOOLS:
                assert citation_class(e) == "external_lookup", (module, n)
            elif module in want:
                assert citation_class(e) == want[module], (module, n)
