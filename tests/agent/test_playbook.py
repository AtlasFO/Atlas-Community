"""Modular playbook assembly."""
from __future__ import annotations

from agent.playbook import assemble_playbook, load_modules, manifest_names
from agent.prompts import build_system_prompt


def test_manifest_complete():
    names = manifest_names()
    assert names[0].startswith("01_")
    assert "08_reporting.md" in names
    assert "11_gates_reference.md" in names
    assert names[-1].startswith("17_")
    assert len(load_modules()) == len(names)


def test_assemble_contains_core_contracts():
    text = assemble_playbook(include_entry=True)
    assert "Principal DFIR Orchestrator" in text or "primary investigator" in text.lower()
    assert "Case-Question Anchoring" in text
    assert "Distinct-Principal" in text
    assert "Final Report Contract" in text
    assert "write_projected_final_report" in text
    assert "Current Investigation State" in text
    assert "DAIR Phase Director" in text
    assert "mcp_routing" in text
    assert "input_call_ids" in text
    # New architecture note present
    assert "Prompt vs code" in text or "prompt vs code" in text.lower()


def test_build_system_prompt_uses_assembly():
    prompt = build_system_prompt(None)
    assert "ADAPTER" not in prompt  # sanity
    assert "DAIR Phase Director" in prompt
    assert "Final Report Contract" in prompt
    assert len(prompt) > 20000  # full playbook, not thin entry alone
