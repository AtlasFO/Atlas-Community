"""Tool vocabulary: Hayabusa Sigma triage ships as a core tool
(tools/hayabusa.py), not an addon, the event-log namespaces are suggested
for event logs, and a VMDK is opened with img.vmdk_chain_info."""
from __future__ import annotations


def test_manifest_includes_hayabusa_tools():
    from tools.tool_capabilities import allowed_tool_names
    names = allowed_tool_names()
    assert "hayabusa.triage" in names
    assert "hayabusa.summary" in names


def test_annotate_passes_through_priority_tools():
    from tools.tool_capabilities import annotate_directives_with_manifest

    out = annotate_directives_with_manifest({
        "priority_tools": [
            "table.table_query",
            "img.vmdk_chain_info",
        ],
    })
    assert "table.table_query" in out["priority_tools"]
    assert "img.vmdk_chain_info" in out["priority_tools"]


def test_evidence_compat_suggests_disk_and_eventlog_namespaces():
    from tools.evidence_compat import suggested_core_namespaces

    ns = suggested_core_namespaces({
        "present_classes": ["disk", "tabular", "windows_eventlog"],
    })
    assert "img" in ns or "tsk" in ns
    assert "hayabusa" in ns


def test_mount_plan_vmdk_recommends_chain_info(tmp_path):
    from pathlib import Path
    from core import mount_plan as mp

    entry = mp._classify_image(Path(tmp_path / "disk.vmdk"))
    assert entry.get("recommended_tool") == "img.vmdk_chain_info"


def test_register_plugins_finds_the_bundled_addon(monkeypatch):
    from fastmcp import FastMCP
    from core.plugins import register_plugins
    names = register_plugins(FastMCP("t"))
    assert "timeline_builder" in names
    # hayabusa is a core tool (tools/hayabusa.py), not discovered as a plugin.
    assert "hayabusa" not in names
