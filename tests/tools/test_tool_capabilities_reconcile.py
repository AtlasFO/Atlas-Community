"""Manifest ↔ runtime registry reconciliation."""
from __future__ import annotations

import pytest

from tools.tool_capabilities import (
    allowed_tool_names, reconcile_manifest_with_runtime,
)

# install.sh runs this module after every install (pytest -m install_smoke).
pytestmark = pytest.mark.install_smoke


def test_reconcile_all_manifest_tools_resolve_via_toolbox():
    from agent.toolbox import Toolbox
    tb = Toolbox()
    recon = reconcile_manifest_with_runtime(
        {t.alias for t in tb.tools.values()},
        resolve=tb.resolve,
    )
    assert recon["ok"] is True, recon["missing_from_runtime"]
    assert recon["resolved_count"] == recon["manifest_count"]
    assert recon["manifest_count"] == len(allowed_tool_names())
    # Curated planning vocab is a subset of the full MCP surface.
    assert recon["runtime_alias_count"] > recon["manifest_count"]
    assert recon["count_gap_by_design"] is True


def test_listed_names_never_double_a_namespace_and_never_collide():
    """server.py mounts every module under its namespace, which FastMCP
    prepends to each tool name, and about half the modules already name
    their functions with that namespace, so the MCP names come out as
    ``tsk_tsk_mmls``. The model must never see that form: the list carries
    the playbook's dotted name with an underscore, unique across the whole
    server, and every listed name resolves back to its MCP tool."""
    from agent.toolbox import Toolbox
    tb = Toolbox()
    listed = {}
    for info in tb.tools.values():
        assert info.listed, info.name
        assert not info.listed.startswith(f"{info.namespace}_{info.namespace}_"), info.name
        assert info.listed not in listed, (info.name, listed.get(info.listed))
        listed[info.listed] = info.name
        assert tb.resolve(info.listed) == info.name
        assert tb.listed_name(info.name) == info.listed
    assert len(listed) == len(tb.tools)


def test_control_plane_exists_and_survives_any_budget(monkeypatch):
    """Every control tool is a real tool, the control plane is listed with
    nothing loaded, and a budget under its size still lists all of it."""
    import agent.toolbox as toolbox_mod
    from agent.toolbox import CONTROL_TOOLS, META_TOOLS, Toolbox
    tb = Toolbox(loaded=())
    assert tb.control_names == CONTROL_TOOLS, CONTROL_TOOLS - tb.control_names
    names = [t["function"]["name"] for t in tb.openai_tools()]
    assert set(names) == {t["function"]["name"] for t in META_TOOLS} | CONTROL_TOOLS
    assert len(names) == len(set(names))
    monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 8)
    small = Toolbox()
    listed = [t["function"]["name"] for t in small.openai_tools()]
    assert CONTROL_TOOLS <= set(listed), CONTROL_TOOLS - set(listed)
    assert small.pop_schema_overflow_warning() is None


def test_reconcile_detects_missing_alias():
    recon = reconcile_manifest_with_runtime(
        runtime_aliases={"misc.evtx_filter"},  # deliberately tiny
        resolve=lambda name: name if name == "misc.evtx_filter" else None,
    )
    assert recon["ok"] is False
    assert "reason.synthesize" in recon["missing_from_runtime"]
