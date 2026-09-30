"""Disk+tabular cases must reserve schema budget for tsk openers."""
from __future__ import annotations


def test_suggested_core_puts_tsk_before_ez_when_disk_and_file():
    from tools.evidence_compat import suggested_core_namespaces

    ns = suggested_core_namespaces({
        "present_classes": ["tabular", "disk", "file"],
    })
    assert "tsk" in ns
    assert "img" in ns
    # Opener priority: tsk before ez (ez is large and used to starve tsk).
    assert ns.index("tsk") < ns.index("ez")
    assert ns.index("img") < ns.index("tsk")


def test_the_general_namespace_leads_and_the_optional_core_trails():
    """The reasoning pair and the general namespace pack first, then the
    evidence's own namespaces, then the optional rest of the core: a small
    budget leaves out the tail, never the namespace the playbook's first
    working calls live in."""
    from tools.evidence_compat import suggested_core_namespaces

    ns = suggested_core_namespaces({"present_classes": ["disk", "tabular"]})
    assert ns[:3] == ("reason", "dair", "misc")
    assert ns.index("img") < ns.index("hash")
    assert ns.index("tsk") < ns.index("hash")
    assert ns.index("table") < ns.index("hash")
    assert set(("misc", "hash", "coverage", "brain")) <= set(ns)


def test_a_list_one_over_the_ceiling_loses_its_tail_not_the_general_namespace(monkeypatch):
    """A learned ceiling one schema under the suggested set refuses the
    last suggested namespace; the general one is loaded."""
    import agent.toolbox as toolbox_mod
    from agent.toolbox import Toolbox
    from tools.evidence_compat import suggested_core_namespaces

    suggested = suggested_core_namespaces({"present_classes": ["disk", "tabular"]})
    probe = Toolbox(loaded=())
    full = probe.schema_count(set(suggested))
    monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", full - 1)
    tb = Toolbox(loaded=suggested)
    assert "misc" in tb.loaded
    assert suggested[-1] not in tb.loaded
    assert tb.schema_count() <= full - 1


def test_pack_with_budget_loads_tsk_for_disk_tabular_profile():
    from agent.toolbox import Toolbox, META_TOOLS, MAX_OPENAI_TOOLS
    from tools.evidence_compat import suggested_core_namespaces

    suggested = suggested_core_namespaces({
        "present_classes": ["tabular", "disk", "file"],
    })
    tb = Toolbox(loaded=())
    packed = []
    for ns in suggested:
        trial = set(packed) | {ns}
        count = len(META_TOOLS) + sum(
            tb.namespace_tool_count(n) for n in trial
        )
        if count > MAX_OPENAI_TOOLS:
            continue
        packed.append(ns)
    assert "tsk" in packed, (
        f"tsk must fit after opener-priority packing; got {packed} "
        f"(budget {MAX_OPENAI_TOOLS})"
    )


def test_unload_frees_budget_for_oversize_namespace(monkeypatch):
    import agent.toolbox as toolbox_mod
    from agent.toolbox import Toolbox

    tb = Toolbox(loaded=("misc", "table"))
    # Cap just above current load so tsk (+21) cannot fit until we unload.
    monkeypatch.setattr(
        toolbox_mod, "MAX_OPENAI_TOOLS", tb.schema_count() + 5,
    )
    refused = tb.load_with_budget(["tsk"]).get("refused") or []
    assert refused and refused[0]["namespace"] == "tsk"
    removed = tb.unload(["misc"])
    assert "misc" in removed
    # Raise budget enough for table + tsk (+ meta) after misc is gone.
    monkeypatch.setattr(toolbox_mod, "MAX_OPENAI_TOOLS", 128)
    result = tb.load_with_budget(["tsk"])
    assert "tsk" in (result.get("newly_loaded") or [])
    assert "tsk" in tb.loaded