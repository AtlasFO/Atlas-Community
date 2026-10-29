"""ATLAS_HIDE_GRADER: the analyst's toolbox never offers the grader (the
ground-truth comparison): it cannot be listed, loaded or called in a run."""
from __future__ import annotations


def test_the_grader_is_not_in_the_analysts_toolbox(monkeypatch):
    from agent.toolbox import Toolbox
    tb = Toolbox()
    assert "accuracy" not in tb.namespaces
    assert not [n for n in tb.tools if n.startswith("accuracy_")]
    assert tb.load_with_budget(["accuracy"])["unknown"] == ["accuracy"]
    from agent.playbook import assemble_playbook
    text = assemble_playbook(include_entry=True)
    assert "ground_truth" not in text and "accuracy_compare" not in text
