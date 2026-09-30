"""Tests for editing staged Brain candidates."""
from __future__ import annotations


def test_edit_updates_proposed_entry(tmp_path, monkeypatch):
    brain = tmp_path / "brain"
    inbox = brain / "inbox/memory-candidates"
    inbox.mkdir(parents=True)
    (brain / "inbox/processed").mkdir(parents=True)
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))
    name = "2026-08-07-test-cand.md"
    (inbox / name).write_text("""---
title: "Old"
type: "memory_candidate"
status: "pending_review"
candidate_type: "workflow"
suggested_destination: "wiki/concepts"
content_hash: "abc"
origin: {case_id: TEST}
risk: {contains_sensitive_data: false, requires_user_approval: true}
---

# Candidate Memory

## Proposed Entry

Old text that is long enough to be a lesson about workflow.

## Why This May Be Useful

Because.
""")
    from core.brain.edit import edit_candidate
    path = edit_candidate(
        name,
        proposed_entry=(
            "Generalized lesson: always correlate Scheduled Tasks with "
            "Prefetch when hunting Windows persistence across cases."),
        title="Scheduled Tasks correlation",
    )
    text = path.read_text()
    assert "Generalized lesson" in text
    assert "Scheduled Tasks correlation" in text
    assert "Old text that is long" not in text
