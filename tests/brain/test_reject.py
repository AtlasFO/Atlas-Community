import pytest

from core.brain import frontmatter, reject
from core.brain.capture import _content_hash, _existing_hashes
from core.brain.review_candidates import list_candidates

CANDIDATE = """---
title: "Re-check the D partition next run"
type: "memory_candidate"
created: "2026-07-07"
updated: "2026-07-07"
status: "pending_review"
source_classification: "internal"
confidence: "medium"
candidate_type: "workflow"
suggested_destination: "wiki/concepts"
content_hash: "{hash}"
tags: [agent-run, workflow]
related: []
source: {{type: "agent_run", url: "", description: ""}}
origin: {{case_id: "testcase"}}
risk: {{contains_sensitive_data: false, requires_user_approval: true}}
entities: {{cases: [testcase], tools: [], techniques: [], actors: [], cves: []}}
---

# Candidate Memory

## Proposed Entry

{body}

## Suggested Action

- approve / edit / reject
"""

BODY = "Re-run the carve on the D partition before Friday."


def _write_candidate(brain, name="cand.md", body=BODY):
    p = brain / "inbox/memory-candidates" / name
    p.write_text(CANDIDATE.format(hash=_content_hash(body), body=body))
    return p


def test_reject_archives_with_reason(brain):
    p = _write_candidate(brain)
    dest = reject.reject(p, "case-specific to-do, not durable memory",
                         yes=True)
    assert not p.exists()
    assert dest == brain / "inbox/processed" / "cand.md"
    meta, body, _ = frontmatter.parse(dest.read_text())
    assert meta["status"] == "rejected"
    assert "## Review Decision" in body
    assert "case-specific to-do" in body
    assert list_candidates() == []


def test_reject_preserves_dedup_hash(brain):
    """A rejected candidate must keep blocking re-staging of the same text."""
    p = _write_candidate(brain)
    before = _existing_hashes(brain)
    reject.reject(p, "junk", yes=True)
    after = _existing_hashes(brain)
    assert before == after
    assert _content_hash(BODY) in after, \
        "processed candidate must still contribute its content hash"


def test_reject_requires_reason(brain):
    p = _write_candidate(brain)
    with pytest.raises(reject.RejectError, match="reason is required"):
        reject.reject(p, "   ", yes=True)
    assert p.exists()


def test_reject_missing_candidate(brain):
    with pytest.raises(reject.RejectError, match="not found"):
        reject.reject(brain / "inbox/memory-candidates/nope.md", "x", yes=True)


def test_reject_cli_main(brain, capsys):
    p = _write_candidate(brain, name="cli.md")
    rc = reject.main([str(p), "--reason", "redundant with CASE.md", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Rejected ->" in out
    assert (brain / "inbox/processed" / "cli.md").is_file()
