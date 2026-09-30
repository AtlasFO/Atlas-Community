import json

import pytest

from core.brain import approve, frontmatter
from core.brain.review_candidates import list_candidates

CANDIDATE = """---
title: "Coverage report every run"
type: "memory_candidate"
created: "2026-07-07 10:58 UTC"
updated: "2026-07-07 10:58 UTC"
status: "pending_review"
source_classification: "internal"
confidence: "medium"
candidate_type: "workflow"
suggested_destination: "{dest}"
content_hash: "abc123"
tags: [agent-run, workflow]
related: []
source: {{type: "agent_run", url: "", description: ""}}
origin: {{case_id: "testcase", run_id: "2026-07-07-1058-testcase-train", command: "train"}}
risk: {{contains_sensitive_data: {sensitive}, contains_answer_key: {answer_key}, requires_user_approval: true}}
entities: {{cases: [testcase], tools: [], techniques: [], actors: [], cves: []}}
---

# Candidate Memory

## Proposed Entry

{body}

## Suggested Action

- approve / edit / reject
"""


def _write_candidate(brain, name="cand.md", dest="wiki/concepts",
                     sensitive="false", answer_key="false",
                     body="Run coverage_report every run."):
    p = brain / "inbox/memory-candidates" / name
    p.write_text(CANDIDATE.format(dest=dest, sensitive=sensitive,
                                  answer_key=answer_key, body=body))
    return p


def test_approve_creates_note_and_processes(brain):
    p = _write_candidate(brain)
    dest = approve.approve(p, yes=True)
    assert dest.parent == brain / "wiki/concepts"
    assert "coverage_report" in dest.read_text()
    assert not p.exists()
    assert (brain / "inbox/processed" / "cand.md").is_file()
    assert list_candidates() == []
    # indexes were rebuilt and include the new note
    assert "Coverage report every run" in \
        (brain / "indexes" / "topic-index.md").read_text()


def test_approve_preserves_created_and_origin(brain):
    p = _write_candidate(brain)
    dest = approve.approve(p, yes=True)
    meta, _, _ = frontmatter.parse(dest.read_text())
    # creation time and run attribution survive promotion so the globe's
    # growth replay places the note in the run that earned it
    assert meta["created"] == "2026-07-07 10:58 UTC"
    assert meta["origin"]["run_id"] == "2026-07-07-1058-testcase-train"
    assert meta["origin"]["case_id"] == "testcase"


def test_approve_appends_to_existing_file(brain):
    target = brain / "wiki/cases/testcase.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("---\ntitle: testcase\ntype: case\n---\n\n# testcase\n")
    p = _write_candidate(brain, dest="wiki/cases/testcase.md",
                         body="F1 improved to 0.8.")
    approve.approve(p, yes=True)
    text = target.read_text()
    assert "F1 improved to 0.8." in text and "## From cand.md" in text


def test_approve_refuses_secrets(brain):
    p = _write_candidate(brain, body="use password=hunter22")
    with pytest.raises(approve.ApproveError, match="secret-like"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_refuses_sensitive_flag(brain):
    p = _write_candidate(brain, sensitive="true")
    with pytest.raises(approve.ApproveError, match="contains_sensitive_data"):
        approve.approve(p, yes=True)


def test_approve_refuses_answer_key_flag(brain):
    # capture stamps this marker when it scrubs a ground-truth secret.
    p = _write_candidate(brain, answer_key="true",
                         body="The archive was decrypted [REDACTED:answer_key].")
    with pytest.raises(approve.ApproveError, match="contains_answer_key"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_rescans_against_ground_truth(brain, tmp_path, monkeypatch):
    # A hand-authored / pre-guard candidate can quote the answer key verbatim
    # with no marker; approve re-derives the case's secrets and refuses it.
    # (exampleuser=examplesecret31 is not a recognized secret *pattern*, so the
    # generic secrets scan lets it through — the ground-truth rescan is what
    # catches it.)
    cases = tmp_path / "cases"
    (cases / "testcase").mkdir(parents=True)
    (cases / "testcase" / "ground_truth.json").write_text(json.dumps({
        "case_id": "testcase",
        "secrets": ["exampleuser=examplesecret31"],
    }))
    monkeypatch.setenv("ATLAS_CASES_ROOT", str(cases))
    p = _write_candidate(
        brain, body="The AES key exampleuser=examplesecret31 unlocks the payload.")
    with pytest.raises(approve.ApproveError, match="ground-truth answer key"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_refuses_escape(brain):
    p = _write_candidate(brain, dest="../../etc")
    with pytest.raises(approve.ApproveError, match="escapes the brain"):
        approve.approve(p, yes=True)


ENV_CANDIDATE = """---
title: "ACME AD baseline"
type: "memory_candidate"
created: "2026-07-07 10:58 UTC"
updated: "2026-07-07 10:58 UTC"
status: "pending_review"
source_classification: "internal"
confidence: "medium"
candidate_type: "workflow"
suggested_destination: "wiki/environments/acme-corp"
content_hash: "def456"
client: "{client}"
last_verified: "{last_verified}"
tags: [acme-corp]
related: []
source: {{type: "{source_type}", url: "", description: ""}}
origin: {{case_id: "", run_id: "", command: ""}}
risk: {{contains_sensitive_data: false, contains_answer_key: false, requires_user_approval: true}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# ACME AD baseline

## Proposed Entry

{body}
"""


def _write_env_candidate(brain, name="env-cand.md", client="acme-corp",
                         last_verified="2026-07-01",
                         source_type="client_provided",
                         body="DC01/DC02 are the domain controllers; admins "
                              "connect via JUMP01."):
    p = brain / "inbox/memory-candidates" / name
    p.write_text(ENV_CANDIDATE.format(client=client,
                                      last_verified=last_verified,
                                      source_type=source_type, body=body))
    return p


def test_approve_environment_clean_baseline(brain):
    p = _write_env_candidate(brain)
    dest = approve.approve(p, yes=True)
    assert dest.parent == brain / "wiki/environments/acme-corp"
    assert "JUMP01" in dest.read_text()


def test_approve_environment_refuses_agent_run_source(brain):
    p = _write_env_candidate(brain, source_type="agent_run")
    with pytest.raises(approve.ApproveError, match="agent_run"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_environment_refuses_verdict_language(brain):
    p = _write_env_candidate(
        brain, body="Host FS01 was compromised by the attacker's C2 server.")
    with pytest.raises(approve.ApproveError,
                       match="verdict language.*(compromised|attacker|c2)"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_environment_refuses_missing_client_and_date(brain):
    p = _write_env_candidate(brain, client="", last_verified="")
    with pytest.raises(approve.ApproveError, match="client"):
        approve.approve(p, yes=True)


def test_approve_environment_still_scans_secrets(brain):
    p = _write_env_candidate(brain, body="jump host uses password=hunter22")
    with pytest.raises(approve.ApproveError, match="secret-like"):
        approve.approve(p, yes=True)


def test_approve_refuses_ioc_into_public_wiki(brain):
    # A raw IOC must never reach the published wiki concepts/techniques/tools.
    p = _write_candidate(brain, dest="wiki/concepts",
                         body="Block C2 traffic to 203.0.113.9 at the firewall.")
    with pytest.raises(approve.ApproveError, match="identifier"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_refuses_case_specific_into_public_wiki(brain):
    # Case-specific to-do/logistics content is not a generalized lesson.
    p = _write_candidate(
        brain, dest="wiki/techniques",
        body="Follow up with the operator on the next run to confirm the "
             "encryption deadline.")
    with pytest.raises(approve.ApproveError, match="logistics"):
        approve.approve(p, yes=True)
    assert p.exists()


def test_approve_allows_ioc_into_internal_case_page(brain):
    # wiki/cases is internal (private remote only, never published), so a per-case note
    # may legitimately carry IOCs — the public-boundary gate must NOT apply.
    p = _write_candidate(brain, dest="wiki/cases/testcase.md",
                         body="Attacker beaconed to 203.0.113.9 during the run.")
    dest = approve.approve(p, yes=True)
    assert "203.0.113.9" in dest.read_text()
    assert not p.exists()


def test_list_candidates_filters(brain):
    _write_candidate(brain, name="a.md")
    _write_candidate(brain, name="b.md", sensitive="true")
    assert len(list_candidates()) == 2
    assert len(list_candidates(risk_only=True)) == 1
    assert len(list_candidates(candidate_type="workflow")) == 2
    assert list_candidates(candidate_type="decision") == []
