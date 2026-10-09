"""Tests for investigation Brain learning (quality gates, digest, staging)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def brain_case(tmp_path, monkeypatch):
    brain = tmp_path / "brain"
    for d in ("inbox/memory-candidates", "inbox/processed", "logs/runs",
              "wiki/concepts", "wiki/tools", "wiki/techniques", "memory"):
        (brain / d).mkdir(parents=True)
    (brain / "AGENTS.md").write_text("# brain\n")
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))

    case = tmp_path / "CASE1"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "reports").mkdir()
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
        "schema_version": "1.0",
        "case_id": "CASE1",
        "nodes": {
            "C1": {"kind": "claim", "status": "new",
                   "summary": "Malware used Scheduled Tasks for persistence"},
        },
        "edges": [],
    }))
    (case / "analysis" / "CASE1_trace.json").write_text(json.dumps({
        "entries": [
            {"type": "finding", "confidence": "LIKELY",
             "title": "Suspicious schtasks creation"},
            {"type": "self_correction", "trigger": "wrong_tool",
             "prior_belief": "used strings", "new_belief": "used evtx"},
        ],
    }))
    (case / "reports" / "CASE1_run_review.md").write_text(
        "VERDICT: ACCEPTABLE\n\n## Recommendations\n\n"
        "- Prefer EvtxECmd over raw strings for Windows event logs.\n")
    return {"brain": brain, "case": case}


def test_digest_leaves_out_the_analysts_context(brain_case):
    """The estate's hosts and accounts the brief names are no cross-case
    lesson: the learner never sees them."""
    from core.brain.learn import build_investigation_digest
    (brain_case["case"] / ".atlas" / "investigation_memory.json").write_text(json.dumps({
        "analyst_context": [{"id": "ac-0001", "status": "active",
                             "text": "10.0.0.5 is our admin jump host CORP-JUMP01."}],
        "open_questions": ["What persisted?"],
    }))
    dig = build_investigation_digest(brain_case["case"], "CASE1", question="What persisted?")
    assert "CORP-JUMP01" not in dig and "analyst_context" not in dig
    assert "open_questions" in dig


def test_digest_includes_claims_and_review(brain_case):
    from core.brain.learn import build_investigation_digest
    dig = build_investigation_digest(
        brain_case["case"], "CASE1", question="What persisted?",
        review_text="VERDICT: ACCEPTABLE\n## Recommendations\n- x\n",
        verdict="ACCEPTABLE")
    assert "Claim graph" in dig
    assert "Scheduled Tasks" in dig
    assert "Independent run review" in dig


def test_quality_drops_ioc_lesson(brain_case):
    from core.brain import capture
    from core.brain.learn import _passes_quality
    lesson = {
        "title": "Host WIN-ABC had malware",
        "body": ("The host WIN-FOO01 at 10.0.0.5 showed persistence via "
                 "a specific customer ticket next run follow up."),
        "knowledge_kind": "knowledge_gained",
        "candidate_type": "workflow",
        "suggested_destination": "wiki/concepts",
        "confidence": "high",
        "why_exists": "x",
        "origin_sources": ["claim_graph"],
        "supporting_evidence": "",
        "why_reusable": "y",
    }
    ok, reason = _passes_quality(lesson, set(), [])
    assert ok is False
    assert reason in ("identifiers", "likely_case_specific", "case_residue",
                      "body_too_short", "trivial_or_case_bound",
                      "confidence_below_floor")


def test_quality_drops_medium_and_trivial(brain_case):
    from core.brain.learn import _passes_quality
    medium = {
        "title": "Maybe useful tip",
        "body": (
            "When investigating Windows persistence, enumerating Scheduled "
            "Tasks early and correlating task actions with Prefetch is often "
            "worthwhile across many cases and families."),
        "knowledge_kind": "knowledge_gained",
        "candidate_type": "technique_insight",
        "suggested_destination": "wiki/techniques",
        "confidence": "medium",
        "why_exists": "seen in digest",
        "origin_sources": ["claim_graph"],
        "supporting_evidence": "C1",
        "why_reusable": "Applies to any Windows intrusion case with persistence.",
    }
    ok, reason = _passes_quality(medium, set(), [])
    assert ok is False
    assert reason == "confidence_below_floor"

    trivial = dict(medium)
    trivial["confidence"] = "high"
    trivial["body"] = "Always use --json when calling the tool for neat output."
    trivial["title"] = "Prefer --json"
    ok2, reason2 = _passes_quality(trivial, set(), [])
    assert ok2 is False
    assert reason2 in ("trivial_or_case_bound", "body_too_short")


def test_learn_stages_from_mock_llm(brain_case):
    from core.brain.learn import learn_from_investigation

    class Resp:
        content = json.dumps({
            "lessons": [{
                "title": "Scheduled Tasks are a common persistence pivot",
                "body": (
                    "When investigating Windows persistence, always enumerate "
                    "Scheduled Tasks early and correlate task actions with "
                    "execution artifacts such as Prefetch and Amcache. "
                    "This pattern recurs across malware families and changes "
                    "where investigators look first on Windows hosts."),
                "knowledge_kind": "knowledge_gained",
                "candidate_type": "technique_insight",
                "suggested_destination": "wiki/techniques",
                "confidence": "high",
                "why_exists": "Claim graph concluded schtasks persistence.",
                "origin_sources": ["claim_graph", "findings"],
                "supporting_evidence": "C1",
                "why_reusable": (
                    "Applies to any Windows intrusion case when hunting "
                    "persistence mechanisms."),
            }, {
                "title": "too low",
                "body": "short",
                "knowledge_kind": "lesson_learned",
                "candidate_type": "workflow",
                "suggested_destination": "wiki/concepts",
                "confidence": "low",
                "why_exists": "x",
                "origin_sources": [],
                "supporting_evidence": "",
                "why_reusable": "y",
            }]
        })

    def chat(messages, max_tokens=0):
        return Resp()

    result = learn_from_investigation(
        brain_case["case"], case_id="CASE1", chat=chat)
    assert result["status"] == "completed"
    assert result["candidates"] == 1
    inbox = list((brain_case["brain"] / "inbox/memory-candidates").glob("*.md"))
    assert len(inbox) == 1
    text = inbox[0].read_text()
    assert "Why Reusable" in text
    assert "knowledge_gained" in text or "Knowledge kind" in text
    assert "Scheduled Tasks" in text


def test_digest_only_skips_llm(brain_case):
    from core.brain.learn import learn_from_investigation
    result = learn_from_investigation(
        brain_case["case"], case_id="CASE1", skip_llm=True)
    assert result["status"] == "skipped_llm"
    assert (brain_case["case"] / ".atlas" / "brain_learn_digest.md").is_file()


def test_spawn_reads_the_case_before_the_learner_starts(brain_case, monkeypatch):
    """The finishing run reads the case while it still holds the run lock; the
    detached learner gets the digest, not the case's analysis/ and reports/."""
    from core.brain import background

    seen = {}

    class _Proc:
        pid = 4242

    def _popen(cmd, **kw):
        job = json.loads(Path(cmd[cmd.index("--job-file") + 1]).read_text())
        seen["job"] = job
        seen["digest_at_spawn"] = Path(job["digest_file"]).read_text()
        return _Proc()

    monkeypatch.setattr(background.subprocess, "Popen", _popen)
    out = background.spawn_investigation_learn(brain_case["case"], case_id="CASE1")
    assert out["spawned"] is True, out
    assert seen["job"]["digest_file"].endswith("brain_learn_digest.md")
    assert "Scheduled Tasks" in seen["digest_at_spawn"]
    assert "Independent run review" in seen["digest_at_spawn"]


def test_the_learner_uses_the_given_digest_after_a_fresh_start_wiped_the_case(brain_case):
    import shutil
    from core.brain.learn import learn_from_investigation, prepare_learn_inputs

    case = brain_case["case"]
    prepared = prepare_learn_inputs(case, "CASE1")
    shutil.rmtree(case / "analysis")
    shutil.rmtree(case / "reports")
    (case / "analysis").mkdir()
    prompts = []

    class Resp:
        content = json.dumps({"lessons": []})

    def chat(messages, max_tokens=0):
        prompts.append(json.dumps(messages))
        return Resp()

    result = learn_from_investigation(case, case_id="CASE1", chat=chat,
                                      prepared=prepared)
    assert result["status"] == "completed"
    assert prompts and "Scheduled Tasks" in prompts[0]


def test_a_mirror_runs_learner_reads_the_mirror_and_keeps_the_real_case(brain_case, monkeypatch, tmp_path):
    """--output-dir: the run wrote its claim graph into the mirror; the job,
    the status and the answer key stay with the real case."""
    import shutil
    from core.brain import background

    real = brain_case["case"]
    mirror = tmp_path / "mirror"
    shutil.copytree(real, mirror)
    (real / ".atlas" / "claim_graph.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": "CASE1",
        "nodes": {"C1": {"kind": "claim", "status": "new", "summary": "an older run"}},
        "edges": []}))
    seen = {}

    class _Proc:
        pid = 4343

    def _popen(cmd, **kw):
        seen["cmd"] = cmd
        return _Proc()

    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)
    monkeypatch.delenv("ATLAS_NO_BRAIN_LEARN", raising=False)
    monkeypatch.setattr(background.subprocess, "Popen", _popen)
    out = background.spawn_investigation_learn(real, case_id="CASE1", source_dir=mirror)
    assert out["spawned"] is True, out
    job = json.loads((real / ".atlas" / "brain_learn_job.json").read_text())
    assert job["case_dir"] == str(real.resolve())
    digest = Path(job["digest_file"]).read_text()
    assert "Scheduled Tasks" in digest and "an older run" not in digest
    assert seen["cmd"][seen["cmd"].index("--case") + 1] == str(real.resolve())
