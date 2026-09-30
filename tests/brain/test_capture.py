import json
import re

import pytest

from core.brain import capture, frontmatter

REVIEW = """# Run Review — TESTCASE

VERDICT: ACCEPTABLE

## Assessment

Solid evidence chain but coverage was skipped.

## Recommendations

- Run coverage.coverage_report before the Report phase so TTPs get mapped.
- Volatility needs the Win11 symbol pack flag on modern memory images.
- Verify credentials found at password=hunter22 before reporting them.
"""

TRACE = {
    "case_id": "TESTCASE",
    "entries": [
        {"type": "finding", "confidence": "LIKELY"},
        {"type": "finding", "confidence": "CONFIRMED"},
        {"type": "self_correction", "trigger": "dair",
         "prior_belief": "the USB was mounted at boot",
         "new_belief": "the USB was mounted manually at 14:02 UTC"},
        {"type": "system_error"},
    ],
}


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / "case"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "reports").mkdir()
    (case_dir / "analysis" / "TESTCASE_trace.json").write_text(json.dumps(TRACE))
    return case_dir


def test_capture_stages_candidates_and_summary(brain, case):
    result = capture.capture_run(case, "TESTCASE", "who did it?",
                                 REVIEW, "ACCEPTABLE")
    # 3 recommendations + 1 self-correction
    assert result["candidates"] == 4
    files = list((brain / "inbox/memory-candidates").glob("*.md"))
    assert len(files) == 4
    summary = next((brain / "logs/runs").glob("*-testcase-train.md"))
    text = summary.read_text()
    assert "CONFIRMED: 1" in text and "LIKELY: 1" in text
    assert "who did it?" in text
    # candidates carry a full timestamp and run attribution tying them to
    # the run summary (its filename stem is the shared run_id)
    run_id = summary.name[:-len(".md")]
    for p in files + [summary]:
        meta, _, _ = frontmatter.parse(p.read_text())
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC",
                            str(meta["created"]))
        assert meta["origin"]["case_id"] == "TESTCASE"
        assert meta["origin"]["run_id"] == run_id
        assert meta["origin"]["command"] == "train"


def _trace_with_corrections(corrections):
    return {"case_id": "TESTCASE",
            "entries": [{"type": "self_correction", **c} for c in corrections]}


def _challenged(n):
    return [{"trigger": "evaluate_challenged",
             "prior_belief": f"finding {i} holds",
             "new_belief": f"finding {i} needs more evidence"}
            for i in range(n)]


def test_challenged_corrections_collapse_to_one_aggregate(brain, case, tmp_path):
    """Near-identical evaluate_challenged candidates are gate-normal
    retries, not lessons. High volume collapses to a single aggregate
    candidate."""
    (case / "analysis" / "TESTCASE_trace.json").write_text(
        json.dumps(_trace_with_corrections(_challenged(4))))
    result = capture.capture_run(case, "TESTCASE", "q", "", "ACCEPTABLE")
    files = list((brain / "inbox/memory-candidates").glob("*.md"))
    assert result["candidates"] == 1
    assert len(files) == 1
    body = files[0].read_text()
    assert "CHALLENGED 4 finding evaluations" in body


def test_few_challenged_corrections_stage_nothing(brain, case):
    """Below the aggregate threshold, challenge retries are protocol noise."""
    (case / "analysis" / "TESTCASE_trace.json").write_text(
        json.dumps(_trace_with_corrections(_challenged(2))))
    result = capture.capture_run(case, "TESTCASE", "q", "", "ACCEPTABLE")
    assert result["candidates"] == 0


def test_substantive_corrections_still_stage_individually(brain, case):
    """Non-challenge triggers keep their per-correction candidates even when
    challenge noise is present."""
    corrections = _challenged(2) + [
        {"trigger": "dair", "prior_belief": "USB mounted at boot",
         "new_belief": "USB mounted manually at 14:02 UTC"}]
    (case / "analysis" / "TESTCASE_trace.json").write_text(
        json.dumps(_trace_with_corrections(corrections)))
    result = capture.capture_run(case, "TESTCASE", "q", "", "ACCEPTABLE")
    files = list((brain / "inbox/memory-candidates").glob("*.md"))
    assert result["candidates"] == 1
    assert "USB mounted manually" in files[0].read_text()


def test_secret_recommendation_redacted_and_flagged(brain, case):
    capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    flagged = []
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        text = p.read_text()
        assert "hunter22" not in text
        meta, _, _ = frontmatter.parse(text)
        if meta["risk"]["contains_sensitive_data"]:
            flagged.append(p)
            assert meta["source_classification"] == "confidential"
    assert flagged


def test_credential_assignment_marks_candidate_confidential(brain, case):
    # A j_password=/password= assignment must be flagged sensitive even if the
    # secrets redactor misses the form: `j_password` (the Java EE form-login
    # field) has no word boundary before `password`, so a candidate carrying
    # it would otherwise stage as `internal`. Use a technique_insight (not
    # dropped) so it reaches staging. Fixture values below are synthetic.
    review = ("# Run Review — TESTCASE\n\nVERDICT: ACCEPTABLE\n\n"
              "## Recommendations\n\n"
              "- The technique used credentials j_password=ExamplePass1! "
              "on a login endpoint.\n")
    capture.capture_run(case, "TESTCASE", "q", review, "ACCEPTABLE")
    cred = None
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        meta, body, _ = frontmatter.parse(p.read_text())
        if "j_password" in body or "credentials" in body:
            cred = meta
    assert cred, "credential candidate should have staged (technique_insight)"
    assert cred["source_classification"] == "confidential"
    assert cred["risk"]["contains_sensitive_data"] is True


def test_answer_key_scrubbed_from_candidates_and_summary(brain, case):
    # The case ships a ground truth naming the answer-key secrets. A recovered
    # key that leaks into reviewer recs / self-corrections must be scrubbed out
    # of every staged candidate and out of the durable run summary.
    (case / "ground_truth.json").write_text(json.dumps({
        "case_id": "TESTCASE",
        "secrets": ["vaultkey=examplesecret31", "confidential.bin"],
    }))
    (case / "analysis" / "TESTCASE_trace.json").write_text(json.dumps({
        "case_id": "TESTCASE",
        "entries": [
            {"type": "self_correction", "trigger": "dair",
             "prior_belief": "the archive was not encrypted",
             "new_belief": "vaultkey=examplesecret31 decrypts confidential.bin"},
        ],
    }))
    review = ("## Recommendations\n\n"
              "- Record that vaultkey=examplesecret31 opens confidential.bin.\n")
    capture.capture_run(case, "TESTCASE", "decrypt confidential.bin?", review,
                        "ACCEPTABLE")

    flagged = 0
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        text = p.read_text()
        assert "examplesecret31" not in text
        assert "confidential.bin" not in text
        meta, _, _ = frontmatter.parse(text)
        if meta["risk"].get("contains_answer_key"):
            flagged += 1
            assert meta["risk"]["contains_sensitive_data"]
    assert flagged >= 1  # the candidates that quoted the key are flagged

    summary = next((brain / "logs/runs").glob("*-testcase-train.md")).read_text()
    assert "examplesecret31" not in summary
    assert "confidential.bin" not in summary


def test_no_ground_truth_leaves_candidates_untouched(brain, case):
    # Without a ground_truth.json the guard is inert — normal capture behavior.
    result = capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    assert result["candidates"] == 4
    for p in (brain / "inbox/memory-candidates").glob("*.md"):
        meta, _, _ = frontmatter.parse(p.read_text())
        assert meta["risk"]["contains_answer_key"] is False


def test_strong_verdict_skips_recommendations(brain, case):
    result = capture.capture_run(case, "TESTCASE", "q", REVIEW, "STRONG")
    # only the self-correction remains
    assert result["candidates"] == 1


def test_dedupe_across_runs(brain, case):
    first = capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    second = capture.capture_run(case, "TESTCASE", "q", REVIEW, "ACCEPTABLE")
    assert first["candidates"] == 4
    assert second["candidates"] == 0


def test_cap_per_run(brain, case):
    bullets = "\n".join(f"- Unique recommendation number {i} about workflow"
                        for i in range(20))
    review = f"## Recommendations\n\n{bullets}\n"
    result = capture.capture_run(case, "TESTCASE", "q", review, "ACCEPTABLE")
    assert result["candidates"] == capture.MAX_CANDIDATES_PER_RUN


def test_review_without_recommendations_is_fine(brain, case):
    result = capture.capture_run(case, "TESTCASE", "q",
                                 "# Review\n\nAll good.", "ACCEPTABLE")
    assert result["candidates"] == 1  # self-correction only


def test_summary_includes_injection_manifest(brain, case):
    """The run summary logs which brain entries were injected (and which the
    caps dropped) when the prompt builder left a manifest — injection
    effectiveness becomes measurement, not inference."""
    (case / "analysis" / "brain_injection.json").write_text(json.dumps({
        "generated_at": "2031-02-04 12:00 UTC",
        "memory": {"files": ["MEMORY.md"], "bytes": 900, "cap": 4096,
                   "truncated": False},
        "concepts": [
            {"title": "Carry leads", "path": "wiki/concepts/carry-leads.md",
             "pinned": True, "status": "injected"},
            {"title": "Old lesson", "path": "wiki/concepts/old.md",
             "pinned": False, "status": "dropped:byte-cap"},
        ],
        "retrieval": {"tags": ["volatility"],
                      "notes": [{"title": "Vol gotcha",
                                 "path": "wiki/tools/vol.md",
                                 "status": "injected"}]},
    }))
    capture.capture_run(case, "TESTCASE", "q?", REVIEW, "ACCEPTABLE")
    text = next((brain / "logs/runs").glob("*-testcase-train.md")).read_text()
    assert "## Brain Injection" in text
    assert "durable memory: MEMORY.md (900/4096 B)" in text
    assert "concept `wiki/concepts/carry-leads.md`: injected, pinned" in text
    assert "concept `wiki/concepts/old.md`: dropped:byte-cap" in text
    assert "retrieval tags: volatility" in text
    assert "note `wiki/tools/vol.md`: injected" in text
    assert "manifest generated: 2031-02-04 12:00 UTC" in text


class _FakeUI:
    def info(self, *a, **k):
        pass

    def warn(self, *a, **k):
        pass

    def markdown(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


class _FakeAgent:
    """Stands in for a finished investigation so cmd_run can be driven without
    a real LLM run."""
    def __init__(self):
        # finish_status=complete so cmd_run does not sys.exit(4) after the
        # truthful-completion contract (incomplete → exit 4).
        self.stats = {"stopped_reason": "finished",
                      "finish_status": "complete"}
        self.ui = _FakeUI()


def test_run_capture_brain_flag_stages_candidates(brain, case, monkeypatch):
    """`atlas run --capture-brain` stages candidates from the finished trace,
    the way train does automatically."""
    from agent import cli
    monkeypatch.setattr(cli, "_run_investigation",
                        lambda *a, **k: _FakeAgent())
    # Do not wipe the fixture's analysis/trace before capture.
    monkeypatch.setattr(cli, "_prepare_run_isolation", lambda *a, **k: None)
    args = cli.build_parser().parse_args(
        ["run", "--case", str(case), "--capture-brain", "--skip-sudo-check"])
    cli.cmd_run(args)
    staged = list((brain / "inbox/memory-candidates").glob("*.md"))
    assert staged, "--capture-brain should stage at least one candidate"
    # tagged with command=run provenance (not train)
    meta, _, _ = frontmatter.parse(staged[0].read_text())
    assert meta["origin"]["command"] == "run"


def test_run_without_capture_brain_stages_nothing(brain, case, monkeypatch):
    """A plain `atlas run` leaves the brain untouched (capture is opt-in)."""
    from agent import cli
    monkeypatch.setattr(cli, "_run_investigation",
                        lambda *a, **k: _FakeAgent())
    monkeypatch.setattr(cli, "_prepare_run_isolation", lambda *a, **k: None)
    args = cli.build_parser().parse_args(["run", "--case", str(case), "--skip-sudo-check"])
    assert args.capture_brain is False
    cli.cmd_run(args)
    assert not list((brain / "inbox/memory-candidates").glob("*.md"))


class _FakeAgentWithStatus(_FakeAgent):
    def __init__(self, finish_status: str):
        super().__init__()
        self.stats = {"stopped_reason": "finished",
                      "finish_status": finish_status}
        self.warned: list[str] = []
        agent = self

        class _UI(_FakeUI):
            def warn(self, msg, *a, **k):
                agent.warned.append(str(msg))

        self.ui = _UI()


def test_incomplete_run_does_not_feed_brain_and_exits_4(
        brain, case, monkeypatch):
    """A finished-but-incomplete run (open coverage / empty CIS) must not
    spawn brain learning — the brain would learn from exactly the runs that
    failed — and the CLI exit code must distinguish it from a truthful
    completion."""
    from agent import cli
    import core.brain.background as bg

    agent = _FakeAgentWithStatus("incomplete_coverage")
    monkeypatch.setattr(cli, "_run_investigation", lambda *a, **k: agent)
    spawned = []
    monkeypatch.setattr(
        bg, "spawn_investigation_learn",
        lambda *a, **k: spawned.append(k) or {"spawned": True, "pid": 1})

    args = cli.build_parser().parse_args(["run", "--case", str(case), "--skip-sudo-check"])
    with pytest.raises(SystemExit) as exc:
        cli.cmd_run(args)
    assert exc.value.code == 4
    assert spawned == []
    assert any("learning skipped" in w for w in agent.warned)


def test_incomplete_run_skips_legacy_capture_brain(brain, case, monkeypatch):
    """--capture-brain must use the same complete-gate as primary learn."""
    from agent import cli
    import core.brain.capture as cap

    agent = _FakeAgentWithStatus("incomplete_coverage")
    monkeypatch.setattr(cli, "_run_investigation", lambda *a, **k: agent)
    monkeypatch.setattr(cli, "_prepare_run_isolation", lambda *a, **k: None)
    called = []
    monkeypatch.setattr(
        cap, "capture_case",
        lambda *a, **k: called.append(k) or {
            "candidates": 1, "run_summary": "x"})

    args = cli.build_parser().parse_args(
        ["run", "--case", str(case), "--capture-brain", "--skip-sudo-check"])
    with pytest.raises(SystemExit) as exc:
        cli.cmd_run(args)
    assert exc.value.code == 4
    assert called == []
    assert any("legacy capture skipped" in w for w in agent.warned)


def test_incomplete_train_does_not_feed_brain_and_exits_4(
        brain, case, monkeypatch):
    """atlas train must not stage/learn from non-complete finish_status."""
    from agent import cli
    import core.brain.background as bg
    import core.brain.capture as cap

    agent = _FakeAgentWithStatus("incomplete_coverage")
    agent.client = type("C", (), {"model": "analyst"})()
    monkeypatch.setattr(cli, "_run_investigation", lambda *a, **k: agent)
    monkeypatch.setattr(
        cli, "_resolve_case_question", lambda *a, **k: "objective?")
    monkeypatch.setattr(
        "tools.misc.clear_case_run",
        lambda *a, **k: {"success": True, "cleared_count": 0, "errors": []})

    class _Rev:
        def __init__(self, *a, **k):
            pass

        def review(self, *a, **k):
            return {
                "verdict": "STRONG", "needs_work": False,
                "review": "ok", "path": "x",
                "reviewer_model": "reviewer",
            }

    monkeypatch.setattr(cli, "_build_reviewer_client",
                        lambda *a, **k: type("C", (), {"model": "r"})())
    monkeypatch.setattr("agent.review.Reviewer", _Rev)

    spawned, captured = [], []
    monkeypatch.setattr(
        bg, "spawn_investigation_learn",
        lambda *a, **k: spawned.append(k) or {"spawned": True, "pid": 1})
    monkeypatch.setattr(
        cap, "capture_run",
        lambda *a, **k: captured.append(k) or {
            "candidates": 1, "sensitive_flagged": 0,
            "dropped_case_residue": 0, "run_summary": "x"})

    args = cli.build_parser().parse_args(
        ["train", "--case", str(case), "--skip-sudo-check",
         "-q", "objective?", "--no-clear"])
    # Ensure flag is honoured even if parser defaults change.
    args.skip_sudo_check = True
    with pytest.raises(SystemExit) as exc:
        cli.cmd_train(args)
    assert exc.value.code == 4
    assert spawned == []
    assert captured == []
    assert any("capture/learn skipped" in w for w in agent.warned)


def test_complete_run_feeds_brain_and_exits_0(brain, case, monkeypatch):
    from agent import cli
    import core.brain.background as bg

    agent = _FakeAgentWithStatus("complete")
    monkeypatch.setattr(cli, "_run_investigation", lambda *a, **k: agent)
    spawned = []
    monkeypatch.setattr(
        bg, "spawn_investigation_learn",
        lambda *a, **k: spawned.append(k) or {"spawned": True, "pid": 1})

    args = cli.build_parser().parse_args(["run", "--case", str(case), "--skip-sudo-check"])
    cli.cmd_run(args)  # no SystemExit — truthful completion exits 0
    assert len(spawned) == 1


def test_run_status_artifact_persisted(tmp_path):
    """The completion classification must land on disk for status/dashboard/
    rerun consumers — the TUI banner alone is not propagation."""
    from agent.cli import _persist_run_status
    case = tmp_path / "case"
    case.mkdir()
    _persist_run_status(case, {
        "finish_status": "incomplete_coverage",
        "stopped_reason": "finished",
        "turns": 42, "duration_seconds": 123.4,
    })
    data = json.loads((case / ".atlas" / "run_status.json").read_text())
    assert data["finish_status"] == "incomplete_coverage"
    assert data["stopped_reason"] == "finished"
    assert data["turns"] == 42


def test_summary_notes_missing_injection_manifest(brain, case):
    capture.capture_run(case, "TESTCASE", "q?", REVIEW, "ACCEPTABLE")
    text = next((brain / "logs/runs").glob("*-testcase-train.md")).read_text()
    assert "## Brain Injection" in text
    assert "no injection manifest" in text


def test_capture_case_reads_disk_artifacts(brain, case):
    (case / "reports" / "TESTCASE_run_review.md").write_text(REVIEW)
    result = capture.capture_case(case)
    assert result["candidates"] == 4


def test_capture_case_without_artifacts_errors(brain, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(capture.CaptureError, match="nothing to capture"):
        capture.capture_case(empty)
