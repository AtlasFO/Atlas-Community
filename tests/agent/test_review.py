"""Tests for the independent post-run reviewer (`atlas train`)."""
import argparse
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.llm import ChatResponse
from agent.review import (NO_RECOMMENDATIONS, CrossCaseTraceError, Reviewer,
                          find_latest_report, ground_truth_path,
                          reviewer_model)
from agent.tui import UI


class StubClient:
    """LLMHubClient stand-in: canned review text, records the request."""

    def __init__(self, content: str, model: str = "reviewer-model"):
        self.content = content
        self.model = model
        self.messages = None

    def chat(self, messages, **kw) -> ChatResponse:
        self.messages = messages
        return ChatResponse(content=self.content)


STRONG_REVIEW = (
    "VERDICT: STRONG\n\n## Assessment\nSolid run.\n\n"
    f"## Recommendations\n{NO_RECOMMENDATIONS}\n")
WEAK_REVIEW = (
    "VERDICT: NEEDS WORK\n\n## Assessment\nStalled in Triage.\n\n"
    "## Recommendations\n1. Mount the image before carving.\n")

RUN_STATS = {"stopped_reason": "finished", "finish_status": "complete",
             "turns": 12,
             "duration_seconds": 340.0, "findings_recorded": 3,
             "input_tokens": 1000, "output_tokens": 200,
             "tool_calls": [{"name": "misc_record_finding", "seconds": 1.0,
                             "error": False}]}


@pytest.fixture
def case_dir(tmp_path):
    case = tmp_path / "case"
    (case / "reports").mkdir(parents=True)
    (case / "analysis").mkdir()
    return case


def _reviewer(case_dir, content=STRONG_REVIEW):
    client = StubClient(content)
    return Reviewer(client, case_dir, UI(quiet=True)), client


def test_strong_run_gets_no_recommendations_and_writes_review(case_dir):
    reviewer, _ = _reviewer(case_dir)
    result = reviewer.review(RUN_STATS, question="who sent it?")
    assert result["verdict"] == "STRONG"
    assert result["needs_work"] is False
    path = Path(result["path"])
    assert path == case_dir / "reports" / "PYTEST_run_review.md"
    text = path.read_text(encoding="utf-8")
    assert NO_RECOMMENDATIONS in text
    assert "PYTEST" in text


def test_needs_work_verdict_is_parsed(case_dir):
    reviewer, _ = _reviewer(case_dir, WEAK_REVIEW)
    result = reviewer.review(RUN_STATS)
    assert result["verdict"] == "NEEDS WORK"
    assert result["needs_work"] is True


def test_missing_verdict_defaults_to_needs_work(case_dir):
    # No verdict on the review AND none on the repair re-ask (stub returns the
    # same content both times) → falls back to NEEDS WORK.
    reviewer, _ = _reviewer(case_dir, "no verdict line at all")
    assert reviewer.review(RUN_STATS)["needs_work"] is True


def test_missing_verdict_is_repaired_by_reask(case_dir):
    # A clearly-positive audit that omits the VERDICT line must not silently
    # default to NEEDS WORK — one re-ask recovers the intended grade.
    class TwoShotClient:
        model = "reviewer-model"
        def __init__(self):
            self.messages = None
            self._n = 0
        def chat(self, messages, **kw):
            self.messages = messages
            self._n += 1
            # First call: the full review with no VERDICT line. Second call
            # (repair re-ask): just the verdict.
            if self._n == 1:
                return ChatResponse(content="# DFIR Run Audit\n\n## Assessment\n"
                                    "All findings CONFIRMED. Excellent run.")
            return ChatResponse(content="VERDICT: STRONG")
    client = TwoShotClient()
    reviewer = Reviewer(client, case_dir, UI(quiet=True))
    result = reviewer.review(RUN_STATS)
    assert result["verdict"] == "STRONG"
    assert result["needs_work"] is False
    assert client._n == 2  # the repair re-ask happened


def test_markdown_heading_verdict_is_parsed(case_dir):
    # A heading-prefixed verdict ("## VERDICT: ACCEPTABLE") must not be
    # mis-graded NEEDS WORK because of the heading prefix.
    reviewer, _ = _reviewer(case_dir, "# Audit\n\n## VERDICT: ACCEPTABLE\n\nok")
    result = reviewer.review(RUN_STATS)
    assert result["verdict"] == "ACCEPTABLE"
    assert result["needs_work"] is False


def test_verdict_matches_by_position_not_tuple_order(case_dir):
    reviewer, _ = _reviewer(
        case_dir, "VERDICT: ACCEPTABLE (close to STRONG, not quite)")
    assert reviewer.review(RUN_STATS)["verdict"] == "ACCEPTABLE"


def test_context_includes_trace_findings_report_and_question(case_dir):
    import core.execution_log as elog
    elog.log._entries.append(
        {"call_id": 99, "type": "finding", "confidence": "CONFIRMED",
         "description": "malicious .msc payload dropped",
         "input_call_ids": [42]})
    (case_dir / "reports" / "PYTEST_Final_Report.md").write_text(
        "# Final Report\nthe payload was X", encoding="utf-8")
    reviewer, client = _reviewer(case_dir)
    reviewer.review(RUN_STATS, question="what was the payload?")
    context = client.messages[1]["content"]
    assert "malicious .msc payload dropped" in context
    assert "the payload was X" in context
    assert "what was the payload?" in context
    assert client.messages[0]["role"] == "system"
    assert "INDEPENDENT" in client.messages[0]["content"]


def test_complete_report_reaches_reviewer_unclipped(case_dir):
    """A 12k cap clips a complete report and the reviewer then fabricates
    'report truncated' weaknesses; complete reports must reach the prompt
    whole."""
    body = "# Final Report\n" + ("evidence line\n" * 2000)  # ~28k chars
    (case_dir / "reports" / "PYTEST_Final_Report.md").write_text(
        body, encoding="utf-8")
    reviewer, client = _reviewer(case_dir)
    reviewer.review(RUN_STATS)
    context = client.messages[1]["content"]
    assert body in context
    assert "clipped" not in context


def test_oversize_report_clip_is_annotated_as_review_artifact():
    from agent.review import _MAX_REPORT_CHARS, _clip_report
    text = "x" * (_MAX_REPORT_CHARS + 500)
    clipped = _clip_report(text)
    assert clipped.startswith("x" * 100)
    assert "FOR REVIEW ONLY" in clipped
    assert "Do NOT grade truncation" in clipped
    assert str(len(text)) in clipped
    # under the limit: untouched
    assert _clip_report("short report") == "short report"


def test_prior_run_review_is_not_treated_as_the_final_report(case_dir):
    (case_dir / "reports" / "PYTEST_run_review.md").write_text(
        "old review", encoding="utf-8")
    assert find_latest_report(case_dir) is None
    (case_dir / "reports" / "PYTEST_Final_Report.md").write_text(
        "real report", encoding="utf-8")
    assert find_latest_report(case_dir).name == "PYTEST_Final_Report.md"


def test_ground_truth_discovery(case_dir):
    assert ground_truth_path(case_dir) is None
    gt = case_dir / "analysis" / "ground_truth.json"
    gt.write_text("{}", encoding="utf-8")
    assert ground_truth_path(case_dir) == gt


def test_answer_key_scrubbed_from_prompt_and_persisted_review(case_dir):
    # The reviewer reads findings that quote a recovered answer-key secret and
    # can echo it in its own text. Neither the prompt it sees nor the durable
    # reports/<CASE_ID>_run_review.md may carry the raw secret.
    (case_dir / "ground_truth.json").write_text(
        '{"case_id": "PYTEST", "secrets": ["vaultkey=examplesecret31"]}',
        encoding="utf-8")
    import core.execution_log as elog
    elog.log._entries.append(
        {"call_id": 7, "type": "finding", "confidence": "CONFIRMED",
         "description": "recovered AES key vaultkey=examplesecret31 from memory",
         "input_call_ids": [1]})
    leaky = ("VERDICT: NEEDS WORK\n\n## Assessment\nThe run found "
             "vaultkey=examplesecret31 but never decrypted the payload.\n\n"
             "## Recommendations\n1. Decrypt it.\n")
    reviewer, client = _reviewer(case_dir, leaky)
    result = reviewer.review(RUN_STATS)

    context = client.messages[1]["content"]
    assert "examplesecret31" not in context  # prompt sanitized
    text = Path(result["path"]).read_text()
    assert "examplesecret31" not in text  # persisted artifact sanitized
    assert "[REDACTED:answer_key]" in text
    assert "examplesecret31" not in result["review"]  # returned copy too
    assert result["verdict"] == "NEEDS WORK"  # verdict survives the scrub


def test_objective_metrics_data_shape(case_dir, monkeypatch):
    """Structured metrics carry the accuracy summary + coverage verbatim,
    and the prose renderer feeds the same data to the review prompt."""
    (case_dir / "ground_truth.json").write_text("{}", encoding="utf-8")
    summary = {"precision": 0.9, "recall": 0.7, "f1": 0.79,
               "true_positive_count": 4, "false_positive_count": 1,
               "false_negative_count": 2}
    import tools.accuracy as acc
    import tools.coverage as cov
    monkeypatch.setattr(acc, "accuracy_compare", lambda p: {
        "success": True, "summary": summary,
        "false_negatives": [{"id": "F9", "description": "missed implant"}]})
    monkeypatch.setattr(cov, "coverage_report", lambda: {
        "success": True, "summary": "3/10 TTPs", "gaps": ["T1055"]})
    reviewer, client = _reviewer(case_dir)
    data = reviewer.objective_metrics_data()
    assert data["accuracy"] == summary
    assert data["ground_truth"] == "ground_truth.json"
    assert data["false_negatives"] == [{"id": "F9",
                                        "description": "missed implant"}]
    assert data["coverage"] == {"summary": "3/10 TTPs", "gaps": ["T1055"]}
    prose = reviewer._objective_metrics(data)
    assert "f1=0.79" in prose and "missed implant" in prose
    assert "T1055" in prose
    # review() returns the same structured dict for machine consumers
    result = reviewer.review(RUN_STATS)
    assert result["metrics"]["accuracy"] == summary


def test_bundled_miss_is_marked_as_recorded(case_dir, monkeypatch):
    """A false negative whose fact a credited finding states in another
    sentence is annotated for the reviewer, so it is not read as a gap."""
    (case_dir / "ground_truth.json").write_text("{}", encoding="utf-8")
    import tools.accuracy as acc
    import tools.coverage as cov
    monkeypatch.setattr(acc, "accuracy_compare", lambda p: {
        "success": True, "summary": {"precision": 1.0, "recall": 0.5, "f1": 0.667},
        "false_negatives": [{"id": "F2", "description": "computer name"},
                            {"id": "F3", "description": "image hash"}],
        "bundled": [{"ground_truth_id": "F2", "trace_call_id": 41}]})
    monkeypatch.setattr(cov, "coverage_report", lambda: {"success": True,
                                                         "summary": "", "gaps": []})
    reviewer, _client = _reviewer(case_dir)
    data = reviewer.objective_metrics_data()
    by_id = {fn["id"]: fn for fn in data["false_negatives"]}
    assert by_id["F2"]["bundled_in_call_id"] == 41
    assert "bundled_in_call_id" not in by_id["F3"]
    prose = reviewer._objective_metrics(data)
    assert "F2: computer name [stated inside finding call #41" in prose
    assert "F3: image hash\n" in prose or prose.endswith("F3: image hash")


def test_objective_metrics_without_ground_truth(case_dir, monkeypatch):
    import tools.coverage as cov
    monkeypatch.setattr(cov, "coverage_report",
                        lambda: {"success": False})
    reviewer, _ = _reviewer(case_dir)
    data = reviewer.objective_metrics_data()
    assert data["accuracy"] is None and data["ground_truth"] is None
    assert "no objective metrics available" \
        in reviewer._objective_metrics(data)


def test_summary_splits_gate_refusals_from_tool_errors(case_dir):
    """The trace digest must not lump gate refusals in with genuine tool
    errors — doing so made the reviewer mis-frame record_finding refusals as a
    'schema bug'."""
    reviewer, _ = _reviewer(case_dir)
    entries = [
        {"type": "dair_call", "current_phase": "Collect"},
        {"type": "tool_call", "tool": "misc_record_finding", "success": False,
         "failure_class": "gate_refusal"},
        {"type": "tool_call", "tool": "misc_record_finding", "success": False,
         "failure_class": "gate_refusal"},
        {"type": "tool_call", "tool": "vol_vol_netscan", "success": False,
         "failure_class": "tool_error"},
    ]
    _, digest = reviewer._summarize_trace(entries=entries, case_id="X")
    assert "failed tool calls (genuine errors): 1" in digest
    assert "vol_vol_netscan" in digest
    assert "gate refusals (protections working, NOT tool failures): 2" in digest
    assert "do not recommend 'fix the schema'" in digest


def test_unscorable_accuracy_is_not_rendered_as_zero(case_dir, monkeypatch):
    """A CTF flag/hash GT yields unscorable — the reviewer prose must say so
    explicitly and NOT present precision=0 / 0% accuracy."""
    (case_dir / "ground_truth.json").write_text("{}", encoding="utf-8")
    import tools.accuracy as acc
    import tools.coverage as cov
    monkeypatch.setattr(acc, "accuracy_compare", lambda p: {
        "success": True, "unscorable": True, "summary": None,
        "reason": "ground_truth has no `expected_findings` and looks like a "
                  "CTF flag/hash answer key; accuracy not computed"})
    monkeypatch.setattr(cov, "coverage_report", lambda: {"success": False})
    reviewer, _ = _reviewer(case_dir)
    data = reviewer.objective_metrics_data()
    assert data["accuracy"] is None
    assert data["accuracy_unscorable"]
    prose = reviewer._objective_metrics(data)
    assert "UNSCORABLE" in prose
    assert "NOT 0% accuracy" in prose
    assert "precision=" not in prose


def test_reviewer_model_env_precedence(monkeypatch):
    monkeypatch.delenv("ATLAS_REVIEW_MODEL", raising=False)
    monkeypatch.delenv("REASON_MODEL", raising=False)
    monkeypatch.delenv("ATLAS_REVIEW_PROVIDER", raising=False)
    assert reviewer_model() == ""
    monkeypatch.setenv("REASON_MODEL", "reason-x")
    assert reviewer_model() == "reason-x"
    monkeypatch.setenv("ATLAS_REVIEW_MODEL", "review-y")
    assert reviewer_model() == "review-y"


def test_reviewer_provider_outranks_reason_model(monkeypatch):
    """REASON_MODEL belongs to the reason role. While the reviewer has a
    provider of its own, that assignment is what the reviewer follows."""
    monkeypatch.delenv("ATLAS_REVIEW_MODEL", raising=False)
    monkeypatch.setenv("REASON_MODEL", "reason-x")
    monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "revgw")
    monkeypatch.setenv("ATLAS_PROVIDERS", "revgw")
    monkeypatch.setenv("ATLAS_PROVIDER_REVGW_BASE_URL", "https://gw.example/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_REVGW_MODEL", "reviewer-model")
    assert reviewer_model() == "reviewer-model"


def test_reviewer_provider_without_a_model_falls_back(monkeypatch):
    monkeypatch.delenv("ATLAS_REVIEW_MODEL", raising=False)
    monkeypatch.setenv("REASON_MODEL", "reason-x")
    monkeypatch.setenv("ATLAS_REVIEW_PROVIDER", "revgw2")
    monkeypatch.setenv("ATLAS_PROVIDERS", "revgw2")
    monkeypatch.setenv("ATLAS_PROVIDER_REVGW2_BASE_URL", "https://gw.example/v1")
    monkeypatch.delenv("ATLAS_PROVIDER_REVGW2_MODEL", raising=False)
    assert reviewer_model("analyst-m") == "reason-x"


# ── cmd_train flow ────────────────────────────────────────────────────────

def _train_args(case, **over):
    base = dict(case=str(case), question="q?", model="", review_model="",
                no_clear=False, all_tools=False, quiet=True, json=False,
                skip_sudo_check=True,
                no_brain=True)  # keep tests from staging brain/logs/runs/
    base.update(over)
    return argparse.Namespace(**base)


def _fake_agent(stopped="finished"):
    agent = MagicMock()
    agent.stats = dict(RUN_STATS, stopped_reason=stopped)
    agent.client.model = "analyst-model"
    agent.ui = UI(quiet=True)
    return agent


def _run_train(case_dir, args, review_result):
    from agent import cli
    fake_reviewer = MagicMock()
    fake_reviewer.review.return_value = review_result
    with patch.object(cli, "_run_investigation",
                      return_value=_fake_agent()) as run_inv, \
         patch.object(cli, "_build_reviewer_client",
                      return_value=MagicMock(model="reviewer-model")), \
         patch("tools.misc.clear_case_run",
               return_value={"success": True, "cleared_count": 2,
                             "errors": []}) as clear, \
         patch("agent.review.Reviewer", return_value=fake_reviewer):
        cli.cmd_train(args)
    return run_inv, clear, fake_reviewer


GOOD_REVIEW_RESULT = {"verdict": "STRONG", "needs_work": False,
                      "review": STRONG_REVIEW, "path": "x",
                      "reviewer_model": "reviewer-model"}


def test_train_clears_by_default_and_reviews(case_dir):
    run_inv, clear, reviewer = _run_train(
        case_dir, _train_args(case_dir), GOOD_REVIEW_RESULT)
    clear.assert_called_once_with(str(case_dir), clear_memory=True)
    assert run_inv.call_args.kwargs.get("command") == "train"
    reviewer.review.assert_called_once()


def test_train_output_dir_clears_mirror_not_case(case_dir, tmp_path):
    """--output-dir redirects the clear (and the reviewer) to the mirror;
    the real case is untouched and no memory dir is wiped."""
    from agent import cli
    out = tmp_path / "mirror"
    args = _train_args(case_dir, output_dir=str(out))
    fake_reviewer = MagicMock()
    fake_reviewer.review.return_value = GOOD_REVIEW_RESULT
    with patch.object(cli, "_run_investigation",
                      return_value=_fake_agent()), \
         patch.object(cli, "_build_reviewer_client",
                      return_value=MagicMock(model="reviewer-model")), \
         patch("tools.misc.clear_case_run",
               return_value={"success": True, "cleared_count": 0,
                             "errors": []}) as clear, \
         patch("agent.review.Reviewer",
               return_value=fake_reviewer) as reviewer_cls:
        cli.cmd_train(args)
    clear.assert_called_once_with(str(out.resolve()), clear_memory=False)
    assert reviewer_cls.call_args.args[1] == out.resolve()
    # ground truth still resolves against the real case, not the mirror
    assert reviewer_cls.call_args.kwargs.get("gt_dir") == case_dir


def test_mirror_never_contains_answer_key(case_dir, tmp_path):
    """The analyst works inside the mirror — the answer key must not be
    reachable there (the model under review could read it and grade-inflate).
    The reviewer reads it from the real case via gt_dir instead."""
    from agent.cli import _prepare_output_dir
    gt = case_dir / "analysis" / "ground_truth.json"
    gt.write_text("{}", encoding="utf-8")
    out = _prepare_output_dir(case_dir, str(tmp_path / "mirror"))
    assert ground_truth_path(out) is None
    reviewer = Reviewer(StubClient(STRONG_REVIEW), out, UI(quiet=True),
                        gt_dir=case_dir)
    assert reviewer.objective_metrics_data()["ground_truth"] \
        == "ground_truth.json"


def test_train_no_clear_skips_the_wipe(case_dir):
    _, clear, _ = _run_train(
        case_dir, _train_args(case_dir, no_clear=True), GOOD_REVIEW_RESULT)
    clear.assert_not_called()


def test_train_without_question_runs_the_standard_objective(case_dir):
    """A case that states no question is not an error: the run asks the
    standard objective rather than refusing to start."""
    from agent import cli
    from core.investigation_tasks import DEFAULT_OBJECTIVE

    args = _train_args(case_dir, question=None)
    assert cli._resolve_case_question(args, case_dir) == DEFAULT_OBJECTIVE
    assert cli.question_was_defaulted(args, case_dir)

    _, clear, _ = _run_train(case_dir, args, GOOD_REVIEW_RESULT)
    clear.assert_called_once()


def test_a_stated_question_is_not_reported_as_defaulted(case_dir):
    from agent import cli
    args = _train_args(case_dir, question="who exfiltrated the archive?")
    assert cli._resolve_case_question(args, case_dir) == (
        "who exfiltrated the archive?")
    assert not cli.question_was_defaulted(args, case_dir)


def test_train_exits_3_when_review_needs_work(case_dir):
    bad = dict(GOOD_REVIEW_RESULT, verdict="NEEDS WORK", needs_work=True)
    with pytest.raises(SystemExit) as exc:
        _run_train(case_dir, _train_args(case_dir), bad)
    assert exc.value.code == 3


def test_train_parser_wiring():
    # main() builds its parser at call time, so patching the module attribute
    # is enough for set_defaults(func=...) to bind the fake.
    import agent.cli as cli
    with patch.object(cli, "_bootstrap_env"), \
         patch.object(cli, "cmd_train") as fake:
        cli.main(["train", "--case", "/tmp/x", "-q", "why?",
                  "--no-clear", "--review-model", "rm", "--json"])
    ns = fake.call_args.args[0]
    assert ns.no_clear is True
    assert ns.review_model == "rm"
    assert ns.json is True
    assert ns.question == "why?"


# ── cross-case bleed: review must bind to the run's own case dir ───────────

def _write_case_trace(case_dir: Path, case_id: str,
                      finding_descriptions: list[str]) -> Path:
    """Create case_dir/analysis/<case_id>_trace.json with the given findings
    and an empty reports/ dir. Returns the trace path."""
    import json
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    (case_dir / "reports").mkdir(parents=True, exist_ok=True)
    entries = [{"call_id": i, "type": "finding", "confidence": "CONFIRMED",
                "description": d}
               for i, d in enumerate(finding_descriptions, start=1)]
    trace = analysis / f"{case_id}_trace.json"
    trace.write_text(json.dumps({"schema_version": "2.0", "case_id": case_id,
                                 "entry_count": len(entries),
                                 "entries": entries}), encoding="utf-8")
    return trace


def test_sequential_runs_each_review_names_only_its_own_case(tmp_path):
    """Two back-to-back runs for different case_ids in one process: each
    review must name — and summarize — only its own case, even though the
    process-global execution-log singleton is repointed between runs.

    A review that reads the drifted singleton instead of the run's own case
    dir + trace names another case and carries that case's tool-call
    counts."""
    import core.execution_log as elog
    case_a = tmp_path / "alpha"
    case_b = tmp_path / "beta"
    trace_a = _write_case_trace(case_a, "ALPHA", ["alpha-only finding"])
    trace_b = _write_case_trace(case_b, "BETA", ["beta-only finding"])

    # Run 1: the singleton is bound to ALPHA (as it would be right after
    # ALPHA's investigation finished in this process).
    elog.log.configure("ALPHA", str(trace_a), save_session=False)
    client_a = StubClient(STRONG_REVIEW)
    res_a = Reviewer(client_a, case_a, UI(quiet=True)).review(RUN_STATS)
    assert Path(res_a["path"]).name == "ALPHA_run_review.md"
    ctx_a = client_a.messages[1]["content"]
    assert "alpha-only finding" in ctx_a
    assert "beta-only finding" not in ctx_a
    text_a = (case_a / "reports" / "ALPHA_run_review.md").read_text("utf-8")
    assert "# Run Review — ALPHA" in text_a
    assert "BETA" not in text_a

    # Run 2: the singleton is now bound to BETA. The ALPHA review must not be
    # revisited, and the BETA review must name only BETA.
    elog.log.configure("BETA", str(trace_b), save_session=False)
    client_b = StubClient(STRONG_REVIEW)
    res_b = Reviewer(client_b, case_b, UI(quiet=True)).review(RUN_STATS)
    assert Path(res_b["path"]).name == "BETA_run_review.md"
    ctx_b = client_b.messages[1]["content"]
    assert "beta-only finding" in ctx_b
    assert "alpha-only finding" not in ctx_b
    # ALPHA's review dir gained no BETA-named artifact.
    assert not (case_a / "reports" / "BETA_run_review.md").exists()


def test_review_binds_to_own_trace_not_drifted_singleton(tmp_path):
    """The digest + case_id come from the run's own on-disk trace even when
    the singleton is unloaded — never the global pointer."""
    import core.execution_log as elog
    case = tmp_path / "alpha"
    trace = _write_case_trace(case, "ALPHA", ["alpha-only finding"])
    # Singleton has NO case bound (fresh process / server restart): the review
    # still resolves ALPHA from the case's own trace on disk.
    elog.log._case_id = None
    elog.log._path = None
    elog.log._entries = []
    client = StubClient(STRONG_REVIEW)
    res = Reviewer(client, case, UI(quiet=True)).review(RUN_STATS)
    assert Path(res["path"]).name == "ALPHA_run_review.md"
    assert "alpha-only finding" in client.messages[1]["content"]
    assert str(trace)  # trace path was the binding source


def test_singleton_drift_to_other_case_is_a_hard_error(tmp_path):
    """When the singleton is bound to a DIFFERENT case than the run's own
    trace, the review refuses (CrossCaseTraceError) rather than silently
    adopting the other case's trace, counts, and metrics."""
    import core.execution_log as elog
    case_a = tmp_path / "alpha"
    case_b = tmp_path / "beta"
    _write_case_trace(case_a, "ALPHA", ["alpha-only finding"])
    trace_b = _write_case_trace(case_b, "BETA", ["beta-only finding"])
    # The singleton drifted to BETA while we ask to review ALPHA.
    elog.log.configure("BETA", str(trace_b), save_session=False)
    with pytest.raises(CrossCaseTraceError):
        Reviewer(StubClient(STRONG_REVIEW), case_a,
                 UI(quiet=True)).review(RUN_STATS)


def test_live_and_meta_reviews_are_not_treated_as_the_final_report(case_dir):
    # A live or meta review that another process wrote into this case's
    # reports/ (here one named after a different case) must never be graded
    # as the run's final report.
    (case_dir / "reports" / "CASE-B_live_review.md").write_text(
        "foreign live review", encoding="utf-8")
    (case_dir / "reports" / "PYTEST_meta_review.md").write_text(
        "meta review", encoding="utf-8")
    assert find_latest_report(case_dir) is None
    (case_dir / "reports" / "PYTEST_Final_Report.md").write_text(
        "real report", encoding="utf-8")
    assert find_latest_report(case_dir).name == "PYTEST_Final_Report.md"
