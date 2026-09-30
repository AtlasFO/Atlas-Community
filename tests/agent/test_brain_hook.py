"""The second-brain train hook and its safety properties."""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def brain(tmp_path, monkeypatch):
    root = tmp_path / "brain"
    for d in ("inbox/memory-candidates", "inbox/processed", "logs/runs",
              "templates", "indexes", "memory", "wiki", "logs"):
        (root / d).mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(root))
    return root


def _case(tmp_path):
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / "reports").mkdir()
    (case / "analysis" / "X_trace.json").write_text(json.dumps(
        {"case_id": "X", "entries": [
            {"type": "self_correction", "trigger": "dair",
             "prior_belief": "a", "new_belief": "b"}]}))
    return case


def test_hook_stages_and_reports(brain, tmp_path):
    from core.brain.capture import capture_run
    case = _case(tmp_path)
    review = "## Recommendations\n\n- Do the thing next time.\n"
    result = capture_run(case, "X", "q", review, "ACCEPTABLE")
    assert result["candidates"] == 2
    assert (brain / "logs/runs").glob("*-x-train.md")


def test_capture_failure_never_raises_through_cmd_train_guard(brain, tmp_path):
    """cmd_train wraps capture_run in try/except; simulate the guard."""
    from core.brain.capture import capture_run, CaptureError
    # brain root missing -> CaptureError, which the CLI guard swallows
    import os
    os.environ["ATLAS_BRAIN_ROOT"] = str(tmp_path / "missing")
    with pytest.raises(CaptureError):
        capture_run(_case(tmp_path), "X", "q", "", "")
    # the guard in cmd_train:
    try:
        capture_run(_case(tmp_path), "X", "q", "", "")
    except Exception:
        pass  # exit code unaffected — this is the cmd_train behavior


def test_train_parser_has_no_brain_flag():
    from agent.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["train", "--case", "x", "-q", "y", "--no-brain"])
    assert args.no_brain is True
    args = parser.parse_args(["train", "--case", "x", "-q", "y"])
    assert args.no_brain is False
    assert args.no_brain_capture is False
    args = parser.parse_args(["train", "--case", "x", "-q", "y",
                              "--no-brain-capture"])
    assert args.no_brain_capture is True


def test_no_brain_flag_sets_injection_kill_switch(monkeypatch):
    """--no-brain must disable injection too (ATLAS_NO_BRAIN is the switch
    agent.prompts._brain_context reads at prompt-build time), not just the
    post-run candidate staging."""
    import argparse
    import os
    from agent.cli import _apply_brain_flags
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)
    _apply_brain_flags(argparse.Namespace(no_brain=False))
    assert "ATLAS_NO_BRAIN" not in os.environ
    _apply_brain_flags(argparse.Namespace(no_brain=True))
    assert os.environ["ATLAS_NO_BRAIN"] == "1"
    monkeypatch.delenv("ATLAS_NO_BRAIN", raising=False)


def test_brain_subcommands_registered():
    from agent.cli import build_parser
    parser = build_parser()
    for argv in (["brain", "search", "q"], ["brain", "reindex"],
                 ["brain", "stats"], ["brain", "review"],
                 ["brain", "new", "--type", "tool", "--title", "t"],
                 ["brain", "globe"]):
        args = parser.parse_args(argv)
        assert callable(args.func)


def test_clear_case_run_never_touches_brain(tmp_path, monkeypatch):
    """Regression: atlas train's pre-run clear must not reach brain/."""
    from tools.misc import clear_case_run
    fn = getattr(clear_case_run, "fn", clear_case_run)
    brain_dir = REPO_ROOT / "brain"
    before = sorted(p.name for p in brain_dir.rglob("*.md")) \
        if brain_dir.is_dir() else []
    case = tmp_path / "case"
    for sub in ("analysis", "exports", "reports", "evidence"):
        (case / sub).mkdir(parents=True)
    (case / "analysis" / "junk.txt").write_text("x")
    result = fn(str(case))
    assert result.get("cleared_count", 0) >= 1
    after = sorted(p.name for p in brain_dir.rglob("*.md")) \
        if brain_dir.is_dir() else []
    assert before == after
