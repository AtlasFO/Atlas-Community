"""Tests for dashboard/run_options.py — the run/rerun options spec and the
build_argv() choke point that turns a validated options dict into a
subprocess argv tail for dashboard/run_manager.py."""
from __future__ import annotations

import pytest

from dashboard import run_options


class TestSpec:
    def test_run_and_rerun_specs_are_distinct(self):
        run_ids = {f["id"] for f in run_options.spec("run")}
        rerun_ids = {f["id"] for f in run_options.spec("rerun")}
        assert "case_id" in run_ids and "case_id" not in rerun_ids
        assert "no_agent" in rerun_ids and "no_agent" not in run_ids

    def test_unknown_mode_rejected(self):
        with pytest.raises(run_options.OptionsError):
            run_options.spec("explode")


class TestBuildArgvRun:
    def test_empty_options_is_empty_argv(self):
        assert run_options.build_argv("run", {}) == []
        assert run_options.build_argv("run", None) == []

    def test_text_option(self):
        argv = run_options.build_argv("run", {"question": "who did it?"})
        assert argv == ["--question", "who did it?"]

    def test_blank_text_is_dropped(self):
        assert run_options.build_argv("run", {"question": "   "}) == []

    def test_checkbox_true_adds_bare_flag(self):
        assert run_options.build_argv("run", {"all_tools": True}) == ["--all-tools"]

    def test_checkbox_false_omits_flag(self):
        assert run_options.build_argv("run", {"all_tools": False}) == []

    def test_select_valid_choice(self):
        assert run_options.build_argv("run", {"language": "de"}) == ["-L", "de"]

    def test_select_blank_choice_omitted(self):
        assert run_options.build_argv("run", {"language": ""}) == []

    def test_select_invalid_choice_rejected(self):
        with pytest.raises(run_options.OptionsError, match="language"):
            run_options.build_argv("run", {"language": "fr"})

    def test_start_mode_maps_to_bare_flag(self):
        assert run_options.build_argv("run", {"start_mode": "fresh"}) == ["--fresh"]
        assert run_options.build_argv("run", {"start_mode": "resume"}) == ["--resume"]
        assert run_options.build_argv("run", {"start_mode": ""}) == []

    def test_unknown_option_rejected(self):
        with pytest.raises(run_options.OptionsError, match="nonexistent"):
            run_options.build_argv("run", {"nonexistent": "x"})

    def test_rerun_only_option_rejected_in_run_mode(self):
        with pytest.raises(run_options.OptionsError):
            run_options.build_argv("run", {"no_agent": True})

    def test_multiple_options_combine(self):
        argv = run_options.build_argv("run", {
            "question": "focus on host A", "language": "en", "all_tools": True,
        })
        assert argv == ["--question", "focus on host A", "-L", "en", "--all-tools"]


class TestBuildArgvRerun:
    def test_no_agent_and_dry_run(self):
        argv = run_options.build_argv("rerun", {"no_agent": True, "dry_run": True})
        assert argv == ["--no-agent", "--dry-run"]

    def test_report_format_choice(self):
        argv = run_options.build_argv(
            "rerun", {"assemble_report": True, "report_format": "html"})
        assert argv == ["--assemble-report", "--format", "html"]

    def test_run_only_option_rejected_in_rerun_mode(self):
        with pytest.raises(run_options.OptionsError):
            run_options.build_argv("rerun", {"remote": "sift-lab"})


class TestQuickAddAndModes:
    """What the start dialog types into the brief never reaches argv, and
    the two ways to start each come with a label and a sentence."""

    def test_quick_add_fields_never_reach_argv(self):
        opts = {"new_questions": "Was data taken?",
                "new_context": "IP 10.0.0.5 is the print server.", "no_agent": True}
        assert run_options.build_argv("rerun", opts) == ["--no-agent"]
        assert run_options.local_options("rerun", opts) == {
            "new_questions": "Was data taken?",
            "new_context": "IP 10.0.0.5 is the print server."}

    def test_quick_add_fields_exist_in_both_modes(self):
        for mode in ("run", "rerun"):
            ids = {f["id"] for f in run_options.spec(mode)}
            assert {"new_questions", "new_context"} <= ids

    def test_context_ids_are_not_dashboard_options_any_more(self):
        ids = {f["id"] for f in run_options.spec("rerun")}
        assert not ids & {"withdraw_context", "correct_context", "question"}

    def test_modes_carry_a_label_and_a_sentence(self):
        assert [m["id"] for m in run_options.MODES] == ["rerun", "run"]
        assert all(m["label"] and m["help"] for m in run_options.MODES)

    def test_local_options_rejects_an_unknown_mode(self):
        with pytest.raises(run_options.OptionsError):
            run_options.local_options("explode", {})
