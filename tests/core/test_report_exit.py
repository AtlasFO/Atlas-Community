"""The report a stopped run owes is on disk before the narrative is tried.

Long runs ended with an empty reports/ although every finding was recorded:
the exit path built the whole projection — one live model call per narrative
section — before its first write, so anything that killed the process inside
that window threw the report away. These tests hold the floor-first order,
the atomic replace, the stage the dashboard reads, and the boundary that
keeps an exit report from passing as the analyst's own deliverable.
"""

from __future__ import annotations

import json
import os
import types
from pathlib import Path

import pytest

from core import report_exit
from core.report_exit import official_report_exists, write_exit_report
from core.report_projection import load_manifest


def _case(tmp_path: Path, *, claims: int = 2) -> Path:
    from tests.core.test_audit_fixes import _graph_with_claims
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.md").write_text(
        "# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n"
        "- What happened?\n", encoding="utf-8")
    if claims:
        _graph_with_claims(case, claims)
    return case


def _no_projection(monkeypatch):
    """Any narrative attempt is a test failure, not a slow test."""
    import core.investigation_state as inv

    def _boom(*a, **k):
        raise AssertionError("the exit path made a model call")
    monkeypatch.setattr(inv, "project_report_from_state", _boom)


# ── the floor lands first, without a network call ───────────────────────────

def test_the_deterministic_report_is_written_without_a_model_call(tmp_path,
                                                                  monkeypatch):
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    res = write_exit_report(case, "turn_cap", allow_llm=False)
    out = Path(res["path"])
    text = out.read_text(encoding="utf-8")
    assert res["written"] and res["stage"] == "deterministic"
    assert "Written at run end (turn_cap)" in text
    assert "without the narrative sections" in text
    assert "user1" in text                      # the findings are in the file
    man = load_manifest(case)
    assert man["report_stage"] == "deterministic"
    assert man["report_stage_reason"] == "turn_cap"
    assert man["last_deliverable_source"] == report_exit.EXIT_SOURCE_ASSEMBLED


def test_the_limitations_and_timeline_notice_are_in_the_document(tmp_path,
                                                                 monkeypatch):
    """Layer-4 policy belongs where a reader sees it, not in the manifest."""
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    text = Path(write_exit_report(case, "quiet", allow_llm=False)["path"]
                ).read_text(encoding="utf-8")
    assert "## Limitations" in text
    assert "Timeline unavailable" in text


def test_a_case_with_no_findings_gets_the_partial_stub(tmp_path, monkeypatch):
    """An empty section skeleton looks more finished than the case is."""
    case = _case(tmp_path, claims=0)
    _no_projection(monkeypatch)
    text = Path(write_exit_report(case, "stall", allow_llm=False)["path"]
                ).read_text(encoding="utf-8")
    assert "Investigation Report (Partial)" in text
    assert "No findings were promoted" in text
    assert "## Limitations" in text


def test_the_report_is_replaced_atomically(tmp_path, monkeypatch):
    """A reader never sees half a report: the text is written to a temp file
    in the same directory and moved into place in one step."""
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    out = report_exit.exit_report_path(case)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("previous report\n", encoding="utf-8")
    seen: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy(src, dst, *a, **k):
        # At this instant the new text is complete in the temp file and the
        # old report is still whole — that is what makes the swap safe.
        seen.append((Path(src).read_text(encoding="utf-8"),
                     Path(dst).read_text(encoding="utf-8")))
        assert Path(src).parent == Path(dst).parent
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(report_exit.os, "replace", spy)
    write_exit_report(case, "turn_cap", allow_llm=False)
    assert seen and "Written at run end" in seen[0][0]
    assert seen[0][1] == "previous report\n"
    assert not list(out.parent.glob(".*tmp"))


# ── the narrative sections are an upgrade over a file that exists ───────────

def test_the_upgrade_overwrites_the_floor_and_records_complete(tmp_path,
                                                               monkeypatch):
    case = _case(tmp_path)
    import core.investigation_state as inv
    stages: list[str] = []

    def fake_projection(case_dir, **kw):
        # The floor is on disk and the stage says so *before* the first call.
        stages.append(load_manifest(case_dir)["report_stage"])
        assert Path(kw["output_path"]).is_file()
        return {"success": True, "regenerate": {"fallbacks": []},
                "markdown": "# Report\n\n## 1. Executive Summary\n\nprose"}

    monkeypatch.setattr(inv, "project_report_from_state", fake_projection)
    res = write_exit_report(case, "finished", allow_llm=True)
    text = Path(res["path"]).read_text(encoding="utf-8")
    assert stages == ["upgrading"]
    assert res["stage"] == "complete" and res["upgraded"]
    assert "prose" in text and "without the narrative sections" not in text
    man = load_manifest(case)
    assert man["report_stage"] == "complete"
    assert man["last_deliverable_source"] == report_exit.EXIT_SOURCE_PROJECTED


def test_a_failed_upgrade_leaves_the_floor_in_place(tmp_path, monkeypatch):
    case = _case(tmp_path)
    import core.investigation_state as inv

    def boom(*a, **k):
        raise RuntimeError("no provider")

    monkeypatch.setattr(inv, "project_report_from_state", boom)
    res = write_exit_report(case, "finished", allow_llm=True)
    text = Path(res["path"]).read_text(encoding="utf-8")
    assert res["stage"] == "upgrade_failed" and not res["upgraded"]
    assert "without the narrative sections" in text and "user1" in text
    man = load_manifest(case)
    assert man["report_stage"] == "upgrade_failed"
    assert man["last_deliverable_source"] == report_exit.EXIT_SOURCE_ASSEMBLED


def test_an_interrupt_inside_the_upgrade_keeps_the_report(tmp_path, monkeypatch):
    case = _case(tmp_path)
    import core.investigation_state as inv

    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(inv, "project_report_from_state", interrupt)
    res = write_exit_report(case, "keyboard_interrupt", allow_llm=True)
    assert Path(res["path"]).is_file() and res["stage"] == "upgrade_failed"


# ── an exit report is never the analyst's deliverable ───────────────────────

def test_exit_and_official_deliverables_never_overlap():
    """The load-bearing guard: if an exit report could pass as an official
    one, every killed run would read as a finished one."""
    from core.report_exit import (
        EXIT_SOURCES, OFFICIAL_NAMES, OFFICIAL_NAME_PREFIXES, OFFICIAL_SOURCES,
    )
    assert not (EXIT_SOURCES & OFFICIAL_SOURCES)
    name = report_exit.exit_report_path(Path("/cases/c")).name.lower()
    assert name not in OFFICIAL_NAMES
    assert not name.startswith(OFFICIAL_NAME_PREFIXES)


def test_the_written_exit_report_does_not_count_as_a_final_report(tmp_path,
                                                                  monkeypatch):
    from agent.loop import Agent
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    write_exit_report(case, "turn_cap", allow_llm=False)
    assert official_report_exists(case) is False
    # The loop's own guard reads the same case directory and agrees.
    stub = types.SimpleNamespace(_tool_stats=[], case_dir=case)
    assert Agent._report_written(stub) is False


def test_an_official_report_is_left_alone_unless_forced(tmp_path, monkeypatch):
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    (case / "reports").mkdir(exist_ok=True)
    (case / "reports" / "final_report.md").write_text(
        "# The analyst's own report\n" + "x" * 128, encoding="utf-8")
    assert official_report_exists(case) is True
    assert write_exit_report(case, "turn_cap", allow_llm=False) == {
        "written": False, "skipped": "official_report_exists"}
    assert not report_exit.exit_report_path(case).exists()
    assert write_exit_report(case, "turn_cap", allow_llm=False,
                            force=True)["written"]


def test_a_case_with_only_an_exit_report_is_not_complete(tmp_path, monkeypatch):
    from core.investigation_exit import classify_finish_status
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    write_exit_report(case, "quiet", allow_llm=False)
    assert classify_finish_status(
        "quiet", case_dir=case,
        report_written=official_report_exists(case),
        synthesize_ok=True, pre_report_ready=True) != "complete"


# ── the dashboard says which version of the report is on screen ─────────────

@pytest.mark.parametrize("stage,alive,label", [
    ("deterministic", False, "Basis version — narrative pending"),
    ("upgrading", True, "Report generation in progress"),
    ("upgrading", False, "Report generation interrupted — basis version only"),
    ("upgrade_failed", False,
     "Narrative generation failed — basis version only"),
    ("complete", False, ""),
])
def test_the_report_tab_labels_every_stage(tmp_path, monkeypatch, stage, alive,
                                           label):
    from dashboard import read_models as rm
    case = _case(tmp_path)
    report_exit.record_report_stage(case, stage, "turn_cap",
                                    path=report_exit.exit_report_path(case),
                                    source=report_exit.EXIT_SOURCE_ASSEMBLED)
    monkeypatch.setattr(rm, "run_process_alive", lambda cd: alive)
    st = rm.report_stage(str(case))
    assert st["report_stage"] == stage
    assert st["report_label"] == label
    assert st["report_complete"] is (stage == "complete")


def test_an_analyst_written_report_carries_no_stage(tmp_path, monkeypatch):
    from dashboard import read_models as rm
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    write_exit_report(case, "turn_cap", allow_llm=False)
    (case / "reports" / "final_report.md").write_text(
        "# The analyst's own report\n" + "x" * 128, encoding="utf-8")
    st = rm.report_status(str(case))
    assert st["report_stage"] is None and st["report_complete"] is True
    assert st["report_label"] == ""


# ── the command that survives a kill ────────────────────────────────────────

def test_write_report_command_writes_from_the_case_directory_alone(tmp_path,
                                                                   monkeypatch,
                                                                   capsys):
    """Nothing in the dying process has to cooperate: the case directory is
    the whole input."""
    from agent import cli
    case = _case(tmp_path)
    _no_projection(monkeypatch)
    args = types.SimpleNamespace(case=str(case), force=False, no_llm=True)
    cli.cmd_write_report(args)
    out = capsys.readouterr().out
    assert str(report_exit.exit_report_path(case)) in out
    assert report_exit.exit_report_path(case).is_file()
    assert json.loads(
        (case / ".atlas" / "report_projection" / "manifest.json").read_text(
            encoding="utf-8"))["report_stage"] == "deterministic"


def test_a_per_host_deliverable_is_not_the_official_report(tmp_path):
    """The projection manifest records whatever was assembled last. One
    host's report under an official source must not read as the case's
    report, or a run that still owes the estate's report is taken for
    complete."""
    from core.report_projection import save_manifest
    case = tmp_path / "CaseX"
    (case / "reports").mkdir(parents=True)
    host = case / "reports" / "host_WS01_report.md"
    host.write_text("# WS01\n" + "findings " * 20)
    save_manifest(case, {"last_assembled_path": str(host),
                         "last_deliverable_source": "write_projected_final_report"})
    assert official_report_exists(case) is False
    estate = case / "reports" / "estate_report.md"
    estate.write_text("# Estate\n" + "findings " * 20)
    save_manifest(case, {"last_assembled_path": str(estate),
                         "last_deliverable_source": "write_projected_final_report"})
    assert official_report_exists(case) is True


def _projection_stub(root, **kw):
    return {"success": True,
            "markdown": f"# Report\n\nbody for {Path(kw['output_path']).name}\n"}


def test_the_close_out_writes_the_host_reports_owed_and_then_the_estate_report(tmp_path, monkeypatch):
    """Every host that carries claims and has no report gets one, then the
    estate report; the estate report is the manifest's last deliverable
    under an official source, so the run reads as reported."""
    from core.claim_graph import load_graph, save_graph
    import core.investigation_state as inv
    case = _case(tmp_path)
    g = load_graph(case)
    g["nodes"]["C0002"]["host"] = "HOST02"
    save_graph(case, g)
    (case / "reports").mkdir()
    (case / "reports" / "host_HOST02_report.md").write_text("# already there\n")
    monkeypatch.setattr(inv, "project_report_from_state", _projection_stub)
    res = report_exit.close_out_reports(case, reason="gate_ready",
                                        verdict="READY_TO_REPORT: true")
    assert [Path(p).name for p in res["written"]] == ["host_HOST01_report.md", "estate_report.md"]
    assert res["errors"] == {}
    estate = (case / "reports" / "estate_report.md").read_text()
    assert "Closed out by Atlas (gate_ready)" in estate
    assert "body for estate_report.md" in estate
    assert "documented as limitations" not in estate
    assert official_report_exists(case) is True
    assert load_manifest(case)["last_deliverable_source"] == report_exit.CLOSE_OUT_SOURCE


def test_the_close_out_note_says_when_blockers_became_limitations(tmp_path, monkeypatch):
    import core.investigation_state as inv
    case = _case(tmp_path)
    monkeypatch.setattr(inv, "project_report_from_state", _projection_stub)
    verdict = ("READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none\n"
               "DOCUMENTED_LIMITATIONS (1): DOCUMENTED LIMITATION (budget wrap-up — was blocking): x")
    report_exit.close_out_reports(case, reason="report_stall", verdict=verdict)
    text = (case / "reports" / "estate_report.md").read_text()
    assert "Closed out by Atlas (report_stall)" in text
    assert "documented as limitations" in text


def test_a_report_the_projection_cannot_produce_is_reported_not_raised(tmp_path, monkeypatch):
    """One report failing leaves the others written and the failure named."""
    import core.investigation_state as inv
    case = _case(tmp_path)

    def _flaky(root, **kw):
        if "host_" in kw["output_path"]:
            return {"success": False, "error": "no beliefs for this host"}
        return _projection_stub(root, **kw)

    monkeypatch.setattr(inv, "project_report_from_state", _flaky)
    res = report_exit.close_out_reports(case, reason="gate_ready")
    assert [Path(p).name for p in res["written"]] == ["estate_report.md"]
    assert list(res["errors"]) and "no beliefs" in next(iter(res["errors"].values()))
    assert official_report_exists(case) is True


def test_close_out_and_exit_sources_never_overlap():
    assert report_exit.CLOSE_OUT_SOURCE in report_exit.OFFICIAL_SOURCES
    assert report_exit.CLOSE_OUT_SOURCE not in report_exit.EXIT_SOURCES


# ── the ending the loop reached, not the reason it stopped ─────────────────

def test_every_reason_classify_accepts_is_an_ending():
    """The two lists are one decision, so they cannot drift apart.

    classify_finish_status treats these stop reasons like ``finished`` and
    lets the coverage verdict decide; a caller asking "did it end" must get
    the same answer for each of them.
    """
    from core.investigation_exit import (
        classify_finish_status,
        ended_through_a_completion_path,
    )
    for reason in ("finished", "quiet", "stall", "finish_deferred",
                   "report_stall", "closed_out"):
        status = classify_finish_status(
            reason, case_dir=None, report_written=True,
            synthesize_ok=True, pre_report_ready=True)
        assert ended_through_a_completion_path(status), reason


def test_a_run_that_was_cut_off_is_not_an_ending():
    """A cap or a deadlock echoes the stop reason back; that is not an end."""
    from core.investigation_exit import (
        classify_finish_status,
        ended_through_a_completion_path,
    )
    for reason in ("turn_cap", "wall_clock", "gate_deadlock", "llm_deadline"):
        status = classify_finish_status(
            reason, case_dir=None, report_written=True,
            synthesize_ok=True, pre_report_ready=True)
        assert status == reason
        assert not ended_through_a_completion_path(status), reason
    # Fail-closed: an unset status is never an ending.
    assert not ended_through_a_completion_path("")


def test_the_cli_reads_the_verdict_off_finish_status_alone(tmp_path):
    """A closed-out run is complete, and must not be read as unfinished.

    The regression: both CLI commands derived ``complete`` as
    ``stopped_reason == "finished" and finish_status == "complete"``, so a
    run the loop closed out itself scored exit 2 and never fed the brain,
    although its reports were written and its gate had passed.
    """
    import inspect
    from agent import cli
    from core.investigation_exit import ended_through_a_completion_path

    # The commands' bodies run under the case's run lock.
    for fn in (cli._run_locked, cli._train_locked):
        src = inspect.getsource(fn)
        assert 'stopped_reason") == "finished"' not in src, fn.__name__
        assert "ended_through_a_completion_path" in src, fn.__name__

    # The verdict a closed-out complete run yields.
    assert ended_through_a_completion_path("complete")
    assert ended_through_a_completion_path("incomplete_coverage")


def test_the_close_out_delivers_the_indicator_files(tmp_path, monkeypatch):
    """The indicator list is a deliverable of its own on the close-out path
    as on the tool path: both files land beside the reports."""
    import core.investigation_state as inv
    case = _case(tmp_path)
    monkeypatch.setattr(inv, "project_report_from_state", _projection_stub)
    res = report_exit.close_out_reports(case, reason="gate_ready", verdict="READY_TO_REPORT: true")
    files = res["indicator_files"]
    assert Path(files["markdown"]).is_file() and Path(files["csv"]).is_file()
    assert Path(files["markdown"]).parent == case / "reports"
    assert "Verify ownership before deploying a block item." in Path(files["markdown"]).read_text()
