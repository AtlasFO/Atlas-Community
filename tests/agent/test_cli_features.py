"""Small CLI features: --output-dir (mirror case), --case-id (prompt anchor),
and the live progress graph in the TUI."""
import pytest

pytest.importorskip("rich")
from pathlib import Path  # noqa: E402
from rich.console import Console  # noqa: E402
from agent.tui import UI  # noqa: E402


def test_usr1_dumps_every_threads_stack_into_the_case(tmp_path):
    """A run that stops moving can be asked where it is: the signal writes
    all thread stacks under the case's analysis directory."""
    import faulthandler
    import os
    import signal
    from agent import cli
    cli._install_stack_dump_signal(tmp_path)
    try:
        os.kill(os.getpid(), signal.SIGUSR1)
        log = tmp_path / "analysis" / "run_stacks.log"
        assert "most recent call first" in log.read_text(encoding="utf-8")
    finally:
        faulthandler.unregister(signal.SIGUSR1)
        if cli._STACK_DUMP_HANDLE is not None:
            cli._STACK_DUMP_HANDLE.close()
            cli._STACK_DUMP_HANDLE = None


class TestOutputDirMirror:
    def _case(self, tmp_path):
        case = tmp_path / "mycase"
        (case / "evidence").mkdir(parents=True)
        (case / "evidence" / "disk.E01").write_text("x")
        (case / "CASE.md").write_text("**Case ID**: MYCASE\n")
        return case

    def test_creates_output_subdirs(self, tmp_path):
        from agent.cli import _prepare_output_dir
        case = self._case(tmp_path)
        out = _prepare_output_dir(case, str(tmp_path / "runout"))
        assert out == (tmp_path / "runout").resolve()
        for sub in ("analysis", "exports", "reports"):
            assert (out / sub).is_dir()

    def test_symlinks_evidence_and_brief(self, tmp_path):
        from agent.cli import _prepare_output_dir
        case = self._case(tmp_path)
        out = _prepare_output_dir(case, str(tmp_path / "runout"))
        assert (out / "evidence").is_symlink() or (out / "evidence").is_dir()
        assert (out / "evidence" / "disk.E01").exists()
        assert (out / "CASE.md").exists()

    def test_evidence_readonly_contract_preserved(self, tmp_path):
        from agent.cli import _prepare_output_dir
        from core.paths import is_evidence_path
        case = self._case(tmp_path)
        out = _prepare_output_dir(case, str(tmp_path / "runout"))
        # A write through the mirror's evidence symlink still resolves into a
        # protected evidence tree, so the read-only guard fires.
        assert is_evidence_path(str(out / "evidence" / "disk.E01")) is True
        # Output dirs are NOT evidence — writes there are allowed.
        assert is_evidence_path(str(out / "analysis" / "trace.json")) is False

    def test_same_dir_is_noop(self, tmp_path):
        from agent.cli import _prepare_output_dir
        case = self._case(tmp_path)
        assert _prepare_output_dir(case, str(case)) == case

    def test_engagement_mirrored_only_without_ground_truth(self, tmp_path):
        """engagement.yaml keys Tier-D brain injection; the mirror must carry
        it for real engagements but never for graded cases — ground_truth.json
        is deliberately not mirrored, so mirroring the client identity anyway
        would let a graded case bypass the Tier-D ground-truth gate."""
        from agent.cli import _prepare_output_dir
        case = self._case(tmp_path)
        (case / "engagement.yaml").write_text("client: acme-corp\n")
        out = _prepare_output_dir(case, str(tmp_path / "runout"))
        assert (out / "engagement.yaml").exists()
        graded = self._case(tmp_path / "g")
        (graded / "engagement.yaml").write_text("client: acme-corp\n")
        (graded / "ground_truth.json").write_text("{}")
        out2 = _prepare_output_dir(graded, str(tmp_path / "runout2"))
        assert not (out2 / "engagement.yaml").exists()


class TestCaseIdInjection:
    def test_message_carries_case_id_directive(self):
        from agent.prompts import initial_user_message
        m = initial_user_message("who?", "ns-summary", case_id="ACME-7")
        assert "ACME-7" in m
        assert "ACME-7_trace.json" in m

    def test_no_case_id_leaves_message_clean(self):
        from agent.prompts import initial_user_message
        m = initial_user_message("who?", "ns-summary")
        assert "USE THIS CASE ID" not in m

    def test_run_and_train_expose_case_id(self):
        from agent.cli import build_parser
        p = build_parser()
        assert p.parse_args(["run", "-q", "x", "--case-id", "C"]).case_id == "C"
        assert p.parse_args(["train", "-q", "x", "--case-id", "C"]).case_id == "C"

    def test_run_exposes_output_dir(self):
        from agent.cli import build_parser
        ns = build_parser().parse_args(["run", "-q", "x", "--output-dir", "/o"])
        assert ns.output_dir == "/o"


class TestProgressGraph:
    def test_note_tool_builds_flow_and_artifacts(self):
        ui = UI(quiet=True)
        ui.note_tool("hash_hash_file", '{"path": "/ev/mem.raw"}')
        ui.note_tool("ewf_ewf_mount", '{"image": "/ev/disk.E01"}')
        ui.note_tool("vol_vol_pslist", '{"image": "/ev/mem.raw"}')
        assert ui._graph == ["file", "mount", "pslist"]
        assert ui._artifacts == {"mem.raw", "disk.E01"}
        assert ui._graph_total == 3

    def test_graph_ring_caps_at_eight(self):
        ui = UI(quiet=True)
        for i in range(12):
            ui.note_tool(f"ns_tool{i}", "")
        assert len(ui._graph) == 8
        assert ui._graph_total == 12

    def test_short_tool_names(self):
        assert UI._short_tool("vol_vol_pslist") == "pslist"
        assert UI._short_tool("misc.record_finding") == "finding"
        assert UI._short_tool("dair_dair_assess") == "assess"

    def test_dashboard_renders_flow_and_artifacts(self):
        c = Console(record=True, width=100, force_terminal=True)
        # Pin the default skin: UI() otherwise resolves ATLAS_LIVE_SKIN /
        # ~/.atlas/ui.json, and a user preference (e.g. aquarium) renders a
        # different layout than the one asserted below.
        ui = UI(console=c, skin="atlas")
        ui.set_run_state(command="run", turn=1, tools=2)
        ui.note_tool("tsk_tsk_fls", '{"image": "/ev/disk.E01"}')
        ui.note_tool("misc_record_finding", '{"description": "x"}')
        c.print(ui._render_dashboard())
        out = c.export_text()
        assert "fls" in out and "finding" in out
        assert "1 artifacts" in out

    def test_no_graph_row_before_any_tool(self):
        c = Console(record=True, width=100, force_terminal=True)
        ui = UI(console=c, skin="atlas")
        ui.set_run_state(command="run", turn=1)
        c.print(ui._render_dashboard())  # must not raise with empty graph
        assert "\u25c7" not in c.export_text()

    def test_artifact_regex_ignores_bare_words(self):
        ui = UI(quiet=True)
        # No path separator → not treated as an artifact.
        ui.note_tool("misc_record_finding",
                     '{"description": "exfil via smtp", "confidence": "HIGH"}')
        assert ui._artifacts == set()


class TestTheAnalystIsToldWhatIsMounted:
    """The pre-run pass opens each disk image and records where on the access
    plan. An analyst not told of it works the raw containers — and TSK cannot
    read a compressed EWF container, so every such call fails and the run
    spends its turns rediscovering a problem already solved for it.

    The plan is the source, not a directory layout: the module that mounts an
    image knows where it put it, and a second guess at the convention would
    go quiet the day that module changed it."""

    def _case(self, tmp_path, images, live=True):
        import json
        from unittest.mock import patch
        plan = {"images": [
            {"basename": name, "stem": name,
             "mount_result": {"success": ok,
                              "mount_point": str(tmp_path / "mnt" / name / "fs")}}
            for name, ok in images]}
        (tmp_path / ".atlas").mkdir(parents=True, exist_ok=True)
        return plan, patch("core.mount_plan.load_mount_plan",
                           return_value=plan), patch(
            "core.mount_plan._path_is_mounted", return_value=live)

    def _render(self, tmp_path, images, live=True):
        from agent.prompts import _mounted_filesystems
        _, p1, p2 = self._case(tmp_path, images, live)
        with p1, p2:
            return _mounted_filesystems(tmp_path)

    def test_a_mounted_image_is_named(self, tmp_path):
        out = self._render(tmp_path, [("imgA", True)])
        assert "mnt/imgA/fs" in out
        assert "evidence/" in out          # says which one NOT to use

    def test_the_path_is_case_relative(self, tmp_path):
        """The analyst works in case-relative paths; an absolute one from the
        plan would not match anything it writes."""
        out = self._render(tmp_path, [("imgA", True)])
        assert str(tmp_path) not in out

    def test_a_failed_mount_is_not_advertised(self, tmp_path):
        assert self._render(tmp_path, [("imgA", False)]) == ""

    def test_a_recorded_mount_that_is_gone_is_not_advertised(self, tmp_path):
        """A plan left by an earlier run must not send the analyst somewhere
        nothing is mounted any more."""
        assert self._render(tmp_path, [("imgA", True)], live=False) == ""

    def test_a_case_with_no_images_says_nothing(self, tmp_path):
        from agent.prompts import _mounted_filesystems
        assert _mounted_filesystems(tmp_path) == ""
        assert _mounted_filesystems(None) == ""

    def test_it_reaches_the_opening_message(self, tmp_path):
        from agent.prompts import initial_user_message
        _, p1, p2 = self._case(tmp_path, [("imgA", True)])
        with p1, p2:
            msg = initial_user_message("who?", "ns", case_id="X",
                                       case_dir=tmp_path)
        assert "ALREADY MOUNTED" in msg and "mnt/imgA/fs" in msg


_HIDDEN_REQUESTS_BRIEF = (
    "# Case CASE-A\n\n## What you already know\n\n```\npasted line\n\n"
    "## Investigation Requests\n\n- Which account logged on to CORP-DC01?\n")


def test_a_start_whose_requests_a_block_hides_is_refused(tmp_path, capsys):
    from types import SimpleNamespace
    from agent import cli
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text(_HIDDEN_REQUESTS_BRIEF, encoding="utf-8")
    with pytest.raises(SystemExit) as stop:
        cli._check_brief_fences(SimpleNamespace(question=""), case, refuse=True)
    assert "line 5" in str(stop.value) and "nothing was started" in str(stop.value)
    # -q names the objective: the start goes on, warned.
    cli._check_brief_fences(SimpleNamespace(question="Who logged on?"), case, refuse=True)
    # A rerun warns only.
    cli._check_brief_fences(SimpleNamespace(), case, refuse=False)
    assert capsys.readouterr().err.count("never closed") == 2
