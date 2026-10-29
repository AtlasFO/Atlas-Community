"""A start checks its model configuration before it changes the case, a
fresh start keeps the previous run's reports and trace, and a process that
ends between the intake and the session never leaves a "running" record."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ── a finished case and a fingerprint of its tree ─────────────────────────────

def _finished_case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-A"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "disk.raw").write_bytes(b"\0" * 64)
    (case / "CASE.md").write_text(
        "**Case ID:** CASE-A\n\n## Investigation Requests\n\n- What happened on CORP-WS01?\n",
        encoding="utf-8")
    atlas = case / ".atlas"
    atlas.mkdir()
    (atlas / "run_status.json").write_text(json.dumps(
        {"stopped_reason": "closed_out", "finish_status": "complete"}), encoding="utf-8")
    (atlas / "report_snapshots_index.json").write_text('{"snapshots": ["rerun_0001"]}', encoding="utf-8")
    (case / "analysis").mkdir()
    (case / "analysis" / "CASE-A_trace.json").write_text('{"case_id": "CASE-A", "entries": []}', encoding="utf-8")
    (case / "analysis" / "agent_transcript_20310102T030405Z.jsonl").write_text("{}\n", encoding="utf-8")
    (case / "analysis" / "parsed_events.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (case / "exports").mkdir()
    (case / "exports" / "carved.bin").write_bytes(b"\1" * 32)
    reports = case / "reports"
    (reports / "initial_report").mkdir(parents=True)
    (reports / "initial_report" / "CASE-A_investigation_report.md").write_text("# first\n", encoding="utf-8")
    (reports / "rerun_0001").mkdir()
    (reports / "rerun_0001" / "CASE-A_investigation_report.md").write_text("# second\n", encoding="utf-8")
    (reports / "latest").symlink_to("rerun_0001")
    (reports / "CASE-A_run_review.md").write_text("# review\n", encoding="utf-8")
    return case


def _tree(root: Path) -> dict:
    """Every path under ``root`` with its content hash or link target. The run
    lock file is left out: taking the lock is what any start does first."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            if rel == os.path.join(".atlas", "run.lock"):
                continue
            if p.is_symlink():
                out[rel] = "link:" + os.readlink(p)
            elif p.is_dir():
                out[rel] = "dir"
            else:
                out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


# ── the configuration is checked before the case changes ─────────────────────

class _Provider:
    name = "corp-gateway"


def _client(*, provider=None, model="corp-model-1", api_key="k-123", unknown=False):
    from core import providers

    class _C:
        @property
        def provider(self):
            if unknown:
                raise providers.UnknownProvider("unknown model provider 'corp-gateway'; known: none")
            return provider or _Provider()

        @property
        def model(self):
            return model

    c = _C()
    c.api_key = api_key
    c.key_missing = not api_key     # a keyed profile: the client's own test (LLMHubClient.key_missing)
    return c


_FAILURES = {
    "unknown provider": dict(client=dict(unknown=True), want="unknown model provider"),
    "no model": dict(client=dict(model=""), want="no model configured"),
    "identity-shaped model": dict(client=dict(model="analyst"), want="looks like a dashboard role"),
    "no key": dict(client=dict(api_key=""), want="no API key"),
    "catalogue miss": dict(client=dict(), probe="unknown_model", want="not served by"),
}


def _probe(kind: str):
    if kind == "unknown_model":
        return SimpleNamespace(source="unknown_model", error="model 'corp-model-1' is not served by corp-gateway")
    return SimpleNamespace(source="live", error="")


@pytest.mark.parametrize("command", ["run", "train"])
@pytest.mark.parametrize("failure", sorted(_FAILURES))
def test_a_configuration_the_run_cannot_use_leaves_the_case_as_it_was(tmp_path, command, failure):
    from agent import cli
    spec = _FAILURES[failure]
    case = _finished_case(tmp_path)
    before = _tree(case)
    argv = [command, "--case", str(case), "--skip-sudo-check", "-L", "de"]
    with patch("agent.llm.LLMHubClient", lambda **k: _client(**spec["client"])), \
         patch("core.model_context.probe_and_apply", lambda *a, **k: _probe(spec.get("probe", ""))), \
         patch("core.incremental.plane_a_scan", side_effect=AssertionError("Plane A ran")), \
         pytest.raises(SystemExit) as ended:
        cli.main(argv)
    assert spec["want"] in str(ended.value.code)
    assert _tree(case) == before


def test_a_review_configuration_train_cannot_use_leaves_the_case_as_it_was(tmp_path):
    from agent import cli
    case = _finished_case(tmp_path)
    before = _tree(case)
    with patch("agent.llm.LLMHubClient", lambda **k: _client()), \
         patch("core.model_context.probe_and_apply", lambda *a, **k: _probe("")), \
         patch.object(cli, "_build_reviewer_client",
                      side_effect=SystemExit("atlas: unknown model provider 'corp-review'")), \
         patch("core.incremental.plane_a_scan", side_effect=AssertionError("Plane A ran")), \
         pytest.raises(SystemExit) as ended:
        cli.main(["train", "--case", str(case), "--skip-sudo-check"])
    assert "corp-review" in str(ended.value.code)
    assert _tree(case) == before


def test_the_checked_client_reaches_the_session_and_is_not_probed_again(tmp_path):
    from agent import cli
    case = _finished_case(tmp_path)
    probes = []
    seen = {}

    def _investigation(args, case_dir, command="run", lock_fd=None, client=None):
        seen["client"] = client
        raise SystemExit(9)

    def _probe_once(*a, **k):
        probes.append(a)
        return _probe("")

    with patch("agent.llm.LLMHubClient", lambda **k: _client()), \
         patch("core.model_context.probe_and_apply", _probe_once), \
         patch.object(cli, "_run_investigation", _investigation), \
         pytest.raises(SystemExit):
        cli.main(["run", "--case", str(case), "--skip-sudo-check", "--fresh"])
    assert seen["client"] is not None and seen["client"].model == "corp-model-1"
    assert len(probes) == 1


# ── a fresh start archives the reports and the trace ──────────────────────────

def test_the_clear_moves_the_reports_and_their_snapshots_to_the_archive(tmp_path):
    from tools.misc import clear_case_run
    case = _finished_case(tmp_path)
    r = clear_case_run(str(case), clear_memory=False)
    assert r["success"] is True, r
    archive = Path(r["archive"])
    assert archive.parent == case / ".atlas" / "run_history"
    moved = archive / "reports"
    assert (moved / "initial_report" / "CASE-A_investigation_report.md").read_text() == "# first\n"
    assert (moved / "CASE-A_run_review.md").is_file()
    assert (moved / "latest").is_symlink() and os.readlink(moved / "latest") == "rerun_0001"
    assert (moved / "latest" / "CASE-A_investigation_report.md").read_text() == "# second\n"
    assert (archive / "report_snapshots_index.json").is_file()
    assert not (case / ".atlas" / "report_snapshots_index.json").exists()
    assert (archive / "CASE-A_trace.json").is_file()
    assert (archive / "agent_transcript_20310102T030405Z.jsonl").is_file()
    # What a clear still deletes: analysis/ and exports/ are derived from the evidence.
    assert (case / "reports").is_dir() and not os.listdir(case / "reports")
    assert not os.listdir(case / "analysis") and not os.listdir(case / "exports")


@pytest.mark.parametrize("fails_on", ["rerun_0001", "report_snapshots_index.json", "CASE-A_trace.json"])
def test_a_failed_archive_puts_everything_back(tmp_path, fails_on):
    """A move that fails part-way (an entry of reports/ after others, the
    snapshot index, a trace) moves back what had moved and refuses the
    clear: the case is as it was."""
    import shutil
    from tools.misc import clear_case_run
    case = _finished_case(tmp_path)
    before = _tree(case)
    real_move = shutil.move

    def _move(src, dst, *a, **k):
        if os.path.basename(src) == fails_on:
            raise OSError(28, "No space left on device")
        return real_move(src, dst, *a, **k)

    with patch("shutil.move", _move):
        r = clear_case_run(str(case), clear_memory=False)
    assert r["success"] is False and "No space left" in r["errors"][0]
    assert _tree(case) == before


def test_the_reports_folder_itself_is_kept(tmp_path):
    """Only what reports/ holds moves: the folder keeps its mode (a setgid
    group folder of a shared case) and a link to another disk stays a link."""
    from tools.misc import clear_case_run
    case = _finished_case(tmp_path)
    os.chmod(case / "reports", 0o2775)
    r = clear_case_run(str(case), clear_memory=False)
    assert r["success"] is True
    assert (os.stat(case / "reports").st_mode & 0o7777) == 0o2775
    linked = _finished_case(tmp_path / "linked")
    elsewhere = tmp_path / "other-disk" / "reports"
    elsewhere.parent.mkdir()
    os.rename(linked / "reports", elsewhere)
    (linked / "reports").symlink_to(elsewhere)
    r = clear_case_run(str(linked), clear_memory=False)
    assert r["success"] is True
    assert (linked / "reports").is_symlink() and os.readlink(linked / "reports") == str(elsewhere)
    assert not os.listdir(elsewhere)
    assert (Path(r["archive"]) / "reports" / "rerun_0001" / "CASE-A_investigation_report.md").is_file()


def test_a_second_clear_in_the_same_second_gets_its_own_archive(tmp_path):
    from tools.misc import clear_case_run
    case = _finished_case(tmp_path)
    history = case / ".atlas" / "run_history"
    now = _dt.datetime.now(_dt.timezone.utc)
    taken = {f"trace-{(now + _dt.timedelta(seconds=s)).strftime('%Y%m%dT%H%M%SZ')}" for s in (0, 1, 2)}
    for name in taken:
        (history / name).mkdir(parents=True)
    r = clear_case_run(str(case), clear_memory=False)
    assert r["success"] is True
    name = Path(r["archive"]).name
    assert name not in taken and name.rsplit("-", 1)[0] in taken
    assert (Path(r["archive"]) / "reports" / "rerun_0001").is_dir()


def test_the_start_message_names_the_archive_and_what_was_deleted(tmp_path, capsys):
    from agent import cli
    case = _finished_case(tmp_path)
    cli._prepare_run_isolation(SimpleNamespace(resume=False, fresh=False), case)
    err = capsys.readouterr().err
    assert "run_history" in err and "analysis/ and exports/ were deleted" in err


def test_a_refused_clear_names_its_reason(tmp_path):
    from agent import cli
    with pytest.raises(SystemExit) as ended:
        cli._exit_on_clear_failure({"success": False, "errors": ["Refusing to clear: mounted"]})
    assert "Refusing to clear: mounted" in str(ended.value.code)
    with pytest.raises(SystemExit) as ended:
        cli._exit_on_clear_failure({"success": False, "error": "a handling stop stands"})
    assert "handling stop" in str(ended.value.code)
    cli._exit_on_clear_failure({"success": True, "errors": []})


# ── an exit before the session settles the intake record ─────────────────────

def _drive(case: Path, make_agent):
    from agent import cli as cli_mod
    args = SimpleNamespace(json=False, quiet=False, remote=None, output_dir=None,
                           question=None, case_id="")
    with patch("core.incremental.plane_a_scan", return_value={"success": True, "case_id": "CASE-A"}), \
         patch("core.evidence_inventory_gate.clear_inventory_stamp"), \
         patch.object(cli_mod, "_configure_remote", return_value=None), \
         patch.object(cli_mod, "_make_agent", make_agent), \
         patch.object(cli_mod, "_resolve_case_question", return_value="What happened?"), \
         patch("core.paths.register_answer_keys"), \
         patch("core.brain.answer_key.has_ground_truth", return_value=False):
        cli_mod._run_investigation(args, case, command="run")


@pytest.mark.parametrize("resume", [False, True])
def test_a_configuration_exit_after_plane_a_ends_the_running_record(tmp_path, monkeypatch, resume):
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "default")
    case = _finished_case(tmp_path)
    if not resume:
        (case / ".atlas" / "run_status.json").write_text(json.dumps(
            {"stopped_reason": "starting", "finish_status": ""}), encoding="utf-8")
    ended = MagicMock(side_effect=SystemExit("atlas: model 'corp-model-1' is not served by corp-gateway"))
    with pytest.raises(SystemExit):
        _drive(case, ended)
    status = json.loads((case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["stopped_reason"] == "crashed" and status["finish_status"] == "error"
    assert "not served by" in status["error"]


def test_a_session_record_is_never_overwritten_by_the_intake(tmp_path, monkeypatch):
    """The session ends on a provider failure, records it and exits 1; the
    exit passes through the intake guard, which must leave that record."""
    from agent.llm import LLMError
    monkeypatch.setenv("ATLAS_EFFORT_AGENT", "default")
    case = _finished_case(tmp_path)
    agent = SimpleNamespace(ui=MagicMock(), stats=None, interactive=False,
                            toolbox=SimpleNamespace(namespace_summary=lambda: "ns"),
                            run=MagicMock(side_effect=LLMError("context limit reached")))
    with patch("agent.prompts.build_system_prompt", return_value="sys"), \
         patch("agent.prompts.initial_user_message", return_value="user"), \
         patch("agent.cli._teardown_local_mounts"), \
         patch("agent.cli._reports_at_exit"), \
         pytest.raises(SystemExit):
        _drive(case, MagicMock(return_value=agent))
    status = json.loads((case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["stopped_reason"] == "llm_error"


def test_make_agent_takes_the_checked_client_without_checking_again(tmp_path):
    from agent import cli

    class _Stop(Exception):
        pass

    checked = MagicMock(model="corp-model-1")
    checked.learned_max_tools.side_effect = _Stop      # the step after the client
    again = MagicMock()
    with patch.object(cli, "_analyst_client", again), \
         patch("core.provider_profiles.pin_for_children"), \
         pytest.raises(_Stop):
        cli._make_agent(SimpleNamespace(quiet=True, skin=None, model=None), None, client=checked)
    again.assert_not_called()


def test_a_rerun_whose_session_cannot_start_ends_the_running_record(tmp_path):
    from agent import cli as cli_mod
    case = _finished_case(tmp_path)
    plane = {"success": True, "case_id": "CASE-A",
             "work": {"pending": True, "reasons": ["1 open question"]},
             "context_reconcile": {"added": [], "reactivated": [], "withdrawn": []}}
    args = SimpleNamespace(
        case=str(case), diff=None, list_runs=False, question=None, withdraw_context=None,
        correct_context=None, dry_run=False, json=False, full_hash=False,
        regenerate_sections=False, assemble_report=False, report_format="markdown",
        no_agent=False, model=None, language=None)
    with patch("core.run_lock.acquire", return_value=None), \
         patch("core.incremental.plane_a_scan", return_value=plane), \
         patch.object(cli_mod, "_open_trace_before_plane_a"), \
         patch.object(cli_mod, "_require_sudo_preflight"), \
         patch.object(cli_mod, "_run_plane_b",
                      side_effect=SystemExit("atlas: no API key for provider 'corp-gateway'")), \
         pytest.raises(SystemExit):
        cli_mod.cmd_rerun(args)
    status = json.loads((case / ".atlas" / "run_status.json").read_text(encoding="utf-8"))
    assert status["stopped_reason"] == "crashed" and "no API key" in status["error"]


# ── a session never clears its own case ──────────────────────────────────────

def test_no_session_toolbox_offers_or_resolves_the_clear():
    """The clear belongs to a run's start and to an operator: the analyst's
    toolbox neither lists it nor runs a call that names it."""
    from agent.toolbox import Toolbox
    tb = Toolbox()
    assert "misc_clear_case_run" not in tb.tools
    assert tb.resolve("misc_clear_case_run") is None
    assert tb.resolve("misc.clear_case_run") is None
    text, _ = tb.call("misc_clear_case_run", {"case_dir": "/cases/CASE-A"})
    assert text.startswith("ERROR: unknown tool")
    assert "misc_list_evidence_dir" in tb.tools          # the rest of misc stays


def test_the_operator_paths_still_reach_the_clear(tmp_path):
    """A fresh start (agent/cli.py) and the MCP server, which serves an
    operator's own client, still have it."""
    import inspect
    from agent import cli
    from tools import misc
    assert "clear_case_run" in inspect.getsource(cli._prepare_run_isolation)
    assert "clear_case_run" in inspect.getsource(cli._train_locked)
    assert callable(misc.clear_case_run)
    from tools.tool_capabilities import registered_tool_schemas
    assert "misc_clear_case_run" in {row[0] for row in registered_tool_schemas()}
