"""The usage ledger's context in the CLI: one run id per command, the
brief's case id, and a missing user name never stops a run."""
from __future__ import annotations

import json
from types import SimpleNamespace

from core import usage_ledger


def test_a_command_keeps_its_run_id_when_the_agent_starts_later(tmp_path):
    from agent import cli
    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.md").write_text("# Case\n\n**Case ID:** BRIEF-ID\n", encoding="utf-8")
    cli._configure_usage(case, "rerun")
    first = usage_ledger.current()
    assert first["case_id"] == "BRIEF-ID" and first["command"] == "rerun" and first["run_id"]
    cli._configure_usage(case, "rerun", "20990101T000000Z")
    assert usage_ledger.current()["run_id"] == first["run_id"]
    other = tmp_path / "other"
    other.mkdir()
    cli._configure_usage(other, "run", "20990101T000000Z")
    assert usage_ledger.current()["case_id"] == "other"
    assert usage_ledger.current()["run_id"] == "20990101T000000Z"


def test_a_user_without_a_name_records_none(tmp_path, monkeypatch):
    import getpass
    from agent import cli

    def no_name():
        raise OSError("no passwd entry")

    monkeypatch.setattr(getpass, "getuser", no_name)
    monkeypatch.delenv("ATLAS_RUN_USER", raising=False)
    case = tmp_path / "case"
    case.mkdir()
    cli._configure_usage(case, "run", "20990101T000000Z")
    assert usage_ledger.current()["started_by"] == ""


def _transcript(case, command, stamp):
    from agent.loop import Agent
    return Agent(SimpleNamespace(), SimpleNamespace(), case, ui=SimpleNamespace(),
                 command=command, stamp=stamp).transcript_path


def test_a_rerun_names_its_transcript_after_its_ledger_run(tmp_path):
    """The rerun configures the ledger before its agent starts; the agent's
    transcript carries that id, so the history import finds the run known
    instead of adding it a second time."""
    from agent import cli
    from core import usage_import
    case = tmp_path / "cases" / "case"
    case.mkdir(parents=True)
    early = cli._configure_usage(case, "rerun", "20310102T000000Z")
    run_id = cli._agent_run(case, "rerun")
    transcript = _transcript(case, "rerun", run_id)
    assert run_id == early == usage_ledger.current()["run_id"]
    assert transcript.name == f"agent_transcript_{run_id}.jsonl"
    usage_ledger.record(role="analyst", provider="p", model="m", input_tokens=5, output_tokens=1)
    start = json.dumps({"event": "run_start", "roles": {"analyst": "m"}}) + "\n"
    transcript.write_text(start, encoding="utf-8")
    assert usage_import.import_history(str(tmp_path / "cases"))["runs"] == 0
    (case / "analysis" / "agent_transcript_20310101T000000Z.jsonl").write_text(start, encoding="utf-8")
    assert usage_import.import_history(str(tmp_path / "cases"))["runs"] == 1   # an unknown run is added


def test_an_agent_never_takes_a_run_id_inherited_from_its_parent(tmp_path, monkeypatch):
    """A child process inherits its parent's ledger context through the
    environment; its agent gets a run id and a transcript of its own."""
    from agent import cli
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.setenv(usage_ledger.ENV_CONTEXT, json.dumps(
        {"case_id": "case", "run_id": "20310101T000000Z", "command": "run"}))
    run_id = cli._agent_run(case, "run")
    assert run_id != "20310101T000000Z" and usage_ledger.current()["run_id"] == run_id


def test_an_id_a_transcript_already_carries_is_not_reused(tmp_path):
    from agent import cli
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    cli._configure_usage(case, "rerun", "20310101T000000Z")
    (case / "analysis" / "agent_transcript_20310101T000000Z.jsonl").write_text("{}\n", encoding="utf-8")
    run_id = cli._agent_run(case, "rerun")
    assert run_id != "20310101T000000Z" and usage_ledger.current()["run_id"] == run_id


def test_a_chat_transcript_keeps_its_own_name(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    assert _transcript(case, "chat", "20310101T000000Z").name == "chat_transcript_20310101T000000Z.jsonl"
