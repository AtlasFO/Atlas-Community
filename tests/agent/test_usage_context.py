"""The usage ledger's context in the CLI: one run id per command, the
brief's case id, and a missing user name never stops a run."""
from __future__ import annotations

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
