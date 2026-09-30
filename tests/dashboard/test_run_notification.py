"""A run outlives the tab that started it, so the person who started it is
told when it ends — best-effort in every direction."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core import mail
from dashboard import run_manager


def _status(**over):
    base = {"finish_status": "complete", "stopped_reason": "finished",
            "turns": 42, "tool_calls": 310, "findings_recorded": 9,
            "error_count": 0, "duration_seconds": 5400.0}
    base.update(over)
    return base


class TestRunFinishedMessage:
    def test_it_carries_the_outcome_and_the_numbers(self):
        sent = {}
        with patch.object(mail, "send_mail",
                          side_effect=lambda to, s, b: sent.update(
                              to=to, subject=s, body=b)):
            mail.send_run_finished_email("analyst@example.com", "CASE-1",
                                         _status())
        assert sent["to"] == "analyst@example.com"
        assert "CASE-1" in sent["subject"] and "complete" in sent["subject"]
        for fragment in ("Turns:", "42", "Tool calls:", "310", "90 min"):
            assert fragment in sent["body"]

    def test_it_carries_no_case_content(self):
        """A mailbox is not a place for evidence — only run bookkeeping."""
        sent = {}
        with patch.object(mail, "send_mail",
                          side_effect=lambda to, s, b: sent.update(body=b)):
            mail.send_run_finished_email(
                "a@example.com", "CASE-1",
                _status(recent_errors=["/evidence/secret-disk.E01 failed"],
                        activity="reading C:/Users/someone/NTUSER.DAT"))
        assert "secret-disk" not in sent["body"]
        assert "NTUSER" not in sent["body"]

    def test_an_unknown_outcome_still_produces_a_message(self):
        sent = {}
        with patch.object(mail, "send_mail",
                          side_effect=lambda to, s, b: sent.update(subject=s)):
            mail.send_run_finished_email("a@example.com", "C", {})
        assert "ended" in sent["subject"]


class TestNotifyOnExit:
    def _session(self, tmp_path, notify="analyst@example.com"):
        sess = run_manager.RunSession.__new__(run_manager.RunSession)
        sess.case_dir = str(tmp_path)
        sess.case_name = "CASE-1"
        sess.notify_email = notify
        sess.proc = MagicMock()
        sess.proc.wait.return_value = 0
        return sess

    def test_it_sends_once_the_process_exits(self, tmp_path):
        atlas = tmp_path / ".atlas"
        atlas.mkdir()
        (atlas / "run_status.json").write_text(json.dumps(_status()),
                                               encoding="utf-8")
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email") as send:
            self._session(tmp_path)._notify_on_exit()
        send.assert_called_once()
        assert send.call_args[0][0] == "analyst@example.com"
        assert send.call_args[0][2]["turns"] == 42

    def test_no_mail_server_means_no_notification_and_no_error(self, tmp_path):
        with patch.object(mail, "is_configured", return_value=False), \
             patch.object(mail, "send_run_finished_email") as send:
            self._session(tmp_path)._notify_on_exit()
        send.assert_not_called()

    def test_a_refused_message_never_escapes(self, tmp_path, capsys):
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email",
                          side_effect=mail.MailError("relay refused")):
            self._session(tmp_path)._notify_on_exit()   # must not raise
        assert "could not send" in capsys.readouterr().err

    def test_an_unreadable_status_still_sends_what_is_known(self, tmp_path):
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email") as send:
            self._session(tmp_path)._notify_on_exit()
        send.assert_called_once()
        assert send.call_args[0][2] == {}


class TestStartWiring:
    def test_the_manager_passes_the_address_to_the_session(self, tmp_path,
                                                           monkeypatch):
        case = tmp_path / "CASE-1"
        (case / ".atlas").mkdir(parents=True)
        captured = {}

        class FakeSession:
            def __init__(self, *a, **kw):
                captured.update(kw)
            alive = False

        monkeypatch.setattr(run_manager, "RunSession", FakeSession)
        with patch("dashboard.read_models.run_process_alive", return_value=False), \
             patch("core.run_lock.is_locked", return_value=False):
            run_manager.MANAGER.start(str(tmp_path), "CASE-1",
                                      notify_email="analyst@example.com")
        assert captured["notify_email"] == "analyst@example.com"


class TestCliRunNotifies:
    """A run started from the terminal reports its own ending; one started by
    the dashboard does not, because the dashboard already does."""

    def _stats(self):
        return {"finish_status": "complete", "turns": 7}

    def test_it_sends_when_an_address_is_configured(self, tmp_path,
                                                    monkeypatch):
        from agent import cli
        monkeypatch.setenv("ATLAS_RUN_NOTIFY_EMAIL", "me@example.com")
        monkeypatch.delenv("ATLAS_RUN_NOTIFY_HANDLED", raising=False)
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email") as send:
            cli._notify_run_finished(tmp_path / "CASE-9", self._stats())
        send.assert_called_once()
        assert send.call_args[0][:2] == ("me@example.com", "CASE-9")

    def test_no_address_means_no_mail(self, tmp_path, monkeypatch):
        from agent import cli
        monkeypatch.delenv("ATLAS_RUN_NOTIFY_EMAIL", raising=False)
        with patch.object(mail, "send_run_finished_email") as send:
            cli._notify_run_finished(tmp_path / "C", self._stats())
        send.assert_not_called()

    def test_a_dashboard_started_run_stays_quiet(self, tmp_path, monkeypatch):
        """No duplicate: the dashboard watches this process and sends."""
        from agent import cli
        monkeypatch.setenv("ATLAS_RUN_NOTIFY_EMAIL", "me@example.com")
        monkeypatch.setenv("ATLAS_RUN_NOTIFY_HANDLED", "1")
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email") as send:
            cli._notify_run_finished(tmp_path / "C", self._stats())
        send.assert_not_called()

    def test_a_failed_send_never_reaches_the_run(self, tmp_path, monkeypatch,
                                                 capsys):
        from agent import cli
        monkeypatch.setenv("ATLAS_RUN_NOTIFY_EMAIL", "me@example.com")
        monkeypatch.delenv("ATLAS_RUN_NOTIFY_HANDLED", raising=False)
        with patch.object(mail, "is_configured", return_value=True), \
             patch.object(mail, "send_run_finished_email",
                          side_effect=mail.MailError("relay refused")):
            cli._notify_run_finished(tmp_path / "C", self._stats())
        assert "could not send" in capsys.readouterr().err


