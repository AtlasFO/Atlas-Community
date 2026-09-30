"""Runs of several cases on one host: a second start of a live case fails
before it changes anything, nothing clears, moves or deletes a case under a
live run, a loop device is detached only by its own case, and mail carries
the headers receiving servers expect."""
from __future__ import annotations

import fcntl
import os
from argparse import Namespace
from email import message_from_bytes

import pytest

from core import run_lock


def _case(tmp_path, name="CASE"):
    case = tmp_path / name
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "CASE.md").write_text(f"# Case: {name}\n\n**Case ID:** {name}\n", encoding="utf-8")
    return case


def _held_by_another(case):
    """A lock on the case's lock file through a descriptor run_lock does not
    know: to run_lock it is another process's."""
    fd = os.open(str(case / ".atlas" / "run.lock"), os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def test_the_holder_tells_its_own_lock_from_another(tmp_path):
    case = _case(tmp_path)
    fd = run_lock.acquire(case)
    try:
        assert run_lock.held_here(case) and not run_lock.held_elsewhere(case)
        assert run_lock.is_locked(case)
    finally:
        run_lock.release(fd)
    assert not run_lock.held_here(case) and not run_lock.is_locked(case)
    other = _held_by_another(case)
    try:
        assert run_lock.held_elsewhere(case)
    finally:
        os.close(other)


def test_a_second_start_of_a_live_case_changes_nothing(tmp_path, monkeypatch):
    from agent import cli
    case = _case(tmp_path)
    (case / "analysis" / "CASE_trace.json").write_text("{}", encoding="utf-8")
    calls = []
    monkeypatch.setattr("tools.misc.clear_case_run", lambda *a, **k: calls.append(a) or {})
    monkeypatch.setattr(cli, "_apply_report_language", lambda *a, **k: calls.append("lang"))
    other = _held_by_another(case)
    try:
        with pytest.raises(SystemExit) as exc:
            cli.cmd_run(Namespace(case=str(case), no_capture_brain=True, fresh=True, resume=False,
                                  language=None, json=False, quiet=True))
        assert "already in progress" in str(exc.value)
    finally:
        os.close(other)
    assert calls == []
    assert (case / "analysis" / "CASE_trace.json").exists()


def test_the_lock_is_held_for_the_whole_command(tmp_path, monkeypatch):
    from agent import cli
    case = _case(tmp_path)
    seen = {}

    def fake_investigation(args, case_dir, command="run", lock_fd=None):
        seen["lock_fd"] = lock_fd
        seen["held"] = run_lock.held_here(case_dir)
        raise SystemExit(4)

    monkeypatch.setattr(cli, "_require_sudo_preflight", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_apply_report_language", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_prepare_run_isolation", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_run_investigation", fake_investigation)
    with pytest.raises(SystemExit):
        cli.cmd_run(Namespace(case=str(case), no_capture_brain=True))
    assert seen["held"] is True and isinstance(seen["lock_fd"], int)
    assert not run_lock.held_here(case) and not run_lock.is_locked(case)


def test_nothing_clears_a_case_another_process_is_running(tmp_path):
    from tools.misc import clear_case_run
    case = _case(tmp_path)
    (case / "analysis" / "CASE_trace.json").write_text("{}", encoding="utf-8")
    other = _held_by_another(case)
    try:
        result = clear_case_run(str(case), clear_memory=False)
    finally:
        os.close(other)
    assert result["success"] is False and result["gate"] == "run_lock"
    assert (case / "analysis" / "CASE_trace.json").exists()


def test_the_dashboard_neither_moves_nor_deletes_a_running_case(tmp_path):
    from dashboard import case_admin
    root = tmp_path / "cases"
    case = _case(root, "LIVE")
    other = _held_by_another(case)
    try:
        with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
            case_admin.delete_case(str(root), "LIVE")
        with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
            case_admin.move_case(str(root), "LIVE", "LIVE2")
    finally:
        os.close(other)
    assert case.is_dir()


def test_a_loop_device_is_detached_only_by_its_own_case(tmp_path, monkeypatch):
    from tools import imaging
    case = _case(tmp_path)
    (case / "evidence").mkdir()
    image = case / "evidence" / "disk.raw"
    image.write_bytes(b"\x00" * 16)
    elsewhere = tmp_path / "other" / "disk.raw"
    elsewhere.parent.mkdir()
    elsewhere.write_bytes(b"\x00" * 16)
    sysfs = tmp_path / "sys"
    for n, backing in ((3, image), (4, elsewhere)):
        (sysfs / f"loop{n}").mkdir(parents=True)
        (sysfs / f"loop{n}" / "backing_file").write_text(f"{backing}\n", encoding="utf-8")
    monkeypatch.setattr(imaging, "_LOOP_BACKING_FILE", str(sysfs / "loop{n}" / "backing_file"))
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))
    ran = []
    monkeypatch.setattr(imaging, "run", lambda cmd, **k: ran.append(cmd) or {"success": True})
    detach = getattr(imaging.losetup_detach, "fn", imaging.losetup_detach)
    assert detach("/dev/loop3")["success"] is True and ran == [["losetup", "-d", "/dev/loop3"]]
    refused = detach("/dev/loop4")
    assert refused["success"] is False and "outside this case" in refused["error"]
    assert detach("/dev/sda")["success"] is False
    assert detach("/dev/loop9")["success"] is False
    monkeypatch.setattr("core.paths.active_case_dir", lambda: None)
    assert detach("/dev/loop3")["success"] is False
    assert len(ran) == 1


def test_mail_carries_a_date_and_a_message_id_from_the_sender_domain(monkeypatch):
    from core import mail
    sent = []

    class FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def send_message(self, msg):
            sent.append(msg.as_bytes())

    monkeypatch.setenv("ATLAS_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("ATLAS_SMTP_FROM", "Atlas <atlas@example.test>")
    monkeypatch.setattr(mail, "_smtp_connect", lambda cfg: FakeSMTP())
    mail.send_mail("someone@example.org", "subject", "body")
    msg = message_from_bytes(sent[0])
    assert msg["Date"]
    assert msg["Message-ID"].endswith("@example.test>")
