"""The privileged group kill: sudo kill -KILL on the group Atlas created for
a tool it ran through sudo, refused for any group that is not that one."""
import os

from core import privileged_kill as pk


def test_the_group_is_killed_through_sudo(no_privileged_kill, monkeypatch):
    import subprocess
    monkeypatch.setattr(pk, "_run", lambda cmd, **kw: (no_privileged_kill.append(list(cmd)),
                                                      subprocess.CompletedProcess(cmd, 0))[1])
    assert pk.kill_group_as_root(987654) is True
    assert no_privileged_kill == [["sudo", "-n", "kill", "-KILL", "--", "-987654"]]


def test_a_refused_sudo_is_reported(no_privileged_kill):
    assert pk.kill_group_as_root(987654) is False
    assert len(no_privileged_kill) == 1


def test_our_own_group_and_the_low_numbers_are_never_signalled(no_privileged_kill):
    for pgid in (os.getpgrp(), os.getsid(0), 1, 0, -5, "x"):
        assert pk.kill_group_as_root(pgid) is False
    assert no_privileged_kill == []


def test_a_number_now_held_by_another_process_is_not_signalled(no_privileged_kill):
    """The leader was reaped and its number handed to a new process: that
    process's start time differs from the one recorded at spawn."""
    me = os.getpid()
    assert pk.start_time(me) is not None
    assert pk.kill_group_as_root(me, leader_start="1") is False
    assert no_privileged_kill == []
    # The same start time is our own leader, still alive: the kill goes out.
    pk.kill_group_as_root(me, leader_start=pk.start_time(me))
    assert no_privileged_kill == [["sudo", "-n", "kill", "-KILL", "--", f"-{me}"]]


def test_the_start_time_of_a_missing_process_is_none():
    assert pk.start_time(2 ** 22 + 12345) is None
