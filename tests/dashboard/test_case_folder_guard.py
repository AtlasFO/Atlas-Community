"""A case folder is renamed or deleted only while no run is live, checked
and changed under the run manager's lock: a run this dashboard just
started counts from its spawn on, before the child has taken the run lock,
and no start can begin between the check and the rename. A purge needs the
case named twice, leaves the case list at once (renamed into .deleted/),
is on record from that point, and says which folder is left when the
removal fails. An open chat worker for the case is ended first. Invented
cases only."""
from __future__ import annotations

import http.client
import json
import os
import threading
import time

import pytest

from dashboard import auth, case_admin, chat, run_manager
from tests.tools.test_dashboard import standalone_server  # noqa: F401


@pytest.fixture
def cases_root(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    return str(root)


class _LiveSession:
    """A session as RunManager.start leaves it the moment the child is
    spawned: alive, no run lock taken, nothing written yet."""
    alive = True


@pytest.fixture
def live(monkeypatch):
    sessions = {}
    monkeypatch.setattr(run_manager.MANAGER, "_sessions", sessions)
    return sessions


def test_a_run_started_a_moment_ago_blocks_delete_and_rename(cases_root, live):
    case_admin.create_case(cases_root, "CASE-A")
    live["CASE-A"] = _LiveSession()
    with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
        case_admin.delete_case(cases_root, "CASE-A")
    with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
        case_admin.delete_case(cases_root, "CASE-A", purge=True)
    with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
        case_admin.move_case(cases_root, "CASE-A", "CASE-B")
    assert os.path.isdir(os.path.join(cases_root, "CASE-A"))
    assert not os.path.exists(os.path.join(cases_root, "CASE-B"))
    live["CASE-A"].alive = False
    assert case_admin.delete_case(cases_root, "CASE-A")["action"] == "moved_to_trash"


@pytest.mark.parametrize("action", ["delete", "purge", "rename"])
def test_a_refused_change_touches_nothing_of_the_live_run(cases_root, live, monkeypatch, action):
    """A delete or rename refused because the case runs must not first pull
    the run's evidence mounts or end its chat worker."""
    case_admin.create_case(cases_root, "CASE-A")
    live["CASE-A"] = _LiveSession()
    touched = []
    monkeypatch.setattr(case_admin, "unmount_all_under", lambda *a, **k: touched.append("unmount") or {"remaining": []})
    monkeypatch.setattr(chat.MANAGER, "close_case", lambda name: touched.append("chat"))
    with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
        if action == "rename":
            case_admin.move_case(cases_root, "CASE-A", "CASE-B")
        else:
            case_admin.delete_case(cases_root, "CASE-A", purge=action == "purge")
    assert touched == []
    assert os.path.isdir(os.path.join(cases_root, "CASE-A"))


@pytest.mark.parametrize("action", ["delete", "rename"])
def test_a_run_started_after_the_first_check_still_stops_the_rename(cases_root, live, monkeypatch, action):
    """The busy read before the unmount is released at once; the check that
    guards the folder change runs again under the lock, right before it."""
    case_admin.create_case(cases_root, "CASE-A")
    # The start lands while the chat worker is being closed, after the first check.
    monkeypatch.setattr(chat.MANAGER, "close_case", lambda name: live.__setitem__("CASE-A", _LiveSession()))
    with pytest.raises(case_admin.CaseAdminError, match="run is in progress"):
        if action == "rename":
            case_admin.move_case(cases_root, "CASE-A", "CASE-B")
        else:
            case_admin.delete_case(cases_root, "CASE-A")
    assert os.path.isdir(os.path.join(cases_root, "CASE-A"))


def test_no_start_slips_in_between_the_check_and_the_rename(cases_root, live):
    case_admin.create_case(cases_root, "CASE-A")
    outcome = {}

    def start():
        try:
            run_manager.MANAGER.start(cases_root, "CASE-A")
        except run_manager.RunError as exc:
            outcome["error"] = str(exc)
    with run_manager.MANAGER.held(cases_root, "CASE-A") as busy:
        assert busy == ""
        t = threading.Thread(target=start)
        t.start()
        time.sleep(0.3)
        assert t.is_alive(), "a start must wait while the folder is being changed"
        os.rename(os.path.join(cases_root, "CASE-A"), os.path.join(cases_root, "CASE-Z"))
    t.join(5)
    assert "no such case" in outcome["error"]


def test_a_case_folder_on_another_filesystem_is_refused(cases_root, monkeypatch):
    case_admin.create_case(cases_root, "CASE-A")
    real = os.stat
    case = os.path.join(cases_root, "CASE-A")

    def stat(p, *a, **k):
        st = real(p, *a, **k)
        if os.fspath(p) != case:
            return st
        fields = list(st)
        fields[2] += 1          # st_dev: the folder is its own mount
        return os.stat_result(fields)
    monkeypatch.setattr(case_admin.os, "stat", stat)
    with pytest.raises(case_admin.CaseAdminError, match="another filesystem"):
        case_admin.delete_case(cases_root, "CASE-A")
    with pytest.raises(case_admin.CaseAdminError, match="another filesystem"):
        case_admin.move_case(cases_root, "CASE-A", "CASE-B")
    assert os.path.isdir(case)


def test_an_open_chat_for_the_case_is_ended_before_the_folder_moves(cases_root, monkeypatch):
    closed = []
    monkeypatch.setattr(chat.MANAGER, "close_case", closed.append)
    case_admin.create_case(cases_root, "CASE-A")
    case_admin.move_case(cases_root, "CASE-A", "CASE-B")
    case_admin.delete_case(cases_root, "CASE-B")
    assert closed == ["CASE-A", "CASE-B"]


def test_a_purge_leaves_the_list_first_and_names_what_is_left_when_removal_fails(cases_root, monkeypatch):
    case_admin.create_case(cases_root, "CASE-A")
    seen = []

    def boom(path, *a, **k):
        raise OSError(16, "Device or resource busy")
    monkeypatch.setattr(case_admin.shutil, "rmtree", boom)
    with pytest.raises(case_admin.PurgeIncomplete, match=r"\.deleted/CASE-A-.*-purging") as err:
        case_admin.delete_case(cases_root, "CASE-A", purge=True,
                               on_committed=lambda: seen.append("committed"))
    assert seen == ["committed"]
    assert not os.path.exists(os.path.join(cases_root, "CASE-A"))
    left = os.listdir(os.path.join(cases_root, ".deleted"))
    assert len(left) == 1 and left[0].endswith("-purging") and left[0] in str(err.value)


def _post(server, route, body):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=10)
    conn.request("POST", f"/_dashboard/api/{route}", body=json.dumps(body).encode(),
                 headers={"Content-Type": "application/json"})
    try:
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read() or b"{}")
    finally:
        conn.close()


def _events():
    return [(r["event"], r["case_id"]) for r in auth.list_activity()[0]]


def test_a_purge_needs_the_case_named_twice_and_is_on_record(standalone_server):
    srv = standalone_server
    assert _post(srv, "case/create", {"case_id": "CASE-A"})[0] == 200
    case = srv["cases_root"] / "CASE-A"
    for confirm in (None, "", "case-a", "CASE-B"):
        body = {"case_id": "CASE-A", "purge": True, **({} if confirm is None else {"confirm_case": confirm})}
        status, data = _post(srv, "case/delete", body)
        assert status == 400 and data["confirm_case_required"] is True, (confirm, data)
        assert case.is_dir()
    status, data = _post(srv, "case/delete", {"case_id": "CASE-A", "purge": True, "confirm_case": "CASE-A"})
    assert status == 200 and data["action"] == "purged"
    assert not case.exists() and not os.listdir(srv["cases_root"] / ".deleted")
    assert ("case_purge", "CASE-A") in _events()


def test_a_delete_and_a_rename_are_on_record(standalone_server):
    srv = standalone_server
    assert _post(srv, "case/create", {"case_id": "CASE-A"})[0] == 200
    assert _post(srv, "case/move", {"case_id": "CASE-A", "new_case_id": "CASE-B"})[0] == 200
    assert _post(srv, "case/delete", {"case_id": "CASE-B"})[0] == 200
    events = _events()
    assert ("case_move", "CASE-A") in events and ("case_delete", "CASE-B") in events


def test_a_failed_removal_answers_with_the_folder_left_behind(standalone_server, monkeypatch):
    srv = standalone_server
    assert _post(srv, "case/create", {"case_id": "CASE-A"})[0] == 200
    monkeypatch.setattr(case_admin.shutil, "rmtree", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "denied")))
    status, data = _post(srv, "case/delete", {"case_id": "CASE-A", "purge": True, "confirm_case": "CASE-A"})
    assert status == 500 and "-purging" in data["error"] and "by hand" in data["error"]
    assert ("case_purge", "CASE-A") in _events()


def test_only_an_admin_may_delete_rename_or_purge():
    assert auth.ROUTE_MIN_ROLE["case/delete"] == "admin"
    assert auth.ROUTE_MIN_ROLE["case/move"] == "admin"
