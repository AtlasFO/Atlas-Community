"""A case is named by its folder name in every request, and the dashboard
acts on no case a request does not name exactly: create answers with the
name, a path form, an unknown or an empty case is a 404 before anything
runs, stops, chats or writes, and a start that removes the case's working
files needs the case named a second time (confirm_case). Invented cases
only (CASE-A, CASE-B), on a scratch server."""
from __future__ import annotations

import http.client
import json

import pytest

from dashboard import chat, run_manager
from tests.tools.test_dashboard import standalone_server  # noqa: F401


def _post(server, route, body):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=5)
    conn.request("POST", f"/_dashboard/api/{route}", body=json.dumps(body).encode(),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read() or b"{}")


def _get(server, route):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=5)
    conn.request("GET", f"/_dashboard/api/{route}")
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read() or b"{}")


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, *a, **k):
        self.calls.append((a, k))
        return type("Sess", (), {"status": lambda self: {"state": "running"}})()


@pytest.fixture
def server(standalone_server, monkeypatch):
    rec = {"start": _Recorder(), "stop": _Recorder(), "chat": _Recorder()}
    monkeypatch.setattr(run_manager.MANAGER, "start", rec["start"])
    monkeypatch.setattr(run_manager.MANAGER, "stop", lambda *a, **k: rec["stop"](*a, **k) and {"success": True})
    monkeypatch.setattr(chat.MANAGER, "get_or_spawn", rec["chat"])
    for name in ("CASE-A", "CASE-B"):
        assert _post(standalone_server, "case/create", {"case_id": name})[0] == 200
    return standalone_server, rec


def test_create_answers_with_the_name_the_case_list_and_every_route_use(standalone_server):
    status, data = _post(standalone_server, "case/create", {"case_id": "CASE-A"})
    assert status == 200 and data["case_dir"] == "CASE-A"
    assert "CASE-A" in [c["case_dir"] for c in _get(standalone_server, "cases")[1]["cases"]]
    assert _get(standalone_server, "case/run/status?case=CASE-A")[0] == 200


@pytest.mark.parametrize("route,extra", [("case/run/start", {"mode": "run"}), ("case/run/stop", {}),
                                         ("chat/send", {"message": "what ran on CORP-WS01?"}),
                                         ("case/case_md/save", {"content": "# CASE-B\n"})])
def test_a_path_form_unknown_or_empty_case_is_refused_before_anything_acts(server, route, extra):
    srv, rec = server
    before = (srv["cases_root"] / "CASE-B" / "CASE.md").read_text()
    for case in (str(srv["cases_root"] / "CASE-B"), "CASE-NOPE", "", "../CASE-B"):
        status, data = _post(srv, route, {"case": case, **extra})
        assert status == 404, (route, case, status, data)
    assert not rec["start"].calls and not rec["stop"].calls and not rec["chat"].calls
    assert (srv["cases_root"] / "CASE-B" / "CASE.md").read_text() == before


def test_a_start_that_removes_the_working_files_needs_the_case_named_twice(server, monkeypatch):
    srv, rec = server
    import core.run_state as RS
    prior = {"CASE-A": True, "CASE-B": False}
    monkeypatch.setattr(RS, "prior_run_exists", lambda d: prior[str(d).rstrip("/").rsplit("/", 1)[-1]])
    wiping = [{"case": "CASE-A", "mode": "run"},                                       # over a prior run
              {"case": "CASE-B", "mode": "run", "options": {"start_mode": "fresh"}}]    # fresh
    for n, body in enumerate(wiping):
        for confirm in (None, "", "CASE-OTHER", str(srv["cases_root"] / body["case"])):
            status, data = _post(srv, "case/run/start", {**body, **({"confirm_case": confirm} if confirm is not None else {})})
            assert status == 400 and data["confirm_case_required"] is True, (body, confirm)
            assert data["error"] == (f"starting over removes the working files of {body['case']!r}; "
                                     "confirm the case name")
        assert len(rec["start"].calls) == n
        assert _post(srv, "case/run/start", {**body, "confirm_case": body["case"]})[0] == 200
        assert rec["start"].calls[-1][0][1] == body["case"]
    assert len(rec["start"].calls) == 2
    # no confirmation: a resume, a rerun, the first run of a case
    for body in ({"case": "CASE-A", "mode": "run", "options": {"start_mode": "resume"}},
                 {"case": "CASE-A", "mode": "rerun"}, {"case": "CASE-B", "mode": "run"}):
        assert _post(srv, "case/run/start", body)[0] == 200, body
    assert len(rec["start"].calls) == 5


@pytest.mark.parametrize("name", ["..", ".hidden", "", "CASE-A/../CASE-B", "/srv/cases/CASE-A", "a\\b"])
def test_the_run_manager_refuses_a_name_that_is_no_folder_name(tmp_path, name):
    (tmp_path / "CASE-A").mkdir()
    with pytest.raises(run_manager.RunError, match="invalid case name"):
        run_manager.RunManager(repo_root=str(tmp_path)).start(str(tmp_path), name)


def test_a_tracked_run_whose_folder_is_gone_can_still_be_stopped(server, monkeypatch):
    srv, rec = server
    tracked = {"CASE-GONE": object()}
    monkeypatch.setattr(run_manager.MANAGER, "get", lambda name: tracked.get(name))
    assert not (srv["cases_root"] / "CASE-GONE").exists()
    status, _data = _post(srv, "case/run/stop", {"case": "CASE-GONE"})
    assert status == 200 and len(rec["stop"].calls) == 1
    # a name the manager does not track and no folder holds stays refused
    assert _post(srv, "case/run/stop", {"case": "CASE-NOPE"})[0] == 404 and len(rec["stop"].calls) == 1
