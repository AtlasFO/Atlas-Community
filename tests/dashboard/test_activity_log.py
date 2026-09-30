"""The admin activity log: what is recorded, how it is pruned, cleared and
exported, and that only an administrator reaches it."""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from dashboard import auth


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()


def _admin():
    return auth.create_user("root", "root@example.com", "password123", "admin")


class TestStore:
    def test_events_are_recorded_newest_first_with_the_actor(self):
        adm = _admin()
        auth.log_event("login", user=adm, ip="10.0.0.5")
        auth.log_event("run_start", user=adm, case_id="CASE-A", detail="run --fresh")
        rows, total = auth.list_activity(10)
        assert total == 2
        assert [r["event"] for r in rows] == ["run_start", "login"]
        assert rows[1]["username"] == "root" and rows[1]["role"] == "admin"
        assert rows[1]["user_id"] == adm.id and rows[1]["ip"] == "10.0.0.5"
        assert rows[0]["case_id"] == "CASE-A" and rows[0]["detail"] == "run --fresh"

    def test_a_failed_sign_in_carries_the_typed_name_and_no_user(self):
        auth.log_event("login_failed", username="nobody", detail="invalid username or password")
        rows, _ = auth.list_activity(10)
        assert rows[0]["user_id"] is None and rows[0]["username"] == "nobody"
        assert rows[0]["role"] == ""

    def test_rows_older_than_the_retention_go_on_the_next_write(self):
        adm = _admin()
        auth.log_event("login", user=adm)
        old = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        with auth._connect() as conn:
            conn.execute("UPDATE activity_log SET ts = ?", (old,))
            conn.commit()
        auth.log_event("logout", user=adm)
        rows, total = auth.list_activity(10)
        assert total == 1 and rows[0]["event"] == "logout"

    def test_the_default_retention_is_ninety_days_and_bounds_hold(self):
        assert auth.activity_retention_days() == 90
        adm = _admin()
        assert auth.set_activity_retention(30, user=adm) == 30
        assert auth.activity_retention_days() == 30
        with pytest.raises(auth.AuthError):
            auth.set_activity_retention(0, user=adm)
        with pytest.raises(auth.AuthError):
            auth.set_activity_retention("many", user=adm)
        rows, _ = auth.list_activity(10)
        assert rows[0]["event"] == "retention_changed"
        assert rows[0]["detail"].startswith("90 -> 30 days")

    def test_lowering_the_retention_prunes_at_once(self):
        adm = _admin()
        auth.log_event("login", user=adm)
        old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        with auth._connect() as conn:
            conn.execute("UPDATE activity_log SET ts = ?", (old,))
            conn.commit()
        auth.set_activity_retention(5, user=adm)
        rows, total = auth.list_activity(10)
        assert total == 1 and rows[0]["event"] == "retention_changed"
        assert "1 entries removed" in rows[0]["detail"]

    def test_a_clear_leaves_one_row_that_says_so(self):
        adm = _admin()
        for _ in range(3):
            auth.log_event("login", user=adm)
        assert auth.clear_activity(user=adm, ip="10.0.0.5") == 3
        rows, total = auth.list_activity(10)
        assert total == 1
        assert rows[0]["event"] == "log_cleared" and rows[0]["username"] == "root"
        assert rows[0]["detail"] == "3 entries removed"

    def test_a_write_failure_never_raises(self, monkeypatch):
        monkeypatch.setattr(auth, "DEFAULT_DB_PATH", auth.DEFAULT_DB_PATH / "missing" / "auth.db")
        auth.log_event("login", username="x")  # the parent path is a file, not a directory


class TestCsvGuard:
    def test_formula_leaders_get_a_quote(self):
        from core.csv_safe import csv_safe
        assert csv_safe("=1+1") == "'=1+1"
        assert csv_safe("-x") == "'-x"
        assert csv_safe("+x") == "'+x"
        assert csv_safe("@x") == "'@x"
        assert csv_safe("\tx") == "'\tx"
        assert csv_safe("\rx") == "'\rx"
        assert csv_safe("plain") == "plain"
        assert csv_safe(None) == ""
        assert csv_safe(7) == "7"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def server(tmp_path):
    from dashboard import serve as dash_serve
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    port = _free_port()
    httpd, chosen = dash_serve._bind(str(cases_root), port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    try:
        yield chosen
    finally:
        httpd.shutdown()


def _req(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body)
    if cookie:
        headers["Cookie"] = f"atlas_session={cookie}"
    conn.request(method, "/_dashboard/api/" + path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        payload = json.loads(raw.decode())
    except ValueError:
        payload = raw
    return resp.status, payload, {k.lower(): v for k, v in resp.getheaders()}


# install.sh runs these after every install (pytest -m install_smoke): a real
# server bound on a free port, real sign-in, real session cookies.
@pytest.mark.install_smoke
class TestHttp:
    def test_an_analyst_is_refused_and_an_admin_reads_the_log(self, server):
        _admin()
        analyst = auth.create_user("ana", "ana@example.com", "password123", "analyst")
        status, payload, _ = _req(server, "GET", "config/activity",
                                  cookie=auth.create_session(analyst.id))
        assert status == 403 and payload["error"] == "insufficient role"
        status, payload, _ = _req(server, "POST", "config/activity/clear", {},
                                  cookie=auth.create_session(analyst.id))
        assert status == 403
        adm = auth.get_user_by_username("root")
        status, payload, _ = _req(server, "GET", "config/activity",
                                  cookie=auth.create_session(adm.id))
        assert status == 200 and payload["retention_days"] == 90

    def test_sign_in_and_out_are_recorded_with_the_address(self, server):
        _admin()
        status, _, headers = _req(server, "POST", "login",
                                  {"username": "root", "password": "password123"})
        assert status == 200
        token = headers["set-cookie"].split("atlas_session=", 1)[1].split(";", 1)[0]
        status, _, _ = _req(server, "POST", "logout", {}, cookie=token)
        assert status == 200
        rows, _ = auth.list_activity(10)
        assert [r["event"] for r in rows[:2]] == ["logout", "login"]
        assert rows[1]["username"] == "root" and rows[1]["ip"] == "127.0.0.1"

    def test_a_failed_sign_in_names_only_a_real_account(self, server):
        _admin()
        _req(server, "POST", "login", {"username": "root", "password": "wrong-password"})
        _req(server, "POST", "login", {"username": "=HYPERLINK(1)", "password": "x"})
        _req(server, "POST", "login", {"username": "Summer2026pw", "password": "x"})
        rows, _ = auth.list_activity(10)
        assert rows[2]["event"] == "login_failed" and rows[2]["username"] == "root"
        assert rows[2]["user_id"] is not None
        assert rows[1]["username"] == "(unknown account)" and rows[1]["user_id"] is None
        assert rows[0]["username"] == "(unknown account)"

    def test_a_sign_in_without_json_is_refused(self, server):
        _admin()
        conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
        conn.request("POST", "/_dashboard/api/login",
                     body=json.dumps({"username": "root", "password": "password123"}),
                     headers={"Content-Type": "text/plain"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 403
        rows, total = auth.list_activity(10)
        assert total == 0

    def test_the_export_is_csv_with_guarded_cells(self, server):
        adm = _admin()
        auth.log_event("run_start", user=adm, case_id="-CASE", detail="=cmd()")
        status, payload, headers = _req(server, "GET", "config/activity/export",
                                        cookie=auth.create_session(adm.id))
        assert status == 200
        assert headers["content-type"].startswith("text/csv")
        assert "attachment" in headers["content-disposition"]
        lines = payload.decode().splitlines()
        assert lines[0] == "id,ts,event,username,role,case_id,detail,ip"
        assert "'-CASE" in lines[1] and "'=cmd()" in lines[1]

    def test_a_run_start_records_the_user_the_case_and_the_flags(self, server, tmp_path, monkeypatch):
        from types import SimpleNamespace
        from dashboard import run_manager
        adm = _admin()
        started = {}

        def fake_start(cases_root, case_name, mode="run", options=None, notify_email="",
                       started_by=""):
            started["case"] = case_name
            return SimpleNamespace(status=lambda: {"case": case_name, "running": True})

        monkeypatch.setattr(run_manager.MANAGER, "start", fake_start)
        monkeypatch.setattr(run_manager.MANAGER, "stop",
                            lambda case, **actor: {"success": True, "already_stopped": True})
        # the server's cases root is a sibling of the auth DB under tmp_path
        (tmp_path / "cases" / "CASE-A").mkdir(parents=True)
        cookie = auth.create_session(adm.id)
        status, payload, _ = _req(server, "POST", "case/run/start",
                                  {"case": "CASE-A", "mode": "run",
                                   "options": {"start_mode": "fresh", "all_tools": True,
                                               "question": "who is the named person"}},
                                  cookie=cookie)
        assert status == 200 and started["case"] == "CASE-A"
        status, _, _ = _req(server, "POST", "case/run/stop", {"case": "CASE-A"}, cookie=cookie)
        assert status == 200
        rows, _ = auth.list_activity(10)
        assert [r["event"] for r in rows[:2]] == ["run_stop", "run_start"]
        assert rows[1]["username"] == "root" and rows[1]["case_id"] == "CASE-A"
        assert rows[1]["detail"].startswith("run") and "--fresh" in rows[1]["detail"]
        assert "--all-tools" in rows[1]["detail"]
        assert "named person" not in rows[1]["detail"] and "--question" not in rows[1]["detail"]
        assert rows[1]["ip"] == "127.0.0.1"

    def test_retention_is_saved_through_the_api(self, server):
        adm = _admin()
        cookie = auth.create_session(adm.id)
        status, payload, _ = _req(server, "POST", "config/activity/retention",
                                  {"days": 45}, cookie=cookie)
        assert status == 200 and payload["retention_days"] == 45
        status, payload, _ = _req(server, "POST", "config/activity/retention",
                                  {"days": 5000}, cookie=cookie)
        assert status == 400
