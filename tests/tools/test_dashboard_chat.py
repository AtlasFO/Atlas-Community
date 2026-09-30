"""Dashboard chat endpoints: POST /_dashboard/api/chat/send and GET
/_dashboard/api/chat/poll.

The send surface is open by operator choice (no approval secret), but it is a
mutating endpoint, so it carries a CSRF guard: it requires an
application/json body and rejects a foreign Origin. Real worker subprocesses
are not spawned here — dashboard.chat.MANAGER is replaced with a stub so these
tests exercise the serve.py routing/guards without an LLM Hub key.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time

import pytest

from dashboard import serve as dash_serve
from dashboard import chat as chat_mod


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeSession:
    """Echoes each message back as an assistant turn, synchronously."""

    def __init__(self):
        self.events: list[dict] = []
        self.busy = False
        self.sent: list[str] = []

    def send(self, text: str, role: str = "", user: str = "") -> dict:
        self.users = getattr(self, "users", []) + [user]
        # The role rides with every message (a viewer's turn is read-only).
        assert isinstance(role, str)
        self.sent.append(text)
        self.events.append({"type": "user", "text": text, "role": role,
                            "index": len(self.events)})
        self.events.append({"type": "assistant", "text": f"echo: {text}",
                            "index": len(self.events)})
        return {"ok": True, "total": len(self.events)}

    def snapshot(self, since: int = 0) -> dict:
        since = max(0, int(since))
        return {"events": self.events[since:], "total": len(self.events),
                "busy": self.busy, "alive": True}


class _FakeManager:
    def __init__(self):
        self.sessions: dict[str, _FakeSession] = {}

    def get_or_spawn(self, cases_root, case, model=""):
        return self.sessions.setdefault(case, _FakeSession())

    def peek(self, case):
        return self.sessions.get(case)


_TOKEN = ""  # set per-test by the `server` fixture; _req reads it so none
             # of the many call sites below need to pass a session explicitly.


@pytest.fixture
def server(tmp_path, monkeypatch):
    global _TOKEN
    from dashboard import auth
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    # analyst, not admin — chat/send requires analyst+ and this file is
    # specifically about the chat surface, not RBAC-by-role itself.
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "analyst")
    _TOKEN = auth.create_session(user.id)

    cases_root = tmp_path / "cases"
    (cases_root / "TEST-CASE").mkdir(parents=True)

    monkeypatch.setattr(chat_mod, "MANAGER", _FakeManager())
    discovery = tmp_path / "discovery.json"
    monkeypatch.setattr(dash_serve, "DISCOVERY_FILE", str(discovery))

    port = _free_port()
    httpd, chosen = dash_serve._bind(str(cases_root), port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    try:
        yield {"port": chosen, "case_id": "TEST-CASE", "token": _TOKEN}
    finally:
        httpd.shutdown()
        # A server thread that outlives its shutdown is the suspected cause
        # of a crash at interpreter exit seen twice; make it a visible
        # failure rather than a silent wait.
        thread.join(timeout=5)
        _TOKEN = ""
        assert not thread.is_alive(), "dashboard server thread outlived shutdown()"


def _req(port, method, path, *, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    payload = json.dumps(body) if body is not None else None
    merged = {"Cookie": f"atlas_session={_TOKEN}", **(headers or {})}
    conn.request(method, path, body=payload, headers=merged)
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    return resp.status, (json.loads(raw) if raw else {})


_JSON = {"Content-Type": "application/json"}


class TestChatSend:
    def test_send_then_poll_roundtrip(self, server):
        status, data = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                            headers=_JSON,
                            body={"case": server["case_id"], "message": "hi"})
        assert status == 200, data
        assert data["ok"] is True

        status, data = _req(server["port"], "GET",
                           f"/_dashboard/api/chat/poll?case={server['case_id']}&since=0")
        assert status == 200
        kinds = [(e["type"], e.get("text")) for e in data["events"]]
        assert kinds == [("user", "hi"), ("assistant", "echo: hi")]
        assert data["total"] == 2
        assert data["alive"] is True

    def test_poll_since_cursor_returns_only_new(self, server):
        _req(server["port"], "POST", "/_dashboard/api/chat/send",
             headers=_JSON, body={"case": server["case_id"], "message": "one"})
        # consume up to the cursor, then send again
        _, first = _req(server["port"], "GET",
                       f"/_dashboard/api/chat/poll?case={server['case_id']}&since=0")
        cursor = first["total"]
        _req(server["port"], "POST", "/_dashboard/api/chat/send",
             headers=_JSON, body={"case": server["case_id"], "message": "two"})
        _, data = _req(server["port"], "GET",
                      f"/_dashboard/api/chat/poll?case={server['case_id']}&since={cursor}")
        texts = [e.get("text") for e in data["events"]]
        assert texts == ["two", "echo: two"]


class TestCsrfGuard:
    def test_missing_json_content_type_403(self, server):
        # no Content-Type header at all → refused
        status, _ = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                        body={"case": server["case_id"], "message": "hi"})
        assert status == 403

    def test_foreign_origin_403(self, server):
        headers = {**_JSON, "Origin": "http://evil.example"}
        status, _ = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                        headers=headers,
                        body={"case": server["case_id"], "message": "hi"})
        assert status == 403

    def test_matching_origin_ok(self, server):
        headers = {**_JSON, "Origin": f"http://127.0.0.1:{server['port']}"}
        status, data = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                           headers=headers,
                           body={"case": server["case_id"], "message": "hi"})
        assert status == 200, data


class TestValidation:
    def test_unknown_case_404(self, server):
        status, _ = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                        headers=_JSON,
                        body={"case": "../etc", "message": "hi"})
        assert status == 404

    def test_empty_message_400(self, server):
        status, _ = _req(server["port"], "POST", "/_dashboard/api/chat/send",
                        headers=_JSON,
                        body={"case": server["case_id"], "message": "   "})
        assert status == 400

    def test_poll_unknown_case_404(self, server):
        status, _ = _req(server["port"], "GET",
                        "/_dashboard/api/chat/poll?case=../etc")
        assert status == 404

    def test_poll_no_session_is_empty_not_alive(self, server):
        status, data = _req(server["port"], "GET",
                           f"/_dashboard/api/chat/poll?case={server['case_id']}")
        assert status == 200
        assert data == {"events": [], "total": 0, "busy": False, "alive": False}


class TestChatUiShips:
    def test_chat_ships_in_shared_shell(self, server):
        """Chat lives in the shared shell (assets/shell.js) so it is
        available on every page and always bound to the active case."""
        conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=3)
        conn.request("GET", "/_dashboard/assets/shell.js")
        shell = conn.getresponse().read().decode()
        conn.close()
        assert "chat/send" in shell
        assert "chat/poll" in shell
        # Cross-case leakage guard: cursor resets on case switch.
        assert "onCaseChanged" in shell
        # Every case-scoped page loads the shell (and with it, chat).
        conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=3)
        conn.request("GET", "/_dashboard/dashboard.html",
                    headers={"Cookie": f"atlas_session={_TOKEN}"})
        body = conn.getresponse().read().decode()
        conn.close()
        assert "assets/shell.js" in body
