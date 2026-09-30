"""The live change stream: a write under a case reaches a connected tab as
one `change` event naming that case, and the stream is session-gated."""
from __future__ import annotations

import http.client
import json
import threading
import time

import pytest

from dashboard.events import ChangeFeed


class TestCasesFor:
    def test_maps_paths_to_case_dirs(self, tmp_path):
        feed = ChangeFeed(str(tmp_path))
        changes = {
            (1, str(tmp_path / "alpha" / "analysis" / "x_trace.json")),
            (2, str(tmp_path / "alpha" / ".atlas" / "claim_graph.json")),
            (1, str(tmp_path / "beta" / "CASE.md")),
            (1, str(tmp_path / "root-file.txt")),           # nothing to re-read
            (1, str(tmp_path / "_dashboard" / "auth.db")),  # not a case
            (1, str(tmp_path / ".hidden" / "x")),           # not a case
            (1, str(tmp_path.parent / "elsewhere" / "y")),  # outside the root
        }
        assert feed.cases_for(changes) == {"alpha", "beta"}


@pytest.fixture
def server(tmp_path, monkeypatch):
    from dashboard import auth
    from dashboard import serve as dash_serve

    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "viewer")
    token = auth.create_session(user.id)
    cases_root = tmp_path / "cases"
    (cases_root / "alpha").mkdir(parents=True)
    httpd, port = dash_serve._bind(str(cases_root), 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)   # the watcher starts with the app's lifespan
    try:
        yield {"port": port, "cases_root": cases_root,
               "cookie": f"atlas_session={token}"}
    finally:
        httpd.shutdown()


def _read_event(resp, timeout: float) -> tuple[str, str]:
    """Next (event, data) pair from an SSE stream, skipping pings."""
    deadline = time.monotonic() + timeout
    event, data = "", ""
    while time.monotonic() < deadline:
        line = resp.readline().decode().rstrip("\r\n")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data = line[5:].strip()
        elif line == "" and event:
            return event, data
    raise AssertionError("no event before the deadline")


def test_stream_needs_a_session(server):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=3)
    conn.request("GET", "/_dashboard/api/events")
    assert conn.getresponse().status == 401


def test_write_under_a_case_reaches_the_stream(server):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=10)
    conn.request("GET", "/_dashboard/api/events",
                 headers={"Cookie": server["cookie"]})
    resp = conn.getresponse()
    assert resp.status == 200
    assert resp.getheader("Content-Type", "").startswith("text/event-stream")
    assert _read_event(resp, 3)[0] == "hello"

    probe = server["cases_root"] / "alpha" / "analysis" / "probe.json"
    probe.parent.mkdir()
    probe.write_text(json.dumps({"n": 1}))

    event, data = _read_event(resp, 8)
    assert event == "change"
    assert json.loads(data) == {"case": "alpha"}
    conn.close()


def test_stream_answers_204_when_the_feed_is_unavailable(tmp_path, monkeypatch):
    """Without watchfiles the dashboard still serves; the stream says so in
    the one way EventSource does not retry."""
    from dashboard import app as dash_app, auth
    from dashboard import serve as dash_serve

    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    token = auth.create_session(
        auth.create_user("tester", "t@example.com", "testerpassword1", "viewer").id)
    monkeypatch.setattr(dash_app, "ChangeFeed", None)
    (tmp_path / "cases").mkdir()
    httpd, port = dash_serve._bind(str(tmp_path / "cases"), 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/_dashboard/api/events",
                     headers={"Cookie": f"atlas_session={token}"})
        assert conn.getresponse().status == 204
    finally:
        httpd.shutdown()
