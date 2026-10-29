"""Test connection's capability check: no chat call to a host that gave no
HTTP answer at all, chat calls after any HTTP status, and one deadline for
the whole check.

``reached`` comes from the listing's HTTP status, never from error text, so
the cases below are made with real sockets where a socket can make them: a
refused port, TLS spoken to a plain HTTP server, and a server answering
401, 404 and 405. A failed name lookup is raised as httpx raises it.
"""
from __future__ import annotations

import http.server
import socket
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

from agent import llm
from core import llm_setup as ls


def _reply():
    return SimpleNamespace(content="ok", thinking_observed=False, reasoning_tokens=0,
                           raw_message={}, tool_calls=[{"id": "c1"}])


@pytest.fixture
def chats(monkeypatch):
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    sent = []

    def _chat(self, messages, **kw):
        sent.append(messages)
        return _reply()

    monkeypatch.setattr(llm.LLMHubClient, "chat", _chat)
    return sent


@pytest.fixture
def status_server():
    """A plain HTTP server that answers every request with ``codes[0]``."""
    codes = [200]

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"error": "no"}'
            self.send_response(codes[0])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1], codes
    srv.shutdown()
    srv.server_close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestNoAnswerMeansNoChat:
    def test_a_refused_port_gets_no_chat_call(self, chats):
        started = time.monotonic()
        caps = ls.probe_capabilities(f"http://127.0.0.1:{_free_port()}/v1", "k", "m")
        assert chats == []
        assert caps.reached is False and caps.ok is False
        assert caps.error and caps.to_dict()["reached"] is False
        assert time.monotonic() - started < 10

    def test_tls_spoken_to_a_plain_server_gets_no_chat_call(self, chats, status_server):
        port, _codes = status_server
        caps = ls.probe_capabilities(f"https://127.0.0.1:{port}/v1", "k", "m")
        assert chats == []
        assert caps.reached is False and caps.error

    def test_a_failed_name_lookup_gets_no_chat_call(self, chats, monkeypatch):
        def _no_name(*a, **k):
            raise httpx.ConnectError("[Errno -2] Name or service not known")

        monkeypatch.setattr(httpx, "get", _no_name)
        caps = ls.probe_capabilities("https://gw.example.invalid/v1", "k", "m")
        assert chats == []
        assert caps.reached is False

    def test_a_listing_timeout_still_asks_the_model(self, chats, monkeypatch):
        def _slow(*a, **k):
            raise httpx.ReadTimeout("timed out")

        monkeypatch.setattr(httpx, "get", _slow)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert len(chats) == 2
        assert caps.reached is False and caps.answered is True

    def test_error_text_alone_does_not_decide(self, chats, monkeypatch):
        # A status-bearing listing whose error text reads like a refusal
        # still reached the host.
        monkeypatch.setattr(ls, "probe", lambda *a, **k: ls.ProbeResult(
            ok=False, status=502, url="u", error="Connection refused"))
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.reached is True and len(chats) == 2


@pytest.mark.parametrize("code", [401, 404, 405])
def test_any_http_status_still_runs_the_chat_calls(chats, status_server, code):
    port, codes = status_server
    codes[0] = code
    caps = ls.probe_capabilities(f"http://127.0.0.1:{port}/v1", "k", "m")
    assert caps.status == code and caps.reached is True
    assert len(chats) == 2
    assert caps.answered is True and caps.reachable is False


class TestDeadline:
    def _listed(self, monkeypatch):
        monkeypatch.setattr(ls, "probe", lambda *a, **k: ls.ProbeResult(
            ok=True, status=200, url="u", models=["m"]))

    def test_the_check_ends_at_its_deadline(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        self._listed(monkeypatch)
        calls = []

        def _slow_chat(self, messages, **kw):
            calls.append(self.stop_at)
            time.sleep(0.8)
            return _reply()

        monkeypatch.setattr(llm.LLMHubClient, "chat", _slow_chat)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m", deadline=1.5)
        assert len(calls) == 1 and calls[0] is not None
        assert caps.answered is True
        assert caps.finished is False and "did not finish within 1.5 s" in caps.error
        assert caps.to_dict()["finished"] is False

    def test_a_call_cut_by_the_deadline_reads_as_unfinished(self, monkeypatch):
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        self._listed(monkeypatch)

        def _cut(self, messages, **kw):
            time.sleep(0.6)
            raise llm.LLMDeadlineError("Turn time budget of 1s exhausted")

        monkeypatch.setattr(llm.LLMHubClient, "chat", _cut)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m", deadline=1.5)
        assert caps.finished is False and caps.error.startswith("the check did not finish")

    def test_a_check_inside_its_deadline_is_finished(self, chats, monkeypatch):
        self._listed(monkeypatch)
        caps = ls.probe_capabilities("https://gw.example/v1", "k", "m")
        assert caps.finished is True and caps.ok is True and caps.error == ""


def test_the_client_stop_ends_every_request(monkeypatch):
    """``stop_at`` bounds the client's requests as a whole: past it, a call
    sends nothing, whatever its turn budget."""
    monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
    posted = []
    monkeypatch.setattr("agent.llm.httpx.post", lambda *a, **k: posted.append(a) or None)
    client = llm.LLMHubClient(base_url="https://gw.example/v1", api_key="k", model="m",
                              turn_time_budget=600)
    client.stop_at = time.monotonic() - 1
    with pytest.raises(llm.LLMError):
        client.chat([{"role": "user", "content": "x"}], role="", temperature=None)
    assert posted == []
