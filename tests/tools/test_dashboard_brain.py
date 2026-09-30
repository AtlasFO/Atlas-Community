"""The dashboard's /_dashboard/api/brain/globe endpoint."""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from unittest.mock import patch

import pytest


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


_TOKEN = ""  # set per-test by the `server` fixture; _get/_post/_get_h read
             # it so none of the many call sites below need to pass a session.


@pytest.fixture
def server(tmp_path, monkeypatch):
    global _TOKEN
    from dashboard import auth
    from dashboard import serve as dash_serve

    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "admin")
    _TOKEN = auth.create_session(user.id)

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    brain_root = tmp_path / "brain"
    (brain_root / "analytics" / "globe").mkdir(parents=True)
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain_root))

    with patch.object(dash_serve, "DISCOVERY_FILE",
                      str(tmp_path / "discovery.json")):
        httpd, port = dash_serve._bind(str(cases_root), _free_port())
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.05)
        try:
            yield {"port": port, "brain_root": brain_root, "token": _TOKEN}
        finally:
            httpd.shutdown()
            _TOKEN = ""


def _get(port: int, path: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode())
    conn.close()
    return resp.status, body


def test_globe_endpoint_404_with_hint_when_absent(server):
    status, body = _get(server["port"], "/_dashboard/api/brain/globe")
    assert status == 404
    assert "atlas brain globe" in body["error"]


def test_globe_endpoint_serves_generated_json(server):
    data = {"generated": "now", "mode": "full",
            "nodes": [{"id": "a"}], "edges": [],
            "summary": {"nodes": 1, "edges": 0, "clusters": 1}}
    (server["brain_root"] / "analytics/globe/brain-globe.json").write_text(
        json.dumps(data))
    status, body = _get(server["port"], "/_dashboard/api/brain/globe")
    assert status == 200
    assert body["nodes"] == [{"id": "a"}]


def _write_note(brain_root, rel="wiki/tools/vol.md", title="Volatility"):
    p = brain_root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"""---
title: "{title}"
type: "tool"
created: "2026-07-07 10:00 UTC"
updated: "2026-07-07 10:00 UTC"
status: "active"
source_classification: "internal"
confidence: "medium"
tags: [memory]
related: []
source: {{type: "manual", url: "", description: ""}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# {title}
""")
    return p


def test_globe_endpoint_rebuilds_when_json_missing(server):
    _write_note(server["brain_root"])
    status, body = _get(server["port"], "/_dashboard/api/brain/globe")
    assert status == 200
    assert {n["id"] for n in body["nodes"]} == {"vol"}
    assert (server["brain_root"] / "analytics/globe/brain-globe.json").is_file()


def test_globe_endpoint_rebuilds_when_stale(server):
    _write_note(server["brain_root"])
    _get(server["port"], "/_dashboard/api/brain/globe")
    time.sleep(0.05)  # note must be strictly newer than the JSON
    _write_note(server["brain_root"], rel="wiki/tools/zeek.md", title="Zeek")
    status, body = _get(server["port"], "/_dashboard/api/brain/globe")
    assert status == 200
    assert {n["id"] for n in body["nodes"]} == {"vol", "zeek"}


def test_globe_endpoint_keeps_focused_view(server):
    # a deliberately filtered globe (atlas brain globe --case ...) is never
    # clobbered by the auto-rebuild
    data = {"generated": "then", "mode": "full", "case": "nitroba",
            "topic": "", "nodes": [], "edges": [], "timeline": [],
            "summary": {}}
    globe_path = server["brain_root"] / "analytics/globe/brain-globe.json"
    globe_path.write_text(json.dumps(data))
    time.sleep(0.05)
    _write_note(server["brain_root"])
    status, body = _get(server["port"], "/_dashboard/api/brain/globe")
    assert status == 200
    assert body["case"] == "nitroba" and body["nodes"] == []


def test_globe_html_asset_served(server):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=5)
    conn.request("GET", "/_dashboard/brain_globe.html",
                headers={"Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    assert resp.status == 200
    assert "Brain Earth" in text


# ── brain/candidates + brain/review (the web review surface) ────────────────

_CANDIDATE = """---
title: "Test lesson"
candidate_type: "workflow"
suggested_destination: "wiki/concepts/"
status: "pending_review"
confidence: "medium"
created: "2026-07-07 10:00 UTC"
tags: [workflow]
origin: {case_id: TEST}
---

# Candidate Memory

## Proposed Entry

Always do the thing.
"""


def _post(port: int, path: str, payload: dict,
          secret: str | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json",
              "Cookie": f"atlas_session={_TOKEN}"}
    if secret:
        headers["X-Atlas-Approval-Secret"] = secret
    conn.request("POST", path, json.dumps(payload), headers)
    resp = conn.getresponse()
    body = json.loads(resp.read().decode())
    conn.close()
    return resp.status, body


def _get_h(port: int, path: str, secret: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"X-Atlas-Approval-Secret": secret,
                                       "Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode())
    conn.close()
    return resp.status, body


def _stage_candidate(brain_root, name="2026-07-07-test-cand.md"):
    inbox = brain_root / "inbox/memory-candidates"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / name).write_text(_CANDIDATE)
    (brain_root / "inbox/processed").mkdir(parents=True, exist_ok=True)


def test_brain_candidates_lists_pending_with_body(server):
    _stage_candidate(server["brain_root"])
    status, body = _get(server["port"], "/_dashboard/api/brain/candidates")
    assert status == 200
    assert len(body["candidates"]) == 1
    c = body["candidates"][0]
    assert c["name"] == "2026-07-07-test-cand.md"
    assert c["candidate_type"] == "workflow"
    assert "Always do the thing" in c["body"]


def test_brain_review_fails_closed_without_secret(server):
    _stage_candidate(server["brain_root"])
    status, body = _post(server["port"], "/_dashboard/api/brain/review",
                         {"candidate": "2026-07-07-test-cand.md",
                          "decision": "approve", "nonce": "x"})
    assert status == 403
    # untouched: still pending
    status, body = _get(server["port"], "/_dashboard/api/brain/candidates")
    assert len(body["candidates"]) == 1


def test_brain_review_approve_promotes_candidate(server, tmp_path):
    from response import gates
    secret_file = tmp_path / "dash-secret"
    secret_file.write_text("s3cret")
    secret_file.chmod(0o600)
    _stage_candidate(server["brain_root"])

    with patch.object(gates, "DASHBOARD_SECRET_PATH", secret_file):
        status, body = _get_h(server["port"],
                              "/_dashboard/api/approval/nonce", "s3cret")
        assert status == 200
        status, body = _post(
            server["port"], "/_dashboard/api/brain/review",
            {"candidate": "2026-07-07-test-cand.md", "decision": "approve",
             "nonce": body["nonce"]},
            secret="s3cret")
    assert status == 200 and body["success"] is True
    assert body["decision"] == "approved"
    dest = server["brain_root"] / "wiki/concepts/test-lesson.md"
    assert dest.is_file()
    assert "Always do the thing" in dest.read_text()
    # candidate moved out of the inbox, archived to processed
    assert not (server["brain_root"]
                / "inbox/memory-candidates/2026-07-07-test-cand.md").exists()
    assert (server["brain_root"]
            / "inbox/processed/2026-07-07-test-cand.md").is_file()


def test_brain_review_reject_requires_reason_and_archives(server, tmp_path):
    from response import gates
    secret_file = tmp_path / "dash-secret"
    secret_file.write_text("s3cret")
    secret_file.chmod(0o600)
    _stage_candidate(server["brain_root"])

    with patch.object(gates, "DASHBOARD_SECRET_PATH", secret_file):
        _, n = _get_h(server["port"], "/_dashboard/api/approval/nonce",
                      "s3cret")
        status, body = _post(
            server["port"], "/_dashboard/api/brain/review",
            {"candidate": "2026-07-07-test-cand.md", "decision": "reject",
             "reason": "", "nonce": n["nonce"]}, secret="s3cret")
        assert status == 400  # reason is the audit record

        _, n = _get_h(server["port"], "/_dashboard/api/approval/nonce",
                      "s3cret")
        status, body = _post(
            server["port"], "/_dashboard/api/brain/review",
            {"candidate": "2026-07-07-test-cand.md", "decision": "reject",
             "reason": "too case-specific", "nonce": n["nonce"]},
            secret="s3cret")
    assert status == 200 and body["decision"] == "rejected"
    archived = (server["brain_root"]
                / "inbox/processed/2026-07-07-test-cand.md")
    assert "too case-specific" in archived.read_text()


def test_brain_review_html_asset_served(server):
    conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=5)
    conn.request("GET", "/_dashboard/brain_review.html",
                headers={"Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    text = resp.read().decode()
    conn.close()
    assert resp.status == 200
    assert "Brain Review" in text
