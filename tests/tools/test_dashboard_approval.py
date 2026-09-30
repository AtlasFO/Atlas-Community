"""Tests for the dashboard live-response feed + fail-closed approval controls.

Read half: GET /_dashboard/api/alerts and /_dashboard/api/response glob the
on-disk JSON the MCP tools write — no Atlas imports on that path.

Approval half: off by default (no secret file → 403 everywhere); when enabled
it is a two-factor gate — possession of the 0600 secret + a single-use,
same-origin-issued nonce (key 2), plus the operator typing the action_id
verbatim (key 1). On success it writes the SAME approval token file that the
chat path writes, so response.gates.check_approval accepts it unchanged.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time

import pytest

from dashboard import serve as dash_serve
from response import gates as gates_mod


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _seed_case(cases_root, case_id="TEST-CASE"):
    resp = cases_root / case_id / "monitoring" / "response"
    (resp / "suggestions").mkdir(parents=True)
    (resp / "executions").mkdir(parents=True)
    (resp / "approvals").mkdir(parents=True)
    (cases_root / case_id / "monitoring" / "alerts").mkdir(parents=True)
    (cases_root / case_id / "monitoring" / "baselines").mkdir(parents=True)
    # one pending suggestion, one already executed
    (resp / "suggestions" / "ACT-1.json").write_text(json.dumps({
        "action_id": "ACT-1", "case_id": case_id,
        "detector": "Custom.Atlas.NewNetwork",
        "description": "Block 203.0.113.10", "manual_command": "iptables ... 203.0.113.10",
        "risk": "high", "reversible": True, "unresolved_placeholders": [],
    }))
    (resp / "suggestions" / "ACT-2.json").write_text(json.dumps({
        "action_id": "ACT-2", "case_id": case_id,
        "detector": "Custom.Atlas.NewProcess", "description": "Kill pid 42",
        "manual_command": "kill 42", "risk": "medium", "reversible": False,
        "unresolved_placeholders": [],
    }))
    (resp / "executions" / "ACT-2.json").write_text(json.dumps({
        "action_id": "ACT-2", "case_id": case_id, "success": True,
    }))
    (cases_root / case_id / "monitoring" / "alerts" / "7_Custom.Atlas.NewNetwork.json").write_text(
        json.dumps({"seq": 7, "detector": "Custom.Atlas.NewNetwork",
                    "evidence": {"remote_ip": "203.0.113.10"}}))
    (cases_root / case_id / "monitoring" / "alerts" / "3_Custom.Atlas.NewProcess.json").write_text(
        json.dumps({"seq": 3, "detector": "Custom.Atlas.NewProcess"}))
    return case_id


_TOKEN = ""  # set per-test by the `server` fixture; _req reads it so none
             # of the many call sites below need to pass a session explicitly.


@pytest.fixture
def server(tmp_path, monkeypatch):
    global _TOKEN
    from dashboard import auth
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "analyst")
    _TOKEN = auth.create_session(user.id)

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    case_id = _seed_case(cases_root)

    # gates writes/reads tokens under CASES_ROOT — align it with the dashboard's.
    monkeypatch.setattr(gates_mod, "CASES_ROOT", cases_root)
    secret_path = tmp_path / "secret"
    monkeypatch.setattr(gates_mod, "DASHBOARD_SECRET_PATH", secret_path)

    port = _free_port()
    discovery = tmp_path / "discovery.json"
    monkeypatch.setattr(dash_serve, "DISCOVERY_FILE", str(discovery))
    httpd, chosen = dash_serve._bind(str(cases_root), port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    try:
        yield {"port": chosen, "cases_root": cases_root, "case_id": case_id,
               "secret_path": secret_path, "token": _TOKEN}
    finally:
        httpd.shutdown()
        _TOKEN = ""


def _req(port, method, path, *, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    payload = json.dumps(body) if body is not None else None
    merged = {"Cookie": f"atlas_session={_TOKEN}"}
    # Every real dashboard POST goes through assets/shell.js's apiPost(),
    # which always sets this — matched here so this raw-socket test client
    # exercises the same same-origin JSON check every gated POST enforces
    # (dashboard/serve.py's _csrf_ok).
    if payload is not None:
        merged["Content-Type"] = "application/json"
    merged.update(headers or {})
    conn.request(method, path, body=payload, headers=merged)
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    data = json.loads(raw) if raw else {}
    return resp.status, data


def _enable_secret(secret_path, value="s3cr3t-token", mode=0o600):
    secret_path.write_text(value)
    os.chmod(secret_path, mode)
    return value


def _get_nonce(port, secret):
    status, data = _req(port, "GET", "/_dashboard/api/approval/nonce",
                        headers={"X-Atlas-Approval-Secret": secret})
    assert status == 200, data
    return data["nonce"]


# ── read half ────────────────────────────────────────────────────────────────

class TestReadFeed:
    def test_alerts_newest_first(self, server):
        status, data = _req(server["port"], "GET",
                           f"/_dashboard/api/alerts?case={server['case_id']}")
        assert status == 200
        assert [a["seq"] for a in data["alerts"]] == [7, 3]

    def test_response_merges_status(self, server):
        status, data = _req(server["port"], "GET",
                           f"/_dashboard/api/response?case={server['case_id']}")
        assert status == 200
        by_id = {a["action_id"]: a for a in data["actions"]}
        assert by_id["ACT-1"]["status"] == "needs_approval"
        assert by_id["ACT-2"]["status"] == "executed"

    def test_unknown_case_404(self, server):
        status, _ = _req(server["port"], "GET",
                        "/_dashboard/api/response?case=../etc")
        assert status == 404

    def test_read_never_needs_secret(self, server):
        # read endpoints work with no secret configured at all
        status, _ = _req(server["port"], "GET",
                        f"/_dashboard/api/alerts?case={server['case_id']}")
        assert status == 200

    def test_panel_markup_ships_in_html(self, server):
        conn = http.client.HTTPConnection("127.0.0.1", server["port"], timeout=3)
        conn.request("GET", "/_dashboard/dashboard.html",
                    headers={"Cookie": f"atlas_session={_TOKEN}"})
        body = conn.getresponse().read().decode()
        conn.close()
        assert 'id="response-panel"' in body
        assert "ResponsePanel" in body
        assert "X-Atlas-Approval-Secret" in body


# ── approval fail-closed ─────────────────────────────────────────────────────

class TestApprovalGate:
    def test_disabled_by_default_nonce_403(self, server):
        status, data = _req(server["port"], "GET", "/_dashboard/api/approval/nonce")
        assert status == 403
        assert data["gate"] == "dashboard_approval"

    def test_disabled_by_default_post_403(self, server):
        status, _ = _req(server["port"], "POST", "/_dashboard/api/approval",
                        body={"case": server["case_id"], "action_id": "ACT-1",
                              "operator_text": "approve ACT-1", "nonce": "x"})
        assert status == 403

    def test_world_readable_secret_treated_as_absent(self, server):
        _enable_secret(server["secret_path"], mode=0o644)
        status, _ = _req(server["port"], "GET", "/_dashboard/api/approval/nonce",
                        headers={"X-Atlas-Approval-Secret": "s3cr3t-token"})
        assert status == 403

    def test_wrong_secret_403(self, server):
        _enable_secret(server["secret_path"])
        status, _ = _req(server["port"], "GET", "/_dashboard/api/approval/nonce",
                        headers={"X-Atlas-Approval-Secret": "nope"})
        assert status == 403

    def test_missing_nonce_403(self, server):
        secret = _enable_secret(server["secret_path"])
        status, _ = _req(server["port"], "POST", "/_dashboard/api/approval",
                        headers={"X-Atlas-Approval-Secret": secret},
                        body={"case": server["case_id"], "action_id": "ACT-1",
                              "operator_text": "approve ACT-1", "nonce": "bogus"})
        assert status == 403

    def test_nonce_single_use(self, server):
        secret = _enable_secret(server["secret_path"])
        nonce = _get_nonce(server["port"], secret)
        hdr = {"X-Atlas-Approval-Secret": secret}
        body = {"case": server["case_id"], "action_id": "ACT-1",
                "operator_text": "approve ACT-1", "nonce": nonce}
        s1, _ = _req(server["port"], "POST", "/_dashboard/api/approval",
                    headers=hdr, body=body)
        assert s1 == 200
        s2, _ = _req(server["port"], "POST", "/_dashboard/api/approval",
                    headers=hdr, body=body)
        assert s2 == 403  # nonce already consumed

    def test_action_id_must_be_verbatim(self, server):
        secret = _enable_secret(server["secret_path"])
        nonce = _get_nonce(server["port"], secret)
        status, _ = _req(server["port"], "POST", "/_dashboard/api/approval",
                        headers={"X-Atlas-Approval-Secret": secret},
                        body={"case": server["case_id"], "action_id": "ACT-1",
                              "operator_text": "yes do it", "nonce": nonce})
        assert status == 400


# ── token round-trip + deny ──────────────────────────────────────────────────

class TestApprovalRoundTrip:
    def test_approve_issues_token_check_approval_accepts(self, server):
        secret = _enable_secret(server["secret_path"])
        nonce = _get_nonce(server["port"], secret)
        status, data = _req(server["port"], "POST", "/_dashboard/api/approval",
                           headers={"X-Atlas-Approval-Secret": secret},
                           body={"case": server["case_id"], "action_id": "ACT-1",
                                 "operator_text": "approve ACT-1", "nonce": nonce})
        assert status == 200 and data["success"]
        assert data["approval"]["origin"] == "dashboard"
        # the execution gate accepts the dashboard-issued token unchanged
        record, refusal = gates_mod.check_approval(server["case_id"], "ACT-1")
        assert refusal is None and record is not None
        assert record["approval_token"] == data["approval"]["approval_token"]

    def test_deny_removes_token_and_marks_suggestion(self, server):
        secret = _enable_secret(server["secret_path"])
        # first approve
        nonce = _get_nonce(server["port"], secret)
        _req(server["port"], "POST", "/_dashboard/api/approval",
             headers={"X-Atlas-Approval-Secret": secret},
             body={"case": server["case_id"], "action_id": "ACT-1",
                   "operator_text": "approve ACT-1", "nonce": nonce})
        # then deny
        nonce2 = _get_nonce(server["port"], secret)
        status, data = _req(server["port"], "POST", "/_dashboard/api/approval",
                           headers={"X-Atlas-Approval-Secret": secret},
                           body={"case": server["case_id"], "action_id": "ACT-1",
                                 "decision": "deny", "nonce": nonce2})
        assert status == 200 and data["denied"]
        _, refusal = gates_mod.check_approval(server["case_id"], "ACT-1")
        assert refusal is not None  # token gone
        sug = json.loads((server["cases_root"] / server["case_id"] / "monitoring"
                          / "response" / "suggestions" / "ACT-1.json").read_text())
        assert sug["denied"] is True
