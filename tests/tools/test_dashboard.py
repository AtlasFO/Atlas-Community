"""Tests for the Atlas dashboard discovery + standalone server.

The dashboard runs as a separate long-lived process (`atlas-dashboard`,
i.e. `python -m dashboard.serve`). MCP-side code never spawns a server;
it discovers the running one via ~/.cache/atlas/dashboard.url and returns
a deep-link URL pre-loaded with the case's trace.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from unittest.mock import patch

import pytest


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


@pytest.fixture
def standalone_server(tmp_path, monkeypatch):
    """Spin up dashboard.serve in a thread, isolated under tmp_path."""
    from dashboard import auth
    from dashboard import serve as dash_serve

    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "admin")
    token = auth.create_session(user.id)

    # This file's ~20 tests each build their own raw HTTPConnection with no
    # shared request helper to inject a session cookie into — patch the
    # transport itself instead of touching every call site individually.
    # A caller passing its own Cookie header (none currently do) still wins.
    orig_request = http.client.HTTPConnection.request

    def _request_with_cookie(self, method, url, body=None, headers=None, **kw):
        headers = dict(headers or {})
        headers.setdefault("Cookie", f"atlas_session={token}")
        return orig_request(self, method, url, body=body, headers=headers, **kw)

    monkeypatch.setattr(http.client.HTTPConnection, "request", _request_with_cookie)

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    port = _free_port()

    discovery = tmp_path / "discovery.json"
    with patch.object(dash_serve, "DISCOVERY_FILE", str(discovery)):
        httpd, chosen = dash_serve._bind(str(cases_root), port)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        dash_serve._write_discovery(
            f"http://127.0.0.1:{chosen}/_dashboard/dashboard.html",
            chosen, str(cases_root),
        )
        try:
            time.sleep(0.05)
            yield {
                "cases_root": cases_root,
                "port": chosen,
                "discovery": discovery,
                "url": f"http://127.0.0.1:{chosen}/_dashboard/dashboard.html",
            }
        finally:
            httpd.shutdown()
            dash_serve._clear_discovery()


def _seed_case(cases_root, case_dir_name, case_id, trace_name=None):
    case = cases_root / case_dir_name
    case.mkdir()
    (case / "CASE.md").write_text(f"**Case ID**: {case_id}\n")
    (case / "analysis").mkdir()
    if trace_name:
        (case / "analysis" / trace_name).write_text(
            json.dumps({"case_id": case_id, "entries": []})
        )
    return case


class TestStandaloneServer:
    def test_redirect_to_overview(self, standalone_server):
        """The investigator-facing Case Overview is the front door; the
        trace viewer stays reachable at dashboard.html (Process view)."""
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 302
        assert resp.getheader("Location") == "/_dashboard/overview.html"

    def test_serves_overview_html(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/overview.html")
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert "assets/shell.js" in body
        assert "assets/atlas.css" in body

    def test_serves_dashboard_html(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/dashboard.html")
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert "Atlas · Process" in body
        # Trace picking stays page-local; case selection moved to the
        # shared shell (assets/shell.js) — no page-local case dropdown.
        assert 'id="trace-select"' in body
        assert 'id="case-select"' not in body
        assert "assets/shell.js" in body

    def test_serves_shell_assets(self, standalone_server):
        port = standalone_server["port"]
        for rel, ctype in (("assets/shell.js", "application/javascript"),
                           ("assets/atlas.css", "text/css")):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", f"/_dashboard/{rel}")
            resp = conn.getresponse()
            assert resp.status == 200, rel
            assert resp.getheader("Content-Type").startswith(ctype)
            resp.read()

    def test_chain_view_is_retired(self, standalone_server):
        # Its block toggles, phase strip and block detail live in the
        # Process view now; the old page must not quietly keep serving.
        conn = http.client.HTTPConnection("127.0.0.1", standalone_server["port"], timeout=5)
        conn.request("GET", "/_dashboard/chain_view.html")
        resp = conn.getresponse(); resp.read()
        assert resp.status == 404
        conn.request("GET", "/_dashboard/dashboard.html")
        assert conn.getresponse().status in (200, 302)

    def test_serves_vendor_dagre(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/vendor/dagre.min.js")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("Content-Type").startswith("application/javascript")

    def test_dashboard_asset_rejects_traversal(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/../tools/misc.py")
        resp = conn.getresponse()
        # SimpleHTTPRequestHandler normalizes the path before do_GET sees it,
        # so traversal under the dashboard prefix never reaches the source dir.
        assert resp.status in (403, 404)

    def test_api_cases_lists_seeded_cases(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "alpha-case", "ALPHA",
                   trace_name="ALPHA_trace.json")
        _seed_case(cases_root, "beta-case", "BETA",
                   trace_name="BETA_trace.json")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        ids = {c["case_id"] for c in data["cases"]}
        assert {"ALPHA", "BETA"} <= ids
        alpha = next(c for c in data["cases"] if c["case_id"] == "ALPHA")
        assert alpha["traces"][0]["path"] == "/alpha-case/analysis/ALPHA_trace.json"
        assert "tokens" in alpha
        assert alpha["tokens"]["total_tokens"] == 0

    def test_api_tokens_reads_the_usage_ledger(self, standalone_server):
        """Every role of every run of the case, as the ledger recorded them;
        the trace and the transcript in the folder are no source (a nudge
        logs a reply twice there, the report and reviewer calls not at all)."""
        from core import usage_ledger
        from dashboard.serve import case_token_totals

        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "tok-case", "TOK",
                          trace_name="TOK_trace.json")
        (case / "analysis" / "TOK_trace.json").write_text(json.dumps({
            "case_id": "TOK",
            "entries": [{"type": "reason_call", "input_tokens": 99999, "output_tokens": 999}],
        }))
        for run_id, role, tin, tout in (("r1", "analyst", 1000, 40), ("r1", "reason", 100, 20),
                                        ("r2", "dair", 50, 10)):
            with usage_ledger.context(case_id="TOK", run_id=run_id):
                usage_ledger.record(role=role, provider="llmhub", model="m",
                                    input_tokens=tin, output_tokens=tout)
        with usage_ledger.context(case_id="OTHER", run_id="r9"):
            usage_ledger.record(role="analyst", provider="llmhub", model="m",
                                input_tokens=5000, output_tokens=5)
        assert usage_ledger.totals("TOK", "r1")["input_tokens"] == 1100
        totals = case_token_totals(str(case))
        assert totals == {
            "input_tokens": 1150,
            "output_tokens": 70,
            "total_tokens": 1220,
        }
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/tokens?case=tok-case")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["total_tokens"] == 1220
        assert data["case"] == "tok-case"

        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        cases = json.loads(conn.getresponse().read())["cases"]
        tok = next(c for c in cases if c["case_dir"] == "tok-case")
        assert tok["tokens"]["total_tokens"] == 1220

    def test_dashboard_html_has_tokens_metric(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/dashboard.html")
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert 'id="metric-tokens"' in body
        assert 'id="metric-tokens"' in body   # the band cell the case-wide token total fills

    def test_api_cases_picks_up_new_trace_without_restart(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "live-case", "LIVE")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        before = json.loads(conn.getresponse().read())
        live = next(c for c in before["cases"] if c["case_id"] == "LIVE")
        assert live["traces"] == []
        # Drop a trace while the server is running.
        (case / "analysis" / "LIVE_trace.json").write_text(
            '{"case_id":"LIVE","entries":[]}'
        )
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        after = json.loads(conn.getresponse().read())
        live2 = next(c for c in after["cases"] if c["case_id"] == "LIVE")
        assert len(live2["traces"]) == 1

    def test_serves_trace_json_from_case(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "ts-case", "TS",
                   trace_name="TS_trace.json")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/ts-case/analysis/TS_trace.json")
        resp = conn.getresponse()
        assert resp.status == 200
        assert b'"case_id": "TS"' in resp.read()


class TestServeDashboardDiscovery:
    """The MCP `serve_dashboard` tool just builds a deep-link URL into the
    running standalone dashboard."""

    def test_no_dashboard_returns_hint(self, tmp_path, monkeypatch):
        from tools import misc
        case = tmp_path / "fallback-case"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: FALLBACK\n")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(tmp_path / "missing.url"),
        )
        r = misc.launch_dashboard(str(case))
        assert r["success"] is False
        assert "atlas-dashboard" in r["error"]
        # The hint URL still uses the case's expected trace path so the
        # operator can open it as soon as the dashboard is running.
        assert "?trace=/fallback-case/analysis/FALLBACK_trace.json" in r["hint_url"]

    def test_invalid_case_dir(self, tmp_path):
        from tools import misc
        r = misc.launch_dashboard(str(tmp_path / "nope"))
        assert r["success"] is False
        assert "not a directory" in r["error"]

    def test_live_dashboard_returns_deep_link(self, standalone_server, monkeypatch):
        from tools import misc

        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "deep-case", "DEEP")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(case))
        assert r["success"] is True
        assert r["url"].startswith(standalone_server["url"])
        assert "?trace=/deep-case/analysis/DEEP_trace.json" in r["url"]
        assert r["case_id"] == "DEEP"

    def test_case_outside_cases_root_refuses(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        from tools import misc

        outsider = tmp_path / "outside-case"
        outsider.mkdir()
        (outsider / "CASE.md").write_text("**Case ID**: OUT\n")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(outsider))
        assert r["success"] is False
        assert "outside the dashboard's cases_root" in r["error"]

    def test_stale_discovery_file_is_ignored(self, tmp_path, monkeypatch):
        """A discovery file with a dead PID must not look like a live dashboard."""
        from tools import misc

        case = tmp_path / "stale-case"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: STALE\n")
        discovery = tmp_path / "stale.json"
        # PID 1 is init — exists, but won't match a Python dashboard.
        # Use a definitely-dead PID instead by picking a very large one.
        discovery.write_text(json.dumps({
            "url": "http://127.0.0.1:65535/_dashboard/dashboard.html",
            "port": 65535,
            "cases_root": str(tmp_path),
            "pid": 999999,
        }))
        monkeypatch.setattr(misc, "_DASHBOARD_DISCOVERY_FILE", str(discovery))
        r = misc.launch_dashboard(str(case))
        assert r["success"] is False
        assert "no standalone dashboard reachable" in r["error"]


class TestDeepLinkFromRealTracePath:
    """Regression for the deep-link 404: the URL must be built from the real
    trace file the agent writes, not re-derived as `{case_id}_trace.json`
    (which mismatched the true filename's casing and 404'd on case-sensitive
    static serving)."""

    def test_deep_link_uses_real_filename_not_case_id(
        self, standalone_server, monkeypatch,
    ):
        from tools import misc
        cases_root = standalone_server["cases_root"]
        # Case dir lowercase; Case ID uppercase; real trace has a third name.
        case = _seed_case(cases_root, "acme_estate", "ACME_ESTATE",
                          trace_name="ACME_ESTATE_SWEEP_trace.json")
        trace = case / "analysis" / "ACME_ESTATE_SWEEP_trace.json"
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(case), trace_path=str(trace))
        assert r["success"] is True
        assert "?trace=/acme_estate/analysis/ACME_ESTATE_SWEEP_trace.json" \
            in r["url"]
        # The wrong, re-derived name must NOT appear.
        assert "ACME_ESTATE_trace.json" not in r["url"]

    def test_deep_link_served_trace_actually_loads(
        self, standalone_server, monkeypatch,
    ):
        """The deep link the tool returns resolves to a real 200 on the server."""
        from urllib.parse import urlparse
        from tools import misc
        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "acme_estate", "ACME_ESTATE",
                          trace_name="ACME_ESTATE_SWEEP_trace.json")
        trace = case / "analysis" / "ACME_ESTATE_SWEEP_trace.json"
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(case), trace_path=str(trace))
        trace_url = urlparse(r["url"]).query.split("trace=", 1)[1]
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        conn.request("GET", trace_url)
        resp = conn.getresponse()
        assert resp.status == 200

    def test_hint_url_uses_real_filename_when_offline(self, tmp_path, monkeypatch):
        from tools import misc
        case = tmp_path / "acme_estate"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: ACME_ESTATE\n")
        (case / "analysis").mkdir()
        trace = case / "analysis" / "ACME_ESTATE_SWEEP_trace.json"
        trace.write_text("{}")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(tmp_path / "missing.url"),
        )
        r = misc.launch_dashboard(str(case), trace_path=str(trace))
        assert r["success"] is False
        assert "ACME_ESTATE_SWEEP_trace.json" in r["hint_url"]

    def test_empty_trace_path_keeps_legacy_derivation(
        self, standalone_server, monkeypatch,
    ):
        from tools import misc
        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "legacy-case", "LEGACY")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(case))  # no trace_path
        assert "?trace=/legacy-case/analysis/LEGACY_trace.json" in r["url"]

    def test_outside_cases_root_still_errors_with_trace_path(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        from tools import misc
        outsider = tmp_path / "outside-case"
        (outsider / "analysis").mkdir(parents=True)
        (outsider / "CASE.md").write_text("**Case ID**: OUT\n")
        trace = outsider / "analysis" / "OUT_trace.json"
        trace.write_text("{}")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(outsider), trace_path=str(trace))
        assert r["success"] is False
        assert "outside the dashboard's cases_root" in r["error"]

    def test_start_execution_log_link_matches_written_file(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        """End-to-end: even when Case ID casing differs from the output file,
        the URL start_execution_log surfaces points at the real trace."""
        from tools import misc
        from tools.misc import start_execution_log
        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "acme_case", "ACME-CASE")
        # Output filename intentionally unlike `{case_id}_trace.json`.
        log_path = str(case / "analysis" / "run42_trace.json")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log("ACME-CASE", log_path)
        assert r["success"] is True
        assert "?trace=/acme_case/analysis/run42_trace.json" in r["dashboard_url"]


class TestCaseInsensitiveStaticFallback:
    """serve.py defense-in-depth: a *.json deep link with drifted casing still
    resolves rather than 404ing."""

    def test_wrong_case_trace_still_serves(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "ci-case", "CI", trace_name="CI_trace.json")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        # Request with lowercased filename + case dir.
        conn.request("GET", "/ci-case/analysis/ci_trace.json")
        resp = conn.getresponse()
        assert resp.status == 200
        assert b'"case_id": "CI"' in resp.read()

    def test_truly_missing_json_still_404s(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "gone-case", "GONE")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        conn.request("GET", "/gone-case/analysis/nonexistent_trace.json")
        resp = conn.getresponse()
        assert resp.status == 404


class TestHandlerCrashSafetyNet:
    """A bug inside any API handler (or a module it lazily imports) must
    turn into a diagnosable JSON error response, not a dropped connection —
    a dropped mid-request connection is exactly what browsers report as the
    generic, undiagnosable "NetworkError when attempting to fetch resource".
    do_GET's API dispatch and do_POST's handler dispatch each wrap the call
    in a try/except as a backstop; these tests prove an *unexpected*
    exception (not the handler's own validation error) still gets a real
    HTTP response."""

    def test_get_api_unexpected_exception_returns_clean_500(
        self, standalone_server, monkeypatch,
    ):
        from dashboard import config_llm

        def _boom():
            raise RuntimeError("simulated unexpected failure")

        monkeypatch.setattr(config_llm, "list_providers", _boom)
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        conn.request("GET", "/_dashboard/api/config/llm")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 503
        data = json.loads(body)
        assert "RuntimeError" in data["error"]

    def test_post_handler_unexpected_exception_returns_clean_500(
        self, standalone_server, monkeypatch,
    ):
        from dashboard import case_admin

        def _boom(*a, **kw):
            raise RuntimeError("simulated unexpected failure")

        monkeypatch.setattr(case_admin, "create_case", _boom)
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        body = json.dumps({"case_id": "CRASHTEST"}).encode()
        conn.request(
            "POST", "/_dashboard/api/case/create", body=body,
            headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        assert resp.status == 503
        assert "RuntimeError" in data["error"]

    def test_post_handler_expected_error_still_returns_400(
        self, standalone_server,
    ):
        """The safety net must not swallow handlers' own specific errors —
        an invalid case ID still gets the friendly 400, not a generic 503."""
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        body = json.dumps({"case_id": "not valid! id"}).encode()
        conn.request(
            "POST", "/_dashboard/api/case/create", body=body,
            headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 400


class TestUserAdminNonexistentId:
    """Regression: config/users/set_active and config/users/delete used to
    call auth.py with no try/except at all, and auth.py's UPDATE/DELETE
    statements didn't check whether any row actually matched — so acting on
    a stale/mistyped user_id silently returned {"success": true} while
    doing nothing. Both layers are fixed; this proves the HTTP-level 400."""

    def test_set_active_nonexistent_user_400s(self, standalone_server):
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        body = json.dumps({"user_id": 999999, "active": False}).encode()
        conn.request(
            "POST", "/_dashboard/api/config/users/set_active", body=body,
            headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        assert resp.status == 400
        assert "no such user" in data["error"]

    def test_delete_nonexistent_user_400s(self, standalone_server):
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2)
        body = json.dumps({"user_id": 999999}).encode()
        conn.request(
            "POST", "/_dashboard/api/config/users/delete", body=body,
            headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        assert resp.status == 400
        assert "no such user" in data["error"]


class TestStartExecutionLogIntegratesDashboard:
    def test_url_written_when_dashboard_live(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        from tools import misc
        from tools.misc import start_execution_log
        from core.execution_log import log as global_log

        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "EL-CASE", "EL-CASE")
        log_path = str(case / "analysis" / "EL-CASE_trace.json")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log("EL-CASE", log_path)
        assert r["success"] is True
        assert r.get("dashboard_url"), r
        assert "?trace=/EL-CASE/analysis/EL-CASE_trace.json" in r["dashboard_url"]
        # Also persisted next to the trace so the operator can grab it from
        # the analysis dir.
        url_file = case / "analysis" / "dashboard.url"
        assert url_file.exists()
        assert r["dashboard_url"] in url_file.read_text()
        # Happy path: start_execution_log's trace-open mark is no error, so
        # no system_error at all may be on the trace. Anything means a silent
        # failure slipped through.
        bad = [e for e in global_log._entries if e.get("type") == "system_error"]
        assert not bad, f"unexpected system_error entries on happy path: {bad}"

    def test_no_dashboard_surfaces_hint(
        self, tmp_path, monkeypatch,
    ):
        from tools import misc
        from tools.misc import start_execution_log

        case = tmp_path / "OFFLINE-CASE"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: OFFLINE-CASE\n")
        (case / "analysis").mkdir()
        log_path = str(case / "analysis" / "OFFLINE-CASE_trace.json")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(tmp_path / "missing.url"),
        )
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log("OFFLINE-CASE", log_path)
        assert r["success"] is True
        assert "dashboard_url" not in r
        assert r.get("dashboard_error")
        assert r.get("dashboard_hint_url")

    def test_launch_dashboard_false_skips_discovery(self, tmp_path):
        from tools.misc import start_execution_log
        case = tmp_path / "SKIP-CASE"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: SKIP-CASE\n")
        (case / "analysis").mkdir()
        log_path = str(case / "analysis" / "SKIP-CASE_trace.json")
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log(
                "SKIP-CASE", log_path, launch_dashboard=False,
            )
        assert r["success"] is True
        assert "dashboard_url" not in r
        assert "dashboard_error" not in r
        assert not (case / "analysis" / "dashboard.url").exists()
