"""Investigator-centric dashboard: read models + case_overview/questions API.

Covers the redesign's core guarantees:
- answers shown for a question are DERIVED from the claim graph
  (no second source of truth),
- projections are strictly case-scoped (no cross-case leakage),
- the new endpoints work end-to-end against a live server,
- every page ships the shared shell (one case selector / session).
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from dashboard import read_models as rm

DASH_SRC = Path(__file__).resolve().parents[2] / "dashboard"


# ── fixtures ────────────────────────────────────────────────────────────────

def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


_TOKEN = ""  # set per-test by standalone_server; _get/_get_raw read it so
             # none of the many call sites below need to pass a session.


@pytest.fixture
def standalone_server(tmp_path, monkeypatch):
    global _TOKEN
    from dashboard import auth, serve as dash_serve
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()
    user = auth.create_user("tester", "tester@example.com",
                            "testerpassword1", "admin")
    _TOKEN = auth.create_session(user.id)
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    discovery = tmp_path / "discovery.json"
    with patch.object(dash_serve, "DISCOVERY_FILE", str(discovery)):
        httpd, chosen = dash_serve._bind(str(cases_root), _free_port())
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            time.sleep(0.05)
            yield {"cases_root": cases_root, "port": chosen, "token": _TOKEN}
        finally:
            httpd.shutdown()
            _TOKEN = ""


def _get(port: int, path: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", path, headers={"Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    body = resp.read()
    try:
        return resp.status, json.loads(body)
    except json.JSONDecodeError:
        return resp.status, {}


def _get_raw(port: int, path: str) -> tuple[int, bytes, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", path, headers={"Cookie": f"atlas_session={_TOKEN}"})
    resp = conn.getresponse()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, resp.read(), headers


def _seed_full_case(cases_root: Path, name: str, case_id: str,
                    question: str, statement: str) -> Path:
    """A case with one CASE.md question answered by one conclusion."""
    case = cases_root / name
    atlas = case / ".atlas"
    atlas.mkdir(parents=True)
    (case / "CASE.md").write_text(
        f"# Case: {case_id}\n\n**Case ID:** {case_id}\n\n"
        f"## Investigation Requests\n\n- {question}\n",
        encoding="utf-8",
    )
    (atlas / "investigation_tasks.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": case_id, "next_id": 2,
        "tasks": [{
            "id": "task-0001", "text": question, "status": "answered",
            "related_claim_ids": ["C0001"],
            "created_at": "2026-08-07T00:00:00Z",
            "updated_at": "2026-08-07T01:00:00Z",
        }],
    }))
    (atlas / "investigation_tasks.json").parent.mkdir(exist_ok=True)
    (atlas / "claim_graph.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": case_id,
        "nodes": {
            "C0001": {"id": "C0001", "kind": "conclusion", "status": "new",
                      "statement": statement, "confidence": "LIKELY",
                      "host": "HOSTX",
                      "evidence": [{"artifact": "tool", "call_id": 7}]},
        },
        "edges": [],
    }))
    return case


# ── answer derivation (the no-second-source-of-truth rule) ─────────────────

GRAPH = {
    "nodes": {
        "C1": {"id": "C1", "kind": "conclusion", "status": "new",
               "statement": "Data was exfiltrated to 1.2.3.4.",
               "confidence": "LIKELY", "host": "HOSTA",
               "evidence": [{"artifact": "net.pcap", "call_id": 12}]},
        "C2": {"id": "C2", "kind": "claim", "status": "new",
               "statement": "Archive staged in C:\\tmp.",
               "confidence": "CONFIRMED", "host": "HOSTA", "evidence": []},
        "C3": {"id": "C3", "kind": "claim", "status": "superseded",
               "statement": "Old superseded belief.",
               "confidence": "CONFIRMED", "evidence": []},
        "K1": {"id": "K1", "kind": "conflict", "status": "conflict",
               "statement": "Timestamps disagree between sources.",
               "conflicting_claim_ids": ["C2"], "evidence": []},
    },
    "edges": [{"from": "C2", "to": "C1", "type": "supports"}],
}


class TestAnswerDerivation:
    def test_answer_prefers_conclusions_and_reports_confidence(self):
        task = {"id": "task-0001", "text": "Did exfil occur?",
                "status": "answered", "related_claim_ids": ["C1", "C2"]}
        a = rm.derive_task_answer(task, GRAPH)
        assert a["has_answer"] is True
        assert "exfiltrated" in a["summary"]
        # A conclusion *is* the answer: the summary is its statement, read
        # as prose, not a verdict label with the statement glued behind it.
        # The position taken is still reported separately for the pill.
        assert a["verdict"] == "Indicators found"
        assert a["summary"].startswith("Data was exfiltrated")
        assert "Indicators found" not in a["summary"]
        assert a["confidence"] == "LIKELY"
        supp_ids = [s["id"] for s in a["supporting"]]
        assert supp_ids[0] == "C1"          # conclusions first
        assert "C2" in supp_ids
        assert a["supporting"][0]["evidence_call_ids"] == [12]

    def test_superseded_claims_do_not_answer(self):
        task = {"id": "t", "text": "q", "status": "answered",
                "related_claim_ids": ["C3"]}
        a = rm.derive_task_answer(task, GRAPH)
        assert a["has_answer"] is False
        assert a["summary"] is None
        assert a["supporting"] == []

    def test_conflicts_touching_related_claims_flagged(self):
        task = {"id": "t", "text": "q", "status": "partial",
                "related_claim_ids": ["C2"]}
        a = rm.derive_task_answer(task, GRAPH)
        assert len(a["conflicts"]) == 1
        assert a["conflicts"][0]["id"] == "K1"

    def test_unknown_claim_ids_surface_not_crash(self):
        task = {"id": "t", "text": "q", "status": "answered",
                "related_claim_ids": ["NOPE"]}
        a = rm.derive_task_answer(task, GRAPH)
        assert a["missing_claim_ids"] == ["NOPE"]
        assert a["has_answer"] is False

    def test_no_related_claims_no_answer(self):
        a = rm.derive_task_answer({"id": "t", "text": "q", "status": "open",
                                   "related_claim_ids": []}, GRAPH)
        assert a["has_answer"] is False


class TestStatusLanguage:
    """Investigators see the filled/half/open circle progression and words —
    never internal enum values."""

    @pytest.mark.parametrize("status,glyph,bucket", [
        ("answered", "\u25cf", "answered"),
        ("partial", "\u25d0", "partial"),
        ("in_progress", "\u25d0", "partial"),
        ("reopened", "\u25d0", "partial"),
        ("open", "\u25cb", "open"),
        ("blocked_missing_evidence", "\u25cb", "open"),
        ("dropped", "—", "dropped"),
        ("withdrawn", "—", "dropped"),  # legacy alias
    ])
    def test_glyph_and_bucket(self, status, glyph, bucket):
        t = rm.task_projection({"id": "t", "text": "q", "status": status},
                               {"nodes": {}, "edges": []})
        assert t["glyph"] == glyph
        assert t["bucket"] == bucket
        assert "_" not in t["status_label"]   # human-readable, no enums

    def test_derived_prefix_stripped_and_marked(self):
        t = rm.task_projection(
            {"id": "t", "text": "[derived] Check Host B", "status": "open"},
            {"nodes": {}, "edges": []})
        assert t["derived"] is True
        assert t["text"] == "Check Host B"


class TestReportAndEvidence:
    def test_trace_md_is_not_a_report(self, tmp_path):
        case = tmp_path / "c"
        (case / "reports").mkdir(parents=True)
        (case / "reports" / "X_trace.md").write_text("trace export")
        assert rm.report_status(str(case))["available"] is False
        (case / "reports" / "X_report.md").write_text("# Report")
        st = rm.report_status(str(case))
        assert st["available"] is True
        assert st["name"] == "X_report.md"

    def test_latest_dir_wins(self, tmp_path):
        case = tmp_path / "c"
        (case / "reports" / "latest").mkdir(parents=True)
        (case / "reports" / "old_report.md").write_text("old")
        (case / "reports" / "latest" / "new_report.md").write_text("new")
        st = rm.report_status(str(case))
        assert "latest/new_report.md" in st["path"]

    def test_report_files_include_timeline_exclude_traces(self, tmp_path):
        case = tmp_path / "c"
        (case / "reports").mkdir(parents=True)
        (case / "reports" / "c_report.md").write_text("# R")
        (case / "reports" / "master_timeline.tsv").write_text(
            "Timestamp\tMachine\n")
        (case / "reports" / "c_trace.md").write_text("trace")
        (case / "reports" / "c_trace.json").write_text("{}")
        (case / "reports" / "claim_snapshot.json").write_text("{}")
        st = rm.report_status(str(case))
        names = {f["name"] for f in st["files"]}
        assert names == {"c_report.md", "master_timeline.tsv"}
        assert st["bundle_available"] is True
        kinds = {f["name"]: f["kind"] for f in st["files"]}
        assert kinds["master_timeline.tsv"] == "timeline"

    def test_report_bundle_zip_contains_timeline(self, tmp_path):
        import zipfile
        import io
        case = tmp_path / "c"
        (case / "reports").mkdir(parents=True)
        (case / "reports" / "c_report.md").write_text("# Hello")
        (case / "reports" / "master_timeline.tsv").write_text(
            "Timestamp\tMachine\n2026-01-01\tHOST\n")
        data = rm.build_report_bundle_zip(str(case))
        assert data
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            assert set(zf.namelist()) == {"c_report.md", "master_timeline.tsv"}
            assert b"Hello" in zf.read("c_report.md")

    def test_timeline_template_gated_on_plugin(self, monkeypatch):
        monkeypatch.setattr(rm, "timeline_plugin_active", lambda: False)
        assert rm.timeline_template_tsv() is None
        monkeypatch.setattr(rm, "timeline_plugin_active", lambda: True)
        # Real plugin columns when importable.
        tsv = rm.timeline_template_tsv()
        assert tsv is not None
        assert tsv.startswith("Timestamp\tMachine\tUser\tEvent")
        assert tsv.endswith("\n")

    def test_evidence_summary_from_catalog(self, tmp_path):
        case = tmp_path / "c"
        (case / ".atlas").mkdir(parents=True)
        (case / ".atlas" / "evidence_catalog.json").write_text(json.dumps({
            "units": {
                "e1": {"status": "current", "size": 100},
                "e2": {"status": "stale", "size": 50},
            },
        }))
        ev = rm.evidence_summary(str(case))
        assert ev == {"cataloged": True, "files": 2, "current_files": 1,
                      "total_bytes": 150}


# ── live endpoints + case isolation ─────────────────────────────────────────

class TestOverviewEndpoint:
    def test_case_overview_end_to_end(self, standalone_server):
        root = standalone_server["cases_root"]
        _seed_full_case(root, "alpha", "ALPHA",
                        "Did data exfiltration occur?",
                        "Yes — data left via HTTPS to a rented VPS.")
        status, data = _get(standalone_server["port"],
                            "/_dashboard/api/case_overview?case=alpha")
        assert status == 200
        assert data["case_id"] == "ALPHA"
        q = data["questions"]["questions"]
        assert len(q) == 1
        assert q[0]["glyph"] == "\u25cf"
        assert q[0]["status_label"] == "Answered"
        answer = q[0]["answer"]
        assert answer["summary"].startswith("Yes — data left")
        assert answer["verdict"] == "Indicators found"
        assert data["questions"]["progress"]["answered"] == 1

    def test_case_isolation_no_leakage(self, standalone_server):
        """Two cases: each overview must contain only its own content."""
        root = standalone_server["cases_root"]
        _seed_full_case(root, "alpha", "ALPHA", "Question about ALPHA?",
                        "ALPHA-only conclusion.")
        _seed_full_case(root, "beta", "BETA", "Question about BETA?",
                        "BETA-only conclusion.")
        port = standalone_server["port"]
        _, a = _get(port, "/_dashboard/api/case_overview?case=alpha")
        _, b = _get(port, "/_dashboard/api/case_overview?case=beta")
        assert "BETA" not in json.dumps(a)
        assert "ALPHA" not in json.dumps(b)

    def test_unknown_case_404(self, standalone_server):
        status, data = _get(standalone_server["port"],
                            "/_dashboard/api/case_overview?case=nope")
        assert status == 404
        assert "unknown" in data["error"]

    def test_traversal_rejected(self, standalone_server):
        status, _ = _get(standalone_server["port"],
                         "/_dashboard/api/case_overview?case=../../etc")
        assert status == 404

    def test_empty_case_graceful(self, standalone_server):
        """A bare case dir (no .atlas, no trace, no report) must not error."""
        root = standalone_server["cases_root"]
        case = root / "bare"
        case.mkdir()
        (case / "CASE.md").write_text("**Case ID**: BARE\n")
        status, data = _get(standalone_server["port"],
                            "/_dashboard/api/case_overview?case=bare")
        assert status == 200
        assert data["questions"]["questions"] == []
        assert data["claims"]["has_graph"] is False
        assert data["report"]["available"] is False
        assert data["activity"]["busy"] is False

    def test_questions_endpoint(self, standalone_server):
        root = standalone_server["cases_root"]
        _seed_full_case(root, "alpha", "ALPHA", "Q1?", "A1.")
        status, data = _get(standalone_server["port"],
                            "/_dashboard/api/questions?case=alpha")
        assert status == 200
        assert data["questions"][0]["text"] == "Q1?"
        assert "busy" in data

    def test_capabilities_and_timeline_template(self, standalone_server,
                                                monkeypatch):
        root = standalone_server["cases_root"]
        case = root / "rep-case"
        (case / "reports").mkdir(parents=True)
        (case / "CASE.md").write_text("**Case ID**: REP\n")
        (case / "reports" / "REP_report.md").write_text("# Report body\n")
        (case / "reports" / "master_timeline.tsv").write_text(
            "Timestamp\tMachine\n2026-01-01T00:00:00Z\tHOSTA\n")
        port = standalone_server["port"]

        status, caps = _get(port, "/_dashboard/api/capabilities")
        assert status == 200
        assert "timeline_plugin_active" in caps

        _, ov = _get(port, "/_dashboard/api/case_overview?case=rep-case")
        kinds = {f["kind"] for f in ov["report"]["files"]}
        assert "report" in kinds and "timeline" in kinds

        # Template available when plugin is active (typical in this repo).
        status, body, headers = _get_raw(
            port, "/_dashboard/api/timeline_template?case=rep-case")
        if status == 200:
            assert b"Timestamp" in body
            assert "master_timeline_template.tsv" in headers.get(
                "content-disposition", "")
        else:
            assert status == 404

        monkeypatch.setattr(rm, "timeline_template_tsv", lambda: None)
        status, data = _get(port, "/_dashboard/api/timeline_template")
        assert status == 404


class TestBrainKnowledgeEndpoint:
    def test_lists_notes_excluding_confidential(self, standalone_server,
                                                tmp_path, monkeypatch):
        brain = tmp_path / "brain"
        wiki = brain / "wiki" / "techniques"
        wiki.mkdir(parents=True)
        (wiki / "persistence-run-keys.md").write_text(
            "---\ntitle: Registry run keys\ntype: technique\n"
            "tags: [persistence]\nupdated: 2026-08-01\n---\n"
            "Check HKCU\\...\\Run for persistence.\n")
        (wiki / "secret-note.md").write_text(
            "---\ntitle: Secret\ntype: technique\n"
            "source_classification: confidential\n---\nhidden\n")
        monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(brain))
        status, data = _get(standalone_server["port"],
                            "/_dashboard/api/brain/knowledge")
        assert status == 200
        titles = [n["title"] for n in data["notes"]]
        assert "Registry run keys" in titles
        assert "Secret" not in titles


# ── shell integration: one session, one selector, every page ───────────────

CASE_PAGES = ["overview.html", "questions.html", "claim_view.html",
              "trace_viewer.html", "report.html",
              "timeline.html", "brain.html"]


class TestSharedShell:
    @pytest.mark.parametrize("page", CASE_PAGES)
    def test_every_page_loads_shell_and_tokens(self, page):
        body = (DASH_SRC / page).read_text(encoding="utf-8")
        assert "assets/shell.js" in body, f"{page} must load the shared shell"
        assert "assets/atlas.css" in body, f"{page} must load shared tokens"

    @pytest.mark.parametrize("page", CASE_PAGES)
    def test_no_page_local_case_selector(self, page):
        """Regression: the Board bug (c.dir || c.path || c.name against an
        API returning case_dir/case_id) came from page-local case pickers.
        Case selection now lives ONLY in the shell."""
        body = (DASH_SRC / page).read_text(encoding="utf-8")
        assert 'id="case-select"' not in body, page
        assert "c.dir || c.path" not in body, page

    def test_shell_uses_correct_api_fields(self):
        shell = (DASH_SRC / "assets" / "shell.js").read_text(encoding="utf-8")
        assert "case_dir" in shell and "case_id" in shell
        assert "c.dir || c.path" not in shell
        # active case persists in localStorage; approval secret must not.
        assert "localStorage" in shell
        assert "atlas-approval-secret" not in shell

    def test_old_pages_redirect_to_new(self):
        board = (DASH_SRC / "investigation_board.html").read_text("utf-8")
        assert "questions.html" in board
        review = (DASH_SRC / "brain_review.html").read_text("utf-8")
        assert "brain.html" in review

    def test_approval_secret_stays_session_scoped(self):
        brain = (DASH_SRC / "brain.html").read_text(encoding="utf-8")
        assert "sessionStorage.getItem('atlas-approval-secret')" in brain
        assert "localStorage.setItem('atlas-approval-secret'" not in brain

    def test_report_page_uses_preview_dropdown_not_zip(self):
        body = (DASH_SRC / "report.html").read_text(encoding="utf-8")
        assert 'id="report-select"' in body
        assert "report_bundle" not in body
        assert "Download all reports" not in body

    def test_timeline_tab_gated_in_shell_and_page(self):
        shell = (DASH_SRC / "assets" / "shell.js").read_text(encoding="utf-8")
        assert "timeline.html" in shell
        assert "requiresPlugin" in shell
        assert "timeline_plugin_active" in shell or "capabilities" in shell
        body = (DASH_SRC / "timeline.html").read_text(encoding="utf-8")
        assert "timeline_template" in body
        assert "timelinePluginActive" in body
        assert 'id="tl-select"' in body


# ── documented architecture decision ────────────────────────────────────────

def test_no_resolution_field_written_to_tasks():
    """The dashboard derives answers; it must never persist a competing
    'resolution' answer store into investigation_tasks.json."""
    src = (Path(rm.__file__)).read_text(encoding="utf-8")
    assert "read-only" in src
    serve_src = (DASH_SRC / "serve.py").read_text(encoding="utf-8")
    assert '"resolution"' not in serve_src
