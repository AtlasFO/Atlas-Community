"""The Coverage tab and the Time layout: the nav, the endpoint and its
role, the Incident tab's absence, the strings of both pages in every
dashboard language, and the words a class line says."""
from __future__ import annotations

import functools
import html
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from dashboard import app, auth, read_models

ROOT = Path(__file__).resolve().parents[2]
DASH = ROOT / "dashboard"
I18N = DASH / "assets" / "i18n.js"

# Evaluates i18n.js with the two browser globals it touches and prints its
# string tables (the Brain Earth test's harness).
_DUMP = """
const fs = require("fs"), vm = require("vm");
const ctx = { localStorage: { getItem: () => null, setItem() {} },
              document: { documentElement: { dataset: {} } } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") +
                "\\n;globalThis.STRINGS = AtlasI18n.STRINGS;", ctx);
process.stdout.write(JSON.stringify(ctx.STRINGS));
"""

# Runs the Coverage page's script under a stub shell and DOM (the shell's
# t() is the real i18n table) and prints classLine() for the units in
# argv[3], so what a line says is checked as rendered.
_LINES = """
const fs = require("fs"), vm = require("vm");
const page = fs.readFileSync(process.argv[1], "utf8");
const src = page.slice(page.lastIndexOf("<script>") + "<script>".length, page.lastIndexOf("</script>"));
const el = () => ({ innerHTML: "", classList: { add() {}, remove() {} }, querySelectorAll: () => [] });
const ctx = { localStorage: { getItem: () => null, setItem() {} },
              document: { documentElement: { dataset: {} }, getElementById: el, addEventListener() {}, querySelectorAll: () => [] },
              setTimeout, clearTimeout };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);
vm.runInContext(`const AtlasShell = { esc: (s) => String(s ?? "").replace(/[&<>"']/g, (c) => "&#" + c.charCodeAt(0) + ";"),
  t: AtlasI18n.t, activeCase: () => "CASE-A", caseInfo: () => null, init() {}, poll() { return () => {}; },
  api: async () => ({}), isTransient: () => false };`, ctx);
vm.runInContext(src, ctx);
const out = {};
for (const [k, c] of Object.entries(JSON.parse(process.argv[3]))) out[k] = vm.runInContext(`classLine(${JSON.stringify(c)})`, ctx);
process.stdout.write(JSON.stringify(out));
"""

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@functools.lru_cache(maxsize=1)
def _tables() -> dict:
    done = subprocess.run(["node", "-e", _DUMP, str(I18N)], capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def test_the_coverage_tab_follows_case_findings_and_the_incident_tab_is_gone():
    shell = (DASH / "assets/shell.js").read_text(encoding="utf-8")
    nav = shell[shell.index("const CASE_NAV"):shell.index("const GLOBAL_NAV")]
    assert nav.index("'claims'") < nav.index("'coverage'") < nav.index("'iocs'")
    assert "coverage.html" in nav and "requiresCapability" not in shell
    assert "incident" not in shell.lower()
    assert not (DASH / "incident_map.html").exists() and (DASH / "coverage.html").is_file()


def test_the_endpoint_is_for_every_signed_in_role_and_the_old_one_is_gone():
    assert "case/coverage" in app.GET_ROUTES and "incident_map" not in app.GET_ROUTES
    assert "incident_map" not in auth.ROUTE_MIN_ROLE
    assert auth.effective_min_role("case/coverage") == "viewer"
    assert not auth.can_access(None, "case/coverage")
    viewer = auth.User(id=1, username="v", email="", role="viewer", is_active=True, created_at="")
    assert auth.can_access(viewer, "case/coverage")
    assert not hasattr(read_models, "incident_map") and not hasattr(read_models, "incident_map_present")


def test_the_capabilities_no_longer_carry_a_case_flag():
    src = (DASH / "app.py").read_text(encoding="utf-8")
    body = src[src.index("def _get_capabilities"):src.index("def _get_coverage")]
    assert "incident" not in body and "case" not in body.split('"""')[2]


@needs_node
def test_every_key_the_pages_use_exists_in_every_language():
    tables = _tables()
    assert "nav.coverage" in tables["en"] and "nav.incident" not in tables["en"]
    pages = {"coverage.html": r"'(cov\.[\w.]+)'", "claim_view.html": r"'(claims\.time\.\w+)'"}
    for name, pattern in pages.items():
        keys = set(re.findall(pattern, (DASH / name).read_text(encoding="utf-8")))
        assert keys, f"no keys found in {name}"
        for lang, table in tables.items():
            missing = sorted(k for k in keys if k not in table)
            assert not missing, f"{name}: {lang} lacks {missing}"
            for k in keys:
                assert sorted(re.findall(r"\{(\w+)\}", table[k])) == sorted(re.findall(r"\{(\w+)\}", tables["en"][k])), \
                    f"{k}: placeholders differ between en and {lang}"
    # The leave kinds the page maps are the closed set the leave module checks.
    from core.evidence_leave import KINDS
    page = (DASH / "coverage.html").read_text(encoding="utf-8")
    for kind in KINDS:
        assert f"'cov.kind.{kind}'" in page and f"cov.kind.{kind}" in tables["de"]


@needs_node
def test_a_class_line_says_the_pages_words_and_hides_an_empty_file_count():
    units = {
        "walked": {"label": "processes", "files": 0, "state": "partial", "note": "walked",
                   "reason_kind": "", "reason": "", "proof": []},
        "swept": {"label": "network endpoints", "files": 0, "state": "partial", "note": "swept",
                  "reason_kind": "", "reason": "", "proof": []},
        "credited": {"label": "registry hives", "files": 7, "state": "partial", "note": "",
                     "reason_kind": "", "reason": "", "proof": []},
        "refused": {"label": "file objects", "files": 0, "state": "open", "note": "refused",
                    "reason_kind": "", "reason": "", "proof": []},
        "file": {"label": "lnk", "read": 0, "total": 2, "state": "open", "note": "file",
                 "detail": "analysis/exports/dc01/desk.lnk", "reason_kind": "", "reason": "", "proof": []},
        "left": {"label": "browser history", "files": 2, "state": "left", "note": "",
                 "reason_kind": "outside_window", "reason": "its newest row is from 2031-01-20", "proof": ["31"]},
    }
    done = subprocess.run(["node", "-e", _LINES, str(DASH / "coverage.html"), str(I18N), json.dumps(units)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    lines = {k: html.unescape(v) for k, v in json.loads(done.stdout).items()}
    en = _tables()["en"]
    assert en["cov.note.walked"] in lines["walked"] and "0 files" not in lines["walked"]
    assert en["cov.note.swept"] in lines["swept"] and "parsed and swept" not in lines["swept"]
    assert en["cov.state.partial"] in lines["credited"] and "7 files" in lines["credited"]
    assert en["cov.open.refused"] in lines["refused"] and "0 files" not in lines["refused"]
    assert "read analysis/exports/dc01/desk.lnk" in lines["file"] and "0 of 2" in lines["file"]
    assert en["cov.kind.outside_window"] + ": its newest row is from 2031-01-20" in lines["left"]
    assert "2 files" in lines["left"] and "#31" in lines["left"]
    # The page's words, never the ledger's: no state word of the ledger in any line.
    for text in lines.values():
        assert not re.search(r"\b(relevant|pending|walked|swept)\b", text), text
