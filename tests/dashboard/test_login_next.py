"""The sign-in page returns to the page it was sent from, query and fragment
included, and never to another origin (dashboard/login.html safeNext, run
under node)."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _safe_next_source() -> str:
    html = (ROOT / "dashboard" / "login.html").read_text(encoding="utf-8")
    start = html.index("function safeNext(")
    depth, i = 0, html.index("{", start)
    while True:
        depth += {"{": 1, "}": -1}.get(html[i], 0)
        if depth == 0:
            return html[start:i + 1]
        i += 1


def _run_safe_next(here: str, cases: dict) -> dict:
    script = (_safe_next_source() + "\nconst here = new URL(%s);\nconst cases = %s;\n"
              "const out = {};\nfor (const k of Object.keys(cases)) out[k] = safeNext(k, here);\n"
              "console.log(JSON.stringify(out));\n") % (json.dumps(here), json.dumps(cases))
    proc = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_next_stays_on_this_dashboard():
    here = "https://atlas.example:8443/_dashboard/login.html?next=x"
    cases = {
        "overview.html?case=CASE-A": "/_dashboard/overview.html?case=CASE-A",
        "/_dashboard/overview.html?case=CASE-A#runs": "/_dashboard/overview.html?case=CASE-A#runs",
        "": "overview.html",
        "//evil.example/x": "overview.html",
        "/\\evil.example/x": "overview.html",
        "\\\\evil.example/x": "overview.html",
        "\\/evil.example": "overview.html",
        "https://evil.example/": "overview.html",
        "https://atlas.example:8443@evil.example/": "overview.html",
        "javascript:alert(1)": "overview.html",
    }
    assert _run_safe_next(here, cases) == cases


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_a_fragment_survives_sign_in():
    """A redirect's `next` can hold no fragment (the server never sees one);
    the browser carries it onto the login page's own URL instead."""
    here = "https://atlas.example:8443/_dashboard/login.html?next=x#usage"
    cases = {
        "/_dashboard/config.html": "/_dashboard/config.html#usage",
        "/_dashboard/overview.html?case=CASE-A": "/_dashboard/overview.html?case=CASE-A#usage",
        "/_dashboard/config.html#runs": "/_dashboard/config.html#runs",
        "https://evil.example/": "overview.html",
        "": "overview.html",
    }
    assert _run_safe_next(here, cases) == cases


def test_an_unauthenticated_deep_link_keeps_its_query():
    from dashboard.app import _path_and_query

    class _Url:
        path, query = "/_dashboard/overview.html", "case=CASE-A"

    class _Req:
        url = _Url()

    assert _path_and_query(_Req()) == "/_dashboard/overview.html?case=CASE-A"
    assert re.search(r"next=%2F_dashboard%2Foverview\.html%3Fcase%3DCASE-A",
                     __import__("dashboard.app", fromlist=["x"])._redirect_to_login(
                         _path_and_query(_Req())).headers["location"])
