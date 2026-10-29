"""The Brief page's own script under node (brief_harness.js): saves carry the
version the editor started from, a conflict shows both texts, and a poll
reloads only an editor with nothing unsaved."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_brief_page_saves_with_its_version_and_shows_a_conflict():
    proc = subprocess.run(["node", str(ROOT / "tests/dashboard/brief_harness.js"),
                           str(ROOT / "dashboard/case_md.html")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "brief harness: ok" in proc.stdout
