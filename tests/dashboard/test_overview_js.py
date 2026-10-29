"""The Overview's own script under node (overview_harness.js): one Start in
the run options dialog starts one run after any number of in-page case
switches, a dismissed dialog starts none, and the run strip says how a run
this dashboard started ended."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_run_dialog_starts_once_and_the_strip_names_the_end():
    proc = subprocess.run(["node", str(ROOT / "tests/dashboard/overview_harness.js"),
                           str(ROOT / "dashboard/overview.html")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "overview harness: ok" in proc.stdout
