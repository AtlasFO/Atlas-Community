"""The Process chart's zoom and pan arithmetic, run under node
(dashboard/assets/timeview.js through timeview_harness.js)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_view_zooms_pans_and_follows_within_the_run():
    proc = subprocess.run(
        ["node", str(ROOT / "tests/dashboard/timeview_harness.js"),
         str(ROOT / "dashboard/assets/timeview.js")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "timeview harness: ok" in proc.stdout
