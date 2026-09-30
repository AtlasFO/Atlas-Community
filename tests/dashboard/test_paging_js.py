"""The paging arithmetic behind the Settings page's run list, run under node
(dashboard/assets/paging.js through paging_harness.js)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_pages_split_groups_clamp_and_keep_the_first_row():
    proc = subprocess.run(
        ["node", str(ROOT / "tests/dashboard/paging_harness.js"),
         str(ROOT / "dashboard/assets/paging.js")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "paging harness: ok" in proc.stdout

