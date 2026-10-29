"""Which case a dashboard page opens on, checked by running
dashboard/assets/shell.js under node with a stub DOM (case_open_harness.js):
a ?case= the case list does not hold opens no case, never another one."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_an_unknown_case_in_the_link_opens_no_case():
    proc = subprocess.run(
        ["node", str(ROOT / "tests/dashboard/case_open_harness.js"), str(ROOT / "dashboard/assets/shell.js")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "case harness: ok" in proc.stdout
