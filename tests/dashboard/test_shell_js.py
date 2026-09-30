"""The shell's network policy and poll loop, checked by running
dashboard/assets/shell.js under node with a stub DOM (shell_harness.js)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_shell_network_policy_and_polling():
    proc = subprocess.run(
        ["node", str(ROOT / "tests/dashboard/shell_harness.js"),
         str(ROOT / "dashboard/assets/shell.js")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "shell harness: ok" in proc.stdout
