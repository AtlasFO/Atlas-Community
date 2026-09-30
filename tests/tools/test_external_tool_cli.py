"""The installed external tools have the command lines Atlas runs. A pinned
release that renames a subcommand or drops a flag would otherwise fail every
call while the tool still looks installed. install.sh runs this module after
every install (pytest -m install_smoke); where a tool is not installed its
check is skipped."""
from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.install_smoke


def test_hayabusa_has_the_scan_command_atlas_runs():
    import tools.hayabusa as hb
    status = hb.status()
    if not status.get("installed"):
        pytest.skip("Hayabusa is not installed")
    assert status["healthy"], status["problems"]


def test_chainsaw_hunt_takes_the_flags_atlas_passes():
    chainsaw = shutil.which("chainsaw")
    if not chainsaw:
        pytest.skip("chainsaw is not installed")
    proc = subprocess.run([chainsaw, "--no-banner", "hunt", "--help"],
                          capture_output=True, text=True, timeout=60)
    usage = proc.stdout + proc.stderr
    for flag in ("--load-unknown", "--skip-errors", "--jsonl", "--output", "--mapping"):
        assert flag in usage, flag
