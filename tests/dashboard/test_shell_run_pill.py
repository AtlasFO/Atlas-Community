"""The header's run pill is drawn from two inputs, the cached list of live
runs and the case on screen; a change of either redraws it. Without that,
picking a case would leave "no case" or a stale "working in <case>" until
the next poll."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SHELL = Path(__file__).resolve().parents[2] / "dashboard" / "assets" / "shell.js"


def _body(src: str, header: str) -> str:
    start = src.index(header)
    nxt = re.search(r"\n  (?:async )?function \w+\(", src[start + len(header):])
    return src[start:start + len(header) + (nxt.start() if nxt else len(src))]


def test_picking_a_case_redraws_the_pill_from_the_cached_runs():
    src = SHELL.read_text(encoding="utf-8")
    assert re.search(r"if \(changed\) renderBusy\(\);", _body(src, "function setActiveCase("))
    poll = _body(src, "async function refreshBusy(")
    assert "renderBusy();" in poll and "setWorking(" not in poll
    draw = _body(src, "function renderBusy(")
    assert "S.runningCases" in draw and "S.activeCase" in draw


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_shell_still_parses():
    subprocess.run(["node", "--check", str(SHELL)], check=True)
