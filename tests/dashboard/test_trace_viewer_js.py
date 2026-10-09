"""The Process page reads a trace from a case folder, and a case folder is
case content: markup in any field of any entry stays text, and another JSON
type in any field neither breaks the page nor drops an entry. Checked by
running dashboard/trace_viewer.html's script under node with a stub DOM
(trace_viewer_harness.js), against invented traces."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _harness(*flags):
    return subprocess.run(
        ["node", str(ROOT / "tests/dashboard/trace_viewer_harness.js"),
         str(ROOT / "dashboard/trace_viewer.html"),
         str(ROOT / "dashboard/assets/timeview.js"), *flags],
        capture_output=True, text=True, timeout=300)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_a_hostile_trace_stays_text_and_every_entry_is_listed():
    proc = _harness()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "trace viewer harness: ok" in proc.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_escaping_where_values_are_written_holds_on_its_own():
    """Entries are normalised as they load; the escaping at each place a value
    is written is the second layer, checked with the first taken out."""
    proc = _harness("--sink-only")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "trace viewer harness: ok (sink only)" in proc.stdout
