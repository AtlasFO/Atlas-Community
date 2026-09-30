"""Every dashboard page's inline script must parse.

A page whose script does not parse loads with no handlers at all: no data
request, dead buttons, and nothing in the server log to show for it, because
the browser never calls back. The failure is invisible server-side, so it is
caught here, the same way test_shell_js.py checks the shared script.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGES = sorted((ROOT / "dashboard").glob("*.html"))
_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("page", PAGES, ids=[p.name for p in PAGES])
def test_inline_scripts_parse(page, tmp_path):
    scripts = _INLINE.findall(page.read_text(encoding="utf-8"))
    for i, source in enumerate(scripts):
        path = tmp_path / f"{page.stem}_{i}.js"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run(["node", "--check", str(path)],
                                capture_output=True, text=True)
        assert result.returncode == 0, f"{page.name} script {i}: {result.stderr.strip()}"
