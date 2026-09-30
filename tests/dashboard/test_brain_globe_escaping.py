"""The Brain Earth page builds its tooltip, detail card and legend as HTML
strings from note data. Note titles, types, tags and paths come from notes
that runs write from case evidence, so each value must be escaped where it
enters markup, or a crafted file name in a title runs script in the analyst's
dashboard session."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "dashboard" / "brain_globe.html"
_FIELDS = r"(?:label|type|cluster|created|updated|tags|flags|path)"


def test_no_note_field_enters_html_unescaped():
    html = PAGE.read_text(encoding="utf-8")
    raw = re.findall(rf"\+\s*d\.{_FIELDS}\b|date:\s*d\.{_FIELDS}\b|\+\s*ty\b", html)
    assert raw == [], raw


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_escape_helper_neutralises_markup():
    html = PAGE.read_text(encoding="utf-8")
    helper = re.search(r"const esc = .*?\);\n", html, re.S).group(0)
    script = helper + "process.stdout.write(esc(`<img src=x onerror=\"a('1')\">&`));"
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    assert out == "&lt;img src=x onerror=&quot;a(&#39;1&#39;)&quot;&gt;&amp;"
