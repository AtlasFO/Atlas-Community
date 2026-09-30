"""Every CSS custom property a dashboard page uses without a fallback is
defined. An undefined `var(--x)` is invalid at computed-value time, so the
declaration silently falls back to the inherited or initial value and the
intended size or colour never renders."""
import re
from pathlib import Path

DASH = Path(__file__).resolve().parents[2] / "dashboard"
_DEFINED = re.compile(r"(--[\w-]+)\s*:")
_USED = re.compile(r"var\((--[\w-]+)\s*\)")


def test_every_token_a_page_uses_is_defined():
    shared = set(_DEFINED.findall((DASH / "assets" / "atlas.css").read_text(encoding="utf-8")))
    for page in [*DASH.glob("*.html"), *(DASH / "assets").glob("*.js")]:
        if page.name == "brain_globe.html":   # own palette: DESIGN.md "Out of system"
            continue
        text = page.read_text(encoding="utf-8")
        local = set(_DEFINED.findall(text))
        for name in _USED.findall(text):
            assert name in shared | local, f"{page.name}: {name} is not defined"
