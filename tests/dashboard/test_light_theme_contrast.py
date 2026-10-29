"""The light theme's colours that are used as text reach WCAG AA (4.5:1)
against every light surface (bg-0 to bg-3 and the hover surface bg-hl) and
against the tinted pill or button they sit on, on each of those surfaces, and text on a solid status or accent fill (--on-fill)
reaches it against those fills in both themes. Pairs are read from
atlas.css itself, so a new pill or button is checked as it is added; the
dark palette is not part of this claim (DESIGN.md says what is checked)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = (Path(__file__).resolve().parents[2] / "dashboard" / "assets" / "atlas.css").read_text(encoding="utf-8")
AA = 4.5


def _block(selector: str) -> dict[str, str]:
    body = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CSS).group(1)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\b", body))


DARK = _block(":root")
LIGHT = {**DARK, **_block(':root[data-theme="light"]')}


def _rgb(h):
    h = h.lstrip("#")
    return [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]


def _lum(c):
    lin = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a, b):
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _over(rgba, surface):
    r, g, b, a = rgba
    return [a * x + (1 - a) * y for x, y in zip((r / 255, g / 255, b / 255), surface)]


def _tinted_text():
    """(text token, rgba tint) for every rule that sets a token colour on a
    translucent background, hover rules included (they keep the base rule's
    text colour)."""
    rules = re.findall(r"([^{}]+)\{([^{}]*)\}", CSS)
    colour_of = {}
    pairs = []
    for sel, body in rules:
        c = re.search(r"(?<![-\w])color:\s*var\((--[\w-]+)\)", body)
        if c:
            for one in sel.split(","):
                colour_of[one.strip()] = c.group(1)
    for sel, body in rules:
        bg = re.search(r"background:\s*rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)", body)
        if not bg:
            continue
        for one in sel.split(","):
            one = one.strip()
            token = colour_of.get(one) or colour_of.get(one.split(":")[0])
            if token:
                pairs.append((token, tuple(int(x) for x in bg.groups()[:3]) + (float(bg.group(4)),)))
    return pairs


TEXT_TOKENS = ["--fg-0", "--fg-1", "--fg-2", "--ok", "--warn", "--bad", "--partial", "--accent",
               "--neutral", "--conf-confirmed", "--conf-likely", "--conf-suspected", "--conf-unconfirmed"]
SURFACES = ["--bg-0", "--bg-1", "--bg-2", "--bg-3", "--bg-hl"]


@pytest.mark.parametrize("token", TEXT_TOKENS)
def test_light_text_colours_clear_aa_on_every_light_surface(token):
    for surface in SURFACES:
        r = _ratio(_rgb(LIGHT[token]), _rgb(LIGHT[surface]))
        assert r >= AA, f"{token} on {surface}: {r:.2f}"


def test_light_text_colours_clear_aa_on_their_pill_and_button_tints():
    pairs = _tinted_text()
    assert {t for t, _ in pairs} >= {"--ok", "--warn", "--bad", "--accent", "--conf-likely"}
    for token, tint in pairs:
        for surface in SURFACES:
            r = _ratio(_rgb(LIGHT[token]), _over(tint, _rgb(LIGHT[surface])))
            assert r >= AA, f"{token} on rgba{tint} over {surface}: {r:.2f}"


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_text_on_a_solid_fill_clears_aa_in_both_themes(theme):
    pal = DARK if theme == "dark" else LIGHT
    for fill in ["--accent", "--ok", "--bad", "--partial", "--fg-2"]:   # the fills that carry text
        r = _ratio(_rgb(pal["--on-fill"]), _rgb(pal[fill]))
        assert r >= AA, f"{theme}: --on-fill on {fill}: {r:.2f}"


def test_no_fill_carries_a_fixed_text_colour():
    assert not re.search(r"background:\s*var\(--[\w-]+\)[^;}]*;[^}]*color:\s*#", CSS)
