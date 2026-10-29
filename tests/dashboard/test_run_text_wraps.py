"""A run's activity is free text of any length (a phase, a count, a long
path). Wherever the dashboard shows it inside a one-line context, it may
fold within itself, so on a phone it never runs past the screen: the
Overview's run strip (its own fact, while the numeric facts stay whole) and
the header chip's hover card (the chip's label stays on one line). The card
hangs from the chip and is narrowed to the room left of it where the header
wraps, so even hidden it never widens the page."""
from __future__ import annotations

import re
from pathlib import Path

DASH = Path(__file__).resolve().parents[2] / "dashboard"


def _rule(css: str, selector: str) -> str:
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert m, selector
    return re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)


def test_the_run_strips_activity_folds_and_the_numeric_facts_do_not():
    page = (DASH / "overview.html").read_text(encoding="utf-8")
    act = _rule(page, ".band-run .rb-facts > .rb-activity")
    assert "white-space: normal" in act and "overflow-wrap: anywhere" in act and "min-width: 0" in act
    assert "white-space: nowrap" in _rule(page, ".band-run .rb-facts > span")


def test_the_activity_cards_text_folds_inside_the_one_line_chip():
    css = (DASH / "assets" / "atlas.css").read_text(encoding="utf-8")
    assert "white-space: nowrap" in _rule(css, ".shell-activity")
    card = _rule(css, ".activity-pop")
    assert "white-space: normal" in card
    # Folding text alone would shrink the card to its minimum width.
    assert "width: max-content" in card and "min-width" in card and "max-width" in card
    # The "This case" pill moves whole, it never splits across lines.
    assert "white-space: nowrap" in _rule(css, ".activity-pop .ap-here")
    assert "overflow-wrap: anywhere" in _rule(css, ".activity-pop .ap-what")


def test_the_card_is_fitted_to_the_room_beside_the_chip():
    js = (DASH / "assets" / "shell.js").read_text(encoding="utf-8")
    fit = js[js.index("function fitPopover()"):js.index("function renderRunningPopover(")]
    assert "getBoundingClientRect().left" in fit and "clientWidth" in fit
    assert "pop.style.maxWidth" in fit and "pop.style.minWidth" in fit
    render = js[js.index("function renderRunningPopover("):js.index("function renderBusy()")]
    assert render.count("fitPopover();") == 2          # the empty card and the list
    assert "addEventListener('resize', fitPopover)" in js
