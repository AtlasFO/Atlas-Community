"""The Settings page's wiring: which sections it has, and which of its
controls the page script reads. The page's behaviour was checked by hand in a
browser; no browser runs in this suite, so this pins the structure the script
and other tests rely on."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_settings_page_wires_the_runs_pager():
    """The arithmetic is checked in test_paging_js.py; this pins that the
    page loads it before its own script uses it, and that the pager's
    controls exist, since the script reads each of them without a check."""
    html = (ROOT / "dashboard/config.html").read_text(encoding="utf-8")
    assert html.index('src="assets/paging.js"') < html.index("AtlasPaging.slice")
    for token in ('id="usage-pager"', 'id="usage-pager-nav"', 'id="usage-pager-status"',
                  'id="usage-page-size"', "AtlasPaging.pageList",
                  "AtlasPaging.resized"):
        assert token in html


def _page():
    return (ROOT / "dashboard/config.html").read_text(encoding="utf-8")


def test_every_sidebar_entry_opens_a_section_of_its_own():
    """The address names the section (config.html#usage); a link without a
    section would open the Overview instead, silently."""
    import re
    html = _page()
    tabs = re.findall(r'class="nav-item" href="#([a-z]+)" data-tab="([a-z]+)"', html)
    assert tabs and all(href == tab for href, tab in tabs)
    for _href, tab in tabs:
        assert html.count(f'id="panel-{tab}"') == 1, tab
    sections = re.findall(r'<section class="set-sec" id="panel-([a-z]+)"', html)
    assert sorted(sections) == sorted(tab for _href, tab in tabs)


def test_the_page_asks_in_place_never_in_a_browser_dialog():
    """A confirmation or a new value is asked for beside the button that
    started it; the browser's own dialogs block the page and cannot be
    styled or reached the same way."""
    import re
    script = _page().split('<script src="assets/paging.js"></script>', 1)[1]
    assert not re.findall(r"(?<![\w.])(?:confirm|prompt|alert)\(", script)


def _script():
    return _page().split('<script src="assets/paging.js"></script>', 1)[1]


def test_every_control_the_script_reads_exists():
    """The script reads its controls without checking for them, so a
    renamed id stops the whole page at load."""
    import re
    html, script = _page(), _script()
    ids = set(re.findall(r'id="([^"]+)"', html))
    used = set(re.findall(r"\$\('([a-z0-9-]+)'\)", script))
    assert used and not used - ids
    for prefix in ("usage", "activity"):
        for suffix in ("-pager", "-pager-nav", "-pager-status", "-page-size"):
            assert f'id="{prefix}{suffix}"' in html


def test_the_page_has_one_title():
    import re
    assert len(re.findall(r"<h1\b", _page())) == 1


def test_every_group_that_saves_has_a_line_to_report_on():
    """A group marked data-form says "Unsaved changes" on its message line;
    one without a line would change silently."""
    from html.parser import HTMLParser

    class Groups(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack, self.missing = [], []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            classes = (a.get("class") or "").split()
            if tag == "div" and "set-group" in classes and "data-form" in a:
                self.stack.append([a.get("id") or "(unnamed group)", 0, False])
            elif self.stack:
                self.stack[-1][1] += tag not in ("input", "br", "hr", "img", "use", "symbol")
                if "say" in classes:
                    self.stack[-1][2] = True

        def handle_endtag(self, tag):
            if not self.stack:
                return
            if self.stack[-1][1] == 0 and tag == "div":
                name, _depth, found = self.stack.pop()
                if not found:
                    self.missing.append(name)
            elif tag not in ("input", "br", "hr", "img", "use", "symbol"):
                self.stack[-1][1] -= 1

    groups = Groups()
    groups.feed(_page())
    assert not groups.missing
