"""The HTML rendering of a report is inert.

A report quotes evidence, and evidence can carry HTML. The rendered file is
opened in a browser (a download from the dashboard, `atlas report --format
html`, an assembled .html), so markup from the text must show as text, a link
may only lead to a web or mail address or a place in the document, and the
page must run nothing and load nothing. Ordinary report Markdown renders as
the stock parser renders it. All content below is invented.
"""
import re
import sys
from html.parser import HTMLParser

import pytest

from agent.report import render_html

markdown = pytest.importorskip("markdown")


def _body(md: str) -> str:
    return render_html(md).split("<body>", 1)[1].rsplit("</body>", 1)[0]


def _tags(md: str) -> list[str]:
    """The markup the page carries; escaped text (&lt;...&gt;) is not markup."""
    return re.findall(r"<[^>]*>", _body(md))


def _stock(md: str) -> str:
    return markdown.markdown(md, extensions=["tables", "fenced_code"])


def _targets(page: str) -> list[tuple[str, str]]:
    """Every href and src of the page, decoded as a browser decodes them."""
    found: list[tuple[str, str]] = []

    class Collect(HTMLParser):
        def handle_starttag(self, tag, attrs):
            found.extend((k, v or "") for k, v in attrs if k in ("href", "src"))

    Collect(convert_charrefs=True).feed(page)
    return found


RAW_HTML = [
    "<script>alert(1)</script>",
    "Seen in the page: <img src=x onerror=alert(1)> here.",
    "<svg onload=alert(1)></svg>",
    "<style>body { background: url(javascript:alert(1)) }</style>",
    '<iframe src="https://203.0.113.9/"></iframe>',
    '<div onclick="alert(1)">\nblock\n</div>',
    '<a href="javascript:alert(1)">link</a>',
    '<form action="https://203.0.113.9/"><input name="pw"></form>',
]
REFUSED_LINKS = [
    "[a](javascript:alert(1))",
    "[a](JaVaScRiPt:alert(1))",
    "[a](jav&#x61;script:alert(1))",
    "[a](&#106;avascript:alert(1))",
    "[a](javascript&colon;alert(1))",
    "[a](java&Tab;script:alert(1))",
    "[a](<java\tscript:alert(1)>)",
    "[a](<javascript:alert(1)>)",
    "[a]( javascript:alert(1))",
    "[a][1]\n\n[1]: javascript:alert(1)",
    "[a](vbscript:msgbox(1))",
    "[a](data:text/html;base64,PHNjcmlwdD4=)",
    "[a](file:///etc/passwd)",
    "[a](ms-msdt:/id%20PCWDiagnostic)",
    "[a](search-ms:query=report)",
    "[a](//203.0.113.9/share)",
    "[a](\\\\\\\\203.0.113.9\\\\share)",
]
NESTED_LINKS = [
    "[*e* [a](/&Tab;/203.0.113.9/share)](#d)",
    "[`c` [a](\\&bsol;203.0.113.9\\share)](#d)",
    "[*e* [a](&sol;&sol;203.0.113.9/share)](#d)",
    "[*e* [a](/&#47;203.0.113.9/share)](#d)",
    "[*e* [a](/&NewLine;/203.0.113.9/share)](#d)",
    "[*e* [a](/&#9;/203.0.113.9/share)](#d)",
    "[*e* [a](java&Tab;script:alert(1)//203.0.113.9)](#d)",
    "- [x [a](/&Tab;/203.0.113.9/share)](#d)\n    - a sub-item",
]
REFUSED_IMAGES = [
    "![a](javascript:alert(1))",
    "![a](https://203.0.113.9/pixel.png)",
    "![a](//203.0.113.9/pixel.png)",
    "![a](data:image/svg+xml;base64,PHN2Zz4=)",
]


class TestMarkupFromTheTextIsText:
    @pytest.mark.parametrize("md", RAW_HTML)
    def test_raw_html_is_escaped(self, md):
        tags = _tags(md)
        assert all(t in ("<p>", "</p>") for t in tags), tags
        assert "&lt;" in _body(md)

    def test_an_event_handler_never_reaches_a_tag(self):
        md = ('<img src=x onerror=alert(1)> <a id="f-001" onclick="alert(1)">'
              '</a> <body onload=alert(1)>\n')
        assert not any(re.search(r"\son\w+\s*=", t) for t in _tags(md))

    def test_a_comment_is_dropped_even_one_that_ends_early(self):
        """`--!>` ends a comment in a browser; nothing of it is emitted."""
        body = _body("<!-- --!> <script>alert(1)</script> -->\n")
        assert "script" not in body
        assert _body("<!-- section:exec_summary status:current -->\n") \
            == "<p></p>"

    def test_the_writers_anchor_is_kept_and_nothing_else_of_its_kind(self):
        assert _tags('<a id="f-001"></a>\n') == ["<p>", '<a id="f-001">',
                                                "</a>", "</p>"]
        assert '<a id="f-1"' not in _body('<a id="f-1" title="x"></a>\n')


class TestTargets:
    @pytest.mark.parametrize("md", REFUSED_LINKS)
    def test_a_link_that_is_not_a_web_or_mail_address_loses_its_target(
            self, md):
        assert "<a>a</a>" in _body(md + "\n")

    @pytest.mark.parametrize("md", NESTED_LINKS)
    def test_a_link_inside_link_text_is_judged_as_the_browser_reads_it(
            self, md):
        """The parser reads an inner link in a later pass, when an entity in
        its target is still a placeholder; only the finished text shows the
        target a browser follows."""
        assert "203.0.113.9" not in _body(md + "\n")

    @pytest.mark.parametrize("md", REFUSED_IMAGES)
    def test_an_image_never_keeps_an_address(self, md):
        assert _tags(md + "\n") == ["<p>", '<img alt="a" />', "</p>"]

    @pytest.mark.parametrize(
        "md", REFUSED_LINKS + NESTED_LINKS + REFUSED_IMAGES + RAW_HTML)
    def test_every_target_left_is_one_a_browser_reads_as_allowed(self, md):
        """Read back the way a browser reads the page: references decoded,
        tab and newline removed, C0 controls and spaces trimmed."""
        for attr, value in _targets(render_html(md + "\n")):
            url = re.sub(r"[\t\n\r]", "", value).strip("\x00- ")
            assert not re.match(r"[/\\]{2}", url), (md, url)
            scheme = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", url)
            allowed = {"http", "https", "mailto"} if attr == "href" else set()
            assert scheme is None or scheme.group(1).lower() in allowed, \
                (md, url)

    @pytest.mark.parametrize("md, href", [
        ("[advisory](https://example.com/a?b=1&c=2)",
         "https://example.com/a?b=1&amp;c=2"),
        ("[plain](http://example.com/)", "http://example.com/"),
        ("[mail](mailto:jane.doe@example.com)", "mailto:jane.doe@example.com"),
        ("[4. Detailed Findings](#4-detailed-findings)", "#4-detailed-findings"),
        ("[timeline](analysis/master_timeline.tsv)",
         "analysis/master_timeline.tsv"),
    ])
    def test_web_mail_and_in_document_links_keep_their_target(self, md, href):
        assert f'href="{href}"' in _body(md + "\n")

    def test_autolinks_still_link(self):
        body = _body("<https://example.com/advisory> <jane.doe@example.com>\n")
        assert '<a href="https://example.com/advisory">' in body
        assert body.count("<a href=") == 2


ORDINARY = """# CASE-A Investigation Report

## 1. Executive Summary

Data left **CORP-DC01** via `rclone` to 203.0.113.7, see
[4. Detailed Findings](#4-detailed-findings) and the
[technique](https://attack.mitre.org/techniques/T1567/).

| Host | Address | Note |
|:-----|--------:|------|
| CORP-DC01 | 10.0.0.5 | *primary* |
| CORP-WS02 | 10.0.0.23 | |

<a id="f-001"></a>
### F-001 Exfiltration over HTTPS

- the archive was staged first
- then uploaded

1. first
2. second

```powershell
Get-Process | Where-Object { $_.Name -eq "rclone" }  # <script>quoted</script>
```

    indented code <b>quoted</b>

> Reported by jane.doe@example.com: "done"

Sources: <https://example.com/advisory>, <jane.doe@example.com>,
[timeline](analysis/master_timeline.tsv). &copy; 2031 &amp; a < b, x > y.

---
"""


class TestOrdinaryReports:
    def test_render_exactly_as_the_stock_parser(self):
        assert _body(ORDINARY) == _stock(ORDINARY)

    def test_the_page_runs_and_loads_nothing(self):
        page = render_html(ORDINARY, title="CASE-A report")
        assert ("<meta http-equiv='Content-Security-Policy' "
                "content=\"default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'\">") in page
        assert "<title>CASE-A report</title>" in page

    def test_without_the_parser_the_text_is_escaped(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "markdown", None)
        page = render_html("<script>alert(1)</script>")
        assert "<pre>&lt;script&gt;alert(1)&lt;/script&gt;</pre>" in page
        assert "Content-Security-Policy" in page
