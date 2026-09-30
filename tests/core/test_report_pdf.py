"""Rendering a report's Markdown as PDF.

The failure this file mostly guards is not layout but character coverage: the
layout engine's built-in fonts are Latin-1, Atlas prose uses em dashes
throughout, and evidence carries whatever a filesystem carried. A renderer that
raises on any of those turns a finished investigation into no deliverable.
"""
import pytest

from core import report_pdf

pytestmark = pytest.mark.skipif(not report_pdf.available(),
                                reason="fpdf2 not installed")

SAMPLE = """# CASE-1 Investigation Report

## Summary

A **compromise** was confirmed on `HOST-1` — the account `user` authenticated
from `10.0.0.1`.

## Findings

| ID | Host | Confidence |
|----|------|-----------|
| F01 | HOST-1 | CONFIRMED |

1. First step
2. Second step

```
raw tool output
```

> A quoted remark.

- *emphasis* and **strength**
"""


def _is_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")


class TestRender:
    def test_produces_a_well_formed_document(self):
        data = report_pdf.render_pdf(SAMPLE, title="t", case_id="CASE-1")
        assert _is_pdf(data)
        assert len(data) > 1000

    def test_every_markdown_construct_survives(self):
        """Headings, a table, both list kinds, a code block, a quotation and
        emphasis in one document: each is a separate path through the layout
        engine, and emphasis in particular needs a font style that the package
        shipping the regular face does not install."""
        assert _is_pdf(report_pdf.render_pdf(SAMPLE))

    def test_an_empty_report_still_renders(self):
        assert _is_pdf(report_pdf.render_pdf(""))

    def test_the_case_id_reaches_the_document(self):
        data = report_pdf.render_pdf(SAMPLE, title="t", case_id="CASE-1")
        assert b"CASE-1" in data


class TestCharacterCoverage:
    @pytest.mark.parametrize("text", [
        "An em dash — in prose",
        "German: Änderung an Größe und Prüfsumme, Benutzer Müller",
        "Cyrillic filename otchet.docx and отчет.docx",
        "Arrows and marks: A → B · C \u2713",
        "Greek: αβγ δεζ",
    ])
    def test_text_outside_latin1_does_not_raise(self, text):
        """The built-in fonts stop at Latin-1. Each of these can appear in a
        report or in evidence, and each aborts an export that has no font
        registration and fallback pass."""
        assert _is_pdf(report_pdf.render_pdf(text))

    def test_a_script_no_font_draws_is_marked_not_dropped(self):
        """A reader comparing the PDF against the Markdown has to be able to
        see that something was there, and to learn that the PDF is not
        byte-faithful."""
        assert _is_pdf(report_pdf.render_pdf("File 一二三.xlsx was copied."))
        # The document's own text is font-subset encoded, so the claim is
        # checked where it is decided rather than by searching the bytes.
        out, n = report_pdf._substitute("File 一二三.xlsx",
                                        set(range(0x100)) | {0xFFFD})
        assert n == 3
        assert report_pdf.REPLACEMENT * 3 in out

    def test_substitution_counts_what_it_replaced(self):
        covered = set(range(0x100)) | {0xFFFD}
        out, n = report_pdf._substitute("ab一c", covered)
        assert n == 1
        assert out == f"ab{report_pdf.REPLACEMENT}c"

    def test_the_marker_is_one_the_fonts_can_draw(self):
        """The preferred marker is outside Latin-1, so on the built-in fonts
        it would itself be the character that fails."""
        latin1 = set(range(0x100))
        assert report_pdf.marker_for(latin1) == report_pdf.REPLACEMENT_ASCII
        out, n = report_pdf._substitute("a一b", latin1)
        assert (out, n) == ("a?b", 1)

    def test_substitution_keeps_whitespace_it_cannot_measure(self):
        out, n = report_pdf._substitute("a\nb\tc", set())
        assert (out, n) == ("a\nb\tc", 0)


class TestFontFallback:
    def test_a_machine_with_no_unicode_font_still_renders(self, monkeypatch):
        """Falling back to the built-in fonts is the whole point: a host
        without the font package produces a plainer PDF, not an error."""
        monkeypatch.setattr(report_pdf, "_FONT_DIRS", ())
        monkeypatch.setenv("ATLAS_PDF_FONT_DIR", "/nonexistent")
        assert report_pdf._font_dir() is None
        assert _is_pdf(report_pdf.render_pdf("An em dash — survives"))

    def test_the_font_directory_can_be_pointed_elsewhere(self, monkeypatch,
                                                        tmp_path):
        monkeypatch.setattr(report_pdf, "_FONT_DIRS", ())
        monkeypatch.setenv("ATLAS_PDF_FONT_DIR", str(tmp_path))
        assert report_pdf._font_dir() is None
        (tmp_path / "DejaVuSans.ttf").write_bytes(b"not really a font")
        assert report_pdf._font_dir() == tmp_path

    def test_an_unreadable_font_file_does_not_break_the_export(
            self, monkeypatch, tmp_path):
        """A truncated or wrong-format file at the expected path is a real
        host condition; it must cost fidelity, not the document."""
        monkeypatch.setattr(report_pdf, "_FONT_DIRS", ())
        monkeypatch.setenv("ATLAS_PDF_FONT_DIR", str(tmp_path))
        (tmp_path / "DejaVuSans.ttf").write_bytes(b"not really a font")
        assert _is_pdf(report_pdf.render_pdf("plain text"))


class TestMissingPackage:
    def test_the_error_names_the_fix(self, monkeypatch):
        """An operator meeting this has to be told what to install, not handed
        an ImportError from three frames down."""
        import builtins
        real = builtins.__import__

        def _no_fpdf(name, *a, **kw):
            if name == "fpdf" or name.startswith("fpdf."):
                raise ImportError("no fpdf")
            return real(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", _no_fpdf)
        with pytest.raises(RuntimeError, match="fpdf2"):
            report_pdf.render_pdf("x")


# The shape every report writer produces: a contents list and a findings table
# that link to a named anchor in front of each finding, and table cells whose
# text inline markup splits into several runs.
LINKED_REPORT = """# CASE-A Report

## Contents

- [F-001 · Service installed](#f-001)

| ID | Summary |
|----|---------|
| [F-001](#f-001) | `svc.exe` installed by *jane.doe* on **CORP-DC01** |

<a id="f-001"></a>

### F-001 · Service installed

See [the vendor advisory](https://example.com/advisory).
"""


class TestLayoutSubset:
    def test_a_report_with_anchors_and_rich_cells_renders(self):
        """fpdf2 reads every <a> as a link and raises on an anchor without
        href, and it refuses a table cell whose text arrives in more than one
        run. Every report type carries both."""
        assert _is_pdf(report_pdf.render_pdf(LINKED_REPORT))

    def test_a_named_anchor_alone_renders(self):
        assert _is_pdf(report_pdf.render_pdf(
            '<a id="f-001"></a>\n\n### F-001 · Service installed\n'))

    def test_anchors_and_in_document_links_keep_their_text(self):
        out = report_pdf._layout_subset(
            '<p><a id="f-1"></a><a href="#f-1">F-1</a> and '
            '<a href="https://example.com/x">ref</a><a name="n"/></p>')
        assert out == '<p>F-1 and <a href="https://example.com/x">ref</a></p>'

    def test_a_cell_becomes_one_run_of_its_text(self):
        out = report_pdf._layout_subset(
            '<table><tr><td><code>a.exe</code> ran <em>twice</em><br>late'
            '</td><th><a href="#f-2">F-2</a></th></tr></table>')
        assert '>a.exe ran twice late</td>' in out
        assert '>F-2</th>' in out
        assert "<code>" not in out and "<a " not in out

    def test_markup_outside_cells_passes_through(self):
        html = ('<h2>T</h2><p>x <strong>y</strong> <code>&lt;z&gt;</code>'
                '</p><pre><code>a &amp; b</code></pre><hr>')
        assert report_pdf._layout_subset(html) == html

    def test_tag_shaped_text_in_a_cell_does_not_raise(self):
        """Model text such as a path with a <placeholder> reaches the HTML as
        an unknown tag; inside a cell it is a second run, which fpdf2
        refuses."""
        md = "| Path |\n|---|\n| \\\\\\\\<share>\\\\docs and more |\n"
        assert _is_pdf(report_pdf.render_pdf(md))


class TestTableLayout:
    TABLE = ("| ID | Statement | Confidence |\n|----|-----------|:----------:|\n"
             "| F-001 | " + "A service was installed and started by an "
             "account that had not logged on before " * 2 + "| LIKELY |\n")

    def _first_row_widths(self, html):
        import re
        head = html.split("</tr>", 1)[0]
        # Written as tenths, in whole numbers.
        return [int(w) / 10 for w in re.findall(r'width="([0-9]+)"', head)]

    def test_a_sentence_column_gets_the_room_a_short_value_does_not_need(self):
        """fpdf2 splits a table into equal columns, which wraps a finding's
        statement into a narrow strip beside an ID column of five
        characters."""
        from core.report_pdf import _html_from_markdown, _layout_subset
        widths = self._first_row_widths(
            _layout_subset(_html_from_markdown(self.TABLE), 90.0))
        assert len(widths) == 3
        ident, statement, confidence = widths
        assert statement > 3 * ident and statement > 3 * confidence
        # The narrow columns keep their longest word on one line.
        assert ident >= len("F-001") and confidence >= len("Confidence")

    def test_cells_are_left_aligned_unless_the_markdown_aligned_them(self):
        from core.report_pdf import _html_from_markdown, _layout_subset
        html = _layout_subset(_html_from_markdown(self.TABLE), 90.0)
        assert html.count('align="left"') == 4
        assert html.count('align="center"') == 2

    def test_weights_follow_the_content_when_the_line_has_room(self):
        assert report_pdf._column_weights([["ab", "abcdef"]], 90.0) == [
            5.0, 9.0]

    def test_widths_are_whole_numbers(self):
        """fpdf2 before 2.8.6 reads a cell's width with int(), where a
        decimal width fails every table."""
        import re

        from core.report_pdf import _html_from_markdown, _layout_subset
        widths = re.findall(r'width="([^"]*)"',
                            _layout_subset(_html_from_markdown(self.TABLE)))
        assert widths and all(w.isdigit() and int(w) > 0 for w in widths)

    def test_a_long_word_cannot_claim_the_line(self):
        """Uncapped, a hash's length would be its column's minimum and would
        leave the column beside it three characters wide."""
        weights = report_pdf._column_weights([["x" * 200, "word " * 30]],
                                             90.0)
        assert weights[1] / sum(weights) > 0.25

    def test_a_ragged_table_gets_no_widths(self):
        """fpdf2 raises on a row with more cells than widths were given."""
        out = report_pdf._layout_subset(
            "<table><tr><td>a</td></tr><tr><td>b</td><td>c</td></tr></table>")
        assert "width=" not in out
        assert _is_pdf(report_pdf.render_pdf(
            "<table><tr><td>a</td></tr><tr><td>b</td><td>c</td></tr>"
            "</table>"))

    def test_a_code_only_cell_keeps_its_face(self):
        out = report_pdf._layout_subset(
            "<table><tr><td><code>svc.exe</code></td><td>x <code>y</code>"
            "</td></tr></table>")
        assert "><code>svc.exe</code></td>" in out
        assert ">x y</td>" in out


# ── What the rewrite keeps, and what it never lets through ─────────────────
_SEPARATE = {"td", "th", "tr", "table", "p", "li", "ul", "ol", "h1", "h2",
             "h3", "h4", "h5", "h6", "pre", "blockquote", "hr", "br", "div",
             "dt", "dd"}


def _text_of(html):
    """The text an HTML reader sees, blocks and cells kept apart."""
    import re
    from html.parser import HTMLParser

    class _Text(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []

        def handle_data(self, data):
            self.parts.append(data)

        def handle_starttag(self, tag, attrs):
            if tag in _SEPARATE:
                self.parts.append(" ")

        handle_startendtag = handle_starttag

        def handle_endtag(self, tag):
            if tag in _SEPARATE:
                self.parts.append(" ")

    reader = _Text()
    reader.feed(html)
    reader.close()
    return re.sub(r"\s+", " ", "".join(reader.parts)).strip()


class TestNothingIsLost:
    @pytest.mark.parametrize("html", [
        # a cell left open, then more of the report
        "<table><tr><td>a<td>b</tr></table><h2>After</h2><p>tail</p>",
        # a tag-shaped word inside a cell, with text after the table
        "<table><tr><td>x <td> y</td><td>z</td></tr></table><h2>After</h2><p>tail</p>",
        "<table><tr><td>x <th> y</td></tr></table><h2>After</h2><p>tail</p>",
        # a table inside a cell
        ("<table><tr><td>outer<table><tr><td>inner</td></tr></table>tail</td>"
         "<td>x</td></tr></table><p>end</p>"),
        # end tags without their start
        "<p>a</td>b</p><p>c</table>d</p><p>e</ul>f</p><p>g</ol>h</p>",
        # blocks inside a cell
        ("<table><tr><td><p>Admin</p><p>Guest</p></td><td><ul><li>a</li>"
         "<li>b</li></ul></td></tr></table>"),
        # script text, which a browser would not show but a reader of the
        # Markdown does
        "<p>a <script>b && c</script> d</p>",
        # a table never closed
        "<p>before</p><table><tr><td>a</td><td>b</td>",
    ])
    def test_the_text_survives_the_rewrite(self, html):
        """A stray or missing tag must cost formatting, not the text: a cell
        state left open would swallow the table's end and everything after
        it, without an error."""
        assert _text_of(report_pdf._layout_subset(html)) == _text_of(html)

    def test_a_report_keeps_its_structure(self):
        import collections
        import re
        html = report_pdf._html_from_markdown(SAMPLE + LINKED_REPORT)
        out = report_pdf._layout_subset(html)
        tags = lambda h: collections.Counter(
            re.findall(r"<(h[1-6]|p|li|pre|blockquote|table|tr|td|th)\b", h))
        assert tags(out) == tags(html)
        assert _text_of(out) == _text_of(html)


def _fallbacks(caplog):
    """The renderer's own fallback records; fpdf2 logs warnings of its own."""
    return [r for r in caplog.records if r.name == "core.report_pdf"]


class TestNeverRaises:
    """Each input makes fpdf2 raise when it reaches it unchanged. Raw HTML
    goes to the layout as it is; Markdown goes through the Markdown step
    first."""

    @pytest.mark.parametrize("source, raw", [
        ('<p><a id="f-1"></a>anchor</p>', True),
        ("<table><tr><td>a<td>b</tr></table><h2>After</h2>", True),
        ("<p>a</td>b</table>c</ul>d</ol>e</p>", True),
        ("<p>a <td>b</td> <tr>c</tr> d</p>", True),
        ('<table><tr><td colspan="x" align="middle">a</td></tr></table>', True),
        ('<ul type="xyz"><li>a</li></ul><hr width="abc">', True),
        ('<ol type="a">' + "<li>x</li>" * 30 + "</ol>", True),
        (('<font color="notacolor">x</font><table width="x"><tr><td>a</td>'
          "</tr></table>"), True),
        ('<p><img src="nonexistent.png" alt="a chart"></p>', True),
        ("[five](5)", False),
        ("[script](javascript:alert(1))", False),
        ("| A | B |\n|---|---|\n| x | y <script> z |\n\nafter", False),
    ])
    def test_the_rewrite_alone_is_enough(self, source, raw, monkeypatch,
                                         caplog):
        if raw:
            monkeypatch.setattr(report_pdf, "_html_from_markdown", lambda s: s)
        with caplog.at_level("WARNING", logger="core.report_pdf"):
            assert _is_pdf(report_pdf.render_pdf(source))
        assert not _fallbacks(caplog), "fell back to plain text"

    @pytest.mark.parametrize("source", [
        # a row taller than a page
        "| A | B | C |\n|---|---|---|\n| x | " + "y" * 6000 + " | z |\n",
        # more columns than the line has room for
        "| " + " | ".join(f"H{i}" for i in range(40)) + " |\n|"
        + "---|" * 40 + "\n| " + " | ".join(f"v{i}" for i in range(40))
        + " |\n",
    ])
    def test_what_the_layout_engine_cannot_lay_out_still_renders(self,
                                                                 source):
        """Both are beyond fpdf2 today and fall back to plain text; a later
        fpdf2 may lay them out. Either way a PDF comes back. The fallback
        itself is pinned by the next test."""
        assert _is_pdf(report_pdf.render_pdf(source))

    def test_a_layout_failure_falls_back_and_is_logged(self, monkeypatch,
                                                       caplog):
        import fpdf
        real = fpdf.FPDF.write_html
        calls = []

        def _fail_once(self, *a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise ValueError("layout engine refused")
            return real(self, *a, **kw)

        monkeypatch.setattr(fpdf.FPDF, "write_html", _fail_once)
        with caplog.at_level("WARNING", logger="core.report_pdf"):
            assert _is_pdf(report_pdf.render_pdf(SAMPLE))
        assert len(calls) == 2
        assert any(r.exc_info for r in _fallbacks(caplog))

    @pytest.mark.parametrize("source", [SAMPLE, LINKED_REPORT])
    def test_an_ordinary_report_does_not_fall_back(self, source, caplog):
        """A fallback that ordinary reports reach would hide a broken
        rewrite; this keeps it the last resort."""
        with caplog.at_level("WARNING", logger="core.report_pdf"):
            report_pdf.render_pdf(source)
        assert not _fallbacks(caplog)


class TestLinksAndImages:
    def test_an_image_is_never_loaded_and_its_alt_text_stays(self):
        """fpdf2 fetches a remote image while laying out the page, from the
        machine that exports, and evidence can decide the address."""
        html = report_pdf._html_from_markdown(
            "See ![the console](http://127.0.0.1:9/x.png) here.")
        out = report_pdf._layout_subset(html)
        assert "<img" not in out
        assert "[image: the console]" in out

    @pytest.mark.parametrize("target", ["5", "#f-001", "report.md",
                                        "javascript:alert(1)"])
    def test_a_link_a_pdf_cannot_follow_keeps_only_its_text(self, target):
        out = report_pdf._layout_subset(
            report_pdf._html_from_markdown(f"[the text]({target})"))
        assert "<a" not in out and "the text" in out

    def test_a_web_link_stays_a_link(self):
        out = report_pdf._layout_subset(
            '<p><a href="https://example.com/a?b=1&amp;c=2" title="t">x</a></p>')
        assert out == '<p><a href="https://example.com/a?b=1&amp;c=2">x</a></p>'


class TestWellFormed:
    def test_a_self_closed_tag_leaves_nothing_open(self):
        """fpdf2 keeps superscript, preformatted and heading state until the
        end tag, so a self-closed tag written as a bare start tag would
        carry that state through the rest of the report."""
        for tag in ("sup", "sub", "pre", "b", "code", "h2", "blockquote", "u"):
            out = report_pdf._layout_subset(f"<p>a <{tag}/> b</p>")
            assert out.count(f"<{tag}>") == out.count(f"</{tag}>"), out

    def test_a_stray_code_tag_ends_with_its_cell(self):
        out = report_pdf._layout_subset(
            "<table><tr><td>x <code> y</td><td>zzzz</td></tr>"
            "<tr><td>row2</td><td>w</td></tr></table>")
        assert "<code>zzzz</code>" not in out and "<code>row2</code>" not in out

    def test_a_cell_keeps_its_no_break_space(self):
        """Only the whitespace HTML collapses is collapsed; a no-break space
        is text, as it is outside a table."""
        out = report_pdf._layout_subset(
            "<table><tr><td>Program\u00a0Files \n x</td></tr></table>")
        assert "Program\u00a0Files x" in out

    def test_lists_are_written_balanced(self):
        html = "<ul><li>a</li><li>b<ol><li>c</li></ol></li></ul><ol><li>d</li></ol>"
        assert report_pdf._layout_subset(html) == html

    def test_a_list_closes_the_lists_opened_inside_it(self):
        assert report_pdf._layout_subset("<ul><ol><li>x</li></ul><p>y</p>") == (
            "<ul><ol><li>x</li></ol></ul><p>y</p>")

    def test_an_ordered_list_keeps_its_start(self):
        html = '<ol start="4"><li>a</li></ol>'
        assert report_pdf._layout_subset(html) == html

    def test_a_stray_cell_tag_keeps_the_structure_after_the_table(self):
        html = ("<table><tr><td>x <td> y</td><td>z</td></tr></table>"
                "<h2>After</h2><p>tail</p>")
        out = report_pdf._layout_subset(html)
        assert out.count("<table>") == out.count("</table>") == 1
        assert "<h2>After</h2>" in out and "<p>tail</p>" in out


class TestRenderWiring:
    SMALL = "# T\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n- a\n- b\n"

    def test_the_table_is_sized_for_the_page_in_the_fonts_own_metrics(
            self, monkeypatch):
        seen = {}
        real = report_pdf._layout_subset

        def spy(html, capacity=90.0, measure=len):
            seen["capacity"], seen["measure"] = capacity, measure
            return real(html, capacity, measure)

        monkeypatch.setattr(report_pdf, "_layout_subset", spy)
        report_pdf.render_pdf(self.SMALL)
        assert 150 < seen["capacity"] < 200          # A4 less the margins, in mm
        assert seen["measure"] is not len and 0 < seen["measure"]("nnn") < 20

    def test_the_plain_text_fallback_says_so_in_the_document(self, monkeypatch):
        import fpdf
        real_html, real_cell = fpdf.FPDF.write_html, fpdf.FPDF.multi_cell
        failed, notes = [], []

        def fail_once(self, *a, **kw):
            if not failed:
                failed.append(1)
                raise ValueError("layout engine refused")
            return real_html(self, *a, **kw)

        def spy_cell(self, w, h=None, text="", *a, **kw):
            notes.append(text)
            return real_cell(self, w, h, text, *a, **kw)

        monkeypatch.setattr(fpdf.FPDF, "write_html", fail_once)
        monkeypatch.setattr(fpdf.FPDF, "multi_cell", spy_cell)
        report_pdf.render_pdf(self.SMALL)
        assert any("Markdown text" in n and "record" in n for n in notes)

    def test_an_fpdf2_without_textstyle_names_the_floor(self, monkeypatch):
        import sys
        import types
        monkeypatch.setitem(sys.modules, "fpdf.fonts",
                            types.ModuleType("fpdf.fonts"))   # as in 2.7.x
        assert not report_pdf.available()
        with pytest.raises(RuntimeError, match="2.8.1"):
            report_pdf.render_pdf("x")

    def test_a_long_table_spanning_pages_renders(self):
        rows = "".join(f"| F-{i:03d} | {'word ' * 40}| LIKELY |\n"
                       for i in range(60))
        assert _is_pdf(report_pdf.render_pdf(
            "| ID | Statement | Confidence |\n|---|---|---|\n" + rows))
