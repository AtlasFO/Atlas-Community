"""Render a report's Markdown as PDF.

The pipeline: the Markdown a run already writes
goes through the same Markdown parser ``atlas report --format html`` uses, and
the resulting semantic HTML is laid out by fpdf2. Nothing new renders the
report itself, so the PDF says what the Markdown says.

**Why fpdf2.** It is a pure-Python wheel whose own dependencies are wheels too,
so a PDF export costs no system libraries. That mattered more than fidelity
here: the alternative with the best CSS support needs pango, cairo and
gdk-pixbuf through the package manager, and ``install.sh`` already carries
three OS tiers plus a SIFT path, each of which a new system dependency can
break on a host nobody tested. A headless browser is heavier again for the same
job. The price is that fpdf2 understands a subset of HTML and ignores CSS,
which is why this module feeds it plain semantic markup and sets the type
itself rather than handing it the styled web page.

**Fonts are the part that actually breaks.** fpdf2's built-in fonts cover
Latin-1 only, and Atlas prose is full of em dashes, so a naive export fails on
almost every real report before any evidence text is reached. A DejaVu face is
registered when one is on the machine, which covers Latin, Greek, Cyrillic and
the punctuation reports use. Evidence can still carry anything — a filename in
a script no installed font draws — so characters no registered font covers are
replaced with a marker and the document states how many were replaced. An
export that renders and says what it could not draw beats one that refuses, and
the Markdown remains the artefact of record either way.

**The subset is enforced, not assumed.** Report Markdown carries raw HTML the
layout engine cannot take: a named anchor in front of each finding, so a
contents list or findings table can jump to it, table cells whose text is split
by inline markup, and whatever tag-shaped text a model quoted from evidence.
fpdf2 raises on all of them. ``_layout_subset`` rewrites the HTML into the
part fpdf2 lays out before layout, and a report that still cannot be laid out
is set as plain text, so what a report contains decides how plainly it prints,
never whether it prints.
"""
from __future__ import annotations

import logging
import os
import re
from html import escape as _escape
from html.parser import HTMLParser
from pathlib import Path

# Where a Unicode face is looked for, in order. ATLAS_PDF_FONT_DIR overrides
# the search for a host that keeps fonts somewhere else. The regular face has
# to exist for the family to be registered at all; the others are optional and
# fpdf2 synthesises what is missing.
_FONT_DIRS = (
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu",
    "/usr/share/fonts/TTF",
    "/usr/local/share/fonts/dejavu",
    "/Library/Fonts",
)
_FAMILY = "DejaVu"
_MONO_FAMILY = "DejaVuMono"

# Every style fpdf2 may be asked for, each with the files that can serve it in
# order of preference. The fallbacks are not decoration: the package that ships
# the regular and bold faces on Debian and Ubuntu (fonts-dejavu-core) does not
# ship the oblique ones, which live in a separate package. A report containing
# a single emphasised word would otherwise fail to export on a stock install,
# because fpdf2 raises on a style that was never registered. Serving italic
# from the upright file loses the slant and keeps the document.
_FACES = {
    "": ("DejaVuSans.ttf",),
    "B": ("DejaVuSans-Bold.ttf", "DejaVuSans.ttf"),
    "I": ("DejaVuSans-Oblique.ttf", "DejaVuSans.ttf"),
    "BI": ("DejaVuSans-BoldOblique.ttf", "DejaVuSans-Bold.ttf",
           "DejaVuSans.ttf"),
}
_MONO_FACES = {
    "": ("DejaVuSansMono.ttf",),
    "B": ("DejaVuSansMono-Bold.ttf", "DejaVuSansMono.ttf"),
    "I": ("DejaVuSansMono-Oblique.ttf", "DejaVuSansMono.ttf"),
    "BI": ("DejaVuSansMono-BoldOblique.ttf", "DejaVuSansMono-Bold.ttf",
           "DejaVuSansMono.ttf"),
}
_REGULAR = _FACES[""][0]

# What replaces a character no registered font can draw. A visible marker
# rather than a silent drop: a reader comparing the PDF against the Markdown
# must be able to see that something was there. The preferred marker is itself
# outside Latin-1, so on a machine reduced to the built-in fonts it would be
# the thing that fails; the plain question mark is the fallback for exactly
# that case.
REPLACEMENT = "\ufffd"
REPLACEMENT_ASCII = "?"

_MISSING_FPDF = (
    "PDF export needs fpdf2 2.8.1 or newer, as requirements.txt names it. "
    "Install it into Atlas's venv: .venv/bin/pip install -U 'fpdf2>=2.8.1'"
)

_LOG = logging.getLogger(__name__)


def _font_dir() -> Path | None:
    """The first directory holding the regular face, or None."""
    override = (os.environ.get("ATLAS_PDF_FONT_DIR") or "").strip()
    candidates = ([override] if override else []) + list(_FONT_DIRS)
    for d in candidates:
        if d and (Path(d) / _REGULAR).is_file():
            return Path(d)
    return None


def _codepoints(path: Path) -> set[int]:
    """Every code point the font at ``path`` can draw.

    Read from the font's own character map with fontTools, which fpdf2 already
    depends on. Asking the file beats discovering the answer from an exception
    per character.
    """
    try:
        from fontTools.ttLib import TTFont
        font = TTFont(str(path), fontNumber=0, lazy=True)
        try:
            out: set[int] = set()
            for table in font["cmap"].tables:
                out.update(table.cmap.keys())
            return out
        finally:
            font.close()
    except Exception:
        # An unreadable font is not a reason to refuse the export; treat it as
        # Latin-1 and let the replacement pass handle the rest.
        return set(range(0x00, 0x100))


def _register_fonts(pdf) -> tuple[str, str, set[int]]:
    """Register a Unicode family if one is on the machine.

    Returns the body family, the monospace family, and the set of code points
    that can be drawn. With the built-in fonts that set is Latin-1, which is
    the whole of their coverage and the reason the replacement pass exists.
    """
    builtin = ("helvetica", "courier", set(range(0x00, 0x100)))
    directory = _font_dir()
    if directory is None:
        return builtin
    covered: set[int] = set()
    try:
        for family, faces in ((_FAMILY, _FACES), (_MONO_FAMILY, _MONO_FACES)):
            for style, filenames in faces.items():
                path = next((directory / f for f in filenames
                             if (directory / f).is_file()), None)
                if path is None:
                    # The regular face decided the directory, so this can only
                    # be a monospace family that is not installed; its family
                    # then goes unregistered and the caller falls back.
                    continue
                pdf.add_font(family, style, str(path))
                if style == "" and family == _FAMILY:
                    covered |= _codepoints(path)
    except Exception:
        # A font that will not register leaves the built-ins, which always
        # work. An export that looks plainer beats an export that fails.
        return builtin
    if not covered:
        return builtin
    # A monospace family that never registered would raise the moment a code
    # block appeared; fall back to the body family, which is registered.
    mono = _MONO_FAMILY
    if not (directory / _MONO_FACES[""][0]).is_file():
        mono = _FAMILY
    return _FAMILY, mono, covered


def marker_for(covered: set[int]) -> str:
    """The replacement marker these fonts can actually draw."""
    return (REPLACEMENT if ord(REPLACEMENT) in covered
            else REPLACEMENT_ASCII)


def _substitute(text: str, covered: set[int]) -> tuple[str, int]:
    """``text`` with undrawable characters replaced, and how many were."""
    if not covered:
        return text, 0
    marker = marker_for(covered)
    out = []
    replaced = 0
    for ch in text:
        if ch in "\n\r\t" or ord(ch) in covered:
            out.append(ch)
        else:
            out.append(marker)
            replaced += 1
    return "".join(out), replaced


def _html_from_markdown(md_text: str) -> str:
    """Semantic HTML for the layout engine, or escaped text if the parser is
    absent — the same fallback ``agent.report.render_html`` makes, for the
    same reason: a report that renders plainly beats no report."""
    try:
        import markdown
        return markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    except ImportError:
        import html as _html
        return f"<pre>{_html.escape(md_text)}</pre>"


# The tags fpdf2's HTML reader lays out, written without their attributes. A
# tag outside the set loses its markup and keeps its text. This is the layout
# engine's capability, a public and closed list, not a view of the content.
_KEEP = frozenset({
    "b", "blockquote", "code", "dd", "del", "dt", "em", "h1", "h2", "h3", "h4",
    "h5", "h6", "i", "li", "p", "pre", "s", "strong", "sub", "sup", "u",
})
# Tags whose edges separate words once markup is flattened into text, as a
# browser's line breaks would.
_SEPARATES = frozenset({
    "blockquote", "br", "dd", "div", "dt", "h1", "h2", "h3", "h4", "h5", "h6",
    "hr", "li", "ol", "p", "pre", "table", "td", "th", "tr", "ul",
})
# The characters HTML collapses. A no-break or other Unicode space is text, as
# it is outside a table.
_HTML_SPACE_CHARS = " \t\n\r\f"
_HTML_SPACE = re.compile(f"[{_HTML_SPACE_CHARS}]+")
# A link target a PDF can follow. fpdf2 reads an all-digit target as a page
# number and raises when that page does not exist, and a relative or
# in-document target opens nothing from a PDF.
_LINK = re.compile(r"(?i)(?:https?|mailto):")


class _LayoutSubset(HTMLParser):
    """Re-serialises report HTML into the part of HTML fpdf2 lays out.

    fpdf2 raises where a browser carries on: on an anchor without ``href``
    (the writers put ``<a id="...">`` before every finding), on a second run
    of text in a table cell, on an end tag without its start, on an attribute
    value it cannot parse, on an image it cannot fetch. So this parser writes
    only what fpdf2 takes. A tag outside ``_KEEP`` loses its markup and keeps
    its text, attributes are dropped except a link's target and the ones
    computed here, and a list's end tag is written only for a list that is
    open.

    A link keeps its tag only for a web or mail target; an in-document link
    keeps its text, and the outline built from the headings navigates the
    PDF. An image is never loaded: fpdf2 would fetch a remote address while
    laying out the page, from the machine that exports it, and evidence can
    decide what that address is. Its alt text stands in its place.

    A table is read whole and written back as a well-formed grid: one run of
    text per cell, since fpdf2 takes no more; aligned left unless the
    Markdown aligned the column, where fpdf2 would justify; and column widths
    in proportion to what the columns hold (``_column_weights``), where fpdf2
    would split the line evenly. Text between cells joins the cell before it,
    and a table inside a cell joins that cell's text, so a stray or missing
    tag costs formatting, never content.
    """

    def __init__(self, capacity: float = 90.0, measure=len) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._capacity = capacity
        self._measure = measure
        self._links: list[bool] = []   # per open <a>: whether its tag was written
        self._lists: list[str] = []    # the open ul/ol, innermost last
        # The open table as rows of cells, a cell being [tag, align, chunks]
        # and a chunk (text, inside <code>); None outside a table.
        self._rows: list[list[list]] | None = None
        self._cell: list | None = None   # the cell text in the table joins
        self._loose: list = []           # text before the table's first cell
        self._nested = 0                 # tables open inside the open table
        self._code = 0                   # <code> open inside the open table

    # -- text ---------------------------------------------------------------
    def _text(self, text: str) -> None:
        if self._rows is None:
            # The parser hands text over unescaped; escaping it again keeps
            # text that looks like markup from turning into markup.
            self.out.append(_escape(text, quote=False))
        else:
            (self._cell[2] if self._cell else self._loose).append(
                (text, self._code > 0))

    def handle_data(self, data):
        self._text(data)

    # -- tags ---------------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        if tag == "img":
            alt = " ".join((dict(attrs).get("alt") or "").split())
            self._text(f" [image: {alt}] " if alt else " [image] ")
            return
        if self._rows is not None:
            self._table_start(tag, attrs)
            return
        if tag in ("br", "hr"):
            self.out.append(f"<{tag}>")
        elif tag == "table":
            self._rows, self._cell, self._loose = [], None, []
            self._nested = self._code = 0
        elif tag == "a":
            href = (dict(attrs).get("href") or "").strip()
            keep = bool(_LINK.match(href))
            self._links.append(keep)
            if keep:
                self.out.append(f'<a href="{_escape(href)}">')
        elif tag in ("ul", "ol"):
            self._lists.append(tag)
            start = (dict(attrs).get("start") or "").strip()
            self.out.append(f'<ol start="{start}">'
                            if tag == "ol" and start.isdigit() else f"<{tag}>")
        elif tag in _KEEP:
            self.out.append(f"<{tag}>")
        elif tag in _SEPARATES:
            self._text(" ")

    def handle_endtag(self, tag):
        if self._rows is not None:
            self._table_end(tag)
        elif tag == "a":
            if self._links and self._links.pop():
                self.out.append("</a>")
        elif tag in ("ul", "ol") and tag in self._lists:
            # The lists opened inside this one close with it.
            while True:
                inner = self._lists.pop()
                self.out.append(f"</{inner}>")
                if inner == tag:
                    break
        elif tag in _KEEP:
            self.out.append(f"</{tag}>")
        elif tag in _SEPARATES:
            self._text(" ")

    # -- tables -------------------------------------------------------------
    def _table_start(self, tag, attrs):
        if tag == "table":
            self._nested += 1
        elif self._nested:
            pass
        elif tag == "tr":
            self._rows.append([])
        elif tag in ("td", "th"):
            if not self._rows:
                self._rows.append([])
            m = _TEXT_ALIGN.search(dict(attrs).get("style") or "")
            self._code = 0   # a <code> left open ends with its cell
            self._cell = [tag, m.group(1) if m else "left", []]
            self._rows[-1].append(self._cell)
        elif tag == "code":
            self._code += 1
        if tag in _SEPARATES:
            self._text(" ")

    def _table_end(self, tag):
        if tag == "table" and not self._nested:
            self._flush_table()
            return
        if tag == "table":
            self._nested -= 1
        elif tag == "code":
            self._code = max(0, self._code - 1)
        if tag in _SEPARATES:
            self._text(" ")

    def _flush_table(self) -> None:
        rows = [r for r in self._rows if r]
        loose = " ".join("".join(t for t, _ in self._loose).split())
        self._rows, self._cell, self._loose = None, None, []
        if loose:
            self.out.append(f"<p>{_escape(loose, quote=False)}</p>")
        if not rows:
            return
        texts = [[_HTML_SPACE.sub(" ", "".join(t for t, _ in cell[2])).strip(_HTML_SPACE_CHARS)
                  for cell in row] for row in rows]
        # fpdf2 raises on a row with more cells than widths it was given, so
        # widths go only to a table whose rows all match. They are written as
        # whole numbers: fpdf2 before 2.8.6 reads the attribute with int(),
        # and it scales the widths to the line either way.
        weights = (_column_weights(texts, self._capacity, self._measure)
                   if all(len(r) == len(rows[0]) for r in rows) else None)
        self.out.append("<table>")
        for i, (row, row_texts) in enumerate(zip(rows, texts)):
            self.out.append("<tr>")
            for j, ((tag, align, chunks), text) in enumerate(zip(row, row_texts)):
                width = (f' width="{max(1, round(weights[j] * 10))}"'
                         if i == 0 and weights else "")
                body = _escape(text, quote=False)
                # A cell that is all one monospaced run keeps its face; it is
                # still the single run fpdf2 takes.
                runs = [code for t, code in chunks if t.strip()]
                if runs and all(runs):
                    body = f"<code>{body}</code>"
                self.out.append(f'<{tag} align="{align}"{width}>{body}</{tag}>')
            self.out.append("</tr>")
        self.out.append("</table>")

    def close(self):
        super().close()
        if self._rows is not None:
            self._flush_table()


# The Markdown table extension states a column's alignment as inline CSS,
# which fpdf2 does not read; its own attribute is ``align``.
_TEXT_ALIGN = re.compile(r"text-align:\s*(left|right|center)")

# A word longer than this share of the line may wrap inside its cell rather
# than widen its column: a hash or a long path would otherwise claim the
# whole table.
_WORD_SHARE = 0.25
# Room for a cell's padding and a bold heading, as a width of body text, so
# the longest word of a narrow column stays on one line.
_CELL_SLACK = "nnn"


def _column_weights(rows: list[list[str]], capacity: float,
                    measure=len) -> list[float]:
    """Column widths, in proportion, for a table holding ``rows`` of text.

    The automatic layout browsers use: every column gets at least its longest
    word, and the room the line has beyond that goes to the columns in
    proportion to how much more text they hold. ``measure`` gives a text's
    width and ``capacity`` the line's, in the same unit: the PDF passes the
    registered font's metrics in millimetres, and character counts are the
    default.
    """
    ncols = len(rows[0])
    slack = measure(_CELL_SLACK)
    least = [slack] * ncols
    most = [slack] * ncols
    for row in rows:
        for j, text in enumerate(row):
            longest = max((measure(w) for w in text.split()), default=0)
            least[j] = max(least[j],
                           min(longest, capacity * _WORD_SHARE) + slack)
            most[j] = max(most[j], measure(text) + slack)
    if sum(most) <= capacity:
        return [float(m) for m in most]
    spare = capacity - sum(least)
    flex = [m - n for n, m in zip(least, most)]
    if spare <= 0 or not sum(flex):
        return [float(n) for n in least]
    return [n + spare * f / sum(flex) for n, f in zip(least, flex)]


def _layout_subset(html: str, capacity: float = 90.0, measure=len) -> str:
    """``html`` with the constructs fpdf2 cannot lay out rewritten, and its
    tables sized for a line ``capacity`` wide as ``measure`` counts width."""
    parser = _LayoutSubset(capacity, measure)
    parser.feed(html)
    parser.close()
    return "".join(parser.out)


def _require_fpdf() -> None:
    """Raise RuntimeError, naming the fix, unless fpdf2 2.8.1 or newer is
    installed. 2.8.1 is the first release with ``fpdf.fonts.TextStyle``."""
    try:
        import fpdf  # noqa: F401
        from fpdf.fonts import TextStyle  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(_MISSING_FPDF) from exc


def available() -> bool:
    """Whether this machine can produce a PDF at all."""
    try:
        _require_fpdf()
        return True
    except RuntimeError:
        return False


def render_pdf(md_text: str, *, title: str = "Atlas report",
               case_id: str = "") -> bytes:
    """The report Markdown as PDF bytes.

    Raises RuntimeError when fpdf2 is missing or older than 2.8.1, naming the
    fix. Every other failure is handled rather than raised: a font family
    that will not register falls back to the built-in ones, a character
    nothing can draw is replaced and counted, HTML outside fpdf2's subset is
    rewritten into it, and a report the layout engine still cannot lay out (a
    table row taller than a page, say) is logged and set as plain text, with
    a note in the document saying so.
    """
    _require_fpdf()
    try:
        return _render(md_text, title, case_id, plain=False)
    except Exception:  # noqa: BLE001 - the contract in the docstring
        _LOG.warning("PDF layout failed for %s; the report is set as plain text",
                     case_id or title, exc_info=True)
        return _render(md_text, title, case_id, plain=True)


def _render(md_text: str, title: str, case_id: str, *, plain: bool) -> bytes:
    """Lay the report out, with its formatting or, with ``plain``, as the
    Markdown text itself."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    from fpdf.fonts import TextStyle

    heading = (case_id or title or "").strip()

    class _Report(FPDF):
        atlas_body = "helvetica"

        def footer(self):
            # Page numbers matter for a document that gets printed, filed and
            # referred to by page in a handover.
            self.set_y(-15)
            self.set_font(self.atlas_body, "", 8)
            self.set_text_color(110, 110, 110)
            label = f"page {self.page_no()} of {{nb}}"
            self.cell(0, 10, f"{heading}  -  {label}" if heading else label,
                      align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf = _Report(format="A4")
    body_family, mono_family, covered = _register_fonts(pdf)
    pdf.atlas_body = body_family
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(18, 16, 18)
    pdf.set_title(title)
    if case_id:
        pdf.set_subject(case_id)
    pdf.set_creator("Atlas")
    pdf.add_page()
    pdf.set_font(body_family, "", 10.5)

    # Headings in near-black rather than the writer's own dark red, which in a
    # report where red marks a finding reads as a severity it does not carry.
    # Sizes step down enough to show the structure of a long document without
    # the top level dominating a page.
    ink = (26, 26, 26)
    sizes = {"h1": 19, "h2": 15, "h3": 12.5, "h4": 11, "h5": 10.5, "h6": 10.5}
    tag_styles = {
        tag: TextStyle(color=ink, font_style="B", font_size_pt=size,
                       t_margin=(5 if tag in ("h1", "h2") else 3), b_margin=1.5)
        for tag, size in sizes.items()
    }
    # A quotation is the reviewer's voice in these reports; grey sets it apart
    # without claiming the emphasis a colour would.
    tag_styles["blockquote"] = TextStyle(color=(90, 90, 90), font_style="I",
                                         t_margin=2, b_margin=2, l_margin=6)
    # Tool output and paths read as data only in a monospaced face, and the
    # dedicated parameter for it is deprecated in favour of these styles.
    for tag in ("code", "pre"):
        tag_styles[tag] = TextStyle(font_family=mono_family, font_size_pt=9)

    # Table columns are sized in the registered face's own metrics. The text
    # is measured after substitution, since that is the text that is drawn.
    def _measure(text: str) -> float:
        return pdf.get_string_width(_substitute(text, covered)[0])

    if plain:
        # Said first, so a reader knows before the first page why the
        # report looks like its source.
        pdf.set_font(body_family, "", 8)
        pdf.set_text_color(110, 110, 110)
        pdf.multi_cell(0, 4, "The layout engine could not set this report with "
                       "its formatting, so it is shown as its Markdown text. The "
                       "Markdown report is unaffected and remains the record.",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font(body_family, "", 10.5)
    markup = (f"<pre>{_escape(md_text, quote=False)}</pre>" if plain else
              _layout_subset(_html_from_markdown(md_text), pdf.epw, _measure))
    html, replaced = _substitute(markup, covered)
    pdf.write_html(
        html,
        font_family=body_family,
        tag_styles=tag_styles,
        li_prefix_color=(60, 60, 60),
        warn_on_tags_not_matching=False,
    )

    if replaced:
        pdf.ln(6)
        pdf.set_font(body_family, "", 8)
        pdf.set_text_color(110, 110, 110)
        pdf.multi_cell(
            0, 4,
            f"{replaced} character(s) in this report are outside the range the "
            f"available fonts can draw and appear as {marker_for(covered)}. "
            f"The Markdown report is unaffected and remains the record.")

    return bytes(pdf.output())
