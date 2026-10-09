"""Render a final-report Markdown file as standalone HTML.

Uses the `markdown` package when available; otherwise falls back to a
minimal escaped <pre> so `atlas report --format html` always works.

A report quotes evidence, and evidence can carry HTML: a phishing page, a
script from a web log, a link a document pointed at. The file is opened in a
browser, so nothing in it may be active. The parser runs without its raw-HTML
handlers, so markup in the text shows as text; the one tag taken from the
text is the anchor the report writers put before a finding (``<a id="...">``
and nothing else), and an HTML comment is dropped. A link keeps its target
only for a web or mail address or a place without a scheme, an image only
for a place without a scheme. The page also carries a Content-Security-Policy
under which nothing runs and nothing loads, should anything get past that.
"""
from __future__ import annotations

import html
import re

_STYLE = """
body { max-width: 60rem; margin: 2rem auto; padding: 0 1rem;
       font: 16px/1.6 system-ui, sans-serif; color: #1a1a1a; }
h1, h2, h3 { line-height: 1.25; }
code, pre { font-family: ui-monospace, monospace; background: #f4f4f4; }
pre { padding: .75rem; overflow-x: auto; }
table { border-collapse: collapse; }
th, td { border: 1px solid #ccc; padding: .3rem .6rem; }
@media (prefers-color-scheme: dark) {
  body { background: #111; color: #ddd; }
  code, pre { background: #1e1e1e; }
  th, td { border-color: #444; }
}
"""

# The page's own <style> and the tables' alignment attributes are all it needs.
# base-uri and form-action do not fall back to default-src, so they are named.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'")

# The anchor the report writers place before a finding (core.report_assemble,
# core.report_projection), the same narrow form the dashboard preview turns
# back into an anchor; and an HTML comment, such as the writers' section
# markers.
_ANCHOR = r'<a id="([A-Za-z0-9._-]+)"></a>'
_COMMENT = r"(?s)<!--.*?-->"

# Schemes a link may keep. An image keeps none: fetched from an address, it
# would tell whoever chose that address, and evidence can choose it, that the
# report was opened and from where; the PDF export never loads one either.
_SCHEMES = {"href": frozenset({"http", "https", "mailto"}), "src": frozenset()}
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*(?=:)")
# A link or image tag of the finished page, and its targets. With raw HTML off
# every tag is the serializer's own, which writes each value in double quotes
# and escapes any quote or angle bracket inside it.
_TARGET_TAG = re.compile(r"<(?:a|img)\b[^<>]*>")
_TARGET_ATTR = re.compile(r' (href|src)="([^"]*)"')


def _target_allowed(url: str, schemes: frozenset[str]) -> bool:
    """Whether a link or image may keep ``url``, read the way a browser reads
    it: character references decoded, ASCII whitespace and control characters
    (which a browser skips) left out. A target that starts with two slashes
    names another host whatever the scheme, so it is never kept."""
    plain = re.sub(r"[\x00-\x20]", "", html.unescape(url))
    if re.match(r"[/\\]{2}", plain):
        return False
    scheme = _SCHEME.match(plain)
    return scheme is None or scheme.group(0).lower() in schemes


def _inert_tag(tag: re.Match) -> str:
    """The tag without the targets it may not keep."""
    def keep(attr: re.Match) -> str:
        name, url = attr.groups()
        return attr.group(0) if _target_allowed(url, _SCHEMES[name]) else ""
    return _TARGET_ATTR.sub(keep, tag.group(0))


def _parser(markdown):
    """A Markdown parser that emits only markup it writes itself."""
    import xml.etree.ElementTree as etree

    from markdown.inlinepatterns import InlineProcessor
    from markdown.postprocessors import Postprocessor

    class Anchor(InlineProcessor):
        def handleMatch(self, m, data):
            return etree.Element("a", {"id": m.group(1)}), m.start(0), m.end(0)

    class Comment(InlineProcessor):
        def handleMatch(self, m, data):
            return "", m.start(0), m.end(0)

    class Targets(Postprocessor):
        # Judges the finished text, after the parser has put back what it
        # held aside (an entity in a target is a placeholder until then, and
        # an ampersand another): what is judged is what a browser reads.
        def run(self, text):
            return _TARGET_TAG.sub(_inert_tag, text)

    md = markdown.Markdown(extensions=["tables", "fenced_code"])
    md.preprocessors.deregister("html_block")
    md.inlinePatterns.deregister("html")
    md.inlinePatterns.register(Anchor(_ANCHOR, md), "report_anchor", 90)
    md.inlinePatterns.register(Comment(_COMMENT, md), "html_comment", 89)
    md.postprocessors.register(Targets(md), "inert_targets", 10)
    return md


def render_html(md_text: str, title: str = "Atlas report") -> str:
    try:
        import markdown
    except ImportError:
        body = f"<pre>{html.escape(md_text)}</pre>"
    else:
        body = _parser(markdown).convert(md_text)
    return (f"<!doctype html>\n<html><head><meta charset='utf-8'>"
            f"<meta http-equiv='Content-Security-Policy' content=\"{_CSP}\">"
            f"<title>{html.escape(title)}</title>"
            f"<style>{_STYLE}</style></head>\n"
            f"<body>{body}</body></html>\n")
