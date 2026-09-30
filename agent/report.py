"""Render a final-report Markdown file as standalone HTML.

Uses the `markdown` package when available; otherwise falls back to a
minimal escaped <pre> so `atlas report --format html` always works.
"""
from __future__ import annotations

import html

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


def render_html(md_text: str, title: str = "Atlas report") -> str:
    try:
        import markdown
        body = markdown.markdown(md_text,
                                 extensions=["tables", "fenced_code"])
    except ImportError:
        body = f"<pre>{html.escape(md_text)}</pre>"
    return (f"<!doctype html>\n<html><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title>"
            f"<style>{_STYLE}</style></head>\n"
            f"<body>{body}</body></html>\n")
