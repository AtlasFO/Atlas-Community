"""The route behind the Report tab's format picker.

Markdown is served as it stands; HTML and PDF are rendered from that same file
on request, so what a reader downloads matches the report on disk. The name
comes from the caller, which is why the traversal cases below are here.
"""
from types import SimpleNamespace

import pytest

from core import report_pdf
from dashboard.app import _get_report_export

SAMPLE = """# DEMO-1 Investigation Report

A finding on `HOST-1` — recorded at CONFIRMED.
"""


@pytest.fixture
def ctx(tmp_path):
    reports = tmp_path / "DEMO-1" / "reports"
    reports.mkdir(parents=True)
    (reports / "DEMO-1_report.md").write_text(SAMPLE, encoding="utf-8")
    return SimpleNamespace(cases_root=str(tmp_path))


def _call(ctx, **q):
    q.setdefault("case", "DEMO-1")
    q.setdefault("name", "DEMO-1_report.md")
    return _get_report_export(ctx, None, q)


class TestFormats:
    def test_markdown_is_the_file_itself(self, ctx):
        r = _call(ctx, format="md")
        assert r.status_code == 200
        assert r.body.decode("utf-8") == SAMPLE
        assert "DEMO-1_report.md" in r.headers["content-disposition"]

    def test_html_is_rendered(self, ctx):
        r = _call(ctx, format="html")
        assert r.status_code == 200
        assert r.media_type == "text/html"
        assert b"<h1" in r.body
        assert "DEMO-1_report.html" in r.headers["content-disposition"]

    @pytest.mark.skipif(not report_pdf.available(),
                        reason="fpdf2 not installed")
    def test_pdf_is_a_real_document(self, ctx):
        r = _call(ctx, format="pdf")
        assert r.status_code == 200
        assert r.media_type == "application/pdf"
        assert r.body.startswith(b"%PDF-")
        assert r.body.rstrip().endswith(b"%%EOF")
        assert "DEMO-1_report.pdf" in r.headers["content-disposition"]

    def test_an_unknown_format_is_refused(self, ctx):
        assert _call(ctx, format="docx").status_code == 400


class TestGuards:
    @pytest.mark.parametrize("name", [
        "../../../etc/passwd",
        "../../outside.md",
        "/etc/passwd",
        "",
    ])
    def test_a_name_that_leaves_the_reports_directory_is_refused(
            self, ctx, name):
        """The name is a path component from the caller. Only files inside
        this case's own reports directory may be served."""
        assert _call(ctx, name=name, format="md").status_code == 404

    def test_only_markdown_sources_are_served(self, ctx, tmp_path):
        """The route renders from a report's Markdown; pointing it at anything
        else would turn it into a general file reader for the case."""
        (tmp_path / "DEMO-1" / "reports" / "notes.txt").write_text(
            "not a report", encoding="utf-8")
        assert _call(ctx, name="notes.txt", format="md").status_code == 404

    def test_an_unknown_case_is_refused(self, ctx):
        assert _call(ctx, case="NO-SUCH", format="md").status_code == 404

    def test_a_missing_report_is_refused(self, ctx):
        assert _call(ctx, name="absent_report.md",
                     format="md").status_code == 404
