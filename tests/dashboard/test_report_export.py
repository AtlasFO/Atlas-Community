"""The route behind the Report tab's format picker.

Markdown is served as it stands; HTML and PDF are rendered from that same file
on request, so what a reader downloads matches the report on disk. The name
comes from the caller and is looked up in the listing the tab is built from,
which is why the traversal cases and the rerun-snapshot layouts are here.
"""
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from core import report_pdf
from dashboard import read_models
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

    def test_a_byte_that_is_not_utf8_downloads_and_renders(self, ctx, tmp_path):
        """Markdown is the file's bytes; the rendered copy shows the odd byte
        as a replacement character instead of failing the download."""
        raw = b"# DEMO-1 Investigation Report\n\nByte \xe9 from a Latin-1 tool.\n"
        (tmp_path / "DEMO-1" / "reports" / "DEMO-1_report.md").write_bytes(raw)
        assert _call(ctx, format="md").body == raw
        assert _call(ctx, format="html").status_code == 200

    def test_a_name_outside_latin1_gets_the_rfc6266_header(self, ctx, tmp_path):
        """Header values are Latin-1 on the wire. A host named in another
        script still downloads, its name carried by filename*=."""
        name = "host_ДС-01_report.md"
        (tmp_path / "DEMO-1" / "reports" / name).write_text(
            SAMPLE, encoding="utf-8")
        r = _call(ctx, name=name, format="md")
        assert r.status_code == 200
        assert r.headers["content-disposition"] == \
            "attachment; filename*=utf-8''" + quote(name)


CRLF_REPORT = b"# CASE-A Investigation Report\r\n\r\nA finding on CORP-DC01.\r\n"


@pytest.fixture
def rerun_ctx(tmp_path):
    """CASE-A after a persisting `atlas rerun`: the first report pack frozen
    in reports/initial_report/, reports/latest pointing at it, and reports/
    itself holding only the change history (core.report_snapshots)."""
    reports = tmp_path / "CASE-A" / "reports"
    snapshot = reports / "initial_report"
    snapshot.mkdir(parents=True)
    (snapshot / "CASE-A_investigation_report.md").write_bytes(CRLF_REPORT)
    (snapshot / "claim_snapshot.json").write_text("{}", encoding="utf-8")
    (reports / "latest").symlink_to("initial_report")
    (reports / "diff_report.md").write_text(
        "# Investigation Change History\n", encoding="utf-8")
    return SimpleNamespace(cases_root=str(tmp_path))


def _export(ctx, name, fmt="md"):
    return _get_report_export(ctx, None,
                              {"case": "CASE-A", "name": name, "format": fmt})


def _listed(ctx):
    return read_models.list_report_files(f"{ctx.cases_root}/CASE-A")


class TestRerunSnapshot:
    @pytest.mark.parametrize("fmt", ["md", "html", "pdf"])
    def test_a_report_only_in_the_snapshot_downloads_in_every_format(
            self, rerun_ctx, fmt):
        if fmt == "pdf" and not report_pdf.available():
            pytest.skip("fpdf2 not installed")
        r = _export(rerun_ctx, "CASE-A_investigation_report.md", fmt)
        assert r.status_code == 200

    def test_the_markdown_download_is_the_snapshot_file_byte_for_byte(
            self, rerun_ctx):
        r = _export(rerun_ctx, "CASE-A_investigation_report.md")
        assert r.body == CRLF_REPORT

    def test_reports_holds_the_copy_that_is_listed_and_served(
            self, rerun_ctx, tmp_path):
        """A rerun that changed no investigation state regenerates its report
        in reports/; the snapshot keeps the older copy of the same name. The
        tab lists one file under that name and the download is that file."""
        (tmp_path / "CASE-A" / "reports" /
         "CASE-A_investigation_report.md").write_bytes(b"# Regenerated\n")
        paths = [f["path"] for f in _listed(rerun_ctx)
                 if f["name"] == "CASE-A_investigation_report.md"]
        assert paths == ["/CASE-A/reports/CASE-A_investigation_report.md"]
        r = _export(rerun_ctx, "CASE-A_investigation_report.md")
        assert r.body == b"# Regenerated\n"

    def test_a_latest_link_out_of_reports_is_not_followed(self, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "CASE-B_report.md").write_text("# CASE-B", encoding="utf-8")
        reports = tmp_path / "CASE-A" / "reports"
        reports.mkdir(parents=True)
        (reports / "CASE-A_report.md").write_text("# CASE-A", encoding="utf-8")
        (reports / "latest").symlink_to(elsewhere)
        ctx = SimpleNamespace(cases_root=str(tmp_path))
        assert [f["name"] for f in _listed(ctx)] == ["CASE-A_report.md"]
        assert _export(ctx, "CASE-B_report.md").status_code == 404

    def test_a_latest_link_loop_leaves_reports_as_the_source(self, tmp_path):
        reports = tmp_path / "CASE-A" / "reports"
        reports.mkdir(parents=True)
        (reports / "CASE-A_report.md").write_text("# CASE-A", encoding="utf-8")
        (reports / "latest").symlink_to("latest")
        ctx = SimpleNamespace(cases_root=str(tmp_path))
        assert [f["name"] for f in _listed(ctx)] == ["CASE-A_report.md"]
        assert _export(ctx, "CASE-A_report.md").status_code == 200


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

    def test_a_trace_export_is_refused(self, ctx, tmp_path):
        """A process trace written as Markdown is not a report: the tab does
        not list it, so this route does not serve it either."""
        (tmp_path / "DEMO-1" / "reports" / "DEMO-1_trace.md").write_text(
            "# trace", encoding="utf-8")
        assert _call(ctx, name="DEMO-1_trace.md",
                     format="md").status_code == 404

    def test_a_symlink_out_of_reports_is_refused(self, ctx, tmp_path):
        outside = tmp_path / "outside.md"
        outside.write_text("# not this case's report", encoding="utf-8")
        (tmp_path / "DEMO-1" / "reports" / "leak_report.md").symlink_to(outside)
        assert _call(ctx, name="leak_report.md", format="md").status_code == 404
