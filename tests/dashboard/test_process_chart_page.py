"""The Process page carries the chart's fold and zoom hooks, the Case Findings
form is shared with the IoCs page, and the tabs formerly named Evidence Board
and IOCs are Case Findings and IoCs everywhere a user reads them."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard"


def test_process_page_folds_and_zooms_its_chart():
    body = (DASHBOARD / "trace_viewer.html").read_text(encoding="utf-8")
    for token in ('id="chart-fold"', 'id="chart-range"', "assets/timeview.js",
                  "setupChartView", "TimeView.zoom", "TimeView.pan", "TimeView.follow"):
        assert token in body, f"{token} missing from the Process page"


def test_toolbars_are_two_rows_with_labelled_groups():
    for page in ("trace_viewer.html", "claim_view.html", "iocs.html"):
        body = (DASHBOARD / page).read_text(encoding="utf-8")
        assert 'class="tools lead"' in body, page
        assert 'class="tools filters"' in body, page
        assert 'class="tg-l"' in body, page


def test_the_tab_is_called_case_findings():
    for path in list(DASHBOARD.glob("*.html")) + list((DASHBOARD / "assets").glob("*.js")):
        assert "Evidence Board" not in path.read_text(encoding="utf-8"), path.name
    shell = (DASHBOARD / "assets" / "shell.js").read_text(encoding="utf-8")
    assert "label: 'Case Findings'" in shell


def test_iocs_page_shares_the_board_and_list_and_is_called_iocs():
    body = (DASHBOARD / "iocs.html").read_text(encoding="utf-8")
    for token in ("<title>Atlas · IoCs</title>", 'data-layout="board"', 'data-layout="list"',
                  'data-group="host"', 'id="sheet"', "case/iocs", 'id="copy-shown"'):
        assert token in body, f"{token} missing from the IoCs page"
    shell = (DASHBOARD / "assets" / "shell.js").read_text(encoding="utf-8")
    assert "label: 'IoCs'" in shell and "label: 'IOCs'" not in shell
    i18n = (DASHBOARD / "assets" / "i18n.js").read_text(encoding="utf-8")
    assert i18n.count("'nav.iocs': 'IoCs'") == 2
    # The lanes, columns, cards and rows are drawn once, in the shared sheet.
    css = (DASHBOARD / "assets" / "atlas.css").read_text(encoding="utf-8")
    for rule in (".lane {", ".cols {", ".bc {", ".rows {", ".rows-h, .lrow {"):
        assert rule in css, f"{rule} missing from atlas.css"
    for page in ("claim_view.html", "iocs.html"):
        page_css = (DASHBOARD / page).read_text(encoding="utf-8").split("</style>")[0]
        assert ".lane {" not in page_css and ".bc {" not in page_css, page
