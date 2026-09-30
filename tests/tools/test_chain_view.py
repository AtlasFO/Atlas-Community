"""The investigation-chain blueprint view was folded into the Process view:
its block-type toggles became the type chips, its wires became the "rests
on" chips and the pulse highlight, its phase strip became the chart's
phase bands. Nothing may still point at the retired page."""
import os

DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "dashboard",
)


def test_chain_view_is_retired():
    assert not os.path.exists(os.path.join(DASHBOARD_DIR, "chain_view.html"))


def test_nothing_links_to_the_retired_page():
    for name in os.listdir(DASHBOARD_DIR):
        if not name.endswith(".html"):
            continue
        body = open(os.path.join(DASHBOARD_DIR, name), encoding="utf-8").read()
        assert "chain_view.html" not in body, f"{name} still links to chain_view.html"
    shell = open(os.path.join(DASHBOARD_DIR, "assets", "shell.js"), encoding="utf-8").read()
    assert "chain_view" not in shell


def test_process_view_carries_the_chain_views_functions():
    body = open(os.path.join(DASHBOARD_DIR, "trace_viewer.html"), encoding="utf-8").read()
    # type toggles, the run-in-time chart with phase bands, the brush, and
    # the per-entry detail sheet
    for token in ('class="type-filter"', 'id="chart"', "renderChart", "setupBrush",
                  'id="phase-select"', 'id="detail"', "pulseLinked"):
        assert token in body, f"{token} missing from the Process view"
