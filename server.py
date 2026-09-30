"""
Atlas MCP Server — SIFT Workstation forensic tool gateway.
Exposes all SIFT tools as typed MCP tools for the Atlas agent.
"""
import os
import sys
from dotenv import load_dotenv
load_dotenv()  # must run before tool modules read os.environ

from core.secrets import load_into_environ as _load_secrets
_filled = _load_secrets()
if _filled:
    print(f"[Atlas] Loaded from GNOME Keyring: {', '.join(_filled)}", file=sys.stderr)

from fastmcp import FastMCP
from core.middleware import NarrationMiddleware

from tools.imaging import mcp as imaging_mcp
from tools.volatility import mcp as vol_mcp
from tools.sleuthkit import mcp as tsk_mcp
from tools.ewf import mcp as ewf_mcp
from tools.eztools import mcp as ez_mcp
from tools.plaso import mcp as plaso_mcp
from tools.hayabusa import mcp as hayabusa_mcp
from tools.yara_tools import mcp as yara_mcp
from tools.hashing import mcp as hash_mcp
from tools.strings_tools import mcp as strings_mcp
from tools.carving import mcp as carving_mcp
from tools.network import mcp as network_mcp
from tools.enrichment import mcp as enrichment_mcp
from tools.bintriage import mcp as bintriage_mcp
from tools.deobfuscation import mcp as deob_mcp
from tools.crypto import mcp as crypto_mcp
from tools.misc import mcp as misc_mcp
from tools.reasoning import mcp as reason_mcp
from tools.dair import mcp as dair_mcp
from tools.accuracy import mcp as accuracy_mcp
from tools.correlate import mcp as correlate_mcp
from tools.coverage import mcp as coverage_mcp
import tools.coverage_audit  # noqa: F401 — registers audit_* on coverage
from tools.antiforensics import mcp as antiforensics_mcp
from tools.attribution import mcp as attribution_mcp
from tools.live import mcp as live_mcp
from tools.velo import mcp as velo_mcp
from tools.monitor import mcp as monitor_mcp
from tools.respond import mcp as respond_mcp
from tools.jobs import mcp as jobs_mcp
from tools.tabular import mcp as tabular_mcp
from tools.search_tools import mcp as search_mcp
from tools.export_tools import mcp as export_mcp
from tools.claim_tools import mcp as claim_mcp
from tools.brain_tools import mcp as brain_mcp
from tools.archives import mcp as archives_mcp
from tools.steg import mcp as steg_mcp
from tools.ese import mcp as ese_mcp
from tools.evt import mcp as evt_mcp

mcp = FastMCP(
    "atlas-sift",
    instructions=(
        "Atlas SIFT MCP Server — exposes SANS SIFT Workstation forensic tools as typed MCP tools. "
        "All tools are read-only with respect to evidence. "
        "Output paths must be within analysis/, exports/, or reports/ directories. "
        "Timestamps are always UTC."
    ),
)
mcp.add_middleware(NarrationMiddleware())

from core.plugins import register_plugins
register_plugins(mcp)

mcp.mount(imaging_mcp, namespace="img")
mcp.mount(vol_mcp, namespace="vol")
mcp.mount(tsk_mcp, namespace="tsk")
mcp.mount(ewf_mcp, namespace="ewf")
mcp.mount(ez_mcp, namespace="ez")
mcp.mount(plaso_mcp, namespace="plaso")
mcp.mount(hayabusa_mcp, namespace="hayabusa")
mcp.mount(yara_mcp, namespace="yara")
mcp.mount(hash_mcp, namespace="hash")
mcp.mount(strings_mcp, namespace="strings")
mcp.mount(carving_mcp, namespace="carve")
mcp.mount(network_mcp, namespace="net")
mcp.mount(enrichment_mcp, namespace="enrich")
mcp.mount(bintriage_mcp, namespace="bin")
mcp.mount(deob_mcp, namespace="deob")
mcp.mount(crypto_mcp, namespace="crypto")
mcp.mount(misc_mcp, namespace="misc")
mcp.mount(reason_mcp, namespace="reason")
mcp.mount(dair_mcp, namespace="dair")
mcp.mount(accuracy_mcp, namespace="accuracy")
mcp.mount(correlate_mcp, namespace="correlate")
mcp.mount(coverage_mcp, namespace="coverage")
mcp.mount(antiforensics_mcp, namespace="af")
mcp.mount(attribution_mcp, namespace="attribution")
mcp.mount(live_mcp, namespace="live")
mcp.mount(velo_mcp, namespace="velo")
mcp.mount(monitor_mcp, namespace="monitor")
mcp.mount(respond_mcp, namespace="respond")
mcp.mount(jobs_mcp, namespace="job")
# Addons under plugins/ (e.g. timeline_builder) are discovered and mounted
# separately by register_plugins() — see core/plugins.py.
mcp.mount(tabular_mcp, namespace="table")
mcp.mount(search_mcp, namespace="search")
mcp.mount(export_mcp, namespace="export")
mcp.mount(claim_mcp, namespace="claim")
mcp.mount(brain_mcp, namespace="brain")
mcp.mount(archives_mcp, namespace="archive")
mcp.mount(steg_mcp, namespace="steg")
mcp.mount(ese_mcp, namespace="ese")
mcp.mount(evt_mcp, namespace="evt")


if __name__ == "__main__":
    # The trace dashboard runs as a separate long-lived process (`atlas-dashboard`).
    # We no longer autostart a per-case copy here — it caused port collisions and
    # died whenever MCP restarted. start_execution_log surfaces the standalone
    # URL via ~/.cache/atlas/dashboard.url instead.
    mcp.run(transport="stdio")
