"""Every registered tool the lexical listing rule names a listing is pinned
here as a listing or as a content reader (core.coverage_ledger
.is_listing_tool, CONTENT_READERS_NAMED_AS_LISTINGS): a new tool whose name
reads like a listing fails this test until someone decides which it is."""
from __future__ import annotations

from core.coverage_ledger import (CONTENT_READERS_NAMED_AS_LISTINGS, _LISTING_TOOL_RE, is_listing_tool,
                                  is_probe_tool, listed_tool_name, reads_content)
from core.work_order import tool_kind

# Names, metadata, catalogs and hex views: no content read.
LISTINGS = {
    "claim_list_recommendations", "img_losetup_list", "img_vshadow_list", "job_list",
    "misc_list_investigation_tasks", "misc_regripper_list_plugins", "monitor_list_watchers",
    "plaso_list_parsers", "respond_list_actions", "strings_file_identify", "strings_file_identify_directory",
    "strings_hexdump", "tsk_fls", "tsk_ils", "tsk_index_find", "velo_list_clients",
}


def test_every_listing_named_tool_is_decided():
    from tools.tool_capabilities import registered_tool_schemas
    named = {listed_tool_name(e[0]) for e in registered_tool_schemas()}
    by_rule = {n for n in named if _LISTING_TOOL_RE.search(n) and is_probe_tool(n)}
    assert by_rule == LISTINGS | CONTENT_READERS_NAMED_AS_LISTINGS, sorted(by_rule ^ (LISTINGS | CONTENT_READERS_NAMED_AS_LISTINGS))


def test_the_content_readers_read_and_close_read_items():
    for name in CONTENT_READERS_NAMED_AS_LISTINGS:
        assert reads_content(name) and not is_listing_tool(name) and tool_kind(name) == "read", name
    for name in LISTINGS:
        assert not reads_content(name) and tool_kind(name) == "listing", name


def test_the_device_log_parser_reads_its_whole_input(tmp_path):
    """A device installed after many thousand lines is in the inventory: no
    head cap stands behind the content credit."""
    from core.device_inventory import parse_device_install_log
    filler = "".join(f"     dvi: filler line {n}\n" for n in range(50_000))
    log = tmp_path / "setupapi.dev.log"
    log.write_text("[Device Install Log]\n[BeginLog]\n" + filler
                   + ">>>  [Device Install (Hardware initiated) - USB\\VID_ABCD&PID_0002\\late-device]\n"
                   + ">>>  Section start 2031/03/04 10:00:00.000\n<<<  Section end 2031/03/04 10:00:01.000\n",
                   encoding="utf-8")
    inv = parse_device_install_log(str(log))
    assert inv["device_count"] == 1 and inv["devices"][0]["identity"] == "vidpid:abcd:0002"


def test_the_capture_readers_set_no_packet_count(monkeypatch):
    """Both capture readers run over every packet (no -c): a successful call
    read the capture."""
    import tools.network as N
    seen = []
    monkeypatch.setattr(N, "run", lambda cmd, **kw: seen.append(cmd) or {"success": True, "stdout": ""})
    monkeypatch.setattr(N, "run_with_output_file", lambda cmd, **kw: seen.append(cmd) or {"success": True, "stdout": ""})
    monkeypatch.setattr(N, "assert_output_safe", lambda *a, **k: None, raising=False)
    for fn in (N.tcpdump_list_connections, N.http_session_inventory):
        try:
            fn("evidence/capture.pcap")
        except Exception:  # noqa: BLE001 - only the command is looked at
            pass
    assert len(seen) == 2 and all("-c" not in cmd for cmd in seen)
