"""Tests for unresolved critical scan timeout gate."""
from tools._gates.critical_scan_timeout import (
    format_blocking_issue,
    unresolved_critical_scan_timeouts,
)


def test_truncated_eventlog_scan_without_retry_is_unresolved():
    entries = [
        {
            "type": "tool_call",
            "call_id": 10,
            "cmd": "dotnet /opt/ez/EvtxECmd.dll -f /case/analysis/evtx_HOST01/SecEvent.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": True,
            "truncated": True,
            "elapsed_seconds": 60,
        },
    ]
    u = unresolved_critical_scan_timeouts(entries)
    assert len(u) == 1
    assert u[0]["call_id"] == 10
    assert "SecEvent.evtx" in (u[0]["path"] or "")
    msg = format_blocking_issue(u)
    assert "truncated" in msg.lower() or "timed out" in msg.lower()
    assert "retry" in msg.lower()


def test_later_non_truncated_retry_clears_debt():
    entries = [
        {
            "type": "tool_call",
            "call_id": 10,
            "cmd": "dotnet /opt/ez/EvtxECmd.dll -f /case/analysis/evtx_HOST01/SecEvent.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": False,
            "truncated": True,
        },
        {
            "type": "tool_call",
            "call_id": 20,
            "cmd": "dotnet /opt/ez/EvtxECmd.dll -f /case/analysis/evtx_HOST01/SecEvent.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": True,
            "truncated": False,
        },
    ]
    assert unresolved_critical_scan_timeouts(entries) == []


def test_unrelated_truncated_strings_ignored():
    entries = [
        {
            "type": "tool_call",
            "call_id": 1,
            "cmd": "strings -a big.bin",
            "mcp_tool": "strings_strings_extract",
            "success": True,
            "truncated": True,
        },
    ]
    assert unresolved_critical_scan_timeouts(entries) == []


def test_truncated_grep_under_hayabusa_outdir_not_critical():
    """Path segment 'hayabusa_…' must not fake critical auth-scan debt."""
    entries = [
        {
            "type": "tool_call",
            "call_id": 30,
            "cmd": (
                "grep -i powershell "
                "/case/analysis/hayabusa_WS01/hayabusa_Eventlog.jsonl"
            ),
            "mcp_tool": "misc_batch_run",
            "success": True,
            "truncated": True,
        },
    ]
    assert unresolved_critical_scan_timeouts(entries) == []


def test_evtxecmd_on_same_path_clears_truncated_scan():
    entries = [
        {
            "type": "tool_call",
            "call_id": 10,
            "cmd": "dotnet /opt/ez/EvtxECmd.dll -f /case/analysis/evtx_HOST01/SecEvent.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": False,
            "truncated": True,
        },
        {
            "type": "tool_call",
            "call_id": 20,
            "cmd": (
                "dotnet EvtxECmd.dll -f /case/analysis/evtx_HOST01/SecEvent.evtx "
                "--csv /case/analysis/out"
            ),
            "mcp_tool": "ez_evtxecmd",
            "success": True,
            "truncated": False,
        },
    ]
    assert unresolved_critical_scan_timeouts(entries) == []


def test_evtxecmd_on_parent_dir_clears_truncated_child():
    entries = [
        {
            "type": "tool_call",
            "call_id": 10,
            "cmd": "dotnet /opt/ez/EvtxECmd.dll -f /case/hosts/HOST01/SecEvent.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": False,
            "truncated": True,
        },
        {
            "type": "tool_call",
            "call_id": 20,
            "cmd": "dotnet EvtxECmd.dll -d /case/hosts/HOST01 --csv /case/analysis/out",
            "mcp_tool": "ez_evtxecmd",
            "success": True,
            "truncated": False,
        },
    ]
    assert unresolved_critical_scan_timeouts(entries) == []


def test_other_host_evtx_does_not_clear_by_basename_alone():
    """Multi-host estates share Security.evtx names — basename ≠ clearance."""
    entries = [
        {
            "type": "tool_call",
            "call_id": 1,
            "cmd": "dotnet EvtxECmd.dll -f /case/hosts/A/Security.evtx",
            "mcp_tool": "ez_ez_evtxecmd",
            "success": False,
            "truncated": True,
        },
        {
            "type": "tool_call",
            "call_id": 2,
            "cmd": "EvtxECmd -f /case/hosts/B/Security.evtx --csv /out",
            "mcp_tool": "ez_evtxecmd",
            "success": True,
            "truncated": False,
        },
    ]
    u = unresolved_critical_scan_timeouts(entries)
    assert len(u) == 1
    assert u[0]["call_id"] == 1
