"""Full-text search over the case's accumulated tool output.

Every tool call's FULL output (including the spilled 90%+ that never fits
the context window) is indexed into <case>/analysis/evidence_index.db as it
runs. These tools query that index so analysis can pivot on evidence
already gathered instead of re-running extractions.
"""
from typing import Optional

from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("search")


@mcp.tool()
@output_safe
def search_evidence(query: str, tool: Optional[str] = None,
                    time_start: Optional[str] = None,
                    time_end: Optional[str] = None,
                    max_results: int = 100) -> dict:
    """
    Full-text search across ALL tool output gathered so far this case —
    including the truncated majority of large outputs that never reached
    your context. Use it to pivot on an IOC (hostname, IP, hash, filename,
    event ID) before re-running any extraction tool.

    query: FTS5 syntax — terms (spinlock.exe), phrases ("brute force"),
      boolean (4624 AND logon), alternatives (cmd|powershell).
    tool: restrict to one originating tool binary (e.g. "tcpdump").
    time_start/time_end: ISO 8601 bounds on the window's extracted event
      time (windows without a parseable timestamp are excluded).

    Each hit carries the originating call_id — cite it as linked_call_id /
    input_call_ids when recording findings. For structured CSVs (EZ Tools
    output, SIEM exports) prefer table.table_query / table.table_pivot:
    they preserve columns, FTS windows do not.
    """
    from core import evidence_index
    return evidence_index.search(query, tool=tool, time_start=time_start,
                                 time_end=time_end, max_results=max_results)


@mcp.tool()
@output_safe
def intel_sweep(ids: Optional[list[str]] = None) -> dict:
    """
    Search the evidence gathered so far for every active row of the case's
    threat context (the indicators the operator supplied, shown in the
    THREAT CONTEXT block), or only the row ids given (e.g. ["intel-0003"]).

    Each hit names the call whose output shows the value (source_call_id)
    with an excerpt: cite THAT call for presence. This sweep's own output is
    a lookup and never shows a value was present. A row not found was not
    found in what the index holds (what command-line tools printed; not
    table queries or in-process parsers); it is a coverage statement, never
    a sign the system is clean.
    """
    from core.claim_graph import resolve_case_dir
    from core.threat_context import sweep
    case_dir = resolve_case_dir(None)
    if not case_dir:
        return {"success": False, "error": "no active case (start_execution_log first)"}
    return sweep(case_dir, ids or ())


@mcp.tool()
@output_safe
def search_index_status() -> dict:
    """
    Evidence-index health: how many sources/windows are indexed, broken
    down by tool. An empty index early in a run is normal — it fills as
    tools execute.
    """
    from core import evidence_index
    return evidence_index.stats()
