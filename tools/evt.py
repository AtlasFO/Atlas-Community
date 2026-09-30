"""Legacy Windows event logs (.evt, Windows NT through 2003 and XP),
exported with libevt's evtexport. Vista and later write .evtx, which
ez.evtxecmd, misc.chainsaw_hunt and hayabusa.triage read; the two formats
share nothing but the name.
"""
from __future__ import annotations

import os

from fastmcp import FastMCP

from core import DEFAULT_TIMEOUT, output_safe, run
from core.input_kind import refuse_non_evt
from core.paths import assert_output_safe, missing_program_result, tool_program

mcp = FastMCP("evt")

_INSTALL = ("apt install libevt-utils (libevt-tools with the GIFT PPA), "
            "or re-run ./install.sh")
_RECORD_MARKERS = ("Event number", "Record number")


@mcp.tool()
@output_safe
def evt_export(evt_path: str, output_dir: str, mode: str = "items",
               resources_dir: str = "") -> dict:
    """
    Export a legacy .evt event log to text, output_dir/<name>.txt: one block
    per record with its times, source, event id, type and strings.
    mode: items (allocated records, default), recovered (deleted records
    still present in the file), all. resources_dir: a folder holding the
    message DLLs of the same system resolves event message strings.
    """
    bad = refuse_non_evt(evt_path)
    if bad:
        return bad
    if mode not in ("items", "recovered", "all"):
        return {"success": False, "error": f"mode must be items, recovered or all, not {mode!r}"}
    assert_output_safe(output_dir)
    program = tool_program("evtexport")
    if not program:
        return missing_program_result("evt.evt_export", "evtexport", _INSTALL)
    os.makedirs(output_dir, exist_ok=True)
    argv = [program, "-m", mode]
    if resources_dir:
        argv += ["-p", resources_dir]
    argv.append(evt_path)
    result = run(argv, timeout=DEFAULT_TIMEOUT, line_cap=None)
    text = result.get("stdout") or ""
    if not result.get("success") or not text.strip():
        return {
            "success": False,
            "error": ("evtexport produced no records: "
                      + (result.get("stderr") or result.get("error") or "no output")[:300]),
            "exit_code": result.get("exit_code"),
            "next_step": "mode=all also lists recovered records; a zero-record log is an answer too",
        }
    out = os.path.join(output_dir, os.path.basename(evt_path) + ".txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    lines = text.splitlines()
    records = sum(1 for line in lines if line.startswith(_RECORD_MARKERS))
    return {
        "success": True,
        "output_path": out,
        "artifact_paths": [out],
        "mode": mode,
        "records": records or None,
        "lines": len(lines),
        "preview": "\n".join(lines[:40]),
        "note": "strings.strings_grep or table tools read the export; cite this call for any record",
    }
