"""Extensible Storage Engine databases: what Windows keeps in ESE files
(SRUM's SRUDB.dat, WebCacheV01.dat, Windows.edb, the DHCP and Exchange
stores), exported table by table with libesedb's esedbexport.

ez.srumecmd is the readable route for SRUM; this is the generic one for
every other ESE file, and the raw route when dotnet is absent.
"""
from __future__ import annotations

import os

from fastmcp import FastMCP

from core import DEFAULT_TIMEOUT, output_safe, run
from core.input_kind import refuse_non_ese
from core.paths import assert_output_safe, missing_program_result, tool_program

mcp = FastMCP("ese")

_INSTALL = ("apt install libesedb-utils (libesedb-tools with the GIFT PPA), "
            "or re-run ./install.sh")
_MAX_TABLES_LISTED = 40
_MAX_ARTIFACTS = 20


def _count_lines(path: str, cap: int = 5_000_000) -> int:
    count = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            count += chunk.count(b"\n")
            if count >= cap:
                break
    return count


def _tables_in(export_dir: str) -> list[dict]:
    """One row per exported table file: name, data rows (header excluded), bytes."""
    if not os.path.isdir(export_dir):
        return []
    rows = []
    for name in sorted(os.listdir(export_dir)):
        path = os.path.join(export_dir, name)
        if not os.path.isfile(path):
            continue
        rows.append({"table": name, "rows": max(_count_lines(path) - 1, 0),
                     "bytes": os.path.getsize(path)})
    return rows


@mcp.tool()
def esedb_info(db_path: str) -> dict:
    """
    Tables and record counts of an ESE database (esedbinfo), to pick a table
    for esedb_export. db_path: the .dat/.edb file itself.
    """
    bad = refuse_non_ese(db_path)
    if bad:
        return bad
    if os.path.isdir(db_path):
        return {"success": False, "error": f"{db_path!r} is a directory; pass the database file"}
    program = tool_program("esedbinfo")
    if not program:
        return missing_program_result("ese.esedb_info", "esedbinfo", _INSTALL)
    return run([program, db_path], timeout=DEFAULT_TIMEOUT)


@mcp.tool()
@output_safe
def esedb_export(db_path: str, output_dir: str, table: str = "", mode: str = "tables") -> dict:
    """
    Export an ESE database (SRUDB.dat, WebCacheV01.dat, Windows.edb, ...) to
    one tab-separated text file per table under output_dir/<name>.export/.
    table: export only this table (names from esedb_info). mode: tables
    (default) or all (tables and their indexes). SRUM tables carry GUID
    names; for a readable SRUM use ez.srumecmd and keep this for the other
    ESE files, or as the raw route when dotnet is absent.
    """
    bad = refuse_non_ese(db_path)
    if bad:
        return bad
    if os.path.isdir(db_path):
        return {"success": False, "error": f"{db_path!r} is a directory; pass the database file"}
    if mode not in ("tables", "all"):
        return {"success": False, "error": f"mode must be tables or all, not {mode!r}"}
    assert_output_safe(output_dir)
    program = tool_program("esedbexport")
    if not program:
        return missing_program_result("ese.esedb_export", "esedbexport", _INSTALL)
    os.makedirs(output_dir, exist_ok=True)
    target = os.path.join(output_dir, os.path.basename(db_path))
    export_dir = target + ".export"
    argv = [program, "-m", mode]
    if table:
        argv += ["-T", table]
    argv += ["-t", target, db_path]
    result = run(argv, timeout=1800, output_dir=output_dir)
    tables = _tables_in(export_dir)
    if not tables:
        result["success"] = False
        result["error"] = ("esedbexport produced no table files: "
                           + (result.get("stderr") or result.get("error") or "no output")[:300])
        result["next_step"] = ("check the table name with esedb_info; a database left dirty by "
                               "an unclean shutdown can still export with mode=all")
        return result
    files = [os.path.join(export_dir, t["table"]) for t in tables]
    return {
        "success": True,
        "export_dir": export_dir,
        "table_count": len(tables),
        "tables": tables[:_MAX_TABLES_LISTED],
        "artifact_paths": files[:_MAX_ARTIFACTS],
        "note": ("each file is tab-separated with a header line; table.table_query reads it, "
                 "strings.strings_grep searches it"),
    }
