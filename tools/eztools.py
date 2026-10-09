"""EZ Tools (Eric Zimmerman) — Windows artifact parsers via .NET runtime."""
import json
import os
import re
from pathlib import Path
from typing import Optional
from fastmcp import FastMCP
from core import (run_dotnet, run, output_safe, DEFAULT_TIMEOUT, VOL_TIMEOUT,
                  PLASO_TIMEOUT, scale_timeout)
from core.paths import assert_output_safe

mcp = FastMCP("eztools")

EZ = os.environ.get("ATLAS_EZ_TOOLS", "/opt/zimmermantools")
_LOCAL_EZ = Path.home() / ".local" / "share" / "zimmermantools"


def _resolve_ez_dll(dll: str) -> str:
    """Prefer ATLAS_EZ_TOOLS /opt path; fall back to user-local Zimmerman tools."""
    p = Path(dll)
    if p.is_file():
        return str(p)
    name = p.name
    for base in (Path(EZ), _LOCAL_EZ, Path("/opt/zimmermantools")):
        cand = base / name
        if cand.is_file():
            return str(cand)
    return dll


def _ez(dll: str, args: list[str], output_dir: Optional[str] = None, timeout: int = 300,
        stdin_path: Optional[str] = None, cwd: Optional[str] = None) -> dict:
    if output_dir:
        assert_output_safe(output_dir)
    # Hard-refuse nonexistent input paths BEFORE spawning. Zimmerman tools
    # exit 0 when -f points at a missing file, which surfaced as a phantom
    # success. A missing input is an analyst-error refusal, not a tool run.
    for flag in ("-f", "-d"):
        try:
            i = args.index(flag)
        except ValueError:
            continue
        if i + 1 < len(args):
            in_path = args[i + 1]
            probe = in_path if os.path.isabs(in_path) else os.path.join(
                cwd or os.getcwd(), in_path)
            if not os.path.exists(probe):
                return {
                    "success": False,
                    "error": (
                        f"input path does not exist: {in_path!r}. Do not "
                        "guess artifact locations — discover them first."
                    ),
                    "hint": (
                        "Use misc.list_evidence_dir on the parent directory "
                        "(or misc.inventory_evidence) to find the real path. "
                        "Example: Amcache lives at Windows/AppCompat/"
                        "Programs/Amcache.hve, not System32/config/."
                    ),
                    "gate": "missing_input",
                }
    resolved = _resolve_ez_dll(dll)
    # A tool that was never provisioned otherwise surfaces as an opaque dotnet
    # "command or file was not found" — say which tool is missing and how to get
    # it. (PECmd is absent from the SIFT-seeded /opt/zimmermantools; install.sh
    # provisions the full set.)
    if not os.path.isfile(resolved):
        name = Path(resolved).name
        return {
            "success": False,
            "error": f"{name} is not installed at {resolved}",
            "hint": f"EZ Tools tool {Path(name).stem} is missing on this host. "
                    "Run install.sh (it provisions the full EZ Tools set into "
                    "$ATLAS_EZ_TOOLS), or set ATLAS_EZ_TOOLS to an install that "
                    "has it.",
        }
    return run_dotnet(resolved, args, timeout=timeout, output_dir=output_dir,
                      stdin_path=stdin_path, cwd=cwd)


# Every parser here writes its CSVs somewhere the caller names. The case
# already says where its outputs go, so a call that names no directory gets
# analysis/exports under the open case; only outside a case is the name
# required. A required parameter a tool can derive costs a turn each time a
# model leaves it out or puts it under another name.
_NO_OUTPUT_DIR = {
    "success": False,
    "error": ("output_dir is required when no case is open: name the directory "
              "the CSV output goes to, e.g. analysis/exports."),
}


def _case_exports_dir() -> str:
    try:
        from core.execution_log import log as _elog
        case = str(_elog.case_dir() or "")
    except Exception:  # noqa: BLE001 - no log, no case
        return ""
    return os.path.join(case, "analysis", "exports") if case else ""


def _prepare_output_dir(output_dir: str) -> Optional[dict]:
    """Create output_dir, returning an error dict instead of raising.

    os.makedirs raises FileExistsError when output_dir names an existing FILE
    (a caller passing analysis/out.csv where a directory was wanted), and that
    escaped the wrapper as a traceback rather than a tool result."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        return None
    except OSError as e:
        return {"success": False,
                "error": f"cannot use output_dir {output_dir}: {e}",
                "hint": "output_dir must be a directory (it is created if "
                        "absent), not a file path."}


def _snapshot(output_dir: str, suffix: str = "") -> dict:
    """Map path -> (size, mtime_ns) for files under output_dir, used to tell what
    a run actually produced. A missing directory snapshots as empty."""
    seen = {}
    for root, _dirs, files in os.walk(output_dir):
        for fn in files:
            if suffix and not fn.lower().endswith(suffix):
                continue
            p = os.path.join(root, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            seen[p] = (st.st_size, st.st_mtime_ns)
    return seen


def _produced(before: dict, after: dict) -> list[str]:
    """Files that are new or changed between two _snapshot() calls. Comparing
    against a snapshot rather than just listing the directory keeps unrelated
    artifacts already in analysis/ from being credited to this run."""
    return sorted(p for p, meta in after.items() if before.get(p) != meta)


# System.Data.SQLite needs its own native SQLite.Interop.dll, and no EZ Tools
# distribution ships a Linux build of it — neither the WxTCmd 1.1.0.0/SQLECmd
# 1.1.0.0 builds nor the upstream net9 2026.5.0 zips — so upgrading is not a
# remedy. Two near-misses that look like a fix and are not:
# SQLECmd extracts a libSQLite.Interop.so into its cwd, and a stock libsqlite3
# can be renamed into place — both then fail with EntryPointNotFoundException
# because they export plain sqlite3_* symbols and none of the
# obfuscated 'SI<hash>' entry points the managed wrapper imports. Both tools
# catch the failure, print their normal "Results saved to:" banner, and exit 0
# without writing anything.
_INTEROP_MARKER = "SQLite.Interop.dll"
_SQLITE_ALT_HINT = (
    "This tool cannot run on Linux — it needs the Windows-only "
    "SQLite.Interop.dll that no EZ Tools build ships, so upgrading will not "
    "help. Linux-native alternatives: plaso.plaso_create_targeted with parser "
    "'sqlite/windows_timeline' (ActivitiesCache.db) or 'sqlite/chrome_27_history' "
    "/ 'sqlite/firefox_history' (browser history), or misc.hindsight_chrome for "
    "a full Chromium profile."
)


def _guard_output(result: dict, output_dir: str, before: dict, tool: str,
                  suffix: str = "", hint: str = "") -> dict:
    """Downgrade an exit-0 run that produced no artifact to success=False.

    Every tool here exits 0 on unrecognized flags, unreadable input and native
    library failures alike, printing a success banner either way. Without this,
    an analyst reads "success" and an empty result as "the evidence is clean"."""
    if not result.get("success"):
        return result
    made = _produced(before, _snapshot(output_dir, suffix))
    if made:
        result["output_paths"] = made
        return result

    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    result["success"] = False
    # WxTCmd catches the load failure and prints it on stdout; SQLECmd lets it
    # escape as an unhandled exception on stderr. Check both.
    if _INTEROP_MARKER in stdout or _INTEROP_MARKER in stderr:
        result["error"] = (
            f"{tool} exited 0 but wrote no output: it could not load its native "
            f"{_INTEROP_MARKER}, so no database was ever read.")
        result["hint"] = _SQLITE_ALT_HINT
        return result
    result["error"] = (
        f"{tool} exited 0 but wrote no output file — it did not parse the "
        f"input. stdout: {stdout.strip()[:300]}")
    if hint:
        result["hint"] = hint
    return result


# ── Silent-empty-result guard for the artifact parsers ───────────────────────
#
# EvtxECmd/PECmd/JLECmd/LECmd/RBCmd all exit 0 no matter what they were handed,
# so "no output" reads as "the evidence is clean". Measured on this host against
# real evidence, they split into two output families:
#
#   * EvtxECmd and RBCmd write a HEADER-ONLY CSV when nothing parsed, so
#     checking that a file appeared is not enough — the rows have to be counted.
#   * JLECmd and LECmd write no CSV at all. (JLECmd also RENAMES --csvf output to
#     '<name>_AutomaticDestinations.csv', which is why the guard compares
#     directory snapshots instead of looking for output_file.)
#
# The hard part is that zero rows is often a legitimate finding. It is a true
# negative when the tool demonstrably read something (a filter that matched no
# records) or when there was nothing to read (a Prefetch directory with no .pf
# in it); it is a failure only when candidate artifacts were present and none of
# them parsed. Those three cases are what _guard_parsed_output separates.


def _suffix_match(*suffixes: str):
    """Case-insensitive artifact-name test. Case matters in practice: real
    evidence carries 8.3-shortened PREFETCH names like 'AUDIOD~1.PF' and
    'Bluetooth File Transfer.LNK'."""
    lowered = tuple(s.lower() for s in suffixes)
    return lambda name: name.lower().endswith(lowered)


def _is_recycle_record(name: str) -> bool:
    """A Recycle Bin metadata record is '$I' + 6 characters + the deleted file's
    original extension ('$IA1B2C3.txt').

    The length test is what keeps NTFS '$I30' index attributes out: they also
    start with '$I' but are not Recycle Bin records."""
    stem = os.path.splitext(name)[0]
    return stem.startswith("$I") and len(stem) >= 8


def _count_candidates(path: str, match) -> int:
    """How many files at `path` even look like this tool's artifact.

    This is what distinguishes "there was nothing here to parse" from "there was
    something and none of it parsed" — the first is a true negative, the second
    is the bug this guard exists to catch.

    followlinks=True because the tools themselves follow symlinked directories:
    counting 0 candidates under a symlinked subtree the tool did read would
    relabel a real parse failure as a forensic negative, which is the dangerous
    direction. misc.symlink_evidence exists to hand tools symlinked paths, so
    this is a live shape. realpath bookkeeping keeps a symlink cycle from
    spinning forever."""
    if os.path.isfile(path):
        return 1 if match(os.path.basename(path)) else 0
    total, seen = 0, set()
    for root, dirs, files in os.walk(path, followlinks=True):
        real = os.path.realpath(root)
        if real in seen:
            dirs[:] = []
            continue
        seen.add(real)
        total += sum(1 for f in files if match(f))
    return total


def _processed_count(stdout: str) -> Optional[int]:
    """The 'Processed 0 files' / 'Processed 2 out of 2 files' summary this tool
    family prints, or None if it never appeared.

    Anchored to the start of a line: JLECmd prints a per-file
    '---------- Processed <path> in 0.14 seconds ----------' line for every
    artifact, and a relative path whose name begins with digits would otherwise
    be read as the count. The last match wins because the numeric summary comes
    after those per-file lines.

    Note the captured number is how many files SUCCEEDED, not how many were
    attempted: 'Processed 0 out of 1 files' captures only the 0, because
    'out of 1' is not preceded by 'Processed'."""
    import re
    found = re.findall(r"^Processed\s+(\d+)", stdout, re.MULTILINE)
    return int(found[-1]) if found else None


# Sections these tools print when they opened a file and could not parse it.
# Their presence is the tool's own admission of a per-file failure, which is a
# sounder partial-parse signal than comparing counts: EvtxECmd de-duplicates
# identical logs by SHA-1, so processed < candidates happens on healthy runs.
_FAILURE_SECTIONS = ("Failed files", "error count:")

# Per-file lines proving a tool actually opened an artifact, used only when the
# trailing summary was cut off. run() keeps the FIRST 150 lines of stdout
# (MAX_TOOL_OUTPUT_LINES), so an EvtxECmd sweep of a full winevt/Logs directory
# — thousands of lines — loses its "Processed N files" summary entirely.
_READ_MARKERS = ("Total event log records found:",)


def _has_data_rows(paths: list[str]) -> bool:
    """True if any produced CSV holds a row past its header.

    Deliberately a byte-level check and not a csv parse: an EvtxECmd sweep of a
    full winevt/Logs directory runs to millions of rows and can embed newlines
    inside quoted fields, and the guard only needs to know whether anything at
    all was parsed."""
    for p in paths:
        try:
            with open(p, "rb") as fh:
                fh.readline()    # header
                for line in fh:
                    if line.strip():
                        return True
        except OSError:
            continue
    return False


def _guard_parsed_output(result: dict, output_dir: str, before: dict, tool: str,
                         input_path: str, match, artifact: str,
                         hint: str = "") -> dict:
    """Separate a real zero-result from a silent failure for the artifact parsers.

    Success, in descending order of evidence that the tool actually worked:
      * it wrote rows                                    -> success
      * it reported processing at least one file         -> success + note
      * no candidate `artifact` existed at input_path    -> success + note
      * its own summary was truncated away               -> success + note
    Only a run where candidates were present, nothing was read and nothing was
    written is the silent-empty-result bug, and only that is downgraded."""
    if not result.get("success"):
        return result

    # Only CSVs count. Snapshotting everything credited Atlas's own trace.json /
    # trace.jsonl / evidence_index.db, which it rewrites *during* the tool call,
    # as though they were parsed output — and callers overwhelmingly pass the
    # case's analysis/ directory, where the trace lives. That made the guard
    # inert on most real calls and advertised the trace log as forensic output.
    made = _produced(before, _snapshot(output_dir, ".csv"))
    stdout = result.get("stdout") or ""
    if made:
        result["output_paths"] = made
    if _has_data_rows(made):
        # A truncated or partially-corrupt log still yields the records that came
        # before the damage. That is real evidence, so it stays a success — but
        # the analyst has to know the parse was incomplete.
        if any(s in stdout for s in _FAILURE_SECTIONS):
            result["note"] = (
                f"{tool} parsed {artifact} records but reported per-file "
                "failures, so this output covers only the files that parsed. "
                "Treat an absence in it as unproven, not as a negative.")
        return result

    processed = _processed_count(stdout)

    # Checked before anything about the input path: if the tool says it read a
    # file, it read one, whatever the file is named. Ordering this after the
    # wrong-input branch below declared a carved artifact with no extension
    # "not a .evtx log" while EvtxECmd's own output said it had parsed it.
    if processed:
        result["note"] = (
            f"{tool} read {processed} file(s) and they held no {artifact} "
            "records in scope — a true negative, not a failure.")
        return result

    candidates = _count_candidates(input_path, match)

    if candidates == 0:
        # A directory holding none of this artifact is a finding: an empty
        # Prefetch directory, a user with no jump lists, an empty Recycle Bin.
        # A single file that is not this artifact at all is a different thing —
        # the caller pointed the wrong parser at it, and calling that a true
        # negative would license "no evidence" from a file never suited to
        # answer the question. (Live case: an NTFS '$I30' index attribute handed
        # to RBCmd, which writes a header-only CSV and exits 0.)
        if os.path.isfile(input_path):
            result["success"] = False
            result["error"] = (
                f"{input_path} is not a {artifact}, so {tool} parsed nothing. "
                "This is a wrong-input error, not a negative finding.")
            result["hint"] = hint
            return result
        result["note"] = (
            f"No {artifact}s found under {input_path}, so {tool} had nothing to "
            f"parse — a true negative, not a failure. Confirm this is the right "
            f"path before reading it as 'no {artifact} evidence'.")
        return result

    # The summary that would settle it was cut off. Saying "parsed nothing" here
    # would fail the canonical absence-proof sweep (a whole winevt/Logs directory
    # under an --inc filter), so report what is actually known instead: either a
    # per-file marker survived the cut and proves files were read, or nothing did
    # and the result is unverified rather than empty.
    if result.get("truncated"):
        if any(m in stdout for m in _READ_MARKERS):
            result["note"] = (
                f"{tool} read {artifact}s — its per-file output shows so — and "
                "they held no records in scope. A true negative, not a failure. "
                "(Its summary line was past the stdout cap.)")
        else:
            result["note"] = (
                f"{tool} produced no {artifact} records, and its stdout was "
                f"truncated past the summary line, so whether it read the "
                f"{candidates} {artifact}(s) present could not be confirmed. "
                "Do not read this as an absence without re-running on a "
                "narrower path.")
        return result

    result["success"] = False
    result["error"] = (
        f"{tool} exited 0 but parsed nothing: {candidates} {artifact}(s) "
        f"are present at {input_path} and none of them produced a "
        f"record. stdout: {stdout.strip()[:300]}")
    result["hint"] = hint or (
        f"Confirm the files really are {artifact}s and are not truncated, "
        "and that the path points at the artifact rather than a parent "
        "directory.")
    return result


def _attach_evtx_coverage(result: dict, output_dir: str, output_file: str) -> None:
    """Stamp the parsed log's event time-range (min/max TimeCreated) onto the
    tool_call entry as `coverage_window`, so the negative_completeness gate can
    tell whether the log actually covers a claim's window — a log that is silent
    about the window cannot ground a negative. Best-effort; never raises."""
    try:
        cid = result.get("_atlas_call_id")
        if not cid:
            return
        import csv as _csv
        import os as _os
        path = _os.path.join(output_dir, output_file)
        if not _os.path.exists(path):
            return
        start = end = None
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            rdr = _csv.DictReader(fh)
            col = next((c for c in (rdr.fieldnames or [])
                        if c.lstrip("﻿").strip().lower() == "timecreated"), None)
            if not col:
                return
            for row in rdr:
                ts = (row.get(col) or "").strip()
                if not ts:
                    continue
                if start is None or ts < start:
                    start = ts
                if end is None or ts > end:
                    end = ts
        if start and end:
            from core.execution_log import log
            log.annotate_tool_call(cid, coverage_window={"start": start, "end": end})
    except Exception:
        pass


# ── MFT ──────────────────────────────────────────────────────────────────────

_RESIDENT_MODES = {"": [], "inline": ["--ir"], "dump": ["--dr"], "both": ["--ir", "--dr"]}
_RESIDENT_MAX_BYTES = 1_024_000   # MFTECmd's own ceiling for --rm


@mcp.tool()
@output_safe
def ez_mftecmd(
    mft_path: str,
    output_dir: str = "",
    output_file: str = "mft.csv",
    include_slack: bool = False,
    resident: str = "",
    resident_ext: str = "",
    resident_max_bytes: int = 0,
) -> dict:
    """
    Parse the Master File Table ($MFT) from a mounted or extracted NTFS volume.
    mft_path: path to $MFT file (e.g. /mnt/windows_mount/$MFT or extracted copy).
    Produces CSV with all file metadata, timestamps, and attributes.
    The optional parameters default to that output, unchanged:
    include_slack: also recover the slack space of FILE records (--rs).
    resident: the content of small files kept inside their MFT record (scripts,
      shortcuts, Zone.Identifier streams): "inline" puts it in the CSV (--ir),
      "dump" writes each such file under <output_dir>/Resident (--dr), "both".
    resident_ext: with inline, only these extensions, e.g. ".txt,.ps1,.bat".
    resident_max_bytes: with inline, the largest value kept (MFTECmd's default
      is 1024 bytes, at most 1024000).
    For the USN journal ($J) use ez.mftecmd_usn.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    resident = (resident or "").strip().lower()
    if resident not in _RESIDENT_MODES:
        return {"success": False, "error": f"resident is one of inline, dump or both, not {resident!r}"}
    if resident in ("dump", "both"):
        # A dump writes copies of file content; under a handling stop no
        # content is copied (core.handling_stop).
        try:
            from core.claim_graph import resolve_case_dir
            from core.handling_stop import is_stopped
            if is_stopped(resolve_case_dir(None)):
                return {"success": False, "error": ("a handling stop stands: resident file content is "
                                                    "not dumped; resident=inline keeps metadata work going")}
        except Exception:  # noqa: BLE001 - no case, no stop
            pass
    args = ["-f", mft_path, "--csv", output_dir, "--csvf", output_file]
    if include_slack:
        args.append("--rs")
    args += _RESIDENT_MODES[resident]
    if resident in ("inline", "both"):
        if resident_ext:
            args += ["--re", resident_ext]
        if resident_max_bytes:
            args += ["--rm", str(max(1, min(int(resident_max_bytes), _RESIDENT_MAX_BYTES)))]
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_mftecmd_usn(
    j_path: str,
    mft_path: str = "",
    output_dir: str = "",
    output_file: str = "usn.csv",
) -> dict:
    """
    Parse the NTFS change journal ($UsnJrnl:$J, usually extracted as $J) into
    CSV: every create, rename, write and delete the journal still holds.
    mft_path: the $MFT of the same volume; with it each record carries its full
      parent path (MFTECmd -m), without it only entry and parent numbers.
    One file's history is a filter on this CSV: table.table_query on the Name
    or ParentPath column, or on the EntryNumber of its MFT record.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-f", j_path, "--csv", output_dir, "--csvf", output_file]
    if mft_path:
        args += ["-m", mft_path]
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_sumecmd(sum_dir: str, output_dir: str = "") -> dict:
    """
    Parse Windows Server User Access Logging (the SUM databases in
    Windows/System32/LogFiles/Sum: SystemIdentity.mdb, Current.mdb and one
    {GUID}.mdb per year) into CSV: which account, from which address, used
    which server role, day by day, for up to three years.
    sum_dir: the whole Sum folder. The databases are ESE files; a copy taken
      from a running server can be dirty, and SumECmd then says so.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    return _ez(f"{EZ}/SumECmd.dll", ["-d", sum_dir, "--csv", output_dir], output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_mftecmd_dir(
    volume_dir: str,
    output_dir: str = "",
    output_file: str = "mft_dir.csv",
) -> dict:
    """Parse $MFT from a directory scan of a mounted volume (searches for $MFT automatically)."""
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-d", volume_dir, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


# ── Event Logs ────────────────────────────────────────────────────────────────

_EVTX_MEMO_NAME = ".evtx_parse_registry.json"


def _normalize_event_ids(event_ids) -> Optional[str]:
    """``--inc`` form of an event-id filter: digits, commas and ranges only,
    sorted and deduplicated. Accepts what models send — ``"(4624, 4625)"``,
    ``"[4624,4625]"``, a list, ``"5500-5600"``."""
    if isinstance(event_ids, (list, tuple, set)):
        event_ids = ",".join(str(x) for x in event_ids)
    raw = re.sub(r"[^\d,\-]+", ",", str(event_ids or ""))
    ids = sorted({x.strip("-") for x in raw.split(",") if x.strip("-")})
    return ",".join(ids) or None


def _evtx_time_bound(raw, *, end: bool = False) -> Optional[str]:
    """EvtxECmd ``--sd``/``--ed`` form (``yyyy-MM-dd HH:mm:ss.fffffff``, UTC)
    of a bound as the model writes it: ``2031-02-04``, ``2031-02-04 14:00``,
    ``2031-02-04T14:00:00Z``, ``2031-02-04T16:00:00+02:00``. A date alone is
    the whole day — start 00:00:00, end 23:59:59.999999. Raises ValueError
    for anything else, so a typo is refused rather than silently ignored.
    """
    from datetime import datetime, timedelta, timezone
    text = str(raw or "").strip()
    if not text:
        return None
    t = text[:10] + "T" + text[11:] if re.match(r"^\d{4}-\d{2}-\d{2} \d", text) else text
    if t[-1:] in ("Z", "z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError as e:
        raise ValueError(
            f"{text!r} is not a date/time. Use 2031-02-04 (whole day) or "
            "2031-02-04T14:00:00Z — UTC, like the TimeCreated column.") from e
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    if end and re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        dt = dt + timedelta(days=1) - timedelta(microseconds=1)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + "0"


def _evtx_memo_load(output_dir: str) -> dict:
    try:
        with open(os.path.join(output_dir, _EVTX_MEMO_NAME), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _evtx_parse_memo_lookup(
    output_dir: str, evtx_path: str, event_ids: Optional[str],
    window: Optional[tuple] = None,
) -> Optional[dict]:
    """Refusal dict when this parse already exists on disk, else None.

    A parse covers a request when it had the same filter (event ids and
    time window) or no filter at all; a windowed parse never stands in for
    a request outside its window.
    """
    key = os.path.abspath(evtx_path)
    norm = _normalize_event_ids(event_ids)
    win = list(window) if window else None
    entries = _evtx_memo_load(output_dir).get(key) or []
    exact = full = None
    for e in entries:
        if not isinstance(e, dict):
            continue
        csv = e.get("csv") or ""
        if not (csv and os.path.isfile(csv)):
            continue
        if e.get("event_ids") == norm and (e.get("window") or None) == win:
            exact = e
        if not e.get("event_ids") and not e.get("window"):
            full = e
    hit = exact or (full if (norm or win) else None)
    if not hit:
        return None
    scope = ("unfiltered parse" if not (hit.get("event_ids") or hit.get("window"))
             else "parse with " + " ".join(
                 x for x in (f"event_ids={hit.get('event_ids')}" if hit.get("event_ids") else "",
                             f"window={hit.get('window')}" if hit.get("window") else "") if x))
    return {
        "success": False,
        "gate": "parse_memo",
        "error": (
            f"{os.path.basename(evtx_path)} was already parsed (an existing "
            f"{scope} covers this request): {hit['csv']}. Re-parsing the "
            "same log re-reads the whole file for no new information."
        ),
        "use_instead": "table.table_query",
        "existing_csv": hit["csv"],
        "hint": (
            f"Query the existing CSV instead, e.g. table.table_query("
            f"path={hit['csv']!r}, where=[\"EventId=<id>\"]). To force a "
            "genuine re-parse, delete that CSV first."
        ),
    }


def _evtx_parse_memo_record(
    output_dir: str, evtx_path: str, event_ids: Optional[str], output_file: str,
    window: Optional[tuple] = None,
) -> None:
    try:
        reg = _evtx_memo_load(output_dir)
        key = os.path.abspath(evtx_path)
        entries = [e for e in (reg.get(key) or []) if isinstance(e, dict)]
        entries.append({
            "event_ids": _normalize_event_ids(event_ids),
            "window": list(window) if window else None,
            "csv": os.path.join(output_dir, output_file),
        })
        reg[key] = entries[-20:]
        with open(os.path.join(output_dir, _EVTX_MEMO_NAME), "w",
                  encoding="utf-8") as f:
            json.dump(reg, f, indent=1)
    except OSError:
        pass


@mcp.tool()
@output_safe
def ez_evtxecmd(
    evtx_path: str,
    output_dir: str = "",
    output_file: str = "evtx.csv",
    maps_dir: str = f"{EZ}/EvtxeCmd/Maps",
    event_ids: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> dict:
    """
    Parse Windows Event Log (.evtx) files with enriched field mapping.
    evtx_path: path to a single .evtx file or a directory of .evtx files.
    event_ids: comma-separated event IDs to filter (e.g. '4624,4625,4688';
        ranges like '5500-5600' allowed).
    time_start / time_end: keep only events inside this window, UTC and
        inclusive — '2031-02-04' (a whole day) or '2031-02-04T14:00:00Z'.
        The narrow way to read a large Security.evtx: filter by IDs AND a
        window around the case timeframe instead of parsing everything.
    Maps decode raw XML fields into human-readable columns.

    EvtxECmd always writes its CSV even when it parsed nothing, so an empty
    result is checked for rows rather than for the file's existence. A log that
    genuinely holds no events in scope comes back as success with a note; a
    directory of .evtx that yielded no records at all is reported as a failure.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    from core.input_kind import refuse_preparsed_evtx
    bad = refuse_preparsed_evtx(evtx_path)
    if bad:
        return bad
    if not os.path.exists(evtx_path):
        return {"success": False, "error": f"path not found: {evtx_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    # Parse memo: EvtxECmd re-parses the whole log on every call (~5-6 s and
    # a full context block each), so the same Security.evtx would be parsed
    # once per event_ids set. Once a parse of
    # this log exists on disk, redirect identical requests — and, when an
    # UNFILTERED parse exists, all filtered requests — to table.table_query
    # on the existing CSV instead of re-running the parser.
    try:
        sd = _evtx_time_bound(time_start)
        ed = _evtx_time_bound(time_end, end=True)
    except ValueError as e:
        return {"success": False, "gate": "bad_args", "error": str(e),
                "hint": "time_start/time_end are UTC: '2031-02-04' (whole day) "
                        "or '2031-02-04T14:00:00Z'."}
    if sd and ed and sd > ed:
        return {"success": False, "gate": "bad_args",
                "error": f"time_start {time_start!r} lies after time_end {time_end!r}."}
    window = (sd, ed) if (sd or ed) else None
    ids = _normalize_event_ids(event_ids)
    memo = _evtx_parse_memo_lookup(output_dir, evtx_path, ids, window)
    if memo:
        return memo
    before = _snapshot(output_dir)
    # Dispatch on what the path IS, not on its name. endswith(".evtx") sent every
    # log that had been carved, renamed, or extracted without its extension to -d
    # as though it were a directory (and any directory called "…evtx" to -f).
    flag = "-d" if os.path.isdir(evtx_path) else "-f"
    args = [flag, evtx_path, "--csv", output_dir, "--csvf", output_file, "--maps", maps_dir]
    if ids:
        args += ["--inc", ids]
    if sd:
        args += ["--sd", sd]
    if ed:
        args += ["--ed", ed]
    result = _ez(f"{EZ}/EvtxeCmd/EvtxECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)
    if result.get("success"):
        _evtx_parse_memo_record(output_dir, evtx_path, ids, output_file, window)
        if window:
            result["time_window_utc"] = {"start": sd, "end": ed}
    _attach_evtx_coverage(result, output_dir, output_file)
    hint = ("EvtxECmd skips files whose signature is not 'ElfFile'. Check the "
            "logs are real .evtx and not truncated, and that --maps points at "
            "the EvtxeCmd/Maps directory.")
    if ids or window:
        # With a filter in play the likeliest reason for an empty result is the
        # filter itself, so say so before the analyst reads it as an absence.
        what = " and ".join(x for x in (
            f"event_ids {ids}" if ids else "",
            f"the window {sd or '…'} – {ed or '…'} (UTC)" if window else "") if x)
        hint = (f"Nothing matched {what}. Re-run without the filter to see "
                "whether the log holds any events at all before reading this "
                "as a negative. ") + hint
    return _guard_parsed_output(
        result, output_dir, before, "EvtxECmd", evtx_path,
        _suffix_match(".evtx"), ".evtx log", hint=hint)


# ── Registry ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_recmd_hive(
    hive_path: str,
    output_dir: str = "",
    output_file: str = "registry.csv",
    batch_file: str = f"{EZ}/RECmd/BatchExamples/DFIRBatch.reb",
) -> dict:
    """
    Parse a single registry hive using a RECmd batch file.
    hive_path: path to SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, etc.
    batch_file: path to .reb batch file (defaults to DFIRBatch.reb)
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    from core.input_kind import refuse_preparsed_hive
    bad = refuse_preparsed_hive(hive_path)
    if bad:
        return bad
    args = ["-f", hive_path, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


@mcp.tool()
@output_safe
def ez_recmd_dir(
    hives_dir: str,
    output_dir: str = "",
    output_file: str = "registry_all.csv",
    batch_file: str = f"{EZ}/RECmd/BatchExamples/DFIRBatch.reb",
) -> dict:
    """Parse all registry hives in a directory recursively using a RECmd batch file."""
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def ez_recmd_batch(
    hives_dir: str,
    batch_file: str,
    output_dir: str = "",
) -> dict:
    """Run a RECmd batch config against a directory of hives (targeted key extraction)."""
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── Amcache & AppCompat ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_amcacheparser(
    amcache_path: str,
    output_dir: str = "",
    output_file: str = "amcache.csv",
) -> dict:
    """
    Parse Amcache.hve — program execution evidence with SHA1 hashes.
    amcache_path: path to Amcache.hve (usually Windows/AppCompat/Programs/Amcache.hve).
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    from core.input_kind import refuse_preparsed_hive
    bad = refuse_preparsed_hive(amcache_path)
    if bad:
        return bad
    args = ["-f", amcache_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AmcacheParser.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_appcompatcacheparser(
    system_hive: str,
    output_dir: str = "",
    output_file: str = "shimcache.csv",
) -> dict:
    """
    Parse AppCompatCache (ShimCache) from SYSTEM hive — execution evidence with timestamps.
    system_hive: path to SYSTEM registry hive.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    from core.input_kind import refuse_preparsed_hive
    bad = refuse_preparsed_hive(system_hive)
    if bad:
        return bad
    args = ["-f", system_hive, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AppCompatCacheParser.dll", args, output_dir=output_dir)


# ── SRUM ─────────────────────────────────────

@mcp.tool()
@output_safe
def ez_srumecmd(
    srum_path: str,
    output_dir: str = "",
    software_hive: str = "",
) -> dict:
    """
    Parse SRUM (Windows/System32/sru/SRUDB.dat): per-application network
    bytes, CPU and energy use and push notifications, kept for about 30
    days — the artifact for "which program sent how much, and when". One
    CSV per table. srum_path: SRUDB.dat, or a directory holding SRUDB.dat
    and the SOFTWARE hive (KAPE layout, searched recursively).
    software_hive: the SOFTWARE hive; optional, but it resolves application
    ids and network profiles to names.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    from core.input_kind import refuse_non_ese, refuse_preparsed_hive
    bad = refuse_non_ese(srum_path)
    if bad:
        return bad
    if software_hive:
        bad = refuse_preparsed_hive(software_hive)
        if bad:
            return bad
    prep = _prepare_output_dir(output_dir)
    if prep:
        return prep
    if os.path.isdir(srum_path):
        args = ["-d", srum_path, "--csv", output_dir]
    else:
        args = ["-f", srum_path, "--csv", output_dir]
        if software_hive:
            args += ["-r", software_hive]
    before = _snapshot(output_dir, ".csv")
    result = _ez(f"{EZ}/SrumECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)
    return _guard_output(result, output_dir, before, "SrumECmd", ".csv",
                         hint="SRUDB.dat must be the database itself; a database left dirty "
                              "by an unclean shutdown may need ese.esedb_export as the raw route")


# ── Prefetch ──────────────────────────────────────────────────────────────────

_PECMD_PLATFORM_MSG = "Non-Windows platforms not supported"
_PREFETCH_RUN_SLOTS = 8


def _prefetch_files(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    out = []
    for name in sorted(os.listdir(path)):
        if name.lower().endswith(".pf"):
            out.append(os.path.join(path, name))
    return out


def _prefetch_row(pf, f: str) -> dict:
    """One prefetch file's row in PECmd's shape, from an open pyscca file."""
    runs: list[str] = []
    for i in range(_PREFETCH_RUN_SLOTS):
        try:
            t = pf.get_last_run_time(i)
        except Exception:  # noqa: BLE001 - no more run-time slots
            break
        if t and getattr(t, "year", 1601) > 1601:
            runs.append(t.strftime("%Y-%m-%d %H:%M:%S"))
    try:
        loaded = [pf.get_filename(i) for i in range(int(pf.number_of_filenames))]
    except Exception:  # noqa: BLE001
        loaded = []
    row = {
        "SourceFilename": f,
        "ExecutableName": getattr(pf, "executable_filename", "") or "",
        "Hash": format(int(getattr(pf, "prefetch_hash", 0) or 0), "X"),
        "Version": getattr(pf, "format_version", "") or "",
        "RunCount": getattr(pf, "run_count", "") or "",
        "LastRun": runs[0] if runs else "",
    }
    for i in range(_PREFETCH_RUN_SLOTS - 1):
        row[f"PreviousRun{i}"] = runs[i + 1] if len(runs) > i + 1 else ""
    row["FilesLoaded"] = ", ".join(loaded)
    return row


def _prefetch_fallback(prefetch_path: str, output_dir: str, output_file: str) -> dict:
    """Parse prefetch files with libscca into a CSV shaped like PECmd's
    (executable, hash, run count, last and previous run times, files loaded)."""
    try:
        import pyscca
    except ImportError:
        return {
            "success": False,
            "error": (
                "PECmd cannot decompress Windows 8+ prefetch on this platform "
                "and the fallback parser is not installed: pip install "
                "libscca-python (listed in requirements.txt)."
            ),
        }
    import csv
    files = _prefetch_files(prefetch_path)
    rows: list[dict] = []
    failed: list[str] = []
    for f in files:
        # One file libscca cannot read (a property of a corrupt file raises)
        # is named in the note; the batch goes on.
        try:
            rows.append(_prefetch_row(pyscca.open(f), f))
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{os.path.basename(f)}: {exc}")
    out_path = os.path.join(output_dir, output_file)
    if rows:
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    note = f"libscca parsed {len(rows)} of {len(files)} prefetch file(s)"
    if failed:
        note += "; failed: " + "; ".join(failed[:5])
    return {
        "success": bool(rows),
        "stdout": note,
        "output_paths": [out_path] if rows else [],
        "records": len(rows),
        "note": note if rows else "",
        "error": "" if rows else (note + " — no prefetch records parsed"),
    }


@mcp.tool()
@output_safe
def ez_pecmd(
    prefetch_path: str,
    output_dir: str = "",
    output_file: str = "prefetch.csv",
) -> dict:
    """
    Parse Windows Prefetch files — execution timestamps (up to 8 last run times), file references.
    prefetch_path: path to a single .pf file or the Prefetch directory.

    A Prefetch directory holding no .pf files is reported as success with a note
    (prefetch can legitimately be empty — it is disabled on SSDs by some builds
    and is a routine anti-forensics target); .pf files that yield no records are
    reported as a failure.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(prefetch_path):
        return {"success": False, "error": f"path not found: {prefetch_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir)
    # Dispatch on what the path IS, not on its name. endswith(".pf") is also
    # case-sensitive, so the uppercase 8.3 names that really do show up in
    # extracted Prefetch directories (AUDIOD~1.PF) were handed to -d as though
    # they were directories.
    flag = "-d" if os.path.isdir(prefetch_path) else "-f"
    args = [flag, prefetch_path, "--csv", output_dir, "--csvf", output_file]
    result = _ez(f"{EZ}/PECmd.dll", args, output_dir=output_dir)
    if _PECMD_PLATFORM_MSG in str(result.get("stdout") or ""):
        # PECmd declines compressed (Windows 8+) prefetch off Windows; the
        # libscca parser reads them anywhere.
        return _prefetch_fallback(prefetch_path, output_dir, output_file)
    return _guard_parsed_output(
        result, output_dir, before, "PECmd", prefetch_path,
        _suffix_match(".pf"), ".pf file",
        hint="An empty Prefetch directory can mean prefetching was disabled or "
             "the files were wiped — corroborate with Amcache/ShimCache "
             "(ez_amcacheparser, ez_appcompatcacheparser) before concluding a "
             "program never ran. af.af_prefetch_deletion tests for wiping.")


# ── Jump Lists & LNK ──────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_jlecmd(
    jump_list_path: str,
    output_dir: str = "",
    output_file: str = "jumplists.csv",
) -> dict:
    """
    Parse Jump Lists (AutomaticDestinations / CustomDestinations).
    jump_list_path: path to a single .automaticDestinations-ms file or directory.

    JLECmd splits its output by jump list type and renames output_file
    accordingly ('jumplists_AutomaticDestinations.csv'), so the paths it actually
    wrote are returned as output_paths rather than the name requested.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(jump_list_path):
        return {"success": False, "error": f"path not found: {jump_list_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir)
    # Dispatch on what the path IS, not on its name. The substring test this
    # replaces was correct only by an accident of casing: it matched the
    # lowercase ".automaticDestinations-ms" file suffix while missing the real
    # Windows directory name "AutomaticDestinations" (capital A). Any
    # case-normalised export, or a file renamed off its suffix, misrouted.
    flag = "-d" if os.path.isdir(jump_list_path) else "-f"
    args = [flag, jump_list_path, "--csv", output_dir, "--csvf", output_file]
    result = _ez(f"{EZ}/JLECmd.dll", args, output_dir=output_dir)
    return _guard_parsed_output(
        result, output_dir, before, "JLECmd", jump_list_path,
        _suffix_match(".automaticdestinations-ms", ".customdestinations-ms"),
        "jump list",
        hint="Point jump_list_path at a user's AutomaticDestinations / "
             "CustomDestinations directory (under "
             "AppData/Roaming/Microsoft/Windows/Recent), or at the Recent "
             "directory itself to pick up both.")


@mcp.tool()
@output_safe
def ez_lecmd(
    lnk_path: str,
    output_dir: str = "",
    output_file: str = "lnk.csv",
) -> dict:
    """
    Parse Windows shortcut (.lnk) files — reveal accessed paths, timestamps, machine info.
    lnk_path: path to a single .lnk file or a directory to scan recursively.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(lnk_path):
        return {"success": False, "error": f"path not found: {lnk_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir)
    # Dispatch on what the path IS, not on its name — endswith(".lnk") is
    # case-sensitive and misses ".LNK", and a shortcut recovered from unallocated
    # space rarely keeps its extension at all.
    flag = "-d" if os.path.isdir(lnk_path) else "-f"
    args = [flag, lnk_path, "--csv", output_dir, "--csvf", output_file]
    result = _ez(f"{EZ}/LECmd.dll", args, output_dir=output_dir)
    return _guard_parsed_output(
        result, output_dir, before, "LECmd", lnk_path,
        _suffix_match(".lnk"), ".lnk shortcut",
        hint="LECmd skips files with an invalid LNK signature. Confirm the "
             "files are shortcuts and not truncated.")


# ── Shellbags ─────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_sbecmd(
    usrclass_path: str,
    output_dir: str = "",
    output_file: str = "shellbags.csv",
) -> dict:
    """
    Parse Shellbags (UsrClass.dat) — folder access history including network and removable media.
    usrclass_path: path to UsrClass.dat hive.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-f", usrclass_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/SBECmd.dll", args, output_dir=output_dir)


# ── Recycle Bin ───────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_rbcmd(
    recycle_bin_path: str,
    output_dir: str = "",
    output_file: str = "recyclebin.csv",
) -> dict:
    """
    Parse Recycle Bin $I files — deleted file metadata (original path, deletion time, file size).
    recycle_bin_path: path to $Recycle.Bin directory or a single $I file.

    An empty $Recycle.Bin is reported as success with a note — nothing in the
    bin is a normal state. A $I file that yields no record is a failure: like
    EvtxECmd, RBCmd writes a header-only CSV in that case, so the rows are
    checked rather than the file's existence.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(recycle_bin_path):
        return {"success": False, "error": f"path not found: {recycle_bin_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir)
    # Dispatch on what the path IS, not on its name. The "$I" name test cut both
    # ways: a $I file extracted under an analyst-chosen name went to -d, and any
    # directory that merely happened to sit below a path component starting "$I"
    # went to -f.
    flag = "-d" if os.path.isdir(recycle_bin_path) else "-f"
    args = [flag, recycle_bin_path, "--csv", output_dir, "--csvf", output_file]
    result = _ez(f"{EZ}/RBCmd.dll", args, output_dir=output_dir)
    return _guard_parsed_output(
        result, output_dir, before, "RBCmd", recycle_bin_path,
        _is_recycle_record, "$I Recycle Bin record",
        hint="RBCmd reads the '$I' metadata records ('$IA1B2C3.txt'), not the "
             "'$R' file contents and not NTFS '$I30' index attributes. Point it "
             "at $Recycle.Bin and let it recurse into the per-SID directories.")


# ── Windows Timeline ──────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_wxtcmd(
    timeline_db: str,
    output_dir: str = "",
) -> dict:
    """
    Parse Windows 10 Timeline database (ActivitiesCache.db) — user activity history.
    timeline_db: path to ActivitiesCache.db.

    WxTCmd names its own CSVs (one per table, timestamp-prefixed); the paths it
    wrote are returned as output_paths. It has --csv but no --csvf, so there is
    no way to force a filename — rename afterwards if you need a fixed name.

    Note: WxTCmd cannot run on Linux (it needs the Windows-only
    SQLite.Interop.dll, which no EZ Tools build ships). It will report a clear
    failure rather than a silent empty result; use plaso's
    'sqlite/windows_timeline' parser instead.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.isfile(timeline_db):
        return {"success": False, "error": f"file not found: {timeline_db}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir, ".csv")
    # --csvf is not a WxTCmd flag: passing it made the tool print usage, exit 0
    # and write nothing, which Atlas recorded as a success.
    timeline_db, output_dir = os.path.abspath(timeline_db), os.path.abspath(output_dir)
    args = ["-f", timeline_db, "--csv", output_dir]
    # cwd=output_dir for the same reason as ez_sqlecmd — keep any native-library
    # byproduct out of the directory Atlas was started from.
    result = _ez(f"{EZ}/WxTCmd.dll", args, output_dir=output_dir, cwd=output_dir)
    return _guard_output(result, output_dir, before, "WxTCmd", suffix=".csv")


# ── SQLite ────────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_sqlecmd(
    db_path: str,
    output_dir: str = "",
    maps_dir: str = f"{EZ}/SQLECmd/Maps",
) -> dict:
    """
    Parse SQLite databases with known schema maps (browser history, Windows Timeline, etc.).
    db_path: path to a single database file or a directory to scan.

    SQLECmd names its own CSVs (one per map query); the paths it wrote are
    returned as output_paths. It has --csv but no --csvf, so a filename cannot
    be forced — rename afterwards if you need a fixed name.

    Note: SQLECmd cannot run on Linux (it needs the Windows-only
    SQLite.Interop.dll, which no EZ Tools build ships). It will report a clear
    failure rather than a silent empty result; use plaso's sqlite/* parsers or
    misc.hindsight_chrome instead.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(db_path):
        return {"success": False, "error": f"path not found: {db_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir, ".csv")
    # Dispatch on what the path IS, not on its extension: the databases SQLECmd
    # has maps for are frequently extensionless (Chromium 'History', 'Cookies',
    # 'Web Data', 'Favicons'), and those were being passed to -d as if they were
    # directories.
    db_path, output_dir = os.path.abspath(db_path), os.path.abspath(output_dir)
    flag = "-d" if os.path.isdir(db_path) else "-f"
    # --csvf is not a SQLECmd flag: passing it made the tool print usage, exit 0
    # and write nothing, which Atlas recorded as a success.
    args = [flag, db_path, "--csv", output_dir, "--maps", os.path.abspath(maps_dir)]
    # cwd=output_dir: SQLECmd extracts a 3.4 MB libSQLite.Interop.so into its
    # working directory on every run. Left unset that lands in whatever
    # directory Atlas was started from (it littered the repo checkout); keep the
    # byproduct with the analysis output instead. Args above are absolute so
    # nothing resolves against the changed cwd.
    result = _ez(f"{EZ}/SQLECmd/SQLECmd.dll", args, output_dir=output_dir,
                 timeout=DEFAULT_TIMEOUT, cwd=output_dir)
    return _guard_output(
        result, output_dir, before, "SQLECmd", suffix=".csv",
        hint="SQLECmd only parses databases it has a map for, matched by "
             f"filename against {maps_dir}. An unmapped or renamed database "
             "produces nothing.")


# ── bstrings ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_bstrings(
    target_path: str,
    output_dir: str = "",
    output_file: str = "bstrings.txt",
    min_length: int = 5,
    pattern: Optional[str] = None,
) -> dict:
    """
    Extract strings from a binary file with better filtering than GNU strings.
    target_path: single file to scan (directories are not supported — see below).
    min_length: minimum string length.
    pattern: optional regex to filter results — either a regex or the name of a
    bstrings built-in pattern (b64, cc, bitcoin, bitlocker, ...).

    Output is a plain text file, one hit per line — not CSV.

    Note: bstrings' own -f/-d flags do not scan (they print "input from
    stdin or file" and exit 0), so the file is fed on stdin instead.
    bstrings copies stdin to a temp file, so scanning needs free space
    equal to the target's size. For directory-wide sweeps use
    strings.strings_extract per file instead.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if os.path.isdir(target_path):
        return {
            "success": False,
            "error": f"target_path is a directory: {target_path}",
            "hint": "ez_bstrings takes a single file — bstrings' -d directory "
                    "mode is broken upstream and cannot be fed on stdin. Call "
                    "ez_bstrings once per file, or use strings.strings_extract.",
        }
    if not os.path.isfile(target_path):
        return {"success": False, "error": f"file not found: {target_path}"}

    out_path = os.path.join(output_dir, output_file)
    # bstrings APPENDS to -o instead of truncating, so a re-run would silently
    # duplicate every hit and inflate the count. Clear it first.
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    if os.path.exists(out_path):
        os.remove(out_path)
    # -s keeps the (potentially enormous) hit list off stdout; it still reports
    # the total. -o is bstrings' only output flag — it has no --csv/--csvf.
    args = ["-o", out_path, "-m", str(min_length), "-s"]
    if pattern:
        args += ["--lr", pattern]
    result = _ez(f"{EZ}/bstrings.dll", args, output_dir=output_dir,
                 timeout=scale_timeout(DEFAULT_TIMEOUT, target_path),
                 stdin_path=target_path)

    # bstrings exits 0 even when it never scans anything (broken -f/-d, an
    # unrecognized flag, a usage dump). It always creates -o once a scan really
    # runs — empty on a genuine zero-hit result — so a missing output file means
    # the scan did not happen, not that the evidence is clean.
    if result.get("success") and not os.path.isfile(out_path):
        result["success"] = False
        result["error"] = (
            "bstrings exited 0 but wrote no output file — it did not scan. "
            f"stdout: {(result.get('stdout') or '').strip()[:300]}")
        return result
    if not result.get("success"):
        return result

    with open(out_path, "rb") as fh:
        hits = sum(1 for _ in fh)
    result["output_path"] = out_path
    result["hits"] = hits
    if hits == 0:
        result["note"] = ("bstrings scanned the file and found no matching "
                          "strings — a true zero-hit result, not a failure.")
    return result


# ── RLA (Registry Log Analysis) ──────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_rla(
    hive_path: str,
    output_dir: str = "",
    flatten_names: bool = False,
) -> dict:
    """
    Replay registry transaction logs (.LOG1/.LOG2) into their hives, so later
    parsing sees keys that were still only in the logs at acquisition time.

    hive_path: a single hive, or a directory searched recursively for hives.
      Keep each hive's .LOG1/.LOG2 siblings alongside it — those are the input.

    This tool emits UPDATED HIVE FILES into output_dir, not CSV: it is a
    pre-processing step, not a parser. Feed the returned output_paths to
    ez_recmd_hive / ez_recmd_dir or misc.regripper_hive to actually read them.
    Clean hives are copied through as well, so output_dir holds the full set.

    flatten_names: by default rla encodes each hive's source path into its
      output filename, which is ugly but keeps same-named hives (several users'
      NTUSER.DAT) from overwriting each other. Set True for plain basenames only
      when the input cannot collide.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    if not os.path.exists(hive_path):
        return {"success": False, "error": f"path not found: {hive_path}"}
    assert_output_safe(output_dir)
    _err = _prepare_output_dir(output_dir)
    if _err:
        return _err
    before = _snapshot(output_dir)
    # rla has neither --csv nor --csvf; its output flag is --out and it writes
    # hives. The old --csv/--csvf pair made it print usage, exit 0 and write
    # nothing, which Atlas recorded as a success.
    flag = "-d" if os.path.isdir(hive_path) else "-f"
    args = [flag, hive_path, "--out", output_dir]
    if flatten_names:
        args += ["--nop", "true"]
    result = _ez(f"{EZ}/rla.dll", args, output_dir=output_dir)

    stdout = result.get("stdout") or ""
    # "Hives found: 0" is a real exit-0-with-no-output case, but it means the
    # path held no hives rather than that the tool failed — say which.
    if result.get("success") and "Hives found: 0" in stdout:
        return {**result, "success": False,
                "error": f"rla found no registry hives under {hive_path}",
                "hint": "Point hive_path at the hives themselves (e.g. "
                        "Windows/System32/config, or a user's NTUSER.DAT), with "
                        "their .LOG1/.LOG2 siblings present."}
    result = _guard_output(result, output_dir, before, "rla")
    if not result.get("success"):
        return result
    result["hives_written"] = len(result.get("output_paths", []))
    result["logs_applied"] = stdout.count("At least one transaction log was applied")
    result["hint"] = ("These are hives, not parsed output — read them with "
                      "ez_recmd_hive / ez_recmd_dir or misc.regripper_hive.")
    return result


# ── RecentFileCacheParser ─────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_recentfilecache(
    rfc_path: str,
    output_dir: str = "",
    output_file: str = "recentfilecache.csv",
) -> dict:
    """
    Parse RecentFileCache.bcf — Windows XP/Vista execution artifact.
    rfc_path: path to RecentFileCache.bcf.
    """
    output_dir = output_dir or _case_exports_dir()
    if not output_dir:
        return dict(_NO_OUTPUT_DIR)
    args = ["-f", rfc_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RecentFileCacheParser.dll", args, output_dir=output_dir)
