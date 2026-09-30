"""Anti-forensics detection — surface evidence that the attacker tried to
cover their tracks. Each detector returns a structured candidate finding;
the agent is responsible for calling record_finding (so the gate flow is
preserved).

Coverage:
  af_timestomp_drift       — MFT $SI vs $FN timestamp divergence
  af_event_log_clear       — EID 1102 / 104 in evtxecmd output
  af_sysmon_evasion        — Sysmon service disabled or log truncated
  af_usn_gaps              — DEPRECATED (unsound); use af_usn_journal_deleted
  af_prefetch_deletion     — executables in AppCompat/Amcache with no prefetch
  af_usn_journal_deleted   — $UsnJrnl reset/deleted (MFT $Extend heuristic)
  af_ads_enumeration       — suspicious NTFS alternate data streams
  af_zone_identifier_read  — parse an extracted Zone.Identifier ADS (download provenance)
  af_linux_history_tampering — symlinked/zeroed shell history, HISTFILE neutering
  af_linux_log_tampering   — wtmp/btmp zeroing, non-monotonic logins, cleared auth.log

This module is intentionally read-only: every detector reads tool output
already in the trace or a CSV path on disk and emits findings. None of them
spawn forensic binaries directly — the source data is produced by ez.* or
misc.* tools the agent has already run.
"""
from __future__ import annotations
import csv
import datetime
import os
import re
import shlex
import struct
from typing import Optional
from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("antiforensics")


def _parse_iso(ts: str) -> Optional[datetime.datetime]:
    """Parse an MFTECmd / EvtxECmd ISO-ish timestamp. Returns None on failure."""
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            if fmt is None:
                return datetime.datetime.fromisoformat(s)
            return datetime.datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


# ── file-first CSV discovery ─────────────────────────────────────────────────
# The truncation trap: the execution trace keeps only a 600-char
# `stdout_excerpt` per tool_call, so regexing it for EvtxECmd/PECmd rows misses
# almost everything real. But EZTools always writes a full CSV via
# `--csv <dir> --csvf <file>`, and the trace keeps the *full* command line — so
# the complete output is recoverable from disk. These helpers find and read it,
# preserving lineage back to the producing call_id.

def _discover_csv_from_trace(cmd_markers: list[str]) -> list[tuple[str, int]]:
    """Find CSV outputs of prior EZTools runs whose command matched a marker.

    Parses `--csv <dir>` / `--csvf <file>` out of each matching tool_call's full
    command line. Returns existing `(csv_path, call_id)` pairs, newest call
    first. When only `--csv <dir>` is present (the tool auto-named the file),
    the newest *.csv in that dir is used.
    """
    from core.execution_log import log
    idx = log.index()
    results: list[tuple[str, int]] = []
    for e in idx.by_type.get("tool_call", []):
        cmd = e.get("cmd") or ""
        low = cmd.lower()
        if not any(m.lower() in low for m in cmd_markers):
            continue
        try:
            toks = shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
        csv_dir = csvf = None
        for i, t in enumerate(toks):
            if t == "--csv" and i + 1 < len(toks):
                csv_dir = toks[i + 1]
            elif t == "--csvf" and i + 1 < len(toks):
                csvf = toks[i + 1]
        call_id = int(e.get("call_id") or 0)
        if csv_dir and csvf:
            p = os.path.join(csv_dir, csvf)
            if os.path.exists(p):
                results.append((p, call_id))
        elif csv_dir and os.path.isdir(csv_dir):
            csvs = [os.path.join(csv_dir, p) for p in os.listdir(csv_dir)
                    if p.lower().endswith(".csv")]
            csvs = [p for p in csvs if os.path.exists(p)]
            if csvs:
                newest = max(csvs, key=os.path.getmtime)
                results.append((newest, call_id))
    results.sort(key=lambda pc: -pc[1])
    return results


# Reading a CSV can fail three ways we treat as "unusable input", not a crash:
# an OS error, a malformed-CSV `csv.Error` (e.g. a NUL byte on Python <3.11),
# or a decode error. Detectors catch this tuple, never bare OSError.
_CSV_READ_ERRORS = (OSError, csv.Error, UnicodeError)

# Column sets that let us tell a real EZTools CSV apart from a wrong file passed
# to a *_csv parameter. Each is the set of columns the detector actually reads,
# so passing the check guarantees the detector can find its data.
_RECMD_COLS = ("KeyPath", "ValueName", "ValueData")   # RECmd hive dump
_MFT_COLS = ("EntryNumber", "FileName", "ParentPath")  # MFTECmd $MFT


def _norm_col(name: str) -> str:
    """Normalise a CSV column name for tolerant matching: drop a UTF-8 BOM,
    lowercase, and strip spaces so 'Key Path' == 'KeyPath'."""
    return (name or "").replace("﻿", "").strip().lower().replace(" ", "")


def _csv_format_error(path: str,
                      expected_cols: Optional[tuple[str, ...]] = None) -> Optional[str]:
    """Return a human-readable reason if `path` is not a usable CSV, else None.

    Guards the two ways a wrong file reaches a *_csv parameter:
      1. a binary / UTF-16 / non-CSV *text* file (e.g. a RegRipper `.txt` dump,
         which PowerShell `>` redirection writes as UTF-16) — detected by a NUL
         byte or a UTF-16/32 BOM in the *header line*, where a real UTF-8 CSV
         never has one. NUL bytes buried in later binary fields are legitimate
         in RECmd `ValueData` and are deliberately not examined here — csv
         itself either chokes on them (`csv.Error` on Python <3.11) or silently
         mis-parses (>=3.11) into a zero-hit false negative, so `_CSV_READ_ERRORS`
         still backstops the read;
      2. a text file whose header carries none of the expected columns (checked
         only when `expected_cols` is given, since some producers legitimately
         vary their schema — e.g. usnparser and the various amcache CSVs).
    """
    try:
        with open(path, "rb") as f:
            head = f.read(16384)
    except OSError as e:
        return f"cannot read {os.path.basename(path)}: {e}"
    # Only the header line is inspected: real CSV headers are pure UTF-8 text.
    header_bytes = head.split(b"\n", 1)[0]
    if header_bytes[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in header_bytes:
        return (f"{os.path.basename(path)} is not a text CSV — UTF-16/binary or "
                f"NUL bytes in the header line (e.g. RegRipper .txt output, "
                f"which PowerShell writes as UTF-16), not an EZTools CSV.")
    if expected_cols:
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as f:
                header = next(csv.reader(f), [])
        except _CSV_READ_ERRORS as e:
            return f"failed to read header of {os.path.basename(path)}: {e}"
        have = {_norm_col(h) for h in header}
        if not (have & {_norm_col(c) for c in expected_cols}):
            return (f"{os.path.basename(path)} carries none of the expected "
                    f"columns {list(expected_cols)} (header: {header[:8]}). "
                    f"This is not the EZTools CSV this detector needs.")
    return None


def _resolve_csv(explicit: Optional[str],
                 cmd_markers: list[str],
                 expected_cols: Optional[tuple[str, ...]] = None,
                 ) -> tuple[Optional[str], int, str]:
    """Resolve a detector's input CSV: an explicit path wins; otherwise the
    newest matching EZTools CSV discovered from the trace. Returns
    (csv_path or None, producing call_id, note). For an explicit path we still
    try to recover its producing call_id for lineage.

    An explicit path is validated against `expected_cols` and rejected if it is
    binary/non-CSV or carries none of them — the reason is returned in the note
    as "invalid input: ...". A discovered path is only NUL/binary-guarded (it
    already matched a producing command, so its schema is trusted)."""
    if explicit:
        # The model writes Windows channel names the way Windows spells them
        # ("dc01_Security.csv"); the parser wrote "dc01_security.csv". Every
        # other reader in the tree resolves case-insensitively — this one
        # refused instead, on a detector the run had already asked for twice.
        from core.paths import resolve_path_ci
        resolved, _corrected = resolve_path_ci(os.path.expanduser(explicit))
        if os.path.exists(resolved):
            explicit = resolved
        if not os.path.exists(explicit):
            return None, 0, f"not found: {explicit}"
        bad = _csv_format_error(explicit, expected_cols)
        if bad:
            return None, 0, f"invalid input: {bad}"
        cid = 0
        for p, c in _discover_csv_from_trace(cmd_markers):
            if os.path.realpath(p) == os.path.realpath(explicit):
                cid = c
                break
        return explicit, cid, "explicit"
    for path, cid in _discover_csv_from_trace(cmd_markers):
        if _csv_format_error(path) is None:
            return path, cid, "discovered"
    return None, 0, "no matching CSV in trace"


def _resolve_error(note: str, default: str) -> str:
    """Surface a specific format reason from `_resolve_csv` when present, else
    the detector's generic not-found guidance."""
    marker = "invalid input: "
    return note[len(marker):] if note.startswith(marker) else default


def _csv_rows(path: str):
    """Yield rows from a CSV as dicts; tolerant of encoding issues."""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        yield from csv.DictReader(f)


def _first(row: dict, *names: str) -> str:
    for n in names:
        v = row.get(n)
        if v:
            return str(v).strip()
    return ""


@mcp.tool()
@output_safe
def af_timestomp_drift(
    mft_csv_path: Optional[str] = None,
    threshold_seconds: float = 1.0,
    max_records: int = 200,
) -> dict:
    """
    Detect timestomping by comparing $SI vs $FN timestamps in an MFTECmd CSV.

    A file whose `$STANDARD_INFORMATION` timestamps differ from the
    `$FILE_NAME` (FN) timestamps by more than threshold_seconds is a strong
    indicator the SI timestamps were rewritten with SetFileTime-style APIs.

    mft_csv_path: path to an MFTECmd CSV (`ez.mftecmd` output). If omitted, the
      newest MFTECmd CSV is discovered from the trace.
    threshold_seconds: ignore drifts smaller than this (default 1.0s).
    max_records: cap returned drift_records at this size.
    """
    mft_csv_path, source_call_id, note = _resolve_csv(
        mft_csv_path, ["mftecmd"], _MFT_COLS)
    if mft_csv_path is None:
        return {"success": False,
                "error": _resolve_error(note, "MFT CSV not found — pass "
                         "mft_csv_path or run ez.mftecmd first.")}

    drift_records: list[dict] = []
    total_checked = 0
    try:
        with open(mft_csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            # MFTECmd columns: Created0x10, Created0x30, Modified0x10, Modified0x30,
            # LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30
            for row in reader:
                total_checked += 1
                if total_checked > 1_000_000:
                    break
                # Compare Modified0x10 (SI) vs Modified0x30 (FN) — most common
                # timestomp target.
                si = _parse_iso(row.get("LastModified0x10") or row.get("Modified0x10") or "")
                fn = _parse_iso(row.get("LastModified0x30") or row.get("Modified0x30") or "")
                if si is None or fn is None:
                    continue
                delta = abs((si - fn).total_seconds())
                if delta <= threshold_seconds:
                    continue
                drift_records.append({
                    "path": row.get("ParentPath", "") + "\\" + row.get("FileName", ""),
                    "si_ts": si.isoformat(),
                    "fn_ts": fn.isoformat(),
                    "delta_sec": round(delta, 3),
                    "mft_record": int(row.get("EntryNumber") or row.get("MftRecord") or 0),
                })
                if len(drift_records) >= max_records:
                    break
    except _CSV_READ_ERRORS as e:
        return {"success": False, "error": f"read failed: {e}"}

    return {
        "success": True,
        "total_checked": total_checked,
        "drift_count": len(drift_records),
        "drift_records": drift_records,
        "suggested_finding": (
            {
                "description": (
                    f"Timestomp evidence: {len(drift_records)} MFT records show "
                    f"$SI/$FN drift > {threshold_seconds}s (T1070.006)"
                ),
                "confidence": "LIKELY" if drift_records else "UNCONFIRMED",
                "source": "antiforensics.af_timestomp_drift",
                "linked_call_id": source_call_id,
            }
        ) if drift_records else None,
    }


def _evtx_account(row: dict) -> str:
    """Best-effort clearing account from an EvtxECmd row — UserName column, or
    SubjectUserName / AccountName parsed out of the payload."""
    acct = _first(row, "UserName", "User Name")
    if acct and acct not in ("-", "N/A"):
        return acct
    payload = _first(row, "PayloadData1", "PayloadData2", "PayloadData3",
                     "Payload", "MapDescription")
    m = re.search(r'(?:SubjectUserName|AccountName)["\s:=]+([^",;\s]+)', payload)
    return m.group(1) if m else ""


def _scan_evtx_csv_for_clears(path: str) -> tuple[list[dict], int]:
    """Structured scan of an EvtxECmd CSV for log-clear events. Returns
    (hits, rows_examined). EID 1102 = Security cleared, 104 = System cleared."""
    hits: list[dict] = []
    rows = 0
    for row in _csv_rows(path):
        rows += 1
        eid = _first(row, "EventId", "EventID")
        if eid not in ("1102", "104"):
            continue
        channel = _first(row, "Channel", "ChannelName")
        hits.append({
            "eid": int(eid),
            "log": channel or ("Security" if eid == "1102" else "System"),
            "time": _first(row, "TimeCreated", "TimeCreated UTC"),
            "account": _evtx_account(row),
            "context": _first(row, "MapDescription", "PayloadData1")[:200],
        })
    return hits, rows


@mcp.tool()
@output_safe
def af_event_log_clear(evtx_csv_path: Optional[str] = None) -> dict:
    """
    Detect Windows event-log clearing: EID 1102 (Security log cleared) and
    EID 104 (System log cleared), with the clearing account.

    Reads the full EvtxECmd CSV (structured columns) rather than the truncated
    trace excerpt. Resolution order:
      1. evtx_csv_path if given;
      2. else the newest EvtxECmd CSV discovered from the trace
         (`--csv/--csvf` of a prior `ez.evtxecmd` run);
      3. else a best-effort regex over the trace's 600-char stdout excerpt
         (legacy fallback; `data_source: "trace_excerpt"`).

    evtx_csv_path: optional path to an EvtxECmd CSV (Security/System channels).
    """
    csv_path, call_id, note = _resolve_csv(evtx_csv_path, ["evtxecmd"])
    if evtx_csv_path and csv_path is None:
        return {"success": False,
                "error": _resolve_error(note, f"EvtxECmd CSV not found: {evtx_csv_path}")}

    if csv_path:
        try:
            hits, rows = _scan_evtx_csv_for_clears(csv_path)
        except _CSV_READ_ERRORS as e:
            return {"success": False, "error": f"read failed: {e}"}
        data_source, linked = "csv", call_id
        events_examined = rows
    else:
        # Legacy fallback: regex the truncated stdout excerpt in the trace.
        from core.execution_log import log
        idx = log.index()
        candidates = [e for e in idx.by_type.get("tool_call", [])
                      if "evtxecmd" in (e.get("cmd") or "").lower()]
        if not candidates:
            return {
                "success": False,
                "error": "No EvtxECmd CSV or run found in trace. Parse the "
                         "Security/System event logs first (ez.evtxecmd), or "
                         "pass evtx_csv_path.",
            }
        EID_RE = re.compile(
            r"(?:\b|,)(?:EventID|Event\s*ID)\s*[:=,\s]*(1102|104)\b", re.IGNORECASE)
        hits = []
        for c in candidates:
            excerpt = c.get("stdout_excerpt", "") or ""
            for m in EID_RE.finditer(excerpt):
                eid = int(m.group(1))
                hits.append({
                    "eid": eid,
                    "log": "Security" if eid == 1102 else "System",
                    "time": "", "account": "",
                    "context": _line_around(excerpt, m.start()),
                    "source_call_id": c.get("call_id"),
                })
        data_source = "trace_excerpt"
        linked = hits[0]["source_call_id"] if hits else 0
        events_examined = sum(
            len((c.get("stdout_excerpt") or "").splitlines()) for c in candidates)

    return {
        "success": True,
        "data_source": data_source,
        "csv_path": csv_path or "",
        "events_examined": events_examined,
        "clear_events_found": len(hits),
        "events": hits,
        "suggested_finding": (
            {
                "description": (
                    f"Windows event-log clearing detected ({len(hits)} clear "
                    f"event(s); T1070.001) — adversary removed audit trail"
                    + (f"; cleared by {hits[0]['account']}"
                       if hits and hits[0].get("account") else "")
                ),
                "confidence": "CONFIRMED" if hits else "UNCONFIRMED",
                "source": "antiforensics.af_event_log_clear",
                "linked_call_id": linked,
            }
        ) if hits else None,
    }


def _line_around(text: str, pos: int, span: int = 120) -> str:
    start = max(0, text.rfind("\n", 0, pos) + 1)
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end][:span]


@mcp.tool()
@output_safe
def af_sysmon_evasion(system_hive_csv: Optional[str] = None) -> dict:
    """
    Parse a SYSTEM hive (RECmd CSV) and flag Sysmon-evasion indicators.

    Checks (any Sysmon-keyed service or the SysmonDrv driver):
      - `Start` value >= 4 (disabled)
      - Sysmon `EventLog` MaxSize clamped to < 100 KB

    system_hive_csv: path to RECmd CSV of SYSTEM hive (one row per value). If
      omitted, the newest RECmd CSV is discovered from the trace.
    """
    system_hive_csv, source_call_id, note = _resolve_csv(
        system_hive_csv, ["recmd"], _RECMD_COLS)
    if system_hive_csv is None:
        return {"success": False,
                "error": _resolve_error(note, "SYSTEM hive CSV not found — pass "
                         "system_hive_csv or run ez.recmd on the SYSTEM hive "
                         "first.")}

    indicators: list[dict] = []
    try:
        with open(system_hive_csv, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row.get("KeyPath") or row.get("Key Path") or "").lower()
                value = (row.get("ValueName") or row.get("Value Name") or "").lower()
                data = (row.get("ValueData") or row.get("Value Data") or "").strip()
                if "sysmon" in key:
                    if value == "start":
                        try:
                            start_val = int(data, 0) if data else None
                        except ValueError:
                            start_val = None
                        if start_val is not None and start_val >= 4:
                            indicators.append({
                                "key": key, "value": value, "data": data,
                                "issue": "Sysmon service Start=4 (disabled)",
                            })
                if "microsoft-windows-sysmon" in key and "operational" in key:
                    if value == "maxsize":
                        try:
                            ms = int(data, 0) if data else None
                        except ValueError:
                            ms = None
                        if ms is not None and ms < 100 * 1024:
                            indicators.append({
                                "key": key, "value": value, "data": data,
                                "issue": f"Sysmon log MaxSize clamped to {ms} bytes",
                            })
    except _CSV_READ_ERRORS as e:
        return {"success": False, "error": f"read failed: {e}"}

    return {
        "success": True,
        "indicators": indicators,
        "suggested_finding": (
            {
                "description": (
                    f"Sysmon evasion indicators in SYSTEM hive ({len(indicators)} "
                    f"hits; T1562.001) — adversary disabled or hobbled telemetry"
                ),
                "confidence": "LIKELY" if indicators else "UNCONFIRMED",
                "source": "antiforensics.af_sysmon_evasion",
                "linked_call_id": source_call_id,
            }
        ) if indicators else None,
    }


@mcp.tool()
@output_safe
def af_usn_gaps(usn_csv_path: Optional[str] = None, gap_threshold: int = 100) -> dict:
    """
    DEPRECATED — retired detector. Use `af_usn_journal_deleted` instead.

    This tried to infer selective USN-journal pruning from gaps in the sorted
    USN offsets. It is retired for two independent reasons:

      1. No usable data source. The wired usnparser (usn.py) never emits the USN
         offset in any mode — its --csv writes only
         `timestamp,filename,fileattr,reason` — so the detector could never run
         on Atlas's own output.
      2. The heuristic is unsound even with correct data. A USN *is* the byte
         offset of the record within `$UsnJrnl:$J`, so consecutive records
         differ by their record length (~60–250 bytes, routinely above the old
         threshold) and Windows trims the sparse `$J` front as normal
         maintenance. Sorted-offset deltas cannot separate adversarial deletion
         from normal record spacing / trimming (high false positives), while
         real journal wipers either reset the journal wholesale (caught soundly
         by `af_usn_journal_deleted`, T1070.004) or delete in ways offset deltas
         never see (high false negatives).

    For journal tampering use `af_usn_journal_deleted` backed by timeline
    analysis. Both parameters are accepted for signature stability but ignored.
    """
    return {
        "success": False,
        "deprecated": True,
        "replacement": "antiforensics.af_usn_journal_deleted",
        "error": (
            "af_usn_gaps is deprecated and no longer computes gaps: the wired "
            "usnparser emits no USN offset column, and the sorted-offset-delta "
            "heuristic is unsound (a USN is a byte offset, so normal record "
            "spacing and routine $J trimming look like gaps). Use "
            "af_usn_journal_deleted for USN journal tampering (T1070.004), "
            "backed by timeline analysis."
        ),
    }


_SYS_EXE_NOISE = {"explorer.exe", "wininit.exe", "svchost.exe", "system",
                  "services.exe", "lsass.exe", "csrss.exe", "smss.exe",
                  "winlogon.exe", "taskhostw.exe", "dllhost.exe"}


def _exe_basename(val: str) -> str:
    return os.path.basename(val.replace("\\", "/")).strip().lower()


@mcp.tool()
@output_safe
def af_prefetch_deletion(
    pecmd_csv_path: Optional[str] = None,
    appcompat_csv_path: Optional[str] = None,
    amcache_csv_path: Optional[str] = None,
) -> dict:
    """
    Detect prefetch deletion by cross-referencing executed binaries
    (AppCompat/Amcache) against prefetch files (PECmd). An executable that ran
    but has NO `.pf` is a deletion candidate — Windows creates a prefetch file
    for nearly every user-mode launch (T1070.005).

    Reads the full EZTools CSVs (structured columns) rather than the truncated
    trace excerpt. Each CSV resolves: explicit path → newest discovered from
    the trace. Falls back to the legacy excerpt regex only when no CSV is
    available (`data_source: "trace_excerpt"`).

    pecmd_csv_path:     PECmd CSV (prefetch). appcompat_csv_path: AppCompatCache
    CSV. amcache_csv_path: Amcache CSV. Any omitted path is discovered.
    """
    pf_path, pf_cid, _ = _resolve_csv(pecmd_csv_path, ["pecmd"])
    ac_path, ac_cid, _ = _resolve_csv(appcompat_csv_path, ["appcompatcacheparser"])
    am_path, am_cid, _ = _resolve_csv(amcache_csv_path, ["amcacheparser"])

    if pf_path and (ac_path or am_path):
        # ── file-first path ──
        prefetched: set[str] = set()
        try:
            for row in _csv_rows(pf_path):
                name = _first(row, "ExecutableName", "SourceFilename")
                if name:
                    prefetched.add(_exe_basename(name))
            executed: list[tuple[str, int]] = []
            if ac_path:
                for row in _csv_rows(ac_path):
                    p = _first(row, "Path")
                    if p:
                        executed.append((_exe_basename(p), ac_cid))
            if am_path:
                for row in _csv_rows(am_path):
                    p = _first(row, "FullPath", "ApplicationName", "Name")
                    if p:
                        executed.append((_exe_basename(p), am_cid))
        except _CSV_READ_ERRORS as e:
            return {"success": False, "error": f"read failed: {e}"}
        data_source = "csv"
    else:
        # ── legacy fallback: regex the truncated stdout excerpts ──
        from core.execution_log import log
        idx = log.index()
        pecmd_e, ac_e, am_e = [], [], []
        for e in idx.by_type.get("tool_call", []):
            cmd = (e.get("cmd") or "").lower()
            if "pecmd" in cmd:
                pecmd_e.append(e)
            if "appcompatcacheparser" in cmd:
                ac_e.append(e)
            if "amcacheparser" in cmd:
                am_e.append(e)
        if not pecmd_e:
            return {"success": False,
                    "error": "No PECmd CSV or run found. Parse prefetch first "
                             "(ez.pecmd), or pass pecmd_csv_path."}
        if not (ac_e or am_e):
            return {"success": False,
                    "error": "No appcompat/amcache CSV or run found to "
                             "cross-reference against prefetch."}
        prefetched = set()
        for e in pecmd_e:
            for m in re.finditer(r"([A-Za-z0-9_.\-]+\.[Ee][Xx][Ee])",
                                 e.get("stdout_excerpt", "") or ""):
                prefetched.add(m.group(1).lower())
        executed = []
        for e in ac_e + am_e:
            for m in re.finditer(r"([A-Za-z0-9_.\-]+\.[Ee][Xx][Ee])",
                                 e.get("stdout_excerpt", "") or ""):
                executed.append((m.group(1).lower(), e.get("call_id") or 0))
        data_source = "trace_excerpt"

    deletion_candidates: list[dict] = []
    seen: set[str] = set()
    for exe, source_cid in executed:
        if exe in seen or exe in prefetched or exe in _SYS_EXE_NOISE:
            continue
        deletion_candidates.append({
            "path": exe,
            "appcompat_call_id": source_cid,
            "prefetch_absent": True,
        })
        seen.add(exe)
        if len(deletion_candidates) >= 50:
            break

    linked = deletion_candidates[0]["appcompat_call_id"] if deletion_candidates else 0
    return {
        "success": True,
        "data_source": data_source,
        "prefetched_count": len(prefetched),
        "executed_count": len({e[0] for e in executed}),
        "deletion_candidates": deletion_candidates,
        "cross_ref_complete": True,
        "suggested_finding": (
            {
                "description": (
                    f"Prefetch deletion suspected ({len(deletion_candidates)} "
                    f"executable(s) ran but have no prefetch file; T1070.005)"
                ),
                "confidence": "SUSPECTED" if deletion_candidates else "UNCONFIRMED",
                "source": "antiforensics.af_prefetch_deletion",
                "linked_call_id": linked,
            }
        ) if deletion_candidates else None,
    }


def _bool_col(row: dict, *names: str) -> Optional[bool]:
    """Read a boolean-ish MFTECmd column ('True'/'False'/1/0). None if absent."""
    v = _first(row, *names)
    if not v:
        return None
    return v.strip().lower() in ("true", "1", "yes")


@mcp.tool()
@output_safe
def af_usn_journal_deleted(mft_csv_path: Optional[str] = None) -> dict:
    """
    Detect a deleted / reset USN change journal from an MFTECmd $MFT CSV.

    The journal lives at ``\\$Extend\\$UsnJrnl`` with the change data in its
    ``$J`` data stream. When an attacker runs ``fsutil usn deletejournal`` (or
    reformats the journal) the $UsnJrnl entry is dropped or marked not-in-use
    while its siblings under ``$Extend`` (``$Quota``, ``$ObjId``, ``$Reparse``)
    remain — a strong journal-reset tell. Absence-based, so SUSPECTED tier.
    Maps to T1070.004 (File Deletion / journal tampering).

    mft_csv_path: MFTECmd CSV (`ez.mftecmd` output). If omitted, the newest
      mftecmd CSV is discovered from the trace.
    """
    mft_csv_path, source_call_id, note = _resolve_csv(
        mft_csv_path, ["mftecmd"], _MFT_COLS)
    if mft_csv_path is None:
        return {"success": False,
                "error": _resolve_error(note, "MFT CSV not found — pass "
                         "mft_csv_path or run ez.mftecmd first.")}

    extend_siblings: list[str] = []
    usnjrnl_present = False
    usnjrnl_in_use = None
    usnjrnl_j_size = None
    try:
        for row in _csv_rows(mft_csv_path):
            parent = _first(row, "ParentPath", "Parent Path")
            name = _first(row, "FileName", "File Name")
            if "$Extend" not in parent and name != "$Extend":
                continue
            if name.startswith("$UsnJrnl"):
                usnjrnl_present = True
                in_use = _bool_col(row, "InUse", "In Use")
                if in_use is not None:
                    usnjrnl_in_use = in_use
                # The $J stream carries the journal; a 0-byte $J is a reset.
                if ":$J" in name or name == "$UsnJrnl:$J":
                    sz = _first(row, "FileSize", "File Size")
                    try:
                        usnjrnl_j_size = int(float(sz)) if sz else None
                    except (TypeError, ValueError):
                        usnjrnl_j_size = None
            elif name and name not in ("$Extend", "."):
                extend_siblings.append(name)
    except _CSV_READ_ERRORS as e:
        return {"success": False, "error": f"read failed: {e}"}

    # Journal-reset heuristics, in decreasing strength.
    reset = False
    reason = ""
    if extend_siblings and not usnjrnl_present:
        reset, reason = True, "$Extend present but $UsnJrnl entry missing"
    elif usnjrnl_present and usnjrnl_in_use is False:
        reset, reason = True, "$UsnJrnl present but marked not-in-use"
    elif usnjrnl_present and usnjrnl_j_size == 0:
        reset, reason = True, "$UsnJrnl:$J change stream is 0 bytes"

    return {
        "success": True,
        "usnjrnl_present": usnjrnl_present,
        "usnjrnl_in_use": usnjrnl_in_use,
        "usnjrnl_j_size": usnjrnl_j_size,
        "extend_sibling_count": len(extend_siblings),
        "reset_reason": reason,
        "suggested_finding": (
            {
                "description": (
                    f"USN change journal reset/deleted ({reason}; T1070.004) — "
                    f"file-activity history destroyed while other $Extend "
                    f"metadata records survive"
                ),
                "confidence": "SUSPECTED",
                "source": "antiforensics.af_usn_journal_deleted",
                "linked_call_id": source_call_id,
            }
        ) if reset else None,
    }


# Alternate-data-stream names that are benign OS/browser noise, not hiding.
_BENIGN_ADS = {
    "zone.identifier", "smartscreen", "$data", "wofcompresseddata",
    "favicon", "encryptable", "openmetadata", "kavicheckedstream",
    "ms-properties", "com.dropbox.attrs", "com.apple.quarantine",
}
_ADS_EXEC_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
                 ".scr", ".js", ".jse", ".hta", ".com", ".pif", ".sys")


@mcp.tool()
@output_safe
def af_ads_enumeration(mft_csv_path: Optional[str] = None) -> dict:
    """
    Enumerate suspicious NTFS Alternate Data Streams from an MFTECmd $MFT CSV.

    Attackers hide payloads in ADS (``file.txt:evil.exe``) to keep them off a
    normal directory listing. MFTECmd flags streams via the ``IsAds`` /
    ``HasAds`` columns; this filters out benign OS/browser streams
    (Zone.Identifier, SmartScreen, …) and flags executable-ish or otherwise
    non-benign streams. CSV-only. Maps to T1564.004 (Hide Artifacts: NTFS ADS).

    A Zone.Identifier stream is benign (every browser download gets one) but
    not useless — its content (HostUrl/ReferrerUrl) is the actual "downloaded
    from this URL" evidence, just not read here. Files that carry one are
    listed separately in ``zone_identifier_streams``; extract each with
    tsk.tsk_icat (this file's MFT entry number, ADS name after the colon)
    and read it with af_zone_identifier_read.

    mft_csv_path: MFTECmd CSV (`ez.mftecmd` output). If omitted, discovered
      from the trace.
    """
    mft_csv_path, source_call_id, note = _resolve_csv(
        mft_csv_path, ["mftecmd"], _MFT_COLS)
    if mft_csv_path is None:
        return {"success": False,
                "error": _resolve_error(note, "MFT CSV not found — pass "
                         "mft_csv_path or run ez.mftecmd first.")}

    suspicious: list[dict] = []
    zone_identifier_streams: list[dict] = []
    total_ads = 0
    try:
        for row in _csv_rows(mft_csv_path):
            is_ads = _bool_col(row, "IsAds", "Is Ads")
            name = _first(row, "FileName", "File Name")
            # An ADS row's FileName carries the stream after a colon.
            if not is_ads and ":" not in name:
                continue
            if ":" not in name:
                continue
            total_ads += 1
            stream = name.split(":", 1)[1].strip().lower()
            parent = _first(row, "ParentPath", "Parent Path")
            if stream == "zone.identifier" and len(zone_identifier_streams) < 100:
                zone_identifier_streams.append({
                    "path": f"{parent}\\{name}" if parent else name,
                    "entry_number": _first(row, "EntryNumber", "Entry Number"),
                })
            if not stream or stream in _BENIGN_ADS:
                continue
            exec_like = stream.endswith(_ADS_EXEC_EXT)
            suspicious.append({
                "path": f"{parent}\\{name}" if parent else name,
                "stream": stream,
                "executable_like": exec_like,
                "size": _first(row, "FileSize", "File Size"),
            })
            if len(suspicious) >= 100:
                break
    except _CSV_READ_ERRORS as e:
        return {"success": False, "error": f"read failed: {e}"}

    exec_hits = [s for s in suspicious if s["executable_like"]]
    return {
        "success": True,
        "total_ads_streams": total_ads,
        "suspicious_count": len(suspicious),
        "executable_ads_count": len(exec_hits),
        "suspicious_streams": suspicious,
        "zone_identifier_streams": zone_identifier_streams,
        "suggested_finding": (
            {
                "description": (
                    f"Suspicious NTFS alternate data stream(s) "
                    f"({len(suspicious)} non-benign, {len(exec_hits)} "
                    f"executable-like; T1564.004) — possible payload hiding"
                ),
                # Executable-like ADS is a stronger tell than a stray stream.
                "confidence": "LIKELY" if exec_hits else "SUSPECTED",
                "source": "antiforensics.af_ads_enumeration",
                "linked_call_id": source_call_id,
            }
        ) if suspicious else None,
    }


_ZONE_MEANING = {
    "0": "Local Machine", "1": "Local Intranet",
    "2": "Trusted Sites", "3": "Internet", "4": "Restricted Sites",
}


@mcp.tool()
@output_safe
def af_zone_identifier_read(stream_path: str) -> dict:
    """
    Parse an already-extracted NTFS Zone.Identifier alternate-data-stream.

    Windows tags every file downloaded through a browser/mail client with a
    Zone.Identifier ADS; af_ads_enumeration finds which files carry one but,
    correctly, treats it as benign noise rather than suspicious. This reads
    its content — the [ZoneTransfer] section's HostUrl/ReferrerUrl — which is
    the actual "this file was downloaded from this URL" evidence a phishing
    case needs. Extract the stream first (e.g. tsk.tsk_icat with the file's
    MFT entry number and the ADS name, as 'entry-stream' addressing); this
    tool only reads the already-extracted bytes, per this module's read-only
    contract.

    stream_path: path to the extracted Zone.Identifier stream content.
    """
    import configparser

    try:
        with open(stream_path, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        return {"success": False, "error": f"read failed: {e}"}

    cp = configparser.ConfigParser()
    try:
        cp.read_string(raw)
    except configparser.Error as e:
        return {"success": False,
                "error": f"not a valid Zone.Identifier stream: {e}"}
    if not cp.has_section("ZoneTransfer"):
        return {"success": False,
                "error": "no [ZoneTransfer] section found — not a "
                         "Zone.Identifier stream"}

    zt = cp["ZoneTransfer"]
    zone_id = zt.get("ZoneId")
    return {
        "success": True,
        "zone_id": zone_id,
        "zone_meaning": _ZONE_MEANING.get(zone_id, "unknown"),
        "host_url": zt.get("HostUrl"),
        "referrer_url": zt.get("ReferrerUrl"),
    }


# ── Linux log / history tampering (evidence-mount, read-only) ────────────────

_SHELL_HISTORY_FILES = (
    ".bash_history", ".zsh_history", ".sh_history", ".ksh_history",
    ".python_history", ".mysql_history", ".psql_history", ".node_repl_history",
)
_SHELL_RC_FILES = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv")
# rc-file lines that neuter shell history.
_HISTFILE_TAMPER = re.compile(
    r"(?im)^\s*(?:export\s+)?(?:"
    r"HISTFILE\s*=\s*/dev/null|"
    r"unset\s+HISTFILE|"
    r"HISTFILESIZE\s*=\s*0|"
    r"HISTSIZE\s*=\s*0|"
    r"set\s+\+o\s+history|"
    r"HISTFILE\s*=\s*$"
    r")"
)


def _home_dirs(mount_root: str) -> list[tuple[str, str]]:
    """(user, home_path) pairs under a mounted root: /root plus /home/*."""
    homes: list[tuple[str, str]] = []
    root_home = os.path.join(mount_root, "root")
    if os.path.isdir(root_home):
        homes.append(("root", root_home))
    home_base = os.path.join(mount_root, "home")
    if os.path.isdir(home_base):
        try:
            for entry in sorted(os.listdir(home_base)):
                p = os.path.join(home_base, entry)
                if os.path.isdir(p):
                    homes.append((entry, p))
        except OSError:
            pass
    return homes


@mcp.tool()
@output_safe
def af_linux_history_tampering(mount_root: str) -> dict:
    """
    Detect shell-history tampering on a mounted Linux filesystem.

    Read-only over ``mount_root`` (an ``ewf.*`` / ``img.*`` mount point). Flags
    the classic history-hiding tricks: a history file symlinked to /dev/null, a
    zeroed (0-byte) history file, and HISTFILE/HISTSIZE neutering in shell rc
    files (``HISTFILE=/dev/null``, ``unset HISTFILE``, ``HISTSIZE=0``, …).
    Maps to T1070.003 (Clear Command History).

    mount_root: filesystem root of the mounted evidence (e.g. an ewf mount).
    """
    if not mount_root or not os.path.isdir(mount_root):
        return {"success": False,
                "error": f"mount_root not a directory: {mount_root!r}"}

    indicators: list[dict] = []
    for user, home in _home_dirs(mount_root):
        for hist in _SHELL_HISTORY_FILES:
            hp = os.path.join(home, hist)
            try:
                if os.path.islink(hp):
                    target = os.readlink(hp)
                    indicators.append({"user": user, "path": hp, "file": hist,
                                       "issue": "symlinked", "detail": target})
                elif os.path.isfile(hp) and os.path.getsize(hp) == 0:
                    indicators.append({"user": user, "path": hp, "file": hist,
                                       "issue": "zeroed", "detail": "0 bytes"})
            except OSError:
                continue
        for rc in _SHELL_RC_FILES:
            rp = os.path.join(home, rc)
            if not os.path.isfile(rp):
                continue
            try:
                with open(rp, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            for m in _HISTFILE_TAMPER.finditer(text):
                indicators.append({"user": user, "path": rp, "file": rc,
                                   "issue": "histfile_tamper",
                                   "detail": m.group(0).strip()})

    # Symlinked / rc-tamper are deliberate; zeroed alone is weaker.
    strong = [i for i in indicators
              if i["issue"] in ("symlinked", "histfile_tamper")]
    return {
        "success": True,
        "homes_examined": len(_home_dirs(mount_root)),
        "indicator_count": len(indicators),
        "indicators": indicators,
        "suggested_finding": (
            {
                "description": (
                    f"Shell-history tampering ({len(indicators)} indicator(s): "
                    f"{', '.join(sorted({i['issue'] for i in indicators}))}; "
                    f"T1070.003)"
                ),
                "confidence": "LIKELY" if strong else "SUSPECTED",
                "source": "antiforensics.af_linux_history_tampering",
                "linked_call_id": 0,
                "evidence_paths": [i["path"] for i in indicators[:20]],
            }
        ) if indicators else None,
    }


# glibc utmp/wtmp record on x86_64 is a fixed 384 bytes. This layout is the
# LP64 struct utmp; 32-bit or big-endian images would need a different format,
# so we bail on a size mismatch rather than emit garbage.
_UTMP_RECORD_SIZE = 384
_UTMP_FMT = "<hxxi32s4s32s256shhiii16s20s"
_UTMP_LOGS = ("var/log/wtmp", "var/log/btmp")
_UTMP_ZERO = b"\x00" * _UTMP_RECORD_SIZE


def _parse_utmp(data: bytes) -> list[dict]:
    """Parse utmp/wtmp bytes into records. Assumes glibc x86_64 layout."""
    records: list[dict] = []
    n = len(data) // _UTMP_RECORD_SIZE
    for i in range(n):
        chunk = data[i * _UTMP_RECORD_SIZE:(i + 1) * _UTMP_RECORD_SIZE]
        if chunk == _UTMP_ZERO:
            records.append({"zero": True, "ut_type": 0, "tv_sec": 0, "user": ""})
            continue
        try:
            f = struct.unpack(_UTMP_FMT, chunk)
        except struct.error:
            continue
        records.append({
            "zero": False,
            "ut_type": f[0],
            "user": f[4].split(b"\x00", 1)[0].decode("latin-1", "replace"),
            "tv_sec": f[9],
        })
    return records


@mcp.tool()
@output_safe
def af_linux_log_tampering(mount_root: str) -> dict:
    """
    Detect login-log (wtmp/btmp) and auth.log tampering on a mounted Linux FS.

    Read-only over ``mount_root``. For each utmp-format log it (a) bails with a
    noted anomaly when the file size is not a multiple of the 384-byte glibc
    x86_64 record — a truncation/corruption tell — (b) flags all-zero records
    embedded before later non-zero records (selective wiping), and (c) counts
    non-monotonic timestamps (wtmp is append-only chronological, so a backwards
    jump implies reordering/insertion). Also flags a present-but-empty
    ``/var/log/auth.log`` (logs cleared). Maps to T1070.002 (Clear Linux Logs).

    mount_root: filesystem root of the mounted evidence.
    """
    if not mount_root or not os.path.isdir(mount_root):
        return {"success": False,
                "error": f"mount_root not a directory: {mount_root!r}"}

    per_log: list[dict] = []
    anomalies: list[str] = []
    for rel in _UTMP_LOGS:
        path = os.path.join(mount_root, rel)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue

        size_mismatch = (size % _UTMP_RECORD_SIZE) != 0
        recs = _parse_utmp(data)

        # Embedded zero records: an all-zero record with a non-zero record after
        # it (trailing zero padding alone is normal and ignored).
        embedded_zero = 0
        last_nonzero_idx = max((i for i, r in enumerate(recs) if not r["zero"]),
                               default=-1)
        for i, r in enumerate(recs):
            if r["zero"] and i < last_nonzero_idx:
                embedded_zero += 1

        # Non-monotonic timestamps among real, non-zero records.
        inversions = 0
        prev = None
        for r in recs:
            if r["zero"] or r["tv_sec"] <= 0:
                continue
            if prev is not None and r["tv_sec"] < prev:
                inversions += 1
            prev = r["tv_sec"]

        info = {
            "log": rel,
            "size": size,
            "records": len(recs),
            "size_mismatch": size_mismatch,
            "embedded_zero_records": embedded_zero,
            "timestamp_inversions": inversions,
        }
        per_log.append(info)
        if size_mismatch:
            anomalies.append(f"{rel}: size not a multiple of {_UTMP_RECORD_SIZE} "
                             f"(truncation/corruption)")
        if embedded_zero:
            anomalies.append(f"{rel}: {embedded_zero} embedded all-zero record(s) "
                             f"(selective wipe)")
        if inversions:
            anomalies.append(f"{rel}: {inversions} non-monotonic timestamp(s) "
                             f"(reordering/insertion)")

    # auth.log present but empty → logs cleared.
    for rel in ("var/log/auth.log", "var/log/secure"):
        ap = os.path.join(mount_root, rel)
        try:
            if os.path.isfile(ap) and os.path.getsize(ap) == 0:
                anomalies.append(f"{rel}: present but empty (logs cleared)")
        except OSError:
            continue

    return {
        "success": True,
        "logs_examined": len(per_log),
        "per_log": per_log,
        "anomalies": anomalies,
        "suggested_finding": (
            {
                "description": (
                    f"Login/auth log tampering ({len(anomalies)} anomaly(ies): "
                    f"{'; '.join(anomalies[:4])}; T1070.002)"
                ),
                "confidence": "SUSPECTED",
                "source": "antiforensics.af_linux_log_tampering",
                "linked_call_id": 0,
                "evidence_paths": [os.path.join(mount_root, r["log"])
                                   for r in per_log],
            }
        ) if anomalies else None,
    }
