"""Structured auth.* events from EvtxECmd / tabular authentication exports.

Primary path for Claim Graph auth observations when CSV columns are available.
Text extraction in ``auth_events`` remains the fallback for unstructured spills.

Column aliases cover EvtxECmd maps, Chainsaw exports, and MDE DeviceLogonEvents
shapes — not case-specific filenames or IOCs.
"""
from __future__ import annotations

import csv
import os
import re
from typing import Any, Iterable, Optional

from core.auth_events import AuthEvent, is_ignorable_endpoint
from core.auth_ontology import (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    classify_windows_eid,
)

# Cap rows scanned per file (full Security.evtx exports are huge; fingerprints
# still collapse duplicates — this bounds worst-case parse time).
_MAX_ROWS = 80_000

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DATE_RE = re.compile(r"(?<!\d)(\d{4})[-/](\d{1,2})[-/](\d{1,2})")
_LOGON_TYPE_RE = re.compile(
    r"(?:logon\s*type|logontype)[\"'\s:=/-]{0,6}(\d{1,2})",
    re.IGNORECASE,
)

_EID_COLS = (
    "EventId", "EventID", "Event ID", "event_id", "Event Id",
    "deviceEventId", "qidEventId",
)
_WHEN_COLS = (
    "TimeCreated", "Timestamp", "timestamp", "Time", "DateTime",
    "startDateTime", "timecreated",
)
_ENDPOINT_COLS = (
    "RemoteHost", "IP Address", "IpAddress", "RemoteIP", "Remote IP",
    "Source Network Address", "SourceNetworkAddress", "ClientAddress",
    "src_ip", "source_ip", "Ip Address",
)
_FACTOR_COLS = (
    "PayloadData2", "Logon Type", "LogonType", "logon_type", "Logon type",
)
_ACTION_COLS = ("ActionType", "MapDescription", "detections", "Action")
_SUCCESS_ACTION_RE = re.compile(
    r"(?i)logonsuccess|successful\s+logon|network\s+logon|accepted",
)
_FAILURE_ACTION_RE = re.compile(
    r"(?i)logonfailure|failed\s+logon|logon\s+fail",
)


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (k or "").lstrip("\ufeff").lower())


def _row_get(row: dict[str, Any], aliases: tuple[str, ...]) -> str:
    if not row:
        return ""
    # Exact then normalized match.
    for a in aliases:
        if a in row and str(row.get(a) or "").strip():
            return str(row.get(a) or "").strip()
    norm_map = {_norm_key(k): k for k in row.keys()}
    for a in aliases:
        k = norm_map.get(_norm_key(a))
        if k and str(row.get(k) or "").strip():
            return str(row.get(k) or "").strip()
    return ""


def _endpoint_from_value(raw: str) -> str:
    if not raw or raw in {"-", "—", "N/A", "n/a"}:
        return ""
    # EvtxECmd RemoteHost: "- (10.0.0.5)" or "HOST (10.0.0.1)"
    m = re.search(r"\(([^)]+)\)", raw)
    candidate = (m.group(1) if m else raw).strip()
    if candidate in {"-", "—"}:
        return ""
    ip = _IPV4_RE.search(candidate) or _IPV4_RE.search(raw)
    if ip:
        return ip.group(0)
    # Hostname-only remote (rare in EvtxECmd maps) — keep if looks like a host.
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,63}", candidate):
        return candidate
    return ""


def _when_from_value(raw: str) -> str:
    if not raw:
        return ""
    # "Feb 4, 2031 12:05:00 PM" — best-effort year-month-day elsewhere
    m = _DATE_RE.search(raw.replace(",", " "))
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return f"{y:04d}-{mo:02d}-{d:02d}"
    # Month name forms: Feb 4, 2031
    m2 = re.search(
        r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+"
        r"(\d{1,2}),?\s+(\d{4})\b",
        raw, re.IGNORECASE,
    )
    if m2:
        months = {
            "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
        }
        mo = months[m2.group(1)[:3].lower()]
        return f"{int(m2.group(3)):04d}-{mo:02d}-{int(m2.group(2)):02d}"
    return ""


def _factor_from_value(raw: str) -> str:
    if not raw:
        return ""
    m = _LOGON_TYPE_RE.search(raw)
    if m:
        return m.group(1)
    if re.fullmatch(r"\d{1,2}", raw.strip()):
        return raw.strip()
    return ""


def _class_from_row(row: dict[str, Any]) -> Optional[str]:
    eid = _row_get(row, _EID_COLS)
    cls = classify_windows_eid(eid) if eid else None
    if cls:
        return cls
    action = _row_get(row, _ACTION_COLS)
    if action:
        if _SUCCESS_ACTION_RE.search(action):
            return EVENT_AUTH_SUCCESS
        if _FAILURE_ACTION_RE.search(action):
            return EVENT_AUTH_FAILURE
    return None


def row_to_auth_event(
    row: dict[str, Any],
    *,
    call_id: Optional[int] = None,
    tool: str = "",
    platform: str = "windows",
) -> Optional[AuthEvent]:
    event_class = _class_from_row(row)
    if not event_class:
        return None
    endpoint = _endpoint_from_value(_row_get(row, _ENDPOINT_COLS))
    if is_ignorable_endpoint(endpoint) or not endpoint:
        return None
    when = _when_from_value(_row_get(row, _WHEN_COLS))
    factor = _factor_from_value(_row_get(row, _FACTOR_COLS))
    eid = _row_get(row, _EID_COLS)
    snippet = " ".join(
        p for p in (
            f"EID {eid}" if eid else "",
            f"from {endpoint}",
            f"on {when}" if when else "",
            f"type {factor}" if factor else "",
        ) if p
    )
    return AuthEvent(
        event_class=event_class,
        source_endpoint=endpoint,
        when=when,
        auth_factor=factor,
        platform=platform,
        source_call_id=call_id,
        tool=tool,
        snippet=snippet[:200],
    )


def extract_auth_events_from_csv(
    path: str | os.PathLike,
    *,
    call_id: Optional[int] = None,
    tool: str = "",
    max_rows: int = _MAX_ROWS,
) -> list[AuthEvent]:
    """Parse a tabular auth export into distinct AuthEvent fingerprints."""
    p = os.fspath(path)
    if not p or not os.path.isfile(p):
        return []
    out: dict[str, AuthEvent] = {}
    try:
        with open(p, newline="", encoding="utf-8", errors="replace") as fh:
            # Skip UTF-8 BOM
            sample = fh.read(4096)
            fh.seek(0)
            if not sample.strip():
                return []
            try:
                dialect = csv.Sniffer().sniff(sample[:2048], delimiters=",\t;")
            except csv.Error:
                dialect = csv.excel
            rdr = csv.DictReader(fh, dialect=dialect)
            if not rdr.fieldnames:
                return []
            for i, row in enumerate(rdr):
                if i >= max_rows:
                    break
                if not isinstance(row, dict):
                    continue
                ev = row_to_auth_event(row, call_id=call_id, tool=tool)
                if ev:
                    out[ev.fingerprint()] = ev
    except OSError:
        return []
    return list(out.values())


def looks_like_auth_tabular(path: str | os.PathLike) -> bool:
    """Cheap header check: file has EID or ActionType/Logon columns."""
    p = os.fspath(path)
    if not p or not os.path.isfile(p):
        return False
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            header = fh.readline()
    except OSError:
        return False
    h = header.lstrip("\ufeff").lower()
    return any(
        token in h
        for token in (
            "eventid", "event id", "actiontype", "logontype", "logon type",
            "remotehost", "remoteip", "ip address", "mapdescription",
        )
    )


def csv_paths_from_tool_entry(entry: dict) -> list[str]:
    """Discover CSV paths recorded on a tool_call entry."""
    paths: list[str] = []
    for key in ("auth_csv", "existing_csv"):
        v = entry.get(key)
        if isinstance(v, str) and v.endswith(".csv") and os.path.isfile(v):
            paths.append(v)
    op = entry.get("output_paths")
    if isinstance(op, (list, tuple)):
        for v in op:
            if isinstance(v, str) and v.endswith(".csv") and os.path.isfile(v):
                paths.append(v)
    # Result blobs sometimes nest paths.
    for nest_key in ("result", "data"):
        nest = entry.get(nest_key)
        if isinstance(nest, dict):
            for v in csv_paths_from_tool_entry(nest):
                paths.append(v)
    # Dedup preserve order
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out
