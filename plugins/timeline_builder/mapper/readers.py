"""Readers — parse forensic artifacts into structured EvidenceRecord rows.

Readers never perform reasoning or timeline classification beyond field extraction.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from plugins.timeline_builder.models import EvidenceRecord

# EvtxECmd / SIEM / session-broker / common tabular column aliases
_TS_COLS = (
    "TimeCreated", "Timestamp", "timestamp", "timecreated",
    "startDateTime", "deviceDateTime", "StartDate", "CreatedDate",
    "startTime", "StartTime", "Time", "time",
)
_EID_COLS = (
    # Prefer real Windows EIDs over QRadar placeholders (deviceEventId is often 0).
    "qidEventId", "EventIDCode", "EventId", "Event ID", "EventID", "event_id",
    "deviceEventId",
)
_HOST_COLS = (
    "Computer", "computer", "Hostname", "host",
    "logSourceIdentifier", "deviceName", "identityHostname",
    "MachineName", "ClientName",
)
_USER_COLS = (
    "UserName", "User", "user", "TargetUserName", "SubjectUserName",
    "userName", "identityUsername",
)
_CHANNEL_COLS = ("Channel", "channel", "Provider", "eventName", "categoryDescription")
_SOURCE_COLS = ("SourceFile", "source_file", "Source", "logSourceIdentifier")
# Timestamps without Event IDs (remote sessions, DHCP summaries, etc.)
_GENERIC_TS_COLS = (
    "StartDate", "CreatedDate", "startDateTime", "deviceDateTime",
    "TimeCreated", "Timestamp", "timestamp", "StartTime", "startTime",
)
_DESC_COLS = (
    "eventDescription", "eventName", "categoryDescription", "DesktopGroupName",
    "ClientPlatform", "ClientAddress", "IPAddress", "offenseName",
)


def _pick(row: dict, names: tuple[str, ...]) -> str:
    # Normalize BOM / case so Excel and API exports still match.
    cleaned = {
        (k.lstrip("\ufeff") if isinstance(k, str) else k): v
        for k, v in row.items()
    }
    for n in names:
        if n in cleaned and cleaned[n] not in (None, ""):
            return str(cleaned[n]).strip()
    lower = {
        (k.lower() if isinstance(k, str) else k): v for k, v in cleaned.items()
    }
    for n in names:
        v = lower.get(n.lower())
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _pick_eid(row: dict) -> str:
    """Pick a Windows Event ID, skipping QRadar placeholder zeros."""
    for n in _EID_COLS:
        v = _pick(row, (n,))
        if v and v not in ("0", "0.0", "-1"):
            return v
    return ""


def _normalize_ts(raw: str) -> str:
    if not raw:
        return ""
    return raw.replace("T", " ").split(".")[0].strip()


def _csv_fieldnames(path: Path, delim: str = ",") -> set[str]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh, delimiter=delim)
        # Strip BOM that some Excel/API exports put on the first header.
        names = []
        for n in (reader.fieldnames or []):
            names.append(n.lstrip("\ufeff") if isinstance(n, str) else n)
        return set(names)


def _fields_have(fields: set[str], names: tuple[str, ...]) -> bool:
    lower = {f.lower() for f in fields if isinstance(f, str)}
    return any(n in fields or n.lower() in lower for n in names)


class EvtxCsvReader:
    """Windows event log CSV (EvtxECmd, similar exports)."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = str(path).lower()
        if not p.endswith(".csv"):
            return False
        if "mft" in p or "prefetch" in p or "registry" in p:
            return False
        return any(x in p for x in ("evtx", "event", "security", "sysmon", "all-evtx"))

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                eid = _pick_eid(row)
                ts = _normalize_ts(_pick(row, _TS_COLS))
                if not ts or not eid:
                    continue
                yield EvidenceRecord(
                    timestamp=ts,
                    host=_pick(row, _HOST_COLS),
                    user=_pick(row, _USER_COLS),
                    event_id=eid,
                    channel=_pick(row, _CHANNEL_COLS),
                    artifact_path=str(path),
                    source_file=_pick(row, _SOURCE_COLS),
                    fields=dict(row),
                    line_number=i,
                )


class MftCsvReader:
    """MFTECmd CSV output."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = Path(path)
        if not str(p).lower().endswith(".csv"):
            return False
        if "mft" not in str(p).lower():
            return False
        try:
            fields = _csv_fieldnames(p)
        except OSError:
            return False
        return "Created0x10" in fields and "FileName" in fields

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                yield EvidenceRecord(
                    timestamp=_normalize_ts(str(row.get("Created0x10") or "")),
                    host="",
                    user="",
                    event_id="",
                    channel="",
                    artifact_path=str(path),
                    source_file=str(row.get("SourceFile") or ""),
                    fields=dict(row),
                    line_number=i,
                    artifact_kind="mft",
                )


class PrefetchCsvReader:
    """PECmd CSV output."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = Path(path)
        if not str(p).lower().endswith(".csv"):
            return False
        if "prefetch" not in str(p).lower():
            return False
        try:
            fields = _csv_fieldnames(p)
        except OSError:
            return False
        return "ExecutableName" in fields or "LastRun" in fields

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                ts = _normalize_ts(
                    str(row.get("LastRun") or row.get("RunTime") or "")
                )
                yield EvidenceRecord(
                    timestamp=ts,
                    host="",
                    user="",
                    event_id="",
                    channel="",
                    artifact_path=str(path),
                    source_file=str(row.get("SourceFilename") or ""),
                    fields=dict(row),
                    line_number=i,
                    artifact_kind="prefetch",
                )


class RegistryCsvReader:
    """RECmd batch CSV output (UserAssist, Run keys, Services, AppCompat, etc.)."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = Path(path)
        if not str(p).lower().endswith(".csv"):
            return False
        name = str(p).lower()
        if not any(x in name for x in ("registry", "userassist", "recmd")):
            return False
        try:
            fields = _csv_fieldnames(p)
        except OSError:
            return False
        return "BatchKeyPath" in fields or "KeyName" in fields

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                ts = _normalize_ts(
                    str(
                        row.get("LastExecuted")
                        or row.get("ModifiedTime")
                        or row.get("Timestamp")
                        or row.get("NameKeyLastWrite")
                        or ""
                    )
                )
                yield EvidenceRecord(
                    timestamp=ts,
                    host="",
                    user="",
                    event_id="",
                    channel="",
                    artifact_path=str(path),
                    source_file=str(row.get("Filename") or ""),
                    fields=dict(row),
                    line_number=i,
                    artifact_kind="registry",
                )


class GenericCsvReader:
    """Fallback for tabular tool output with Event ID + Timestamp columns."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = Path(path)
        if not str(p).lower().endswith((".csv", ".tsv")):
            return False
        delim = "\t" if str(p).lower().endswith(".tsv") else ","
        try:
            fields = _csv_fieldnames(p, delim=delim)
        except OSError:
            return False
        has_eid = _fields_have(fields, _EID_COLS)
        has_ts = _fields_have(fields, _TS_COLS)
        return has_eid and has_ts

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        delim = "\t" if str(path).lower().endswith(".tsv") else ","
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter=delim)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                eid = _pick_eid(row)
                ts = _normalize_ts(_pick(row, _TS_COLS))
                if not ts or not eid:
                    continue
                yield EvidenceRecord(
                    timestamp=ts,
                    host=_pick(row, _HOST_COLS),
                    user=_pick(row, _USER_COLS),
                    event_id=eid,
                    channel=_pick(row, _CHANNEL_COLS),
                    artifact_path=str(path),
                    source_file=_pick(row, _SOURCE_COLS),
                    fields=dict(row),
                    line_number=i,
                )


class TimestampedCsvReader:
    """Remote-session tables: timestamp present, no Event ID required."""

    @staticmethod
    def matches(path: str | Path) -> bool:
        p = Path(path)
        if not str(p).lower().endswith((".csv", ".tsv")):
            return False
        if p.name == "master_timeline.tsv":
            return False
        delim = "\t" if str(p).lower().endswith(".tsv") else ","
        try:
            fields = _csv_fieldnames(p, delim=delim)
        except OSError:
            return False
        if _fields_have(fields, _EID_COLS) and _fields_have(fields, _TS_COLS):
            return False
        return _fields_have(fields, _GENERIC_TS_COLS)

    @staticmethod
    def read_rows(
        path: str | Path,
        *,
        max_rows: int = 5000,
    ) -> Iterator[EvidenceRecord]:
        path = Path(path)
        delim = "\t" if str(path).lower().endswith(".tsv") else ","
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh, delimiter=delim)
            for i, row in enumerate(reader, 1):
                if i > max_rows:
                    break
                ts = _normalize_ts(_pick(row, _GENERIC_TS_COLS + _TS_COLS))
                if not ts:
                    continue
                desc_bits = []
                for c in _DESC_COLS:
                    v = _pick(row, (c,))
                    if v:
                        desc_bits.append(f"{c}={v}")
                yield EvidenceRecord(
                    timestamp=ts,
                    host=_pick(row, _HOST_COLS),
                    user=_pick(row, _USER_COLS),
                    event_id="0",
                    channel=_pick(row, _CHANNEL_COLS) or "tabular",
                    artifact_path=str(path),
                    source_file=path.name,
                    fields={**dict(row), "_seed_desc": "; ".join(desc_bits[:4])},
                    line_number=i,
                    artifact_kind="tabular_session",
                )


def read_inline_rows(rows: list[dict], *, artifact_path: str = "") -> Iterator[EvidenceRecord]:
    """Parse table_query/table_grep inline row payloads."""
    for i, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            continue
        eid = _pick_eid(row)
        ts = _normalize_ts(_pick(row, _TS_COLS))
        if not ts or not eid:
            continue
        yield EvidenceRecord(
            timestamp=ts,
            host=_pick(row, _HOST_COLS),
            user=_pick(row, _USER_COLS),
            event_id=eid,
            channel=_pick(row, _CHANNEL_COLS),
            artifact_path=artifact_path,
            source_file="",
            fields=dict(row),
            line_number=i,
        )


_READERS = (
    MftCsvReader,
    PrefetchCsvReader,
    RegistryCsvReader,
    EvtxCsvReader,
    GenericCsvReader,
    TimestampedCsvReader,
)


def reader_for_path(path: str | Path):
    for reader in _READERS:
        if reader.matches(path):
            return reader
    return None


def rows_from_json_payload(payload: dict) -> list[dict]:
    """Extract inline rows from a tool result dict."""
    rows = payload.get("rows")
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    hits = payload.get("hits")
    if isinstance(hits, list):
        return [h for h in hits if isinstance(h, dict)]
    return []
