"""Deterministic forensic normalization — EvidenceRecord → NormalizedTimelineEvent."""
from __future__ import annotations

from dataclasses import dataclass

from plugins.timeline_builder.config import TimelineConfig
from plugins.timeline_builder.models import EvidenceRecord, NormalizedTimelineEvent

# Windows Security Event ID → (event_type, short title, source artifact template)
_EID_MAP: dict[int, tuple[str, str, str]] = {
    4624: ("successful_logon", "User logged on", "Windows Security Event Log (Event ID 4624)"),
    4625: ("failed_logon", "Failed logon", "Windows Security Event Log (Event ID 4625)"),
    4634: ("successful_logon", "User logged off", "Windows Security Event Log (Event ID 4634)"),
    4648: ("successful_logon", "Explicit credential logon", "Windows Security Event Log (Event ID 4648)"),
    4672: ("privilege_escalation", "Special privileges assigned", "Windows Security Event Log (Event ID 4672)"),
    4688: ("process_execution", "Process executed", "Windows Security Event Log (Event ID 4688)"),
    4689: ("process_termination", "Process terminated", "Windows Security Event Log (Event ID 4689)"),
    4698: ("persistence_scheduled_task", "Scheduled task created", "Windows Security Event Log (Event ID 4698)"),
    4697: ("persistence_service", "Windows service installed", "Windows Security Event Log (Event ID 4697)"),
    5140: ("network_share_access", "Network share accessed", "Windows Security Event Log (Event ID 5140)"),
    5145: ("network_share_access", "Network share object checked", "Windows Security Event Log (Event ID 5145)"),
    5156: ("network_connection", "Network connection allowed", "Windows Security Event Log (Event ID 5156)"),
    7045: ("persistence_service", "Windows service installed", "Windows Security Event Log (Event ID 7045)"),
}

# Sysmon channel heuristic
_SYSMON_EIDS: dict[int, tuple[str, str]] = {
    1: ("process_execution", "Process executed"),
    3: ("network_connection", "Network connection established"),
    7: ("process_execution", "Image loaded"),
    11: ("executable_created", "File created"),
    12: ("persistence_run_key", "Registry object created"),
    13: ("persistence_run_key", "Registry value set"),
    22: ("network_connection", "DNS query"),
}


@dataclass
class MapContext:
    original_tool: str = ""
    evidence_reference: str = ""
    call_id: str = ""


def _source_artifact(rec: EvidenceRecord, eid: int) -> str:
    ch = (rec.channel or "").lower()
    if "sysmon" in ch:
        return f"Sysmon Event Log (Event ID {eid})"
    if "security" in ch or "microsoft-windows-security" in ch:
        return f"Windows Security Event Log (Event ID {eid})"
    if rec.channel:
        return f"Windows Event Log — {rec.channel} (Event ID {eid})"
    mapped = _EID_MAP.get(eid)
    if mapped:
        return mapped[2]
    return f"Windows Event Log (Event ID {eid})"


def _event_type_and_title(rec: EvidenceRecord, eid: int) -> tuple[str, str]:
    ch = (rec.channel or "").lower()
    if "sysmon" in ch and eid in _SYSMON_EIDS:
        et, title = _SYSMON_EIDS[eid]
        return et, title
    if eid in _EID_MAP:
        return _EID_MAP[eid][0], _EID_MAP[eid][1]
    return "security_event", f"Windows event {eid}"


def _build_description(rec: EvidenceRecord, eid: int) -> str:
    parts: list[str] = []
    f = rec.fields
    for key in (
        "MapDescription", "ExecutableInfo", "RemoteHost", "PayloadData1",
        "PayloadData2", "PayloadData3", "Details", "IpAddress", "Logon Type",
        "logon_type", "TargetUserName", "SubjectUserName", "ProcessName",
        "CommandLine", "Image", "ParentImage",
    ):
        val = f.get(key) or f.get(key.replace(" ", ""))
        if val and str(val).strip():
            parts.append(f"{key}: {str(val).strip()[:300]}")
    if rec.source_file:
        parts.append(f"Source file: {_basename(rec.source_file)}")
    if not parts:
        parts.append(f"Event ID {eid} recorded on {rec.host or 'unknown host'}.")
    return " ".join(parts[:4])


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1]


def map_record(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> NormalizedTimelineEvent | list[NormalizedTimelineEvent] | None:
    if rec.artifact_kind != "windows_event":
        from plugins.timeline_builder.mapper.artifacts import map_artifact_records
        events = map_artifact_records(rec, ctx, config)
        return events if len(events) != 1 else events[0] if events else None
    try:
        eid = int(rec.event_id)
    except (TypeError, ValueError):
        return None
    event_type, title = _event_type_and_title(rec, eid)
    if not config.passes_filter(event_type, eid):
        return None
    source = _source_artifact(rec, eid)
    desc = _build_description(rec, eid)
    record_ref = f"{rec.artifact_path}:{rec.line_number}:{eid}"
    return NormalizedTimelineEvent(
        timestamp=rec.timestamp,
        host=rec.host,
        user=rec.user,
        event_type=event_type,
        title=title,
        description=desc,
        source_artifact=source,
        source_identifier=f"EID-{eid}",
        original_tool=ctx.original_tool,
        evidence_reference=ctx.evidence_reference,
        record_ref=record_ref,
        facts={
            "event_id": eid,
            "channel": rec.channel,
            "line": rec.line_number,
            "artifact": rec.artifact_path,
        },
    )
