"""Deterministic mappers for non-event-log forensic artifacts (MFT, Prefetch, Registry)."""
from __future__ import annotations

from plugins.timeline_builder.config import TimelineConfig
from plugins.timeline_builder.mapper.forensic import MapContext, _basename
from plugins.timeline_builder.mapper.readers import _normalize_ts
from plugins.timeline_builder.models import EvidenceRecord, NormalizedTimelineEvent

_MFT_SOURCE = "NTFS Master File Table"
_PREFETCH_SOURCE = "Prefetch"
_REGISTRY_USERASSIST = "Registry UserAssist"
_REGISTRY_RUN_KEY = "Registry Run Key"
_REGISTRY_SERVICE = "Registry Windows Service"
_REGISTRY_APPCOMPAT = "Registry AppCompatCache"
_REGISTRY_GENERIC = "Registry Hive"

_MFT_TS_FIELDS = (
    ("Created0x10", "file_created", "File created"),
    ("LastModified0x10", "file_modified", "File modified"),
    ("LastAccess0x10", "file_accessed", "File accessed"),
)


def map_mft_record(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> list[NormalizedTimelineEvent]:
    f = rec.fields
    if str(f.get("IsDirectory", "")).lower() in ("true", "1", "yes"):
        return []
    parent = str(f.get("ParentPath") or "").strip()
    name = str(f.get("FileName") or "").strip()
    if not name or name.startswith("$"):
        return []
    ext = str(f.get("Extension") or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if config.mft_extensions and ext not in config.mft_extensions:
        return []
    full_path = f"{parent}\\{name}" if parent and parent != "." else name
    host = rec.host or _host_from_path(rec.artifact_path)
    out: list[NormalizedTimelineEvent] = []
    for col, event_type, title_prefix in _MFT_TS_FIELDS:
        if col not in config.mft_timestamp_fields:
            continue
        ts = _normalize_ts(str(f.get(col) or ""))
        if not ts:
            continue
        if not config.passes_filter(event_type):
            continue
        desc = f"Path: {full_path}"
        size = f.get("FileSize")
        if size not in (None, ""):
            desc += f"; Size: {size}"
        record_ref = f"{rec.artifact_path}:{rec.line_number}:{col}:{name}"
        out.append(NormalizedTimelineEvent(
            timestamp=ts,
            host=host,
            user=rec.user,
            event_type=event_type,
            title=f"{title_prefix}: {name}",
            description=desc,
            source_artifact=_MFT_SOURCE,
            source_identifier=f"MFT-{col}",
            original_tool=ctx.original_tool,
            evidence_reference=ctx.evidence_reference,
            record_ref=record_ref,
            facts={"path": full_path, "extension": ext, "column": col},
        ))
    return out


def map_prefetch_record(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> NormalizedTimelineEvent | None:
    f = rec.fields
    exe = str(f.get("ExecutableName") or f.get("Executable") or "").strip()
    ts = _normalize_ts(str(f.get("LastRun") or f.get("RunTime") or rec.timestamp or ""))
    if not exe or not ts:
        return None
    event_type = "process_execution"
    if not config.passes_filter(event_type):
        return None
    run_count = f.get("RunCount") or f.get("Run Count")
    desc = f"Executable: {exe}"
    if run_count not in (None, ""):
        desc += f"; Run count: {run_count}"
    src_pf = str(f.get("SourceFilename") or rec.source_file or "").strip()
    if src_pf:
        desc += f"; Prefetch file: {_basename(src_pf)}"
    record_ref = f"{rec.artifact_path}:{rec.line_number}:{exe}"
    return NormalizedTimelineEvent(
        timestamp=ts,
        host=rec.host or _host_from_path(rec.artifact_path),
        user=rec.user,
        event_type=event_type,
        title=f"Process executed: {exe}",
        description=desc,
        source_artifact=_PREFETCH_SOURCE,
        source_identifier=f"PREFETCH-{exe}",
        original_tool=ctx.original_tool,
        evidence_reference=ctx.evidence_reference,
        record_ref=record_ref,
        facts={"executable": exe, "run_count": run_count},
    )


def map_registry_record(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> NormalizedTimelineEvent | None:
    f = rec.fields
    key_path = str(f.get("BatchKeyPath") or f.get("KeyName") or "").strip()
    if not key_path:
        return None

    ts = _normalize_ts(
        str(f.get("LastExecuted") or f.get("ModifiedTime") or f.get("Timestamp")
            or f.get("NameKeyLastWrite") or f.get("ParametersKeyLastWrite") or rec.timestamp or "")
    )
    if not ts:
        return None

    key_lower = key_path.lower()
    program = str(
        f.get("ProgramName") or f.get("DisplayName") or f.get("BatchValueName")
        or f.get("Name") or ""
    ).strip()
    image = str(f.get("ImagePath") or f.get("ProgramName") or "").strip()

    if "userassist" in key_lower:
        event_type = "process_execution"
        source = _REGISTRY_USERASSIST
        title = f"Program executed: {program or image or 'unknown'}"
        sid = "USERASSIST"
    elif "\\run" in key_lower or key_lower.endswith("\\run"):
        event_type = "persistence_run_key"
        source = _REGISTRY_RUN_KEY
        val = str(f.get("BatchValueName") or program or "").strip()
        title = f"Run key entry: {val or 'unknown'}"
        sid = "RUNKEY"
    elif "\\services" in key_lower or f.get("ServiceType"):
        event_type = "persistence_service"
        source = _REGISTRY_SERVICE
        svc = str(f.get("Name") or program or "").strip()
        title = f"Service configured: {svc or 'unknown'}"
        sid = "SERVICE"
    elif "appcompatcache" in key_lower or "appcompat" in key_lower:
        event_type = "process_execution"
        source = _REGISTRY_APPCOMPAT
        title = f"Application cached: {program or image or 'unknown'}"
        sid = "APPCOMPAT"
    else:
        return None

    if not config.passes_filter(event_type):
        return None

    parts: list[str] = []
    if program:
        parts.append(f"Program: {program}")
    if image and image != program:
        parts.append(f"Image: {image}")
    if key_path:
        parts.append(f"Key: {key_path[:200]}")
    desc = "; ".join(parts) or f"Registry activity under {key_path[:120]}"
    record_ref = f"{rec.artifact_path}:{rec.line_number}:{sid}:{program or image}"
    return NormalizedTimelineEvent(
        timestamp=ts,
        host=rec.host or _host_from_path(rec.artifact_path),
        user=rec.user,
        event_type=event_type,
        title=title,
        description=desc,
        source_artifact=source,
        source_identifier=sid,
        original_tool=ctx.original_tool,
        evidence_reference=ctx.evidence_reference,
        record_ref=record_ref,
        facts={"key_path": key_path, "program": program, "image": image},
    )


def _host_from_path(path: str) -> str:
    """Best-effort host hint from artifact filename (e.g. rd01_mft.csv)."""
    base = _basename(path).lower()
    for suffix in ("_mft.csv", "_prefetch.csv", "_registry", "-registry"):
        if suffix in base:
            return base.split(suffix)[0].upper()
    return ""


def map_tabular_session_record(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> NormalizedTimelineEvent | None:
    """Remote-session / SIEM-without-EID / session CSV rows."""
    if not config.passes_filter("session_activity", None):
        return None
    desc = str(rec.fields.get("_seed_desc") or "").strip()
    if not desc:
        desc = f"Session/tabular event from {_basename(rec.artifact_path)}"
    return NormalizedTimelineEvent(
        timestamp=rec.timestamp,
        host=rec.host,
        user=rec.user,
        event_type="session_activity",
        title="Session / tabular event",
        description=desc[:500],
        source_artifact=f"Tabular export ({_basename(rec.artifact_path)})",
        source_identifier=f"tabular:{rec.line_number}",
        original_tool=ctx.original_tool,
        evidence_reference=ctx.evidence_reference,
        record_ref=f"{rec.artifact_path}:{rec.line_number}",
        facts={"line": rec.line_number},
    )


def map_artifact_records(
    rec: EvidenceRecord,
    ctx: MapContext,
    config: TimelineConfig,
) -> list[NormalizedTimelineEvent]:
    kind = rec.artifact_kind
    if kind == "mft":
        return map_mft_record(rec, ctx, config)
    if kind == "prefetch":
        ev = map_prefetch_record(rec, ctx, config)
        return [ev] if ev else []
    if kind == "registry":
        ev = map_registry_record(rec, ctx, config)
        return [ev] if ev else []
    if kind == "tabular_session":
        ev = map_tabular_session_record(rec, ctx, config)
        return [ev] if ev else []
    return []
