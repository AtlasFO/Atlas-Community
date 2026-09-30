"""Timeline builder configuration — defaults + optional per-case overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Report-quality Windows Security / Sysmon event IDs (extend via YAML).
DEFAULT_INCLUDE_EVENT_TYPES: frozenset[str] = frozenset({
    "process_execution",
    "process_termination",
    "successful_logon",
    "failed_logon",
    "network_logon",
    "network_connection",
    "network_share_access",
    "persistence_run_key",
    "persistence_service",
    "persistence_scheduled_task",
    "powershell_activity",
    "office_document",
    "usb_activity",
    "privilege_escalation",
    "remote_access",
    "lateral_movement",
    "executable_created",
    "executable_deleted",
    "security_policy_change",
    "file_created",
    "file_modified",
    "file_accessed",
    "investigation_finding",
    "session_activity",
})

DEFAULT_MFT_TIMESTAMP_FIELDS: frozenset[str] = frozenset({
    "Created0x10",
    "LastModified0x10",
})

DEFAULT_MFT_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".msi", ".scr", ".hta", ".lnk",
})

DEFAULT_INCLUDE_EIDS: frozenset[int] = frozenset({
    4624, 4625, 4634, 4647, 4648, 4672,
    4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702,
    4720, 4722, 4723, 4724, 4728, 4732,
    4769, 4776,
    5140, 5145, 5156,
    7045,
})

DEFAULT_EXCLUDE_EIDS: frozenset[int] = frozenset({0})


@dataclass
class TimelineConfig:
    include_event_types: frozenset[str] = DEFAULT_INCLUDE_EVENT_TYPES
    include_eids: frozenset[int] = DEFAULT_INCLUDE_EIDS
    exclude_eids: frozenset[int] = DEFAULT_EXCLUDE_EIDS
    max_rows_per_artifact: int = 5000
    max_session_rows_per_artifact: int = 800
    llm_enrich: bool = False
    mft_timestamp_fields: frozenset[str] = DEFAULT_MFT_TIMESTAMP_FIELDS
    mft_extensions: frozenset[str] = DEFAULT_MFT_EXTENSIONS
    collapse_keep_interior: int = 2
    collapse_bulk_keep_interior: int = 1
    collapse_max_gap_seconds: int = 1800
    collapse_bulk_max_gap_seconds: int = 86400
    collapse_bulk_event_types: frozenset[str] = field(
        default_factory=lambda: frozenset({"session_activity"}))
    curate_enabled: bool = True
    curate_max_unmatched_noise: int = 0
    curate_aggregate: bool = True
    curate_aggregate_min_group: int = 8
    curate_aggregate_bucket_seconds: int = 600

    def passes_filter(self, event_type: str, event_id: int | None = None) -> bool:
        if event_id is not None and event_id in self.exclude_eids:
            return False
        if event_id is not None and self.include_eids and event_id not in self.include_eids:
            return False
        return event_type in self.include_event_types

    @classmethod
    def load(cls, case_dir: Path | None = None) -> "TimelineConfig":
        llm = (os.environ.get("ATLAS_TIMELINE_LLM") or "0").strip().lower() in (
            "1", "true", "yes", "on")
        cfg = cls(llm_enrich=llm)
        paths = [
            Path(__file__).with_name("config.yaml"),
        ]
        if case_dir:
            paths.append(case_dir / "timeline_config.yaml")
        for p in paths:
            if not p.is_file():
                continue
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            cfg = cfg._merge(raw)
        return cfg

    def _merge(self, raw: dict) -> "TimelineConfig":
        inc_types = raw.get("include_event_types")
        inc_eids = raw.get("include_eids")
        exc_eids = raw.get("exclude_eids")
        max_rows = raw.get("max_rows_per_artifact")
        max_sess = raw.get("max_session_rows_per_artifact")
        mft_fields = raw.get("mft_timestamp_fields")
        mft_ext = raw.get("mft_extensions")
        collapse = raw.get("collapse") or {}
        bulk_types = collapse.get("bulk_event_types")
        return TimelineConfig(
            include_event_types=frozenset(inc_types) if inc_types else self.include_event_types,
            include_eids=frozenset(int(x) for x in inc_eids) if inc_eids else self.include_eids,
            exclude_eids=frozenset(int(x) for x in exc_eids) if exc_eids else self.exclude_eids,
            max_rows_per_artifact=int(max_rows) if max_rows else self.max_rows_per_artifact,
            max_session_rows_per_artifact=(
                int(max_sess) if max_sess else self.max_session_rows_per_artifact
            ),
            llm_enrich=bool(raw.get("llm_enrich", self.llm_enrich)),
            mft_timestamp_fields=(
                frozenset(mft_fields) if mft_fields else self.mft_timestamp_fields
            ),
            mft_extensions=(
                frozenset(
                    e if str(e).startswith(".") else f".{e}" for e in mft_ext
                ) if mft_ext else self.mft_extensions
            ),
            collapse_keep_interior=int(
                collapse.get("keep_interior", self.collapse_keep_interior)),
            collapse_bulk_keep_interior=int(
                collapse.get("bulk_keep_interior", self.collapse_bulk_keep_interior)),
            collapse_max_gap_seconds=int(
                collapse.get("max_gap_seconds", self.collapse_max_gap_seconds)),
            collapse_bulk_max_gap_seconds=int(
                collapse.get(
                    "bulk_max_gap_seconds", self.collapse_bulk_max_gap_seconds)),
            collapse_bulk_event_types=(
                frozenset(bulk_types) if bulk_types
                else self.collapse_bulk_event_types
            ),
            curate_enabled=bool(
                (raw.get("curate") or {}).get("enabled", self.curate_enabled)),
            curate_max_unmatched_noise=int(
                (raw.get("curate") or {}).get(
                    "max_unmatched_noise", self.curate_max_unmatched_noise)),
            curate_aggregate=bool(
                (raw.get("curate") or {}).get("aggregate", self.curate_aggregate)),
            curate_aggregate_min_group=int(
                (raw.get("curate") or {}).get(
                    "aggregate_min_group", self.curate_aggregate_min_group)),
            curate_aggregate_bucket_seconds=int(
                (raw.get("curate") or {}).get(
                    "aggregate_bucket_seconds",
                    self.curate_aggregate_bucket_seconds)),
        )
