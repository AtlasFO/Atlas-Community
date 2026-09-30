"""Timeline data model — tool-agnostic normalized events."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    """Structured row from a forensic artifact (reader output, not a timeline event)."""

    timestamp: str
    host: str
    user: str
    event_id: str
    channel: str
    artifact_path: str
    source_file: str
    fields: dict[str, Any]
    line_number: int = 0
    artifact_kind: str = "windows_event"


@dataclass
class NormalizedTimelineEvent:
    """Internal timeline event consumed by the builder (no tool names in export)."""

    timestamp: str
    host: str
    user: str
    event_type: str
    title: str
    description: str
    source_artifact: str
    source_identifier: str
    original_tool: str = ""
    evidence_reference: str = ""
    record_ref: str = ""
    facts: dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> tuple:
        return (
            self.timestamp,
            self.host,
            self.user,
            self.event_type,
            self.source_identifier,
            self.record_ref,
        )

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "NormalizedTimelineEvent":
        return cls(
            timestamp=str(data.get("timestamp") or ""),
            host=str(data.get("host") or ""),
            user=str(data.get("user") or ""),
            event_type=str(data.get("event_type") or ""),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            source_artifact=str(data.get("source_artifact") or ""),
            source_identifier=str(data.get("source_identifier") or ""),
            original_tool=str(data.get("original_tool") or ""),
            evidence_reference=str(data.get("evidence_reference") or ""),
            record_ref=str(data.get("record_ref") or ""),
            facts=dict(data.get("facts") or {}),
        )
