"""Seed the timeline from leftover analysis artifacts.

Used at finalize when live middleware capture produced few/no events — common
for Excel/SIEM/remote-session cases that never went through EvtxECmd CSV export.

Claim Graph findings are **not** seeded into the timeline. Sources must be
real evidence artifacts (EVTX, DHCP logs, MFT, USB device logs, …).
"""
from __future__ import annotations

from pathlib import Path

from plugins.timeline_builder.builder import TimelineBuilder
from plugins.timeline_builder.config import TimelineConfig
from plugins.timeline_builder.mapper.forensic import MapContext, map_record
from plugins.timeline_builder.mapper.readers import reader_for_path
from plugins.timeline_builder.models import NormalizedTimelineEvent


def events_from_claims(case_dir: str | Path) -> list[NormalizedTimelineEvent]:
    """Deprecated no-op: Claim Graph nodes are not timeline Sources."""
    return []


def ingest_analysis_csvs(
    case_dir: str | Path,
    builder: TimelineBuilder,
    *,
    max_files: int = 80,
    max_rows_per_file: int | None = None,
) -> int:
    """Map leftover analysis/exports tabular artifacts into the builder.

    Covers SIEM CSVs, remote-session exports, EvtxECmd exports, DHCP summaries — not
    only Windows EVTX. Idempotent via later dedupe/collapse.
    """
    case_dir = Path(case_dir)
    config = TimelineConfig.load(case_dir)
    if max_rows_per_file is None:
        max_rows_per_file = config.max_rows_per_artifact
    ctx = MapContext(original_tool="timeline_seed_analysis_csv")
    count = 0
    files: list[Path] = []
    for sub in ("analysis", "exports"):
        root = case_dir / sub
        if not root.is_dir():
            continue
        files.extend(sorted(root.glob("*.csv")))
        files.extend(sorted(root.glob("*.tsv")))
        # One level of subdirs (e.g. analysis/host_x/*.csv)
        files.extend(sorted(root.glob("*/*.csv")))
        files.extend(sorted(root.glob("*/*.tsv")))
    files = [p for p in files if p.name != "master_timeline.tsv"][:max_files]
    for path in files:
        reader = reader_for_path(path)
        if reader is None:
            continue
        # Cap session dumps harder than EvtxECmd CSVs.
        row_cap = max_rows_per_file
        name_l = path.name.lower()
        if any(tok in name_l for tok in (
                "session", "connection", "dhcp")):
            row_cap = min(row_cap, config.max_session_rows_per_artifact)
        for rec in reader.read_rows(path, max_rows=row_cap):
            ev = map_record(rec, ctx, config)
            if not ev:
                continue
            if isinstance(ev, list):
                for item in ev:
                    builder.append(item)
                    count += 1
            else:
                builder.append(ev)
                count += 1
    return count


def seed_case_timeline(case_dir: str | Path, builder: TimelineBuilder) -> dict:
    """Fill gaps before export. Returns counts of what was added.

    Does **not** seed Claim Graph findings — those are not forensic Sources.
    """
    csv_n = ingest_analysis_csvs(case_dir, builder)
    return {"claims_seeded": 0, "analysis_csv_events": csv_n}
