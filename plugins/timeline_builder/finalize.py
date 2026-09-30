"""Finalize investigation timeline — sort, merge, export, report hook.

Always writes ``reports/master_timeline.tsv`` (mandatory deliverable).
When live capture produced nothing, seeds from analysis CSVs/exports.
Claim Graph findings are never timeline Sources.
"""
from __future__ import annotations

import sys
from pathlib import Path

from plugins.timeline_builder.builder import TimelineBuilder
from plugins.timeline_builder.collapse import collapse_event_chains
from plugins.timeline_builder.curate import curate_relevant_events
from plugins.timeline_builder.enrich import enrich_events
from plugins.timeline_builder.export import (
    append_snippet_to_report,
    report_snippet_markdown,
    write_master_timeline,
)
from plugins.timeline_builder.mapper.dispatch import extract_payload
from plugins.timeline_builder.seed import seed_case_timeline


def finalize_timeline(
    *,
    case_dir: str | Path | None = None,
    report_path: str | Path | None = None,
) -> dict:
    """Sort, dedupe, collapse, curate to relevant events, write master_timeline.tsv.

    ``master_timeline.tsv`` is the curated investigation timeline. Raw captured
    events remain under ``reports/.timeline_build/`` for search — they are not
    what the client deliverable contains.
    """
    if case_dir is None:
        try:
            from core.execution_log import log
            case_dir = log.case_dir()
        except Exception:
            case_dir = None
    if not case_dir:
        return {"success": False, "error": "no active case directory"}

    builder = TimelineBuilder.for_case(case_dir)
    if builder is None:
        return {"success": False, "error": "timeline builder unavailable"}

    from plugins.timeline_builder.config import TimelineConfig
    cfg = TimelineConfig.load(Path(case_dir))

    seed_info = seed_case_timeline(case_dir, builder)
    events = builder.merged_sorted_deduped()
    if events:
        events = enrich_events(events)

    collapse_stats: dict = {}
    curate_stats: dict = {}
    if events:
        events, collapse_stats = collapse_event_chains(
            events,
            keep_interior=cfg.collapse_keep_interior,
            bulk_keep_interior=cfg.collapse_bulk_keep_interior,
            max_gap_seconds=cfg.collapse_max_gap_seconds,
            bulk_max_gap_seconds=cfg.collapse_bulk_max_gap_seconds,
            bulk_types=cfg.collapse_bulk_event_types,
        )
        events, curate_stats = curate_relevant_events(
            events,
            case_dir=case_dir,
            enabled=cfg.curate_enabled,
            max_unmatched_noise=cfg.curate_max_unmatched_noise,
            aggregate=cfg.curate_aggregate,
            aggregate_min_group=cfg.curate_aggregate_min_group,
            aggregate_bucket_seconds=cfg.curate_aggregate_bucket_seconds,
        )

    # Mandatory: always emit the artifact (header-only only if still empty).
    summary = write_master_timeline(events, builder.master_timeline_path)
    summary["success"] = True
    summary["mandatory"] = True
    summary["curated"] = True
    summary["seed"] = seed_info
    summary["collapse"] = collapse_stats
    summary["curate"] = curate_stats
    if not events:
        summary["note"] = (
            "master_timeline.tsv written with header only — no mappable "
            "events, analysis CSVs, or active claims yet"
        )
    else:
        omitted = collapse_stats.get("events_omitted", 0)
        dropped = curate_stats.get("dropped", 0)
        summary["note"] = (
            "master_timeline.tsv written as curated investigation timeline "
            f"({summary['event_count']} relevant rows"
            + (f"; collapsed {omitted} repetitive" if omitted else "")
            + (f"; dropped {dropped} non-relevant" if dropped else "")
            + f"; claims_seeded={seed_info.get('claims_seeded', 0)}; "
            "not a raw dump — raw capture stays in .timeline_build/)"
        )

    if report_path is None:
        report_path = _latest_report_path(case_dir)
    if report_path:
        snippet = report_snippet_markdown(summary)
        append_snippet_to_report(Path(report_path), snippet)
        summary["report_updated"] = str(report_path)

    return summary


def _latest_report_path(case_dir: str | Path) -> Path | None:
    case_dir = Path(case_dir)
    candidates: list[Path] = []
    for sub in ("reports", "analysis"):
        d = case_dir / sub
        if d.is_dir():
            candidates.extend(p for p in d.glob("*.md") if p.is_file())
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def maybe_finalize_from_tool(tool_name: str, args: dict, result) -> None:
    """Called from middleware after report/export tools succeed."""
    if tool_name in (
        "misc_write_final_report",
        "misc_write_projected_final_report",
    ):
        payload = extract_payload(result) or {}
        rp = args.get("output_path") or payload.get("path") or payload.get("output_path")
        finalize_timeline(report_path=rp)
        return
    if tool_name == "misc_export_execution_log":
        finalize_timeline()
