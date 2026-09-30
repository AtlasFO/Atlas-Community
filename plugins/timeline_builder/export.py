"""Export master_timeline.tsv and optional report snippet."""
from __future__ import annotations

from pathlib import Path

from plugins.timeline_builder.models import NormalizedTimelineEvent

# Line / RecordRef are optional trailing columns (backward-compatible for readers
# that only use the first six).
TSV_COLUMNS = (
    "Timestamp", "Machine", "User", "Event", "Source", "Description",
    "Line", "RecordRef",
)


def _line_from_event(ev: NormalizedTimelineEvent) -> str:
    facts = ev.facts or {}
    for key in ("line", "line_number", "Line"):
        if facts.get(key) is not None:
            return str(facts[key])
    return ""


def write_master_timeline(
    events: list[NormalizedTimelineEvent],
    output_path: Path,
) -> dict:
    """Write tab-separated master timeline. Returns summary dict."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["\t".join(TSV_COLUMNS)]
    for ev in events:
        row = [
            ev.timestamp,
            ev.host,
            ev.user,
            ev.title,
            ev.source_artifact,
            ev.description.replace("\t", " ").replace("\n", " "),
            _line_from_event(ev),
            (ev.record_ref or ev.evidence_reference or "").replace("\t", " "),
        ]
        lines.append("\t".join(row))
    tmp = output_path.with_suffix(".tsv.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(output_path)
    return {
        "path": str(output_path),
        "event_count": len(events),
        "columns": list(TSV_COLUMNS),
    }


def report_snippet_markdown(summary: dict) -> str:
    n = summary.get("event_count", 0)
    path = summary.get("path", "reports/master_timeline.tsv")
    rel = Path(path).name if path else "master_timeline.tsv"
    collapse = summary.get("collapse") or {}
    curate = summary.get("curate") or {}
    omitted = collapse.get("events_omitted", 0)
    dropped = curate.get("dropped", 0)
    bits = []
    if omitted:
        bits.append(f"collapsed {omitted} repetitive events")
    if dropped:
        bits.append(f"dropped {dropped} non-relevant rows")
    extra = ""
    if bits:
        extra = (
            " (" + "; ".join(bits)
            + "; critical/finding rows always kept). "
            "This is not a raw EVTX/session dump."
        )
    return (
        f"\n\n## Master Timeline\n\n"
        f"A curated investigation timeline ({n} relevant rows, UTC) is "
        f"available at `{rel}`.{extra}\n"
    )


def append_snippet_to_report(report_path: Path, snippet: str) -> bool:
    """Append timeline reference to report if not already present."""
    if not report_path.is_file():
        return False
    try:
        text = report_path.read_text(encoding="utf-8")
    except OSError:
        return False
    if "## Master Timeline" in text:
        return False
    report_path.write_text(text.rstrip() + snippet, encoding="utf-8")
    return True
