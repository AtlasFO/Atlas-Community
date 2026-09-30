"""Aggregate repetitive timeline storms into summary rows.

Example: 2000 failed logons from one IP across many users → a handful of
time-bucketed summary events whose description lists the usernames.
Raw events remain in ``.timeline_build/``; only the curated export shrinks.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from plugins.timeline_builder.models import NormalizedTimelineEvent
from plugins.timeline_builder.taxonomy import AGGREGATABLE_EVENT_TYPES


def _parse_ts(ts: str) -> datetime | None:
    raw = (ts or "").strip()
    if not raw:
        return None
    # Normalize trailing Z
    cand = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(cand)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(raw[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _bucket_key(ts: str, bucket_seconds: int) -> str:
    dt = _parse_ts(ts)
    if dt is None:
        return ts or ""
    epoch = int(dt.timestamp())
    b = epoch - (epoch % max(1, bucket_seconds))
    return datetime.fromtimestamp(b, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _storm_key(ev: NormalizedTimelineEvent, bucket_seconds: int) -> tuple:
    return (
        ev.event_type or "",
        (ev.host or "").lower(),
        _bucket_key(ev.timestamp, bucket_seconds),
        # Group failed logons by source IP when present in facts/description
        str((ev.facts or {}).get("src_ip")
            or (ev.facts or {}).get("ip")
            or "").lower(),
    )


def aggregate_storms(
    events: Iterable[NormalizedTimelineEvent],
    *,
    min_group_size: int = 8,
    bucket_seconds: int = 600,
    max_summaries_per_storm: int = 5,
    aggregatable_types: frozenset[str] | None = None,
) -> tuple[list[NormalizedTimelineEvent], dict]:
    """Collapse large same-type bursts into summary events.

    Groups smaller than ``min_group_size`` pass through unchanged.
    Oversized groups become up to ``max_summaries_per_storm`` summaries
    (split by time order) with user lists in the description.
    """
    types = aggregatable_types or AGGREGATABLE_EVENT_TYPES
    ordered = list(events)
    groups: dict[tuple, list[NormalizedTimelineEvent]] = defaultdict(list)
    passthrough: list[NormalizedTimelineEvent] = []

    for ev in ordered:
        if (ev.event_type or "") not in types:
            passthrough.append(ev)
            continue
        # Never aggregate narrative anchors
        if (ev.facts or {}).get("claim_id") or (
                ev.event_type or "") == "investigation_finding":
            passthrough.append(ev)
            continue
        groups[_storm_key(ev, bucket_seconds)].append(ev)

    out: list[NormalizedTimelineEvent] = list(passthrough)
    storms = 0
    collapsed = 0

    for key, members in groups.items():
        if len(members) < min_group_size:
            out.extend(members)
            continue
        storms += 1
        members.sort(key=lambda e: (e.timestamp or "", e.user or ""))
        # Split into at most max_summaries_per_storm chronological chunks
        n = len(members)
        chunk = max(1, (n + max_summaries_per_storm - 1) // max_summaries_per_storm)
        for i in range(0, n, chunk):
            part = members[i:i + chunk]
            if len(part) < min_group_size and i > 0:
                # leftover small tail → attach to previous summary already emitted
                # by merging into last out summary of same type/host if possible
                out.extend(part)
                continue
            users = sorted({
                (e.user or "").strip()
                for e in part
                if (e.user or "").strip() and not (e.user or "").endswith("$")
            })
            first, last = part[0], part[-1]
            et = first.event_type or "event"
            user_preview = ", ".join(users[:40])
            if len(users) > 40:
                user_preview += f", … (+{len(users) - 40} more)"
            desc = (
                f"Aggregated {len(part)} {et} events"
                f" from {first.timestamp} to {last.timestamp}."
            )
            if user_preview:
                desc += f" Users: {user_preview}."
            src_ip = key[3]
            if src_ip:
                desc += f" Source IP: {src_ip}."
            sample_refs = [
                e.record_ref for e in part[:3] if e.record_ref
            ]
            if sample_refs:
                desc += f" Sample refs: {'; '.join(sample_refs)}."
            facts = dict(first.facts or {})
            facts["aggregated"] = True
            facts["aggregated_count"] = len(part)
            facts["aggregated_users"] = users[:100]
            if src_ip:
                facts["src_ip"] = src_ip
            out.append(NormalizedTimelineEvent(
                timestamp=first.timestamp,
                host=first.host,
                user=users[0] if len(users) == 1 else "",
                event_type=et,
                title=f"Summary: {len(part)}× {et.replace('_', ' ')}",
                description=desc,
                source_artifact=first.source_artifact,
                source_identifier=first.source_identifier,
                original_tool=first.original_tool,
                evidence_reference=first.evidence_reference,
                record_ref=first.record_ref,
                facts=facts,
            ))
            collapsed += len(part) - 1

    out.sort(key=lambda e: (e.timestamp or "", e.host or "", e.event_type or ""))
    stats = {
        "input_events": len(ordered),
        "output_events": len(out),
        "storms_aggregated": storms,
        "events_collapsed": collapsed,
        "min_group_size": min_group_size,
        "bucket_seconds": bucket_seconds,
    }
    return out, stats
