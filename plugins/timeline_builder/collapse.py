"""Collapse repetitive event chains for the curated master timeline.

Raw dumps (thousands of failed logons, remote-session CSVs, DHCP chatter) are
not analyst-useful. This module groups similar consecutive events into chains
and keeps:

  1. the first event
  2. up to ``keep_interior`` additional samples from the chain interior
  3. a summary row: ``~N more events in this eventchain``
  4. the last event

**Critical attack events are never collapsed away** — they always appear as
their own rows (claims, privilege escalation, persistence, lateral movement,
remote access, etc.).

Bulk estate dumps (``session_activity``, generic tabular sessions) use a
*coarse* chain key (event type + source file + calendar day) so thousands of
different users/hosts from the same CSV collapse into a few curated rows
instead of one row per session.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

from plugins.timeline_builder.models import NormalizedTimelineEvent

# Event types that always survive collapse (attack-critical / narrative anchors).
DEFAULT_CRITICAL_EVENT_TYPES: frozenset[str] = frozenset({
    "investigation_finding",
    "privilege_escalation",
    "persistence_run_key",
    "persistence_service",
    "persistence_scheduled_task",
    "lateral_movement",
    "remote_access",
    "usb_activity",
    "security_policy_change",
    "executable_created",
    "executable_deleted",
    "event_chain_summary",  # never collapse summaries into each other
})

# High-volume estate dumps — collapse across hosts/users within a day.
DEFAULT_BULK_EVENT_TYPES: frozenset[str] = frozenset({
    "session_activity",
})

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _parse_ts(raw: str) -> datetime | None:
    if not raw or raw == "unknown":
        return None
    s = raw.strip().replace("T", " ").split(".")[0]
    for n, fmt in (
        (19, "%Y-%m-%d %H:%M:%S"),
        (16, "%Y-%m-%d %H:%M"),
        (10, "%Y-%m-%d"),
        (19, "%m/%d/%Y %H:%M:%S"),
        (10, "%m/%d/%Y"),
    ):
        try:
            return datetime.strptime(s[:n], fmt)
        except ValueError:
            continue
    return None


def _day_bucket(ev: NormalizedTimelineEvent) -> str:
    ts = _parse_ts(ev.timestamp)
    if ts is None:
        return (ev.timestamp or "")[:10] or "unknown-day"
    return ts.strftime("%Y-%m-%d")


def _src_ip(ev: NormalizedTimelineEvent) -> str:
    facts = ev.facts or {}
    for key in ("src_ip", "source_ip", "IpAddress", "ip", "ClientAddress"):
        v = facts.get(key)
        if v:
            return str(v).strip()
    blob = f"{ev.description} {ev.title}"
    m = _IP_RE.search(blob)
    return m.group(0) if m else ""


def _source_family(ev: NormalizedTimelineEvent) -> str:
    """Stable artifact family (basename), ignoring line numbers."""
    art = (ev.source_artifact or "").strip()
    # "Tabular export (sessions.csv)" → sessions.csv
    m = re.search(r"\(([^)]+)\)\s*$", art)
    if m:
        return m.group(1).strip().lower()[:80]
    base = art.split("/")[-1].split("\\")[-1]
    return base.lower()[:80] or "unknown-source"


def _is_bulk(ev: NormalizedTimelineEvent,
             bulk_types: frozenset[str]) -> bool:
    if (ev.event_type or "") in bulk_types:
        return True
    title = (ev.title or "").lower()
    return title.startswith("session / tabular")


def _stable_source_id(ev: NormalizedTimelineEvent) -> str:
    """Drop per-row uniqueness (line numbers) so chains can form."""
    sid = (ev.source_identifier or "").strip().lower()
    if not sid:
        return ""
    if sid.startswith("tabular:"):
        return "tabular"
    if sid.startswith("eid-"):
        # EID-4688 / EID-4688:12345 → EID-4688
        return sid.split(":")[0]
    # call_id=12:line=4 → call_id=12
    sid = re.sub(r":\d+$", "", sid)
    sid = re.sub(r"[:_]line[=_]?\d+", "", sid)
    return sid[:60]


def chain_key(
    ev: NormalizedTimelineEvent,
    *,
    bulk_types: frozenset[str] | None = None,
) -> tuple:
    """Identity of a repetitive event chain (same actor/action pattern)."""
    bulk = bulk_types or DEFAULT_BULK_EVENT_TYPES
    if _is_bulk(ev, bulk):
        # Coarse: one chain per dump-file per calendar day (not per user/host).
        return (
            "bulk",
            (ev.event_type or "").lower(),
            _source_family(ev),
            _day_bucket(ev),
        )
    return (
        "fine",
        (ev.event_type or "").lower(),
        (ev.host or "").lower(),
        (ev.user or "").lower(),
        _stable_source_id(ev),
        _src_ip(ev),
        _source_family(ev),
    )


def is_critical(ev: NormalizedTimelineEvent,
                critical_types: frozenset[str] | None = None) -> bool:
    types = critical_types or DEFAULT_CRITICAL_EVENT_TYPES
    if (ev.facts or {}).get("critical") is True:
        return True
    if (ev.facts or {}).get("claim_id"):
        return True  # Claim Graph rows are attack narrative anchors
    if (ev.event_type or "") in types:
        return True
    # High-signal titles from findings
    title = (ev.title or "").lower()
    if title.startswith("finding "):
        return True
    return False


def _gap_seconds(a: NormalizedTimelineEvent, b: NormalizedTimelineEvent) -> float:
    ta, tb = _parse_ts(a.timestamp), _parse_ts(b.timestamp)
    if ta is None or tb is None:
        return 0.0
    return abs((tb - ta).total_seconds())


def _build_chains(
    events: list[NormalizedTimelineEvent],
    *,
    max_gap_seconds: int,
    bulk_types: frozenset[str],
    bulk_max_gap_seconds: int,
) -> list[list[NormalizedTimelineEvent]]:
    """Group events into gap-bounded chains.

    Events are first bucketed by ``chain_key`` so interleaved users/hosts
    (common in merged EVTX dumps) do not fracture each other into tiny
    one-row chains.
    """
    if not events:
        return []
    from collections import defaultdict

    by_key: dict[tuple, list[NormalizedTimelineEvent]] = defaultdict(list)
    for ev in events:
        by_key[chain_key(ev, bulk_types=bulk_types)].append(ev)

    chains: list[list[NormalizedTimelineEvent]] = []
    for key, group in by_key.items():
        group.sort(key=lambda e: (e.timestamp or "", e.host or ""))
        current: list[NormalizedTimelineEvent] = [group[0]]
        limit = (
            bulk_max_gap_seconds if key[0] == "bulk" else max_gap_seconds
        )
        for ev in group[1:]:
            gap = _gap_seconds(current[-1], ev)
            if gap <= limit:
                current.append(ev)
            else:
                chains.append(current)
                current = [ev]
        chains.append(current)
    return chains


def _interior_samples(
    chain: list[NormalizedTimelineEvent],
    keep_interior: int,
) -> list[NormalizedTimelineEvent]:
    """Pick up to ``keep_interior`` evenly spaced samples from the interior."""
    if len(chain) <= 2 or keep_interior <= 0:
        return []
    interior = chain[1:-1]
    if len(interior) <= keep_interior:
        return list(interior)
    n = len(interior)
    samples: list[NormalizedTimelineEvent] = []
    for i in range(keep_interior):
        idx = int(round(i * (n - 1) / (keep_interior - 1))) if keep_interior > 1 else 0
        samples.append(interior[idx])
    seen: set[int] = set()
    out: list[NormalizedTimelineEvent] = []
    for s in samples:
        oid = id(s)
        if oid in seen:
            continue
        seen.add(oid)
        out.append(s)
    return out


def _summary_event(
    chain: list[NormalizedTimelineEvent],
    omitted: int,
    kept: list[NormalizedTimelineEvent],
    *,
    bulk_types: frozenset[str],
) -> NormalizedTimelineEvent:
    first, last = chain[0], chain[-1]
    key = chain_key(first, bulk_types=bulk_types)
    etype = first.event_type or "event"
    ip = _src_ip(first)
    who = first.user or "unknown user"
    host = first.host or "unknown host"
    src = _source_family(first)
    if key[0] == "bulk":
        hosts = sorted({(e.host or "").strip() for e in chain if (e.host or "").strip()})
        users = sorted({(e.user or "").strip() for e in chain if (e.user or "").strip()})
        desc_bits = [
            f"Collapsed {omitted} similar '{etype}' rows from {src}",
            f"on {_day_bucket(first)}",
            f"({len(hosts)} host(s), {len(users)} user(s))",
            f"between {first.timestamp} and {last.timestamp}",
            f"— kept first, {max(0, len(kept) - 2)} interior sample(s), and last.",
        ]
        if hosts[:3]:
            desc_bits.append(f"Hosts sample: {', '.join(hosts[:3])}")
        if users[:3]:
            desc_bits.append(f"Users sample: {', '.join(users[:3])}")
    else:
        desc_bits = [
            f"Collapsed {omitted} similar '{etype}' events",
            f"on {host} as {who}",
            f"between {first.timestamp} and {last.timestamp}",
        ]
        if ip:
            desc_bits.append(f"(source/peer {ip})")
        desc_bits.append(
            f"— kept first, {max(0, len(kept) - 2)} interior sample(s), and last."
        )
    return NormalizedTimelineEvent(
        timestamp=last.timestamp or first.timestamp,
        host=first.host if key[0] != "bulk" else (hosts[0] if hosts else first.host),
        user=first.user if key[0] != "bulk" else (users[0] if users else first.user),
        event_type="event_chain_summary",
        title=f"~{omitted} more events in this eventchain",
        description=" ".join(desc_bits),
        source_artifact="Timeline Builder (collapsed chain)",
        source_identifier=f"chain:{etype}:{src}:{_day_bucket(first)}",
        original_tool="timeline_collapse",
        facts={
            "omitted": omitted,
            "chain_size": len(chain),
            "chain_key": list(key),
            "critical": False,
            "bulk": key[0] == "bulk",
        },
    )


def collapse_event_chains(
    events: Iterable[NormalizedTimelineEvent],
    *,
    keep_interior: int = 2,
    bulk_keep_interior: int = 1,
    min_chain_size: int | None = None,
    max_gap_seconds: int = 1800,
    bulk_max_gap_seconds: int = 86400,
    critical_types: frozenset[str] | None = None,
    bulk_types: frozenset[str] | None = None,
) -> tuple[list[NormalizedTimelineEvent], dict]:
    """Return curated timeline rows + collapse stats.

    ``min_chain_size`` defaults to ``keep_interior + 3`` (first + interior +
    last + at least one omitted) so small groups stay raw. Bulk session dumps
    use a lower interior count and a day-scoped chain key.
    """
    bulk = bulk_types or DEFAULT_BULK_EVENT_TYPES
    ordered = sorted(
        list(events),
        key=lambda e: (e.timestamp or "", e.host or "", e.event_type or ""),
    )
    if min_chain_size is None:
        # first + interior + last + at least 5 omitted → avoid "~1 more events"
        min_chain_size = keep_interior + 2 + 5  # e.g. 9 with keep_interior=2

    critical: list[NormalizedTimelineEvent] = []
    collapsible: list[NormalizedTimelineEvent] = []
    for ev in ordered:
        if is_critical(ev, critical_types):
            critical.append(ev)
        else:
            collapsible.append(ev)

    chains = _build_chains(
        collapsible,
        max_gap_seconds=max_gap_seconds,
        bulk_types=bulk,
        bulk_max_gap_seconds=bulk_max_gap_seconds,
    )
    collapsed_rows: list[NormalizedTimelineEvent] = []
    chains_collapsed = 0
    events_omitted = 0

    for chain in chains:
        is_bulk_chain = _is_bulk(chain[0], bulk)
        interior_n = bulk_keep_interior if is_bulk_chain else keep_interior
        # Bulk dumps collapse earlier (estate session CSVs are huge).
        need = 6 if is_bulk_chain else min_chain_size
        if len(chain) < need:
            collapsed_rows.extend(chain)
            continue
        first = chain[0]
        last = chain[-1]
        interior = _interior_samples(chain, interior_n)
        kept = [first, *interior]
        if last is not first and last not in interior:
            kept_with_last = kept + [last]
        else:
            kept_with_last = kept
        omitted = len(chain) - len(kept_with_last)
        min_omit = 3 if is_bulk_chain else 5
        if omitted < min_omit:
            collapsed_rows.extend(chain)
            continue
        chains_collapsed += 1
        events_omitted += omitted
        collapsed_rows.append(first)
        collapsed_rows.extend(interior)
        collapsed_rows.append(
            _summary_event(chain, omitted, kept_with_last, bulk_types=bulk))
        if last is not first and id(last) not in {id(x) for x in interior}:
            collapsed_rows.append(last)

    merged = critical + collapsed_rows
    merged.sort(key=lambda e: (e.timestamp or "", e.host or "", e.event_type or ""))
    seen: set[tuple] = set()
    out: list[NormalizedTimelineEvent] = []
    for ev in merged:
        if ev.event_type == "event_chain_summary" or is_critical(ev, critical_types):
            out.append(ev)
            continue
        key = ev.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)

    stats = {
        "input_events": len(ordered),
        "output_events": len(out),
        "chains_collapsed": chains_collapsed,
        "events_omitted": events_omitted,
        "critical_kept": len(critical),
    }
    return out, stats
