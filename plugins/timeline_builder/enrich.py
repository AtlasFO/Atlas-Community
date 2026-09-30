"""Optional LLM pass — rewrite title/description from deterministic facts only."""
from __future__ import annotations

import json
import os

from plugins.timeline_builder.models import NormalizedTimelineEvent


def enrich_events(events: list[NormalizedTimelineEvent]) -> list[NormalizedTimelineEvent]:
    """Batch-enrich events when ATLAS_TIMELINE_LLM is enabled. Fail-open."""
    if not events:
        return events
    if not (os.environ.get("ATLAS_TIMELINE_LLM") or "").strip().lower() in (
        "1", "true", "yes", "on"):
        return events
    try:
        from agent.llm import LLMHubClient, LLMError
        from core import providers
    except ImportError:
        return events

    name = providers.role_name("ATLAS_AGENT_PROVIDER")
    if not name:
        return events
    try:
        client = LLMHubClient(provider=name)
        if not client.api_key:
            return events
    except (providers.UnknownProvider, LLMError):
        return events

    # Batch in chunks to limit token use
    out: list[NormalizedTimelineEvent] = []
    chunk_size = 20
    for i in range(0, len(events), chunk_size):
        chunk = events[i:i + chunk_size]
        enriched = _enrich_chunk(client, chunk)
        out.extend(enriched if enriched else chunk)
    return out


def _enrich_chunk(client, chunk: list[NormalizedTimelineEvent]) -> list[NormalizedTimelineEvent] | None:
    from agent.llm import LLMError

    payload = [
        {
            "timestamp": e.timestamp,
            "host": e.host,
            "user": e.user,
            "event_type": e.event_type,
            "source_artifact": e.source_artifact,
            "facts": e.description,
        }
        for e in chunk
    ]
    prompt = (
        "Rewrite each forensic event into a professional DFIR timeline row. "
        "Return JSON array with objects {title, description} in the same order. "
        "Rules: use ONLY facts provided; do not infer malice or attacker intent; "
        "do not mention parser or tool names; titles are short (3-6 words); "
        "descriptions are one or two sentences suitable for a client report.\n\n"
        f"Events:\n{json.dumps(payload, ensure_ascii=False)}"
    )
    try:
        resp = client.chat(
            messages=[
                {"role": "system", "content": "You format forensic timeline rows. Output JSON only."},
                {"role": "user", "content": prompt},
            ],
            tools=None,
        )
        text = (resp.content or "").strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) != len(chunk):
            return None
    except (LLMError, json.JSONDecodeError, ValueError, TypeError):
        return None

    out: list[NormalizedTimelineEvent] = []
    for ev, row in zip(chunk, rows):
        if not isinstance(row, dict):
            out.append(ev)
            continue
        title = str(row.get("title") or ev.title).strip() or ev.title
        desc = str(row.get("description") or ev.description).strip() or ev.description
        out.append(NormalizedTimelineEvent(
            timestamp=ev.timestamp,
            host=ev.host,
            user=ev.user,
            event_type=ev.event_type,
            title=title,
            description=desc,
            source_artifact=ev.source_artifact,
            source_identifier=ev.source_identifier,
            original_tool=ev.original_tool,
            evidence_reference=ev.evidence_reference,
            record_ref=ev.record_ref,
            facts=ev.facts,
        ))
    return out
