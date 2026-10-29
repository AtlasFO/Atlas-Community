"""CLI helpers for investigation continuity commands (explain / timeline / status).

Used by ``agent.cli`` — keeps argparse thin and unit-testable.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Optional


def _edges_touching(graph: dict[str, Any], node_id: str) -> list[dict[str, Any]]:
    out = []
    for e in graph.get("edges") or []:
        src = e.get("source") or e.get("from")
        tgt = e.get("target") or e.get("to")
        if src == node_id or tgt == node_id:
            out.append(e)
    return out


def _journal_mentions(case_dir: str | os.PathLike, needle: str) -> list[dict[str, Any]]:
    from core.run_journal import list_runs, load_run

    hits: list[dict[str, Any]] = []
    needle_l = needle.lower()
    for meta in list_runs(case_dir):
        rid = meta.get("run_id") or ""
        run = load_run(case_dir, rid)
        if not run:
            continue
        for entry in run.get("journal") or run.get("entries") or []:
            blob = json.dumps(entry, default=str).lower()
            if needle_l in blob:
                hits.append({
                    "run_id": rid,
                    "reason": entry.get("reason"),
                    "summary": (entry.get("summary") or entry.get("what")
                                or entry.get("why") or "")[:200],
                    "at": entry.get("at") or entry.get("ts") or run.get("finished_at"),
                })
    return hits[-40:]  # newest-ish tail


def explain(
    case_dir: str | os.PathLike,
    *,
    node_id: str | None = None,
    section_id: str | None = None,
    conflict_id: str | None = None,
) -> dict[str, Any]:
    """Explain a claim/conclusion/conflict or a report projection section."""
    from core.claim_graph import get_node, load_graph
    from core.report_projection import load_manifest, section_context

    root = Path(case_dir).resolve()
    graph = load_graph(root)

    if section_id:
        from core.report_projection import resolve_section_id
        section_id = resolve_section_id(section_id)
        manifest = load_manifest(root)
        sec = (manifest.get("sections") or {}).get(section_id)
        if not sec:
            return {
                "success": False,
                "error": f"unknown section {section_id!r}",
                "known_sections": sorted((manifest.get("sections") or {}).keys()),
            }
        ctx = section_context(root, section_id)
        bound = []
        for key in ("claim_ids", "conclusion_ids", "conflict_ids", "hypothesis_ids"):
            for nid in sec.get(key) or []:
                n = get_node(graph, nid)
                if n:
                    bound.append({
                        "id": nid,
                        "kind": n.get("kind"),
                        "status": n.get("status"),
                        "statement": (n.get("statement") or "")[:240],
                        "confidence": n.get("confidence"),
                    })
        return {
            "success": True,
            "kind": "section",
            "section_id": section_id,
            "status": sec.get("status"),
            "bindings": bound,
            "context_keys": sorted(ctx.keys()) if isinstance(ctx, dict) else [],
            "journal_events": _journal_mentions(root, section_id),
            "section_meta": {
                k: sec.get(k) for k in (
                    "status", "content_sha256", "updated_at", "claim_ids",
                    "conclusion_ids", "conflict_ids",
                )
            },
        }

    target = conflict_id or node_id
    if not target:
        return {"success": False, "error": "pass a node id, --section, or --conflict"}

    node = get_node(graph, target)
    if node is None:
        # Soft-match conflict by prefix X
        if not conflict_id and target.upper().startswith("X"):
            node = get_node(graph, target.upper())
        if node is None:
            return {
                "success": False,
                "error": f"node {target!r} not found in claim graph",
            }

    edges = _edges_touching(graph, node["id"])
    related = []
    for e in edges:
        src = e.get("source") or e.get("from")
        tgt = e.get("target") or e.get("to")
        other = tgt if src == node["id"] else src
        other_n = get_node(graph, other) if other else None
        related.append({
            "edge_kind": e.get("kind") or e.get("type"),
            "from": src,
            "to": tgt,
            "other_id": other,
            "other_statement": (
                (other_n.get("statement") or "")[:160] if other_n else None
            ),
        })

    return {
        "success": True,
        "kind": node.get("kind"),
        "id": node.get("id"),
        "statement": node.get("statement") or node.get("summary") or "",
        "confidence": node.get("confidence"),
        "status": node.get("status"),
        "host": node.get("host"),
        "scope": node.get("scope"),
        "evidence": node.get("evidence") or [],
        "reasoning": node.get("reasoning") or "",
        "gaps": node.get("gaps") or [],
        "temporal_qualifier": node.get("temporal_qualifier"),
        "related_edges": related,
        "journal_events": _journal_mentions(root, node["id"]),
        "created_at": node.get("created_at"),
        "updated_at": node.get("updated_at"),
    }


def format_explain(result: dict[str, Any]) -> str:
    if not result.get("success"):
        return f"explain failed: {result.get('error')}"
    if result.get("kind") == "section":
        lines = [
            f"Section: {result['section_id']}  status={result.get('status')}",
            "Bound beliefs:",
        ]
        for b in result.get("bindings") or []:
            lines.append(
                f"  - [{b.get('kind')}] {b.get('id')} ({b.get('status')}) "
                f"{b.get('statement')}"
            )
        if not result.get("bindings"):
            lines.append("  (none)")
        je = result.get("journal_events") or []
        lines.append(f"Journal events mentioning section: {len(je)}")
        for e in je[-8:]:
            lines.append(f"  · {e.get('run_id')} {e.get('reason')}: {e.get('summary')}")
        return "\n".join(lines)

    lines = [
        f"{result.get('kind')} {result.get('id')}",
        f"Status: {result.get('status')}  Confidence: {result.get('confidence')}",
        f"Host: {result.get('host') or '—'}  Scope: {result.get('scope') or '—'}",
        "",
        "Statement:",
        f"  {result.get('statement') or '(empty)'}",
    ]
    if result.get("reasoning"):
        lines += ["", "Reasoning:", f"  {result['reasoning']}"]
    gaps = result.get("gaps") or []
    if gaps:
        lines += ["", "Gaps:"]
        for g in gaps:
            lines.append(f"  - {g}")
    ev = result.get("evidence") or []
    if ev:
        lines += ["", "Evidence locators:"]
        for e in ev[:20]:
            if isinstance(e, dict):
                loc = e.get("locator") or e.get("path") or e.get("source") or e
                lines.append(f"  - {loc}")
            else:
                lines.append(f"  - {e}")
    related = result.get("related_edges") or []
    lines += ["", f"Related edges ({len(related)}):"]
    for r in related:
        lines.append(
            f"  {r.get('from')} —{r.get('edge_kind')}→ {r.get('to')}"
            + (f"  ({r.get('other_statement')})" if r.get("other_statement") else "")
        )
    je = result.get("journal_events") or []
    lines += ["", f"Journal events ({len(je)}):"]
    for e in je[-10:]:
        lines.append(f"  · {e.get('run_id')} [{e.get('reason')}] {e.get('summary')}")
    if not je:
        lines.append("  (none)")
    return "\n".join(lines)


def _master_timeline_path(root: Path) -> Optional[Path]:
    """The case's master_timeline.tsv: where the Timeline Builder writes it
    (reports/, or the newest rerun snapshot), else analysis/ (cases from
    versions that wrote it there)."""
    from core.report_snapshots import report_files
    for f in report_files(root):
        if f["name"] == "master_timeline.tsv":
            return Path(f["abs_path"])
    legacy = root / "analysis" / "master_timeline.tsv"
    return legacy if legacy.is_file() else None


# Header names a master timeline may use for its columns, by role (the
# Timeline Builder's own: Timestamp, Machine, User, Event, Source,
# Description; plaso-style: datetime, message). Matched case-insensitively.
_TS_COLUMNS = ("timestamp", "datetime", "date", "time")
_TEXT_COLUMNS = ("description", "message", "event", "summary")
_HOST_COLUMNS = ("machine", "host", "computer")
_USER_COLUMNS = ("user", "account")


def _read_master_timeline(tsv: Path, limit: Optional[int]) -> tuple[list[dict[str, Any]], int]:
    """Stream the TSV: keep the first ``limit`` rows (every row when None)
    and count them all, so a file of millions of rows costs no more memory
    than the rows shown."""
    events: list[dict[str, Any]] = []
    total = 0
    with tsv.open(encoding="utf-8", errors="replace", newline="") as fh:
        # The Timeline Builder writes tab-joined lines without quoting, and a
        # Windows command line starts with a quote: a quote is text here.
        reader = csv.reader(fh, delimiter="\t", quoting=csv.QUOTE_NONE)
        first = next(reader, None)
        if first is None:
            return events, 0
        names = [c.strip().lower() for c in first]
        has_header = any(n in _TS_COLUMNS + _TEXT_COLUMNS for n in names)

        def col(roles):
            return next((names.index(r) for r in roles if r in names), None)

        ts_i, text_i = col(_TS_COLUMNS), col(_TEXT_COLUMNS)
        host_i, user_i = col(_HOST_COLUMNS), col(_USER_COLUMNS)

        def event(row: list[str]) -> dict[str, Any]:
            def at(i):
                return row[i] if i is not None and i < len(row) else ""
            if has_header:
                ts, text = at(ts_i), at(text_i)
            else:           # a headerless file: first column, last column
                ts, text = (row[0] if row else ""), (row[-1] if len(row) > 1 else "")
            e = {"ts": ts, "kind": "master_timeline", "summary": text[:240],
                 "source": "master_timeline.tsv"}
            if at(host_i):
                e["host"] = at(host_i)
            if at(user_i):
                e["user"] = at(user_i)
            return e

        rows = reader if has_header else _chain_first(first, reader)
        for row in rows:
            if not any(cell.strip() for cell in row):
                continue
            total += 1
            if limit is None or len(events) < limit:
                events.append(event(row))
    return events, total


def _chain_first(first: list[str], rest):
    yield first
    yield from rest


def build_timeline(
    case_dir: str | os.PathLike,
    *,
    source: str = "claims",
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Case-level timeline from claims/journal or master_timeline.tsv.

    For the master timeline ``limit`` bounds the events kept (None keeps
    every row); ``count`` is always the number of rows in the file and
    ``shown`` the number kept."""
    root = Path(case_dir).resolve()
    if source == "master":
        tsv = _master_timeline_path(root)
        if tsv is None:
            return {
                "success": False,
                "error": (f"no master_timeline.tsv under {root / 'reports'} (or its newest "
                          f"snapshot, or analysis/) — run the Timeline Builder or use --from-claims"),
                "source": "master",
            }
        events, total = _read_master_timeline(tsv, limit)
        return {
            "success": True,
            "source": "master",
            "path": str(tsv),
            "events": events,
            "count": total,
            "shown": len(events),
        }

    # default: claims + journal milestones
    from core.claim_graph import load_graph
    from core.run_journal import list_runs, load_milestones, load_run

    graph = load_graph(root)
    events: list[dict[str, Any]] = []
    for n in (graph.get("nodes") or {}).values():
        if n.get("kind") not in ("claim", "conclusion", "conflict", "hypothesis"):
            continue
        ts = n.get("updated_at") or n.get("created_at") or ""
        events.append({
            "ts": ts,
            "kind": n.get("kind"),
            "id": n.get("id"),
            "status": n.get("status"),
            "confidence": n.get("confidence"),
            "summary": (n.get("statement") or "")[:240],
            "source": "claim_graph",
        })

    for m in (load_milestones(root).get("milestones") or []):
        events.append({
            "ts": m.get("at") or m.get("created_at") or "",
            "kind": "milestone",
            "milestone_kind": m.get("kind"),
            "summary": (m.get("summary") or "")[:240],
            "source": "milestones",
        })

    for meta in list_runs(root):
        rid = meta.get("run_id") or ""
        run = load_run(root, rid)
        if not run:
            continue
        for entry in run.get("journal") or run.get("entries") or []:
            events.append({
                "ts": entry.get("at") or entry.get("ts") or run.get("finished_at") or "",
                "kind": "journal",
                "run_id": rid,
                "reason": entry.get("reason"),
                "summary": (
                    entry.get("summary") or entry.get("what") or entry.get("why") or ""
                )[:240],
                "source": "run_journal",
            })

    events.sort(key=lambda e: e.get("ts") or "")
    return {
        "success": True,
        "source": "claims",
        "events": events,
        "count": len(events),
    }


def format_timeline(result: dict[str, Any], *, limit: int = 200) -> str:
    if not result.get("success"):
        return f"timeline failed: {result.get('error')}"
    events = result.get("events") or []
    lines = [
        f"Timeline ({result.get('source')}) — {result.get('count')} event(s)",
        "",
    ]
    shown = events if not limit else events[:limit]
    for e in shown:
        ts = e.get("ts") or "—"
        kind = e.get("kind") or "?"
        ident = e.get("id") or e.get("run_id") or e.get("milestone_kind") or ""
        prefix = f"[{ident}] " if ident else ""
        where = e.get("host") or ""
        where = f"{where}  " if where else ""
        lines.append(f"{ts}  {kind:12}  {prefix}{where}{e.get('summary') or ''}")
    count = int(result.get("count") or len(events))
    if count > len(shown):
        lines.append(f"showing {len(shown)} of {count} (--limit N for more, --limit 0 for all)")
    return "\n".join(lines)


def investigation_status(case_dir: str | os.PathLike) -> dict[str, Any]:
    """One-screen investigation health from Current Investigation State."""
    from core.investigation_state import build_current_investigation_state, atlas_dir

    root = Path(case_dir).resolve()
    state = build_current_investigation_state(root, compact=True)
    dirty_evidence: list[str] = []
    dirty_paths: list[str] = []
    inv_path = atlas_dir(root) / "invalidation_queue.json"
    if inv_path.is_file():
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            dirty_evidence = list(inv.get("dirty_evidence") or [])[:40]
            dirty_paths = list(inv.get("dirty_paths") or [])[:40]
        except (OSError, json.JSONDecodeError):
            pass

    journal = state.get("journal") or {}
    projection = state.get("report_projection") or {}
    counts = state.get("counts") or {}
    last = journal.get("last_run")
    last_id = None
    if isinstance(last, dict):
        last_id = last.get("run_id") or last.get("id")
    elif last:
        last_id = str(last)
    return {
        "success": True,
        "case_id": state.get("case_id"),
        "case_dir": str(root),
        "has_beliefs": state.get("has_beliefs"),
        "counts": counts,
        "open_conflicts": (state.get("claim_graph") or {}).get("open_conflicts") or [],
        "needs_review": state.get("needs_review") or [],
        "dirty_evidence_count": len(dirty_evidence) or len(dirty_paths),
        "dirty_evidence": dirty_evidence or dirty_paths,
        "stale_sections": projection.get("stale_sections") or [],
        "missing_sections": projection.get("missing_sections") or [],
        "last_run": last_id,
        "last_run_meta": last if isinstance(last, dict) else None,
        "run_count": journal.get("run_count"),
        "last_assembled_at": projection.get("last_assembled_at"),
        "last_assembled_path": projection.get("last_assembled_path"),
        "built_at": state.get("built_at"),
    }


def format_status(result: dict[str, Any]) -> str:
    if not result.get("success"):
        return f"status failed: {result.get('error')}"
    c = result.get("counts") or {}
    lines = [
        f"Investigation status — {result.get('case_id')}",
        f"  Case dir: {result.get('case_dir')}",
        f"  Beliefs: {'yes' if result.get('has_beliefs') else 'no'}",
        f"  Conclusions: {c.get('conclusions', 0)}  Claims: {c.get('claims', 0)}  "
        f"Hypotheses: {c.get('hypotheses', 0)}",
        f"  Open conflicts: {c.get('conflicts', 0)}  needs_review: {c.get('needs_review', 0)}",
        f"  Dirty evidence: {result.get('dirty_evidence_count', 0)}",
        f"  Stale sections: {', '.join(result.get('stale_sections') or []) or '(none)'}",
        f"  Missing sections: {', '.join(result.get('missing_sections') or []) or '(none)'}",
        f"  Last journal run: {result.get('last_run') or '—'} "
        f"(runs={result.get('run_count') or 0})",
        f"  Last assembled: {result.get('last_assembled_at') or '—'} "
        f"{result.get('last_assembled_path') or ''}".rstrip(),
    ]
    conflicts = result.get("open_conflicts") or []
    if conflicts:
        lines.append("  Conflicts:")
        for n in conflicts[:8]:
            if isinstance(n, dict):
                lines.append(
                    f"    - {n.get('id')}: {(n.get('statement') or '')[:100]}"
                )
            else:
                lines.append(f"    - {n}")
    needs = result.get("needs_review") or []
    if needs:
        lines.append("  Needs review:")
        for n in needs[:8]:
            lines.append(
                f"    - {n.get('id')} [{n.get('kind')}]: "
                f"{(n.get('statement') or '')[:100]}"
            )
    dirty = result.get("dirty_evidence") or []
    if dirty:
        lines.append("  Dirty (sample):")
        for d in dirty[:6]:
            lines.append(f"    - {d}")
    return "\n".join(lines)
