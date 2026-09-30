"""Brain Earth: node/edge graph of the second brain.

Writes brain/analytics/globe/brain-globe.json; the dashboard renders it at
/_dashboard/brain_globe.html using the vendored cytoscape. Deterministic —
no graph libraries; clusters are the top-level knowledge domains.
"""

from __future__ import annotations

import argparse
import datetime as dt
import itertools
import json
import re
from collections import Counter, defaultdict

from core.brain import store

TYPE_WEIGHT = {"case": 4, "concept": 4, "actor": 3, "decision": 3,
               "tool": 2, "technique": 2, "research": 1, "run": 1,
               "note": 1, "memory_candidate": 1}

MAX_TAG_PAIRS_PER_TAG = 12  # cap shared-tag edge fan-out

# "YYYY-MM-DD" or "YYYY-MM-DD HH:MM[ UTC]" (also matches str(datetime.date))
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}))?")


def _created_key(value) -> tuple[str, bool] | None:
    """Normalize a created value to a sortable 'YYYY-MM-DD HH:MM' key.

    Returns (key, has_time); day-only values sort at 00:00. None when the
    value is unparseable (those notes stay visible at every replay step).
    """
    m = _TS.match(str(value or ""))
    if not m:
        return None
    return f"{m.group(1)} {m.group(2) or '00:00'}", bool(m.group(2))


def _build_timeline(nodes: list[dict], run_info: dict[str, dict]) -> list[dict]:
    """Group nodes into replay buckets: one per agent run (origin.run_id),
    falling back to the created timestamp (minute) and finally the created
    date for legacy day-only notes. Mutates each node's 'bucket' field."""
    buckets: dict[str, dict] = {}
    for n in nodes:
        parsed = _created_key(n["created"])
        key, has_time = parsed if parsed else ("", False)
        if n["run_id"]:
            bid, kind = f"run:{n['run_id']}", "run"
        elif has_time:
            bid, kind = f"ts:{key}", "ts"
        elif key:
            bid, kind = f"date:{key[:10]}", "date"
        else:
            n["bucket"] = ""
            continue
        n["bucket"] = bid
        b = buckets.setdefault(bid, {"id": bid, "kind": kind, "added": 0,
                                     "start": "9999", "titles": []})
        b["added"] += 1
        b["titles"].append(n["title"])
        if key and key < b["start"]:
            b["start"] = key

    timeline, running = [], 0
    for b in sorted(buckets.values(), key=lambda b: (b["start"], b["id"])):
        bid, kind = b["id"], b["kind"]
        if kind == "run":
            run_id = bid[len("run:"):]
            info = run_info.get(run_id, {})
            if b["start"] == "9999":  # no member had a parseable created
                m = re.match(r"(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})", run_id)
                b["start"] = f"{m.group(1)} {m.group(2)}:{m.group(3)}" if m \
                    else ""
            case_id = str(info.get("case_id", "")) or run_id
            command = str(info.get("command", "")) or "agent"
            label = f"{case_id} {command} run"
        elif kind == "ts":
            label = b["titles"][0] if b["added"] == 1 else b["start"]
        else:
            label = bid[len("date:"):]
        running += b["added"]
        timeline.append({"id": bid, "kind": kind, "label": label,
                         "start": b["start"], "added": b["added"],
                         "total": running})
    return timeline


def _cluster(rel_path: str) -> str:
    parts = rel_path.split("/")
    if parts[0] == "wiki" and len(parts) > 1:
        return parts[1]
    return parts[0]


def _recency(updated: str, today: dt.date) -> float:
    """1.0 = updated today, decaying to 0.2 at 180+ days."""
    try:
        age = (today - dt.date.fromisoformat(str(updated)[:10])).days
    except ValueError:
        return 0.5
    return max(0.2, 1.0 - age / 180.0 * 0.8)


def _open_loop_slugs(root) -> set[str]:
    path = root / "memory" / "open-loops.md"
    if not path.is_file():
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r"- \[ \].*?\[\[(.+?)\]\]", text))


def build(case: str | None = None, topic: str | None = None,
          mode: str = "full") -> dict:
    root = store.brain_root()
    today = dt.date.today()
    notes = list(store.iter_notes())
    by_slug = {n.slug: n for n in notes}
    open_loops = _open_loop_slugs(root)

    # ── filters ──────────────────────────────────────────────────────────
    if case:
        case_l = case.lower()
        keep = {n.slug for n in notes
                if case_l in [str(c).lower() for c in
                              (n.meta.get("entities") or {}).get("cases") or []]
                or case_l in n.slug}
        keep |= {r for n in notes if n.slug in keep for r in n.related_slugs()}
        notes = [n for n in notes if n.slug in keep]
    if topic:
        topic_l = topic.lower()
        notes = [n for n in notes
                 if topic_l in [t.lower() for t in n.tags]
                 or topic_l in n.title.lower()]

    # ── edges ────────────────────────────────────────────────────────────
    slugs = {n.slug for n in notes}
    edges: dict[tuple[str, str], dict] = {}

    def add_edge(a: str, b: str, etype: str, weight: float):
        if a == b or a not in slugs or b not in slugs:
            return
        key = (min(a, b), max(a, b))
        prev = edges.get(key)
        if prev is None or weight > prev["weight"]:
            edges[key] = {"source": key[0], "target": key[1],
                          "type": etype, "weight": round(weight, 2)}

    tag_members: dict[str, list[str]] = defaultdict(list)
    entity_members: dict[str, list[str]] = defaultdict(list)
    for n in notes:
        for r in n.related_slugs():
            add_edge(n.slug, r, "related", 1.0)
        for t in n.tags:
            tag_members[t].append(n.slug)
        entities = n.meta.get("entities") or {}
        for kind in ("cases", "tools"):
            for e in entities.get(kind) or []:
                entity_members[f"{kind}:{e}"].append(n.slug)
    for members in tag_members.values():
        for a, b in itertools.islice(itertools.combinations(members, 2),
                                     MAX_TAG_PAIRS_PER_TAG):
            add_edge(a, b, "shared_tag", 0.4)
    for members in entity_members.values():
        for a, b in itertools.islice(itertools.combinations(members, 2),
                                     MAX_TAG_PAIRS_PER_TAG):
            add_edge(a, b, "shared_entity", 0.6)

    degree: Counter = Counter()
    for e in edges.values():
        degree[e["source"]] += 1
        degree[e["target"]] += 1

    # ── nodes ────────────────────────────────────────────────────────────
    nodes = []
    run_info: dict[str, dict] = {}  # run_id -> origin (case_id, command)
    for n in notes:
        warning = n.slug in open_loops
        quality_flags = []
        if not n.tags:
            quality_flags.append("missing_tags")
        if n.warnings:
            quality_flags.append("missing_metadata")
        recency = _recency(str(n.meta.get("updated", "")), today)
        if mode == "growth" and recency < 0.9:
            continue
        if mode == "quality" and not (quality_flags or warning):
            continue
        origin = n.meta.get("origin")
        origin = origin if isinstance(origin, dict) else {}
        run_id = str(origin.get("run_id", "") or "")
        if run_id and run_id not in run_info:
            run_info[run_id] = origin
        nodes.append({
            "id": n.slug,
            "path": n.rel_path,
            "title": n.title,
            "type": n.type,
            "cluster": _cluster(n.rel_path),
            "tags": n.tags,
            "created": str(n.meta.get("created", "")),
            "updated": str(n.meta.get("updated", "")),
            "run_id": run_id,
            "bucket": "",
            "size": degree[n.slug] + TYPE_WEIGHT.get(n.type, 1),
            "recency": round(recency, 2),
            "status": str(n.meta.get("status", "")),
            "confidence": str(n.meta.get("confidence", "")),
            "warning": warning,
            "quality_flags": quality_flags,
        })
    node_ids = {n["id"] for n in nodes}
    edge_list = [e for e in edges.values()
                 if e["source"] in node_ids and e["target"] in node_ids]

    # ── timeline: growth replay buckets — by run, then created timestamp,
    # then legacy created date. Notes with unparseable created get no bucket;
    # the viewer shows them at every step of the replay instead.
    timeline = _build_timeline(nodes, run_info)

    clusters = Counter(n["cluster"] for n in nodes)
    pending = len(list((root / "inbox/memory-candidates").glob("*.md")))
    return {
        "generated": dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"),
        "mode": mode, "case": case or "", "topic": topic or "",
        "nodes": nodes,
        "edges": edge_list,
        "timeline": timeline,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edge_list),
            "clusters": len(clusters),
            "largest_cluster": clusters.most_common(1)[0][0] if clusters else "",
            "pending_candidates": pending,
            "open_loops": len(open_loops),
            "confidential_skipped": store.count_confidential(),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Brain Earth data")
    parser.add_argument("--case", help="focus on one case")
    parser.add_argument("--topic", help="focus on one tag/topic")
    parser.add_argument("--mode", default="full",
                        choices=["full", "growth", "quality", "security"])
    args = parser.parse_args(argv)
    data = build(case=args.case, topic=args.topic, mode=args.mode)
    root = store.brain_root()
    out = root / "analytics/globe" / "brain-globe.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    s = data["summary"]
    print("Brain Earth generated.")
    print()
    print(f"Nodes: {s['nodes']}")
    print(f"Edges: {s['edges']}")
    print(f"Clusters: {s['clusters']}")
    print(f"Largest cluster: {s['largest_cluster']}")
    print(f"Pending memory candidates: {s['pending_candidates']}")
    print(f"Open loops: {s['open_loops']}")
    print(f"Confidential files skipped: {s['confidential_skipped']}")
    if data["timeline"]:
        t = data["timeline"]
        print(f"Timeline: {t[0]['start']} → {t[-1]['start']} "
              f"({len(t)} growth step{'s' if len(t) != 1 else ''})")
    print()
    print(f"Data: {out}")
    print("View: start the dashboard (atlas-dashboard) and open "
          "http://127.0.0.1:8765/_dashboard/brain_globe.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
