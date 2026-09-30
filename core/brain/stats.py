"""Brain statistics: answers "how much have we learned?"

Writes a JSON snapshot per day; snapshots are the growth time series that
`brain report` diffs against. Includes the cross-case accuracy roll-up pulled
from run summaries.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter

from core.brain import frontmatter, indexes, store


def _open_loops(root) -> tuple[int, int]:
    path = root / "memory" / "open-loops.md"
    if not path.is_file():
        return 0, 0
    text = path.read_text(encoding="utf-8", errors="replace")
    open_ = len(re.findall(r"^\s*- \[ \]", text, re.M))
    closed = len(re.findall(r"^\s*- \[x\]", text, re.M | re.I))
    return open_, closed


def collect() -> dict:
    root = store.brain_root()
    index_summary = indexes.rebuild()

    by_type: Counter = Counter()
    tags: Counter = Counter()
    cases_seen: set[str] = set()
    accuracy: dict[str, dict] = {}
    created_dates: list[str] = []

    for note in store.iter_notes():
        by_type[note.type] += 1
        tags.update(note.tags)
        created = str(note.meta.get("created", ""))[:10]
        if re.match(r"\d{4}-\d{2}-\d{2}", created):
            created_dates.append(created)
        entities = note.meta.get("entities") or {}
        cases_seen.update(str(c) for c in entities.get("cases") or [])
        if note.type == "run" and isinstance(note.meta.get("accuracy"), dict):
            for case in entities.get("cases") or []:
                accuracy[str(case)] = note.meta["accuracy"]

    pending = len(list((root / "inbox/memory-candidates").glob("*.md")))
    processed = len(list((root / "inbox/processed").glob("*.md")))
    open_loops, closed_loops = _open_loops(root)
    warnings = index_summary["warnings"]

    return {
        "date": dt.date.today().isoformat(),
        "totals": {
            "knowledge_objects": sum(by_type.values()),
            "wiki_pages": sum(v for k, v in by_type.items()
                              if k in ("case", "tool", "technique", "actor",
                                       "concept")),
            "decisions": by_type.get("decision", 0),
            "research": by_type.get("research", 0),
            "run_summaries": by_type.get("run", 0),
            "open_loops": open_loops,
            "closed_loops": closed_loops,
            "candidates_pending": pending,
            "candidates_processed": processed,
        },
        "by_type": dict(by_type),
        "top_tags": tags.most_common(10),
        "created_dates": sorted(Counter(created_dates).items()),
        "cases_seen": sorted(cases_seen),
        "accuracy": accuracy,
        "quality": {
            "warnings": len(warnings),
            "orphans": sum(1 for w in warnings if "orphan" in w),
            "missing_tags": sum(1 for w in warnings if "missing tags" in w),
            "broken_links": sum(1 for w in warnings if "broken link" in w),
        },
        "security": {
            "confidential_skipped": index_summary["skipped_confidential"],
            "secret_warnings": index_summary["skipped_secrets"],
        },
    }


def snapshot() -> tuple[dict, str]:
    root = store.brain_root()
    stats = collect()
    out = root / "analytics/snapshots" / f"{stats['date']}-brain-snapshot.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return stats, str(out)


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description="Brain stats + snapshot").parse_args(argv)
    stats, path = snapshot()
    t = stats["totals"]
    print("Second Brain Learning Report")
    print()
    print(f"Knowledge objects: {t['knowledge_objects']}")
    print(f"Wiki pages: {t['wiki_pages']}  Decisions: {t['decisions']}  "
          f"Research: {t['research']}  Run summaries: {t['run_summaries']}")
    print(f"Open loops: {t['open_loops']} open / {t['closed_loops']} closed")
    print(f"Memory candidates: {t['candidates_pending']} pending / "
          f"{t['candidates_processed']} processed")
    if stats["top_tags"]:
        print("Top tags: " + ", ".join(f"{t}({n})" for t, n in stats["top_tags"][:6]))
    if stats["accuracy"]:
        print("Accuracy by case: " + "; ".join(
            f"{c}: F1={m.get('f1', '?')}" for c, m in
            sorted(stats["accuracy"].items())))
    q, s = stats["quality"], stats["security"]
    print(f"Quality warnings: {q['warnings']} "
          f"(orphans {q['orphans']}, missing tags {q['missing_tags']}, "
          f"broken links {q['broken_links']})")
    print(f"Security: {s['confidential_skipped']} confidential skipped, "
          f"{s['secret_warnings']} secret-like warnings")
    print()
    print(f"Snapshot: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
