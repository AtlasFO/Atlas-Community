"""Markdown learning reports: current stats diffed against a prior snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter

from core.brain import store
from core.brain.stats import snapshot


def _prior_snapshot(root, cutoff: dt.date) -> dict | None:
    """Newest snapshot dated on or before the cutoff (window start)."""
    best = None
    for p in sorted((root / "analytics/snapshots").glob("*-brain-snapshot.json")):
        m = re.match(r"(\d{4}-\d{2}-\d{2})", p.name)
        if not m:
            continue
        date = dt.date.fromisoformat(m.group(1))
        if date <= cutoff:
            try:
                best = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
    return best


def _recurring_recommendations(root) -> list[tuple[str, int]]:
    """Candidate texts that keep coming back across runs — the systemic gaps."""
    counts: Counter = Counter()
    for d in ("inbox/memory-candidates", "inbox/processed"):
        for p in (root / d).glob("*.md"):
            text = p.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"## Proposed Entry\n+(.+)", text)
            if m:
                key = re.sub(r"\W+", " ", m.group(1).lower()).strip()[:80]
                counts[key] += 1
    return [(k, n) for k, n in counts.most_common(5) if n > 1]


def _delta(current: dict, prior: dict | None, key: str) -> str:
    cur = current["totals"].get(key, 0)
    if prior is None:
        return f"{cur}"
    diff = cur - prior.get("totals", {}).get(key, 0)
    return f"{cur} ({'+' if diff >= 0 else ''}{diff})"


def generate(period: str | None = None, since: str | None = None) -> str:
    root = store.brain_root()
    today = dt.date.today()
    if since:
        cutoff = dt.date.fromisoformat(since)
        label = f"since {since}"
    elif period == "month":
        cutoff = today - dt.timedelta(days=30)
        label = "monthly"
    else:
        period = period or "week"
        cutoff = today - dt.timedelta(days=7)
        label = "weekly"

    prior = _prior_snapshot(root, cutoff)
    current, _ = snapshot()
    t = current["totals"]

    new_notes = sum(n for d, n in current["created_dates"]
                    if dt.date.fromisoformat(d) > cutoff)

    lines = [f"# {label.title()} Brain Report — {today.isoformat()}", ""]
    lines += ["## Summary", "",
              f"- Knowledge objects: {_delta(current, prior, 'knowledge_objects')}",
              f"- Notes created in window: {new_notes}",
              f"- Decisions: {_delta(current, prior, 'decisions')}",
              f"- Research findings: {_delta(current, prior, 'research')}",
              f"- Run summaries: {_delta(current, prior, 'run_summaries')}",
              f"- Open loops: {_delta(current, prior, 'open_loops')} open",
              f"- Pending memory candidates: "
              f"{_delta(current, prior, 'candidates_pending')}", ""]
    if prior is None:
        lines += ["_No prior snapshot inside the window — deltas unavailable; "
                  "totals shown as-is._", ""]

    lines += ["## Growing Topics", ""]
    lines += [f"- {tag} ({n} notes)" for tag, n in current["top_tags"][:5]] or ["- (none)"]
    lines.append("")

    lines += ["## Accuracy Trend", ""]
    if current["accuracy"]:
        for case, m in sorted(current["accuracy"].items()):
            lines.append(f"- {case}: precision={m.get('precision', '?')}, "
                         f"recall={m.get('recall', '?')}, f1={m.get('f1', '?')}")
    else:
        lines.append("- No ground-truth accuracy recorded yet "
                     "(run `atlas train` on a case with ground_truth.json).")
    lines.append("")

    lines += ["## Recurring Reviewer Recommendations", ""]
    recurring = _recurring_recommendations(root)
    lines += [f"- ({n}×) {text}" for text, n in recurring] or \
        ["- None recur — no systemic gaps detected."]
    lines.append("")

    q, s = current["quality"], current["security"]
    lines += ["## Quality Issues", "",
              f"- {q['orphans']} orphan notes",
              f"- {q['missing_tags']} notes missing tags",
              f"- {q['broken_links']} broken links",
              f"- {t['candidates_pending']} memory candidates pending review",
              "", "## Security Hygiene", "",
              f"- {s['confidential_skipped']} confidential files excluded "
              "(aggregate count only)",
              f"- {s['secret_warnings']} secret-like warnings", "",
              "## Recommended Cleanup Actions", ""]
    actions = []
    if t["candidates_pending"]:
        actions.append(f"- Review {t['candidates_pending']} pending candidates: "
                       "`atlas brain review`")
    if q["broken_links"]:
        actions.append("- Fix broken [[links]]: `atlas brain reindex --verbose`")
    if q["missing_tags"]:
        actions.append("- Tag untagged notes for better retrieval")
    lines += actions or ["- Nothing pressing."]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Markdown learning report")
    parser.add_argument("--period", choices=["week", "month"])
    parser.add_argument("--since", help="YYYY-MM-DD")
    args = parser.parse_args(argv)
    text = generate(period=args.period, since=args.since)
    root = store.brain_root()
    label = "since" if args.since else (args.period or "week") + "ly"
    out = (root / "analytics/reports" /
           f"{dt.date.today().isoformat()}-{label}-brain-report.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"Report written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
