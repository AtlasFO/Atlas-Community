"""Simple ranked search over brain notes.

Ranking: title match > tag match > backlink match > body term frequency,
tie-broken by `updated` recency. Also powers system-prompt retrieval
injection (agent/prompts.py), so keep it dependency-free and fast.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field

from core.brain import store


@dataclass
class Hit:
    rel_path: str
    title: str
    type: str
    updated: str
    score: float
    snippet: str
    body: str
    # note frontmatter (origin etc.) — lets injection-time filters see
    # provenance without re-reading the note
    meta: dict = field(default_factory=dict)


def _terms(query: str) -> list[str]:
    return [t for t in re.split(r"\W+", query.lower()) if len(t) > 1]


def _snippet(body: str, terms: list[str], width: int = 160) -> str:
    lower = body.lower()
    for term in terms:
        pos = lower.find(term)
        if pos >= 0:
            start = max(0, pos - width // 3)
            return re.sub(r"\s+", " ", body[start:start + width]).strip()
    return re.sub(r"\s+", " ", body[:width]).strip()


def search(query: str, types: list[str] | None = None,
           tags: list[str] | None = None, limit: int = 10,
           include_confidential: bool = False) -> list[Hit]:
    terms = _terms(query)
    hits: list[Hit] = []
    for note in store.iter_notes(include_confidential=include_confidential):
        if types and note.type not in types:
            continue
        if tags and not set(t.lower() for t in note.tags) & set(t.lower() for t in tags):
            continue
        title_l = note.title.lower()
        tags_l = [t.lower() for t in note.tags]
        body_l = note.body.lower()
        backlinks_l = [s.lower() for s in note.related_slugs()]
        score = 0.0
        for term in terms:
            if term in title_l:
                score += 10.0
            if any(term in t for t in tags_l):
                score += 6.0
            if any(term in s for s in backlinks_l):
                score += 3.0
            score += min(body_l.count(term), 5) * 1.0
        if score <= 0:
            continue
        hits.append(Hit(rel_path=note.rel_path, title=note.title,
                        type=note.type, updated=str(note.meta.get("updated", "")),
                        score=score, snippet=_snippet(note.body, terms),
                        body=note.body, meta=dict(note.meta or {})))
    hits.sort(key=lambda h: (h.score, h.updated), reverse=True)
    return hits[:limit]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Search brain notes")
    parser.add_argument("query")
    parser.add_argument("--type", action="append", dest="types")
    parser.add_argument("--tag", action="append", dest="tags")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--include-confidential", action="store_true")
    args = parser.parse_args(argv)
    hits = search(args.query, types=args.types, tags=args.tags,
                  limit=args.limit, include_confidential=args.include_confidential)
    if not hits:
        # A search that finds nothing succeeded; a non-zero exit read as a
        # failure to every script and made the audit's table say so.
        print("No matches.")
        return 0
    for h in hits:
        print(f"{h.rel_path}  [{h.type}]  {h.title}  (updated {h.updated}, score {h.score:.0f})")
        print(f"    {h.snippet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
