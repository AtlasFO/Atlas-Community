"""List staged memory candidates awaiting human review.

The ``likely_case_specific`` hint surfaced here (from ``capture._review_hints``)
is now also ENFORCED at ``approve()`` for public-wiki destinations: a candidate
flagged case-specific — or carrying raw identifiers/IOCs — cannot be promoted
into ``wiki/{concepts,techniques,tools,actors}`` until it is generalized. This
list is the soft signal; approve is the hard gate at the public boundary.
"""

from __future__ import annotations

import argparse
from collections import defaultdict

from core.brain import frontmatter, store


def list_candidates(candidate_type: str | None = None,
                    risk_only: bool = False) -> list[dict]:
    root = store.brain_root()
    items = []
    for path in sorted((root / "inbox/memory-candidates").glob("*.md")):
        raw = path.read_text(encoding="utf-8", errors="replace")
        meta, body, _ = frontmatter.parse(raw)
        ctype = str(meta.get("candidate_type", "unknown"))
        sensitive = bool((meta.get("risk") or {}).get("contains_sensitive_data"))
        if candidate_type and ctype != candidate_type:
            continue
        if risk_only and not sensitive:
            continue
        hints = meta.get("review_hints") or {}
        signals = [str(s) for s in (hints.get("signals") or [])]
        expl = meta.get("explainability") or {}
        origin = meta.get("origin") or {}
        # Prefer structured explainability; fall back to body sections.
        def _section(name: str) -> str:
            lines, capture = [], False
            for line in body.splitlines():
                if line.startswith("#"):
                    capture = name.lower() in line.lower()
                    continue
                if capture:
                    lines.append(line)
            return "\n".join(lines).strip()

        proposed = _section("Proposed Entry")
        items.append({
            "path": path,
            "title": str(meta.get("title", path.stem)),
            "candidate_type": ctype,
            "knowledge_kind": str(meta.get("knowledge_kind") or ""),
            "destination": str(meta.get("suggested_destination", "")),
            "status": str(meta.get("status", "pending_review")),
            "confidence": str(meta.get("confidence", "")),
            "sensitive": sensitive,
            "contains_answer_key": bool(
                (meta.get("risk") or {}).get("contains_answer_key")),
            "case": str(origin.get("case_id", "")),
            "learning_phase": str(origin.get("learning_phase") or "capture"),
            "origin_sources": list(expl.get("origin_sources")
                                   or origin.get("sources") or []),
            "why_exists": str(expl.get("why_exists")
                              or _section("Why This Candidate Exists")
                              or _section("Why This May Be Useful")),
            "why_reusable": str(expl.get("why_reusable")
                                or _section("Why Reusable")),
            "supporting_evidence": str(
                expl.get("supporting_evidence")
                or _section("Supporting Evidence")),
            "proposed_entry": proposed,
            "likely_case_specific": bool(hints.get("likely_case_specific")),
            "signals": signals,
            # e.g. "deadline, next_run_todo" — category names only
            "hints": ", ".join(sorted({s.split(":", 1)[0] for s in signals})),
        })
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List staged memory candidates")
    parser.add_argument("--type", dest="candidate_type")
    parser.add_argument("--risk", action="store_true",
                        help="only candidates flagged sensitive")
    args = parser.parse_args(argv)
    items = list_candidates(candidate_type=args.candidate_type,
                            risk_only=args.risk)
    if not items:
        print("No pending memory candidates.")
        return 0

    groups: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        groups[item["candidate_type"]].append(item)
    try:
        from rich.console import Console
        from rich.table import Table
        table = Table(title=f"Memory candidates ({len(items)} pending)")
        for col in ("type", "title", "case", "destination", "risk", "hints",
                    "file"):
            table.add_column(col)
        for ctype in sorted(groups):
            for item in groups[ctype]:
                hints = item["hints"]
                if item["likely_case_specific"]:
                    hints = f"⚠ case-specific? {hints}"
                table.add_row(ctype, item["title"], item["case"],
                              item["destination"],
                              "⚠ sensitive" if item["sensitive"] else "",
                              hints,
                              item["path"].name)
        Console().print(table)
    except ImportError:
        for ctype in sorted(groups):
            print(f"\n[{ctype}]")
            for item in groups[ctype]:
                flag = " (SENSITIVE)" if item["sensitive"] else ""
                if item["likely_case_specific"]:
                    flag += f" (CASE-SPECIFIC? {item['hints']})"
                print(f"  {item['title']}{flag}")
                print(f"    -> {item['destination']}  [{item['path']}]")
    print(f"\nApprove with: atlas brain approve "
          f"inbox/memory-candidates/<file> --yes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
