"""Reject a staged memory candidate with a recorded rationale.

The counterpart to approve: nothing enters durable memory, but the candidate
is archived to inbox/processed/ with status "rejected" and the reviewer's
reasoning appended. Deleting a rejected candidate instead would (a) discard
the audit record of *why* it was rejected and (b) break capture's
content-hash dedup — the same learning would be re-staged on the very next
run and rejected again, forever.
"""

from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path

from core.brain import frontmatter, indexes, store


class RejectError(Exception):
    pass


def reject(candidate: Path, reason: str, yes: bool = False) -> Path:
    root = store.brain_root()
    candidate = candidate if candidate.is_absolute() else root / candidate
    if not candidate.is_file():
        raise RejectError(f"candidate not found: {candidate}")
    reason = (reason or "").strip()
    if not reason:
        raise RejectError(
            "a rejection reason is required — it is the audit record")

    text = candidate.read_text(encoding="utf-8", errors="replace")
    meta, body, _ = frontmatter.parse(text)

    if not yes:
        print(f"Will reject and archive: {candidate.name}")
        answer = input("Reject? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            raise RejectError("aborted")

    date = dt.date.today().isoformat()
    meta["status"] = "rejected"
    meta["updated"] = date
    body = (body.rstrip()
            + f"\n\n## Review Decision ({date})\n\nREJECTED — {reason}\n")

    processed = root / "inbox/processed" / candidate.name
    processed.parent.mkdir(parents=True, exist_ok=True)
    processed.write_text(frontmatter.serialize(meta, body), encoding="utf-8")
    candidate.unlink()
    indexes.rebuild()
    return processed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reject a memory candidate, archiving it with a reason")
    parser.add_argument("candidate")
    parser.add_argument("--reason", required=True,
                        help="why the candidate was rejected (audit record)")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        dest = reject(Path(args.candidate), args.reason, yes=args.yes)
    except RejectError as e:
        print(f"error: {e}")
        return 1
    print(f"Rejected -> {dest}")
    print("Indexes rebuilt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
