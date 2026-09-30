"""Note creation from templates."""

from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path

from core.brain import secrets, store


class NoteError(Exception):
    pass


def new_note(note_type: str, title: str, tags: list[str] | None = None,
             body: str | None = None, force: bool = False,
             client: str = "") -> Path:
    if note_type not in store.TYPE_DIRS:
        raise NoteError(f"unknown note type '{note_type}' "
                        f"(expected one of: {', '.join(sorted(store.TYPE_DIRS))})")
    client_slug = store.slugify(client) if client.strip() else ""
    if note_type == "environment" and not client_slug:
        raise NoteError("environment notes require --client "
                        "(the client slug the baseline belongs to)")
    root = store.brain_root()
    template = root / "templates" / f"{note_type.replace('_', '-')}.md"
    if note_type == "run":
        template = root / "templates" / "run-summary.md"
    if not template.is_file():
        template = root / "templates" / "note.md"
    if not template.is_file():
        raise NoteError(f"no template found under {root / 'templates'}")

    dest_dir = root / store.TYPE_DIRS[note_type]
    if note_type == "environment":
        dest_dir = dest_dir / client_slug
    dest = dest_dir / f"{store.slugify(title)}.md"
    if dest.exists() and not force:
        raise NoteError(f"refusing to overwrite {dest} (use --force)")

    now = dt.datetime.now(dt.timezone.utc)
    text = (template.read_text(encoding="utf-8")
            .replace("{{title}}", title)
            .replace("{{client}}", client_slug)
            .replace("{{datetime}}", now.strftime("%Y-%m-%d %H:%M UTC"))
            .replace("{{date}}", now.strftime("%Y-%m-%d")))
    if tags:
        text = text.replace("tags: []", "tags: [" + ", ".join(tags) + "]", 1)
    if body:
        text = text.rstrip() + "\n\n" + body.strip() + "\n"

    hits = secrets.scan_text(title) + secrets.scan_text(body or "")
    if hits:
        kinds = ", ".join(sorted({h.pattern for h in hits}))
        raise NoteError(f"refusing to create note: secret-like content detected ({kinds})")

    if note_type == "environment":
        from core.brain import environment
        verdicts = environment.verdict_hits(title + "\n" + (body or ""))
        if verdicts:
            raise NoteError(
                "refusing to create environment note: verdict language "
                f"detected ({', '.join(verdicts)}) — baselines carry facts, "
                "not judgments; prior-incident IOCs belong in the per-case "
                "wiki entry")

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a brain note from a template")
    parser.add_argument("--type", required=True, choices=sorted(store.TYPE_DIRS))
    parser.add_argument("--title", required=True)
    parser.add_argument("--tags", default="", help="comma-separated tags")
    parser.add_argument("--client", default="",
                        help="client slug (required for --type environment)")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    try:
        path = new_note(args.type, args.title, tags=tags, force=args.force,
                        client=args.client)
    except NoteError as e:
        print(f"error: {e}")
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
