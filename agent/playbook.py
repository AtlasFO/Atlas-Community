"""Assemble the Atlas investigation playbook from modular sources.

Source of truth: ``hub/playbook/*.md`` + ``MANIFEST`` (+ ``hub/ENTRY.md``).
Consumers:

- ``agent/prompts.py`` — ``bin/atlas`` analyst system prompt
- ``python -m agent.playbook`` — print or write assembled playbook

The thin ``hub/ENTRY.md`` is the agent entry point; it must not duplicate the
modules. Legacy ``claude/`` paths are accepted if present (one-release dual-read).
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _resolve_paths() -> tuple[Path, Path, Path]:
    """Return (playbook_dir, manifest_path, entry_path). Prefer hub/, else claude/."""
    hub_play = REPO_ROOT / "hub" / "playbook"
    if hub_play.is_dir():
        entry = REPO_ROOT / "hub" / "ENTRY.md"
        if not entry.is_file():
            # legacy filename inside hub/
            alt = REPO_ROOT / "hub" / "CLAUDE.md"
            entry = alt if alt.is_file() else entry
        return hub_play, hub_play / "MANIFEST", entry
    legacy = REPO_ROOT / "claude" / "playbook"
    return legacy, legacy / "MANIFEST", REPO_ROOT / "claude" / "CLAUDE.md"


PLAYBOOK_DIR, MANIFEST_PATH, ENTRY_PATH = _resolve_paths()

# Separates entrypoint from modules in the assembled prompt.
_MODULE_SEP = "\n\n────────────────────────────────────────────────────────\n\n"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def manifest_names() -> list[str]:
    text = _read(MANIFEST_PATH)
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    return names


def load_modules() -> list[tuple[str, str]]:
    """Return ordered (filename, body) pairs from the MANIFEST."""
    out: list[tuple[str, str]] = []
    for name in manifest_names():
        path = PLAYBOOK_DIR / name
        body = _read(path).strip()
        if not body:
            raise FileNotFoundError(f"playbook module missing or empty: {path}")
        out.append((name, body))
    return out


def assemble_playbook(*, include_entry: bool = True) -> str:
    """Concatenate entry + playbook modules in order."""
    # Re-resolve in case tests move trees mid-process
    playbook_dir, manifest_path, entry_path = _resolve_paths()
    global PLAYBOOK_DIR, MANIFEST_PATH, ENTRY_PATH
    PLAYBOOK_DIR, MANIFEST_PATH, ENTRY_PATH = playbook_dir, manifest_path, entry_path

    parts: list[str] = []
    if include_entry:
        entry = _read(ENTRY_PATH).strip()
        if entry:
            parts.append(entry)
    for _name, body in load_modules():
        parts.append(body)
    return _MODULE_SEP.join(parts).rstrip() + "\n"


def write_assembled(dest: Path | None = None) -> Path:
    """Write the assembled playbook. Default: ``hub/playbook.assembled.md``."""
    path = dest or (REPO_ROOT / "hub" / "playbook.assembled.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(assemble_playbook(include_entry=True), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(description="Assemble Atlas hub/playbook")
    p.add_argument(
        "-o", "--output",
        help="write assembled playbook to this path (default: stdout)",
    )
    p.add_argument(
        "--no-entry", action="store_true",
        help="omit hub/ENTRY.md entrypoint (modules only)",
    )
    args = p.parse_args(argv)
    text = assemble_playbook(include_entry=not args.no_entry)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output} ({len(text)} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
