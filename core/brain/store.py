"""Note store: brain root resolution, slugs, type routing, iteration.

Every filesystem walk in the brain package goes through ``iter_notes`` so the
safety invariant — never read outside ``brain/`` — is enforced in one place.
"""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from core.brain import frontmatter

REPO_ROOT = Path(__file__).resolve().parents[2]

# Subdirectories of brain/ that hold knowledge notes. analytics/, templates/,
# scripts/, and indexes/ are never indexed as notes.
DATA_DIRS = ("memory", "wiki", "logs", "inbox")

# type -> destination directory (brain-relative)
TYPE_DIRS = {
    "note": "inbox/raw",
    "case": "wiki/cases",
    "tool": "wiki/tools",
    "technique": "wiki/techniques",
    "actor": "wiki/actors",
    "concept": "wiki/concepts",
    "environment": "wiki/environments",
    "decision": "logs/decisions",
    "research": "logs/research",
    "run": "logs/runs",
    "memory_candidate": "inbox/memory-candidates",
}


def brain_root() -> Path:
    """The brain data directory. ATLAS_BRAIN_ROOT overrides (used by tests)."""
    override = os.environ.get("ATLAS_BRAIN_ROOT")
    return Path(override) if override else REPO_ROOT / "brain"


def slugify(title: str) -> str:
    text = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text).strip("-").lower()
    return text or "untitled"


@dataclass
class Note:
    path: Path            # absolute
    rel_path: str         # brain-relative, posix
    meta: dict
    body: str
    warnings: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return str(self.meta.get("title") or self.path.stem)

    @property
    def type(self) -> str:
        return str(self.meta.get("type") or "note")

    @property
    def slug(self) -> str:
        return self.path.stem

    @property
    def confidential(self) -> bool:
        return self.meta.get("source_classification") == "confidential"

    @property
    def tags(self) -> list[str]:
        tags = self.meta.get("tags") or []
        return [str(t) for t in tags] if isinstance(tags, list) else []

    def related_slugs(self) -> list[str]:
        """Slugs referenced via YAML `related` and [[wikilinks]] in the body."""
        slugs = []
        for item in self.meta.get("related") or []:
            m = re.match(r"\[\[(.+?)\]\]", str(item))
            slugs.append(m.group(1) if m else str(item))
        slugs.extend(re.findall(r"\[\[(.+?)\]\]", self.body))
        return sorted({s.strip() for s in slugs if s.strip()})


def iter_notes(include_confidential: bool = False, root: Path | None = None):
    """Yield every Note under the brain data dirs. Sorted for determinism."""
    base = root or brain_root()
    for data_dir in DATA_DIRS:
        d = base / data_dir
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*.md")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meta, body, warnings = frontmatter.parse(text)
            note = Note(path=path,
                        rel_path=path.relative_to(base).as_posix(),
                        meta=meta, body=body, warnings=warnings)
            if note.confidential and not include_confidential:
                continue
            yield note


def count_confidential(root: Path | None = None) -> int:
    return sum(1 for n in iter_notes(include_confidential=True, root=root)
               if n.confidential)
