"""Atlas second brain: durable, Markdown-based cross-case knowledge.

Data lives under ``brain/`` at the repo root; this package holds all
executable logic. ``brain/scripts/*.py`` are thin standalone wrappers so
non-Atlas agents can invoke the same code per brain/AGENTS.md.
"""

from core.brain.store import brain_root  # noqa: F401
