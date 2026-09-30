"""Contributor allow-list for durable brain growth.

Only identities listed in ``brain/CONTRIBUTORS`` may promote candidates into
durable memory (``atlas brain approve``) or commit changes under the durable
brain trees (``memory/``, ``wiki/``, ``logs/``, ``indexes/``). Casual users
still read the brain and may *propose* candidates under ``brain/inbox/`` via a
branch + merge request.

Design: the gate is a no-op while ``brain/CONTRIBUTORS`` is absent, so existing
single-user installs, dev checkouts, and the test suite behave exactly as
before. It engages the moment the file exists with at least one entry — which
is what a multi-user release ships. The pre-commit hook (``.githooks/
pre-commit``) enforces the same rule at commit time; branch protection on
``main`` is the ultimate merge gate.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from core.brain import store


def contributors_file() -> Path:
    """Absolute path to the allow-list (brain-root relative)."""
    return store.brain_root() / "CONTRIBUTORS"


def load_contributors() -> set[str]:
    """Lowercased git emails from CONTRIBUTORS. Empty set if the file is absent
    or holds only comments/blank lines."""
    path = contributors_file()
    if not path.is_file():
        return set()
    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()  # strip whole-line + trailing comments
        if line:
            out.add(line.lower())
    return out


def current_identity() -> str | None:
    """The caller's git identity (email), lowercased. ``ATLAS_BRAIN_IDENTITY``
    overrides for non-git contexts and tests. None if it cannot be determined."""
    override = os.environ.get("ATLAS_BRAIN_IDENTITY")
    if override and override.strip():
        return override.strip().lower()
    try:
        r = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=5,
            cwd=str(store.brain_root()),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    email = (r.stdout or "").strip().lower()
    return email or None


def is_contributor(identity: str | None = None) -> bool:
    """True if durable brain growth is permitted for ``identity`` (defaults to
    the current git identity). Fail-open when no allow-list is configured."""
    allowed = load_contributors()
    if not allowed:
        return True  # gate disabled until CONTRIBUTORS exists with entries
    if identity is None:
        identity = current_identity()
    return bool(identity) and identity.lower() in allowed
