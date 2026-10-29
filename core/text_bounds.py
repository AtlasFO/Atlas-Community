"""One cut rule for texts a model reads in a bounded room."""
from __future__ import annotations

import re
from typing import Any


def cut(text: Any, limit: int) -> str:
    """The text within ``limit``: whole when it fits, else up to its last
    sentence end inside the bound when that keeps half of it, else up to
    its last word boundary, with a clip mark; never a cut inside a word."""
    t = " ".join(str(text or "").split())
    if len(t) <= limit:
        return t
    ends = [m.end() for m in re.finditer(r"[.;](?=\s)", t[:limit])]
    if ends and ends[-1] >= limit // 2:
        return t[:ends[-1]]
    head = t[:max(1, limit - 1)]
    space = head.rfind(" ")
    if space >= limit // 2:
        head = head[:space]
    return head.rstrip(" ,;:-") + "\u2026"
