"""Client environment baselines: validation shared by approve, notes, indexes.

Environment notes (brain/wiki/environments/<client-slug>/) are descriptive
baselines of a real client's estate — naming conventions, topology, AD
structure, logging/EDR coverage, known-benign admin patterns. They are the
one client-scoped knowledge class in the brain, injected only into runs that
declare that client via engagement.yaml AND ship no ground truth.

Hard content policy (the reason this module exists): baselines carry facts,
never verdicts. Prior-incident IOCs and "what we found last time" belong in
the per-case wiki entry, which is never injected — otherwise old solves
anchor new investigations and stale indicators become false positives.
"""

from __future__ import annotations

import re

# Provenance a baseline may claim. agent_run is deliberately absent: a
# baseline derived from a run is a prior solve wearing a disguise.
ALLOWED_SOURCES = ("client_provided", "baseline", "manual")

# Verdict vocabulary a baseline never needs — describe the behavior
# ("TIER0 admins run PsExec nightly from JUMP01"), not the judgment.
_VERDICT_RE = re.compile(
    r"(?i)\b(malicious|compromis\w*|attacker|adversary|intrusion|"
    r"c2|command[- ]and[- ]control|exfil\w*|backdoor|web[- ]?shell|"
    r"implant|beacon\w*|ioc|indicators?[- ]of[- ]compromise|breach\w*|"
    r"infect\w*|ransom\w*|dropper|persistence[- ]mechanism|"
    r"lateral[- ]movement)\b")


def verdict_hits(text: str) -> list[str]:
    """Sorted unique verdict words found in text (lowercased)."""
    return sorted({m.group(1).lower() for m in _VERDICT_RE.finditer(text or "")})


def is_environment_destination(destination: str) -> bool:
    return destination.strip().lstrip("./").startswith("wiki/environments")


def validate(meta: dict, text: str) -> list[str]:
    """Problems that make a note unfit for wiki/environments/. Empty = ok."""
    problems: list[str] = []
    source_type = str((meta.get("source") or {}).get("type") or "")
    if source_type not in ALLOWED_SOURCES:
        problems.append(
            f"source.type '{source_type or '(missing)'}' not allowed "
            f"(must be one of: {', '.join(ALLOWED_SOURCES)}; agent_run "
            "provenance is never accepted)")
    if not str(meta.get("client") or "").strip():
        problems.append("missing client (the environment's client slug)")
    if not str(meta.get("last_verified") or "").strip():
        problems.append("missing last_verified (date a human confirmed the "
                        "facts current)")
    hits = verdict_hits(text)
    if hits:
        problems.append(f"verdict language present ({', '.join(hits)})")
    return problems
