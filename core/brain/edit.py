"""Edit a staged Brain candidate before approval."""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

from core.brain import answer_key, capture, frontmatter, secrets, store


class EditError(Exception):
    pass


def _replace_section(body: str, heading: str, new_text: str) -> str:
    """Replace the first markdown section whose heading contains ``heading``."""
    lines = body.splitlines()
    out: list[str] = []
    i = 0
    replaced = False
    while i < len(lines):
        line = lines[i]
        hm = re.match(r"^(#+)\s+(.*)$", line)
        if hm and heading.lower() in hm.group(2).lower() and not replaced:
            level = len(hm.group(1))
            out.append(line)
            out.append("")
            out.append(new_text.rstrip())
            out.append("")
            i += 1
            while i < len(lines):
                hm2 = re.match(r"^(#+)\s+", lines[i])
                if hm2 and len(hm2.group(1)) <= level:
                    break
                i += 1
            replaced = True
            continue
        out.append(line)
        i += 1
    if not replaced:
        out.extend(["", f"## {heading}", "", new_text.rstrip(), ""])
    return "\n".join(out).rstrip() + "\n"


def edit_candidate(candidate: Path | str, *,
                   proposed_entry: str | None = None,
                   title: str | None = None,
                   clear_sensitive: bool = False,
                   why_reusable: str | None = None) -> Path:
    """Update a pending candidate in place. Recomputes content_hash / risk."""
    root = store.brain_root()
    path = Path(candidate) if Path(candidate).is_absolute() else root / candidate
    if not path.is_file():
        # Also accept bare inbox filename
        alt = root / "inbox/memory-candidates" / Path(candidate).name
        if alt.is_file():
            path = alt
        else:
            raise EditError(f"candidate not found: {candidate}")

    text = path.read_text(encoding="utf-8", errors="replace")
    meta, body, _ = frontmatter.parse(text)
    if str(meta.get("status") or "") not in ("pending_review", ""):
        raise EditError(f"candidate is not pending_review: {meta.get('status')}")

    if proposed_entry is not None:
        clean, findings = secrets.redact(proposed_entry)
        case_id = str((meta.get("origin") or {}).get("case_id") or "")
        clean, ak_hits = answer_key.redact(
            clean, answer_key.secrets_for_case_id(case_id))
        body = _replace_section(body, "Proposed Entry", clean)
        meta["content_hash"] = capture._content_hash(clean)
        risk = dict(meta.get("risk") or {})
        risk["contains_sensitive_data"] = (
            capture._is_sensitive(clean, bool(findings)) or bool(ak_hits))
        risk["contains_answer_key"] = bool(ak_hits)
        meta["risk"] = risk
        if risk["contains_sensitive_data"]:
            meta["source_classification"] = "confidential"
        elif clear_sensitive:
            meta["source_classification"] = "internal"
        meta["review_hints"] = capture._review_hints(clean)
        if not title:
            meta["title"] = clean if len(clean) <= 70 else clean[:67] + "…"

    if title is not None and title.strip():
        meta["title"] = title.strip()[:120]

    if why_reusable is not None:
        body = _replace_section(body, "Why Reusable", why_reusable.strip())
        expl = dict(meta.get("explainability") or {})
        expl["why_reusable"] = why_reusable.strip()
        meta["explainability"] = expl

    if clear_sensitive:
        risk = dict(meta.get("risk") or {})
        if risk.get("contains_answer_key"):
            raise EditError("cannot clear_sensitive: answer-key flag is permanent")
        # Only clear if a fresh scan is clean.
        hits = secrets.scan_text(
            frontmatter.serialize(meta, body))
        if hits:
            raise EditError(
                "cannot clear_sensitive: secret-like content still present")
        risk["contains_sensitive_data"] = False
        meta["risk"] = risk
        meta["source_classification"] = "internal"

    meta["updated"] = dt.datetime.now(dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")
    path.write_text(frontmatter.serialize(meta, body), encoding="utf-8")
    return path
